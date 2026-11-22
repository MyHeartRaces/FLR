import importlib.util
from io import BytesIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RelayBenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = ROOT / 'server/relay-benchmark/flr-relay-benchmark.py'
        spec = importlib.util.spec_from_file_location('relay_benchmark', path)
        cls.benchmark = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.benchmark)

    def test_curl_connects_only_to_the_pinned_address_and_has_transfer_limits(self):
        args = self.benchmark.parser().parse_args([
            'run', '--target-ip', '198.51.100.42', '--source-ip', '192.168.8.3',
            '--tls-name', 'relay.example.com', '--direction', 'upload',
        ])
        command = self.benchmark.curl_command('/usr/bin/curl', args, 8192, 1.5)
        self.assertEqual(command[:2], ['/usr/bin/curl', '-q'])
        for flag, value in [('--resolve', 'relay.example.com:443:198.51.100.42'),
                            ('--noproxy', '*'), ('--proto', '=https'),
                            ('--interface', '192.168.8.3'), ('--max-time', '1.500'),
                            ('--data-binary', '@-'), ('--max-filesize', '1')]:
            self.assertEqual(command[command.index(flag) + 1], value)
        self.assertNotIn('--insecure', command)
        self.assertNotIn('--location', command)
        self.assertEqual(command[-1], 'https://relay.example.com:443/flr-benchmark/upload')

    def test_fixture_budget_caps_total_bytes_even_with_multiple_streams(self):
        budget = self.benchmark.PayloadBudget(100)
        self.assertTrue(budget.reserve(60))
        self.assertFalse(budget.reserve(41))
        self.assertTrue(budget.reserve(40))
        self.assertFalse(budget.reserve(1))

    def test_udp_report_counts_timeout_as_loss_and_skips_gaps_in_jitter(self):
        result = self.benchmark.udp_report(5, {0: 12, 1: 15, 3: 40, 4: 45})
        self.assertEqual(result['received'], 4)
        self.assertEqual(result['lost'], 1)
        self.assertEqual(result['p95_rtt_ms'], 45)
        self.assertEqual(result['p95_jitter_ms'], 5)

    def test_fixture_acknowledges_complete_upload_and_enforces_the_shared_budget(self):
        class MemorySocket:
            def __init__(self, request):
                self.request = request
                self.output = bytearray()

            def settimeout(self, timeout):
                pass

            def makefile(self, mode, buffering):
                return BytesIO(self.request)

            def sendall(self, data):
                self.output.extend(data)

        server = SimpleNamespace(deadline=float('inf'), budget=self.benchmark.PayloadBudget(6),
                                 bytes={'upload': 0, 'download': 0}, lock=threading.Lock(), payload=b'abcdef')
        def request(raw):
            sock = MemorySocket(raw)
            self.benchmark.FixtureHandler(sock, ('127.0.0.1', 50000), server)
            return bytes(sock.output)

        sent = request(b'POST /flr-benchmark/upload HTTP/1.0\r\nContent-Length: 3\r\n\r\nabc')
        self.assertTrue(sent.startswith(b'HTTP/1.0 204 '))
        self.assertEqual(server.bytes['upload'], 3)
        over_budget = request(b'GET /flr-benchmark/download/4 HTTP/1.0\r\n\r\n')
        self.assertTrue(over_budget.startswith(b'HTTP/1.0 429 '))
        precise_budget = request(b'GET /flr-benchmark/download/3 HTTP/1.0\r\n\r\n')
        self.assertTrue(precise_budget.endswith(b'\r\n\r\nabc'))
        self.assertEqual(server.bytes['download'], 3)

    def test_matched_receipts_report_goodput_and_udp_differences(self):
        control = self.receipt(120, 7, 8, 2, 1)
        candidate = self.receipt(90, 10, 12, 3, 4)
        result = self.benchmark.compare([(control, candidate)] * 3)
        self.assertEqual(result['matched_pairs'], 3)
        self.assertEqual(result['median'], {
            'https_goodput_ratio': 0.75, 'udp_p95_rtt_delta_ms': 3,
            'udp_p99_rtt_delta_ms': 4, 'udp_p95_jitter_delta_ms': 1,
            'udp_loss_delta_pct_points': 3,
        })

    def test_failed_or_differently_configured_runs_do_not_count_as_matched(self):
        control = self.receipt(120, 7, 8, 2, 1)
        candidate = self.receipt(90, 10, 12, 3, 4)
        candidate['workload']['udp_bytes'] = 120
        with self.assertRaisesRegex(ValueError, 'different workloads'):
            self.benchmark.compare([(control, candidate)])
        candidate['workload']['udp_bytes'] = 96
        candidate['errors'] = ['worker deadline']
        with self.assertRaisesRegex(ValueError, 'failed benchmark run'):
            self.benchmark.compare([(control, candidate)])

    def test_compare_cli_reads_saved_receipts_and_keeps_budget_evidence(self):
        with TemporaryDirectory() as directory:
            control, candidate = Path(directory) / 'control.json', Path(directory) / 'candidate.json'
            control.write_text(json.dumps(self.receipt(120, 7, 8, 2, 1)))
            candidate.write_text(json.dumps(self.receipt(90, 10, 12, 3, 4)))
            args = self.benchmark.parser().parse_args(['compare', '--pair', str(control), str(candidate)])
            result = self.benchmark.compare_files(args.pair)
        self.assertEqual(result['pairs'][0]['control_https_elapsed_seconds'], 50)
        self.assertTrue(result['pairs'][0]['candidate_https_budget_reached'])

    @staticmethod
    def receipt(goodput, p95, p99, jitter, lost):
        return {
            'direction': 'download', 'seconds': 60,
            'workload': {'https_streams': 1, 'https_byte_budget': 512 * 1024 * 1024,
                         'udp_rate': 25, 'udp_bytes': 96},
            'https_goodput_mbps': goodput, 'https_elapsed_seconds': 50,
            'https_budget_reached': True, 'https_transfer_complete': True, 'errors': [],
            'udp': {'sent': 100, 'lost': lost, 'received': 100 - lost, 'p95_rtt_ms': p95,
                    'p99_rtt_ms': p99, 'p95_jitter_ms': jitter},
        }
