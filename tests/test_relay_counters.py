import csv
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


SAMPLER = Path(__file__).resolve().parents[1] / 'server/relay-benchmark/flr-relay-counters.sh'


class RelayCounterTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.proc = root / 'current'
        self.after = root / 'after'
        self.bin = root / 'bin'
        self.bin.mkdir()
        for fixture in (self.proc, self.after):
            (fixture / 'net').mkdir(parents=True)
            (fixture / 'sys/wan0').mkdir(parents=True)
            (fixture / 'sys/wan0/ifindex').write_text('4\n')
        self.tool('sleep', 'cp -R "$NEXT/." "$FLR_BENCH_PROC_ROOT"')
        self.tool('timeout', 'shift 3\nexec "$@"')
        self.tool('tc', 'cat "$FLR_BENCH_PROC_ROOT/qdisc"')
        self.env = dict(os.environ, PATH=str(self.bin) + ':/usr/bin:/bin',
                        FLR_BENCH_PROC_ROOT=str(self.proc), FLR_BENCH_NET_ROOT=str(self.proc / 'sys'),
                        NEXT=str(self.after))

    def tool(self, name, script):
        tool = self.bin / name
        tool.write_text('#!/bin/sh\n' + script + '\n')
        tool.chmod(0o700)

    def fixture(self, root, *, finish=False):
        (root / 'uptime').write_text(('124.08' if finish else '123.05') + ' 0.00\n')
        softirq, idle = (45, 200) if finish else (40, 100)
        (root / 'stat').write_text(f'cpu 1 2 3 {idle} 5 6 {softirq} 8 0 0\ncpu0 1 2 3 {idle} 5 6 {softirq} 8 0 0\nctxt 10\n')
        octets = '9007199254740999' if finish else '9007199254740993'
        drops = 0 if finish else 2
        (root / 'net/dev').write_text(f'   wan0: {octets} 11 12 {drops} 0 0 0 0 20 21 22 23 0 0 0 0\nother: 1 2 3 4 0 0 0 0 1 2 3 4 0 0 0 0\n')
        (root / 'net/snmp').write_text(f'Tcp: MaxConn OutSegs RetransSegs\nTcp: -1 100 {10 if finish else 6}\nUdp: InErrors RcvbufErrors SndbufErrors\nUdp: {9 if finish else 7} 0 0\n')
        (root / 'qdisc').write_text(f'qdisc cake 8001: root refcnt 2\n Sent 100 bytes 32 pkt (dropped {4 if finish else 1}, overlimits 0 requeues 0)\n backlog {9 if finish else 3}b {2 if finish else 1}p requeues 0\nqdisc fq_codel 0: parent 8001:1\n Sent 9999 bytes 500 pkt (dropped 99, overlimits 0 requeues 0)\n')

    def run_sampler(self, *args):
        return subprocess.run(['/bin/sh', str(SAMPLER), *args], env=self.env,
                              capture_output=True, text=True, timeout=5)

    def rows(self, *args):
        result = self.run_sampler(*args)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        return {(r['group'], r['name'], r['metric']): r for r in csv.DictReader(io.StringIO(result.stdout), delimiter='\t')}

    def test_reports_exact_deltas_and_scopes_to_selected_devices(self):
        self.fixture(self.proc)
        self.fixture(self.after, finish=True)
        rows = self.rows('--seconds', '1', '--interface', 'wan0')
        self.assertEqual(rows['sample', '-', 'uptime_centiseconds']['delta'], '103')
        self.assertEqual(rows['cpu', 'cpu0', 'idle']['delta'], '100')
        self.assertEqual(rows['cpu', 'cpu0', 'softirq']['delta'], '5')
        self.assertEqual(rows['cpu', 'cpu0', 'steal']['delta'], '0')
        self.assertEqual(rows['link', 'wan0', 'rx_bytes']['before'], '9007199254740993')
        self.assertEqual(rows['link', 'wan0', 'rx_bytes']['delta'], '6')
        self.assertEqual(rows['link', 'wan0', 'rx_dropped']['delta'], '-')
        self.assertEqual(rows['tcp', '-', 'RetransSegs']['delta'], '4')
        self.assertEqual(rows['udp', '-', 'InErrors']['delta'], '2')
        self.assertEqual(rows['qdisc', 'wan0/cake/8001:', 'dropped']['delta'], '3')
        self.assertEqual(rows['qdisc', 'wan0/cake/8001:', 'backlog_packets']['after'], '2')
        self.assertEqual(rows['qdisc', 'wan0/cake/8001:', 'backlog_packets']['delta'], '-')
        self.assertFalse(any(key[1] == 'other' or 'fq_codel' in key[1] for key in rows))

    def test_replaced_link_suppresses_delta_even_when_counters_increase(self):
        self.fixture(self.proc)
        self.fixture(self.after, finish=True)
        (self.after / 'sys/wan0/ifindex').write_text('9\n')
        rows = self.rows('--seconds', '1', '--interface', 'wan0', '--interface', 'absent')
        self.assertEqual(rows['link', 'wan0', 'rx_bytes']['delta'], '-')
        self.assertEqual(rows['qdisc', 'wan0/cake/8001:', 'dropped']['delta'], '-')
        self.assertEqual(rows['link', 'absent', 'present']['after'], '0')

    def test_optional_qdisc_and_snmp_fail_independently(self):
        self.fixture(self.proc)
        self.fixture(self.after, finish=True)
        (self.proc / 'net/snmp').unlink()
        (self.after / 'net/snmp').unlink()
        self.tool('tc', 'printf "qdisc other 0: root\\n"\nexit 1')
        rows = self.rows('--seconds', '1', '--interface', 'wan0')
        self.assertFalse(any(key[0] in {'qdisc', 'tcp', 'udp'} for key in rows))
        self.assertEqual(rows['link', 'wan0', 'rx_bytes']['delta'], '6')

    def test_uptime_reset_invalidates_host_counter_deltas(self):
        self.fixture(self.proc)
        self.fixture(self.after, finish=True)
        (self.after / 'uptime').write_text('23.01 0.00\n')
        rows = self.rows('--seconds', '1', '--interface', 'wan0')
        self.assertEqual(rows['sample', '-', 'uptime_centiseconds']['delta'], '-')
        self.assertEqual(rows['cpu', 'cpu0', 'idle']['delta'], '-')
        self.assertEqual(rows['link', 'wan0', 'rx_bytes']['delta'], '-')

    def test_rejects_invalid_duration_or_interface_arguments(self):
        for args in (('--seconds', '121', '--interface', 'wan0'),
                     ('--seconds', '0', '--interface', 'wan0'),
                     ('--seconds', '1', '--interface', 'wan0/unsafe'),
                     ('--seconds', '1', '--interface', 'wan0', '--interface', 'wan0'),
                     ('--seconds', '1', '--interface', 'a', '--interface', 'b', '--interface', 'c', '--interface', 'd', '--interface', 'e'),
                     ('--seconds', '1')):
            with self.subTest(args=args):
                result = self.run_sampler(*args)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, '')
