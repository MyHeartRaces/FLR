#!/usr/bin/env python3
"""Explicit, bounded HTTPS and UDP path measurements on operator-owned fixtures."""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import select
import shutil
import socket
from statistics import median
import struct
import subprocess
import sys
import threading
import time


MIB = 1024 * 1024
MAX_CHUNK = 8 * MIB
MAX_UDP_BYTES = 1200
MAX_UDP_RATE = 200
MAX_RECEIPT_BYTES = 64 * 1024
MAX_COMPARISON_PAIRS = 12
MAGIC = b'FLR1'
HEADER = struct.Struct('!4s8sI')
PATH = '/flr-benchmark'


def bounded(minimum, maximum):
    def parse(value):
        try:
            number = int(value)
        except ValueError as error:
            raise argparse.ArgumentTypeError('expected an integer') from error
        if not minimum <= number <= maximum:
            raise argparse.ArgumentTypeError(f'expected {minimum} to {maximum}')
        return number
    return parse


def ipv4(value):
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise argparse.ArgumentTypeError('expected a numeric IPv4 address') from error
    if address.is_multicast or address.is_unspecified or int(address) == 0xffffffff:
        raise argparse.ArgumentTypeError('expected a specific unicast address')
    return str(address)


def tls_name(value):
    labels = value.split('.')
    label = r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
    if len(value) > 253 or len(labels) < 2 or labels[-1].isdigit() or any(not re.fullmatch(label, x) for x in labels):
        raise argparse.ArgumentTypeError('expected a DNS name covered by the existing TLS certificate')
    return value


def parser():
    options = argparse.ArgumentParser(description=__doc__)
    commands = options.add_subparsers(dest='command', required=True)
    run = commands.add_parser('run', help='measure a preconfigured fixture over the selected route')
    run.add_argument('--target-ip', type=ipv4, required=True)
    run.add_argument('--source-ip', type=ipv4, required=True)
    run.add_argument('--tls-name', type=tls_name)
    run.add_argument('--https-port', type=bounded(1, 65535), default=443)
    run.add_argument('--udp-port', type=bounded(1024, 65535), default=39080)
    run.add_argument('--seconds', type=bounded(1, 120), default=60)
    run.add_argument('--direction', choices=['download', 'upload', 'idle'], default='download')
    run.add_argument('--streams', type=int, choices=[1, 4], default=1)
    run.add_argument('--max-mib', type=bounded(1, 16384), default=512)
    run.add_argument('--udp-rate', type=bounded(1, MAX_UDP_RATE), default=25)
    run.add_argument('--udp-bytes', type=bounded(HEADER.size, MAX_UDP_BYTES), default=96)
    serve = commands.add_parser('serve', help='serve bounded fixture traffic behind an existing TLS listener')
    serve.add_argument('--http-port', type=bounded(1024, 65535), default=39081)
    serve.add_argument('--udp-port', type=bounded(1024, 65535), default=39080)
    serve.add_argument('--udp-bind', type=ipv4, required=True)
    serve.add_argument('--allow-source', type=ipv4, required=True)
    serve.add_argument('--seconds', type=bounded(1, 300), default=180)
    serve.add_argument('--max-mib', type=bounded(1, 16384), default=512)
    comparison = commands.add_parser('compare', help='compare saved receipts from matching workloads')
    comparison.add_argument('--pair', action='append', nargs=2, metavar=('CONTROL', 'CANDIDATE'), required=True)
    return options


class PayloadBudget:
    def __init__(self, limit):
        self.remaining = limit
        self.lock = threading.Lock()

    def reserve(self, size):
        with self.lock:
            if size > self.remaining:
                return False
            self.remaining -= size
            return True


class FixtureHTTP(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 8

    def __init__(self, port, budget, deadline):
        super().__init__(('127.0.0.1', port), FixtureHandler)
        self.budget = budget
        self.deadline = deadline
        self.slots = threading.BoundedSemaphore(4)
        self.payload = os.urandom(MAX_CHUNK)
        self.bytes = {'download': 0, 'upload': 0}
        self.lock = threading.Lock()

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def handle_error(self, request, address):
        # Fixture evidence records aggregate counters only.
        pass


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def setup(self):
        self.request.settimeout(2)
        super().setup()

    def body_budget(self, value):
        size = int(value) if re.fullmatch(r'[0-9]{1,8}', value) else 0
        if not 1 <= size <= MAX_CHUNK:
            self.send_error(400)
            return 0
        if time.monotonic() >= self.server.deadline or not self.server.budget.reserve(size):
            self.send_error(429)
            return 0
        return size

    def response(self, status, size):
        self.send_response(status)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', str(size))
        self.send_header('Cache-Control', 'no-store, no-transform')
        self.end_headers()

    def account(self, direction, size):
        with self.server.lock:
            self.server.bytes[direction] += size

    def do_GET(self):
        prefix = PATH + '/download/'
        if not self.path.startswith(prefix):
            self.send_error(404)
            return
        size = self.body_budget(self.path[len(prefix):])
        if size:
            self.connection.settimeout(min(2, max(0.001, self.server.deadline - time.monotonic())))
            self.response(200, size)
            self.wfile.write(memoryview(self.server.payload)[:size])
            self.account('download', size)

    def do_POST(self):
        if self.path != PATH + '/upload':
            self.send_error(404)
            return
        lengths = self.headers.get_all('Content-Length', [])
        if len(lengths) != 1 or self.headers.get('Transfer-Encoding'):
            self.send_error(400)
            return
        left = size = self.body_budget(lengths[0])
        if not size:
            return
        while left:
            remaining = self.server.deadline - time.monotonic()
            if remaining <= 0:
                return
            self.connection.settimeout(min(2, remaining))
            chunk = self.rfile.read1(min(left, 65536))
            if not chunk:
                return
            left -= len(chunk)
        self.response(204, 0)
        self.account('upload', size)


def serve(args):
    deadline = time.monotonic() + args.seconds
    budget = PayloadBudget(args.max_mib * MIB)
    received = replied = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, FixtureHTTP(args.http_port, budget, deadline) as http:
        udp.bind((args.udp_bind, args.udp_port))
        udp.settimeout(0.2)
        server = threading.Thread(target=http.serve_forever, kwargs={'poll_interval': 0.1}, daemon=True)
        server.start()
        window = time.monotonic()
        allowed = 0
        try:
            while time.monotonic() < deadline:
                if not select.select([udp], [], [], min(0.2, max(0, deadline - time.monotonic())))[0]:
                    continue
                data, peer = udp.recvfrom(MAX_UDP_BYTES + 1)
                if peer[0] != args.allow_source or not HEADER.size <= len(data) <= MAX_UDP_BYTES or not data.startswith(MAGIC):
                    continue
                received += 1
                now = time.monotonic()
                if now - window >= 1:
                    window, allowed = now, 0
                if allowed < MAX_UDP_RATE:
                    allowed += 1
                    try:
                        udp.sendto(data, peer)
                    except OSError:
                        continue
                    replied += 1
        finally:
            http.shutdown()
        return {'https_payload_bytes': http.bytes.copy(), 'udp_valid_requests': received, 'udp_replies_sent': replied}


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[math.ceil(len(ordered) * fraction) - 1], 3)


def udp_report(sent, rtt):
    jitter = [abs(value - rtt[seq - 1]) for seq, value in rtt.items() if seq - 1 in rtt]
    return {'sent': sent, 'received': len(rtt), 'lost': sent - len(rtt),
            'p50_rtt_ms': percentile(rtt.values(), 0.5), 'p95_rtt_ms': percentile(rtt.values(), 0.95),
            'p99_rtt_ms': percentile(rtt.values(), 0.99), 'p95_jitter_ms': percentile(jitter, 0.95)}


def measure_udp(args, deadline, stats):
    nonce = os.urandom(8)
    sent_at, rtt = {}, {}
    sequence = send_errors = 0
    padding = bytes(args.udp_bytes - HEADER.size)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind((args.source_ip, 0))
        udp.connect((args.target_ip, args.udp_port))
        udp.setblocking(False)
        next_send = time.monotonic()
        while (now := time.monotonic()) < deadline:
            if now >= next_send:
                try:
                    udp.send(HEADER.pack(MAGIC, nonce, sequence) + padding)
                except OSError as error:
                    stats['socket_error'] = error.errno
                    send_errors += 1
                else:
                    sent_at[sequence] = now
                sequence += 1
                next_send = now + 1 / args.udp_rate
            timeout = max(0, min(next_send, deadline) - time.monotonic())
            if not select.select([udp], [], [], timeout)[0]:
                continue
            try:
                reply = udp.recv(MAX_UDP_BYTES + 1)
            except OSError as error:
                stats['socket_error'] = error.errno
                continue
            if len(reply) != args.udp_bytes:
                continue
            magic, session, seq = HEADER.unpack_from(reply)
            if magic == MAGIC and session == nonce and seq in sent_at and seq not in rtt and reply[HEADER.size:] == padding:
                rtt[seq] = (time.monotonic() - sent_at[seq]) * 1000
    stats.update(udp_report(len(sent_at), rtt))
    stats['send_errors'] = send_errors


def curl_command(curl, args, size, timeout):
    upload = args.direction == 'upload'
    connect = f'{args.tls_name}:{args.https_port}'
    command = [curl, '-q', '--silent', '--proto', '=https', '--noproxy', '*',
               '--resolve', f'{connect}:{args.target_ip}', '--interface', args.source_ip,
               '--max-time', f'{timeout:.3f}', '--connect-timeout', f'{min(timeout, 5):.3f}',
               '--max-filesize', str(1 if upload else size), '--output', os.devnull,
               '--write-out', '%{http_code} %{size_download} %{size_upload}']
    if upload:
        command += ['--header', 'Expect:', '--header', 'Content-Type: application/octet-stream', '--data-binary', '@-']
    path = '/upload' if upload else f'/download/{size}'
    return command + [f'https://{connect}{PATH}{path}']


def curl_path():
    curl = shutil.which('curl')
    if not curl:
        raise ValueError('curl 8.4 or later is required for bounded HTTPS measurements')
    result = subprocess.run([curl, '-q', '--version'], capture_output=True, text=True, timeout=2, check=True)
    version = re.match(r'curl (\d+)\.(\d+)', result.stdout)
    if not version or tuple(map(int, version.groups())) < (8, 4):
        raise ValueError('curl 8.4 or later is required for bounded HTTPS measurements')
    return curl


def measure_https(curl, args, payload, limit, deadline, stats):
    started = time.monotonic()
    while stats['payload_bytes'] < limit and (remaining := deadline - time.monotonic()) >= 0.01:
        size = min(MAX_CHUNK, limit - stats['payload_bytes'])
        command = curl_command(curl, args, size, remaining)
        upload = args.direction == 'upload'
        try:
            result = subprocess.run(command, input=payload[:size] if upload else None, capture_output=True, timeout=remaining + 0.2)
        except subprocess.TimeoutExpired:
            stats['deadline_reached'] = True
            break
        if result.returncode == 28 and deadline - time.monotonic() < 0.05:
            stats['deadline_reached'] = True
            break
        expected = f'204 0 {size}' if upload else f'200 {size} 0'
        if result.returncode or result.stdout.strip() != expected.encode():
            stats['curl_exit'] = result.returncode
            status = result.stdout.split(maxsplit=1)[0] if result.stdout else b''
            if re.fullmatch(rb'\d{3}', status):
                stats['http_status'] = int(status)
            break
        stats['payload_bytes'] += size
        stats['completed_requests'] += 1
    stats['elapsed_seconds'] = round(time.monotonic() - started, 3)


def run(args):
    active = args.direction != 'idle'
    curl = curl_path() if active else None
    payload = os.urandom(MAX_CHUNK) if args.direction == 'upload' else b''
    started_epoch = int(time.time())
    deadline = time.monotonic() + args.seconds
    udp = {}
    errors = []

    def worker(target, parameters):
        try:
            target(*parameters)
        except (OSError, ValueError) as error:
            errors.append(type(error).__name__)

    threads = [threading.Thread(target=worker, args=(measure_udp, (args, deadline, udp)), daemon=True)]
    https = []
    if active:
        for _ in range(args.streams):
            stats = {'payload_bytes': 0, 'completed_requests': 0}
            https.append(stats)
            params = (curl, args, payload, args.max_mib * MIB // args.streams, deadline, stats)
            threads.append(threading.Thread(target=worker, args=(measure_https, params), daemon=True))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(max(0, deadline - time.monotonic() + 0.5))
    if any(thread.is_alive() for thread in threads):
        errors.append('worker deadline')
    https = [stats.copy() for stats in https]
    total = sum(stream['payload_bytes'] for stream in https)
    elapsed = max((stream.get('elapsed_seconds', 0) for stream in https), default=0)
    transfer_complete = all(stream['completed_requests'] and 'curl_exit' not in stream for stream in https)
    workload = {'https_streams': args.streams if active else 0,
                'https_byte_budget': args.max_mib * MIB if active else 0,
                'udp_rate': args.udp_rate, 'udp_bytes': args.udp_bytes}
    return {'direction': args.direction, 'seconds': args.seconds, 'workload': workload,
            'started_epoch_seconds': started_epoch, 'finished_epoch_seconds': int(time.time()),
            'https_payload_bytes': total,
            'https_elapsed_seconds': elapsed, 'https_budget_reached': active and total == args.max_mib * MIB,
            'https_transfer_complete': transfer_complete,
            'https_goodput_mbps': round(total * 8 / 1e6 / elapsed, 3) if elapsed else None,
            'https_streams': https, 'udp': udp.copy(), 'errors': errors.copy()}


def receipt_shape(report):
    if not isinstance(report, dict):
        raise ValueError('invalid benchmark receipt')
    direction, seconds, workload = (report.get(key) for key in ('direction', 'seconds', 'workload'))
    if direction not in ('upload', 'download', 'idle') or type(seconds) is not int or not 1 <= seconds <= 120:
        raise ValueError('invalid benchmark direction or duration')
    keys = ('https_streams', 'https_byte_budget', 'udp_rate', 'udp_bytes')
    if not isinstance(workload, dict) or any(type(workload.get(key)) is not int for key in keys):
        raise ValueError('benchmark receipt needs explicit workload settings')
    streams, budget, rate, size = (workload[key] for key in keys)
    if not (1 <= rate <= MAX_UDP_RATE and HEADER.size <= size <= MAX_UDP_BYTES):
        raise ValueError('invalid UDP workload')
    if direction == 'idle':
        if streams != 0 or budget != 0:
            raise ValueError('invalid idle workload')
    elif streams not in (1, 4) or not MIB <= budget <= 16384 * MIB or budget % MIB:
        raise ValueError('invalid HTTPS workload')
    if report.get('https_transfer_complete') is not True or report.get('errors') != []:
        raise ValueError('failed benchmark run')
    return direction, seconds, streams, budget, rate, size


def report_metric(report, key, maximum, optional=False):
    value = report.get(key)
    if optional and value is None:
        return None
    if type(value) not in (int, float) or not 0 <= value <= maximum:
        raise ValueError(f'invalid benchmark metric {key}')
    return value


def compare_pair(control, candidate, direction):
    result = {}
    if direction != 'idle':
        control_speed = report_metric(control, 'https_goodput_mbps', 1e9)
        candidate_speed = report_metric(candidate, 'https_goodput_mbps', 1e9)
        if control_speed < 0.001 or candidate_speed < 0.001:
            raise ValueError('HTTPS goodput must be positive')
        result['https_goodput_ratio'] = round(candidate_speed / control_speed, 4)
        for label, report in (('control', control), ('candidate', candidate)):
            result[f'{label}_https_elapsed_seconds'] = report_metric(report, 'https_elapsed_seconds', 121)
            reached = report.get('https_budget_reached')
            if type(reached) is not bool:
                raise ValueError('invalid HTTPS budget evidence')
            result[f'{label}_https_budget_reached'] = reached

    udp_control, udp_candidate = control.get('udp'), candidate.get('udp')
    if not isinstance(udp_control, dict) or not isinstance(udp_candidate, dict):
        raise ValueError('benchmark receipt needs UDP evidence')
    loss = []
    for udp in (udp_control, udp_candidate):
        sent, received, lost = (udp.get(key) for key in ('sent', 'received', 'lost'))
        if any(type(count) is not int for count in (sent, received, lost)):
            raise ValueError('failed benchmark run: invalid UDP packet counts')
        if not (0 < received <= sent <= 120 * MAX_UDP_RATE and lost == sent - received):
            raise ValueError('failed benchmark run: invalid UDP packet counts')
        if udp.get('send_errors', 0) or udp.get('socket_error') is not None:
            raise ValueError('failed benchmark run: UDP socket error')
        loss.append(lost * 100 / sent)
    result['udp_loss_delta_pct_points'] = round(loss[1] - loss[0], 3)
    for field in ('p95_rtt_ms', 'p99_rtt_ms', 'p95_jitter_ms'):
        optional = field == 'p95_jitter_ms'
        before = report_metric(udp_control, field, 120000, optional)
        after = report_metric(udp_candidate, field, 120000, optional)
        result[f'udp_{field[:-3]}_delta_ms'] = round(after - before, 3) if before is not None and after is not None else None
    return result


def compare(pairs):
    if not 1 <= len(pairs) <= MAX_COMPARISON_PAIRS:
        raise ValueError(f'expected 1 to {MAX_COMPARISON_PAIRS} benchmark pairs')
    shape = receipt_shape(pairs[0][0])
    direction = shape[0]
    results = []
    for control, candidate in pairs:
        if receipt_shape(control) != shape or receipt_shape(candidate) != shape:
            raise ValueError('benchmark receipts have different workloads')
        results.append(compare_pair(control, candidate, direction))
    metrics = ('https_goodput_ratio', 'udp_p95_rtt_delta_ms', 'udp_p99_rtt_delta_ms',
               'udp_p95_jitter_delta_ms', 'udp_loss_delta_pct_points')
    summary, samples = {}, {}
    for key in metrics:
        values = [row[key] for row in results if key in row and row[key] is not None]
        samples[key] = len(values)
        summary[key] = round(median(values), 4) if values else None
    return {'direction': direction, 'matched_pairs': len(results), 'pairs': results,
            'median': summary, 'metric_sample_counts': samples}


def compare_files(pairs):
    if not 1 <= len(pairs) <= MAX_COMPARISON_PAIRS:
        raise ValueError(f'expected 1 to {MAX_COMPARISON_PAIRS} benchmark pairs')

    def read(path):
        if not Path(path).is_file():
            raise ValueError('benchmark receipt must be a file')
        with open(path, 'rb') as file:
            data = file.read(MAX_RECEIPT_BYTES + 1)
        if len(data) > MAX_RECEIPT_BYTES:
            raise ValueError('benchmark receipt is too large')
        try:
            return json.loads(data)
        except (ValueError, RecursionError) as error:
            raise ValueError('invalid benchmark receipt JSON') from error

    return compare([(read(control), read(candidate)) for control, candidate in pairs])


def main():
    options = parser()
    args = options.parse_args()
    if args.command == 'run' and args.direction != 'idle' and not args.tls_name:
        options.error('--tls-name is required for HTTPS measurements')
    try:
        if args.command == 'compare':
            result = compare_files(args.pair)
        else:
            result = serve(args) if args.command == 'serve' else run(args)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    if args.command == 'run' and (result['errors'] or not result['udp'].get('received') or not result['https_transfer_complete']):
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
