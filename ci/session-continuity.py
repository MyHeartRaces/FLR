#!/usr/bin/env python3
"""Kernel affinity qualification in disposable CI; never touches host routing.

Uses production rules with isolated veth stand-ins for carrier and anchor
egress, covering Linux classification, conntrack and NAT continuity.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import select
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

UNMATCHED = '198.51.100.41'
EXPLICIT_VPN = '198.51.100.42'
LAN_TARGET = '192.168.8.1'
ANCHOR_CLIENT = '192.168.8.4'
ANCHOR_SOURCE = '172.16.12.1'

SERVER = r'''
import socket,threading,sys
name,host=sys.argv[1:];ready=threading.Event()
def tcp():
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((host,9090));s.listen();ready.set()
 def serve(c):
  with c:
   for b in c.makefile('rb'):
    c.sendall(name.encode()+b)
 while True:
  c,_=s.accept();threading.Thread(target=serve,args=(c,),daemon=True).start()
threading.Thread(target=tcp,daemon=True).start()
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind((host,9090));ready.wait();print('ready',flush=True)
while True:
 b,a=u.recvfrom(256);u.sendto(name.encode()+b,a)
'''
CLIENT = r'''
import socket,sys,json
source,host=sys.argv[1:];port=30000
def pair(target):
 global port
 address=(target,9090)
 t=socket.socket();t.bind((source,port));port+=1;t.settimeout(3);t.connect(address)
 u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind((source,port));port+=1;u.settimeout(3);u.connect(address)
 return t,u
def exchange(sockets):
 results=[]
 for i,s in enumerate(sockets):
  b=('probe-'+str(i)+'\n').encode();s.sendall(b);reply=b''
  while len(reply)<len(b)+1:
   chunk=s.recv(256)
   if not chunk:raise RuntimeError('echo connection closed')
   reply+=chunk
  if reply[1:]!=b:raise RuntimeError('echo payload mismatch')
  results.append(reply[:1].decode())
 return results
old=pair(host);print(json.dumps({'ready':exchange(old)}),flush=True)
for command in sys.stdin:
 fields=command.split()
 if fields[0]=='new':
  fresh=pair(fields[1] if len(fields)>1 else host)
  try: result=exchange(fresh)
  finally:
   for s in fresh:s.close()
 else:result=exchange(old)
 print(json.dumps({'paths':result}),flush=True)
'''

BLOCKED = r'''
import errno,socket,sys
protocol,source,target,*mark=sys.argv[1:]
kind=socket.SOCK_STREAM if protocol=='tcp' else socket.SOCK_DGRAM
with socket.socket(socket.AF_INET,kind) as s:
 if mark:s.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,int(mark[0],0))
 s.bind((source,0));s.settimeout(1)
 try:
  s.connect((target,9090));s.send(b'blocked\n');s.recv(32)
 except TimeoutError:
  sys.exit(0)
 except OSError as e:
  if e.errno in (errno.ENETUNREACH,errno.EHOSTUNREACH):sys.exit(0)
  # A Linux OUTPUT drop can return EPERM directly to a local UDP sender.
  # The caller separately requires the output guard counter to increase.
  if mark and protocol=='udp' and e.errno==errno.EPERM:sys.exit(0)
  raise
 raise RuntimeError('blocked connection reached an endpoint')
'''

def validate_receipt(record, source):
    required_true=['qualified','tcp_udp_old_proxy_survived','new_flows_awg','ready_proxy_reused','proxy_process_link_routes_unchanged']
    required_true+=['direct_default_with_vpn_down','explicit_vpn_blocked_with_vpn_down','lan_reachable_with_vpn_down','tcp_udp_old_proxy_survived_mode_change','direct_ignores_vpn_and_device_rules']
    required_true+=['anchored_tcp_udp_survived_carrier_retirement']
    required_false=['wan_leak','real_tunnels_tested','hardware_tested']
    if not re.fullmatch(r'[a-f0-9]{40}', source or '') or record.get('source')!=source:
        raise ValueError('kernel receipt source differs from final build')
    if any(record.get(k) is not True for k in required_true) or any(record.get(k) is not False for k in required_false):
        raise ValueError('kernel qualification missing or false claim')
    hashes = ['production_nft_sha256', 'production_anchor_nft_sha256']
    if any(not isinstance(record.get(key), str) or not re.fullmatch(r'[a-f0-9]{64}', record[key]) for key in hashes) or not isinstance(record.get('kernel'),str) or not 1<=len(record['kernel'])<=128:
        raise ValueError('kernel receipt provenance missing')
    counters = ['wan_guard_dropped_packets', 'direct_mode_wan_guard_dropped_packets',
                'anchored_forward_guard_dropped_packets', 'anchored_output_guard_dropped_packets']
    if record.get('transport_simulation')!='isolated veth' or any(type(record.get(key)) is not int or record[key]<2 for key in counters):
        raise ValueError('kernel receipt lacks actual WAN guard evidence')



def conntrack_rows(output, protocol, source, target):
    # -o extended prefixes entries with the L3 family before tcp/udp.
    # Match complete tuple/mark tokens; substring matches can admit wrong marks.
    for row in output.splitlines():
        if not re.match(r'^(?:ipv4\s+\d+\s+)?' + protocol + r'\s+\d+\s', row):
            continue
        fields = {}
        for token in row.split():
            if '=' in token:
                name, value = token.split('=', 1)
                fields.setdefault(name, []).append(value)
        if fields.get('src', [])[:1] == [source] and fields.get('dst', [])[:1] == [target]:
            yield fields


def validate_conntrack_affinity(output):
    for protocol in ['tcp', 'udp']:
        marks = {m for row in conntrack_rows(output, protocol, '192.168.8.2', UNMATCHED) for m in row.get('mark', [])}
        if not {'553648128', '285212672'}.issubset(marks):
            raise ValueError('missing old/new channel affinity: ' + protocol)


def continuity_tuples(output):
    tuples = {}
    for protocol, port in [('tcp', '30000'), ('udp', '30001')]:
        rows = list(conntrack_rows(output, protocol, ANCHOR_CLIENT, UNMATCHED))
        if len(rows) != 1:
            raise ValueError('missing or ambiguous anchored flow: ' + protocol)
        fields = rows[0]
        dports = fields.get('dport', [])
        if (fields.get('mark') != [str(0x51000000)] or fields.get('src') != [ANCHOR_CLIENT, UNMATCHED]
                or fields.get('dst') != [UNMATCHED, ANCHOR_SOURCE] or fields.get('sport') != [port, '9090']
                or len(dports) != 2 or dports[0] != '9090' or not dports[1].isdigit() or not 0 < int(dports[1]) < 65536):
            raise ValueError('anchored flow lost its egress mapping: ' + protocol)
        tuples[protocol] = (ANCHOR_SOURCE, int(dports[1]), UNMATCHED, 9090)
    return tuples


def copy_fixture_policy(source, fixture):
    # Treat the fixture's documentation prefix as Internet-class traffic.
    # Preserve the shipped policy and all the actual private LAN matchers.
    shutil.copytree(source, fixture)
    path = fixture / 'rulesets' / 'local-ips.json'
    doc = json.loads(path.read_text())
    for rule in doc['rules']:
        cidrs = rule.get('ip_cidr', [])
        if '198.51.100.0/24' in cidrs:
            cidrs.remove('198.51.100.0/24')
    path.write_text(json.dumps(doc))


def qualify(renderer, policy, output):
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'Linux' or platform.system() != 'Linux':
        raise ValueError('kernel qualification requires disposable CI')
    if os.geteuid() != 0:
        raise ValueError('kernel qualification requires disposable CI root')
    for tool in ['ip', 'nft', 'conntrack', 'sysctl', 'python3']:
        if not shutil.which(tool):
            raise ValueError('missing kernel qualification tool: ' + tool)
    renderer, policy, output = Path(renderer).resolve(), Path(policy).resolve(), Path(output).resolve()
    if not renderer.is_file() or not policy.is_dir():
        raise ValueError('compiled production renderer and policy required')
    prefix = 'flrq-' + uuid.uuid4().hex[:10]
    names = {key: prefix + '-' + key for key in ['r', 'c', 'a', 'p', 'w', 's']}
    created, processes = [], []
    def run(*args, data=None):
        return subprocess.run(list(map(str, args)), input=data, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=True).stdout
    def ns(key, *args, data=None):
        return run('ip', 'netns', 'exec', names[key], *args, data=data)
    def line(process):
        if not select.select([process.stdout], [], [], 5)[0]:
            raise ValueError('isolated echo process timed out')
        value = process.stdout.readline()
        if not value:
            raise ValueError('isolated echo process exited')
        return value.strip()
    def proc(key, script, *args):
        p = subprocess.Popen(['ip', 'netns', 'exec', names[key], 'python3', '-u', '-c', script, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        processes.append(p)
        return p
    try:
        with tempfile.TemporaryDirectory(prefix='flr-affinity-') as directory:
            fixture = Path(directory) / 'policy'
            copy_fixture_policy(policy, fixture)
            rendered = json.loads(run(renderer, fixture))
        if set(rendered) != {'initial', 'recovered', 'failed', 'tunnel', 'direct', 'down', 'routes', 'rules', 'anchor'} or set(rendered['anchor']) != {'nft', 'routes', 'rules'}:
            raise ValueError('production renderer receipt rejected')
        for key in names:
            run('ip', 'netns', 'add', names[key]); created.append(names[key])
            ns(key, 'ip', 'link', 'set', 'lo', 'up')
            ns(key, 'sysctl', '-q', '-w', 'net.ipv4.conf.all.rp_filter=0', 'net.ipv4.conf.default.rp_filter=0')
        # Create pairs *inside* owned namespaces, never on the host network.
        links = [('c', 'br-lan', '192.168.8'), ('a', 'flr_awg', '172.16.10'), ('p', 'flr-hy', '172.16.11'),
                 ('w', 'eth1', '10.99.0'), ('s', 'flr_cont', '172.16.12')]
        for peer, device, subnet in links:
            ns('r', 'ip', 'link', 'add', device, 'type', 'veth', 'peer', 'name', 'peer-'+peer)
            ns('r', 'ip', 'link', 'set', 'peer-'+peer, 'netns', names[peer])
            ns(peer, 'ip', 'link', 'set', 'peer-'+peer, 'name', 'eth0')
            ns('r', 'ip', 'addr', 'add', subnet+'.1/24', 'dev', device)
            ns(peer, 'ip', 'addr', 'add', subnet+'.2/24', 'dev', 'eth0')
            ns('r', 'ip', 'link', 'set', device, 'up'); ns(peer, 'ip', 'link', 'set', 'eth0', 'up')
            ns(peer, 'ip', 'route', 'add', 'default', 'via', subnet+'.1')
            if peer != 'c':
                ns(peer, 'ip', 'addr', 'add', UNMATCHED+'/32', 'dev', 'lo')
        ns('c', 'ip', 'addr', 'add', '192.168.8.3/24', 'dev', 'eth0')
        ns('c', 'ip', 'addr', 'add', ANCHOR_CLIENT+'/24', 'dev', 'eth0')
        for peer in ['p', 'w']:
            ns(peer, 'ip', 'addr', 'add', EXPLICIT_VPN+'/32', 'dev', 'lo')
        ns('r', 'ip', 'link', 'add', 'flr-vless', 'type', 'dummy'); ns('r', 'ip', 'link', 'set', 'flr-vless', 'up')
        ns('r', 'sysctl', '-q', '-w', 'net.ipv4.ip_forward=1')
        ns('r', 'ip', 'route', 'add', 'default', 'via', '10.99.0.2', 'dev', 'eth1')
        def install_routes(recipe, tables=None):
            for rule in recipe['rules']:
                if tables is None or rule['Table'] in tables:
                    ns('r', 'ip', 'rule', 'add', 'pref', rule['Priority'], 'fwmark', hex(rule['Mark'])+'/'+hex(rule['Mask']), 'lookup', rule['Table'])
            for route in recipe['routes']:
                if tables is not None and route['Table'] not in tables:
                    continue
                args = ['ip', 'route', 'add']
                if route['Unreachable']: args.append('unreachable')
                args += ['default', 'table', route['Table'], 'metric', route['Metric']]
                if route['Device']: args += ['dev', route['Device']]
                ns('r', *args)
        install_routes(rendered)
        ns('r', 'nft', '-f', '-', data=rendered['initial'])
        servers = {}
        for key, tag in [('p', 'P'), ('a', 'A'), ('w', 'W'), ('s', 'S')]:
            servers[key] = proc(key, SERVER, tag, UNMATCHED)
            if line(servers[key]) != 'ready': raise ValueError('echo server not ready')
        for key, tag, target in [('p', 'P', EXPLICIT_VPN), ('w', 'W', EXPLICIT_VPN), ('r', 'L', LAN_TARGET)]:
            if line(proc(key, SERVER, tag, target)) != 'ready': raise ValueError('routing echo server not ready')
        def open_client(source, expected='P'):
            client = proc('c', CLIENT, source, UNMATCHED)
            if json.loads(line(client)) != {'ready': [expected, expected]}: raise ValueError('initial TCP/UDP used the wrong egress')
            return client
        client = open_client('192.168.8.2')
        def sample(command, expected, peer=client):
            peer.stdin.write(command+'\n'); peer.stdin.flush()
            result = json.loads(line(peer))
            if result != {'paths': [expected, expected]}:
                raise ValueError(f'TCP/UDP path continuity failed for {command}: {result!r}')
        def blocked(source, target, key='c', mark=None, counter=None):
            for protocol in ['tcp', 'udp']:
                before = counter() if counter is not None else None
                try:
                    flags = [hex(mark)] if mark is not None else []
                    ns(key, 'python3', '-c', BLOCKED, protocol, source, target, *flags)
                except subprocess.CalledProcessError as error:
                    raise ValueError(f'expected {protocol} blocking for {target}: {error.stderr.strip()}') from error
                if counter is not None and counter() <= before:
                    raise ValueError(f'continuity guard did not record a {protocol} drop')
        def resources():
            return {'proxy_pid': servers['p'].pid,
                    'link': json.loads(ns('r', 'ip', '-j', 'link', 'show', 'dev', 'flr-hy')),
                    'routes': json.loads(ns('r', 'ip', '-j', 'route', 'show', 'table', '771'))}
        before = resources()
        sample('sample', 'P')
        ns('r', 'nft', '-f', '-', data=rendered['recovered'])
        for _ in range(20):
            sample('sample', 'P'); time.sleep(.1)
        sample('new', 'A')
        marks = ns('r', 'conntrack', '-L', '-o', 'extended')
        print('Synthetic conntrack evidence:', marks, flush=True)
        validate_conntrack_affinity(marks)
        ns('r', 'nft', '-f', '-', data=rendered['failed'])
        sample('sample', 'P'); sample('new', 'P')
        after = resources()
        if before != after or any(p.poll() is not None for p in processes):
            raise ValueError('proxy process/link/route changed during default transitions')
        # Exercise kill switch: even a deliberately misrouted AWG table cannot reach
        # the WAN echo process (which would return W and fail the echo assertion).
        ns('r', 'ip', 'route', 'del', 'default', 'dev', 'flr_awg', 'table', '770', 'metric', '100')
        ns('r', 'ip', 'route', 'add', 'default', 'via', '10.99.0.2', 'dev', 'eth1', 'table', '770', 'metric', '50')
        ns('r', 'nft', '-f', '-', data=rendered['recovered'])
        def drop_count(chain='guard', anchored=False):
            chains=json.loads(ns('r','nft','-j','list','chain','inet','flr',chain))
            anchor_match = {'match': {'op': '!=', 'left': {'meta': {'key': 'oifname'}}, 'right': 'flr_cont'}}
            expressions = [item['rule']['expr'] for item in chains['nftables'] if 'rule' in item]
            return sum(e['counter']['packets'] for expr in expressions if not anchored or anchor_match in expr for e in expr if 'counter' in e)
        drops_before=drop_count()
        blocked('192.168.8.2', UNMATCHED)
        drops_after=drop_count()
        if drops_after-drops_before<2:raise ValueError('production WAN drop counter did not prove TCP/UDP blocking')
        sample('sample', 'P')
        # The second LAN address has no per-device override. Its existing
        # flows keep the proxy mark through a policy and selection change.
        ns('r', 'nft', '-f', '-', data=rendered['failed'])
        policy_client = open_client('192.168.8.3')
        ns('r', 'nft', '-f', '-', data=rendered['tunnel'])
        sample('sample', 'P', policy_client)
        sample('new', 'W', policy_client)
        sample('new '+EXPLICIT_VPN, 'P', policy_client)
        ns('r', 'nft', '-f', '-', data=rendered['down'])
        sample('sample', 'P', policy_client)
        sample('new', 'W', policy_client)
        sample('new '+LAN_TARGET, 'L', policy_client)
        blocked('192.168.8.3', EXPLICIT_VPN)
        # Model a route failure in the VPN fallback table. The WAN guard must
        # still see the explicit VPN class and drop both protocols.
        ns('r', 'ip', 'route', 'add', 'default', 'via', '10.99.0.2', 'dev', 'eth1', 'table', '773', 'metric', '50')
        direct_drops_before = drop_count()
        blocked('192.168.8.3', EXPLICIT_VPN)
        direct_drops = drop_count() - direct_drops_before
        if direct_drops < 2:
            raise ValueError('production WAN drop counter did not prove explicit VPN blocking in Tunnel mode')
        ns('r', 'nft', '-f', '-', data=rendered['direct'])
        sample('new '+EXPLICIT_VPN, 'W', policy_client)
        sample('new '+EXPLICIT_VPN, 'W', client)
        sample('sample', 'P', policy_client)

        # Replace the classifier without resetting conntrack. The anchor veth
        # stands in for the stable tunnel device while both carriers retire.
        ns('r', 'ip', 'route', 'del', 'default', 'via', '10.99.0.2', 'dev', 'eth1', 'table', '770', 'metric', '50')
        ns('r', 'ip', 'route', 'add', 'default', 'dev', 'flr_awg', 'table', '770', 'metric', '100')
        install_routes(rendered['anchor'], {774})
        ns('r', 'nft', '-f', '-', data=rendered['anchor']['nft'])
        anchored = open_client(ANCHOR_CLIENT, 'S')
        tuples = continuity_tuples(ns('r', 'conntrack', '-L', '-o', 'extended'))
        for device, table, mask in [('flr_awg', '770', '0x10000000/0x70000000'), ('flr-hy', '771', '0x20000000/0x70000000')]:
            ns('r', 'ip', 'route', 'del', 'default', 'dev', device, 'table', table, 'metric', '100')
            try:
                ns('r', 'conntrack', '-D', '--mark', mask)
            except subprocess.CalledProcessError as error:
                if error.returncode != 1 or '0 flow entries have been deleted' not in error.stderr:
                    raise
            sample('sample', 'S', anchored)
            ns('r', 'ip', 'route', 'add', 'default', 'dev', device, 'table', table, 'metric', '100')
            sample('sample', 'S', anchored)
            if continuity_tuples(ns('r', 'conntrack', '-L', '-o', 'extended')) != tuples:
                raise ValueError('carrier retirement changed the application NAT tuple')

        # Force the anchor table toward WAN. Test both client forwarding and
        # marked router output, including the path used for protected DNS.
        ns('r', 'ip', 'route', 'add', 'default', 'via', '10.99.0.2', 'dev', 'eth1', 'table', '774', 'metric', '50')
        forward_before = drop_count(anchored=True)
        output_before = drop_count('output_guard', anchored=True)
        blocked(ANCHOR_CLIENT, UNMATCHED, counter=lambda: drop_count(anchored=True))
        blocked(ANCHOR_SOURCE, UNMATCHED, 'r', 0x51000000, counter=lambda: drop_count('output_guard', anchored=True))
        anchor_forward_drops = drop_count(anchored=True) - forward_before
        anchor_output_drops = drop_count('output_guard', anchored=True) - output_before
        if min(anchor_forward_drops, anchor_output_drops) < 2:
            raise ValueError('continuity guard counters did not prove TCP/UDP blocking')
        ns('r', 'ip', 'route', 'del', 'default', 'via', '10.99.0.2', 'dev', 'eth1', 'table', '774', 'metric', '50')
        sample('sample', 'S', anchored)
        output.parent.mkdir(parents=True, exist_ok=True)
        record={'qualified': True, 'kernel': platform.release(), 'source': os.environ.get('GITHUB_SHA', ''),
            'production_nft_sha256': hashlib.sha256(rendered['initial'].encode()).hexdigest(),
            'production_anchor_nft_sha256': hashlib.sha256(rendered['anchor']['nft'].encode()).hexdigest(),
            'tcp_udp_old_proxy_survived': True, 'new_flows_awg': True, 'ready_proxy_reused': True,
            'proxy_process_link_routes_unchanged': True, 'wan_leak': False,
            'wan_guard_dropped_packets': drops_after-drops_before, 'transport_simulation': 'isolated veth', 'real_tunnels_tested': False, 'hardware_tested': False,
            'direct_default_with_vpn_down': True, 'explicit_vpn_blocked_with_vpn_down': True,
            'lan_reachable_with_vpn_down': True, 'tcp_udp_old_proxy_survived_mode_change': True,
            'direct_mode_wan_guard_dropped_packets': direct_drops,
            'direct_ignores_vpn_and_device_rules': True,
            'anchored_tcp_udp_survived_carrier_retirement': True,
            'anchored_forward_guard_dropped_packets': anchor_forward_drops,
            'anchored_output_guard_dropped_packets': anchor_output_drops}
        validate_receipt(record,os.environ.get('GITHUB_SHA',''))
        output.write_text(json.dumps(record,indent=2)+'\n')
    finally:
        for p in reversed(processes):
            if p.poll() is None: p.terminate()
        for p in reversed(processes):
            try: p.wait(timeout=3)
            except subprocess.TimeoutExpired: p.kill();p.wait(timeout=3)
        for name in reversed(created):
            subprocess.run(['ip', 'netns', 'del', name], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=10, check=True)

if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit('usage: session-continuity.py RENDERER POLICY OUTPUT')
    qualify(*map(Path, sys.argv[1:]))
