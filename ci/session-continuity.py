#!/usr/bin/env python3
"""Kernel affinity qualification in disposable CI; never touches host routing.

Uses production rules with isolated veth stand-ins for transport egress. This
proves Linux classification/conntrack continuity, not a real sing-box/AWG tunnel.
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
import time
import uuid

SERVER = r'''
import socket,threading,sys
name=sys.argv[1];ready=threading.Event()
def tcp():
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('9.9.9.9',9090));s.listen();ready.set()
 def serve(c):
  with c:
   for b in c.makefile('rb'):
    c.sendall(name.encode()+b)
 while True:
  c,_=s.accept();threading.Thread(target=serve,args=(c,),daemon=True).start()
threading.Thread(target=tcp,daemon=True).start()
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind(('9.9.9.9',9090));ready.wait();print('ready',flush=True)
while True:
 b,a=u.recvfrom(256);u.sendto(name.encode()+b,a)
'''
CLIENT = r'''
import socket,sys,json
address=('9.9.9.9',9090);port=30000
def pair():
 global port
 t=socket.socket();t.bind(('192.168.8.2',port));port+=1;t.settimeout(3);t.connect(address)
 u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind(('192.168.8.2',port));port+=1;u.settimeout(3);u.connect(address)
 return t,u
def exchange(sockets):
 results=[]
 for i,s in enumerate(sockets):
  b=('probe-'+str(i)+'\n').encode();s.sendall(b);reply=b''
  while len(reply)<len(b)+1:reply+=s.recv(256)
  if reply[1:]!=b:raise RuntimeError('echo payload mismatch')
  results.append(reply[:1].decode())
 return results
old=pair();print(json.dumps({'ready':exchange(old)}),flush=True)
for command in sys.stdin:
 if command.strip()=='new':
  fresh=pair()
  try: result=exchange(fresh)
  finally:
   for s in fresh:s.close()
 else:result=exchange(old)
 print(json.dumps({'paths':result}),flush=True)
'''

def validate_receipt(record, source):
    required_true=['qualified','tcp_udp_old_proxy_survived','new_flows_awg','ready_proxy_reused','proxy_process_link_routes_unchanged']
    required_false=['wan_leak','real_tunnels_tested','hardware_tested']
    if not re.fullmatch(r'[a-f0-9]{40}', source or '') or record.get('source')!=source:
        raise ValueError('kernel receipt source differs from final build')
    if any(record.get(k) is not True for k in required_true) or any(record.get(k) is not False for k in required_false):
        raise ValueError('kernel qualification missing or false claim')
    if not re.fullmatch(r'[a-f0-9]{64}', record.get('production_nft_sha256','')) or not isinstance(record.get('kernel'),str) or not 1<=len(record['kernel'])<=128:
        raise ValueError('kernel receipt provenance missing')
    if record.get('transport_simulation')!='isolated veth' or type(record.get('wan_guard_dropped_packets')) is not int or record['wan_guard_dropped_packets']<2:
        raise ValueError('kernel receipt lacks actual WAN guard evidence')



def validate_conntrack_affinity(output):
    # -o extended prefixes entries with the L3 family before tcp/udp.
    # Match complete tuple/mark tokens; substring matches can admit wrong marks.
    for protocol in ['tcp', 'udp']:
        marks = set()
        for row in output.splitlines():
            if not re.match(r'^(?:ipv4\s+\d+\s+)?' + protocol + r'\s+\d+\s', row):
                continue
            tokens = row.split()
            sources = [token for token in tokens if token.startswith('src=')]
            destinations = [token for token in tokens if token.startswith('dst=')]
            if not sources or sources[0] != 'src=192.168.8.2' or not destinations or destinations[0] != 'dst=9.9.9.9':
                continue
            marks.update(token for token in tokens if token.startswith('mark='))
        if not {'mark=553648128', 'mark=285212672'}.issubset(marks):
            raise ValueError('missing old/new channel affinity: ' + protocol)


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
    names = {key: prefix + '-' + key for key in ['r', 'c', 'a', 'p', 'w']}
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
        rendered = json.loads(run(renderer, policy))
        if set(rendered) != {'initial', 'recovered', 'failed', 'routes', 'rules'}:
            raise ValueError('production renderer receipt rejected')
        for key in names:
            run('ip', 'netns', 'add', names[key]); created.append(names[key])
            ns(key, 'ip', 'link', 'set', 'lo', 'up')
            ns(key, 'sysctl', '-q', '-w', 'net.ipv4.conf.all.rp_filter=0', 'net.ipv4.conf.default.rp_filter=0')
        # Create pairs *inside* owned namespaces, never on the host network.
        for peer, device, subnet in [('c', 'br-lan', '192.168.8'), ('a', 'flr_awg', '172.16.10'), ('p', 'flr-hy', '172.16.11'), ('w', 'eth1', '10.99.0')]:
            ns('r', 'ip', 'link', 'add', device, 'type', 'veth', 'peer', 'name', 'peer-'+peer)
            ns('r', 'ip', 'link', 'set', 'peer-'+peer, 'netns', names[peer])
            ns(peer, 'ip', 'link', 'set', 'peer-'+peer, 'name', 'eth0')
            ns('r', 'ip', 'addr', 'add', subnet+'.1/24', 'dev', device)
            ns(peer, 'ip', 'addr', 'add', subnet+'.2/24', 'dev', 'eth0')
            ns('r', 'ip', 'link', 'set', device, 'up'); ns(peer, 'ip', 'link', 'set', 'eth0', 'up')
            ns(peer, 'ip', 'route', 'add', 'default', 'via', subnet+'.1')
            if peer != 'c':
                ns(peer, 'ip', 'addr', 'add', '9.9.9.9/32', 'dev', 'lo')
        ns('r', 'ip', 'link', 'add', 'flr-vless', 'type', 'dummy'); ns('r', 'ip', 'link', 'set', 'flr-vless', 'up')
        ns('r', 'sysctl', '-q', '-w', 'net.ipv4.ip_forward=1')
        ns('r', 'ip', 'route', 'add', 'default', 'via', '10.99.0.2', 'dev', 'eth1')
        for rule in rendered['rules']:
            ns('r', 'ip', 'rule', 'add', 'pref', rule['Priority'], 'fwmark', hex(rule['Mark'])+'/'+hex(rule['Mask']), 'lookup', rule['Table'])
        for route in rendered['routes']:
            args = ['ip', 'route', 'add']
            if route['Unreachable']: args.append('unreachable')
            args += ['default', 'table', route['Table'], 'metric', route['Metric']]
            if route['Device']: args += ['dev', route['Device']]
            ns('r', *args)
        ns('r', 'nft', '-f', '-', data=rendered['initial'])
        servers = {}
        for key, tag in [('p', 'P'), ('a', 'A'), ('w', 'W')]:
            servers[key] = proc(key, SERVER, tag)
            if line(servers[key]) != 'ready': raise ValueError('echo server not ready')
        client = proc('c', CLIENT)
        if json.loads(line(client)) != {'ready': ['P', 'P']}: raise ValueError('initial TCP/UDP did not use proxy')
        def sample(command, expected):
            client.stdin.write(command+'\n'); client.stdin.flush()
            if json.loads(line(client)) != {'paths': [expected, expected]}:
                raise ValueError('TCP/UDP path continuity failed: '+command)
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
        def drop_count():
            chains=json.loads(ns('r','nft','-j','list','chain','inet','flr','guard'))
            return sum(e['counter']['packets'] for item in chains['nftables'] if 'rule' in item for e in item['rule']['expr'] if 'counter' in e)
        drops_before=drop_count()
        for protocol in ['tcp', 'udp']:
            packet = "import socket; s=socket.socket(socket.AF_INET,"+('socket.SOCK_STREAM' if protocol=='tcp' else 'socket.SOCK_DGRAM')+");s.settimeout(1);s.connect(('9.9.9.9',9090));s.send(b'blocked\\n');print(s.recv(32))"
            try:
                ns('c', 'python3', '-c', packet)
            except subprocess.CalledProcessError as error:
                if 'TimeoutError' not in error.stderr and 'Network is unreachable' not in error.stderr:
                    raise ValueError('unexpected kill-switch probe error') from error
            else:
                raise ValueError('failed AWG escaped VPN guard: '+protocol)
        drops_after=drop_count()
        if drops_after-drops_before<2:raise ValueError('production WAN drop counter did not prove TCP/UDP blocking')
        sample('sample', 'P')
        output.parent.mkdir(parents=True, exist_ok=True)
        record={'qualified': True, 'kernel': platform.release(), 'source': os.environ.get('GITHUB_SHA', ''),
            'production_nft_sha256': hashlib.sha256(rendered['initial'].encode()).hexdigest(),
            'tcp_udp_old_proxy_survived': True, 'new_flows_awg': True, 'ready_proxy_reused': True,
            'proxy_process_link_routes_unchanged': True, 'wan_leak': False,
            'wan_guard_dropped_packets': drops_after-drops_before, 'transport_simulation': 'isolated veth', 'real_tunnels_tested': False, 'hardware_tested': False}
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
