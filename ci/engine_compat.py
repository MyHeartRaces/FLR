"""Isolated matching-version native config gates, runnable only on disposable CI."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tarfile
import zipfile

from buildlib import check_elf, check_sing_box_capabilities
from engine_releases import Incompatible, IntegrityError


def require_ci():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'amd64'):
        raise IntegrityError('native compatibility checks require existing disposable Linux AMD64 CI')


def member(data, name):
    try:
        if data[:2] == b'PK':
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                matches = [x for x in archive.infolist() if x.filename == name]
                if len(matches) != 1 or matches[0].file_size > 128 * 1024 * 1024:
                    raise Incompatible('expected bounded archive payload missing: ' + name)
                return archive.read(matches[0])
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as archive:
            matches = [x for x in archive if x.name.rstrip('/') == name]
            if len(matches) != 1 or not matches[0].isfile() or matches[0].size > 128 * 1024 * 1024:
                raise Incompatible('expected bounded archive payload missing: ' + name)
            return archive.extractfile(matches[0]).read()
    except (tarfile.TarError, zipfile.BadZipFile, EOFError) as error:
        raise IntegrityError('verified archive is corrupt') from error


def invoke(binary, args, case):
    require_ci()
    try:
        result = subprocess.run([str(binary), *args], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=20, text=True, errors='replace')
    except subprocess.TimeoutExpired as error:
        raise IntegrityError('native validation timed out without compatibility evidence: ' + case) from error
    except OSError as error:
        raise IntegrityError('CI native execution unavailable: ' + case) from error
    if result.returncode:
        # A signal, crash or generic failure is never config incompatibility.
        if parser_rejection(Path(binary).name, args, result.returncode, result.stdout):
            raise Incompatible(case + ': native parser rejected owned input: ' + result.stdout[-1800:])
        raise IntegrityError(case + ': unclassified native execution failure (exit ' + str(result.returncode) + '): ' + result.stdout[-1800:])
    return result.stdout


class NativeContracts:
    def __init__(self, directory, scratch):
        self.directory = Path(directory)
        self.scratch = Path(scratch)
        self.manifest = json.loads((self.directory / 'manifest.json').read_text())
        if self.manifest.get('format') != 'flr-engine-contracts-v1' or self.manifest.get('hardware_tested') is not False:
            raise IntegrityError('production renderer compatibility manifest missing')
        cases = self.manifest.get('cases', [])
        expected = {'bundle-json','gecko-json','gecko-bounds','salamander-uri','xhttp-json','xhttp-uri','shadowtls-json','wgws-json','wgws-compact','tls-raw','reality-raw','tls-xhttp','reality-xhttp','xray-tls-raw','xray-tls-ws','xray-reality-raw','xray-reality-xhttp','xray-reality-grpc','xray-tls-grpc','xray-reality-splithttp','tls-vision','reality-vision','xray-tls-ws-nondefault','xray-tls-grpc-nondefault','xray-reality-grpc-nondefault'}
        if not expected.issubset({c.get('id') for c in cases}) or len(cases) > 100:
            raise IntegrityError('complete supported fixture matrix missing or unbounded')
        self.inputs = {}
        for case in cases:
            if case.get('wan') != 'eth1' or len(case.get('outer_endpoints', [])) != 1:
                raise IntegrityError('owned renderer WAN contract missing')
            for key in ('sing_box', 'xray'):
                if case.get(key):
                    relative = case[key]
                    path = self.directory / relative
                    if path.resolve().parent.parent != self.directory.resolve() or path.is_symlink():
                        raise IntegrityError('unsafe renderer fixture path')
                    self.inputs[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.digest = hashlib.sha256(json.dumps({'manifest':self.manifest,'inputs':self.inputs},sort_keys=True).encode()).hexdigest()

    def validate(self, component, release, arm_data, host_data):
        require_ci()
        tag = release['tag_name']
        version = tag.removeprefix('v')
        folder = self.scratch / component / version
        folder.mkdir(parents=True, exist_ok=True)
        if component == 'sing_box':
            layout = 'static' if release.get('asset_kind') == 'source-build' else 'musl'
            arm_path = f'sing-box-{version}-linux-arm64-{layout}/sing-box'
            host_path = f'sing-box-{version}-linux-amd64-{layout}/sing-box'
            program = 'sing-box'
        elif component == 'xray':
            arm_path = host_path = program = 'xray'
        elif component == 'wstunnel':
            arm_path = host_path = program = 'wstunnel'
        else:
            prefix = 'zapret2-' + tag
            arm_path = prefix + '/binaries/linux-arm64/nfqws2'
            host_path = prefix + '/binaries/linux-x86_64/nfqws2'
            program = 'nfqws2'
        arm = folder / 'arm64-payload'
        arm.write_bytes(member(arm_data, arm_path))
        try:
            check_elf(arm, static=True)
            if component == 'sing_box':
                check_sing_box_capabilities(arm)
        except ValueError as error:
            raise Incompatible('ARM64 runtime ABI/capability validation failed: ' + str(error)) from error
        host = folder / program
        host.write_bytes(member(host_data, host_path))
        if host.read_bytes()[:6] != b'\x7fELF\x02\x01' or int.from_bytes(host.read_bytes()[18:20], 'little') != 62:
            raise Incompatible('matching-version CI validation binary is not Linux AMD64 ELF')
        host.chmod(0o700)
        if component == 'sing_box':
            check_sing_box_capabilities(host)
        license_path = f'sing-box-{version}-linux-arm64-{layout}/LICENSE' if component == 'sing_box' else 'LICENSE'
        evidence_files = {}
        if component != 'zapret2':
            license_data = member(arm_data, license_path)
            if not license_data or len(license_data) > 1024 * 1024:
                raise Incompatible('required license payload missing or unbounded')
            evidence_files['usr/share/licenses/' + ('sing-box' if component == 'sing_box' else component) + '/LICENSE'] = hashlib.sha256(license_data).hexdigest()
        checked = []
        if component == 'zapret2':
            lua = folder / 'lua'
            lua.mkdir(exist_ok=True)
            for name in ('zapret-lib','zapret-antidpi','zapret-auto'):
                try:
                    data = bounded_gunzip(member(arm_data,prefix+'/lua/'+name+'.lua.gz'))
                    (lua / (name + '.lua')).write_bytes(data)
                    evidence_files['usr/share/flr-bypass/lua/' + name + '.lua'] = hashlib.sha256(data).hexdigest()
                except (gzip.BadGzipFile, EOFError) as error:
                    raise IntegrityError('verified Lua archive payload corrupt') from error
            args = [a.replace('@/usr/share/flr-bypass/lua/', '@'+str(lua)+'/') for a in self.manifest['bypass_args']]
            invoke(host, [*args,'--dry-run'], 'zapret fixed TCP/QUIC/Lua/WAN-loop arguments')
            checked.append('fixed-tcp-quic-lua-native-dry-run')
        for case in self.manifest['cases']:
            if component == 'sing_box':
                invoke(host, ['check','-c',str(self.directory / case['sing_box'])], case['id'])
                checked.append(case['id'])
            elif component == 'xray' and case.get('xray'):
                invoke(host, ['run','-test','-config',str(self.directory / case['xray'])], case['id'])
                checked.append(case['id'])
            elif component == 'wstunnel' and case.get('sidecar_args'):
                args = case['sidecar_args']
                help_text = invoke(host, ['--help'], 'wstunnel global CLI') + invoke(host, ['client','--help'], 'wstunnel client CLI')
                check_cli_surface(help_text, args)
                # Confirm --help does not bypass unknown-option validation on this release.
                try:
                    invoke(host, [*args,'--flr-deliberately-invalid-option','--help'], 'wstunnel parser sentinel')
                except Incompatible as error:
                    if '--flr-deliberately-invalid-option' not in str(error):
                        raise Incompatible('wstunnel sentinel did not prove unknown-option rejection') from error
                else:
                    raise Incompatible('wstunnel help bypasses owned argument validation')
                invoke(host, [*args,'--help'], case['id'] + ' owned WGWS CLI')
                checked.append(case['id'])
        if not checked:
            raise IntegrityError('native component had no contract checks')
        return {'level':'arm64-static-and-matching-amd64-native-config','cases':checked,
                'arm64_binary_sha256':hashlib.sha256(arm.read_bytes()).hexdigest(),
                'host_binary_sha256':hashlib.sha256(host.read_bytes()).hexdigest(), 'payload_sha256':evidence_files,
                'hardware_tested':False,'end_to_end_tested':False}


def bounded_gunzip(payload):
    with gzip.GzipFile(fileobj=io.BytesIO(payload)) as stream:
        data = stream.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise Incompatible('Lua helper exceeds bounded contract size')
    return data


def check_cli_surface(help_text, args):
    for arg in args:
        flag = arg.split('=', 1)[0]
        if arg.startswith('-') and not re.search(r'(?<![A-Za-z0-9_-])' + re.escape(flag) + r'(?![A-Za-z0-9_-])', help_text):
            raise Incompatible('wstunnel owned CLI option missing: ' + arg)


# Xray's JSON loader can ignore unknown fields. Require these supported schema
# fields in matching official source as well as successful native config checks.
XRAY_FIELDS = {
    'SocketConfig': {'mark','interface','domainStrategy'},
    'StreamConfig': {'network','security','tlsSettings','realitySettings','rawSettings','tcpSettings','xhttpSettings','wsSettings','grpcSettings','sockopt'},
    'SplitHTTPConfig': {'host','path','mode','headers','extra','noGRPCHeader','noSSEHeader','xPaddingBytes','scMaxEachPostBytes','scMinPostsIntervalMs','scMaxBufferedPosts','scStreamUpServerSecs','xmux'},
    'XmuxConfig': {'maxConcurrency','maxConnections','cMaxReuseTimes','hMaxRequestTimes','hMaxReusableSecs','hKeepAlivePeriod'},
    'TLSConfig': {'serverName','fingerprint','alpn','allowInsecure'},
    'REALITYConfig': {'serverName','fingerprint','publicKey','password','shortId','spiderX','show'},
    'WebSocketConfig': {'path','headers'},
    'GRPCConfig': {'serviceName','authority','multiMode','idle_timeout','health_check_timeout','permit_without_stream','initial_windows_size'},
}


def check_xray_schema(text):
    for name, expected in XRAY_FIELDS.items():
        block = re.search(r'type\s+'+name+r'\s+struct\s*\{(.*?)\n\}', text, re.S)
        fields = set(re.findall(r'`json:"([^",]+)', block[1])) if block else set()
        if not expected.issubset(fields):
            raise Incompatible('matching official Xray schema lacks supported fields: '+name+' '+str(sorted(expected-fields)))


def source_function(text, declaration):
    block = re.search(declaration + r'[^\n]*\{(.*?)^\}', text, re.S | re.M)
    return re.sub(r'\s+', '', block[1]) if block else ''


def check_xray_ws_source(transport, dialer):
    # The production adapter emits native ed path semantics, not ignored JSON
    # tags. Keep the proof inside the actual matching Build/Dial/Write bodies.
    build = source_function(transport, r'func\s+\(c\s+\*WebSocketConfig\)\s+Build\(\)')
    required = ['url.Parse(path)', 'u.Query()', 'q.Get("ed")',
                'strconv.Atoi(q.Get("ed"))', 'ed=uint32(Ed)', 'q.Del("ed")',
                'u.RawQuery=q.Encode()', 'path=u.String()', 'Path:path,', 'Ed:ed']
    if not all(token in build for token in required):
        raise Incompatible('matching official Xray lacks lossless native WS ed translation')
    dial = source_function(dialer, r'func\s+Dial\(')
    websocket = source_function(dialer, r'func\s+dialWebSocket\(')
    write = source_function(dialer, r'func\s+\(d\s+\*delayDialConn\)\s+Write\(')
    if ('ProtocolSettings.(*Config).Ed>0' not in dial
            or 'header.Set("Sec-WebSocket-Protocol",base64.RawURLEncoding.EncodeToString(ed))' not in websocket
            or 'len(ed)>int(d.streamSettings.ProtocolSettings.(*Config).Ed)' not in write):
        raise Incompatible('matching official Xray lacks standard WS early-data header or size enforcement')


def parser_rejection(program, args, code, output):
    """Only explicit known parser protocols; unknown diagnostics remain fatal.

    Clap unexpected-argument diagnostics identify the supplied option and exit 2.
    sing-box readConfig wraps decode errors separately from read/initialization
    errors; only its unknown-field/type decode messages are classified here.
    Xray recognizes only the observed path-bound REALITY transport build
    rejection. Other Xray/nfqws diagnostics remain fatal rather than guessed.
    """
    if code <= 0:
        return False
    lines = output.strip().splitlines()
    if program == 'wstunnel' and code == 2 and '--help' in args and lines:
        match = re.fullmatch(r"error: unexpected argument '([^']+)' found", lines[0])
        return bool(match and match[1] in args and match[1].startswith('-'))
    if program == 'xray' and code == 23 and len(args) == 4 and args[:3] == ['run','-test','-config']:
        # Exact observed config-build chain, bound to this owned fixture path.
        # Exit 23 alone and other Xray diagnostics remain fatal.
        diagnostic = ('Failed to start: main: failed to load config files: [' + args[3]
                      + '] > infra/conf: failed to build outbound config with tag proxy'
                      + ' > infra/conf: failed to build stream settings for outbound detour'
                      + ' > infra/conf: REALITY only supports RAW, XHTTP and gRPC for now.')
        return diagnostic in lines
    if program == 'sing-box' and code == 1 and len(args) == 3 and args[:2] == ['check','-c']:
        marker = 'decode config at ' + args[2] + ': '
        diagnostic = next((line for line in lines if line.startswith('FATAL[') and marker in line), '')
        if diagnostic:
            reason = diagnostic.split(marker, 1)[1]
            return bool(re.fullmatch(r'(?:[A-Za-z0-9_.\[\]]+: )*(?:json: )?unknown field "[A-Za-z0-9_.]+"', reason)
                        or re.fullmatch(r'(?:[A-Za-z0-9_.\[\]]+: )*unknown outbound type: (?:hysteria2|vless|shadowsocks|shadowtls|socks|direct)', reason))
    return False
