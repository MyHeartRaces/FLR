"""Static validation of a GL-MT6000 sysupgrade; no device operations."""

import hashlib
from pathlib import Path, PurePosixPath
import struct
import tarfile


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def check_sysupgrade(path, metadata, lock):
    expected = lock["openwrt"]
    if expected["supported_device"] not in metadata.get("supported_devices", []):
        raise ValueError("metadata device does not match GL-MT6000")
    version = metadata.get("version", {})
    numbers = [version[key] for key in ("number", "release", "version") if key in version]
    if not numbers or any(number != expected["version"] for number in numbers):
        raise ValueError("metadata OpenWrt version does not match lock")
    board = expected["profile"]
    prefix = "sysupgrade-" + board
    required = {prefix + "/" + name for name in ("CONTROL", "kernel", "root")}
    found = set()
    with tarfile.open(path, "r:*") as archive:
        for member in archive:
            name = member.name.rstrip("/")
            parts = PurePosixPath(name).parts
            if name.startswith("/") or ".." in parts or "\\" in name:
                raise ValueError("unsafe sysupgrade path: " + name)
            if not parts or parts[0] != prefix:
                raise ValueError("tar device does not match GL-MT6000: " + name)
            if member.isdir() and name == prefix:
                continue
            if name not in required or not member.isfile():
                raise ValueError("unexpected sysupgrade entry: " + name)
            if name in found or member.size <= 0:
                raise ValueError("duplicate or empty sysupgrade payload: " + name)
            found.add(name)
    if found != required:
        raise ValueError("missing sysupgrade payload: " + str(sorted(required - found)))
    return {"board": board, "entries": sorted(found), "sha256": sha256(path)}


def check_manifest(text, lock):
    packages = {}
    for line in text.splitlines():
        if " - " in line:
            name, version = line.split(" - ", 1)
            if name in packages:
                raise ValueError("duplicate manifest package: " + name)
            packages[name] = version
    for name in lock["packages"]:
        if name not in packages:
            raise ValueError("missing image package: " + name)
    kernel = packages.get("kernel", "")
    expected = lock["openwrt"]
    required_kernel = expected["kernel"] + "~" + expected["kernel_abi"] + "-r" + str(expected.get("kernel_release", 1))
    if kernel != required_kernel:
        raise ValueError("kernel version or ABI mismatch: " + kernel)
    versions = {
        "kmod-amneziawg": expected["kernel"] + "." + lock["awg"]["module_version"],
        "amneziawg-tools": lock["awg"]["tools_version"],
        "flint-sing-box": sing_box_package_version(lock["sing_box"]),
    }
    for name in ['kmod-nfnetlink-queue', 'kmod-nft-queue']:
        if name in lock['packages']:
            versions[name] = expected['kernel']
    if "runtime" in lock:
        versions.update({"flr-runtime": lock["runtime"]["version"], "luci-app-flr": "0.7"})
    versions.update({n["package"]: n["version"] for n in lock.get("native", {}).values() if "package" in n})
    for name, version in versions.items():
        if name not in lock["packages"]:
            continue
        if packages[name] != version + "-r1":
            raise ValueError(name + " version mismatch: " + packages[name])
    if "sing-box" in packages or "sing-box-tiny" in packages:
        raise ValueError("stock sing-box conflicts with pinned flint-sing-box")
    return packages


def check_elf(path, static=False, machine=183):
    if machine not in (183, 62):
        raise ValueError('unapproved ELF machine')
    with Path(path).open("rb") as stream:
        header = stream.read(64)
        if len(header) < 64 or header[:6] != b"\x7fELF\x02\x01" or int.from_bytes(header[18:20], "little") != machine:
            raise ValueError("expected 64-bit little-endian " + ("AArch64" if machine == 183 else "AMD64") + " ELF: " + str(path))
        offset = struct.unpack_from("<Q", header, 32)[0]
        entry_size, count = struct.unpack_from("<HH", header, 54)
        size = Path(path).stat().st_size
        if count and (entry_size < 56 or offset < 64 or offset + entry_size * count > size):
            raise ValueError("truncated or invalid ELF program headers: " + str(path))
        interpreter = None
        for index in range(count):
            stream.seek(offset + index * entry_size)
            program = struct.unpack("<IIQQQQQQ", stream.read(56))
            if static and program[0] in (2, 3):
                raise ValueError("expected static ELF without interpreter/dynamic loader: " + str(path))
            if program[0] != 3:  # PT_INTERP; static binaries and kernel modules have none.
                continue
            start, length = program[2], program[5]
            if interpreter is not None or not 1 <= length <= 256 or start + length > size:
                raise ValueError("invalid ELF interpreter record: " + str(path))
            stream.seek(start)
            interpreter = stream.read(length)
            if interpreter != b"/lib/ld-musl-aarch64.so.1\0":
                raise ValueError("unsupported ELF interpreter for OpenWrt musl: " + repr(interpreter))
    return "aarch64" if machine == 183 else "x86_64"


RUNTIME_FILES = [
    'usr/sbin/flr-controller', 'usr/sbin/flr-rollback',
    'lib/upgrade/keep.d/flr-runtime',
    'etc/init.d/flr-runtime', 'etc/init.d/flr-proxies',
    'etc/hotplug.d/iface/95-flr-runtime', 'etc/uci-defaults/99-flr-runtime',
    'usr/libexec/rpcd/luci.flr',
    'usr/share/luci/menu.d/luci-app-flr.json',
    'usr/share/rpcd/acl.d/luci-app-flr.json',
    'www/luci-static/resources/flr.js', 'www/luci-static/resources/flr.css',
    *['www/luci-static/resources/view/flr/' + name + '.js'
      for name in ['overview', 'profiles', 'proxy', 'settings', 'help',
                   'proxy/status', 'proxy/connections', 'proxy/order', 'proxy/import',
                   'routing/overview', 'routing/rules', 'routing/transfer']],
    # Russian LuCI catalog from luci-i18n-flr-ru (luci.mk: po/ru/flr.po).
    'usr/lib/lua/luci/i18n/flr.ru.lmo',
]


def check_native_lock(lock):
    import re
    expected = {'xray': 'XTLS/Xray-core', 'wstunnel': 'erebe/wstunnel', 'zapret2': 'bol-van/zapret2'}
    if set(lock.get('native', {})) != set(expected):
        raise ValueError('native lock must include all approved components')
    for component, repo in expected.items():
        item = lock['native'][component]
        prefix = f'https://github.com/{repo}/releases/download/{item.get("release_tag", "v" + item.get("version", ""))}/'
        if (not re.fullmatch('[0-9a-f]{64}', item.get('sha256', ''))
                or item.get('url') != prefix + item.get('archive', '')
                or not item.get('archive') or '/' in item['archive']
                or item.get('static') is not True):
            raise ValueError('native archive must be officially pinned: ' + component)


def check_payload_hash(path, relative, report):
    expected = report.get('payload_sha256', {}).get(relative)
    if not expected or sha256(path) != expected:
        raise ValueError('missing or mismatched verified payload hash: ' + relative)


def check_private_state(root):
    import json
    for directory in ['etc/flint-vpn', 'etc/sing-box', 'etc/amnezia', 'etc/flr-runtime']:
        if (root / directory).exists():
            raise ValueError('private VPN/runtime configuration unexpectedly included: ' + directory)
    retired = root / 'etc/init.d/flr-proxies'
    if retired.exists() and ('procd_set_param command' in retired.read_text() or 'sing-box run' in retired.read_text()):
        raise ValueError('retired proxy service starts engines')
    for link in (root / 'etc/rc.d').glob('*'):
        if 'flr-proxies' in link.name or 'zapret' in link.name or 'nfqws' in link.name:
            raise ValueError('retired or bypass service auto-enabled')
    build = root / 'usr/share/flint-vpn/build.json'
    if build.exists():
        metadata = json.loads(build.read_text())
        for flag in ['vpn_enabled', 'direct_bypass_enabled', 'router_contacted', 'boot_runtime_tested', 'recovery_tested', 'isp_bypass_tested']:
            if metadata.get(flag) is not False:
                raise ValueError('unsafe or missing image default/acceptance flag: ' + flag)


def check_runtime_root(root, lock, report):
    import json
    for relative in RUNTIME_FILES:
        path = root / relative
        if not path.is_file() or path.is_symlink() or not path.stat().st_size:
            raise ValueError('missing runtime payload: ' + relative)
        check_payload_hash(path, relative, report)
        if relative.startswith(('usr/sbin/', 'usr/libexec/', 'etc/init.d/', 'etc/hotplug.d/', 'etc/uci-defaults/')) and not path.stat().st_mode & 0o111:
            raise ValueError('runtime payload is not executable: ' + relative)
    check_elf(root / 'usr/sbin/flr-controller', static=True)
    for item in lock['native'].values():
        path = root / item['binary']
        check_elf(path, static=True)
        check_payload_hash(path, item['binary'], report)
    for name in ['zapret-lib', 'zapret-antidpi', 'zapret-auto']:
        relative = 'usr/share/flr-bypass/lua/' + name + '.lua'
        check_payload_hash(root / relative, relative, report)
    for relative in ['usr/share/luci/menu.d/luci-app-flr.json', 'usr/share/rpcd/acl.d/luci-app-flr.json']:
        json.loads((root / relative).read_text())
    for name in ['sing-box','xray','wstunnel','zapret2']:
        relative = 'usr/share/licenses/' + name + '/LICENSE'
        if 'engine_resolution' in lock:
            check_payload_hash(root / relative, relative, report)
    check_private_state(root)
    return True


def go_build_info(path):
    payload = Path(path).read_bytes()
    # Go >=1.18 embeds two varint-prefixed strings after this 32-byte header.
    # Read build metadata rather than arbitrary rodata: the disabled Naive stub
    # legitimately contains the forbidden tag name in its error message.
    # Format reference: https://go.dev/src/debug/buildinfo/buildinfo.go
    magic = b'\xff Go buildinf:'
    offset = payload.find(magic)
    while offset >= 0 and (offset % 16 or offset+32 > len(payload) or payload[offset+15] != 2):
        offset = payload.find(magic, offset+1)
    if offset < 0:
        raise ValueError('sing-box Go build-info missing or unsupported')
    offset += 32
    def read_string():
        nonlocal offset
        size = 0
        for shift in range(0, 70, 7):
            if offset >= len(payload):
                raise ValueError('truncated sing-box build-info')
            value = payload[offset]
            offset += 1
            size |= (value & 127) << shift
            if value < 128:
                if size > 1048576 or offset+size > len(payload):
                    raise ValueError('sing-box build-info size rejected')
                result = payload[offset:offset+size]
                offset += size
                return result
        raise ValueError('invalid sing-box build-info varint')
    version, module = read_string(), read_string()
    if not version.startswith(b'go1.') or len(module) < 33 or module[-17] != 10:
        raise ValueError('sing-box build-info framing rejected')
    try:
        lines = module[16:-16].decode('utf-8').splitlines()
    except UnicodeError as error:
        raise ValueError('sing-box build-info encoding rejected') from error
    settings = {}
    modules = []
    for line in lines:
        if line.startswith('build\t'):
            key, sep, value = line[6:].partition('=')
            if not sep or key in settings:
                raise ValueError('sing-box build settings rejected')
            settings[key] = value
        elif line.startswith(('dep\t', '=>\t')):
            modules.append(line.split('\t')[1])
    return {'go_version': version.decode('ascii'), 'settings': settings, 'linked_modules': sorted(set(modules))}


def check_sing_box_capabilities(path):
    info = go_build_info(path)
    settings, modules = info['settings'], info['linked_modules']
    tags = settings.get('-tags', '').split(',')
    required = ['with_quic', 'with_wireguard', 'with_utls']
    for tag in required:
        if tag not in tags:
            raise ValueError('approved sing-box capability missing: ' + tag)
    if 'with_naive_outbound' in tags or any('cronet' in name.lower() for name in modules):
        raise ValueError('sing-box Naive or linked cronet is forbidden')
    if settings.get('CGO_ENABLED') != '0':
        raise ValueError('sing-box must disable CGO')
    return required


def sing_box_package_version(item):
    """APK version of flint-sing-box for a lock section.

    The binary reports e.g. 1.14.4-flr-random-sni.1, which is not a valid
    apk-tools v3 version, so patched builds record `package_version` (digits and
    dots only) next to it. A lock without the key must already be a plain
    numeric version; anything else fails closed.
    """
    import re
    version = item.get('package_version', item.get('version'))
    if not isinstance(version, str) or not re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,5}', version):
        raise ValueError('sing-box package version is not a valid apk version')
    return version


def check_sing_box_markers(path, version, capabilities=()):
    """Static identity check usable on any architecture (no execution).

    The version is injected with -ldflags -X and the capability names are string
    constants of the patched sources, so both appear verbatim in the binary.
    """
    payload = Path(path).read_bytes()
    markers = [version.encode()]
    if capabilities:
        markers += [capability.encode() for capability in capabilities] + [b'flr_random_sni_suffix']
    for marker in markers:
        if marker not in payload:
            raise ValueError('sing-box identity marker missing: ' + marker.decode())


def parse_flr_capabilities(text):
    import json
    try:
        value = json.loads(text)
    except ValueError as error:
        raise ValueError('sing-box flr-capabilities output is not JSON') from error
    if not isinstance(value, dict):
        raise ValueError('sing-box flr-capabilities output rejected')
    capabilities = value.get('capabilities')
    if (value.get('version') != 1 or not isinstance(capabilities, list)
            or any(not isinstance(item, str) or not item for item in capabilities)):
        raise ValueError('sing-box flr-capabilities output rejected')
    return capabilities


def check_sing_box_host_identity(path, version, capabilities=()):
    """Run a host (AMD64) binary: reported version and FLR capabilities must match."""
    import subprocess
    def run(args):
        try:
            result = subprocess.run([str(path), *args], capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError('sing-box identity command could not run: ' + ' '.join(args)) from error
        if result.returncode:
            raise ValueError('sing-box identity command failed: ' + ' '.join(args))
        return result.stdout
    lines = run(['version']).splitlines()
    if not lines or lines[0] != 'sing-box version ' + version:
        raise ValueError('sing-box reported version differs from the pinned version')
    if capabilities:
        reported = parse_flr_capabilities(run(['flr-capabilities']))
        if sorted(reported) != sorted(capabilities):
            raise ValueError('sing-box FLR capabilities differ from the pinned capabilities')
    return list(capabilities)


def check_conntrack_accounting(root):
    import re
    path = root / 'etc/sysctl.d/11-nf-conntrack.conf'
    if not path.is_file() or not re.search(r'^\s*net\.netfilter\.nf_conntrack_acct\s*=\s*1\s*$', path.read_text(), re.M):
        raise ValueError('pinned OpenWrt conntrack accounting default missing or disabled')


def check_queue_modules(root, lock):
    for name in ['nft_queue', 'nfnetlink_queue']:
        modules = list((root / 'lib/modules').rglob(name + '.ko'))
        if len(modules) != 1:
            raise ValueError('native queue module missing or duplicated: ' + name)
        check_elf(modules[0])
        if ('vermagic=' + lock['openwrt']['kernel'] + ' ').encode() not in modules[0].read_bytes():
            raise ValueError('native queue module kernel vermagic mismatch: ' + name)


def load_resolved_lock(project, output, source_commit=None):
    import json
    import re
    from engine_releases import validate_selection, IntegrityError, version, Incompatible
    from awg_release import REQUIRED
    path = output / 'resolved-versions.lock.json'
    if not path.is_file() or path.is_symlink():
        raise ValueError('verified per-build resolved engine lock required')
    lock = json.loads(path.read_text())
    reference = json.loads((project / 'build/versions.lock.json').read_text())
    record = lock.get('engine_resolution', {})
    if record.get('format') != 'flr-engine-resolution-v1' or record.get('policy') != 'latest-compatible-stable':
        raise ValueError('resolved compatibility record required')
    if record.get('source_lock_sha256') != sha256(project / 'build/versions.lock.json'):
        raise ValueError('resolved lock belongs to a different source snapshot')
    if source_commit and record.get('source_commit') != source_commit:
        raise ValueError('resolved source commit mismatch')
    for digest in ['source_lock_sha256', 'contract_sha256']:
        if not re.fullmatch('[0-9a-f]{64}', record.get(digest, '')):
            raise ValueError('resolved source/contract digest invalid')
    if not re.fullmatch('[0-9a-f]{40}', record.get('source_commit', '')):
        raise ValueError('resolved source commit invalid')
    for key in ['openwrt', 'runtime', 'actions', 'packages', 'remove_packages', 'engine_policy']:
        if lock.get(key) != reference.get(key):
            raise ValueError('resolved lock changed pinned platform/build dependency: ' + key)
    for key in ['integration_repository','integration_commit','luci_version']:
        if lock['awg'].get(key) != reference['awg'].get(key):
            raise ValueError('resolved AWG integration platform reference changed')
    if record.get('hardware_tested') is not False or record.get('end_to_end_tested') is not False:
        raise ValueError('resolved native config checks cannot claim hardware qualification')
    components = record.get('components', {})
    if set(components) != {'sing_box','xray','wstunnel','zapret2','awg_module','awg_tools'}:
        raise ValueError('resolved complete component compatibility evidence missing')
    for name in ['sing_box','xray','wstunnel','zapret2']:
        selected = lock['sing_box'] if name == 'sing_box' else lock['native'][name]
        item = components[name]
        try:
            validate_selection(name, item)
        except IntegrityError as error:
            raise ValueError('unsafe resolved native selection: ' + name) from error
        baseline = reference['sing_box'] if name == 'sing_box' else reference['native'][name]
        dynamic = {'version','release_tag','archive','url','sha256'}
        if {k:v for k,v in selected.items() if k not in dynamic} != {k:v for k,v in baseline.items() if k not in dynamic}:
            raise ValueError('resolved native package/layout contract changed: ' + name)
        source_build = name == 'sing_box' and baseline.get('asset_kind') == 'source-build'
        fields = ['version','release_tag','archive','sha256'] if source_build else ['version','release_tag','archive','url','sha256']
        if source_build:
            from sing_box_source import load_local
            if item.get('source_pin') != baseline or item.get('asset_kind') != 'source-build':
                raise ValueError('source-built sing-box cannot fall back to official prebuilt')
            built = load_local(baseline, output / 'sing-box')
            if item.get('source_build') != built['receipt'] or item.get('receipt_sha256') != built['receipt_sha256']:
                raise ValueError('resolved source receipt differs from local verified artifacts')
            for arch, target in [('arm64', item), ('amd64', item.get('validation_asset', {}))]:
                if target.get('sha256') != built['archives'][arch]['sha256']:
                    raise ValueError('resolved source archive digest mismatch')
                if item.get('compatibility', {}).get(('arm64' if arch == 'arm64' else 'host') + '_binary_sha256') != built['receipt']['targets']['linux/' + arch]['sha256']:
                    raise ValueError('native compatibility checked a different source-built binary')
            if item.get('compatibility', {}).get('payload_sha256', {}).get('usr/share/licenses/sing-box/LICENSE') != built['license_sha256']:
                raise ValueError('source build license differs from compatibility evidence')
        for key in fields:
            if selected.get(key) != item.get(key):
                raise ValueError('resolved native metadata/payload selection mismatch: ' + name)
        evidence = item.get('compatibility', {})
        if (evidence.get('level') != 'arm64-static-and-matching-amd64-native-config'
                or not evidence.get('cases') or not re.fullmatch('[0-9a-f]{64}', evidence.get('arm64_binary_sha256', ''))
                or not re.fullmatch('[0-9a-f]{64}', evidence.get('host_binary_sha256', ''))
                or evidence.get('hardware_tested') is not False
                or evidence.get('end_to_end_tested') is not False):
            raise ValueError('resolved candidate has incomplete native compatibility evidence: ' + name)
        expected_payloads = {'usr/share/licenses/' + ('sing-box' if name == 'sing_box' else name) + '/LICENSE'}
        if name == 'zapret2':
            expected_payloads.update('usr/share/flr-bypass/lua/' + helper + '.lua' for helper in ['zapret-lib','zapret-antidpi','zapret-auto'])
        payloads = evidence.get('payload_sha256', {})
        if set(payloads) != expected_payloads or any(not re.fullmatch('[0-9a-f]{64}', value) for value in payloads.values()):
            raise ValueError('resolved license/Lua compatibility evidence missing or unsafe: ' + name)
    for field,name in [('module','awg_module'),('tools','awg_tools')]:
        item = components[name]
        try:
            version(item.get('version'))
            if item['version'].startswith('v') or item.get('tag_name', '').removeprefix('v') != item['version']:
                raise ValueError('resolved AWG numeric version/tag mismatch')
        except Incompatible as error:
            raise ValueError('unsafe resolved AWG version') from error
        if not re.fullmatch('[0-9a-f]{40}', item.get('commit', '')):
            raise ValueError('unsafe resolved AWG commit')
        source_paths = {'src/uapi/wireguard.h','src/netlink.c'} if field == 'module' else {'src/uapi/linux/linux/wireguard.h','src/config.c'}
        if set(item.get('source_blobs', {})) != source_paths or set(item.get('uapi', {})) != set(REQUIRED):
            raise ValueError('resolved AWG complete 3.1 source/UAPI evidence missing')
        if any(type(index) is not int or not 0 <= index <= 65535 for index in item['uapi'].values()):
            raise ValueError('resolved AWG UAPI indices invalid')
        for blob in item.get('source_blobs', {}).values():
            if not re.fullmatch('[0-9a-f]{40}', blob.get('git_blob', '')) or not re.fullmatch('[0-9a-f]{64}', blob.get('sha256', '')):
                raise ValueError('resolved AWG source digest invalid')
        if lock['awg'][field+'_version'] != components[name].get('version') or lock['awg'][field+'_commit'] != components[name].get('commit'):
            raise ValueError('resolved AWG metadata/source mismatch')
        if not components[name].get('uapi') or not components[name].get('source_blobs'):
            raise ValueError('resolved AWG source contract evidence missing')
    if components['awg_module']['uapi'] != components['awg_tools']['uapi']:
        raise ValueError('resolved AWG pair UAPI mismatch')
    check_native_lock(lock)
    return lock


def sdk_feeds(default, pins):
    """Retain the immutable base source supplied by the hash-pinned official SDK."""
    import re
    base = [line.strip() for line in default.splitlines()
            if re.match(r'^src-git(?:-full)?\s+(?:--root=package\s+)?base\s', line.strip())]
    pattern = (r'src-git(?:-full)? --root=package base https://'
               r'(?:git\.openwrt\.org/openwrt/openwrt|github\.com/openwrt/openwrt)\.git\^[0-9a-f]{40}')
    if len(base) != 1 or not re.fullmatch(pattern, base[0]):
        raise ValueError('official SDK commit-pinned base feed missing or unexpected')
    if set(pins) != {'packages','luci'} or any(not re.fullmatch('[0-9a-f]{40}', value) for value in pins.values()):
        raise ValueError('packages/LuCI feed commit pins required')
    return base[0] + '\n' + ''.join(
        'src-git-full ' + name + ' https://github.com/openwrt/' + name + '.git^' + pins[name] + '\n'
        for name in ['packages','luci'])
