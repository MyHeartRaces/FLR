#!/usr/bin/env python3
"""Build only the pinned, FLR-patched sing-box engine, exclusively in approved disposable CI."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from engine_compat import require_ci
from engine_releases import OfficialAPI
from sing_box_source import validate_pin, unpack_source, patch_source, manifest_digests, validate_binary, validate_host_binary, validate_receipt, archive_bytes


def main():
    # Check before even reading a source URL or invoking any compiler.
    require_ci()
    project = Path(__file__).resolve().parents[1]
    pin = validate_pin(json.loads((project / 'build/versions.lock.json').read_text())['sing_box'])
    output = project / 'out/sing-box'
    output.mkdir(parents=True, exist_ok=True)
    base_env = {**os.environ, 'GOTOOLCHAIN': 'local', 'GOENV': 'off', 'GOFLAGS': '',
                'GO111MODULE': 'on', 'CGO_ENABLED': '0', 'GOOS': 'linux',
                'GOPROXY': 'https://proxy.golang.org', 'GOSUMDB': 'sum.golang.org',
                'GOPRIVATE': '', 'GONOPROXY': '', 'GONOSUMDB': ''}
    version = subprocess.check_output(['go', 'version'], env=base_env, text=True, timeout=10)
    if not re.fullmatch(r'go version go' + re.escape(pin['go_version']) + r' linux/amd64\n', version):
        raise ValueError('exact approved Go compiler required')
    source = OfficialAPI().read(pin['source_url'], 32 * 1024 * 1024)
    receipt = {'version': 1, 'asset_kind': 'source-build', 'upstream_version': pin['upstream_version'],
               'custom_version': pin['version'], 'capabilities': pin['capabilities'],
               **{key: pin[key] for key in ['upstream_commit', 'source_url', 'source_sha256',
                                            'go_version', 'tags', 'cgo_enabled']},
               'targets': {}, 'linked_modules': [], 'hardware_tested': False, 'end_to_end_tested': False}
    payloads = {}
    sums = []
    with tempfile.TemporaryDirectory(prefix='flr-sing-box-source-') as temp:
        root = unpack_source(pin, source, Path(temp))
        # go.mod/go.sum digests are derived from the archive-verified source (see sing_box_source).
        derived = manifest_digests(root)
        receipt.update(derived)
        patch = patch_source(pin, root, project)
        # Offline wrapper tests authored with the patch; no TLS handshake or tunnel is executed.
        with (output / 'build-patch-tests.log').open('wb') as stream:
            subprocess.run(['go', 'test', '-mod=readonly', '-tags', ','.join(pin['tags']),
                            './protocol/hysteria2', '-run', '^TestFLR', '-count=1'],
                           cwd=root, env={**base_env, 'GOARCH': 'amd64'}, stdout=stream,
                           stderr=subprocess.STDOUT, timeout=1200, check=True)
        receipt['patch'] = {**patch, 'offline_tests_passed': True}
        license_data = (root / 'LICENSE').read_bytes()
        if not license_data or len(license_data) > 1024 * 1024:
            raise ValueError('bounded upstream license required')
        for arch in ['amd64', 'arm64']:
            target = output / ('linux-' + arch)
            target.mkdir(exist_ok=True)
            binary = target / 'sing-box'
            command = ['go', 'build', '-mod=readonly', '-trimpath', '-buildvcs=false',
                       '-tags', ','.join(pin['tags']), '-ldflags',
                       '-X github.com/sagernet/sing-box/constant.Version=' + pin['version'] + ' -s -w -buildid=',
                       '-o', str(binary), './cmd/sing-box']
            log = output / ('build-' + arch + '.log')
            with log.open('wb') as stream:
                subprocess.run(command, cwd=root, env={**base_env, 'GOARCH': arch},
                               stdout=stream, stderr=subprocess.STDOUT, timeout=1200, check=True)
            info = validate_binary(pin, arch, binary)
            data = binary.read_bytes()
            payloads['linux/' + arch] = data
            receipt['targets']['linux/' + arch] = {'sha256': hashlib.sha256(data).hexdigest(),
                'size': len(data), 'go_version': info['go_version'], 'tags': info['settings']['-tags'].split(','),
                'cgo_enabled': False, 'linked_modules': info['linked_modules']}
            (target / 'LICENSE').write_bytes(license_data)
            name = 'sing-box-' + pin['version'] + '-linux-' + arch + '-static.tar.gz'
            archive = archive_bytes(pin['version'], arch, data, license_data)
            (output / name).write_bytes(archive)
            sums.append(hashlib.sha256(archive).hexdigest() + '  ' + name)
        if manifest_digests(root) != derived:
            raise ValueError('compiler changed the dependency manifests')
    # Executes the AMD64 binary: reported version and flr-capabilities must match the pin.
    validate_host_binary(pin, output / 'linux-amd64/sing-box')
    receipt['linked_modules'] = sorted({name for item in receipt['targets'].values() for name in item['linked_modules']})
    validate_receipt(pin, receipt, payloads)
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    (output / 'SHA256SUMS').write_text('\n'.join(sums) + '\n')
    print(json.dumps({'source_build': pin['upstream_commit'], 'version': pin['version'], 'targets': list(receipt['targets']),
                      'receipt': 'out/sing-box/receipt.json', 'native_config_validation': 'required before image'}))


if __name__ == '__main__':
    main()
