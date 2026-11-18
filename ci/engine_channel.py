#!/usr/bin/env python3
"""Build and validate the router-side engine channel manifest (stdlib only).

The engine channel publishes CI-built, FLR-patched engine binaries as GitHub
release assets together with `channel.json`, which an on-device updater reads.
This module never downloads, signs or uploads anything: the workflow does the
publishing; this only derives the manifest from verified build outputs and
re-validates it (also usable by the updater's tests).

    engine_channel.py build  --lock L --receipt R --native N --binary B --repo OWNER/REPO ...
    engine_channel.py verify --manifest channel.json [--binary sing-box=PATH]
    engine_channel.py same   --candidate channel.json [--current published.json]
    engine_channel.py api-url --manifest channel.json --engine sing-box --asset-id N
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
from urllib.parse import urlsplit

FORMAT = 'flr-engine-channel-v1'
CHANNEL = 'stable'
MIN_CONTROLLER = '0.7'
REQUIRED_ENGINES = ('sing-box',)
REQUIRED_CAPABILITIES = {'sing-box': {'hysteria2-random-sni-per-quic-dial-v1'}}
MIN_SIZE = 64
MAX_SIZE = 128 * 1024 * 1024
HEX64 = re.compile(r'[0-9a-f]{64}')
HEX40 = re.compile(r'[0-9a-f]{40}')
TIME = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z')
TAG = re.compile(r'engines-[0-9]{8}-[0-9]{1,10}')
REPO = re.compile(r'[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}')
VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]{1,64})?')
PACKAGE_VERSION = re.compile(r'[0-9]+(?:\.[0-9]+){1,5}')
CONTROLLER = re.compile(r'[0-9]+\.[0-9]+')
CAPABILITY = re.compile(r'[a-z0-9][a-z0-9._-]{0,127}')
ASSET = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,200}')
TOP_KEYS = {'format', 'channel', 'generated_at', 'published_at', 'source_commit', 'engines'}
ENGINE_KEYS = {'version', 'package_version', 'asset', 'url', 'sha256', 'size', 'capabilities',
               'min_controller', 'contract_sha256'}
# api_url (REST asset URL, for private repositories) is known only after upload.
OPTIONAL_ENGINE_KEYS = {'api_url'}
API_URL = re.compile(r'https://api\.github\.com/repos/([A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100})/releases/assets/([0-9]{1,20})')


def release_tag(date, run_number):
    """Immutable dated release tag, e.g. engines-20261118-42."""
    tag = 'engines-' + str(date) + '-' + str(run_number)
    if not TAG.fullmatch(tag) or not re.fullmatch(r'[0-9]{8}', str(date)):
        raise ValueError('release tag components rejected')
    return tag


def asset_name(engine, version):
    if engine != 'sing-box':
        raise ValueError('unapproved engine')
    name = 'sing-box-' + version + '-linux-arm64'
    if not VERSION.fullmatch(version) or not ASSET.fullmatch(name):
        raise ValueError('engine version cannot form an asset name')
    return name


def asset_url(repo, tag, asset):
    if not REPO.fullmatch(repo) or not TAG.fullmatch(tag) or not ASSET.fullmatch(asset):
        raise ValueError('asset URL components rejected')
    return 'https://github.com/' + repo + '/releases/download/' + tag + '/' + asset


def engine_entry(engine, *, version, package_version, binary, repo, tag, capabilities,
                 contract_sha256, min_controller=MIN_CONTROLLER):
    asset = asset_name(engine, version)
    return {'version': version, 'package_version': package_version, 'asset': asset,
            'url': asset_url(repo, tag, asset), 'sha256': hashlib.sha256(binary).hexdigest(),
            'size': len(binary), 'capabilities': sorted(capabilities),
            'min_controller': min_controller, 'contract_sha256': contract_sha256}


def build_manifest(engines, *, source_commit, generated_at, published_at):
    manifest = {'format': FORMAT, 'channel': CHANNEL, 'generated_at': generated_at,
                'published_at': published_at, 'source_commit': source_commit, 'engines': engines}
    validate_manifest(manifest)
    return manifest


def _time(value, name):
    if not isinstance(value, str) or not TIME.fullmatch(value):
        raise ValueError(name + ' must be UTC YYYY-MM-DDTHH:MM:SSZ')
    try:
        return datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')
    except ValueError as error:
        raise ValueError(name + ' is not a real timestamp') from error


def _text(value, pattern, name):
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(name + ' rejected')
    return value


def validate_manifest(manifest, binaries=None, repo=None):
    """Strictly validate a channel manifest.

    `binaries` optionally maps engine name -> bytes; each must match the recorded
    sha256 and size. `repo` optionally pins the OWNER/REPO the URLs must name.
    """
    if not isinstance(manifest, dict) or set(manifest) != TOP_KEYS:
        raise ValueError('channel manifest keys rejected')
    if manifest['format'] != FORMAT or manifest['channel'] != CHANNEL:
        raise ValueError('channel manifest format or channel rejected')
    generated = _time(manifest['generated_at'], 'generated_at')
    published = _time(manifest['published_at'], 'published_at')
    if published < generated:
        raise ValueError('published_at precedes generated_at')
    _text(manifest['source_commit'], HEX40, 'source_commit')
    engines = manifest['engines']
    if not isinstance(engines, dict):
        raise ValueError('engines object required')
    missing = [name for name in REQUIRED_ENGINES if name not in engines]
    if missing:
        raise ValueError('required engine missing: ' + ', '.join(missing))
    if set(engines) != set(REQUIRED_ENGINES):
        raise ValueError('unapproved engine in channel')
    tags = set()
    for name, entry in engines.items():
        if not isinstance(entry, dict) or not ENGINE_KEYS <= set(entry) or set(entry) - ENGINE_KEYS - OPTIONAL_ENGINE_KEYS:
            raise ValueError('engine entry keys rejected: ' + name)
        _text(entry['version'], VERSION, name + ' version')
        _text(entry['package_version'], PACKAGE_VERSION, name + ' package_version')
        _text(entry['sha256'], HEX64, name + ' sha256')
        _text(entry['contract_sha256'], HEX64, name + ' contract_sha256')
        _text(entry['min_controller'], CONTROLLER, name + ' min_controller')
        size = entry['size']
        if type(size) is not int or not MIN_SIZE <= size <= MAX_SIZE:
            raise ValueError(name + ' size outside bounds')
        capabilities = entry['capabilities']
        if (not isinstance(capabilities, list) or len(capabilities) > 32 or len(set(capabilities)) != len(capabilities)
                or any(not isinstance(c, str) or not CAPABILITY.fullmatch(c) for c in capabilities)):
            raise ValueError(name + ' capabilities rejected')
        if not REQUIRED_CAPABILITIES.get(name, set()).issubset(capabilities):
            raise ValueError(name + ' required capability missing')
        if entry['asset'] != asset_name(name, entry['version']):
            raise ValueError(name + ' asset name does not match version')
        url = entry['url']
        parts = urlsplit(url) if isinstance(url, str) else None
        segments = parts.path.split('/') if parts else []
        if (parts is None or parts.scheme != 'https' or parts.netloc != 'github.com' or parts.query or parts.fragment
                or parts.username or parts.password or len(segments) != 7
                or segments[0] != '' or segments[3:5] != ['releases', 'download']):
            raise ValueError(name + ' url must be an absolute github.com release asset URL')
        url_repo = segments[1] + '/' + segments[2]
        if not REPO.fullmatch(url_repo) or not TAG.fullmatch(segments[5]) or segments[6] != entry['asset']:
            raise ValueError(name + ' url does not name the dated release asset')
        if repo is not None and url_repo != repo:
            raise ValueError(name + ' url names a different repository')
        if 'api_url' in entry:
            api = API_URL.fullmatch(entry['api_url']) if isinstance(entry['api_url'], str) else None
            if not api or api.group(1) != url_repo or int(api.group(2)) == 0:
                raise ValueError(name + ' api_url must be the api.github.com asset URL of the same repository')
        tags.add(segments[5])
        if binaries is not None:
            data = binaries.get(name)
            if data is None:
                raise ValueError(name + ' binary not supplied for verification')
            if hashlib.sha256(data).hexdigest() != entry['sha256'] or len(data) != size:
                raise ValueError(name + ' binary sha256 or size mismatch')
    if len(tags) != 1:
        raise ValueError('engines must come from one dated release')
    return manifest


def with_api_url(manifest, engine, asset_id):
    """Return a copy whose engine entry also carries the REST asset URL."""
    if type(asset_id) is not int or asset_id <= 0:
        raise ValueError('asset id must be a positive integer')
    value = json.loads(json.dumps(manifest))
    entry = value['engines'][engine]
    segments = urlsplit(entry['url']).path.split('/')
    entry['api_url'] = 'https://api.github.com/repos/' + segments[1] + '/' + segments[2] + '/releases/assets/' + str(asset_id)
    validate_manifest(value)
    return value


def same_engines(current, candidate):
    """True when the published channel already offers exactly the candidate binaries.

    Only the engine set and sha256 values count, so timestamps and URLs never
    force a new release (and never reset the routers' soak period). Anything
    malformed in `current` means "not the same".
    """
    try:
        validate_manifest(current)
    except ValueError:
        return False
    validate_manifest(candidate)
    return {n: e['sha256'] for n, e in current['engines'].items()} == {n: e['sha256'] for n, e in candidate['engines'].items()}


def _read_json(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError) as error:
        raise ValueError('cannot read JSON: ' + str(path)) from error


def build(args):
    """Cross-check lock, receipt, native report and binary, then write the channel."""
    lock = _read_json(args.lock)['sing_box']
    receipt = _read_json(args.receipt)
    native = _read_json(args.native)
    binary_path = Path(args.binary)
    if binary_path.is_symlink() or not binary_path.is_file():
        raise ValueError('engine binary missing or unsafe')
    binary = binary_path.read_bytes()
    digest = hashlib.sha256(binary).hexdigest()
    source_commit = args.source_commit or os.environ.get('GITHUB_SHA', '')
    _text(source_commit, HEX40, 'source_commit')
    target = receipt.get('targets', {}).get('linux/arm64', {})
    if target.get('sha256') != digest or target.get('size') != len(binary):
        raise ValueError('binary differs from the verified build receipt')
    compat = native.get('engine', {}).get('compatibility', {})
    if compat.get('arm64_binary_sha256') != digest:
        raise ValueError('binary differs from the natively checked ARM64 payload')
    if native.get('source_commit') != source_commit:
        raise ValueError('native report belongs to a different source commit')
    if (native.get('version') != lock['version'] or native.get('package_version') != lock['package_version']
            or native.get('capabilities') != lock['capabilities']
            or receipt.get('custom_version') != lock['version'] or receipt.get('capabilities') != lock['capabilities']):
        raise ValueError('lock, receipt and native report disagree on version or capabilities')
    now = args.now or datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    date = args.date or _time(now, 'now').strftime('%Y%m%d')
    tag = release_tag(date, args.run_number)
    entry = engine_entry('sing-box', version=lock['version'], package_version=lock['package_version'],
                         binary=binary, repo=args.repo, tag=tag, capabilities=lock['capabilities'],
                         contract_sha256=native.get('contract_sha256', ''), min_controller=args.min_controller)
    manifest = build_manifest({'sing-box': entry}, source_commit=source_commit,
                              generated_at=now, published_at=now)
    validate_manifest(manifest, {'sing-box': binary}, repo=args.repo)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(binary_path, output / entry['asset'])
    (output / 'channel.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'tag': tag, 'asset': entry['asset'], 'manifest': str(output / 'channel.json')}))


def verify(args):
    manifest = _read_json(args.manifest)
    binaries = {}
    for item in args.binary or []:
        name, sep, path = item.partition('=')
        if not sep:
            raise ValueError('--binary expects ENGINE=PATH')
        binaries[name] = Path(path).read_bytes()
    validate_manifest(manifest, binaries or None, repo=args.repo)
    print(json.dumps({'valid': True, 'engines': sorted(manifest['engines'])}))


def same(args):
    candidate = _read_json(args.candidate)
    try:
        current = _read_json(args.current) if args.current else None
    except ValueError:
        current = None
    validate_manifest(candidate)
    print('true' if current is not None and same_engines(current, candidate) else 'false')


def api_url(args):
    manifest = with_api_url(_read_json(args.manifest), args.engine, int(args.asset_id))
    Path(args.manifest).write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'api_url': manifest['engines'][args.engine]['api_url']}))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    make = commands.add_parser('build')
    make.add_argument('--lock', default='build/versions.lock.json')
    make.add_argument('--receipt', default='out/sing-box/receipt.json')
    make.add_argument('--native', default='out/sing-box-native.json')
    make.add_argument('--binary', default='out/sing-box/linux-arm64/sing-box')
    make.add_argument('--repo', required=True)
    make.add_argument('--run-number', required=True)
    make.add_argument('--source-commit')
    make.add_argument('--min-controller', default=MIN_CONTROLLER)
    make.add_argument('--date', help='YYYYMMDD; default from --now/UTC clock')
    make.add_argument('--now', help='UTC YYYY-MM-DDTHH:MM:SSZ; default current time')
    make.add_argument('--output', default='out/engine-channel')
    check = commands.add_parser('verify')
    check.add_argument('--manifest', required=True)
    check.add_argument('--binary', action='append', help='ENGINE=PATH, repeatable')
    check.add_argument('--repo')
    compare = commands.add_parser('same')
    compare.add_argument('--candidate', required=True)
    compare.add_argument('--current', help='published channel.json; missing or unreadable means different')
    link = commands.add_parser('api-url')
    link.add_argument('--manifest', required=True)
    link.add_argument('--engine', required=True)
    link.add_argument('--asset-id', required=True)
    args = parser.parse_args(argv)
    {'build': build, 'verify': verify, 'same': same, 'api-url': api_url}[args.command](args)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError) as error:
        print('engine channel: ' + str(error), file=sys.stderr)
        sys.exit(1)
