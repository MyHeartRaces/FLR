#!/usr/bin/env python3
"""Resolve exact OpenWrt release pins for build/versions.lock.json.

CI only (needs network and Docker). Nothing here is used by the image build:
the output is a reviewed lock change that a human commits.

Method, in order of trust:
  1. Official release files on downloads.openwrt.org: sha256sums (SDK and
     ImageBuilder archives), feeds.buildinfo (feed commits),
     version.buildinfo (source revision) and the target .manifest (kernel
     version, ABI hash and release).
  2. The official SDK/ImageBuilder containers on ghcr.io, pinned by digest.
     The SDK's feeds.conf.default must agree with feeds.buildinfo.
  3. SOURCE_DATE_EPOCH: the SDK's version.date when present, otherwise the
     commit date of the release revision in openwrt/openwrt.

Self-check: before emitting pins for a new release, the same method is run
for the release already in the lock. Values derived from official files must
reproduce the lock exactly or nothing is emitted. A moved container tag is
reported, not fatal: a digest pin stays immutable either way.
"""
import argparse
import datetime
import json
import pathlib
import re
import subprocess
import sys
import urllib.request

TARGET = 'mediatek/filogic'
BASE = 'https://downloads.openwrt.org/releases/{version}/targets/' + TARGET + '/'
CONTAINER_TAGS = ['mediatek-filogic-v{version}', 'mediatek-filogic-{version}']
VERSION_RE = re.compile(r'^\d{2}\.\d{2}\.\d{1,2}$')
SHA256_RE = re.compile(r'^[0-9a-f]{64}$')
COMMIT_RE = re.compile(r'^[0-9a-f]{40}$')
MAX_TEXT = 4 * 1024 * 1024


def parse_sha256sums(text):
    sums = {}
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) != 2:
            continue
        digest, name = parts
        name = name.lstrip('*')
        if SHA256_RE.fullmatch(digest) and '/' not in name:
            sums[name] = digest
    if not sums:
        raise ValueError('sha256sums has no entries')
    return sums


def find_archive(sums, kind, version):
    if kind == 'sdk':
        pattern = re.compile(r'^openwrt-sdk-' + re.escape(version) + r'-mediatek-filogic_gcc-[0-9.]+_musl\.Linux-x86_64\.tar\.(zst|xz)$')
    elif kind == 'imagebuilder':
        pattern = re.compile(r'^openwrt-imagebuilder-' + re.escape(version) + r'-mediatek-filogic\.Linux-x86_64\.tar\.(zst|xz)$')
    else:
        raise ValueError('unknown archive kind')
    found = sorted(name for name in sums if pattern.fullmatch(name))
    if len(found) != 1:
        raise ValueError(kind + ' archive not found exactly once in sha256sums')
    return found[0], sums[found[0]]


def parse_feeds(text):
    feeds = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 3 or parts[0] not in ('src-git', 'src-git-full'):
            continue
        name, location = parts[1], parts[2]
        if '^' not in location:
            continue
        commit = location.rsplit('^', 1)[1]
        if not COMMIT_RE.fullmatch(commit):
            raise ValueError('feed ' + name + ' is not pinned to a full commit')
        if name in feeds and feeds[name] != commit:
            raise ValueError('feed ' + name + ' pinned twice')
        feeds[name] = commit
    for required in ('packages', 'luci'):
        if required not in feeds:
            raise ValueError('feed ' + required + ' missing')
    return feeds


def parse_manifest_kernel(text):
    matches = []
    for line in text.splitlines():
        match = re.fullmatch(r'kernel - (\d+\.\d+\.\d+)~([0-9a-f]{32})-r(\d+)', line.strip())
        if match:
            matches.append(match.groups())
    if len(matches) != 1:
        raise ValueError('manifest must name the kernel exactly once')
    kernel, abi, release = matches[0]
    return {'kernel': kernel, 'kernel_abi': abi, 'kernel_release': int(release)}


def parse_revision(text):
    match = re.fullmatch(r'r(\d+)-([0-9a-f]{10,40})', text.strip())
    if not match:
        raise ValueError('version.buildinfo is not a release revision')
    return {'revision': text.strip(), 'commit_prefix': match.group(2)}


def epoch_from_version_date(text):
    value = text.strip()
    if not value.isdigit():
        raise ValueError('version.date is not an epoch')
    epoch = int(value)
    if not 1704067200 <= epoch <= 2208988800:
        raise ValueError('version.date out of range')
    return epoch


def epoch_from_commit(payload):
    date = payload['commit']['committer']['date']
    return int(datetime.datetime.fromisoformat(date.replace('Z', '+00:00')).timestamp())


def official_pins(version, fetch):
    if not VERSION_RE.fullmatch(version):
        raise ValueError('OpenWrt version must look like 25.12.6')
    base = BASE.format(version=version)
    sums = parse_sha256sums(fetch(base + 'sha256sums'))
    sdk_name, sdk_sha = find_archive(sums, 'sdk', version)
    ib_name, ib_sha = find_archive(sums, 'imagebuilder', version)
    manifest = 'openwrt-' + version + '-mediatek-filogic.manifest'
    pins = {
        'version': version,
        'sdk_archive': sdk_name,
        'sdk_archive_sha256': sdk_sha,
        'imagebuilder_archive': ib_name,
        'imagebuilder_archive_sha256': ib_sha,
        'feeds': parse_feeds(fetch(base + 'feeds.buildinfo')),
    }
    pins.update(parse_manifest_kernel(fetch(base + manifest)))
    pins.update(parse_revision(fetch(base + 'version.buildinfo')))
    return pins


def lock_section(previous, pins, containers, epoch):
    section = dict(previous)
    section.update({
        'version': pins['version'],
        'kernel': pins['kernel'],
        'kernel_abi': pins['kernel_abi'],
        'source_date_epoch': epoch,
        'sdk_archive_sha256': pins['sdk_archive_sha256'],
        'imagebuilder_archive_sha256': pins['imagebuilder_archive_sha256'],
        'sdk_container': containers['sdk'],
        'imagebuilder_container': containers['imagebuilder'],
        'feeds': {'packages': pins['feeds']['packages'], 'luci': pins['feeds']['luci']},
    })
    if pins['kernel_release'] != 1:
        section['kernel_release'] = pins['kernel_release']
    else:
        section.pop('kernel_release', None)
    return section


def compare_official(lock, pins):
    """Lock fields that differ from values derived from official files.

    SOURCE_DATE_EPOCH is compared separately: it only affects embedded
    timestamps, so a different derivation is reported, not fatal."""
    expected = {
        'kernel': pins['kernel'],
        'kernel_abi': pins['kernel_abi'],
        'sdk_archive_sha256': pins['sdk_archive_sha256'],
        'imagebuilder_archive_sha256': pins['imagebuilder_archive_sha256'],
        'feeds': {'packages': pins['feeds']['packages'], 'luci': pins['feeds']['luci']},
    }
    if lock.get('kernel_release', 1) != pins['kernel_release']:
        expected['kernel_release'] = pins['kernel_release']
    return sorted(key for key, value in expected.items() if lock.get(key, 1 if key == 'kernel_release' else None) != value)


def http_text(url, token=None):
    request = urllib.request.Request(url, headers={'User-Agent': 'flr-openwrt-pins'})
    if token:
        request.add_header('Authorization', 'Bearer ' + token)
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read(MAX_TEXT + 1)
    if len(data) > MAX_TEXT:
        raise ValueError('response too large: ' + url)
    return data.decode('utf-8')


def docker(*args, timeout=1800):
    result = subprocess.run(['docker', *args], capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError('docker ' + args[0] + ' failed: ' + result.stderr.strip()[-400:])
    return result.stdout


def container_digest(kind, version):
    for template in CONTAINER_TAGS:
        reference = 'ghcr.io/openwrt/' + kind + ':' + template.format(version=version)
        try:
            docker('pull', '--platform', 'linux/amd64', reference)
        except RuntimeError:
            continue
        digests = json.loads(docker('image', 'inspect', '--format', '{{json .RepoDigests}}', reference))
        pinned = [d for d in digests if d.startswith('ghcr.io/openwrt/' + kind + '@sha256:')]
        if len(pinned) == 1:
            return reference, pinned[0]
    raise RuntimeError('no official ' + kind + ' container found for ' + version)


def sdk_facts(digest):
    script = 'cat /builder/feeds.conf.default; echo ===; cat /builder/version.date 2>/dev/null || true'
    out = docker('run', '--rm', '--platform', 'linux/amd64', '--entrypoint', '/bin/sh', digest, '-c', script, timeout=600)
    feeds_text, _, date_text = out.partition('===')
    return parse_feeds(feeds_text), date_text.strip()


def resolve(version, token, containers_required=True):
    """Pins for one release. With containers_required=False (the self-check of
    the release already in the lock) a vanished container tag is reported as
    None instead of aborting: containers are only compared there."""
    pins = official_pins(version, lambda url: http_text(url))
    containers, tags = {}, {}
    try:
        for kind in ('sdk', 'imagebuilder'):
            tags[kind], containers[kind] = container_digest(kind, version)
    except RuntimeError:
        if containers_required:
            raise
        containers, tags = {'sdk': None, 'imagebuilder': None}, {'sdk': None, 'imagebuilder': None}
    version_date = ''
    if containers['sdk']:
        sdk_feeds, version_date = sdk_facts(containers['sdk'])
        for name in ('packages', 'luci'):
            if sdk_feeds.get(name) != pins['feeds'][name]:
                raise ValueError('SDK feeds.conf.default disagrees with feeds.buildinfo for ' + name)
    if version_date:
        epoch, epoch_source = epoch_from_version_date(version_date), 'sdk-version.date'
    else:
        api = 'https://api.github.com/repos/openwrt/openwrt/commits/' + pins['commit_prefix']
        epoch, epoch_source = epoch_from_commit(json.loads(http_text(api, token))), 'release-commit-date'
    return pins, containers, tags, epoch, epoch_source


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--version', required=True)
    parser.add_argument('--lock', default='build/versions.lock.json')
    parser.add_argument('--out', default='out/openwrt-pins')
    parser.add_argument('--token-env', default='GITHUB_TOKEN')
    args = parser.parse_args(argv)
    import os
    token = os.environ.get(args.token_env) or None
    lock = json.loads(pathlib.Path(args.lock).read_text())
    current = lock['openwrt']
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    report = {'format': 'flr-openwrt-pins-v1', 'current': current['version'], 'requested': args.version}

    pins, containers, tags, epoch, epoch_source = resolve(current['version'], token, containers_required=False)
    report['self_check'] = {
        'epoch_source': epoch_source,
        'official_mismatches': compare_official(current, pins),
        'epoch_reproduced': epoch == current.get('source_date_epoch'),
        # None: the tag is gone (reported only); True: the tag now points elsewhere.
        'sdk_container_moved': None if containers['sdk'] is None else containers['sdk'] != current['sdk_container'],
        'imagebuilder_container_moved': None if containers['imagebuilder'] is None else containers['imagebuilder'] != current['imagebuilder_container'],
    }
    if report['self_check']['official_mismatches']:
        (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print('self-check failed: method does not reproduce ' + ', '.join(report['self_check']['official_mismatches']), file=sys.stderr)
        return 2

    pins, containers, tags, epoch, epoch_source = resolve(args.version, token)
    section = lock_section(current, pins, containers, epoch)
    report.update({'pins': pins, 'container_tags': tags, 'epoch_source': epoch_source, 'openwrt': section})
    updated = dict(lock)
    updated['openwrt'] = section
    updated['locked_at'] = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    (out / ('openwrt-' + args.version + '.json')).write_text(json.dumps(section, indent=2) + '\n')
    (out / 'versions.lock.json').write_text(json.dumps(updated, indent=2) + '\n')
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(section, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
