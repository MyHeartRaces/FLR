#!/usr/bin/env python3
"""Inspect a private sysupgrade backup without extracting or printing secrets.

Syntax/permissions/inventory preflight only. The Go runtime owns semantic
settings/profile/AWG validation. No device access, writes or restore operations.
"""
import argparse
import hashlib
import gzip
import json
from pathlib import Path, PurePosixPath
import stat
import tarfile

PREFIX = 'etc/flr-runtime/'
KEEP = Path(__file__).resolve().parents[1] / 'packages/flr-runtime/files/flr-runtime.keep'
MAX_FILE = 16 << 20
MAX_TOTAL = 64 << 20
MAX_MEMBERS = 4096


def durable_paths():
    return {line.lstrip('/') for line in KEEP.read_text().splitlines()
            if line and not line.startswith('#')}


def check_keep(root):
    """Check the installed payload, including exact source provenance."""
    path = Path(root) / 'lib/upgrade/keep.d/flr-runtime'
    if not path.is_file() or path.is_symlink() or path.read_bytes() != KEEP.read_bytes():
        raise ValueError('FLR preservation payload missing or differs from source')
    return True


def check_checkpoint_completeness(contents):
    """Require recovery inputs before restore; runtime still owns semantics."""
    def require(names):
        if any(PREFIX + name not in contents for name in names):
            raise ValueError('private checkpoint dependencies missing')

    settings = json.loads(contents.get(PREFIX + 'settings.json', b'{}'))
    if PREFIX + 'rollback.disabled' in contents and contents[PREFIX + 'rollback.disabled'] != b'disable-v1\n':
        raise ValueError('rollback disabled intent rejected')
    migration = PREFIX + 'migration-v2.json' in contents
    if settings.get('version') == 2 and not migration:
        require(['registry.json'])
    if PREFIX + 'connection-state.json' in contents:
        require(['registry.json', 'settings.json', '.connection-old-registry.json',
                 '.connection-old-settings.json', '.connection-new-registry.json',
                 '.connection-new-settings.json'])
    if migration:
        require(['.registry-v2.json', '.settings-v2.json', 'migration-v1/manifest.json'])
        manifest = json.loads(contents[PREFIX + 'migration-v1/manifest.json'])
        sources = manifest.get('sources')
        allowed = {'settings.json', 'profiles.json', 'primary-awg.conf', 'gecko.json', 'vless.json'}
        if not isinstance(sources, dict) or not set(sources).issubset(allowed):
            raise ValueError('migration snapshot inventory rejected')
        require(['migration-v1/' + name for name in sources])


class BoundedReader:
    def __init__(self, source):
        self.source, self.remaining = source, MAX_TOTAL

    def read(self, size=-1):
        size = self.remaining + 1 if size < 0 else min(size, self.remaining + 1)
        data = self.source.read(size)
        self.remaining -= len(data)
        if self.remaining < 0:
            raise ValueError('decompressed stream size bound exceeded')
        return data


def inspect(path, expected=None, require_state=False):
    path = Path(path)
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o600:
        raise ValueError('archive must be a regular private 0600 file')
    if st.st_size > MAX_TOTAL:
        raise ValueError('archive size bound exceeded')
    allowed = durable_paths()
    current = {'etc/config/' + name for name in ('network', 'firewall', 'dhcp')}
    protected_ancestors = {str(parent) for name in allowed | current
                           for parent in PurePosixPath(name).parents if str(parent) != '.'}
    seen, files, contents = {}, {}, {}
    total = 0
    with gzip.open(path, 'rb') as source, tarfile.open(fileobj=BoundedReader(source), mode='r|', ignore_zeros=True) as archive:
        for member in archive:
            name = member.name
            if (not name or name.startswith('/') or '\\' in name or
                    any(ord(c) < 32 for c in name) or
                    any(p in ('', '.', '..') for p in name.rstrip('/').split('/'))):
                raise ValueError('unsafe archive path')
            name = name.rstrip('/')
            if name in seen or len(seen) >= MAX_MEMBERS:
                raise ValueError('duplicate archive member or member bound exceeded')
            # All links/special entries rejected, even outside FLR. This avoids
            # ordering-dependent traversal when a later device restore extracts.
            if not (member.isfile() or member.isdir()):
                raise ValueError('archive links and special files are forbidden')
            seen[name] = member.isdir()
            if member.mode & 0o7000:
                raise ValueError('special permission bits forbidden')
            if member.isdir():
                if name in ('etc/flr-runtime', 'etc/flr-runtime/backup', 'etc/flr-runtime/migration-v1') and (member.mode != 0o700 or member.uid != 0 or member.gid != 0):
                    raise ValueError('FLR directory must be root-owned private 0700')
                if name in protected_ancestors and (member.uid != 0 or member.gid != 0 or member.mode & 0o022):
                    raise ValueError('state ancestor directory must be root-owned and not group/other-writable')
                continue
            if name.startswith(PREFIX) and name not in allowed:
                raise ValueError('unknown FLR state must be reviewed separately')
            if name.startswith(('var/', 'run/', 'tmp/')):
                raise ValueError('volatile state cannot be restored')
            total += member.size
            if member.size < 0 or member.size > MAX_FILE or total > MAX_TOTAL:
                raise ValueError('uncompressed archive size bound exceeded')
            if name.startswith(PREFIX) and (member.mode != 0o600 or member.size == 0 or member.uid != 0 or member.gid != 0):
                raise ValueError('FLR state must be nonempty root-owned private 0600')
            stream = archive.extractfile(member)
            data = stream.read(MAX_FILE + 1)
            if len(data) != member.size:
                raise ValueError('truncated archive member')
            files[name] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data), 'mode': oct(member.mode)}
            if name.startswith(PREFIX):
                contents[name] = data
                if name.endswith('.json'):
                    def unique_pairs(pairs):
                        result = {}
                        for key, value in pairs:
                            if key in result:
                                raise ValueError('duplicate JSON field')
                            result[key] = value
                        return result
                    value = json.loads(data, object_pairs_hook=unique_pairs,
                                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('non-finite JSON')))
                    if not isinstance(value, dict):
                        raise ValueError('FLR JSON object required')
    # Check the complete hierarchy so file-as-parent conflicts fail in either
    # archive order. Absent directory entries remain valid for file-only backups.
    for name in seen:
        if any(seen.get(str(parent)) is False for parent in PurePosixPath(name).parents):
            raise ValueError('regular archive member cannot be a parent')
    if require_state and PREFIX + 'settings.json' not in files:
        raise ValueError('expected configured FLR state is missing')
    check_checkpoint_completeness(contents)
    for name in ('network', 'firewall', 'dhcp'):
        if not files.get('etc/config/' + name, {}).get('bytes'):
            raise ValueError('current network/firewall/dhcp snapshot missing')
    restoration = {PREFIX + 'backup/' + n for n in ('network', 'firewall', 'dhcp')}
    pending = PREFIX + 'rollback.pending' in files
    disabled = PREFIX + 'rollback.disabled' in files
    if pending or disabled or PREFIX + 'boot-guard.nft' in files or restoration.intersection(files):
        if not restoration.issubset(files):
            raise ValueError('recovery evidence requires complete restoration snapshot')
    if expected is not None:
        # sha256sum inventory captured on the old device from the explicit
        # allowlist. Missing paths are legitimate only when absent there too.
        expected_names = set()
        for line in Path(expected).read_text().splitlines():
            digest, name = line.split(maxsplit=1)
            name = name.lstrip('*').lstrip('/')
            if name not in allowed or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
                raise ValueError('invalid expected FLR manifest')
            if name in expected_names:
                raise ValueError('duplicate expected FLR inventory entry')
            expected_names.add(name)
            if files.get(name, {}).get('sha256') != digest:
                raise ValueError('archive differs from fresh FLR inventory')
        if expected_names != set(contents):
            raise ValueError('FLR inventory is incomplete or stale')
    return {'state': 'present' if contents else 'absent', 'pending_recovery': pending,
            'rollback_disabled': disabled,
            'migration_sources': [n for n in ('gecko.json', 'vless.json') if PREFIX + n in files],
            'files': files, 'archive_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'semantic_runtime_validation_required': True, 'device_restore_tested': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--expected', type=Path, help='fresh old-device sha256sum inventory of existing allowlisted FLR files')
    parser.add_argument('--require-state', action='store_true')
    args = parser.parse_args()
    try:
        result = inspect(args.archive, args.expected, args.require_state)
    except (ValueError, OSError, tarfile.TarError, UnicodeError, RecursionError, EOFError):
        parser.exit(1, 'Backup preflight rejected: inspect paths, permissions, inventory and state privately.\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
