"""Synthetic preservation/preflight coverage; no router or private backup access."""
import importlib.util
import io
import hashlib
import gzip
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
KEEP = ROOT / 'packages/flr-runtime/files/flr-runtime.keep'
EXPECTED = {
    'settings.json', 'profiles.json', 'primary-awg.conf', 'gecko.json',
    'vless.json', 'backup/network', 'backup/firewall', 'backup/dhcp',
    'boot-guard.nft', 'rollback.pending', 'rollback.disabled',
    'registry.json', 'connection-state.json',
    '.connection-old-registry.json', '.connection-old-settings.json',
    '.connection-new-registry.json', '.connection-new-settings.json',
    'migration-v2.json', '.registry-v2.json', '.settings-v2.json',
    'engine-update.json', 'engines.lock.json',
    'policy/policy.json', 'policy/rulesets/local-domains.json',
    'policy/rulesets/local-ips.json', 'policy/rulesets/vpn-required.json',
    'policy/rulesets/direct-essential.json', 'policy/rulesets/game-platforms.json',
    'policy/rulesets/vpn-services.json', 'policy/rulesets/roscom-direct-domains.json',
    'policy/rulesets/roscom-direct-ips.json',
    'custom-rules.json',
    'policy.backup/policy.json', 'policy.backup/rulesets/local-domains.json',
    'policy.backup/rulesets/local-ips.json', 'policy.backup/rulesets/vpn-required.json',
    'policy.backup/rulesets/direct-essential.json', 'policy.backup/rulesets/game-platforms.json',
    'policy.backup/rulesets/vpn-services.json', 'policy.backup/rulesets/roscom-direct-domains.json',
    'policy.backup/rulesets/roscom-direct-ips.json',
    'migration-v1/manifest.json', 'migration-v1/settings.json',
    'migration-v1/profiles.json', 'migration-v1/primary-awg.conf',
    'migration-v1/gecko.json', 'migration-v1/vless.json',
}

class Preservation(unittest.TestCase):
    def test_future_backup_manifest_preserves_only_durable_state(self):
        # Apply the shipped list to a synthetic directory, as sysupgrade's
        # find over keep.d does; unknown credentials and run state must stay out.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in EXPECTED | {'unknown-secret', 'manual-games.json', 'direct-session.json'}:
                path = root / 'etc/flr-runtime' / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('synthetic')
            lines = KEEP.read_text().splitlines() if KEEP.exists() else []
            kept = set()
            for line in lines:
                if line.strip() and not line.startswith('#'):
                    path = root / line.lstrip('/')
                    if path.is_dir():
                        kept.update(str(p.relative_to(root / 'etc/flr-runtime')) for p in path.rglob('*') if p.is_file())
                    elif path.is_file():
                        kept.add(str(path.relative_to(root / 'etc/flr-runtime')))
            self.assertEqual(kept, EXPECTED)

class ArchivePreflight(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.root.chmod(0o700)
        self.archive = self.root / 'backup.tgz'
        self.entries = {
            'etc/config/network': b'network synthetic',
            'etc/config/firewall': b'firewall synthetic',
            'etc/config/dhcp': b'dhcp synthetic',
            'etc/flr-runtime/settings.json': b'{"options":{},"dns_port":"1054"}',
            'etc/flr-runtime/gecko.json': b'{"outbounds":[]}',
            'etc/flr-runtime/primary-awg.conf': b'synthetic-private-key',
            'etc/flr-runtime/backup/network': b'original-network',
            'etc/flr-runtime/backup/firewall': b'original-firewall',
            'etc/flr-runtime/backup/dhcp': b'original-dhcp',
            'etc/flr-runtime/boot-guard.nft': b'# tracegate-flr-v1\n',
            'etc/flr-runtime/rollback.pending': b'old-boot-id\n',
        }

    def write_archive(self, extra=None, extra_first=False):
        extras = [] if extra is None else [extra] if isinstance(extra, tarfile.TarInfo) else extra
        with tarfile.open(self.archive, 'w:gz', format=tarfile.USTAR_FORMAT) as tar:
            if extra_first:
                for member in extras:
                    tar.addfile(member, io.BytesIO(b'{}' if member.size == 2 else b'x' * member.size))
            for name, data in self.entries.items():
                member = tarfile.TarInfo(name)
                member.mode = 0o600
                member.size = len(data)
                tar.addfile(member, io.BytesIO(data))
            if not extra_first:
                for member in extras:
                    tar.addfile(member, io.BytesIO(b'{}' if member.size == 2 else b'x' * member.size))
        self.archive.chmod(0o600)

    def run_preflight(self, *args):
        return subprocess.run([sys.executable, str(ROOT / 'ci/upgrade_archive.py'), str(self.archive), *args], capture_output=True, text=True)

    def test_old_archive_preflight_inventory_and_no_extraction(self):
        self.write_archive()
        result = self.run_preflight()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report['pending_recovery'])
        self.assertEqual(report['migration_sources'], ['gecko.json'])
        self.assertFalse(report['device_restore_tested'])
        self.assertNotIn('synthetic-private-key', result.stdout)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ['backup.tgz'])

    def test_rollback_disabled_intent_is_preserved_and_checked(self):
        name = 'etc/flr-runtime/rollback.disabled'
        self.entries[name] = b'disable-v1\n'
        self.write_archive()
        result = self.run_preflight()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['rollback_disabled'])
        self.entries[name] = b'invalid-public-marker\n'
        self.write_archive()
        self.assertNotEqual(self.run_preflight().returncode, 0)

    def test_v2_registry_in_fresh_backup_is_accepted_and_inventory_checked(self):
        self.entries['etc/flr-runtime/settings.json'] = b'{"version":2}'
        self.entries['etc/flr-runtime/registry.json'] = b'{"version":2,"connections":[]}'
        manifest = self.root / 'manifest'
        manifest.write_text(''.join(hashlib.sha256(data).hexdigest() + '  /' + name + '\n'
                                   for name, data in self.entries.items()
                                   if name.startswith('etc/flr-runtime/')))
        self.write_archive()
        result = self.run_preflight('--expected', str(manifest), '--require-state')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('etc/flr-runtime/registry.json', json.loads(result.stdout)['files'])
        del self.entries['etc/flr-runtime/registry.json']
        self.write_archive()
        self.assertNotEqual(self.run_preflight('--expected', str(manifest)).returncode, 0)

    def test_v2_settings_without_registry_rejected_without_inventory(self):
        self.entries['etc/flr-runtime/settings.json'] = b'{"version":2}'
        self.write_archive()
        self.assertNotEqual(self.run_preflight('--require-state').returncode, 0)

    def test_complete_connection_checkpoint_preserved_and_partial_rejected(self):
        names = ['connection-state.json', '.connection-old-registry.json',
                 '.connection-old-settings.json', '.connection-new-registry.json',
                 '.connection-new-settings.json', 'registry.json']
        for name in names:
            self.entries['etc/flr-runtime/' + name] = b'{}'
        self.write_archive()
        result = self.run_preflight('--require-state')
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in names[1:]:
            with self.subTest(missing=name):
                raw = self.entries.pop('etc/flr-runtime/' + name)
                self.write_archive()
                self.assertNotEqual(self.run_preflight().returncode, 0)
                self.entries['etc/flr-runtime/' + name] = raw

    def test_complete_migration_checkpoint_and_snapshot_preserved(self):
        staged = ['migration-v2.json', '.registry-v2.json', '.settings-v2.json']
        for name in staged:
            self.entries['etc/flr-runtime/' + name] = b'{}'
        self.entries['etc/flr-runtime/migration-v1/manifest.json'] = b'{"version":1,"sources":{"gecko.json":"synthetic"}}'
        self.entries['etc/flr-runtime/migration-v1/gecko.json'] = b'{"outbounds":[]}'
        self.write_archive()
        result = self.run_preflight()
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in staged[1:] + ['migration-v1/manifest.json', 'migration-v1/gecko.json']:
            with self.subTest(missing=name):
                raw = self.entries.pop('etc/flr-runtime/' + name)
                self.write_archive()
                self.assertNotEqual(self.run_preflight().returncode, 0)
                self.entries['etc/flr-runtime/' + name] = raw

    def test_missing_backup_with_pending_rejected(self):
        del self.entries['etc/flr-runtime/backup/dhcp']
        self.write_archive()
        self.assertNotEqual(self.run_preflight().returncode, 0)

    def test_regular_member_cannot_be_parent_in_either_order(self):
        manifest = self.root / 'manifest'
        manifest.write_text(''.join(hashlib.sha256(data).hexdigest() + '  /' + name + '\n'
                                   for name, data in self.entries.items()
                                   if name.startswith('etc/flr-runtime/')))
        self.entries['usr/share/synthetic/child'] = b'ordinary backup file'
        for name in ('etc', 'etc/config', 'etc/flr-runtime',
                     'etc/flr-runtime/backup', 'usr/share/synthetic'):
            for extra_first in (True, False):
                with self.subTest(parent=name, parent_first=extra_first):
                    member = tarfile.TarInfo(name)
                    member.mode, member.size = 0o600, 2
                    self.write_archive(member, extra_first=extra_first)
                    result = self.run_preflight('--expected', str(manifest), '--require-state')
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, '')

    def test_explicit_system_ancestors_require_safe_root_metadata(self):
        for name in ('etc', 'etc/config'):
            for uid, gid, mode in ((1000, 0, 0o755), (0, 1000, 0o755),
                                   (1000, 1000, 0o777), (0, 0, 0o777),
                                   (0, 0, 0o775), (0, 0, 0o757)):
                with self.subTest(parent=name, uid=uid, gid=gid, mode=oct(mode)):
                    member = tarfile.TarInfo(name)
                    member.type, member.mode = tarfile.DIRTYPE, mode
                    member.uid, member.gid = uid, gid
                    self.write_archive(member)
                    result = self.run_preflight()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, '')

    def test_safe_explicit_ancestors_and_private_directories_accepted(self):
        for mode in (0o755, 0o750, 0o700):
            for extra_first in (True, False):
                with self.subTest(system_mode=oct(mode), directories_first=extra_first):
                    directories = []
                    for name in ('etc', 'etc/config', 'etc/flr-runtime', 'etc/flr-runtime/backup'):
                        member = tarfile.TarInfo(name)
                        member.type = tarfile.DIRTYPE
                        member.mode = 0o700 if name.startswith('etc/flr-runtime') else mode
                        directories.append(member)
                    # Prefix similarity is not an ancestor relationship.
                    self.entries['etc/config-old'] = b'ordinary backup file'
                    self.write_archive(directories, extra_first=extra_first)
                    result = self.run_preflight('--require-state')
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(sorted(p.name for p in self.root.iterdir()), ['backup.tgz'])

    def test_unknown_flr_private_state_rejected(self):
        self.entries['etc/flr-runtime/unknown-secret'] = b'private'
        self.write_archive()
        self.assertNotEqual(self.run_preflight().returncode, 0)

    def test_unsafe_members_rejected(self):
        for kind in ['traversal', 'absolute', 'symlink', 'hardlink', 'duplicate', 'public', 'fifo', 'oversized', 'nonroot', 'directory-nonroot', 'duplicate-json']:
            with self.subTest(kind=kind):
                member = tarfile.TarInfo('etc/flr-runtime/profiles.json')
                member.mode = 0o600
                member.size = 2
                if kind == 'traversal': member.name = '../escape'
                if kind == 'absolute': member.name = '/etc/escape'
                if kind == 'symlink': member.type, member.linkname, member.size = tarfile.SYMTYPE, '/etc/shadow', 0
                if kind == 'hardlink': member.type, member.linkname, member.size = tarfile.LNKTYPE, 'etc/shadow', 0
                if kind == 'duplicate': member.name = 'etc/flr-runtime/settings.json'
                if kind == 'public': member.mode = 0o644
                if kind == 'fifo': member.type, member.size = tarfile.FIFOTYPE, 0
                if kind == 'oversized': member.size = 17 << 20
                if kind == 'nonroot': member.uid = 1000
                if kind == 'directory-nonroot':
                    member.name, member.type, member.size = 'etc/flr-runtime/backup', tarfile.DIRTYPE, 0
                    member.mode, member.uid = 0o700, 1000
                if kind == 'duplicate-json':
                    self.entries['etc/flr-runtime/settings.json'] = b'{"enabled":true,"enabled":false}'
                self.write_archive(member)
                self.assertNotEqual(self.run_preflight().returncode, 0)

    def test_fresh_manifest_detects_omission_stale_or_changed_state(self):
        self.write_archive()
        manifest = self.root / 'manifest'
        expected = ''.join(hashlib.sha256(v).hexdigest() + '  /' + k + '\n'
                           for k, v in self.entries.items() if k.startswith('etc/flr-runtime/'))
        manifest.write_text(expected)
        result = self.run_preflight('--expected', str(manifest), '--require-state')
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest.write_text(expected.split('\n', 1)[1])
        self.assertNotEqual(self.run_preflight('--expected', str(manifest)).returncode, 0)
        manifest.write_text(expected)
        self.entries['etc/flr-runtime/gecko.json'] = b'{"changed":true}'
        self.write_archive()
        self.assertNotEqual(self.run_preflight('--expected', str(manifest)).returncode, 0)

    def test_concatenated_archive_cannot_hide_unsafe_member(self):
        self.write_archive()
        hidden = io.BytesIO()
        with tarfile.open(fileobj=hidden, mode='w') as tar:
            member = tarfile.TarInfo('../hidden')
            member.size = 1
            tar.addfile(member, io.BytesIO(b'x'))
        with self.archive.open('ab') as archive:
            archive.write(gzip.compress(hidden.getvalue()))
        self.assertNotEqual(self.run_preflight().returncode, 0)

    def test_image_preservation_payload_checked_against_source(self):
        spec = importlib.util.spec_from_file_location('upgrade_archive', ROOT / 'ci/upgrade_archive.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with self.assertRaises(ValueError):
            module.check_keep(self.root)
        installed = self.root / 'lib/upgrade/keep.d/flr-runtime'
        installed.parent.mkdir(parents=True)
        installed.write_bytes(KEEP.read_bytes())
        self.assertTrue(module.check_keep(self.root))
        installed.write_bytes(KEEP.read_bytes() + b'/etc/flr-runtime/unknown-secret\n')
        with self.assertRaises(ValueError):
            module.check_keep(self.root)

    def test_archive_itself_must_be_private(self):
        self.write_archive()
        self.archive.chmod(0o644)
        self.assertNotEqual(self.run_preflight().returncode, 0)

    def test_clean_archive_and_malformed_json(self):
        self.entries = {k: v for k, v in self.entries.items() if not k.startswith('etc/flr-runtime/')}
        self.write_archive()
        result = self.run_preflight()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['state'], 'absent')
        self.entries['etc/flr-runtime/settings.json'] = b'not-json'
        self.write_archive()
        self.assertNotEqual(self.run_preflight().returncode, 0)

if __name__ == '__main__':
    unittest.main()
