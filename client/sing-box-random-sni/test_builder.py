"""Behavioral tests; never build, fetch dependencies, or run network protocols."""
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
import zipfile

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('flr_client_builder', HERE / 'build.py')
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


class BuilderTests(unittest.TestCase):
    def test_corrupt_archive_is_rejected_before_workspace_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'input.tar.gz').write_bytes(b'not the approved source')
            result = subprocess.run(['python3', str(HERE/'build.py'), '--archive', str(root/'input.tar.gz'), '--workdir', str(root/'workspace'), '--prepare-only'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('source archive SHA256 mismatch', result.stderr)
            self.assertFalse((root/'workspace').exists())


class SharedPatchLogicTests(unittest.TestCase):
    """build.py shares its patch logic with the CI firmware build (ci/sing_box_patch.py)."""

    def setUp(self):
        self.patcher = BUILD.sing_box_patch
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def synthetic(self, before=b'package a\nvar X = 1\n'):
        tree = self.root / 'tree'
        tree.mkdir()
        (tree / 'a.go').write_bytes(before)
        patch = {'manifest': {'edits': [{'file': 'a.go', 'before_sha256': BUILD.sha(before),
                                         'replacements': [{'before': 'X = 1', 'after': 'X = 2'}]}]},
                 'manifest_sha256': 'm' * 64, 'payloads': {'b.go': b'package a\n'},
                 'payload_sha256': {'b.go': BUILD.sha(b'package a\n')}}
        return tree, patch

    def test_apply_patch_edits_adds_payloads_and_chains_tree_digests(self):
        tree, patch = self.synthetic()
        original = self.patcher.tree_sha(tree)
        evidence = self.patcher.apply_patch(tree, patch)
        self.assertEqual(evidence['original_tree_sha256'], original)
        self.assertEqual(evidence['patched_tree_sha256'], self.patcher.tree_sha(tree))
        self.assertNotEqual(original, evidence['patched_tree_sha256'])
        self.assertIn('X = 2', (tree / 'a.go').read_text())
        self.assertTrue((tree / 'b.go').is_file())

    def test_changed_input_is_rejected(self):
        tree, patch = self.synthetic()
        (tree / 'a.go').write_text('package a\nvar X = 1 // changed\n')
        with self.assertRaisesRegex(ValueError, 'input digest'):
            self.patcher.apply_patch(tree, patch)

    def test_ambiguous_anchor_is_rejected(self):
        tree, patch = self.synthetic(b'package a\nvar X = 1\nvar Y = X = 1\n')
        with self.assertRaisesRegex(ValueError, 'not unique'):
            self.patcher.apply_patch(tree, patch)

    def test_payload_collision_is_rejected(self):
        tree, patch = self.synthetic()
        (tree / 'b.go').write_bytes(b'existing')
        with self.assertRaisesRegex(ValueError, 'collision'):
            self.patcher.apply_patch(tree, patch)

    def test_extract_source_rejects_traversal_before_writing(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w:gz') as archive:
            entry = tarfile.TarInfo('sing-box-' + BUILD.COMMIT + '/../escape')
            entry.size = 1
            archive.addfile(entry, io.BytesIO(b'x'))
        workspace = self.root / 'workspace'
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            self.patcher.extract_source(data.getvalue(), BUILD.COMMIT, workspace)
        self.assertFalse(workspace.exists())

    def test_repository_patch_manifest_and_payloads_verify(self):
        patch = self.patcher.load_patch(HERE, BUILD.COMMIT)
        self.assertEqual(patch['manifest_sha256'], BUILD.sha((HERE / 'patch.json').read_bytes()))
        with self.assertRaisesRegex(ValueError, 'revision'):
            self.patcher.load_patch(HERE, 'f' * 40)


def make_module(cache, path, version, filename='mod.go', content='package mod\n'):
    """Materialize one fake cached module and return its go.sum line."""
    prefix = path + '@' + version + '/'
    archive = cache/'cache/download'/path/'@v'/(version + '.zip')
    archive.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive, 'w') as source:
        source.writestr(prefix + filename, content)
    directory = cache/(path + '@' + version)
    directory.mkdir(parents=True)
    (directory/filename).write_text(content)
    listing = BUILD.sha(content.encode()) + '  ' + prefix + filename + '\n'
    digest = 'h1:' + base64.b64encode(hashlib.sha256(listing.encode()).digest()).decode()
    return f'{path} {version} {digest}'


def dep_json(path, version, directory):
    return json.dumps({'Module': {'Path': path, 'Version': version, 'Dir': str(directory)}})


class FakeListRun:
    """Emulates `go list -deps -json` for host vs a linux target."""
    def __init__(self, host_dep, target_deps):
        self.host_dep = host_dep
        self.target_deps = [host_dep] + list(target_deps)
        self.environments = []

    def __call__(self, go, root, env, args, timeout=1200):
        assert args[:2] == ['list', '-mod=readonly']
        self.environments.append({k: env.get(k) for k in ('GOOS', 'GOARCH')})
        deps = self.target_deps if env.get('GOOS') == 'linux' else [self.host_dep]
        return ''.join(deps)


class PerTargetModuleAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.cache = root/'modcache'
        self.work = root/'work'
        self.work.mkdir()
        self.host_line = make_module(self.cache, 'example.com/hostdep', 'v1.0.0')
        self.host_dir = self.cache/'example.com/hostdep@v1.0.0'
        self.target_line = make_module(self.cache, 'example.com/targetdep', 'v1.0.0')
        self.target_dir = self.cache/'example.com/targetdep@v1.0.0'
        (self.work/'go.sum').write_text(self.host_line + '\n' + self.target_line + '\n')
        self.original_run = BUILD.run
        self.addCleanup(setattr, BUILD, 'run', self.original_run)

    def install_run(self, fake):
        BUILD.run = fake

    def test_host_audit_alone_cannot_see_target_only_dependency(self):
        (self.cache/'cache/download/example.com/targetdep/@v/v1.0.0.zip').unlink()
        fake = FakeListRun(dep_json('example.com/hostdep', 'v1.0.0', self.host_dir),
                           [dep_json('example.com/targetdep', 'v1.0.0', self.target_dir)])
        self.install_run(fake)
        host_evidence = BUILD.module_evidence('fake-go', self.work, {}, self.cache)
        self.assertEqual([m['path'] for m in host_evidence], ['example.com/hostdep'])
        with self.assertRaisesRegex(ValueError, 'targetdep'):
            BUILD.verify_modules('fake-go', self.work, {}, self.cache, ['linux/arm64'])
        self.assertIn({'GOOS': None, 'GOARCH': None}, fake.environments)
        self.assertIn({'GOOS': 'linux', 'GOARCH': 'arm64'}, fake.environments)

    def test_per_target_evidence_binding_and_union(self):
        fake = FakeListRun(dep_json('example.com/hostdep', 'v1.0.0', self.host_dir),
                           [dep_json('example.com/targetdep', 'v1.0.0', self.target_dir)])
        self.install_run(fake)
        result = BUILD.verify_modules('fake-go', self.work, {}, self.cache, ['linux/arm64'])
        self.assertEqual([m['path'] for m in result['by_target']['host']], ['example.com/hostdep'])
        self.assertEqual([m['path'] for m in result['by_target']['linux/arm64']],
                         ['example.com/hostdep', 'example.com/targetdep'])
        union = {(m['path'], tuple(m['targets'])) for m in result['union']}
        self.assertEqual(union, {
            ('example.com/hostdep', ('host', 'linux/arm64')),
            ('example.com/targetdep', ('linux/arm64',)),
        })


if __name__ == '__main__':
    unittest.main()
