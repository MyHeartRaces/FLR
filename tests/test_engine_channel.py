import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT / 'ci/engine_channel.py'
spec = importlib.util.spec_from_file_location('engine_channel', SCRIPT)
channel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(channel)

VERSION = '1.14.4-flr-random-sni.1'
CAPS = ['hysteria2-random-sni-per-quic-dial-v1']
COMMIT = 'a' * 40
CONTRACT = 'c' * 64
REPO = 'owner/tracegate-flr'
NOW = '2026-11-18T03:00:00Z'
BINARY = b'ARM64-SING-BOX-FIXTURE' * 8


def manifest(binary=BINARY, tag='engines-20261118-7'):
    entry = channel.engine_entry('sing-box', version=VERSION, package_version='1.14.4.1', binary=binary,
                                 repo=REPO, tag=tag, capabilities=CAPS, contract_sha256=CONTRACT)
    return channel.build_manifest({'sing-box': entry}, source_commit=COMMIT, generated_at=NOW, published_at=NOW)


class ManifestShape(unittest.TestCase):
    def test_built_manifest_has_the_documented_shape(self):
        value = manifest()
        self.assertEqual(set(value), {'format', 'channel', 'generated_at', 'published_at', 'source_commit', 'engines'})
        self.assertEqual((value['format'], value['channel']), ('flr-engine-channel-v1', 'stable'))
        entry = value['engines']['sing-box']
        self.assertEqual(entry['version'], VERSION)
        self.assertEqual(entry['package_version'], '1.14.4.1')
        self.assertEqual(entry['asset'], 'sing-box-' + VERSION + '-linux-arm64')
        self.assertEqual(entry['url'], 'https://github.com/' + REPO + '/releases/download/engines-20261118-7/' + entry['asset'])
        self.assertEqual(entry['sha256'], hashlib.sha256(BINARY).hexdigest())
        self.assertEqual(entry['size'], len(BINARY))
        self.assertEqual((entry['capabilities'], entry['min_controller'], entry['contract_sha256']), (CAPS, '0.7', CONTRACT))
        channel.validate_manifest(value, {'sing-box': BINARY}, repo=REPO)

    def test_release_tag_format(self):
        self.assertEqual(channel.release_tag('20261118', 42), 'engines-20261118-42')
        for date, run in [('2026-11-18', 1), ('20261118', 'x'), ('20261118', ''), ('20261118', '1' * 11)]:
            with self.subTest(date=date, run=run), self.assertRaises(ValueError):
                channel.release_tag(date, run)


class ManifestRejections(unittest.TestCase):
    def mutated(self, mutate):
        value = manifest()
        mutate(value)
        return value

    def test_bad_sha256(self):
        for bad in ['', 'zz', 'A' * 64, '0' * 63, 5]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                channel.validate_manifest(self.mutated(lambda m: m['engines']['sing-box'].update(sha256=bad)))
        for key in ['contract_sha256']:
            with self.assertRaises(ValueError):
                channel.validate_manifest(self.mutated(lambda m: m['engines']['sing-box'].update({key: 'x'})))

    def test_sha_or_size_mismatch_against_the_binary(self):
        value = manifest()
        with self.assertRaisesRegex(ValueError, 'mismatch'):
            channel.validate_manifest(value, {'sing-box': BINARY + b'x'})
        value['engines']['sing-box']['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'mismatch'):
            channel.validate_manifest(value, {'sing-box': BINARY})
        with self.assertRaisesRegex(ValueError, 'not supplied'):
            channel.validate_manifest(manifest(), {})

    def test_missing_or_unapproved_engine(self):
        with self.assertRaisesRegex(ValueError, 'missing'):
            channel.validate_manifest(self.mutated(lambda m: m['engines'].clear()))
        with self.assertRaisesRegex(ValueError, 'unapproved'):
            channel.validate_manifest(self.mutated(lambda m: m['engines'].update(xray=copy.deepcopy(m['engines']['sing-box']))))
        with self.assertRaises(ValueError):
            channel.validate_manifest(self.mutated(lambda m: m.update(engines=[])))

    def test_size_bounds(self):
        for size in [0, 63, channel.MAX_SIZE + 1, -1, '100', 100.0, True]:
            with self.subTest(size=size), self.assertRaises(ValueError):
                channel.validate_manifest(self.mutated(lambda m: m['engines']['sing-box'].update(size=size)))
        for size in [channel.MIN_SIZE, channel.MAX_SIZE]:
            channel.validate_manifest(self.mutated(lambda m: m['engines']['sing-box'].update(size=size)))

    def test_url_must_be_an_absolute_https_dated_release_asset(self):
        good = manifest()['engines']['sing-box']['url']
        asset = 'sing-box-' + VERSION + '-linux-arm64'
        for bad in ['http://github.com/' + REPO + '/releases/download/engines-20261118-7/' + asset,
                    'https://example.com/' + REPO + '/releases/download/engines-20261118-7/' + asset,
                    'https://github.com/' + REPO + '/releases/download/engines-stable/' + asset,
                    'https://github.com/' + REPO + '/releases/latest/download/' + asset,
                    'https://github.com/' + REPO + '/releases/download/engines-20261118-7/other',
                    good + '?x=1', good + '#frag', 'https://user@github.com/' + REPO + '/releases/download/engines-20261118-7/' + asset,
                    '/' + REPO + '/releases/download/engines-20261118-7/' + asset, asset, '', None]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                channel.validate_manifest(self.mutated(lambda m: m['engines']['sing-box'].update(url=bad)))
        with self.assertRaisesRegex(ValueError, 'different repository'):
            channel.validate_manifest(manifest(), repo='someone/else')

    def test_asset_name_must_match_version(self):
        with self.assertRaisesRegex(ValueError, 'asset'):
            channel.validate_manifest(self.mutated(lambda m: m['engines']['sing-box'].update(asset='sing-box-1.14.2-linux-arm64')))

    def test_capabilities_versions_and_metadata(self):
        cases = [('capabilities', []), ('capabilities', ['other']), ('capabilities', CAPS + CAPS), ('capabilities', 'x'),
                 ('package_version', '1.14.4-flr-random-sni.1'), ('version', 'latest'), ('min_controller', 'v0.7'),
                 ('contract_sha256', None)]
        for key, value in cases:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                channel.validate_manifest(self.mutated(lambda m: m['engines']['sing-box'].update({key: value})))

    def test_top_level_fields_and_unknown_keys(self):
        for key, value in [('format', 'flr-engine-channel-v2'), ('channel', 'beta'), ('source_commit', 'abc'),
                           ('generated_at', '2026-11-18'), ('published_at', '2026-11-18T02:59:59Z'),
                           ('generated_at', '2026-13-45T00:00:00Z')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                channel.validate_manifest(self.mutated(lambda m: m.update({key: value})))
        with self.assertRaises(ValueError):
            channel.validate_manifest(self.mutated(lambda m: m.update(extra=1)))
        with self.assertRaises(ValueError):
            channel.validate_manifest(self.mutated(lambda m: m['engines']['sing-box'].update(extra=1)))
        with self.assertRaises(ValueError):
            channel.validate_manifest(self.mutated(lambda m: m['engines']['sing-box'].pop('url')))


API = 'https://api.github.com/repos/' + REPO + '/releases/assets/123456'


class ApiUrl(unittest.TestCase):
    def test_with_api_url_adds_validated_rest_url_and_keeps_url(self):
        base = manifest()
        value = channel.with_api_url(base, 'sing-box', 123456)
        self.assertEqual(value['engines']['sing-box']['api_url'], API)
        self.assertEqual(value['engines']['sing-box']['url'], base['engines']['sing-box']['url'])
        self.assertNotIn('api_url', base['engines']['sing-box'])
        channel.validate_manifest(value, {'sing-box': BINARY}, repo=REPO)

    def test_api_url_format_is_enforced(self):
        for bad in ['http://api.github.com/repos/' + REPO + '/releases/assets/1',
                    'https://github.com/repos/' + REPO + '/releases/assets/1',
                    'https://api.github.com/repos/other/repo/releases/assets/1',
                    'https://api.github.com/repos/' + REPO + '/releases/assets/abc',
                    'https://api.github.com/repos/' + REPO + '/releases/assets/0',
                    'https://api.github.com/repos/' + REPO + '/releases/assets/1?x=1',
                    'https://api.github.com/repos/' + REPO + '/releases/tags/engines-20261118-7', '', None, 5]:
            value = manifest()
            value['engines']['sing-box']['api_url'] = bad
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                channel.validate_manifest(value)
        for bad in [0, -1, '5', True]:
            with self.subTest(id=bad), self.assertRaises(ValueError):
                channel.with_api_url(manifest(), 'sing-box', bad)


class SameEngines(unittest.TestCase):
    def test_identical_binaries_are_the_same_regardless_of_time_url_or_api_url(self):
        current = channel.with_api_url(manifest(tag='engines-20261111-3'), 'sing-box', 9)
        current['published_at'] = '2026-11-11T00:00:00Z'
        current['generated_at'] = '2026-11-11T00:00:00Z'
        self.assertTrue(channel.same_engines(current, manifest()))

    def test_changed_binary_or_engine_set_is_different(self):
        self.assertFalse(channel.same_engines(manifest(BINARY + b'x'), manifest()))
        empty = manifest()
        empty['engines'] = {}
        self.assertFalse(channel.same_engines(empty, manifest()))

    def test_malformed_current_is_different_but_bad_candidate_is_an_error(self):
        for bad in [None, {}, [], {'engines': {'sing-box': {'sha256': hashlib.sha256(BINARY).hexdigest()}}}]:
            self.assertFalse(channel.same_engines(bad, manifest()))
        with self.assertRaises(ValueError):
            channel.same_engines(manifest(), {})

    def test_same_and_api_url_subcommands(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'cand.json').write_text(json.dumps(manifest()))
            (root / 'cur.json').write_text(json.dumps(manifest(tag='engines-20261111-3')))
            (root / 'other.json').write_text(json.dumps(manifest(BINARY + b'y')))

            def run(*args):
                return subprocess.run([sys.executable, '-I', str(SCRIPT), *args], capture_output=True, text=True)
            self.assertEqual(run('same', '--candidate', str(root / 'cand.json'), '--current', str(root / 'cur.json')).stdout.strip(), 'true')
            self.assertEqual(run('same', '--candidate', str(root / 'cand.json'), '--current', str(root / 'other.json')).stdout.strip(), 'false')
            self.assertEqual(run('same', '--candidate', str(root / 'cand.json'), '--current', str(root / 'missing.json')).stdout.strip(), 'false')
            self.assertEqual(run('same', '--candidate', str(root / 'cand.json')).stdout.strip(), 'false')
            self.assertNotEqual(run('same', '--candidate', str(root / 'missing.json')).returncode, 0)
            done = run('api-url', '--manifest', str(root / 'cand.json'), '--engine', 'sing-box', '--asset-id', '123456')
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(json.loads((root / 'cand.json').read_text())['engines']['sing-box']['api_url'], API)
            self.assertNotEqual(run('api-url', '--manifest', str(root / 'cand.json'), '--engine', 'xray', '--asset-id', '1').returncode, 0)
            self.assertNotEqual(run('api-url', '--manifest', str(root / 'cand.json'), '--engine', 'sing-box', '--asset-id', 'x').returncode, 0)


class BuildCommand(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        digest = hashlib.sha256(BINARY).hexdigest()
        (self.root / 'lock.json').write_text(json.dumps({'sing_box': {'version': VERSION, 'package_version': '1.14.4.1', 'capabilities': CAPS}}))
        self.receipt = {'custom_version': VERSION, 'capabilities': CAPS, 'targets': {'linux/arm64': {'sha256': digest, 'size': len(BINARY)}}}
        self.native = {'source_commit': COMMIT, 'contract_sha256': CONTRACT, 'version': VERSION, 'package_version': '1.14.4.1',
                       'capabilities': CAPS, 'engine': {'compatibility': {'arm64_binary_sha256': digest}}}
        (self.root / 'sing-box').write_bytes(BINARY)
        self.write()

    def write(self):
        (self.root / 'receipt.json').write_text(json.dumps(self.receipt))
        (self.root / 'native.json').write_text(json.dumps(self.native))

    def run_build(self, *extra):
        return subprocess.run([sys.executable, '-I', str(SCRIPT), 'build', '--lock', str(self.root / 'lock.json'),
                               '--receipt', str(self.root / 'receipt.json'), '--native', str(self.root / 'native.json'),
                               '--binary', str(self.root / 'sing-box'), '--repo', REPO, '--run-number', '7',
                               '--source-commit', COMMIT, '--now', NOW, '--output', str(self.root / 'out'), *extra],
                              capture_output=True, text=True)

    def test_build_writes_asset_and_valid_manifest_that_verify_accepts(self):
        result = self.run_build()
        self.assertEqual(result.returncode, 0, result.stderr)
        out = self.root / 'out'
        value = json.loads((out / 'channel.json').read_text())
        self.assertEqual(value['engines']['sing-box']['url'].split('/')[-2], 'engines-20261118-7')
        self.assertEqual((out / ('sing-box-' + VERSION + '-linux-arm64')).read_bytes(), BINARY)
        verify = subprocess.run([sys.executable, '-I', str(SCRIPT), 'verify', '--manifest', str(out / 'channel.json'),
                                 '--binary', 'sing-box=' + str(out / ('sing-box-' + VERSION + '-linux-arm64')), '--repo', REPO],
                                capture_output=True, text=True)
        self.assertEqual(verify.returncode, 0, verify.stderr)

    def test_build_refuses_inconsistent_inputs(self):
        self.receipt['targets']['linux/arm64']['sha256'] = '0' * 64
        self.write()
        result = self.run_build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('receipt', result.stderr)
        self.assertFalse((self.root / 'out/channel.json').exists())

    def test_build_refuses_unchecked_binary_wrong_commit_or_capabilities(self):
        for mutate, text in [(lambda: self.native['engine']['compatibility'].update(arm64_binary_sha256='1' * 64), 'natively'),
                             (lambda: self.native.update(source_commit='b' * 40), 'commit'),
                             (lambda: self.native.update(capabilities=[]), 'disagree'),
                             (lambda: self.receipt.update(custom_version='1.14.4'), 'disagree')]:
            with self.subTest(text=text):
                self.setUp()
                mutate()
                self.write()
                result = self.run_build()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(text, result.stderr)

    def test_build_refuses_a_tampered_binary_even_if_size_matches(self):
        (self.root / 'sing-box').write_bytes(b'X' * len(BINARY))
        self.assertNotEqual(self.run_build().returncode, 0)


class WorkflowGuards(unittest.TestCase):
    def test_workflow_uses_only_commit_pinned_actions_and_guards_the_signing_key(self):
        text = (PROJECT / '.github/workflows/engine-channel.yml').read_text()
        import re
        for line in text.splitlines():
            match = re.match(r'\s*-?\s*uses:\s*(\S+)', line)
            if match:
                self.assertRegex(match.group(1), r'^[\w./-]+@[0-9a-f]{40}$', line)
        self.assertIn('workflow_dispatch', text)
        self.assertIn('schedule', text)
        self.assertIn('FLR_CHANNEL_SIGNING_KEY', text)
        self.assertIn('openssl pkeyutl -sign -rawin', text)
        self.assertNotIn('set -x', text)
        self.assertNotRegex(text, r'echo[^\n]*FLR_CHANNEL_SIGNING_KEY')
        self.assertIn('--latest=false', text)
        self.assertIn('engines-stable', text)

    def test_build_job_is_read_only_and_never_sees_secrets_or_publishes(self):
        text = (PROJECT / '.github/workflows/engine-channel.yml').read_text()
        build, publish = text.split('\n  publish:\n')
        build = build[build.index('\n  build:\n'):]
        self.assertIn('contents: read', build)
        self.assertNotIn('contents: write', build)
        self.assertNotIn('secrets.', build)
        self.assertNotIn('gh release', build)
        self.assertIn('persist-credentials: false', build)
        self.assertIn('contents: write', publish)
        self.assertIn('needs: build', publish)
        self.assertNotIn('go build', publish)
        self.assertIn('engine_channel.py same', publish)
        self.assertIn('steps.compare.outputs.same != \'true\'', publish)
        self.assertIn('api-url', publish)
        self.assertIn('application/octet-stream', text)


if __name__ == '__main__':
    unittest.main()
