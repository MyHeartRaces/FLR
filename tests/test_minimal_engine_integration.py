import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import importlib.util
from unittest.mock import patch

from test_sing_box_source_build import PIN, fixture_binary, receipt, source
import test_engine_releases as release_tests
from engine_compat import NativeContracts


def write_source(folder):
    record = receipt()
    for arch in ['amd64', 'arm64']:
        data = fixture_binary(arch=arch)
        target = folder / ('linux-' + arch)
        target.mkdir(parents=True)
        (target / 'sing-box').write_bytes(data)
        (target / 'LICENSE').write_bytes(b'public license fixture')
        record['targets']['linux/' + arch].update(sha256=hashlib.sha256(data).hexdigest(), size=len(data))
        archive = source.archive_bytes(PIN['version'], arch, data, b'public license fixture')
        (folder / ('sing-box-' + PIN['version'] + '-linux-' + arch + '-static.tar.gz')).write_bytes(archive)
    (folder / 'receipt.json').write_text(json.dumps(record))
    return source.load_local(PIN, folder)


class LocalSourceArtifacts(unittest.TestCase):
    def test_source_resolver_uses_workspace_and_refuses_missing_build(self):
        spec=importlib.util.spec_from_file_location('resolve_engines_module',Path(__file__).resolve().parents[1]/'ci/resolve-engines.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        class Contracts:
            def validate(self,component,release,arm,host):
                return {'arm64_binary_sha256':self.receipt['targets']['linux/arm64']['sha256'],
                        'host_binary_sha256':self.receipt['targets']['linux/amd64']['sha256'],
                        'payload_sha256':{'usr/share/licenses/sing-box/LICENSE':self.license_sha}}
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp);built=write_source(folder);contracts=Contracts()
            contracts.receipt=built['receipt'];contracts.license_sha=built['license_sha256']
            with patch('engine_releases.OfficialAPI.asset',side_effect=AssertionError('custom engine replaced with prebuilt')):
                item=module.resolve_source_engine(PIN,contracts,folder)
                self.assertEqual(item['source_build'],built['receipt'])
                self.assertNotIn('url',item)
                (folder/'receipt.json').unlink()
                with self.assertRaises(ValueError):module.resolve_source_engine(PIN,contracts,folder)
    def test_production_lock_requires_pinned_source_engine(self):
        project=Path(__file__).resolve().parents[1]
        source.validate_pin(json.loads((project/'build/versions.lock.json').read_text())['sing_box'])
    def test_changed_binary_archive_license_and_symlink_abort(self):
        for mutation in ['binary', 'archive', 'license', 'symlink', 'receipt']:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                folder = Path(temp)
                write_source(folder)
                paths = {'binary': folder / 'linux-arm64/sing-box',
                         'archive': folder / ('sing-box-'+PIN['version']+'-linux-arm64-static.tar.gz'),
                         'license': folder / 'linux-amd64/LICENSE', 'receipt': folder / 'receipt.json',
                         'symlink': folder / 'linux-arm64/sing-box'}
                path = paths[mutation]
                if mutation == 'symlink':
                    path.unlink(); path.symlink_to(folder / 'linux-amd64/sing-box')
                else:
                    path.write_bytes(b'changed public fixture')
                with self.assertRaises(Exception):
                    source.load_local(PIN, folder)

    def test_production_native_contract_uses_both_static_source_archives(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            built = write_source(folder)
            contracts = NativeContracts.__new__(NativeContracts)
            contracts.scratch = folder / 'validate'
            contracts.directory = folder
            contracts.manifest = {'cases': [{'id': 'public-owned-config', 'sing_box': 'config.json'}]}
            with patch('engine_compat.require_ci'), patch('engine_compat.invoke', return_value='ok') as invoked:
                evidence = contracts.validate('sing_box', {'tag_name': 'v'+PIN['version'], 'asset_kind': 'source-build'},
                    built['archives']['arm64']['data'], built['archives']['amd64']['data'])
            self.assertEqual(evidence['arm64_binary_sha256'], built['receipt']['targets']['linux/arm64']['sha256'])
            self.assertEqual(evidence['host_binary_sha256'], built['receipt']['targets']['linux/amd64']['sha256'])
            self.assertEqual(evidence['cases'], ['public-owned-config'])
            self.assertEqual(invoked.call_args.args[1], ['check', '-c', str(folder / 'config.json')])


class MinimalResolvedLock(release_tests.ResolvedLockPayloadGate):
    def setUp(self):
        super().setUp()
        built = write_source(self.root / 'out/sing-box')
        reference = json.loads((self.root / 'build/versions.lock.json').read_text())
        reference['sing_box'] = copy.deepcopy(PIN)
        raw = json.dumps(reference).encode()
        (self.root / 'build/versions.lock.json').write_bytes(raw)
        self.lock['engine_resolution']['source_lock_sha256'] = hashlib.sha256(raw).hexdigest()
        original = self.lock['engine_resolution']['components']['sing_box']['compatibility']
        original.update(arm64_binary_sha256=built['receipt']['targets']['linux/arm64']['sha256'],
                        host_binary_sha256=built['receipt']['targets']['linux/amd64']['sha256'])
        original['payload_sha256']['usr/share/licenses/sing-box/LICENSE'] = built['license_sha256']
        item = {'version': PIN['version'], 'release_tag': 'v'+PIN['version'], 'asset_kind': 'source-build',
                'source_pin': copy.deepcopy(PIN), 'source_build': built['receipt'],
                'receipt_sha256': built['receipt_sha256'], 'compatibility': original,
                'archive': built['archives']['arm64']['name'], 'sha256': built['archives']['arm64']['sha256'],
                'validation_asset': {key: built['archives']['amd64'][key] for key in ['name', 'sha256']}}
        self.lock['sing_box'] = {**PIN, **{key: item[key] for key in ['release_tag', 'archive', 'sha256']}}
        self.lock['engine_resolution']['components']['sing_box'] = item

    def test_newer_exact_selection_accepted(self):
        self.assertEqual(self.load()['sing_box']['asset_kind'], 'source-build')

    def test_source_receipt_hash_and_compatibility_payload_must_agree(self):
        for field in ['receipt_sha256', 'source_build', 'compatibility', 'local_binary']:
            original = copy.deepcopy(self.lock)
            item = self.lock['engine_resolution']['components']['sing_box']
            if field == 'receipt_sha256': item[field] = '0' * 64
            if field == 'source_build': item[field]['targets']['linux/amd64']['sha256'] = '0' * 64
            if field == 'compatibility': item[field]['arm64_binary_sha256'] = '0' * 64
            if field == 'local_binary': (self.root / 'out/sing-box/linux-arm64/sing-box').write_bytes(b'changed')
            with self.subTest(field=field), self.assertRaises(ValueError): self.load()
            self.lock = original

    def test_sdk_preparation_copies_verified_source_payload_and_license(self):
        self.load()
        project=self.root
        sdk=project/'sdk';sdk.mkdir()
        (sdk/'feeds.conf.default').write_text('src-git --root=package base https://git.openwrt.org/openwrt/openwrt.git^'+'a'*40+'\n')
        (project/'packages/flint-sing-box').mkdir(parents=True)
        (project/'packages/flr-runtime').mkdir()
        (project/'packages/flint-zapret2/files').mkdir(parents=True)
        (project/'runtime/openwrt').mkdir(parents=True)
        (project/'out/runtime').mkdir()
        (project/'out/runtime/flr-controller').write_bytes(fixture_binary())
        license_path=project/'out/engine-licenses/zapret2/LICENSE'
        license_path.parent.mkdir(parents=True);license_path.write_bytes(b'public zapret license')
        self.lock['engine_resolution']['components']['zapret2']['compatibility']['payload_sha256']['usr/share/licenses/zapret2/LICENSE']=hashlib.sha256(license_path.read_bytes()).hexdigest()
        self.load()
        spec=importlib.util.spec_from_file_location('prepare_sdk_module',Path(__file__).resolve().parents[1]/'ci/prepare-sdk.py')
        module=importlib.util.module_from_spec(spec)
        try:spec.loader.exec_module(module)
        except (ValueError,IndexError):self.fail('SDK preparation still executes at import instead of exposing a testable gate')
        module.prepare_sdk(project,sdk,project/'out','f'*40)
        self.assertEqual((sdk/'package/flint-sing-box/src/sing-box').read_bytes(),(project/'out/sing-box/linux-arm64/sing-box').read_bytes())
        self.assertEqual((sdk/'package/flint-sing-box/src/LICENSE').read_bytes(),b'public license fixture')
        definitions=(sdk/'flr-engine-lock.mk').read_text()
        self.assertNotIn('FLR_SING_BOX_SOURCE_URL',definitions)
        self.assertNotIn('FLR_SING_BOX_ARCHIVE',definitions)
        self.assertIn('FLR_SING_BOX_PACKAGE_VERSION:='+self.lock['sing_box']['package_version']+'\n',definitions)


if __name__ == '__main__': unittest.main()
