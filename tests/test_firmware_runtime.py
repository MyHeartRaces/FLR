import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('buildlib', PROJECT / 'ci/buildlib.py')
lib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lib)
LOCK = json.loads((PROJECT / 'build/versions.lock.json').read_text())

class FirmwareRuntime(unittest.TestCase):
    def test_native_hash_required(self):
        lock = copy.deepcopy(LOCK)
        lock['native'] = {'xray': {'version':'26.3.27','url':'https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-arm64-v8a.zip'}}
        with self.assertRaisesRegex(ValueError, 'native'):
            lib.check_native_lock(lock)

    def test_missing_runtime_components(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, 'runtime payload'):
                lib.check_runtime_root(Path(temp), LOCK, {})

    def test_missing_payload_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'binary'
            path.write_bytes(b'payload')
            with self.assertRaisesRegex(ValueError, 'hash'):
                lib.check_payload_hash(path, 'usr/bin/xray', {})

    def test_private_runtime_files_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'etc/flr-runtime').mkdir(parents=True)
            (root / 'etc/flr-runtime/settings.json').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'private'):
                lib.check_private_state(root)

    def test_retired_engine_service_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'etc/init.d').mkdir(parents=True)
            (root / 'etc/init.d/flr-proxies').write_text('procd_set_param command /usr/bin/sing-box run')
            with self.assertRaisesRegex(ValueError, 'retired'):
                lib.check_private_state(root)

    def test_runtime_and_native_versions_checked(self):
        lock = copy.deepcopy(LOCK)
        lock['native'] = {'xray': {'version':'26.3.27'}}
        lock['packages'] = ['flr-runtime', 'flint-xray']
        manifest = 'kernel - 6.12.112~f0a7348f9cb959e1bf4d0447669b031e-r1\nflr-runtime - wrong-r1\nflint-xray - 26.3.27-r1\n'
        with self.assertRaisesRegex(ValueError, 'runtime'):
            lib.check_manifest(manifest, lock)

if __name__ == '__main__':
    unittest.main()

class CompleteRuntimeFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.report = {'payload_sha256': {}}
        elf = bytearray(64)
        elf[:6] = b'\x7fELF\x02\x01'
        elf[18:20] = (183).to_bytes(2, 'little')
        files = lib.RUNTIME_FILES + [x['binary'] for x in LOCK['native'].values()] + [
            'usr/share/flr-bypass/lua/' + n + '.lua' for n in ['zapret-lib','zapret-antidpi','zapret-auto']]
        for relative in files:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            data = bytes(elf) if relative in ['usr/sbin/flr-controller'] + [x['binary'] for x in LOCK['native'].values()] else b'{}' if relative.endswith('.json') else b'payload'
            path.write_bytes(data)
            path.chmod(0o755)
            self.report['payload_sha256'][relative] = lib.sha256(path)

    def test_complete_root_passes(self):
        self.assertTrue(lib.check_runtime_root(self.root, LOCK, self.report))

    def test_each_api_menu_acl_init_file_required(self):
        for relative in lib.RUNTIME_FILES:
            with self.subTest(relative=relative):
                path = self.root / relative
                data = path.read_bytes()
                path.unlink()
                with self.assertRaisesRegex(ValueError, 'runtime payload'):
                    lib.check_runtime_root(self.root, LOCK, self.report)
                path.write_bytes(data)
                path.chmod(0o755)

    def test_changed_native_payload_rejected(self):
        (self.root / 'usr/bin/xray').write_bytes((self.root / 'usr/bin/xray').read_bytes() + b'tamper')
        with self.assertRaisesRegex(ValueError, 'hash'):
            lib.check_runtime_root(self.root, LOCK, self.report)

    def test_native_lock_urls_and_hashes(self):
        self.assertIsNone(lib.check_native_lock(LOCK))
        for key,value in [('sha256',''),('url','https://untrusted.invalid/native'),('static',False)]:
            lock = copy.deepcopy(LOCK)
            lock['native']['xray'][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'native'):
                lib.check_native_lock(lock)

    def test_static_elf_rejects_dynamic_loader(self):
        import struct
        path = self.root / 'usr/bin/xray'
        data = bytearray(path.read_bytes()) + bytearray(56)
        struct.pack_into('<Q', data, 32, 64)
        struct.pack_into('<HH', data, 54, 56, 1)
        struct.pack_into('<IIQQQQQQ', data, 64, 2, 0, 0, 0, 0, 0, 0, 1)
        path.write_bytes(data)
        with self.assertRaisesRegex(ValueError, 'static ELF'):
            lib.check_elf(path, static=True)

class ConntrackDefault(unittest.TestCase):
    def test_missing_and_disabled_accounting_fail(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaisesRegex(ValueError, 'accounting'):
                lib.check_conntrack_accounting(root)
            path = root / 'etc/sysctl.d/11-nf-conntrack.conf'
            path.parent.mkdir(parents=True)
            path.write_text('net.netfilter.nf_conntrack_acct=0\n')
            with self.assertRaisesRegex(ValueError, 'accounting'):
                lib.check_conntrack_accounting(root)
            path.write_text('# pinned OpenWrt\nnet.netfilter.nf_conntrack_acct=1\n')
            self.assertIsNone(lib.check_conntrack_accounting(root))

class NFQueueModules(unittest.TestCase):
    def test_native_queue_module_versions_match_kernel(self):
        lock = copy.deepcopy(LOCK)
        lock['packages'] = ['kmod-nft-queue', 'kmod-nfnetlink-queue']
        kernel = lock['openwrt']['kernel']
        manifest = f"kernel - {kernel}~{lock['openwrt']['kernel_abi']}-r1\nkmod-nft-queue - {kernel}-r1\nkmod-nfnetlink-queue - {kernel}-r1\n"
        self.assertIn('kmod-nft-queue', lib.check_manifest(manifest, lock))
        with self.assertRaisesRegex(ValueError, 'queue.*version'):
            lib.check_manifest(manifest.replace('kmod-nft-queue - '+kernel, 'kmod-nft-queue - 6.12.95'), lock)

    def test_missing_native_queue_modules_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, 'queue module'):
                lib.check_queue_modules(Path(temp), LOCK)

    def test_queue_module_arm64_and_vermagic(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            directory = root / 'lib/modules' / LOCK['openwrt']['kernel']
            directory.mkdir(parents=True)
            elf = bytearray(64)
            elf[:6] = b'\x7fELF\x02\x01'
            elf[18:20] = (183).to_bytes(2, 'little')
            payload = elf + ('vermagic=' + LOCK['openwrt']['kernel'] + ' ').encode()
            for name in ['nft_queue','nfnetlink_queue']:
                (directory / (name + '.ko')).write_bytes(payload)
            self.assertIsNone(lib.check_queue_modules(root, LOCK))
            (directory / 'nft_queue.ko').write_bytes(elf + b'vermagic=6.12.95 ')
            with self.assertRaisesRegex(ValueError, 'vermagic'):
                lib.check_queue_modules(root, LOCK)
