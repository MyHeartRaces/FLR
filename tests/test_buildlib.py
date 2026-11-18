import importlib.util
import io
import struct
from pathlib import Path
import tarfile
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[1] / "ci" / "buildlib.py"
if MODULE.exists():
    spec = importlib.util.spec_from_file_location("buildlib", MODULE)
    lib = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lib)
else:
    lib = None

LOCK = {
    "openwrt": {
        "version": "25.12.5", "profile": "glinet_gl-mt6000",
        "supported_device": "glinet,gl-mt6000", "kernel": "6.12.94",
        "kernel_abi": "5a6c1f71be683ae9980b15d3ce73e24d",
    },
    "awg": {"module_version": "3.1.20260906", "tools_version": "3.1.20260812"},
    "sing_box": {"version": "1.14.2"},
    "packages": ["luci", "kmod-amneziawg", "amneziawg-tools", "luci-proto-amneziawg", "flint-sing-box"],
}
METADATA = {"supported_devices": ["glinet,gl-mt6000"], "version": {"number": "25.12.5"}}
MANIFEST = """kernel - 6.12.94~5a6c1f71be683ae9980b15d3ce73e24d-r1
luci - 26.167.12345
kmod-amneziawg - 6.12.94.3.1.20260906-r1
amneziawg-tools - 3.1.20260812-r1
luci-proto-amneziawg - 3.1.1-r1
flint-sing-box - 1.14.2-r1
"""


class ArtifactChecks(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(lib, "build verification has not been implemented")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "image.bin"

    def sing_box_fixture(self, tags='with_quic,with_wireguard,with_utls', cgo='0', deps=''):
        def encoded(value):
            raw=value if isinstance(value,bytes) else value.encode()
            size=len(raw);prefix=bytearray()
            while size>=128:
                prefix.append((size&127)|128);size>>=7
            prefix.append(size)
            return bytes(prefix)+raw
        module=('path\tgithub.com/SagerNet/sing-box/cmd/sing-box\n'
                'mod\tgithub.com/SagerNet/sing-box\tv1.14.2\n'+deps+
                'build\t-tags='+tags+'\nbuild\tCGO_ENABLED='+cgo+'\n').encode()
        header=b'\xff Go buildinf:'+bytes([8,2])+b'\x00'*16
        # Ordinary stub error text must not masquerade as a compiled build tag.
        self.path.write_bytes(header+encoded('go1.26.8')+encoded(b'0'*16+module+b'1'*16)+
                              b'Naive outbound is not included: rebuild with -tags with_naive_outbound')
        return self.path

    def test_sing_box_without_naive_accepts_remaining_production_tags(self):
        lib.check_sing_box_capabilities(self.sing_box_fixture())

    def test_sing_box_rejects_naive_tags_linked_cronet_or_cgo(self):
        for values in [
            {'tags':'with_quic,with_wireguard,with_utls,with_naive_outbound'},
            {'deps':'dep\tgithub.com/sagernet/cronet-go\tv0.0.0\n'},
            {'cgo':'1'},
            {'tags':'with_quic,with_utls'},
        ]:
            with self.subTest(values=values),self.assertRaises(ValueError):
                lib.check_sing_box_capabilities(self.sing_box_fixture(**values))

    def test_sing_box_rejects_truncated_or_unframed_build_info(self):
        payload=self.sing_box_fixture().read_bytes()
        for content in [payload[:32],payload[:38],b'with_quic with_wireguard with_utls']:
            self.path.write_bytes(content)
            with self.subTest(size=len(content)),self.assertRaises(ValueError):
                lib.check_sing_box_capabilities(self.path)

    def image(self, extra=None, board="glinet_gl-mt6000"):
        names = [f"sysupgrade-{board}/CONTROL", f"sysupgrade-{board}/kernel", f"sysupgrade-{board}/root"]
        if extra:
            names.append(extra)
        with tarfile.open(self.path, "w") as tf:
            for name in names:
                info = tarfile.TarInfo(name)
                info.size = 4
                tf.addfile(info, io.BytesIO(b"data"))
        return self.path

    def test_valid_image(self):
        report = lib.check_sysupgrade(self.image(), METADATA, LOCK)
        self.assertEqual(report["board"], "glinet_gl-mt6000")

    def test_glinet_metadata_format(self):
        gl_metadata = {"supported_devices": ["glinet,gl-mt6000"],
                       "version": {"release": "25.12.5", "version": "25.12.5"}}
        self.assertEqual(lib.check_sysupgrade(self.image(), gl_metadata, LOCK)["board"], "glinet_gl-mt6000")

    def test_bootloader_entry_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unexpected"):
            lib.check_sysupgrade(self.image("sysupgrade-glinet_gl-mt6000/bl31-uboot.fip"), METADATA, LOCK)

    def test_path_traversal_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsafe"):
            lib.check_sysupgrade(self.image("../outside"), METADATA, LOCK)

    def test_wrong_tar_board_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "device"):
            lib.check_sysupgrade(self.image(board="another-router"), METADATA, LOCK)

    def test_wrong_metadata_device_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "device"):
            lib.check_sysupgrade(self.image(), {**METADATA, "supported_devices": ["another,router"]}, LOCK)

    def test_kernel_abi_mismatch_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "ABI"):
            lib.check_manifest(MANIFEST.replace(LOCK["openwrt"]["kernel_abi"], "0" * 32), LOCK)

    def test_abi_substring_is_rejected(self):
        abi = LOCK["openwrt"]["kernel_abi"]
        with self.assertRaisesRegex(ValueError, "ABI"):
            lib.check_manifest(MANIFEST.replace(abi, "0" + abi), LOCK)

    def test_version_prefix_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "sing-box"):
            lib.check_manifest(MANIFEST.replace("1.14.2-r1", "1.14.20-r1"), LOCK)

    def test_missing_vpn_package_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "missing"):
            lib.check_manifest(MANIFEST.replace("flint-sing-box - 1.14.2-r1\n", ""), LOCK)

    def test_old_sing_box_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "sing-box"):
            lib.check_manifest(MANIFEST.replace("1.14.2", "1.13.21"), LOCK)

    def test_arm64_elf(self):
        elf = bytearray(64)
        elf[:6] = b"\x7fELF\x02\x01"
        elf[18:20] = (183).to_bytes(2, "little")
        self.path.write_bytes(elf)
        self.assertEqual(lib.check_elf(self.path), "aarch64")

    def test_x86_elf_is_rejected(self):
        elf = bytearray(64)
        elf[:6] = b"\x7fELF\x02\x01"
        elf[18:20] = (62).to_bytes(2, "little")
        self.path.write_bytes(elf)
        with self.assertRaisesRegex(ValueError, "AArch64"):
            lib.check_elf(self.path)

    def dynamic_elf(self, interpreter):
        data = interpreter.encode() + b"\0"
        elf = bytearray(120) + data
        elf[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", elf, 18, 183)
        struct.pack_into("<Q", elf, 32, 64)
        struct.pack_into("<HH", elf, 54, 56, 1)
        struct.pack_into("<IIQQQQQQ", elf, 64, 3, 0, 120, 0, 0, len(data), len(data), 1)
        self.path.write_bytes(elf)

    def test_musl_interpreter_is_accepted(self):
        self.dynamic_elf("/lib/ld-musl-aarch64.so.1")
        self.assertEqual(lib.check_elf(self.path), "aarch64")

    def test_glibc_interpreter_is_rejected(self):
        self.dynamic_elf("/lib/ld-linux-aarch64.so.1")
        with self.assertRaisesRegex(ValueError, "interpreter"):
            lib.check_elf(self.path)

    def test_truncated_program_headers_are_rejected(self):
        self.dynamic_elf("/lib/ld-musl-aarch64.so.1")
        self.path.write_bytes(self.path.read_bytes()[:100])
        with self.assertRaisesRegex(ValueError, "truncated"):
            lib.check_elf(self.path)


if __name__ == "__main__":
    unittest.main()
