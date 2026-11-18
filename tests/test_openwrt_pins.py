"""Offline coverage for ci/resolve-openwrt-pins.py parsing and lock assembly."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('openwrt_pins', ROOT / 'ci/resolve-openwrt-pins.py')
pins = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pins)

SDK = 'openwrt-sdk-25.12.6-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64.tar.zst'
IB = 'openwrt-imagebuilder-25.12.6-mediatek-filogic.Linux-x86_64.tar.zst'
SUMS = '\n'.join([
    '1c04ac47bdfc361d6aab299eb520d570e368013dedcb8d29cf39dc7168ae642e *' + SDK,
    '8ce0da1e2fb3d0454ebeb1e3df5705f2145e09ffe6f00d5077c18369719daf83 *' + IB,
    'a25a05977027deae000b10b025b75ed3e9c12a4b7d42ae57e8d5a8a019493658 *openwrt-25.12.6-mediatek-filogic-glinet_gl-mt6000-squashfs-sysupgrade.bin',
    'not-a-hash *junk',
])
FEEDS = '\n'.join([
    'src-git packages https://git.openwrt.org/feed/packages.git^' + 'a' * 40,
    'src-git luci https://git.openwrt.org/project/luci.git^' + 'b' * 40,
    'src-git routing https://git.openwrt.org/feed/routing.git^' + 'c' * 40,
])
MANIFEST = 'base-files - 1680-r33311\nkernel - 6.12.112~0123456789abcdef0123456789abcdef-r1\nkmod-nft-core - 6.12.112-r1\n'


class Parsing(unittest.TestCase):
    def test_sha256sums_and_archives(self):
        sums = pins.parse_sha256sums(SUMS)
        self.assertEqual(pins.find_archive(sums, 'sdk', '25.12.6'), (SDK, '1c04ac47bdfc361d6aab299eb520d570e368013dedcb8d29cf39dc7168ae642e'))
        self.assertEqual(pins.find_archive(sums, 'imagebuilder', '25.12.6')[0], IB)
        with self.assertRaises(ValueError):
            pins.find_archive(sums, 'sdk', '25.12.5')
        with self.assertRaises(ValueError):
            pins.parse_sha256sums('nothing here')

    def test_feeds_require_full_commits(self):
        self.assertEqual(pins.parse_feeds(FEEDS)['luci'], 'b' * 40)
        with self.assertRaises(ValueError):
            pins.parse_feeds('src-git packages https://x/packages.git^abc\nsrc-git luci https://x/luci.git^' + 'b' * 40)
        with self.assertRaises(ValueError):
            pins.parse_feeds('src-git packages https://x/packages.git^' + 'a' * 40)

    def test_manifest_kernel(self):
        self.assertEqual(pins.parse_manifest_kernel(MANIFEST), {'kernel': '6.12.112', 'kernel_abi': '0123456789abcdef0123456789abcdef', 'kernel_release': 1})
        with self.assertRaises(ValueError):
            pins.parse_manifest_kernel('base-files - 1\n')
        with self.assertRaises(ValueError):
            pins.parse_manifest_kernel(MANIFEST + MANIFEST)

    def test_revision_and_epochs(self):
        self.assertEqual(pins.parse_revision('r33311-981c978eff\n')['commit_prefix'], '981c978eff')
        with self.assertRaises(ValueError):
            pins.parse_revision('SNAPSHOT')
        self.assertEqual(pins.epoch_from_version_date('1782737960\n'), 1782737960)
        with self.assertRaises(ValueError):
            pins.epoch_from_version_date('yesterday')
        self.assertEqual(pins.epoch_from_commit({'commit': {'committer': {'date': '2026-06-29T12:59:20Z'}}}), 1782737960)

    def test_official_pins_use_only_release_files(self):
        files = {'sha256sums': SUMS, 'feeds.buildinfo': FEEDS, 'openwrt-25.12.6-mediatek-filogic.manifest': MANIFEST, 'version.buildinfo': 'r33311-981c978eff'}
        seen = []

        def fetch(url):
            seen.append(url)
            self.assertTrue(url.startswith('https://downloads.openwrt.org/releases/25.12.6/targets/mediatek/filogic/'))
            return files[url.rsplit('/', 1)[1]]

        result = pins.official_pins('25.12.6', fetch)
        self.assertEqual(result['kernel'], '6.12.112')
        self.assertEqual(result['sdk_archive_sha256'], '1c04ac47bdfc361d6aab299eb520d570e368013dedcb8d29cf39dc7168ae642e')
        self.assertEqual(len(seen), 4)
        with self.assertRaises(ValueError):
            pins.official_pins('latest', fetch)


class Assembly(unittest.TestCase):
    PREVIOUS = {
        'version': '25.12.5', 'target': 'mediatek/filogic', 'profile': 'glinet_gl-mt6000',
        'supported_device': 'glinet,gl-mt6000', 'arch': 'aarch64_cortex-a53', 'kernel': '6.12.94',
        'kernel_abi': '5a6c1f71be683ae9980b15d3ce73e24d', 'source_date_epoch': 1782737960,
        'sdk_archive_sha256': 'f' * 64, 'imagebuilder_archive_sha256': 'e' * 64,
        'sdk_container': 'ghcr.io/openwrt/sdk@sha256:' + '1' * 64,
        'imagebuilder_container': 'ghcr.io/openwrt/imagebuilder@sha256:' + '2' * 64,
        'feeds': {'packages': '5' * 40, 'luci': '6' * 40},
    }

    def official(self, **override):
        value = {'version': '25.12.6', 'kernel': '6.12.112', 'kernel_abi': '0' * 32, 'kernel_release': 1,
                 'sdk_archive_sha256': 'a' * 64, 'imagebuilder_archive_sha256': 'b' * 64,
                 'feeds': {'packages': 'c' * 40, 'luci': 'd' * 40, 'routing': 'e' * 40}}
        value.update(override)
        return value

    def test_lock_section_keeps_device_fields(self):
        containers = {'sdk': 'ghcr.io/openwrt/sdk@sha256:' + '3' * 64, 'imagebuilder': 'ghcr.io/openwrt/imagebuilder@sha256:' + '4' * 64}
        section = pins.lock_section(self.PREVIOUS, self.official(), containers, 1790000000)
        self.assertEqual(section['profile'], 'glinet_gl-mt6000')
        self.assertEqual(section['version'], '25.12.6')
        self.assertEqual(section['feeds'], {'packages': 'c' * 40, 'luci': 'd' * 40})
        self.assertNotIn('kernel_release', section)
        self.assertEqual(section['sdk_container'], containers['sdk'])
        self.assertEqual(pins.lock_section(self.PREVIOUS, self.official(kernel_release=2), containers, 1)['kernel_release'], 2)

    def test_self_check_reports_only_real_differences(self):
        same = self.official(version='25.12.5', kernel='6.12.94', kernel_abi='5a6c1f71be683ae9980b15d3ce73e24d',
                             sdk_archive_sha256='f' * 64, imagebuilder_archive_sha256='e' * 64,
                             feeds={'packages': '5' * 40, 'luci': '6' * 40})
        self.assertEqual(pins.compare_official(self.PREVIOUS, same), [])
        moved = dict(same, kernel_abi='9' * 32)
        self.assertEqual(pins.compare_official(self.PREVIOUS, moved), ['kernel_abi'])
        self.assertEqual(pins.compare_official(self.PREVIOUS, dict(same, kernel_release=2)), ['kernel_release'])


if __name__ == '__main__':
    unittest.main()
