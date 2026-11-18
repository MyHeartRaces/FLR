import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ci'))
import buildlib

class SDKBaseFeed(unittest.TestCase):
    def test_preserve_sdk_base_commit_and_put_dependency_metadata_first(self):
        base='src-git --root=package base https://git.openwrt.org/openwrt/openwrt.git^'+'a'*40
        result=buildlib.sdk_feeds(base+'\nsrc-git packages floating\n',{'packages':'b'*40,'luci':'c'*40})
        self.assertEqual(result.splitlines()[0],base)
        self.assertEqual(result.splitlines()[1],'src-git-full packages https://github.com/openwrt/packages.git^'+'b'*40)
        self.assertEqual(result.splitlines()[2],'src-git-full luci https://github.com/openwrt/luci.git^'+'c'*40)
    def test_missing_floating_unofficial_and_duplicate_base_rejected(self):
        good='src-git --root=package base https://git.openwrt.org/openwrt/openwrt.git^'+'a'*40
        for text in ['',good.split('^')[0],good.replace('git.openwrt.org','evil.invalid'),good+'\n'+good,good+'\nEVIL:=yes']:
            if text.endswith('EVIL:=yes'):
                # Unrelated upstream feeds are ignored; only owned entries are emitted.
                self.assertNotIn('EVIL',buildlib.sdk_feeds(text,{'packages':'b'*40,'luci':'c'*40}))
            else:
                with self.subTest(text=text),self.assertRaises(ValueError):buildlib.sdk_feeds(text,{'packages':'b'*40,'luci':'c'*40})

if __name__=='__main__':unittest.main()
