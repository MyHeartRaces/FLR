"""Required SDK targets must survive the pinned OpenWrt package discovery scan."""
from pathlib import Path
import re
import subprocess
import unittest

PROJECT = Path(__file__).resolve().parents[1]
# OpenWrt f0a60eee2fe051741c643ea6118718aae1ef17fb include/scan.mk:
# discovery greps each Makefile before evaluating its includes. LuCI recipes
# therefore need the standard signature even though luci.mk calls BuildPackage.
SCANNER_PATTERN = r'call (Build/DefaultTargets|BuildPackage|KernelPackage)'


class SDKPackageDiscovery(unittest.TestCase):
    def test_every_required_compile_target_is_discoverable_before_make_evaluation(self):
        script = (PROJECT / 'ci/sdk-build.sh').read_text()
        required = set(re.findall(r'package/([a-z0-9-]+)/compile', script))
        self.assertIn('luci-app-flr', required)
        self.assertIn('luci-proto-amneziawg', required)
        makefiles = [PROJECT / 'packages' / name / 'Makefile' for name in sorted(required)]
        result = subprocess.run(['grep', '-aHE', SCANNER_PATTERN, *map(str, makefiles)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertIn(result.returncode, (0, 1), result.stderr)
        discovered = {Path(line.split(':', 1)[0]).parent.name for line in result.stdout.splitlines()}
        self.assertEqual(required - discovered, set(),
                         'required SDK targets omitted by the pinned package discovery scanner')


if __name__ == '__main__':
    unittest.main()
