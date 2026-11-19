"""The RoscomVPN import runs only when the owner starts it.

Nothing in the image, the init and upgrade scripts, the build or the
controller's start, migration and upgrade code may start it, and the overlay
it installs is the ordinary private overlay that sysupgrade keeps.
"""
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Files that may name the import: its implementation, the API dispatch and
# permission list, the LuCI page that starts it, translations, docs, tests.
ALLOWED = {
    "runtime/internal/controller/roscomvpn_api.go",
    "runtime/internal/controller/roscomvpn_api_test.go",
    "runtime/internal/controller/policy_api.go",
    "runtime/internal/controller/controller.go",
    "runtime/internal/control/api.go",
    "packages/luci-app-flr/htdocs/luci-static/resources/flr.js",
    "packages/luci-app-flr/htdocs/luci-static/resources/view/flr/routing/transfer.js",
    "packages/luci-app-flr/po/ru/flr.po",
    "packages/luci-app-flr/po/templates/flr.pot",
    "packages/luci-app-flr/tests/frontend.test.js",
    "docs/ROUTER-API.md",
    "policy/README.md",
    "tests/test_roscomvpn_manual_only.py",
}
NEEDLES = ("roscomvpn", "roscomimport", "runroscom", "geodata.convert", "installroutingpolicy")


def tracked():
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
                             check=True, capture_output=True).stdout
        return [v.decode() for v in out.split(b"\0") if v]
    except (FileNotFoundError, subprocess.CalledProcessError):
        return [p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts]


class RoscomVPNManualOnlyTest(unittest.TestCase):
    def test_only_the_api_and_luci_start_the_import(self):
        offenders = []
        for rel in tracked():
            if rel in ALLOWED or rel.startswith("runtime/internal/geodata/"):
                continue
            path = ROOT / rel
            try:
                text = path.read_text(encoding="utf-8").lower()
            except (UnicodeDecodeError, OSError):
                continue
            if any(n in text for n in NEEDLES):
                offenders.append(rel)
        self.assertEqual(offenders, [], "the RoscomVPN import may only be started from the routing API / LuCI")

    def test_startup_and_upgrade_paths_never_name_it(self):
        paths = [ROOT / "files", ROOT / "packages" / "flr-runtime", ROOT / "runtime" / "cmd", ROOT / "ci", ROOT / "build",
                 ROOT / "runtime" / "internal" / "controller" / "migration.go"]
        for base in paths:
            files = [base] if base.is_file() else [p for p in base.rglob("*") if p.is_file()]
            for p in files:
                try:
                    text = p.read_text(encoding="utf-8").lower()
                except (UnicodeDecodeError, OSError):
                    continue
                for n in NEEDLES + ("routing-import-commit",):
                    self.assertNotIn(n, text, f"{p.relative_to(ROOT)} names {n}")

    def test_controller_start_never_imports(self):
        src = (ROOT / "runtime/internal/controller/controller.go").read_text()
        start = src.index("func (c *Controller) Run(")
        end = src.index("\nfunc ", start + 1)
        run = src[start:end]
        for n in ("roscomImport", "runRoscom", "installRoutingPolicy", "installOverlay", "stageOverlay"):
            self.assertNotIn(n, run)

    def test_sysupgrade_keeps_the_overlay_and_its_backup(self):
        keep = (ROOT / "packages/flr-runtime/files/flr-runtime.keep").read_text().splitlines()
        for d in ("policy", "policy.backup"):
            self.assertIn(f"/etc/flr-runtime/{d}/policy.json", keep)
            for name in ("local-domains", "local-ips", "vpn-required", "direct-essential", "game-platforms", "vpn-services",
                         "roscom-direct-domains", "roscom-direct-ips"):
                self.assertIn(f"/etc/flr-runtime/{d}/rulesets/{name}.json", keep)


if __name__ == "__main__":
    unittest.main()
