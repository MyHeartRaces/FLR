"""Tests for flr-awg-roam. A fake nft records calls; nothing touches a host."""
import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "flr-awg-roam"
SHELLS = [s for s in ("sh", "dash", "busybox") if shutil.which(s)]


class AWGRoamTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        self.log = self.dir / "nft.log"
        self.present = self.dir / "present"
        fake = self.dir / "nft"
        fake.write_text(
            "#!/bin/sh\n"
            f'echo "ARGS $*" >> "{self.log}"\n'
            'if [ "$1" = "-f" ]; then cat >> "%s"; touch "%s"; exit 0; fi\n' % (self.log, self.present)
            + f'if [ "$1" = "list" ]; then [ -e "{self.present}" ]; exit $?; fi\n'
            + f'if [ "$1" = "delete" ]; then rm -f "{self.present}"; exit 0; fi\n'
            "exit 0\n"
        )
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC)

    def tearDown(self):
        self.tmp.cleanup()

    def run_script(self, *args, shell="sh", fake=True):
        env = dict(os.environ)
        env["PATH"] = (str(self.dir) + os.pathsep if fake else "") + env.get("PATH", "")
        command = [shell, str(SCRIPT), *args] if shell != "busybox" else ["busybox", "sh", str(SCRIPT), *args]
        return subprocess.run(command, capture_output=True, text=True, env=env)

    def nft_log(self):
        return self.log.read_text() if self.log.exists() else ""

    def test_dry_run_prints_ruleset_without_nft(self):
        for shell in SHELLS:
            result = self.run_script("--ports", "40000-40999", "--listen", "51820", "--dry-run", shell=shell)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("table inet flr_awg_roam {", result.stdout)
            self.assertIn("type nat hook prerouting priority dstnat; policy accept;", result.stdout)
            self.assertIn("udp dport 40000-40999 redirect to :51820", result.stdout)
            self.assertTrue(result.stdout.startswith("table inet flr_awg_roam\ndelete table inet flr_awg_roam\n"))
        self.assertEqual(self.nft_log(), "")

    def test_apply_is_one_atomic_replacement_and_idempotent(self):
        for _ in range(2):
            result = self.run_script("--ports", "40000-40009", "--listen", "27000")
            self.assertEqual(result.returncode, 0, result.stderr)
        log = self.nft_log()
        self.assertEqual(log.count("ARGS -f -"), 2)
        self.assertEqual(log.count("udp dport 40000-40009 redirect to :27000"), 2)
        self.assertEqual(log.count("delete table inet flr_awg_roam"), 2)

    def test_remove(self):
        result = self.run_script("--remove")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("not present", result.stdout)
        self.run_script("--ports", "40000-40009", "--listen", "27000")
        result = self.run_script("--remove")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("removed", result.stdout)
        self.assertIn("ARGS delete table inet flr_awg_roam", self.nft_log())
        dry = self.run_script("--remove", "--dry-run", "--table", "roam_test")
        self.assertEqual(dry.stdout, "delete table inet roam_test\n")

    def test_single_port_and_custom_table(self):
        result = self.run_script("--ports", "40000", "--listen", "51820", "--table", "awg_roam2", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("udp dport 40000 redirect to :51820", result.stdout)
        self.assertIn("table inet awg_roam2 {", result.stdout)

    def test_rejects_invalid_input(self):
        cases = [
            ("--ports", "1023-2000", "--listen", "51820"),
            ("--ports", "40000-65536", "--listen", "51820"),
            ("--ports", "41000-40000", "--listen", "51820"),
            ("--ports", "40000-50000", "--listen", "51820"),
            ("--ports", "40000-40100-40200", "--listen", "51820"),
            ("--ports", "4e4-40100", "--listen", "51820"),
            ("--ports", "040000-40100", "--listen", "51820"),
            ("--ports", "40000-40999", "--listen", "40500"),
            ("--ports", "40000-40999", "--listen", "0"),
            ("--ports", "40000-40999", "--listen", "70000"),
            ("--ports", "40000-40999"),
            ("--ports", "40000-40999", "--listen", "51820", "--table", "bad-name"),
            ("--ports", "40000-40999", "--listen", "51820", "--table", "x; flush ruleset"),
            ("--remove", "--ports", "40000-40999"),
            ("--unknown",),
        ]
        for args in cases:
            result = self.run_script(*args, "--dry-run")
            self.assertNotEqual(result.returncode, 0, args)
            self.assertEqual(result.stdout, "", args)
        self.assertEqual(self.nft_log(), "")


if __name__ == "__main__":
    unittest.main()
