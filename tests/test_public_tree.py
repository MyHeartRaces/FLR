import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("check_public_tree", ROOT / "ci" / "check_public_tree.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


class PublicTreeTest(unittest.TestCase):
    def test_repository_is_clean(self):
        self.assertEqual(check.scan(ROOT), [])

    def scan_text(self, name, text):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
            return check.scan(Path(d))

    def test_refuses_private_material(self):
        key = "PrivateKey = " + "A" * 43 + "="
        cases = {
            "docs/a.md": key,
            "docs/b.md": "vless://" + "1" * 36 + "@vpn.real-host.net:443?security=reality",
            "docs/d.md": "connect to " + ".".join(("8", "34", "12", "9")),
            "docs/e.md": "https://admin:hunter2pass@" + "panel.real-host.net/",
            "docs/f.md": "token ghp_" + "a" * 36,
        }
        for name, text in cases.items():
            with self.subTest(name=name):
                self.assertTrue(self.scan_text(name, text), name)

    def test_allows_examples(self):
        for text in ("vless://uuid@vpn.example.com:443", "198.51.100.7", "https://user:password@example.com/", "1.1.1.1"):
            with self.subTest(text=text):
                self.assertEqual(self.scan_text("docs/x.md", text), [])

    def test_private_needles_file(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / ".private-needles").write_text("# live names\nvpn.owner-private.example\n")
            (root / "docs").mkdir()
            (root / "docs" / "a.md").write_text("host vpn.owner-private.example")
            self.assertTrue(check.scan(root))
            (root / "docs" / "a.md").write_text("host vpn.example.com")
            self.assertEqual(check.scan(root), [])

    def test_private_files_refused(self):
        self.assertTrue(self.scan_text("files/etc/flr-runtime/custom-rules.json", "{}"))
        self.assertTrue(self.scan_text("keys/router.key", "x"))


if __name__ == "__main__":
    unittest.main()
