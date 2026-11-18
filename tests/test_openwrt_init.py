"""Exercise FLR scripts with the pinned rc.common link-management functions."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
FUNCTIONS = PROJECT / 'tests/fixtures/openwrt-init-enable-disable.sh'
spec = importlib.util.spec_from_file_location('buildlib', PROJECT / 'ci/buildlib.py')
lib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lib)


class OpenWrtInitLinks(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.rc = self.root / 'etc/rc.d'
        self.rc.mkdir(parents=True)
        (self.root / 'etc/init.d').mkdir()
        for service in ('flr-proxies', 'flr-runtime'):
            shutil.copyfile(PROJECT / 'runtime/openwrt' / (service + '.init'),
                            self.root / 'etc/init.d' / service)

    def action(self, service, action):
        # Same definition/source/dispatch order as rc.common. Only link actions
        # run here: no procd, native engine, SDK or target-device execution.
        env = dict(os.environ, IPKG_INSTROOT=str(self.root))
        for name in ('START', 'STOP', 'USE_PROCD', 'BASH_ENV'):
            env.pop(name, None)
        result = subprocess.run([
            'bash', '-c', '. "$1"; initscript="$2"; . "$initscript"; "$3"',
            'init-link-test', str(FUNCTIONS), str(self.root / 'etc/init.d' / service), action,
        ], env=env, capture_output=True, text=True)
        self.assertEqual(result.stderr, '')
        return result.returncode

    def test_image_finalization_does_not_enable_retired_service(self):
        # default_postinst and prepare_rootfs both invoke enable in the build
        # root; neither executes first-boot uci-defaults there. Repeated calls
        # must leave the image acceptable to the unchanged production guard.
        for _ in range(2):
            self.assertIn(self.action('flr-proxies', 'enable'), (0, 1))
            self.assertEqual(list(self.rc.iterdir()), [])
            lib.check_private_state(self.root)

    def test_runtime_still_autoenables(self):
        self.assertEqual(self.action('flr-runtime', 'enable'), 0)
        self.assertEqual({p.name for p in self.rc.iterdir()},
                         {'S95flr-runtime', 'K10flr-runtime'})
        for link in self.rc.iterdir():
            self.assertEqual(os.readlink(link), '../init.d/flr-runtime')
        lib.check_private_state(self.root)

    def test_migration_disable_removes_old_priorities_without_touching_runtime(self):
        self.assertEqual(self.action('flr-runtime', 'enable'), 0)
        for name in ('S90flr-proxies', 'K11flr-proxies', 'S80flr-proxies', 'K20flr-proxies'):
            (self.rc / name).symlink_to('../init.d/flr-proxies')
        # Existing uci-defaults and runtime migration invoke this inherited
        # disable action, which removes historical links without START/STOP.
        self.assertEqual(self.action('flr-proxies', 'disable'), 0)
        self.assertEqual(self.action('flr-proxies', 'disable'), 0)
        self.assertEqual({p.name for p in self.rc.iterdir()},
                         {'S95flr-runtime', 'K10flr-runtime'})
        lib.check_private_state(self.root)


if __name__ == '__main__':
    unittest.main()
