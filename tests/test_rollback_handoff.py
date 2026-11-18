"""Run rollback/init shell glue with every native effect redirected to spies.

FLR_TEST_BASE_REF permits the same focused regressions against an earlier
tracked source revision without changing the checkout or executing payloads.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


def source(name):
    ref = os.environ.get('FLR_TEST_BASE_REF')
    path = 'runtime/openwrt/' + name
    if ref:
        return subprocess.check_output(['git', 'show', ref + ':' + path], cwd=ROOT, text=True)
    return (ROOT / path).read_text()


class RollbackGlue(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.state = self.root / 'state'
        self.state.mkdir()
        self.boot = self.root / 'boot'
        self.boot.write_text('test-boot\n')
        self.calls = self.root / 'calls'
        self.release = self.root / 'release'
        self.controller = self.root / 'controller'
        self.controller.write_text('''#!/bin/sh
printf '%s|%s|%s\\n' "$1" "${2:-}" "${3:-}" >> "$FLR_CALLS"
case "$1:${2:-}" in
 rollback-token:arm)
  n=0; [ ! -f "$FLR_STATE/count" ] || n=$(cat "$FLR_STATE/count")
  n=$((n+1)); echo "$n" > "$FLR_STATE/count"
  echo "test-boot generation-$n 1180" > "$FLR_STATE/rollback.pending"
  cat "$FLR_STATE/rollback.pending"
 ;;
 rollback-token:recover) [ "$FLR_RECOVER" != failure ] || exit 1; [ "$FLR_RECOVER" != recovered ] || echo recovered ;;
 rollback:*) [ "$FLR_RECOVER" != failure ] || exit 1 ;;
esac
exit 0
''')
        self.controller.chmod(0o700)
        sleeper = self.root / 'sleep'
        sleeper.write_text('''#!/bin/sh
while [ ! -f "$FLR_RELEASE" ]; do /bin/sleep 0.01; done
''')
        sleeper.chmod(0o700)
        self.env = dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ['PATH'],
                        FLR_CALLS=str(self.calls), FLR_STATE=str(self.state),
                        FLR_RELEASE=str(self.release), FLR_RECOVER='none')
        self.addCleanup(lambda: self.release.touch())

    def script(self, name):
        text = source(name).replace('/usr/sbin/flr-controller', str(self.controller))
        text = text.replace('/etc/flr-runtime', str(self.state))
        text = text.replace('/proc/sys/kernel/random/boot_id', str(self.boot))
        text = text.replace('/tmp/flr-rollback.log', str(self.root / 'rollback.log'))
        path = self.root / name
        path.write_text(text)
        return path

    def test_each_watcher_dispatches_its_own_immutable_generation(self):
        script = self.script('flr-runtime.rollback')
        for _ in range(2):
            subprocess.run(['/bin/sh', str(script), 'arm'], env=self.env, check=True,
                           capture_output=True, timeout=3)
        self.release.touch()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            calls = self.calls.read_text()
            if calls.count('rollback-token|expire|') == 2:
                break
            time.sleep(.01)
        self.assertIn('rollback-token|expire|test-boot generation-1 1180', calls)
        self.assertIn('rollback-token|expire|test-boot generation-2 1180', calls)
        self.assertNotIn('rollback|--backup|', calls)

    def test_failed_or_completed_boot_recovery_never_starts_runtime(self):
        init = self.script('flr-runtime.init')
        for outcome in ('failure', 'recovered', 'none'):
            marker = self.state / 'rollback.pending'
            marker.write_text('other-boot generation-1 1180\n')
            self.calls.write_text('')
            env = dict(self.env, FLR_RECOVER=outcome)
            result = subprocess.run(['/bin/sh', '-c',
                '. "$1"; disable() { echo DISABLED; }; procd_open_instance() { echo LIVE; }; procd_set_param() { :; }; '
                'procd_close_instance() { :; }; start_service', 'test', str(init)],
                env=env, capture_output=True, text=True, timeout=3)
            if outcome == 'none':
                self.assertEqual(result.returncode, 0)
                self.assertIn('LIVE', result.stdout)
            else:
                self.assertNotIn('LIVE', result.stdout)
                if outcome == 'recovered':
                    self.assertIn('DISABLED', result.stdout)
            if outcome == 'failure':
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(marker.exists(), 'failed recovery deleted retry token')
            self.assertIn('rollback-token|recover|', self.calls.read_text())


if __name__ == '__main__':
    unittest.main()
