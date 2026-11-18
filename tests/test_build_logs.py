import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
import io

spec=importlib.util.spec_from_file_location('build_logs',Path(__file__).resolve().parents[1]/'ci/build_logs.py')
logs=importlib.util.module_from_spec(spec)
spec.loader.exec_module(logs)

class BuildLogs(unittest.TestCase):
    def test_failure_retains_log_exit_and_bounded_tail(self):
        with tempfile.TemporaryDirectory() as temp, redirect_stdout(io.StringIO()) as captured:
            command=[sys.executable,'-c','import sys; [print("line"+str(i)) for i in range(1000)]; sys.exit(7)']
            with self.assertRaises(subprocess.CalledProcessError) as error:
                logs.run_logged(command,temp,'sdk')
            self.assertEqual(error.exception.returncode,7)
            self.assertEqual(len((Path(temp)/'sdk.log').read_text().splitlines()),1000)
            self.assertLessEqual(len(captured.getvalue().splitlines()),121)
            self.assertEqual(json.loads((Path(temp)/'sdk.json').read_text())['return_code'],7)
    def test_signing_private_blocks_omitted(self):
        with tempfile.TemporaryDirectory() as temp, redirect_stdout(io.StringIO()):
            text='-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\nvisible'
            logs.run_logged([sys.executable,'-c','print('+repr(text)+')'],temp,'image')
            data=(Path(temp)/'image.log').read_text()
            self.assertNotIn('secret',data)
            self.assertIn('visible',data)
