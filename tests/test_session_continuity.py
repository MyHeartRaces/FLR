import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

class SessionContinuitySafetyTests(unittest.TestCase):
    def module(self):
        spec = importlib.util.spec_from_file_location('session_continuity', ROOT / 'ci/session-continuity.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_refuses_workstation_before_network_changes(self):
        module = self.module()
        with patch.dict('os.environ', {}, clear=True), patch.object(module.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'disposable CI'):
                module.qualify(Path('/missing-renderer'), Path('/missing-policy'), Path('/missing-output'))
            run.assert_not_called()

    def test_missing_tools_fail_before_creating_namespace(self):
        module = self.module()
        with patch.dict('os.environ', {'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'Linux'}, clear=True), patch.object(module.platform, 'system', return_value='Linux'), patch.object(module.os, 'geteuid', return_value=0), patch.object(module.shutil, 'which', return_value=None), patch.object(module.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'missing kernel qualification tool'):
                module.qualify(Path('/missing-renderer'), Path('/missing-policy'), Path('/missing-output'))
            run.assert_not_called()

    def test_extended_conntrack_family_prefix_keeps_exact_channel_marks(self):
        module = self.module()
        self.assertTrue(callable(getattr(module, 'validate_conntrack_affinity', None)), 'extended conntrack parser is missing')
        lines = [
            'ipv4     2 tcp      6 119 TIME_WAIT src=192.168.8.2 dst=9.9.9.9 sport=30002 dport=9090 src=9.9.9.9 dst=172.16.10.1 sport=9090 dport=30002 [ASSURED] mark=285212672 use=1',
            'ipv4     2 udp      17 29 src=192.168.8.2 dst=9.9.9.9 sport=30001 dport=9090 src=9.9.9.9 dst=192.168.8.2 sport=9090 dport=30001 mark=553648128 use=1',
            'ipv4     2 udp      17 29 src=192.168.8.2 dst=9.9.9.9 sport=30003 dport=9090 src=9.9.9.9 dst=172.16.10.1 sport=9090 dport=30003 mark=285212672 use=1',
            'ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.8.2 dst=9.9.9.9 sport=30000 dport=9090 src=9.9.9.9 dst=192.168.8.2 sport=9090 dport=30000 [ASSURED] mark=553648128 use=1',
        ]
        module.validate_conntrack_affinity('\n'.join(lines))
        for bad in ['\n'.join(lines).replace('mark=553648128', 'mark=1553648128'), '\n'.join(lines[:-1]), '\n'.join(lines).replace('dst=9.9.9.9', 'dst=9.9.9.90')]:
            with self.assertRaises(ValueError): module.validate_conntrack_affinity(bad)
