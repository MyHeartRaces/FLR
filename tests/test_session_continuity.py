import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
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

    def test_fixture_uses_document_addresses_without_changing_the_image_policy(self):
        module = self.module()
        original = ROOT / 'policy'
        local = Path('rulesets/local-ips.json')
        installed = (original / local).read_bytes()
        with TemporaryDirectory() as directory:
            fixture = Path(directory) / 'policy'
            module.copy_fixture_policy(original, fixture)
            doc = json.loads((fixture / local).read_text())
            self.assertNotIn('198.51.100.0/24', doc['rules'][0]['ip_cidr'])
            self.assertIn('192.168.0.0/16', doc['rules'][0]['ip_cidr'])
            self.assertEqual((original / local).read_bytes(), installed)
            self.assertEqual((original / 'policy.json').read_bytes(), (fixture / 'policy.json').read_bytes())

    def test_extended_conntrack_family_prefix_keeps_exact_channel_marks(self):
        module = self.module()
        self.assertTrue(callable(getattr(module, 'validate_conntrack_affinity', None)), 'extended conntrack parser is missing')
        target = module.UNMATCHED
        lines = [
            f'ipv4     2 tcp      6 119 TIME_WAIT src=192.168.8.2 dst={target} sport=30002 dport=9090 src={target} dst=172.16.10.1 sport=9090 dport=30002 [ASSURED] mark=285212672 use=1',
            f'ipv4     2 udp      17 29 src=192.168.8.2 dst={target} sport=30001 dport=9090 src={target} dst=192.168.8.2 sport=9090 dport=30001 mark=553648128 use=1',
            f'ipv4     2 udp      17 29 src=192.168.8.2 dst={target} sport=30003 dport=9090 src={target} dst=172.16.10.1 sport=9090 dport=30003 mark=285212672 use=1',
            f'ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.8.2 dst={target} sport=30000 dport=9090 src={target} dst=192.168.8.2 sport=9090 dport=30000 [ASSURED] mark=553648128 use=1',
        ]
        module.validate_conntrack_affinity('\n'.join(lines))
        for bad in ['\n'.join(lines).replace('mark=553648128', 'mark=1553648128'), '\n'.join(lines[:-1]), '\n'.join(lines).replace(f'dst={target}', f'dst={module.EXPLICIT_VPN}')]:
            with self.assertRaises(ValueError): module.validate_conntrack_affinity(bad)

    def test_anchored_conntrack_proves_stable_nat_identity(self):
        module = self.module()
        target = module.UNMATCHED
        peer = module.ANCHOR_CLIENT
        anchor = module.ANCHOR_SOURCE
        rows = [
            f'ipv4 2 tcp 6 431999 ESTABLISHED src={peer} dst={target} sport=30000 dport=9090 src={target} dst={anchor} sport=9090 dport=40000 mark=1358954496 use=1',
            f'ipv4 2 udp 17 29 src={peer} dst={target} sport=30001 dport=9090 src={target} dst={anchor} sport=9090 dport=40001 mark=1358954496 use=1',
        ]
        output = '\n'.join(rows)
        original = module.continuity_tuples(output)
        self.assertEqual(original, {'tcp': (anchor, 40000, target, 9090), 'udp': (anchor, 40001, target, 9090)})
        self.assertNotEqual(module.continuity_tuples(output.replace('dport=40001', 'dport=40002')), original)
        for bad in [rows[0], output.replace('mark=1358954496', 'mark=285212672'), output.replace(f'dst={anchor}', 'dst=172.16.11.1')]:
            with self.assertRaises(ValueError):
                module.continuity_tuples(bad)
