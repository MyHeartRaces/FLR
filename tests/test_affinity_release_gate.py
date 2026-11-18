import importlib.util
from pathlib import Path
import sys
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'ci'))

class AffinityReleaseGateTests(unittest.TestCase):
    def validator(self):
        spec = importlib.util.spec_from_file_location('session_continuity', ROOT / 'ci/session-continuity.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.validate_receipt

    def test_missing_wrong_source_or_false_claim_cannot_qualify_release(self):
        validate = self.validator()
        valid = dict(qualified=True, source='a'*40, kernel='Linux CI', production_nft_sha256='b'*64,
                     tcp_udp_old_proxy_survived=True, new_flows_awg=True, ready_proxy_reused=True,
                     proxy_process_link_routes_unchanged=True, wan_leak=False, wan_guard_dropped_packets=2,
                     transport_simulation='isolated veth', real_tunnels_tested=False, hardware_tested=False)
        validate(valid, 'a'*40)
        for key, value in [('qualified',False),('source','c'*40),('wan_leak',True),('wan_guard_dropped_packets',0),('hardware_tested',True),('real_tunnels_tested',True),('tcp_udp_old_proxy_survived',1)]:
            with self.subTest(key=key):
                record={**valid,key:value}
                with self.assertRaises(ValueError): validate(record, 'a'*40)
        for missing in valid:
            with self.subTest(missing=missing):
                record=valid.copy();del record[missing]
                with self.assertRaises(ValueError): validate(record, 'a'*40)

    def test_workflow_failure_before_tee_is_not_success(self):
        for name in ['affinity.yml', 'build.yml']:
            text = (ROOT / '.github/workflows' / name).read_text()
            body = text.split('- name: Qualify existing TCP and UDP kernel affinity',1)[1].split('- name:',1)[0]
            explicit = 'shell: bash' in body
            result = subprocess.run(['bash', '-e' + ('o' if explicit else ''), *(['pipefail'] if explicit else []), '-c', 'false | cat'], capture_output=True)
            with self.subTest(workflow=name):
                self.assertNotEqual(result.returncode, 0, 'qualification failure is hidden by tee')
