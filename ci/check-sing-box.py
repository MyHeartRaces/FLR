#!/usr/bin/env python3
"""Run the real production config matrix with the matching source-built host and check its identity."""
import importlib.util
import json
import os
from pathlib import Path

from engine_compat import NativeContracts, require_ci
from sing_box_source import validate_pin, validate_host_binary


def main():
    require_ci()
    project = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location('flr_resolve_engines', project / 'ci/resolve-engines.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    pin = validate_pin(json.loads((project / 'build/versions.lock.json').read_text())['sing_box'])
    contracts = NativeContracts(project / 'out/engine-contracts', project / 'out/engine-validation')
    item = module.resolve_source_engine(pin, contracts, project / 'out/sing-box')
    # The matching AMD64 binary must report the pinned version and FLR capabilities,
    # otherwise the router controller would refuse flr_random_sni_suffix profiles.
    validate_host_binary(pin, project / 'out/sing-box/linux-amd64/sing-box')
    report = {'source_commit': os.environ['GITHUB_SHA'], 'contract_sha256': contracts.digest,
              'engine': item, 'version': pin['version'], 'package_version': pin['package_version'],
              'capabilities': pin['capabilities'], 'hardware_tested': False, 'end_to_end_tested': False}
    (project / 'out/sing-box-native.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'native_config_cases': len(item['compatibility']['cases']),
                      'report': 'out/sing-box-native.json', 'hardware_tested': False}))


if __name__ == '__main__':
    main()
