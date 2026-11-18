#!/usr/bin/env python3
"""Resolve latest compatible stable engines into an immutable per-build lock."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys

from awg_release import MODULE_REPO, TOOLS_REPO, resolve_pair, decode_blob
from engine_compat import NativeContracts, require_ci, check_xray_schema, check_xray_ws_source
from engine_releases import OfficialAPI, stable, select_compatible, validate_asset, Incompatible, NotFound, REPOSITORIES, asset_names, validate_selection
from sing_box_source import load_local


def resolve_source_engine(pin, contracts, folder):
    built = load_local(pin, folder)
    release = {'tag_name': 'v' + pin['version'], 'asset_kind': 'source-build'}
    evidence = contracts.validate('sing_box', release, built['archives']['arm64']['data'], built['archives']['amd64']['data'])
    item = {'version': pin['version'], 'release_tag': release['tag_name'], 'asset_kind': 'source-build',
            'source_pin': copy.deepcopy(pin), 'source_build': built['receipt'], 'receipt_sha256': built['receipt_sha256'],
            'archive': built['archives']['arm64']['name'], 'sha256': built['archives']['arm64']['sha256'],
            'validation_asset': {key: built['archives']['amd64'][key] for key in ['name', 'sha256']},
            'compatibility': evidence, 'requested_tag': release['tag_name'], 'selected_tag': release['tag_name'], 'rejected': []}
    validate_selection('sing_box', item)
    for arch, key in [('arm64', 'arm64_binary_sha256'), ('amd64', 'host_binary_sha256')]:
        if evidence.get(key) != built['receipt']['targets']['linux/' + arch]['sha256']:
            raise ValueError('native source validation used a different target binary')
    if evidence.get('payload_sha256', {}).get('usr/share/licenses/sing-box/LICENSE') != built['license_sha256']:
        raise ValueError('native source validation used a different license')
    return item


def releases(api, repository, reference):
    candidates=api.releases(repository)
    if reference not in [r['tag_name'] for r in candidates]:
        fallback=api.json(repository+'/releases/tags/'+reference)
        if not stable([fallback]):
            raise Incompatible('reference build release is no longer an official stable candidate')
        candidates.append(fallback)
    return candidates


def main():
    require_ci()
    project=Path(__file__).resolve().parents[1]
    output=project/'out'
    output.mkdir(exist_ok=True)
    source_bytes=(project/'build/versions.lock.json').read_bytes()
    reference=json.loads(source_bytes)
    lock=copy.deepcopy(reference)
    contracts=NativeContracts(output/'engine-contracts',output/'engine-validation')
    api=OfficialAPI(os.environ.get('GITHUB_TOKEN'))
    record={'format':'flr-engine-resolution-v1','source_commit':os.environ['GITHUB_SHA'],
            'source_lock_sha256':hashlib.sha256(source_bytes).hexdigest(),
            'contract_sha256':contracts.digest,'policy':'latest-compatible-stable',
            'hardware_tested':False,'end_to_end_tested':False,'components':{}}
    licenses = {}
    selected_source = resolve_source_engine(reference['sing_box'], contracts, output / 'sing-box')
    record['components']['sing_box'] = selected_source
    lock['sing_box'].update({key: selected_source[key] for key in ['release_tag', 'archive', 'sha256']})
    for component,repository in REPOSITORIES.items():
        if component == 'sing_box':
            continue
        previous=reference['sing_box'] if component=='sing_box' else reference['native'][component]
        candidates=releases(api,repository,'v'+previous['version'])
        checked={}
        def check(candidate):
            version=candidate['tag_name'].removeprefix('v')
            arm_name,host_name=asset_names(component,version)
            arm_asset,arm_data=api.asset(candidate,repository,arm_name)
            if host_name==arm_name:
                host_asset,host_data=arm_asset,arm_data
            else:
                host_asset,host_data=api.asset(candidate,repository,host_name)
            source_schema = {}
            if component == 'xray':
                texts = {}
                # gRPC's retained settings live in a separate matching-release file.
                for path in ['infra/conf/transport_internet.go','infra/conf/grpc.go','transport/internet/websocket/dialer.go']:
                    try:
                        blob = api.json(repository + '/contents/' + path + '?ref=' + candidate['tag_name'])
                    except NotFound as error:
                        # The release moved the config schema this build checks: it is not
                        # a proven-compatible candidate, so an older release is selected.
                        raise Incompatible('xray ' + candidate['tag_name'] + ' no longer has ' + path) from error
                    data = decode_blob(blob, blob.get('sha', ''))
                    texts[path] = data.decode()
                    source_schema[path] = {'git_blob':blob['sha'], 'sha256':hashlib.sha256(data).hexdigest()}
                # Reject a known missing schema before any native subprocess.
                check_xray_schema('\n'.join(texts.values()))
                check_xray_ws_source(texts['infra/conf/transport_internet.go'], texts['transport/internet/websocket/dialer.go'])
            evidence=contracts.validate(component,candidate,arm_data,host_data)
            if source_schema:
                evidence['source_schema'] = source_schema
            if component == 'zapret2':
                blob = api.json(repository + '/contents/docs/LICENSE.txt?ref=' + candidate['tag_name'])
                data = decode_blob(blob, blob.get('sha', ''))
                if b'Permission is hereby granted, free of charge' not in data or b'MIT License' not in data:
                    raise Incompatible('zapret selected release no longer supplies the supported MIT license')
                licenses[candidate['tag_name']] = data
                evidence['payload_sha256']['usr/share/licenses/zapret2/LICENSE'] = hashlib.sha256(data).hexdigest()
                evidence['license_git_blob'] = blob['sha']
            checked[candidate['tag_name']]={'version':version,'release_tag':candidate['tag_name'],'archive':arm_name,
                'url':arm_asset['browser_download_url'],'sha256':validate_asset(arm_asset,repository,candidate['tag_name']),
                'validation_asset':{'name':host_name,'url':host_asset['browser_download_url'],
                    'sha256':validate_asset(host_asset,repository,candidate['tag_name'])},
                'compatibility':evidence}
        chosen,rejected=select_compatible(candidates,check)
        selected=checked[chosen['tag_name']]
        validate_selection(component, selected)
        if component == 'zapret2':
            path = output / 'engine-licenses/zapret2/LICENSE'
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(licenses[chosen['tag_name']])
        record['components'][component]={'requested_tag':candidates[0]['tag_name'],'selected_tag':chosen['tag_name'],
                                        'rejected':rejected,**selected}
        lock['native'][component].update({k:selected[k] for k in ('version','release_tag','archive','url','sha256')})
    tool_releases=releases(api,TOOLS_REPO,'v'+reference['awg']['tools_version'])
    module,tools,rejected=resolve_pair(api,'v'+reference['awg']['module_version'],tool_releases)
    for name,selected in [('awg_module',module),('awg_tools',tools)]:
        record['components'][name]={**selected,'level':'official-git-blob-and-paired-uapi; SDK ABI/netifd required',
                                    'rejected':rejected,'hardware_tested':False}
    lock['awg'].update(module_version=module['version'],module_commit=module['commit'],tools_version=tools['version'],tools_commit=tools['commit'])
    lock['engine_resolution']=record
    # Publish only after every chosen component passed its applicable pre-SDK gate.
    (output/'source-versions.lock.json').write_bytes(source_bytes)
    path=output/'resolved-versions.lock.json'
    path.write_text(json.dumps(lock,indent=2)+'\n')
    print(json.dumps({'resolved_lock':str(path),'selected':{name:item.get('selected_tag',item.get('tag_name')) for name,item in record['components'].items()},
                      'compatibility':'native config/CLI and source UAPI; SDK pending; no end-to-end qualification'}))


if __name__=='__main__':
    try:
        main()
    except Exception as error:
        output = Path(__file__).resolve().parents[1] / 'out/logs'
        output.mkdir(parents=True, exist_ok=True)
        (output / 'engine-resolution-failure.json').write_text(json.dumps({
            'source_commit': os.environ.get('GITHUB_SHA'), 'stage': 'engine-resolution',
            'error_type': type(error).__name__, 'error': str(error)[-4096:],
            'hardware_tested': False, 'end_to_end_tested': False}, indent=2)+'\n')
        raise
