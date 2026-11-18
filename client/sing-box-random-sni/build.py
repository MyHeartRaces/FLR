#!/usr/bin/env python3
"""Opt-in offline build. No downloads, installation, or protocol execution."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import zipfile

HERE = Path(__file__).resolve().parent
# Patch logic is shared with the CI firmware build (ci/sing_box_patch.py).
sys.path.insert(0, str(HERE.parents[1] / 'ci'))
import sing_box_patch  # noqa: E402

COMMIT = 'c005f35300ce76427dc285481ec5695f5b179cd2'
SOURCE_SHA = '1c4d2b3bf261a8d98e1b026be0bbcddbcb3f53bbca77eb15e8f25f7d4e602e59'
VERSION = '1.14.4-flr-random-sni.1'
CAPABILITY = 'hysteria2-random-sni-per-quic-dial-v1'
TAGS = 'with_quic,with_wireguard,with_utls,with_gvisor'


def sha(data):
    return sing_box_patch.sha(data)


def tree_sha(root):
    return sing_box_patch.tree_sha(root)


def prepare(archive, workspace):
    data = archive.read_bytes()
    if sha(data) != SOURCE_SHA:
        raise ValueError('source archive SHA256 mismatch')
    patch = sing_box_patch.load_patch(HERE, COMMIT)
    if workspace.exists():
        raise ValueError('build workspace must not already exist')
    workspace.mkdir(parents=True, mode=0o700)
    workspace.chmod(0o700)
    try:
        root = sing_box_patch.extract_source(data, COMMIT, workspace)
    except Exception:
        # Archive validation happens before any file is written; drop the empty dir.
        if not any(workspace.iterdir()):
            workspace.rmdir()
        raise
    evidence = sing_box_patch.apply_patch(root, patch)
    receipt = {'format':'flr-custom-client-build-v1', 'upstream_version':'1.14.4',
               'custom_version':VERSION, 'source_commit':COMMIT, 'source_sha256':SOURCE_SHA,
               'original_tree_sha256':evidence['original_tree_sha256'],
               'patch_manifest_sha256':evidence['manifest_sha256'],
               'payload_sha256':evidence['payload_sha256'],
               'patched_tree_sha256':evidence['patched_tree_sha256'], 'capabilities':[CAPABILITY],
               'builder_sha256':sha(Path(__file__).read_bytes()),
               'offline_tests_passed':False, 'hardware_tested':False,
               'tls_or_quic_executed':False, 'artifacts':{}}
    return root, receipt


def run(go, root, env, args, timeout=1200):
    result = subprocess.run([str(go)] + args, cwd=root, env=env,
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        # Build inputs contain no operational profiles, names or credentials.
        raise ValueError('offline Go command failed: ' + ' '.join(args) + '\n' + result.stderr[-16000:])
    return result.stdout


def module_escape(value):
    return ''.join('!' + c.lower() if 'A' <= c <= 'Z' else c for c in value)


def module_evidence(go, root, env, cache):
    """Verify one linked module set for the GOOS/GOARCH already in `env`.

    `go mod verify` attempts to load uncached unused graph modules. This checks
    every selected module's ZIP h1 plus the extracted files instead, offline.
    """
    output = run(go, root, env, ['list','-mod=readonly','-deps','-json','-tags',TAGS,'./cmd/sing-box'])
    decoder = json.JSONDecoder()
    modules = {}
    while output.strip():
        item, end = decoder.raw_decode(output.lstrip())
        output = output.lstrip()[end:]
        module = item.get('Module', {})
        if module.get('Replace'):
            raise ValueError('unexpected module replacement')
        if module.get('Version'):
            modules[(module['Path'], module['Version'])] = module
    sums = {}
    for line in (root/'go.sum').read_text().splitlines():
        name, version, digest = line.split()
        sums[(name, version)] = digest
    evidence = []
    for (name, version), module in sorted(modules.items()):
        archive = cache/'cache/download'/module_escape(name)/'@v'/(module_escape(version)+'.zip')
        if not archive.is_file():
            raise ValueError('linked module archive missing from approved cache: '+name+'@'+version)
        directory = Path(module['Dir'])
        if cache.resolve() not in directory.resolve().parents or directory.is_symlink():
            raise ValueError('module directory outside approved cache')
        prefix = name+'@'+version+'/'
        files = {}
        with zipfile.ZipFile(archive) as source:
            for item in source.infolist():
                if item.is_dir():
                    continue
                path = PurePosixPath(item.filename)
                if not item.filename.startswith(prefix) or '..' in path.parts or path.is_absolute():
                    raise ValueError('unsafe module ZIP')
                if item.filename in files:
                    raise ValueError('duplicate module ZIP entry')
                files[item.filename] = source.read(item)
        lines = ''.join(sha(content)+'  '+path+'\n' for path, content in sorted(files.items()))
        digest = 'h1:'+base64.b64encode(hashlib.sha256(lines.encode()).digest()).decode()
        if sums.get((name, version)) != digest:
            raise ValueError('module ZIP go.sum mismatch: '+name)
        expected = {path[len(prefix):]:content for path, content in files.items()}
        present = {p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file()}
        if present != set(expected):
            raise ValueError('module cache file inventory mismatch: '+name)
        for relative, content in expected.items():
            path = directory/relative
            if path.is_symlink() or path.read_bytes() != content:
                raise ValueError('modified extracted module: '+name+'/'+relative)
        evidence.append({'path':name,'version':version,'go_sum':digest,'archive_sha256':sha(archive.read_bytes())})
    if not evidence:
        raise ValueError('linked dependency evidence missing')
    return evidence


def verify_modules(go, root, env, cache, targets):
    """Audit the linked modules of the host and of every build target.

    Cross-target builds can link platform-only modules that the host audit
    never sees, so each target is audited under its own GOOS/GOARCH before
    any compilation. Evidence stays bound to the host or target that linked
    it, plus a union view for quick comparison across targets.
    """
    evidence = {'host': module_evidence(go, root, env, cache)}
    for target in targets:
        system, arch = target.split('/')
        target_env = {**env, 'GOOS': system, 'GOARCH': arch}
        evidence[target] = module_evidence(go, root, target_env, cache)
    union = {}
    for binding, modules in evidence.items():
        for module in modules:
            key = (module['path'], module['version'])
            entry = union.setdefault(key, {k: module[k] for k in ('path','version','go_sum','archive_sha256')})
            if entry['go_sum'] != module['go_sum'] or entry['archive_sha256'] != module['archive_sha256']:
                raise ValueError('linked module evidence differs between host and target: '+module['path'])
            entry.setdefault('targets', []).append(binding)
    return {'by_target': evidence, 'union': sorted(union.values(), key=lambda m: (m['path'], m['version']))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--workdir', type=Path, required=True)
    parser.add_argument('--go', type=Path)
    parser.add_argument('--module-cache', type=Path)
    parser.add_argument('--targets', default='linux/arm64')
    parser.add_argument('--gocache', type=Path,
                        help='existing build cache to reuse instead of a fresh workdir/gocache')
    parser.add_argument('--prepare-only', action='store_true')
    args = parser.parse_args()
    if not args.prepare_only and (not args.go or not args.module_cache):
        parser.error('--go and --module-cache are mandatory for an offline build')
    root, receipt = prepare(args.archive.resolve(), args.workdir.resolve())
    if not args.prepare_only:
        go, cache = args.go.resolve(), args.module_cache.resolve()
        gocache = args.gocache.resolve() if args.gocache else args.workdir.resolve()/'gocache'
        env = {**os.environ, 'GOPROXY':'off','GOSUMDB':'off','GOTOOLCHAIN':'local',
               'GOENV':'off','GOFLAGS':'','GO111MODULE':'on','CGO_ENABLED':'0',
               'GOMODCACHE':str(cache),'GOCACHE':str(gocache),
               'GOWORK':'off','GOPRIVATE':'','GONOPROXY':'','GONOSUMDB':''}
        # Reset externally supplied cross-compilation settings before host tests.
        env.pop('GOOS', None)
        env.pop('GOARCH', None)
        env.pop('GOEXPERIMENT', None)
        version = run(go, root, env, ['version'], timeout=10).strip()
        if not version.startswith('go version go1.26.8 '):
            raise ValueError('exact existing Go 1.26.8 compiler required')
        receipt['go_version'] = version
        targets = []
        for target in args.targets.split(','):
            if target not in {'linux/arm64','linux/amd64','darwin/arm64','darwin/amd64'}:
                raise ValueError('unsupported explicit build target')
            targets.append(target)
        receipt['linked_modules'] = verify_modules(go, root, env, cache, targets)
        # Run only the offline tests authored here, never upstream protocol tests.
        run(go, root, env, ['test','-mod=readonly','-tags',TAGS,'./protocol/hysteria2','-run','^TestFLR','-count=1'])
        receipt['offline_tests_passed'] = True
        receipt['tags'] = TAGS.split(',')
        receipt['cgo_enabled'] = False
        for target in targets:
            system, arch = target.split('/')
            out = args.workdir.resolve()/('sing-box-'+VERSION+'-'+system+'-'+arch)
            build_env = {**env,'GOOS':system,'GOARCH':arch}
            run(go, root, build_env, ['build','-mod=readonly','-trimpath','-buildvcs=false','-tags',TAGS,
                '-ldflags','-s -w -buildid= -X github.com/sagernet/sing-box/constant.Version='+VERSION,
                '-o',str(out),'./cmd/sing-box'])
            receipt['artifacts'][target] = {'sha256':sha(out.read_bytes()),'size':out.stat().st_size,'filename':out.name}
        for name, expected in [('go.mod','e5f23c00072adeee7285fabe8ea8dab9049ed8ae5e86fbf06b7a033b6126d24c'),
                               ('go.sum','a93ea3b691cdfbba29d49ac63ed8352601306d89625e0abc87e41241434e8592')]:
            if sha((root/name).read_bytes()) != expected:
                raise ValueError('build changed pinned dependency manifest')
        if tree_sha(root) != receipt['patched_tree_sha256']:
            raise ValueError('build changed patched source tree')
    (args.workdir/'receipt.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'receipt':str(args.workdir/'receipt.json'),'artifacts':receipt['artifacts'],
                      'offline_tests_passed':receipt['offline_tests_passed']}))

if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
