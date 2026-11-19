#!/usr/bin/env python3
"""Export custom packages, never the SDK's private signing key."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from buildlib import sha256, check_elf, RUNTIME_FILES, check_sing_box_capabilities, check_native_lock, load_resolved_lock

sdk, output = map(Path, sys.argv[1:3])
destination = output / "packages"
destination.mkdir(parents=True, exist_ok=True)
lock = load_resolved_lock(Path("/work"), output, os.environ.get("GIT_COMMIT"))
check_native_lock(lock)
names = ["kmod-amneziawg", "amneziawg-tools", "luci-proto-amneziawg", "luci-i18n-amneziawg-ru", "flint-sing-box", "flr-runtime", "luci-app-flr", "luci-i18n-flr-ru", "flint-xray", "flint-wstunnel", "flint-zapret2"]
packages = {}
for name in names:
    paths = list((sdk / "bin").rglob(name + "-*.apk"))
    if len(paths) != 1:
        raise ValueError(f"expected one {name} APK, found {len(paths)}")
    source = paths[0]
    shutil.copyfile(source, destination / source.name)
    packages[source.name] = sha256(source)
    apk = sdk / "staging_dir/host/bin/apk"
    data = subprocess.check_output([str(apk), "adbdump", "--format", "json", str(source)])
    (destination / (source.name + ".json")).write_bytes(data)
original = next((sdk / "build_dir").rglob("flint-sing-box-" + lock["sing_box"]["version"] + "/sing-box"))
payloads = [p for p in (sdk / "build_dir").rglob("flint-sing-box/usr/bin/sing-box") if "/ipkg-" in str(p)]
if len(payloads) != 1:
    raise ValueError("expected one final sing-box package payload")
binary = payloads[0]
check_elf(binary, static=True)
check_sing_box_capabilities(binary)
report = {"resolved_lock_sha256": sha256(output / "resolved-versions.lock.json"),
          "sdk_feeds_sha256": sha256(output / "sdk-feeds.conf"),
          "sdk_base_feed": (output / "sdk-feeds.conf").read_text().splitlines()[0],
          "source_commit": os.environ.get("GIT_COMMIT", "local-unpublished"), "packages": packages, "sing_box_binary_sha256": sha256(binary),
          "sing_box_source_binary_sha256": sha256(original),
          "sing_box_source_receipt_sha256": sha256(output / "sing-box/receipt.json")}
if sha256(binary) != sha256(original):
    raise ValueError('packaging changed approved sing-box payload')
if sha256(binary) != lock['engine_resolution']['components']['sing_box']['compatibility']['arm64_binary_sha256']:
    raise ValueError('packaged sing-box differs from compatibility-checked ARM64 payload')
report['native_original_binary_sha256'] = {}
report['native_archive_sha256'] = {}
report['payload_sha256'] = {}
for component, item in lock['native'].items():
    archive = sdk / 'dl' / item['archive']
    if sha256(archive) != item['sha256']:
        raise ValueError('native release archive hash mismatch: ' + component)
    report['native_archive_sha256'][component] = sha256(archive)
    payload = 'binaries/linux-arm64/nfqws2' if component == 'zapret2' else component
    originals = list((sdk / 'build_dir').rglob(item['package'] + '-' + item['version'] + '/' + payload))
    if len(originals) != 1:
        raise ValueError('missing original native binary: ' + component)
    check_elf(originals[0], static=True)
    report['native_original_binary_sha256'][component] = sha256(originals[0])
    if sha256(originals[0]) != lock['engine_resolution']['components'][component]['compatibility']['arm64_binary_sha256']:
        raise ValueError('native source differs from compatibility-checked ARM64 payload: ' + component)
for relative in RUNTIME_FILES + [n['binary'] for n in lock['native'].values()] + [
        'usr/share/flr-bypass/lua/' + n + '.lua' for n in ['zapret-lib','zapret-antidpi','zapret-auto']] + [
        'usr/share/licenses/' + n + '/LICENSE' for n in ['sing-box','xray','wstunnel','zapret2']]:
    paths = [p for p in (sdk / 'build_dir').rglob(relative) if '/ipkg-' in str(p)]
    if len(paths) != 1:
        raise ValueError('expected one runtime package payload: ' + relative)
    report['payload_sha256'][relative] = sha256(paths[0])
    if relative in ['usr/sbin/flr-controller'] + [n['binary'] for n in lock['native'].values()]:
        check_elf(paths[0], static=True)
for item in lock['engine_resolution']['components'].values():
    for relative, expected in item.get('compatibility', {}).get('payload_sha256', {}).items():
        if report['payload_sha256'].get(relative) != expected:
            raise ValueError('SDK license/Lua differs from compatible release: ' + relative)
for component, item in lock['native'].items():
    if report['payload_sha256'][item['binary']] != report['native_original_binary_sha256'][component]:
        raise ValueError('packaging changed native binary: ' + component)
if report['payload_sha256']['usr/sbin/flr-controller'] != sha256(Path('/work/out/runtime/flr-controller')):
    raise ValueError('SDK controller differs from tested runtime binary')
(output / "sdk-report.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps({"exported_packages": list(packages)}))
