#!/usr/bin/env python3
"""Prepare the pinned SDK; runs only on the GitHub build worker."""

import json
import os
from buildlib import check_native_lock, check_elf, load_resolved_lock, sha256, sdk_feeds
from pathlib import Path
import shutil
import sys

def prepare_sdk(project, sdk, output, source_commit):
    lock = load_resolved_lock(project, output, source_commit)
    check_native_lock(lock)
    check_elf(project / "out/runtime/flr-controller", static=True)
    definitions = []
    definitions.extend(['FLR_SING_BOX_VERSION:='+lock['sing_box']['version'], 'FLR_SING_BOX_TAG:='+lock['sing_box']['release_tag']])
    # The apk version (e.g. 1.14.4.1) differs from the binary's own version string
    # (1.14.4-flr-random-sni.1); pass it explicitly instead of relying on the
    # Makefile's fallback mapping.
    if lock['sing_box'].get('package_version'):
        definitions.append('FLR_SING_BOX_PACKAGE_VERSION:='+lock['sing_box']['package_version'])
    for name, item in lock['native'].items():
        for field, value in [('VERSION',item['version']),('TAG',item['release_tag']),('ARCHIVE',item['archive']),('SOURCE_URL',item['url'].rsplit('/',1)[0]),('SHA256',item['sha256'])]:
            definitions.append('FLR_' + name.upper() + '_' + field + ':=' + value)
    for name in ['module','tools']:
        definitions.append('FLR_AWG_' + name.upper() + '_VERSION:=' + lock['awg'][name+'_version'])
        definitions.append('FLR_AWG_' + name.upper() + '_COMMIT:=' + lock['awg'][name+'_commit'])
    (sdk / 'flr-engine-lock.mk').write_text('\n'.join(definitions) + '\n')
    feeds = lock["openwrt"]["feeds"]
    (sdk / "feeds.conf").write_text(sdk_feeds((sdk / "feeds.conf.default").read_text(), feeds))
    # The SDK archive/container digest anchors its own base commit; retain it in provenance.
    (output / "sdk-feeds.conf").write_text((sdk / "feeds.conf").read_text())
    for source in (project / "packages").iterdir():
        if source.is_dir():
            shutil.copytree(source, sdk / "package" / source.name, dirs_exist_ok=True)
    engine_source = sdk / 'package/flint-sing-box/src'
    engine_source.mkdir(exist_ok=True)
    for name in ['sing-box', 'LICENSE']:
        shutil.copyfile(project / 'out/sing-box/linux-arm64' / name, engine_source / name)
    license_source = project / 'out/engine-licenses/zapret2/LICENSE'
    expected_license = lock['engine_resolution']['components']['zapret2']['compatibility']['payload_sha256']['usr/share/licenses/zapret2/LICENSE']
    if sha256(license_source) != expected_license:
        raise ValueError('selected zapret license provenance mismatch')
    shutil.copyfile(license_source, sdk / 'package/flint-zapret2/files/LICENSE')
    runtime_source = sdk / "package/flr-runtime/src"
    runtime_source.mkdir(exist_ok=True)
    shutil.copyfile(project / "out/runtime/flr-controller", runtime_source / "flr-controller")
    for path in (project / "runtime/openwrt").iterdir():
        shutil.copyfile(path, runtime_source / path.name)
    (sdk / ".config").write_text("\n".join([
        "CONFIG_TARGET_mediatek=y", "CONFIG_TARGET_mediatek_filogic=y",
        "# CONFIG_ALL is not set", "# CONFIG_ALL_NONSHARED is not set", "# CONFIG_ALL_KMODS is not set",
        "# CONFIG_AUTOREMOVE is not set",  # Retain ELF payloads for post-package verification.
        "CONFIG_PACKAGE_kmod-amneziawg=m", "CONFIG_PACKAGE_amneziawg-tools=y",
        "CONFIG_PACKAGE_luci-proto-amneziawg=y", "CONFIG_PACKAGE_luci-i18n-amneziawg-ru=y",
        "CONFIG_LUCI_LANG_ru=y", "CONFIG_PACKAGE_flint-sing-box=y",
        *["CONFIG_PACKAGE_" + name + "=y" for name in ["flr-runtime", "luci-app-flr", "flint-xray", "flint-wstunnel", "flint-zapret2"]],
        "CONFIG_PACKAGE_luci-i18n-flr-ru=y",
        "CONFIG_SIGNED_PACKAGES=y", "CONFIG_SIGNATURE_CHECK=y", "",
    ]))
    print("SDK configured for pinned AWG, runtime, LuCI and approved native releases")


if __name__ == "__main__":
    prepare_sdk(*map(Path, sys.argv[1:3]), Path("/output"), os.environ.get("GIT_COMMIT"))
