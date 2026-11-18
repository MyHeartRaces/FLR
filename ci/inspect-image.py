#!/usr/bin/env python3
"""Inspect the actual firmware before making the release directory available."""

import json
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

from upgrade_archive import check_keep

from buildlib import check_elf, check_manifest, check_sysupgrade, sha256, check_sing_box_capabilities, check_native_lock, check_runtime_root, check_conntrack_accounting, check_queue_modules, load_resolved_lock


def main():
    builder, output, lock_path = map(Path, sys.argv[1:4])
    if lock_path != output / "resolved-versions.lock.json":
        raise ValueError("image inspection must use the exact resolved per-build lock")
    lock = load_resolved_lock(Path("/work"), output, os.environ.get("GIT_COMMIT"))
    check_native_lock(lock)
    affinity_path=output/'affinity/receipt.json'
    if not affinity_path.is_file() or affinity_path.stat().st_size>16384:
        raise ValueError('matching kernel qualification required for release')
    spec=importlib.util.spec_from_file_location('flr_affinity_release',Path('/work/ci/session-continuity.py'))
    gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
    gate.validate_receipt(json.loads(affinity_path.read_text()),os.environ.get('GIT_COMMIT'))
    target = builder / "bin/targets/mediatek/filogic"
    images = list(target.glob("*glinet_gl-mt6000-squashfs-sysupgrade.bin"))
    if len(images) != 1:
        raise ValueError("expected exactly one GL-MT6000 sysupgrade")
    image = images[0]
    host = builder / "staging_dir/host/bin"
    with tempfile.TemporaryDirectory() as temporary:
        temp = Path(temporary)
        metadata_file = temp / "metadata.json"
        subprocess.run([str(host / "fwtool"), "-i", str(metadata_file), str(image)], check=True)
        metadata = json.loads(metadata_file.read_text())
        tar_report = check_sysupgrade(image, metadata, lock)
        manifests = list(target.glob("*.manifest"))
        if len(manifests) != 1:
            raise ValueError("expected exactly one image manifest")
        manifest = manifests[0]
        packages = check_manifest(manifest.read_text(), lock)
        with tarfile.open(image, "r:*") as archive:
            source = archive.extractfile("sysupgrade-glinet_gl-mt6000/root")
            with (temp / "root.squashfs").open("wb") as stream:
                shutil.copyfileobj(source, stream)
        root = temp / "root"
        # The official builder runs without root. Its image has /dev/console;
        # filesystem inspection needs regular payloads, not recreated devices.
        subprocess.run([str(host / "unsquashfs4"), "-no-xattrs", "-no-progress",
                        "-d", str(root), "-excludes", str(temp / "root.squashfs"), "dev"], check=True)
        binary = root / "usr/bin/sing-box"
        check_elf(binary, static=True)
        check_sing_box_capabilities(binary)
        check_elf(root / "usr/bin/awg")
        sdk_report = json.loads((output / "sdk-report.json").read_text())
        if sdk_report.get("resolved_lock_sha256") != sha256(lock_path):
            raise ValueError("SDK/image resolved engine selection differs")
        check_runtime_root(root, lock, sdk_report)
        check_conntrack_accounting(root)
        check_keep(root)
        check_queue_modules(root, lock)
        for component, item in lock["native"].items():
            if sdk_report.get("native_archive_sha256", {}).get(component) != item["sha256"]:
                raise ValueError("native SDK archive provenance missing: " + component)
        if sha256(binary) != sdk_report["sing_box_binary_sha256"]:
            raise ValueError("sing-box in rootfs differs from verified package payload")
        modules = list((root / "lib/modules").rglob("amneziawg.ko"))
        if len(modules) != 1:
            raise ValueError("AWG module missing or duplicated")
        check_elf(modules[0])
        if ("vermagic=" + lock["openwrt"]["kernel"] + " ").encode() not in modules[0].read_bytes():
            raise ValueError("AWG kernel vermagic differs from pinned kernel")
        netifd = (root / "lib/netifd/proto/amneziawg.sh").read_text()
        for field in ["awg_header_protection_key", "awg_content_padding_addition", "awg_random_trailers", "awg_disable_cookies"]:
            if field not in netifd:
                raise ValueError("AWG 3.1 field missing: " + field)
        baseline = (root / "etc/uci-defaults/99-flint-base").read_text()
        if "network.lan.ip6assign='0'" not in baseline or "dhcp.lan.ra='disabled'" not in baseline:
            raise ValueError("LAN IPv6 baseline missing")
        for directory in ["etc/flint-vpn", "etc/sing-box", "etc/amnezia"]:
            if (root / directory).exists():
                raise ValueError("personal VPN configuration unexpectedly included: " + directory)
        build_info = json.loads((root / "usr/share/flint-vpn/build.json").read_text())
        if build_info != json.loads((output / "build-info.json").read_text()) or build_info["git_commit"] != sdk_report["source_commit"]:
            raise ValueError("runtime image source provenance mismatch")
        if build_info["vpn_enabled"] or not build_info["runtime_controller_implemented"]:
            raise ValueError("runtime implementation metadata missing")
        report = {
            "status": "static-image-checks-passed", "sysupgrade": tar_report,
            "metadata": metadata, "kernel_package": packages["kernel"],
            "vpn_packages": {p: packages[p] for p in lock["packages"]},
            "sing_box_sha256": sha256(binary), "awg_module_sha256": sha256(modules[0]),
            "arm64_elf": True, "awg31_netifd": True,
            "personal_credentials_present": False, "router_contacted": False,
            "boot_runtime_tested": False, "recovery_tested": False,
            "routing_dns_failover_implemented": True, "runtime_controller_implemented": True,
            "isp_bypass_tested": False, "direct_bypass_enabled": False,
            "runtime_native_payload_sha256": sdk_report["payload_sha256"],
        }
    # Export after every validation succeeded; the uploader sees nothing on failure.
    release = output / "release"
    if release.exists():
        shutil.rmtree(release)
    release.mkdir()
    shutil.copyfile(image, release / image.name)
    shutil.copyfile(affinity_path, release / "kernel-affinity.json")
    shutil.copyfile(manifest, release / "image.manifest")
    shutil.copyfile(lock_path, release / "versions.lock.json")
    shutil.copyfile(output / "source-versions.lock.json", release / "source-versions.lock.json")
    shutil.copyfile(output / "sdk-report.json", release / "sdk-report.json")
    shutil.copyfile(output / "sdk-feeds.conf", release / "sdk-feeds.conf")
    shutil.copyfile(output / "build-info.json", release / "build-info.json")
    shutil.copytree(output / "packages", release / "packages")
    public_key = builder / "keys/local-public-key.pem"
    if public_key.exists():
        shutil.copyfile(public_key, release / "package-signing-public.pem")
    (release / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    (release / "README.ru.txt").write_text(
        "Образ платформы GL-MT6000. Проверены состав и ABI; загрузка на роутере не тестировалась.\n"
        "Контроллер VPN/DNS/failover включён в образ; при первом запуске VPN выключен. Персональных профилей нет.\n"
        "Не прошивать до отдельного этапа проверки устройства и процедуры восстановления.\n"
        "SHA256SUMS содержит контрольные суммы всех файлов этой выдачи.\n"
    )
    checksums = []
    for path in sorted(release.rglob("*")):
        if path.is_file():
            if "private" in path.name or path.name.endswith(".key"):
                raise ValueError("private signing material in release")
            checksums.append(sha256(path) + "  " + str(path.relative_to(release)))
    (release / "SHA256SUMS").write_text("\n".join(checksums) + "\n")
    print(json.dumps({"image": image.name, "status": report["status"], "sha256": tar_report["sha256"]}))


if __name__ == "__main__":
    main()
