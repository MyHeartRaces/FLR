#!/usr/bin/env python3
"""Compose a generic image overlay. Client credentials are intentionally absent."""

from buildlib import load_resolved_lock

import json
import os
from pathlib import Path
import shutil
import sys

project, builder, output = map(Path, sys.argv[1:4])
lock = load_resolved_lock(project, output, os.environ.get("GIT_COMMIT"))
for apk in (output / "packages").glob("*.apk"):
    shutil.copyfile(apk, builder / "packages" / apk.name)
overlay = Path("/tmp/flint-files")
if overlay.exists():
    shutil.rmtree(overlay)
shutil.copytree(project / "files", overlay)
share = overlay / "usr/share/flint-vpn"
shutil.copytree(project / "policy", share / "policy", dirs_exist_ok=True)
metadata = {
    "project": "flr", "stage": "runtime-image",
    "git_commit": os.environ.get("GIT_COMMIT", "local-unpublished"),
    "runtime_controller_implemented": True, "routing_dns_failover_implemented": True,
    "router_contacted": False, "boot_runtime_tested": False, "recovery_tested": False,
    "isp_bypass_tested": False, "direct_bypass_enabled": False, "vpn_enabled": False,
    "openwrt": lock["openwrt"], "awg": lock["awg"], "sing_box": lock["sing_box"], "runtime": lock["runtime"], "native": lock["native"], "engine_resolution": lock["engine_resolution"],
}
(share / "build.json").write_text(json.dumps(metadata, indent=2) + "\n")
(output / "build-info.json").write_text(json.dumps(metadata, indent=2) + "\n")
selection = lock["packages"] + ["-" + p for p in lock["remove_packages"]]
(output / "package-selection.txt").write_text(" ".join(selection) + "\n")
(builder / ".config").write_text((builder / ".config").read_text().replace(
    "# CONFIG_SIGNATURE_CHECK is not set", "CONFIG_SIGNATURE_CHECK=y"
))
if "CONFIG_SIGNATURE_CHECK=y" not in (builder / ".config").read_text():
    raise ValueError("ImageBuilder signature verification must be enabled")
