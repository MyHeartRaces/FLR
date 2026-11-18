#!/usr/bin/env python3
"""Run pinned OpenWrt containers on an existing GitHub-hosted Docker runtime."""

from build_logs import run_logged
from buildlib import load_resolved_lock
from engine_compat import require_ci
import importlib.util

import argparse
import json
import os
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", choices=["sdk", "image", "all"], default="all")
    args = parser.parse_args()
    require_ci()
    project = Path(__file__).resolve().parents[1]
    output = project / "out"
    lock = load_resolved_lock(project, output, os.environ.get("GITHUB_SHA"))
    if args.stage in ['all','image']:
        spec=importlib.util.spec_from_file_location('flr_affinity_gate',project/'ci/session-continuity.py')
        gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
        receipt=output/'affinity/receipt.json'
        if not receipt.is_file() or receipt.stat().st_size>16384:
            raise ValueError('matching kernel qualification required before image')
        gate.validate_receipt(json.loads(receipt.read_text()),os.environ.get('GITHUB_SHA'))
    output.mkdir(exist_ok=True)
    output.chmod(0o777)  # The official container runs as buildbot (UID 1000).
    stages = ["sdk", "image"] if args.stage == "all" else [args.stage]
    for stage in stages:
        key = "sdk_container" if stage == "sdk" else "imagebuilder_container"
        image = lock["openwrt"][key]
        if not re.fullmatch(r"ghcr\.io/openwrt/(sdk|imagebuilder)@sha256:[0-9a-f]{64}", image):
            raise ValueError("unpinned or unexpected container reference")
        script = "sdk-build.sh" if stage == "sdk" else "image-build.sh"
        command = [
            "docker", "run", "--rm", "--platform", "linux/amd64",
            "--volume", f"{project}:/work:ro", "--volume", f"{output}:/output",
            "--env", "SOURCE_DATE_EPOCH=" + str(lock["openwrt"]["source_date_epoch"]),
            "--env", "GIT_COMMIT=" + os.environ.get("GITHUB_SHA", "local-unpublished"),
            image, "/bin/sh", "/work/ci/" + script,
        ]
        run_logged(command, output / "logs", stage)


if __name__ == "__main__":
    main()
