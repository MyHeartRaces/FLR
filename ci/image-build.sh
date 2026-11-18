#!/bin/sh
set -eu
cd /builder
test -d scripts
mkdir -p packages
python3 /work/ci/prepare-image.py /work /builder /output
selection=$(cat /output/package-selection.txt)
make image PROFILE=glinet_gl-mt6000 PACKAGES="$selection" FILES=/tmp/flint-files ADD_LOCAL_KEY=1 V=s
python3 /work/ci/inspect-image.py /builder /output /output/resolved-versions.lock.json
