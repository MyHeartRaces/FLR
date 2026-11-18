#!/bin/sh
set -eu
cd /builder
test -d scripts
python3 /work/ci/prepare-sdk.py /work /builder
./scripts/feeds update base packages luci
# Register core dependency metadata (including libmnl) before dependent feeds.
./scripts/feeds install -a -p base
./scripts/feeds install -a -p packages
./scripts/feeds install -a -p luci
make defconfig
# LuCI's language menu depends on luci-base; the SDK need not select that
# target package. Select this vendored translation explicitly for packaging.
make -j2 CONFIG_AUTOREMOVE= CONFIG_PACKAGE_luci-i18n-amneziawg-ru=m \
  package/kmod-amneziawg/compile package/amneziawg-tools/compile \
  package/luci-proto-amneziawg/compile package/flint-sing-box/compile \
  package/flr-runtime/compile package/luci-app-flr/compile \
  package/flint-xray/compile package/flint-wstunnel/compile package/flint-zapret2/compile V=s
python3 /work/ci/sdk-output.py /builder /output
