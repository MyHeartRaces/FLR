# sing-box-random-sni — audited optional client build

Deterministic, fail-closed offline build of sing-box 1.14.4
(source commit `c005f35300ce76427dc285481ec5695f5b179cd2`) with the opt-in
Hysteria2 per-QUIC-dial random SNI extension.

## What the patch adds

- `option/hysteria2.go`: top-level outbound field
  `flr_random_sni_suffix` (`*string`, opt-in only).
- `protocol/hysteria2/outbound.go`: when the field is set, the outbound TLS
  config is wrapped before the Hysteria client is constructed.
- `protocol/hysteria2/flr_random_sni.go`: the wrapper. For every new QUIC dial
  (including UDP port hops that open a new session) it draws 16 bytes from
  `crypto/rand`, hex-encodes them as one DNS label, and sets
  `<random>.<suffix>` as the TLS ServerName on a clone of the verified base
  config. Existing session reuse and per-stream behavior are untouched: the
  name is chosen at the dial callback, never cached across dials, and the
  immutable base config, fixed IPv4 endpoint and CA verification stay intact.
  Entropy failure or a repeated name (8 attempts) fails closed.
- `cmd/sing-box/cmd_flr_capabilities.go`: `sing-box flr-capabilities` prints
  `{"version":1,"capabilities":["hysteria2-random-sni-per-quic-dial-v1"]}`.
  The FLR runtime refuses to start a rotation-enabled profile unless the
  installed engine affirms this capability, so a stock engine never silently
  downgrades the profile.

Narrow contract enforced at construction: fixed IPv4 `server`, verified TLS
only (no insecure/utls/reality/ech/engine/disable_sni), Go TLS engine
(`STDClientConfig`) only, and a one-label seed `server_name` ending in
`.<suffix>` so a `*.<suffix>` certificate keeps verifying every rotated name.

## Non-goals

- No downloads, no package installation, no network, DNS, TLS, QUIC or tunnel
  execution. The Go commands below are native compilation/tests only.
- Not compatible with the standard firmware's locked sing-box 1.14.2 build;
  this patch applies only to the recorded 1.14.4 source revision above.

FLR integration also requires the updated runtime in this branch: it imports
the suffix and checks the engine's capability before WAN changes. The locally
built ARM64 companion controller is a separate artifact, not a new firmware
image. Neither component is installed automatically.

## Inputs

- `.ops/maintenance-20261107/sing-box-source.tar.gz`
  (SHA-256 `1c4d2b3bf261a8d98e1b026be0bbcddbcb3f53bbca77eb15e8f25f7d4e602e59`)
- Existing Go 1.26.8 toolchain (`.ops/maintenance-20261107/toolchain/go`)
- Existing module cache (`.ops/maintenance-20261107/gomodcache`)

`patch.json` pins every edited file's before-SHA and every payload SHA;
`build.py` verifies them before touching the workspace and re-verifies the
patched tree, `go.mod`/`go.sum` pins, linked module ZIPs and extracted cache
files after the build. Linked modules are audited separately for the host
and for each requested build target under its own GOOS/GOARCH — cross-target
builds can link platform-only modules (e.g. Linux netlink/nftables) that a
host-only audit never sees, and each of them must still match `go.sum`, the
cached ZIP and the extracted files before any compilation starts. The
receipt records host and per-target evidence plus a union view with the
target binding of every linked module.

## Build

```sh
python3 client/sing-box-random-sni/build.py \
  --archive .ops/maintenance-20261107/sing-box-source.tar.gz \
  --workdir <fresh scratch dir> \
  --go .ops/maintenance-20261107/toolchain/go/bin/go \
  --module-cache .ops/maintenance-20261107/gomodcache \
  --targets linux/arm64
```

`--prepare-only` verifies the archive, manifest anchors and payload digests
without compiling. The build writes `receipt.json` with the source/patch/tree
SHA-256 chain, linked-module evidence, offline test result and artifact
hashes. Installation on a router is a separate, explicit operation.

## Tests

- Wrapper tests (`random_sni_test.go`, names `TestFLR*`): deterministic
  entropy, fake terminal QUIC dial, pure `x509.Certificate` structs — they
  cover rotation at the dial boundary, immutability of the base TLS config,
  retry, concurrent dials, entropy failure, clone sharing, wildcard/one-label
  hostname verification, and rejection of unsupported TLS modes, foreign
  engines and malformed suffixes. No TLS handshake or tunnel is executed.
- `test_builder.py`: behavioral builder checks (corrupt archive rejected
  before workspace mutation).
