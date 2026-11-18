# Engine updates with a compatibility lock

Status: design and v1 implementation.

The engine version policy (AGENTS.md): engines track upstream stable releases
for as long as every connection keeps working. This document adds the other
half: **a release that breaks a working connection is locked out, and the
last compatible version stays installed.** Compatibility is defined by the
connections that matter: the router's connections
to the main server.

`docs/ENGINE-POLICY.ru.md` still governs what goes into a firmware image
(CI-time resolution of the latest compatible versions). This document
covers updates between images.

## 1. What is updated, where, and how

| Engine | Host | Source | Update between images |
| --- | --- | --- | --- |
| sing-box (patched random-SNI build) | router | FLR engine channel (CI build) | yes: canary, then binary swap |
| xray, wstunnel, nfqws2 | router | FLR engine channel (official arm64 assets verified in CI) | only when a connection uses the engine |
| kmod-amneziawg, amneziawg-tools | router | firmware image only | no: tied to the kernel ABI |
| flr-controller | router | runtime build, installed with `flr-rollback arm` / `confirm` | no: owner-driven |
| hysteria (server) | main server, backup server | upstream GitHub release + `hashes.txt` | yes: canary, idle promotion, router-traffic check |
| amneziawg DKMS module | main server | rebuilt by DKMS when a kernel is installed | no: kernel gate only |
| caddy | main server | Debian security updates (unattended-upgrades) | outside this system |
| xray (server) | backup server | upstream release + `.dgst` | possible via config; not enabled |

## 2. The compatibility lock

Router: `/etc/flr-runtime/engines.lock.json` (kept across sysupgrade).
Server: `/var/lib/flr-engine/lock.json`. Same schema:

```json
{
  "format": "flr-compat-lock-v1",
  "engines": {
    "sing-box": {
      "current":   {"version": "1.14.4-flr-random-sni.1", "sha256": "…", "installed_at": "…"},
      "last_good": {"version": "…", "sha256": "…", "installed_at": "…"},
      "candidate": null,
      "blocked":   [{"version": "…", "sha256": "…", "reason": "canary: main-server Hysteria2 HTTPS 0/8388608 bytes", "at": "…"}],
      "hold": false
    }
  }
}
```

Rules:

- **Forward only through the gate.** `current` changes only to a candidate
  that passed every check for every connection in scope.
- **Blocked is permanent.** A failed version is never retried automatically.
  A newer release is a new candidate, so an upstream fix is picked up.
  `unblock` is the owner's override.
- **Hold.** `hold` freezes an engine at `current`.
- **Last good.** The previous binary is kept for one-command rollback.
- **Reconcile.** On every run the updater compares `current` with the
  binary actually installed (version and sha256). A sysupgrade replaces
  `/usr/bin` but not the lock; the lock then follows the image's binary and
  keeps the blocked list.

## 3. Router: `flr-controller engine`

Config `/etc/flr-runtime/engine-update.json`; absent or `"enabled": false`
means nothing runs. Default `"mode": "check"` reports and changes nothing;
`"apply"` is the owner's opt-in.

One cycle:

1. Fetch `channel.json` (and `channel.json.sig` when a public key is
   configured) **through the tunnel only**: bound to `flr_awg` when AWG is
   healthy, otherwise through the proxy slot's SOCKS. Never via plain WAN.
2. Pick a candidate per engine: version differs from `current`, not blocked,
   not on hold, published at least `soak_hours` ago (default 72).
3. Download into a fresh private directory (`os.MkdirTemp`, 0700, created
   with `O_EXCL|O_NOFOLLOW`; only that directory is removed afterwards) and
   verify size and sha256 against the manifest. The token, if any, is sent
   only to the configured channel origin, never across a redirect to another
   host; asset URLs are validated before any fetch.
4. Static checks: AArch64 static ELF; exactly one `sing-box version <v>`
   line whose version equals the manifest's exactly; `flr-capabilities`
   reports at least every capability the current binary reports (random SNI
   cannot silently disappear; if the installed binary's capabilities cannot
   be read, the cycle is inconclusive); `check -c` accepts each scoped
   connection's canary config.
   Scope must be complete: if any eligible connection cannot be classified,
   resolved or rendered (or needs a sidecar the canary cannot exercise), the
   cycle is inconclusive rather than deciding on a smaller scope.
5. **Canary, the compatibility gate.** For each connection in scope (default:
   every enabled auto-eligible connection that uses the engine; or only those
   whose server is in `scope_servers`, e.g. the main server's address): render the
   production config, keep the outbound exactly (its sockets carry the bearer
   mark and leave via WAN, like production), replace the inbounds with one
   SOCKS listener on 127.0.0.1:10891, start the candidate, and measure
   through it: an HTTPS download of at least 8 MiB within 60 s plus at least
   three UDP DNS answers. This is the project's acceptance rule, measured
   from the router's WAN. The port must be free before the start, and the
   listening socket must belong to the candidate process (inode in
   `/proc/net/tcp` matched against the child's file descriptors) before and
   after the probes, so another listener can never pass for the candidate.
   The canary never touches nft, routes, the firewall, the production slot or
   its ports.
6. Decide. A candidate failure (in `check -c` or the traffic canary) is
   followed by the *current* binary as a control and then the candidate
   again: only candidate-fail, control-pass, candidate-fail blocks the
   version, with the exact reason. A control failure, a passing retry,
   cancellation or a timeout is "inconclusive" and blocks nothing. Download
   and checksum errors are retried next cycle. In apply
   mode, a full pass promotes: the current binary becomes
   `/usr/bin/<engine>.last-good`, the candidate is written to a temporary
   name, synced and renamed over `/usr/bin/<engine>`.
7. **No session is touched.** A running engine keeps its old inode; the new
   binary is used the next time the controller starts a process (failover,
   a new warm reserve, or a controller restart).

Commands: `status`, `check`, `run`, `hold`, `unhold`, `unblock`,
`rollback` (also blocks the version rolled back from), and `loop` (run by
procd every `interval_hours`, jittered). `min_controller` in the manifest is
validated but not enforced yet: the running controller reports its version
in a different form (`0.6-runtime`).

## 4. Server: `flr-engine-update`

Python 3 standard library, systemd timer, config
`/etc/flr-engine/config.json`, default mode `check`. Code and install notes:
`server/engine-update/`.

One cycle for Hysteria:

1. Newest stable upstream release at least `soak_days` old (default 3), newer
   than `current`, not blocked, not on hold.
2. Verify sha256 against upstream `hashes.txt` and the GitHub asset digest,
   the ELF architecture, and the `version` output.
3. **Canary instance**: a second Hysteria process on `canary_port` with a
   copy of the production config must report "server up and running".
   Production is not touched.
4. **Promote only when the router is connected but idle**: Hysteria's
   traffic-stats API must show the router's user online with probe-level
   traffic only (at most 256 KiB in two minutes). A router that is offline,
   or that does not keep a warm reserve yet, defers promotion: without the
   router there is nobody to prove compatibility. Without the stats API,
   `promote_when: "idle"` always defers; `"any"` is the explicit override.
5. Promote, restart, check the service.
6. **Router-traffic verification**: within 20 minutes the router's user must
   move at least 4 KiB in each direction through the new version, or stay
   online with traffic in both directions for three consecutive polls (stats
   API). The router's warm reserve guarantees this traffic: it keeps a
   Hysteria session up and probes it every 30-60 s. Online but no traffic:
   the new version cannot serve the router, so roll back to `last_good`,
   restart and block the version. Never connected during the window: roll
   back but do not block ("inconclusive"); the version is retried later.
   A canary or rollback failure that the current binary shares is likewise
   inconclusive, never a block.
7. **Kernel gate** (read-only): for every installed kernel, is there an
   amneziawg module? `safe_to_reboot` is false when the newest kernel has
   none. The tool never reboots and never runs apt; it reports, so the owner
   reboots only into a kernel that brings the tunnel up.

Without the stats API the server can only check that the service starts;
the lock then records `"evidence": "service-only"`.

## 5. CI engine channel

Workflow `engine-channel.yml` (weekly and on demand) builds the patched
sing-box through the same pinned path as the image, runs the existing
compatibility checks, and publishes:

- an immutable release `engines-<YYYYMMDD>-<run>` with the binaries and
  `channel.json`;
- a rolling release `engines-stable` whose `channel.json` always points at
  the newest dated release. Routers poll
  `…/releases/download/engines-stable/channel.json`.

`channel.json` (`flr-engine-channel-v1`): `channel`, `generated_at`,
`published_at`, `source_commit`, and per engine `version`, `package_version`,
`asset`, `url`, `sha256`, `size`, `capabilities`, `min_controller`,
`contract_sha256`, and optional `api_url` (REST asset URL for private
repositories).

The build job runs with read-only permissions; a separate publish job writes
releases. When the engine digests equal those already on `engines-stable`,
nothing is published, so `published_at` (and the routers' soak period) does
not reset every week.

## 6. Trust

- Manifest and binaries come over HTTPS from GitHub, through the tunnel.
  Every binary is pinned by sha256 in the manifest.
- Optional ed25519 signature over `channel.json`. Generating the signing key
  is a separate, owner-approved step; until then signatures are off and
  `require_signature` stays false.
- GitHub does not serve `…/releases/download/…` URLs of a private
  repository to token-authenticated clients; private assets must be fetched
  from the REST asset URL (`api_url` in the manifest) with
  `Accept: application/octet-stream`. The router updater v1 fetches `url`
  only, so it needs a public channel: a public FLR repository, or a separate
  public repository that holds only the engine releases (open-source
  binaries, no secrets). Fetching `api_url` with a token is a planned v2
  step.
- Server engines are verified against upstream checksums. Hysteria's
  canonical repository is `HyNetworks/hysteria` (the former
  `apernet/hysteria`, which redirects); the similarly named `HyNetwork`
  organisation is deprecated and must not be used.

## 7. Safety properties

- The router updater never restarts, signals or reconfigures a running
  engine, never touches nft, routes or the firewall, and never downloads
  outside the tunnel.
- The server updater promotes Hysteria only while the router is connected
  but idle (probe-level traffic), and rolls back on its own when the router
  cannot use the new version.
- Both default to report-only. Switching either to apply mode, and
  installing the server timer, are owner decisions.
- AWG is never updated in place on either side: the router's module comes
  with the image; the server's module is guarded by the kernel gate.
