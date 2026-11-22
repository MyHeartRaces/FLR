# flr-engine-update

Server-side engine auto-updater with a compatibility lock, for the personal
FLR VPS servers (the main server and any backup server). One Python 3.11+ script, standard
library only. Replaces the bash prototype.

It updates the Hysteria2 server binary to the latest compatible stable
release, keeps the last known good version, and blocks proven compatibility
regressions. It also reports, read-only, whether
the AmneziaWG DKMS module exists for the kernel the server will boot next.

It never runs apt or dpkg, never reboots, never touches the firewall or the
port-hopping nftables table, and never prints the stats secret.

## Files

| File | Purpose |
| --- | --- |
| `flr-engine-update` | the tool |
| `config.example.json` | example config (a main server; other servers differ only in values) |
| `flr-engine-update.service`, `.timer` | hardened oneshot, every 2 h (+0-20 min random) |
| `tests/test_engine_update.py` | offline unit tests |

## Qualification and promotion

Check mode reports eligible upstream versions without staging or qualifying
them. Apply mode keeps the production service running while it downloads an
eligible stable release and verifies the asset checksum, digest when supplied,
ELF architecture and version. The default release soak is three days.

Apply mode requires the qualification config below, explicit restart
permission and authenticated loopback production stats. With
`promote_when: "idle"`, the updater measures production traffic for the
configured router user first. The router must be online and its total traffic
growth must stay within `idle_max_bytes` (default 256 KiB over two minutes).
Busy, offline or unavailable production stats defer promotion. The
`promote_when: "any"` setting skips the idle measurement.

The updater starts a candidate Hysteria process from a private copy of the
production configuration with a separate UDP bind and authenticated loopback
stats port. It verifies both sockets belong to the candidate process and asks
the router to transfer at least 8 MiB over HTTPS within 60 seconds and receive
at least three UDP DNS answers through that listener. The candidate's
dedicated counters for the router user must grow in both directions and show
at least 8 MiB of growth in one direction. A failing candidate only
enters the compatibility block list if the current version qualifies on the
same staging endpoint and the candidate fails again. Missing or stale
receipts, configuration changes, and shared failures are inconclusive.

A passed canary authorizes a single maintenance restart within its receipt
window. Idle mode checks production traffic growth during qualification
before replacement and again before restart. The updater records the installing
stage, saves the last-good binary, and atomically replaces the production
binary. An expired receipt stops the restart. It verifies the
restarted process and its production listeners, repeats the same router
probes against the final endpoint, and checks production counters. The
existing warm-reserve traffic check then observes continued traffic for the
router user. Decreasing counters start a new measurement baseline. A missing
final receipt, changed listener, changed binary, unavailable stats or missing
warm traffic restores last good and leaves the release eligible to retry.
A service startup failure blocks the release when the restored service is
healthy. An interrupted install reconciles the recorded last-good process and
binary. If the original process still owns the production listeners, the
updater restores the binary on disk without interrupting that process.

### Private qualification configuration

Leave `qualification` as `null` to keep check-only operation. The following
example belongs inside `engines.hysteria` in the server's private config.

```json
{
  "command": ["/usr/local/libexec/flr-qualify-router"],
  "router_build": "1111111111111111111111111111111111111111",
  "profile_revision": "2222222222222222222222222222222222222222222222222222222222222222",
  "relay_id": "relay-example",
  "address": "203.0.113.10",
  "bind_address": "192.0.2.10",
  "stats_port": 25414,
  "production_port": 443,
  "allow_restart": false
}
```

- `command` is an absolute executable and argument vector. Use a trusted
  local bridge to the router's authenticated management channel, such as
  existing pinned-host SSH with runner credentials readable by the service.
  Command output is limited to one receipt and the invocation to 100 seconds.
- The bridge can forward stdin and stdout to the router command
  `/usr/sbin/flr-controller engine qualify-relay <connection-id> <relay-id> <candidate-port>`.
  Fix these arguments in the trusted bridge. Use the build's 40-character
  Git revision and the fixed-port saved connection's 64-character revision
  for `router_build` and `profile_revision`.
- `address` is the router-visible IPv4 address. `bind_address` is the
  corresponding explicit local IPv4 interface address. Both the configured
  `production_port` and the existing `canary_port` are UDP ports. The
  production port must match the actual serving socket. The candidate port
  needs an existing, scoped firewall rule that allows the qualifying router.
- `stats_port` is a free loopback TCP port separate from production
  `stats_url`. Production stats must be on `http://127.0.0.1:<port>` and
  use the configured secret file. The candidate stats secret is generated
  per process. Both sets of counters are keyed by the configured router
  auth user.
- `allow_restart` permits the same-endpoint maintenance restart after the
  gates pass. Set it for a window when a restart can safely drop sessions.
- The production YAML must use block-style top-level keys, a static readable
  tunnel certificate and key, and no extra masquerade HTTP(S) listeners.
  Keep certificate paths absolute and the cover site independently serving.

The command receives a JSON object on stdin with `format`
(`flr-relay-attempt-v1`), `nonce`, `router_build`, `candidate_sha256`,
`profile_revision`, `relay_id`, `listener` (`candidate` or `production`),
`address`, `port` and `expires_at` (UTC RFC 3339). The trusted router
bridge validates the router build, private profile digest or revision, the
relay and port allowlist, and expiry before probing. On stdout it returns
`{"attempt": ..., "outcome": ..., "https_bytes": ..., "https_ms": ..., "udp_answers": ...}`.
`attempt` must exactly echo the input. Use `passed`, `failed`, or
`inconclusive` for `outcome`. A receipt is scoped to a single invocation.
The router's candidate profile retains the production TLS, obfuscation and
protocol options for the intended test, and binds the bearer to the WAN.

## Lock file

`/var/lib/flr-engine/lock.json`, mode 0600, written atomically (temp file,
fsync, rename). Format `flr-compat-lock-v1`; under `engines.hysteria`:

- `current`: `{version, sha256, installed_at}` of the installed binary.
- `last_good`: the newest version that passed its verification. It is the
  rollback target. During `verifying` it is the previous version; afterwards it
  equals `current`. Copies are kept as `<binary>.last-good-<ver>` (only the
  versions the lock references are kept).
- `candidate`: `null`, or `{version, sha256, stage, started_at, baseline}`.
  Stages: `ready` (binary verified, waiting for idle and qualification), `installing`
  (crash marker; the next run restores last good without blocking),
  `verifying` (installed, waiting for router traffic; `baseline` holds the
  tx/rx counters, `progress` the poll state). `qualification` holds the
  matched attempts and production socket ownership during the promotion.
  `idle_check` records the last idle decision.
- `last_attempt`: `null` or `{version, result, reason, at}` of the last failed
  attempt (`blocked`, `rolled-back`, `inconclusive`, `environment-failure`).
- `blocked`: `[{version, sha256, reason, at}]`. A blocked version is never
  retried; newer versions stay eligible. Clear with `unblock`.
- `hold`: freezes the engine (no new installs).
- `evidence`: `router-traffic` for a verified promotion. Older state or
  the initial installed binary can have `service-only` evidence.

Concurrent runs are excluded with `flock` on `lock.json.flock` (exit 5).

## Commands and exit codes

```
flr-engine-update [--config PATH] status
                                  check               # strictly read-only report of what `run` would do
                                  run                 # honors config "mode"
                                  hold|unhold <engine>
                                  unblock <engine> <version>
                                  rollback <engine>   # restore last_good, block current
                                  gate
```

`mode` is `check` (default; report only) or `apply`. Engine is `hysteria`.

`check` takes the run lock (exit 5 if a run is active) but writes nothing but
the `.flock` file: no lock.json write, no crash recovery, no restarts, no
verification polling, no idle measurement. It reports `current`, any candidate
stage and whether an update is available. `run` in `check` mode behaves the
same unless a promotion is already `installing`/`verifying`, which it still
finishes. `status` takes no lock and is read-only too.

| Code | Meaning |
| --- | --- |
| 0 | success, nothing to do, deferred, or update available (check) |
| 1 | usage, config, I/O or unexpected error; `unblock` of an unknown version |
| 2 | a version was blocked and/or rolled back, or environment failure after rollback |
| 3 | network or verification failure, or an inconclusive result (rolled back if needed, never blocked) |
| 4 | `gate`: newest installed kernel has no AWG module, unsafe to reboot |
| 5 | another run holds the lock |

## Kernel gate

`gate` lists kernels under `gate.modules_root` (only directories that contain
`modules.dep` or `kernel/`, so leftovers of removed kernels are ignored) and
reports for each whether `amneziawg.ko[.xz|.zst|.gz]` exists under
`updates/dkms` or `extra`, plus `reboot_required` and
`safe_to_reboot` (module present for the newest installed kernel, ordered by
the numbers in the name). When unsafe it prints a suggested command for the
owner (for example `dkms autoinstall -k <kernel>`); it never runs it. `run`
also logs a warning when the gate is unsafe. Note the newest kernel by number
is a heuristic for "boots next": check GRUB's default if cloud and non-cloud
kernels are both installed.

## Install (owner runs these after approving the installation)

Nothing here is done by the tool or its tests.

```sh
sudo install -m 755 flr-engine-update /usr/local/sbin/flr-engine-update
sudo install -d -m 700 /etc/flr-engine /var/lib/flr-engine
sudo install -m 600 config.example.json /etc/flr-engine/config.json
sudoedit /etc/flr-engine/config.json          # set stats_url, router_user, binary, unit
# stats secret: the same value as trafficStats.secret in server.yaml
sudoedit /etc/flr-engine/stats.secret && sudo chmod 600 /etc/flr-engine/stats.secret
sudo install -m 644 flr-engine-update.service flr-engine-update.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo flr-engine-update status                 # read-only first look
sudo flr-engine-update check                  # dry run against GitHub
sudo flr-engine-update gate
```

Enable in `"mode": "check"` for unattended reports. To promote an update,
configure the paired gate and enable `"apply"` for an approved window.

```sh
sudo systemctl enable --now flr-engine-update.timer
```

Requirements on the server: `trafficStats` enabled in the Hysteria YAML
(listen address must match `stats_url`, `router_user` is the auth user id the
router logs in with), and a free `canary_port` (UDP, not inside the hopping
range, if you use port hopping). Each server uses its own config file with
its unit, binary and config path; nothing is hardcoded to a host.

## Risks and notes

- A probe-only warm reserve counts as idle (step 6); tune `idle_max_bytes` if
  probes exceed 256 KiB per window. An offline router never promotes.
- A restart drops Hysteria sessions. Games run on AWG, so this is acceptable
  only while AWG is primary; the idle gate exists to protect other users.
- The canary config edit is textual and requires exactly one top-level
  `listen:` key. The staged process uses the same Hysteria protocol and TLS
  configuration, with separate UDP and stats sockets.
- The service needs root for `systemctl restart`; hardening limits writes to
  `/var/lib/flr-engine` and `/usr/local/bin`. The canary child inherits this
  sandbox: the unit allows `AF_UNIX AF_INET AF_INET6 AF_NETLINK`, TLS cert/key
  and `server.yaml` must be readable outside `/home`.
