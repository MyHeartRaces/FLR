# flr-engine-update

Server-side engine auto-updater with a compatibility lock, for the personal
FLR VPS servers (the main server and any backup server). One Python 3.11+ script, standard
library only. Replaces the bash prototype.

It updates the Hysteria2 server binary to the latest compatible stable
release, keeps the last known good version, and permanently blocks a version
that breaks the home router's connection. It also reports, read-only, whether
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

## What one cycle does

1. Bootstrap: if the lock is new, read the installed version from
   `<binary> version` and record it as current and last good.
2. If a previous promotion is still `verifying`, evaluate it first (this runs
   even under `hold`, because it finishes work already done).
3. Pick the newest non-draft, non-prerelease release that is older than
   `soak_days`, newer than current, and not blocked. (`hold` stops here.)
4. Verify before installing: sha256 from `hashes.txt` (basename match), the
   API `digest` when present, ELF magic and `e_machine`, `<bin> version`
   reports the tag, download at most 64 MiB. Any failure aborts the cycle,
   changes nothing and is retried next run (exit 3). It does not block.
5. Canary: run the candidate as a second process with a temp copy of the
   production config whose top-level `listen:` is set to `canary_port`
   (and whose `trafficStats:` block is dropped so it cannot grab the stats
   port). Wait up to `canary_timeout_s` for `ready_pattern`. If it fails, the
   same canary is run with the CURRENT binary as a control. Control passes:
   the candidate is blocked. Control also fails: the environment is at fault
   (port in use, sandbox, certificate), so the result is `inconclusive`, the
   version is not blocked and is retried next run. The production instance and
   firewall are untouched.
6. Idle gate (`promote_when: "idle"`): the router user must be online and
   quiet. `/online` must show `router_user` >= 1 (the warm reserve session)
   and its tx+rx growth over `idle_window_s` (default 120; two `/traffic`
   samples, waiting inline) must be at most `idle_max_bytes` (default 262144).
   Real failover traffic moves far more. Router offline (online 0), busy, stats
   API unreachable, or no stats API configured all DEFER (stage `ready`, retried
   next run). The measured bytes and decision (`idle`, `busy`, `offline`,
   `unavailable`, `unconfigured`) are stored in `candidate.idle_check` and shown
   by `status`; with no stats API `status` adds `promotion_note`. Apply mode
   therefore effectively needs the stats API unless `promote_when` is `"any"`,
   the explicit override that skips the check (and records `service-only`
   evidence when stats are absent).
7. Promote: keep `<binary>.last-good-<ver>`, atomic install, `systemctl
   restart <unit>`, wait `restart_wait_s`, require `is-active` and the ready
   line in `journalctl -u <unit> --since <restart time>`. Failure restores the
   last-good binary, restarts and blocks the candidate.
8. Router verification: record the router user's `/traffic` tx/rx right after
   restart. Within `verify_window_minutes` the version passes when both tx and
   rx grow by at least `verify_min_bytes` (default 4096; probes are tens of KB
   per window), OR when `verify_consecutive_polls` (3) consecutive polls show
   the router online with growth in both directions. With `verify_inline`
   (default) the run polls every 30 s; otherwise later runs evaluate it
   (progress is kept in `candidate.progress`; growth is checked before expiry).
   At expiry:
   - router was online (or moved bytes) but not enough traffic: restore last
     good, restart, BLOCK ("no router traffic within window");
   - router never connected (online stayed 0, no growth): INCONCLUSIVE. Restore
     last good and restart but do not block; reason "inconclusive: router not
     connected" goes to `last_attempt`; the version is eligible again next run;
   - stats API unreachable throughout: keep the version on `service-only`
     evidence.
   If the restored last-good binary also fails to start, the candidate is not
   blocked and the result is `environment-failure`.

Compatibility evidence relies on the router keeping the Hysteria2 reserve
"warm" so a compatible server sees authenticated router traffic within minutes.

## Lock file

`/var/lib/flr-engine/lock.json`, mode 0600, written atomically (temp file,
fsync, rename). Format `flr-compat-lock-v1`; under `engines.hysteria`:

- `current`: `{version, sha256, installed_at}` of the installed binary.
- `last_good`: the newest version that passed its verification. It is the
  rollback target. During `verifying` it is the previous version; afterwards it
  equals `current`. Copies are kept as `<binary>.last-good-<ver>` (only the
  versions the lock references are kept).
- `candidate`: `null`, or `{version, sha256, stage, started_at, baseline}`.
  Stages: `ready` (verified and canaried, waiting for idle), `installing`
  (crash marker; the next run restores last good without blocking),
  `verifying` (installed, waiting for router traffic; `baseline` holds the
  tx/rx counters, `progress` the poll state). `idle_check` records the last
  idle decision.
- `last_attempt`: `null` or `{version, result, reason, at}` of the last failed
  attempt (`blocked`, `rolled-back`, `inconclusive`, `environment-failure`).
- `blocked`: `[{version, sha256, reason, at}]`. A blocked version is never
  retried; newer versions stay eligible. Clear with `unblock`.
- `hold`: freezes the engine (no new installs).
- `evidence`: how the current version was accepted, `router-traffic` or
  `service-only` (no stats API configured, or it was unreachable).

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

Enable only when satisfied. Start in `"mode": "check"`; switch to `"apply"`
when you want updates installed:

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
- The canary config edit is textual: it needs exactly one top-level
  `listen:` line and does not rewrite other listeners (for example
  `masquerade.listenHTTP`).
- The service needs root for `systemctl restart`; hardening limits writes to
  `/var/lib/flr-engine` and `/usr/local/bin`. The canary child inherits this
  sandbox: the unit allows `AF_UNIX AF_INET AF_INET6 AF_NETLINK`, TLS cert/key
  and `server.yaml` must be readable outside `/home`, and an `acme:` storage
  directory in the YAML must be added to `ReadWritePaths`.
