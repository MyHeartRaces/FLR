# FLR: agent context

Shared context for coding agents (Codex, Claude and others). `CLAUDE.md`
imports this file, so edit here and both tools stay in sync.

## What this is

OpenWrt firmware and a Go controller for a permanent home VPN on a GL.iNet
Flint 2 (GL-MT6000) router. The router connects to the owner's own standalone
VPS servers over AmneziaWG (primary) and Hysteria2 (reserve). It is tuned for
low and stable latency in online games and is in daily use. The project grew
out of the owner's earlier VPN projects and shares no code or infrastructure
with them.

## Hard rules

0. **This repository is public.** Never commit private configuration:
   routing/filtration lists, rules, DNS settings, connection profiles, keys,
   live host addresses or the owner's inventory. Private configuration lives in
   the owner's private repository and on the router under
   `/etc/flr-runtime`. Use documentation addresses (203.0.113.0/24,
   198.51.100.0/24) and `example.com` names in docs, tests and examples.
1. **The router is in daily use.** Do not flash, reconfigure, restart services
   on, or install anything on the router without the owner's explicit go-ahead
   for that step. Prepare and verify first, then ask. Preserve the WAN setup,
   saved connections, device policies and recovery path through every change.
   Never write the bootloader, its environment or calibration partitions.
2. **Installing software and enabling encryption each need explicit
   authorization** for the specific action (owner's global rule). That covers
   packages on the router, on any VPS and on the owner's computer, CI-only
   toolchains included. A blanket "do whatever you need on this VPS" granted for
   one server in one session does not carry over.
3. **Permanent tunnel carriers are native AmneziaWG or Hysteria2 only.** TCP
   lanes (VLESS over CDN, SSH relays, WebSocket wrappers) hurt game traffic and
   never carry games automatically. Do not implement or propose them as the main
   route. NaiveProxy is removed and must not come back.
4. **Acceptance means sustained traffic from the home WAN.** A handshake, a few
   pings inside the tunnel, or success from another network proves nothing.
   Require HTTPS transfer plus UDP through the tunnel, measured from the router
   itself.
5. **Measure from the router's WAN, not from a workstation.** The workstation is
   often behind another VPN, which produces false positives. Bind probes to the
   WAN interface and confirm with a packet capture when it matters.
6. **Failover must not kill sessions.** Healthy existing connections keep their
   channel; only new connections move. When the primary recovers, the reserve
   keeps running; the controller must not tear it down on failback.
7. **Engine versions follow latest-compatible, not hard pins.** Binaries track
   upstream stable for as long as all connections keep working. Exception:
   sing-box is a pinned, patched source build (1.14.4 with the random-SNI patch;
   see `docs/ENGINE-POLICY.ru.md`). Updates between images go through the
   compatibility lock in `docs/ENGINE-UPDATES.md`: a version that fails the
   canary against the live connections is blocked for good and the last
   compatible version stays.
8. **Never store or repeat credentials.** The owner may paste passwords and
   tokens in chat; use them for the task and keep them out of tracked files,
   commit messages and replies.

## Layout

| Path | Contents |
| --- | --- |
| `runtime/` | Go controller (module `github.com/MyHeartRaces/FLR/runtime`): `cmd/flr-controller`, `flr-affinity`, `flr-compat`; `internal/` holds policy, dataplane (routes, nftables, marks), dns, health, transport, profile import, socks, rollback, `lan` (LAN discovery), `engineupdate` (compat-locked engine updates). `runtime/internal/policy/testdata/split` is a synthetic test fixture, not a real policy |
| `packages/` | OpenWrt packages: AmneziaWG kmod and tools, LuCI apps, `flint-sing-box`, `flr-runtime`, optional xray, wstunnel, zapret2 |
| `policy/` | Public default policy (local direct, everything else through the VPN) and `README.md` describing the private overlay installed at `/etc/flr-runtime/policy` |
| `client/sing-box-random-sni/` | sing-box extension that picks a fresh wildcard SNI for each new Hysteria connection |
| `ci/`, `build/`, `.github/workflows/` | Reproducible firmware and runtime builds, engine resolution, version locks |
| `files/` | Files baked into the firmware image |
| `tests/` | Python tests for build tooling, firmware contracts, rollback, session continuity |
| `server/` | VPS-side tools: `engine-update/` (compat-locked Hysteria updater with router-traffic verification and an AWG kernel gate) |
| `docs/` | Architecture, router, runtime, proxy-management, recovery and engine-policy guides; server build guide (`SERVER.ru.md`); `MAX-PACKAGE.md` (router and server architecture), `ENGINE-UPDATES.md` |

Most older docs are in Russian; newer ones are in English.

## Commands

```sh
python3 -m unittest discover -s tests -v                       # build and firmware tooling
python3 -m unittest discover -s server/engine-update/tests -v  # VPS engine updater
```

The Go transport packages use Linux-only socket constants and do not build on
macOS. Run Go tests in CI (workflow "Flint runtime") or on a Linux host.
Firmware images are built by `.github/workflows/build.yml`, manually or from a
`main` commit prefixed `build: final image`. Nothing needs to be installed on
a workstation for either.

## Design in brief

- AmneziaWG runs in the router kernel as the primary path. sing-box runs the
  reserve proxy/TUN paths. One controller owns marks, routes, nftables and
  switching; adapters never change global policy on their own.
- Channel order: AWG, then Hysteria2 Gecko automatically. Games never fall to
  a TCP-carried channel automatically.
- One "Proxy" menu in LuCI: auto, protocol-only, or a specific connection,
  with per-protocol ordering of servers.
- Routing lists come from the private overlay; without one, everything except
  local destinations goes through the VPN. A direct SOCKS5 listener on the
  router LAN address serves apps that must use the ISP (for example torrent
  clients).
- DNS: DoH inside the VPN; a separate resolver for direct destinations if the
  overlay defines any; no silent fallback to WAN DNS. The kill switch blocks the
  VPN class when all channels are down while direct and LAN keep working.
- LAN IPv6 is disabled until a full policy exists.
- The LAN (router address and prefix) is read from `br-lan`; nothing assumes a
  fixed subnet.
- Warm reserve: in auto mode the first UDP proxy connection is kept started
  and probed every 30 s while AWG is primary, so failover is make-before-break.

Canonical design: `docs/architecture.ru.md` (historical spec),
`docs/ROUTER-0.6.ru.md`, `docs/PROXY-MANAGEMENT.ru.md`, `docs/RUNTIME.ru.md`,
`docs/RECOVERY-0.6.ru.md`, `docs/MAX-PACKAGE.md`.

## Practical notes

- Do not ask for or commit anything that identifies the owner's servers,
  network or ISP; use placeholders.
- When the owner names a server by address, confirm which host it is in the
  private records before acting. Addresses have been mixed up before.
- If key-based SSH suddenly fails (for example, the workstation locked its
  key), ask the owner to unlock it; do not retry in a loop.
- Leave a short checkpoint in the owner's private notes (not this repository)
  when stopping mid-task.
- Reply to the owner in English.
