# FLR

OpenWrt firmware and a Go controller that turn a GL.iNet Flint 2 (GL-MT6000)
into a permanent home VPN router. It connects to your own VPS over
AmneziaWG (primary) and Hysteria2 (reserve) and is tuned for low, stable
latency in online games.

Кратко по-русски: прошивка и контроллер для домашнего VPN-роутера Flint 2;
основной канал — AmneziaWG в ядре, резерв — Hysteria2; документация в основном
на русском (`docs/*.ru.md`).

## Features

- Kernel AmneziaWG 3.1 as the primary path; no userspace hop for games.
- Hysteria2 (Gecko) reserve through sing-box, with a fresh random SNI for every
  new connection (pinned, patched sing-box 1.14.4 build).
- Session-preserving failover: healthy connections keep their channel, only new
  connections move; the reserve stays warm so switching is make-before-break.
- DoH DNS inside the tunnel, no silent fallback to the ISP resolver.
- Names routed directly (private overlay) resolve over Yandex DoH through the
  WAN first, the ISP resolvers only as fallback, so the ISP can neither read
  nor rewrite them.
- Kill switch: when every channel is down the VPN class is blocked while local
  and direct traffic keep working.
- One LuCI "Proxy" menu: auto, protocol-only or a specific connection, with
  per-protocol ordering of servers.
- Compat-locked engine updates: a release that breaks a working connection is
  blocked and the last compatible version stays ([docs/ENGINE-UPDATES.md](docs/ENGINE-UPDATES.md)).
- Reproducible builds on pinned OpenWrt 25.12 containers, feeds and kernel ABI.
- Neutral default routing: local destinations stay local, everything else goes
  through the VPN. Your own routing lists are a private overlay.

## Build

Everything is built in GitHub Actions; nothing is installed on your computer.

- `.github/workflows/build.yml` builds the firmware image. Run it manually, or
  push a `main` commit whose message starts with `build: final image`.
- `.github/workflows/runtime.yml` ("Flint runtime") tests and builds the Go
  controller on every push.

Local checks that need no extra dependencies:

```sh
python3 -m unittest discover -s tests -v
python3 -m unittest discover -s server/engine-update/tests -v
```

## Install

See [docs/INSTALL.ru.md](docs/INSTALL.ru.md) for fetching and verifying a build
and preparing the router, [docs/RUNTIME.ru.md](docs/RUNTIME.ru.md) for the
controller, and [docs/SERVER.ru.md](docs/SERVER.ru.md) for the VPS side. Back up
the router and keep a recovery path before flashing anything
([docs/RECOVERY-0.6.ru.md](docs/RECOVERY-0.6.ru.md)).

## Private policy overlay

This repository ships no routing lists, DNS settings or connection profiles.
You install your own policy on the router under `/etc/flr-runtime/policy`;
see [policy/README.md](policy/README.md). Server profiles (keys, endpoints) are
imported on the device and never belong in Git.

## Documentation

- [Architecture](docs/architecture.ru.md) and [router 0.6](docs/ROUTER-0.6.ru.md)
- [Connection management and reserve](docs/PROXY-MANAGEMENT.ru.md)
- [Router controller API](docs/ROUTER-API.md)
- [Router/server architecture for 0.7](docs/MAX-PACKAGE.md)
- [Engine policy](docs/ENGINE-POLICY.ru.md) and [engine updates](docs/ENGINE-UPDATES.md)
- [Random-SNI sing-box client](client/sing-box-random-sni/README.md)
- [Third-party components](THIRD_PARTY.md)

## Status

Version 0.7 is in development. The project grew out of the author's earlier
VPN projects and shares no code or infrastructure with them.
