# FLR maximum package: router ↔ server architecture

Status: design. Applies to FLR 0.7 and later. The reference setup is a Flint 2
and one VPS ("the main server"), but nothing here depends on that pair: every
host, port, domain and address is configuration.

## 1. Goals

1. **All traffic through the server.** Every household flow leaves via the
   server unless the owner deliberately exempts it.
2. **The tunnel adds nothing you can feel.** Latency, jitter and loss seen in
   a game should be those of the path to the server, not of the tunnel. The
   kernel AWG path should add only its encapsulation overhead and no
   userspace hop.
3. **Unattractive to the regulator.** Hard to classify, nothing to find when
   probed, low volume per exposed address, and cheap to move when an address
   is blocked anyway.
4. **Never broken by its own maintenance.** Failover without session loss,
   engine updates that cannot brick a working connection, kernel updates
   that cannot boot a server without its tunnel module.
5. **Generic.** Anyone with a GL-MT6000 and their own VPS can run it.

Non-goals: anonymity from the server operator, protection against a
compromised server, IPv6.

## 2. Threat model (November 2026)

What public reporting and FLR's own captures show:

- **IP-level blocking of individual servers is the main tactic now.** Since
  June 2026 the filtering system watches who uses a connection, finds the
  server addresses and blocks them one by one, instead of blocking protocols
  outright. In the autumn of 2026 personal VLESS/REALITY/XHTTP servers on
  different providers were blocked within days to weeks; blocks did not
  depend on protocol, provider or country. Neighbouring addresses in the same
  /24 stayed reachable, and some blocked addresses came back after about a
  week. Small personal servers used by two or three people are reported
  blocked too.
- **Scoring, not single signatures.** An Amnezia developer describes a
  score over roughly 50 traffic criteria, with a block above about half the
  maximum score. Traffic volume is weighted heavily, so busy servers are
  noticed and quiet ones much less. Signatures are rolled out in waves.
  AmneziaWG 1.0 was fingerprinted in 2025; signatures for 2.0 were collected
  for about a year; AmneziaWG 3.x worked after the July 2026 wave.
- **UDP is under pressure.** The June 2026 rules hit UDP harder and
  disrupted some online games. Plain WireGuard and OpenVPN are blocked
  outright (February 2026).
- **Raw TCP to foreign hosting freezes after about 16 KB.** Since February
  2026, VLESS+REALITY over raw TCP passes the first ~16 KB and then stalls.
  More than three parallel TLS handshakes to one SNI from a hosting subnet,
  together with a non-browser TLS fingerprint, reportedly freezes traffic for
  about two minutes.
- **Suspected trigger: Russian apps reporting the IP they see.** Unproven,
  but consistent with how servers get found: an app inside the tunnel sees
  the server's address as the user's address.
- **Whitelists.** Mobile networks can be switched to a whitelist regime
  quickly; traffic to whitelisted Russian addresses is not filtered.
- **Residential lines can be hostile.** On some home lines direct UDP or TCP
  to individual VPS addresses never arrives or stalls, and changing ports,
  MTU, fragmentation or obfuscation profiles does not help. Test every
  server from the router's own WAN before relying on it.

## 3. Design principles

- **P1 Diversity, cheap to rotate.** Several independent lanes (protocol
  family, port, address). Any one lane can die; rotating a port or an address
  must not need a human.
- **P2 Don't be the loudest address.** Spread volume, never let apps see the
  address the router connects to, and keep the per-address footprint small.
- **P3 Boring on every exposed port.** A real website on TCP 80/443, silence
  toward unauthenticated UDP, certificates that match a real site, no
  well-known VPN ports.
- **P4 Zero-overhead game path.** Kernel AWG, right-sized MTU, no TCP
  carriers for games, no double encapsulation, per-flow fair queueing inside
  the tunnel.
- **P5 Make-before-break everywhere.** Warm standby, endpoint roaming without
  tunnel teardown, engine updates only through a canary and a compatibility
  lock.

## 4. Topology

```
LAN ─ br-lan ─┐                              ┌─ ingress IP A (UDP lanes, site on 80/443)
              │ Flint 2 (FLR)   WAN (ISP)     │
Wi-Fi ────────┤ controller ─── eth1 ─────────► main server ── egress IP B ──► Internet
              │ AWG kernel                    │   (apps only ever see B)
              │ sing-box reserve              └─ ingress IP C (spare, unused until A is blocked)
              └ DNS broker (DoH inside tunnel)
Optional: relay (whitelist regime) ─► main server;  second provider as last resort
```

## 5. Lanes

A lane is one way of carrying the tunnel from the router to the server.
"Game-safe" lanes are UDP-carried and may carry the Games class
automatically. TCP-carried lanes never do (FLR hard rule).

| ID | Lane | Carrier | Game-safe | Overhead | Status |
| --- | --- | --- | --- | --- | --- |
| A1 | AWG main: AmneziaWG 3.1, kernel | UDP | yes | ~60 B/packet + padding; kernel crypto | exists (UDP 51820) |
| A2 | AWG spare: different obfuscation profile | UDP | yes | as A1 | exists (separate UDP port) |
| A3 | AWG roam: server accepts a port range, router moves its endpoint port | UDP | yes | none: WireGuard roaming keeps the session | implemented in 0.7 (off by default; per AWG connection `roam_ports`; server `server/awg-roam/`) |
| H1 | Hysteria2 Gecko, random SNI per QUIC dial, Chrome QUIC fingerprint | UDP/QUIC | yes (userspace) | QUIC + Gecko padding (512-1200 B packets) | exists; random SNI ships in the 0.7 image |
| H2 | Hysteria2 with port hopping and randomized hop interval | UDP/QUIC | yes | as H1 | exists (a UDP port range redirected to 443); randomized interval planned |
| H3 | Hysteria2 over Mimic (fake TCP headers on UDP payloads), Hysteria ≥ 2.12 | UDP disguised as TCP | yes | small header rewrite in eBPF | option for UDP-hostile networks; test from the router's WAN before use |
| T1 | VLESS + XHTTP + REALITY (self-steal: the server's own site as target), browser TLS fingerprint, multiplexing | TCP | **no** | TCP head-of-line blocking | proposal; needs Xray on the server and the owner's approval |
| T2 | CDN emergency lane: XHTTP through a CDN to the server, separate domain | TCP | **no** | +CDN hop | proposal; CDN routes are not for games, so manual and General-only |
| R1 | Relay: small VPS in the local country forwarding UDP to the server | UDP | yes | +5-20 ms | proposal; only if a whitelist regime reaches the home line |
| S1 | Second provider and country as last resort ("backup server") | UDP/QUIC | yes | path-dependent | adding it to the router order is phase 3 |

### Lane notes

- **A1/A2 profiles must differ.** Signature waves hit one parameter set at a
  time. Keep A1 and A2 on different H1-H4 ranges, S1-S4 sizes, junk counts,
  padding and trailers, and add I1-I5 signature packets (CPS) on one of them.
  FLR already validates all AWG 3.1 fields (`internal/config/awg.go`).
- **Move A1 off UDP 51820.** It is WireGuard's well-known port. Migrate with
  an overlap: server listens on the new port and redirects the old one to it
  for a week; router switches; then the old port closes.
- **A3 is the cheapest stealth win.** WireGuard re-learns the peer address
  from any authenticated packet, so changing the router's endpoint port
  (`awg set flr_awg peer … endpoint ip:newport`) keeps the tunnel, the
  handshake and every inner session. The server redirects a port range to the
  AWG listen port (as the server already does for Hysteria). The controller rotates
  on a jittered schedule, and immediately when it sees a stall (section 7).
  This attacks "one long, high-volume flow to one UDP port" without any
  added latency.
- **H1 fingerprint.** sing-box 1.14 makes Hysteria2 clients imitate Chrome's
  QUIC handshake by default; servers with Ed25519 certificates then fail the
  handshake. Keep ECDSA or RSA certificates on the server. FLR's importer must
  learn the new 1.14 keys (`hop_interval_max`, `bbr_profile`,
  `disable_chrome_parrot`) so profiles can use them; today it rejects unknown
  keys.
- **Brutal is a fingerprint**: leave
  `up_mbps`/`down_mbps` unset and use BBR.
- **T1 avoids the raw-TCP freeze** by using XHTTP rather than raw TCP, a
  browser TLS fingerprint and multiplexing (one connection instead of parallel
  handshakes). It is for the General class when every UDP lane is down, never
  for games.

## 6. Routing modes: "all traffic through the server"

A global setting, `routing_mode`:

| Mode | What goes direct | Use |
| --- | --- | --- |
| `full` | LAN, router-local, explicit per-app direct (SOCKS 1080/1088, device profile `direct`) | Maximum coverage |
| `full_domestic` | as `full`, plus a short curated list of domestic services that refuse foreign addresses or check the client IP (supplied by the private overlay) | Recommended default for other users |
| `split` | broad domestic destinations from the private overlay | Lowest volume to the server |

Trade-offs to state to users:

- `full` sends domestic services the server's address. If apps reporting the
  address they see really is a blocking trigger (section 2), `full` exposes
  that address unless egress is split from ingress (section 8). With an
  egress split, `full` is safe from that trigger.
- `full` raises volume to the server address, which the scoring weights
  heavily. Multiple ingress addresses (section 8) spread it.
- `full` adds the round trip to the server for domestic sites and breaks services that refuse foreign IPs; that is
  why `full_domestic` exists.

Implementation: a settings flag; with `full`, `classify` skips the
`essential4`, `direct_domains4` and `broad_direct4` rules and the DNS broker
treats the Direct class as General (except local names). Per device, this
already exists today: device profile `general` sends all of one device's
traffic through the tunnel.

## 7. Failure-mode-aware selection

The controller already measures HTTPS and UDP per channel and keeps
baselines. It should also say *how* a lane failed, because each failure has
a different cheapest fix:

| Observation | Likely cause | First response | Then |
| --- | --- | --- | --- |
| No handshake, no reply on any port | address blocked | next ingress address (section 8) | next provider (backup server) |
| No reply on one port, other ports fine | port or 5-tuple filter | roam port (A3/H2) | next lane family |
| Handshake fine, flow stalls after N KB | per-flow DPI freeze | new 5-tuple (roam), then switch family (TCP→UDP) | — |
| Loss/latency up on both probe providers | congestion or shaping | stay, lower probe weight, try other port | Hysteria (handles loss better) |
| Works for minutes, dies, repeats | signature wave on this profile | switch AWG profile A1↔A2 | rotate profile parameters |

Add a "stall probe": a 64-256 KB download that reports bytes received before
the stall, so the 16 KB freeze is recognised as such.

## 8. Server blueprint

| Area | Design | Status on the main server |
| --- | --- | --- |
| Exposed TCP | 80/443: a real website (Caddy), real 404s | done 2026-11-17 |
| Exposed UDP | Hysteria on 443 (+ hop range), AWG on non-default ports; silence toward unauthenticated packets | done except AWG main on 51820 |
| Certificates | site certificate for the site name; separate wildcard for VPN SNI via DNS-01; ECDSA keys | done |
| Domain hygiene | personal servers on an apex domain not shared with any commercial service | open: keep it on a separate apex domain |
| Ingress ≠ egress | router connects to ingress address A; outbound traffic is SNATed to egress address B; apps only ever see B, so reporting or blocking B never touches the tunnel | planned, phase 2 (needs a second IPv4) |
| Spare ingress | address C reserved; the router profile lists A and C; the controller moves to C when A is classed "blocked" | planned, phase 2 |
| Admin plane | SSH reachable only through the tunnel; provider console as the emergency path | proposal (owner decision) |
| Kernel safety | never boot a kernel without the AWG module (DKMS gate) | gate in `server/engine-update` |
| Engine updates | compat-locked updater with router-traffic verification | `server/engine-update` |
| Buffers and queueing | rmem/wmem ≥ 16 MiB for QUIC, fq + BBR for TCP egress | done |

## 9. Router blueprint

| Feature | Purpose | Status |
| --- | --- | --- |
| LAN derived from the router, not hardcoded | direct SOCKS, device profiles and the 1088 session work on any LAN (the code used to assume 192.168.8.1) | 0.7 |
| Warm reserve | Hysteria reserve started and probed slowly while AWG is primary: failover becomes make-before-break; new connections return to the first healthy AWG (main, then spare) while existing flows stay on the reserve | 0.7 |
| Random SNI in the image | the image ships the patched sing-box, so sysupgrade no longer downgrades it | 0.7 |
| Compat-locked engine updates | `docs/ENGINE-UPDATES.md` | 0.7 (router v1 + server) |
| Routing modes | section 6 (`routing_mode`: split, full_domestic, full; lists come from the private policy overlay) | 0.7 |
| Games never on TCP lanes | the selection map sends Games to `down` (fail closed) when the default lane is TCP-carried; an explicitly chosen connection keeps the owner's choice | 0.7 |
| AWG endpoint roaming | lane A3 | 0.7, off by default |
| CAKE on the tunnel interface | per-flow fair queueing *inside* the tunnel, so a download cannot add queueing delay to game packets | 0.7 (`tunnel_qos`, off by default; image adds kmod-sched-core, kmod-sched-cake, kmod-ifb, tc-full) |
| Failure classification and stall probe | section 7 | phase 2 |
| Multi-address profiles | section 8 | phase 2 |
| Direct-traffic DPI bypass | only matters in `split`/`full_domestic` | phase 3 |

## 10. Overhead budget (what "adds nothing" means)

- **Crypto and encapsulation.** AWG data packets carry about 60 bytes of
  outer headers and tag, plus the configured padding and trailers. With a
  1500-byte WAN, the 1380-byte tunnel MTU leaves 120 bytes; check that the
  largest padding plus trailer fits, with DF pings at 1380 through the tunnel.
  Fragmentation is the one thing that turns overhead into loss.
- **Kernel path for games.** AWG runs in the kernel; no userspace hop. The
  sing-box reserve is userspace and only carries traffic after failover.
- **Queueing is the real jitter source.** A saturated uplink adds tens of
  milliseconds. CAKE on `flr_awg` egress at ~95% of the measured uplink, with
  per-flow fairness, keeps game packets from waiting behind downloads; the
  same on WAN ingress via IFB if downstream bufferbloat shows up. Measure
  ping-under-load before and after.
- **No TCP under games.** Head-of-line blocking turns one lost segment into
  a stall for every packet behind it.
- **Probes are tiny.** Health probes are a few KB per 5 s on the active lane
  and every 30-60 s on the warm reserve.
- **Flow offloading stays off.** FLR's marks need the slow path. Measured
  throughput on the router is far above game needs.
- **What the tunnel cannot remove.** The router-to-server path. Pick the
  server by RTT and loss from the router's WAN, not by price.

## 11. Stealth scorecard

| Signal the filter can score | Mitigation | Lane/feature |
| --- | --- | --- |
| Protocol fingerprint (handshake sizes, header values) | AWG 3.1 junk, S1-S4, H ranges, header protection, I1-I5; two different profiles | A1, A2 |
| One long flow to one UDP port | port hopping, endpoint roaming | H2, A3 |
| High volume to one address | `split`/`full_domestic` where acceptable; several ingress addresses | §6, §8 |
| Active probing | silence on UDP, Hysteria masquerade, real site on TCP | §8 |
| TLS/QUIC fingerprint | Chrome QUIC parroting; browser TLS fingerprint on TCP lanes | H1, T1 |
| SNI and certificate correlation | per-dial random SNI under a wildcard; apex not shared with commercial services | H1, §8 |
| Parallel handshakes to one SNI | random SNI per dial; multiplexing on TCP | H1, T1 |
| Apps reporting the address they see | ingress ≠ egress; domestic apps direct in `full_domestic` | §6, §8 |
| Regular probe timing | jittered probe intervals; ordinary destinations | controller |
| Raw-TCP 16 KB freeze | no raw TCP lanes; XHTTP only | T1 |

## 12. Phases and acceptance

Every phase is accepted only on sustained traffic measured from the router's
WAN: an HTTPS transfer plus UDP through the tunnel, plus ping-under-load for
the jitter work. Each router or server step needs the owner's go-ahead.

| Phase | Content |
| --- | --- |
| 0 (0.7) | LAN fix, warm reserve, random-SNI sing-box in the image, OpenWrt 25.12 image, compat-locked engine updates (router and server), these documents |
| 1 | done in 0.7 except the server-side port move: routing modes; games never on TCP lanes; AWG roam; importer support for sing-box 1.14 Hysteria keys; CAKE inside the tunnel. Open: move AWG main off 51820 with an overlap (server and router change, owner go-ahead) |
| 2 | ingress/egress split and spare ingress address on the main server (second IPv4); multi-address profiles; failure classification and stall probe |
| 3 | TCP stealth lane for the General class (approval for Xray on the server); CDN emergency lane (manual); backup server in the router order; direct-traffic DPI bypass |
| 4 | relay lane if a whitelist regime reaches the home line; `server/` kit for other users |

## References

- Meduza, interview with an Amnezia VPN developer, 2026-08-03:
  https://meduza.io/feature/2026/08/03/teoreticheski-oni-mogut-zablokirovat-lyuboy-servis-tselikom
- Habr, personal servers blocked in autumn 2026: https://habr.com/p/1103460/
- VGTimes, personal VPN servers for two or three people blocked, 2026-11-02:
  https://vgtimes.ru/news/173171-v-rossii-nachali-blokirovat-lichnye-vpn-servery-kotorymi-polzuyutsya-dva-tri-cheloveka.html
- sing-box 1.14.0 release notes (Hysteria2 Chrome QUIC parroting, `hop_interval_max`,
  `bbr_profile`, Gecko obfs): https://newreleases.io/project/github/SagerNet/sing-box/release/v1.14.0
- OpenWrt 25.12.6 announcement: https://forum.openwrt.org/t/openwrt-25-12-6-service-release/254604
