# flr-awg-roam: AWG endpoint roaming on the server (lane A3)

The router can move the endpoint port of its AmneziaWG peer inside a port range
(`roam_ports` on the AWG connection, see `docs/ROUTER-API.md`). WireGuard
re-learns the peer from the next authenticated packet, so the tunnel, its
handshake and every session inside it continue. This changes the outer 5-tuple
on a schedule and when the controller sees a stall (docs/MAX-PACKAGE.md,
sections 5 and 7).

The server side is one nft table that redirects the range to the AWG listen
port, like Hysteria port hopping:

```
table inet flr_awg_roam {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		udp dport 40000-40999 redirect to :51820
	}
}
```

## Why the router changes both ports

Every rotation moves the router's AWG source (listen) port together with the
endpoint port, in one `awg set flr_awg listen-port <lp> peer <key> endpoint
<ip>:<port>` call. Changing only the destination port is not enough with a
redirect: the server rewrites every port of the range to the same listen port,
so the old flow and the new one would have the same reply tuple
(`server:listen -> router:sport`). While the old flow's conntrack entry is
alive (30 s unreplied, 120-180 s once replied) the new flow clashes with it in
NAT and its packets are dropped, and late replies on the old tuple can move
WireGuard's endpoint back. A fresh source port makes each rotation a distinct
5-tuple on both sides, so each one gets its own conntrack entry here and in
any NAT on the home side, and the server re-learns the peer from the first
authenticated packet of the new flow.

The router draws source ports from 49152-65535, never reuses the original one
or a recently used one, and retries with another port if the bind fails. Only
the kernel device changes (not UCI). Outer AWG packets are recognised on the
router by their socket mark, which a rebind keeps, so routing and the firewall
do not depend on the source port. Turning roaming off restores the stored
endpoint port and the source port that was in use before the first rotation.
On the server nothing depends on the router's source port: the input chain
sees the listen port after the redirect.

## Use

```sh
./flr-awg-roam --ports 40000-40999 --listen 51820 --dry-run   # print, change nothing
./flr-awg-roam --ports 40000-40999 --listen 51820             # apply (root, nft)
./flr-awg-roam --remove                                       # delete the table
```

- `--ports`: 1024-65535, ordered, at most 10000 ports; the same rules as the
  router setting. Use the same range on both sides.
- `--listen`: the AWG listen port (`ListenPort` of the server interface); it
  must be outside the range. For a second AWG interface use a separate range
  and `--table`.
- `--table`: default `flr_awg_roam`.
- Applying is idempotent: the table is created if missing, deleted and
  rewritten in one atomic `nft -f` transaction. Other tables are untouched.

## Before enabling it on the router

1. Run with `--dry-run` and review the output.
2. Apply on the server. The redirect happens in prerouting, so a default-drop
   input chain sees the listen port: the existing allow rule for it is enough;
   the range itself needs no input rule.
3. Make it persistent the way the server already keeps its nft tables (an
   include in `/etc/nftables.conf` with the printed ruleset, or a oneshot unit
   that runs this script). The script itself persists nothing.
4. Only then set `roam_ports` on the router connection. Roaming is off by
   default. Acceptance follows the FLR rules: sustained HTTPS and UDP traffic
   through the tunnel measured from the router's WAN across several rotations,
   not a handshake.

Turning roaming off on the router moves both ports back first; remove the
server table only after that.

Tests (no host is touched; a fake `nft` records the calls):

```sh
python3 -m unittest discover -s server/awg-roam/tests -v
```
