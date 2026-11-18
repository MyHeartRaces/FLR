# Router API v1

`flr-controller api` reads one JSON object from stdin (at most 1 MiB), requires
UID 0 and emits exactly one reply: `{"ok":true,"data":{},"error":""}` or
`{"ok":false,"data":null,"error":"safe error text"}`. Validation failures may
also include `error_detail`; activation handoff failures retain safe `data`
with pending/error state. Exit status is not the
operation result; callers must inspect `ok`. No operation accepts filenames,
commands, argv, shell fragments or outbound listener/routing rules.

`flr-controller api --rpc` reads rpcd's wrapper
`{"request":"{\"operation\":\"status\"}"}`. The plugin's read method must use
`api --rpc --read-only`; its write method uses `api --rpc`. `--read-only` rejects
all writes after decoding the inner request. It cannot be overridden by fields
inside that request. The rpcd plugin and FLR ACL must authorize these fixed
methods; this CLI does not authenticate a remotely supplied username/token.
Direct CLI calls require root. Runtime sockets are in a private 0700 directory
and mode 0600. There is no HTTP management listener.

Live calls use `/var/run/flr-runtime/api.sock`, whose controller validates each
request again and serializes mutations with transport rounds. Offline calls
hold `controller.lock` and `admin.lock`, load validated private state, and never
start proxy engines during reads/imports. A live controller holds the singleton
lock; handlers use the distinct administrative lock, avoiding nested singleton
locking. Startup windows fail with a retry error. A failed socket dial can use
the offline path only after acquiring the singleton lock; ambiguous replies
are never replayed.

## Requests and exact data shapes

Only listed fields are accepted. Duplicate JSON keys, unknown fields, trailing
JSON and excessive nesting are rejected. `operation` is always required.

| Operation | Additional request fields | Successful `data` |
| --- | --- | --- |
| `status` | none | `{runtime:bool,vpn_enabled:bool,status:RuntimeStatus,active_profile:ProfileSummary|null,profile_selection:string,rollback_pending:bool,deactivation_pending:bool}` |
| `profiles` | none | `{profiles:ProfileSummary[],selection:string}` |
| `import` | exactly one of `content:string`, `url:string` | `{imported:ProfileSummary[]}` |
| `select` | `id:"auto"` or enabled profile ID | `{selection:string}` |
| `profile-update` | `id`, at least one of `enabled:bool`, `priority:int`, `server_group:string` | `{profiles:ProfileSummary[],selection:string}` |
| `profile-delete` | `id` | `{profiles:ProfileSummary[],selection:string}` |
| `device` | `client:"192.168.8.2"` through `.254`, `value:"auto"|"general"|"games"|"direct"` | `{devices:{IPv4:class}}` |
| `settings` | no fields for read; `settings:SettingsPatch` for update | `Settings` |
| `refresh` | none | `{scheduled:bool}` (`false` when offline) |
| `primary-awg` | optional `content:string` (max 64 KiB), optional `activate:true` | `{configured:bool,stored:bool,activated:false,activation_state?:"idle"|"pending"|"error",service_start_requested?:bool,endpoint?:string,address?:string,awg_version?:"3.1"}` |
| `rollback-confirm` | `accepted:true` | `{confirmed:true,rollback_pending:false}` |
| `help`, `capabilities` | none | `{api_version:1,max_import_bytes:1048576,max_profiles:64,operations:string[],components:{"sing-box":bool,xray:bool,wstunnel:bool},managed_slot:"gecko",tun_address:"198.18.0.1/30",tun_peer:"198.18.0.2",authentication:string,tcp_only_games:"fail-closed"}` |

`ProfileSummary` has exactly `id`, `name`, `family`, `server_group`, `priority`,
`enabled`, optional `disabled_reason`, `engine`, and
`capabilities:{tcp:bool,udp:bool,tcp_only:bool,required_components:string[]}`.
Families: `hy2`, `reality`, `vless`, `ss2022`, `naive`, `wgws`. Generated names
and metadata are redacted against credentials; no private outbound, keys,
passwords, UUIDs, tokens, rendered configs or source URLs are returned. Priority
updates and imports accept integers −1000000..1000000. Profile and primary
groups share the same bound: at most 80 UTF-8 bytes, excluding CR, LF, NUL and
`://`. Unicode and other previously supported group text are preserved. LuCI
only resubmits changed priority/group fields, so redacted unchanged metadata
also survives an enabled-state edit. Deleting/disabling the selected
profile resets selection to `auto`.

`RuntimeStatus` preserves the existing fields: `version`, `selection` with
`general/games` channels (`down`, `awg`, `gecko`), `manual_games` (legacy field),
`generation`, optional `test_client`, `dns_port`, optional `profiles` (device
map), optional `direct_session`, `channels`, `updated`, optional `last_error`.
`channels.awg` and `channels.gecko` contain `healthy`, `consecutive_failures`,
`recovery_since`, `last_check`, `last_change`, and
`probe:{tcp,udp,round_duration_ns}`. Legacy `games vless` CLI calls now return an
explicit instruction to use managed profile selection; the independent VLESS
slot is retired.

`Settings` is stored atomically in `/etc/flr-runtime/settings.json`:

```json
{
  "version": 1,
  "enabled": false,
  "options": {
    "lan": "br-lan",
    "wan": "eth1",
    "selection": {"general": "down", "games": "down"},
    "manual_games": false
  },
  "dns_port": "1054",
  "local_dns_port": "53",
  "profile_selection": "auto"
}
```

Optional stored fields: `primary_group:string`, `family_order:string[]` and
`options.profiles:{IPv4:class}`. `SettingsPatch` accepts only
`profile_selection`, `primary_group` (the same 80-byte UTF-8 group contract as profiles),
`family_order` (unique subset of `reality,vless,ss2022,naive,wgws`) and
`enabled:false`, complete `direct_proxy`, and complete `health_policy` (below). Enabling through a patch is rejected: use explicit
`primary-awg activate`. Selection IDs must exist and be enabled. Validation or
persistence rejection preserves prior settings and causes no native effects.
Existing versionless settings migrate to v1,
`enabled:true` and `profile_selection:"auto"`, preserving existing device/DNS
choices. Missing settings use disabled safe defaults.
Stored empty TCP/QUIC bypass presets normalize to `off` in memory, retaining
`enabled` and any other valid preset. A read does not rewrite private files.
Stored primary groups previously accepted by `^[a-zA-Z0-9_. -]*$` at 81–128
bytes are preserved across unrelated settings edits and save/reload. Explicitly
supplying `primary_group` always enforces the current 80-byte rule, even if its
value equals an inherited legacy group; an explicit empty string clears it.
Null/malformed groups or bypass values, unknown fields and duplicate keys remain
invalid. Profile/import
group limits remain 80 bytes. LuCI omits an unchanged displayed primary group
(including `[redacted]` and a retained legacy label) when saving family order;
only explicitly changed metadata is validated and sent.

## Import and primary activation

Imports are bounded and transactional. All profiles in the batch are parsed,
rendered and checked with fixed installed engine commands before private
registry replacement. Missing optional engines disable affected profiles;
installation is never automatic. URLs must be HTTPS, port443, without userinfo
or fragments. At most three redirects,15-second timeout and1-MiB decoded body
apply. Every redirect and actual dial uses validated public IPv4 DNS answers
through the marked WAN resolver. Mixed private/public answers, private,
loopback, link-local, multicast, CGNAT, benchmark and documentation destinations
are rejected. URL token/query data and transport engine stderr are hidden from
errors. URLs are not persisted.

Validation errors retain the human-readable `error` and add optional
`error_detail:{code,message,field?,item?,component?}`. Codes include
`duplicate_profile`, `registry_capacity`, `invalid_format`, `unsupported_transport`,
`unsupported_field`, `missing_field`, `invalid_profile`, `invalid_awg` and `engine_validation`.
Reasons are exact allowlisted validator literals with corrective guidance;
unknown parser/native errors use a fixed fallback. `item` is one-based when
known (URI, JSON array, bundle profile, outbound or imported native-check position). Native
checks name only the validated component and never return its stderr.
Registry existence is the migration checkpoint: an intentionally saved empty
registry is never repopulated from retained legacy source files.

`primary-awg` reads public endpoint/address metadata; existing UCI metadata is
available even if no complete configuration has yet been stored. Import writes
a validated private fixed `/etc/flr-runtime/primary-awg.conf` and leaves VPN
activation unchanged. Only `activate:true` changes UCI and activates policy:
backup validation and rollback arming precede AWG/firewall/DNS changes, the
owned boot guard is installed, full-LAN settings are saved, and the controller
service receives a start request after the offline CLI releases its singleton
lock. A successful activation response has `activated:false` and
`activation_state:"pending"`; offline handoff adds `service_start_requested:true`.
This means procd accepted the request, not that VPN/DNS is ready. Check live
`status` and connectivity before acceptance. A start failure returns `ok:false`
with `activation_state:"error"`, `service_start_requested:false` and a retry
message; rollback remains armed. Rollback remains armed until the existing LAN/WAN acceptance
confirmation. The GUI must show `status.rollback_pending` and offer an explicit
LAN/WAN connectivity acceptance action: `{operation:"rollback-confirm",accepted:true}`.
Confirmation requires an active configured VPN and a pending rollback from this
boot and an unexpired activation generation. Each arm creates a unique
generation and a 180-second deadline from Linux `CLOCK_BOOTTIME`, shared by
separate CLI invocations and including suspend time. Wall-clock changes do not
change this window. The private marker is `b1 <boot-id> <generation> <deadline-ns>`
within the existing 128-byte status bound. Expiry and confirmation compare that
generation under one file lock; stale watchers cannot restore or remove a later activation.
Startup recovers expired, cross-boot, malformed and legacy markers (including
old wall-time deadlines). Clock failure rejects arming/confirmation; matching
expiry/startup conservatively restores rather than extending an unknown deadline.
Failed restoration retains its private marker and prevents service startup. Import/activation
never clears it automatically. The user must verify LAN
access, WAN access, intended VPN routing and direct routing before accepting.
`settings:{enabled:false}` restores the validated pre-FLR
network/firewall/DNS configuration while leaving the administrative controller
available. The private registry and primary file remain for later use.
Offline disable first saves disabled intent, then restores native state. If
restoration fails, the response error is `VPN deactivation incomplete; disabled
settings saved, retry disable`. Settings remain disabled and the recovery marker
remains until all native reloads finish. Repeat the same disable request or start
the controller to retry restoration; reading settings shows the saved disabled
intent and `status.deactivation_pending:true` indicates incomplete native
restoration. A completed disable does not repeat native teardown on another request.

AWG accepts one interface and peer, strict32-byte base64 keys (including header
protection), IPv4 address/endpoint, S1-S4 >=12, validated AWG3.1 numeric ranges,
non-overlapping H1-H4, bounded CPS I1-I5 and boolean fields. It rejects scripts,
unknown fields and repeated sections. `DNS` may contain validated IPv4 values;
FLR's owned split-DNS configuration governs runtime resolution. Upstream field
semantics: [AmneziaWG documentation](https://docs.amnezia.org/documentation/amnezia-wg/).

## Transport lifecycle

Automatic selection prefers healthy AWG, then HY2 in `primary_group`, remaining
HY2 by priority, then each configured family. It exhausts each family before
advancing. Manual selection probes only that profile; failure remains down.
Candidates are sequential, failed children are stopped, retries back off from
30seconds up to5minutes, live failures use three consecutive probes, and AWG
must remain recovered for60seconds before reclaiming selection. Every reusable
slot replacement publishes down, clears its owned conntrack and advances DNS
generation before startup. Healthy AWG marks are not cleared by slot replacement.
TCP-only engines reject general UDP and keep games down; VPN DNS retains the
existing SOCKS/DoH TCP path.

Generated TUN uses `198.18.0.1/30`, peer`198.18.0.2`. Legacy processes/interfaces
are stopped first and the owned firewall allowance is migrated before start.
The retired procd proxy service launches no children. WAN resolution/pinning
uses a dependency-injected adapter. Wstunnel has no bind-interface CLI: its
actual bearer is resolved to IPv4, its TLS/HTTP hostname preserved, a verified
WAN route pinned with owned protocol186, and the child receives the literal
bearer IP plus its mark. A private pre-add journal and exact protocol/interface
checks clean stale pins on restart without flushing foreign routes.

These are source/API contracts, not hardware acceptance evidence. Go/native
engine checks and router behavior require the authorized CI/hardware gates.

## Permanent direct proxy (0.6 Task 3)

`Settings` now includes `direct_proxy:{enabled:bool,bind:string,port:int}`;
missing fields in older stored settings receive defaults
`{enabled:true,bind:"192.168.8.1",port:1080}` without changing VPN activation.
`SettingsPatch` accepts a complete `direct_proxy` object. The supported bind is
exactly the platform's router LAN `192.168.8.1`, never a wildcard, WAN, IPv6 or
other LAN host. LuCI displays this address read-only. Ports are integers1024..65535 excluding1088 and configured DNS
ports. Enable/port are configurable; migrating the router LAN address is outside
this API. Invalid settings preserve prior persisted/live settings. Offline writes
save intent; the listener starts with the controller. Live updates notify the
controller, which closes prior sockets/flows before replacement.

`RuntimeStatus.direct_proxy` is
`{config:{enabled,bind,port},running:bool,error?:string}`. Offline status shows
`running:false`. Startup/accept/UDP-listener failures remain visible; repeat
`refresh` or save settings after correcting the port/LAN problem. The listener
runs independently of `vpn_enabled`, including on clean-image safe defaults.
TCP CONNECT and UDP ASSOCIATE are IPv4 only, with64 concurrent TCP owners,
one UDP association per client IPv4,32 destinations per association and4096-byte
SOCKS datagrams; RSV/FRAG must be zero. The TCP owner's source IP and declared
(or first learned) UDP port bind the association; connected destination sockets
filter replies. Closing the TCP owner closes its UDP sockets. Destinations with
no received response for60seconds are released. Controller shutdown/config reload
closes all listener sockets/flows. No temporary-session TTL applies.

WAN-bound egress and direct DNS use permanent mark`0x80400000` with an owned
`inet flr_direct` LAN-only guard and output conntrack stamp. Cleanup uses
`0x80400000/0xffc00000`, distinct from legacy temporary1088's
`0x80800000/0xff800000`. No arbitrary interface, path, shell or routing fields
are accepted. The separate guard survives VPN deactivation until direct stops.

LuCI's executable `/usr/libexec/rpcd/luci.flr` exposes only `read` and `write`,
each with a string `request` containing bounded JSON. Read execs fixed
`/usr/sbin/flr-controller api --rpc --read-only`; write execs fixed
`/usr/sbin/flr-controller api --rpc`. Payload stays on stdin. The FLR ACL grants
only those ubus methods, with separate read/write scopes and no filesystem ACL.
The GUI rejects malformed/empty/negative CLI replies even when rpcd returns an
otherwise successful transport frame. `deactivation_pending` offers the same
retry disable request; rollback acceptance remains a separate explicit action.

## Sustained AWG impairment policy (0.6 Task 5)

Clean images and legacy settings with no `health_policy` receive the following
provisional defaults. `Settings` returns the complete object. A settings write
accepts a **complete** `health_policy` object; omission leaves it unchanged.
Null, missing fields (including `enabled`), noninteger thresholds, duplicate or
unknown keys, out-of-range values and invalid relationships are rejected before
persisting anything or performing native effects. This also applies to combined
updates such as `enabled:false` plus invalid policy. The existing complete,
presence-aware `direct_proxy` object and explicit rollback acceptance remain
unchanged.

| Field | Default | Accepted bounds / unit |
| --- | ---: | --- |
| `enabled` | `true` | boolean; controls sustained impairment only |
| `window_seconds` | 60 | 30..300 seconds |
| `min_samples` | 8 | 6..60 rounds; at most `floor(window_seconds/5)+1` |
| `failure_percent` | 25 | 25..100 percent, independently for each provider |
| `slow_percent` | 75 | 50..100 percent, independently for each provider and same protocol |
| `tcp_floor_ms` | 1500 | 500..3500 milliseconds |
| `udp_floor_ms` | 400 | 100..2000 milliseconds |
| `tcp_recovery_ms` | 750 | 100..`tcp_floor_ms-1` milliseconds; also baseline admission ceiling |
| `udp_recovery_ms` | 200 | 25..`udp_floor_ms-1` milliseconds; also baseline admission ceiling |
| `latency_multiplier` | 4 | integer factor 2..10 |
| `recovery_multiplier` | 2 | integer factor 1..`latency_multiplier-1` |
| `baseline_samples` | 12 | 6..60 fully clean rounds |
| `recovery_seconds` | 60 | 60..600 seconds |
| `max_gap_seconds` | 30 | 10..60 seconds between checks; larger gaps reset qualification |

Example complete authenticated update:

```json
{"operation":"settings","settings":{"health_policy":{"enabled":true,"window_seconds":60,"min_samples":8,"failure_percent":25,"slow_percent":75,"tcp_floor_ms":1500,"udp_floor_ms":400,"tcp_recovery_ms":750,"udp_recovery_ms":200,"latency_multiplier":4,"recovery_multiplier":2,"baseline_samples":12,"recovery_seconds":60,"max_gap_seconds":30}}}
```

A round has two independently operated providers in fixed index order:

| Index/provider | HTTPS request (fixed TLS hostname and socket) | UDP DNS socket |
| --- | --- | --- |
| 0 Cloudflare | `www.cloudflare.com/cdn-cgi/trace`, `104.16.124.96:443`; HTTP200 plus `ip=` response | `1.1.1.1:53` |
| 1 Google | `dns.google/resolve?name=example.com&type=A`, `8.8.8.8:443`; HTTP200 plus valid DNS JSON status0/answers | `8.8.8.8:53` |

Both DNS requests ask for `example.com A` and validate the response ID, success
rcode and nonempty answer. Redirects are rejected. The controlled AWG sockets
use owned probe/channel marks and interface; imported slots use the existing
fixed SOCKS path. There are at most four concurrent requests, one shared
4-second deadline, at most8192 HTTPS response bytes, and no probe DNS resolution
of the HTTPS host. TCP-only candidates make just the two HTTPS requests and
never receive a UDP capability through aggregation. A protocol is available
when **either** provider succeeds. One provider outage therefore cannot alone
trigger the three-round failure rule or the sustained impairment verdict.

At most one evidence sample is admitted per5 seconds, including manual refresh.
The rolling window expires observations by age and contains at most61 entries
in a fixed64-entry buffer. At least `min_samples` are required. For failures,
each provider independently must have a failed required protocol in at least
`failure_percent` of the same window's rounds, and at least two such rounds.
Failures may be offset between providers: alternating provider failures are
observable even while aggregate availability stays true. For latency, each
provider must independently exceed its threshold in at least `slow_percent`
of all window rounds **for the same protocol**, again at least two rounds.
Failure counts and slow successful request counts remain separate. A single
outlier and isolated single-provider outage/slowness cannot degrade AWG.

Each provider/protocol has a separate baseline: the upper median of
`baseline_samples` consecutive fully clean cadence rounds, all four timings
within their TCP/UDP admission ceilings, with no impairment observations left
in the window. Qualification resets on error, slowness, missing timings or a
check gap above `max_gap_seconds` (default30 seconds). Once learned, the baseline is fixed until policy
change or controller restart; it cannot drift up with an impaired path.
Degraded/down samples cannot train it. Until a baseline qualifies, its value
is0 and the absolute floors still detect a slow cold path.

Exit threshold is `max(protocol_floor_ms, baseline_ms * latency_multiplier)`;
a successful time must be strictly greater to count as slow. Recovery threshold
is `max(protocol_recovery_ms, baseline_ms * recovery_multiplier)` and times must
be at or below it. Recovery needs **all four** valid successful timings, at least
`floor(recovery_seconds/5)+1` cadence samples, and the full elapsed qualification
interval. The default30-second gap allowance covers known probe/start budgets
and bounded per-child shutdown waits; it does not reduce the required13 clean
observations even when sampling is slower. Any error, absent/missing timing or slow response resets qualification;
a gap above `max_gap_seconds` (default30 seconds) resets it as well. Boolean success alone cannot recover
AWG. At defaults this is at least13 clean samples spanning60 seconds. Qualified
recovery discards stale impairment history. Disabling `enabled` preserves
immediate absent-interface failure, three consecutive rounds with a required
protocol unavailable across both providers, and fast qualified recovery.
Changing any policy field requalifies history/baseline/recovery without
promoting an unhealthy AWG. Manual profile selection remains authoritative.

Status retains `probe.round_duration_ns` as **aggregate round elapsed time**,
not a request timing or ICMP RTT. New fields in each `probe` are `measured:bool`
and `targets:[{tcp,udp,tcp_duration_ms,udp_duration_ms}, ...]` in the index order
above. Successful request durations are rounded up to milliseconds; failures
have0 timing. HTTPS timing includes connect, TLS, request and bounded body read;
UDP timing covers the DNS exchange. These are application observations, not
packet-loss measurements or evidence of deliberate restrictions.

AWG state adds `reason` (`healthy`, `interface_absent`, `consecutive_failures`,
`sustained_failures`, `sustained_latency`), `degraded:bool`,
`window:{samples,failed:[int,int],tcp_slow:[int,int],udp_slow:[int,int]}`,
`baselines:[{tcp_ms,udp_ms},{tcp_ms,udp_ms}]`, `baseline_samples` (qualified sample
count), and `recovery_clean_samples`. Existing `recovery_since` records the
current qualification start. Slot state keeps its existing availability policy;
its new impairment fields are empty/zero. No private history or transport secrets
are exposed. Russian LuCI explains these values and offers all policy controls.

Losing AWG health retires its owned conntrack mark after publishing down and
before publishing a backup. Selection/cleanup failures remain visible and
retry on later rounds; kill guards are retained. Backup startup failure leaves
VPN-designated traffic down; it never selects direct WAN. AWG cleanup itself
has a2-second command timeout.

Candidate start/preparation and probes share a4-second `Manager.Step` context;
a continued ordered sweep prevents expired steps repeatedly retrying the first
candidate. A selected process uses the controller lifetime, so ending the
startup budget does not kill it. Cooldowns remain30..300 seconds. This bounds
context-aware candidate work even with64 failed profiles, allowing subsequent
AWG checks and recovery. **It is not a hard total native wall-clock bound:**
existing slot quiescence (`UpdateSelection`, `ClearSlot`), firewall migration
(`config.MigrateSlot`), route installation (`EnsureRoutes`) and pin release use
synchronous native commands outside that context. `Stop` can wait up to5 seconds
per child. Slow/hung native commands and real startup timing remain installed
router acceptance gaps; a gap above `max_gap_seconds` (default30 seconds) conservatively restarts recovery.

### Configuring same-server HY2 order

There is no automatic AWG endpoint-to-registry group inference. On both clean
activation and legacy settings, set `settings.primary_group` to a chosen safe
label (for example `main-server`) and set **the HY2 profiles on that AWG VPS**
to the exact same `server_group` via `profile-update`. LuCI exposes this on
Settings and Profiles and warns when the primary group is empty. Then matching
HY2 sorts before other HY2 regardless of their numeric priority; all HY2 still
sorts before other families. An empty or nonmatching primary group provides
only ordinary HY2 priority order, and does not promise same-server fallback.
The operator establishes which profiles share the AWG server; a label alone
does not validate endpoint identity.

These defaults deliberately require multi-provider, repeated evidence and
stricter recovery. The separate400/200ms UDP floors detect sustained DNS/game
path delay that1500ms HTTPS floors would miss. Their suitability for the
installed router, ISP and endpoints is **provisional**, pending separately
authorized hardware qualification. No router or server was contacted for this
source change.

## Device policy transitions

An active device update first blocks that device's routed public IPv4 traffic,
replaces the owned profile sets, clears that device's original-source and reply-source FLR class affinity
and unclassified NAT entries, persists settings, and then reopens traffic.
Other devices, outer-marked connections and unclassified local sessions retain
their policy. Source-NAT and destination-NAT filters cover unclassified public
connections; zero matches are accepted only with the exact conntrack summary,
while operational errors remain failures. Direct takes
precedence over old VPN affinity and classifies unmarked established replies
from already permitted incoming IPv4 connections. Existing sessions may need
to reconnect when their NAT path changes. General/Games retain VPN kill guards.
A failure after blocking returns an actionable error and keeps the device
blocked; retry its desired policy to complete cleanup. If saving succeeded but
unblocking failed, the saved choice is authoritative and the error says so.
No successful response is returned while required cleanup is pending.

## Additions in 0.7 (2026-11-18)

### Router LAN

The LAN (router address and prefix) is read from `br-lan` instead of the old
fixed 192.168.8.0/24. The controller re-reads it on every tick and for every
control-socket and API request, through a cache with a 5-second TTL, so a LAN
that appears or changes after start is used without a restart.

- Loading `settings.json` checks structure only: a device profile needs a
  private IPv4 address and a known class; the direct proxy needs a private
  IPv4 bind and a port 1024..65535 other than 1088. Membership in the live LAN
  is never checked at load, so a LAN change or a restored configuration cannot
  stop the controller from starting.
- The direct-proxy bind in use is derived, not chosen: whenever the LAN is
  known, the listener binds the router's LAN address with the stored `enabled`
  and `port`, and `settings` and `status` report that address. The listener is
  rebound when the router address or prefix changes. A transient discovery
  failure keeps the running listener.
- The bind stored in `settings.json` is kept as loaded (192.168.8.1 when none
  was saved), and every save keeps it, a `direct_proxy` change included: that
  change persists `enabled` and `port` only. A rollback to the 0.6 controller,
  which refuses any other bind, therefore still loads the file. A stored bind
  that is not a private IPv4 address at all is replaced by 192.168.8.1 at load
  once the LAN is known.
- If the LAN has not been discovered yet (for example `br-lan` has no IPv4
  address when the controller starts), the controller still runs. The direct
  proxy is not started on any fallback address: `status.direct_proxy` shows
  `running:false` with `error` and `lan_error`, and discovery is retried on
  every tick.
- Device profiles whose address is not a client of the current LAN (outside
  it, or its router, network or broadcast address) stay in `settings.json` but
  are not rendered into the nft sets. `status.ignored_profiles` lists them as
  `[{client, class, reason}]`. While the LAN is unknown every stored profile is
  rendered. When the LAN appears or changes, the profile sets are re-rendered
  once for it.
- Changes keep the strict check. A new device profile (API `device`, control
  socket `profile`) must be a client of the current LAN, and a `direct_proxy`
  bind sent in `settings` must equal the router's LAN address. While the LAN is
  unknown, new profiles are refused and `direct_proxy` accepts only `enabled`
  and `port` changes with the bind unchanged. Removing a profile (`auto`)
  needs only a private IPv4 address, so an ignored profile can be deleted.
- `status.direct_proxy` has `lan` (for example `192.168.1.1/24`) and
  `lan_error` (the current discovery failure, if any).
- The permanent direct SOCKS listener admits only clients of the current LAN
  and refuses targets inside it or inside the former 192.168.8.0/24.

### Warm reserve

Settings field `warm_reserve` (unified v2 settings only), a complete object:

```json
{"operation":"settings","settings":{"warm_reserve":{"enabled":true,"interval_seconds":30}}}
```

`interval_seconds` is 30..300. The effective default is enabled, 30 s; it is
not written to `settings.json` while it equals the default, so an older
controller can still read the file. Saving it never changes the choice epoch,
so it never drops sessions. In `auto` mode with a healthy AWG default, the
first enabled UDP proxy connection in order is started as a standby and probed
at the interval (every round while AWG is unsettled). `status.proxy` gains
`reserve_warm`; the diagnostic history gains reason `warm_reserve`. On AWG
failure new flows move to the running standby without a start; this means the
second AWG connection is tried only if the standby fails (owner decision
pending).

Admission runs in a background worker and is adopted at the next round only
if the generation, mode and connection still match, so a slow start (for
example a full firewall migration) never delays AWG probing. Reselect,
disable, restore and shutdown cancel it. A failover keeps an admission still
running for the first proxy connection it would start and waits for it within
the round instead of starting that connection cold; an admission for any
other connection is cancelled. A standby that never carried flows
is stopped without any conntrack cleanup; if stopping fails it is quarantined
and retried, and it never blocks AWG probing or failover to the AWG spare. A
reserve retained after failback (it may carry old sessions) is probed every
round; only a never-used standby gets the slow cadence.

With the warm standby running, a failure of AWG main moves new connections to
the standby (make-before-break). After such a fallback the controller keeps
probing the AWG connections ranked above the proxy, main before spare, and
moves new connections back to the first one that passes a clean TCP and UDP
sample ("re-advance", recorded as `failback`). A configured AWG that is
healthy, recovering or not yet measured this round is never displaced; at
most one switch-in per round, with the usual 30 s to 5 min cool-down. The
reserve and every flow on it keep running.

### Games never on TCP lanes

In auto and protocol modes the Games class is published only on game-safe
families (`awg`, `hy2`). When the default lane is TCP-carried (VLESS,
Reality, XHTTP, WS wrappers, SS2022), General may use it and Games fails
closed (`down`). A connection the owner selects explicitly keeps today's
behaviour.

### AWG endpoint roaming

Per AWG connection, `connection-update` metadata accepts `roam_ports`
(`"start-end"`, 1024-65535, at most 10000 ports; `""` turns roaming off) and
`roam_interval` (seconds, 60-86400; 0 = 600). It does not change the
connection's revision or start a new choice. While that connection is the
healthy default, the controller moves the kernel peer endpoint
(`awg set flr_awg peer … endpoint ip:port`) to a random other port in the
range every interval (±30 % jitter), and once per failure episode right after
the first failed probe while the handshake is recent, before failover is
considered. WireGuard re-learns the endpoint from authenticated packets, so
the tunnel and all inner sessions continue. Roaming is suspended during a
connection test. The server must redirect the range to its AWG port first
(`server/awg-roam/`). `status.proxy.roam` reports the port in use, the next
rotation and the last reason (`schedule`, `stall`, `range`, `disabled`).
Decisions are recorded with reason `roam`.

### Connection export

`{"operation":"connection-export","id":"…","expected_generation":N}` (write
permission; the read-only RPC refuses it) returns `{id, name, family,
revision, format, engine, config, filename, note?, generation}`. `format` is
`url` (a share URL the importer reads back to the same profile), `json` (the
outbound JSON when a URL would lose settings, e.g. random SNI or 1.14 keys)
or `awg-conf` (the AmneziaWG `.conf`). The response contains credentials.

### Engine updates

`flr-controller engine status|check|run|hold|unhold|unblock|rollback|loop`,
configured by `/etc/flr-runtime/engine-update.json` (absent = disabled; default
mode `check`). State: `/etc/flr-runtime/engines.lock.json`. Both files are in
the sysupgrade keep list. Design: `docs/ENGINE-UPDATES.md`. The procd instance
`engine_update` exists only when the config file exists.

### Routing policy overlay

The image ships a neutral policy (`/usr/share/flint-vpn/policy`): local
destinations stay local, everything else goes through the VPN. A private
policy with the same layout at `/etc/flr-runtime/policy` (kept across
sysupgrade; see `policy/README.md`) is used instead when it loads cleanly. A
broken overlay is reported on stderr at start and the image policy is used,
so a bad list never stops the router. The policy is read when the controller
starts.

### Routing mode

`settings` reports `routing_mode`; a patch `{"routing_mode":"full"}` changes
it. Values:

| Mode | Direct lists of the installed policy that apply |
| --- | --- |
| `split` (default) | all (`direct-essential`, broad direct domains and CIDRs) |
| `full_domestic` | only `direct-essential` |
| `full` | none: everything except local destinations goes through the VPN |

Local, VPN-required, service and game lists, device profiles and the direct
SOCKS listeners are unaffected. The change is applied by the next controller
round without a restart: the static broad-direct set is rewritten in one nft
transaction, the DNS broker classifies new answers with the new view, and the
address bindings of lists the mode switched off are dropped. Classification
applies to new flows only, so established connections keep their channel.
`split` is stored as an absent key; any other mode is stored, and a rollback
to the 0.6 controller needs it removed first (RECOVERY-0.6).

### Tunnel queueing (CAKE)

`settings` reports `tunnel_qos`; a patch needs the complete object
`{"tunnel_qos":{"enabled":true,"upload_kbit":45000,"download_kbit":90000}}`
(rates 0 or 1000-10000000 kbit/s, at least one non-zero when enabled). The
controller keeps CAKE (`besteffort triple-isolate nat`) as the root qdisc of
`flr_awg` for upload and, for download, redirects `flr_awg` ingress to the
`flr_ifb` device with CAKE `ingress`. Set the rates slightly below the real
line rate; above it CAKE does nothing useful. The qdiscs are reinstalled when
netifd recreates `flr_awg`, and removed when queueing is turned off or the VPN
stops. Only FLR's own qdiscs are touched. Disabled is stored as an absent key
(same rollback note as the routing mode). The image includes
`kmod-sched-core`, `kmod-sched-cake`, `kmod-ifb` and `tc-full`.
