package dataplane

import (
	"errors"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/lan"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
	"net"
	"net/netip"
	"strings"
	"testing"
)

// These inspect the emitted kernel request, not checked-in config text.
func TestBuildRetainsFlowsAndScopesLAN(t *testing.T) {
	p, e := policy.Load("../policy/testdata/split")
	if e != nil {
		t.Fatal(e)
	}
	b, e := Build(p, Options{LAN: "br-lan", WAN: "eth1", TestClient: "192.168.8.100", Selection: contract.Selection{General: contract.AWG, Games: contract.Gecko}})
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(b.Nft, `iifname "br-lan" ip saddr 192.168.8.100 jump classify`) {
		t.Fatal("test policy escaped its LAN client")
	}
	if !strings.Contains(b.Nft, `ct mark & 0xff800000 != 0 jump restore`) {
		t.Fatal("healthy existing flow mark not restored with foreign bits retained")
	}
	if !strings.Contains(b.Nft, `ct mark & 0x10000000 != 0 meta mark set meta mark | 0x10000000`) {
		t.Fatal("foreign packet mark bits are overwritten")
	}
	if !strings.Contains(b.Nft, `ct state != new ip saddr != @profile_games4 return`) {
		t.Fatal("existing unowned flow reclassified")
	}
	if !strings.Contains(b.Nft, `0x01000000 : goto awg, 0x02000000 : goto gecko`) {
		t.Fatal("general/games selected the wrong channel")
	}
	if strings.Contains(b.Nft, `flush ruleset`) {
		t.Fatal("builder removes unrelated firewall")
	}
}

func TestEveryChannelKeepsTerminalUnreachable(t *testing.T) {
	p, e := policy.Load("../policy/testdata/split")
	if e != nil {
		t.Fatal(e)
	}
	b, e := Build(p, Options{LAN: "br-lan", WAN: "eth1", Selection: contract.Selection{General: contract.Down, Games: contract.Down}})
	if e != nil {
		t.Fatal(e)
	}
	seen := map[int]bool{}
	for _, r := range b.Routes {
		if r.Unreachable && r.Metric == 32767 {
			seen[r.Table] = true
		}
	}
	for _, table := range []int{770, 771, 772, 773} {
		if !seen[table] {
			t.Errorf("table %d falls through when device disappears", table)
		}
	}
	if !strings.Contains(b.Nft, `meta mark & 0x0f000000 { 0x01000000, 0x02000000 } oifname "eth1" counter drop`) {
		t.Fatal("missing scoped WAN kill switch")
	}
}

func TestGamingVLESSRequiresExplicitManualFlag(t *testing.T) {
	p, e := policy.Load("../policy/testdata/split")
	if e != nil {
		t.Fatal(e)
	}
	options := Options{LAN: "br-lan", WAN: "eth1", Selection: contract.Selection{General: contract.VLESS, Games: contract.VLESS}}
	if _, e = Build(p, options); e == nil {
		t.Fatal("automatic games selected VLESS")
	}
	options.ManualGames = true
	if _, e = Build(p, options); e != nil {
		t.Fatal(e)
	}
}

func TestPreflightRejectsOwnedResources(t *testing.T) {
	for _, s := range []Snapshot{
		{Rules: []Rule{{Priority: 1770, Table: 100, Mark: 0x10000000, Mask: 0x70000000}}},
		{Rules: []Rule{{Priority: 500, Table: 100, Mark: 0x01000000, Mask: 0xff000000}}},
		{Routes: []Route{{Table: 770, Device: "foreign0"}}},
	} {
		if e := Preflight(s); e == nil {
			t.Fatal("conflicting owner accepted")
		}
	}
	if e := Preflight(Snapshot{Rules: []Rule{{Priority: 32766, Table: 254}}}); e != nil {
		t.Fatal(e)
	}
}
func TestOwnershipStampDoesNotAuthorizeForeignRoutes(t *testing.T) {
	if e := Preflight(Snapshot{Own: true, Routes: []Route{{Table: 770, Device: "foreign0", Metric: 100}}}); e == nil {
		t.Fatal("stamp accepted a foreign route")
	}
}
func TestBootGuardBlocksUnclassifiedPublicWANAndKeepsDirect(t *testing.T) {
	p, e := policy.Load("../policy/testdata/split")
	if e != nil {
		t.Fatal(e)
	}
	guard, e := BuildBootGuard(p, Options{LAN: "br-lan", WAN: "eth1", Selection: contract.Selection{General: contract.Down, Games: contract.Down}})
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(guard, `ct mark & 0x0f000000 != 0x03000000 counter drop`) {
		t.Fatal("boot leaks unclassified WAN before controller starts")
	}
	if strings.Contains(guard, "flush ruleset") {
		t.Fatal("boot guard owns foreign tables")
	}
}
func TestDeviceGamingProfileKeepsBankPriority(t *testing.T) {
	p, e := policy.Load("../policy/testdata/split")
	if e != nil {
		t.Fatal(e)
	}
	b, e := Build(p, Options{LAN: "br-lan", WAN: "eth1", Selection: contract.Selection{General: contract.AWG, Games: contract.Gecko}, Profiles: map[string]contract.Class{"192.168.8.126": contract.Games}})
	if e != nil {
		t.Fatal(e)
	}
	bank := strings.Index(b.Nft, "ip daddr @essential4")
	game := strings.Index(b.Nft, "ip saddr @profile_games4")
	if game < bank || game < 0 {
		t.Fatal("gaming device overrode required bank direct")
	}
}

func TestOwnershipDoesNotAllowForeignPrefixInOwnedTable(t *testing.T) {
	s := Snapshot{Own: true, Routes: []Route{{Table: 770, Device: "flr_awg", Metric: 100, Destination: "203.0.113.0/24"}}}
	if Preflight(s) == nil {
		t.Fatal("ownership accepted a foreign non-default route")
	}
}

func TestDirectGuardTableFollowsLAN(t *testing.T) {
	legacy := directGuardTable(lan.Legacy(), 1080, "eth1")
	want := "table inet flr_direct {\n comment \"tracegate-flr-direct-v1\"\n chain input {\n type filter hook input priority -5; policy accept;\n meta l4proto { tcp, udp } th dport 1080 iifname != \"br-lan\" counter drop\n meta l4proto { tcp, udp } th dport 1080 meta nfproto ipv6 counter drop\n meta l4proto { tcp, udp } th dport 1080 ip saddr != 192.168.8.0/24 counter drop\n }\n chain output {\n type filter hook output priority -151; policy accept;\n meta mark & 0xffc00000 == 0x80400000 ct mark set (ct mark & 0x003fffff) | 0x80400000\n meta mark & 0xffc00000 == 0x80400000 oifname != \"eth1\" counter drop\n }\n}\n"
	if legacy != want {
		t.Fatalf("192.168.8.1/24 guard changed:\n%s", legacy)
	}
	for cidr, prefix := range map[string]string{"192.168.1.1/24": "192.168.1.0/24", "10.10.0.1/24": "10.10.0.0/24"} {
		p := netip.MustParsePrefix(cidr)
		router, e := lan.New(p.Addr(), p.Bits())
		if e != nil {
			t.Fatal(e)
		}
		got := directGuardTable(router, 1080, "eth1")
		if got != strings.Replace(want, "192.168.8.0/24", prefix, 1) || strings.Contains(got, "192.168.8") {
			t.Fatalf("%s:\n%s", cidr, got)
		}
	}
}

func TestPermanentDirectGuardRejectsForeignBind(t *testing.T) {
	router, _ := lan.New(netip.MustParseAddr("192.168.1.1"), 24)
	for _, bind := range []string{"192.168.8.1", "192.168.1.2", "0.0.0.0", ""} {
		if PermanentDirectGuard(router, bind, 1080, "eth1", true) == nil {
			t.Fatalf("accepted bind %q", bind)
		}
	}
	if PermanentDirectGuard(router, "192.168.1.1", 1088, "eth1", true) == nil || PermanentDirectGuard(lan.LAN{}, "192.168.1.1", 1080, "eth1", true) == nil {
		t.Fatal("accepted invalid guard")
	}
}

func TestDeviceProfilesFollowRouterLAN(t *testing.T) {
	check := func(cidr string, ok, ignored []string) {
		p := netip.MustParsePrefix(cidr)
		router, e := lan.New(p.Addr(), p.Bits())
		if e != nil {
			t.Fatal(e)
		}
		o := Options{LAN: "br-lan", WAN: "eth1", Net: router, Selection: contract.Selection{General: contract.Down, Games: contract.Down}}
		for _, ip := range append(append([]string{}, ok...), ignored...) {
			o.Profiles = map[string]contract.Class{ip: contract.Games}
			// Structure only: a stored profile never makes the options invalid.
			if e := ValidateOptions(o); e != nil {
				t.Fatalf("%s %s: %v", cidr, ip, e)
			}
		}
		for _, ip := range ok {
			if active, skipped := ActiveProfiles(map[string]contract.Class{ip: contract.Games}, router); active[ip] != contract.Games || len(skipped) != 0 {
				t.Fatalf("%s did not keep %s", cidr, ip)
			}
		}
		for _, ip := range ignored {
			active, skipped := ActiveProfiles(map[string]contract.Class{ip: contract.Games}, router)
			if len(active) != 0 || len(skipped) != 1 || skipped[0].Client != ip || skipped[0].Class != contract.Games || skipped[0].Reason == "" {
				t.Fatalf("%s kept %s: %+v", cidr, ip, skipped)
			}
		}
	}
	check("192.168.1.1/24", []string{"192.168.1.2", "192.168.1.254"}, []string{"192.168.1.1", "192.168.1.0", "192.168.1.255", "192.168.8.2"})
	check("10.10.0.1/24", []string{"10.10.0.7"}, []string{"10.10.0.1", "10.10.0.0", "10.10.0.255", "192.168.1.2"})
	check("192.168.8.1/24", []string{"192.168.8.126"}, []string{"192.168.8.1", "192.168.8.0", "192.168.8.255", "192.168.1.2"})
	base := Options{LAN: "br-lan", WAN: "eth1", Selection: contract.Selection{General: contract.Down, Games: contract.Down}}
	for _, bad := range []string{"8.8.8.8", "100.65.1.2", "fd00::2", "::ffff:192.168.1.2", "192.168.1.x", ""} {
		o := base
		o.Profiles = map[string]contract.Class{bad: contract.Games}
		if ValidateOptions(o) == nil {
			t.Fatalf("profile %q accepted", bad)
		}
	}
	o := base
	o.Profiles = map[string]contract.Class{"192.168.1.2": "vpn"}
	if ValidateOptions(o) == nil {
		t.Fatal("unknown class accepted")
	}
	o = Options{LAN: "br-lan", WAN: "eth1", Net: lan.LAN{Addr: netip.MustParseAddr("8.8.8.8"), Prefix: netip.MustParsePrefix("8.8.8.0/24")}, Selection: contract.Selection{General: contract.Down, Games: contract.Down}}
	if ValidateOptions(o) == nil {
		t.Fatal("public LAN accepted")
	}
}

func TestDeviceValidationUsesDiscoveredLAN(t *testing.T) {
	useLAN(t, "192.168.1.1/24")
	// The device gate checks structure; LAN membership of new profiles is the
	// controller's check, and removing a stale profile must reach the gate.
	if validateDevice("192.168.1.30") != nil || validateDevice("192.168.8.30") != nil || validateDevice("8.8.8.8") == nil || validateDevice("192.168.1.x") == nil {
		t.Fatal("device validation is not structural")
	}
	b, e := Build(mustPolicy(t), Options{LAN: "br-lan", WAN: "eth1", Selection: contract.Selection{General: contract.AWG, Games: contract.Gecko}, Profiles: map[string]contract.Class{"192.168.1.126": contract.Games}})
	if e != nil || !strings.Contains(b.Nft, "192.168.1.126") {
		t.Fatalf("%v", e)
	}
}

// Regression (a): a profile saved for the old 192.168.8.0/24 LAN is not an
// error on a router now at 192.168.1.1; it is skipped and reported.
func TestBuildSkipsProfilesOutsideCurrentLAN(t *testing.T) {
	useLAN(t, "192.168.1.1/24")
	o := Options{LAN: "br-lan", WAN: "eth1", Selection: contract.Selection{General: contract.AWG, Games: contract.Gecko}, Profiles: map[string]contract.Class{"192.168.8.50": contract.Direct, "192.168.1.20": contract.Games}}
	b, e := Build(mustPolicy(t), o)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(b.Nft, "192.168.8.50") || !strings.Contains(b.Nft, " set profile_games4 { type ipv4_addr; elements = { 192.168.1.20 }; }\n") || !strings.Contains(b.Nft, " set profile_direct4 { type ipv4_addr; }\n") {
		t.Fatalf("ignored profile rendered:\n%s", b.Nft)
	}
	if b.LAN.String() != "192.168.1.1/24" || len(b.Profiles) != 1 || b.Profiles["192.168.1.20"] != contract.Games {
		t.Fatalf("%v %v", b.LAN, b.Profiles)
	}
	_, ignored := ActiveProfiles(o.Profiles, b.LAN)
	if len(ignored) != 1 || ignored[0] != (IgnoredProfile{Client: "192.168.8.50", Class: contract.Direct, Reason: "outside LAN 192.168.1.0/24"}) {
		t.Fatalf("%+v", ignored)
	}
	if _, e = BuildBootGuard(mustPolicy(t), o); e != nil {
		t.Fatal(e)
	}
}

// With the LAN unknown nothing is dropped: a real device keeps its profile and
// a stale element matches no LAN source.
func TestBuildKeepsProfilesWhenLANUnknown(t *testing.T) {
	old := lan.Source
	lan.Source = func(string) ([]net.Addr, error) { return nil, errors.New("no IPv4 on br-lan") }
	t.Cleanup(func() { lan.Source = old })
	b, e := Build(mustPolicy(t), Options{LAN: "br-lan", WAN: "eth1", Selection: contract.Selection{General: contract.AWG, Games: contract.Gecko}, Profiles: map[string]contract.Class{"192.168.8.50": contract.Direct, "192.168.1.20": contract.Games}})
	if e != nil || !b.LAN.IsZero() || len(b.Profiles) != 2 || !strings.Contains(b.Nft, "192.168.8.50") || !strings.Contains(b.Nft, "192.168.1.20") {
		t.Fatalf("%v %v %v", e, b.LAN, b.Profiles)
	}
}

// The 192.168.8.1/24 router renders exactly as before.
func TestLegacyLANProfileRenderingUnchanged(t *testing.T) {
	b, e := Build(mustPolicy(t), Options{LAN: "br-lan", WAN: "eth1", Selection: contract.Selection{General: contract.AWG, Games: contract.Gecko}, Profiles: map[string]contract.Class{"192.168.8.126": contract.Games, "192.168.8.2": contract.Direct, "192.168.8.3": contract.Direct, "192.168.8.40": contract.General}})
	if e != nil {
		t.Fatal(e)
	}
	want := " set profile_pending4 { type ipv4_addr; }\n set profile_direct4 { type ipv4_addr; elements = { 192.168.8.2, 192.168.8.3 }; }\n set profile_general4 { type ipv4_addr; elements = { 192.168.8.40 }; }\n set profile_games4 { type ipv4_addr; elements = { 192.168.8.126 }; }\n"
	if !strings.Contains(b.Nft, want) || b.LAN != lan.Legacy() || len(b.Profiles) != 4 {
		t.Fatalf("legacy rendering changed:\n%s", b.Nft)
	}
}

func TestBuildOutputIsIndependentOfLANPrefix(t *testing.T) {
	p := mustPolicy(t)
	opts := func(cidr string) Options {
		pp := netip.MustParsePrefix(cidr)
		router, _ := lan.New(pp.Addr(), pp.Bits())
		return Options{LAN: "br-lan", WAN: "eth1", Net: router, Selection: contract.Selection{General: contract.AWG, Games: contract.Gecko}}
	}
	base, e := Build(p, opts("192.168.8.1/24"))
	if e != nil {
		t.Fatal(e)
	}
	for _, cidr := range []string{"192.168.1.1/24", "10.10.0.1/24"} {
		b, e := Build(p, opts(cidr))
		if e != nil || b.Nft != base.Nft {
			t.Fatalf("%s: nft batch depends on the LAN prefix (%v)", cidr, e)
		}
	}
}

func mustPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	p, e := policy.Load("../policy/testdata/split")
	if e != nil {
		t.Fatal(e)
	}
	return p
}
