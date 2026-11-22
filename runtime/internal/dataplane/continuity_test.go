package dataplane

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
)

func TestSelectionPublishesStableContinuityEgress(t *testing.T) {
	batch, err := SelectionBatch(contract.Selection{General: contract.Continuity, Games: contract.Continuity}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(batch, "0x01000000 : goto continuity, 0x02000000 : goto continuity") {
		t.Fatalf("protected classes did not select the same stable egress: %s", batch)
	}
}

func TestContinuityBuildKeepsOneGuardedEgressForProtectedFlows(t *testing.T) {
	p := mustPolicy(t)
	o := Options{LAN: "br-lan", WAN: "wan0", Continuity: true, DNSPort: "1054",
		Selection: contract.Selection{General: contract.Continuity, Games: contract.Continuity}}
	batch, err := Build(p, o)
	if err != nil {
		t.Fatal(err)
	}
	wantRule := Rule{Priority: 1773, Table: 774, Mark: 0x50000000, Mask: 0x70000000}
	if !slices.Contains(batch.Rules, wantRule) {
		t.Fatal("no separate continuity policy route for forwarded and local traffic")
	}
	for _, route := range []Route{{Table: 774, Device: "flr_cont", Metric: 100}, {Table: 774, Unreachable: true, Metric: 32767}} {
		if !slices.Contains(batch.Routes, route) {
			t.Errorf("missing continuity route %+v", route)
		}
	}
	for _, rule := range []string{
		"0x01000000 : goto continuity, 0x02000000 : goto continuity",
		"chain continuity { ct mark set (ct mark & 0x8fffffff) | 0x50000000; jump restore; }",
		"ct mark & 0xff800000 != 0 jump restore",
		`iifname "br-lan" meta nfproto ipv4 oifname "flr_cont" masquerade`,
	} {
		if !strings.Contains(batch.Nft, rule) {
			t.Errorf("missing continuity nftables rule %q", rule)
		}
	}
	guard := `meta mark & 0x70000000 == 0x50000000 oifname != "flr_cont" counter drop`
	if strings.Count(batch.Nft, guard) != 2 {
		t.Error("forwarded and locally generated anchored packets must both stay on flr_cont")
	}
	ingress := `iifname "flr_cont" ct state != { established, related } counter drop`
	if strings.Count(batch.Nft, ingress) != 2 {
		t.Error("unsolicited anchor traffic must not reach the router or LAN")
	}

	direct, err := Build(p.ForMode(policy.ModeDirect), o)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(direct.Nft, "chain routing_mode {\n  goto route_direct\n }") || strings.Contains(direct.Nft, "redirect to :1054") {
		t.Fatal("continuity intercepted new ISP-direct traffic")
	}
}

func TestContinuityRoutingIsOptIn(t *testing.T) {
	o := Options{LAN: "br-lan", WAN: "wan0", Selection: contract.Selection{General: contract.Continuity, Games: contract.Down}}
	p := mustPolicy(t)
	if _, err := Build(p, o); err == nil {
		t.Fatal("selection installed without continuity enabled")
	}
	o.Selection.General = contract.AWG
	batch, err := Build(p, o)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(batch.Nft, "flr_cont") || slices.Contains(batch.Rules, channelRule(contract.Continuity)) {
		t.Fatal("default routing installed continuity egress")
	}
	if strings.Count(batch.Nft, "meta mark & 0x70000000 == 0x50000000 counter drop") != 2 {
		t.Fatal("disabled continuity allowed stale anchored marks to reach another egress")
	}
}

func TestRouteRefreshRestoresContinuityOnlyForOwnedRule(t *testing.T) {
	for _, installed := range []bool{false, true} {
		snap := Snapshot{Own: true, Routes: []Route{
			{Table: 770, Device: "flr_awg", Metric: 100},
			{Table: 771, Device: "flr-hy", Metric: 100},
			{Table: 772, Device: "flr-vless", Metric: 100},
		}}
		if installed {
			snap.Rules = append(snap.Rules, channelRule(contract.Continuity))
		}
		var commands []string
		output := func(name string, args ...string) ([]byte, error) {
			if name == "ip" && slices.Equal(args, []string{"link", "show", "dev", "flr_cont"}) {
				return nil, nil
			}
			t.Fatalf("unexpected route refresh lookup: %s %v", name, args)
			return nil, nil
		}
		run := func(name string, args ...string) error {
			commands = append(commands, name+" "+strings.Join(args, " "))
			return nil
		}
		if err := ensureRoutesWith(snap, output, run); err != nil {
			t.Fatal(err)
		}
		var want []string
		if installed {
			want = []string{"ip -4 route replace default dev flr_cont metric 100 table 774"}
		}
		if !slices.Equal(commands, want) {
			t.Errorf("installed=%v: route refresh ran %v, want %v", installed, commands, want)
		}
	}
}

func TestContinuityOwnershipRejectsConflictingRulesAndRoutes(t *testing.T) {
	for _, snap := range []Snapshot{
		{Rules: []Rule{channelRule(contract.Continuity)}},
		{Own: true, Rules: []Rule{{Priority: 1773, Table: 100, Mark: 0x50000000, Mask: 0x70000000}}},
		{Routes: []Route{{Table: 774, Device: "flr_cont", Metric: 100}}},
		{Own: true, Routes: []Route{{Table: 774, Device: "eth1", Metric: 100}}},
	} {
		if err := Preflight(snap); err == nil {
			t.Fatalf("conflicting continuity state accepted: %+v", snap)
		}
	}
}

func TestRetireContinuityRoutesRetriesPartialCleanup(t *testing.T) {
	flushError := errors.New("fixture flush failure")
	snap := Snapshot{
		Own:    true,
		Rules:  []Rule{channelRule(contract.AWG), channelRule(contract.Continuity)},
		Routes: []Route{{Table: 770, Device: "flr_awg", Metric: 100}, {Table: 774, Device: "flr_cont", Metric: 100}},
	}
	var commands []string
	flushFailure := false
	run := func(name string, args ...string) error {
		command := name + " " + strings.Join(args, " ")
		commands = append(commands, command)
		switch command {
		case "ip -4 rule del pref 1773 fwmark 0x50000000/0x70000000 lookup 774":
			snap.Rules = snap.Rules[:1]
		case "ip -4 route flush table 774":
			if !flushFailure {
				flushFailure = true
				return flushError
			}
			snap.Routes = snap.Routes[:1]
		default:
			t.Fatalf("retirement touched another resource: %s", command)
		}
		return nil
	}
	if err := retireContinuityRoutes(snap, run); err != flushError {
		t.Fatalf("partial cleanup returned %v", err)
	}
	if err := retireContinuityRoutes(snap, run); err != nil {
		t.Fatal(err)
	}
	if err := retireContinuityRoutes(snap, run); err != nil {
		t.Fatal(err)
	}
	if len(commands) != 3 || len(snap.Rules) != 1 || len(snap.Routes) != 1 {
		t.Fatalf("retirement did not resume the owned route cleanup: %v", commands)
	}
}
