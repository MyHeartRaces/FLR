package dataplane

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
)

func TestStaticSetsBatchFollowsRoutingMode(t *testing.T) {
	p, e := policy.Load("../policy/testdata/split")
	if e != nil {
		t.Fatal(e)
	}
	split := StaticSetsBatch(p)
	full := StaticSetsBatch(p.ForMode(policy.ModeFull))
	for _, want := range []string{"flush set inet flr local4\n", "flush set inet flr broad_direct4\n", "flush set inet flr service_static4\n", "add element inet flr service_static4 { 17.0.0.0/8 }"} {
		if !strings.Contains(split, want) || !strings.Contains(full, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if !strings.Contains(split, "add element inet flr broad_direct4 { 5.255.255.0/24 }") || strings.Contains(full, "add element inet flr broad_direct4") {
		t.Fatalf("broad direct set does not follow the mode:\n%s\n%s", split, full)
	}
	if strings.Contains(split, "delete table") || strings.Contains(split, "flush ruleset") {
		t.Fatal("static set update must not replace the table")
	}
}

func TestCustomRulesRenderAsSetsMatchedBeforeLists(t *testing.T) {
	base, e := policy.Load("../policy/testdata/split")
	if e != nil {
		t.Fatal(e)
	}
	rules := policy.EmptyCustomRules()
	rules.Rules = []policy.CustomRule{
		{Type: "cidr", Value: "17.1.0.0/16", Mode: "vpn", Enabled: true},
		{Type: "ip", Value: "17.1.2.3", Mode: "direct", Enabled: true},
		{Type: "cidr", Value: "5.255.255.0/25", Mode: "vpn", Enabled: false},
	}
	if e = rules.Normalize(netip.Prefix{}); e != nil {
		t.Fatal(e)
	}
	p := base.WithCustom(rules)
	b, e := Build(p, Options{LAN: "br-lan", WAN: "eth1", Selection: contract.Selection{General: contract.AWG, Games: contract.Gecko}})
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(b.Nft, " set custom_direct4 { type ipv4_addr; flags interval; auto-merge; elements = { 17.1.2.3/32 }; }") {
		t.Fatalf("custom direct set missing:\n%s", b.Nft)
	}
	if !strings.Contains(b.Nft, " set custom_vpn4 { type ipv4_addr; flags interval; auto-merge; elements = { 17.1.0.0/23, 17.1.2.0/31, 17.1.2.2/32, ") {
		t.Fatalf("custom vpn set must exclude the more specific direct address:\n%s", b.Nft)
	}
	order := []string{"ip daddr @local4 return", "ct mark & 0xff800000 != 0 jump restore", "ip daddr @custom_vpn4 ", "ip daddr @custom_direct4 ", "ip daddr @required4 ", "ip daddr @essential4 ", "ip daddr @service_static4 ", "ip daddr @broad_direct4 "}
	previous := -1
	for _, rule := range order {
		index := strings.Index(b.Nft, rule)
		if index <= previous {
			t.Fatalf("custom rules not matched before the lists: %q", rule)
		}
		previous = index
	}
	batch := StaticSetsBatch(p)
	for _, want := range []string{"flush set inet flr custom_vpn4\n", "flush set inet flr custom_direct4\n", "add element inet flr custom_direct4 { 17.1.2.3/32 }"} {
		if !strings.Contains(batch, want) {
			t.Fatalf("missing %q in\n%s", want, batch)
		}
	}
	if full := StaticSetsBatch(p.ForMode(policy.ModeFull)); strings.Contains(full, "add element inet flr custom_direct4") || !strings.Contains(full, "add element inet flr custom_vpn4") {
		t.Fatalf("full mode must drop custom direct and keep custom vpn:\n%s", full)
	}
	if empty := StaticSetsBatch(base); !strings.Contains(empty, "flush set inet flr custom_vpn4\n") || strings.Contains(empty, "add element inet flr custom_") {
		t.Fatalf("policy without custom rules must still flush the custom sets:\n%s", empty)
	}
}
