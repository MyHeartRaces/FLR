package dataplane

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/lan"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
)

func TestRoutingFallbackIsPartOfNewFlowClassification(t *testing.T) {
	p, err := policy.Load("../policy/testdata/split")
	if err != nil {
		t.Fatal(err)
	}
	for mode, class := range map[string]contract.Class{"tunnel": contract.Direct, "proxy": contract.General} {
		view := p.ForMode(mode)
		batch, err := Build(view, Options{LAN: "br-lan", WAN: "eth1", Selection: contract.Selection{General: contract.Down, Games: contract.Down}})
		if err != nil {
			t.Fatal(err)
		}
		mark := fmt.Sprintf("ct mark set (ct mark & 0x007fffff) | %#08x goto selected", contract.ClassMark(class))
		if !strings.Contains(batch.Nft, "goto routing_default\n") || !strings.Contains(batch.Nft, "chain routing_default {\n  "+mark+"\n") {
			t.Errorf("%s: missing mode fallback in classifier", mode)
		}
		if got := StaticSetsBatch(view); !strings.Contains(got, "flush chain inet flr routing_default\nadd rule inet flr routing_default "+mark+"\n") {
			t.Errorf("%s: missing atomic mode fallback in %s", mode, got)
		}
	}
}

func TestDirectRoutingBypassesPolicyAndKeepsExistingMarks(t *testing.T) {
	p, err := policy.Load("../policy/testdata/split")
	if err != nil {
		t.Fatal(err)
	}
	o := Options{LAN: "br-lan", WAN: "eth1", Selection: contract.Selection{General: contract.AWG, Games: contract.Gecko}}
	direct := p.ForMode(policy.ModeDirect)
	batch, err := Build(direct, o)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"chain routing_mode {\n  goto route_direct\n }",
		"chain routing_guards {\n }",
		"ct mark & 0xff800000 != 0 goto restore\n  ct mark set (ct mark & 0x007fffff) | 0x43000000\n",
		"ct mark & 0xff800000 == 0x43000000 return\n  iifname \"br-lan\" jump routing_mode\n",
		"meta mark & 0x0f000000 { 0x01000000, 0x02000000 } oifname \"eth1\" counter drop",
	} {
		if !strings.Contains(batch.Nft, want) {
			t.Errorf("Direct ruleset is missing %q", want)
		}
	}
	if update := StaticSetsBatch(direct); !strings.Contains(update, "flush chain inet flr routing_mode\nadd rule inet flr routing_mode goto route_direct\nflush chain inet flr routing_guards\n") {
		t.Error("live switch to Direct does not turn off policy routing and guards together")
	}
	if update := StaticSetsBatch(p); !strings.Contains(update, "add rule inet flr routing_mode goto classify\nflush chain inet flr routing_guards\nadd rule inet flr routing_guards jump policy_guards\n") {
		t.Error("live switch to a VPN policy does not restore policy routing and guards together")
	}
	guard, err := BuildBootGuard(p, o)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(guard, "meta nfproto ipv6 ct mark & 0xff800000 != 0x43000000 counter drop") {
		t.Error("boot guard blocks IPv6 flows that began in Direct mode")
	}
}

func TestRoutingModeUpdatesDNSInterception(t *testing.T) {
	p := mustPolicy(t)
	o := Options{LAN: "lan0", WAN: "wan0", TestClient: "10.240.5.20", DNSPort: "1054", Selection: contract.Selection{General: contract.Down, Games: contract.Down}}
	redirect := `iifname "lan0" ip saddr 10.240.5.20 meta nfproto ipv4 meta l4proto { tcp, udp } th dport 53 redirect to :1054`
	for _, mode := range []string{policy.ModeDirect, policy.ModeProxy, policy.ModeTunnel} {
		t.Run(mode, func(t *testing.T) {
			view := p.ForMode(mode)
			initial, err := Build(view, o)
			if err != nil {
				t.Fatal(err)
			}
			transition, err := RoutingPolicyBatch(view, o)
			if err != nil {
				t.Fatal(err)
			}
			expected := "flush chain inet flr dns\n"
			dnsChain := "chain dns { type nat hook prerouting priority -100; policy accept;\n"
			if mode != policy.ModeDirect {
				expected += "add rule inet flr dns " + redirect + "\n"
				dnsChain += "  " + redirect + "\n"
			}
			if !strings.Contains(initial.Nft, dnsChain+" }") {
				t.Error("incorrect DNS chain in the initial ruleset")
			}
			if !strings.HasSuffix(transition, expected) {
				t.Error("incorrect DNS change in the mode transaction")
			}
		})
	}
}

func TestRoutingModePublishesActiveDeviceProfiles(t *testing.T) {
	p := mustPolicy(t).ForMode(policy.ModeProxy)
	o := Options{
		LAN: "br-lan", WAN: "eth1", Selection: contract.Selection{General: contract.Down, Games: contract.Down},
		Net:      lan.LAN{Addr: netip.MustParseAddr("10.240.5.1"), Prefix: netip.MustParsePrefix("10.240.5.0/24")},
		Profiles: map[string]contract.Class{"10.240.5.20": contract.Games, "10.240.6.20": contract.General},
	}
	batch, err := RoutingPolicyBatch(p, o)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(batch, "flush set inet flr profile_games4\nadd element inet flr profile_games4 { 10.240.5.20 }\n") ||
		!strings.Contains(batch, "flush set inet flr profile_general4\n") ||
		strings.Contains(batch, "10.240.6.20") || strings.Contains(batch, "profile_pending4") {
		t.Fatal("policy transaction did not replace only the current LAN's active profiles")
	}
}

func TestPrepareRoutingBootGuardRefreshesOwnedInclude(t *testing.T) {
	p := mustPolicy(t).ForMode(policy.ModeDirect)
	o := Options{LAN: "br-lan", WAN: "eth1", Selection: contract.Selection{General: contract.Down, Games: contract.Down}}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "boot-guard.nft")
	if result, err := prepareRoutingBootGuard(path, p, o); result != "" || err != nil {
		t.Fatalf("absent guard: %q, %v", result, err)
	}
	foreign := "table inet flr_boot {}\n"
	if err := os.WriteFile(path, []byte(foreign), 0644); err != nil {
		t.Fatal(err)
	}
	if result, err := prepareRoutingBootGuard(path, p, o); result != "" || err != nil {
		t.Fatalf("foreign guard: %q, %v", result, err)
	}
	if raw, err := os.ReadFile(path); string(raw) != foreign || err != nil {
		t.Fatal("foreign guard was changed", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("# tracegate-flr-v1\nold guard\n"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := prepareRoutingBootGuard(path, p, o)
	if err != nil || !strings.Contains(result, "meta nfproto ipv6 ct mark & 0xff800000 != 0x43000000 counter drop") {
		t.Fatalf("owned guard was not prepared for the nft transaction: %q, %v", result, err)
	}
	if raw, err := os.ReadFile(path); string(raw) != result || err != nil {
		t.Fatal("firewall include was not updated", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if retry, err := prepareRoutingBootGuard(path, p, o); retry != result || err != nil {
		t.Fatal("retry cannot refresh the live guard", err)
	}
	if after, err := os.Stat(path); err != nil || !os.SameFile(before, after) {
		t.Fatal("retry rewrote an unchanged include", err)
	}
}

func TestCheckBootOwnershipRejectsUnverifiedLiveTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "boot-guard.nft")
	listError := errors.New("cannot list tables")
	failed := func(string, ...string) ([]byte, error) { return nil, listError }
	if err := checkBootOwnership(path, failed); !errors.Is(err, listError) {
		t.Fatal("failed table listing was treated as an absent guard", err)
	}
	present := func(string, ...string) ([]byte, error) { return []byte("table inet flr_boot\n"), nil }
	if err := checkBootOwnership(path, present); err == nil {
		t.Fatal("live guard without an include was treated as owned")
	}
	if err := os.WriteFile(path, []byte("foreign guard\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkBootOwnership(path, present); err == nil {
		t.Fatal("live guard with a foreign include was treated as owned")
	}
	if err := os.WriteFile(path, []byte("# tracegate-flr-v1\nold guard\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkBootOwnership(path, present); err != nil {
		t.Fatal("existing owned guard was rejected", err)
	}
}

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
	order := []string{"ip daddr @local4 ct mark & 0xff800000 == 0 return", "ct mark & 0xff800000 != 0 jump restore", "ip daddr @custom_vpn4 ", "ip daddr @custom_direct4 ", "ip daddr @required4 ", "ip daddr @essential4 ", "ip daddr @service_static4 ", "ip daddr @broad_direct4 "}
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
