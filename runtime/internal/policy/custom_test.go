package policy

import (
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func customRules(t *testing.T, lan string, rules ...CustomRule) *CustomRules {
	t.Helper()
	r := EmptyCustomRules()
	r.Rules = rules
	var prefix netip.Prefix
	if lan != "" {
		prefix = netip.MustParsePrefix(lan)
	}
	if err := r.Normalize(prefix); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCustomRuleValidation(t *testing.T) {
	lan := netip.MustParsePrefix("192.168.1.1/24")
	good := []struct{ in, typ, value string }{
		{"Example.COM.", "domain", "example.com"}, {"*.cdn.example.net", "domain", "cdn.example.net"}, {".example.org", "domain", "example.org"},
		{"xn--e1afmkfd.example", "domain", "xn--e1afmkfd.example"}, {"198.51.100.7", "ip", "198.51.100.7"},
		{"198.51.100.77/24", "cidr", "198.51.100.0/24"}, {"198.51.100.10 - 198.51.100.20", "range", "198.51.100.10-198.51.100.20"},
		{"my-host.example.com", "domain", "my-host.example.com"},
	}
	for _, c := range good {
		rule := CustomRule{Value: c.in, Mode: "direct"}
		if err := rule.Normalize(lan); err != nil || rule.Type != c.typ || rule.Value != c.value {
			t.Errorf("%q: %v %s %s", c.in, err, rule.Type, rule.Value)
		}
	}
	bad := []CustomRule{
		{Value: "example.com", Mode: "proxy"}, {Value: "com", Mode: "vpn"}, {Value: "exa mple.com", Mode: "vpn"},
		{Value: "пример.рф", Mode: "vpn"}, {Value: "-bad.example.com", Mode: "vpn"}, {Value: "example.123", Mode: "vpn"},
		{Value: "0.0.0.0/0", Mode: "direct"}, {Value: "10.0.0.0/7", Mode: "direct"}, {Value: "2001:db8::/32", Mode: "vpn"},
		{Value: "2001:db8::1", Mode: "vpn", Type: "ip"}, {Value: "127.0.0.1", Mode: "direct"}, {Value: "224.0.0.1", Mode: "vpn"},
		{Value: "255.255.255.255", Mode: "vpn"}, {Value: "192.168.1.0/24", Mode: "vpn"}, {Value: "192.168.0.0/16", Mode: "vpn"},
		{Value: "192.168.1.20", Mode: "vpn"}, {Value: "198.51.100.20-198.51.100.10", Mode: "vpn", Type: "range"},
		{Value: "1.0.0.1-1.255.255.254", Mode: "vpn"}, {Value: "example.com", Mode: "vpn", Type: "regex"},
		{Value: "example.com", Mode: "vpn", Comment: strings.Repeat("x", MaxCustomComment+1)}, {Value: "example.com", Mode: "vpn", Comment: "a\nb"},
		{Value: "", Mode: "vpn"}, {Value: strings.Repeat("a.", 130) + "com", Mode: "vpn"},
	}
	for _, rule := range bad {
		if err := rule.Normalize(lan); err == nil {
			t.Errorf("accepted %+v", rule)
		}
	}
	// The router LAN is only refused as a VPN destination.
	direct := CustomRule{Value: "192.168.1.0/24", Mode: "direct"}
	if err := direct.Normalize(lan); err != nil {
		t.Fatal(err)
	}
	r := EmptyCustomRules()
	r.Rules = []CustomRule{{Value: "198.51.100.0/24", Mode: "vpn"}, {Value: "198.51.100.0-198.51.100.255", Mode: "direct"}}
	if err := r.Normalize(lan); err == nil || !strings.Contains(err.Error(), "repeats rule 1") {
		t.Fatalf("same destination twice: %v", err)
	}
	r.Rules = []CustomRule{{Value: "Example.com", Mode: "vpn"}, {Value: "example.com.", Mode: "direct"}}
	if err := r.Normalize(lan); err == nil {
		t.Fatal("same domain in both modes accepted")
	}
	r.Rules = make([]CustomRule, MaxCustomRules+1)
	if err := r.Normalize(lan); err == nil {
		t.Fatal("rule count not bounded")
	}
	if err := (&CustomRules{Format: "x", Version: 1}).Normalize(lan); err == nil {
		t.Fatal("unknown format accepted")
	}
}

func TestCustomRuleIDsAreStableAndUnique(t *testing.T) {
	a := customRules(t, "", CustomRule{Value: "example.com", Mode: "vpn"}, CustomRule{ID: "keep_me", Value: "example.net", Mode: "direct"}, CustomRule{ID: "keep_me", Value: "example.org", Mode: "direct"})
	b := customRules(t, "", CustomRule{Value: "example.com", Mode: "vpn"}, CustomRule{ID: "keep_me", Value: "example.net", Mode: "direct"}, CustomRule{ID: "keep_me", Value: "example.org", Mode: "direct"})
	if a.Rules[1].ID != "keep_me" || a.Rules[2].ID == "keep_me" || a.Rules[0].ID == "" || !reflect.DeepEqual(a, b) {
		t.Fatalf("%+v", a.Rules)
	}
	if a.Revision() != b.Revision() || a.Revision() == EmptyCustomRules().Revision() {
		t.Fatal("revision must follow the rule list")
	}
	if id := a.NewRuleID(a.Rules[0]); id == a.Rules[0].ID || id == "" {
		t.Fatal("new ID collides")
	}
}

func TestRangePrefixesAndResolution(t *testing.T) {
	got := rangePrefixes(v4(netip.MustParseAddr("198.51.100.10")), v4(netip.MustParseAddr("198.51.100.20")))
	want := []string{"198.51.100.10/31", "198.51.100.12/30", "198.51.100.16/30", "198.51.100.20/32"}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("%v", got)
		}
	}
	if all := rangePrefixes(0, 0xffffffff); len(all) != 1 || all[0].String() != "0.0.0.0/0" {
		t.Fatalf("full range: %v", all)
	}
	p := netip.MustParsePrefix
	vpn, direct := resolveCustomIPs([]netip.Prefix{p("198.51.100.0/24"), p("203.0.113.0/24")}, []netip.Prefix{p("198.51.100.128/25"), p("198.51.100.200/32"), p("203.0.113.0/24")})
	if strings.Join(prefixStrings(vpn), ",") != "198.51.100.0/25,203.0.113.0/24" || strings.Join(prefixStrings(direct), ",") != "198.51.100.128/25" {
		t.Fatalf("vpn %v direct %v", vpn, direct)
	}
	vpn, direct = resolveCustomIPs([]netip.Prefix{p("198.51.100.0/24"), p("198.51.100.64/26")}, []netip.Prefix{p("198.51.100.0/25")})
	if strings.Join(prefixStrings(vpn), ",") != "198.51.100.64/26,198.51.100.128/25" || strings.Join(prefixStrings(direct), ",") != "198.51.100.0/26" {
		t.Fatalf("nested: vpn %v direct %v", vpn, direct)
	}
}

func prefixStrings(list []netip.Prefix) []string {
	var out []string
	for _, p := range list {
		out = append(out, p.String())
	}
	return out
}

func TestCustomRulesPrecedeListsAndFollowModes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "policy")
	writePolicy(t, dir, []string{"198.51.100.0/24"})
	base, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	base.sources["vpn-required"].suffix["example.com"] = true
	base.sources["direct-essential"].suffix["example.net"] = true
	base.sources["local-domains"].suffix["lan"] = true
	rules := customRules(t, "192.168.1.1/24",
		CustomRule{Value: "example.com", Mode: "direct", Enabled: true},
		CustomRule{Value: "secure.example.com", Mode: "vpn", Enabled: true},
		CustomRule{Value: "example.net", Mode: "vpn", Enabled: true},
		CustomRule{Value: "printer.lan", Mode: "vpn", Enabled: true},
		CustomRule{Value: "example.org", Mode: "direct", Enabled: false},
		CustomRule{Value: "198.51.100.64/26", Mode: "vpn", Enabled: true},
		CustomRule{Value: "203.0.113.5", Mode: "direct", Enabled: true},
	)
	p := base.WithCustom(rules)
	domains := []struct {
		name   string
		class  Class
		source string
	}{
		{"www.example.com", Direct, "direct-essential"}, {"a.secure.example.com", General, "vpn-required"},
		{"example.net", General, "vpn-required"}, {"printer.lan", Local, "local-domains"},
		{"example.org", General, ""},
	}
	for _, c := range domains {
		if class, source := p.DomainDecision(c.name); class != c.class || source != c.source {
			t.Errorf("%s: %s/%s", c.name, class, source)
		}
	}
	if c, _ := base.DomainDecision("www.example.com"); c != General {
		t.Fatal("base policy changed by WithCustom")
	}
	ips := map[string]Class{"198.51.100.10": Direct, "198.51.100.70": General, "203.0.113.5": Direct, "203.0.113.6": General}
	for ip, want := range ips {
		if got := p.ClassifyIP(netip.MustParseAddr(ip)); got != want {
			t.Errorf("%s: %s", ip, got)
		}
	}
	full := p.ForMode(ModeFull)
	if c, _ := full.DomainDecision("www.example.com"); c != General {
		t.Fatal("custom direct must be ignored in full mode")
	}
	if c, _ := full.DomainDecision("example.net"); c != General || full.ClassifyIP(netip.MustParseAddr("203.0.113.5")) != General || len(full.CIDRs(CustomDirectSource)) != 0 || len(full.CIDRs(CustomVPNSource)) == 0 {
		t.Fatal("full mode keeps custom vpn and drops custom direct")
	}
	domestic := p.ForMode(ModeFullDomestic)
	if c, _ := domestic.DomainDecision("www.example.com"); c != Direct || domestic.ClassifyIP(netip.MustParseAddr("203.0.113.5")) != Direct {
		t.Fatal("custom direct must apply in full_domestic")
	}
	if !ActiveInMode(CustomVPNSource, ModeFull) || ActiveInMode(CustomDirectSource, ModeFull) || !ActiveInMode(CustomDirectSource, ModeFullDomestic) || ActiveInMode("roscom-direct-ips", ModeFullDomestic) {
		t.Fatal("mode table")
	}
	empty := base.WithCustom(nil)
	if c, s := empty.DomainDecision("www.example.com"); c != General || s != "vpn-required" {
		t.Fatal("empty custom rules change decisions")
	}
}

func TestInspectAndEntries(t *testing.T) {
	info, err := Inspect("testdata/split")
	if err != nil {
		t.Fatal(err)
	}
	if info.Meta["status"] != "synthetic-test-fixture" || len(info.Rulesets) != len(sources) {
		t.Fatalf("%+v", info.Meta)
	}
	for _, rs := range info.Rulesets {
		if rs.Error != "" {
			t.Fatalf("%s: %s", rs.Name, rs.Error)
		}
		if rs.Name == "direct-essential" && (rs.Counts["domain_suffix"] != 2 || rs.Counts["ip_cidr"] != 1 || rs.Total != 3 || rs.Class != Direct) {
			t.Fatalf("%+v", rs)
		}
	}
	entries, err := RulesetEntries("testdata/split", "vpn-required")
	if err != nil || len(entries) != 3 || entries[0] != (Entry{"domain", "mirror.yandex.ru"}) {
		t.Fatalf("%v %v", entries, err)
	}
	if _, err := RulesetEntries("testdata/split", "../policy"); err == nil {
		t.Fatal("path outside the rulesets accepted")
	}
}
