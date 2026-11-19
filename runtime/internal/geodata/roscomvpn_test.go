package geodata

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
)

// Synthetic profile and data only: example names and documentation
// addresses. The shape follows the published RoscomVPN DEFAULT profile.
const syntheticProfile = `{
 "Name": "Synthetic <b>RoscomVPN</b>",
 "GlobalProxy": "true",
 "UseChunkFiles": "true",
 "RemoteDns": "192.0.2.53",
 "DomesticDns": "198.51.100.53",
 "RemoteDNSType": "DoH",
 "Geoipurl": "https://cdn.example.com/geoip.dat",
 "Geositeurl": "https://cdn.example.com/geosite.dat",
 "LastUpdated": "1795001644",
 "DnsHosts": {"a.example.net": "192.0.2.10", "b.example.net": "192.0.2.11"},
 "RouteOrder": "block-proxy-direct",
 "DirectSites": ["geosite:private", "geosite:ru", "geosite:games@cn", "domain:bank.example", "full:exact.example", "keyword:shop", "regexp:^cdn[0-9]+\\.example\\.net$", "plain.example", "ext:other.dat:tag", "geosite:missing", "домен.example"],
 "DirectIp": ["geoip:private", "geoip:direct", "203.0.113.9", "2001:db8::1", "geoip:!direct", "not-an-ip"],
 "ProxySites": ["geosite:video", "domain:www.bank.example", "geosite:private"],
 "ProxyIp": ["198.51.100.128/25"],
 "BlockSites": ["geosite:ads", "domain:ads.example"],
 "BlockIp": [],
 "DomainStrategy": "IPIfNonMatch",
 "FakeDNS": "false"
}`

func syntheticSites() []byte {
	return list(
		site("PRIVATE", dom(RootDomain, "lan"), dom(Full, "router.example"), dom(Regex, `^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)),
		site("RU", dom(RootDomain, "ru.example"), dom(RootDomain, "Shop.RU.example."), dom(Plain, "yandex")),
		site("GAMES", dom(RootDomain, "game.example", "cn"), dom(RootDomain, "other-game.example")),
		site("VIDEO", dom(RootDomain, "video.example"), dom(Full, "cdn.video.example")),
		site("ADS", dom(RootDomain, "ads.example")),
	)
}

func syntheticIPs() []byte {
	return list(
		geoip("PRIVATE", false, cidr("10.0.0.0/8"), cidr("192.168.0.0/16"), cidr("fc00::/7")),
		geoip("DIRECT", false, cidr("198.51.100.0/24"), cidr("192.0.2.0/25"), cidr("2001:db8::/32")),
	)
}

func convertSynthetic(t *testing.T, raw string) (*Overlay, string) {
	t.Helper()
	body, err := ProfileJSON([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParseProfile(body)
	if err != nil {
		t.Fatal(err)
	}
	sites, err := ParseSites(context.Background(), syntheticSites())
	if err != nil {
		t.Fatal(err)
	}
	ips, err := ParseIPs(context.Background(), syntheticIPs())
	if err != nil {
		t.Fatal(err)
	}
	o, err := Convert(context.Background(), Input{Profile: p, Sites: sites, IPs: ips, ImportedAt: time.Unix(1795000000, 0),
		ProfileSource: "https://user:secret1@profiles.example.com/DEFAULT.JSON?token=abc#frag", ProfileSHA256: strings.Repeat("a", 64),
		GeositeSource: "https://cdn.example.com/geosite.dat?sig=xyz", GeositeSHA256: strings.Repeat("b", 64), GeoipSource: "https://cdn.example.com/geoip.dat", GeoipSHA256: strings.Repeat("c", 64),
		LocalDomains: []policy.Entry{{Kind: "domain", Value: "localhost"}, {Kind: "domain_suffix", Value: "lan"}},
		LocalIPs:     []policy.Entry{{Kind: "ip_cidr", Value: "10.0.0.0/8"}, {Kind: "ip_cidr", Value: "fe80::/10"}}})
	if err != nil {
		t.Fatal(err)
	}
	return o, writeOverlay(t, o)
}

func writeOverlay(t *testing.T, o *Overlay) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "rulesets"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), o.Policy, 0600); err != nil {
		t.Fatal(err)
	}
	for name, raw := range o.Rulesets {
		if err := os.WriteFile(filepath.Join(dir, "rulesets", name+".json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func issue(list []Issue, field, reason string) *Issue {
	for i := range list {
		if list[i].Field == field && strings.Contains(list[i].Reason, reason) {
			return &list[i]
		}
	}
	return nil
}

func TestConvertMapsProfileOntoFLRRulesets(t *testing.T) {
	o, dir := convertSynthetic(t, syntheticProfile)
	p, err := policy.Load(dir)
	if err != nil {
		t.Fatalf("policy.Load refused the overlay: %v", err)
	}
	for name, want := range map[string]policy.Class{
		"router.example":       policy.Local,   // geosite:private (full)
		"printer.lan":          policy.Local,   // image default and geosite:private
		"localhost":            policy.Local,   // image default kept
		"nas":                  policy.Local,   // geosite:private regexp (dotless names)
		"www.ru.example":       policy.Direct,  // geosite:ru suffix
		"a.shop.ru.example":    policy.Direct,  // normalized case and dot
		"mail.yandex.example":  policy.Direct,  // geosite plain → keyword
		"game.example":         policy.Direct,  // @cn kept
		"other-game.example":   policy.General, // @cn dropped it
		"bank.example":         policy.Direct,  // domain:
		"www.bank.example":     policy.General, // ProxySites beats DirectSites
		"exact.example":        policy.Direct,  // full:
		"sub.exact.example":    policy.General, // full: is exact only
		"myshop.example.org":   policy.Direct,  // keyword:
		"cdn12.example.net":    policy.Direct,  // regexp:
		"plain.example.org":    policy.Direct,  // bare entry: Xray substring
		"video.example":        policy.General, // ProxySites geosite
		"unlisted.example.org": policy.General, // default stays VPN
		"ads.example":          policy.General, // BlockSites not applied
	} {
		if got, source := p.DomainDecision(name); got != want {
			t.Errorf("%s: %s (%s), want %s", name, got, source, want)
		}
	}
	if got, source := p.DomainDecision("cdn.video.example"); got != policy.General || source != "vpn-required" {
		t.Errorf("ProxySites must land in vpn-required, got %s/%s", got, source)
	}
	for ip, want := range map[string]policy.Class{
		"192.168.1.20":   policy.Local,   // geoip:private
		"10.1.2.3":       policy.Local,   // image default
		"198.51.100.10":  policy.Direct,  // geoip:direct
		"198.51.100.200": policy.General, // ProxyIp (vpn-services) beats geoip:direct
		"203.0.113.9":    policy.Direct,  // bare address
		"192.0.2.200":    policy.General, // outside geoip:direct /25
	} {
		if got := p.ClassifyIP(netip.MustParseAddr(ip)); got != want {
			t.Errorf("%s: %s, want %s", ip, got, want)
		}
	}
	if got := p.CIDRs("vpn-services"); len(got) != 1 || got[0].String() != "198.51.100.128/25" {
		t.Errorf("ProxyIp must be the static VPN set vpn-services, got %v", got)
	}
	if got := p.CIDRs("local-ips"); len(got) != 3 {
		t.Errorf("local-ips must keep the image defaults (IPv6 included) and add private IPv4: %v", got)
	}

	r := o.Report
	if r.Name != "Synthetic <b>RoscomVPN</b>" {
		t.Errorf("name %q", r.Name)
	}
	if got := r.Rulesets["roscom-direct-ips"]; got.Total != 3 || got.Imported != 3 {
		t.Errorf("direct ips %+v", got)
	}
	if got := r.Rulesets["local-ips"]; got.Total != 3 || got.Imported != 1 {
		t.Errorf("local ips %+v", got)
	}
	for _, want := range []struct{ field, reason string }{
		{"DirectSites", "external data files"}, {"DirectSites", "category not found"}, {"DirectSites", "punycode"},
		{"DirectIp", "IPv6"}, {"DirectIp", "inverted"}, {"DirectIp", "not an IP address"},
		{"ProxySites", "always stay local"},
	} {
		if issue(r.Skipped, want.field, want.reason) == nil {
			t.Errorf("missing skipped %s/%s in %+v", want.field, want.reason, r.Skipped)
		}
	}
	for _, want := range []struct {
		field string
		count int
	}{{"BlockSites", 2}, {"DnsHosts", 2}, {"DNS", 3}, {"DomainStrategy", 1}} {
		if is := issue(r.NotApplied, want.field, ""); is == nil || is.Count != want.count {
			t.Errorf("not applied %s: %+v", want.field, is)
		}
	}
	if issue(r.NotApplied, "GlobalProxy", "") != nil || issue(r.NotApplied, "RouteOrder", "") != nil || issue(r.NotApplied, "FakeDNS", "") != nil {
		t.Errorf("matching settings reported as not applied: %+v", r.NotApplied)
	}
	if issue(r.NotApplied, "BlockIp", "") != nil {
		t.Error("empty BlockIp reported")
	}

	var meta map[string]any
	if err := json.Unmarshal(o.Policy, &meta); err != nil {
		t.Fatal(err)
	}
	if meta["status"] != PolicyStatus || meta["name"] != "Synthetic <b>RoscomVPN</b>" || meta["source"] != "https://profiles.example.com/DEFAULT.JSON" ||
		meta["geosite"] != "https://cdn.example.com/geosite.dat" || meta["profile_last_updated"] != "2026-11-18T11:34:04Z" || meta["imported_at"] != "2026-11-18T11:06:40Z" {
		t.Errorf("policy.json %v", meta)
	}
	if meta["source_sha256"] != strings.Repeat("a", 64) || meta["geosite_sha256"] != strings.Repeat("b", 64) || meta["geoip"] != "https://cdn.example.com/geoip.dat" {
		t.Errorf("provenance %v", meta)
	}
	for _, secret := range []string{"secret1", "token", "abc", "frag", "sig=", "xyz", "?"} {
		if strings.Contains(string(o.Policy), secret) {
			t.Errorf("policy.json keeps %q: %s", secret, o.Policy)
		}
	}
	info, err := policy.Inspect(dir)
	if err != nil || info.Meta["status"] != PolicyStatus {
		t.Fatalf("inspect: %v %v", info.Meta, err)
	}
	// Every issue and note carries a stable code with an English fallback.
	for _, is := range append(append([]Issue{}, r.Skipped...), r.NotApplied...) {
		if Reasons[is.Code] == "" || is.Reason == "" {
			t.Errorf("issue without code or text: %+v", is)
		}
	}
	for _, n := range r.Notes {
		if Reasons[n.Code] == "" || n.Text == "" {
			t.Errorf("note without code or text: %+v", n)
		}
	}
	if is := issue(r.Skipped, "DirectSites", "punycode"); is == nil || is.Code != "name_not_punycode" {
		t.Errorf("code %+v", is)
	}
}

func TestIPv6PrivateCounted(t *testing.T) {
	o, _ := convertSynthetic(t, syntheticProfile)
	// geoip:private carries fc00::/7, geoip:direct 2001:db8::/32 and the
	// bare 2001:db8::1: all three are IPv6 and skipped.
	if is := issue(o.Report.Skipped, "DirectIp", "IPv6"); is == nil || is.Count != 3 {
		t.Fatalf("IPv6 skipped %+v", is)
	}
}

func TestDeepLinksAndProfileValues(t *testing.T) {
	plain := `{"Name":"Links","GlobalProxy":false,"LastUpdated":1795001644,"DirectSites":["domain:example.com"]}`
	for _, link := range []string{
		"happ://routing/onadd/" + base64.StdEncoding.EncodeToString([]byte(plain)),
		"INCY://routing/add/" + base64.RawURLEncoding.EncodeToString([]byte(plain)) + "\n",
		"\xef\xbb\xbf" + plain,
	} {
		body, err := ProfileJSON([]byte(link))
		if err != nil {
			t.Fatalf("%q: %v", link, err)
		}
		p, err := ParseProfile(body)
		if err != nil {
			t.Fatal(err)
		}
		if p.Name != "Links" || p.GlobalProxy == nil || *p.GlobalProxy || p.LastUpdated != "1795001644" {
			t.Fatalf("profile %+v", p)
		}
	}
	for _, bad := range []string{"", "vless://x", "happ://routing/onadd/!!!", "[1,2]", "happ://routing/" + base64.StdEncoding.EncodeToString([]byte(plain))} {
		if _, err := ProfileJSON([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, bad := range []string{
		`{"Name":"x","DirectSites":"geosite:ru"}`,
		`{"Name":"x","GlobalProxy":"maybe"}`,
		`{"Name":"x","DnsHosts":[1]}`,
		`{"UseChunkFiles":"true"}`,
		`{"Name":"x","DirectSites":[` + strings.Repeat(`"a.example",`, MaxProfileEntries) + `"b.example"]}`,
	} {
		if _, err := ParseProfile([]byte(bad)); err == nil {
			t.Errorf("%.60s accepted", bad)
		}
	}
	p, _ := ParseProfile([]byte(plain))
	o, err := Convert(context.Background(), Input{Profile: p, ImportedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if issue(o.Report.NotApplied, "GlobalProxy", "unlisted destinations through the VPN") == nil {
		t.Errorf("GlobalProxy=false not reported: %+v", o.Report.NotApplied)
	}
	if geosite, geoip := p.Needs(); geosite || geoip {
		t.Error("a profile without categories needs no data files")
	}
	full, _ := ParseProfile([]byte(syntheticProfile))
	if geosite, geoip := full.Needs(); !geosite || !geoip {
		t.Error("categories need the data files")
	}
}

func TestConvertWithoutDataSkipsCategories(t *testing.T) {
	p, err := ParseProfile([]byte(syntheticProfile))
	if err != nil {
		t.Fatal(err)
	}
	o, err := Convert(context.Background(), Input{Profile: p, ImportedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if is := issue(o.Report.Skipped, "DirectSites", "no geosite data"); is == nil || is.Count != 4 {
		t.Fatalf("%+v", o.Report.Skipped)
	}
	if _, err := policy.Load(writeOverlay(t, o)); err != nil {
		t.Fatal(err)
	}
}

func TestConvertLimits(t *testing.T) {
	entries := func(n int, format string) string {
		var parts []string
		for i := 0; i < n; i++ {
			parts = append(parts, fmt.Sprintf("%q", fmt.Sprintf(format, i)))
		}
		return strings.Join(parts, ",")
	}
	for name, profile := range map[string]string{
		"keywords": `{"Name":"x","DirectSites":[` + entries(MaxKeywords+1, "keyword:k%d") + `]}`,
		"regexps":  `{"Name":"x","ProxySites":[` + entries(MaxRegexps+1, `regexp:^r%d\\.example$`) + `]}`,
	} {
		p, err := ParseProfile([]byte(profile))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Convert(context.Background(), Input{Profile: p, ImportedAt: time.Now()}); err == nil || !strings.Contains(err.Error(), "too large") {
			t.Errorf("%s: %v", name, err)
		}
	}
	p, _ := ParseProfile([]byte(`{"Name":"x","DirectSites":[` + entries(MaxKeywords, "keyword:k%d") + `]}`))
	if _, err := Convert(context.Background(), Input{Profile: p, ImportedAt: time.Now()}); err != nil {
		t.Errorf("at the keyword limit: %v", err)
	}
	// A ruleset above MaxRulesetEntries: one geoip category with too many
	// CIDRs.
	var cidrs [][]byte
	for i := 0; i <= MaxRulesetEntries; i++ {
		cidrs = append(cidrs, pbUint(pbBytes(nil, 1, []byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), 2, 32))
	}
	ips, err := ParseIPs(context.Background(), list(geoip("BIG", false, cidrs...)))
	if err != nil {
		t.Fatal(err)
	}
	p, _ = ParseProfile([]byte(`{"Name":"x","DirectIp":["geoip:big"]}`))
	if _, err := Convert(context.Background(), Input{Profile: p, IPs: ips, ImportedAt: time.Now()}); err == nil || !strings.Contains(err.Error(), "roscom-direct-ips") {
		t.Errorf("ruleset limit: %v", err)
	}
}

// Xray matches keyword:, bare entries and geosite Plain values as
// substrings of the full name: their dots are literal.
func TestKeywordsKeepTheirDots(t *testing.T) {
	p, err := ParseProfile([]byte(`{"Name":"k","DirectSites":["keyword:.RU","geosite:kw","..","keyword:."]}`))
	if err != nil {
		t.Fatal(err)
	}
	sites, err := ParseSites(context.Background(), list(site("KW", dom(Plain, ".su"))))
	if err != nil {
		t.Fatal(err)
	}
	o, err := Convert(context.Background(), Input{Profile: p, Sites: sites, ImportedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load(writeOverlay(t, o))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]policy.Class{
		"trust.example":   policy.General, // would match a dot-stripped "ru"
		"sushi.example":   policy.General, // would match a dot-stripped "su"
		"a.ru":            policy.Direct,
		"shop.ru.example": policy.Direct,
		"mail.su":         policy.Direct,
	} {
		if got, _ := pol.DomainDecision(name); got != want {
			t.Errorf("%s: %s, want %s", name, got, want)
		}
	}
	if got := o.Report.Rulesets["roscom-direct-domains"].Counts["domain_keyword"]; got != 2 {
		t.Errorf("keywords %d, want 2", got)
	}
	if is := issue(o.Report.Skipped, "DirectSites", "empty domain"); is == nil || is.Count != 2 {
		t.Errorf("dot-only keywords: %+v", o.Report.Skipped)
	}
}

func TestDeepLinkPayloadWithSlash(t *testing.T) {
	var body string
	for i := 0; ; i++ {
		body = fmt.Sprintf(`{"Name":"slash %d ???>>>","DirectSites":["domain:example.com"]}`, i)
		if strings.Contains(base64.StdEncoding.EncodeToString([]byte(body)), "/") {
			break
		}
		if i > 1000 {
			t.Fatal("no payload with /")
		}
	}
	std := base64.StdEncoding.EncodeToString([]byte(body))
	for _, link := range []string{
		"happ://routing/onadd/" + std,
		"happ://routing/onadd/" + strings.TrimRight(std, "="),
		"incy://routing/add/" + base64.URLEncoding.EncodeToString([]byte(body)) + "?from=app",
		"happ://routing/onadd/" + std[:20] + "\n" + std[20:],
	} {
		got, err := ProfileJSON([]byte(link))
		if err != nil || string(got) != body {
			t.Fatalf("%q: %q %v", link, got, err)
		}
	}
}

// Category entries stream into the sets: 100k duplicates of one domain and
// a repeated reference cost (almost) no allocations.
func TestStreamingDedupDoesNotMaterialize(t *testing.T) {
	doms := make([][]byte, 0, 100000)
	for i := 0; i < 100000; i++ {
		doms = append(doms, dom(RootDomain, "dup.example"))
	}
	sites, err := ParseSites(context.Background(), list(site("DUP", doms...)))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := ParseProfile([]byte(`{"Name":"d","DirectSites":["geosite:dup","geosite:DUP"],"ProxySites":["geosite:dup"]}`))
	var o *Overlay
	allocs := testing.AllocsPerRun(1, func() {
		if o, err = Convert(context.Background(), Input{Profile: p, Sites: sites, ImportedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	})
	if allocs > 5000 {
		t.Fatalf("%.0f allocations for 200k streamed duplicates", allocs)
	}
	if o.Report.Rulesets["roscom-direct-domains"].Total != 1 || o.Report.Rulesets["vpn-required"].Total != 1 {
		t.Fatalf("dedup: %+v", o.Report.Rulesets)
	}
	// One walk per (list, category); the repeated reference is noted.
	if len(o.Report.Categories) != 2 || o.Report.Categories[0].Entries != 100000 {
		t.Fatalf("categories %+v", o.Report.Categories)
	}
	found := false
	for _, n := range o.Report.Notes {
		found = found || n.Code == "note_duplicate_refs" && n.Args[0] == "1"
	}
	if !found {
		t.Fatalf("notes %+v", o.Report.Notes)
	}
}

func TestBudgetsFailEarlyAndContextCancels(t *testing.T) {
	oldExpanded, oldRuleset := maxExpandedEntries, maxRulesetEntries
	t.Cleanup(func() { maxExpandedEntries, maxRulesetEntries = oldExpanded, oldRuleset })
	var doms [][]byte
	for i := 0; i < 5000; i++ {
		doms = append(doms, dom(RootDomain, fmt.Sprintf("h%d.example", i)))
	}
	sites, err := ParseSites(context.Background(), list(site("BIG", doms...)))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := ParseProfile([]byte(`{"Name":"b","DirectSites":["geosite:big"]}`))
	in := Input{Profile: p, Sites: sites, ImportedAt: time.Now()}
	var le *LimitError
	maxExpandedEntries = 1000
	if _, err := Convert(context.Background(), in); !errors.As(err, &le) || !strings.Contains(err.Error(), "expand") {
		t.Fatalf("expansion budget: %v", err)
	}
	maxExpandedEntries, maxRulesetEntries = oldExpanded, 100
	if _, err := Convert(context.Background(), in); !errors.As(err, &le) || !strings.Contains(err.Error(), "roscom-direct-domains") {
		t.Fatalf("ruleset budget: %v", err)
	}
	maxRulesetEntries = oldRuleset
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Convert(ctx, in); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled conversion: %v", err)
	}
}

func TestSourceURLDropsSecrets(t *testing.T) {
	for raw, want := range map[string]string{
		"https://user:secret1@cdn.example.com/a/geoip.dat?token=x#y": "https://cdn.example.com/a/geoip.dat",
		"HTTPS://cdn.example.com:443/geosite.dat":                    "https://cdn.example.com:443/geosite.dat",
		"uploaded file": "",
		"":              "",
	} {
		if got := SourceURL(raw); got != want {
			t.Errorf("%q: %q, want %q", raw, got, want)
		}
	}
}
