package geodata

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
)

// RoscomVPN routing profiles (Happ and INCY): one JSON object whose list
// entries use Xray routing syntax. Convert maps them onto the FLR rulesets;
// docs/ROUTER-API.md, "RoscomVPN import", has the mapping table.

const (
	// MaxProfileBytes bounds a profile (JSON or deep link).
	MaxProfileBytes = 1 << 20
	// MaxProfileEntries bounds one list of a profile.
	MaxProfileEntries = 10000
	// MaxRulesetEntries bounds one generated ruleset.
	MaxRulesetEntries = 250000
	// MaxKeywords and MaxRegexps bound the substring and regular-expression
	// matchers of the whole overlay: the DNS broker checks them one by one
	// for every new name.
	MaxKeywords = 2048
	MaxRegexps  = 256
	// PolicyStatus marks an overlay made by Convert.
	PolicyStatus = "imported-roscomvpn"
)

// Profile is the part of a RoscomVPN routing profile FLR reads.
type Profile struct {
	Name           string
	GlobalProxy    *bool
	GeositeURL     string
	GeoipURL       string
	LastUpdated    string
	RouteOrder     string
	DomainStrategy string
	FakeDNS        *bool
	DNSHosts       int
	DNSFields      []string
	DirectSites    []string
	DirectIP       []string
	ProxySites     []string
	ProxyIP        []string
	BlockSites     []string
	BlockIP        []string
}

var deepLinkSchemes = []string{"happ://routing/", "incy://routing/"}

// ProfileJSON returns the JSON object of a profile given as JSON or as a
// Happ/INCY deep link (happ://routing/onadd/<base64 JSON>).
func ProfileJSON(raw []byte) ([]byte, error) {
	if len(raw) > MaxProfileBytes {
		return nil, fmt.Errorf("profile larger than %d bytes", MaxProfileBytes)
	}
	t := bytes.TrimSpace(bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf")))
	if len(t) > 0 && t[0] == '{' {
		return t, nil
	}
	s := string(t)
	for _, scheme := range deepLinkSchemes {
		if len(s) <= len(scheme) || !strings.EqualFold(s[:len(scheme)], scheme) {
			continue
		}
		payload := s[len(scheme):]
		if i := strings.IndexAny(payload, "?#"); i >= 0 {
			payload = payload[:i]
		}
		payload = payload[strings.LastIndexByte(payload, '/')+1:]
		payload = strings.TrimRight(payload, "=")
		for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
			if b, err := enc.DecodeString(payload); err == nil {
				if b = bytes.TrimSpace(b); len(b) > 0 && b[0] == '{' {
					return b, nil
				}
			}
		}
		return nil, fmt.Errorf("routing link carries no base64 JSON profile")
	}
	return nil, fmt.Errorf("not a RoscomVPN routing profile: expected a JSON object or a happ:// or incy:// routing link")
}

var dnsFields = []string{"RemoteDns", "DomesticDns", "RemoteDNSType", "RemoteDNSDomain", "RemoteDNSIP", "DomesticDNSType", "DomesticDNSDomain", "DomesticDNSIP"}

// ParseProfile reads a profile JSON object (see ProfileJSON). Booleans may
// be JSON booleans or the strings "true"/"false", as the published profiles
// write them. Unknown keys are ignored.
func ParseProfile(raw []byte) (*Profile, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, fmt.Errorf("profile is not a JSON object")
	}
	p := &Profile{}
	str := func(key string) (string, error) {
		v, ok := m[key]
		if !ok || string(v) == "null" {
			return "", nil
		}
		var s string
		if json.Unmarshal(v, &s) == nil {
			if len(s) > 8192 {
				return "", fmt.Errorf("%s too long", key)
			}
			return s, nil
		}
		var n json.Number
		if json.Unmarshal(v, &n) == nil {
			return n.String(), nil
		}
		return "", fmt.Errorf("%s must be a string", key)
	}
	boolean := func(key string) (*bool, error) {
		v, ok := m[key]
		if !ok || string(v) == "null" {
			return nil, nil
		}
		var b bool
		if json.Unmarshal(v, &b) == nil {
			return &b, nil
		}
		var s string
		if json.Unmarshal(v, &s) == nil {
			if b, err := strconv.ParseBool(strings.TrimSpace(s)); err == nil {
				return &b, nil
			}
		}
		return nil, fmt.Errorf("%s must be true or false", key)
	}
	list := func(key string) ([]string, error) {
		v, ok := m[key]
		if !ok || string(v) == "null" {
			return nil, nil
		}
		var out []string
		if json.Unmarshal(v, &out) != nil {
			return nil, fmt.Errorf("%s must be a list of strings", key)
		}
		if len(out) > MaxProfileEntries {
			return nil, fmt.Errorf("%s has more than %d entries", key, MaxProfileEntries)
		}
		for _, s := range out {
			if len(s) > 1024 {
				return nil, fmt.Errorf("%s has an entry longer than 1024 bytes", key)
			}
		}
		return out, nil
	}
	var err error
	for _, f := range []struct {
		key string
		dst *string
	}{{"Name", &p.Name}, {"Geositeurl", &p.GeositeURL}, {"Geoipurl", &p.GeoipURL}, {"LastUpdated", &p.LastUpdated}, {"RouteOrder", &p.RouteOrder}, {"DomainStrategy", &p.DomainStrategy}} {
		if *f.dst, err = str(f.key); err != nil {
			return nil, err
		}
	}
	if p.GlobalProxy, err = boolean("GlobalProxy"); err != nil {
		return nil, err
	}
	if p.FakeDNS, err = boolean("FakeDNS"); err != nil {
		return nil, err
	}
	for _, f := range []struct {
		key string
		dst *[]string
	}{{"DirectSites", &p.DirectSites}, {"DirectIp", &p.DirectIP}, {"ProxySites", &p.ProxySites}, {"ProxyIp", &p.ProxyIP}, {"BlockSites", &p.BlockSites}, {"BlockIp", &p.BlockIP}} {
		if *f.dst, err = list(f.key); err != nil {
			return nil, err
		}
	}
	if v, ok := m["DnsHosts"]; ok && string(v) != "null" {
		var hosts map[string]json.RawMessage
		if json.Unmarshal(v, &hosts) != nil {
			return nil, fmt.Errorf("DnsHosts must be an object")
		}
		p.DNSHosts = len(hosts)
	}
	for _, key := range dnsFields {
		if s, _ := str(key); s != "" {
			p.DNSFields = append(p.DNSFields, key)
		}
	}
	if len(p.DirectSites)+len(p.DirectIP)+len(p.ProxySites)+len(p.ProxyIP)+len(p.BlockSites)+len(p.BlockIP) == 0 && p.Name == "" {
		return nil, fmt.Errorf("profile has no name and no routing lists")
	}
	return p, nil
}

// Needs reports whether the applied lists (direct and proxy) reference
// geosite and geoip categories, i.e. which data files must be read.
func (p *Profile) Needs() (geosite, geoip bool) {
	for _, s := range append(append([]string{}, p.DirectSites...), p.ProxySites...) {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(s)), "geosite:") {
			geosite = true
		}
	}
	for _, s := range append(append([]string{}, p.DirectIP...), p.ProxyIP...) {
		if v := strings.ToLower(strings.TrimSpace(s)); strings.HasPrefix(v, "geoip:") && !strings.HasPrefix(v, "geoip:!") {
			geoip = true
		}
	}
	return geosite, geoip
}

// Input is what Convert needs besides the profile: the data files (nil when
// Needs says they are not used), their sources, and the image's local
// defaults, which the overlay keeps.
type Input struct {
	Profile       *Profile
	Sites         *Sites
	IPs           *IPs
	ProfileSource string
	ImportedAt    time.Time
	LocalDomains  []policy.Entry
	LocalIPs      []policy.Entry
}

// Issue counts profile entries or settings FLR skips or does not apply.
type Issue struct {
	Field    string   `json:"field"`
	Reason   string   `json:"reason"`
	Count    int      `json:"count"`
	Examples []string `json:"examples,omitempty"`
}

// RulesetCount is one generated ruleset: entries per matcher kind, all
// entries, and how many came from the profile (the rest are image defaults).
type RulesetCount struct {
	Counts   map[string]int `json:"counts"`
	Total    int            `json:"total"`
	Imported int            `json:"imported"`
}

// Category is one geosite or geoip category the profile used.
type Category struct {
	List    string `json:"list"`
	Name    string `json:"name"`
	Entries int    `json:"entries"`
}

// Report describes a conversion.
type Report struct {
	Name        string                  `json:"name"`
	Rulesets    map[string]RulesetCount `json:"rulesets"`
	Categories  []Category              `json:"categories"`
	Skipped     []Issue                 `json:"skipped"`
	NotApplied  []Issue                 `json:"not_applied"`
	Notes       []string                `json:"notes"`
	TotalImport int                     `json:"total_imported"`
}

// Overlay is a converted profile: policy.json and every ruleset, in the
// format policy.Load reads.
type Overlay struct {
	Policy   json.RawMessage
	Rulesets map[string]json.RawMessage
	Report   Report
}

type ruleset struct {
	values   map[string][]string
	seen     map[string]bool
	imported int
}

func newRuleset() *ruleset {
	return &ruleset{values: map[string][]string{}, seen: map[string]bool{}}
}

func (r *ruleset) add(kind, value string, imported bool) {
	key := kind + "\x00" + value
	if r.seen[key] {
		return
	}
	r.seen[key] = true
	r.values[kind] = append(r.values[kind], value)
	if imported {
		r.imported++
	}
}

func (r *ruleset) total() int { return len(r.seen) }

type converter struct {
	in       Input
	sets     map[string]*ruleset
	issues   map[string]*Issue
	skipped  []*Issue
	notApp   []*Issue
	cats     []Category
	catIndex map[string]int
	notes    []string
	bare     int
}

func (c *converter) issue(dst *[]*Issue, field, reason, example string, count int) {
	list := "n"
	if dst == &c.skipped {
		list = "s"
	}
	key := list + "|" + field + "|" + reason
	is := c.issues[key]
	if is == nil {
		is = &Issue{Field: field, Reason: reason}
		c.issues[key] = is
		*dst = append(*dst, is)
	}
	is.Count += count
	if example != "" && len(is.Examples) < 3 {
		is.Examples = append(is.Examples, shortExample(example))
	}
}

func shortExample(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) > 80 {
		s = string([]rune(s)[:80]) + "…"
	}
	return s
}

func (c *converter) skip(field, reason, example string) {
	c.issue(&c.skipped, field, reason, example, 1)
}

func (c *converter) category(list, name string, n int) {
	key := list + "|" + strings.ToLower(name)
	if i, ok := c.catIndex[key]; ok {
		c.cats[i].Entries = n
		return
	}
	c.catIndex[key] = len(c.cats)
	c.cats = append(c.cats, Category{List: list, Name: name, Entries: n})
}

// cleanName normalizes a domain or keyword: lower case, no surrounding
// dots, ASCII letters, digits, "-", "_" and "." only.
func cleanName(v string) (string, string) {
	v = strings.Trim(strings.ToLower(strings.TrimSpace(v)), ".")
	if v == "" {
		return "", "empty domain"
	}
	if len(v) > 253 {
		return "", "domain longer than 253 characters"
	}
	for i := 0; i < len(v); i++ {
		b := v[i]
		switch {
		case b >= 0x80:
			return "", "internationalized name not in punycode (xn--…)"
		case b >= 'a' && b <= 'z', b >= '0' && b <= '9', b == '-', b == '_', b == '.':
		default:
			return "", "invalid characters in domain"
		}
	}
	if strings.Contains(v, "..") {
		return "", "invalid characters in domain"
	}
	return v, ""
}

func (c *converter) addDomain(target, field, kind, value, example string) {
	switch kind {
	case "domain_regex":
		if len(value) > 1024 {
			c.skip(field, "regular expression longer than 1024 bytes", example)
			return
		}
		if _, err := regexp.Compile(value); err != nil {
			c.skip(field, "invalid regular expression", example)
			return
		}
	default:
		clean, reason := cleanName(value)
		if reason != "" {
			c.skip(field, reason, example)
			return
		}
		value = clean
	}
	c.sets[target].add(kind, value, true)
}

var domainKinds = map[DomainType]string{Plain: "domain_keyword", Regex: "domain_regex", RootDomain: "domain_suffix", Full: "domain"}

// sites maps one DirectSites or ProxySites list.
func (c *converter) sites(field, target string, entries []string) {
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		low := strings.ToLower(e)
		switch {
		case e == "":
			c.skip(field, "empty entry", "")
		case strings.HasPrefix(low, "geosite:"):
			spec := strings.TrimSpace(e[len("geosite:"):])
			name := strings.ToLower(strings.SplitN(spec, "@", 2)[0])
			dst := target
			if name == "private" {
				if target != "roscom-direct-domains" {
					c.skip(field, "private destinations always stay local in FLR", e)
					continue
				}
				dst = "local-domains"
			}
			if c.in.Sites == nil {
				c.skip(field, "no geosite data", e)
				continue
			}
			domains, ok, err := c.in.Sites.Lookup(spec)
			if err != nil {
				c.skip(field, "unreadable geosite category: "+err.Error(), e)
				continue
			}
			if !ok {
				c.skip(field, "geosite category not found in the data file", e)
				continue
			}
			c.category(field, "geosite:"+spec, len(domains))
			for _, d := range domains {
				c.addDomain(dst, field, domainKinds[d.Type], d.Value, e+" → "+d.Value)
			}
		case strings.HasPrefix(low, "domain:"):
			c.addDomain(target, field, "domain_suffix", e[len("domain:"):], e)
		case strings.HasPrefix(low, "full:"):
			c.addDomain(target, field, "domain", e[len("full:"):], e)
		case strings.HasPrefix(low, "keyword:"):
			c.addDomain(target, field, "domain_keyword", e[len("keyword:"):], e)
		case strings.HasPrefix(low, "regexp:"):
			c.addDomain(target, field, "domain_regex", e[len("regexp:"):], e)
		case strings.HasPrefix(low, "ext:"), strings.HasPrefix(low, "ext-domain:"):
			c.skip(field, "external data files are not supported", e)
		case strings.Contains(e, ":"):
			c.skip(field, "unsupported matcher prefix", e)
		default:
			// Xray matches a bare entry as a substring of the name.
			c.bare++
			c.addDomain(target, field, "domain_keyword", e, e)
		}
	}
}

// ips maps one DirectIp or ProxyIp list.
func (c *converter) ips(field, target string, entries []string) {
	add := func(dst string, p netip.Prefix, example string) {
		if !p.Addr().Is4() {
			c.skip(field, "IPv6: FLR routes IPv4 only", example)
			return
		}
		c.sets[dst].add("ip_cidr", p.Masked().String(), true)
	}
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		low := strings.ToLower(e)
		switch {
		case e == "":
			c.skip(field, "empty entry", "")
		case strings.HasPrefix(low, "geoip:!"):
			c.skip(field, "inverted geoip categories are not supported", e)
		case strings.HasPrefix(low, "geoip:"):
			code := strings.TrimSpace(e[len("geoip:"):])
			dst := target
			if strings.EqualFold(code, "private") {
				if target != "roscom-direct-ips" {
					c.skip(field, "private destinations always stay local in FLR", e)
					continue
				}
				dst = "local-ips"
			}
			if c.in.IPs == nil {
				c.skip(field, "no geoip data", e)
				continue
			}
			prefixes, reverse, ok, err := c.in.IPs.Lookup(code)
			switch {
			case err != nil:
				c.skip(field, "unreadable geoip category: "+err.Error(), e)
				continue
			case !ok:
				c.skip(field, "geoip category not found in the data file", e)
				continue
			case reverse:
				c.skip(field, "inverted geoip categories are not supported", e)
				continue
			}
			c.category(field, "geoip:"+code, len(prefixes))
			for _, p := range prefixes {
				add(dst, p, e+" → "+p.String())
			}
		case strings.HasPrefix(low, "ext:"), strings.HasPrefix(low, "ext-ip:"):
			c.skip(field, "external data files are not supported", e)
		default:
			if p, err := netip.ParsePrefix(e); err == nil {
				add(target, p, e)
			} else if a, err := netip.ParseAddr(e); err == nil && a.Zone() == "" {
				add(target, netip.PrefixFrom(a, a.BitLen()), e)
			} else {
				c.skip(field, "not an IP address, CIDR or geoip category", e)
			}
		}
	}
}

func rulesetJSON(r *ruleset, source string) json.RawMessage {
	rule := map[string][]string{}
	for kind, values := range r.values {
		if len(values) > 0 {
			rule[kind] = values
		}
	}
	doc := struct {
		Version int                   `json:"version"`
		Source  string                `json:"source"`
		Rules   []map[string][]string `json:"rules"`
	}{Version: 3, Source: source, Rules: []map[string][]string{}}
	if len(rule) > 0 {
		doc.Rules = append(doc.Rules, rule)
	}
	b, _ := json.Marshal(doc)
	return b
}

func plainText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if utf8.RuneCountInString(s) > max {
		s = string([]rune(s)[:max])
	}
	return s
}

// Convert turns a profile and its data into an FLR overlay. It fails when a
// generated ruleset or the matcher totals exceed the limits above.
func Convert(in Input) (*Overlay, error) {
	p := in.Profile
	if p == nil {
		return nil, fmt.Errorf("no profile")
	}
	c := &converter{in: in, sets: map[string]*ruleset{}, issues: map[string]*Issue{}, catIndex: map[string]int{}}
	for _, name := range policy.RulesetNames() {
		c.sets[name] = newRuleset()
	}
	for _, e := range in.LocalDomains {
		c.sets["local-domains"].add(e.Kind, e.Value, false)
	}
	for _, e := range in.LocalIPs {
		c.sets["local-ips"].add(e.Kind, e.Value, false)
	}
	c.sites("ProxySites", "vpn-required", p.ProxySites)
	c.ips("ProxyIp", "vpn-services", p.ProxyIP)
	c.sites("DirectSites", "roscom-direct-domains", p.DirectSites)
	c.ips("DirectIp", "roscom-direct-ips", p.DirectIP)

	if len(p.BlockSites) > 0 {
		c.issue(&c.notApp, "BlockSites", "FLR does not block destinations; they follow the other lists (unlisted: VPN)", "", len(p.BlockSites))
	}
	if len(p.BlockIP) > 0 {
		c.issue(&c.notApp, "BlockIp", "FLR does not block destinations; they follow the other lists (unlisted: VPN)", "", len(p.BlockIP))
	}
	if p.DNSHosts > 0 {
		c.issue(&c.notApp, "DnsHosts", "FLR resolves every name through its own DNS broker; static host entries are not imported", "", p.DNSHosts)
	}
	if len(p.DNSFields) > 0 {
		c.issue(&c.notApp, "DNS servers", "FLR uses its own resolvers: DoH inside the VPN, and the direct resolver of its settings for direct names", strings.Join(p.DNSFields, ", "), len(p.DNSFields))
	}
	if p.FakeDNS != nil && *p.FakeDNS {
		c.issue(&c.notApp, "FakeDNS", "FLR does not use fake DNS answers", "", 1)
	}
	if p.DomainStrategy != "" {
		reason := "FLR always matches the name first and, for unlisted names, the resolved IPv4 address (the same as IPIfNonMatch)"
		c.issue(&c.notApp, "DomainStrategy", reason, plainText(p.DomainStrategy, 40), 1)
	}
	if order := strings.ToLower(strings.TrimSpace(p.RouteOrder)); order != "" && order != "block-proxy-direct" {
		c.issue(&c.notApp, "RouteOrder", "FLR always gives the VPN lists precedence over the direct lists (block-proxy-direct)", plainText(p.RouteOrder, 40), 1)
	}
	if p.GlobalProxy != nil && !*p.GlobalProxy {
		c.issue(&c.notApp, "GlobalProxy", "FLR still sends unlisted destinations through the VPN", "false", 1)
	}
	if c.bare > 0 {
		c.notes = append(c.notes, fmt.Sprintf("%d bare entries were imported as substring (keyword) matches, as Xray matches them; write domain:example.com for a domain and its subdomains", c.bare))
	}
	if len(c.sets["vpn-services"].values["ip_cidr"]) > 0 && len(p.DirectSites) > 0 {
		c.notes = append(c.notes, "an address in ProxyIp goes through the VPN even when its name is in DirectSites (FLR matches address sets before name-derived direct sets)")
	}
	c.notes = append(c.notes, "DirectSites and DirectIp apply in routing mode split only; full_domestic and full ignore them")

	keywords, regexps := 0, 0
	report := Report{Name: plainText(p.Name, 120), Rulesets: map[string]RulesetCount{}, Categories: c.cats, Notes: c.notes}
	for _, name := range policy.RulesetNames() {
		r := c.sets[name]
		if r.total() > MaxRulesetEntries {
			return nil, fmt.Errorf("the profile is too large for FLR: ruleset %s would hold %d entries (limit %d)", name, r.total(), MaxRulesetEntries)
		}
		keywords += len(r.values["domain_keyword"])
		regexps += len(r.values["domain_regex"])
		counts := map[string]int{}
		for kind, values := range r.values {
			counts[kind] = len(values)
		}
		report.Rulesets[name] = RulesetCount{Counts: counts, Total: r.total(), Imported: r.imported}
		report.TotalImport += r.imported
	}
	if keywords > MaxKeywords {
		return nil, fmt.Errorf("the profile is too large for FLR: %d keyword matchers (limit %d)", keywords, MaxKeywords)
	}
	if regexps > MaxRegexps {
		return nil, fmt.Errorf("the profile is too large for FLR: %d regular expressions (limit %d)", regexps, MaxRegexps)
	}
	for _, is := range c.skipped {
		report.Skipped = append(report.Skipped, *is)
	}
	for _, is := range c.notApp {
		report.NotApplied = append(report.NotApplied, *is)
	}
	if report.Skipped == nil {
		report.Skipped = []Issue{}
	}
	if report.NotApplied == nil {
		report.NotApplied = []Issue{}
	}
	if report.Categories == nil {
		report.Categories = []Category{}
	}

	counts := map[string]int{}
	for name, r := range report.Rulesets {
		counts[name] = r.Total
	}
	updated := plainText(p.LastUpdated, 64)
	if n, err := strconv.ParseInt(updated, 10, 64); err == nil && n > 0 && n < 1<<35 {
		updated = time.Unix(n, 0).UTC().Format(time.RFC3339)
	}
	name := report.Name
	if name == "" {
		name = "RoscomVPN"
	}
	meta := struct {
		Format         string         `json:"format"`
		Version        int            `json:"version"`
		Status         string         `json:"status"`
		DefaultClass   string         `json:"default_class"`
		Name           string         `json:"name"`
		Source         string         `json:"source"`
		Geosite        string         `json:"geosite,omitempty"`
		Geoip          string         `json:"geoip,omitempty"`
		ProfileUpdated string         `json:"profile_last_updated,omitempty"`
		ImportedAt     string         `json:"imported_at"`
		Note           string         `json:"note"`
		Counts         map[string]int `json:"counts"`
	}{
		Format: "flint2-home-vpn-routing-policy", Version: 3, Status: PolicyStatus, DefaultClass: "vpn-general",
		Name: name, Source: plainText(in.ProfileSource, 1000), ProfileUpdated: updated,
		ImportedAt: in.ImportedAt.UTC().Format(time.RFC3339),
		Note:       "Imported from a RoscomVPN routing profile: DirectSites/DirectIp are the broad direct lists, ProxySites/ProxyIp go through the VPN, private destinations stay local; everything else goes through the VPN.",
		Counts:     counts,
	}
	if in.Sites != nil {
		meta.Geosite = plainText(p.GeositeURL, 1000)
	}
	if in.IPs != nil {
		meta.Geoip = plainText(p.GeoipURL, 1000)
	}
	policyJSON, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	out := &Overlay{Policy: policyJSON, Rulesets: map[string]json.RawMessage{}, Report: report}
	for _, name := range policy.RulesetNames() {
		source := "roscomvpn"
		if strings.HasPrefix(name, "local-") {
			source = "image defaults + roscomvpn private"
		}
		out.Rulesets[name] = rulesetJSON(c.sets[name], source)
	}
	return out, nil
}
