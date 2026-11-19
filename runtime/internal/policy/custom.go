package policy

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Custom routing rules are the owner's hand-picked exceptions, stored on the
// router only (/etc/flr-runtime/custom-rules.json, docs/ROUTER-API.md). They
// are merged into a view of the installed policy by WithCustom:
//
//   - a "vpn" rule always sends matching destinations through the VPN;
//   - a "direct" rule sends them through the ISP in the split and
//     full_domestic routing modes and is ignored in full (modeOff);
//   - custom rules precede every ruleset class except local destinations
//     (local-domains, local-ips), which always stay local;
//   - between custom rules the most specific match wins (the longest domain
//     suffix, the longest IPv4 prefix); an exact tie goes to the VPN.
//
// Only IPv4 addresses are accepted: the dataplane's address sets are IPv4 and
// LAN IPv6 is not routed by FLR.
const (
	CustomRulesFormat  = "flr-custom-routing-rules"
	CustomRulesVersion = 1
	MaxCustomRules     = 2048
	MaxCustomComment   = 120
	// CustomVPNSource and CustomDirectSource name the custom matchers; the
	// dataplane renders their resolved IPv4 prefixes as its own sets.
	CustomVPNSource    = "custom-vpn"
	CustomDirectSource = "custom-direct"

	maxRangePrefixes = 32
	minCustomBits    = 8
)

const (
	RuleDomain = "domain"
	RuleIP     = "ip"
	RuleCIDR   = "cidr"
	RuleRange  = "range"
	RuleDirect = "direct"
	RuleVPN    = "vpn"
)

type CustomRule struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Value   string `json:"value"`
	Mode    string `json:"mode"`
	Comment string `json:"comment,omitempty"`
	Enabled bool   `json:"enabled"`
}

type CustomRules struct {
	Format  string       `json:"format"`
	Version int          `json:"version"`
	Rules   []CustomRule `json:"rules"`
}

// EmptyCustomRules is the state without a custom rules file.
func EmptyCustomRules() *CustomRules {
	return &CustomRules{Format: CustomRulesFormat, Version: CustomRulesVersion, Rules: []CustomRule{}}
}

// Revision identifies the rule list for optimistic concurrency: an edit names
// the revision it was made against and is refused when the list changed.
func (r *CustomRules) Revision() string {
	rules := r.Rules
	if rules == nil {
		rules = []CustomRule{}
	}
	b, _ := json.Marshal(rules)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

var (
	ruleIDRE    = regexp.MustCompile(`^[a-z0-9_-]{1,40}$`)
	domainLabel = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)
	allDigits   = regexp.MustCompile(`^[0-9]+$`)
	// Never valid as a destination rule: "this network", loopback, multicast
	// and the reserved block with the limited broadcast address.
	reservedPrefixes = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
	}
)

// Normalize validates every rule in place: canonical values, inferred types,
// unique IDs, no duplicate destinations. lanPrefix is the router's LAN (may
// be invalid when unknown); a "vpn" rule must not overlap it.
func (r *CustomRules) Normalize(lanPrefix netip.Prefix) error {
	if r.Format != CustomRulesFormat || r.Version != CustomRulesVersion {
		return fmt.Errorf("custom rules need format %q version %d", CustomRulesFormat, CustomRulesVersion)
	}
	if r.Rules == nil {
		r.Rules = []CustomRule{}
	}
	if len(r.Rules) > MaxCustomRules {
		return fmt.Errorf("at most %d custom rules are allowed", MaxCustomRules)
	}
	seen := map[string]int{}
	ids := map[string]bool{}
	for i := range r.Rules {
		rule := &r.Rules[i]
		if e := rule.Normalize(lanPrefix); e != nil {
			return fmt.Errorf("rule %d (%s): %w", i+1, short(rule.Value), e)
		}
		key := rule.key()
		if j, ok := seen[key]; ok {
			return fmt.Errorf("rule %d (%s) repeats rule %d", i+1, rule.Value, j+1)
		}
		seen[key] = i
		if !ruleIDRE.MatchString(rule.ID) || ids[rule.ID] {
			rule.ID = newRuleID(key, ids)
		}
		ids[rule.ID] = true
	}
	return nil
}

// Find returns the index of the rule with this ID, or -1.
func (r *CustomRules) Find(id string) int {
	for i, rule := range r.Rules {
		if rule.ID == id {
			return i
		}
	}
	return -1
}

// NewRuleID gives a rule added by the API a stable ID unique in r.
func (r *CustomRules) NewRuleID(rule CustomRule) string {
	ids := map[string]bool{}
	for _, item := range r.Rules {
		ids[item.ID] = true
	}
	return newRuleID(rule.key(), ids)
}

func newRuleID(key string, used map[string]bool) string {
	for n := 0; ; n++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s#%d", key, n)))
		id := "r" + hex.EncodeToString(sum[:5])
		if !used[id] {
			return id
		}
	}
}

func short(s string) string {
	if utf8.RuneCountInString(s) > 60 {
		return string([]rune(s)[:60]) + "…"
	}
	return s
}

// Normalize validates one rule and rewrites its value in canonical form. An
// empty type is inferred from the value.
func (rule *CustomRule) Normalize(lanPrefix netip.Prefix) error {
	if rule.Mode != RuleDirect && rule.Mode != RuleVPN {
		return fmt.Errorf("mode must be direct or vpn")
	}
	comment := strings.TrimSpace(rule.Comment)
	if !utf8.ValidString(comment) || utf8.RuneCountInString(comment) > MaxCustomComment {
		return fmt.Errorf("comment must be valid text of at most %d characters", MaxCustomComment)
	}
	for _, c := range comment {
		if unicode.IsControl(c) {
			return fmt.Errorf("comment must not contain control characters")
		}
	}
	rule.Comment = comment
	value := strings.ToLower(strings.TrimSpace(rule.Value))
	if value == "" || len(value) > 253 {
		return fmt.Errorf("value must be 1 to 253 characters")
	}
	if rule.Type == "" {
		rule.Type = inferRuleType(value)
	}
	var prefixes []netip.Prefix
	switch rule.Type {
	case RuleDomain:
		d, e := normalizeDomain(value)
		if e != nil {
			return e
		}
		rule.Value = d
		return nil
	case RuleIP:
		a, e := parseIPv4(value)
		if e != nil {
			return e
		}
		rule.Value = a.String()
		prefixes = []netip.Prefix{netip.PrefixFrom(a, 32)}
	case RuleCIDR:
		p, e := netip.ParsePrefix(value)
		if e != nil {
			return fmt.Errorf("not a CIDR subnet such as 198.51.100.0/24")
		}
		if !p.Addr().Is4() {
			return fmt.Errorf("only IPv4 is supported; FLR does not route IPv6 destinations")
		}
		p = p.Masked()
		rule.Value = p.String()
		prefixes = []netip.Prefix{p}
	case RuleRange:
		from, to, ok := strings.Cut(value, "-")
		if !ok {
			return fmt.Errorf("a range is written as first-last, for example 198.51.100.10-198.51.100.20")
		}
		a, e := parseIPv4(strings.TrimSpace(from))
		if e != nil {
			return e
		}
		b, e := parseIPv4(strings.TrimSpace(to))
		if e != nil {
			return e
		}
		if b.Less(a) {
			return fmt.Errorf("range start is after its end")
		}
		prefixes = rangePrefixes(v4(a), v4(b))
		if len(prefixes) > maxRangePrefixes {
			return fmt.Errorf("range is too fragmented (more than %d subnets); split it or use CIDR subnets", maxRangePrefixes)
		}
		rule.Value = a.String() + "-" + b.String()
	default:
		return fmt.Errorf("type must be domain, ip, cidr or range")
	}
	for _, p := range prefixes {
		if p.Bits() < minCustomBits {
			return fmt.Errorf("subnet %s is too broad; the shortest allowed prefix is /%d", p, minCustomBits)
		}
		for _, reserved := range reservedPrefixes {
			if p.Overlaps(reserved) {
				return fmt.Errorf("covers reserved, loopback or multicast addresses (%s)", reserved)
			}
		}
		if rule.Mode == RuleVPN && lanPrefix.IsValid() && p.Overlaps(lanPrefix.Masked()) {
			return fmt.Errorf("a vpn rule cannot cover the router LAN %s", lanPrefix.Masked())
		}
	}
	return nil
}

func inferRuleType(value string) string {
	if strings.Contains(value, "/") {
		return RuleCIDR
	}
	if from, to, ok := strings.Cut(value, "-"); ok {
		_, e1 := netip.ParseAddr(strings.TrimSpace(from))
		_, e2 := netip.ParseAddr(strings.TrimSpace(to))
		if e1 == nil && e2 == nil {
			return RuleRange
		}
	}
	if _, e := netip.ParseAddr(value); e == nil {
		return RuleIP
	}
	return RuleDomain
}

func parseIPv4(s string) (netip.Addr, error) {
	a, e := netip.ParseAddr(s)
	if e != nil {
		return netip.Addr{}, fmt.Errorf("%q is not an IPv4 address", short(s))
	}
	if !a.Is4() {
		return netip.Addr{}, fmt.Errorf("only IPv4 is supported; FLR does not route IPv6 destinations")
	}
	return a, nil
}

func normalizeDomain(value string) (string, error) {
	for _, c := range value {
		if c > unicode.MaxASCII {
			return "", fmt.Errorf("write internationalized domains in punycode (xn--…)")
		}
	}
	value = strings.TrimPrefix(value, "*.")
	value = strings.TrimPrefix(value, ".")
	value = strings.TrimSuffix(value, ".")
	if _, e := netip.ParseAddr(value); e == nil {
		return "", fmt.Errorf("this is an address; choose the IP type")
	}
	labels := strings.Split(value, ".")
	if len(value) > 253 || len(labels) < 2 {
		return "", fmt.Errorf("a domain needs at least two labels, such as example.com")
	}
	for _, label := range labels {
		if !domainLabel.MatchString(label) {
			return "", fmt.Errorf("invalid domain label %q", short(label))
		}
	}
	if allDigits.MatchString(labels[len(labels)-1]) {
		return "", fmt.Errorf("the top-level label of a domain cannot be numeric")
	}
	return value, nil
}

// key identifies the destination of a rule independent of its mode, so the
// same destination cannot be listed twice.
func (rule CustomRule) key() string {
	if rule.Type == RuleDomain {
		return "d:" + rule.Value
	}
	var parts []string
	for _, p := range rule.Prefixes() {
		parts = append(parts, p.String())
	}
	return "i:" + strings.Join(parts, ",")
}

// Prefixes are the IPv4 prefixes of a normalized address rule (nil for a
// domain rule).
func (rule CustomRule) Prefixes() []netip.Prefix {
	switch rule.Type {
	case RuleIP:
		if a, e := netip.ParseAddr(rule.Value); e == nil && a.Is4() {
			return []netip.Prefix{netip.PrefixFrom(a, 32)}
		}
	case RuleCIDR:
		if p, e := netip.ParsePrefix(rule.Value); e == nil && p.Addr().Is4() {
			return []netip.Prefix{p.Masked()}
		}
	case RuleRange:
		from, to, _ := strings.Cut(rule.Value, "-")
		a, e1 := netip.ParseAddr(from)
		b, e2 := netip.ParseAddr(to)
		if e1 == nil && e2 == nil && a.Is4() && b.Is4() && !b.Less(a) {
			return rangePrefixes(v4(a), v4(b))
		}
	}
	return nil
}

func v4(a netip.Addr) uint32 { b := a.As4(); return binary.BigEndian.Uint32(b[:]) }
func addr4(n uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	return netip.AddrFrom4(b)
}

// rangePrefixes covers [a, b] with the fewest CIDR blocks.
func rangePrefixes(a, b uint32) []netip.Prefix {
	var out []netip.Prefix
	for start := uint64(a); start <= uint64(b); {
		bits := 32
		for bits > 0 {
			size := uint64(1) << (32 - (bits - 1))
			if start%size != 0 || start+size-1 > uint64(b) {
				break
			}
			bits--
		}
		out = append(out, netip.PrefixFrom(addr4(uint32(start)), bits))
		start += uint64(1) << (32 - bits)
	}
	return out
}

// resolveCustomIPs turns possibly nested VPN and direct prefixes into two
// disjoint prefix lists in which every address carries the mode of its most
// specific rule (an exact tie goes to the VPN). The dataplane can then match
// the two sets in any order.
func resolveCustomIPs(vpn, direct []netip.Prefix) (vpnOut, directOut []netip.Prefix) {
	modes := map[netip.Prefix]bool{} // true: VPN
	var points []uint64
	add := func(list []netip.Prefix, isVPN bool) {
		for _, p := range list {
			p = p.Masked()
			if !p.Addr().Is4() {
				continue
			}
			if old, ok := modes[p]; !ok || isVPN && !old {
				modes[p] = isVPN
			}
			start := uint64(v4(p.Addr()))
			points = append(points, start, start+(uint64(1)<<(32-p.Bits())))
		}
	}
	add(vpn, true)
	add(direct, false)
	if len(points) == 0 {
		return nil, nil
	}
	sort.Slice(points, func(i, j int) bool { return points[i] < points[j] })
	type span struct {
		from, to uint64 // to is exclusive
		vpn      bool
	}
	var spans []span
	for i := 0; i+1 < len(points); i++ {
		from, to := points[i], points[i+1]
		if from == to {
			continue
		}
		x := addr4(uint32(from))
		for bits := 32; bits >= 0; bits-- {
			p, _ := x.Prefix(bits)
			if isVPN, ok := modes[p]; ok {
				if n := len(spans); n > 0 && spans[n-1].to == from && spans[n-1].vpn == isVPN {
					spans[n-1].to = to
				} else {
					spans = append(spans, span{from, to, isVPN})
				}
				break
			}
		}
	}
	for _, s := range spans {
		list := rangePrefixes(uint32(s.from), uint32(s.to-1))
		if s.vpn {
			vpnOut = append(vpnOut, list...)
		} else {
			directOut = append(directOut, list...)
		}
	}
	return vpnOut, directOut
}

// WithCustom returns a view of p with the enabled custom rules added. The
// view shares the ruleset matchers of p; p itself is not changed. A nil or
// empty rule list still yields (empty) custom matchers.
func (p *Policy) WithCustom(r *CustomRules) *Policy {
	v := &Policy{sources: make(map[string]*match, len(p.sources)+2)}
	for name, m := range p.sources {
		v.sources[name] = m
	}
	vpn := &match{exact: map[string]bool{}, suffix: map[string]bool{}}
	direct := &match{exact: map[string]bool{}, suffix: map[string]bool{}}
	var vpnIPs, directIPs []netip.Prefix
	if r != nil {
		for _, rule := range r.Rules {
			if !rule.Enabled {
				continue
			}
			isVPN := rule.Mode == RuleVPN
			if rule.Type == RuleDomain {
				if isVPN {
					vpn.suffix[rule.Value] = true
				} else {
					direct.suffix[rule.Value] = true
				}
				continue
			}
			if isVPN {
				vpnIPs = append(vpnIPs, rule.Prefixes()...)
			} else {
				directIPs = append(directIPs, rule.Prefixes()...)
			}
		}
	}
	vpn.prefixes, direct.prefixes = resolveCustomIPs(vpnIPs, directIPs)
	v.sources[CustomVPNSource], v.sources[CustomDirectSource] = vpn, direct
	return v
}

// customDomain applies the custom domain rules: the longest matching suffix
// across both modes decides.
func (p *Policy) customDomain(name string) (Class, bool) {
	vpn, direct := p.sources[CustomVPNSource], p.sources[CustomDirectSource]
	if vpn == nil && direct == nil {
		return "", false
	}
	for part := normalize(name); part != ""; {
		if vpn != nil && vpn.suffix[part] {
			return General, true
		}
		if direct != nil && direct.suffix[part] {
			return Direct, true
		}
		i := strings.IndexByte(part, '.')
		if i < 0 {
			break
		}
		part = part[i+1:]
	}
	return "", false
}

// customDecisionSource reports a custom decision under the list whose DNS
// bindings take precedence in the dataplane (dns.MappingSet: required4 and
// essential4 are matched before games and the other lists), so a custom rule
// outranks the ruleset classes for addresses learned through DNS as well.
func customDecisionSource(c Class) string {
	if c == Direct {
		return "direct-essential"
	}
	return "vpn-required"
}

func (p *Policy) customIP(ip netip.Addr) (Class, bool) {
	if m := p.sources[CustomVPNSource]; m != nil && m.ip(ip) {
		return General, true
	}
	if m := p.sources[CustomDirectSource]; m != nil && m.ip(ip) {
		return Direct, true
	}
	return "", false
}
