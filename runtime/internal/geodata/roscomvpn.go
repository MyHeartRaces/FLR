package geodata

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
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
// Happ/INCY routing link: <scheme>://routing/<action>/<base64 JSON>, for
// example happ://routing/onadd/eyJ…. Everything after the action segment is
// the payload; standard base64 contains "/", so it is never split further.
// Standard and URL-safe alphabets are accepted, with or without padding.
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
		rest := s[len(scheme):]
		slash := strings.IndexByte(rest, '/')
		if slash <= 0 || !isAction(rest[:slash]) {
			return nil, fmt.Errorf("routing link has no action segment (for example onadd/)")
		}
		payload := rest[slash+1:]
		if i := strings.IndexAny(payload, "?#"); i >= 0 {
			payload = payload[:i]
		}
		payload = strings.TrimRight(strings.Join(strings.Fields(payload), ""), "=")
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

func isAction(s string) bool {
	if len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-' || c == '_') {
			return false
		}
	}
	return true
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
// Needs says they are not used), sanitized provenance (Source: scheme, host
// and path only, see SourceURL; SHA256 of the content) and the image's local
// defaults, which the overlay keeps.
type Input struct {
	Profile       *Profile
	Sites         *Sites
	IPs           *IPs
	ProfileSource string
	ProfileSHA256 string
	GeositeSource string
	GeositeSHA256 string
	GeoipSource   string
	GeoipSHA256   string
	ImportedAt    time.Time
	LocalDomains  []policy.Entry
	LocalIPs      []policy.Entry
}

// SourceURL is the provenance of a URL that may be published: scheme, host
// and path, without user information, query or fragment (which may carry
// tokens). Anything that does not parse as an absolute URL becomes "".
func SourceURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	clean := url.URL{Scheme: strings.ToLower(u.Scheme), Host: u.Host, Path: u.Path}
	return plainText(clean.String(), 1000)
}

// Issue counts profile entries or settings FLR skips or does not apply.
// Code and Args are stable for translation; Reason is the English text.
type Issue struct {
	Field    string   `json:"field"`
	Code     string   `json:"code"`
	Args     []string `json:"args,omitempty"`
	Reason   string   `json:"reason"`
	Count    int      `json:"count"`
	Examples []string `json:"examples,omitempty"`
}

// Note is a remark on the conversion, with a stable code like Issue.
type Note struct {
	Code string   `json:"code"`
	Args []string `json:"args,omitempty"`
	Text string   `json:"text"`
}

// Reasons are the English texts of the issue and note codes; %s are Args.
var Reasons = map[string]string{
	"empty_entry":           "empty entry",
	"private_in_proxy":      "private destinations always stay local in FLR",
	"no_geosite_data":       "no geosite data",
	"no_geoip_data":         "no geoip data",
	"category_unreadable":   "unreadable category: %s",
	"category_missing":      "category not found in the data file",
	"ext_unsupported":       "external data files are not supported",
	"prefix_unsupported":    "unsupported matcher prefix",
	"ipv6":                  "IPv6: FLR routes IPv4 only",
	"geoip_inverted":        "inverted geoip categories are not supported",
	"not_ip":                "not an IP address, CIDR or geoip category",
	"regex_too_long":        "regular expression longer than 1024 bytes",
	"regex_invalid":         "invalid regular expression",
	"name_empty":            "empty domain",
	"name_too_long":         "domain longer than 253 characters",
	"name_not_punycode":     "internationalized name not in punycode (xn--…)",
	"name_invalid":          "invalid characters in domain",
	"block_not_applied":     "FLR does not block destinations; they follow the other lists (unlisted: VPN)",
	"dns_hosts":             "FLR resolves every name through its own DNS broker; static host entries are not imported",
	"dns_servers":           "FLR uses its own resolvers: DoH inside the VPN, and the direct resolver of its settings for direct names",
	"fake_dns":              "FLR does not use fake DNS answers",
	"domain_strategy":       "FLR always matches the name first and, for unlisted names, the resolved IPv4 address (the same as IPIfNonMatch)",
	"route_order":           "FLR always gives the VPN lists precedence over the direct lists (block-proxy-direct)",
	"global_proxy":          "FLR still sends unlisted destinations through the VPN",
	"note_bare_keywords":    "%s bare entries were imported as substring (keyword) matches, as Xray matches them; write domain:example.com for a domain and its subdomains",
	"note_proxyip_wins":     "an address in ProxyIp goes through the VPN even when its name is in DirectSites (FLR matches address sets before name-derived direct sets)",
	"note_split_only":       "DirectSites and DirectIp apply in routing mode split only; full_domestic and full ignore them",
	"note_duplicate_refs":   "%s repeated category references were expanded once",
	"note_attribute_filter": "attribute filters follow Xray: geosite:name@attr keeps domains with the attribute key attr; a leading ! is part of the key",
}

func reasonText(code string, args []string) string {
	text := Reasons[code]
	if len(args) == 0 {
		return text
	}
	vals := make([]any, len(args))
	for i, a := range args {
		vals[i] = a
	}
	return fmt.Sprintf(text, vals...)
}

// RulesetCount is one generated ruleset: entries per matcher kind, all
// entries, and how many came from the profile (the rest are image defaults).
type RulesetCount struct {
	Counts   map[string]int `json:"counts"`
	Total    int            `json:"total"`
	Imported int            `json:"imported"`
}

// Category is one geosite or geoip category the profile used; Entries
// counts the entries walked (before deduplication and validation).
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
	Notes       []Note                  `json:"notes"`
	TotalImport int                     `json:"total_imported"`
}

// Overlay is a converted profile: policy.json and every ruleset, in the
// format policy.Load reads.
type Overlay struct {
	Policy   json.RawMessage
	Rulesets map[string]json.RawMessage
	Report   Report
}

// MaxExpandedEntries bounds the category entries one conversion walks, all
// references together and duplicates included, so a profile that names big
// categories many times fails early instead of working for minutes.
const MaxExpandedEntries = 4 << 20

// limits in force (lowered in tests).
var (
	maxRulesetEntries  = MaxRulesetEntries
	maxKeywords        = MaxKeywords
	maxRegexps         = MaxRegexps
	maxExpandedEntries = MaxExpandedEntries
)

var domainKindOrder = []string{"domain", "domain_suffix", "domain_keyword", "domain_regex"}

// kindSet keeps the values of one matcher kind in first-seen order; the
// order slice and the set share each string.
type kindSet struct {
	order []string
	set   map[string]struct{}
}

type ruleset struct {
	name     string
	kinds    map[string]*kindSet
	cidrs    []netip.Prefix
	cidrSet  map[netip.Prefix]struct{}
	total    int
	imported int
}

func newRuleset(name string) *ruleset {
	r := &ruleset{name: name, kinds: map[string]*kindSet{}, cidrSet: map[netip.Prefix]struct{}{}}
	for _, k := range domainKindOrder {
		r.kinds[k] = &kindSet{set: map[string]struct{}{}}
	}
	return r
}

type converter struct {
	ctx        context.Context
	in         Input
	sets       map[string]*ruleset
	issues     map[string]*Issue
	skipped    []*Issue
	notApp     []*Issue
	cats       []Category
	refs       map[string]bool
	dupRefs    int
	notes      []Note
	bare       int
	keywords   int
	regexps    int
	expanded   int
	badRegexp  map[string]struct{}
	scratch    []byte
	attrFilter bool
}

func (c *converter) issue(dst *[]*Issue, field, code string, args []string, example func() string, count int) {
	list := "n"
	if dst == &c.skipped {
		list = "s"
	}
	key := list + "|" + field + "|" + code + "|" + strings.Join(args, "\x00")
	is := c.issues[key]
	if is == nil {
		is = &Issue{Field: field, Code: code, Args: args, Reason: reasonText(code, args)}
		c.issues[key] = is
		*dst = append(*dst, is)
	}
	is.Count += count
	if example != nil && len(is.Examples) < 3 {
		if ex := example(); ex != "" {
			is.Examples = append(is.Examples, shortExample(ex))
		}
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

func text1(s string) func() string { return func() string { return s } }

func (c *converter) skip(field, code string, example func() string) {
	c.issue(&c.skipped, field, code, nil, example, 1)
}

func (c *converter) note(code string, args ...string) {
	c.notes = append(c.notes, Note{Code: code, Args: args, Text: reasonText(code, args)})
}

// LimitError is a conversion refused by one of the limits above.
type LimitError struct{ msg string }

func (e *LimitError) Error() string { return e.msg }

func tooLarge(format string, args ...any) error {
	return &LimitError{fmt.Sprintf("the profile is too large for FLR: "+format, args...)}
}

// fatal reports errors that end the conversion: a limit or a cancelled
// context. Other errors of a category walk only skip that category.
func (c *converter) fatal(err error) bool {
	var le *LimitError
	return errors.As(err, &le) || c.ctx.Err() != nil
}

// example builds the text of an issue example only when it is kept.
func example(prefix string, value []byte) func() string {
	if value == nil {
		return text1(prefix)
	}
	return func() string { return prefix + " → " + string(value) }
}

// normalizeName checks a suffix or exact domain: lower case, no surrounding
// dots, ASCII letters, digits, "-", "_" and "." only, no empty labels. It
// returns v itself when v is already normal (no allocation) and a code when
// v is refused.
func (c *converter) normalizeName(v []byte, keyword bool) ([]byte, string) {
	v = bytes.TrimSpace(v)
	if !keyword {
		v = bytes.Trim(v, ".")
	}
	if len(v) == 0 {
		return nil, "name_empty"
	}
	if len(v) > 253 {
		return nil, "name_too_long"
	}
	upper := false
	for i := 0; i < len(v); i++ {
		b := v[i]
		switch {
		case b >= 0x80:
			return nil, "name_not_punycode"
		case b >= 'A' && b <= 'Z':
			upper = true
		case b >= 'a' && b <= 'z', b >= '0' && b <= '9', b == '-', b == '_', b == '.':
		default:
			return nil, "name_invalid"
		}
	}
	// A keyword is a substring of the full name, as in Xray: its dots are
	// literal (".ru" matches "a.ru" and "a.ru.example", not "trust.example")
	// and stay as written. A domain has no empty labels.
	if !keyword && bytes.Contains(v, []byte("..")) {
		return nil, "name_invalid"
	}
	if keyword && len(bytes.Trim(v, ".")) == 0 {
		return nil, "name_empty"
	}
	if upper {
		c.scratch = append(c.scratch[:0], v...)
		for i, b := range c.scratch {
			if b >= 'A' && b <= 'Z' {
				c.scratch[i] = b + 'a' - 'A'
			}
		}
		v = c.scratch
	}
	return v, ""
}

// addDomain adds one domain matcher. Duplicates are found without
// allocating; budgets are enforced as entries arrive.
func (c *converter) addDomain(target, field, kind string, raw []byte, exPrefix string, exValue []byte) error {
	var value []byte
	switch kind {
	case "domain_regex":
		value = raw
	default:
		var code string
		if value, code = c.normalizeName(raw, kind == "domain_keyword"); code != "" {
			c.skip(field, code, example(exPrefix, exValue))
			return nil
		}
	}
	r := c.sets[target]
	ks := r.kinds[kind]
	if _, dup := ks.set[string(value)]; dup {
		return nil
	}
	if kind == "domain_regex" {
		if _, bad := c.badRegexp[string(value)]; bad {
			c.skip(field, "regex_invalid", example(exPrefix, exValue))
			return nil
		}
		if len(value) > 1024 {
			c.skip(field, "regex_too_long", example(exPrefix, exValue))
			return nil
		}
		if _, err := regexp.Compile(string(value)); err != nil {
			if len(c.badRegexp) < 4096 {
				c.badRegexp[string(value)] = struct{}{}
			}
			c.skip(field, "regex_invalid", example(exPrefix, exValue))
			return nil
		}
	}
	return c.store(r, kind, string(value), true)
}

func (c *converter) store(r *ruleset, kind, value string, imported bool) error {
	if r.total >= maxRulesetEntries {
		return tooLarge("ruleset %s would hold more than %d entries", r.name, maxRulesetEntries)
	}
	switch kind {
	case "domain_keyword":
		if c.keywords >= maxKeywords {
			return tooLarge("more than %d keyword matchers", maxKeywords)
		}
		c.keywords++
	case "domain_regex":
		if c.regexps >= maxRegexps {
			return tooLarge("more than %d regular expressions", maxRegexps)
		}
		c.regexps++
	}
	ks := r.kinds[kind]
	ks.set[value] = struct{}{}
	ks.order = append(ks.order, value)
	r.total++
	if imported {
		r.imported++
	}
	return nil
}

func (c *converter) addPrefix(target, field string, p netip.Prefix, exPrefix string, fromCategory bool) error {
	if !p.Addr().Is4() {
		ex := text1(exPrefix)
		if fromCategory {
			ex = func() string { return exPrefix + " → " + p.String() }
		}
		c.skip(field, "ipv6", ex)
		return nil
	}
	p = p.Masked()
	r := c.sets[target]
	if _, dup := r.cidrSet[p]; dup {
		return nil
	}
	if r.total >= maxRulesetEntries {
		return tooLarge("ruleset %s would hold more than %d entries", r.name, maxRulesetEntries)
	}
	r.cidrSet[p] = struct{}{}
	r.cidrs = append(r.cidrs, p)
	r.total++
	r.imported++
	return nil
}

// expand counts one walked category entry against MaxExpandedEntries.
func (c *converter) expand() error {
	if c.expanded++; c.expanded > maxExpandedEntries {
		return tooLarge("its categories expand to more than %d entries", maxExpandedEntries)
	}
	return nil
}

// reference reports whether a category reference is new for its target;
// a repeated one is expanded once.
func (c *converter) reference(field, target, name string) bool {
	key := target + "|" + strings.ToLower(name)
	if c.refs[key] {
		c.dupRefs++
		return false
	}
	c.refs[key] = true
	c.cats = append(c.cats, Category{List: field, Name: name})
	return true
}

// unreference drops the last category reference when it could not be
// walked, so the report lists only categories that were used and a repeat
// of it is reported again rather than counted as a duplicate.
func (c *converter) unreference(target, name string) {
	c.cats = c.cats[:len(c.cats)-1]
	delete(c.refs, target+"|"+strings.ToLower(name))
}

var domainKinds = map[DomainType]string{Plain: "domain_keyword", Regex: "domain_regex", RootDomain: "domain_suffix", Full: "domain"}

// sites maps one DirectSites or ProxySites list.
func (c *converter) sites(field, target string, entries []string) error {
	for _, raw := range entries {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		e := strings.TrimSpace(raw)
		low := strings.ToLower(e)
		ex := text1(e)
		var err error
		switch {
		case e == "":
			c.skip(field, "empty_entry", nil)
		case strings.HasPrefix(low, "geosite:"):
			spec := strings.TrimSpace(e[len("geosite:"):])
			name := strings.ToLower(strings.SplitN(spec, "@", 2)[0])
			dst := target
			if name == "private" {
				if target != "roscom-direct-domains" {
					c.skip(field, "private_in_proxy", ex)
					continue
				}
				dst = "local-domains"
			}
			if c.in.Sites == nil {
				c.skip(field, "no_geosite_data", ex)
				continue
			}
			if strings.Contains(spec, "@") {
				c.attrFilter = true
			}
			if !c.reference(field, dst, "geosite:"+spec) {
				continue
			}
			cat := &c.cats[len(c.cats)-1]
			found, werr := c.in.Sites.Each(c.ctx, spec, func(d Domain) error {
				if err := c.expand(); err != nil {
					return err
				}
				cat.Entries++
				return c.addDomain(dst, field, domainKinds[d.Type], d.Value, e, d.Value)
			})
			switch {
			case werr != nil && c.fatal(werr):
				return werr
			case werr != nil:
				c.unreference(dst, "geosite:"+spec)
				c.issue(&c.skipped, field, "category_unreadable", []string{werr.Error()}, ex, 1)
			case !found:
				c.unreference(dst, "geosite:"+spec)
				c.skip(field, "category_missing", ex)
			}
		case strings.HasPrefix(low, "domain:"):
			err = c.addDomain(target, field, "domain_suffix", []byte(e[len("domain:"):]), e, nil)
		case strings.HasPrefix(low, "full:"):
			err = c.addDomain(target, field, "domain", []byte(e[len("full:"):]), e, nil)
		case strings.HasPrefix(low, "keyword:"):
			err = c.addDomain(target, field, "domain_keyword", []byte(e[len("keyword:"):]), e, nil)
		case strings.HasPrefix(low, "regexp:"):
			err = c.addDomain(target, field, "domain_regex", []byte(e[len("regexp:"):]), e, nil)
		case strings.HasPrefix(low, "ext:"), strings.HasPrefix(low, "ext-domain:"):
			c.skip(field, "ext_unsupported", ex)
		case strings.Contains(e, ":"):
			c.skip(field, "prefix_unsupported", ex)
		default:
			// Xray matches a bare entry as a substring of the full name.
			c.bare++
			err = c.addDomain(target, field, "domain_keyword", []byte(e), e, nil)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// ips maps one DirectIp or ProxyIp list.
func (c *converter) ips(field, target string, entries []string) error {
	for _, raw := range entries {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		e := strings.TrimSpace(raw)
		low := strings.ToLower(e)
		ex := text1(e)
		var err error
		switch {
		case e == "":
			c.skip(field, "empty_entry", nil)
		case strings.HasPrefix(low, "geoip:!"):
			c.skip(field, "geoip_inverted", ex)
		case strings.HasPrefix(low, "geoip:"):
			code := strings.TrimSpace(e[len("geoip:"):])
			dst := target
			if strings.EqualFold(code, "private") {
				if target != "roscom-direct-ips" {
					c.skip(field, "private_in_proxy", ex)
					continue
				}
				dst = "local-ips"
			}
			if c.in.IPs == nil {
				c.skip(field, "no_geoip_data", ex)
				continue
			}
			if !c.reference(field, dst, "geoip:"+code) {
				continue
			}
			cat := &c.cats[len(c.cats)-1]
			reverse, found, werr := c.in.IPs.Each(c.ctx, code, func(p netip.Prefix) error {
				if err := c.expand(); err != nil {
					return err
				}
				cat.Entries++
				return c.addPrefix(dst, field, p, e, true)
			})
			switch {
			case werr != nil && c.fatal(werr):
				return werr
			case werr != nil:
				c.unreference(dst, "geoip:"+code)
				c.issue(&c.skipped, field, "category_unreadable", []string{werr.Error()}, ex, 1)
			case !found:
				c.unreference(dst, "geoip:"+code)
				c.skip(field, "category_missing", ex)
			case reverse:
				c.unreference(dst, "geoip:"+code)
				c.skip(field, "geoip_inverted", ex)
			}
		case strings.HasPrefix(low, "ext:"), strings.HasPrefix(low, "ext-ip:"):
			c.skip(field, "ext_unsupported", ex)
		default:
			if p, perr := netip.ParsePrefix(e); perr == nil {
				err = c.addPrefix(target, field, p, e, false)
			} else if a, aerr := netip.ParseAddr(e); aerr == nil && a.Zone() == "" {
				err = c.addPrefix(target, field, netip.PrefixFrom(a, a.BitLen()), e, false)
			} else {
				c.skip(field, "not_ip", ex)
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func rulesetJSON(r *ruleset, source string) json.RawMessage {
	rule := map[string][]string{}
	for kind, ks := range r.kinds {
		if len(ks.order) > 0 {
			rule[kind] = ks.order
		}
	}
	if len(r.cidrs) > 0 {
		cidrs := make([]string, len(r.cidrs))
		for i, p := range r.cidrs {
			cidrs[i] = p.String()
		}
		rule["ip_cidr"] = cidrs
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

// Convert turns a profile and its data into an FLR overlay. Category
// entries are streamed into per-kind sets (duplicates cost no allocation),
// the limits above are enforced as entries arrive, and ctx is checked while
// walking, so a stopping controller cancels promptly.
func Convert(ctx context.Context, in Input) (*Overlay, error) {
	p := in.Profile
	if p == nil {
		return nil, fmt.Errorf("no profile")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	c := &converter{ctx: ctx, in: in, sets: map[string]*ruleset{}, issues: map[string]*Issue{}, refs: map[string]bool{}, badRegexp: map[string]struct{}{}}
	for _, name := range policy.RulesetNames() {
		c.sets[name] = newRuleset(name)
	}
	for _, e := range in.LocalDomains {
		if c.sets["local-domains"].kinds[e.Kind] != nil {
			if _, dup := c.sets["local-domains"].kinds[e.Kind].set[e.Value]; !dup {
				if err := c.store(c.sets["local-domains"], e.Kind, e.Value, false); err != nil {
					return nil, err
				}
			}
		}
	}
	for _, e := range in.LocalIPs {
		if prefix, err := netip.ParsePrefix(e.Value); e.Kind == "ip_cidr" && err == nil {
			// Image defaults keep their IPv6 entries.
			r := c.sets["local-ips"]
			if _, dup := r.cidrSet[prefix.Masked()]; !dup {
				r.cidrSet[prefix.Masked()] = struct{}{}
				r.cidrs = append(r.cidrs, prefix.Masked())
				r.total++
			}
		}
	}
	for _, step := range []func() error{
		func() error { return c.sites("ProxySites", "vpn-required", p.ProxySites) },
		func() error { return c.ips("ProxyIp", "vpn-services", p.ProxyIP) },
		func() error { return c.sites("DirectSites", "roscom-direct-domains", p.DirectSites) },
		func() error { return c.ips("DirectIp", "roscom-direct-ips", p.DirectIP) },
	} {
		if err := step(); err != nil {
			return nil, err
		}
	}

	if len(p.BlockSites) > 0 {
		c.issue(&c.notApp, "BlockSites", "block_not_applied", nil, nil, len(p.BlockSites))
	}
	if len(p.BlockIP) > 0 {
		c.issue(&c.notApp, "BlockIp", "block_not_applied", nil, nil, len(p.BlockIP))
	}
	if p.DNSHosts > 0 {
		c.issue(&c.notApp, "DnsHosts", "dns_hosts", nil, nil, p.DNSHosts)
	}
	if len(p.DNSFields) > 0 {
		c.issue(&c.notApp, "DNS", "dns_servers", nil, text1(strings.Join(p.DNSFields, ", ")), len(p.DNSFields))
	}
	if p.FakeDNS != nil && *p.FakeDNS {
		c.issue(&c.notApp, "FakeDNS", "fake_dns", nil, nil, 1)
	}
	if p.DomainStrategy != "" {
		c.issue(&c.notApp, "DomainStrategy", "domain_strategy", nil, text1(plainText(p.DomainStrategy, 40)), 1)
	}
	if order := strings.ToLower(strings.TrimSpace(p.RouteOrder)); order != "" && order != "block-proxy-direct" {
		c.issue(&c.notApp, "RouteOrder", "route_order", nil, text1(plainText(p.RouteOrder, 40)), 1)
	}
	if p.GlobalProxy != nil && !*p.GlobalProxy {
		c.issue(&c.notApp, "GlobalProxy", "global_proxy", nil, text1("false"), 1)
	}
	if c.bare > 0 {
		c.note("note_bare_keywords", strconv.Itoa(c.bare))
	}
	if c.attrFilter {
		c.note("note_attribute_filter")
	}
	if c.dupRefs > 0 {
		c.note("note_duplicate_refs", strconv.Itoa(c.dupRefs))
	}
	if len(c.sets["vpn-services"].cidrs) > 0 && len(p.DirectSites) > 0 {
		c.note("note_proxyip_wins")
	}
	c.note("note_split_only")

	report := Report{Name: plainText(p.Name, 120), Rulesets: map[string]RulesetCount{}, Categories: c.cats, Notes: c.notes, Skipped: []Issue{}, NotApplied: []Issue{}}
	for _, name := range policy.RulesetNames() {
		r := c.sets[name]
		counts := map[string]int{}
		for kind, ks := range r.kinds {
			if len(ks.order) > 0 {
				counts[kind] = len(ks.order)
			}
		}
		if len(r.cidrs) > 0 {
			counts["ip_cidr"] = len(r.cidrs)
		}
		report.Rulesets[name] = RulesetCount{Counts: counts, Total: r.total, Imported: r.imported}
		report.TotalImport += r.imported
	}
	for _, is := range c.skipped {
		report.Skipped = append(report.Skipped, *is)
	}
	for _, is := range c.notApp {
		report.NotApplied = append(report.NotApplied, *is)
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
	// Provenance only: sanitized URLs and content hashes, never a query.
	source := SourceURL(in.ProfileSource)
	if source == "" {
		source = plainText(in.ProfileSource, 120)
	}
	meta := struct {
		Format         string         `json:"format"`
		Version        int            `json:"version"`
		Status         string         `json:"status"`
		DefaultClass   string         `json:"default_class"`
		Name           string         `json:"name"`
		Source         string         `json:"source"`
		SourceSHA256   string         `json:"source_sha256,omitempty"`
		Geosite        string         `json:"geosite,omitempty"`
		GeositeSHA256  string         `json:"geosite_sha256,omitempty"`
		Geoip          string         `json:"geoip,omitempty"`
		GeoipSHA256    string         `json:"geoip_sha256,omitempty"`
		ProfileUpdated string         `json:"profile_last_updated,omitempty"`
		ImportedAt     string         `json:"imported_at"`
		Note           string         `json:"note"`
		Counts         map[string]int `json:"counts"`
	}{
		Format: "flint2-home-vpn-routing-policy", Version: 3, Status: PolicyStatus, DefaultClass: "vpn-general",
		Name: name, Source: source, SourceSHA256: in.ProfileSHA256, ProfileUpdated: updated,
		ImportedAt: in.ImportedAt.UTC().Format(time.RFC3339),
		Note:       "Imported from a RoscomVPN routing profile: DirectSites/DirectIp are the broad direct lists, ProxySites/ProxyIp go through the VPN, private destinations stay local; everything else goes through the VPN.",
		Counts:     counts,
	}
	if in.Sites != nil {
		meta.Geosite, meta.GeositeSHA256 = SourceURL(in.GeositeSource), in.GeositeSHA256
	}
	if in.IPs != nil {
		meta.Geoip, meta.GeoipSHA256 = SourceURL(in.GeoipSource), in.GeoipSHA256
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
