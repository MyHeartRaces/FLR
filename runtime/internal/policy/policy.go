package policy

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
)

type Class = contract.Class

const (
	Local   = contract.Local
	Direct  = contract.Direct
	General = contract.General
	Games   = contract.Games
)

type match struct {
	exact    map[string]bool
	suffix   map[string]bool
	keywords []string
	regex    []*regexp.Regexp
	prefixes []netip.Prefix
}
type Policy struct{ sources map[string]*match }

var sources = []string{"local-domains", "local-ips", "vpn-required", "direct-essential", "game-platforms", "vpn-services", "roscom-direct-domains", "roscom-direct-ips"}

func Load(dir string) (*Policy, error) {
	b, e := os.ReadFile(filepath.Join(dir, "policy.json"))
	if e != nil {
		return nil, e
	}
	var meta struct {
		Format  string `json:"format"`
		Version int    `json:"version"`
		Default string `json:"default_class"`
	}
	if e = json.Unmarshal(b, &meta); e != nil {
		return nil, e
	}
	if meta.Format != "flint2-home-vpn-routing-policy" || meta.Version != 3 || meta.Default != "vpn-general" {
		return nil, fmt.Errorf("unsupported policy contract")
	}
	p := &Policy{sources: make(map[string]*match)}
	for _, name := range sources {
		b, e = os.ReadFile(filepath.Join(dir, "rulesets", name+".json"))
		if e != nil {
			return nil, fmt.Errorf("%s: %w", name, e)
		}
		var rs struct {
			Version int                          `json:"version"`
			Rules   []map[string]json.RawMessage `json:"rules"`
		}
		if e = json.Unmarshal(b, &rs); e != nil {
			return nil, fmt.Errorf("%s: %w", name, e)
		}
		if rs.Version != 3 {
			return nil, fmt.Errorf("%s: unsupported ruleset version", name)
		}
		m := &match{exact: make(map[string]bool), suffix: make(map[string]bool)}
		for _, rule := range rs.Rules {
			for key, value := range rule {
				var values []string
				if e = json.Unmarshal(value, &values); e != nil {
					return nil, fmt.Errorf("%s/%s: %w", name, key, e)
				}
				for _, v := range values {
					switch key {
					case "domain":
						m.exact[normalize(v)] = true
					case "domain_suffix":
						m.suffix[normalize(v)] = true
					case "domain_keyword":
						m.keywords = append(m.keywords, strings.ToLower(v))
					case "domain_regex":
						r, e := regexp.Compile(v)
						if e != nil {
							return nil, fmt.Errorf("%s: %w", name, e)
						}
						m.regex = append(m.regex, r)
					case "ip_cidr":
						prefix, e := netip.ParsePrefix(v)
						if e != nil {
							return nil, fmt.Errorf("%s: %w", name, e)
						}
						m.prefixes = append(m.prefixes, prefix.Masked())
					default:
						return nil, fmt.Errorf("%s: unsupported matcher %s", name, key)
					}
				}
				if len(values) == 0 {
					switch key {
					case "domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr":
					default:
						return nil, fmt.Errorf("%s: unsupported matcher %s", name, key)
					}
				}
			}
		}
		p.sources[name] = m
	}
	return p, nil
}

func normalize(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}
func (m *match) domain(s string) bool {
	s = normalize(s)
	if m.exact[s] {
		return true
	}
	for part := s; part != ""; {
		if m.suffix[part] {
			return true
		}
		i := strings.IndexByte(part, '.')
		if i < 0 {
			break
		}
		part = part[i+1:]
	}
	for _, kw := range m.keywords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	for _, r := range m.regex {
		if r.MatchString(s) {
			return true
		}
	}
	return false
}
func (m *match) ip(ip netip.Addr) bool {
	for _, p := range m.prefixes {
		if p.Contains(ip.Unmap()) {
			return true
		}
	}
	return false
}
func (p *Policy) IsRequiredVPN(name string) bool   { return p.sources["vpn-required"].domain(name) }
func (p *Policy) ClassifyDomain(name string) Class { c, _ := p.DomainDecision(name); return c }
func (p *Policy) DomainDecision(name string) (Class, string) {
	if p.sources["local-domains"].domain(name) {
		return Local, "local-domains"
	}
	// Custom rules (custom.go) precede every list except local destinations.
	if class, ok := p.customDomain(name); ok {
		return class, customDecisionSource(class)
	}
	for _, r := range []struct {
		source string
		class  Class
	}{
		{"local-domains", Local}, {"vpn-required", General}, {"direct-essential", Direct}, {"game-platforms", Games},
		{"vpn-services", General}, {"roscom-direct-domains", Direct},
	} {
		if p.sources[r.source].domain(name) {
			return r.class, r.source
		}
	}
	return General, ""
}
func (p *Policy) ClassifyIP(ip netip.Addr) Class {
	if p.sources["local-ips"].ip(ip) {
		return Local
	}
	if class, ok := p.customIP(ip); ok {
		return class
	}
	if p.sources["vpn-required"].ip(ip) || p.sources["vpn-services"].ip(ip) {
		return General
	}
	if p.sources["roscom-direct-ips"].ip(ip) {
		return Direct
	}
	return General
}
func (p *Policy) CIDRs(source string) []netip.Prefix {
	m := p.sources[source]
	if m == nil {
		return nil
	}
	return append([]netip.Prefix(nil), m.prefixes...)
}

// ImageDir holds the policy shipped in the public image: everything goes
// through the VPN except local destinations. OverlayDir holds an owner's
// private policy (routing lists, direct services); it lives under
// /etc/flr-runtime, so sysupgrade keeps it, and it is never part of the image.
const (
	ImageDir   = "/usr/share/flint-vpn/policy"
	OverlayDir = "/etc/flr-runtime/policy"
)

// LoadInstalled loads the private overlay when one is installed and valid,
// otherwise the image policy. A broken overlay never stops the router: the
// image policy (all traffic through the VPN) is used and the overlay error is
// returned beside it for status reporting.
func LoadInstalled() (p *Policy, dir string, overlayErr error, err error) {
	return loadInstalled(OverlayDir, ImageDir)
}

func loadInstalled(overlay, image string) (*Policy, string, error, error) {
	var overlayErr error
	if _, e := os.Stat(filepath.Join(overlay, "policy.json")); e == nil {
		p, e := Load(overlay)
		if e == nil {
			return p, overlay, nil, nil
		}
		overlayErr = fmt.Errorf("private policy overlay ignored: %w", e)
	} else if !os.IsNotExist(e) {
		overlayErr = fmt.Errorf("private policy overlay unreadable: %w", e)
	}
	p, e := Load(image)
	return p, image, overlayErr, e
}

// InstalledDir is the directory LoadInstalled would use, for callers that
// take a directory (the legacy CLI default).
func InstalledDir() string {
	if _, dir, _, e := LoadInstalled(); e == nil {
		return dir
	}
	return ImageDir
}

// Routing modes (docs/MAX-PACKAGE.md, section 6). The installed policy is the
// "split" view; the other modes switch direct lists off without touching the
// local and VPN lists:
//   - full_domestic keeps only the essential direct services (direct-essential);
//   - full sends everything except local destinations through the VPN.
const (
	ModeSplit        = "split"
	ModeFullDomestic = "full_domestic"
	ModeFull         = "full"
)

func ValidMode(m string) bool {
	return m == ModeSplit || m == ModeFullDomestic || m == ModeFull
}

// modeOff lists the sources a routing mode switches off (nil: none). Custom
// "direct" rules follow direct-essential: they apply in split and
// full_domestic and are ignored in full; custom "vpn" rules always apply.
func modeOff(mode string) []string {
	switch mode {
	case ModeFull:
		return []string{"direct-essential", "roscom-direct-domains", "roscom-direct-ips", CustomDirectSource}
	case ModeFullDomestic:
		return []string{"roscom-direct-domains", "roscom-direct-ips"}
	}
	return nil
}

// ForMode returns a read-only view of p for a routing mode. The view shares the
// matchers of p; sources the mode switches off match nothing. An unknown or
// empty mode is the split view (p itself).
func (p *Policy) ForMode(mode string) *Policy {
	off := modeOff(mode)
	if off == nil {
		return p
	}
	v := &Policy{sources: make(map[string]*match, len(p.sources))}
	for name, m := range p.sources {
		v.sources[name] = m
	}
	for _, name := range off {
		v.sources[name] = &match{exact: map[string]bool{}, suffix: map[string]bool{}}
	}
	return v
}
