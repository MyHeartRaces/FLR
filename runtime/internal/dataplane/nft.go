package dataplane

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/lan"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
)

type Options struct {
	LAN         string                    `json:"lan"`
	WAN         string                    `json:"wan"`
	TestClient  string                    `json:"test_client,omitempty"`
	Selection   contract.Selection        `json:"selection"`
	ManualGames bool                      `json:"manual_games"`
	Profiles    map[string]contract.Class `json:"profiles,omitempty"`
	Replace     bool                      `json:"-"`
	DNSPort     string                    `json:"-"`
	Continuity  bool                      `json:"-"`
	// Net is the router's LAN. It is never persisted: when unset it is read
	// from the LAN interface (see lan.Resolve) each time it is needed.
	Net lan.LAN `json:"-"`
}

// ResolveLAN returns the router LAN. A non-nil error means discovery failed
// and the returned LAN is the legacy fallback; callers must surface it.
func (o Options) ResolveLAN() (lan.LAN, error) {
	if !o.Net.IsZero() {
		return o.Net, nil
	}
	return lan.Resolve(o.LAN)
}

// LANNet is ResolveLAN for callers that only validate addresses.
func (o Options) LANNet() lan.LAN {
	l, _ := o.ResolveLAN()
	return l
}

type Batch struct {
	Nft     string
	Routes  []Route
	Rules   []Rule
	Options Options
	// LAN is the router LAN the device profile sets were rendered for; zero
	// when it was unknown. Profiles holds the rendered device profiles.
	LAN      lan.LAN
	Profiles map[string]contract.Class
}

// IgnoredProfile is a stored device profile that is not rendered because its
// address is not a client of the router's current LAN.
type IgnoredProfile struct {
	Client string         `json:"client"`
	Class  contract.Class `json:"class"`
	Reason string         `json:"reason"`
}

// ActiveProfiles splits stored device profiles into those rendered for the
// router LAN and those ignored. A zero router (LAN unknown) keeps every
// profile: an element for an address that is not on the LAN matches no LAN
// traffic, while dropping a real device's profile would change its routing.
func ActiveProfiles(profiles map[string]contract.Class, router lan.LAN) (map[string]contract.Class, []IgnoredProfile) {
	active := make(map[string]contract.Class, len(profiles))
	var ignored []IgnoredProfile
	for client, class := range profiles {
		if reason := profileReason(client, router); reason != "" {
			ignored = append(ignored, IgnoredProfile{Client: client, Class: class, Reason: reason})
			continue
		}
		active[client] = class
	}
	sort.Slice(ignored, func(i, j int) bool { return ignored[i].Client < ignored[j].Client })
	return active, ignored
}

func profileReason(client string, router lan.LAN) string {
	if router.IsZero() {
		return ""
	}
	ip, e := netip.ParseAddr(client)
	switch {
	case e != nil || !ip.Is4():
		return "not an IPv4 address"
	case ip == router.Addr:
		return "router address on LAN " + router.String()
	case !router.Contains(ip):
		return "outside LAN " + router.Prefix.String()
	case ip == router.Network():
		return "network address of LAN " + router.Prefix.String()
	case ip == router.Broadcast():
		return "broadcast address of LAN " + router.Prefix.String()
	}
	return ""
}

var ifaceRE = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)

// Direct mode uses the Direct class for boot-guard compatibility and an
// unused channel value for conntrack-only affinity. Never restore this
// combination into the packet mark.
const (
	directAffinityField = "ct mark & 0xff800000"
	directAffinityMark  = "0x43000000"
	directAffinity      = directAffinityField + " == " + directAffinityMark
)

// ValidateOptions checks structure only. Device profiles need a private IPv4
// address and a known class; membership in the live LAN is not checked here,
// because stored settings must load whatever the LAN is now. Build renders
// only the profiles of the current LAN (see ActiveProfiles), and new profiles
// are checked against the LAN where they are requested.
func ValidateOptions(o Options) error {
	if !ifaceRE.MatchString(o.LAN) || !ifaceRE.MatchString(o.WAN) || o.LAN == o.WAN {
		return fmt.Errorf("invalid LAN/WAN interfaces")
	}
	if o.Continuity && (o.LAN == contract.ContinuityDevice || o.WAN == contract.ContinuityDevice) {
		return fmt.Errorf("continuity interface conflicts with LAN/WAN")
	}
	if o.TestClient != "" {
		ip, e := netip.ParseAddr(o.TestClient)
		if e != nil || !ip.Is4() {
			return fmt.Errorf("test client must be IPv4")
		}
	}
	for _, c := range []contract.Channel{o.Selection.General, o.Selection.Games} {
		switch c {
		case contract.Down, contract.AWG, contract.Gecko, contract.VLESS:
		case contract.Continuity:
			if !o.Continuity {
				return fmt.Errorf("continuity egress requires an enabled bridge")
			}
		default:
			return fmt.Errorf("invalid channel %q", c)
		}
	}
	if o.Selection.Games == contract.VLESS && !o.ManualGames {
		return fmt.Errorf("VLESS games requires explicit manual selection")
	}
	if !o.Net.IsZero() {
		if e := o.Net.Validate(); e != nil {
			return fmt.Errorf("invalid LAN: %w", e)
		}
	}
	for client, class := range o.Profiles {
		ip, e := netip.ParseAddr(client)
		if e != nil || !ip.Is4() || !ip.IsPrivate() {
			return fmt.Errorf("profile needs a private IPv4 LAN host")
		}
		if class != contract.Direct && class != contract.General && class != contract.Games {
			return fmt.Errorf("invalid device profile")
		}
	}
	return nil
}

func Build(p *policy.Policy, o Options) (Batch, error) {
	if e := ValidateOptions(o); e != nil {
		return Batch{}, e
	}
	dnsRule, err := dnsRedirectRule(p, o)
	if err != nil {
		return Batch{}, err
	}
	router, profiles := activeProfileOptions(o)
	var s strings.Builder
	if o.Replace {
		s.WriteString("delete table inet flr\n")
	}
	s.WriteString("table inet flr {\n")
	staticSet := func(name, source string) {
		var entries []string
		for _, ip := range p.CIDRs(source) {
			if ip.Addr().Is4() {
				entries = append(entries, ip.String())
			}
		}
		fmt.Fprintf(&s, " set %s { type ipv4_addr; flags interval; auto-merge;", name)
		if len(entries) > 0 {
			fmt.Fprintf(&s, " elements = { %s };", strings.Join(entries, ", "))
		}
		s.WriteString(" }\n")
	}
	staticSet("local4", "local-ips")
	staticSet("broad_direct4", "roscom-direct-ips")
	staticSet("required_static4", "vpn-required")
	staticSet("essential_static4", "direct-essential")
	staticSet("games_static4", "game-platforms")
	staticSet("service_static4", "vpn-services")
	// The owner's custom address rules (policy/custom.go): disjoint sets
	// matched before every list-derived set below.
	staticSet("custom_vpn4", policy.CustomVPNSource)
	staticSet("custom_direct4", policy.CustomDirectSource)
	s.WriteString(" set profile_pending4 { type ipv4_addr; }\n")
	for _, class := range []contract.Class{contract.Direct, contract.General, contract.Games} {
		var ips []string
		for ip, c := range profiles {
			if c == class {
				ips = append(ips, ip)
			}
		}
		sort.Strings(ips)
		fmt.Fprintf(&s, " set profile_%s4 { type ipv4_addr;", class)
		if len(ips) > 0 {
			fmt.Fprintf(&s, " elements = { %s };", strings.Join(ips, ", "))
		}
		s.WriteString(" }\n")
	}
	for _, class := range []contract.Class{contract.Direct, contract.General} {
		fmt.Fprintf(&s, " chain profile_%s { ct mark set (ct mark & 0x007fffff) | %#08x; goto selected; }\n", class, contract.ClassMark(class))
	}
	for _, name := range []string{"required4", "essential4", "games4", "services4", "direct_domains4"} {
		fmt.Fprintf(&s, " set %s { type ipv4_addr; flags timeout; timeout 1h; }\n", name)
	}
	fmt.Fprintf(&s, " map egress { type mark : verdict; elements = { 0x01000000 : goto %s, 0x02000000 : goto %s }; }\n", o.Selection.General, o.Selection.Games)
	channels := []contract.Channel{contract.Down, contract.AWG, contract.Gecko, contract.VLESS}
	if o.Continuity {
		channels = append(channels, contract.Continuity)
	}
	for _, channel := range channels {
		fmt.Fprintf(&s, " chain %s { ct mark set (ct mark & 0x8fffffff) | %#08x; jump restore; }\n", channel, contract.ChannelMark(channel))
	}
	s.WriteString(" chain restore {\n")
	// OpenWrt 6.12 rejects register-to-register bitwise OR. Copy only our nine bits using constant operations.
	for bit := uint(23); bit < 32; bit++ {
		mask := uint32(1) << bit
		fmt.Fprintf(&s, "  ct mark & %#08x != 0 meta mark set meta mark | %#08x\n  ct mark & %#08x == 0 meta mark set meta mark & %#08x\n", mask, mask, mask, ^mask)
	}
	s.WriteString(" }\n")
	s.WriteString(" chain classify {\n  meta mark & 0x80000000 != 0 return\n  ip daddr @local4 ct mark & 0xff800000 == 0 return\n  ip saddr @profile_pending4 counter drop\n  ip saddr @profile_direct4 goto profile_direct\n  ct mark & 0xff800000 != 0 jump restore\n  ct mark & 0xff800000 != 0 return\n  ip saddr @profile_general4 goto profile_general\n  ct state != new ip saddr != @profile_games4 return\n")
	assign := func(c contract.Class) {
		s.WriteString(classificationRule(c))
	}
	s.WriteString("  ip daddr @custom_vpn4 ")
	assign(contract.General)
	s.WriteString("  ip daddr @custom_direct4 ")
	assign(contract.Direct)
	s.WriteString("  ip daddr @required4 ")
	assign(contract.General)
	s.WriteString("  ip daddr @required_static4 ")
	assign(contract.General)
	s.WriteString("  ip daddr @essential4 ")
	assign(contract.Direct)
	s.WriteString("  ip daddr @essential_static4 ")
	assign(contract.Direct)
	s.WriteString("  ip saddr @profile_games4 ")
	assign(contract.Games)
	s.WriteString("  ip daddr @games4 ")
	assign(contract.Games)
	s.WriteString("  ip daddr @games_static4 ")
	assign(contract.Games)
	s.WriteString("  ip daddr @services4 ")
	assign(contract.General)
	s.WriteString("  ip daddr @service_static4 ")
	assign(contract.General)
	s.WriteString("  ip daddr @direct_domains4 ")
	assign(contract.Direct)
	s.WriteString("  ip daddr @broad_direct4 ")
	assign(contract.Direct)
	s.WriteString("  goto routing_default\n }\n chain routing_default {\n  ")
	assign(p.DefaultClass())
	s.WriteString(" }\n")
	s.WriteString(" chain selected {\n  ct mark & 0x0f000000 vmap @egress\n  jump restore\n }\n")
	s.WriteString(" chain route_direct {\n  meta mark & 0x80000000 != 0 return\n  ct mark & 0xff800000 != 0 goto restore\n  ct mark set (ct mark & 0x007fffff) | " + directAffinityMark + "\n }\n")
	route, guard := routingModeRules(p)
	fmt.Fprintf(&s, " chain routing_mode {\n  %s\n }\n chain routing_guards {\n", route)
	if guard != "" {
		fmt.Fprintf(&s, "  %s\n", guard)
	}
	s.WriteString(" }\n")
	scope := lanIngress(o)
	s.WriteString(" chain dns_handoff {\n }\n")
	fmt.Fprintf(&s, " chain preroute { type filter hook prerouting priority -151; policy accept;\n  iifname %q jump dns_handoff\n  %s return\n  %s jump routing_mode\n }\n", o.LAN, directAffinity, scope)
	fmt.Fprintf(&s, " chain policy_guards {\n  meta mark & 0x80000000 == 0 ip daddr @profile_pending4 ip saddr != @local4 counter drop\n  meta mark & 0x80000000 == 0 ip saddr @profile_pending4 ip daddr != @local4 counter drop\n  iifname \"%s\" meta nfproto ipv6 oifname \"%s\" counter drop\n }\n", o.LAN, o.WAN)
	// Reject stale anchored flows even when the optional egress has been
	// removed. Their conntrack mark can outlive the controller that set it.
	continuityMark := fmt.Sprintf("  meta mark & %#08x == %#08x", contract.ChannelMask, contract.ChannelMark(contract.Continuity))
	continuityEgressGuard := continuityMark + " counter drop\n"
	var continuityIngressGuard string
	if o.Continuity {
		continuityEgressGuard = fmt.Sprintf("%s oifname != %q counter drop\n", continuityMark, contract.ContinuityDevice)
		continuityIngressGuard = fmt.Sprintf("  iifname %q ct state != { established, related } counter drop\n", contract.ContinuityDevice)
		fmt.Fprintf(&s, " chain input_guard { type filter hook input priority -5; policy accept;\n%s }\n", continuityIngressGuard)
	}
	fmt.Fprintf(&s, " chain guard { type filter hook forward priority -5; policy accept;\n%s%s  meta mark & 0x0f000000 { 0x01000000, 0x02000000 } oifname \"%s\" counter drop\n  %s return\n  jump routing_guards\n }\n", continuityEgressGuard, continuityIngressGuard, o.WAN, directAffinity)
	fmt.Fprintf(&s, " chain output_guard { type filter hook output priority -5; policy accept;\n%s  meta mark & 0x80000000 == 0 meta mark & 0x0f000000 { 0x01000000, 0x02000000 } oifname \"%s\" counter drop\n }\n", continuityEgressGuard, o.WAN)
	fmt.Fprintf(&s, " chain nat { type nat hook postrouting priority 99; policy accept;\n  %s oifname \"flr_awg\" masquerade\n", scope)
	if o.Continuity {
		fmt.Fprintf(&s, "  %s meta nfproto ipv4 oifname %q masquerade\n", scope, contract.ContinuityDevice)
	}
	s.WriteString(" }\n")
	s.WriteString(" chain dns { type nat hook prerouting priority -100; policy accept;\n")
	if dnsRule != "" {
		fmt.Fprintf(&s, "  %s\n", dnsRule)
	}
	s.WriteString(" }\n")
	s.WriteString(" chain session_out { type filter hook output priority -151; policy accept; meta mark & 0xff800000 == 0x80800000 ct mark set (ct mark & 0x007fffff) | 0x80800000; }\n")
	s.WriteString("}\n")
	b := Batch{Nft: s.String(), Options: o, LAN: router, Profiles: profiles}
	for _, c := range channels[1:] {
		table := contract.Table(c)
		b.Routes = append(b.Routes, Route{Table: table, Unreachable: true, Metric: 32767}, Route{Table: table, Device: ownedRouteDevices[table], Metric: 100})
		b.Rules = append(b.Rules, channelRule(c))
	}
	b.Routes = append(b.Routes, Route{Table: terminalClassTable, Unreachable: true, Metric: 32767})
	b.Rules = append(b.Rules, terminalClassRules[:]...)
	return b, nil
}

// SelectionBatch is the same atomic map transaction used by runtime and the
// isolated kernel qualification. It cannot change channel resources.
func SelectionBatch(s contract.Selection, manualGames bool) (string, error) {
	if e := ValidateOptions(Options{LAN: "br-lan", WAN: "eth1", Selection: s, ManualGames: manualGames, Continuity: true}); e != nil {
		return "", e
	}
	return fmt.Sprintf("flush map inet flr egress\nadd element inet flr egress { 0x01000000 : goto %s, 0x02000000 : goto %s }\n", s.General, s.Games), nil
}
func UpdateSelection(s contract.Selection, manualGames bool) error {
	request, err := SelectionBatch(s, manualGames)
	if err != nil {
		return err
	}
	return runInput(request, "nft", "-f", "-")
}

func classificationRule(class contract.Class) string {
	return fmt.Sprintf("ct mark set (ct mark & 0x007fffff) | %#08x goto selected\n", contract.ClassMark(class))
}

func routingModeRules(p *policy.Policy) (route, guard string) {
	if p.Bypass() {
		return "goto route_direct", ""
	}
	return "goto classify", "jump policy_guards"
}

func lanIngress(o Options) string {
	scope := fmt.Sprintf(`iifname "%s"`, o.LAN)
	if o.TestClient != "" {
		scope += " ip saddr " + o.TestClient
	}
	return scope
}

func dnsRedirectRule(p *policy.Policy, o Options) (string, error) {
	if p.Bypass() || o.DNSPort == "" {
		return "", nil
	}
	port, err := strconv.Atoi(o.DNSPort)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid DNS port")
	}
	return fmt.Sprintf("%s meta nfproto ipv4 meta l4proto { tcp, udp } th dport 53 redirect to :%d", lanIngress(o), port), nil
}

const flushDNSHandoff = "flush chain inet flr dns_handoff\n"

// DNSHandoffBatch stops LAN DNS before either listener is reconfigured. It
// matches the original destination before redirect or direct flow affinity.
func DNSHandoffBatch(brokerPort, localPort string) (string, error) {
	ports := []string{"53"}
	seen := map[int]bool{53: true}
	for _, value := range []string{brokerPort, localPort} {
		port, err := strconv.Atoi(value)
		if err != nil || port < 1 || port > 65535 {
			return "", fmt.Errorf("invalid DNS port")
		}
		if !seen[port] {
			ports = append(ports, strconv.Itoa(port))
			seen[port] = true
		}
	}
	match := ports[0]
	if len(ports) > 1 {
		match = "{ " + strings.Join(ports, ", ") + " }"
	}
	return flushDNSHandoff + "add rule inet flr dns_handoff meta l4proto { tcp, udp } th dport " + match + " counter drop\n", nil
}

// StaticSetsBatch updates static CIDRs, the fallback classifier, and the
// mode's routing and forwarding chains without replacing the table.
func StaticSetsBatch(p *policy.Policy) string {
	var s strings.Builder
	for _, set := range []struct{ name, source string }{{"local4", "local-ips"}, {"broad_direct4", "roscom-direct-ips"}, {"required_static4", "vpn-required"}, {"essential_static4", "direct-essential"}, {"games_static4", "game-platforms"}, {"service_static4", "vpn-services"}, {"custom_vpn4", policy.CustomVPNSource}, {"custom_direct4", policy.CustomDirectSource}} {
		fmt.Fprintf(&s, "flush set inet flr %s\n", set.name)
		var entries []string
		for _, ip := range p.CIDRs(set.source) {
			if ip.Addr().Is4() {
				entries = append(entries, ip.String())
			}
		}
		if len(entries) > 0 {
			fmt.Fprintf(&s, "add element inet flr %s { %s }\n", set.name, strings.Join(entries, ", "))
		}
	}
	s.WriteString("flush chain inet flr routing_default\nadd rule inet flr routing_default ")
	s.WriteString(classificationRule(p.DefaultClass()))
	route, guard := routingModeRules(p)
	fmt.Fprintf(&s, "flush chain inet flr routing_mode\nadd rule inet flr routing_mode %s\nflush chain inet flr routing_guards\n", route)
	if guard != "" {
		fmt.Fprintf(&s, "add rule inet flr routing_guards %s\n", guard)
	}
	return s.String()
}

// RoutingPolicyBatch publishes DNS interception, active profiles, and the
// routing mode together, releasing any DNS handoff guard. Existing NAT
// associations remain in conntrack.
func RoutingPolicyBatch(p *policy.Policy, o Options) (string, error) {
	if err := ValidateOptions(o); err != nil {
		return "", err
	}
	rule, err := dnsRedirectRule(p, o)
	if err != nil {
		return "", err
	}
	_, profiles := activeProfileOptions(o)
	batch := StaticSetsBatch(p) + profilesBatch(profiles) + "flush chain inet flr dns\n"
	if rule != "" {
		batch += "add rule inet flr dns " + rule + "\n"
	}
	return batch + flushDNSHandoff, nil
}

func activeProfileOptions(o Options) (lan.LAN, map[string]contract.Class) {
	router, err := o.ResolveLAN()
	if err != nil {
		router = lan.LAN{}
	}
	profiles, _ := ActiveProfiles(o.Profiles, router)
	return router, profiles
}

// UpdateStaticSets applies StaticSetsBatch to the kernel.
func UpdateStaticSets(p *policy.Policy) error { return Nft(StaticSetsBatch(p)) }
