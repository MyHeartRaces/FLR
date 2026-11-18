package config

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/MyHeartRaces/FLR/runtime/internal/native"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/MyHeartRaces/FLR/runtime/internal/dataplane"
)

const SlotAddress = "198.18.0.1/30"
const SlotPeer = "198.18.0.2"
const SlotHost = "198.18.0.1"

var awgUCIFields = map[string]string{
	"Jc": "jc", "Jmin": "jmin", "Jmax": "jmax", "S1": "s1", "S2": "s2", "S3": "s3", "S4": "s4",
	"H1": "h1", "H2": "h2", "H3": "h3", "H4": "h4", "I1": "i1", "I2": "i2", "I3": "i3", "I4": "i4", "I5": "i5",
	"HeaderProtectionKey": "header_protection_key", "ContentPaddingAddition": "content_padding_addition",
	"RandomTrailers": "random_trailers", "DisableCookies": "disable_cookies", "RekeyAfterTime": "rekey_after_time",
	"RekeyTimeout": "rekey_timeout", "RejectAfterTime": "reject_after_time", "KeepaliveTimeout": "keepalive_timeout", "MaxHandshakeAttempts": "max_handshake_attempts",
}

func awgRange(v string, bits int) (uint64, uint64, error) {
	parts := strings.Split(v, "-")
	if len(parts) > 2 || !regexp.MustCompile(`^[0-9]+(-[0-9]+)?$`).MatchString(v) {
		return 0, 0, fmt.Errorf("invalid AWG range")
	}
	low, e := strconv.ParseUint(parts[0], 10, bits)
	if e != nil {
		return 0, 0, fmt.Errorf("invalid AWG range")
	}
	high := low
	if len(parts) == 2 {
		high, e = strconv.ParseUint(parts[1], 10, bits)
	}
	if e != nil || low > high {
		return 0, 0, fmt.Errorf("invalid AWG range")
	}
	return low, high, nil
}
func validCPS(v string) bool {
	if len(v) > 4096 || strings.ContainsAny(v, "\r\n\x00") {
		return false
	}
	tags := regexp.MustCompile(`<[^<>]+>`).FindAllString(v, -1)
	if len(tags) == 0 || strings.Join(tags, "") != v {
		return false
	}
	timestamps := 0
	for _, tag := range tags {
		fields := strings.Fields(tag[1 : len(tag)-1])
		if len(fields) == 1 && fields[0] == "t" {
			timestamps++
			if timestamps > 1 {
				return false
			}
			continue
		}
		if len(fields) != 2 {
			return false
		}
		switch fields[0] {
		case "b":
			if !regexp.MustCompile(`^0x([a-fA-F0-9]{2})+$`).MatchString(fields[1]) {
				return false
			}
		case "r", "rc", "rd":
			n, e := strconv.Atoi(fields[1])
			if e != nil || n < 0 || n > 1000 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// ParseAWG accepts one interface/peer and only fields that FLR applies. Unknown
// hooks/routes/file references are rejected rather than executed or discarded.
func ParseAWG(raw []byte) (map[string]string, error) {
	if len(raw) == 0 || len(raw) > 65536 {
		return nil, fmt.Errorf("AWG configuration size rejected")
	}
	result := map[string]string{}
	seenFields := map[string]bool{}
	section := ""
	seenInterface, seenPeer := false, false
	interfaceFields := map[string]bool{"PrivateKey": true, "HeaderProtectionKey": true, "Address": true, "MTU": true, "DNS": true, "Table": true}
	for field := range awgUCIFields {
		interfaceFields[field] = true
	}
	peerFields := map[string]bool{"PublicKey": true, "PresharedKey": true, "Endpoint": true, "AllowedIPs": true, "PersistentKeepalive": true}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if line == "[Interface]" {
			if seenInterface || seenPeer {
				return nil, fmt.Errorf("invalid AWG sections")
			}
			seenInterface = true
			section = "interface"
			continue
		}
		if line == "[Peer]" {
			if !seenInterface || seenPeer {
				return nil, fmt.Errorf("one AWG peer required")
			}
			seenPeer = true
			section = "peer"
			continue
		}
		field, value, ok := strings.Cut(line, "=")
		field = strings.TrimSpace(field)
		value = strings.TrimSpace(value)
		if !ok || value == "" || seenFields[field] || strings.ContainsAny(value, "\r\x00") || ((section != "interface" || !interfaceFields[field]) && (section != "peer" || !peerFields[field])) {
			return nil, fmt.Errorf("unsupported or repeated AWG field")
		}
		seenFields[field] = true
		if field == "Table" {
			if value != "off" {
				return nil, fmt.Errorf("AWG Table must be off")
			}
			// FLR owns routing. This directive is accepted but never applied.
			continue
		}
		result[field] = value
	}
	if !seenInterface || !seenPeer {
		return nil, fmt.Errorf("AWG interface and peer required")
	}
	for _, key := range []string{"PrivateKey", "PublicKey", "PresharedKey", "HeaderProtectionKey"} {
		decoded, e := base64.StdEncoding.Strict().DecodeString(result[key])
		if e != nil || len(decoded) != 32 || bytes.Equal(decoded, make([]byte, 32)) {
			return nil, fmt.Errorf("invalid AWG key")
		}
	}
	address, e := netip.ParsePrefix(result["Address"])
	if e != nil || !address.Addr().Is4() || address.Addr().IsUnspecified() || address.Addr().IsMulticast() {
		return nil, fmt.Errorf("invalid AWG address")
	}
	endpoint, e := netip.ParseAddrPort(result["Endpoint"])
	if e != nil || !endpoint.Addr().Is4() || endpoint.Port() == 0 || endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() {
		return nil, fmt.Errorf("AWG endpoint requires IPv4:port")
	}
	for _, field := range []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4"} {
		value := result[field]
		if value == "" {
			if strings.HasPrefix(field, "S") {
				return nil, fmt.Errorf("AWG header protection requires S1-S4")
			}
			continue
		}
		low, high, e := awgRange(value, 16)
		if e != nil || low != high {
			return nil, fmt.Errorf("invalid AWG scalar")
		}
		if strings.HasPrefix(field, "S") && low < 12 {
			return nil, fmt.Errorf("AWG header protection requires prefixes >=12")
		}
	}
	if result["Jmin"] != "" && result["Jmax"] != "" {
		low, _, _ := awgRange(result["Jmin"], 16)
		high, _, _ := awgRange(result["Jmax"], 16)
		if low > high {
			return nil, fmt.Errorf("AWG junk size range reversed")
		}
	}
	type interval struct{ low, high uint64 }
	headers := []interval{}
	for i, field := range []string{"H1", "H2", "H3", "H4"} {
		value := result[field]
		if value == "" {
			value = strconv.Itoa(i + 1)
		}
		low, high, e := awgRange(value, 32)
		if e != nil {
			return nil, e
		}
		for _, h := range headers {
			if low <= h.high && high >= h.low {
				return nil, fmt.Errorf("AWG header ranges overlap")
			}
		}
		headers = append(headers, interval{low, high})
	}
	for _, field := range []string{"ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts"} {
		if result[field] != "" {
			if _, _, e := awgRange(result[field], 16); e != nil {
				return nil, e
			}
		}
	}
	for _, field := range []string{"RandomTrailers", "DisableCookies"} {
		switch result[field] {
		case "", "on", "off", "true", "false", "1", "0":
		default:
			return nil, fmt.Errorf("invalid AWG boolean")
		}
	}
	for _, field := range []string{"I1", "I2", "I3", "I4", "I5"} {
		if result[field] != "" && !validCPS(result[field]) {
			return nil, fmt.Errorf("unsupported AWG CPS signature")
		}
	}
	if result["MTU"] != "" {
		n, e := strconv.Atoi(result["MTU"])
		if e != nil || n < 576 || n > 9000 {
			return nil, fmt.Errorf("invalid AWG MTU")
		}
	}
	if result["PersistentKeepalive"] != "" {
		n, e := strconv.Atoi(result["PersistentKeepalive"])
		if e != nil || n < 0 || n > 65535 {
			return nil, fmt.Errorf("invalid AWG keepalive")
		}
	}
	if result["AllowedIPs"] != "" && result["AllowedIPs"] != "0.0.0.0/0" {
		return nil, fmt.Errorf("FLR requires controlled AWG default peer route")
	}
	if result["DNS"] != "" {
		for _, v := range strings.Split(result["DNS"], ",") {
			a, e := netip.ParseAddr(strings.TrimSpace(v))
			if e != nil || !a.Is4() {
				return nil, fmt.Errorf("AWG DNS must be IPv4")
			}
		}
	}
	return result, nil
}
func SaveAWG(path string, raw []byte) error {
	if _, e := ParseAWG(raw); e != nil {
		return e
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("invalid AWG state path")
	}
	dir := filepath.Dir(path)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	st, e := os.Lstat(dir)
	if e != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return fmt.Errorf("AWG directory must be private")
	}
	if st, e = os.Lstat(path); e == nil && (!st.Mode().IsRegular() || st.Mode().Perm() != 0600) {
		return fmt.Errorf("unsafe AWG state file")
	}
	f, e := os.CreateTemp(dir, ".awg-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(raw)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if e = os.Rename(f.Name(), path); e != nil {
		return e
	}
	d, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func migrateFirewall() error { return migrateFirewallWith(dataplane.Run) }

// slotRuleOptions are the scalar options of firewall.flr_tun_tcp, in the
// order they are written; src_ip and dest_ip are single-element lists.
var slotRuleOptions = [][2]string{{"name", "FLR-system-stack"}, {"src", "flr"}, {"proto", "tcp"}, {"target", "ACCEPT"}}

// migrateFirewallWith recreates the whole flr_tun_tcp section, so an option
// added by hand or by an older image (enabled, family, dest_port, ...) cannot
// survive it and keep the fast-path check (slotFirewallCurrent) from matching
// on every later standby start.
func migrateFirewallWith(run func(string, ...string) error) error {
	uciRun := func(args ...string) error { return run("uci", args...) }
	setField := func(key, value string) error { return uciRun("set", "firewall."+key+"="+value) }
	if e := uciRun("-q", "delete", "firewall.flr_tun_tcp"); e != nil && !native.Exit(e, 1) {
		return e
	}
	if e := setField("flr_tun_tcp", "rule"); e != nil {
		return e
	}
	for _, option := range slotRuleOptions {
		if e := setField("flr_tun_tcp."+option[0], option[1]); e != nil {
			return e
		}
	}
	if e := uciRun("add_list", "firewall.flr_tun_tcp.src_ip="+SlotPeer); e != nil {
		return e
	}
	if e := uciRun("add_list", "firewall.flr_tun_tcp.dest_ip="+SlotHost); e != nil {
		return e
	}
	if e := uciRun("commit", "firewall"); e != nil {
		return e
	}
	if e := run("fw4", "check"); e != nil {
		return e
	}
	return run("/etc/init.d/firewall", "restart")
}

// MigrateSlot is called before any generated imported engine starts. Legacy
// TUNs are removed first, so the conflicting connected subnet cannot coexist.
// A warm reserve starts the slot while AWG carries all traffic, so a rule that
// is already committed and loaded skips the commit, check and firewall restart.
func MigrateSlot() error { return migrateSlotWith(RetireLegacy, native.Output, dataplane.Run) }

func migrateSlotWith(retire func() error, output func(string, ...string) ([]byte, error), run func(string, ...string) error) error {
	if e := retire(); e != nil {
		return e
	}
	current, reason := slotFirewallCurrent(output)
	if current {
		return nil
	}
	slotFirewallLog("slot firewall rule not current (" + reason + "); recreating it with commit, fw4 check and firewall restart")
	return migrateFirewallWith(run)
}

// slotFirewallLog records why the fast path missed (stderr, which procd sends
// to the system log). Reasons name UCI options only, never their values.
var slotFirewallLog = func(message string) { slotLogger.Println(message) }
var slotLogger = log.New(os.Stderr, "flr-controller: ", 0)

// slotFirewallCurrent is true only when the UCI rule is exactly what
// migrateFirewallWith writes (every option, nothing more), has no staged
// change, and the running fw4 ruleset carries exactly that rule in the flr
// zone. Any read error or difference takes the full migration, which is the
// previous behaviour; the reason says which check missed.
func slotFirewallCurrent(output func(string, ...string) ([]byte, error)) (bool, string) {
	shown, e := output("uci", "-q", "show", "firewall.flr_tun_tcp")
	if e != nil {
		return false, "UCI rule flr_tun_tcp missing or unreadable"
	}
	want := map[string]bool{
		"firewall.flr_tun_tcp=rule":                       true,
		"firewall.flr_tun_tcp.src_ip='" + SlotPeer + "'":  true,
		"firewall.flr_tun_tcp.dest_ip='" + SlotHost + "'": true,
	}
	for _, option := range slotRuleOptions {
		want["firewall.flr_tun_tcp."+option[0]+"='"+option[1]+"'"] = true
	}
	differs := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(shown)), "\n") {
		line = strings.TrimSpace(line)
		if want[line] {
			delete(want, line)
		} else {
			differs[slotRuleOptionName(line)] = true
		}
	}
	for line := range want {
		differs[slotRuleOptionName(line)] = true
	}
	if len(differs) != 0 {
		names := make([]string, 0, len(differs))
		for name := range differs {
			names = append(names, name)
		}
		sort.Strings(names)
		return false, "UCI rule options differ: " + strings.Join(names, ", ")
	}
	staged, e := output("uci", "-q", "changes", "firewall")
	if e != nil {
		return false, "staged UCI firewall changes unreadable"
	}
	if strings.Contains(string(staged), "flr_tun_tcp") {
		return false, "uncommitted UCI changes to flr_tun_tcp"
	}
	live, e := output("nft", "-j", "list", "chain", "inet", "fw4", "input_flr")
	if e != nil {
		return false, "fw4 chain input_flr unreadable"
	}
	if !slotRuleLoaded(live) {
		return false, "loaded fw4 rule differs from flr_tun_tcp"
	}
	return true, ""
}

var slotOptionName = regexp.MustCompile(`^[A-Za-z0-9_]{1,32}$`)

// slotRuleOptionName names the option of one `uci show firewall.flr_tun_tcp`
// line ("type" for the section line) without its value.
func slotRuleOptionName(line string) string {
	rest, ok := strings.CutPrefix(line, "firewall.flr_tun_tcp")
	if !ok {
		return "unexpected line"
	}
	if strings.HasPrefix(rest, "=") {
		return "type"
	}
	name, _, _ := strings.Cut(strings.TrimPrefix(rest, "."), "=")
	if !slotOptionName.MatchString(name) {
		return "unexpected line"
	}
	return name
}

// slotRuleLoaded parses `nft -j list chain inet fw4 input_flr`. It is true
// only when exactly one rule carries the FLR-system-stack comment and that
// rule is exactly what fw4 renders for flr_tun_tcp: TCP from the slot peer to
// the slot host, one anonymous counter, accept. Any other match or statement
// (a port, an interface, a set or prefix, another verdict) is a mismatch.
// The order of the three matches is not significant.
func slotRuleLoaded(raw []byte) bool {
	var listing struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(raw, &listing) != nil {
		return false
	}
	named, exact := 0, false
	for _, object := range listing.Nftables {
		encoded, ok := object["rule"]
		if !ok {
			continue
		}
		var rule struct {
			Family  string            `json:"family"`
			Table   string            `json:"table"`
			Chain   string            `json:"chain"`
			Comment string            `json:"comment"`
			Expr    []json.RawMessage `json:"expr"`
		}
		if json.Unmarshal(encoded, &rule) != nil {
			return false
		}
		if rule.Comment != "!fw4: FLR-system-stack" {
			continue
		}
		named++
		exact = rule.Family == "inet" && rule.Table == "fw4" && rule.Chain == "input_flr" && slotRuleStatements(rule.Expr)
	}
	return named == 1 && exact
}

func slotRuleStatements(expr []json.RawMessage) bool {
	if len(expr) != 5 {
		return false
	}
	want := map[string]bool{"meta l4proto == tcp": true, "ip saddr == " + SlotPeer: true, "ip daddr == " + SlotHost: true}
	counters := 0
	for i, encoded := range expr {
		var statement map[string]json.RawMessage
		if json.Unmarshal(encoded, &statement) != nil || len(statement) != 1 {
			return false
		}
		for kind, body := range statement {
			switch kind {
			case "match":
				key, ok := slotRuleMatch(body)
				if !ok || !want[key] {
					return false
				}
				delete(want, key)
			case "counter":
				var counter map[string]json.Number
				if json.Unmarshal(body, &counter) != nil || len(counter) != 2 || counter["packets"] == "" || counter["bytes"] == "" {
					return false
				}
				counters++
			case "accept":
				if i != len(expr)-1 || string(bytes.TrimSpace(body)) != "null" {
					return false
				}
			default:
				return false
			}
		}
	}
	return len(want) == 0 && counters == 1
}

// slotRuleMatch renders one equality match on a meta key or a payload field
// against a single literal. Anything else (another operator, a set, a prefix,
// a range or a number) does not render.
func slotRuleMatch(body json.RawMessage) (string, bool) {
	var match map[string]json.RawMessage
	if json.Unmarshal(body, &match) != nil || len(match) != 3 {
		return "", false
	}
	var op, right string
	var left map[string]json.RawMessage
	if json.Unmarshal(match["op"], &op) != nil || op != "==" || json.Unmarshal(match["right"], &right) != nil || json.Unmarshal(match["left"], &left) != nil || len(left) != 1 {
		return "", false
	}
	var fields map[string]string
	if encoded, ok := left["meta"]; ok {
		if json.Unmarshal(encoded, &fields) != nil || len(fields) != 1 || fields["key"] == "" {
			return "", false
		}
		return "meta " + fields["key"] + " == " + right, true
	}
	if encoded, ok := left["payload"]; ok {
		if json.Unmarshal(encoded, &fields) != nil || len(fields) != 2 || fields["protocol"] == "" || fields["field"] == "" {
			return "", false
		}
		return fields["protocol"] + " " + fields["field"] + " == " + right, true
	}
	return "", false
}
func ActivateAWG(path, wan string) error {
	if path != "/etc/flr-runtime/primary-awg.conf" {
		return fmt.Errorf("fixed AWG path required")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	awg, e := ParseAWG(b)
	if e != nil {
		return e
	}
	return ActivateVPN(context.Background(), awg, wan)
}

// ActivateVPN arms the same rollback for imported-only and native setups.
func ActivateVPN(ctx context.Context, awg map[string]string, wan string) error {
	if awg != nil {
		if _, err := AWGText(awg); err != nil {
			return err
		}
	}
	var e error
	if e = Backup("/etc/flr-runtime/backup"); e != nil {
		return e
	}
	if e = ValidateBackup("/etc/flr-runtime/backup"); e != nil {
		return e
	}
	if e = dataplane.Run("/usr/sbin/flr-rollback", "arm"); e != nil {
		return e
	}
	if awg != nil {
		if e = configureAWGWith(awg, func(name string, args ...string) error { _, err := awgCommand(ctx, name, args...); return err }); e != nil {
			return e
		}
	}
	if e = configureFirewall(); e != nil {
		return e
	}
	for _, pkg := range []string{"network", "firewall"} {
		if e = uci("commit", pkg); e != nil {
			return e
		}
	}
	if e = dataplane.Run("ubus", "call", "network", "reload"); e != nil {
		return e
	}
	return migrateFirewall()
}

// CurrentAWGMetadata reads only public UCI fields; no key-bearing command or
// legacy private file is opened for a status request.
func CurrentAWGMetadata() (map[string]any, error) {
	var readErr error
	read := func(field string) string {
		b, e := native.Output("uci", "-q", "get", field)
		if e != nil {
			if !native.Exit(e, 1) {
				readErr = e
			}
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	host := read("network.flr_peer.endpoint_host")
	port := read("network.flr_peer.endpoint_port")
	address := strings.Fields(read("network.flr_awg.addresses"))
	if readErr != nil {
		return nil, readErr
	}
	endpoint, e := netip.ParseAddrPort(host + ":" + port)
	if e != nil || !endpoint.Addr().Is4() || len(address) != 1 {
		return map[string]any{"configured": false, "stored": false, "activated": false}, nil
	}
	prefix, e := netip.ParsePrefix(address[0])
	if e != nil || !prefix.Addr().Is4() {
		return map[string]any{"configured": false, "stored": false, "activated": false}, nil
	}
	return map[string]any{"configured": true, "stored": false, "activated": false, "endpoint": endpoint.String(), "address": prefix.String(), "awg_version": "3.1"}, nil
}

// ConfirmRollback snapshots the generation; the locked primitive rechecks it
// atomically with boot identity/deadline and removal.
func ConfirmRollback() error {
	if e := ValidateBackup("/etc/flr-runtime/backup"); e != nil {
		return e
	}
	pending, e := os.ReadFile("/etc/flr-runtime/rollback.pending")
	if e != nil {
		return fmt.Errorf("no pending rollback confirmation")
	}
	_, e = RollbackToken("confirm", strings.TrimSpace(string(pending)))
	return e
}
