package config

import (
	"encoding/json"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const dummyKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="

func publicAWG() string {
	return "[Interface]\nPrivateKey = " + dummyKey + "\nAddress = 10.77.0.2/32\nHeaderProtectionKey = " + dummyKey + "\nS1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\nContentPaddingAddition = 0-32\nRandomTrailers = on\nDisableCookies = off\n[Peer]\nPublicKey = " + dummyKey + "\nPresharedKey = " + dummyKey + "\nEndpoint = 192.0.2.10:51820\nAllowedIPs = 0.0.0.0/0\n"
}
func TestAWGTableOff(t *testing.T) {
	raw := publicAWG()
	baseline, err := ParseAWG([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	withTable := strings.Replace(raw, "[Interface]\n", "[Interface]\nTable = off\n", 1)
	parsed, err := ParseAWG([]byte(withTable))
	if err != nil {
		t.Fatalf("Table=off rejected: %v", err)
	}
	if _, exists := parsed["Table"]; exists {
		t.Fatal("Table directive leaked into native fields")
	}
	if len(parsed) != len(baseline) {
		t.Fatal("Table=off changed native field count")
	}
	for field, value := range baseline {
		if parsed[field] != value {
			t.Fatalf("Table=off changed native field %s", field)
		}
	}
	for _, bad := range []string{
		strings.Replace(withTable, "Table = off", "Table = auto", 1),
		strings.Replace(withTable, "Table = off", "Table = 42", 1),
		strings.Replace(withTable, "Table = off", "Table = off\nTable = off", 1),
		raw + "Table = off\n",
		withTable + "PostUp = sh evil\n",
		strings.Replace(withTable, "PrivateKey = "+dummyKey, "PrivateKey = /tmp/key", 1),
	} {
		if _, err = ParseAWG([]byte(bad)); err == nil {
			t.Fatal("unsafe AWG directive accepted")
		}
	}
	path := filepath.Join(t.TempDir(), "private", "primary-awg.conf")
	if err = SaveAWG(path, []byte(withTable)); err != nil {
		t.Fatal(err)
	}
	if err = SaveAWG(path, []byte(strings.Replace(withTable, "Table = off", "Table = auto", 1))); err == nil {
		t.Fatal("unsafe Table overwrite accepted")
	}
	stored, err := os.ReadFile(path)
	if err != nil || string(stored) != withTable {
		t.Fatal("rejected overwrite changed saved AWG")
	}
}
func TestPrimaryAWGStrictValidationAndPrivateAtomicStore(t *testing.T) {
	raw := publicAWG()
	if _, e := ParseAWG([]byte(raw)); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{strings.Replace(raw, dummyKey, "bad", 1), raw + "PostUp = sh evil\n", strings.Replace(raw, "S1 = 12", "S1 = 11", 1), strings.Replace(raw, "0-32", "32-0", 1), strings.Replace(raw, "192.0.2.10:51820", "[::1]:51820", 1), raw + "[Peer]\nPublicKey = x\n"} {
		if _, e := ParseAWG([]byte(bad)); e == nil {
			t.Fatal("invalid AWG accepted")
		}
	}
	path := filepath.Join(t.TempDir(), "private", "primary-awg.conf")
	if e := SaveAWG(path, []byte(raw)); e != nil {
		t.Fatal(e)
	}
	if e := SaveAWG(path, []byte("invalid")); e == nil {
		t.Fatal("invalid overwrite accepted")
	}
	b, _ := os.ReadFile(path)
	if string(b) != raw {
		t.Fatal("invalid overwrite mutated existing config")
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0600 {
		t.Fatal("AWG secret file is not private")
	}
	directory, e := os.Stat(filepath.Dir(path))
	if e != nil || directory.Mode().Perm() != 0700 {
		t.Fatal("AWG parent directory is not private")
	}
}
func TestManagedSlotFirewallAddressContract(t *testing.T) {
	if SlotAddress != "198.18.0.1/30" || SlotPeer != "198.18.0.2" {
		t.Fatal("slot collides with legacy AWG")
	}
}

func TestAWGHeaderDefaultsCannotOverlapAndZeroKeysRejected(t *testing.T) {
	raw := publicAWG()
	bad := strings.Replace(raw, "S1 = 12", "H1 = 2\nS1 = 12", 1)
	if _, e := ParseAWG([]byte(bad)); e == nil {
		t.Fatal("header range overlaps default H2")
	}
	bad = strings.Replace(raw, dummyKey, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", 1)
	if _, e := ParseAWG([]byte(bad)); e == nil {
		t.Fatal("zero key accepted")
	}
}

func TestFirewallMigrationMatchesGeneratedManagedTUN(t *testing.T) {
	profiles, e := profile.Parse([]byte(`hysteria2://PUBLIC_TEST_PASSWORD@example.com:443/?obfs=salamander&obfs-password=PUBLIC_TEST_OBFS&sni=example.com`))
	if e != nil {
		t.Fatal(e)
	}
	rendered, e := profile.Render(profiles[0], "eth1", "/var/run/flr-runtime/transport")
	if e != nil {
		t.Fatal(e)
	}
	var generated struct {
		Inbounds []struct {
			Type    string   `json:"type"`
			Address []string `json:"address"`
		} `json:"inbounds"`
	}
	if e = json.Unmarshal(rendered.SingBox, &generated); e != nil {
		t.Fatal(e)
	}
	prefix, e := netip.ParsePrefix(generated.Inbounds[0].Address[0])
	if e != nil {
		t.Fatal(e)
	}
	commands := []string{}
	run := func(name string, args ...string) error {
		commands = append(commands, name+" "+strings.Join(args, " "))
		return nil
	}
	if e = migrateFirewallWith(run); e != nil {
		t.Fatal(e)
	}
	joined := strings.Join(commands, "\n")
	if !strings.Contains(joined, "firewall.flr_tun_tcp.dest_ip="+prefix.Addr().String()) || !strings.Contains(joined, "firewall.flr_tun_tcp.src_ip="+prefix.Addr().Next().String()) {
		t.Fatal("firewall does not match generated TUN")
	}
	if strings.Contains(joined, "10.78.") || strings.Contains(joined, "10.79.") {
		t.Fatal("legacy overlapping allowance retained")
	}
}

func TestAWGStoreRejectsExplicitNonPrivateDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not-private")
	if e := os.Mkdir(dir, 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(dir, 0755); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "primary-awg.conf")
	if e := SaveAWG(path, []byte(publicAWG())); e == nil {
		t.Fatal("0755 AWG directory accepted")
	}
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("rejected private store wrote secret file")
	}
}

func TestSlotFirewallFastPathSkipsCommitCheckAndRestart(t *testing.T) {
	rule := "firewall.flr_tun_tcp=rule\nfirewall.flr_tun_tcp.name='FLR-system-stack'\nfirewall.flr_tun_tcp.src='flr'\nfirewall.flr_tun_tcp.proto='tcp'\nfirewall.flr_tun_tcp.target='ACCEPT'\nfirewall.flr_tun_tcp.src_ip='198.18.0.2'\nfirewall.flr_tun_tcp.dest_ip='198.18.0.1'\n"
	// `nft -j list chain inet fw4 input_flr` as fw4 renders flr_tun_tcp.
	match := func(left, right string) string {
		return `{"match":{"op":"==","left":` + left + `,"right":` + right + `}}`
	}
	l4 := match(`{"meta":{"key":"l4proto"}}`, `"tcp"`)
	saddr := match(`{"payload":{"protocol":"ip","field":"saddr"}}`, `"198.18.0.2"`)
	daddr := match(`{"payload":{"protocol":"ip","field":"daddr"}}`, `"198.18.0.1"`)
	counter := `{"counter":{"packets":3,"bytes":180}}`
	accept := `{"accept":null}`
	named := func(expr ...string) string {
		return `{"rule":{"family":"inet","table":"fw4","chain":"input_flr","handle":12,"comment":"!fw4: FLR-system-stack","expr":[` + strings.Join(expr, ",") + `]}}`
	}
	chainOf := func(rules ...string) string {
		rules = append(rules, `{"rule":{"family":"inet","table":"fw4","chain":"input_flr","handle":13,"expr":[{"jump":{"target":"reject_from_flr"}}]}}`)
		return `{"nftables":[{"metainfo":{"version":"1.1.1","json_schema_version":1}},{"chain":{"family":"inet","table":"fw4","name":"input_flr","handle":5}},` + strings.Join(rules, ",") + `]}`
	}
	chain := chainOf(named(l4, saddr, daddr, counter, accept))
	singlePort := named(saddr, daddr, match(`{"payload":{"protocol":"tcp","field":"dport"}}`, `22`), counter, accept)
	type state struct {
		rule, staged, chain string
		ruleErr, chainErr   bool
	}
	for name, tc := range map[string]state{
		"current":           {rule: rule, chain: chain},
		"current-reordered": {rule: rule, chain: chainOf(named(saddr, daddr, l4, counter, accept))},
		"missing":           {ruleErr: true, chain: chain},
		"other-address":     {rule: strings.Replace(rule, "src_ip='198.18.0.2'", "src_ip='198.18.0.6'", 1), chain: chain},
		"second-address":    {rule: strings.Replace(rule, "src_ip='198.18.0.2'", "src_ip='198.18.0.2' '198.18.0.6'", 1), chain: chain},
		"extra-option":      {rule: rule + "firewall.flr_tun_tcp.enabled='0'\n", chain: chain},
		"missing-option":    {rule: strings.Replace(rule, "firewall.flr_tun_tcp.proto='tcp'\n", "", 1), chain: chain},
		"staged-change":     {rule: rule, staged: "firewall.flr_tun_tcp.src_ip+='198.18.0.2'\n", chain: chain},
		"not-loaded":        {rule: rule, chain: chainOf()},
		"loaded-elsewhere":  {rule: rule, chain: strings.Replace(chain, `"198.18.0.2"`, `"198.18.0.20"`, 1)},
		"other-host":        {rule: rule, chain: strings.Replace(chain, `"198.18.0.1"`, `"198.18.0.5"`, 1)},
		"single-port":       {rule: rule, chain: chainOf(singlePort)},
		"extra-match":       {rule: rule, chain: chainOf(named(l4, match(`{"meta":{"key":"iifname"}}`, `"flr-hy"`), saddr, daddr, counter, accept))},
		"address-set":       {rule: rule, chain: chainOf(named(l4, match(`{"payload":{"protocol":"ip","field":"saddr"}}`, `{"set":["198.18.0.2","198.18.0.6"]}`), daddr, counter, accept))},
		"address-prefix":    {rule: rule, chain: chainOf(named(l4, match(`{"payload":{"protocol":"ip","field":"saddr"}}`, `{"prefix":{"addr":"198.18.0.0","len":30}}`), daddr, counter, accept))},
		"negated":           {rule: rule, chain: chainOf(named(l4, strings.Replace(saddr, `"=="`, `"!="`, 1), daddr, counter, accept))},
		"no-counter":        {rule: rule, chain: chainOf(named(l4, saddr, daddr, accept))},
		"other-verdict":     {rule: rule, chain: chainOf(named(l4, saddr, daddr, counter, `{"drop":null}`))},
		"verdict-not-last":  {rule: rule, chain: chainOf(named(l4, saddr, daddr, accept, counter))},
		"also-partial":      {rule: rule, chain: chainOf(named(l4, saddr, daddr, counter, accept), singlePort)},
		"text-listing":      {rule: rule, chain: "table inet fw4 {\n\tchain input_flr {\n\t\tmeta l4proto tcp ip saddr 198.18.0.2 ip daddr 198.18.0.1 counter packets 3 bytes 180 accept comment \"!fw4: FLR-system-stack\"\n\t}\n}\n"},
		"no-zone-chain":     {rule: rule, chainErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			output := func(name string, args ...string) ([]byte, error) {
				switch name + " " + strings.Join(args, " ") {
				case "uci -q show firewall.flr_tun_tcp":
					if tc.ruleErr {
						return nil, os.ErrNotExist
					}
					return []byte(tc.rule), nil
				case "uci -q changes firewall":
					return []byte(tc.staged), nil
				case "nft -j list chain inet fw4 input_flr":
					if tc.chainErr {
						return nil, os.ErrNotExist
					}
					return []byte(tc.chain), nil
				}
				t.Fatal("unexpected native read", name, args)
				return nil, nil
			}
			commands := []string{}
			run := func(name string, args ...string) error {
				commands = append(commands, name+" "+strings.Join(args, " "))
				return nil
			}
			logs := captureSlotFirewallLog(t)
			if e := migrateSlotWith(func() error { return nil }, output, run); e != nil {
				t.Fatal(e)
			}
			joined := strings.Join(commands, "\n")
			full := strings.Contains(joined, "uci commit firewall") && strings.Contains(joined, "fw4 check") && strings.HasSuffix(joined, "/etc/init.d/firewall restart")
			exact := strings.HasPrefix(name, "current")
			if exact && (len(commands) != 0 || len(*logs) != 0) {
				t.Fatal("committed and loaded rule repeated commit, check or firewall restart", commands, *logs)
			}
			if !exact && !full {
				t.Fatal("unverified rule skipped the full migration", commands)
			}
			// A miss is logged once, with its reason and without option values.
			if !exact && (len(*logs) != 1 || !strings.Contains((*logs)[0], "not current (") || strings.Contains((*logs)[0], "198.18.") || strings.Contains((*logs)[0], "'")) {
				t.Fatal("fast-path miss not logged once without values", *logs)
			}
		})
	}
	unexpected := func(name string, args ...string) ([]byte, error) {
		t.Fatal("firewall inspected after legacy retirement failed")
		return nil, nil
	}
	if e := migrateSlotWith(func() error { return os.ErrPermission }, unexpected, func(string, ...string) error {
		t.Fatal("firewall changed after legacy retirement failed")
		return nil
	}); e == nil {
		t.Fatal("legacy retirement failure ignored")
	}
}

// captureSlotFirewallLog collects fast-path miss messages for one test.
func captureSlotFirewallLog(t *testing.T) *[]string {
	t.Helper()
	logs := &[]string{}
	old := slotFirewallLog
	slotFirewallLog = func(message string) { *logs = append(*logs, message) }
	t.Cleanup(func() { slotFirewallLog = old })
	return logs
}

// fakeSlotFirewall models `uci` for the flr_tun_tcp section (staged and
// committed views, as `uci show` and `uci changes` report them) and fw4
// loading the committed rule on a firewall restart.
type fakeSlotFirewall struct {
	t                 *testing.T
	staged, committed []string // `uci show` lines of the section; nil when absent
	changes           bool
	loaded            []string // committed lines loaded by the last restart
	restarts          int
}

func (f *fakeSlotFirewall) find(lines []string, prefix string) int {
	for i, line := range lines {
		if strings.HasPrefix(line, prefix) {
			return i
		}
	}
	return -1
}

func (f *fakeSlotFirewall) run(name string, args ...string) error {
	const section = "firewall.flr_tun_tcp"
	command := name + " " + strings.Join(args, " ")
	switch {
	case command == "uci -q delete "+section:
		f.staged, f.changes = nil, true
	case strings.HasPrefix(command, "uci -q delete "+section+"."):
		option := strings.TrimPrefix(command, "uci -q delete ")
		if i := f.find(f.staged, option+"="); i >= 0 {
			f.staged = append(f.staged[:i:i], f.staged[i+1:]...)
			f.changes = true
		}
	case command == "uci set "+section+"=rule":
		if f.find(f.staged, section+"=") < 0 {
			f.staged = append([]string{section + "=rule"}, f.staged...)
		}
		f.changes = true
	case strings.HasPrefix(command, "uci set "+section+"."):
		key, value, _ := strings.Cut(strings.TrimPrefix(command, "uci set "), "=")
		line := key + "='" + value + "'"
		if i := f.find(f.staged, key+"="); i >= 0 {
			f.staged[i] = line
		} else {
			f.staged = append(f.staged, line)
		}
		f.changes = true
	case strings.HasPrefix(command, "uci add_list "+section+"."):
		key, value, _ := strings.Cut(strings.TrimPrefix(command, "uci add_list "), "=")
		if i := f.find(f.staged, key+"="); i >= 0 {
			f.staged[i] += " '" + value + "'"
		} else {
			f.staged = append(f.staged, key+"='"+value+"'")
		}
		f.changes = true
	case command == "uci commit firewall":
		f.committed, f.changes = append([]string{}, f.staged...), false
	case command == "fw4 check":
	case command == "/etc/init.d/firewall restart":
		f.loaded = append([]string{}, f.committed...)
		f.restarts++
	default:
		f.t.Fatal("unexpected native command", command)
	}
	return nil
}

func (f *fakeSlotFirewall) output(name string, args ...string) ([]byte, error) {
	switch name + " " + strings.Join(args, " ") {
	case "uci -q show firewall.flr_tun_tcp":
		if f.staged == nil {
			return nil, os.ErrNotExist
		}
		return []byte(strings.Join(f.staged, "\n") + "\n"), nil
	case "uci -q changes firewall":
		if f.changes {
			return []byte("firewall.flr_tun_tcp.x='y'\n"), nil
		}
		return nil, nil
	case "nft -j list chain inet fw4 input_flr":
		// fw4 renders the rule as long as it is enabled; options such as family
		// or a stale helper do not change it.
		if f.find(f.loaded, "firewall.flr_tun_tcp=") < 0 || f.find(f.loaded, "firewall.flr_tun_tcp.enabled='0'") >= 0 {
			return []byte(`{"nftables":[{"chain":{"family":"inet","table":"fw4","name":"input_flr","handle":5}}]}`), nil
		}
		return []byte(`{"nftables":[{"chain":{"family":"inet","table":"fw4","name":"input_flr","handle":5}},{"rule":{"family":"inet","table":"fw4","chain":"input_flr","handle":12,"comment":"!fw4: FLR-system-stack","expr":[` +
			`{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"tcp"}},` +
			`{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"198.18.0.2"}},` +
			`{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"198.18.0.1"}},` +
			`{"counter":{"packets":0,"bytes":0}},{"accept":null}]}}]}`), nil
	}
	f.t.Fatal("unexpected native read", name, args)
	return nil, nil
}

// Finding 2: a stray option on flr_tun_tcp (here enabled and family, which fw4
// renders identically) made the fast path miss forever, so every standby start
// restarted the firewall. The slow path recreates the section, after which the
// next check takes the fast path; each miss is logged with its reason.
func TestSlotFirewallSlowPathConvergesToFastPath(t *testing.T) {
	canonical := []string{"firewall.flr_tun_tcp=rule", "firewall.flr_tun_tcp.name='FLR-system-stack'", "firewall.flr_tun_tcp.src='flr'", "firewall.flr_tun_tcp.proto='tcp'", "firewall.flr_tun_tcp.target='ACCEPT'", "firewall.flr_tun_tcp.src_ip='198.18.0.2'", "firewall.flr_tun_tcp.dest_ip='198.18.0.1'"}
	stray := append(append([]string{}, canonical[:2]...), "firewall.flr_tun_tcp.enabled='1'", "firewall.flr_tun_tcp.family='ipv4'")
	stray = append(stray, canonical[2:]...)
	for name, initial := range map[string][]string{"stray-options": stray, "missing": nil, "list-grew": append(append([]string{}, canonical[:5]...), "firewall.flr_tun_tcp.src_ip='198.18.0.2' '198.18.0.6'", canonical[6])} {
		t.Run(name, func(t *testing.T) {
			f := &fakeSlotFirewall{t: t, staged: initial, committed: initial, loaded: initial}
			logs := captureSlotFirewallLog(t)
			if e := migrateSlotWith(func() error { return nil }, f.output, f.run); e != nil {
				t.Fatal(e)
			}
			if f.restarts != 1 || len(*logs) != 1 {
				t.Fatal("first start did not take the full migration once", f.restarts, *logs)
			}
			if name == "stray-options" && !strings.Contains((*logs)[0], "enabled, family") {
				t.Fatal("miss reason does not name the stray options", *logs)
			}
			// Exactly the canonical options; their order is not significant.
			if len(f.committed) != len(canonical) {
				t.Fatal("slow path left the section with other options", f.committed)
			}
			for _, line := range canonical {
				if f.find(f.committed, line) < 0 {
					t.Fatal("recreated section differs", f.committed)
				}
			}
			for i := 0; i < 3; i++ {
				if e := migrateSlotWith(func() error { return nil }, f.output, f.run); e != nil {
					t.Fatal(e)
				}
			}
			if f.restarts != 1 || len(*logs) != 1 {
				t.Fatal("standby starts after the slow path did not take the fast path", f.restarts, *logs)
			}
		})
	}
}
