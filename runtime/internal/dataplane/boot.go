package dataplane

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/native"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
	"github.com/MyHeartRaces/FLR/runtime/internal/privatefile"
)

const (
	bootGuardPath   = "/etc/flr-runtime/boot-guard.nft"
	bootGuardHeader = "# tracegate-flr-v1\n"
)

func BuildBootGuard(p *policy.Policy, o Options) (string, error) {
	if e := ValidateOptions(o); e != nil {
		return "", e
	}
	var ips []string
	for _, ip := range p.CIDRs("local-ips") {
		if ip.Addr().Is4() {
			ips = append(ips, ip.String())
		}
	}
	scope := fmt.Sprintf(`iifname "%s" oifname "%s"`, o.LAN, o.WAN)
	if o.TestClient != "" {
		scope += " ip saddr " + o.TestClient
	}
	var elements string
	if len(ips) != 0 {
		elements = " elements = { " + strings.Join(ips, ", ") + " };"
	}
	return fmt.Sprintf(bootGuardHeader+`destroy table inet flr_boot
table inet flr_boot {
 set local4 { type ipv4_addr; flags interval; auto-merge;%s }
 chain forward { type filter hook forward priority -6; policy accept;
  %s ip daddr != @local4 ct mark & 0x0f000000 != 0x03000000 counter drop
  iifname "%s" oifname "%s" meta nfproto ipv6 %s != %s counter drop
 }
}
`, elements, scope, o.LAN, o.WAN, directAffinityField, directAffinityMark), nil
}

// PrepareRoutingBootGuard refreshes the owned firewall include and returns
// its rules for the same transaction as the routing table. Always return the
// rules for an owned include so a retry also refreshes a stale kernel table.
func PrepareRoutingBootGuard(p *policy.Policy, o Options) (string, error) {
	if err := CheckBootOwnership(); err != nil {
		return "", err
	}
	return prepareRoutingBootGuard(bootGuardPath, p, o)
}

func prepareRoutingBootGuard(path string, p *policy.Policy, o Options) (string, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", nil
	}
	current, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(string(current), bootGuardHeader) {
		return "", nil
	}
	guard, err := BuildBootGuard(p, o)
	if err != nil {
		return "", err
	}
	if guard != string(current) {
		if err := privatefile.Write(path, []byte(guard)); err != nil {
			return "", err
		}
	}
	return guard, nil
}

func ValidateBackup(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("backup must be absolute")
	}
	info, e := os.Lstat(dir)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return fmt.Errorf("backup directory must be private and real")
	}
	for _, name := range []string{"network", "firewall", "dhcp"} {
		path := filepath.Join(dir, name)
		stat, e := os.Lstat(path)
		if e != nil {
			return e
		}
		if !stat.Mode().IsRegular() || stat.Size() == 0 || stat.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("invalid/private backup file %s", name)
		}
		if _, e = os.ReadFile(path); e != nil {
			return e
		}
	}
	return nil
}

// UpdateProfiles replaces the device profile sets with exactly profiles.
// Callers pass the profiles of the current LAN (ActiveProfiles); addresses are
// checked for structure only.
func UpdateProfiles(profiles map[string]contract.Class) error {
	if e := ValidateOptions(Options{LAN: "br-lan", WAN: "eth1", Selection: contract.Selection{General: contract.Down, Games: contract.Down}, Profiles: profiles}); e != nil {
		return e
	}
	return Nft(profilesBatch(profiles))
}

func profilesBatch(profiles map[string]contract.Class) string {
	var s strings.Builder
	for _, c := range []contract.Class{contract.Direct, contract.General, contract.Games} {
		name := "profile_" + string(c) + "4"
		fmt.Fprintf(&s, "flush set inet flr %s\n", name)
		var ips []string
		for ip, class := range profiles {
			if class == c {
				ips = append(ips, ip)
			}
		}
		if len(ips) > 0 {
			fmt.Fprintf(&s, "add element inet flr %s { %s }\n", name, strings.Join(ips, ", "))
		}
	}
	return s.String()
}
func SessionGuard(client, mac string) error {
	ip, e := netip.ParseAddr(client)
	hw, me := net.ParseMAC(mac)
	if e != nil || !ip.Is4() || me != nil || len(hw) != 6 {
		return fmt.Errorf("invalid direct client")
	}
	if _, e := output("nft", "list", "chain", "inet", "flr", "session_guard"); e == nil {
		return fmt.Errorf("another direct guard exists")
	} else if native.Interrupted(e) {
		return e
	}
	return Nft(fmt.Sprintf("add chain inet flr session_guard { type filter hook input priority -5; policy accept; }\nadd rule inet flr session_guard tcp dport 1088 iifname != \"br-lan\" counter drop\nadd rule inet flr session_guard tcp dport 1088 ip saddr != %s counter drop\nadd rule inet flr session_guard tcp dport 1088 ether saddr != %s counter drop\nadd rule inet flr session_guard tcp dport 1088 meta nfproto ipv6 counter drop\n", client, mac))
}
func ClearSession() error {
	if e := conntrackCleanup("-D", "--mark", "0x80800000/0xff800000"); e != nil {
		return e
	}
	if _, e := output("nft", "list", "chain", "inet", "flr", "session_guard"); e == nil {
		if e = Nft("flush chain inet flr session_guard\ndelete chain inet flr session_guard\n"); e != nil {
			return e
		}
	} else if native.Interrupted(e) {
		return e
	}
	return nil
}

func CheckBootOwnership() error {
	return checkBootOwnership(bootGuardPath, output)
}

func checkBootOwnership(path string, out func(string, ...string) ([]byte, error)) error {
	tables, err := out("nft", "list", "tables")
	if err != nil {
		return fmt.Errorf("cannot check boot guard ownership: %w", err)
	}
	for _, line := range strings.Split(string(tables), "\n") {
		if strings.TrimSpace(line) == "table inet flr_boot" {
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() {
				return fmt.Errorf("flr_boot table has no regular owned include")
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("cannot read boot guard include: %w", err)
			}
			if !strings.HasPrefix(string(b), bootGuardHeader) {
				return fmt.Errorf("foreign flr_boot table")
			}
			return nil
		}
	}
	return nil
}

// ClearSlot invalidates just the reusable imported-profile mark. conntrack
// exits 1 when no entries match; that is a successful empty cleanup.
func ClearSlot() error {
	return conntrackCleanup("-D", "--mark", "0x20000000/0x70000000")
}

// ClearAWG retires failed/degraded AWG affinity without touching kill guards.
func ClearAWG() error {
	return conntrackCleanup("-D", "--mark", "0x10000000/0x70000000")
}
