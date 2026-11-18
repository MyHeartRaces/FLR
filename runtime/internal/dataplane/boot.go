package dataplane

import (
	"fmt"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/native"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
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
	return fmt.Sprintf("# tracegate-flr-v1\ndestroy table inet flr_boot\ntable inet flr_boot {\n set local4 { type ipv4_addr; flags interval; auto-merge; elements = { %s }; }\n chain forward { type filter hook forward priority -6; policy accept;\n  %s ip daddr != @local4 ct mark & 0x0f000000 != 0x03000000 counter drop\n  iifname \"%s\" oifname \"%s\" meta nfproto ipv6 counter drop\n }\n}\n", strings.Join(ips, ", "), scope, o.LAN, o.WAN), nil
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
	return Nft(s.String())
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
	if _, e := output("nft", "list", "table", "inet", "flr_boot"); e != nil {
		if native.Interrupted(e) {
			return e
		}
		return nil
	}
	b, e := os.ReadFile("/etc/flr-runtime/boot-guard.nft")
	if e != nil || !strings.HasPrefix(string(b), "# tracegate-flr-v1\n") {
		return fmt.Errorf("foreign flr_boot table")
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
