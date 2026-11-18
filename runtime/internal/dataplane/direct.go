package dataplane

import (
	"fmt"
	"github.com/MyHeartRaces/FLR/runtime/internal/lan"
	"github.com/MyHeartRaces/FLR/runtime/internal/native"
	"regexp"
	"strings"
)

// PermanentDirectGuard owns only its separately named table. The table comment
// is checked before replacement/removal; no generic firewall flush is used.
func PermanentDirectGuard(router lan.LAN, bind string, port int, wan string, start bool) error {
	if !regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`).MatchString(wan) {
		return fmt.Errorf("invalid direct WAN interface")
	}
	if e := router.Validate(); e != nil || bind != router.Addr.String() || port < 1024 || port > 65535 || port == 1088 {
		return fmt.Errorf("invalid permanent direct guard")
	}
	old, e := output("nft", "list", "table", "inet", "flr_direct")
	if native.Interrupted(e) {
		return e
	}
	exists := e == nil
	if exists && !strings.Contains(string(old), `comment "tracegate-flr-direct-v1"`) {
		return fmt.Errorf("foreign direct guard exists")
	}
	batch := ""
	if exists {
		batch = "delete table inet flr_direct\n"
	}
	if start {
		batch += directGuardTable(router, port, wan)
	}
	if !start {
		if e := conntrackCleanup("-D", "--mark", "0x80400000/0xffc00000"); e != nil {
			return e
		}
	}
	if batch != "" {
		if e := Nft(batch); e != nil {
			return fmt.Errorf("permanent direct guard update failed")
		}
	}
	return nil
}

func directGuardTable(router lan.LAN, port int, wan string) string {
	return fmt.Sprintf("table inet flr_direct {\n comment \"tracegate-flr-direct-v1\"\n chain input {\n type filter hook input priority -5; policy accept;\n meta l4proto { tcp, udp } th dport %d iifname != \"br-lan\" counter drop\n meta l4proto { tcp, udp } th dport %d meta nfproto ipv6 counter drop\n meta l4proto { tcp, udp } th dport %d ip saddr != %s counter drop\n }\n chain output {\n type filter hook output priority -151; policy accept;\n meta mark & 0xffc00000 == 0x80400000 ct mark set (ct mark & 0x003fffff) | 0x80400000\n meta mark & 0xffc00000 == 0x80400000 oifname != \"%s\" counter drop\n }\n}\n", port, port, port, router.Prefix, wan)
}
