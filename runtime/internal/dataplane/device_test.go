package dataplane

import (
	"errors"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
	"reflect"
	"strings"
	"testing"
)

func TestDirectOverridesAffinityAndClassifiesIncomingReplies(t *testing.T) {
	p, e := policy.Load("../policy/testdata/split")
	if e != nil {
		t.Fatal(e)
	}
	o := Options{LAN: "br-lan", WAN: "eth1", Selection: contract.Selection{General: contract.AWG, Games: contract.Gecko}}
	batch, e := Build(p, o)
	if e != nil {
		t.Fatal(e)
	}
	// These are the emitted classifier decisions for established marked outgoing
	// packets and unmarked replies to already permitted WAN DNAT connections.
	rules := []string{"meta mark & 0x80000000 != 0 return", "ip daddr @local4 return", "ip saddr @profile_pending4 counter drop", "ip saddr @profile_direct4 goto profile_direct", "ct mark & 0xff800000 != 0 jump restore", "ct mark & 0xff800000 != 0 return", "ip saddr @profile_general4 goto profile_general", "ct state != new ip saddr != @profile_games4 return"}
	previous := -1
	for _, rule := range rules {
		index := strings.Index(batch.Nft, rule)
		if index <= previous {
			t.Fatal("classifier ordering loses exclusion, transition gate, Direct override or incoming reply", rule)
		}
		previous = index
	}
	if !strings.Contains(batch.Nft, "chain profile_direct { ct mark set (ct mark & 0x007fffff) | 0x03000000; goto selected;") {
		t.Fatal("Direct retained VPN channel bits or lost foreign bits")
	}
	if !strings.Contains(batch.Nft, "ip daddr @profile_pending4 ip saddr != @local4 counter drop") {
		t.Fatal("incoming transition is not gated")
	}
	guard, e := BuildBootGuard(p, o)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(guard, "ct mark & 0x0f000000 != 0x03000000 counter drop") {
		t.Fatal("boot guard weakened")
	}
	if !strings.Contains(batch.Nft, `meta mark & 0x0f000000 { 0x01000000, 0x02000000 } oifname "eth1" counter drop`) {
		t.Fatal("kill guard weakened")
	}
}
func TestDeviceCleanupIsScopedBothDirectionsAndFailsClosed(t *testing.T) {
	var calls [][]string
	e := clearDeviceWith("192.168.8.2", func(args ...string) error { calls = append(calls, args); return nil })
	expected := [][]string{}
	for _, direction := range []string{"--orig-src", "--reply-src"} {
		for _, mark := range []string{"0x01000000/0x8f000000", "0x02000000/0x8f000000", "0x03000000/0x8f000000"} {
			expected = append(expected, []string{"-D", "-f", "ipv4", direction, "192.168.8.2", "--mark", mark})
		}
		nat := "--src-nat"
		if direction == "--reply-src" {
			nat = "--dst-nat"
		}
		expected = append(expected, []string{"-D", "-f", "ipv4", direction, "192.168.8.2", "--mark", "0x00000000/0xff800000", nat})
	}
	if e != nil || !reflect.DeepEqual(calls, expected) {
		t.Fatal(calls, e)
	}
	for _, failAt := range []int{1, 4, 5, 8} {
		n := 0
		e = clearDeviceWith("192.168.8.2", func(...string) error {
			n++
			if n == failAt {
				return errors.New("native stderr")
			}
			return nil
		})
		if e == nil || n != failAt || strings.Contains(e.Error(), "stderr") {
			t.Fatal("cleanup failure lost", e)
		}
	}
	n := 0
	if e = clearDeviceWith("192.0.2.1", func(...string) error { n++; return nil }); e == nil || n != 0 {
		t.Fatal("unvalidated cleanup")
	}
}

func TestDeviceCleanupDistinguishesEmptyFromOperationalFailure(t *testing.T) {
	empty := "conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.\n"
	if deviceCleanupResult(0, "", false) != nil || deviceCleanupResult(1, empty, false) != nil {
		t.Fatal("success/empty rejected")
	}
	for _, raw := range []string{"", "Operation not permitted", empty + "Netlink error", strings.Repeat("x", 2048)} {
		if deviceCleanupResult(1, raw, false) == nil {
			t.Fatal("operational failure accepted as empty")
		}
	}
	d := &deviceDiagnostics{}
	d.Write([]byte(empty + strings.Repeat(" ", 2048) + "operational error"))
	if !d.truncated || len(d.text) > 1024 {
		t.Fatal("native diagnostics are not bounded")
	}
	if deviceCleanupResult(1, empty, true) == nil || deviceCleanupResult(2, empty, false) == nil {
		t.Fatal("timeout/usage failure ignored")
	}
}
