package bypass

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
)

func TestBoundedConfigAndDisabledDefault(t *testing.T) {
	if e := (Config{}).Validate(); e != nil {
		t.Fatal(e)
	}
	for _, c := range []Config{{Enabled: true}, {Enabled: true, TCP: "--lua-init=@/tmp/x"}, {TCP: "fake", QUIC: "command"}} {
		if c.Validate() == nil {
			t.Fatalf("accepted unsafe config: %+v", c)
		}
	}
	if LoopMark&(contract.OwnedMask|0x00400000) != 0 {
		t.Fatal("loop mark overlaps FLR ownership")
	}
	if s, e := Rules(Config{}, "eth1"); e != nil || s != "" {
		t.Fatal("disabled config installs queue", s, e)
	}
}
func TestDirectOnlyBoundedRules(t *testing.T) {
	rules, e := Rules(Config{Enabled: true, TCP: "fake", QUIC: "fake"}, "eth1")
	if e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"oifname != \"eth1\" return", "oifname != \"eth1\" drop", "0xff800000 == 0x03000000", "0xffc00000 == 0x80400000", "ct original packets <= 6", "0x00010000", "queue num 206", "0x80010000", "ct state new", "@fresh_tcp", "@fresh_udp", "timeout 10s"} {
		if !strings.Contains(rules, want) {
			t.Fatal("missing guard", want)
		}
	}
	if strings.Index(rules, "oifname != \"eth1\" return") > strings.Index(rules, "queue num 206") {
		t.Fatal("queue precedes WAN exclusion")
	}
	if _, e := Rules(Config{Enabled: true, TCP: "fake"}, "eth1\";drop"); e == nil {
		t.Fatal("WAN injection accepted")
	}
}
func TestNativeArgumentsCannotContainUserPaths(t *testing.T) {
	args, e := Arguments(Config{Enabled: true, TCP: "fake", QUIC: "fake"})
	if e != nil {
		t.Fatal(e)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{"--bind-fix4", "--fwmark=0x00010000", "--filter-tcp=443", "--filter-udp=443", "--lua-init=@/usr/share/flr-bypass/lua/zapret-lib.lua"} {
		if !strings.Contains(joined, want) {
			t.Fatal("missing argument", want)
		}
	}
}

func TestNoQueuesUntilNativeDryRunAndOwnedCleanup(t *testing.T) {
	var calls []string
	m := &Manager{accounting: func() bool { return true }, runner: func(_ context.Context, input, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " ")+" "+input)
		if name == "/usr/bin/nfqws2" {
			return nil, fmt.Errorf("invalid native config")
		}
		return nil, nil
	}}
	if e := m.Reconcile(context.Background(), Config{}, "eth1"); e != nil {
		t.Fatal(e)
	}
	if len(calls) != 1 || strings.Contains(calls[0], "queue") {
		t.Fatal("disabled config installed queues", calls)
	}
	calls = nil
	if e := m.Reconcile(context.Background(), Config{Enabled: true, TCP: "fake"}, "eth1"); e == nil {
		t.Fatal("native validation failure ignored")
	}
	for _, call := range calls {
		if strings.Contains(call, "-f -") {
			t.Fatal("queue effect before valid native config", call)
		}
	}
	m.runner = func(_ context.Context, input, name string, args ...string) ([]byte, error) {
		if strings.Join(args, " ") == "list tables" {
			return []byte("table ip flr_bypass"), nil
		}
		if strings.Join(args, " ") == "list table ip flr_bypass" {
			return []byte(`table ip flr_bypass { comment "foreign"; }`), nil
		}
		t.Fatal("foreign table modified")
		return nil, nil
	}
	if m.Stop(context.Background()) == nil {
		t.Fatal("foreign table ownership accepted")
	}
}

func TestNativeLoopMaskAllowsOriginalDirectPackets(t *testing.T) {
	args, e := Arguments(Config{Enabled: true, TCP: "fake", QUIC: "fake"})
	if e != nil {
		t.Fatal(e)
	}
	var mark uint64
	for _, arg := range args {
		if strings.HasPrefix(arg, "--fwmark=") {
			mark, e = strconv.ParseUint(strings.TrimPrefix(arg, "--fwmark="), 0, 32)
			if e != nil {
				t.Fatal(e)
			}
		}
	}
	if mark != uint64(LoopMark) {
		t.Fatal("native ignore mask must be only the reserved low loop bit")
	}
	// Pinned nfqws2 skips packets when ANY configured fwmark bit matches.
	for _, original := range []uint64{0x03000000, 0x80400000} {
		if original&mark != 0 {
			t.Fatal("native ignore mask skips original direct traffic", original)
		}
	}
	if 0x80010000&mark == 0 {
		t.Fatal("generated packets can reenter native handling")
	}
	rules, e := Rules(Config{Enabled: true, TCP: "fake"}, "eth1")
	if e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"type route hook output priority -152", "meta mark & 0x00010000 != 0 meta mark set 0x80010000", "type filter hook output priority -5", "meta mark & 0xffff0000 == 0x80010000 oifname != \"eth1\" drop"} {
		if !strings.Contains(rules, want) {
			t.Fatal("missing controlled fake WAN promotion or final guard", want)
		}
	}
}
