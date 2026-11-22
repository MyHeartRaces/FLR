package config

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/MyHeartRaces/FLR/runtime/internal/native"
)

const (
	testPolicyDNS = `config dnsmasq
	option port '1053'
	option noresolv '1'
	option domain 'example.com'
config dhcp 'lan'
	list dhcp_option '6,192.0.2.1'
	list dhcp_option '42,192.0.2.2'
`
	testNativeDNS = `config dnsmasq
	option noresolv '1'
	list server '203.0.113.1'
	list server '/example.com/203.0.113.2#5353'
config dhcp 'lan'
	list dhcp_option '6,203.0.113.3'
`
)

func TestRoutingDNSChangesOnlyOwnedOptions(t *testing.T) {
	d := newRoutingDNSTest(t, testPolicyDNS, testNativeDNS)
	d.afterCommit = strings.Replace(testPolicyDNS, "\toption port '1053'\n", "\tlist server '203.0.113.1'\n\tlist server '/example.com/203.0.113.2#5353'\n", 1)
	if err := d.set(true); err != nil {
		t.Fatal(err)
	}
	want := []string{"delete .@dnsmasq[0].port", "add_list .@dnsmasq[0].server=203.0.113.1", "add_list .@dnsmasq[0].server=/example.com/203.0.113.2#5353"}
	if !reflect.DeepEqual(d.mutations, want) || d.restarts != 1 {
		t.Fatalf("mutations %v, restarts %d", d.mutations, d.restarts)
	}
	d.mutations, d.afterCommit = nil, testPolicyDNS
	if err := d.set(false); err != nil {
		t.Fatal(err)
	}
	want = []string{"set .@dnsmasq[0].port=1053", "delete .@dnsmasq[0].server"}
	if !reflect.DeepEqual(d.mutations, want) || d.restarts != 2 {
		t.Fatalf("mutations %v, restarts %d", d.mutations, d.restarts)
	}
}

func TestRoutingDNSRejectsUnownedOrUnusableSettings(t *testing.T) {
	for _, tc := range []struct {
		name, current, saved, staged string
	}{
		{"foreign settings", strings.Replace(testPolicyDNS, "'1053'", "'5300'", 1), testNativeDNS, ""},
		{"different primary section", strings.Replace(testPolicyDNS, "config dnsmasq", "config dnsmasq 'guest'", 1), testNativeDNS, ""},
		{"no DNS in backup", testPolicyDNS, "config dhcp 'lan'\n", ""},
		{"nonstandard native port", testPolicyDNS, strings.Replace(testNativeDNS, "config dnsmasq\n", "config dnsmasq\n\toption port '5353'\n", 1), ""},
		{"pending UCI edits", testPolicyDNS, testNativeDNS, "dhcp.lan.leasetime='1h'\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newRoutingDNSTest(t, tc.current, tc.saved)
			d.staged = tc.staged
			if err := d.set(true); err == nil || len(d.mutations) != 0 || d.commits != 0 || d.restarts != 0 {
				t.Fatalf("transition crossed its validation boundary: %v %#v", err, d)
			}
		})
	}
}

func TestRoutingDNSRetriesRestartAfterCommit(t *testing.T) {
	d := newRoutingDNSTest(t, testPolicyDNS, testNativeDNS)
	d.afterCommit, d.restartError = testNativeDNS, errors.New("restart interrupted")
	if err := d.set(true); err == nil || d.commits != 1 || d.restarts != 1 {
		t.Fatalf("commit and restart failure: %v, commits %d, restarts %d", err, d.commits, d.restarts)
	}
	d.restartError = nil
	if err := d.set(true); err != nil || d.commits != 1 || d.restarts != 2 {
		t.Fatalf("restart retry: %v, commits %d, restarts %d", err, d.commits, d.restarts)
	}
	if err := d.set(true); err != nil || d.commits != 1 || d.restarts != 2 {
		t.Fatalf("clean Direct cold start: %v, commits %d, restarts %d", err, d.commits, d.restarts)
	}
}

func TestRoutingDNSColdStartAcceptsExistingPolicyWithoutBackup(t *testing.T) {
	d := newRoutingDNSTest(t, testPolicyDNS, "")
	if err := d.set(false); err != nil || d.commits != 0 || d.restarts != 0 {
		t.Fatalf("protected cold start: %v, commits %d, restarts %d", err, d.commits, d.restarts)
	}
}

func TestNativeDNSPreflightDoesNotChangeTheResolver(t *testing.T) {
	d := newRoutingDNSTest(t, testPolicyDNS, testNativeDNS)
	if err := routingDNS(true, true, d.live, d.backup, d.pending, d.command); err != nil {
		t.Fatal(err)
	}
	if len(d.mutations) != 0 || d.commits != 0 || d.restarts != 0 {
		t.Fatal("native DNS preflight changed router configuration")
	}
	d.staged = "dhcp.lan.ignore=1"
	if err := routingDNS(true, true, d.live, d.backup, d.pending, d.command); err == nil {
		t.Fatal("preflight accepted staged DHCP changes")
	}
}

func TestRoutingDNSStopsBeforeCommitIfLiveDNSChanges(t *testing.T) {
	d := newRoutingDNSTest(t, testPolicyDNS, testNativeDNS)
	d.changedWhileStaging = strings.Replace(testPolicyDNS, "'1053'", "'5300'", 1)
	if err := d.set(true); err == nil || d.commits != 0 || d.restarts != 0 {
		t.Fatalf("transition overwrote a concurrent DNS edit: %v, commits %d, restarts %d", err, d.commits, d.restarts)
	}
}

func TestRoutingDNSNativeUCI(t *testing.T) {
	if _, err := exec.LookPath("uci"); err != nil {
		t.Skip("OpenWrt uci is unavailable")
	}
	d := newRoutingDNSTest(t, testPolicyDNS+"config dnsmasq 'guest'\n\toption port '5353'\n", testNativeDNS)
	command := func(name string, args ...string) ([]byte, error) {
		if name == "/etc/init.d/dnsmasq" || reflect.DeepEqual(args, []string{"-s", "changes", "dhcp"}) {
			return d.command(name, args...)
		}
		return native.Output(name, args...)
	}
	if err := setRoutingDNS(true, d.live, d.backup, d.pending, command); err != nil {
		t.Fatal(err)
	}
	current := func() string {
		t.Helper()
		out, err := os.ReadFile(d.live)
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	active := current()
	for _, value := range []string{"list server '203.0.113.1'", "list server '/example.com/203.0.113.2#5353'", "list dhcp_option '6,192.0.2.1'", "list dhcp_option '42,192.0.2.2'", "config dnsmasq 'guest'\n\toption port '5353'"} {
		if !strings.Contains(active, value) {
			t.Fatalf("lost fixture value %q", value)
		}
	}
	if err := setRoutingDNS(false, d.live, d.backup, d.pending, command); err != nil {
		t.Fatal(err)
	}
	if got := current(); !strings.Contains(got, "option port '1053'") || strings.Contains(got, "list server") || d.restarts != 2 {
		t.Fatalf("could not recover protected DNS\n%s", got)
	}
}

type routingDNSTest struct {
	live, backup, pending       string
	current, saved, afterCommit string
	staged                      string
	changedWhileStaging         string
	restartError                error
	mutations                   []string
	commits, restarts           int
}

func newRoutingDNSTest(t *testing.T, current, saved string) *routingDNSTest {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	d := &routingDNSTest{live: filepath.Join(dir, "dhcp"), backup: filepath.Join(dir, "backup-dhcp"), pending: filepath.Join(dir, "restart.pending"), current: current, saved: saved}
	if err := os.WriteFile(d.live, []byte(current), 0600); err != nil {
		t.Fatal(err)
	}
	if saved != "" {
		if err := os.WriteFile(d.backup, []byte(saved), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func (d *routingDNSTest) set(direct bool) error {
	return setRoutingDNS(direct, d.live, d.backup, d.pending, d.command)
}

func (d *routingDNSTest) command(name string, args ...string) ([]byte, error) {
	if name == "/etc/init.d/dnsmasq" && reflect.DeepEqual(args, []string{"restart"}) {
		d.restarts++
		return nil, d.restartError
	}
	if name != "uci" {
		return nil, errors.New("unexpected command")
	}
	if reflect.DeepEqual(args, []string{"-s", "changes", "dhcp"}) {
		return []byte(d.staged), nil
	}
	if len(args) != 10 || args[0] != "-s" || args[1] != "-N" || args[2] != "-c" || args[4] != "-C" || args[6] != "-t" {
		return nil, errors.New("UCI operation lacked an isolated context")
	}
	verb, arg := args[8], args[9]
	pkg, option, _ := strings.Cut(arg, ".")
	target, err := os.Readlink(filepath.Join(args[3], pkg))
	if err != nil {
		return nil, err
	}
	switch verb {
	case "export":
		if target == d.backup {
			return []byte("package " + pkg + "\n" + d.saved), nil
		}
		return []byte("package " + pkg + "\n" + d.current), nil
	case "delete", "set", "add_list":
		if target != d.live {
			return nil, errors.New("mutation addressed wrong configuration file")
		}
		d.mutations = append(d.mutations, verb+" ."+option)
		if d.changedWhileStaging != "" {
			d.current = d.changedWhileStaging
		}
	case "commit":
		if _, err := os.Stat(d.pending); err != nil || target != d.live {
			return nil, errors.New("commit lacks owned restart marker or wrong target")
		}
		d.commits++
		d.current = d.afterCommit
	default:
		return nil, errors.New("unexpected UCI command")
	}
	return nil, nil
}
