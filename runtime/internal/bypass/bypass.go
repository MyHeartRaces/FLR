// Package bypass owns an optional, disabled-by-default direct IPv4 experiment.
// Presets are deliberately fixed; this is never a command or Lua input API.
package bypass

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const LoopMark uint32 = 0x00010000
const owner = "tracegate-flr-bypass-v1"

type Config struct {
	Enabled bool   `json:"enabled"`
	TCP     string `json:"tcp"`
	QUIC    string `json:"quic"`
}

func (c Config) Validate() error {
	for _, p := range []string{c.TCP, c.QUIC} {
		if p != "" && p != "off" && p != "fake" {
			return fmt.Errorf("bypass profile must be off or fake")
		}
	}
	if c.Enabled && c.TCP != "fake" && c.QUIC != "fake" {
		return fmt.Errorf("enabled bypass needs an explicit TCP or QUIC preset")
	}
	return nil
}
func Arguments(c Config) ([]string, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	a := []string{"--qnum=206", "--bind-fix4", "--fwmark=0x00010000"}
	for _, n := range []string{"zapret-lib", "zapret-antidpi", "zapret-auto"} {
		a = append(a, "--lua-init=@/usr/share/flr-bypass/lua/"+n+".lua")
	}
	if c.TCP == "fake" {
		a = append(a, "--filter-tcp=443", "--payload=tls_client_hello", "--out-range=-d6", "--lua-desync=fake:blob=fake_default_tls:tcp_md5:repeats=2")
	}
	if c.TCP == "fake" && c.QUIC == "fake" {
		a = append(a, "--new")
	}
	if c.QUIC == "fake" {
		a = append(a, "--filter-udp=443", "--payload=quic_initial", "--out-range=-d6", "--lua-desync=fake:blob=fake_default_quic:repeats=2")
	}
	return a, nil
}
func Rules(c Config, wan string) (string, error) {
	if e := c.Validate(); e != nil {
		return "", e
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`).MatchString(wan) {
		return "", fmt.Errorf("invalid bypass WAN")
	}
	if !c.Enabled {
		return "", nil
	}
	var s strings.Builder
	fmt.Fprintf(&s, "table ip flr_bypass {\n comment \"%s\"\n set fresh_tcp { type ipv4_addr . inet_service . ipv4_addr . inet_service; flags dynamic,timeout; timeout 10s; size 4096; }\n set fresh_udp { type ipv4_addr . inet_service . ipv4_addr . inet_service; flags dynamic,timeout; timeout 10s; size 4096; }\n chain fake_route { type route hook output priority -152; policy accept; meta mark & 0x00010000 != 0 meta mark set 0x80010000; }\n chain fake_guard { type filter hook output priority -5; policy accept; meta mark & 0xffff0000 == 0x80010000 oifname != \"%s\" drop; }\n chain direct { type filter hook postrouting priority -149; policy accept;\n meta mark & 0x00010000 != 0 return\n oifname != \"%s\" return\n ct direction reply return\n ct original packets > 6 return\n", owner, wan, wan)
	for _, selector := range []string{"meta mark & 0xff800000 == 0x03000000", "meta mark & 0xffc00000 == 0x80400000"} {
		if c.TCP == "fake" {
			fmt.Fprintf(&s, " %s ct state new tcp flags & (syn|ack) == syn tcp dport 443 add @fresh_tcp { ip saddr . tcp sport . ip daddr . tcp dport }\n %s ct original packets <= 6 tcp dport 443 ip saddr . tcp sport . ip daddr . tcp dport @fresh_tcp queue num 206 bypass\n", selector, selector)
		}
		if c.QUIC == "fake" {
			fmt.Fprintf(&s, " %s ct state new udp dport 443 add @fresh_udp { ip saddr . udp sport . ip daddr . udp dport }\n %s ct original packets <= 6 udp dport 443 ip saddr . udp sport . ip daddr . udp dport @fresh_udp queue num 206 bypass\n", selector, selector)
		}
	}
	s.WriteString(" }\n}\n")
	return s.String(), nil
}

type Manager struct {
	config     Config
	wan        string
	child      *exec.Cmd
	done       chan error
	accounting func() bool
	runner     func(context.Context, string, string, ...string) ([]byte, error)
}

func native(ctx context.Context, input string, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(input)
	return cmd.CombinedOutput()
}
func (m *Manager) run(ctx context.Context, input string, name string, args ...string) ([]byte, error) {
	if m.runner != nil {
		return m.runner(ctx, input, name, args...)
	}
	return native(ctx, input, name, args...)
}

// Cleanup only recognizes our exact table comment, and never kills by name/PID.
func (m *Manager) cleanup(ctx context.Context) error {
	out, e := m.run(ctx, "", "/usr/sbin/nft", "list", "tables")
	if e != nil {
		return fmt.Errorf("bypass nft inventory unavailable")
	}
	if strings.Contains(string(out), "table ip flr_bypass") {
		out, e = m.run(ctx, "", "/usr/sbin/nft", "list", "table", "ip", "flr_bypass")
		if e != nil || !strings.Contains(string(out), `comment "`+owner+`"`) {
			return fmt.Errorf("foreign bypass table exists")
		}
		if _, e = m.run(ctx, "", "/usr/sbin/nft", "delete", "table", "ip", "flr_bypass"); e != nil {
			return fmt.Errorf("bypass table cleanup failed")
		}
	}
	return nil
}
func (m *Manager) Stop(ctx context.Context) error {
	e := m.cleanup(ctx)
	if m.child != nil {
		m.child.Process.Signal(syscall.SIGTERM)
		select {
		case <-m.done:
		case <-time.After(2 * time.Second):
			m.child.Process.Kill()
			<-m.done
		}
		m.child = nil
	}
	return e
}
func (m *Manager) Reconcile(ctx context.Context, c Config, wan string) error {
	if _, e := Rules(c, wan); e != nil {
		return e
	}
	if m.child != nil {
		select {
		case <-m.done:
			m.child = nil
		default:
			if m.config == c && m.wan == wan {
				return nil
			}
		}
	}
	if e := m.Stop(ctx); e != nil {
		return e
	}
	m.config = c
	m.wan = wan
	if !c.Enabled {
		return nil
	}
	accounting := m.accounting
	if accounting == nil {
		accounting = func() bool {
			b, e := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_acct")
			return e == nil && strings.TrimSpace(string(b)) == "1"
		}
	}
	if !accounting() {
		return fmt.Errorf("bypass requires existing conntrack accounting; no global settings changed")
	}
	a, e := Arguments(c)
	if e != nil {
		return e
	}
	// Native parser validation and nft check precede both child and queues.
	if _, e = m.run(ctx, "", "/usr/bin/nfqws2", append(a, "--dry-run")...); e != nil {
		return fmt.Errorf("bypass native dry-run rejected")
	}
	rules, _ := Rules(c, wan)
	if _, e = m.run(ctx, rules, "/usr/sbin/nft", "-c", "-f", "-"); e != nil {
		return fmt.Errorf("bypass nft dry-run rejected")
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/nfqws2", a...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if e = cmd.Start(); e != nil {
		return fmt.Errorf("bypass process unavailable")
	}
	m.child = cmd
	m.done = make(chan error, 1)
	go func() { m.done <- cmd.Wait() }()
	if _, e = m.run(ctx, rules, "/usr/sbin/nft", "-f", "-"); e != nil {
		m.Stop(ctx)
		return fmt.Errorf("bypass queue installation failed")
	}
	return nil
}
