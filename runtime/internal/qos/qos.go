// Package qos keeps CAKE on the AmneziaWG tunnel interface: per-flow fair
// queueing inside the tunnel, so a bulk download or upload cannot add queueing
// delay to game packets (docs/MAX-PACKAGE.md, router blueprint). CAKE only
// helps when the shaped rate is slightly below the real bottleneck, so the
// owner sets the rates; with both rates zero nothing is installed.
package qos

import (
	"fmt"
	"strings"
)

// Config is the owner's tunnel queueing setting. Rates are in kbit/s; zero
// leaves that direction unshaped.
type Config struct {
	Enabled      bool `json:"enabled"`
	UploadKbit   int  `json:"upload_kbit"`
	DownloadKbit int  `json:"download_kbit"`
}

const (
	Device  = "flr_awg"
	IFB     = "flr_ifb"
	minKbit = 1000
	maxKbit = 10000000
)

func (c Config) Validate() error {
	for _, r := range []int{c.UploadKbit, c.DownloadKbit} {
		if r != 0 && (r < minKbit || r > maxKbit) {
			return fmt.Errorf("tunnel queueing rate must be 0 or %d-%d kbit/s", minKbit, maxKbit)
		}
	}
	if c.Enabled && c.UploadKbit == 0 && c.DownloadKbit == 0 {
		return fmt.Errorf("tunnel queueing needs an upload or download rate")
	}
	return nil
}

// Runner runs one command and returns its output.
type Runner func(name string, args ...string) ([]byte, error)

// Manager installs and removes FLR's own qdiscs. It never touches qdiscs it
// did not install (the cake root on flr_awg is recognised by its kind and the
// ingress redirect by FLR's own ifb device).
type Manager struct {
	Run     Runner
	applied Config
	owned   bool
}

func cakeArgs(dev string, kbit int, ingress bool) []string {
	args := []string{"qdisc", "replace", "dev", dev, "root", "cake", "bandwidth", fmt.Sprintf("%dkbit", kbit), "besteffort", "triple-isolate", "nat"}
	if ingress {
		args = append(args, "ingress")
	}
	return args
}

// Plan lists the commands that install c on a fresh tunnel interface.
func Plan(c Config) [][]string {
	var cmds [][]string
	if c.UploadKbit > 0 {
		cmds = append(cmds, append([]string{"tc"}, cakeArgs(Device, c.UploadKbit, false)...))
	}
	if c.DownloadKbit > 0 {
		cmds = append(cmds,
			[]string{"ip", "link", "add", "name", IFB, "type", "ifb"},
			[]string{"ip", "link", "set", IFB, "up"},
			[]string{"tc", "qdisc", "replace", "dev", Device, "handle", "ffff:", "ingress"},
			[]string{"tc", "filter", "replace", "dev", Device, "parent", "ffff:", "protocol", "all", "prio", "10", "u32", "match", "u32", "0", "0", "action", "mirred", "egress", "redirect", "dev", IFB},
			append([]string{"tc"}, cakeArgs(IFB, c.DownloadKbit, true)...),
		)
	}
	return cmds
}

// present reports whether the interface carries the cake root with the rate
// of c (and the ingress redirect when a download rate is set).
func (m *Manager) present(c Config) bool {
	out, e := m.Run("tc", "qdisc", "show", "dev", Device)
	if e != nil {
		return false
	}
	text := string(out)
	if c.UploadKbit > 0 && !strings.Contains(text, "qdisc cake") {
		return false
	}
	if c.DownloadKbit > 0 {
		if !strings.Contains(text, "qdisc ingress ffff:") {
			return false
		}
		ifb, e := m.Run("tc", "qdisc", "show", "dev", IFB)
		if e != nil || !strings.Contains(string(ifb), "qdisc cake") {
			return false
		}
	}
	return true
}

// Reconcile installs c when the tunnel interface lost it (netifd recreates
// flr_awg on reconnects) or when c changed, and removes FLR's qdiscs when
// queueing is turned off. tunnelUp false means the interface is absent; then
// nothing is done and the next call reinstalls.
func (m *Manager) Reconcile(c Config, tunnelUp bool) error {
	if !c.Enabled {
		if m.owned {
			if e := m.remove(tunnelUp); e != nil {
				return e
			}
			m.owned, m.applied = false, Config{}
		}
		return nil
	}
	if e := c.Validate(); e != nil {
		return e
	}
	if !tunnelUp {
		return nil
	}
	if m.owned && m.applied == c && m.present(c) {
		return nil
	}
	if m.owned && m.applied != c {
		if e := m.remove(true); e != nil {
			return e
		}
	}
	for _, cmd := range Plan(c) {
		out, e := m.Run(cmd[0], cmd[1:]...)
		if e != nil {
			// An existing ifb device from an earlier round is fine.
			if cmd[0] == "ip" && cmd[2] == "add" && strings.Contains(string(out), "File exists") {
				continue
			}
			m.owned = true
			return fmt.Errorf("tunnel queueing not applied: %s: %v", strings.Join(cmd, " "), e)
		}
	}
	m.owned, m.applied = true, c
	return nil
}

// absent reports a tc/ip error that only says the object is already gone.
func absent(out []byte) bool {
	text := string(out)
	for _, s := range []string{"Cannot find device", "No such file", "Invalid handle", "Cannot delete qdisc with handle of zero", "does not exist"} {
		if strings.Contains(text, s) {
			return true
		}
	}
	return false
}

// remove deletes FLR's qdiscs: the ingress redirect before the ifb device it
// points at, so a failure can never leave a redirect into nothing. Ownership
// is kept (and the removal retried) until every step succeeded or found the
// object already gone. With the tunnel interface absent its qdiscs are gone
// with it; only the ifb device is removed.
func (m *Manager) remove(tunnelUp bool) error {
	run := func(args ...string) error {
		out, e := m.Run(args[0], args[1:]...)
		if e != nil && !absent(out) {
			return fmt.Errorf("tunnel queueing not removed: %s: %v", strings.Join(args, " "), e)
		}
		return nil
	}
	if tunnelUp {
		if out, e := m.Run("tc", "qdisc", "show", "dev", Device); e == nil && strings.Contains(string(out), "qdisc cake") {
			if e := run("tc", "qdisc", "del", "dev", Device, "root"); e != nil {
				return e
			}
		}
		if e := run("tc", "qdisc", "del", "dev", Device, "ingress"); e != nil {
			return e
		}
	}
	return run("ip", "link", "del", IFB)
}
