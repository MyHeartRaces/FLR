package dataplane

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/native"
)

type Rule struct {
	Priority int
	Table    int
	Mark     uint32
	Mask     uint32
}
type Route struct {
	Destination string
	Table       int
	Device      string
	Unreachable bool
	Metric      int
}
type Snapshot struct {
	Rules           []Rule
	Routes          []Route
	Own             bool
	TableExists     bool
	BootTableExists bool
}

const (
	firstRouteTable    = 770
	terminalClassTable = 773
	lastRouteTable     = 774
)

var ownedRouteDevices = map[int]string{
	contract.Table(contract.AWG):        "flr_awg",
	contract.Table(contract.Gecko):      "flr-hy",
	contract.Table(contract.VLESS):      "flr-vless",
	contract.Table(contract.Continuity): contract.ContinuityDevice,
}

var channelPriorities = map[contract.Channel]int{
	contract.AWG:        1770,
	contract.Gecko:      1771,
	contract.VLESS:      1772,
	contract.Continuity: 1773,
}

var terminalClassRules = [...]Rule{
	{Priority: 1780, Table: terminalClassTable, Mark: contract.ClassMark(contract.General), Mask: contract.ClassMask},
	{Priority: 1781, Table: terminalClassTable, Mark: contract.ClassMark(contract.Games), Mask: contract.ClassMask},
}

func channelRule(channel contract.Channel) Rule {
	return Rule{Priority: channelPriorities[channel], Table: contract.Table(channel), Mark: contract.ChannelMark(channel), Mask: contract.ChannelMask}
}

func reservedRule(priority int) (Rule, bool) {
	for channel, reserved := range channelPriorities {
		if priority == reserved {
			return channelRule(channel), true
		}
	}
	for _, rule := range terminalClassRules {
		if priority == rule.Priority {
			return rule, true
		}
	}
	return Rule{}, false
}

func Preflight(s Snapshot) error {
	for _, r := range s.Rules {
		expected, reserved := reservedRule(r.Priority)
		if (reserved || r.Mask&contract.OwnedMask != 0) && !s.Own {
			return fmt.Errorf("conflicting rule priority %d", r.Priority)
		}
		if s.Own && (reserved || r.Mask&contract.OwnedMask != 0) {
			if !reserved || r != expected {
				return fmt.Errorf("owned state conflicts with rule priority %d", r.Priority)
			}
		}
	}
	for _, r := range s.Routes {
		if r.Table < firstRouteTable || r.Table > lastRouteTable {
			continue
		}
		if !s.Own {
			return fmt.Errorf("route table %d already used", r.Table)
		}
		if r.Destination != "" && r.Destination != "default" {
			return fmt.Errorf("foreign prefix in owned table %d", r.Table)
		}
		dev := ownedRouteDevices[r.Table]
		if !(r.Unreachable && r.Metric == 32767) && !(r.Device != "" && r.Device == dev && r.Metric == 100) {
			return fmt.Errorf("foreign route in owned table %d", r.Table)
		}
	}
	if s.TableExists && !s.Own {
		return fmt.Errorf("nft table flr already owned by another runtime")
	}
	return nil
}

func runInput(input string, name string, args ...string) error {
	return native.Run(input, name, args...)
}
func Nft(batch string) error                             { return runInput(batch, "nft", "-f", "-") }
func Run(name string, args ...string) error              { return runInput("", name, args...) }
func output(name string, args ...string) ([]byte, error) { return native.Output(name, args...) }

func CurrentSnapshot() (Snapshot, error) { return currentSnapshotWith(output) }

func currentSnapshotWith(output func(string, ...string) ([]byte, error)) (Snapshot, error) {
	s := Snapshot{}
	stamp, e := os.ReadFile("/var/run/flr-runtime/owner.json")
	s.Own = e == nil && strings.Contains(string(stamp), `"owner":"tracegate-flr-v1"`)
	tables, e := output("nft", "list", "tables")
	if e != nil {
		return s, e
	}
	for _, line := range strings.Split(string(tables), "\n") {
		if strings.TrimSpace(line) == "table inet flr" {
			s.TableExists = true
		}
		if strings.TrimSpace(line) == "table inet flr_boot" {
			s.BootTableExists = true
		}
	}
	b, e := output("ip", "-j", "-4", "rule", "show")
	if e != nil {
		return s, e
	}
	var rules []map[string]any
	if e = json.Unmarshal(b, &rules); e != nil {
		return s, e
	}
	for _, r := range rules {
		n := func(key string) uint32 {
			switch v := r[key].(type) {
			case float64:
				return uint32(v)
			case string:
				i, _ := strconv.ParseUint(v, 0, 32)
				return uint32(i)
			}
			return 0
		}
		s.Rules = append(s.Rules, Rule{Priority: int(n("priority")), Table: int(n("table")), Mark: n("fwmark"), Mask: n("fwmask")})
	}
	for table := firstRouteTable; table <= lastRouteTable; table++ {
		b, e = output("ip", "-j", "-4", "route", "show", "table", strconv.Itoa(table))
		if e != nil {
			if native.Interrupted(e) {
				return s, e
			}
			continue
		}
		var rs []map[string]any
		if e = json.Unmarshal(b, &rs); e != nil {
			return s, e
		}
		for _, r := range rs {
			dev, _ := r["dev"].(string)
			metric, _ := r["metric"].(float64)
			kind, _ := r["type"].(string)
			s.Routes = append(s.Routes, Route{Table: table, Destination: fmt.Sprint(r["dst"]), Device: dev, Metric: int(metric), Unreachable: kind == "unreachable"})
		}
	}
	return s, nil
}

func Apply(b Batch) error {
	snap, e := CurrentSnapshot()
	if e != nil {
		return e
	}
	if e = Preflight(snap); e != nil {
		return e
	}
	if e := runInput(b.Nft, "nft", "-c", "-f", "-"); e != nil {
		return e
	}
	if e := os.MkdirAll("/var/run/flr-runtime", 0700); e != nil {
		return e
	}
	data, _ := json.Marshal(map[string]any{"owner": "tracegate-flr-v1", "options": b.Options})
	if e := os.WriteFile("/var/run/flr-runtime/owner.json", data, 0600); e != nil {
		return e
	}
	// Terminal routes precede classification. The nft guard precedes new rules: partial apply fails closed.
	for _, r := range b.Routes {
		if r.Unreachable {
			if e := Run("ip", "-4", "route", "replace", "unreachable", "default", "metric", strconv.Itoa(r.Metric), "table", strconv.Itoa(r.Table)); e != nil {
				return e
			}
		}
	}
	for _, r := range b.Routes {
		if !r.Unreachable {
			if _, e := output("ip", "link", "show", "dev", r.Device); e == nil {
				if e = Run("ip", "-4", "route", "replace", "default", "dev", r.Device, "metric", strconv.Itoa(r.Metric), "table", strconv.Itoa(r.Table)); e != nil {
					return e
				}
			} else if native.Interrupted(e) {
				return e
			}
		}
	}
	if e := runInput(b.Nft, "nft", "-f", "-"); e != nil {
		return e
	}
	for _, r := range b.Rules {
		exists := false
		for _, old := range snap.Rules {
			if old == r {
				exists = true
			}
		}
		if exists {
			continue
		}
		if e := Run("ip", "-4", "rule", "add", "pref", strconv.Itoa(r.Priority), "fwmark", fmt.Sprintf("%#x/%#x", r.Mark, r.Mask), "lookup", strconv.Itoa(r.Table)); e != nil {
			return e
		}
	}
	if !b.Options.Continuity {
		// Remove the stable lookup only after its old flows can fall through
		// to the protected classes' terminal route and the new WAN guard.
		return retireContinuityRoutes(snap, Run)
	}
	return nil
}

func retireContinuityRoutes(snap Snapshot, run func(string, ...string) error) error {
	owned := channelRule(contract.Continuity)
	table := strconv.Itoa(owned.Table)
	for _, rule := range snap.Rules {
		if rule != owned {
			continue
		}
		if err := run("ip", "-4", "rule", "del", "pref", strconv.Itoa(rule.Priority), "fwmark", fmt.Sprintf("%#x/%#x", rule.Mark, rule.Mask), "lookup", table); err != nil {
			return err
		}
	}
	for _, route := range snap.Routes {
		if route.Table == owned.Table {
			return run("ip", "-4", "route", "flush", "table", table)
		}
	}
	return nil
}

// Rollback stops autostart, then uses the same checked, retryable restoration
// path as deactivation. Native cleanup failures must reach the timer owner.
func Rollback(backupDir string) error {
	return rollbackWith(backupDir, nativeDeactivationOps())
}

func EnsureRoutes() error { return EnsureRoutesContext(context.Background()) }
func EnsureRoutesContext(ctx context.Context) error {
	out := func(name string, args ...string) ([]byte, error) {
		result := native.Execute(ctx, native.Limit(name), "", name, args...)
		return result.Stdout, result.Err
	}
	snap, e := currentSnapshotWith(out)
	if e != nil {
		return e
	}
	return ensureRoutesWith(snap, out, func(name string, args ...string) error { _, e := out(name, args...); return e })
}
func ensureRoutesWith(snap Snapshot, output func(string, ...string) ([]byte, error), run func(string, ...string) error) error {
	var e error
	if !snap.Own {
		return fmt.Errorf("runtime does not own routing")
	}
	if e = Preflight(snap); e != nil {
		return e
	}
	for _, ch := range []contract.Channel{contract.AWG, contract.Gecko, contract.VLESS, contract.Continuity} {
		if ch == contract.Continuity && !slices.Contains(snap.Rules, channelRule(ch)) {
			continue
		}
		table := contract.Table(ch)
		dev := ownedRouteDevices[table]
		found := false
		for _, r := range snap.Routes {
			if r.Table == table && r.Device == dev && r.Metric == 100 {
				found = true
			}
		}
		if found {
			continue
		}
		if _, e = output("ip", "link", "show", "dev", dev); e == nil {
			if e = run("ip", "-4", "route", "replace", "default", "dev", dev, "metric", "100", "table", strconv.Itoa(table)); e != nil {
				return e
			}
		} else if native.Interrupted(e) {
			return e
		}
	}
	return nil
}

// Deactivate restores validated pre-FLR configuration while leaving the
// controller API alive. The ownership stamp is retained through all fallible
// restore/reload work so an interrupted transition can be retried.
func Deactivate(backupDir string) error { return deactivateWith(backupDir, nativeDeactivationOps()) }
