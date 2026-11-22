package dataplane

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/MyHeartRaces/FLR/runtime/internal/rollbackintent"
)

type deactivationOps struct {
	snapshot     func() (Snapshot, error)
	checkBoot    func() error
	run          func(string, ...string) error
	read         func(string) ([]byte, error)
	write        func(string, []byte) error
	remove       func(string) error
	disableState func() error
}

func nativeDeactivationOps() deactivationOps {
	return deactivationOps{
		snapshot:     CurrentSnapshot,
		checkBoot:    CheckBootOwnership,
		run:          Run,
		read:         os.ReadFile,
		write:        func(path string, b []byte) error { return os.WriteFile(path, b, 0600) },
		remove:       os.Remove,
		disableState: func() error { return rollbackintent.Mark("/etc/flr-runtime") },
	}
}

func deactivateWith(backupDir string, ops deactivationOps) error {
	if e := ValidateBackup(backupDir); e != nil {
		return e
	}
	snap, e := ops.snapshot()
	if e != nil {
		return e
	}
	if e = Preflight(snap); e != nil {
		return e
	}
	if e = ops.checkBoot(); e != nil {
		return e
	}
	if snap.Own {
		if snap.TableExists {
			if e = ops.run("nft", "delete", "table", "inet", "flr"); e != nil {
				return e
			}
		}
		// A fresh snapshot bounds deletion to still-present owned objects. A
		// retry after a successful partial delete skips the absent object.
		for _, rule := range snap.Rules {
			if _, reserved := reservedRule(rule.Priority); reserved {
				if e = ops.run("ip", "-4", "rule", "del", "pref", strconv.Itoa(rule.Priority)); e != nil {
					return e
				}
			}
		}
		tables := map[int]bool{}
		for _, route := range snap.Routes {
			if route.Table >= firstRouteTable && route.Table <= lastRouteTable {
				tables[route.Table] = true
			}
		}
		for table := firstRouteTable; table <= lastRouteTable; table++ {
			if tables[table] {
				if e = ops.run("ip", "-4", "route", "flush", "table", strconv.Itoa(table)); e != nil {
					return e
				}
			}
		}
	}
	ownedBootGuard := false
	if b, readErr := ops.read("/etc/flr-runtime/boot-guard.nft"); readErr == nil {
		ownedBootGuard = strings.HasPrefix(string(b), "# tracegate-flr-v1\n")
	} else if !os.IsNotExist(readErr) {
		return readErr
	}

	for _, name := range []string{"network", "firewall", "dhcp"} {
		b, e := ops.read(filepath.Join(backupDir, name))
		if e != nil {
			return e
		}
		if e = ops.write(filepath.Join("/etc/config", name), b); e != nil {
			return e
		}
	}
	if e = ops.run("ubus", "call", "network", "reload"); e != nil {
		return e
	}
	if e = ops.run("/etc/init.d/firewall", "restart"); e != nil {
		return e
	}
	if e = ops.run("/etc/init.d/dnsmasq", "restart"); e != nil {
		return e
	}
	// Keep the boot kill guard through every fallible restore and reload.
	if ownedBootGuard && snap.BootTableExists {
		if e = ops.run("nft", "delete", "table", "inet", "flr_boot"); e != nil {
			return e
		}
	}
	// Native state is restored. Remove the source guard and pending token
	// idempotently, then remove ownership last as the completion checkpoint.
	remove := func(path string) error {
		e := ops.remove(path)
		if os.IsNotExist(e) {
			return nil
		}
		return e
	}
	if ownedBootGuard {
		if e = remove("/etc/flr-runtime/boot-guard.nft"); e != nil {
			return e
		}
	}
	if e = remove("/etc/flr-runtime/rollback.pending"); e != nil {
		return e
	}
	return remove("/var/run/flr-runtime/owner.json")
}

func rollbackWith(backupDir string, ops deactivationOps) error {
	return rollbackLifecycleWith(backupDir, ops, false)
}

// start_service owns procd's runtime lock. It has not launched the controller;
// calling that init script recursively would deadlock. The caller disables its
// own autostart links after successful recovery.
func RecoverAtStartup(backupDir string) error {
	return rollbackLifecycleWith(backupDir, nativeDeactivationOps(), true)
}
func rollbackLifecycleWith(backupDir string, ops deactivationOps, startup bool) error {
	if e := ValidateBackup(backupDir); e != nil {
		return e
	}
	snap, e := ops.snapshot()
	if e != nil {
		return e
	}
	if e = Preflight(snap); e != nil {
		return e
	}
	if e = ops.checkBoot(); e != nil {
		return e
	}
	for _, service := range []string{"/etc/init.d/flr-runtime", "/etc/init.d/flr-proxies"} {
		if startup && service == "/etc/init.d/flr-runtime" {
			continue
		}
		for _, action := range []string{"stop", "disable"} {
			if e = ops.run(service, action); e != nil {
				return e
			}
		}
	}
	// Keep settings/registry and both checkpoint families coherent. The next
	// settings read disables them only after checkpoint recovery completes.
	if e = ops.disableState(); e != nil {
		return e
	}
	for _, name := range []string{"manual-games.json", "direct-session.json"} {
		if e = ops.remove(filepath.Join("/etc/flr-runtime", name)); e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	return deactivateWith(backupDir, ops)
}
