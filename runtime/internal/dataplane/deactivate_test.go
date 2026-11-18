package dataplane

import (
	"context"
	"errors"
	"fmt"
	"github.com/MyHeartRaces/FLR/runtime/internal/native"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDeactivateRetriesPartialNativeFailureAndRetainsRecoveryMarker(t *testing.T) {
	for _, failure := range []string{"rule", "restore", "network", "firewall", "dnsmasq", "stop", "disable", "native-timeout"} {
		t.Run(failure, func(t *testing.T) {
			if failure == "native-timeout" {
				t.Setenv("FLR_BOUNDS_HELPER", "partial-sleep")
				t.Setenv("FLR_BOUNDS_MARKER", filepath.Join(t.TempDir(), "partial-effect"))
			}
			backup := privateBackupDir(t)
			for _, name := range []string{"network", "firewall", "dhcp"} {
				if e := os.WriteFile(filepath.Join(backup, name), []byte("public original "+name), 0600); e != nil {
					t.Fatal(e)
				}
			}
			snapshot := Snapshot{Own: true, TableExists: true, BootTableExists: true, Rules: []Rule{{Priority: 1770, Table: 770, Mark: 0x10000000, Mask: 0x70000000}}, Routes: []Route{{Table: 770, Device: "flr_awg", Metric: 100}}}
			marker, pending, guard := true, true, true
			failed := false
			restored := map[string]string{}
			ops := deactivationOps{
				disableState: func() error { return nil },
				snapshot:     func() (Snapshot, error) { snapshot.Own = marker; return snapshot, nil },
				checkBoot:    func() error { return nil },
				read: func(path string) ([]byte, error) {
					if strings.HasSuffix(path, "boot-guard.nft") {
						if !guard {
							return nil, os.ErrNotExist
						}
						return []byte("# tracegate-flr-v1\n"), nil
					}
					return os.ReadFile(path)
				},
				write: func(path string, data []byte) error {
					if failure == "restore" && !failed {
						failed = true
						return errors.New("public restore failure")
					}
					restored[filepath.Base(path)] = string(data)
					return nil
				},
				remove: func(path string) error {
					switch filepath.Base(path) {
					case "owner.json":
						marker = false
					case "rollback.pending":
						pending = false
					case "boot-guard.nft":
						guard = false
					}
					return nil
				},
				run: func(name string, args ...string) error {
					text := name + " " + strings.Join(args, " ")
					hit := (failure == "stop" && name == "/etc/init.d/flr-runtime" && args[0] == "stop") || (failure == "disable" && name == "/etc/init.d/flr-runtime" && args[0] == "disable") || (failure == "rule" && strings.Contains(text, "rule del")) || (failure == "network" && name == "ubus") || (failure == "firewall" && name == "/etc/init.d/firewall") || (failure == "dnsmasq" && name == "/etc/init.d/dnsmasq")
					if failure == "native-timeout" && name == "ubus" && !failed {
						failed = true
						r := native.Execute(context.Background(), 500*time.Millisecond, "", os.Args[0], "-test.run=^TestNativeBoundsHelper$")
						if !errors.Is(r.Err, context.DeadlineExceeded) {
							t.Fatal("deadline lost", r.Err)
						}
						if b, e := os.ReadFile(os.Getenv("FLR_BOUNDS_MARKER")); e != nil || string(b) != "partial" {
							t.Fatal("helper never applied partial effect", e)
						}
						return r.Err
					}
					if hit && !failed {
						failed = true
						return errors.New("public injected failure")
					}
					if text == "nft delete table inet flr" {
						if !snapshot.TableExists {
							return fmt.Errorf("absent nft table deletion")
						}
						snapshot.TableExists = false
					}
					if text == "nft delete table inet flr_boot" {
						if !snapshot.BootTableExists {
							return fmt.Errorf("absent boot table deletion")
						}
						snapshot.BootTableExists = false
					}
					if strings.Contains(text, "rule del") {
						snapshot.Rules = nil
					}
					if strings.Contains(text, "route flush") {
						snapshot.Routes = nil
					}
					return nil
				},
			}
			restoreOperation := deactivateWith
			if failure == "stop" || failure == "disable" {
				restoreOperation = rollbackWith
			}
			if e := restoreOperation(backup, ops); e == nil {
				t.Fatal("injected native failure was ignored")
			}
			if !marker || !pending || !guard || !snapshot.BootTableExists {
				t.Fatal("failed transition lost recovery marker")
			}
			if e := restoreOperation(backup, ops); e != nil {
				t.Fatalf("partial transition could not retry: %v", e)
			}
			if marker || pending || guard || snapshot.TableExists || snapshot.BootTableExists {
				t.Fatal("successful restoration retained owned policy state")
			}
			if e := restoreOperation(backup, ops); e != nil {
				t.Fatalf("completed transition was not idempotent: %v", e)
			}
			for _, name := range []string{"network", "firewall", "dhcp"} {
				if restored[name] != "public original "+name {
					t.Fatal("validated original configuration not restored")
				}
			}
		})
	}
}

func TestDeactivateGuardFailuresHaveNoNativeEffects(t *testing.T) {
	for _, failure := range []string{"backup", "foreign-ruleset", "foreign-boot-guard"} {
		t.Run(failure, func(t *testing.T) {
			backup := privateBackupDir(t)
			if failure != "backup" {
				for _, name := range []string{"network", "firewall", "dhcp"} {
					if e := os.WriteFile(filepath.Join(backup, name), []byte("public backup"), 0600); e != nil {
						t.Fatal(e)
					}
				}
			}
			effects := 0
			ops := deactivationOps{
				snapshot: func() (Snapshot, error) { return Snapshot{TableExists: failure == "foreign-ruleset"}, nil },
				checkBoot: func() error {
					if failure == "foreign-boot-guard" {
						return errors.New("public foreign guard")
					}
					return nil
				},
				run:    func(string, ...string) error { effects++; return nil },
				read:   func(string) ([]byte, error) { effects++; return nil, nil },
				write:  func(string, []byte) error { effects++; return nil },
				remove: func(string) error { effects++; return nil },
			}
			if e := deactivateWith(backup, ops); e == nil {
				t.Fatal("invalid ownership or backup accepted")
			}
			if effects != 0 {
				t.Fatal("rejected guard triggered native effects")
			}
		})
	}
}

func TestRollbackUsesCheckedRestoration(t *testing.T) {
	backup := privateBackupDir(t)
	for _, name := range []string{"network", "firewall", "dhcp"} {
		os.WriteFile(filepath.Join(backup, name), []byte("public backup"), 0600)
	}
	pending := true
	ops := deactivationOps{
		disableState: func() error { return nil },
		snapshot:     func() (Snapshot, error) { return Snapshot{Own: true, TableExists: true}, nil }, checkBoot: func() error { return nil },
		run: func(name string, args ...string) error {
			if name == "nft" {
				return errors.New("native failure")
			}
			return nil
		},
		remove: func(path string) error {
			if strings.HasSuffix(path, "rollback.pending") {
				pending = false
			}
			return nil
		},
	}
	if e := rollbackWith(backup, ops); e == nil || !pending {
		t.Fatal("rollback swallowed native deletion failure or lost token")
	}
}

func TestStartupRecoveryDoesNotReenterRuntimeInit(t *testing.T) {
	backup := privateBackupDir(t)
	for _, name := range []string{"network", "firewall", "dhcp"} {
		os.WriteFile(filepath.Join(backup, name), []byte("public backup"), 0600)
	}
	ops := deactivationOps{
		disableState: func() error { return nil },
		snapshot:     func() (Snapshot, error) { return Snapshot{}, nil }, checkBoot: func() error { return nil },
		run: func(name string, args ...string) error {
			if name == "/etc/init.d/flr-runtime" {
				t.Fatal("startup recursively entered its own procd lock")
			}
			return nil
		},
		read: func(path string) ([]byte, error) {
			if strings.HasSuffix(path, "boot-guard.nft") {
				return nil, os.ErrNotExist
			}
			return os.ReadFile(path)
		},
		write: func(string, []byte) error { return nil }, remove: func(string) error { return nil },
	}
	if e := rollbackLifecycleWith(backup, ops, true); e != nil {
		t.Fatal(e)
	}
}

func privateBackupDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	return dir
}
