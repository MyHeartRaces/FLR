package dataplane

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MyHeartRaces/FLR/runtime/internal/rollbackintent"
)

func TestRollbackRetainsV2StateAndPublishesDisabledIntent(t *testing.T) {
	for _, startup := range []bool{false, true} {
		for _, failRestore := range []bool{false, true} {
			t.Run(fmt.Sprintf("startup=%v/fail=%v", startup, failRestore), func(t *testing.T) {
				dir := privateBackupDir(t)
				backup := filepath.Join(dir, "backup")
				if err := os.Mkdir(backup, 0700); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"network", "firewall", "dhcp"} {
					if err := os.WriteFile(filepath.Join(backup, name), []byte("public original "+name), 0600); err != nil {
						t.Fatal(err)
					}
				}
				files := map[string]string{"settings.json": `{"version":2,"enabled":true}`, "registry.json": `{"version":2,"connections":[]}`, "connection-state.json": "public checkpoint", "rollback.pending": "public pending", "boot-guard.nft": "# tracegate-flr-v1\n"}
				for name, raw := range files {
					if err := os.WriteFile(filepath.Join(dir, name), []byte(raw), 0600); err != nil {
						t.Fatal(err)
					}
				}
				ops := deactivationOps{
					disableState: func() error { return rollbackintent.Mark(dir) },
					snapshot:     func() (Snapshot, error) { return Snapshot{BootTableExists: true}, nil },
					checkBoot:    func() error { return nil },
					run: func(name string, args ...string) error {
						if name == "ubus" && failRestore {
							return fmt.Errorf("public network restore failure")
						}
						return nil
					},
					read: func(path string) ([]byte, error) {
						if strings.HasPrefix(path, "/etc/flr-runtime/") {
							path = filepath.Join(dir, filepath.Base(path))
						}
						return os.ReadFile(path)
					},
					write:  func(string, []byte) error { return nil },
					remove: func(path string) error { return os.Remove(filepath.Join(dir, filepath.Base(path))) },
				}
				err := rollbackLifecycleWith(backup, ops, startup)
				if (err != nil) != failRestore {
					t.Fatal("rollback restore result changed", err)
				}
				for _, name := range []string{"settings.json", "registry.json", "connection-state.json"} {
					raw, err := os.ReadFile(filepath.Join(dir, name))
					if err != nil || string(raw) != files[name] {
						t.Fatal("rollback deleted or altered durable private state", name, err)
					}
				}
				if raw, err := os.ReadFile(filepath.Join(dir, "rollback.disabled")); err != nil || string(raw) != "disable-v1\n" {
					t.Fatal("rollback did not durably disable future runtime startup", err)
				}
				if failRestore {
					for _, name := range []string{"rollback.pending", "boot-guard.nft"} {
						if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
							t.Fatal("failed restore lost recovery evidence", name, err)
						}
					}
				}
			})
		}
	}
}

func TestRollbackIntentFailurePreventsNativeRestoreAndStateRemoval(t *testing.T) {
	backup := privateBackupDir(t)
	for _, name := range []string{"network", "firewall", "dhcp"} {
		if err := os.WriteFile(filepath.Join(backup, name), []byte("public original"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	effects := 0
	ops := deactivationOps{
		snapshot:     func() (Snapshot, error) { return Snapshot{}, nil },
		checkBoot:    func() error { return nil },
		disableState: func() error { return fmt.Errorf("public intent disk failure") },
		run: func(name string, args ...string) error {
			if strings.HasPrefix(name, "/etc/init.d/flr-") && (args[0] == "stop" || args[0] == "disable") {
				return nil
			}
			effects++
			return nil
		},
		read:   func(string) ([]byte, error) { effects++; return nil, nil },
		write:  func(string, []byte) error { effects++; return nil },
		remove: func(string) error { effects++; return nil },
	}
	if err := rollbackWith(backup, ops); err == nil || effects != 0 {
		t.Fatal("failed disable intent allowed restore or recovery evidence deletion", err, effects)
	}
}
