package controller

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/config"
	"github.com/MyHeartRaces/FLR/runtime/internal/rollbackintent"
)

func manualRollbackFixture(t *testing.T) (manualRollbackOps, string, string) {
	t.Helper()
	dir, _ := rollbackV2State(t, false)
	backup := filepath.Join(dir, "backup")
	if err := os.Mkdir(backup, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"network", "firewall", "dhcp"} {
		if err := os.WriteFile(filepath.Join(backup, name), []byte("public original "+name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for name, raw := range map[string]string{"rollback.pending": "b1 test-boot generation-new 180000000000\n", "boot-guard.nft": "# tracegate-flr-v1\npublic guard\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
	}
	lockPath := filepath.Join(t.TempDir(), "run", "controller.lock")
	if err := os.MkdirAll(filepath.Dir(lockPath), 0700); err != nil {
		t.Fatal(err)
	}
	ops := manualRollbackOps{
		stateDir: dir, singleton: lockPath,
		validate: config.ValidateBackup,
		stop:     func() error { return nil },
		restore: func(string) error {
			if err := rollbackintent.Mark(dir); err != nil {
				return err
			}
			for _, name := range []string{"rollback.pending", "boot-guard.nft"} {
				if err := os.Remove(filepath.Join(dir, name)); err != nil {
					return err
				}
			}
			return nil
		},
	}
	return ops, dir, backup
}

func manualTestLock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// Removing singleton exclusion must fail: a restoration must never erase the
// acceptance token or guard while offline activation owns the native transition.
func TestManualRollbackCannotEraseOfflineActivationGeneration(t *testing.T) {
	ops, dir, backup := manualRollbackFixture(t)
	owner, err := manualTestLock(ops.singleton)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	before := map[string]string{}
	for _, name := range []string{"settings.json", "registry.json", "rollback.pending", "boot-guard.nft"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		before[name] = string(raw)
	}
	if err := manualRollbackWith(backup, ops); err == nil {
		t.Error("manual rollback admitted restoration during offline activation")
	}
	for name, want := range before {
		if raw, err := os.ReadFile(filepath.Join(dir, name)); err != nil || string(raw) != want {
			t.Errorf("manual rollback erased or changed newer activation state %s: %v", name, err)
		}
	}
	if pending, err := rollbackintent.Pending(dir); err != nil || pending {
		t.Error("rejected restoration published disabled intent", err)
	}
}

// Releasing admission before native cleanup must fail: another startup must not
// consume intent or start a new generation during the suspended restoration.
func TestManualRollbackHoldsAdmissionThroughoutRestore(t *testing.T) {
	ops, dir, backup := manualRollbackFixture(t)
	registry, _ := os.ReadFile(filepath.Join(dir, "registry.json"))
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	complete := make(chan error, 1)
	cleanup := ops.restore
	ops.restore = func(path string) error {
		if err := rollbackintent.Mark(dir); err != nil {
			return err
		}
		close(entered)
		<-release
		return cleanup(path)
	}
	go func() { complete <- manualRollbackWith(backup, ops) }()
	select {
	case <-entered:
	case err := <-complete:
		t.Fatal("restoration never reached native boundary", err)
	case <-time.After(2 * time.Second):
		t.Fatal("manual restoration stalled before native boundary")
	}
	reads := 0
	contender, _, err := readOwnedSettings(ops.singleton, func() (Settings, error) {
		reads++
		if err := migrateState(dir); err != nil {
			return Settings{}, err
		}
		return readSettingsAt(dir)
	})
	if contender != nil {
		contender.Close()
	}
	if err == nil || reads != 0 {
		t.Error("startup consumed rollback intent during manual native restoration")
	}
	admin, err := manualTestLock(filepath.Join(dir, "admin.lock"))
	if err == nil {
		admin.Close()
		t.Error("offline administration admitted during manual native restoration")
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-complete:
		if err != nil {
			t.Fatal("manual restoration failed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("manual restoration did not release admission")
	}
	if err := migrateState(dir); err != nil {
		t.Fatal(err)
	}
	s, err := readSettingsAt(dir)
	if err != nil || s.Enabled || s.DirectProxy.Enabled || s.DirectBypass.Enabled {
		t.Fatal("completed manual restoration did not disable all runtime services", err)
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "registry.json")); err != nil || string(raw) != string(registry) {
		t.Fatal("manual restoration lost v2 connections", err)
	}
}

func TestManualRollbackStopsBeforeTakingPrivateLocks(t *testing.T) {
	ops, dir, backup := manualRollbackFixture(t)
	stopped := filepath.Join(dir, "public-runtime-stopped")
	ops.stop = func() error {
		for _, path := range []string{ops.singleton, filepath.Join(dir, "admin.lock")} {
			lock, err := manualTestLock(path)
			if err != nil {
				return fmt.Errorf("service stop ran beneath a private lock: %w", err)
			}
			lock.Close()
		}
		return os.WriteFile(stopped, []byte("stopped"), 0600)
	}
	ops.restore = func(path string) error {
		if path != backup {
			return fmt.Errorf("custom backup was replaced")
		}
		if _, err := os.Stat(stopped); err != nil {
			return fmt.Errorf("native restoration preceded service stop")
		}
		return nil
	}
	if err := manualRollbackWith(backup, ops); err != nil {
		t.Fatal("manual rollback violated stop/lock ordering", err)
	}
}

func TestManualRollbackValidationAndStopFailurePreserveRecovery(t *testing.T) {
	for _, failure := range []string{"backup", "stop"} {
		t.Run(failure, func(t *testing.T) {
			ops, dir, backup := manualRollbackFixture(t)
			if failure == "backup" {
				backup = filepath.Join(dir, "missing-backup")
			} else {
				ops.stop = func() error { return fmt.Errorf("public native stop failure") }
			}
			if err := manualRollbackWith(backup, ops); err == nil {
				t.Error("invalid backup or failed service stop admitted native restoration")
			}
			for _, name := range []string{"rollback.pending", "boot-guard.nft"} {
				if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
					t.Error("failed precondition removed recovery evidence", name, err)
				}
			}
			if pending, err := rollbackintent.Pending(dir); err != nil || pending {
				t.Error("failed precondition published rollback intent", err)
			}
		})
	}
}
