package config

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Restoring without the generation lock must fail: every manual transition
// must fence arms/confirms until restoration and pending cleanup are complete.
func TestManualRollbackTransitionOwnsGenerationLock(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(fmt.Sprint(pending), func(t *testing.T) {
			ops, _, _ := rollbackFixture(t)
			path := filepath.Join(ops.dir, "rollback.pending")
			if pending {
				if _, err := rollbackTokenWith("arm", "", ops); err != nil {
					t.Fatal(err)
				}
			}
			restored := filepath.Join(ops.dir, "public-native-restored")
			ops.restore = func() error {
				contender, err := os.OpenFile(ops.lock, os.O_RDWR, 0600)
				if err != nil {
					return err
				}
				defer contender.Close()
				if err := syscall.Flock(int(contender.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
					return fmt.Errorf("manual native restore did not own generation lock")
				}
				if err := os.WriteFile(restored, []byte("restored"), 0600); err != nil {
					return err
				}
				return nil
			}
			if _, err := rollbackTokenWith("manual", "", ops); err != nil {
				t.Fatal("manual rollback transition unavailable", err)
			}
			if raw, err := os.ReadFile(restored); err != nil || string(raw) != "restored" {
				t.Fatal("manual transition skipped native restore", err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("manual completion retained pending token", err)
			}
		})
	}
}

func TestManualRollbackFailureRetainsGeneration(t *testing.T) {
	ops, _, _ := rollbackFixture(t)
	token, err := rollbackTokenWith("arm", "", ops)
	if err != nil {
		t.Fatal(err)
	}
	ops.restore = func() error { return fmt.Errorf("public native restore failure") }
	if _, err := rollbackTokenWith("manual", "", ops); err == nil {
		t.Fatal("manual restore failure was ignored")
	}
	raw, err := os.ReadFile(filepath.Join(ops.dir, "rollback.pending"))
	if err != nil || string(raw) != token+"\n" {
		t.Fatal("failed manual restore changed pending generation", err)
	}
}
