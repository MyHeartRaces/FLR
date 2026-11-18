package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func rollbackFixture(t *testing.T) (rollbackOps, *time.Time, *int) {
	t.Helper()
	dir := t.TempDir()
	now := time.Unix(1000, 0)
	restores := 0
	nonce := 0
	ops := rollbackOps{dir: dir, lock: filepath.Join(dir, "lock"), boot: func() (string, error) { return "test-boot", nil }, bootNow: func() (int64, error) { return now.UnixNano(), nil }, nonce: func() (string, error) { nonce++; return fmt.Sprintf("generation-%d", nonce), nil }, backup: func() error { return nil }, restore: func() error { restores++; return nil }}
	return ops, &now, &restores
}
func TestRollbackConfirmRearmAndOverlappingTimers(t *testing.T) {
	for _, confirm := range []bool{true, false} {
		t.Run(fmt.Sprint(confirm), func(t *testing.T) {
			ops, now, restores := rollbackFixture(t)
			a, e := rollbackTokenWith("arm", "", ops)
			if e != nil {
				t.Fatal(e)
			}
			if confirm {
				if _, e = rollbackTokenWith("confirm", a, ops); e != nil {
					t.Fatal(e)
				}
			}
			*now = now.Add(60 * time.Second)
			b, e := rollbackTokenWith("arm", "", ops)
			if e != nil || a == b {
				t.Fatal("generation not replaced", e)
			}
			*now = now.Add(120 * time.Second)
			if _, e = rollbackTokenWith("expire", a, ops); e != nil {
				t.Fatal(e)
			}
			pending, _ := os.ReadFile(filepath.Join(ops.dir, "rollback.pending"))
			if *restores != 0 || strings.TrimSpace(string(pending)) != b {
				t.Fatal("stale timer affected new activation")
			}
			if _, e = rollbackTokenWith("confirm", a, ops); e == nil {
				t.Fatal("stale confirmation accepted")
			}
			if _, e = rollbackTokenWith("expire", b, ops); e == nil {
				t.Fatal("new deadline shortened")
			}
			*now = now.Add(60 * time.Second)
			if _, e = rollbackTokenWith("expire", b, ops); e != nil || *restores != 1 {
				t.Fatal("matching deadline did not restore", e)
			}
			if _, e = os.Stat(filepath.Join(ops.dir, "rollback.pending")); !os.IsNotExist(e) {
				t.Fatal("completed token retained")
			}
		})
	}
}
func TestRollbackExpiryAndArmAreAtomic(t *testing.T) {
	ops, now, _ := rollbackFixture(t)
	a, _ := rollbackTokenWith("arm", "", ops)
	*now = now.Add(180 * time.Second)
	entered := make(chan struct{})
	release := make(chan struct{})
	ops.restore = func() error { close(entered); <-release; return nil }
	expired := make(chan error, 1)
	go func() { _, e := rollbackTokenWith("expire", a, ops); expired <- e }()
	<-entered
	armed := make(chan string, 1)
	go func() {
		b, e := rollbackTokenWith("arm", "", ops)
		if e != nil {
			armed <- "error"
		} else {
			armed <- b
		}
	}()
	select {
	case <-armed:
		t.Fatal("arm raced locked restoration")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if e := <-expired; e != nil {
		t.Fatal(e)
	}
	b := <-armed
	pending, _ := os.ReadFile(filepath.Join(ops.dir, "rollback.pending"))
	if b == "error" || b == a || strings.TrimSpace(string(pending)) != b {
		t.Fatal("expiry deleted newer token")
	}
}
func TestRollbackBootRecoveryAndFailureRetainPending(t *testing.T) {
	ops, _, restores := rollbackFixture(t)
	token, _ := rollbackTokenWith("arm", "", ops)
	if _, e := rollbackTokenWith("recover", "", ops); e != nil || *restores != 0 {
		t.Fatal("same boot startup restored", e)
	}
	ops.boot = func() (string, error) { return "next-boot", nil }
	if _, e := rollbackTokenWith("confirm", token, ops); e == nil {
		t.Fatal("cross-boot confirmation accepted")
	}
	restore := ops.restore
	ops.restore = func() error { return fmt.Errorf("private-native-error") }
	if _, e := rollbackTokenWith("recover", "", ops); e == nil || strings.Contains(e.Error(), "private-native") {
		t.Fatal("failure lost or exposed", e)
	}
	if b, _ := os.ReadFile(filepath.Join(ops.dir, "rollback.pending")); strings.TrimSpace(string(b)) != token {
		t.Fatal("failure removed token")
	}
	ops.restore = restore
	if _, e := rollbackTokenWith("recover", "", ops); e != nil || *restores != 1 {
		t.Fatal("cross-boot recovery failed", e)
	}
	// Legacy boot-only markers are recovered, never accepted as a generation.
	os.WriteFile(filepath.Join(ops.dir, "rollback.pending"), []byte("next-boot\n"), 0600)
	if _, e := rollbackTokenWith("recover", "", ops); e != nil || *restores != 2 {
		t.Fatal("legacy recovery failed", e)
	}
}

func TestStartupRecoveryNeverWaitsForAnExpiringServiceStop(t *testing.T) {
	ops, now, _ := rollbackFixture(t)
	token, _ := rollbackTokenWith("arm", "", ops)
	*now = now.Add(180 * time.Second)
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	ops.restore = func() error { close(entered); <-release; return nil }
	go func() { _, e := rollbackTokenWith("expire", token, ops); done <- e }()
	<-entered
	// In production startup holds procd's runtime lock, which expiry needs to
	// stop the service. Busy recovery must fail immediately and release procd.
	if _, e := rollbackTokenWith("recover", "", ops); e == nil {
		t.Fatal("startup did not reject concurrent expiry")
	}
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
