package config

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// No real time elapses between arm and confirm. Moving only the injected wall
// clock must not consume the acceptance window.
func TestRollbackForwardWallStepDoesNotExpireAcceptance(t *testing.T) {
	ops, wall, _ := rollbackFixture(t)
	ops.bootNow = func() (int64, error) { return int64(20 * time.Second), nil }
	token, err := rollbackTokenWith("arm", "", ops)
	if err != nil {
		t.Fatal(err)
	}
	*wall = wall.Add(24 * time.Hour)
	if _, err = rollbackTokenWith("confirm", token, ops); err != nil {
		t.Fatal("wall-clock step consumed acceptance window", err)
	}
}

// Independent wall and elapsed inputs: the wall value is deliberately never a
// source for the boot clock, including in a fresh adapter/CLI invocation.
func TestRollbackBootElapsedBoundaryAcrossInvocations(t *testing.T) {
	for _, step := range []time.Duration{-24 * time.Hour, 24 * time.Hour} {
		for _, action := range []string{"confirm", "expire", "recover"} {
			t.Run(step.String()+"/"+action, func(t *testing.T) {
				ops, wall, restores := rollbackFixture(t)
				elapsed := int64(20 * time.Second)
				ops.bootNow = func() (int64, error) { return elapsed, nil }
				token, err := rollbackTokenWith("arm", "", ops)
				if err != nil {
					t.Fatal(err)
				}
				*wall = wall.Add(step)
				// Reconstruct the adapter rather than carrying process-local timing.
				next := rollbackOps{dir: ops.dir, lock: ops.lock, boot: ops.boot, bootNow: func() (int64, error) { return elapsed, nil }, restore: ops.restore}
				elapsed = int64(200*time.Second - time.Nanosecond)
				if action == "confirm" {
					if _, err = rollbackTokenWith("confirm", token, next); err != nil {
						t.Fatal("acceptance expired before elapsed boundary", err)
					}
					return
				}
				_, err = rollbackTokenWith(action, token, next)
				if (action == "expire" && err == nil) || (action == "recover" && err != nil) || *restores != 0 {
					t.Fatal("restoration before elapsed boundary", err, *restores)
				}
				elapsed++
				if _, err = rollbackTokenWith("confirm", token, next); err == nil {
					t.Fatal("accepted at elapsed deadline")
				}
				if _, err = rollbackTokenWith(action, token, next); err != nil || *restores != 1 {
					t.Fatal("deadline did not restore", err, *restores)
				}
			})
		}
	}
}

func TestRollbackClockFailureRetainsEvidenceAndRecovers(t *testing.T) {
	for _, action := range []string{"expire", "recover"} {
		ops, _, restores := rollbackFixture(t)
		token, err := rollbackTokenWith("arm", "", ops)
		if err != nil {
			t.Fatal(err)
		}
		ops.bootNow = func() (int64, error) { return 0, fmt.Errorf("private clock failure") }
		for _, invalid := range []string{"confirm", "arm"} {
			if _, err = rollbackTokenWith(invalid, token, ops); err == nil || strings.Contains(err.Error(), "private") {
				t.Fatal("clock failure accepted or exposed", invalid, err)
			}
		}
		if _, err = rollbackTokenWith("expire", "stale-generation", ops); err != nil || *restores != 0 {
			t.Fatal("clock failure bypassed generation guard", err)
		}
		path := filepath.Join(ops.dir, "rollback.pending")
		original := token + "\n"
		restore := ops.restore
		ops.restore = func() error {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			return fmt.Errorf("native restoration failed")
		}
		if _, err = rollbackTokenWith(action, token, ops); err == nil {
			t.Fatal("failed restoration accepted")
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("pending evidence lost or not private", err)
		}
		if b, err := os.ReadFile(path); err != nil || string(b) != original {
			t.Fatal("pending evidence changed", err)
		}
		ops.restore = restore
		if _, err = rollbackTokenWith(action, token, ops); err != nil || *restores != 1 {
			t.Fatal("clock failure indefinitely delayed restoration", err)
		}
	}
}

func TestRollbackRejectsInvalidClockWithoutArming(t *testing.T) {
	for _, clock := range []int64{-1, math.MaxInt64, math.MaxInt64 - int64(180*time.Second) + 1} {
		ops, _, _ := rollbackFixture(t)
		ops.bootNow = func() (int64, error) { return clock, nil }
		if _, err := rollbackTokenWith("arm", "", ops); err == nil {
			t.Fatal("invalid or overflowing clock armed", clock)
		}
		if _, err := os.Stat(filepath.Join(ops.dir, "rollback.pending")); !os.IsNotExist(err) {
			t.Fatal("invalid clock published marker", err)
		}
	}
}

func TestRollbackVersionedMarkerAndConservativeLegacyRecovery(t *testing.T) {
	for _, token := range []string{"test-boot", "test-boot generation-1 9999999999", "b1 test-boot generation-1 invalid", "b1 test-boot generation-1 -1", "b1 test-boot generation-1 9223372036854775808", "b2 test-boot generation-1 9999999999"} {
		for _, action := range []string{"expire", "recover"} {
			ops, _, restores := rollbackFixture(t)
			path := filepath.Join(ops.dir, "rollback.pending")
			if err := os.WriteFile(path, []byte(token+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := rollbackTokenWith("confirm", token, ops); err == nil {
				t.Fatal("legacy/malformed token accepted", token)
			}
			if _, err := rollbackTokenWith(action, token, ops); err != nil || *restores != 1 {
				t.Fatal("legacy/malformed token did not recover", token, err)
			}
		}
	}
	ops, _, _ := rollbackFixture(t)
	ops.boot = func() (string, error) { return "00000000-0000-0000-0000-000000000000", nil }
	ops.nonce = func() (string, error) { return strings.Repeat("a", 32), nil }
	ops.bootNow = func() (int64, error) { return math.MaxInt64 - int64(180*time.Second), nil }
	token, err := rollbackTokenWith("arm", "", ops)
	if err != nil || len(token)+1 >= 128 {
		t.Fatal("maximum marker no longer visible to status", len(token), err)
	}
	ops.bootNow = func() (int64, error) { t.Fatal("empty startup read clock"); return 0, nil }
	if err = os.Remove(filepath.Join(ops.dir, "rollback.pending")); err != nil {
		t.Fatal(err)
	}
	if _, err = rollbackTokenWith("recover", "", ops); err != nil {
		t.Fatal("clean startup rejected", err)
	}
}
