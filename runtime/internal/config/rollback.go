package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/MyHeartRaces/FLR/runtime/internal/dataplane"
)

// The flock lives in /var/run (cleared on boot), never in the persistent
// backup. All arm/expire/confirm/recover comparisons and effects hold it.
// A watcher carries its immutable token, not just the current boot ID.
type rollbackOps struct {
	dir     string
	lock    string
	boot    func() (string, error)
	bootNow func() (int64, error)
	nonce   func() (string, error)
	backup  func() error
	restore func() error
	recover func() error
}

func nativeRollbackOps() rollbackOps {
	return rollbackOps{
		dir: "/etc/flr-runtime", lock: "/var/run/flr-runtime/rollback.lock",
		boot: func() (string, error) {
			b, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
			return strings.TrimSpace(string(b)), e
		},
		bootNow: rollbackBootNow,
		nonce:   func() (string, error) { b := make([]byte, 16); _, e := rand.Read(b); return hex.EncodeToString(b), e },
		backup: func() error {
			if e := Backup("/etc/flr-runtime/backup"); e != nil {
				return e
			}
			return ValidateBackup("/etc/flr-runtime/backup")
		},
		restore: func() error { return dataplane.Rollback("/etc/flr-runtime/backup") },
		recover: func() error { return dataplane.RecoverAtStartup("/etc/flr-runtime/backup") },
	}
}
func RollbackToken(action, expected string) (string, error) {
	if action == "manual" {
		return "", fmt.Errorf("use the serialized rollback command for manual restoration")
	}
	if e := preparePreservedDirectories("/etc/flr-runtime"); e != nil {
		return "", e
	}
	return rollbackTokenWith(action, expected, nativeRollbackOps())
}

// RestoreManualRollback is called with controller.lock and admin.lock held.
// The generation lock comes last and spans the entire native restoration.
func RestoreManualRollback(backup string) error {
	if e := preparePreservedDirectories("/etc/flr-runtime"); e != nil {
		return e
	}
	ops := nativeRollbackOps()
	ops.restore = func() error { return dataplane.Rollback(backup) }
	_, e := rollbackTokenWith("manual", "", ops)
	return e
}

func rollbackTokenWith(action, expected string, ops rollbackOps) (string, error) {
	if e := os.MkdirAll(filepath.Dir(ops.lock), 0700); e != nil {
		return "", e
	}
	lock, e := os.OpenFile(ops.lock, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return "", e
	}
	defer lock.Close()
	lockMode := syscall.LOCK_EX
	// start_service already owns procd's service lock. Never wait here while an
	// expiry owns rollback.lock and is requesting that service to stop.
	if action == "recover" {
		lockMode |= syscall.LOCK_NB
	}
	if e = syscall.Flock(int(lock.Fd()), lockMode); e != nil {
		return "", fmt.Errorf("rollback transition busy; retry runtime start")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	boot, e := ops.boot()
	if e != nil || boot == "" {
		return "", fmt.Errorf("boot identity unavailable")
	}
	path := filepath.Join(ops.dir, "rollback.pending")
	raw, e := os.ReadFile(path)
	if e != nil && !os.IsNotExist(e) {
		return "", e
	}
	token := strings.TrimSpace(string(raw))
	deadline, current := rollbackDeadline(token, boot)
	switch action {
	case "arm":
		if e = ops.backup(); e != nil {
			return "", fmt.Errorf("rollback backup validation failed")
		}
		nonce, e := ops.nonce()
		if e != nil {
			return "", fmt.Errorf("rollback generation unavailable")
		}
		now, e := ops.bootNow()
		if e != nil || now < 0 || now > math.MaxInt64-int64(180*time.Second) {
			return "", fmt.Errorf("rollback boot clock unavailable")
		}
		if !rollbackIdentity.MatchString(boot) || len(boot) > 36 || !rollbackIdentity.MatchString(nonce) || len(nonce) > 32 {
			return "", fmt.Errorf("rollback identity unavailable")
		}
		token = fmt.Sprintf("b1 %s %s %d", boot, nonce, now+int64(180*time.Second))
		if e = os.MkdirAll(ops.dir, 0700); e != nil {
			return "", e
		}
		f, e := os.CreateTemp(ops.dir, ".rollback-")
		if e != nil {
			return "", e
		}
		defer os.Remove(f.Name())
		_, e = f.WriteString(token + "\n")
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e == nil {
			e = closeErr
		}
		if e == nil {
			e = os.Rename(f.Name(), path)
		}
		if e != nil {
			return "", e
		}
		dir, e := os.Open(ops.dir)
		if e != nil {
			return "", e
		}
		e = dir.Sync()
		dir.Close()
		if e != nil {
			return "", e
		}
		return token, nil
	case "confirm":
		if token == "" || (expected != "" && token != expected) {
			return "", fmt.Errorf("rollback generation changed; refresh status before confirming")
		}
		if !current {
			return "", fmt.Errorf("pending rollback belongs to another boot or legacy activation")
		}
		now, e := ops.bootNow()
		if e != nil || now < 0 {
			return "", fmt.Errorf("rollback boot clock unavailable")
		}
		if now >= deadline {
			return "", fmt.Errorf("rollback acceptance deadline expired")
		}
		if e = os.Remove(path); e != nil {
			return "", e
		}
	case "expire", "recover", "manual":
		if action != "manual" && token == "" {
			return "", nil
		}
		if action == "expire" {
			if expected == "" || token != expected {
				return "", nil
			}
		}
		if action != "manual" && current {
			now, clockErr := ops.bootNow()
			if clockErr == nil && now >= 0 && now < deadline {
				if action == "expire" {
					return "", fmt.Errorf("rollback deadline not reached")
				}
				return "", nil
			}
		}
		// Unknown/legacy time domains and failed clock reads cannot safely
		// extend acceptance. Recover conservatively, with failure evidence.
		// Keep the token on failure so recovery can retry. The restored network and
		// pending-file removal cannot interleave with another activation generation.
		restore := ops.restore
		if action == "recover" && ops.recover != nil {
			restore = ops.recover
		}
		if e = restore(); e != nil {
			if _, statErr := os.Stat(path); token != "" && os.IsNotExist(statErr) {
				if saveErr := os.WriteFile(path, raw, 0600); saveErr != nil {
					return "", fmt.Errorf("rollback restoration incomplete; pending activation could not be retained")
				}
			}
			if action == "manual" {
				return "", fmt.Errorf("manual rollback restoration incomplete; retry rollback")
			}
			return "", fmt.Errorf("rollback restoration incomplete; pending activation retained")
		}
		if e = os.Remove(path); e != nil && !os.IsNotExist(e) {
			return "", e
		}
		if action == "recover" {
			return "recovered", nil
		}
	default:
		return "", fmt.Errorf("unknown rollback action")
	}
	return "", nil
}

// CLOCK_BOOTTIME is kernel-wide, nonsettable and includes suspended time. No
// process-local monotonic origin or adjustable wall clock enters the marker.
func rollbackBootNow() (int64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, err
	}
	if ts.Sec < 0 || ts.Nsec < 0 || ts.Nsec >= int64(time.Second) || ts.Sec > (math.MaxInt64-ts.Nsec)/int64(time.Second) {
		return 0, fmt.Errorf("invalid boot clock")
	}
	return ts.Sec*int64(time.Second) + ts.Nsec, nil
}

var rollbackIdentity = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)

func rollbackDeadline(token, boot string) (int64, bool) {
	fields := strings.Fields(token)
	if len(token)+1 >= 128 || len(fields) != 4 || fields[0] != "b1" || fields[1] != boot || len(fields[1]) > 36 || len(fields[2]) > 32 || !rollbackIdentity.MatchString(fields[1]) || !rollbackIdentity.MatchString(fields[2]) {
		return 0, false
	}
	deadline, err := strconv.ParseInt(fields[3], 10, 64)
	return deadline, err == nil && deadline >= int64(180*time.Second)
}
