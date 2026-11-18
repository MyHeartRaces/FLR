package controller

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/MyHeartRaces/FLR/runtime/internal/privatefile"
)

func TestLegacyApplyRejectsV2AndRecoveryStateBeforeMutation(t *testing.T) {
	names := append([]string{"registry.json", "migration-v2.json", "connection-state.json", "migration-v1/manifest.json", ".registry-v2.json", ".settings-v2.json", "rollback.disabled"}, connectionStageNames...)
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "private")
			if err := WriteJSON(filepath.Join(dir, "settings.json"), DefaultSettings()); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, name)
			if err := privatefile.Write(path, []byte("public invalid state must fail closed")); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(filepath.Join(dir, "settings.json"))
			lock, err := BeginLegacyApply(dir)
			if err == nil || lock != nil {
				if lock != nil {
					lock.Close()
				}
				t.Fatal("v2/recovery state admitted legacy mutation")
			}
			if raw, err := os.ReadFile(filepath.Join(dir, "settings.json")); err != nil || string(raw) != string(before) {
				t.Fatal("compatibility probe changed settings", err)
			}
			if raw, err := os.ReadFile(path); err != nil || string(raw) != "public invalid state must fail closed" {
				t.Fatal("compatibility probe recovered or changed private state", err)
			}
		})
	}
	for _, variant := range []string{"v2-settings", "invalid-settings", "symlink", "public-permissions"} {
		t.Run(variant, func(t *testing.T) {
			dir, _ := rollbackV2State(t, false)
			if err := os.Remove(filepath.Join(dir, "registry.json")); err != nil {
				t.Fatal(err)
			}
			// Isolate the settings check from the independent stage/manifest guard.
			clean := filepath.Join(t.TempDir(), "private")
			if err := os.Mkdir(clean, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(clean, "settings.json")
			raw, _ := os.ReadFile(filepath.Join(dir, "settings.json"))
			if variant == "invalid-settings" {
				raw = []byte("invalid public settings")
			}
			if variant == "symlink" {
				if err := os.Symlink(filepath.Join(dir, "settings.json"), path); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if variant == "public-permissions" {
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if lock, err := BeginLegacyApply(clean); err == nil || lock != nil {
				if lock != nil {
					lock.Close()
				}
				t.Fatal("unsafe or v2 settings allowed legacy apply")
			}
		})
	}
}

func TestLegacyApplyHoldsAdminLockUntilCallerReleasesIt(t *testing.T) {
	for _, original := range []bool{false, true} {
		dir := filepath.Join(t.TempDir(), "private")
		if original {
			if err := WriteJSON(filepath.Join(dir, "settings.json"), DefaultSettings()); err != nil {
				t.Fatal(err)
			}
		}
		lock, err := BeginLegacyApply(dir)
		if err != nil {
			t.Fatal("clean/original state rejected", err)
		}
		other, err := os.OpenFile(filepath.Join(dir, "admin.lock"), os.O_RDWR, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if err := syscall.Flock(int(other.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			t.Fatal("legacy apply did not fence concurrent offline writes")
		}
		if err := lock.Close(); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Flock(int(other.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			t.Fatal("released legacy apply lock still blocks service settings read", err)
		}
		other.Close()
		if _, err := os.Stat(filepath.Join(dir, "registry.json")); !os.IsNotExist(err) {
			t.Fatal("legacy probe performed migration")
		}
	}
}
