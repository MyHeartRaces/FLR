// Package rollbackintent durably disables runtime after native recovery.
package rollbackintent

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/MyHeartRaces/FLR/runtime/internal/privatefile"
)

const filename = "rollback.disabled"
const canonical = "disable-v1\n"

func Pending(dir string) (bool, error) {
	raw, err := privatefile.Read(filepath.Join(dir, filename), len(canonical))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil || string(raw) != canonical {
		return false, fmt.Errorf("private rollback intent rejected")
	}
	return true, nil
}

func Mark(dir string) error {
	if _, err := Pending(dir); err != nil {
		return err
	}
	return privatefile.Write(filepath.Join(dir, filename), []byte(canonical))
}

// Clear follows a synced settings write; replay before it remains disabled.
func Clear(dir string) error {
	pending, err := Pending(dir)
	if err != nil {
		return err
	}
	if pending {
		if err := os.Remove(filepath.Join(dir, filename)); err != nil {
			return fmt.Errorf("cannot clear private rollback intent")
		}
	}
	return privatefile.SyncDir(dir)
}
