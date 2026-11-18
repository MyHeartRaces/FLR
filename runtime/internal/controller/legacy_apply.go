package controller

import (
	"fmt"
	"os"
	"path/filepath"
)

// BeginLegacyApply holds the same private lock as offline administration until
// the caller publishes legacy settings. Close BEFORE restarting the service.
// This guard never migrates or recovers state merely to decide compatibility.
func BeginLegacyApply(dir string) (*os.File, error) {
	lock, err := lockPrivateAdmin(dir)
	if err != nil {
		return nil, err
	}
	reject := func() (*os.File, error) {
		lock.Close()
		return nil, fmt.Errorf("legacy apply unavailable for v2 or pending recovery; use Proxy management activation")
	}
	names := append([]string{"registry.json", "connection-state.json", "migration-v2.json", "migration-v1", ".registry-v2.json", ".settings-v2.json", "rollback.disabled"}, connectionStageNames...)
	for _, name := range names {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil || !os.IsNotExist(err) {
			return reject()
		}
	}
	s, err := readSettingsAt(dir)
	if err != nil || s.Version != 1 {
		return reject()
	}
	return lock, nil
}
