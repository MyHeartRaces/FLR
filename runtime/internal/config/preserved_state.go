package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// sysupgrade's explicit file list does not necessarily carry directory modes.
// Normalize only known private directories; reject links and keep file-mode
// validation at each consumer. No unknown file or credential is rewritten.
func preparePreservedDirectories(dir string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return fmt.Errorf("invalid preserved state path")
	}
	for path := dir; ; path = filepath.Dir(path) {
		info, e := os.Lstat(path)
		if e != nil && !os.IsNotExist(e) {
			return e
		}
		if e == nil && !info.IsDir() {
			return fmt.Errorf("unsafe preserved state ancestor")
		}
		if path == filepath.Dir(path) {
			break
		}
	}
	for _, path := range []string{dir, filepath.Join(dir, "backup"), filepath.Join(dir, "migration-v1")} {
		info, e := os.Lstat(path)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil || !info.IsDir() {
			return fmt.Errorf("unsafe preserved state directory")
		}
		if e = os.Chmod(path, 0700); e != nil {
			return e
		}
	}
	return nil
}
