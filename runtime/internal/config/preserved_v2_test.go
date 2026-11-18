package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPreservedMigrationSnapshotDirectoryPrivateAndLinksRejected(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	snapshot := filepath.Join(dir, "migration-v1")
	unknown := filepath.Join(dir, "unknown")
	for _, path := range []string{snapshot, unknown} {
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := preparePreservedDirectories(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(snapshot)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("restored migration snapshot parent remains public", err)
	}
	info, err = os.Stat(unknown)
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatal("unknown directory changed", err)
	}
	if err := os.Remove(snapshot); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), snapshot); err != nil {
		t.Fatal(err)
	}
	if err := preparePreservedDirectories(dir); err == nil {
		t.Fatal("symlink migration snapshot accepted")
	}
}
