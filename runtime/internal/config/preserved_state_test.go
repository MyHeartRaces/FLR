package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPreservedDirectoriesProtectRestoredParentsAndRejectLinks(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "flr-runtime")
	if e := preparePreservedDirectories(dir); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(dir); !os.IsNotExist(e) {
		t.Fatal("absent state created")
	}
	if e := os.MkdirAll(filepath.Join(dir, "backup"), 0755); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{dir, filepath.Join(dir, "backup")} {
		if e := os.Chmod(p, 0755); e != nil {
			t.Fatal(e)
		}
	}
	if e := preparePreservedDirectories(dir); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{dir, filepath.Join(dir, "backup")} {
		info, e := os.Stat(p)
		if e != nil || info.Mode().Perm() != 0700 {
			t.Fatal("restored directory not private", e)
		}
	}
	if e := os.Remove(filepath.Join(dir, "backup")); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(t.TempDir(), filepath.Join(dir, "backup")); e != nil {
		t.Fatal(e)
	}
	if e := preparePreservedDirectories(dir); e == nil {
		t.Fatal("symlinked backup accepted")
	}
}
