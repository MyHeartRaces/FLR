package privatefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateAtomicWriteRejectsSymlinksAndPublicDirectory(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "private", "state")
	if err := Write(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("second")); err != nil {
		t.Fatal(err)
	}
	bytes, err := Read(path, 6)
	if err != nil || string(bytes) != "second" {
		t.Fatal("atomic private round trip failed", err)
	}
	if _, err := Read(path, 5); err == nil {
		t.Fatal("oversized private state accepted")
	}
	if err := os.Chmod(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("third")); err == nil {
		t.Fatal("public state directory accepted")
	}
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "outside"), path); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("secret")); err == nil {
		t.Fatal("symlink target overwritten")
	}
	if _, err := os.Stat(filepath.Join(root, "outside")); !os.IsNotExist(err) {
		t.Fatal("private writer changed outside target")
	}
}
