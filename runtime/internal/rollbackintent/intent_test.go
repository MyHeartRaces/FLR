package rollbackintent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIntentIsPrivateDurableAndIdempotent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if pending, err := Pending(dir); err != nil || pending {
		t.Fatal("absent intent rejected", err)
	}
	for repeat := 0; repeat < 2; repeat++ {
		if err := Mark(dir); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(filepath.Join(dir, filename))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("intent is not private", err)
		}
		if pending, err := Pending(dir); err != nil || !pending {
			t.Fatal("published intent unavailable", err)
		}
	}
	for repeat := 0; repeat < 2; repeat++ {
		if err := Clear(dir); err != nil {
			t.Fatal(err)
		}
		if pending, err := Pending(dir); err != nil || pending {
			t.Fatal("cleared intent still pending", err)
		}
	}
}

func TestUnsafeIntentCannotBeIgnoredOverwrittenOrCleared(t *testing.T) {
	for _, variant := range []string{"malformed", "permissions", "symlink", "directory"} {
		t.Run(variant, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "private")
			if err := Mark(dir); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, filename)
			switch variant {
			case "malformed":
				if err := os.WriteFile(path, []byte("invalid-public-intent"), 0600); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink", "directory":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if variant == "symlink" {
					if err := os.Symlink(filepath.Join(dir, "absent"), path); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := Pending(dir); err == nil {
				t.Fatal("unsafe intent accepted")
			}
			if err := Mark(dir); err == nil {
				t.Fatal("unsafe intent overwritten")
			}
			if err := Clear(dir); err == nil {
				t.Fatal("unsafe intent cleared")
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatal("rejected evidence lost", err)
			}
		})
	}
}
