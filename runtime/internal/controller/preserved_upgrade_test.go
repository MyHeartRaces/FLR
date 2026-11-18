package controller

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestPreservedMigrationRejectsInvalidSourceWithoutCheckpoint(t *testing.T) {
	for _, mode := range []string{"malformed", "public", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			c := testAdmin(t)
			c.registry = nil
			if e := os.MkdirAll(c.stateDir, 0700); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(c.stateDir, "gecko.json")
			if mode == "symlink" {
				if e := os.Symlink(filepath.Join(t.TempDir(), "absent"), path); e != nil {
					t.Fatal(e)
				}
			} else {
				perm := os.FileMode(0600)
				if mode == "public" {
					perm = 0644
				}
				if e := os.WriteFile(path, []byte(`{"outbounds": [INVALID]}`), perm); e != nil {
					t.Fatal(e)
				}
			}
			if e := c.initializeAdmin(true); e == nil {
				t.Error("invalid migration source silently discarded")
			}
			if _, e := os.Lstat(filepath.Join(c.stateDir, "profiles.json")); !os.IsNotExist(e) {
				t.Fatal("invalid source checkpointed; corrected source could never retry")
			}
		})
	}
}

func TestPreservedLegacySettingsAndSourcesMigrateOnceAndRetry(t *testing.T) {
	c := testAdmin(t)
	c.registry = nil
	if e := os.MkdirAll(c.stateDir, 0700); e != nil {
		t.Fatal(e)
	}
	settings := `{"options":{"lan":"br-lan","wan":"eth1","selection":{"general":"down","games":"down"}},"dns_port":"1054","local_dns_port":"53"}`
	legacy := `{"outbounds":[{"type":"hysteria2","server":"example.com","server_port":443,"password":"PUBLIC_TEST_PASSWORD","obfs":{"type":"salamander","password":"PUBLIC_TEST_OBFS"},"tls":{"enabled":true,"server_name":"example.com"},"bind_interface":"eth1","routing_mark":2147483648}]}`
	// File-only 0.5 backup, restored into the private startup directory. The
	// separate startup-directory test covers implicit 0755 parent repair.
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	for name, text := range map[string]string{"settings.json": settings, "gecko.json": legacy, "vless.json": "invalid", "rollback.pending": "old-boot-id\n", "boot-guard.nft": "# tracegate-flr-v1\n"} {
		if e := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(text))}); e != nil {
			t.Fatal(e)
		}
		if _, e := tw.Write([]byte(text)); e != nil {
			t.Fatal(e)
		}
	}
	if e := tw.Close(); e != nil {
		t.Fatal(e)
	}
	if e := gz.Close(); e != nil {
		t.Fatal(e)
	}
	zr, e := gzip.NewReader(&archive)
	if e != nil {
		t.Fatal(e)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		header, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		if filepath.Base(header.Name) != header.Name || header.Mode != 0600 {
			t.Fatal("unsafe synthetic fixture")
		}
		data, e := io.ReadAll(tr)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(c.stateDir, header.Name), data, os.FileMode(header.Mode)); e != nil {
			t.Fatal(e)
		}
	}
	if b, e := os.ReadFile(filepath.Join(c.stateDir, "rollback.pending")); e != nil || string(b) != "old-boot-id\n" {
		t.Fatal("archive lost pending recovery evidence")
	}
	loaded, e := readSettingsAt(c.stateDir)
	if e != nil || !loaded.Enabled || loaded.ProfileSelection != "auto" {
		t.Fatal("legacy activation/defaults lost", e)
	}
	if e = c.initializeAdmin(true); e == nil {
		t.Fatal("partial migration accepted")
	}
	if _, e = os.Stat(filepath.Join(c.stateDir, "profiles.json")); !os.IsNotExist(e) {
		t.Fatal("partial registry published")
	}
	if e = os.Remove(filepath.Join(c.stateDir, "vless.json")); e != nil {
		t.Fatal(e)
	}
	if e = c.initializeAdmin(true); e != nil || len(c.registry.Profiles) != 1 {
		t.Fatal("corrected source did not retry", e)
	}
	id := c.registry.Profiles[0].ID
	c.registry = nil
	if e = c.initializeAdmin(true); e != nil || len(c.registry.Profiles) != 1 || c.registry.Profiles[0].ID != id {
		t.Fatal("migration changed on repeated startup", e)
	}
	if b, e := os.ReadFile(filepath.Join(c.stateDir, "gecko.json")); e != nil || string(b) != legacy {
		t.Fatal("migration source changed")
	}
}
