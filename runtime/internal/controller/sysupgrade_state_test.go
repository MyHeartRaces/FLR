package controller

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/privatefile"
)

// Exercise the actual shipped keep list, not a test-local copy of its paths.
func copyShippedPreservation(t *testing.T, source string) string {
	t.Helper()
	raw, err := os.ReadFile("../../../packages/flr-runtime/files/flr-runtime.keep")
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "restored")
	if err := os.Mkdir(dest, 0700); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name := strings.TrimPrefix(line, "/etc/flr-runtime/")
		if name == line || filepath.Clean(name) != name || strings.HasPrefix(name, "..") {
			t.Fatal("unsafe preservation fixture path")
		}
		data, err := os.ReadFile(filepath.Join(source, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := privatefile.Write(filepath.Join(dest, name), data); err != nil {
			t.Fatal(err)
		}
	}
	return dest
}

func TestShippedPreservationRestartsV2WithNewConnectionAndPinnedOrder(t *testing.T) {
	c := connectionAdmin(t)
	next := c.connections.Clone()
	if _, err := next.Import([]byte(publicConnectionURI)); err != nil {
		t.Fatal(err)
	}
	s := c.settings
	s.Order = connection.ReconcileOrder(next, s.Order)
	s.Selection = connection.Selection{Mode: "connection", ID: next.Connections[len(next.Connections)-1].ID}
	if err := commitConnectionState(c.stateDir, next, s, nil); err != nil {
		t.Fatal(err)
	}
	restored := copyShippedPreservation(t, c.stateDir)
	if err := recoverConnectionState(restored); err != nil {
		t.Fatal(err)
	}
	if err := migrateState(restored); err != nil {
		t.Fatal("shipped backup cannot start v2 controller", err)
	}
	for _, name := range []string{"registry.json", "settings.json"} {
		before, _ := os.ReadFile(filepath.Join(c.stateDir, name))
		after, err := os.ReadFile(filepath.Join(restored, name))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("upgrade changed IDs, configuration, selection or order", name, err)
		}
	}
}

func TestShippedPreservationRecoversEveryConnectionCommitBoundary(t *testing.T) {
	for cut := 1; cut <= 8; cut++ {
		t.Run(fmt.Sprint(cut), func(t *testing.T) {
			c := connectionAdmin(t)
			next := c.connections.Clone()
			if _, err := next.Import([]byte(publicConnectionURI)); err != nil {
				t.Fatal(err)
			}
			s := c.settings
			s.Order = connection.ReconcileOrder(next, s.Order)
			writes := 0
			func() {
				defer func() {
					if recover() == nil {
						t.Error("fault did not interrupt publication")
					}
				}()
				_ = commitConnectionState(c.stateDir, next, s, func(path string, data []byte) error {
					if err := privatefile.Write(path, data); err != nil {
						return err
					}
					writes++
					if writes == cut {
						panic("synthetic interrupted commit")
					}
					return nil
				})
			}()
			restored := copyShippedPreservation(t, c.stateDir)
			if err := recoverConnectionState(restored); err != nil {
				t.Fatal("backup lost pending transaction", err)
			}
			if err := migrateState(restored); err != nil {
				t.Fatal("backup cannot restart", err)
			}
			r, err := connection.Load(filepath.Join(restored, "registry.json"))
			settings, se := readSettingsAt(restored)
			want := 4
			if cut == 8 {
				want = 5
			}
			if err != nil || se != nil || len(r.Connections) != want || connection.ValidateOrder(r, settings.Order) != nil {
				t.Fatal("backup recovered wrong or mixed transaction")
			}
		})
	}
}

func TestShippedPreservationResumesMigrationFromFrozenSnapshot(t *testing.T) {
	for cut := 7; cut <= 9; cut++ {
		t.Run(fmt.Sprint(cut), func(t *testing.T) {
			dir, _, _ := legacyConnectionState(t)
			writes := 0
			err := migrateStateWith(dir, func(path string, data []byte) error {
				if err := privatefile.Write(path, data); err != nil {
					return err
				}
				writes++
				if writes == cut {
					return fmt.Errorf("synthetic interrupted migration")
				}
				return nil
			})
			if err == nil {
				t.Fatal("fault did not interrupt migration")
			}
			// Once prepared, recovery must use the private frozen source, even
			// when the original legacy file subsequently becomes invalid.
			if err := os.WriteFile(filepath.Join(dir, "profiles.json"), []byte("invalid legacy source"), 0600); err != nil {
				t.Fatal(err)
			}
			restored := copyShippedPreservation(t, dir)
			if err := migrateState(restored); err != nil {
				t.Fatal("backup lost prepared migration or private snapshot", err)
			}
			r, err := connection.Load(filepath.Join(restored, "registry.json"))
			if err != nil || len(r.Connections) != 4 {
				t.Fatal("migration backup changed connections", err)
			}
		})
	}
}
