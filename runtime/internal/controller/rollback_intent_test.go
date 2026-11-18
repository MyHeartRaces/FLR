package controller

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/privatefile"
	"github.com/MyHeartRaces/FLR/runtime/internal/rollbackintent"
)

func rollbackV2State(t *testing.T, legacy bool) (string, Settings) {
	t.Helper()
	var dir string
	if legacy {
		dir, _, _ = legacyConnectionState(t)
	} else {
		dir = filepath.Join(t.TempDir(), "private")
	}
	if err := migrateState(dir); err != nil {
		t.Fatal(err)
	}
	r, err := connection.Load(filepath.Join(dir, "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	items, err := r.Import([]byte(publicConnectionURI))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Save(filepath.Join(dir, "registry.json")); err != nil {
		t.Fatal(err)
	}
	s, err := readSettingsAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.Enabled = true
	s.DirectProxy.Enabled = true
	s.DirectBypass.Enabled = true
	s.DirectBypass.TCP = "fake"
	s.SavedGeneration = 50
	s.Selection = connection.Selection{Mode: "connection", ID: items[0].ID}
	s.Order = connection.DefaultOrder(r)
	if err := WriteJSON(filepath.Join(dir, "settings.json"), s); err != nil {
		t.Fatal(err)
	}
	return dir, s
}

// A rollback must disable intent after any checkpoint recovery, never delete
// the settings that make an existing registry authoritative.
func TestRollbackIntentKeepsCleanAndMigratedV2Connections(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint(legacy), func(t *testing.T) {
			dir, before := rollbackV2State(t, legacy)
			registry, err := os.ReadFile(filepath.Join(dir, "registry.json"))
			if err != nil {
				t.Fatal(err)
			}
			intent := filepath.Join(dir, "rollback.disabled")
			if err := privatefile.Write(intent, []byte("disable-v1\n")); err != nil {
				t.Fatal(err)
			}
			if err := recoverConnectionState(dir); err != nil {
				t.Fatal(err)
			}
			if err := migrateState(dir); err != nil {
				t.Fatal("rollback prevented the next administrative settings read", err)
			}
			after, err := readSettingsAt(dir)
			if err != nil || after.Version != 2 || after.Enabled || after.DirectProxy.Enabled || after.DirectBypass.Enabled {
				t.Fatal("completed recovery retained enabled runtime settings", err)
			}
			if after.Selection != before.Selection || !reflect.DeepEqual(after.Order, before.Order) || after.SavedGeneration != 51 {
				t.Fatal("recovery lost pinned selection/order or allowed a stale generation")
			}
			if raw, err := os.ReadFile(filepath.Join(dir, "registry.json")); err != nil || string(raw) != string(registry) {
				t.Fatal("rollback/restart changed v2 connections", err)
			}
			if _, err := os.Stat(intent); !os.IsNotExist(err) {
				t.Fatal("durably disabled state did not consume recovery intent")
			}
			if err := migrateState(dir); err != nil {
				t.Fatal(err)
			}
			again, err := readSettingsAt(dir)
			if err != nil || again.SavedGeneration != 51 || again.Enabled || again.DirectProxy.Enabled {
				t.Fatal("repeated startup changed completed recovery", err)
			}
		})
	}
}

func TestStableV2RegistryNeverReimportsMissingOrLegacySettings(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, missing := range []bool{false, true} {
			t.Run(fmt.Sprintf("legacy=%v/missing=%v", legacy, missing), func(t *testing.T) {
				dir, _ := rollbackV2State(t, legacy)
				registry, _ := os.ReadFile(filepath.Join(dir, "registry.json"))
				path := filepath.Join(dir, "settings.json")
				if missing {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				} else if legacy {
					raw, err := privatefile.Read(filepath.Join(dir, "migration-v1", "settings.json"), 1<<20)
					if err != nil {
						t.Fatal(err)
					}
					if err := privatefile.Write(path, raw); err != nil {
						t.Fatal(err)
					}
				} else if err := WriteJSON(path, DefaultSettings()); err != nil {
					t.Fatal(err)
				}
				if err := migrateState(dir); err == nil {
					t.Fatal("existing registry allowed a second legacy migration")
				}
				if after, err := os.ReadFile(filepath.Join(dir, "registry.json")); err != nil || string(after) != string(registry) {
					t.Fatal("missing/downgraded settings erased imported connections", err)
				}
			})
		}
	}
}

func TestRollbackIntentOverridesRecoveredConnectionCheckpoint(t *testing.T) {
	for cut := 1; cut <= 8; cut++ {
		t.Run(fmt.Sprint(cut), func(t *testing.T) {
			dir, before := rollbackV2State(t, true)
			r, err := connection.Load(filepath.Join(dir, "registry.json"))
			if err != nil {
				t.Fatal(err)
			}
			next := r.Clone()
			if _, err := next.Import([]byte(strings.Replace(publicConnectionURI, "192.0.2.90", "192.0.2.91", 1))); err != nil {
				t.Fatal(err)
			}
			settings := before
			settings.Order = connection.ReconcileOrder(next, settings.Order)
			writes := 0
			func() {
				defer func() {
					if recover() == nil {
						t.Error("checkpoint fault did not occur")
					}
				}()
				_ = commitConnectionState(dir, next, settings, func(path string, raw []byte) error {
					if err := privatefile.Write(path, raw); err != nil {
						return err
					}
					writes++
					if writes == cut {
						panic("simulated process exit")
					}
					return nil
				})
			}()
			if err := privatefile.Write(filepath.Join(dir, "rollback.disabled"), []byte("disable-v1\n")); err != nil {
				t.Fatal(err)
			}
			if err := recoverConnectionState(dir); err != nil {
				t.Fatal(err)
			}
			if err := migrateState(dir); err != nil {
				t.Fatal(err)
			}
			recovered, err := connection.Load(filepath.Join(dir, "registry.json"))
			s, settingsErr := readSettingsAt(dir)
			want := 5
			if cut == 8 {
				want = 6
			}
			if err != nil || settingsErr != nil || len(recovered.Connections) != want || connection.ValidateOrder(recovered, s.Order) != nil || s.Selection != before.Selection {
				t.Fatal("rollback lost the recovered coherent connection state", err, settingsErr)
			}
			if s.Enabled || s.DirectProxy.Enabled || s.DirectBypass.Enabled || s.SavedGeneration != 51 {
				t.Fatal("checkpoint recovery undid rollback's disabled intent")
			}
		})
	}
}

func TestRollbackIntentOverridesInterruptedMigration(t *testing.T) {
	for cut := 1; cut <= 9; cut++ {
		t.Run(fmt.Sprint(cut), func(t *testing.T) {
			dir, before, _ := legacyConnectionState(t)
			before.SavedGeneration = 50
			before.DirectBypass.Enabled = true
			before.DirectBypass.TCP = "fake"
			if err := WriteJSON(filepath.Join(dir, "settings.json"), before); err != nil {
				t.Fatal(err)
			}
			writes := 0
			if err := migrateStateWith(dir, func(path string, raw []byte) error {
				if err := privatefile.Write(path, raw); err != nil {
					return err
				}
				writes++
				if writes == cut {
					return fmt.Errorf("public simulated migration crash")
				}
				return nil
			}); err == nil {
				t.Fatal("migration crash did not occur")
			}
			if err := privatefile.Write(filepath.Join(dir, "rollback.disabled"), []byte("disable-v1\n")); err != nil {
				t.Fatal(err)
			}
			if err := recoverConnectionState(dir); err != nil {
				t.Fatal(err)
			}
			if err := migrateState(dir); err != nil {
				t.Fatal(err)
			}
			r, err := connection.Load(filepath.Join(dir, "registry.json"))
			s, settingsErr := readSettingsAt(dir)
			if err != nil || settingsErr != nil || len(r.Connections) != 4 || s.Enabled || s.DirectProxy.Enabled || s.DirectBypass.Enabled || s.SavedGeneration != 51 {
				t.Fatal("migration recovery undid rollback or lost imported state", err, settingsErr)
			}
		})
	}
}

func TestRollbackRejectsMalformedIntentWithoutChangingState(t *testing.T) {
	dir, _ := rollbackV2State(t, false)
	before, _ := os.ReadFile(filepath.Join(dir, "settings.json"))
	intent := filepath.Join(dir, "rollback.disabled")
	if err := privatefile.Write(intent, []byte("invalid-public-marker\n")); err != nil {
		t.Fatal(err)
	}
	if err := migrateState(dir); err == nil {
		t.Fatal("malformed rollback intent ignored")
	}
	if after, err := os.ReadFile(filepath.Join(dir, "settings.json")); err != nil || string(after) != string(before) {
		t.Fatal("invalid intent changed saved settings", err)
	}
	if _, err := os.Stat(intent); err != nil {
		t.Fatal("invalid intent lost recovery evidence", err)
	}
}

func TestRollbackIntentSurvivesFailedDisabledPublicationAndCleanup(t *testing.T) {
	for _, failure := range []string{"before-write", "after-write", "before-clear"} {
		t.Run(failure, func(t *testing.T) {
			dir, _ := rollbackV2State(t, true)
			if err := rollbackintent.Mark(dir); err != nil {
				t.Fatal(err)
			}
			write := func(path string, raw []byte) error {
				if failure == "before-write" {
					return fmt.Errorf("public disk failure")
				}
				if err := privatefile.Write(path, raw); err != nil {
					return err
				}
				if failure == "after-write" {
					return fmt.Errorf("public failed sync acknowledgement")
				}
				return nil
			}
			if err := migrateAndDisableWith(dir, write, func(string) error { return fmt.Errorf("public intent removal failure") }); err == nil {
				t.Fatal("publication/cleanup error ignored")
			}
			if pending, err := rollbackintent.Pending(dir); err != nil || !pending {
				t.Fatal("failed recovery discarded intent", err)
			}
			if err := migrateState(dir); err != nil {
				t.Fatal("failed recovery could not retry", err)
			}
			s, err := readSettingsAt(dir)
			if err != nil || s.Enabled || s.DirectProxy.Enabled || s.DirectBypass.Enabled || s.SavedGeneration != 51 {
				t.Fatal("replayed recovery reenabled runtime or counted twice", err)
			}
		})
	}
}

func TestRollbackDisablesAtMaximumSavedGeneration(t *testing.T) {
	dir, s := rollbackV2State(t, false)
	s.SavedGeneration = (1 << 53) - 1
	if err := WriteJSON(filepath.Join(dir, "settings.json"), s); err != nil {
		t.Fatal(err)
	}
	if err := rollbackintent.Mark(dir); err != nil {
		t.Fatal(err)
	}
	if err := migrateState(dir); err != nil {
		t.Fatal("terminal generation prevented safe recovery", err)
	}
	after, err := readSettingsAt(dir)
	if err != nil || after.Enabled || after.DirectProxy.Enabled || after.DirectBypass.Enabled || after.SavedGeneration != s.SavedGeneration {
		t.Fatal("terminal generation overflowed or retained enabled settings", err)
	}
}

func TestRollbackInvalidatesInitialZeroSavedGeneration(t *testing.T) {
	dir, s := rollbackV2State(t, false)
	s.SavedGeneration = 0
	if err := WriteJSON(filepath.Join(dir, "settings.json"), s); err != nil {
		t.Fatal(err)
	}
	initial := New(s).Status().Generation
	if err := rollbackintent.Mark(dir); err != nil {
		t.Fatal(err)
	}
	if err := migrateState(dir); err != nil {
		t.Fatal(err)
	}
	after, err := readSettingsAt(dir)
	if err != nil || after.SavedGeneration <= initial || after.Enabled {
		t.Fatal("rollback reused initial displayed generation", err, initial, after.SavedGeneration)
	}
}
