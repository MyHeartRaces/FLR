package controller

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"github.com/MyHeartRaces/FLR/runtime/internal/privatefile"
)

func TestOfflineAdminCannotReenableFromPreRollbackSettingsSnapshot(t *testing.T) {
	for _, consumed := range []bool{false, true} {
		for _, versioned := range []bool{false, true} {
			t.Run(fmt.Sprintf("consumed=%v/versioned=%v", consumed, versioned), func(t *testing.T) {
				dir, before := rollbackV2State(t, false)
				// Offline API owns singleton and snapshots enabled settings, then
				// timer recovery occurs before it reacquires admin.lock in HandleAPI.
				c := New(before)
				c.stateDir = dir
				c.available = map[string]bool{"sing-box": true, "awg": true}
				if err := c.initializeAdmin(false); err != nil {
					t.Fatal(err)
				}
				if consumed {
					// Another startup has already finished durable recovery. The
					// stale process must honor saved state even without a marker.
					disabled := before
					disabled.Enabled, disabled.DirectProxy.Enabled, disabled.DirectBypass.Enabled = false, false, false
					disabled.SavedGeneration++
					if err := WriteJSON(filepath.Join(dir, "settings.json"), disabled); err != nil {
						t.Fatal(err)
					}
				} else if err := privatefile.Write(filepath.Join(dir, "rollback.disabled"), []byte("disable-v1\n")); err != nil {
					t.Fatal(err)
				}
				fields := map[string]any{"operation": "settings", "settings": map[string]any{"health_policy": health.DefaultPolicy()}}
				if versioned {
					fields = map[string]any{"operation": "selection", "selection": before.Selection, "expected_generation": before.SavedGeneration}
				}
				raw, _ := json.Marshal(fields)
				_, err := c.HandleAPI(apiRequest(t, string(raw)))
				if versioned {
					if err == nil || !strings.Contains(err.Error(), "state changed") {
						t.Fatal("stale pre-rollback edit was not rejected", err)
					}
				} else if err != nil {
					t.Fatal("unversioned compatibility edit could not use current disabled settings", err)
				}
				s, err := readSettingsAt(dir)
				if err != nil || s.Enabled || s.DirectProxy.Enabled || s.DirectBypass.Enabled {
					t.Fatal("ordinary settings edit reenabled services from stale snapshot", err)
				}
				if c.Status().Generation < before.SavedGeneration+1 {
					t.Fatal("offline process ignored saved recovery generation")
				}
			})
		}
	}
}
