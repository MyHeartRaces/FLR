package controller

import (
	"encoding/json"
	"fmt"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/transport"
	"os"
	"path/filepath"
	"testing"

	"github.com/MyHeartRaces/FLR/runtime/internal/control"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
)

func TestHealthPolicyDefaultsAndInvalidPatchPreservesSettings(t *testing.T) {
	c := testAdmin(t)
	if c.settings.HealthPolicy != health.DefaultPolicy() {
		t.Fatal("missing clean default")
	}
	raw, _ := json.Marshal(c.settings)
	var old map[string]json.RawMessage
	json.Unmarshal(raw, &old)
	delete(old, "health_policy")
	raw, _ = json.Marshal(old)
	migrated, e := DecodeSettings(raw)
	if e != nil || migrated.HealthPolicy != health.DefaultPolicy() {
		t.Fatal("legacy health defaults", e)
	}
	p := health.DefaultPolicy()
	p.Enabled = false
	b, _ := json.Marshal(map[string]any{"health_policy": p})
	if _, e = c.HandleAPI(control.APIRequest{Operation: "settings", Settings: b}); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(filepath.Join(c.stateDir, "settings.json"))
	if e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{`null`, `{}`, `{"enabled":true}`, `{"enabled":null}`, `{"unknown":1}`} {
		b = []byte(`{"enabled":false,"primary_group":"changed","health_policy":` + bad + `}`)
		if _, e = c.HandleAPI(control.APIRequest{Operation: "settings", Settings: b}); e == nil {
			t.Fatal("accepted incomplete policy", bad)
		}
		after, _ := os.ReadFile(filepath.Join(c.stateDir, "settings.json"))
		if string(before) != string(after) || c.settings.PrimaryGroup != "" || c.settings.HealthPolicy.Enabled {
			t.Fatal("invalid update changed settings")
		}
	}
	p.WindowSeconds = 999
	b, _ = json.Marshal(map[string]any{"health_policy": p})
	if _, e = c.HandleAPI(control.APIRequest{Operation: "settings", Settings: b}); e == nil {
		t.Fatal("invalid policy persisted")
	}
}

func TestAWGDegradationCleanupFailureRemainsDownAndRetries(t *testing.T) {
	c := testAdmin(t)
	c.selection = contract.Selection{General: contract.AWG, Games: contract.AWG}
	failed := true
	clears := 0
	published := []contract.Selection{}
	c.publishSelection = func(s contract.Selection) error { published = append(published, s); return nil }
	c.clearAWG = func() error {
		clears++
		if failed {
			return fmt.Errorf("cleanup failed")
		}
		return nil
	}
	before := transport.Snapshot{AWG: health.State{Up: true}}
	next := transport.Snapshot{AWG: health.State{Initialized: true, Degraded: true, Reason: "sustained_latency"}, Selection: contract.Selection{General: contract.Gecko, Games: contract.Gecko}}
	c.publishTransport(before, next)
	if c.selection.General != contract.Down || !c.awgCleanupPending || clears != 1 || c.lastError == "" {
		t.Fatal("cleanup failure was ignored")
	}
	failed = false
	c.publishTransport(next, next)
	if c.selection.General != contract.Gecko || c.awgCleanupPending || clears != 2 {
		t.Fatal("pending cleanup not retried")
	}
	if len(published) < 2 || published[0].General != contract.Down {
		t.Fatal("backup published before cleanup")
	}
}
func TestAWGCleanupRetriesAfterSelectionPublicationFailure(t *testing.T) {
	c := testAdmin(t)
	c.selection = contract.Selection{General: contract.AWG, Games: contract.AWG}
	failed := true
	clears := 0
	c.publishSelection = func(contract.Selection) error {
		if failed {
			return fmt.Errorf("nft failed")
		}
		return nil
	}
	c.clearAWG = func() error { clears++; return nil }
	before := transport.Snapshot{AWG: health.State{Up: true}}
	next := transport.Snapshot{Selection: contract.Selection{General: contract.Down, Games: contract.Down}}
	c.publishTransport(before, next)
	if !c.awgCleanupPending || clears != 0 {
		t.Fatal("cleanup skipped failed publication")
	}
	failed = false
	c.publishTransport(next, next)
	if c.awgCleanupPending || clears != 1 || c.selection.General != contract.Down {
		t.Fatal("publication retry did not clear AWG")
	}
}
