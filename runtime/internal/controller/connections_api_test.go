package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/control"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
)

func connectionAdmin(t *testing.T) *Controller {
	t.Helper()
	dir, _, _ := legacyConnectionState(t)
	if err := migrateState(dir); err != nil {
		t.Fatal(err)
	}
	s, err := readSettingsAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	c := New(s)
	c.stateDir = dir
	c.available = map[string]bool{"sing-box": true, "awg": true, "xray": true, "wstunnel": true}
	c.validateEngine = func(context.Context, profile.Profile) error { return nil }
	if err := c.initializeAdmin(false); err != nil {
		t.Fatal(err)
	}
	return c
}
func connectionRequest(t *testing.T, c *Controller, operation string, fields map[string]any) control.APIRequest {
	t.Helper()
	if fields == nil {
		fields = map[string]any{}
	}
	fields["operation"] = operation
	if operation != "connection-list" {
		fields["expected_generation"] = c.Status().Generation
	}
	raw, _ := json.Marshal(fields)
	return apiRequest(t, string(raw))
}

const publicConnectionURI = "hy2://PUBLIC_TEST_PASSWORD@192.0.2.90:443?obfs=salamander&obfs-password=PUBLIC_TEST_OBFS"

func TestConnectionAPIAtomicImportReplaceMetadataAndPinnedDelete(t *testing.T) {
	c := connectionAdmin(t)
	if _, err := c.HandleAPI(connectionRequest(t, c, "connection-import", map[string]any{"data": publicConnectionURI})); err != nil {
		t.Fatal(err)
	}
	last := c.connections.Connections[len(c.connections.Connections)-1]
	if _, err := c.HandleAPI(connectionRequest(t, c, "selection", map[string]any{"selection": connection.Selection{Mode: "connection", ID: last.ID}})); err != nil {
		t.Fatal(err)
	}
	if _, err := c.HandleAPI(connectionRequest(t, c, "connection-update", map[string]any{"id": last.ID, "metadata": map[string]any{"name": "PUBLIC_TEST_PASSWORD", "group": "PUBLIC_TEST_OBFS", "enabled": false}})); err != nil {
		t.Fatal(err)
	}
	if c.settings.Selection.ID != last.ID || c.settings.Selection.Mode != "connection" {
		t.Fatal("disabled pinned selection changed")
	}
	result, err := c.HandleAPI(connectionRequest(t, c, "connection-list", nil))
	encoded, _ := json.Marshal(result)
	if err != nil || strings.Contains(string(encoded), "PUBLIC_TEST_PASSWORD") || strings.Contains(string(encoded), "PUBLIC_TEST_OBFS") || strings.Contains(string(encoded), "private_key") {
		t.Fatal("public list exposed credentials", err)
	}
	if _, err := c.HandleAPI(connectionRequest(t, c, "connection-replace", map[string]any{"id": last.ID, "data": strings.Replace(publicConnectionURI, "192.0.2.90", "192.0.2.91", 1)})); err != nil {
		t.Fatal(err)
	}
	replaced := c.connections.Connections[len(c.connections.Connections)-1]
	if replaced.ID != last.ID || replaced.Revision == last.Revision || replaced.Enabled {
		t.Fatal("replacement lost stable identity or enabled metadata")
	}
	if _, err := c.HandleAPI(connectionRequest(t, c, "connection-delete", map[string]any{"id": last.ID})); err == nil {
		t.Fatal("pinned deletion silently entered auto")
	}
	if _, err := c.HandleAPI(connectionRequest(t, c, "connection-delete", map[string]any{"id": last.ID, "selection": connection.Selection{Mode: "auto"}})); err != nil {
		t.Fatal(err)
	}
	r, err := connection.Load(filepath.Join(c.stateDir, "registry.json"))
	s, se := readSettingsAt(c.stateDir)
	if err != nil || se != nil || s.Selection.Mode != "auto" || connection.ValidateOrder(r, s.Order) != nil {
		t.Fatal("deletion persisted inconsistent registry/order")
	}
}

func TestConnectionAPIFailedValidationStorageAndStaleGenerationAreAtomic(t *testing.T) {
	for _, failure := range []string{"engine", "storage", "stale"} {
		c := connectionAdmin(t)
		before, _ := os.ReadFile(filepath.Join(c.stateDir, "registry.json"))
		settingsBefore, _ := os.ReadFile(filepath.Join(c.stateDir, "settings.json"))
		request := connectionRequest(t, c, "connection-import", map[string]any{"data": publicConnectionURI})
		if failure == "engine" {
			c.validateEngine = func(context.Context, profile.Profile) error { return fmt.Errorf("PUBLIC_TEST_PASSWORD") }
		}
		if failure == "storage" {
			c.writeConnectionState = func(string, []byte) error { return fmt.Errorf("public storage failure") }
		}
		if failure == "stale" {
			c.mu.Lock()
			c.generation++
			c.mu.Unlock()
		}
		if _, err := c.HandleAPI(request); err == nil || strings.Contains(err.Error(), "PUBLIC_TEST_PASSWORD") {
			t.Fatal("failed mutation accepted or leaked private validator diagnostic")
		}
		after, _ := os.ReadFile(filepath.Join(c.stateDir, "registry.json"))
		settingsAfter, _ := os.ReadFile(filepath.Join(c.stateDir, "settings.json"))
		if string(before) != string(after) || string(settingsBefore) != string(settingsAfter) || len(c.connections.Connections) != 4 {
			t.Fatal("failed mutation changed private or in-memory state")
		}
	}
}

func TestConnectionCompatibilityPreservesLogicalIDsAndPinnedDisable(t *testing.T) {
	c := connectionAdmin(t)
	if _, err := c.HandleAPI(control.APIRequest{Operation: "import", Content: publicConnectionURI}); err != nil {
		t.Fatal(err)
	}
	item := c.connections.Connections[len(c.connections.Connections)-1]
	if _, err := c.HandleAPI(control.APIRequest{Operation: "select", ID: item.ID}); err != nil {
		t.Fatal(err)
	}
	no := false
	if _, err := c.HandleAPI(control.APIRequest{Operation: "profile-update", ID: item.ID, Enabled: &no}); err != nil {
		t.Fatal(err)
	}
	if c.settings.Selection.ID != item.ID {
		t.Fatal("legacy adapter changed disabled pinned choice")
	}
	if _, err := c.HandleAPI(control.APIRequest{Operation: "profile-delete", ID: item.ID}); err == nil {
		t.Fatal("legacy adapter bypassed explicit pinned delete transition")
	}
	list, err := c.HandleAPI(control.APIRequest{Operation: "profiles"})
	raw, _ := json.Marshal(list)
	if err != nil || !strings.Contains(string(raw), item.ID) || strings.Contains(string(raw), "PUBLIC_TEST_PASSWORD") {
		t.Fatal("compatibility list lost logical identity or exposed payload")
	}
}

func TestConnectionImportedOnlyGuardedActivation(t *testing.T) {
	c := connectionAdmin(t)
	kept := []connection.Connection{}
	for _, item := range c.connections.Connections {
		if item.Family != "awg" {
			kept = append(kept, item)
		}
	}
	c.connections.Connections = kept
	c.settings.Enabled = false
	c.settings.Order = connection.DefaultOrder(c.connections)
	if err := c.connections.Save(filepath.Join(c.stateDir, "registry.json")); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(filepath.Join(c.stateDir, "settings.json"), c.settings); err != nil {
		t.Fatal(err)
	}
	armed := false
	c.activateVPN = func(_ context.Context, settings Settings, awg *connection.Connection) error {
		if awg != nil || !settings.Enabled {
			t.Fatal("imported-only activation invented AWG or skipped enabled intent")
		}
		armed = true
		return nil
	}
	if _, err := c.HandleAPI(connectionRequest(t, c, "vpn-activate", map[string]any{"accepted": true})); err != nil {
		t.Fatal(err)
	}
	if !armed || !c.settings.Enabled {
		t.Fatal("imported-only guarded activation failed")
	}
}

func TestConnectionLegacySettingsCannotSilentlyIgnorePolicy(t *testing.T) {
	for _, settings := range []string{`{"profile_selection":"auto"}`, `{"family_order":["reality"]}`, `{"primary_group":"srvmain"}`} {
		c := connectionAdmin(t)
		before := mustJSON(c.settings)
		_, err := c.HandleAPI(control.APIRequest{Operation: "settings", Settings: json.RawMessage(settings)})
		if err == nil || string(before) != string(mustJSON(c.settings)) {
			t.Fatal("obsolete policy accepted without updating unified selection")
		}
	}
}

func TestConnectionGenerationSurvivesOfflineProcessRestart(t *testing.T) {
	c := connectionAdmin(t)
	stale := c.Status().Generation
	request := connectionRequest(t, c, "connection-update", map[string]any{"id": c.connections.Connections[0].ID, "metadata": map[string]any{"name": "updated"}})
	if _, err := c.HandleAPI(request); err != nil {
		t.Fatal(err)
	}
	settings, err := readSettingsAt(c.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	restarted := New(settings)
	restarted.stateDir = c.stateDir
	restarted.available = c.available
	if err := restarted.initializeAdmin(false); err != nil {
		t.Fatal(err)
	}
	request.ExpectedGeneration = &stale
	if _, err := restarted.HandleAPI(request); err == nil {
		t.Fatal("stale edit accepted after offline process restart")
	}
}
