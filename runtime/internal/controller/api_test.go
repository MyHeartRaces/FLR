package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/MyHeartRaces/FLR/runtime/internal/control"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
)

func testAdmin(t *testing.T) *Controller {
	t.Helper()
	c := New(DefaultSettings())
	c.stateDir = filepath.Join(t.TempDir(), "private")
	c.registry = &profile.Registry{Version: 1}
	c.available = map[string]bool{"sing-box": true}
	c.validateEngine = func(context.Context, profile.Profile) error { return nil }
	return c
}
func apiRequest(t *testing.T, s string) control.APIRequest {
	t.Helper()
	r, e := control.ParseAPI([]byte(s), false, false)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func TestNewSettingsRejectNaive(t *testing.T) {
	s := DefaultSettings()
	s.FamilyOrder = []string{"naive"}
	if err := ValidateSettings(s); err == nil {
		t.Fatal("removed Naive family accepted in new settings")
	}
	c := testAdmin(t)
	if _, err := c.HandleAPI(control.APIRequest{Operation: "settings", Settings: json.RawMessage(`{"family_order":["naive"]}`)}); err == nil {
		t.Fatal("API accepted removed Naive family")
	}
}
func TestAPIImportTransactionalRedactedAndDeleteSelection(t *testing.T) {
	c := testAdmin(t)
	content := `hysteria2://PUBLIC_TEST_PASSWORD@example.com:443/?obfs=salamander&obfs-password=PUBLIC_TEST_OBFS&sni=example.com`
	r := control.APIRequest{Operation: "import", Content: content}
	if _, e := c.HandleAPI(r); e != nil {
		t.Fatal(e)
	}
	id := c.registry.Profiles[0].ID
	b, _ := json.Marshal(c.registry.Summaries())
	if strings.Contains(string(b), "PUBLIC_TEST_PASSWORD") {
		t.Fatal("secret in summary")
	}
	before, _ := os.ReadFile(filepath.Join(c.stateDir, "profiles.json"))
	if _, e := c.HandleAPI(control.APIRequest{Operation: "import", Content: "invalid"}); e == nil {
		t.Fatal("invalid import accepted")
	}
	after, _ := os.ReadFile(filepath.Join(c.stateDir, "profiles.json"))
	if string(before) != string(after) {
		t.Fatal("failed import mutated private state")
	}
	if _, e := c.HandleAPI(control.APIRequest{Operation: "select", ID: id}); e != nil {
		t.Fatal(e)
	}
	if _, e := c.HandleAPI(control.APIRequest{Operation: "profile-delete", ID: id}); e != nil {
		t.Fatal(e)
	}
	if c.settings.ProfileSelection != "auto" {
		t.Fatal("deleted selected ID remains")
	}
}
func TestAPIInvalidPatchRollbackAndConcurrentRefreshImport(t *testing.T) {
	c := testAdmin(t)
	if _, e := c.HandleAPI(control.APIRequest{Operation: "settings", Settings: json.RawMessage(`{"family_order":["unknown"]}`)}); e == nil {
		t.Fatal("invalid settings accepted")
	}
	if len(c.settings.FamilyOrder) != 0 {
		t.Fatal("failed patch changed settings")
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.HandleAPI(control.APIRequest{Operation: "refresh"})
			c.HandleAPI(control.APIRequest{Operation: "profiles"})
		}()
	}
	wg.Wait()
}
func TestLegacySettingsMigrationAndStrictSettings(t *testing.T) {
	s, e := DecodeSettings([]byte(`{"options":{"lan":"br-lan","wan":"eth1","selection":{"general":"down","games":"down"},"manual_games":false},"dns_port":"1054","local_dns_port":"53"}`))
	if e != nil || !s.Enabled || s.Version != 1 || s.ProfileSelection != "auto" {
		t.Fatalf("migration: %#v %v", s, e)
	}
	if _, e = DecodeSettings([]byte(`{"unknown":true}`)); e == nil {
		t.Fatal("unknown stored settings accepted")
	}
}

func TestEngineRejectionKeepsRegistryAndSelection(t *testing.T) {
	c := testAdmin(t)
	called := false
	c.validateEngine = func(context.Context, profile.Profile) error { called = true; return os.ErrInvalid }
	if _, e := c.HandleAPI(control.APIRequest{Operation: "import", Content: `hysteria2://PUBLIC_TEST_PASSWORD@example.com:443/?obfs=salamander&obfs-password=PUBLIC_TEST_OBFS&sni=example.com`}); e == nil {
		t.Fatal("engine rejection accepted")
	}
	if !called {
		t.Fatal("fixture failed before the engine validator")
	}
	if len(c.registry.Profiles) != 0 || c.settings.ProfileSelection != "auto" {
		t.Fatal("rejected engine changed state")
	}
	if _, e := os.Stat(filepath.Join(c.stateDir, "profiles.json")); !os.IsNotExist(e) {
		t.Fatal("rejected engine persisted credentials")
	}
}
func TestPrimaryAWGReadNeverReturnsKeys(t *testing.T) {
	c := testAdmin(t)
	raw := "[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nHeaderProtectionKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress = 10.77.0.2/32\nS1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\n[Peer]\nPublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nPresharedKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nEndpoint = 192.0.2.10:51820\n"
	data, e := c.HandleAPI(control.APIRequest{Operation: "primary-awg", Content: raw})
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(data)
	if strings.Contains(string(b), "AQEBA") || strings.Contains(string(b), "PrivateKey") {
		t.Fatal("AWG response exposes keys")
	}
	if c.settings.Enabled {
		t.Fatal("AWG import activated VPN")
	}
}

func TestPrivateSettingsRejectSymlinksAndOversizeState(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.json")
	b, _ := json.Marshal(DefaultSettings())
	if e := os.WriteFile(source, b, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(source, filepath.Join(dir, "settings.json")); e != nil {
		t.Fatal(e)
	}
	if _, e := readSettingsAt(dir); e == nil {
		t.Fatal("symlink settings accepted")
	}
	os.Remove(filepath.Join(dir, "settings.json"))
	os.WriteFile(filepath.Join(dir, "settings.json"), []byte(strings.Repeat("x", (1<<20)+1)), 0600)
	if _, e := readSettingsAt(dir); e == nil {
		t.Fatal("oversize state accepted")
	}
}

func TestRollbackConfirmRejectsInactiveController(t *testing.T) {
	c := testAdmin(t)
	if _, e := c.HandleAPI(control.APIRequest{Operation: "rollback-confirm", Accepted: true}); e == nil {
		t.Fatal("inactive configuration confirmed")
	}
}

func TestConcurrentRefreshAndUniqueImportsRemainSerialized(t *testing.T) {
	c := testAdmin(t)
	var wg sync.WaitGroup
	failures := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c.HandleAPI(control.APIRequest{Operation: "refresh"})
			_, e := c.HandleAPI(control.APIRequest{Operation: "import", Content: fmt.Sprintf("hysteria2://PUBLIC_TEST_PASSWORD_%d@example.com:443/?obfs=salamander&obfs-password=PUBLIC_TEST_OBFS&sni=example.com", i)})
			failures <- e
		}(i)
	}
	wg.Wait()
	close(failures)
	for e := range failures {
		if e != nil {
			t.Fatal(e)
		}
	}
	if len(c.registry.Profiles) != 10 {
		t.Fatal("concurrent imports lost a committed profile")
	}
	loaded, e := profile.Load(filepath.Join(c.stateDir, "profiles.json"))
	if e != nil || len(loaded.Profiles) != 10 {
		t.Fatalf("private transaction store: %v", e)
	}
}

func TestInvalidOfflineDisablePatchHasNoDeactivationSideEffect(t *testing.T) {
	for _, patch := range []string{`{"enabled":false,"family_order":["unknown"]}`, `{"enabled":false,"profile_selection":"missing"}`, `{"enabled":false,"primary_group":"bad://group"}`} {
		t.Run(patch, func(t *testing.T) {
			c := testAdmin(t)
			c.settings.Enabled = true
			called := 0
			c.deactivate = func(string) error { called++; return nil }
			if _, e := c.HandleAPI(control.APIRequest{Operation: "settings", Settings: json.RawMessage(patch)}); e == nil {
				t.Fatal("invalid patch accepted")
			}
			if called != 0 || !c.settings.Enabled {
				t.Fatal("invalid patch deactivated or changed settings")
			}
		})
	}
}

func TestOfflineDisablePersistenceFailureHasNoNativeEffect(t *testing.T) {
	c := testAdmin(t)
	c.settings.Enabled = true
	if e := os.MkdirAll(filepath.Join(c.stateDir, "settings.json"), 0700); e != nil {
		t.Fatal(e)
	}
	called := 0
	c.deactivate = func(string) error { called++; return nil }
	if _, e := c.HandleAPI(control.APIRequest{Operation: "settings", Settings: json.RawMessage(`{"enabled":false}`)}); e == nil {
		t.Fatal("persistence failure ignored")
	}
	if called != 0 || !c.settings.Enabled {
		t.Fatal("persistence failure changed native or desired state")
	}
}

func TestOfflineDisableRetainsDisabledIntentAndRetriesNativeFailure(t *testing.T) {
	c := testAdmin(t)
	c.settings.Enabled = true
	called := 0
	c.deactivate = func(string) error {
		called++
		stored, e := readSettingsAt(c.stateDir)
		if e != nil || stored.Enabled {
			t.Fatal("native teardown ran before disabled intent was saved")
		}
		if called == 1 {
			return os.ErrInvalid
		}
		return nil
	}
	request := control.APIRequest{Operation: "settings", Settings: json.RawMessage(`{"enabled":false}`)}
	if _, e := c.HandleAPI(request); e == nil {
		t.Fatal("native failure ignored")
	}
	if c.settings.Enabled {
		t.Fatal("native failure lost disabled intent")
	}
	if _, e := c.HandleAPI(request); e != nil {
		t.Fatal(e)
	}
	if called != 2 {
		t.Fatal("incomplete deactivation was not retried")
	}
	if _, e := c.HandleAPI(request); e != nil {
		t.Fatal(e)
	}
	if called != 2 {
		t.Fatal("completed disable repeated native effects")
	}
}

func TestFreshOfflineControllerRetriesDisabledIntentWithRecoveryMarker(t *testing.T) {
	for _, markerName := range []string{"owner.json", "rollback.pending"} {
		t.Run(markerName, func(t *testing.T) {
			c := testAdmin(t)
			c.settings.Enabled = true
			markerDir := t.TempDir()
			owner := filepath.Join(markerDir, "owner.json")
			pending := filepath.Join(markerDir, "rollback.pending")
			markerPath := filepath.Join(markerDir, markerName)
			if e := os.WriteFile(markerPath, []byte("public recovery marker"), 0600); e != nil {
				t.Fatal(e)
			}
			c.recoveryPending = func() bool { return deactivationMarkers(owner, pending) }
			c.deactivate = func(string) error { return os.ErrInvalid }
			request := control.APIRequest{Operation: "settings", Settings: json.RawMessage(`{"enabled":false}`)}
			if _, e := c.HandleAPI(request); e == nil {
				t.Fatal("native failure ignored")
			}
			stored, e := readSettingsAt(c.stateDir)
			if e != nil || stored.Enabled {
				t.Fatal("disabled intent was not persisted")
			}
			fresh := testAdmin(t)
			fresh.stateDir = c.stateDir
			fresh.settings = stored
			fresh.recoveryPending = func() bool { return deactivationMarkers(owner, pending) }
			calls := 0
			fresh.deactivate = func(string) error { calls++; return os.Remove(markerPath) }
			data, e := fresh.HandleAPI(control.APIRequest{Operation: "status"})
			if e != nil || !data.(map[string]any)["deactivation_pending"].(bool) {
				t.Fatal("fresh controller hid incomplete native restoration")
			}
			if _, e = fresh.HandleAPI(request); e != nil {
				t.Fatal(e)
			}
			if calls != 1 || deactivationMarkers(owner, pending) {
				t.Fatal("fresh offline controller did not retry recovery marker")
			}
			data, e = fresh.HandleAPI(control.APIRequest{Operation: "status"})
			if e != nil || data.(map[string]any)["deactivation_pending"].(bool) {
				t.Fatal("completed restoration remained pending")
			}
			if _, e = fresh.HandleAPI(request); e != nil {
				t.Fatal(e)
			}
			if calls != 1 {
				t.Fatal("clean disabled state repeated teardown")
			}
		})
	}
}

func TestDirectBypassCompleteBoundedAndAtomic(t *testing.T) {
	c := testAdmin(t)
	for _, bad := range []string{`{"tcp":"fake","quic":"off"}`, `{"enabled":null,"tcp":"fake","quic":"off"}`, `{"enabled":true,"tcp":"--lua-init=@/tmp/a","quic":"off"}`, `{"enabled":true,"tcp":"off","quic":"off"}`, `{"enabled":false,"tcp":"off","quic":"off","args":[]}`} {
		_, e := c.HandleAPI(apiRequest(t, `{"operation":"settings","settings":{"enabled":false,"direct_bypass":`+bad+`}}`))
		if e == nil {
			t.Fatal("invalid direct bypass accepted", bad)
		}
		if c.settings.DirectBypass.Enabled {
			t.Fatal("invalid patch changed settings")
		}
	}
	for _, enabled := range []string{"true", "false"} {
		if _, e := c.HandleAPI(apiRequest(t, `{"operation":"settings","settings":{"direct_bypass":{"enabled":`+enabled+`,"tcp":"fake","quic":"off"}}}`)); e != nil {
			t.Fatal(e)
		}
	}
	b, _ := json.Marshal(DefaultSettings())
	var fields map[string]json.RawMessage
	json.Unmarshal(b, &fields)
	fields["direct_bypass"] = json.RawMessage(`{"enabled":null,"tcp":"fake","quic":"off"}`)
	b, _ = json.Marshal(fields)
	if _, e := DecodeSettings(b); e == nil {
		t.Fatal("stored null enable accepted")
	}
}
