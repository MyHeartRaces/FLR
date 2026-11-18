package controller

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/MyHeartRaces/FLR/runtime/internal/control"
)

func readinessSettings(t *testing.T, group string, bypass string) []byte {
	t.Helper()
	b, err := json.Marshal(DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	fields["primary_group"] = json.RawMessage(group)
	fields["direct_bypass"] = json.RawMessage(bypass)
	b, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestStoredBypassEmptyPresetsNormalizeWithoutLosingState(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		enabled bool
		tcp     string
		quic    string
	}{
		{`{"enabled":false,"tcp":"","quic":""}`, false, "off", "off"},
		{`{"enabled":true,"tcp":"fake","quic":""}`, true, "fake", "off"},
		{`{"enabled":true,"tcp":"","quic":"fake"}`, true, "off", "fake"},
	} {
		s, err := DecodeSettings(readinessSettings(t, `""`, tc.raw))
		if err != nil {
			t.Fatal("previously valid stored bypass rejected", tc.raw, err)
		}
		if s.DirectBypass.Enabled != tc.enabled || s.DirectBypass.TCP != tc.tcp || s.DirectBypass.QUIC != tc.quic {
			t.Fatal("stored bypass changed meaning", s.DirectBypass)
		}
	}
}

func TestStoredLegacyGroupReadOfflineEditSaveReload(t *testing.T) {
	for _, size := range []int{81, 128} {
		group := strings.Repeat("a", size)
		b := readinessSettings(t, `"`+group+`"`, `{"enabled":true,"tcp":"fake","quic":"off"}`)
		c := testAdmin(t)
		if err := os.MkdirAll(c.stateDir, 0700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(c.stateDir, "settings.json")
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		privatePath := filepath.Join(c.stateDir, "primary-awg.conf")
		private := []byte("private test fixture: retain byte for byte\n")
		if err := os.WriteFile(privatePath, private, 0600); err != nil {
			t.Fatal(err)
		}
		stored, err := readSettingsAt(c.stateDir)
		if err != nil || stored.PrimaryGroup != group {
			t.Fatal("legacy group cannot be read unchanged", size, err)
		}
		c.settings = stored
		c.deactivate = func(string) error { t.Fatal("unrelated offline edit invoked native deactivation"); return nil }
		if _, err = c.HandleAPI(control.APIRequest{Operation: "settings"}); err != nil {
			t.Fatal(err)
		}
		if after, err := os.ReadFile(path); err != nil || string(after) != string(b) {
			t.Fatal("read-only access rewrote settings", err)
		}
		if _, err = c.HandleAPI(control.APIRequest{Operation: "settings", Settings: json.RawMessage(`{"family_order":["wgws","reality"]}`)}); err != nil {
			t.Fatal("unrelated offline edit rejected legacy state", err)
		}
		reloaded, err := readSettingsAt(c.stateDir)
		if err != nil || reloaded.PrimaryGroup != group || !reloaded.DirectBypass.Enabled || reloaded.DirectBypass.TCP != "fake" || reloaded.DirectBypass.QUIC != "off" {
			t.Fatal("legacy metadata lost across save/reload", err)
		}
		stored.FamilyOrder = []string{"wgws", "reality"}
		if !reflect.DeepEqual(stored, reloaded) {
			t.Fatal("unrelated settings changed")
		}
		if after, err := os.ReadFile(privatePath); err != nil || string(after) != string(private) {
			t.Fatal("private AWG bytes changed", err)
		}
		for _, supplied := range []string{group, strings.Repeat("b", 81)} {
			patch, _ := json.Marshal(map[string]string{"primary_group": supplied})
			if _, err = c.HandleAPI(control.APIRequest{Operation: "settings", Settings: patch}); err == nil {
				t.Fatal("explicit overlong group accepted", size)
			}
		}
		for _, supplied := range []string{"corrected", ""} {
			patch, _ := json.Marshal(map[string]string{"primary_group": supplied})
			if _, err = c.HandleAPI(control.APIRequest{Operation: "settings", Settings: patch}); err != nil {
				t.Fatal("explicit correction/clear rejected", err)
			}
		}
	}
}

func TestStoredCompatibilityRejectsMalformedValues(t *testing.T) {
	for _, raw := range []string{`null`, `{"enabled":false,"tcp":null,"quic":"off"}`, `{"enabled":null,"tcp":"off","quic":"off"}`, `{"enabled":false,"tcp":1,"quic":"off"}`, `{"enabled":false,"tcp":"invalid","quic":"off"}`, `{"enabled":false,"tcp":"off","quic":"off","unknown":true}`, `{"enabled":false,"enabled":true,"tcp":"off","quic":"off"}`} {
		if _, err := DecodeSettings(readinessSettings(t, `""`, raw)); err == nil {
			t.Fatal("invalid stored bypass accepted", raw)
		}
	}
	for _, raw := range []string{`null`, `4`, `"` + strings.Repeat("a", 129) + `"`, `"` + strings.Repeat("Ж", 41) + `"`, `"bad\ngroup"`, `"https://token"`, `"` + strings.Repeat("a", 80) + `/"`} {
		if _, err := DecodeSettings(readinessSettings(t, raw, `{"enabled":false,"tcp":"off","quic":"off"}`)); err == nil {
			t.Fatal("invalid stored group accepted", raw)
		}
	}
}

func TestExplicitPrimaryGroupNullRejectedWithoutWriting(t *testing.T) {
	c := testAdmin(t)
	if _, err := c.HandleAPI(control.APIRequest{Operation: "settings", Settings: json.RawMessage(`{"primary_group":null}`)}); err == nil {
		t.Fatal("explicit null group accepted")
	}
	if _, err := os.Stat(filepath.Join(c.stateDir, "settings.json")); !os.IsNotExist(err) {
		t.Fatal("invalid patch wrote settings", err)
	}
}

func TestLegacyGroupSavePreservesProfileRegistry(t *testing.T) {
	c := testAdmin(t)
	if _, err := c.HandleAPI(control.APIRequest{Operation: "import", Content: "hysteria2://PUBLIC_TEST_PASSWORD@example.com:443/?obfs=salamander&obfs-password=PUBLIC_TEST_OBFS&sni=example.com"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.stateDir, "profiles.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c.settings.PrimaryGroup = strings.Repeat("legacy", 20)
	if _, err = c.HandleAPI(control.APIRequest{Operation: "settings", Settings: json.RawMessage(`{"family_order":["vless"]}`)}); err != nil {
		t.Fatal("unrelated edit with existing private profiles rejected", err)
	}
	if after, err := os.ReadFile(path); err != nil || string(after) != string(before) {
		t.Fatal("unrelated edit rewrote private profiles", err)
	}
}

func TestStoredEmptyPresetOfflineSaveReload(t *testing.T) {
	c := testAdmin(t)
	if err := os.MkdirAll(c.stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.stateDir, "settings.json")
	b := readinessSettings(t, `"group"`, `{"enabled":true,"tcp":"","quic":"fake"}`)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	stored, err := readSettingsAt(c.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	c.settings = stored
	if _, err = c.HandleAPI(control.APIRequest{Operation: "settings"}); err != nil {
		t.Fatal(err)
	}
	if after, err := os.ReadFile(path); err != nil || string(after) != string(b) {
		t.Fatal("read rewrote stored empty preset", err)
	}
	if _, err = c.HandleAPI(control.APIRequest{Operation: "settings", Settings: json.RawMessage(`{"family_order":["vless"]}`)}); err != nil {
		t.Fatal(err)
	}
	reloaded, err := readSettingsAt(c.stateDir)
	stored.FamilyOrder = []string{"vless"}
	if err != nil || !reflect.DeepEqual(stored, reloaded) || !reloaded.DirectBypass.Enabled || reloaded.DirectBypass.TCP != "off" || reloaded.DirectBypass.QUIC != "fake" {
		t.Fatal("normalized stored state failed offline save/reload", err)
	}
}

func TestNewBypassWritesRemainStrictWithLegacyGroup(t *testing.T) {
	for _, raw := range []string{`null`, `{}`, `{"enabled":false}`, `{"enabled":false,"tcp":"","quic":"off"}`, `{"enabled":false,"tcp":"off","quic":""}`, `{"enabled":false,"tcp":null,"quic":"off"}`, `{"enabled":false,"tcp":"unknown","quic":"off"}`} {
		c := testAdmin(t)
		c.settings.PrimaryGroup = strings.Repeat("a", 128)
		if _, err := c.HandleAPI(control.APIRequest{Operation: "settings", Settings: json.RawMessage(`{"direct_bypass":` + raw + `}`)}); err == nil {
			t.Fatal("strict bypass patch accepted", raw)
		}
		if _, err := os.Stat(filepath.Join(c.stateDir, "settings.json")); !os.IsNotExist(err) {
			t.Fatal("invalid bypass patch wrote settings", err)
		}
	}
}
