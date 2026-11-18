package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/privatefile"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
)

func legacyConnectionState(t *testing.T) (string, Settings, []profile.Profile) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	settings := DefaultSettings()
	settings.Enabled = true
	settings.PrimaryGroup = "srvmain"
	settings.DirectProxy.Enabled = true
	if err := WriteJSON(filepath.Join(dir, "settings.json"), settings); err != nil {
		t.Fatal(err)
	}
	profiles := []profile.Profile{}
	for i, group := range []string{"srvbackup", "srvmain", "srvmain"} {
		items, err := profile.Parse([]byte(fmt.Sprintf("hy2://PUBLIC_TEST_PASSWORD@192.0.2.%d:443/?obfs=salamander&obfs-password=PUBLIC_TEST_OBFS&sni=example.com", i+10)))
		if err != nil {
			t.Fatal(err)
		}
		items[0].ServerGroup = group
		profiles = append(profiles, items[0])
	}
	r := &profile.Registry{Version: 1, Profiles: profiles}
	if err := r.Save(filepath.Join(dir, "profiles.json")); err != nil {
		t.Fatal(err)
	}
	key := "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	awg := "[Interface]\nPrivateKey = " + key + "\nHeaderProtectionKey = " + key + "\nAddress = 10.77.0.2/32\nS1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\nTable = off\n[Peer]\nPublicKey = " + key + "\nPresharedKey = " + key + "\nEndpoint = 192.0.2.70:51820\nAllowedIPs = 0.0.0.0/0\n"
	if err := os.WriteFile(filepath.Join(dir, "primary-awg.conf"), []byte(awg), 0600); err != nil {
		t.Fatal(err)
	}
	return dir, settings, profiles
}
func TestConnectionMigrationPreservesIDsPoliciesAndEffectiveOrder(t *testing.T) {
	dir, old, profiles := legacyConnectionState(t)
	if err := migrateState(dir); err != nil {
		t.Fatal(err)
	}
	r, err := connection.Load(filepath.Join(dir, "registry.json"))
	if err != nil || len(r.Connections) != 4 {
		t.Fatal("migration lost AWG or imported connections", err)
	}
	s, err := readSettingsAt(dir)
	if err != nil || s.Version != 2 || !s.Enabled || s.Selection.Mode != "auto" || s.DirectProxy != old.DirectProxy || s.DNSPort != old.DNSPort || s.HealthPolicy != old.HealthPolicy {
		t.Fatal("migration changed existing policies", err)
	}
	for _, p := range profiles {
		found := false
		for _, c := range r.Connections {
			if c.ID == p.ID && c.Group == p.ServerGroup {
				found = true
			}
		}
		if !found {
			t.Fatal("legacy logical ID or VPS metadata changed")
		}
	}
	if s.Order.Families[0] != "awg" || s.Order.Families[1] != "hy2" || s.Order.Connections["hy2"][0] == profiles[0].ID {
		t.Fatal("effective Main preference was not migrated to explicit order")
	}
	if _, err := os.Stat(filepath.Join(dir, "migration-v2.json")); !os.IsNotExist(err) {
		t.Fatal("finished migration retained pending checkpoint")
	}
	if _, err := os.Stat(filepath.Join(dir, "migration-v1", "profiles.json")); err != nil {
		t.Fatal("migration has no private v1 snapshot")
	}
}
func TestConnectionMigrationRecoversEveryPublicationBoundary(t *testing.T) {
	for cut := 1; cut <= 9; cut++ {
		t.Run(fmt.Sprint(cut), func(t *testing.T) {
			dir, _, _ := legacyConnectionState(t)
			writes := 0
			write := func(path string, data []byte) error {
				if err := privatefile.Write(path, data); err != nil {
					return err
				}
				writes++
				if writes == cut {
					return fmt.Errorf("interrupted after durable publication")
				}
				return nil
			}
			if err := migrateStateWith(dir, write); err == nil {
				t.Fatal("fault injection did not stop migration")
			}
			if err := migrateState(dir); err != nil {
				t.Fatal("restart did not recover coherent state", err)
			}
			r, err := connection.Load(filepath.Join(dir, "registry.json"))
			s, settingsErr := readSettingsAt(dir)
			if err != nil || settingsErr != nil || r.Version != 2 || s.Version != 2 || len(r.Connections) != 4 {
				t.Fatal("restart published mixed or missing state")
			}
		})
	}
}
func TestConnectionMigrationRemovesOnlyNaiveAndReportsPinnedReset(t *testing.T) {
	dir, settings, profiles := legacyConnectionState(t)
	outbound := map[string]any{"type": "naive", "server": "192.0.2.90", "server_port": 443, "username": "PUBLIC_TEST_USER", "password": "PUBLIC_TEST_PASSWORD", "tls": map[string]any{"enabled": true}}
	identity, _ := json.Marshal(struct {
		Engine           string
		Outbound, Detour map[string]any
		WGWS             *profile.WGWS
	}{"sing-box", outbound, nil, nil})
	digest := sha256.Sum256(identity)
	removed := profile.Profile{ID: "naive-" + hex.EncodeToString(digest[:]), Name: "naive-192.0.2.90", Family: "naive", Enabled: true, Engine: "sing-box", Outbound: outbound}
	profiles = append(profiles, removed)
	if err := WriteJSON(filepath.Join(dir, "profiles.json"), &profile.Registry{Version: 1, Profiles: profiles}); err != nil {
		t.Fatal(err)
	}
	settings.ProfileSelection = removed.ID
	settings.FamilyOrder = []string{"naive", "wgws"}
	if err := WriteJSON(filepath.Join(dir, "settings.json"), settings); err != nil {
		t.Fatal(err)
	}
	if err := migrateState(dir); err != nil {
		t.Fatal(err)
	}
	r, err := connection.Load(filepath.Join(dir, "registry.json"))
	s, settingsErr := readSettingsAt(dir)
	if err != nil || settingsErr != nil || len(r.Connections) != 4 || s.Selection.Mode != "auto" || s.MigrationNotice == "" {
		t.Fatal("Naive migration lost supported entries or failed to report reset")
	}
	encoded, _ := json.Marshal(s)
	if strings.Contains(string(encoded), "PUBLIC_TEST_PASSWORD") {
		t.Fatal("migration notice leaked credentials")
	}
}
func TestConnectionMigrationCorruptionNeverReplacesLegacyOrReimportsEmpty(t *testing.T) {
	dir, _, _ := legacyConnectionState(t)
	path := filepath.Join(dir, "profiles.json")
	before, _ := os.ReadFile(path)
	bad := strings.Replace(string(before), "hysteria2", "unknown-engine", 1)
	if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
		t.Fatal(err)
	}
	if err := migrateState(dir); err == nil {
		t.Fatal("invalid supported payload silently discarded")
	}
	if after, _ := os.ReadFile(path); string(after) != bad {
		t.Fatal("failed migration changed legacy source")
	}
	if _, err := os.Stat(filepath.Join(dir, "registry.json")); !os.IsNotExist(err) {
		t.Fatal("failed migration published partial registry")
	}
	if err := os.WriteFile(path, before, 0600); err != nil {
		t.Fatal(err)
	}
	if err := migrateState(dir); err != nil {
		t.Fatal(err)
	}
	s, _ := readSettingsAt(dir)
	empty := &connection.Registry{Version: 2}
	s.Order = connection.DefaultOrder(empty)
	if err := WriteJSON(filepath.Join(dir, "settings.json"), s); err != nil {
		t.Fatal(err)
	}
	if err := empty.Save(filepath.Join(dir, "registry.json")); err != nil {
		t.Fatal(err)
	}
	if err := migrateState(dir); err != nil {
		t.Fatal(err)
	}
	r, err := connection.Load(filepath.Join(dir, "registry.json"))
	if err != nil || len(r.Connections) != 0 {
		t.Fatal("intentional empty registry reimported legacy credentials")
	}
}

func TestConnectionMigrationMissingAWGAndCleanImageStayDisabled(t *testing.T) {
	dir, _, _ := legacyConnectionState(t)
	if err := os.Remove(filepath.Join(dir, "primary-awg.conf")); err != nil {
		t.Fatal(err)
	}
	if err := migrateState(dir); err != nil {
		t.Fatal(err)
	}
	r, err := connection.Load(filepath.Join(dir, "registry.json"))
	if err != nil || len(r.Connections) != 3 {
		t.Fatal("missing AWG was invented during migration", err)
	}
	clean := filepath.Join(t.TempDir(), "private")
	if err := migrateState(clean); err != nil {
		t.Fatal(err)
	}
	s, err := readSettingsAt(clean)
	if err != nil || s.Version != 2 || s.Enabled {
		t.Fatal("clean image was activated by migration", err)
	}
}

func TestConnectionMigrationRejectsDamagedStageBeforePublishing(t *testing.T) {
	dir, _, _ := legacyConnectionState(t)
	writes := 0
	err := migrateStateWith(dir, func(path string, data []byte) error {
		if err := privatefile.Write(path, data); err != nil {
			return err
		}
		writes++
		if writes == 7 {
			return fmt.Errorf("stop after checkpoint")
		}
		return nil
	})
	if err == nil {
		t.Fatal("checkpoint fault did not interrupt migration")
	}
	stage := filepath.Join(dir, ".registry-v2.json")
	raw, _ := os.ReadFile(stage)
	if err := privatefile.Write(stage, append(raw, ' ')); err != nil {
		t.Fatal(err)
	}
	if err := migrateState(dir); err == nil {
		t.Fatal("damaged staged hash accepted")
	}
	s, err := readSettingsAt(dir)
	if err != nil || s.Version != 1 {
		t.Fatal("damaged checkpoint published new settings")
	}
	if _, err := os.Stat(filepath.Join(dir, "registry.json")); !os.IsNotExist(err) {
		t.Fatal("damaged checkpoint published registry")
	}
}
