package controller

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/MyHeartRaces/FLR/runtime/internal/config"
	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/control"
	"github.com/MyHeartRaces/FLR/runtime/internal/privatefile"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
	"github.com/MyHeartRaces/FLR/runtime/internal/rollbackintent"
)

type migrationManifest struct {
	Version int               `json:"version"`
	Sources map[string]string `json:"sources"`
}
type migrationCheckpoint struct {
	Version  int    `json:"version"`
	Registry string `json:"registry"`
	Settings string `json:"settings"`
	Backup   string `json:"backup"`
}

var migrationSources = []string{"settings.json", "profiles.json", "primary-awg.conf", "gecko.json", "vless.json"}

func stateHash(raw []byte) string { digest := sha256.Sum256(raw); return hex.EncodeToString(digest[:]) }

// ReadSettings holds admin.lock and recovers the connection checkpoint first.
func migrateState(dir string) error {
	return migrateAndDisableWith(dir, privatefile.Write, rollbackintent.Clear)
}
func migrateAndDisableWith(dir string, write func(string, []byte) error, clear func(string) error) error {
	pending, err := rollbackintent.Pending(dir)
	if err != nil {
		return err
	}
	if err := migrateStateWith(dir, write); err != nil {
		return err
	}
	if !pending {
		return nil
	}
	s, err := readSettingsAt(dir)
	if err != nil {
		return err
	}
	if s.Enabled || s.DirectProxy.Enabled || s.DirectBypass.Enabled {
		// New exposes a missing saved counter as generation 1.
		if s.SavedGeneration == 0 {
			s.SavedGeneration = 1
		}
		// Recovery must remain possible even at the schema's maximum counter.
		// Future mutations already reject overflow, so retain that terminal value.
		if s.SavedGeneration < (1<<53)-1 {
			s.SavedGeneration++
		}
	}
	s.Enabled, s.DirectProxy.Enabled, s.DirectBypass.Enabled = false, false, false
	if err := write(filepath.Join(dir, "settings.json"), mustJSON(s)); err != nil {
		return fmt.Errorf("cannot persist disabled rollback state")
	}
	return clear(dir)
}
func migrateStateWith(dir string, write func(string, []byte) error) error {
	lockPath := filepath.Join(dir, "migration.lock")
	if err := privatefile.SafePath(lockPath); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("cannot create private migration directory")
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return fmt.Errorf("migration directory must be private")
	}
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("cannot open migration lock")
	}
	defer lock.Close()
	if info, err := lock.Stat(); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return fmt.Errorf("unsafe migration lock")
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("cannot lock migration")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	marker, err := privatefile.Read(filepath.Join(dir, "migration-v2.json"), 4096)
	if err == nil {
		return finishMigration(dir, marker, write)
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("migration checkpoint rejected")
	}
	settings, err := readSettingsAt(dir)
	if err != nil {
		return err
	}
	if settings.Version == 2 {
		raw, err := privatefile.Read(filepath.Join(dir, "registry.json"), connection.MaxRegistryBytes)
		if err != nil {
			return fmt.Errorf("v2 registry unavailable")
		}
		_, err = validateMigratedPair(raw, mustJSON(settings))
		return err
	}
	// Only a prepared migration may publish over an existing v2 registry.
	// Missing/downgraded settings must never cause legacy reimport or data loss.
	if _, err := os.Lstat(filepath.Join(dir, "registry.json")); err == nil || !os.IsNotExist(err) {
		return fmt.Errorf("existing registry requires coherent v2 settings")
	}
	// Validate the entire source before creating or publishing any new registry.
	sources := map[string][]byte{}
	for _, name := range migrationSources {
		raw, err := privatefile.Read(filepath.Join(dir, name), connection.MaxRegistryBytes)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("private migration source rejected")
		}
		sources[name] = raw
	}
	r, settings, err := convertLegacy(settings, sources)
	if err != nil {
		return err
	}
	registryRaw, settingsRaw := mustJSON(r), mustJSON(settings)
	if _, err := validateMigratedPair(registryRaw, settingsRaw); err != nil {
		return err
	}
	manifest := migrationManifest{Version: 1, Sources: map[string]string{}}
	for _, name := range migrationSources {
		if raw, exists := sources[name]; exists {
			manifest.Sources[name] = stateHash(raw)
			path := filepath.Join(dir, "migration-v1", name)
			previous, err := privatefile.Read(path, connection.MaxRegistryBytes)
			if err == nil {
				if !bytes.Equal(raw, previous) {
					return fmt.Errorf("migration snapshot differs from legacy source")
				}
			} else if os.IsNotExist(err) {
				if err := write(path, raw); err != nil {
					return err
				}
			} else {
				return fmt.Errorf("private migration snapshot rejected")
			}
		}
	}
	manifestRaw := mustJSON(manifest)
	manifestPath := filepath.Join(dir, "migration-v1", "manifest.json")
	if previous, err := privatefile.Read(manifestPath, 4096); err == nil && !bytes.Equal(previous, manifestRaw) {
		return fmt.Errorf("migration snapshot manifest differs")
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("migration manifest rejected")
	}
	if err := write(manifestPath, manifestRaw); err != nil {
		return err
	}
	if err := write(filepath.Join(dir, ".registry-v2.json"), registryRaw); err != nil {
		return err
	}
	if err := write(filepath.Join(dir, ".settings-v2.json"), settingsRaw); err != nil {
		return err
	}
	checkpoint := migrationCheckpoint{Version: 2, Registry: stateHash(registryRaw), Settings: stateHash(settingsRaw), Backup: stateHash(manifestRaw)}
	marker = mustJSON(checkpoint)
	if err := write(filepath.Join(dir, "migration-v2.json"), marker); err != nil {
		return err
	}
	return finishMigration(dir, marker, write)
}
func mustJSON(value any) []byte { raw, _ := json.Marshal(value); return raw }
func validateMigratedPair(registryRaw, settingsRaw []byte) (*connection.Registry, error) {
	r, err := connection.Decode(registryRaw)
	if err != nil {
		return nil, err
	}
	s, err := DecodeSettings(settingsRaw)
	if err != nil || s.Version != 2 {
		return nil, fmt.Errorf("v2 settings rejected")
	}
	if _, err := connection.Candidates(r, s.Selection, s.Order); err != nil {
		return nil, err
	}
	return r, nil
}
func finishMigration(dir string, marker []byte, write func(string, []byte) error) error {
	var checkpoint migrationCheckpoint
	if err := connection.DecodeStrict(marker, &checkpoint); err != nil || checkpoint.Version != 2 {
		return fmt.Errorf("invalid migration checkpoint")
	}
	registryRaw, err := privatefile.Read(filepath.Join(dir, ".registry-v2.json"), connection.MaxRegistryBytes)
	if err != nil || stateHash(registryRaw) != checkpoint.Registry {
		return fmt.Errorf("migration registry stage rejected")
	}
	settingsRaw, err := privatefile.Read(filepath.Join(dir, ".settings-v2.json"), 1<<20)
	if err != nil || stateHash(settingsRaw) != checkpoint.Settings {
		return fmt.Errorf("migration settings stage rejected")
	}
	if _, err := validateMigratedPair(registryRaw, settingsRaw); err != nil {
		return err
	}
	manifestRaw, err := privatefile.Read(filepath.Join(dir, "migration-v1", "manifest.json"), 4096)
	if err != nil || stateHash(manifestRaw) != checkpoint.Backup {
		return fmt.Errorf("migration snapshot manifest rejected")
	}
	var manifest migrationManifest
	if err := connection.DecodeStrict(manifestRaw, &manifest); err != nil || manifest.Version != 1 {
		return fmt.Errorf("invalid migration snapshot manifest")
	}
	allowed := map[string]bool{}
	for _, name := range migrationSources {
		allowed[name] = true
	}
	for name, hash := range manifest.Sources {
		if !allowed[name] {
			return fmt.Errorf("unknown migration snapshot source")
		}
		raw, err := privatefile.Read(filepath.Join(dir, "migration-v1", name), connection.MaxRegistryBytes)
		if err != nil || stateHash(raw) != hash {
			return fmt.Errorf("migration snapshot rejected")
		}
	}
	if err := write(filepath.Join(dir, "registry.json"), registryRaw); err != nil {
		return err
	}
	if err := write(filepath.Join(dir, "settings.json"), settingsRaw); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, "migration-v2.json")); err != nil {
		return fmt.Errorf("cannot finish migration checkpoint")
	}
	return privatefile.SyncDir(dir)
}
func convertLegacy(settings Settings, sources map[string][]byte) (*connection.Registry, Settings, error) {
	r := &connection.Registry{Version: 2, Connections: []connection.Connection{}}
	legacy := &profile.Registry{Version: 1}
	removed := map[string]bool{}
	if raw, exists := sources["profiles.json"]; exists {
		if err := connection.DecodeStrict(raw, legacy); err != nil || legacy.Version != 1 || len(legacy.Profiles) > profile.MaxProfiles {
			return nil, settings, fmt.Errorf("legacy registry rejected")
		}
		if err := validateFamilyOrder(legacy.FamilyOrder, true); err != nil {
			return nil, settings, err
		}
		seen := map[string]bool{}
		for _, p := range legacy.Profiles {
			if seen[p.ID] {
				return nil, settings, fmt.Errorf("repeated legacy connection identity")
			}
			seen[p.ID] = true
			if p.Family == "naive" {
				identity := mustJSON(struct {
					Engine           string
					Outbound, Detour map[string]any
					WGWS             *profile.WGWS
				}{p.Engine, p.Outbound, p.Detour, p.WGWS})
				if p.Engine != "sing-box" || p.Outbound["type"] != "naive" || p.WGWS != nil || p.Detour != nil || p.ID != "naive-"+stateHash(identity) {
					return nil, settings, fmt.Errorf("legacy removed protocol identity rejected")
				}
				removed[p.ID] = true
				continue
			}
			if err := profile.ValidateStored(p); err != nil {
				return nil, settings, fmt.Errorf("legacy supported payload rejected")
			}
			c, err := connection.FromProfile(p, p.ID)
			if err != nil {
				return nil, settings, err
			}
			r.Connections = append(r.Connections, c)
		}
	} else {
		for _, name := range []string{"gecko.json", "vless.json"} {
			raw, exists := sources[name]
			if !exists {
				continue
			}
			var legacySource struct {
				Outbounds []map[string]any `json:"outbounds"`
			}
			// Legacy renderer files also contain native inbounds/routes. Their only
			// imported input is the allowlisted outbound payload parsed below.
			if len(raw) > profile.MaxImportBytes || control.CheckJSON(raw) != nil || json.Unmarshal(raw, &legacySource) != nil || len(legacySource.Outbounds) == 0 {
				return nil, settings, fmt.Errorf("legacy outbound source rejected")
			}
			for _, out := range legacySource.Outbounds {
				delete(out, "bind_interface")
				delete(out, "routing_mark")
				if out["type"] == "hysteria2" && out["bbr_profile"] == "standard" {
					delete(out, "bbr_profile")
				}
			}
			items, err := connection.ParseImport(mustJSON(legacySource))
			if err != nil {
				return nil, settings, fmt.Errorf("legacy outbound payload rejected")
			}
			for _, c := range items {
				c.ID = c.Profile.ID
				r.Connections = append(r.Connections, c)
				legacy.Profiles = append(legacy.Profiles, *c.Profile)
			}
		}
	}
	if raw, exists := sources["primary-awg.conf"]; exists {
		fields, err := config.ParseAWG(raw)
		if err != nil {
			return nil, settings, fmt.Errorf("legacy native AWG rejected")
		}
		group := settings.PrimaryGroup
		if profile.ValidateGroup(group) != nil {
			group = ""
		}
		r.Connections = append(r.Connections, connection.Connection{ID: "awg-primary", Name: "AWG primary", Family: "awg", Group: group, Enabled: true, Revision: stateHash(mustJSON(fields)), AWG: fields})
	}
	if err := connection.ValidateRegistry(r); err != nil {
		return nil, settings, err
	}
	settings.Version = 2
	settings.Selection = connection.Selection{Mode: "auto"}
	if settings.ProfileSelection != "auto" && !removed[settings.ProfileSelection] {
		settings.Selection = connection.Selection{Mode: "connection", ID: settings.ProfileSelection}
	}
	if len(removed) > 0 {
		settings.MigrationNotice = "Removed obsolete protocol connections during migration; review proxy selection."
	}
	settings.ProfileSelection = "auto"
	settings.Order = connection.DefaultOrder(r)
	families := []string{"awg", "hy2"}
	seen := map[string]bool{"awg": true, "hy2": true}
	for _, family := range append(append([]string{}, settings.FamilyOrder...), connection.Families...) {
		if connection.KnownFamily(family) && !seen[family] {
			families = append(families, family)
			seen[family] = true
		}
	}
	settings.Order.Families = families
	settings.FamilyOrder = nil
	for i := range legacy.Profiles {
		legacy.Profiles[i].Enabled = true
		legacy.Profiles[i].UserDisabled = false
		legacy.Profiles[i].DisabledReason = ""
	}
	legacy.FamilyOrder = families[2:]
	for _, family := range connection.Families {
		if family != "awg" {
			settings.Order.Connections[family] = []string{}
		}
	}
	for _, p := range legacy.Candidates(settings.PrimaryGroup) {
		if !removed[p.ID] {
			settings.Order.Connections[p.Family] = append(settings.Order.Connections[p.Family], p.ID)
		}
	}
	// Deprecated group policy has become an explicit ID order. Retain only valid
	// metadata; no hidden preference is consulted by v2 selection.
	if profile.ValidateGroup(settings.PrimaryGroup) != nil {
		settings.PrimaryGroup = ""
	}
	settings.MigrationNotice = strings.TrimSpace(settings.MigrationNotice)
	return r, settings, nil
}
