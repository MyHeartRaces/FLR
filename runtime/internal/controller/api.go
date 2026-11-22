package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/config"
	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/control"
	"github.com/MyHeartRaces/FLR/runtime/internal/dataplane"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
	"github.com/MyHeartRaces/FLR/runtime/internal/transport"
	"github.com/MyHeartRaces/FLR/runtime/internal/validation"
)

func (c *Controller) initializeAdmin(migrate bool) error {
	if c.stateDir == "" {
		c.stateDir = StateDir
	}
	if _, err := os.Lstat(filepath.Join(c.stateDir, "connection-state.json")); err == nil {
		if err := recoverConnectionState(c.stateDir); err != nil {
			return err
		}
		settings, err := readSettingsAt(c.stateDir)
		if err != nil {
			return err
		}
		c.mu.Lock()
		c.settings = settings
		c.mu.Unlock()
		c.connections, c.registry = nil, nil
		c.advanceChoice()
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("private checkpoint unavailable")
	}
	// Offline dispatch can wait between its initial settings read and this
	// admin lock. Honor recovery published in that interval, including intent
	// already consumed by another reader; never write a stale enabled snapshot.
	if !c.live && c.settings.Version == 2 {
		if err := migrateState(c.stateDir); err != nil {
			return err
		}
		settings, err := readSettingsAt(c.stateDir)
		if err != nil {
			return err
		}
		changed := stateHash(mustJSON(settings)) != stateHash(mustJSON(c.settings))
		c.mu.Lock()
		c.settings = settings
		if settings.SavedGeneration > c.generation {
			c.generation = settings.SavedGeneration
		}
		c.mu.Unlock()
		if changed {
			c.connections, c.registry = nil, nil
			c.advanceChoice()
		}
	}
	if c.settings.Version == 2 && c.connections == nil {
		registry, err := connection.Load(filepath.Join(c.stateDir, "registry.json"))
		if err != nil {
			return fmt.Errorf("private connection registry unavailable")
		}
		if _, err := connection.Candidates(registry, c.settings.Selection, c.settings.Order); err != nil {
			return err
		}
		c.connections = registry
		c.registry = &profile.Registry{Version: 1}
		for _, item := range registry.Connections {
			if item.Profile != nil {
				p := *item.Profile
				p.Enabled = item.Enabled
				p.UserDisabled = !item.Enabled
				c.registry.Profiles = append(c.registry.Profiles, p)
			}
		}
	}
	if c.registry == nil {
		registryPath := filepath.Join(c.stateDir, "profiles.json")
		_, statErr := os.Lstat(registryPath)
		registryMissing := os.IsNotExist(statErr)
		registry, e := profile.Load(registryPath)
		if e != nil {
			return fmt.Errorf("private profile registry unavailable")
		}
		// Standalone legacy outbounds remain a private migration source. No source
		// file is removed and no legacy child is started during import.
		if migrate && registryMissing {
			for _, name := range []string{"gecko.json", "vless.json"} {
				path := filepath.Join(c.stateDir, name)
				info, e := os.Lstat(path)
				if os.IsNotExist(e) {
					continue
				}
				if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > profile.MaxImportBytes {
					return fmt.Errorf("unsafe legacy migration source")
				}
				b, e := os.ReadFile(path)
				if e != nil || control.CheckJSON(b) != nil {
					return fmt.Errorf("invalid legacy migration source")
				}
				var legacy struct {
					Outbounds []map[string]any `json:"outbounds"`
				}
				if json.Unmarshal(b, &legacy) != nil || len(legacy.Outbounds) == 0 {
					return fmt.Errorf("invalid legacy migration outbounds")
				}
				for _, out := range legacy.Outbounds {
					delete(out, "bind_interface")
					delete(out, "routing_mark")
					// Legacy sing-box 1.14 configs spell out the standard default.
					// Keep the source intact while normalizing this redundant field.
					if out["type"] == "hysteria2" && out["bbr_profile"] == "standard" {
						delete(out, "bbr_profile")
					}
				}
				raw, e := json.Marshal(legacy)
				if e != nil {
					return fmt.Errorf("invalid legacy migration source")
				}
				if _, e = registry.Import(raw); e != nil {
					return fmt.Errorf("legacy migration rejected; source retained")
				}
			}
		}
		if migrate && registryMissing {
			if e := registry.Save(registryPath); e != nil {
				return fmt.Errorf("legacy migration checkpoint failed")
			}
		}
		c.registry = registry
	}
	if c.available == nil {
		c.available = transport.Available()
	}
	if c.deactivate == nil {
		c.deactivate = dataplane.Deactivate
	}
	if c.recoveryPending == nil {
		c.recoveryPending = func() bool {
			if c.stateDir != StateDir {
				return false
			}
			return deactivationMarkers("/var/run/flr-runtime/owner.json", "/etc/flr-runtime/rollback.pending")
		}
	}
	c.registry.ApplyAvailability(c.available)
	c.registry.FamilyOrder = append([]string{}, c.settings.FamilyOrder...)
	if c.validateEngine == nil {
		c.validateEngine = func(ctx context.Context, p profile.Profile) error {
			return transport.Validate(ctx, p, c.settings.Options.WAN)
		}
	}
	if c.activateVPN == nil {
		c.activateVPN = c.guardedConnectionActivation
	}
	if c.captureTestAWG == nil {
		c.captureTestAWG = config.SnapshotAWG
	}
	if c.restoreTestAWG == nil {
		c.restoreTestAWG = config.RestoreAWG
	}
	return nil
}
func cloneRegistry(r *profile.Registry) *profile.Registry {
	// A private JSON round-trip yields a complete deep snapshot without sharing
	// payload maps with the runtime manager or a transaction that may fail.
	b, _ := json.Marshal(r)
	var copy profile.Registry
	json.Unmarshal(b, &copy)
	return &copy
}
func (c *Controller) notify() {
	select {
	case c.refresh <- struct{}{}:
	default:
	}
}

func (c *Controller) validateSettingsCandidate(s Settings) error {
	// An unrelated edit can retain an already-loaded legacy group. An explicit
	// API group patch is checked strictly before this full-candidate validation.
	return validateSettings(s, s.PrimaryGroup == c.settings.PrimaryGroup)
}
func (c *Controller) saveSettings(s Settings) error {
	if s.Version == 2 {
		s.SavedGeneration = c.Status().Generation + 1
	}
	if e := c.validateSettingsCandidate(s); e != nil {
		return e
	}
	if s.Version == 2 {
		if _, err := connection.Candidates(c.connections, s.Selection, s.Order); err != nil {
			return err
		}
	}
	if e := WriteJSON(filepath.Join(c.stateDir, "settings.json"), s); e != nil {
		return fmt.Errorf("cannot save private settings")
	}
	changed := s.Version == 2 && (s.Selection != c.settings.Selection || s.Enabled != c.settings.Enabled)
	c.mu.Lock()
	c.settings = s
	c.generation++
	c.mu.Unlock()
	if changed {
		c.advanceChoice()
	}
	c.notify()
	return nil
}
func (c *Controller) restorationPending() bool {
	if c.deactivationPending {
		return true
	}
	// A previous offline process may have saved disabled intent and then failed
	// during teardown. The owned-state marker survives until native restoration
	// finishes, so the next CLI process or service start can retry the operation.
	return c.recoveryPending != nil && c.recoveryPending()
}
func deactivationMarkers(owner, pending string) bool {
	for _, path := range []string{owner, pending} {
		if _, e := os.Stat(path); e == nil {
			return true
		}
	}
	return false
}

// HandleAPI serializes both administrative writes and transport rounds. A
// separate file lock serializes offline CLI processes; the live controller's
// singleton controller.lock is deliberately not reacquired here.
func (c *Controller) HandleAPI(r control.APIRequest) (any, error) {
	c.adminMu.Lock()
	defer c.adminMu.Unlock()
	if c.ctx != nil && c.ctx.Err() != nil {
		return nil, fmt.Errorf("controller is stopping")
	}
	if c.stateDir == "" {
		c.stateDir = StateDir
	}
	lock, e := lockPrivateAdmin(c.stateDir)
	if e != nil {
		return nil, e
	}
	defer lock.Close()
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	// Revalidate even direct in-process callers. CLI/rpcd flags are not the sole
	// argument boundary, and the socket is not a general command/file API.
	raw, e := json.Marshal(r)
	if e != nil {
		return nil, fmt.Errorf("invalid API request")
	}
	if r, e = control.ParseAPI(raw, false, false); e != nil {
		return nil, e
	}
	if e = c.initializeAdmin(r.Write()); e != nil {
		return nil, e
	}
	// Changes are checked against the LAN as it is now, not as it was at start.
	c.refreshLAN()
	if r.Operation == "diagnostics" || r.Operation == "diagnostics-export" {
		return c.diagnosticAPI(r)
	}
	if result, handled, err := c.handleRoutingAPI(r); handled {
		return result, err
	}
	if c.settings.Version == 2 {
		if result, handled, err := c.handleConnectionsAPI(r); handled {
			return result, err
		}
	}
	switch r.Operation {
	case "status":
		s := c.Status()
		return map[string]any{"runtime": c.live, "vpn_enabled": c.settings.Enabled, "status": s, "active_profile": c.activeProfile, "profile_selection": c.settings.ProfileSelection, "rollback_pending": c.rollbackPending(), "deactivation_pending": !c.settings.Enabled && c.restorationPending()}, nil
	case "profiles":
		return map[string]any{"profiles": c.registry.Summaries(), "selection": c.settings.ProfileSelection}, nil
	case "help", "capabilities":
		return map[string]any{"api_version": 1, "max_import_bytes": profile.MaxImportBytes, "max_profiles": profile.MaxProfiles, "operations": []string{"status", "profiles", "import", "select", "profile-update", "profile-delete", "device", "settings", "refresh", "primary-awg", "rollback-confirm", "help", "capabilities"}, "components": c.available, "managed_slot": "gecko", "tun_address": "198.18.0.1/30", "tun_peer": "198.18.0.2", "authentication": "root CLI or rpcd FLR ACL", "tcp_only_games": "fail-closed"}, nil
	case "refresh":
		c.available = transport.Available()
		c.registry.ApplyAvailability(c.available)
		c.notify()
		return map[string]bool{"scheduled": c.live}, nil
	case "import":
		data := []byte(r.Content)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if r.URL != "" {
			data, e = (Fetcher{WAN: c.settings.Options.WAN}).Fetch(ctx, r.URL)
			if e != nil {
				return nil, e
			}
		}
		candidate := cloneRegistry(c.registry)
		imported, e := candidate.Import(data)
		if e != nil {
			return nil, validation.Public(e)
		}
		ids := map[string]int{}
		for index, s := range imported {
			ids[s.ID] = index + 1
		}
		for _, p := range candidate.Profiles {
			if ids[p.ID] > 0 {
				if e = c.validateEngine(ctx, p); e != nil {
					return nil, &validation.Error{Code: "engine_validation", Message: "Native engine configuration check failed; verify supported transport settings and installed component compatibility.", Field: "engine", Component: p.Engine, Item: ids[p.ID]}
				}
			}
		}
		candidate.ApplyAvailability(c.available)
		if e = candidate.Save(filepath.Join(c.stateDir, "profiles.json")); e != nil {
			return nil, fmt.Errorf("profile transaction could not be saved")
		}
		c.registry = candidate
		c.notify()
		summaries := []profile.Summary{}
		for _, s := range candidate.Summaries() {
			if ids[s.ID] > 0 {
				summaries = append(summaries, s)
			}
		}
		return map[string]any{"imported": summaries}, nil
	case "select":
		if r.ID != "auto" {
			found := false
			for _, p := range c.registry.Candidates(c.settings.PrimaryGroup) {
				if p.ID == r.ID {
					found = true
				}
			}
			if !found {
				return nil, fmt.Errorf("profile is missing or disabled")
			}
		}
		s := c.settings
		s.ProfileSelection = r.ID
		if e = c.saveSettings(s); e != nil {
			return nil, e
		}
		return map[string]string{"selection": r.ID}, nil
	case "profile-update", "profile-delete":
		candidate := cloneRegistry(c.registry)
		if r.Operation == "profile-delete" {
			if e = candidate.Delete(r.ID); e != nil {
				return nil, fmt.Errorf("profile not found")
			}
		} else {
			found := false
			for i, p := range candidate.Profiles {
				if p.ID != r.ID {
					continue
				}
				found = true
				if r.Priority != nil {
					candidate.Profiles[i].Priority = *r.Priority
				}
				if r.ServerGroup != nil {
					candidate.Profiles[i].ServerGroup = *r.ServerGroup
				}
			}
			if !found {
				return nil, fmt.Errorf("profile not found")
			}
			if r.Enabled != nil {
				if e = candidate.SetEnabled(r.ID, *r.Enabled); e != nil {
					return nil, fmt.Errorf("profile update rejected")
				}
			}
			candidate.ApplyAvailability(c.available)
		}
		old := c.registry
		// Persist auto before deleting/disabling the selected profile. If registry
		// commit fails, restore the previous settings to retain the transaction.
		settings := c.settings
		next := settings
		for _, p := range candidate.Profiles {
			if p.ID == settings.ProfileSelection && !p.Enabled {
				next.ProfileSelection = "auto"
			}
		}
		if r.Operation == "profile-delete" && settings.ProfileSelection == r.ID {
			next.ProfileSelection = "auto"
		}
		if next.ProfileSelection != settings.ProfileSelection {
			if e = c.saveSettings(next); e != nil {
				return nil, e
			}
		}
		if e = candidate.Save(filepath.Join(c.stateDir, "profiles.json")); e != nil {
			if next.ProfileSelection != settings.ProfileSelection {
				c.saveSettings(settings)
			}
			c.registry = old
			return nil, fmt.Errorf("profile update could not be saved")
		}
		c.registry = candidate
		c.notify()
		return map[string]any{"profiles": candidate.Summaries(), "selection": c.settings.ProfileSelection}, nil
	case "device":
		// A new profile must be a client of the current LAN; stored profiles are
		// never re-checked here. The live handler rolls back nft if persistence
		// fails. Offline writes skip nft and preserve device choices.
		if e = c.checkDeviceChange(r.Client, r.Value); e != nil {
			return nil, e
		}
		if c.live && c.settings.Enabled && c.appliedMode != policy.ModeDirect {
			return c.handleDevice(r.Client, r.Value)
		}
		s := c.settings
		raw, _ := json.Marshal(s.Options.Profiles)
		profiles := map[string]contract.Class{}
		json.Unmarshal(raw, &profiles)
		if profiles == nil {
			profiles = map[string]contract.Class{}
		}
		if r.Value == "auto" {
			delete(profiles, r.Client)
		} else {
			profiles[r.Client] = contract.Class(r.Value)
		}
		s.Options.Profiles = profiles
		if e = c.saveSettings(s); e != nil {
			return nil, e
		}
		return map[string]any{"devices": profiles}, nil
	case "settings":
		if len(r.Settings) == 0 {
			return c.safeSettings(), nil
		}
		var patch struct {
			Enabled          *bool           `json:"enabled"`
			DirectBypass     json.RawMessage `json:"direct_bypass"`
			DirectProxy      json.RawMessage `json:"direct_proxy"`
			HealthPolicy     json.RawMessage `json:"health_policy"`
			WarmReserve      json.RawMessage `json:"warm_reserve"`
			RoutingMode      *string         `json:"routing_mode"`
			TunnelQoS        json.RawMessage `json:"tunnel_qos"`
			ProfileSelection *string         `json:"profile_selection"`
			PrimaryGroup     json.RawMessage `json:"primary_group"`
			FamilyOrder      *[]string       `json:"family_order"`
		}
		if e = decodeStrict(r.Settings, &patch); e != nil {
			return nil, e
		}
		s := c.settings
		if len(patch.DirectBypass) != 0 {
			s.DirectBypass, e = decodeBypass(patch.DirectBypass)
			if e != nil {
				return nil, e
			}
		}
		if len(patch.HealthPolicy) != 0 {
			s.HealthPolicy, e = decodeHealthPolicy(patch.HealthPolicy)
			if e != nil {
				return nil, e
			}
		}
		// The warm reserve is a runtime policy, not a new choice: saving it
		// never advances the choice epoch, so no flow or slot is retired.
		if len(patch.WarmReserve) != 0 {
			if s.Version != 2 {
				return nil, fmt.Errorf("warm reserve requires unified connection selection")
			}
			warm, err := decodeWarmReserve(patch.WarmReserve)
			if err != nil {
				return nil, err
			}
			s.WarmReserve = storedWarmReserve(warm)
		}
		// Publish the validated mode at the next controller reconciliation.
		if patch.RoutingMode != nil {
			mode, err := storedRoutingMode(*patch.RoutingMode)
			if err != nil {
				return nil, err
			}
			s.RoutingMode = mode
		}
		if len(patch.TunnelQoS) != 0 {
			q, err := decodeTunnelQoS(patch.TunnelQoS)
			if err != nil {
				return nil, err
			}
			s.TunnelQoS = q
		}
		if len(patch.DirectProxy) != 0 {
			var direct struct {
				Enabled *bool   `json:"enabled"`
				Bind    *string `json:"bind"`
				Port    *int    `json:"port"`
			}
			if e = decodeStrict(patch.DirectProxy, &direct); e != nil {
				return nil, e
			}
			if direct.Enabled == nil || direct.Bind == nil || direct.Port == nil {
				return nil, fmt.Errorf("direct proxy requires explicit enabled, bind and port")
			}
			next := control.DirectConfig{Enabled: *direct.Enabled, Bind: *direct.Bind, Port: *direct.Port}
			if e = c.checkDirectChange(next); e != nil {
				return nil, e
			}
			// The listener always binds the router's discovered LAN address
			// (effectiveDirect), and checkDirectChange only accepts that
			// address, so the stored bind never needs to change: keeping it
			// leaves settings.json loadable by the 0.6 controller after a
			// rollback (it refuses any bind but 192.168.8.1). Enabled and port
			// are persisted as sent.
			if s.DirectProxy.Bind != "" {
				next.Bind = s.DirectProxy.Bind
			}
			s.DirectProxy = next
		}
		if patch.Enabled != nil {
			if *patch.Enabled && !s.Enabled {
				return nil, fmt.Errorf("use guarded VPN activation to enable VPN")
			}
			s.Enabled = *patch.Enabled
		}
		if s.Version == 2 && (patch.ProfileSelection != nil || patch.FamilyOrder != nil || len(patch.PrimaryGroup) != 0) {
			return nil, fmt.Errorf("use unified connection selection, metadata and order operations")
		}
		if patch.ProfileSelection != nil {
			if *patch.ProfileSelection != "auto" {
				found := false
				for _, p := range c.registry.Candidates(s.PrimaryGroup) {
					if p.ID == *patch.ProfileSelection {
						found = true
					}
				}
				if !found {
					return nil, fmt.Errorf("profile is missing or disabled")
				}
			}
			s.ProfileSelection = *patch.ProfileSelection
		}
		if len(patch.PrimaryGroup) != 0 {
			var group *string
			if e = json.Unmarshal(patch.PrimaryGroup, &group); e != nil || group == nil || profile.ValidateGroup(*group) != nil {
				return nil, fmt.Errorf("invalid primary group")
			}
			s.PrimaryGroup = *group
		}
		if patch.FamilyOrder != nil {
			if e = validateFamilyOrder(*patch.FamilyOrder, false); e != nil {
				return nil, e
			}
			s.FamilyOrder = append([]string{}, (*patch.FamilyOrder)...)
		}
		// Validate the complete candidate before any native effect. A disable flag
		// alongside an invalid family/group/selection must leave the router intact.
		if e = c.validateSettingsCandidate(s); e != nil {
			return nil, e
		}
		disableOffline := patch.Enabled != nil && !*patch.Enabled && !c.live && (c.settings.Enabled || c.restorationPending())
		// Commit disabled intent before native restoration. A persistence failure
		// therefore has no native effect; a partial native failure stays disabled
		// and retains the ownership checkpoint for a safe retry, never reactivation.
		if e = c.saveSettings(s); e != nil {
			return nil, e
		}
		c.registry.FamilyOrder = append([]string{}, s.FamilyOrder...)
		if disableOffline {
			c.deactivationPending = true
			if e = c.deactivate("/etc/flr-runtime/backup"); e != nil {
				return nil, fmt.Errorf("VPN deactivation incomplete; disabled settings saved, retry disable")
			}
			c.deactivationPending = false
		}
		return c.safeSettings(), nil
	case "rollback-confirm":
		if !c.live || !c.vpnStarted || c.vpnRestart || !c.settings.Enabled || c.selection.General == contract.Down || c.stateDir != StateDir {
			return nil, fmt.Errorf("active configured VPN required for confirmation")
		}
		if c.settings.Version != 2 {
			if _, e := os.Stat(filepath.Join(c.stateDir, "primary-awg.conf")); e != nil {
				return nil, fmt.Errorf("stored primary AWG configuration required")
			}
		}
		if e = config.ConfirmRollback(); e != nil {
			return nil, fmt.Errorf("rollback confirmation rejected")
		}
		return map[string]bool{"confirmed": true, "rollback_pending": false}, nil
	case "primary-awg":
		path := filepath.Join(c.stateDir, "primary-awg.conf")
		if r.Content != "" {
			if _, e = config.ParseAWG([]byte(r.Content)); e != nil {
				return nil, validation.Public(e)
			}
			if e = config.SaveAWG(path, []byte(r.Content)); e != nil {
				return nil, fmt.Errorf("cannot save private AWG configuration")
			}
		}
		if r.Activate {
			if c.stateDir != StateDir {
				return nil, fmt.Errorf("activation requires fixed router state path")
			}
			p := c.basePolicy
			if p == nil {
				p, e = loadInstalledPolicy()
				if e != nil {
					return nil, fmt.Errorf("router policy unavailable")
				}
			}
			s := c.settings
			s.Enabled = true
			s.DNSPort = "53"
			s.LocalDNSPort = "1053"
			s.Options.TestClient = ""
			s.Options.Selection = contract.Selection{General: contract.Down, Games: contract.Down}
			guard, e := dataplane.BuildBootGuard(p, s.Options)
			if e != nil {
				return nil, fmt.Errorf("boot guard rejected")
			}
			if e = dataplane.CheckBootOwnership(); e != nil {
				return nil, fmt.Errorf("foreign boot guard exists")
			}
			if e = config.ActivateAWG(path, s.Options.WAN); e != nil {
				return nil, fmt.Errorf("AWG activation failed; rollback remains available")
			}
			if e = config.HomeSetup(guard); e != nil {
				return nil, fmt.Errorf("guarded activation failed; rollback remains available")
			}
			if e = c.saveSettings(s); e != nil {
				return nil, e
			}
			if !c.live {
				if e = dataplane.Run("/etc/init.d/flr-runtime", "enable"); e != nil {
					return nil, fmt.Errorf("runtime service enable failed")
				}
			}
			c.vpnRestart = c.vpnStarted
			c.notify()
		}
		b, e := os.ReadFile(path)
		if os.IsNotExist(e) {
			if c.stateDir == StateDir {
				return config.CurrentAWGMetadata()
			}
			return map[string]any{"configured": false, "stored": false, "activated": false}, nil
		}
		if e != nil {
			return nil, fmt.Errorf("AWG configuration unavailable")
		}
		awg, e := config.ParseAWG(b)
		if e != nil {
			return nil, fmt.Errorf("stored AWG configuration invalid")
		}
		return map[string]any{"configured": true, "stored": true, "activated": false, "activation_state": activationState(r.Activate), "endpoint": awg["Endpoint"], "address": awg["Address"], "awg_version": "3.1"}, nil
	}
	return nil, fmt.Errorf("unknown operation")
}

// Settings metadata may intentionally repeat a transport credential. Use the
// profile redactor rather than exposing such metadata through another DTO.
func (c *Controller) safeSettings() Settings {
	s := c.settings
	// Report the bind in use (the router's LAN address); the stored bind is
	// kept for rollback (storedDirectDefault). Sending this form back as a
	// direct_proxy change persists enabled and port and keeps the stored bind.
	c.mu.RLock()
	s.DirectProxy = c.effectiveDirect()
	c.mu.RUnlock()
	if s.Version == 2 {
		s.PrimaryGroup, s.ProfileSelection, s.FamilyOrder = "", "auto", nil
		// Report the effective policy; the stored form omits the default.
		warm := s.EffectiveWarmReserve()
		s.WarmReserve = &warm
		s.RoutingMode = s.EffectiveRoutingMode()
		q := s.effectiveTunnelQoS()
		s.TunnelQoS = &q
		return s
	}
	for _, p := range c.registry.Profiles {
		p.ServerGroup = s.PrimaryGroup
		s.PrimaryGroup = p.Summary().ServerGroup
	}
	return s
}

func (c *Controller) rollbackPending() bool {
	info, e := os.Lstat(filepath.Join(c.stateDir, "rollback.pending"))
	return e == nil && info.Mode().IsRegular() && info.Size() > 0 && info.Size() < 128
}

func activationState(requested bool) string {
	if requested {
		return "pending"
	}
	return "idle"
}
