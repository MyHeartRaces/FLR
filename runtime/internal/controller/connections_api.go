package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/config"
	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/control"
	"github.com/MyHeartRaces/FLR/runtime/internal/dataplane"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
	"github.com/MyHeartRaces/FLR/runtime/internal/validation"
)

func cloneSettings(s Settings) Settings {
	raw := mustJSON(s)
	var copy Settings
	json.Unmarshal(raw, &copy)
	return copy
}
func (c *Controller) checkConnectionGeneration(expected *uint64) error {
	if expected == nil {
		return nil
	} // compatibility operations are serialized.
	c.mu.RLock()
	current := c.generation
	c.mu.RUnlock()
	if *expected != current {
		return fmt.Errorf("state changed; refresh before repeating the action")
	}
	return nil
}
func (c *Controller) advanceChoice() {
	c.mu.Lock()
	c.choiceEpoch++
	epoch := c.choiceEpoch
	if c.testCancel != nil {
		c.testCancel()
	}
	c.testOverride = nil
	c.transportState.Pending = true
	c.transportState.Requested = c.settings.Selection
	c.mu.Unlock()
	if c.transports != nil {
		c.transports.RequestGeneration(epoch)
	}
}
func (c *Controller) syncProfileAdapter() {
	c.registry = &profile.Registry{Version: 1}
	for _, item := range c.connections.Connections {
		if item.Profile != nil {
			p := *item.Profile
			p.Enabled, p.UserDisabled = item.Enabled, !item.Enabled
			c.registry.Profiles = append(c.registry.Profiles, p)
		}
	}
	c.registry.ApplyAvailability(c.available)
}
func (c *Controller) commitConnections(next *connection.Registry, settings Settings, reselect bool) error {
	settings.SavedGeneration = c.Status().Generation + 1
	if err := ValidateSettings(settings); err != nil {
		return err
	}
	if _, err := connection.Candidates(next, settings.Selection, settings.Order); err != nil {
		return err
	}
	if err := commitConnectionState(c.stateDir, next, settings, c.writeConnectionState); err != nil {
		return err
	}
	changed := settings.Selection != c.settings.Selection || reselect
	if c.testOverride != nil {
		for _, old := range c.connections.Connections {
			if old.ID != c.testOverride.ID && (c.testGuard == nil || (old.ID != c.testGuard.NativeID && old.ID != c.testGuard.ActiveID && old.ID != c.testGuard.ReserveID)) {
				continue
			}
			found := false
			for _, item := range next.Connections {
				if item.ID == old.ID && item.Revision == old.Revision && item.Enabled {
					found = true
				}
			}
			if !found {
				changed = true
			}
		}
	}
	c.mu.Lock()
	c.settings = settings
	c.connections = next
	c.generation++
	c.mu.Unlock()
	c.syncProfileAdapter()
	if changed {
		c.advanceChoice()
	}
	c.notify()
	return nil
}
func (c *Controller) connectionAvailability(item connection.Connection) string {
	for _, component := range item.Summary().Capabilities.RequiredComponents {
		if !c.available[component] {
			return "missing-component:" + component
		}
	}
	return ""
}
func (c *Controller) connectionResponse() map[string]any {
	availability := map[string]string{}
	for _, item := range c.connections.Connections {
		availability[item.ID] = c.connectionAvailability(item)
	}
	status := c.Status()
	return map[string]any{"connections": c.connections.Summaries(), "selection": c.settings.Selection, "order": c.settings.Order, "generation": status.Generation, "status": status, "availability": availability, "vpn_enabled": c.settings.Enabled, "rollback_pending": c.rollbackPending(), "migration_notice": c.settings.MigrationNotice}
}
func (c *Controller) importedConnectionData(r control.APIRequest) ([]byte, error) {
	data := []byte(r.Data)
	if r.URL != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		var err error
		data, err = (Fetcher{WAN: c.settings.Options.WAN}).Fetch(ctx, r.URL)
		if err != nil {
			return nil, err
		}
	}
	return data, nil
}
func (c *Controller) validateConnectionChanges(next *connection.Registry) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, item := range next.Connections {
		unchanged := false
		for _, old := range c.connections.Connections {
			if old.ID == item.ID && old.Revision == item.Revision {
				unchanged = true
			}
		}
		if !unchanged && item.Profile != nil {
			if err := c.validateEngine(ctx, *item.Profile); err != nil {
				return fmt.Errorf("native engine configuration rejected; stored connections unchanged")
			}
		}
	}
	return connection.ValidateRegistry(next)
}

func (c *Controller) handleConnectionsAPI(r control.APIRequest) (any, bool, error) {
	operation := r.Operation
	legacy := false
	switch operation {
	case "profiles":
		items := []profile.Summary{}
		for _, item := range c.connections.Connections {
			if item.Profile == nil {
				continue
			}
			public := item.Profile.Summary()
			labels := item.Summary()
			public.ID, public.Name, public.ServerGroup, public.Enabled = item.ID, labels.Name, labels.Group, item.Enabled
			public.DisabledReason = c.connectionAvailability(item)
			items = append(items, public)
		}
		selection := "auto"
		if c.settings.Selection.Mode == "connection" {
			selection = c.settings.Selection.ID
		}
		return map[string]any{"profiles": items, "selection": selection}, true, nil
	case "import":
		legacy, operation, r.Data = true, "connection-import", r.Content
	case "select":
		legacy, operation = true, "selection"
		selection := connection.Selection{Mode: "connection", ID: r.ID}
		if r.ID == "auto" {
			selection = connection.Selection{Mode: "auto"}
		}
		r.Selection = mustJSON(selection)
	case "profile-update":
		legacy, operation = true, "connection-update"
		metadata := map[string]any{}
		if r.Enabled != nil {
			metadata["enabled"] = *r.Enabled
		}
		if r.ServerGroup != nil {
			metadata["group"] = *r.ServerGroup
		}
		r.Metadata = mustJSON(metadata)
	case "profile-delete":
		legacy, operation = true, "connection-delete"
	case "primary-awg":
		result, err := c.compatibilityAWG(r)
		return result, true, err
	case "help", "capabilities":
		return map[string]any{"api_version": 2, "families": connection.Families, "web_request_bytes": 65536, "cli_import_bytes": profile.MaxImportBytes, "max_import_bytes": profile.MaxImportBytes, "max_profiles": profile.MaxProfiles, "operations": []string{"diagnostics", "diagnostics-export", "connection-list", "connection-import", "connection-update", "connection-replace", "connection-delete", "selection", "connection-order", "connection-test", "connection-export", "vpn-activate", "status", "settings", "refresh", "rollback-confirm", "device", "profiles", "import", "select", "profile-update", "profile-delete", "primary-awg"}, "components": c.available, "managed_slot": "gecko", "tcp_only_games": "fail-closed"}, true, nil
	case "connection-list", "connection-import", "connection-update", "connection-replace", "connection-delete", "selection", "connection-order", "connection-test", "connection-export", "vpn-activate":
	default:
		return nil, false, nil
	}
	if err := c.checkConnectionGeneration(r.ExpectedGeneration); err != nil {
		return nil, true, err
	}
	if operation == "connection-list" {
		return c.connectionResponse(), true, nil
	}
	if operation == "connection-export" {
		for _, item := range c.connections.Connections {
			if item.ID == r.ID {
				result, err := exportConnection(item)
				if err != nil {
					return nil, true, err
				}
				result["generation"] = c.Status().Generation
				return result, true, nil
			}
		}
		return nil, true, fmt.Errorf("connection not found")
	}
	if operation == "connection-test" {
		if !c.live || !c.settings.Enabled || c.transports == nil {
			return nil, true, fmt.Errorf("connection test requires the running VPN")
		}
		if c.testStatus != nil && c.testStatus.Pending {
			return nil, true, fmt.Errorf("another connection test is pending")
		}
		found := false
		for _, item := range c.connections.Connections {
			if item.ID == r.ID && c.connectionAvailability(item) == "" {
				found = true
			}
		}
		if !found {
			return nil, true, fmt.Errorf("connection unavailable for a real test")
		}
		if _, err := os.Lstat(filepath.Join(c.stateDir, "connection-test.json")); err == nil {
			return nil, true, fmt.Errorf("previous connection test recovery required; restart service")
		} else if !os.IsNotExist(err) {
			return nil, true, fmt.Errorf("private connection test watchdog unavailable")
		}
		expected := c.Status().Generation
		c.mu.Lock()
		c.testStatus = &ConnectionTestResult{ID: r.ID, Pending: true, Phase: "queued"}
		c.mu.Unlock()
		c.testWorkers.Add(1)
		go func() { defer c.testWorkers.Done(); c.testConnection(c.ctx, r.ID, expected) }()
		return map[string]any{"pending": true, "id": r.ID}, true, nil
	}
	if operation == "vpn-activate" {
		result, err := c.activateConnectionsVPN()
		return result, true, err
	}
	next := c.connections.Clone()
	settings := cloneSettings(c.settings)
	reselect := false
	switch operation {
	case "connection-import":
		data, err := c.importedConnectionData(r)
		if err != nil {
			return nil, true, err
		}
		if _, err := next.Import(data); err != nil {
			return nil, true, validation.Public(err)
		}
		settings.Order = connection.ReconcileOrder(next, settings.Order)
	case "connection-replace":
		data, err := c.importedConnectionData(r)
		if err != nil {
			return nil, true, err
		}
		if err := next.Replace(r.ID, data); err != nil {
			return nil, true, validation.Public(err)
		}
		settings.Order = connection.ReconcileOrder(next, settings.Order)
	case "connection-update":
		var metadata struct {
			Name         *string `json:"name"`
			Group        *string `json:"group"`
			Enabled      *bool   `json:"enabled"`
			RoamPorts    *string `json:"roam_ports"`
			RoamInterval *int    `json:"roam_interval"`
		}
		if err := connection.DecodeStrict(r.Metadata, &metadata); err != nil {
			return nil, true, err
		}
		found := false
		for i := range next.Connections {
			item := &next.Connections[i]
			if item.ID != r.ID {
				continue
			}
			found = true
			if metadata.Name != nil {
				item.Name = *metadata.Name
			}
			if metadata.Group != nil {
				item.Group = *metadata.Group
			}
			if metadata.Enabled != nil {
				item.Enabled = *metadata.Enabled
			}
			// AWG endpoint roaming: a setting only, applied by the next round
			// without a new choice epoch, so no session moves.
			if metadata.RoamPorts != nil || metadata.RoamInterval != nil {
				ports, interval := item.RoamPorts, item.RoamInterval
				if metadata.RoamPorts != nil {
					ports = *metadata.RoamPorts
				}
				if metadata.RoamInterval != nil {
					interval = *metadata.RoamInterval
				}
				if err := item.SetRoam(ports, interval); err != nil {
					return nil, true, err
				}
			}
		}
		if !found {
			return nil, true, fmt.Errorf("connection not found")
		}
		if legacy && r.Priority != nil {
			for _, item := range next.Connections {
				if item.ID != r.ID {
					continue
				}
				ids := []string{}
				for _, id := range settings.Order.Connections[item.Family] {
					if id != item.ID {
						ids = append(ids, id)
					}
				}
				position := *r.Priority
				if position < 0 {
					position = 0
				}
				if position > len(ids) {
					position = len(ids)
				}
				ids = append(ids, "")
				copy(ids[position+1:], ids[position:])
				ids[position] = item.ID
				settings.Order.Connections[item.Family] = ids
			}
		}
	case "connection-delete":
		moveToAuto := false
		if len(r.Selection) > 0 {
			var selection connection.Selection
			if err := connection.DecodeStrict(r.Selection, &selection); err != nil || selection != (connection.Selection{Mode: "auto"}) {
				return nil, true, fmt.Errorf("deletion transition must explicitly select auto")
			}
			moveToAuto = true
		}
		var err error
		settings.Selection, err = next.Delete(r.ID, settings.Selection, moveToAuto)
		if err != nil {
			return nil, true, err
		}
		settings.Order = connection.ReconcileOrder(next, settings.Order)
	case "selection":
		// Decode into a fresh value: decoding into the stored selection would
		// keep its id/family when the request omits them, so {"mode":"auto"}
		// after a connection selection became an invalid auto-with-id.
		var selection connection.Selection
		if err := connection.DecodeStrict(r.Selection, &selection); err != nil {
			return nil, true, err
		}
		settings.Selection = selection
		reselect = true
	case "connection-order":
		if err := connection.DecodeStrict(r.Order, &settings.Order); err != nil {
			return nil, true, err
		}
		reselect = r.Reselect
	}
	if err := c.validateConnectionChanges(next); err != nil {
		return nil, true, err
	}
	if err := c.commitConnections(next, settings, reselect); err != nil {
		return nil, true, err
	}
	return c.connectionResponse(), true, nil
}

func (c *Controller) compatibilityAWG(r control.APIRequest) (any, error) {
	if r.Content != "" {
		next := c.connections.Clone()
		items, err := connection.ParseImport([]byte(r.Content))
		if err != nil || len(items) != 1 || items[0].Family != "awg" {
			return nil, fmt.Errorf("invalid primary AWG configuration")
		}
		found := false
		for _, item := range next.Connections {
			if item.ID == "awg-primary" {
				found = true
			}
		}
		if found {
			if err := next.Replace("awg-primary", []byte(r.Content)); err != nil {
				return nil, err
			}
		} else {
			item := items[0]
			item.ID, item.Name = "awg-primary", "AWG primary"
			next.Connections = append(next.Connections, item)
		}
		s := cloneSettings(c.settings)
		s.Order = connection.ReconcileOrder(next, s.Order)
		if err := c.commitConnections(next, s, false); err != nil {
			return nil, err
		}
	}
	if r.Activate {
		if _, err := c.activateConnectionsVPN(); err != nil {
			return nil, err
		}
	}
	for _, item := range c.connections.Connections {
		if item.ID == "awg-primary" {
			return map[string]any{"configured": true, "stored": true, "activated": c.activeConnection != nil && c.activeConnection.ID == item.ID, "activation_state": activationState(r.Activate), "endpoint": item.Summary().Endpoint, "address": item.AWG["Address"], "awg_version": "3.1"}, nil
		}
	}
	return map[string]any{"configured": false, "stored": false, "activated": false}, nil
}
func (c *Controller) activateConnectionsVPN() (any, error) {
	candidates, err := connection.Candidates(c.connections, c.settings.Selection, c.settings.Order)
	if err != nil {
		return nil, err
	}
	var chosen *connection.Connection
	for _, item := range candidates {
		if c.connectionAvailability(item) == "" {
			copy := item.Clone()
			chosen = &copy
			break
		}
	}
	if chosen == nil {
		return nil, fmt.Errorf("enable an available connection before VPN activation")
	}
	if !c.settings.Enabled {
		s := cloneSettings(c.settings)
		s.Enabled, s.DNSPort, s.LocalDNSPort = true, "53", "1053"
		s.Options.TestClient = ""
		s.Options.Selection = contract.Selection{General: contract.Down, Games: contract.Down}
		var awg *connection.Connection
		if chosen.Family == "awg" {
			awg = chosen
		}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if err := c.activateVPN(ctx, s, awg); err != nil {
			return nil, fmt.Errorf("guarded activation failed; rollback remains available")
		}
		if err := c.saveSettings(s); err != nil {
			return nil, err
		}
	}
	if c.vpnStarted {
		c.advanceChoice()
	}
	c.vpnRestart = c.vpnStarted
	c.notify()
	return map[string]any{"activated": false, "activation_state": "pending", "confirmation_required": true}, nil
}
func (c *Controller) guardedConnectionActivation(ctx context.Context, settings Settings, awg *connection.Connection) error {
	if c.stateDir != StateDir {
		return fmt.Errorf("activation requires fixed router state")
	}
	p := c.policy
	if p == nil {
		var err error
		p, err = loadInstalledPolicy()
		if err != nil {
			return fmt.Errorf("router policy unavailable")
		}
	}
	guard, err := dataplane.BuildBootGuard(p, settings.Options)
	if err != nil {
		return err
	}
	if err := dataplane.CheckBootOwnership(); err != nil {
		return err
	}
	var fields map[string]string
	if awg != nil {
		fields = awg.AWG
	}
	if err := config.ActivateVPN(ctx, fields, settings.Options.WAN); err != nil {
		return err
	}
	if err := config.HomeSetup(guard); err != nil {
		return err
	}
	if !c.live {
		if err := dataplane.Run("/etc/init.d/flr-runtime", "enable"); err != nil {
			return err
		}
	}
	return nil
}

// exportConnection returns the stored configuration in a form the connection
// importer accepts (format "url", "json" or "awg-conf"). The result contains
// credentials: ParseAPI classifies connection-export as a write, and errors
// never include configuration text.
func exportConnection(item connection.Connection) (map[string]any, error) {
	labels := item.Summary()
	result := map[string]any{"id": item.ID, "name": labels.Name, "family": item.Family, "revision": item.Revision}
	if item.Family == "awg" {
		text, err := config.AWGText(item.AWG)
		if err != nil {
			return nil, fmt.Errorf("stored AWG connection cannot be exported")
		}
		result["format"], result["engine"], result["config"], result["filename"] = "awg-conf", "awg", string(text), item.ID+".conf"
		return result, nil
	}
	if item.Profile == nil {
		return nil, fmt.Errorf("stored connection cannot be exported")
	}
	exported, err := profile.Export(*item.Profile)
	if err != nil {
		return nil, err
	}
	extension := ".txt"
	if exported.Format == profile.ExportJSON {
		extension = ".json"
	}
	result["format"], result["engine"], result["config"], result["filename"] = exported.Format, exported.Engine, exported.Config, item.ID+extension
	if exported.Note != "" {
		result["note"] = exported.Note
	}
	return result, nil
}
