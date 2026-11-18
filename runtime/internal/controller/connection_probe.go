package controller

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/config"
	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/dataplane"
	"github.com/MyHeartRaces/FLR/runtime/internal/diagnostic"
	"github.com/MyHeartRaces/FLR/runtime/internal/privatefile"
	"github.com/MyHeartRaces/FLR/runtime/internal/transport"
)

type ConnectionTestResult struct {
	ID         string `json:"id"`
	Pending    bool   `json:"pending"`
	Phase      string `json:"phase"`
	Measured   bool   `json:"measured"`
	TCP        bool   `json:"tcp"`
	UDP        bool   `json:"udp"`
	Restored   bool   `json:"restored"`
	DurationMS int64  `json:"duration_ms"`
	Reason     string `json:"reason,omitempty"`
}
type connectionTestGuard struct {
	Version         int                  `json:"version"`
	Epoch           uint64               `json:"epoch"`
	ID              string               `json:"id"`
	Requested       connection.Selection `json:"requested"`
	AWG             config.AWGOwnedState `json:"awg"`
	NativeID        string               `json:"native_id,omitempty"`
	NativeRevision  string               `json:"native_revision,omitempty"`
	ActiveID        string               `json:"active_id,omitempty"`
	ActiveRevision  string               `json:"active_revision,omitempty"`
	ReserveID       string               `json:"reserve_id,omitempty"`
	ReserveRevision string               `json:"reserve_revision,omitempty"`
	manager         *transport.Manager
}

func (c *Controller) setConnectionTest(result ConnectionTestResult) {
	c.mu.Lock()
	c.testStatus = &result
	c.mu.Unlock()
}

// The persisted user choice is never overwritten by the temporary test. The
// private marker records native restoration and survives a controller crash.
func (c *Controller) testConnection(ctx context.Context, id string, expectedGeneration uint64) (ConnectionTestResult, error) {
	start := time.Now()
	result := ConnectionTestResult{ID: id, Phase: "failed"}
	c.adminMu.Lock()
	fail := func(reason string) (ConnectionTestResult, error) {
		result.Reason = reason
		if c.testStatus == nil || c.testStatus.Phase != "recovery-pending" {
			c.setConnectionTest(result)
		}
		c.adminMu.Unlock()
		return result, fmt.Errorf("%s", reason)
	}
	if _, err := os.Lstat(filepath.Join(c.stateDir, "connection-test.json")); err == nil {
		return fail("previous connection test recovery required; restart service")
	} else if !os.IsNotExist(err) {
		return fail("private connection test watchdog unavailable")
	}
	if !c.live || !c.settings.Enabled || c.transports == nil || c.testOverride != nil {
		return fail("connection test requires an idle running VPN")
	}
	if c.Status().Proxy.Pending || c.transports.Snapshot().Pending {
		return fail("connection test requires completed route publication")
	}
	if err := c.checkConnectionGeneration(&expectedGeneration); err != nil {
		return fail("state changed before connection test; refresh and retry")
	}
	registry := c.connections.Clone()
	var target *connection.Connection
	for i := range registry.Connections {
		if registry.Connections[i].ID == id {
			registry.Connections[i].Enabled = true
			target = &registry.Connections[i]
		}
	}
	if target == nil || c.connectionAvailability(*target) != "" {
		return fail("connection unavailable for a real test")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	budget := c.connectionTestTimeout
	if budget <= 0 || budget > 15*time.Second {
		budget = 15 * time.Second
	}
	probeCtx, cancel := context.WithTimeout(ctx, budget)
	awg, err := c.captureTestAWG(probeCtx)
	if err != nil {
		cancel()
		return fail("cannot snapshot owned AWG for connection test")
	}
	if err := config.ValidateAWGOwnedState(awg); err != nil {
		cancel()
		return fail("owned AWG test snapshot rejected")
	}
	guard := &connectionTestGuard{Version: 1, Epoch: c.choiceEpoch + 1, ID: id, Requested: c.settings.Selection, AWG: awg, manager: c.transports}
	if native := c.transports.NativeConnection(); native != nil {
		guard.NativeID, guard.NativeRevision = native.ID, native.Revision
	}
	if !c.matchTestNative(guard) {
		cancel()
		return fail("owned AWG identity must be confirmed before connection test")
	}
	snapshot := c.transports.Snapshot()
	if reserve := snapshot.ReserveConnection; reserve != nil {
		guard.ReserveID, guard.ReserveRevision = reserve.ID, reserve.Revision
	}
	if actual := snapshot.ActiveConnection; actual != nil {
		guard.ActiveID, guard.ActiveRevision = actual.ID, actual.Revision
	}
	if err := privatefile.Write(filepath.Join(c.stateDir, "connection-test.json"), mustJSON(guard)); err != nil {
		cancel()
		return fail("cannot save private connection test watchdog")
	}
	selection := connection.Selection{Mode: "connection", ID: id}
	c.mu.Lock()
	c.choiceEpoch = guard.Epoch
	c.generation++
	c.testOverride, c.testCancel, c.testGuard = &selection, cancel, guard
	c.mu.Unlock()
	order := cloneSettings(c.settings).Order
	c.transports.RequestGeneration(guard.Epoch)
	c.transports.ResetConnectionRetry(id, target.Revision)
	result.Pending, result.Phase = true, "probing"
	c.setConnectionTest(result)
	c.recordTestDecision(guard, "prepared")
	// No AWG endpoint roaming while a connection test owns the transports; the
	// controller round lifts the suspension once the test guard is cleared.
	c.transports.SetRoamSuspended(true)
	c.roamSuspended = true
	c.adminMu.Unlock()
	defer cancel()
	next := guard.manager.StepConnections(probeCtx, time.Now(), registry, selection, order, guard.Epoch)
	if next.ProbeConnection == id {
		result.Measured, result.TCP, result.UDP = next.LastProbe.Measured, next.LastProbe.TCP, next.LastProbe.UDP
	}
	c.adminMu.Lock()
	if c.choiceEpoch == guard.Epoch {
		c.publishTransport(transport.Snapshot{}, next)
		result.Phase = "restoring"
		c.setConnectionTest(result)
		result.Restored, err = c.restoreConnectionTest(guard)
	} else {
		// A newer round may already be active. Retire only this test generation.
		err = guard.manager.RetireGeneration(guard.Epoch)
		result.Measured, result.TCP, result.UDP = false, false, false
		result.Reason = "test superseded by newer user choice"
	}
	if err == nil {
		err = c.clearConnectionTestMarker(guard.Epoch)
	}
	if c.testGuard == guard {
		c.mu.Lock()
		c.testGuard = nil
		c.testCancel = nil
		c.testOverride = nil
		c.mu.Unlock()
	}
	result.Pending, result.DurationMS = false, time.Since(start).Milliseconds()
	if err != nil {
		result.Phase, result.Reason = "recovery-pending", "test restoration pending; service restart can retry"
	} else if !result.Restored {
		result.Phase = "cancelled"
	} else {
		result.Phase = "finished"
	}
	c.setConnectionTest(result)
	outcome := "applied"
	if err != nil {
		outcome = "failed"
	} else if !result.Restored {
		outcome = "superseded"
	}
	c.recordTestDecision(guard, outcome)
	c.notify()
	c.adminMu.Unlock()
	return result, err
}

// Caller holds adminMu, so native restoration cannot overtake a newer write.
func (c *Controller) restoreConnectionTest(guard *connectionTestGuard) (bool, error) {
	if c.choiceEpoch != guard.Epoch || !c.settings.Enabled || c.settings.Selection != guard.Requested {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := guard.manager.RetireGeneration(guard.Epoch); err != nil {
		return false, err
	}
	if !c.matchTestNative(guard) {
		return false, fmt.Errorf("native identity changed; snapshot restoration refused")
	}
	if err := c.restoreTestAWG(ctx, guard.AWG); err != nil {
		return false, err
	}
	var native *connection.Connection
	for _, item := range c.connections.Connections {
		if item.ID == guard.NativeID && item.Revision == guard.NativeRevision && item.Enabled {
			copy := item.Clone()
			native = &copy
		}
	}
	guard.manager.RestoreNativeIdentity(native)
	c.mu.Lock()
	c.testOverride = nil
	c.choiceEpoch++
	c.generation++
	epoch := c.choiceEpoch
	c.transportState.Pending = true
	c.mu.Unlock()
	guard.manager.RequestGeneration(epoch)
	// Restore healthy affinity when an order-only edit occurred during the test.
	// This temporary order is not persisted and cannot override a manual mode.
	activeRestored := guard.ActiveID == ""
	if guard.ActiveID != "" {
		candidates, err := connection.Candidates(c.connections, c.settings.Selection, c.settings.Order)
		if err != nil {
			return false, err
		}
		for _, item := range candidates {
			if item.ID != guard.ActiveID || item.Revision != guard.ActiveRevision {
				continue
			}
			order := cloneSettings(c.settings).Order
			order.Families = frontID(order.Families, item.Family)
			order.Connections[item.Family] = frontID(order.Connections[item.Family], item.ID)
			// The recreated process belongs to the service, not the temporary
			// restoration deadline; Manager bounds the individual step itself.
			lifetime := c.ctx
			if lifetime == nil {
				lifetime = context.Background()
			}
			next := guard.manager.StepConnections(lifetime, time.Now(), c.connections, c.settings.Selection, order, epoch)
			c.publishTransport(transport.Snapshot{}, next)
			if next.Pending || c.selection != next.Selection || c.activeConnection == nil || c.activeConnection.ID != item.ID {
				return false, fmt.Errorf("default publication pending")
			}
			if guard.ReserveID != "" {
				if err := guard.manager.RestoreReserve(lifetime, time.Now(), c.connections, c.settings.Selection, c.settings.Order, guard.ReserveID, guard.ReserveRevision, epoch); err != nil {
					return false, err
				}
				c.publishTransport(next, guard.manager.Snapshot())
			}
			activeRestored = true
			break
		}
	}
	return activeRestored, nil
}
func frontID(list []string, id string) []string {
	result := []string{id}
	for _, current := range list {
		if current != id {
			result = append(result, current)
		}
	}
	return result
}
func (c *Controller) clearConnectionTestMarker(epoch uint64) error {
	path := filepath.Join(c.stateDir, "connection-test.json")
	raw, err := privatefile.Read(path, 65536)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("private test marker rejected")
	}
	var guard connectionTestGuard
	if err := connection.DecodeStrict(raw, &guard); err != nil || guard.Epoch != epoch {
		return fmt.Errorf("private test marker generation differs")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("private test marker cleanup failed")
	}
	return privatefile.SyncDir(c.stateDir)
}
func (c *Controller) recoverConnectionTest(ctx context.Context) error {
	raw, err := privatefile.Read(filepath.Join(c.stateDir, "connection-test.json"), 65536)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("private test recovery marker rejected")
	}
	var guard connectionTestGuard
	if err := connection.DecodeStrict(raw, &guard); err != nil || guard.Version != 1 || guard.Epoch == 0 || connection.ValidateSelection(guard.Requested) != nil || config.ValidateAWGOwnedState(guard.AWG) != nil {
		return fmt.Errorf("invalid private test recovery marker")
	}
	// Persistent user settings already hold the original choice. A newer user
	// choice wins, including after an interrupted native restore.
	if c.settings.Selection == guard.Requested && c.settings.Enabled && c.matchTestNative(&guard) {
		if c.stateDir == StateDir {
			snapshot, err := dataplane.CurrentSnapshot()
			if err != nil || dataplane.Preflight(snapshot) != nil {
				return fmt.Errorf("owned routing test recovery rejected")
			}
			if snapshot.TableExists {
				if err := dataplane.UpdateSelection(contract.Selection{General: contract.Down, Games: contract.Down}, false); err != nil {
					return fmt.Errorf("owned routing test recovery pending")
				}
			}
			if snapshot.Own {
				if dataplane.ClearAWG() != nil || dataplane.ClearSlot() != nil {
					return fmt.Errorf("owned flows test recovery pending")
				}
			}
		}
		if err := c.restoreTestAWG(ctx, guard.AWG); err != nil {
			return fmt.Errorf("owned AWG test recovery pending")
		}
	}
	return c.clearConnectionTestMarker(guard.Epoch)
}

// An unnamed legacy marker is safe only when it contains no owned AWG.
// Named identities must remain enabled at the exact revision.
func (c *Controller) matchTestNative(guard *connectionTestGuard) bool {
	if guard.NativeID == "" {
		return guard.NativeRevision == "" && len(guard.AWG) == 0
	}
	for _, item := range c.connections.Connections {
		if item.ID == guard.NativeID && item.Revision == guard.NativeRevision && item.Enabled && item.Family == "awg" && c.connectionAvailability(item) == "" {
			return true
		}
	}
	return false
}

func (c *Controller) recordTestDecision(guard *connectionTestGuard, outcome string) {
	c.recordDecision(diagnostic.Decision{At: time.Now(), Epoch: guard.Epoch, ActualKnown: true, Actual: summaryIdentity(c.activeConnection), ActualSelection: c.selection, From: diagnostic.Identity{ID: guard.ActiveID, Revision: guard.ActiveRevision}, To: diagnostic.Identity{ID: guard.ID}, Reason: "manual_test", Stage: "selection", Outcome: outcome, ReserveRetained: c.transports.Snapshot().ReserveConnection != nil})
}
