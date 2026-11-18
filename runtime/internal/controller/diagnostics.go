package controller

import (
	"context"
	"fmt"
	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/control"
	"github.com/MyHeartRaces/FLR/runtime/internal/diagnostic"
	"github.com/MyHeartRaces/FLR/runtime/internal/transport"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

func newHistory() *diagnostic.History {
	boot := "unknown"
	if raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil && len(raw) < 80 {
		boot = strings.TrimSpace(string(raw))
	}
	source := ""
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				source = setting.Value
			}
		}
	}
	return diagnostic.New(boot, "0.7-runtime", source)
}
func summaryIdentity(s *connection.Summary) diagnostic.Identity {
	if s == nil {
		return diagnostic.Identity{}
	}
	return diagnostic.Identity{ID: s.ID, Revision: s.Revision}
}
func transitionReason(from, to *connection.Summary) string {
	if from != nil && to != nil {
		if from.Family != "awg" && to.Family == "awg" {
			return "failback"
		}
		if from.Family == "awg" && to.Family != "awg" {
			return "fallback"
		}
	}
	return "selection"
}
func operationOutcome(err error) string {
	if err != nil {
		return "failed"
	}
	return "applied"
}
func (c *Controller) saveDiagnostics() {
	if c.history != nil && c.historyPath != "" {
		c.diagnosticSavePending.Store(c.history.Save(c.historyPath) != nil)
	}
}

// Called under different controller/manager locks: it never reacquires either.
func (c *Controller) recordDecision(d diagnostic.Decision) {
	if c.history == nil {
		return
	}
	c.history.AddDecision(d)
	c.saveDiagnostics()
}
func (c *Controller) recordPublication(from *connection.Summary, next transport.Snapshot, stage, outcome string) {
	c.recordDecision(diagnostic.Decision{At: time.Now(), Epoch: next.Generation, ActualKnown: true, Actual: summaryIdentity(c.activeConnection), ActualSelection: c.selection, From: summaryIdentity(from), To: summaryIdentity(next.ActiveConnection), Reason: transitionReason(from, next.ActiveConnection), Stage: stage, Outcome: outcome, ReserveRetained: next.ReserveConnection != nil})
}
func (c *Controller) recordRound(next transport.Snapshot) {
	if c.history == nil {
		return
	}
	native := c.transports.NativeConnection()
	a := diagnostic.Path{Health: next.AWG}
	if native != nil {
		a.ID, a.Revision = native.ID, native.Revision
	}
	slot := next.ReserveConnection
	if slot == nil && next.ActiveConnection != nil && next.ActiveConnection.Family != "awg" {
		slot = next.ActiveConnection
	}
	p := diagnostic.Path{Health: next.Slot}
	if slot != nil {
		p.ID, p.Revision = slot.ID, slot.Revision
	}
	c.mu.RLock()
	actual := c.selection
	c.mu.RUnlock()
	c.history.AddRound(diagnostic.Round{At: time.Now(), Epoch: next.Generation, Native: a, Slot: p, Selection: actual, Requested: next.Requested, WAN: c.wan.Snapshot()})
}
func (c *Controller) diagnosticAPI(r control.APIRequest) (any, error) {
	if r.Operation == "diagnostics" {
		return c.Status().Diagnostics, nil
	}
	if c.history == nil {
		return nil, fmt.Errorf("diagnostic history unavailable")
	}
	parts := strings.Split(r.Value, ":")
	if len(parts) > 2 {
		return nil, fmt.Errorf("invalid diagnostic cursor")
	}
	values := [2]uint64{}
	for i, part := range parts {
		if part == "" && i == 0 {
			continue
		}
		if len(part) > 16 {
			return nil, fmt.Errorf("invalid diagnostic cursor")
		}
		n, err := strconv.ParseUint(part, 10, 64)
		if err != nil || n > 9007199254740991 {
			return nil, fmt.Errorf("invalid diagnostic cursor")
		}
		values[i] = n
	}
	return c.history.PageUntil(values[0], values[1])
}
func (c *Controller) initializeWAN() {
	c.wan = diagnostic.NewWAN(func(ctx context.Context) diagnostic.WANResult {
		c.mu.RLock()
		device := c.settings.Options.WAN
		c.mu.RUnlock()
		return diagnostic.ProbeWAN(ctx, device)
	})
}

func (c *Controller) recordCleanup(reason, stage string, channel contract.Channel, from *connection.Summary, err error) {
	c.recordDecision(diagnostic.Decision{At: time.Now(), Epoch: c.choiceEpoch, ActualKnown: true, Actual: summaryIdentity(c.activeConnection), ActualSelection: c.selection, From: summaryIdentity(from), Reason: reason, Stage: stage, Channel: channel, Outcome: operationOutcome(err)})
}
