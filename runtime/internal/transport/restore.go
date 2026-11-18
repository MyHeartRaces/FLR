package transport

import (
	"context"
	"fmt"
	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"time"
)

// RestoreReserve restores a *new* service-owned backend after an intrusive
// test. It does not resurrect application sessions interrupted by that test.
func (m *Manager) RestoreReserve(lifetime context.Context, now time.Time, registry *connection.Registry, selection connection.Selection, order connection.Order, id, revision string, generation uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.connectionState()
	if lifetime.Err() != nil || m.requestedGeneration.Load() != generation || m.state.Generation != generation || s.active == nil || s.active.Family != "awg" {
		return fmt.Errorf("reserve restoration superseded")
	}
	candidates, err := connection.Candidates(registry, selection, order)
	if err != nil {
		return err
	}
	var item *connection.Connection
	for _, c := range candidates {
		if c.ID == id && c.Revision == revision && c.Family != "awg" && c.Profile != nil {
			v := c.Clone()
			item = &v
			break
		}
	}
	if item == nil {
		return fmt.Errorf("reserve identity unavailable")
	}
	if s.slot != nil && connectionKey(*s.slot) == connectionKey(*item) && m.backend.Alive() {
		m.refreshReserve()
		return nil
	}
	// The single slot must be free: no standby start still running and no
	// quarantined standby process. Neither carried flows, so stopping them
	// needs no conntrack cleanup.
	if s.admission != nil {
		if !m.abandonAdmission(m.AdmissionWait) {
			return fmt.Errorf("reserve cleanup pending")
		}
		m.stopStandby("manual_test", nil, now)
	}
	if !m.retryQuarantine("manual_test", now) || !m.retireSlot("manual_test") {
		return fmt.Errorf("reserve cleanup pending")
	}
	// The new process carries no flows: it is restored as a warm standby when
	// the warm policy is on, otherwise as an ordinary reserve (admitReserve).
	if err := m.admitReserve(lifetime, now, *item, generation, "manual_test"); err != nil {
		return fmt.Errorf("reserve restoration failed or superseded")
	}
	m.recordOperation("manual_test", "selection", contract.Gecko, item, nil)
	return nil
}
