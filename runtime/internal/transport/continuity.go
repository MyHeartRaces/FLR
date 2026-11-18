package transport

import (
	"context"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"sync"
	"time"
)

type connectionSample struct {
	result  health.Result
	present bool
	valid   bool
}

func (m *Manager) connectionProbes(ctx context.Context, now time.Time) (native, slot connectionSample) {
	s := m.connectionState()
	monitorNative := s.native != nil && (s.active != nil || s.slot != nil)
	if ctx.Err() != nil {
		if monitorNative {
			native = unmeasuredSample(ctx)
		}
		if s.slot != nil {
			slot = unmeasuredSample(ctx)
		}
		return
	}
	var workers sync.WaitGroup
	nativePresent := false
	if monitorNative {
		native.present = s.awg != nil && s.awg.Present()
		native.valid = true
		nativePresent = native.present
		if native.present {
			workers.Add(1)
			go func() {
				defer workers.Done()
				bounded, cancel := context.WithTimeout(ctx, m.ProbeTimeout)
				defer cancel()
				native.result = s.awg.Probe(bounded)
				if ctx.Err() == context.Canceled {
					native = unmeasuredSample(ctx)
				}
			}()
		}
	}
	if s.slot != nil {
		// Liveness is checked every round, so a dead standby is retired at once.
		// Only the measurement of a standby beside a settled native default
		// follows the warm interval; it carries no flows meanwhile.
		slot.present = m.backend.Alive()
		slot.valid = true
		if slot.present && m.standbySettled(now, nativePresent) {
			slot = connectionSample{}
		} else if slot.present {
			workers.Add(1)
			go func() {
				defer workers.Done()
				slot.result = m.runProbe(ctx, *s.slot.Profile)
				if ctx.Err() == context.Canceled {
					slot = unmeasuredSample(ctx)
				}
			}()
		}
	}
	workers.Wait()
	return
}

func unmeasuredSample(ctx context.Context) connectionSample {
	reason := "budget_exhausted"
	if ctx.Err() == context.Canceled {
		reason = "cancelled"
	}
	return connectionSample{result: health.Result{NotMeasured: reason}, present: true, valid: true}
}

// Cleanup is scoped to the resources whose affinity is being retired. A healthy
// default switch alone never calls it; shutdown and explicit intent use quiesce.
func (m *Manager) SetChannelCleanup(cleanup func(contract.Channel, string) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.channelCleanup = cleanup
}

// ReserveWarm separates a standby that has carried no flows from a reserve
// retained after failback, whose older sessions still use it.
func (m *Manager) refreshReserve() {
	s := m.connectionState()
	m.state.ReserveConnection = nil
	m.state.ReserveWarm = false
	if s.slot != nil && (s.active == nil || connectionKey(*s.slot) != connectionKey(*s.active)) {
		v := s.slot.Summary()
		m.state.ReserveConnection = &v
		m.state.ReserveWarm = s.warm
	}
}

func (m *Manager) cleanupChannel(channel contract.Channel, reason string) error {
	var err error
	if m.channelCleanup != nil {
		err = m.channelCleanup(channel, reason)
	} else if m.quiesce != nil {
		err = m.quiesce()
	}
	owner := m.connectionState().slot
	if channel == contract.AWG {
		owner = m.connectionState().native
	}
	m.recordOperation(reason, "cleanup", channel, owner, err)
	return err
}

func (m *Manager) deselectConnection() {
	m.connectionState().active = nil
	m.state.ActiveConnection = nil
	m.state.Active = nil
	m.state.Selection = contract.Selection{General: contract.Down, Games: contract.Down}
	m.refreshReserve()
}

// Keep the old owner until both conntrack retirement and Stop succeed. Its mark
// must never be reused for another endpoint after a partial cleanup failure.
func (m *Manager) retireSlot(reason string) bool {
	s := m.connectionState()
	if s.slot == nil && m.active == nil && !m.slotCleanupPending {
		return true
	}
	m.slotCleanupPending = true
	if err := m.cleanupChannel(contract.Gecko, reason); err != nil {
		m.state.LastError = "slot cleanup failed"
		m.state.Pending = true
		return false
	}
	err := m.backend.Stop()
	m.recordOperation(reason, "stop", contract.Gecko, s.slot, err)
	if err != nil {
		m.state.LastError = "engine shutdown failed"
		m.state.Pending = true
		return false
	}
	if s.active != nil && s.active.Family != "awg" {
		m.deselectConnection()
	}
	s.slot = nil
	s.warm = false
	m.active = nil
	m.slotCleanupPending = false
	m.state.Slot = health.State{}
	m.state.ReserveConnection = nil
	m.state.ReserveWarm = false
	return true
}
