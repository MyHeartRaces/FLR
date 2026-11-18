package transport

import (
	"context"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
)

// readvanceAWG runs while a healthy proxy connection is the default for new
// flows and AWG connections rank above it (they failed, or were cooling when
// the proxy was chosen). Owner decision: the warm reserve stays on and takes
// new flows first on an AWG failure; AWG candidates are then tried again in
// their configured order, main before spare, so new flows return to AWG as
// soon as one qualifies. Nothing on the proxy slot changes: its process and
// existing flows stay, and it remains the retained reserve after the switch.
//
// It runs only after a fallback (a native AWG identity was configured when the
// proxy became the default); a proxy chosen by order alone, or kept across an
// order edit, keeps its affinity.
//
// Pacing and hysteresis:
//   - The configured native identity is measured every round beside the slot
//     (connectionProbes); a healthy one past its cool-down fails back through
//     the ordinary check in StepConnections, not here.
//   - A configured native ranked above the proxy that is healthy, recovering
//     (its last sample was clean) or unmeasured this round is never displaced:
//     its recovery window decides.
//   - Only when it failed its latest sample (or is absent) is the next AWG
//     candidate past its cool-down switched in, at most one per round. That
//     replacement retires only AWG conntrack (no new flows use AWG while the
//     proxy is the default). A switched-in candidate that fails its probe is
//     cooled exactly like a failed sweep attempt (30 s doubling to 5 min).
//   - A switched-in candidate is selected only when its health state is up
//     under the policy and the sample just taken passed TCP and UDP.
func (m *Manager) readvanceAWG(ctx context.Context, now time.Time, candidates []connection.Connection, activeRank int, nativeSample connectionSample, generation uint64) {
	s := m.connectionState()
	if !s.readvance || s.awg == nil || ctx.Err() != nil || m.requestedGeneration.Load() != generation || m.state.Generation != generation || m.state.Pending || m.cleanupPending || m.slotCleanupPending {
		return
	}
	if activeRank > len(candidates) {
		activeRank = len(candidates)
	}
	configured := ""
	if s.native != nil && nativeSample.valid && nativeSample.present {
		configured = connectionKey(*s.native)
		for _, c := range candidates[:activeRank] {
			if connectionKey(c) != configured {
				continue
			}
			state := s.health[configured]
			r := nativeSample.result
			failed := r.NotMeasured == "" && (!r.TCP || !r.UDP)
			if state.Healthy() || !failed {
				return
			}
		}
	}
	for _, c := range candidates[:activeRank] {
		key := connectionKey(c)
		if c.Family != "awg" || key == configured || now.Before(m.retries[key].after) {
			continue
		}
		if err := m.cleanupChannel(contract.AWG, "native_replacement"); err != nil {
			// The proxy stays the default; the attempt is repeated next round.
			m.state.LastError = "native cleanup failed"
			return
		}
		err := s.awg.Switch(ctx, c)
		m.recordOperation("native_replacement", "native", contract.AWG, &c, err)
		m.resetRoam()
		if err != nil {
			if s.native != nil {
				delete(s.health, connectionKey(*s.native))
			}
			s.native = nil
			m.state.AWG = health.State{Last: health.Result{NotMeasured: "unavailable"}}
			if ctx.Err() == nil {
				m.cool(key, now)
			}
			return
		}
		copy := c.Clone()
		s.native = &copy
		if ctx.Err() != nil {
			// Measured next round: the native identity is monitored beside the slot.
			return
		}
		state := m.nativeProbe(ctx, now, c)
		if m.requestedGeneration.Load() != generation || state.Last.NotMeasured != "" {
			return
		}
		if state.Healthy() && state.Last.TCP && state.Last.UDP {
			m.selectConnection(c, state, generation)
			return
		}
		if !state.Last.TCP || !state.Last.UDP {
			m.cool(key, now)
		}
		return
	}
}
