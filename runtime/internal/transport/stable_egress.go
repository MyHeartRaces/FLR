package transport

import (
	"context"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
)

func (m *Manager) SetStableEgress(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stableEgress != enabled {
		m.anchorEvidence = anchorEvidence{}
	}
	m.stableEgress = enabled
}

// SetStableEgressProbe provides an independent measurement of the active
// carrier's reachability to the shared egress. The callback must honor the
// context and cannot reenter the manager while the round holds its lock.
func (m *Manager) SetStableEgressProbe(probe func(context.Context, connection.Summary) (measured, reachable bool)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stableEgressProbe = probe
	m.anchorEvidence = anchorEvidence{}
}

type anchorSample struct {
	owner    string
	measured bool
	reached  bool
}

type anchorEvidence struct {
	owner  string
	misses int
}

func (m *Manager) stableEgressAuto() bool {
	return m.stableEgress && m.state.Requested.Mode == "auto"
}

func stableEgressCarrier(c *connection.Connection) bool {
	return c != nil && (c.Family == "awg" || (c.Family == "hy2" && c.Profile != nil && c.Profile.Capabilities.UDP))
}

func (m *Manager) probeStableEgress(ctx context.Context, c *connection.Connection) <-chan anchorSample {
	probe := m.stableEgressProbe
	mode := m.state.Requested.Mode
	if probe == nil || !m.stableEgress || (mode != "auto" && mode != "transport") || !stableEgressCarrier(c) || ctx.Err() != nil {
		return nil
	}
	bounded, cancel := context.WithTimeout(ctx, m.ProbeTimeout)
	owner, summary := connectionKey(*c), c.Summary()
	done := make(chan anchorSample, 1)
	go func() {
		defer cancel()
		measured, reached := probe(bounded, summary)
		done <- anchorSample{owner: owner, measured: measured, reached: reached}
	}()
	return done
}

func collectAnchorSample(ctx context.Context, pending <-chan anchorSample) anchorSample {
	if pending == nil {
		return anchorSample{}
	}
	select {
	case sample := <-pending:
		return sample
	case <-ctx.Done():
		// Health-provider probes can finish at the deadline. Preserve any
		// anchor result already completed within their shared budget.
		select {
		case sample := <-pending:
			return sample
		default:
			return anchorSample{}
		}
	}
}

func (m *Manager) anchorFailed(c *connection.Connection, sample anchorSample) bool {
	if c == nil || sample.owner != connectionKey(*c) || !sample.measured {
		m.anchorEvidence = anchorEvidence{}
		return false
	}
	if sample.reached {
		m.anchorEvidence = anchorEvidence{}
		return false
	}
	if m.anchorEvidence.owner != sample.owner {
		m.anchorEvidence = anchorEvidence{owner: sample.owner}
	}
	m.anchorEvidence.misses = min(m.anchorEvidence.misses+1, 2)
	return m.anchorEvidence.misses == 2
}

func (m *Manager) qualifiedStableEgressCarrier(now time.Time, c *connection.Connection, state health.State) bool {
	if !stableEgressCarrier(c) || now.Before(m.retries[connectionKey(*c)].after) {
		return false
	}
	age := now.Sub(state.LastCheck)
	return state.Healthy() && state.Last.NotMeasured == "" && state.Last.TCP && state.Last.UDP && age >= 0 && age <= m.warm.Interval+health.Interval
}

// A complete provider failure or sustained anchor loss can use a previously
// qualified alternate. Partial degradation follows the ordinary health policy.
func (m *Manager) stableEgressFallback(now time.Time, active connection.Connection, native, proxy connectionSample, anchorFailed bool) (connection.Connection, health.State, connectionSample, bool) {
	s := m.connectionState()
	var alternate *connection.Connection
	var failed, alternateSample connectionSample
	if m.stableEgressAuto() {
		switch active.Family {
		case "awg":
			alternate, failed, alternateSample = s.slot, native, proxy
		case "hy2":
			alternate, failed, alternateSample = s.native, proxy, native
		}
	}
	completeFailure := failed.valid && failed.result.NotMeasured == "" && (!failed.present || (failed.result.Measured && !failed.result.TCP && !failed.result.UDP))
	if alternate == nil || (!anchorFailed && !completeFailure) {
		return connection.Connection{}, health.State{}, connectionSample{}, false
	}
	state := s.health[connectionKey(*alternate)]
	if !m.qualifiedStableEgressCarrier(now, alternate, state) {
		return connection.Connection{}, health.State{}, connectionSample{}, false
	}
	return *alternate, state, alternateSample, true
}
