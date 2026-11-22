package transport

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/diagnostic"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
)

var attemptSequence atomic.Uint64

func (m *Manager) SetAttemptRecorder(record func(diagnostic.Attempt)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recordAttempt = record
}

func beginAttempt(item *connection.Connection, from diagnostic.Identity, generation uint64, reason string) *diagnostic.Attempt {
	return &diagnostic.Attempt{
		AttemptSequence: attemptSequence.Add(1), Started: time.Now(), Epoch: generation,
		Candidate: connectionIdentity(item), Previous: from, Family: item.Family, Reason: reason,
		Outcome: "failed", Handshake: "unavailable",
	}
}

func (m *Manager) finishAttempt(ctx context.Context, a *diagnostic.Attempt) {
	if a == nil || m.recordAttempt == nil {
		return
	}
	if m.requestedGeneration.Load() != a.Epoch {
		a.Outcome = "superseded"
	} else if ctx.Err() == context.Canceled {
		a.Outcome = "cancelled"
	} else if ctx.Err() == context.DeadlineExceeded && a.Outcome != "ok" {
		a.Outcome = "budget_exhausted"
	}
	s := m.connectionState()
	a.Reserve = "none"
	if s.slot != nil {
		a.Reserve = "retained"
		if s.warm {
			a.Reserve = "warm"
		} else if s.active != nil && connectionKey(*s.active) == connectionKey(*s.slot) {
			a.Reserve = "active"
		}
	}
	if a.Finished.IsZero() {
		a.Finished = time.Now()
	}
	a.DurationMS = a.Finished.Sub(a.Started).Milliseconds()
	m.recordAttempt(*a)
}

func attemptStage(start time.Time, outcome string) diagnostic.AttemptStage {
	return diagnostic.AttemptStage{Outcome: outcome, DurationMS: time.Since(start).Milliseconds()}
}

func operationStage(start time.Time, err error) diagnostic.AttemptStage {
	outcome := "ok"
	switch {
	case errors.Is(err, context.Canceled):
		outcome = "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		outcome = "timeout"
	case err != nil:
		outcome = "failed"
	}
	return attemptStage(start, outcome)
}

func (m *Manager) startCandidate(lifetime, ctx context.Context, p profile.Profile, a *diagnostic.Attempt) error {
	if backend, ok := m.backend.(*ProcessBackend); ok {
		return backend.startBudget(lifetime, ctx, p, a)
	}
	start := time.Now()
	var err error
	if backend, ok := m.backend.(budgetBackend); ok {
		err = backend.StartBudget(lifetime, ctx, p)
	} else {
		err = m.backend.Start(ctx, p)
	}
	a.Apply = operationStage(start, err)
	return err
}

func switchCandidateAWG(ctx context.Context, backend AWGBackend, item connection.Connection, a *diagnostic.Attempt) error {
	if native, ok := backend.(interface {
		switchObserved(context.Context, connection.Connection, *diagnostic.Attempt) error
	}); ok {
		return native.switchObserved(ctx, item, a)
	}
	start := time.Now()
	err := backend.Switch(ctx, item)
	a.Apply = operationStage(start, err)
	return err
}

func readinessStage(start time.Time, ready bool) diagnostic.AttemptStage {
	if ready {
		return attemptStage(start, "ok")
	}
	return attemptStage(start, "unavailable")
}

const nativeTelemetryReadLimit = 25 * time.Millisecond

type nativePeerTelemetry interface {
	LatestHandshake(context.Context, connection.Connection) (time.Time, error)
	readTraffic(context.Context, connection.Connection) nativeTrafficSample
}

// Keep diagnostic reads within the existing probe or sweep deadline and leave
// a read's worth of headroom for the work that deadline was allocated to.
func hasNativeTelemetryBudget(ctx context.Context) bool {
	deadline, ok := ctx.Deadline()
	return ctx.Err() == nil && ok && time.Until(deadline) > 2*nativeTelemetryReadLimit
}

func (m *Manager) readAWGTraffic(ctx context.Context, awg AWGBackend, c connection.Connection, epoch uint64) nativeTrafficSample {
	peer, ok := awg.(nativePeerTelemetry)
	if m.recordAttempt == nil || !ok || m.requestedGeneration.Load() != epoch || !hasNativeTelemetryBudget(ctx) {
		return nativeTrafficSample{}
	}
	bounded, cancel := context.WithTimeout(ctx, nativeTelemetryReadLimit)
	defer cancel()
	return peer.readTraffic(bounded, c)
}

func (m *Manager) observeAWGAfterProbe(ctx context.Context, awg AWGBackend, c connection.Connection, a *diagnostic.Attempt, before nativeTrafficSample) {
	peer, ok := awg.(nativePeerTelemetry)
	if m.recordAttempt == nil || !ok || m.requestedGeneration.Load() != a.Epoch || !hasNativeTelemetryBudget(ctx) {
		return
	}
	bounded, cancel := context.WithTimeout(ctx, nativeTelemetryReadLimit)
	stamp, err := peer.LatestHandshake(bounded, c)
	valid := err == nil && bounded.Err() == nil
	cancel()
	if valid {
		a.ObserveHandshake(stamp, time.Now())
	} else {
		a.Handshake = "unknown"
	}
	if before.valid {
		after := m.readAWGTraffic(ctx, awg, c, a.Epoch)
		if rx, tx, ok := nativeTrafficDelta(before, after); ok && m.requestedGeneration.Load() == a.Epoch {
			a.Traffic, a.RXDeltaBytes, a.TXDeltaBytes = "measured", rx, tx
		}
	}
}

func probeObservation(start time.Time, ctx context.Context, r health.Result, udp bool) diagnostic.AttemptProbe {
	outcome := r.NotMeasured
	if outcome == "" {
		switch {
		case r.TCP && (!udp || r.UDP):
			outcome = "ok"
		case ctx.Err() == context.Canceled:
			outcome = "cancelled"
		case ctx.Err() == context.DeadlineExceeded:
			outcome = "timeout"
		default:
			outcome = "failed"
		}
	}
	evidence := diagnostic.AttemptProbe{AttemptStage: attemptStage(start, outcome)}
	for i, target := range r.Targets {
		evidence.Targets[i] = diagnostic.AttemptTarget{HTTPS: target.TCPObservation, UDP: target.UDPObservation}
	}
	return evidence
}

func (m *Manager) selectObservedConnection(ctx context.Context, c connection.Connection, state health.State, generation uint64, from diagnostic.Identity, reason string, sample connectionSample) {
	attempt := beginAttempt(&c, from, generation, reason)
	if !sample.started.IsZero() {
		attempt.Started = sample.started
	}
	attempt.Ready, attempt.Probes[0] = sample.ready, sample.probe
	if c.Family == "awg" && sample.present && sample.probe.Outcome != "" {
		m.observeAWGAfterProbe(ctx, m.connectionState().awg, c, attempt, nativeTrafficSample{})
	}
	if ctx.Err() != context.Canceled {
		m.selectConnection(c, state, generation, attempt)
	}
	m.finishAttempt(ctx, attempt)
}
