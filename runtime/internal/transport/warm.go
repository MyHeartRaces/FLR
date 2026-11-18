package transport

import (
	"context"
	"fmt"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/diagnostic"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
)

// The interval paces warm attempts and the probes of a standby beside a
// settled native default. A failed standby backs off on its own, longer
// schedule, which never delays the failover sweep.
const (
	MinWarmInterval = 30 * time.Second
	MaxWarmInterval = 5 * time.Minute
	warmBackoffMin  = time.Minute
	warmBackoffMax  = 15 * time.Minute
	// DefaultAdmissionWait bounds how long a failover (or a reserve restore)
	// waits for a cancelled standby admission to return. It is far below one
	// health interval; AWG candidates are tried regardless.
	DefaultAdmissionWait = time.Second
	// An explicit teardown (a new choice, a manual test, shutdown) retires every
	// resource of the old intent and so waits for the cancelled worker, whose
	// probe is skipped once cancelled and whose start rarely outlasts its own
	// budget (health.RoundDeadline). The wait holds the manager lock and, in a
	// round or API call, the controller's admin lock, so it is short: past it
	// the round reports the cleanup pending and the next round retries it.
	teardownAdmissionWait = 10 * time.Second
)

// WarmPolicy is off in a new Manager: legacy and direct callers keep the
// cold-start behaviour until the controller turns it on.
type WarmPolicy struct {
	Enabled  bool
	Interval time.Duration
}

func (p WarmPolicy) Validate() error {
	if p.Enabled && (p.Interval < MinWarmInterval || p.Interval > MaxWarmInterval) {
		return fmt.Errorf("invalid warm reserve interval")
	}
	return nil
}

// SetWarmReserve applies from the next round. An invalid policy is rejected
// and leaves the warm reserve off, which is the cold-start behaviour.
func (m *Manager) SetWarmReserve(p WarmPolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := p.Validate(); err != nil {
		m.warm = WarmPolicy{}
		return err
	}
	m.warm = p
	return nil
}

// warmAdmission is a standby start and its qualifying probe. It runs in its
// own goroutine, outside the manager and controller locks, so native AWG
// monitoring keeps its cadence. The worker touches only the backend, the probe
// and the result fields below, which are read after done is closed. Adoption
// and every other state change happen under m.mu (collectAdmission). While it
// is in flight the slot stays empty and nothing else starts or stops the
// backend: whoever needs the slot cancels it and waits a bounded time, except
// a failover whose first proxy candidate it is, which keeps it and waits for
// it within the round's step budget (sweepAdmission).
type warmAdmission struct {
	item       connection.Connection
	generation uint64
	started    time.Time
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	// Under m.mu. cancelled: its failure is not the candidate's (no backoff),
	// but a start that had already qualified is still adopted. abandoned: a
	// newer intent, disable or shutdown; it is never adopted.
	cancelled bool
	abandoned bool
	// Worker results, valid once done is closed.
	err    error
	result health.Result
	alive  bool
}

// StepWarmReserve runs after StepConnections in the same round. In auto mode,
// while a healthy native AWG is the default for new flows, it launches the
// first UDP proxy candidate as a standby, so a later failover reuses a running
// slot (make-before-break) instead of a cold start. The start and probe run in
// the background; the next StepConnections adopts a qualified standby. It never
// changes the default and never replaces an existing slot: a retained reserve
// keeps its sessions. With the policy off it retires only a standby that never
// carried new flows. The boolean reports that the slot changed and the snapshot
// should be published.
func (m *Manager) StepWarmReserve(lifetime context.Context, now time.Time, registry *connection.Registry, selection connection.Selection, order connection.Order, generation uint64) (Snapshot, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.connectionState()
	// Non-destructive intent check, as in RestoreReserve. A newer choice and any
	// pending cleanup belong to StepConnections.
	if lifetime.Err() != nil || m.requestedGeneration.Load() != generation || m.state.Generation != generation || m.state.Pending || m.cleanupPending || m.slotCleanupPending {
		return m.state, false
	}
	// A standby that could not be stopped is retried at the warm pace, never on
	// every round: its Stop may block for seconds.
	if s.quarantine && s.admission == nil && !now.Before(s.quarantineRetry) {
		m.retryQuarantine("warm_reserve", now)
	}
	if !m.warm.Enabled || selection.Mode != "auto" {
		if s.admission != nil {
			// The next StepConnections stops its process once the worker returns.
			s.admission.abandoned, s.admission.cancelled = true, true
			s.admission.cancel()
		}
		if s.slot != nil && s.warm && (s.active == nil || connectionKey(*s.active) != connectionKey(*s.slot)) {
			m.retireStandby("warm_reserve", now)
			return m.state, true
		}
		return m.state, false
	}
	active := s.active
	if s.admission != nil || s.quarantine || active == nil || active.Family != "awg" || s.native == nil || connectionKey(*s.native) != connectionKey(*active) || m.state.Selection.General != contract.AWG || s.slot != nil || m.active != nil {
		return m.state, false
	}
	if state := s.health[connectionKey(*active)]; !state.Healthy() {
		return m.state, false
	}
	if !s.warmAttempt.IsZero() && !now.Before(s.warmAttempt) && now.Sub(s.warmAttempt) < m.warm.Interval {
		return m.state, false
	}
	candidates, err := connection.Candidates(registry, selection, order)
	if err != nil {
		return m.state, false
	}
	var item *connection.Connection
	for _, c := range candidates {
		key := connectionKey(c)
		if c.Family == "awg" || c.Profile == nil || !c.Profile.Capabilities.UDP || now.Before(m.retries[key].after) || now.Before(s.warmRetries[key].after) {
			continue
		}
		v := c.Clone()
		item = &v
		break
	}
	if item == nil {
		return m.state, false
	}
	s.warmAttempt = now
	m.launchAdmission(lifetime, now, *item, generation)
	return m.state, false
}

// launchAdmission starts the worker. The process belongs to lifetime; the
// admission context only bounds and cancels its start and probe.
func (m *Manager) launchAdmission(lifetime context.Context, now time.Time, item connection.Connection, generation uint64) {
	ctx, cancel := context.WithCancel(lifetime)
	adm := &warmAdmission{item: item, generation: generation, started: now, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	m.connectionState().admission = adm
	work := item.Clone()
	go m.runAdmission(lifetime, adm, *work.Profile, m.StepTimeout, m.ProbeTimeout)
}

// runAdmission must not touch manager state: it holds no lock.
func (m *Manager) runAdmission(lifetime context.Context, adm *warmAdmission, p profile.Profile, startBudget, probeBudget time.Duration) {
	defer close(adm.done)
	start, cancel := context.WithTimeout(adm.ctx, startBudget)
	var err error
	if backend, ok := m.backend.(budgetBackend); ok {
		err = backend.StartBudget(lifetime, start, p)
	} else {
		err = m.backend.Start(start, p)
	}
	if err == nil {
		err = start.Err()
	}
	cancel()
	result := health.Result{}
	if err == nil && adm.ctx.Err() == nil {
		bounded, cancel := context.WithTimeout(adm.ctx, probeBudget)
		result = m.probe(bounded, p)
		cancel()
		if !p.Capabilities.UDP {
			result.UDP = false
		}
		// A probe cut short by cancellation is not a measurement.
		if adm.ctx.Err() != nil {
			err = adm.ctx.Err()
		}
	}
	adm.err, adm.result = err, result
	adm.alive = err == nil && m.backend.Alive()
}

// waitAdmission waits for the worker at most wait, or until ctx ends.
func waitAdmission(ctx context.Context, adm *warmAdmission, wait time.Duration) bool {
	select {
	case <-adm.done:
		return true
	default:
	}
	if wait <= 0 {
		return false
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-adm.done:
		return true
	case <-ctx.Done():
	case <-timer.C:
	}
	select {
	case <-adm.done:
		return true
	default:
		return false
	}
}

// collectAdmission harvests a finished admission without waiting. A qualified
// standby for the current intent becomes the slot, marked warm. Anything else
// is stopped as a process that never carried flows: no conntrack cleanup.
func (m *Manager) collectAdmission(now time.Time, available map[string]connection.Connection) {
	s := m.connectionState()
	adm := s.admission
	if adm == nil {
		return
	}
	select {
	case <-adm.done:
	default:
		return
	}
	s.admission = nil
	adm.cancel()
	key := connectionKey(adm.item)
	item, listed := available[key]
	if s.slot != nil || m.active != nil {
		// Not reachable by construction (the slot stays empty while a worker
		// runs). A single-slot backend refuses a second start, so there is no
		// process of this admission to stop, and the slot must not be touched.
		m.recordWarm(&adm.item, "superseded")
		return
	}
	qualified := adm.err == nil && adm.alive && adm.result.NotMeasured == "" && adm.result.TCP && (!adm.item.Profile.Capabilities.UDP || adm.result.UDP)
	current := !adm.abandoned && listed && item.Profile != nil && adm.generation == m.state.Generation && m.requestedGeneration.Load() == adm.generation && m.warm.Enabled && m.state.Requested.Mode == "auto"
	if qualified && current {
		slot := item.Clone()
		s.slot, s.warm = &slot, true
		p := *slot.Profile
		m.active = &p
		state := health.State{Up: true, Initialized: true, Last: adm.result, LastCheck: adm.started, LastChange: adm.started}
		s.health[key] = state
		m.state.Slot = state
		m.refreshReserve()
		m.recordWarm(&adm.item, "applied")
		return
	}
	m.stopStandby("warm_reserve", &adm.item, now)
	if current && !adm.cancelled {
		m.warmBackoff(key, adm.started)
		m.recordWarm(&adm.item, "failed")
	} else {
		m.recordWarm(&adm.item, "superseded")
	}
}

// abandonAdmission cancels an in-flight admission for a new intent, disable,
// restore or shutdown and waits at most wait for its worker. True means no
// worker remains; the caller stops the backend. False means the worker still
// owns the backend and nothing may start or stop it yet.
func (m *Manager) abandonAdmission(wait time.Duration) bool {
	if m.connections == nil || m.connections.admission == nil {
		return true
	}
	adm := m.connections.admission
	adm.abandoned, adm.cancelled = true, true
	adm.cancel()
	if !waitAdmission(context.Background(), adm, wait) {
		return false
	}
	m.connections.admission = nil
	m.recordWarm(&adm.item, "superseded")
	return true
}

// sweepAdmission returns the standby admission in flight when the failover
// sweep should keep it: it is for the first proxy candidate the sweep would
// start (sweep order, past cool-downs; AWG candidates start nothing in the
// slot), it was never cancelled, and it still belongs to the current intent
// (generation, auto mode, warm policy on). Otherwise nil, and the caller
// cancels it.
func (m *Manager) sweepAdmission(sweep []connection.Connection, now time.Time, generation uint64) *warmAdmission {
	adm := m.connectionState().admission
	if adm == nil || adm.cancelled || adm.abandoned || adm.generation != generation || m.state.Generation != generation || m.requestedGeneration.Load() != generation || !m.warm.Enabled || m.state.Requested.Mode != "auto" {
		return nil
	}
	for _, c := range sweep {
		if c.Family == "awg" || now.Before(m.retries[connectionKey(c)].after) {
			continue
		}
		if connectionKey(c) == connectionKey(adm.item) {
			return adm
		}
		return nil
	}
	return nil
}

// freeSlot prepares the single proxy slot for a failover start. A standby
// admission still in flight (cancelled when the failover began, because it was
// not for the first proxy candidate; see sweepAdmission) is waited for at most
// the admission wait within the round, and adopted if it had qualified before
// the cancellation. A quarantined process is stopped again. False means the
// slot is still busy this round; AWG candidates are tried regardless.
func (m *Manager) freeSlot(ctx context.Context, now time.Time, available map[string]connection.Connection) bool {
	s := m.connectionState()
	if adm := s.admission; adm != nil {
		adm.cancelled = true
		adm.cancel()
		if !waitAdmission(ctx, adm, m.AdmissionWait) {
			m.state.Reason = "standby admission cancellation pending"
			return false
		}
		m.collectAdmission(now, available)
	}
	return m.retryQuarantine("slot_replacement", now)
}

// stopStandby stops a process that never carried new flows, so it needs no
// conntrack cleanup. A failed Stop quarantines the slot instead of blocking
// the round: native monitoring and AWG candidates continue, and no proxy is
// started in the slot (its mark and TUN) until a later Stop succeeds.
func (m *Manager) stopStandby(reason string, owner *connection.Connection, now time.Time) {
	err := m.backend.Stop()
	m.recordOperation(reason, "stop", contract.Gecko, owner, err)
	if err != nil {
		s := m.connectionState()
		s.quarantine = true
		s.quarantineRetry = now.Add(MinWarmInterval)
		m.state.LastError = "standby shutdown failed; retry pending"
	}
}

// retireStandby retires a slot admitted as a standby that has not carried
// new flows (s.warm), without conntrack cleanup.
func (m *Manager) retireStandby(reason string, now time.Time) {
	s := m.connectionState()
	owner := s.slot
	s.slot, s.warm = nil, false
	m.active = nil
	m.state.Slot = health.State{}
	m.refreshReserve()
	m.stopStandby(reason, owner, now)
}

// retryQuarantine stops a quarantined standby process again.
func (m *Manager) retryQuarantine(reason string, now time.Time) bool {
	s := m.connectionState()
	if !s.quarantine {
		return true
	}
	err := m.backend.Stop()
	m.recordOperation(reason, "stop", contract.Gecko, nil, err)
	if err != nil {
		s.quarantineRetry = now.Add(MinWarmInterval)
		m.state.LastError = "standby shutdown failed; retry pending"
		return false
	}
	s.quarantine = false
	return true
}

// admitReserve starts item in the empty slot beside the current default and
// qualifies it with one capability-aware probe, synchronously (RestoreReserve
// after a manual test). Start and probe have separate budgets, so a slow start
// cannot consume the measurement. Any failure, or a newer intent, stops the
// half-started process; it carried no flows, so no conntrack cleanup. The
// admitted slot is marked as a warm standby only while the warm policy would
// keep one (on, auto mode); otherwise StepWarmReserve would retire it in the
// next round (a pointless start, probe and stop), so it stays an ordinary
// reserve, probed every round.
func (m *Manager) admitReserve(lifetime context.Context, now time.Time, item connection.Connection, generation uint64, reason string) error {
	s := m.connectionState()
	slot := item.Clone()
	s.slot = &slot
	p := *slot.Profile
	m.active = &p
	start, cancel := context.WithTimeout(lifetime, m.StepTimeout)
	var err error
	if backend, ok := m.backend.(budgetBackend); ok {
		err = backend.StartBudget(lifetime, start, p)
	} else {
		err = m.backend.Start(start, p)
	}
	if err == nil {
		err = start.Err()
	}
	cancel()
	result := health.Result{}
	if err == nil && lifetime.Err() == nil && m.requestedGeneration.Load() == generation {
		result = m.runProbe(lifetime, p)
	}
	if err == nil && (lifetime.Err() != nil || m.requestedGeneration.Load() != generation) {
		err = fmt.Errorf("reserve admission superseded")
	} else if err == nil && (result.NotMeasured != "" || !m.backend.Alive() || !result.TCP || (p.Capabilities.UDP && !result.UDP)) {
		err = fmt.Errorf("reserve start or TCP/UDP probe failed")
	}
	if err != nil {
		m.retireStandby(reason, now)
		return err
	}
	state := health.State{Up: true, Initialized: true, Last: result, LastCheck: now, LastChange: now}
	s.health[connectionKey(slot)] = state
	s.warm = m.warm.Enabled && m.state.Requested.Mode == "auto"
	m.state.Slot = state
	m.refreshReserve()
	return nil
}

// warmBackoff delays only the next warm attempt for key. It never touches the
// cool-down that the failover sweep honours, so a failed standby is still tried
// cold when the native path fails. Failures further apart than the maximum
// delay start again from the minimum.
func (m *Manager) warmBackoff(key string, now time.Time) {
	s := m.connectionState()
	r := s.warmRetries[key]
	if !r.after.IsZero() && now.Sub(r.after) > warmBackoffMax {
		r.failures = 0
	}
	r.failures++
	delay := warmBackoffMin
	for i := 1; i < r.failures && delay < warmBackoffMax; i++ {
		delay *= 2
	}
	if delay > warmBackoffMax {
		delay = warmBackoffMax
	}
	r.after = now.Add(delay)
	s.warmRetries[key] = r
}

// standbySettled reports whether this round may skip measuring the slot: the
// warm policy is on in auto mode, the slot is a standby that has never carried
// new flows (a reserve retained after failback still carries older sessions
// and is measured every round), a present native AWG is the default and
// settled (up, no failures, not degraded, no impairment evidence, last sample
// measured), and the standby passed its last probe less than one warm interval
// ago. Otherwise the slot is measured every round.
func (m *Manager) standbySettled(now time.Time, nativePresent bool) bool {
	s := m.connectionState()
	if !m.warm.Enabled || m.state.Requested.Mode != "auto" || !s.warm || !nativePresent || s.slot == nil || s.native == nil || s.active == nil || s.active.Family != "awg" || connectionKey(*s.active) != connectionKey(*s.native) {
		return false
	}
	native := s.health[connectionKey(*s.native)]
	evidence := native.Window.Failed != [2]int{} || native.Window.TCPSlow != [2]int{} || native.Window.UDPSlow != [2]int{}
	if !native.Up || native.Failures != 0 || native.Degraded || evidence || native.Last.NotMeasured != "" {
		return false
	}
	standby := s.health[connectionKey(*s.slot)]
	return standby.Up && standby.Failures == 0 && !standby.LastCheck.IsZero() && !now.Before(standby.LastCheck) && now.Sub(standby.LastCheck) < m.warm.Interval
}

func (m *Manager) recordWarm(item *connection.Connection, outcome string) {
	if m.recordDecision == nil {
		return
	}
	m.recordDecision(diagnostic.Decision{At: time.Now(), Epoch: m.state.Generation, To: connectionIdentity(item), Reason: "warm_reserve", Stage: "selection", Channel: contract.Gecko, Outcome: outcome, ReserveRetained: outcome == "applied"})
}
