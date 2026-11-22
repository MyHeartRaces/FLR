package transport

import (
	"context"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/diagnostic"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
)

type AWGBackend interface {
	Switch(context.Context, connection.Connection) error
	Probe(context.Context) health.Result
	Present() bool
}
type connectionState struct {
	awg    AWGBackend
	active *connection.Connection
	slot   *connection.Connection
	native *connection.Connection
	health map[string]health.State
	cursor string
	// nativeCleanupRetry is the candidate owed one retry before skipping the AWG family.
	nativeCleanupRetry string
	// warm marks a slot started as a standby that has not carried new flows.
	// Its failures back off in warmRetries, which the failover sweep ignores.
	warm        bool
	warmRetries map[string]retry
	warmAttempt time.Time
	// admission is a standby start still running outside the lock (warm.go).
	admission *warmAdmission
	// quarantine: a standby process whose Stop failed. It never carried flows,
	// so it needs no conntrack cleanup, but the slot is not reused until a
	// later Stop succeeds. It never blocks native monitoring or AWG failover.
	quarantine      bool
	quarantineRetry time.Time
	// roam is the endpoint roaming state of the native identity (roam.go).
	roam roamState
	// readvance: the proxy default was chosen after a native AWG identity had
	// been configured (a fallback), so AWG candidates ranked above it are
	// retried (readvance.go). A proxy chosen by order alone keeps affinity.
	readvance bool
	// awgSkipped: an AWG candidate ranked in this sweep was tried and not
	// selected (its switch failed or it was down). A proxy then chosen is a
	// fallback even when no native identity is left configured, so AWG is
	// retried later (readvance). Reset whenever a connection is selected.
	awgSkipped bool
}

func connectionKey(c connection.Connection) string { return c.ID + ":" + c.Revision }
func (m *Manager) connectionState() *connectionState {
	if m.connections == nil {
		m.connections = &connectionState{health: map[string]health.State{}, warmRetries: map[string]retry{}}
	}
	return m.connections
}
func (m *Manager) SetAWGBackend(backend AWGBackend) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connectionState().awg = backend
}

func (m *Manager) ResetConnectionRetry(id, revision string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.retries, id+":"+revision)
}
func (m *Manager) NativeConnection() *connection.Connection {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.connections == nil || m.connections.native == nil {
		return nil
	}
	copy := m.connections.native.Clone()
	return &copy
}
func (m *Manager) RestoreNativeIdentity(item *connection.Connection) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.connectionState()
	s.native = nil
	m.resetRoam()
	if item != nil {
		copy := item.Clone()
		s.native = &copy
	}
}
func (m *Manager) RetireGeneration(generation uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state.Generation != generation {
		return nil
	}
	if !m.clearConnection("manual_test") {
		return context.Canceled
	}
	return nil
}

// RequestGeneration does not wait for a running probe. Publication rechecks it.
func (m *Manager) RequestGeneration(generation uint64) {
	for {
		old := m.requestedGeneration.Load()
		if old >= generation || m.requestedGeneration.CompareAndSwap(old, generation) {
			return
		}
	}
}

// clearConnection retires every resource of the old intent. A standby
// admission in flight is abandoned first, waiting at most the teardown bound
// for its worker (a failover never comes here; it keeps the admission of its
// first proxy candidate, or cancels it and uses freeSlot).
func (m *Manager) clearConnection(reason ...string) bool {
	if m.connections != nil {
		m.connections.active = nil
	}
	m.state.ActiveConnection = nil
	m.state.AttemptSequence = 0
	if !m.abandonAdmission(m.teardownWait) {
		// The worker still owns the backend: nothing may stop or restart it
		// until it returns. The round reports the cleanup as pending (the
		// controller publishes nothing from a pending snapshot) and the next
		// round retries the whole cleanup instead of blocking longer here.
		m.cleanupPending = true
		m.state.Selection = contract.Selection{General: contract.Down, Games: contract.Down}
		m.state.Active = nil
		m.state.Slot.Up = false
		m.state.Pending = true
		m.state.Reason = "standby admission cleanup pending"
		m.state.LastError = "standby admission cleanup pending"
		return false
	}
	if !m.clear(reason...) {
		return false
	}
	if m.connections != nil {
		m.connections.slot = nil
		m.connections.warm = false
		m.connections.quarantine = false
	}
	m.slotCleanupPending = false
	m.state.ReserveConnection = nil
	m.state.ReserveWarm = false
	return true
}
func (m *Manager) freshGeneration(generation uint64) bool {
	if m.requestedGeneration.Load() == generation {
		return true
	}
	m.clearConnection()
	m.state.Pending = true
	m.state.Reason = "new selection pending"
	return false
}
func (m *Manager) selectConnection(c connection.Connection, state health.State, generation uint64, attempt *diagnostic.Attempt) bool {
	if !m.freshGeneration(generation) {
		return false
	}
	previous := m.connectionState().active
	copy := c.Clone()
	m.connectionState().active = &copy
	summary := c.Summary()
	m.state.ActiveConnection = &summary
	if attempt != nil {
		attempt.Outcome = "ok"
		m.state.AttemptSequence = attempt.AttemptSequence
	}
	m.state.Generation = generation
	m.state.Pending = false
	m.state.Reason = ""
	m.state.LastError = ""
	channel := contract.Gecko
	if previous == nil || connectionKey(*previous) != connectionKey(c) {
		m.connectionState().readvance = c.Family != "awg" && (m.connectionState().native != nil || m.connectionState().awgSkipped)
	}
	m.connectionState().awgSkipped = false
	m.connectionState().nativeCleanupRetry = ""
	if c.Family == "awg" {
		channel = contract.AWG
		m.state.AWG = state
		m.state.Active = nil
	} else {
		m.connectionState().slot = &copy
		// New flows now use the slot: it is no longer a sessionless standby.
		m.connectionState().warm = false
		p := *c.Profile
		m.active = &p
		public := p.Summary()
		m.state.Active = &public
		m.state.Slot = state
	}
	m.refreshReserve()
	m.state.Selection = contract.Selection{General: channel, Games: contract.Down}
	// Games never move to a TCP-carried family automatically (auto and
	// transport modes fail closed to down). An explicit choice of this very
	// connection keeps the capability-based Games path.
	if summary.Capabilities.UDP && (connection.GameSafe(c.Family) || m.state.Requested.Mode == "connection") {
		m.state.Selection.Games = channel
	}
	if m.recordDecision != nil && (previous == nil || connectionKey(*previous) != connectionKey(c)) {
		reason := "selection"
		if previous != nil && previous.Family != "awg" && c.Family == "awg" {
			reason = "failback"
		} else if c.Family != "awg" && m.connectionState().native != nil {
			reason = "fallback"
		}
		m.recordDecision(diagnostic.Decision{At: time.Now(), Epoch: generation, AttemptSequence: m.state.AttemptSequence, From: connectionIdentity(previous), To: connectionIdentity(&c), Reason: reason, Outcome: "prepared", Stage: "selection", Channel: channel, ReserveRetained: m.state.ReserveConnection != nil})
	}
	return true
}

const nativeQualificationRetryDelay = 300 * time.Millisecond

func (m *Manager) nativeProbe(ctx context.Context, now time.Time, c connection.Connection, freshlyApplied bool, attempt *diagnostic.Attempt) health.State {
	s := m.connectionState()
	state := s.health[connectionKey(c)]
	result := health.Result{}
	start := time.Now()
	present := s.awg != nil && s.awg.Present()
	if attempt.Ready.Outcome == "" || !present {
		attempt.Ready = readinessStage(start, present)
	}
	if ctx.Err() != nil {
		result = unmeasuredSample(ctx).result
		present = true
	} else if present {
		bounded, cancel := context.WithTimeout(ctx, m.ProbeTimeout)
		before := m.readAWGTraffic(bounded, s.awg, c, attempt.Epoch)
		start := time.Now()
		result = s.awg.Probe(bounded)
		attempt.Probes[0] = probeObservation(start, bounded, result, true)
		// A newly applied interface can handshake before it can carry the
		// probe traffic. Allow one retry within the existing probe budget
		// and feed only the final result to the health evaluator.
		deadline, _ := bounded.Deadline()
		if freshlyApplied && result.NotMeasured == "" && (!result.TCP || !result.UDP) &&
			bounded.Err() == nil && time.Until(deadline) > nativeQualificationRetryDelay {
			timer := time.NewTimer(nativeQualificationRetryDelay)
			select {
			case <-timer.C:
				if bounded.Err() == nil {
					start := time.Now()
					present = s.awg.Present()
					if present {
						start := time.Now()
						result = s.awg.Probe(bounded)
						attempt.Probes[1] = probeObservation(start, bounded, result, true)
					} else {
						attempt.Ready = readinessStage(start, false)
					}
				}
			case <-bounded.Done():
			}
			timer.Stop()
		}
		if present {
			m.observeAWGAfterProbe(bounded, s.awg, c, attempt, before)
		}
		cancel()
	}
	// A superseded attempt may retain evidence, but it cannot update the
	// evaluator. Cancellation still interrupts the clean recovery streak.
	if m.requestedGeneration.Load() != attempt.Epoch {
		state.Last = health.Result{NotMeasured: "cancelled"}
		return state
	}
	if ctx.Err() == context.Canceled {
		result = unmeasuredSample(ctx).result
		present = true
	}
	state.UpdatePolicy(now, result, present, m.healthPolicy)
	m.state.LastProbe, m.state.ProbeConnection = result, c.ID
	s.health[connectionKey(c)] = state
	m.state.AWG = state
	return state
}

// StepConnections distinguishes the default for new flows from the imported
// backend that still owns older flows. Both configured paths are probed in the
// same bounded round; qualification never tears down the healthy other path.
func (m *Manager) StepConnections(ctx context.Context, now time.Time, registry *connection.Registry, selection connection.Selection, order connection.Order, generation uint64) Snapshot {
	m.RequestGeneration(generation)
	m.mu.Lock()
	defer m.mu.Unlock()
	lifetime := ctx
	ctx, cancel := context.WithTimeout(ctx, m.StepTimeout)
	defer cancel()
	s := m.connectionState()
	candidates, err := connection.Candidates(registry, selection, order)
	if err != nil {
		m.clearConnection()
		m.state.Reason = "invalid connection selection or order"
		return m.state
	}
	if !m.freshGeneration(generation) {
		return m.state
	}
	m.state.LastProbe, m.state.ProbeConnection = health.Result{}, ""
	available := map[string]connection.Connection{}
	stored := map[string]bool{}
	for _, c := range registry.Connections {
		stored[connectionKey(c)] = true
	}
	rank := map[string]int{}
	for i, c := range candidates {
		key := connectionKey(c)
		available[key], rank[key] = c, i
	}
	for key := range s.health {
		if !stored[key] {
			delete(s.health, key)
			delete(m.retries, key)
		}
	}
	for key := range s.warmRetries {
		if !stored[key] {
			delete(s.warmRetries, key)
		}
	}
	changed := m.state.Generation != generation || m.state.Requested != selection
	if changed {
		s.cursor = ""
		s.nativeCleanupRetry = ""
		m.anchorEvidence = anchorEvidence{}
		// A new explicit choice is allowed to retire the previous resources. Merely
		// changing priority metadata keeps the same intent generation and affinity.
		if (s.active != nil || s.slot != nil || s.admission != nil || s.quarantine) && !m.clearConnection() {
			return m.state
		}
	}
	m.state.Requested, m.state.Generation = selection, generation
	m.state.Pending = false
	if m.cleanupPending && !m.clearConnection() {
		return m.state
	}
	// Only a slot that carried flows reaches here: a standby never needs
	// conntrack cleanup (see stopStandby), so it cannot hold up the round.
	if m.slotCleanupPending && !m.retireSlot("cleanup_retry") {
		return m.state
	}
	// A finished standby admission is adopted or stopped; one still running
	// is left alone and does not delay native monitoring.
	m.collectAdmission(now, available)
	if s.slot != nil && available[connectionKey(*s.slot)].ID == "" {
		if s.warm {
			m.retireStandby("connection_unavailable", now)
		} else if !m.retireSlot("connection_unavailable") {
			return m.state
		}
	}
	if s.slot != nil {
		copy := available[connectionKey(*s.slot)].Clone()
		s.slot = &copy
		m.refreshReserve()
	}
	if s.native != nil && available[connectionKey(*s.native)].ID == "" {
		if err := m.cleanupChannel(contract.AWG, "connection_unavailable"); err != nil {
			m.state.LastError = "native cleanup failed"
			m.state.Pending = true
			return m.state
		}
		if s.active != nil && s.active.Family == "awg" {
			m.deselectConnection()
		}
		s.native = nil
		m.resetRoam()
		m.state.AWG = health.State{}
	}
	// Collection runs concurrently and never mutates manager state. Apply only
	// after the newest intent has been rechecked, then publish a coherent snapshot.
	previousOwner := connectionIdentity(s.active)
	m.roamBeforeProbe(ctx, now, available, generation, changed)
	pendingAnchor := m.probeStableEgress(ctx, s.active)
	nativeSample, slotSample := m.connectionProbes(ctx, now)
	anchorSample := collectAnchorSample(ctx, pendingAnchor)
	if !m.freshGeneration(generation) {
		return m.state
	}
	if s.native != nil && nativeSample.valid {
		key := connectionKey(*s.native)
		state := s.health[key]
		state.UpdatePolicy(now, nativeSample.result, nativeSample.present, m.healthPolicy)
		s.health[key], m.state.AWG = state, state
		m.state.LastProbe, m.state.ProbeConnection = nativeSample.result, s.native.ID
		m.roamAfterProbe(nativeSample)
	}
	if s.slot != nil && slotSample.valid {
		key := connectionKey(*s.slot)
		state := s.health[key]
		normalized := slotSample.result
		if !s.slot.Profile.Capabilities.UDP {
			normalized.UDP = normalized.TCP
		}
		state.Update(now, normalized, slotSample.present)
		state.Last = slotSample.result
		s.health[key], m.state.Slot = state, state
		m.state.LastProbe, m.state.ProbeConnection = slotSample.result, s.slot.ID
		if !slotSample.present || !state.Healthy() {
			// A standby never carried new flows: its failure delays only the next
			// warm attempt and must not hide it from a real failover sweep, and
			// its retirement needs no conntrack cleanup.
			if s.warm {
				m.warmBackoff(key, now)
				m.retireStandby("channel_failed", now)
			} else {
				m.cool(key, now)
				if !m.retireSlot("channel_failed") {
					return m.state
				}
			}
		}
	}
	// A canceled round is not a new measurement or a reason to replace a live
	// owner. The service shutdown or newer explicit intent performs retirement.
	if ctx.Err() == context.Canceled {
		return m.state
	}
	anchorFailed := m.anchorFailed(s.active, anchorSample)
	if s.active != nil {
		c := s.active.Clone()
		key := connectionKey(c)
		state := s.health[key]
		if candidate, candidateState, sample, ok := m.stableEgressFallback(now, c, nativeSample, slotSample, anchorFailed); ok {
			m.cool(key, now)
			m.selectObservedConnection(ctx, available[connectionKey(candidate)], candidateState, generation, previousOwner, "fallback", sample)
			return m.state
		}
		if state.Healthy() && !anchorFailed {
			if m.stableEgress {
				// Ordinary failback moves only new flows. Stable egress moves all
				// protected flows, and the shared anchor can only be checked over
				// the selected carrier. Keep this carrier until failure or a new
				// explicit choice rather than testing an alternate with live flows.
				m.selectConnection(available[key], state, generation, nil)
				return m.state
			}
			nativeRecovered := nativeSample.valid && nativeSample.result.NotMeasured == "" && m.state.AWG.Healthy()
			if c.Family != "awg" && s.native != nil && nativeRecovered && rank[connectionKey(*s.native)] < rank[key] && !now.Before(m.retries[connectionKey(*s.native)].after) {
				// Atomic map publication in the controller is the only default transition.
				// Slot ownership, process, TUN, routes and existing conntrack stay intact.
				m.selectObservedConnection(ctx, available[connectionKey(*s.native)], m.state.AWG, generation, previousOwner, "failback", nativeSample)
			} else {
				m.selectConnection(available[key], state, generation, nil)
				if c.Family != "awg" {
					// Re-advance: retry the AWG candidates ranked above the proxy.
					m.readvanceAWG(ctx, now, candidates, rank[key], nativeSample, generation)
				}
			}
			return m.state
		}
		m.cool(key, now)
		s.cursor = key
		if anchorFailed {
			m.state.Reason = "active carrier could not reach stable egress"
			if c.Family == "hy2" && !m.retireSlot("channel_failed") {
				return m.state
			}
		}
		m.deselectConnection()
	}
	// A standby start that has already finished is adopted here if it
	// qualified, and reused below.
	if s.admission != nil {
		m.collectAdmission(now, available)
	}
	// A previously admitted reserve remains the same physical owner. Reusing it
	// has no Start, Stop or cleanup and therefore no additional session break.
	// Owner decision: a healthy warm standby wins before the ordered sweep, so
	// a second AWG connection is tried only if the standby fails
	// (docs/ROUTER-API.md, "Warm reserve").
	if s.slot != nil {
		state := s.health[connectionKey(*s.slot)]
		if state.Healthy() && (!m.stableEgressAuto() || m.qualifiedStableEgressCarrier(now, s.slot, state)) {
			m.selectObservedConnection(ctx, available[connectionKey(*s.slot)], state, generation, previousOwner, "fallback", slotSample)
			return m.state
		}
	}
	m.deselectConnection()
	start := 0
	if s.cursor != "" {
		for i, c := range candidates {
			if connectionKey(c) == s.cursor {
				start = i + 1
				break
			}
		}
	}
	if start == len(candidates) {
		start = 0
	}
	// A standby start still in flight is kept when it is for the proxy this
	// sweep would start first: the sweep waits for it there instead of
	// cancelling it and starting the same connection cold. Any other one (a
	// different candidate, or no longer the current intent) is cancelled now,
	// so its worker winds down while AWG candidates are tried.
	kept := m.sweepAdmission(candidates[start:], now, generation)
	if adm := s.admission; adm != nil && adm != kept {
		adm.cancelled = true
		adm.cancel()
	}
	slotChecked, slotFree := false, false
	awgCleanupFailed := false
	var attempt *diagnostic.Attempt
	defer func() { m.finishAttempt(ctx, attempt) }()
	for _, c := range candidates[start:] {
		m.finishAttempt(ctx, attempt)
		attempt = nil
		if awgCleanupFailed && c.Family == "awg" {
			// Advance even if this round ran out of time, so the next round
			// can start with the proxy instead of trying the same AWG mark.
			s.cursor = connectionKey(c)
			continue
		}
		if ctx.Err() != nil || !m.freshGeneration(generation) {
			break
		}
		key := connectionKey(c)
		if now.Before(m.retries[key].after) {
			continue
		}
		previous := s.cursor
		s.cursor = key
		if c.Family == "awg" {
			attempt = beginAttempt(&c, previousOwner, generation, "sweep")
			if s.awg == nil {
				attempt.Outcome = "unavailable"
				m.state.Reason = "native AWG unavailable"
				continue
			}
			if s.native == nil || connectionKey(*s.native) != key || !s.awg.Present() {
				start := time.Now()
				err := m.cleanupChannel(contract.AWG, "native_replacement")
				attempt.Retirement = operationStage(start, err)
				if err != nil {
					m.state.LastError = "native cleanup failed"
					if s.nativeCleanupRetry != key {
						s.nativeCleanupRetry = key
						s.cursor = previous
						m.state.Pending = true
						return m.state
					}
					// All AWG profiles share this mark. Keep it out of the
					// sweep and let the independently owned proxy take over.
					s.nativeCleanupRetry = ""
					s.awgSkipped = true
					awgCleanupFailed = true
					continue
				}
				s.nativeCleanupRetry = ""
				err = switchCandidateAWG(ctx, s.awg, c, attempt)
				m.recordOperation("native_replacement", "native", contract.AWG, &c, err)
				m.resetRoam()
				if err != nil {
					// Switch's error does not establish that rollback succeeded.
					// A remaining live interface must not be measured as the old ID.
					if s.native != nil {
						delete(s.health, connectionKey(*s.native))
					}
					s.native = nil
					m.state.AWG = health.State{Last: health.Result{NotMeasured: "unavailable"}}
					m.state.LastProbe = health.Result{NotMeasured: "unavailable"}
					m.state.ProbeConnection = ""
					if ctx.Err() == nil {
						m.cool(key, now)
					}
					m.state.Reason = "native identity unconfirmed; known configuration required"
					s.awgSkipped = true
					continue
				}
				copy := c.Clone()
				s.native = &copy
				if ctx.Err() != nil {
					m.state.Reason = "native measurement pending"
					break
				}
				m.nativeProbe(ctx, now, c, true, attempt)
			} else if !nativeSample.valid {
				m.nativeProbe(ctx, now, c, false, attempt)
			} else {
				if !nativeSample.started.IsZero() {
					attempt.Started = nativeSample.started
				}
				attempt.Ready, attempt.Probes[0] = nativeSample.ready, nativeSample.probe
				if nativeSample.present && nativeSample.probe.Outcome != "" {
					m.observeAWGAfterProbe(ctx, s.awg, c, attempt, nativeTrafficSample{})
				}
			}
			if !m.freshGeneration(generation) {
				return m.state
			}
			state := s.health[key]
			if ctx.Err() == context.Canceled || state.Last.NotMeasured != "" {
				if state.Last.NotMeasured != "" {
					attempt.Outcome = state.Last.NotMeasured
				}
				m.state.Reason = "native measurement pending"
				break
			}
			if state.Healthy() {
				m.selectConnection(c, state, generation, attempt)
				s.cursor = ""
				return m.state
			}
			if !state.Last.TCP || !state.Last.UDP {
				m.cool(key, now)
			} else {
				attempt.Outcome = "recovering"
			}
			m.state.Reason = "native connection down or recovery pending"
			s.awgSkipped = true
			continue
		}
		// The proxy slot is single: a cancelled standby admission or a
		// quarantined process must be gone before another start. While it is
		// not, proxy candidates wait for a later round; AWG ones still run.
		if !slotChecked {
			slotChecked = true
			if kept != nil && s.admission == kept && connectionKey(kept.item) == key {
				// The kept standby start of this very candidate: wait for it within
				// the round's step budget. Still running at the end of the budget,
				// it keeps the slot uncancelled; the next round adopts it or reaches
				// it first again.
				if !waitAdmission(ctx, kept, m.StepTimeout) {
					m.state.Reason = "standby start pending"
					s.cursor = previous
					break
				}
				m.collectAdmission(now, available)
				if !m.freshGeneration(generation) {
					return m.state
				}
				// If it was not adopted (it failed or did not qualify), it was
				// stopped as a sessionless standby, and the candidate is started
				// cold below if the round's budget allows.
				slotFree = m.retryQuarantine("slot_replacement", now)
				if s.slot == nil && ctx.Err() != nil {
					break
				}
			} else {
				slotFree = m.freeSlot(ctx, now, available)
			}
			if s.slot != nil {
				// It qualified (while kept, or before its cancellation): reuse it
				// as above, with no second Start.
				if state := s.health[connectionKey(*s.slot)]; state.Healthy() && (!m.stableEgressAuto() || m.qualifiedStableEgressCarrier(now, s.slot, state)) {
					m.selectObservedConnection(ctx, available[connectionKey(*s.slot)], state, generation, previousOwner, "fallback", connectionSample{})
					s.cursor = ""
					return m.state
				}
			}
		}
		if !slotFree {
			continue
		}
		attempt = beginAttempt(&c, previousOwner, generation, "sweep")
		retirementNeeded := s.slot != nil || m.active != nil || m.slotCleanupPending
		start := time.Now()
		retired := m.retireSlot("slot_replacement")
		if retirementNeeded {
			outcome := "failed"
			if retired {
				outcome = "ok"
			}
			attempt.Retirement = attemptStage(start, outcome)
		}
		if !retired {
			return m.state
		}
		copy := c.Clone()
		s.slot = &copy
		p := *c.Profile
		m.active = &p
		startErr := m.startCandidate(lifetime, ctx, p, attempt)
		result := health.Result{}
		if startErr == nil && ctx.Err() == nil {
			start := time.Now()
			result = m.runProbe(ctx, p)
			attempt.Probes[0] = probeObservation(start, ctx, result, p.Capabilities.UDP)
		}
		m.state.LastProbe, m.state.ProbeConnection = result, c.ID
		if !m.freshGeneration(generation) {
			return m.state
		}
		alive := false
		if startErr == nil && ctx.Err() != context.Canceled && result.NotMeasured == "" {
			start := time.Now()
			alive = m.backend.Alive()
			if attempt.Ready.Outcome == "" || !alive {
				attempt.Ready = readinessStage(start, alive)
			}
		}
		if alive && result.TCP && (!p.Capabilities.UDP || result.UDP) {
			state := health.State{Up: true, Initialized: true, Last: result, LastCheck: now, LastChange: now}
			s.health[key] = state
			m.selectConnection(c, state, generation, attempt)
			s.cursor = ""
			return m.state
		}
		if ctx.Err() == nil {
			m.cool(key, now)
		}
		if !m.retireSlot("admission_failed") {
			return m.state
		}
		m.state.Reason = "connection start or TCP/UDP probe failed"
	}
	if ctx.Err() == nil {
		s.cursor = ""
	}
	if m.state.Reason == "" {
		m.state.Reason = "no enabled connection ready; retry pending"
	}
	return m.state
}
