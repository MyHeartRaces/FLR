// Package transport owns the one reusable imported-profile slot.
package transport

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/diagnostic"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
)

type Backend interface {
	Start(context.Context, profile.Profile) error
	Stop() error
	Alive() bool
}

// A process backend separates the child lifetime from the short startup budget.
type budgetBackend interface {
	StartBudget(context.Context, context.Context, profile.Profile) error
}
type Probe func(context.Context, profile.Profile) health.Result

type Snapshot struct {
	DesiredConnection *connection.Summary  `json:"desired_connection,omitempty"`
	DesiredSelection  *contract.Selection  `json:"desired_selection,omitempty"`
	Requested         connection.Selection `json:"requested"`
	ActiveConnection  *connection.Summary  `json:"active_connection,omitempty"`
	ReserveConnection *connection.Summary  `json:"reserve_connection,omitempty"`
	ReserveWarm       bool                 `json:"reserve_warm"`
	Generation        uint64               `json:"generation"`
	AttemptSequence   uint64               `json:"-"`
	Pending           bool                 `json:"pending"`
	Reason            string               `json:"reason,omitempty"`
	Selection         contract.Selection   `json:"selection"`
	Active            *profile.Summary     `json:"active_profile,omitempty"`
	AWG               health.State         `json:"awg"`
	Slot              health.State         `json:"slot"`
	LastError         string               `json:"last_error,omitempty"`
	LastProbe         health.Result        `json:"last_probe"`
	ProbeConnection   string               `json:"probe_connection,omitempty"`
	// Roam is the endpoint roaming state of the configured native AWG
	// connection when it roams (roam.go); absent otherwise.
	Roam *RoamStatus `json:"roam,omitempty"`
}
type retry struct {
	failures int
	after    time.Time
}
type Manager struct {
	mu      sync.Mutex
	backend Backend
	probe   Probe
	// Quiesce must publish down, clear owned slot conntrack and advance DNS
	// generation before the backend destroys or replaces the slot.
	quiesce             func() error
	channelCleanup      func(contract.Channel, string) error
	recordDecision      func(diagnostic.Decision)
	recordAttempt       func(diagnostic.Attempt)
	slotCleanupPending  bool
	active              *profile.Profile
	state               Snapshot
	retries             map[string]retry
	mode                string
	cleanupPending      bool
	ProbeTimeout        time.Duration
	healthPolicy        health.Policy
	warm                WarmPolicy
	stableEgress        bool
	stableEgressProbe   func(context.Context, connection.Summary) (measured, reachable bool)
	anchorEvidence      anchorEvidence
	anchorRejected      map[string]bool
	StepTimeout         time.Duration
	AdmissionWait       time.Duration // bounds the wait for a cancelled standby admission (warm.go)
	teardownWait        time.Duration
	nextCandidate       string
	primaryGroup        string
	connections         *connectionState
	requestedGeneration atomic.Uint64
	// Endpoint roaming (roam.go): held during a manual test; roamRandom
	// replaces the random source in tests.
	roamSuspended bool
	roamRandom    func(int64) int64
}

func New(b Backend, p Probe, quiesce func() error) *Manager {
	return &Manager{backend: b, probe: p, quiesce: quiesce, retries: map[string]retry{}, ProbeTimeout: health.RoundDeadline, healthPolicy: health.DefaultPolicy(), StepTimeout: health.RoundDeadline, AdmissionWait: DefaultAdmissionWait, teardownWait: teardownAdmissionWait, state: Snapshot{Selection: contract.Selection{General: contract.Down, Games: contract.Down}}}
}
func (m *Manager) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.state
	if s.ActiveConnection != nil {
		v := *s.ActiveConnection
		v.Capabilities.RequiredComponents = append([]string{}, v.Capabilities.RequiredComponents...)
		s.ActiveConnection = &v
	}
	if s.ReserveConnection != nil {
		v := *s.ReserveConnection
		v.Capabilities.RequiredComponents = append([]string{}, v.Capabilities.RequiredComponents...)
		s.ReserveConnection = &v
	}
	if s.Active != nil {
		v := *s.Active
		v.Capabilities.RequiredComponents = append([]string{}, v.Capabilities.RequiredComponents...)
		s.Active = &v
	}
	if s.Roam != nil {
		v := *s.Roam
		s.Roam = &v
	}
	return s
}
func (m *Manager) cool(id string, now time.Time) {
	r := m.retries[id]
	r.failures++
	delay := 30 * time.Second
	for i := 1; i < r.failures && delay < 5*time.Minute; i++ {
		delay *= 2
	}
	if delay > 5*time.Minute {
		delay = 5 * time.Minute
	}
	r.after = now.Add(delay)
	m.retries[id] = r
}
func (m *Manager) clear(reason ...string) bool {
	why := "selection"
	if len(reason) > 0 {
		why = reason[0]
	}
	m.cleanupPending = true
	m.state.Selection = contract.Selection{General: contract.Down, Games: contract.Down}
	m.state.Active = nil
	m.state.Slot.Up = false
	if m.quiesce != nil {
		e := m.quiesce()
		m.recordOperation(why, "cleanup", contract.Down, m.connectionState().slot, e)
		if e != nil {
			m.state.LastError = "slot cleanup failed"
			return false
		}
	}
	e := m.backend.Stop()
	m.recordOperation(why, "stop", contract.Gecko, m.connectionState().slot, e)
	if e != nil {
		m.state.LastError = "engine shutdown failed"
		return false
	}
	m.cleanupPending = false
	m.active = nil
	m.state.Active = nil
	m.state.Slot = health.State{}
	m.state.Selection = contract.Selection{General: contract.Down, Games: contract.Down}
	return true
}
func (m *Manager) runProbe(ctx context.Context, p profile.Profile) health.Result {
	bounded, cancel := context.WithTimeout(ctx, m.ProbeTimeout)
	defer cancel()
	result := m.probe(bounded, p)
	if !p.Capabilities.UDP {
		result.UDP = false
	}
	return result
}
func (m *Manager) selected(p profile.Profile, r health.Result, now time.Time, manual bool) {
	copy := p
	m.active = &copy
	summary := p.Summary()
	m.state.Active = &summary
	m.state.Slot = health.State{Up: true, Initialized: true, Last: r, LastCheck: now, LastChange: now}
	m.state.Selection = contract.Selection{General: contract.Gecko, Games: contract.Down}
	// Games never move to a TCP-carried family automatically; a profile the
	// owner chose by ID (manual mode) keeps its capability-based Games path.
	if p.Capabilities.UDP && (manual || connection.GameSafe(p.Family)) {
		m.state.Selection.Games = contract.Gecko
	}
	m.state.LastError = ""
}

// Step is serialized, starts at most one candidate at a time, and never publishes a
// candidate until its bounded capability-aware probe has succeeded.
func (m *Manager) Step(ctx context.Context, now time.Time, awg health.Result, present bool, r *profile.Registry, group, mode string) Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	lifetime := ctx
	ctx, cancel := context.WithTimeout(ctx, m.StepTimeout)
	defer cancel()
	m.state.AWG.UpdatePolicy(now, awg, present, m.healthPolicy)
	if m.cleanupPending && !m.clear() {
		return m.state
	}
	candidates := r.Candidates(group)
	available := map[string]profile.Profile{}
	for _, p := range candidates {
		available[p.ID] = p
	}
	for id := range m.retries {
		if _, exists := available[id]; !exists {
			delete(m.retries, id)
		}
	}
	if m.active != nil {
		_, exists := available[m.active.ID]
		if !exists || (mode != "auto" && mode != m.active.ID) || (m.mode != "" && m.mode != mode) {
			if !m.clear() {
				return m.state
			}
		}
	}
	if m.mode != mode || m.primaryGroup != group {
		m.nextCandidate = ""
	}
	m.primaryGroup = group
	m.mode = mode
	if mode == "auto" && m.state.AWG.Healthy() {
		if m.active != nil && !m.clear() {
			return m.state
		}
		m.state.Selection = contract.Selection{General: contract.AWG, Games: contract.AWG}
		m.state.LastError = ""
		return m.state
	}
	if m.active != nil {
		p := *m.active
		result := health.Result{}
		alive := m.backend.Alive()
		if alive {
			result = m.runProbe(ctx, p)
		}
		good := result.TCP && (!p.Capabilities.UDP || result.UDP)
		slotResult := result
		if !p.Capabilities.UDP {
			slotResult.UDP = result.TCP
		}
		m.state.Slot.Update(now, slotResult, alive)
		m.state.Slot.Last = result
		// A dead process fails immediately; live transient probes retain affinity
		// until the existing three-failure threshold is reached.
		if alive && (good || m.state.Slot.Healthy()) {
			return m.state
		}
		m.cool(p.ID, now)
		if !m.clear() {
			return m.state
		}
	}
	if m.active == nil {
		m.state.Selection = contract.Selection{General: contract.Down, Games: contract.Down}
	}
	start := 0
	if m.nextCandidate != "" {
		for i, p := range candidates {
			if p.ID == m.nextCandidate {
				start = i + 1
				break
			}
		}
	}
	if start == len(candidates) {
		start = 0
	}
	for _, p := range candidates[start:] {
		if ctx.Err() != nil {
			break
		}
		if mode != "auto" && p.ID != mode {
			continue
		}
		if now.Before(m.retries[p.ID].after) {
			continue
		}
		if !m.clear() {
			return m.state
		}
		if ctx.Err() != nil {
			return m.state
		}
		m.nextCandidate = p.ID
		var startErr error
		if b, ok := m.backend.(budgetBackend); ok {
			startErr = b.StartBudget(lifetime, ctx, p)
		} else {
			startErr = m.backend.Start(ctx, p)
		}
		if startErr != nil {
			m.cool(p.ID, now)
			if !m.clear() {
				return m.state
			}
			m.state.LastError = "candidate start failed"
			continue
		}
		result := m.runProbe(ctx, p)
		if m.backend.Alive() && result.TCP && (!p.Capabilities.UDP || result.UDP) {
			m.selected(p, result, now, mode != "auto")
			m.nextCandidate = ""
			return m.state
		}
		m.cool(p.ID, now)
		if !m.clear() {
			return m.state
		}
		m.state.LastError = "candidate probe failed"
	}
	if ctx.Err() == nil {
		m.nextCandidate = ""
	}
	return m.state
}

// Shutdown may wait for a standby admission worker to use up its own start and
// probe budgets, so that no process it started outlives the manager.
func (m *Manager) Shutdown() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.clearConnection("shutdown") {
		return context.Canceled
	}
	return nil
}

// SetHealthPolicy validates before changing the next round's evaluator. Policy
// changes requalify evidence and recovery without making a down path healthy.
func (m *Manager) SetHealthPolicy(p health.Policy) error {
	if e := p.Validate(); e != nil {
		return e
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthPolicy = p
	return nil
}
