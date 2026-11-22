// Package diagnostic retains bounded prepared facts, never configuration or command output.
package diagnostic

import (
	"encoding/json"
	"fmt"
	"hash/maphash"
	"math"
	"regexp"
	"sync"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"github.com/MyHeartRaces/FLR/runtime/internal/privatefile"
)

const MaxBytes = 4 << 20
const MaxPageBytes = 32 << 10

var idPattern = regexp.MustCompile(`^[a-z0-9_-]{1,80}$`)
var hashPattern = regexp.MustCompile(`^[a-f0-9]{40}([a-f0-9]{24})?$`)
var bootPattern = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)

func token(value string, pattern *regexp.Regexp) string {
	if pattern.MatchString(value) {
		return value
	}
	return ""
}
func enum(value string, values ...string) string {
	for _, v := range values {
		if v == value {
			return value
		}
	}
	return "unknown"
}
func utc(t time.Time) time.Time {
	if t.Year() < 0 || t.Year() > 9999 {
		return time.Time{}
	}
	return t.UTC()
}
func probe(r health.Result) health.Result {
	r.NotMeasured = enum(r.NotMeasured, "", "cancelled", "budget_exhausted", "timeout", "unavailable")
	return r
}

type Identity struct {
	ID       string `json:"id,omitempty"`
	Revision string `json:"revision,omitempty"`
}

func identity(v Identity) Identity {
	return Identity{token(v.ID, idPattern), token(v.Revision, hashPattern)}
}

// Input paths may carry the evaluator; retained records copy only its public facts.
type Path struct {
	ID       string
	Revision string
	Health   health.State
}
type Health struct {
	Healthy         bool                  `json:"healthy"`
	Degraded        bool                  `json:"degraded"`
	Reason          string                `json:"reason"`
	Failures        int                   `json:"failures"`
	LastCheck       time.Time             `json:"last_check"`
	RecoverySince   time.Time             `json:"recovery_since"`
	RecoverySamples int                   `json:"recovery_samples"`
	Window          health.EvidenceWindow `json:"window"`
	Baselines       [2]health.Baseline    `json:"baselines"`
	BaselineSamples int                   `json:"baseline_samples"`
	Probe           health.Result         `json:"probe"`
}
type PathRecord struct {
	ID       string `json:"id,omitempty"`
	Revision string `json:"revision,omitempty"`
	Health   Health `json:"health"`
}

func path(v Path) PathRecord {
	s := v.Health
	return PathRecord{token(v.ID, idPattern), token(v.Revision, hashPattern), Health{s.Up, s.Degraded, enum(s.Reason, "", "unavailable", "healthy", "recovering", "sustained_latency", "sustained_loss", "sustained_failures", "missing_measurement", "down", "baseline_learning", "interface_absent", "consecutive_failures"), s.Failures, utc(s.LastCheck), utc(s.RecoverySince), s.RecoveryCleanSamples, s.Window, s.Baselines, s.BaselineSamples, probe(s.Last)}}
}

type Round struct {
	At           time.Time
	Epoch        uint64
	Native, Slot Path
	Selection    contract.Selection
	Requested    connection.Selection
	WAN          WANResult
}
type RoundRecord struct {
	Sequence  uint64               `json:"sequence"`
	At        time.Time            `json:"at"`
	ElapsedMS int64                `json:"elapsed_ms"`
	Epoch     uint64               `json:"epoch"`
	Native    PathRecord           `json:"native"`
	Slot      PathRecord           `json:"slot"`
	Selection contract.Selection   `json:"selection"`
	Requested connection.Selection `json:"requested"`
	WAN       WANResult            `json:"wan"`
}
type Decision struct {
	Sequence        uint64             `json:"sequence"`
	AttemptSequence uint64             `json:"attempt_sequence,omitempty"`
	At              time.Time          `json:"at"`
	ElapsedMS       int64              `json:"elapsed_ms"`
	Epoch           uint64             `json:"epoch"`
	ActualKnown     bool               `json:"actual_known"`
	Actual          Identity           `json:"actual"`
	ActualSelection contract.Selection `json:"actual_selection"`
	From            Identity           `json:"from"`
	To              Identity           `json:"to"`
	Reason          string             `json:"reason"`
	Outcome         string             `json:"outcome"`
	Stage           string             `json:"stage"`
	Channel         contract.Channel   `json:"channel"`
	ReserveRetained bool               `json:"reserve_retained"`
}
type Export struct {
	Boot                    string          `json:"boot"`
	Instance                string          `json:"instance,omitempty"`
	Version                 string          `json:"version"`
	Source                  string          `json:"source"`
	LastSequence            uint64          `json:"last_sequence"`
	DroppedRounds           uint64          `json:"dropped_rounds"`
	DroppedDecisions        uint64          `json:"dropped_decisions"`
	DroppedRoundSequence    uint64          `json:"dropped_round_sequence"`
	DroppedDecisionSequence uint64          `json:"dropped_decision_sequence"`
	DroppedAttempts         uint64          `json:"dropped_attempts,omitempty"`
	DroppedAttemptSequence  uint64          `json:"dropped_attempt_sequence,omitempty"`
	Rounds                  []RoundRecord   `json:"rounds"`
	Decisions               []Decision      `json:"decisions"`
	Attempts                []AttemptRecord `json:"attempts,omitempty"`
}
type Page struct {
	Export
	Next uint64 `json:"next"`
	More bool   `json:"more"`
}
type Summary struct {
	SnapshotPending  bool      `json:"snapshot_pending"`
	Boot             string    `json:"boot"`
	Instance         string    `json:"instance,omitempty"`
	Version          string    `json:"version"`
	Source           string    `json:"source"`
	Rounds           int       `json:"rounds"`
	Decisions        int       `json:"decisions"`
	DroppedRounds    uint64    `json:"dropped_rounds"`
	DroppedDecisions uint64    `json:"dropped_decisions"`
	Attempts         int       `json:"attempts,omitempty"`
	DroppedAttempts  uint64    `json:"dropped_attempts,omitempty"`
	LastDecision     *Decision `json:"last_decision,omitempty"`
	WAN              WANResult `json:"wan"`
}
type History struct {
	mu                        sync.Mutex
	start                     time.Time
	seed                      maphash.Seed
	data                      Export
	roundSizes, decisionSizes []int
	attemptSizes              []int
	bytes                     int
}

func New(boot, version, source string) *History {
	seed := maphash.MakeSeed()
	return &History{start: time.Now(), seed: seed, data: Export{Boot: token(boot, bootPattern), Instance: fmt.Sprintf("%016x", maphash.String(seed, "controller")), Version: enum(version, "0.6-runtime", "0.7-runtime", contract.RuntimeVersion), Source: token(source, hashPattern), Rounds: []RoundRecord{}, Decisions: []Decision{}}}
}
func channel(c contract.Channel) contract.Channel {
	if c == contract.AWG || c == contract.Gecko || c == contract.VLESS {
		return c
	}
	return contract.Down
}
func selection(s contract.Selection) contract.Selection {
	return contract.Selection{General: channel(s.General), Games: channel(s.Games)}
}
func (h *History) AddRound(v Round) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.data.LastSequence++
	v.Requested.Mode = enum(v.Requested.Mode, "auto", "transport", "connection")
	v.Requested.Family = enum(v.Requested.Family, "", "awg", "hy2", "reality", "vless", "ss2022", "wgws")
	v.Requested.ID = token(v.Requested.ID, idPattern)
	v.WAN.Probe = probe(v.WAN.Probe)
	v.WAN.At = utc(v.WAN.At)
	r := RoundRecord{h.data.LastSequence, utc(v.At), time.Since(h.start).Milliseconds(), v.Epoch, path(v.Native), path(v.Slot), selection(v.Selection), v.Requested, v.WAN}
	raw, _ := json.Marshal(r)
	h.data.Rounds = append(h.data.Rounds, r)
	h.roundSizes = append(h.roundSizes, len(raw)+1)
	h.bytes += len(raw) + 1
	for len(h.data.Rounds) > 720 {
		h.dropRound()
	}
	h.bound()
}
func (h *History) AddDecision(v Decision) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.data.LastSequence++
	v.Sequence = h.data.LastSequence
	v.At = utc(v.At)
	v.ElapsedMS = time.Since(h.start).Milliseconds()
	v.From, v.To = identity(v.From), identity(v.To)
	v.Actual = identity(v.Actual)
	v.ActualSelection = selection(v.ActualSelection)
	v.Channel = channel(v.Channel)
	v.Reason = enum(v.Reason, "failback", "fallback", "selection", "native_replacement", "connection_unavailable", "channel_failed", "cleanup_retry", "slot_replacement", "admission_failed", "manual_test", "publication", "shutdown", "selection_requested", "warm_reserve", "roam")
	v.Outcome = enum(v.Outcome, "applied", "failed", "pending", "prepared", "superseded")
	v.Stage = enum(v.Stage, "nft", "conntrack", "cleanup", "stop", "routes", "native", "selection")
	raw, _ := json.Marshal(v)
	h.data.Decisions = append(h.data.Decisions, v)
	h.decisionSizes = append(h.decisionSizes, len(raw)+1)
	h.bytes += len(raw) + 1
	for len(h.data.Decisions) > 256 {
		h.dropDecision()
	}
	h.bound()
}
func (h *History) dropRound() {
	h.data.DroppedRoundSequence = h.data.Rounds[0].Sequence
	h.bytes -= h.roundSizes[0]
	h.roundSizes = h.roundSizes[1:]
	h.data.Rounds = h.data.Rounds[1:]
	h.data.DroppedRounds++
}
func (h *History) dropDecision() {
	h.data.DroppedDecisionSequence = h.data.Decisions[0].Sequence
	h.bytes -= h.decisionSizes[0]
	h.decisionSizes = h.decisionSizes[1:]
	h.data.Decisions = h.data.Decisions[1:]
	h.data.DroppedDecisions++
}
func (h *History) bound() {
	for h.bytes > MaxBytes-8192 {
		switch h.nextRecord(0, 0, 0, math.MaxUint64) {
		case "round":
			h.dropRound()
		case "decision":
			h.dropDecision()
		case "attempt":
			h.dropAttempt()
		default:
			return
		}
	}
}

func (h *History) nextRecord(i, j, k int, until uint64) string {
	kind := ""
	if i < len(h.data.Rounds) && h.data.Rounds[i].Sequence <= until {
		kind, until = "round", h.data.Rounds[i].Sequence
	}
	if j < len(h.data.Decisions) && h.data.Decisions[j].Sequence <= until {
		kind, until = "decision", h.data.Decisions[j].Sequence
	}
	if k < len(h.data.Attempts) && h.data.Attempts[k].Sequence <= until {
		kind = "attempt"
	}
	return kind
}
func (h *History) Export() Export {
	h.mu.Lock()
	defer h.mu.Unlock()
	v := h.data
	v.Rounds = append([]RoundRecord{}, v.Rounds...)
	v.Decisions = append([]Decision{}, v.Decisions...)
	v.Attempts = append([]AttemptRecord(nil), v.Attempts...)
	return v
}
func (h *History) Summary(wan WANResult) Summary {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := Summary{Boot: h.data.Boot, Instance: h.data.Instance, Version: h.data.Version, Source: h.data.Source, Rounds: len(h.data.Rounds), Decisions: len(h.data.Decisions), Attempts: len(h.data.Attempts), DroppedAttempts: h.data.DroppedAttempts, DroppedRounds: h.data.DroppedRounds, DroppedDecisions: h.data.DroppedDecisions, WAN: wan}
	if len(h.data.Decisions) > 0 {
		last := h.data.Decisions[len(h.data.Decisions)-1]
		s.LastDecision = &last
	}
	return s
}
func (h *History) Save(file string) error {
	raw, err := json.Marshal(h.Export())
	if err != nil || len(raw) > MaxBytes {
		return fmt.Errorf("diagnostic snapshot bound exceeded")
	}
	return privatefile.Write(file, raw)
}
func (h *History) Page(cursor uint64) (Page, error) { return h.PageUntil(cursor, 0) }
func (h *History) PageUntil(cursor, until uint64) (Page, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if until == 0 {
		until = h.data.LastSequence
	}
	if cursor > until || until > h.data.LastSequence {
		return Page{}, fmt.Errorf("invalid diagnostic cursor")
	}
	meta := h.data
	meta.LastSequence = until
	meta.Rounds = []RoundRecord{}
	meta.Decisions = []Decision{}
	meta.Attempts = nil
	p := Page{Export: meta, Next: cursor}
	i, j, k, count := 0, 0, 0, 0
	for i < len(h.data.Rounds) && h.data.Rounds[i].Sequence <= cursor {
		i++
	}
	for j < len(h.data.Decisions) && h.data.Decisions[j].Sequence <= cursor {
		j++
	}
	for k < len(h.data.Attempts) && h.data.Attempts[k].Sequence <= cursor {
		k++
	}
	for {
		kind := h.nextRecord(i, j, k, until)
		if kind == "" {
			break
		}
		if count == 16 {
			p.More = true
			break
		}
		next := p
		switch kind {
		case "round":
			next.Rounds = append(next.Rounds, h.data.Rounds[i])
			next.Next = h.data.Rounds[i].Sequence
			i++
		case "decision":
			next.Decisions = append(next.Decisions, h.data.Decisions[j])
			next.Next = h.data.Decisions[j].Sequence
			j++
		case "attempt":
			next.Attempts = append(next.Attempts, h.data.Attempts[k])
			next.Next = h.data.Attempts[k].Sequence
			k++
		}
		raw, _ := json.Marshal(next)
		if len(raw) > MaxPageBytes-128 {
			p.More = true
			break
		}
		p = next
		count++
	}
	return p, nil
}
