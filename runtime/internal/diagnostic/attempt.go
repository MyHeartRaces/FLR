package diagnostic

import (
	"encoding/json"
	"fmt"
	"hash/maphash"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/health"
)

const maxAttempts = 768

type AttemptStage = health.ProbeObservation

type AttemptTarget struct {
	HTTPS AttemptStage `json:"https"`
	UDP   AttemptStage `json:"udp"`
}

type AttemptProbe struct {
	AttemptStage
	Targets [2]AttemptTarget `json:"targets"`
}

// Attempt is the evidence already gathered by a candidate's operations. A
// fixed array preserves the original probe and its optional qualification retry.
// History replaces candidate and revision strings with instance-local references.
type Attempt struct {
	AttemptSequence uint64          `json:"attempt_sequence"`
	Epoch           uint64          `json:"epoch"`
	Started         time.Time       `json:"-"`
	Finished        time.Time       `json:"-"`
	DurationMS      int64           `json:"duration_ms"`
	Candidate       Identity        `json:"candidate"`
	Previous        Identity        `json:"previous"`
	Family          string          `json:"family"`
	Reason          string          `json:"reason"`
	Outcome         string          `json:"outcome"`
	Retirement      AttemptStage    `json:"retirement"`
	Apply           AttemptStage    `json:"apply"`
	Ready           AttemptStage    `json:"ready"`
	Routes          AttemptStage    `json:"routes"`
	Handshake       string          `json:"handshake"`
	HandshakeAge    string          `json:"handshake_age,omitempty"`
	Traffic         string          `json:"traffic"`
	RXDeltaBytes    uint64          `json:"rx_delta_bytes,omitempty"`
	TXDeltaBytes    uint64          `json:"tx_delta_bytes,omitempty"`
	Probes          [2]AttemptProbe `json:"probes"`
	Reserve         string          `json:"reserve"`
}

// ObserveHandshake retains only the peer's handshake state and an age bucket.
func (a *Attempt) ObserveHandshake(handshake, sampled time.Time) {
	a.observeHandshake(handshake, sampled, wallClockStatus())
}

func (a *Attempt) observeHandshake(handshake, sampled time.Time, clock string) {
	a.HandshakeAge = ""
	if handshake.IsZero() {
		a.Handshake = "none"
		return
	}
	if clock != "sane" || sampled.Before(handshake) {
		a.Handshake = "unknown"
		return
	}
	a.Handshake = "fresh"
	switch age := sampled.Sub(handshake); {
	case age < 30*time.Second:
		a.HandshakeAge = "under_30s"
	case age < 3*time.Minute:
		a.HandshakeAge = "under_3m"
	default:
		a.Handshake, a.HandshakeAge = "stale", "over_3m"
	}
}

type AttemptWAN struct {
	AgeMS   int64  `json:"age_ms"`
	Link    string `json:"link"`
	Carrier string `json:"carrier"`
	Route   string `json:"default_route"`
}

type AttemptRecord struct {
	Attempt
	Sequence  uint64     `json:"sequence"`
	ElapsedMS int64      `json:"elapsed_ms"`
	Clock     string     `json:"wall_clock"`
	WAN       AttemptWAN `json:"wan"`
}

func (h *History) opaqueIdentity(v Identity) Identity {
	id := token(v.ID, idPattern)
	if id == "" {
		return Identity{}
	}
	reference := Identity{ID: fmt.Sprintf("%016x", maphash.String(h.seed, "id:"+id))}
	if rev := token(v.Revision, hashPattern); rev != "" {
		reference.Revision = fmt.Sprintf("%016x", maphash.String(h.seed, "revision:"+id+":"+rev))
	}
	return reference
}

func stage(v *AttemptStage) {
	if v.Outcome == "" {
		v.Outcome = "not_run"
	}
	v.Outcome = enum(v.Outcome, "not_run", "ok", "failed", "timeout", "budget_exhausted", "cancelled", "superseded", "unavailable", "recovering")
	v.DurationMS = boundedDuration(v.DurationMS)
}

func boundedDuration(ms int64) int64 {
	return min(max(0, ms), (24 * time.Hour).Milliseconds())
}

func linkFact(known, up bool) string {
	switch {
	case !known:
		return "unavailable"
	case up:
		return "up"
	default:
		return "down"
	}
}

func (h *History) AddAttempt(v Attempt, wan WANResult) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.data.LastSequence++
	record := AttemptRecord{Attempt: v, Sequence: h.data.LastSequence, Clock: wallClockStatus()}
	record.WAN = AttemptWAN{AgeMS: -1, Link: "unavailable", Carrier: "unavailable", Route: "unavailable"}
	if !v.Started.IsZero() && !v.Finished.IsZero() {
		record.ElapsedMS = max(0, v.Started.Sub(h.start).Milliseconds())
		wallElapsed := v.Finished.Round(0).Sub(v.Started.Round(0))
		if drift := wallElapsed - v.Finished.Sub(v.Started); drift > 250*time.Millisecond || drift < -250*time.Millisecond {
			record.Clock = "suspect"
		}
		sampledAt := wan.sampledAt
		if sampledAt.IsZero() {
			sampledAt = wan.At
		}
		if !sampledAt.IsZero() && !v.Finished.Before(sampledAt) {
			record.WAN = AttemptWAN{
				AgeMS: boundedDuration(v.Finished.Sub(sampledAt).Milliseconds()),
				Link:  linkFact(wan.LinkKnown, wan.LinkUp), Carrier: linkFact(wan.CarrierKnown, wan.Carrier),
				Route: linkFact(wan.RouteKnown, wan.DefaultRoute),
			}
		}
	}
	record.Started, record.Finished = time.Time{}, time.Time{}
	record.Candidate, record.Previous = h.opaqueIdentity(v.Candidate), h.opaqueIdentity(v.Previous)
	record.Family = enum(v.Family, "awg", "hy2", "reality", "vless", "ss2022", "wgws")
	record.Reason = enum(v.Reason, "sweep", "failback", "fallback", "warm_reserve", "manual_test")
	record.Reserve = enum(v.Reserve, "none", "warm", "retained", "active")
	record.Handshake = enum(v.Handshake, "none", "fresh", "stale", "unknown", "unavailable", "not_run")
	record.HandshakeAge = enum(v.HandshakeAge, "", "under_30s", "under_3m", "over_3m")
	switch {
	case record.Family != "awg":
		record.Handshake, record.HandshakeAge = "unavailable", ""
	case record.Handshake != "fresh" && record.Handshake != "stale":
		record.HandshakeAge = ""
	case record.Clock != "sane" || record.HandshakeAge == "unknown":
		record.Handshake, record.HandshakeAge = "unknown", ""
	}
	if record.Family != "awg" || v.Traffic != "measured" {
		record.Traffic, record.RXDeltaBytes, record.TXDeltaBytes = "unavailable", 0, 0
	}
	record.Outcome = enum(v.Outcome, "ok", "failed", "timeout", "budget_exhausted", "cancelled", "superseded", "unavailable", "recovering")
	record.DurationMS = boundedDuration(v.DurationMS)
	for _, s := range []*AttemptStage{&record.Retirement, &record.Apply, &record.Ready, &record.Routes} {
		stage(s)
	}
	for i := range record.Probes {
		probe := &record.Probes[i]
		stage(&probe.AttemptStage)
		for j := range probe.Targets {
			stage(&probe.Targets[j].HTTPS)
			stage(&probe.Targets[j].UDP)
		}
	}
	raw, _ := json.Marshal(record)
	h.data.Attempts = append(h.data.Attempts, record)
	h.attemptSizes = append(h.attemptSizes, len(raw)+1)
	h.bytes += len(raw) + 1
	for len(h.data.Attempts) > maxAttempts {
		h.dropAttempt()
	}
	h.bound()
}

func (h *History) dropAttempt() {
	h.data.DroppedAttemptSequence = h.data.Attempts[0].Sequence
	h.bytes -= h.attemptSizes[0]
	h.attemptSizes = h.attemptSizes[1:]
	h.data.Attempts = h.data.Attempts[1:]
	h.data.DroppedAttempts++
}
