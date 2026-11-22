package diagnostic

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestAttemptHistoryUsesSharedCursorAndOpaqueReferences(t *testing.T) {
	h := New("boot", "0.7-runtime", "")
	candidate := Identity{ID: "synthetic-private-name", Revision: strings.Repeat("b", 64)}
	h.AddRound(Round{})
	h.AddAttempt(Attempt{AttemptSequence: 1, Started: time.Now(), Candidate: candidate, Family: "awg", Reason: "sweep", Outcome: "failed"}, WANResult{})
	h.AddDecision(Decision{AttemptSequence: 1, Outcome: "applied"})
	h.AddAttempt(Attempt{AttemptSequence: 2, Started: time.Now(), Candidate: candidate, Family: "awg", Outcome: "ok"}, WANResult{})
	p, err := h.PageUntil(1, 3)
	if err != nil {
		t.Fatal(err)
	}
	if p.Next != 3 || p.More || len(p.Attempts) != 1 || p.Attempts[0].Sequence != 2 || len(p.Decisions) != 1 {
		t.Fatalf("unexpected combined page: %+v", p)
	}
	dump := h.Export()
	raw, err := json.Marshal(dump)
	if err != nil {
		t.Fatal(err)
	}
	if dump.Instance == "" || dump.Attempts[0].Candidate.ID == "" || dump.Attempts[0].Candidate != dump.Attempts[1].Candidate ||
		strings.Contains(string(raw), candidate.ID) || strings.Contains(string(raw), candidate.Revision) {
		t.Fatalf("attempt identities are unstable or unredacted: %s", raw)
	}
}

func TestAttemptHistoryRetainsBoundedPagesAndReportsEvictions(t *testing.T) {
	h := New("boot", "0.7-runtime", "")
	for i := 1; i <= 1000; i++ {
		h.AddAttempt(Attempt{AttemptSequence: uint64(i), Family: "hy2", Outcome: "failed"}, WANResult{})
	}
	dump := h.Export()
	if dump.DroppedAttempts == 0 || dump.DroppedAttemptSequence != dump.DroppedAttempts ||
		len(dump.Attempts)+int(dump.DroppedAttempts) != 1000 {
		t.Fatalf("incorrect attempt eviction bounds: retained %d, dropped %d, last drop %d", len(dump.Attempts), dump.DroppedAttempts, dump.DroppedAttemptSequence)
	}
	cursor := uint64(0)
	for {
		page, err := h.Page(cursor)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(page)
		if err != nil || len(raw) > MaxPageBytes || page.Next <= cursor {
			t.Fatalf("attempt page overflow or stalled cursor: size=%d, cursor=%d, next=%d, err=%v", len(raw), cursor, page.Next, err)
		}
		cursor = page.Next
		if !page.More {
			break
		}
	}
	if cursor != 1000 {
		t.Fatalf("unexpected final attempt cursor: %d", cursor)
	}
}

func TestAttemptHandshakeOnlyReportsAgeWithSaneClock(t *testing.T) {
	now := time.Unix(2000000000, 0)
	for _, tc := range []struct {
		name       string
		stamp      time.Time
		clock, age string
		handshake  string
	}{
		{"never", time.Time{}, "suspect", "", "none"},
		{"fresh", now.Add(-time.Second), "sane", "under_30s", "fresh"},
		{"recent", now.Add(-time.Minute), "sane", "under_3m", "fresh"},
		{"stale", now.Add(-4 * time.Minute), "sane", "over_3m", "stale"},
		{"clock step", now.Add(time.Second), "sane", "", "unknown"},
		{"unsynchronized", now.Add(-time.Second), "suspect", "", "unknown"},
		{"unverified clock", now.Add(-time.Second), "unknown", "", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var a Attempt
			a.observeHandshake(tc.stamp, now, tc.clock)
			if a.Handshake != tc.handshake || a.HandshakeAge != tc.age {
				t.Fatalf("got (%s, %s), want (%s, %s)", a.Handshake, a.HandshakeAge, tc.handshake, tc.age)
			}
		})
	}
}

func TestAttemptHistoryDiscardsUnsampledTrafficDeltas(t *testing.T) {
	h := New("boot", "0.8-runtime", "")
	h.AddAttempt(Attempt{Family: "awg", Traffic: "arbitrary-value", RXDeltaBytes: 78, TXDeltaBytes: 56}, WANResult{})
	h.AddAttempt(Attempt{Family: "awg", Traffic: "measured", RXDeltaBytes: 5, TXDeltaBytes: 3}, WANResult{})
	h.AddAttempt(Attempt{Family: "hy2", Traffic: "measured", Handshake: "none", RXDeltaBytes: 5, TXDeltaBytes: 3}, WANResult{})
	records := h.Export().Attempts
	if records[0].Traffic != "unavailable" || records[0].RXDeltaBytes != 0 || records[0].TXDeltaBytes != 0 {
		t.Fatalf("unsampled byte deltas reached export: %+v", records[0])
	}
	if records[1].Traffic != "measured" || records[1].RXDeltaBytes != 5 || records[1].TXDeltaBytes != 3 {
		t.Fatalf("measured byte deltas are missing from export: %+v", records[1])
	}
	if records[2].Handshake != "unavailable" || records[2].Traffic != "unavailable" || records[2].RXDeltaBytes != 0 || records[2].TXDeltaBytes != 0 {
		t.Fatalf("AWG telemetry was exported for the wrong carrier: %+v", records[2])
	}
}
