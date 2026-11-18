package diagnostic

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"github.com/MyHeartRaces/FLR/runtime/internal/privatefile"
)

func TestHistoryIsBoundedAndChronological(t *testing.T) {
	h := New("boot", "0.6-runtime", strings.Repeat("a", 40))
	for i := 0; i < 1000; i++ {
		h.AddRound(Round{At: time.Unix(int64(i), 0), Epoch: uint64(i + 1), Native: Path{ID: "a", Revision: strings.Repeat("b", 64)}})
		h.AddDecision(Decision{At: time.Unix(int64(i), 0), Epoch: uint64(i + 1), Reason: "failback", Outcome: "applied"})
	}
	dump := h.Export()
	if len(dump.Rounds) != 720 || len(dump.Decisions) != 256 || dump.DroppedRounds != 280 || dump.DroppedDecisions != 744 {
		t.Fatal("ring bounds/truncation lost")
	}
	raw, _ := json.Marshal(dump)
	if len(raw) > 4<<20 {
		t.Fatal("history exceeds serialized cap")
	}
	if dump.Rounds[0].Epoch != 281 || dump.Decisions[0].Epoch != 745 {
		t.Fatal("history order lost")
	}
	if dump.Source != strings.Repeat("a", 40) || dump.Boot != "boot" {
		t.Fatal("missing source/boot identity")
	}
}
func TestHistoryHasFixedSecretSafeSchemaAndPrivateSnapshot(t *testing.T) {
	secret := "https://user:password@example.test/?private_key=SECRET"
	h := New(secret, secret, secret)
	h.AddRound(Round{Native: Path{ID: secret, Revision: secret, Health: health.State{Reason: secret, Last: health.Result{NotMeasured: secret}}}})
	h.AddDecision(Decision{Reason: secret, Outcome: secret, From: Identity{ID: secret, Revision: secret}, To: Identity{ID: secret}})
	raw, _ := json.Marshal(h.Export())
	if strings.Contains(string(raw), "password") || strings.Contains(string(raw), "SECRET") || strings.Contains(string(raw), "example.test") {
		t.Fatal("history leaked arbitrary metadata/command text")
	}
	path := t.TempDir() + "/private/history.json"
	if err := h.Save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := privatefile.Read(path, 4<<20); err != nil {
		t.Fatal(err)
	}
}
func TestHistoryExportPagesAreBoundedAndCursorStable(t *testing.T) {
	h := New("boot", "0.6-runtime", "")
	for i := 0; i < 1000; i++ {
		h.AddRound(Round{Epoch: uint64(i + 1)})
	}
	cursor := uint64(0)
	seen := 0
	for {
		page, err := h.Page(cursor)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(page)
		if len(raw) > 32<<10 {
			t.Fatal("RPC export page too large")
		}
		for _, r := range page.Rounds {
			if r.Sequence <= cursor {
				t.Fatal("cursor repeated data")
			}
			cursor = r.Sequence
			seen++
		}
		if !page.More {
			break
		}
		if len(page.Rounds) == 0 {
			t.Fatal("pagination stalled")
		}
	}
	if seen != 720 {
		t.Fatal("lost retained records", seen)
	}
	if _, err := h.Page(^uint64(0)); err == nil {
		t.Fatal("future cursor accepted")
	}
}
func TestHistoryConcurrentReadersCannotMutateStore(t *testing.T) {
	h := New("boot", "0.6-runtime", "")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				h.AddRound(Round{})
				h.AddDecision(Decision{Reason: "failback", Outcome: "applied"})
				d := h.Export()
				if len(d.Rounds) > 0 {
					d.Rounds[0].Native.ID = "tampered"
				}
			}
		}()
	}
	wg.Wait()
	for _, r := range h.Export().Rounds {
		if r.Native.ID == "tampered" {
			t.Fatal("public copy aliases private history")
		}
	}
}

func TestRetentionReportsSeparateExactEvictionSequenceBounds(t *testing.T) {
	h := New("boot", "0.6-runtime", "")
	for i := 0; i < 720; i++ {
		h.AddRound(Round{})
	}
	for i := 0; i < 256; i++ {
		h.AddDecision(Decision{})
	}
	h.AddRound(Round{})       // evicts round sequence1
	h.AddDecision(Decision{}) // evicts decision sequence721
	page, err := h.PageUntil(16, 976)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(page)
	var data map[string]any
	json.Unmarshal(raw, &data)
	if data["dropped_round_sequence"] != float64(1) || data["dropped_decision_sequence"] != float64(721) {
		t.Fatal("export cannot distinguish already-read from unread evictions", string(raw))
	}
}

func TestWarmReserveReasonIsRetained(t *testing.T) {
	h := New("boot", "0.6-runtime", "")
	for _, outcome := range []string{"applied", "failed", "superseded"} {
		h.AddDecision(Decision{Reason: "warm_reserve", Stage: "selection", Outcome: outcome})
	}
	h.AddDecision(Decision{Reason: "warm_reserve_unlisted", Stage: "selection", Outcome: "applied"})
	got := h.Export().Decisions
	for i, outcome := range []string{"applied", "failed", "superseded"} {
		if got[i].Reason != "warm_reserve" || got[i].Outcome != outcome || got[i].Stage != "selection" {
			t.Fatal("warm reserve decision lost its reason or outcome", got[i])
		}
	}
	if got[3].Reason != "unknown" {
		t.Fatal("reason allowlist accepts arbitrary text", got[3].Reason)
	}
}
