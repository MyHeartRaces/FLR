package transport

import (
	"context"
	"testing"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
)

func TestStableEgressUsesQualifiedStandbyOnFirstCompleteFailure(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	h := managedConnection(t, "hy2", "h", 20)
	f := newWarmFixture(t, a, h)
	f.m.SetStableEgress(true)
	f.admit()
	f.round(5 * time.Second)
	starts, stops := len(f.b.starts), f.b.stops
	f.cleaned = nil
	f.awg.good["a"] = false
	for i := 0; i < 2; i++ {
		s, _ := f.round(5 * time.Second)
		if s.Selection.General != contract.Gecko || s.ReserveWarm || s.AWG.Failures != i+1 {
			t.Fatalf("expected Hysteria2 after failure %d: %+v", i+1, s.Selection)
		}
	}
	if len(f.b.starts) != starts || f.b.stops != stops || len(f.cleaned) != 0 {
		t.Fatal("early fallback replaced an existing carrier")
	}
}

func TestStableEgressFailsOverWhenOnlyTheAnchorStopsResponding(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	h := managedConnection(t, "hy2", "h", 20)
	f := newWarmFixture(t, a, h)
	f.m.SetStableEgress(true)
	f.admit()
	var measured bool
	f.m.SetStableEgressProbe(func(_ context.Context, owner connection.Summary) (bool, bool) {
		return measured, owner.ID != a.ID
	})
	measured = true
	if s, _ := f.round(5 * time.Second); s.Selection.General != contract.AWG {
		t.Fatal("one measured anchor miss switched the carrier")
	}
	measured = false
	f.round(5 * time.Second)
	measured = true
	if s, _ := f.round(5 * time.Second); s.Selection.General != contract.AWG {
		t.Fatal("an unmeasured round did not reset the consecutive miss streak")
	}
	s, _ := f.round(5 * time.Second)
	if s.Selection.General != contract.Gecko || !s.AWG.Last.TCP || !s.AWG.Last.UDP || s.AWG.Failures != 0 {
		t.Fatalf("expected failover while AWG's general reachability stays healthy: %+v", s)
	}
	if s, _ := f.round(5 * time.Second); s.Selection.General != contract.Gecko {
		t.Fatal("a provider-only clean sample overrode the failed carrier's cooldown")
	}
	if s, _ := f.round(30 * time.Second); s.Selection.General != contract.Gecko {
		t.Fatal("cooldown expiry alone overrode the anchor failure")
	}
	f.fail[h.ID] = true
	if s, _ := f.round(5 * time.Second); s.Selection.General != contract.AWG {
		t.Fatal("anchor history prevented a retry after the replacement failed")
	}
}

func TestStableEgressRemembersMultipleAWGAnchorFailures(t *testing.T) {
	main := managedConnection(t, "awg", "a", 10)
	spare := managedConnection(t, "awg", "b", 11)
	reserve := managedConnection(t, "hy2", "h", 20)
	f := newWarmFixture(t, main, spare, reserve)
	f.awg.good[spare.ID] = true
	f.m.SetStableEgress(true)
	f.admit()
	f.m.SetStableEgressProbe(func(_ context.Context, owner connection.Summary) (bool, bool) {
		return true, owner.ID == reserve.ID
	})

	// Both AWG profiles pass their public probes. Each needs two failed
	// anchor checks before returning traffic to the healthy reserve.
	for _, want := range []string{main.ID, reserve.ID, spare.ID, spare.ID, reserve.ID} {
		s, _ := f.round(5 * time.Second)
		if s.ActiveConnection == nil || s.ActiveConnection.ID != want {
			t.Fatalf("at %v, expected active connection %s: %+v", f.now, want, s.ActiveConnection)
		}
	}
	if s, _ := f.round(time.Minute); s.ActiveConnection == nil || s.ActiveConnection.ID != reserve.ID {
		t.Fatalf("the second anchor failure cleared the first after cooldown: %+v", s.ActiveConnection)
	}
}

func TestCollectAnchorSampleKeepsCompletedResultAtDeadline(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	pending := make(chan anchorSample, 1)
	want := anchorSample{owner: "fixture", measured: true}
	for range 32 {
		pending <- want
		if got := collectAnchorSample(ctx, pending); got != want {
			t.Fatalf("discarded completed anchor evidence: %+v", got)
		}
	}
}

func TestStableEgressRetiresUnreachableProxyBeforeColdReplacement(t *testing.T) {
	first := managedConnection(t, "hy2", "first", 20)
	second := managedConnection(t, "hy2", "second", 21)
	f := newWarmFixture(t, first, second)
	f.m.SetStableEgress(true)
	f.m.SetStableEgressProbe(func(_ context.Context, owner connection.Summary) (bool, bool) {
		return true, owner.ID != first.ID
	})
	f.round(0)
	f.round(5 * time.Second)
	s, _ := f.round(5 * time.Second)
	if s.ActiveConnection == nil || s.ActiveConnection.ID != second.ID || len(f.cleaned) != 1 || f.cleaned[0] != contract.Gecko {
		t.Fatalf("failed owner was not retired before replacement: active=%+v cleanup=%v", s.ActiveConnection, f.cleaned)
	}
}
