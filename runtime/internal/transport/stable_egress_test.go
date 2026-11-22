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

func TestStableEgressKeepsHealthyCarrierWhenPreferredPathRecovers(t *testing.T) {
	main := managedConnection(t, "awg", "a", 10)
	spare := managedConnection(t, "awg", "b", 11)
	reserve := managedConnection(t, "hy2", "h", 20)
	f := newWarmFixture(t, main, spare, reserve)
	f.m.SetStableEgress(true)
	f.admit()
	f.m.SetStableEgressProbe(func(_ context.Context, owner connection.Summary) (bool, bool) {
		return true, owner.ID == reserve.ID
	})

	f.awg.good[main.ID] = false
	if s, _ := f.round(5 * time.Second); s.ActiveConnection == nil || s.ActiveConnection.ID != reserve.ID {
		t.Fatalf("fixture did not fail over to the reserve: %+v", s.ActiveConnection)
	}
	// Neither readvance to another native profile nor return to a recovered
	// native path may replace a working anchored carrier on public probes.
	f.awg.good[spare.ID] = true
	if s, _ := f.round(5 * time.Second); s.ActiveConnection == nil || s.ActiveConnection.ID != reserve.ID {
		t.Fatalf("re-advance replaced the working reserve: %+v", s.ActiveConnection)
	}
	f.awg.good[main.ID] = true
	for i := 0; i < 20; i++ {
		if s, _ := f.round(5 * time.Second); s.ActiveConnection == nil || s.ActiveConnection.ID != reserve.ID {
			t.Fatalf("public health alone replaced the working reserve: %+v", s.ActiveConnection)
		}
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
	for _, selection := range []connection.Selection{{Mode: "auto"}, {Mode: "transport", Family: "hy2"}} {
		t.Run(selection.Mode, func(t *testing.T) {
			f := newWarmFixture(t, first, second)
			f.sel = selection
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
		})
	}
}
