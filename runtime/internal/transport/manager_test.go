package transport

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
)

type fakeBackend struct {
	starts []string
	stops  int
	alive  bool
	fail   bool
}

func (b *fakeBackend) Start(_ context.Context, p profile.Profile) error {
	b.starts = append(b.starts, p.ID)
	if b.fail {
		return errors.New("public test failure")
	}
	b.alive = true
	return nil
}
func (b *fakeBackend) Stop() error { b.stops++; b.alive = false; return nil }
func (b *fakeBackend) Alive() bool { return b.alive }
func candidate(id, family, group string, udp bool) profile.Profile {
	return profile.Profile{ID: id, Family: family, ServerGroup: group, Enabled: true, Capabilities: profile.Capabilities{TCP: true, UDP: udp, TCPOnly: !udp}}
}
func TestSequentialFallbackStopsFailedCandidatesAndNoHealthyAWGChildren(t *testing.T) {
	b := &fakeBackend{}
	probes := map[string]bool{"primary": false, "other": false, "tcp-only": true}
	cleaned := 0
	m := New(b, func(_ context.Context, p profile.Profile) health.Result {
		return health.Result{TCP: probes[p.ID], UDP: probes[p.ID]}
	}, func() error { cleaned++; return nil })
	r := &profile.Registry{Version: 1, Profiles: []profile.Profile{candidate("tcp-only", "ss2022", "", false), candidate("other", "hy2", "other", true), candidate("primary", "hy2", "primary", true)}}
	now := time.Unix(100, 0)
	m.Step(context.Background(), now, health.Result{TCP: true, UDP: true}, true, r, "primary", "auto")
	if len(b.starts) != 0 || m.Snapshot().Selection.General != contract.AWG {
		t.Fatal("healthy AWG started child")
	}
	for i := 1; i <= 3; i++ {
		m.Step(context.Background(), now.Add(time.Duration(i)*time.Second), health.Result{}, true, r, "primary", "auto")
	}
	if len(b.starts) != 3 || b.starts[0] != "primary" || b.starts[1] != "other" || b.starts[2] != "tcp-only" {
		t.Fatalf("candidate order: %v", b.starts)
	}
	s := m.Snapshot()
	if s.Selection.General != contract.Gecko || s.Selection.Games != contract.Down || s.Active.ID != "tcp-only" {
		t.Fatalf("TCP-only selection: %#v", s)
	}
	if b.stops < 2 || cleaned < 3 {
		t.Fatal("failed candidates were not cleaned")
	}
	m.Shutdown()
	if b.alive {
		t.Fatal("shutdown left child")
	}
}
func TestManualCrashCooldownRecoveryAndDuplicateStart(t *testing.T) {
	b := &fakeBackend{}
	m := New(b, func(_ context.Context, _ profile.Profile) health.Result { return health.Result{TCP: true, UDP: true} }, func() error { return nil })
	r := &profile.Registry{Version: 1, Profiles: []profile.Profile{candidate("manual", "hy2", "", true)}}
	now := time.Unix(100, 0)
	m.Step(context.Background(), now, health.Result{TCP: true, UDP: true}, true, r, "", "manual")
	m.Step(context.Background(), now.Add(time.Second), health.Result{TCP: true, UDP: true}, true, r, "", "manual")
	if len(b.starts) != 1 || m.Snapshot().Selection.General != contract.Gecko {
		t.Fatal("manual or duplicate start")
	}
	b.alive = false
	m.Step(context.Background(), now.Add(2*time.Second), health.Result{}, false, r, "", "manual")
	if m.Snapshot().Selection.General != contract.Down || len(b.starts) != 1 {
		t.Fatal("crash bypassed cooldown")
	}
	m.Step(context.Background(), now.Add(40*time.Second), health.Result{}, false, r, "", "manual")
	if len(b.starts) != 2 {
		t.Fatal("cooldown never retried")
	}
	m.Step(context.Background(), now.Add(41*time.Second), awgTiming(100), true, r, "", "auto")
	if m.Snapshot().Selection.General != contract.Gecko {
		t.Fatal("AWG returned without recovery window")
	}
	for i := 1; i <= 13; i++ {
		m.Step(context.Background(), now.Add(41*time.Second+time.Duration(i)*health.Interval), awgTiming(100), true, r, "", "auto")
	}
	if m.Snapshot().Selection.General != contract.AWG || b.alive {
		t.Fatal("recovered AWG left backup alive")
	}
}
func TestCandidateProbeDeadlineAndFailureBackoff(t *testing.T) {
	b := &fakeBackend{}
	m := New(b, func(ctx context.Context, _ profile.Profile) health.Result { <-ctx.Done(); return health.Result{} }, func() error { return nil })
	m.ProbeTimeout = time.Millisecond
	r := &profile.Registry{Version: 1, Profiles: []profile.Profile{candidate("timeout", "hy2", "", true)}}
	now := time.Unix(100, 0)
	m.Step(context.Background(), now, health.Result{}, false, r, "", "auto")
	m.Step(context.Background(), now.Add(time.Second), health.Result{}, false, r, "", "auto")
	if b.alive || len(b.starts) != 1 || m.Snapshot().Selection.General != contract.Down {
		t.Fatal("timeout child retained or restarted")
	}
}
