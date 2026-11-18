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

func TestFailedAWGWithoutEligibleCandidatesPublishesDown(t *testing.T) {
	for _, mode := range []string{"empty", "disabled", "cooldown", "manual-unavailable"} {
		t.Run(mode, func(t *testing.T) {
			b := &fakeBackend{}
			m := New(b, func(context.Context, profile.Profile) health.Result { return health.Result{} }, func() error { return nil })
			r := &profile.Registry{Version: 1}
			if mode != "empty" {
				p := candidate("backup", "hy2", "", true)
				p.Enabled = mode != "disabled"
				r.Profiles = []profile.Profile{p}
			}
			now := time.Unix(100, 0)
			if mode == "cooldown" {
				m.retries["backup"] = retry{failures: 1, after: now.Add(time.Hour)}
			}
			m.Step(context.Background(), now, health.Result{TCP: true, UDP: true}, true, r, "", "auto")
			selection := "auto"
			if mode == "manual-unavailable" {
				selection = "missing"
			}
			for i := 1; i <= 3; i++ {
				m.Step(context.Background(), now.Add(time.Duration(i)*time.Second), health.Result{}, true, r, "", selection)
			}
			if m.Snapshot().Selection.General != contract.Down || m.Snapshot().Selection.Games != contract.Down {
				t.Fatal("failed AWG remained published")
			}
			if len(b.starts) != 0 {
				t.Fatal("ineligible candidate started")
			}
		})
	}
}
func TestCleanupFailureRetriesBeforeHealthyActiveProfileCanResume(t *testing.T) {
	b := &fakeBackend{}
	failCleanup := false
	attempts := 0
	m := New(b, func(context.Context, profile.Profile) health.Result { return health.Result{TCP: true, UDP: true} }, func() error {
		attempts++
		if failCleanup {
			return errors.New("public cleanup failure")
		}
		return nil
	})
	r := &profile.Registry{Version: 1, Profiles: []profile.Profile{candidate("manual", "hy2", "", true)}}
	now := time.Unix(100, 0)
	m.Step(context.Background(), now, health.Result{}, false, r, "", "manual")
	failCleanup = true
	if e := m.Shutdown(); e == nil {
		t.Fatal("failed cleanup reported success")
	}
	before := attempts
	m.Step(context.Background(), now.Add(time.Second), health.Result{}, false, r, "", "manual")
	if attempts <= before || m.Snapshot().Selection.General != contract.Down {
		t.Fatal("cleanup was not retried while failing")
	}
	failCleanup = false
	m.Step(context.Background(), now.Add(2*time.Second), health.Result{}, false, r, "", "manual")
	if m.Snapshot().Selection.General != contract.Gecko || len(b.starts) != 2 {
		t.Fatal("healthy old profile stayed down without cleanup/restart")
	}
}

type failingStopBackend struct {
	fakeBackend
	fail     bool
	attempts int
}

func (b *failingStopBackend) Stop() error {
	b.attempts++
	if b.fail {
		return errors.New("public stop failure")
	}
	return b.fakeBackend.Stop()
}
func TestStopFailureRetriesCleanupBeforeReselecting(t *testing.T) {
	b := &failingStopBackend{}
	m := New(b, func(context.Context, profile.Profile) health.Result { return health.Result{TCP: true, UDP: true} }, func() error { return nil })
	r := &profile.Registry{Version: 1, Profiles: []profile.Profile{candidate("manual", "hy2", "", true)}}
	now := time.Unix(100, 0)
	m.Step(context.Background(), now, health.Result{}, false, r, "", "manual")
	b.fail = true
	if e := m.Shutdown(); e == nil {
		t.Fatal("stop failure reported success")
	}
	attempts := b.attempts
	m.Step(context.Background(), now.Add(time.Second), health.Result{}, false, r, "", "manual")
	if b.attempts <= attempts || m.Snapshot().Selection.General != contract.Down {
		t.Fatal("stop failure was not retried")
	}
	b.fail = false
	m.Step(context.Background(), now.Add(2*time.Second), health.Result{}, false, r, "", "manual")
	if m.Snapshot().Selection.General != contract.Gecko || len(b.starts) != 2 {
		t.Fatal("stop retry did not restore healthy selection")
	}
}

func TestProbeFailureRetirementRetriesCleanupBeforeHealthyProbe(t *testing.T) {
	for _, failure := range []string{"quiesce", "stop"} {
		t.Run(failure, func(t *testing.T) {
			b := &failingStopBackend{}
			good := true
			cleanupFails := false
			probes, cleanups := 0, 0
			m := New(b, func(context.Context, profile.Profile) health.Result {
				probes++
				return health.Result{TCP: good, UDP: good}
			}, func() error {
				cleanups++
				if cleanupFails {
					return errors.New("public quiesce failure")
				}
				return nil
			})
			r := &profile.Registry{Version: 1, Profiles: []profile.Profile{candidate("backup", "hy2", "", true)}}
			now := time.Unix(100, 0)
			m.Step(context.Background(), now, health.Result{}, false, r, "", "auto")
			good = false
			cleanupFails = failure == "quiesce"
			b.fail = failure == "stop"
			for i := 1; i <= 3; i++ {
				m.Step(context.Background(), now.Add(time.Duration(i)*time.Second), health.Result{}, false, r, "", "auto")
			}
			if m.Snapshot().Selection.General != contract.Down {
				t.Fatal("failed retirement did not fail closed")
			}
			beforeProbes, beforeCleanup := probes, cleanups
			good = true
			cleanupFails = false
			b.fail = false
			m.Step(context.Background(), now.Add(4*time.Second), health.Result{}, false, r, "", "auto")
			if cleanups <= beforeCleanup || probes != beforeProbes {
				t.Fatal("healthy probe bypassed pending retirement")
			}
			m.Step(context.Background(), now.Add(40*time.Second), health.Result{}, false, r, "", "auto")
			if m.Snapshot().Selection.General != contract.Gecko || len(b.starts) != 2 {
				t.Fatal("backup could not resume after cleanup and cooldown")
			}
		})
	}
}

func awgTiming(ms int64) health.Result {
	r := health.Result{TCP: true, UDP: true, Measured: true}
	for i := range r.Targets {
		r.Targets[i] = health.TargetResult{TCP: true, UDP: true, TCPDurationMS: ms, UDPDurationMS: ms}
	}
	return r
}
func TestDegradedAWGTriesPrimaryHY2ThenOtherHY2ThenFamilies(t *testing.T) {
	for _, failure := range []string{"none", "all-backups", "cleanup"} {
		t.Run(failure, func(t *testing.T) {
			b := &fakeBackend{}
			cleanupFail := false
			m := New(b, func(_ context.Context, p profile.Profile) health.Result {
				return health.Result{TCP: p.ID == "other" && failure != "all-backups", UDP: true}
			}, func() error {
				if cleanupFail {
					return errors.New("cleanup failed")
				}
				return nil
			})
			r := &profile.Registry{Version: 1, Profiles: []profile.Profile{candidate("reality", "reality", "", true), candidate("other", "hy2", "other", true), candidate("primary", "hy2", "primary", true)}}
			now := time.Unix(1000, 0)
			for i := 0; i < 12; i++ {
				m.Step(context.Background(), now, awgTiming(100), true, r, "primary", "auto")
				now = now.Add(health.Interval)
			}
			cleanupFail = failure == "cleanup"
			for i := 0; i < 20; i++ {
				m.Step(context.Background(), now, awgTiming(2000), true, r, "primary", "auto")
				now = now.Add(health.Interval)
			}
			s := m.Snapshot()
			if s.AWG.Healthy() {
				t.Fatal("slow AWG stayed healthy")
			}
			if failure == "none" {
				if s.Active == nil || s.Active.ID != "other" || len(b.starts) != 2 || b.starts[0] != "primary" {
					t.Fatal("wrong fallback", s, b.starts)
				}
			} else if s.Selection.General != contract.Down || s.Selection.Games != contract.Down {
				t.Fatal("unsafe failed fallback", s)
			}
			if failure == "cleanup" {
				if len(b.starts) != 0 {
					t.Fatal("started while cleanup failed")
				}
				cleanupFail = false
				m.Step(context.Background(), now, awgTiming(2000), true, r, "primary", "auto")
				if m.Snapshot().Active == nil {
					t.Fatal("cleanup not retried")
				}
			}
		})
	}
}
func TestDegradationDoesNotOverrideManualSelection(t *testing.T) {
	b := &fakeBackend{}
	m := New(b, func(context.Context, profile.Profile) health.Result { return health.Result{TCP: true, UDP: true} }, nil)
	r := &profile.Registry{Version: 1, Profiles: []profile.Profile{candidate("manual", "hy2", "", true)}}
	now := time.Unix(1000, 0)
	for i := 0; i < 20; i++ {
		m.Step(context.Background(), now, awgTiming(2000), true, r, "", "manual")
		now = now.Add(health.Interval)
	}
	snapshot := m.Snapshot()
	if snapshot.AWG.Healthy() || snapshot.Active.ID != "manual" || len(b.starts) != 1 {
		t.Fatal("manual selection changed")
	}
}

type boundedStartBackend struct {
	fakeBackend
	contexts []context.Context
}

func (b *boundedStartBackend) Start(ctx context.Context, p profile.Profile) error {
	b.contexts = append(b.contexts, ctx)
	b.starts = append(b.starts, p.ID)
	<-ctx.Done()
	return ctx.Err()
}
func TestStepBudgetIncludesStartupAndContinuesCandidateOrder(t *testing.T) {
	b := &boundedStartBackend{}
	m := New(b, func(context.Context, profile.Profile) health.Result {
		t.Fatal("probed failed startup")
		return health.Result{}
	}, nil)
	m.StepTimeout = 5 * time.Millisecond
	r := &profile.Registry{Version: 1, Profiles: []profile.Profile{candidate("reality", "reality", "", true), candidate("other", "hy2", "other", true), candidate("primary", "hy2", "primary", true)}}
	now := time.Unix(1000, 0)
	for i := 0; i < 3; i++ {
		start := time.Now()
		m.Step(context.Background(), now, health.Result{}, false, r, "primary", "auto")
		if time.Since(start) > time.Second {
			t.Fatal("unbounded step")
		}
		now = now.Add(time.Minute)
	}
	if len(b.starts) != 3 || b.starts[0] != "primary" || b.starts[1] != "other" || b.starts[2] != "reality" {
		t.Fatal("budget restarts starved lower candidates", b.starts)
	}
}
func TestAWGRecoversWhileAllBackupsExhaustStepBudget(t *testing.T) {
	b := &fakeBackend{}
	m := New(b, func(ctx context.Context, _ profile.Profile) health.Result { <-ctx.Done(); return health.Result{} }, nil)
	m.StepTimeout = time.Millisecond
	r := &profile.Registry{Version: 1, Profiles: []profile.Profile{candidate("a", "hy2", "", true), candidate("b", "hy2", "", true), candidate("c", "reality", "", true)}}
	now := time.Unix(1000, 0)
	m.Step(context.Background(), now, health.Result{}, false, r, "", "auto")
	for i := 0; i < 13; i++ {
		now = now.Add(health.Interval)
		m.Step(context.Background(), now, awgTiming(100), true, r, "", "auto")
	}
	if m.Snapshot().Selection.General != contract.AWG {
		t.Fatal("failed candidates starved qualified AWG")
	}
}

func TestRecoveryAllowsBoundedSlowCleanupButRequiresAllCleanSamples(t *testing.T) {
	b := &fakeBackend{}
	m := New(b, func(context.Context, profile.Profile) health.Result { return health.Result{} }, nil)
	r := &profile.Registry{Version: 1, Profiles: []profile.Profile{candidate("a", "hy2", "", true), candidate("b", "hy2", "", true), candidate("c", "reality", "", true)}}
	now := time.Unix(1000, 0)
	m.Step(context.Background(), now, health.Result{}, false, r, "", "auto")
	// Fake round completion times include the known combined probe/start/Stop
	// costs. No test sleeps or native process control are needed.
	for i := 0; i < 12; i++ {
		now = now.Add(20 * time.Second)
		m.Step(context.Background(), now, awgTiming(100), true, r, "", "auto")
	}
	snapshot := m.Snapshot()
	if snapshot.AWG.Healthy() {
		t.Fatal("elapsed time alone bypassed clean observation count")
	}
	now = now.Add(20 * time.Second)
	m.Step(context.Background(), now, awgTiming(100), true, r, "", "auto")
	if m.Snapshot().Selection.General != contract.AWG {
		t.Fatal("known bounded cleanup gaps prevent recovery")
	}
}
