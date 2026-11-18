package transport

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
)

func TestHealthyReserveSurvivesQualifiedAWGFailbackAndIsReused(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	h := managedConnection(t, "hy2", "h", 20)
	r := &connection.Registry{Version: 2, Connections: []connection.Connection{a, h}}
	b := &fakeBackend{}
	awg := &fakeAWG{good: map[string]bool{}}
	cleaned := 0
	m := New(b, func(context.Context, profile.Profile) health.Result {
		return health.Result{Measured: true, TCP: true, UDP: true}
	}, func() error { cleaned++; return nil })
	m.SetAWGBackend(awg)
	now := time.Unix(100, 0)
	step := func(at time.Time) Snapshot {
		return m.StepConnections(context.Background(), at, r, connection.Selection{Mode: "auto"}, connection.DefaultOrder(r), 1)
	}
	s := step(now)
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "h" {
		t.Fatal("reserve never admitted")
	}
	stops, clears, starts := b.stops, cleaned, len(b.starts)
	awg.good["a"] = true
	for i := 1; i <= 13; i++ {
		s = step(now.Add(time.Duration(i) * 5 * time.Second))
	}
	if s.Selection.General != contract.AWG || !b.alive || b.stops != stops || cleaned != clears {
		t.Fatal("AWG recovery destroyed a healthy reserve", s.Selection, b.alive, b.stops-stops, cleaned-clears)
	}
	if reserve := retainedReserve(s); reserve == nil || reserve.ID != "h" || reserve.Revision != h.Revision {
		t.Fatal("retained reserve identity missing")
	}
	h.Name = "Main reserve renamed"
	r.Connections[1] = h
	s = step(now.Add(70 * time.Second))
	if reserve := retainedReserve(s); reserve == nil || reserve.Name != h.Name {
		t.Fatal("metadata edit left a stale reserve summary")
	}
	for i := 15; i <= 740; i++ {
		s = step(now.Add(time.Duration(i) * 5 * time.Second))
	}
	if !b.alive || b.stops != stops || cleaned != clears {
		t.Fatal("delayed cleanup broke long reserve sessions")
	}
	awg.good["a"] = false
	for i := 741; i <= 743; i++ {
		s = step(now.Add(time.Duration(i) * 5 * time.Second))
	}
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "h" || s.Selection.General != contract.Gecko || len(b.starts) != starts || b.stops != stops {
		t.Fatal("repeat AWG failure restarted the ready reserve")
	}
}

type timeoutAWG struct {
	fakeAWG
	block   bool
	entered chan struct{}
}

func (a *timeoutAWG) Probe(ctx context.Context) health.Result {
	if !a.block {
		return a.fakeAWG.Probe(ctx)
	}
	select {
	case a.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return health.Result{Measured: true}
}
func TestAWGTimeoutDoesNotConsumeReserveProbeBudget(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	h := managedConnection(t, "hy2", "h", 20)
	r := &connection.Registry{Version: 2, Connections: []connection.Connection{a, h}}
	b := &fakeBackend{}
	awg := &timeoutAWG{fakeAWG: fakeAWG{good: map[string]bool{}}, entered: make(chan struct{}, 1)}
	m := New(b, func(ctx context.Context, _ profile.Profile) health.Result {
		if awg.block {
			select {
			case <-awg.entered:
			case <-ctx.Done():
				return health.Result{Measured: true}
			}
		}
		if ctx.Err() != nil {
			return health.Result{Measured: true}
		}
		return health.Result{Measured: true, TCP: true, UDP: true}
	}, func() error { return nil })
	m.SetAWGBackend(awg)
	now := time.Unix(100, 0)
	m.StepConnections(context.Background(), now, r, connection.Selection{Mode: "auto"}, connection.DefaultOrder(r), 1)
	awg.block = true
	m.StepTimeout = 40 * time.Millisecond
	m.ProbeTimeout = 40 * time.Millisecond
	for i := 1; i <= 3; i++ {
		s := m.StepConnections(context.Background(), now.Add(time.Duration(i)*5*time.Second), r, connection.Selection{Mode: "auto"}, connection.DefaultOrder(r), 1)
		if s.ActiveConnection == nil || s.ActiveConnection.ID != "h" || !s.Slot.Last.TCP || !s.Slot.Last.UDP || s.Slot.Failures != 0 {
			t.Fatal("AWG timeout fabricated reserve failure", s.Slot)
		}
	}
}

func TestReserveDeletionRetiresOnlyImportedChannel(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	h := managedConnection(t, "hy2", "h", 20)
	r := &connection.Registry{Version: 2, Connections: []connection.Connection{a, h}}
	b := &fakeBackend{}
	awg := &fakeAWG{good: map[string]bool{}}
	m := New(b, func(context.Context, profile.Profile) health.Result { return health.Result{TCP: true, UDP: true} }, nil)
	channels := []contract.Channel{}
	cleaner, ok := any(m).(interface {
		SetChannelCleanup(func(contract.Channel, string) error)
	})
	if !ok {
		t.Fatal("channel-specific cleanup API missing")
	}
	cleaner.SetChannelCleanup(func(ch contract.Channel, _ string) error { channels = append(channels, ch); return nil })
	m.SetAWGBackend(awg)
	now := time.Unix(100, 0)
	m.StepConnections(context.Background(), now, r, connection.Selection{Mode: "auto"}, connection.DefaultOrder(r), 1)
	awg.good["a"] = true
	for i := 1; i <= 13; i++ {
		m.StepConnections(context.Background(), now.Add(time.Duration(i)*5*time.Second), r, connection.Selection{Mode: "auto"}, connection.DefaultOrder(r), 1)
	}
	channels = nil
	r.Connections = []connection.Connection{a}
	s := m.StepConnections(context.Background(), now.Add(70*time.Second), r, connection.Selection{Mode: "auto"}, connection.DefaultOrder(r), 1)
	if len(channels) != 1 || channels[0] != contract.Gecko || s.Selection.General != contract.AWG || b.alive || retainedReserve(s) != nil {
		t.Fatal("reserve deletion disturbed native route or retained old backend", channels, s)
	}
}

func retainedReserve(s Snapshot) *connection.Summary {
	field := reflect.ValueOf(s).FieldByName("ReserveConnection")
	if !field.IsValid() || field.IsNil() {
		return nil
	}
	return field.Interface().(*connection.Summary)
}

func TestAWGTimeoutDoesNotStarveColdReserveAdmission(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	h := managedConnection(t, "hy2", "h", 20)
	r := &connection.Registry{Version: 2, Connections: []connection.Connection{a, h}}
	b := &fakeBackend{}
	awg := &timeoutAWG{fakeAWG: fakeAWG{good: map[string]bool{}}, block: true, entered: make(chan struct{}, 1)}
	m := New(b, func(context.Context, profile.Profile) health.Result {
		return health.Result{Measured: true, TCP: true, UDP: true}
	}, func() error { return nil })
	m.SetAWGBackend(awg)
	m.StepTimeout = 40 * time.Millisecond
	m.ProbeTimeout = 40 * time.Millisecond
	now := time.Unix(100, 0)
	m.StepConnections(context.Background(), now, r, connection.Selection{Mode: "auto"}, connection.DefaultOrder(r), 1)
	s := m.StepConnections(context.Background(), now.Add(5*time.Second), r, connection.Selection{Mode: "auto"}, connection.DefaultOrder(r), 1)
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "h" || len(b.starts) != 1 {
		t.Fatal("configured native timeout starved cold reserve admission")
	}
}

func TestReserveCleanupFailureCannotReuseMarkOrDisturbAWG(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	h := managedConnection(t, "hy2", "h", 20)
	r := &connection.Registry{Version: 2, Connections: []connection.Connection{a, h}}
	b := &fakeBackend{}
	awg := &fakeAWG{good: map[string]bool{}}
	fail := false
	channels := []contract.Channel{}
	m := New(b, func(context.Context, profile.Profile) health.Result {
		return health.Result{Measured: true, TCP: true, UDP: true}
	}, nil)
	m.SetAWGBackend(awg)
	m.SetChannelCleanup(func(ch contract.Channel, _ string) error {
		channels = append(channels, ch)
		if fail {
			return context.Canceled
		}
		return nil
	})
	now := time.Unix(100, 0)
	m.StepConnections(context.Background(), now, r, connection.Selection{Mode: "auto"}, connection.DefaultOrder(r), 1)
	awg.good["a"] = true
	for i := 1; i <= 13; i++ {
		m.StepConnections(context.Background(), now.Add(time.Duration(i)*5*time.Second), r, connection.Selection{Mode: "auto"}, connection.DefaultOrder(r), 1)
	}
	replacement := managedConnection(t, "hy2", "h", 21)
	r.Connections[1] = replacement
	fail = true
	channels = nil
	stops, starts := b.stops, len(b.starts)
	s := m.StepConnections(context.Background(), now.Add(70*time.Second), r, connection.Selection{Mode: "auto"}, connection.DefaultOrder(r), 1)
	if !s.Pending || s.Selection.General != contract.AWG || !b.alive || b.stops != stops || len(b.starts) != starts || len(channels) != 1 || channels[0] != contract.Gecko {
		t.Fatal("partial slot retirement reused affinity or disturbed healthy native default")
	}
	fail = false
	s = m.StepConnections(context.Background(), now.Add(75*time.Second), r, connection.Selection{Mode: "auto"}, connection.DefaultOrder(r), 1)
	if s.Pending || s.Selection.General != contract.AWG || b.alive || s.ReserveConnection != nil || b.stops != stops+1 {
		t.Fatal("slot cleanup recovery did not preserve native default")
	}
}

func TestCancelledRoundDoesNotCountFailureOrQualifyAWGRecovery(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	h := managedConnection(t, "hy2", "h", 20)
	r := &connection.Registry{Version: 2, Connections: []connection.Connection{a, h}}
	awg := &fakeAWG{good: map[string]bool{}}
	m := New(&fakeBackend{}, func(context.Context, profile.Profile) health.Result {
		return health.Result{Measured: true, TCP: true, UDP: true}
	}, nil)
	m.SetAWGBackend(awg)
	now := time.Unix(100, 0)
	m.StepConnections(context.Background(), now, r, connection.Selection{Mode: "auto"}, connection.DefaultOrder(r), 1)
	awg.good["a"] = true
	before := m.StepConnections(context.Background(), now.Add(5*time.Second), r, connection.Selection{Mode: "auto"}, connection.DefaultOrder(r), 1)
	if before.AWG.RecoverySince.IsZero() {
		t.Fatal("native recovery qualification was not started")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := m.StepConnections(ctx, now.Add(10*time.Second), r, connection.Selection{Mode: "auto"}, connection.DefaultOrder(r), 1)
	if s.Slot.Failures != before.Slot.Failures || !s.Slot.LastCheck.Equal(before.Slot.LastCheck) || !s.AWG.RecoverySince.IsZero() || s.AWG.RecoveryCleanSamples != 0 || !s.AWG.LastCheck.Equal(before.AWG.LastCheck) {
		t.Fatal("canceled round counted failure, freshness or uninterrupted recovery")
	}
}
