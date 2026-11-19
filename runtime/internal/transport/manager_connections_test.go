package transport

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
)

type fakeAWG struct {
	result   *health.Result
	active   string
	switches []string
	good     map[string]bool
	events   *[]string
	// failSwitch: Switch reports an error and the previous interface stays.
	failSwitch map[string]bool
}

func (a *fakeAWG) Switch(_ context.Context, c connection.Connection) error {
	if a.failSwitch[c.ID] {
		a.switches = append(a.switches, c.ID)
		return fmt.Errorf("native AWG switch failed; previous owned state restored")
	}
	a.active = c.ID
	a.switches = append(a.switches, c.ID)
	if a.events != nil {
		*a.events = append(*a.events, "switch")
	}
	return nil
}
func (a *fakeAWG) Probe(_ context.Context) health.Result {
	if a.result != nil {
		return *a.result
	}
	if a.good[a.active] {
		return awgTiming(100)
	}
	return health.Result{Measured: true}
}
func (a *fakeAWG) Present() bool { return a.active != "" }
func managedConnection(t *testing.T, family, id string, octet int) connection.Connection {
	t.Helper()
	raw := fmt.Sprintf("hy2://public-test@192.0.2.%d:443?obfs=salamander&obfs-password=public-obfs", octet)
	if family == "awg" {
		key := "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
		raw = fmt.Sprintf("[Interface]\nPrivateKey=%s\nHeaderProtectionKey=%s\nAddress=10.77.0.2/32\nS1=12\nS2=12\nS3=12\nS4=12\n[Peer]\nPublicKey=%s\nPresharedKey=%s\nEndpoint=192.0.2.%d:51820\nAllowedIPs=0.0.0.0/0\n", key, key, key, key, octet)
	}
	items, err := connection.ParseImport([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	c := items[0]
	c.ID = id
	return c
}
func TestConnectionOrderedModesAffinityAndGeneration(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	h := managedConnection(t, "hy2", "h", 20)
	r := &connection.Registry{Version: 2, Connections: []connection.Connection{a, h}}
	order := connection.DefaultOrder(r)
	order.Families[0], order.Families[1] = "hy2", "awg"
	b := &fakeBackend{}
	awg := &fakeAWG{good: map[string]bool{"a": true}}
	m := New(b, func(context.Context, profile.Profile) health.Result { return health.Result{TCP: true, UDP: true} }, func() error { return nil })
	m.SetAWGBackend(awg)
	now := time.Unix(100, 0)
	s := m.StepConnections(context.Background(), now, r, connection.Selection{Mode: "auto"}, order, 1)
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "h" || len(awg.switches) != 0 {
		t.Fatal("HY2-first order ignored")
	}
	order = connection.DefaultOrder(r)
	s = m.StepConnections(context.Background(), now.Add(5*time.Second), r, connection.Selection{Mode: "auto"}, order, 1)
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "h" || len(b.starts) != 1 {
		t.Fatal("order metadata edit disturbed healthy affinity")
	}
	s = m.StepConnections(context.Background(), now.Add(10*time.Second), r, connection.Selection{Mode: "auto"}, order, 2)
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "a" || s.Generation != 2 || s.Selection.General != contract.AWG || b.alive {
		t.Fatal("explicit reselect generation did not use new order")
	}
}
func TestConnectionPinnedAndTransportFailuresHaveNoHiddenFallback(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	h := managedConnection(t, "hy2", "h", 20)
	r := &connection.Registry{Version: 2, Connections: []connection.Connection{a, h}}
	for _, selection := range []connection.Selection{{Mode: "connection", ID: "a"}, {Mode: "transport", Family: "awg"}} {
		b := &fakeBackend{}
		awg := &fakeAWG{good: map[string]bool{}}
		m := New(b, func(context.Context, profile.Profile) health.Result { return health.Result{TCP: true, UDP: true} }, func() error { return nil })
		m.SetAWGBackend(awg)
		s := m.StepConnections(context.Background(), time.Unix(100, 0), r, selection, connection.DefaultOrder(r), 1)
		if s.Selection.General != contract.Down || s.Requested != selection || len(b.starts) != 0 {
			t.Fatal("failed manual choice silently fell back")
		}
		m.StepConnections(context.Background(), time.Unix(101, 0), r, selection, connection.DefaultOrder(r), 1)
		if len(awg.switches) != 1 {
			t.Fatal("manual retry bypassed cooldown")
		}
	}
}
func TestConnectionAWGFallbackAndRevisionIsolation(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	b := managedConnection(t, "awg", "b", 11)
	r := &connection.Registry{Version: 2, Connections: []connection.Connection{a, b}}
	awg := &fakeAWG{good: map[string]bool{"b": true}}
	events := []string{}
	awg.events = &events
	m := New(&fakeBackend{}, func(context.Context, profile.Profile) health.Result { return health.Result{} }, func() error { events = append(events, "down-cleanup-dns"); return nil })
	m.SetAWGBackend(awg)
	s := m.StepConnections(context.Background(), time.Unix(100, 0), r, connection.Selection{Mode: "auto"}, connection.DefaultOrder(r), 1)
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "b" || strings.Join(awg.switches, ",") != "a,b" {
		t.Fatal("second native AWG was not tried")
	}
	for i, event := range events {
		if event == "switch" && (i == 0 || events[i-1] != "down-cleanup-dns") {
			t.Fatal("native switch preceded down/owned cleanup/DNS invalidation")
		}
	}
	replacement := managedConnection(t, "awg", "a", 12)
	r.Connections[0] = replacement
	awg.good["a"] = true
	s = m.StepConnections(context.Background(), time.Unix(101, 0), r, connection.Selection{Mode: "connection", ID: "a"}, connection.DefaultOrder(r), 2)
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "a" || s.ActiveConnection.Revision != replacement.Revision || s.AWG.BaselineSamples > 1 {
		t.Fatal("new revision inherited another AWG baseline or cooldown")
	}
}
func TestConnectionAWGQualifiedFailbackOnlyFromHigherRank(t *testing.T) {
	for _, higher := range []bool{true, false} {
		a := managedConnection(t, "awg", "a", 10)
		h := managedConnection(t, "hy2", "h", 20)
		r := &connection.Registry{Version: 2, Connections: []connection.Connection{a, h}}
		order := connection.DefaultOrder(r)
		awg := &fakeAWG{good: map[string]bool{}}
		m := New(&fakeBackend{}, func(context.Context, profile.Profile) health.Result { return health.Result{TCP: true, UDP: true} }, func() error { return nil })
		m.SetAWGBackend(awg)
		now := time.Unix(100, 0)
		m.StepConnections(context.Background(), now, r, connection.Selection{Mode: "auto"}, order, 1)
		awg.good["a"] = true
		if !higher {
			order.Families[0], order.Families[1] = "hy2", "awg"
		}
		for i := 1; i <= 13; i++ {
			s := m.StepConnections(context.Background(), now.Add(time.Duration(i)*5*time.Second), r, connection.Selection{Mode: "auto"}, order, 1)
			if (i < 13 || !higher) && (s.ActiveConnection == nil || s.ActiveConnection.ID != "h") {
				t.Fatal("native failback preceded qualified recovery or ignored rank")
			}
		}
		if higher && m.Snapshot().Selection.General != contract.AWG {
			t.Fatal("qualified higher native path never recovered")
		}
	}
}
func TestConnectionTCPOnlyKeepsGamesDown(t *testing.T) {
	raw, err := os.ReadFile("../profile/testdata/shadowtls.json")
	if err != nil {
		t.Fatal(err)
	}
	items, err := connection.ParseImport(raw)
	if err != nil {
		t.Fatal(err)
	}
	r := &connection.Registry{Version: 2, Connections: items}
	m := New(&fakeBackend{}, func(context.Context, profile.Profile) health.Result { return health.Result{TCP: true, UDP: true} }, func() error { return nil })
	s := m.StepConnections(context.Background(), time.Unix(100, 0), r, connection.Selection{Mode: "auto"}, connection.DefaultOrder(r), 1)
	if s.Selection.General != contract.Gecko || s.Selection.Games != contract.Down {
		t.Fatal("TCP-only profile opened UDP games path")
	}
}
func TestConnectionLateProbeCannotPublishOldGeneration(t *testing.T) {
	h := managedConnection(t, "hy2", "h", 20)
	r := &connection.Registry{Version: 2, Connections: []connection.Connection{h}}
	b := &fakeBackend{}
	var m *Manager
	m = New(b, func(context.Context, profile.Profile) health.Result {
		m.RequestGeneration(2)
		return health.Result{TCP: true, UDP: true}
	}, func() error { return nil })
	s := m.StepConnections(context.Background(), time.Unix(100, 0), r, connection.Selection{Mode: "auto"}, connection.DefaultOrder(r), 1)
	if s.Selection.General != contract.Down || s.ActiveConnection != nil || b.alive {
		t.Fatal("late probe published stale selection")
	}
}

func TestConnectionRestartUsesRequestedAWGInsteadOfLegacyPrimary(t *testing.T) {
	srvmain := managedConnection(t, "awg", "srvmain", 10)
	srvbackup := managedConnection(t, "awg", "srvbackup", 20)
	r := &connection.Registry{Version: 2, Connections: []connection.Connection{srvmain, srvbackup}}
	awg := &fakeAWG{active: "srvmain", good: map[string]bool{"srvbackup": true}}
	m := New(&fakeBackend{}, func(context.Context, profile.Profile) health.Result { return health.Result{} }, func() error { return nil })
	m.SetAWGBackend(awg)
	s := m.StepConnections(context.Background(), time.Unix(100, 0), r, connection.Selection{Mode: "connection", ID: "srvbackup"}, connection.DefaultOrder(r), 1)
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "srvbackup" || strings.Join(awg.switches, ",") != "srvbackup" {
		t.Fatal("restart returned to legacy primary instead of requested AWG")
	}
}

func TestConnectionOneProviderImpairmentKeepsHealthyAWG(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	h := managedConnection(t, "hy2", "h", 20)
	r := &connection.Registry{Version: 2, Connections: []connection.Connection{a, h}}
	b := &fakeBackend{}
	awg := &fakeAWG{good: map[string]bool{"a": true}}
	m := New(b, func(context.Context, profile.Profile) health.Result { return health.Result{TCP: true, UDP: true} }, func() error { return nil })
	m.SetAWGBackend(awg)
	now := time.Unix(100, 0)
	for i := 0; i < 15; i++ {
		m.StepConnections(context.Background(), now.Add(time.Duration(i)*5*time.Second), r, connection.Selection{Mode: "auto"}, connection.DefaultOrder(r), 1)
	}
	result := awgTiming(100)
	result.Targets[0] = health.TargetResult{}
	awg.result = &result
	for i := 15; i < 30; i++ {
		s := m.StepConnections(context.Background(), now.Add(time.Duration(i)*5*time.Second), r, connection.Selection{Mode: "auto"}, connection.DefaultOrder(r), 1)
		if s.Selection.General != contract.AWG || len(b.starts) != 0 {
			t.Fatal("one-provider failure caused false fallback")
		}
	}
}

// A failed forward mutation and failed rollback can leave a live wrong peer.
type uncertainAWG struct {
	fakeAWG
	uncertain bool
	probes    int
}

func (a *uncertainAWG) Switch(ctx context.Context, c connection.Connection) error {
	if a.uncertain {
		if c.ID == "b" {
			a.active = "b"
		}
		return fmt.Errorf("native AWG switch failed; owned recovery pending")
	}
	return a.fakeAWG.Switch(ctx, c)
}
func (a *uncertainAWG) Probe(ctx context.Context) health.Result {
	a.probes++
	return a.fakeAWG.Probe(ctx)
}
func TestUnconfirmedNativeRollbackCannotMeasureOrPublishPreviousIdentity(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	b := managedConnection(t, "awg", "b", 11)
	r := &connection.Registry{Version: 2, Connections: []connection.Connection{a, b}}
	order := connection.DefaultOrder(r)
	backend := &uncertainAWG{fakeAWG: fakeAWG{good: map[string]bool{"a": true, "b": true}}}
	m := New(&fakeBackend{}, nil, func() error { return nil })
	m.SetAWGBackend(backend)
	now := time.Unix(100, 0)
	s := m.StepConnections(context.Background(), now, r, connection.Selection{Mode: "auto"}, order, 1)
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "a" {
		t.Fatal("fixture did not install A")
	}
	backend.uncertain = true
	order.Connections["awg"] = []string{"b", "a"}
	s = m.StepConnections(context.Background(), now.Add(5*time.Second), r, connection.Selection{Mode: "auto"}, order, 2)
	if backend.active != "b" {
		t.Fatal("fixture did not leave wrong physical native B")
	}
	if s.ActiveConnection != nil || s.Selection.General != contract.Down || m.NativeConnection() != nil {
		t.Fatal("unconfirmed rollback retained or published a false native identity", s)
	}
	before := backend.probes
	for i := 2; i <= 15; i++ {
		s = m.StepConnections(context.Background(), now.Add(time.Duration(i)*5*time.Second), r, connection.Selection{Mode: "auto"}, order, 2)
		if s.ActiveConnection != nil || m.NativeConnection() != nil {
			t.Fatal("unknown physical peer admitted as a named connection")
		}
	}
	if backend.probes != before {
		t.Fatal("unknown native peer measurements attributed to prior ID")
	}
	backend.uncertain = false
	s = m.StepConnections(context.Background(), now.Add(10*time.Minute), r, connection.Selection{Mode: "auto"}, order, 2)
	if s.ActiveConnection == nil || s.ActiveConnection.ID != backend.active {
		t.Fatal("successful known reinstall did not restore trustworthy identity", s)
	}
}

func TestNativeCleanupFailureRetriesMainBeforeSelectingSpare(t *testing.T) {
	t.Run("transient failure", func(t *testing.T) {
		testNativeCleanupFailure(t, 1, "main")
	})
	t.Run("persistent failure", func(t *testing.T) {
		testNativeCleanupFailure(t, 3, "reserve")
	})
}

func testNativeCleanupFailure(t *testing.T, failures int, want string) {
	t.Helper()
	main := managedConnection(t, "awg", "main", 10)
	spare := managedConnection(t, "awg", "spare", 11)
	reserve := managedConnection(t, "hy2", "reserve", 12)
	registry := &connection.Registry{Version: 2, Connections: []connection.Connection{main, spare, reserve}}
	order := connection.DefaultOrder(registry)
	awg := &fakeAWG{good: map[string]bool{"main": true, "spare": true}}
	backend := &fakeBackend{}
	manager := New(backend, func(context.Context, profile.Profile) health.Result {
		return health.Result{TCP: true, UDP: true}
	}, func() error { return nil })
	manager.SetAWGBackend(awg)
	var attempts int
	manager.SetChannelCleanup(func(channel contract.Channel, _ string) error {
		if channel == contract.AWG {
			attempts++
			if attempts <= failures {
				return fmt.Errorf("AWG conntrack unavailable")
			}
		}
		return nil
	})

	now := time.Unix(100, 0)
	step := func() Snapshot {
		snapshot := manager.StepConnections(context.Background(), now, registry, connection.Selection{Mode: "auto"}, order, 1)
		now = now.Add(health.Interval)
		return snapshot
	}
	s := step()
	if !s.Pending || s.ActiveConnection != nil || len(awg.switches) != 0 {
		t.Fatalf("first cleanup failure must leave the AWG mark unused, got pending=%v active=%v switches=%v", s.Pending, s.ActiveConnection, awg.switches)
	}
	s = step()
	if s.ActiveConnection == nil || s.ActiveConnection.ID != want {
		t.Fatalf("after retry: wanted %s, got %v (switched %v)", want, s.ActiveConnection, awg.switches)
	}
	if attempts != 2 {
		t.Fatalf("expected exactly two cleanup attempts, got %d", attempts)
	}
	if want == "main" {
		s = step()
		if s.ActiveConnection == nil || s.ActiveConnection.ID != "main" || attempts != 2 || strings.Join(awg.switches, ",") != "main" {
			t.Fatalf("healthy Main was disturbed: active=%v cleanups=%d switches=%v", s.ActiveConnection, attempts, awg.switches)
		}
		return
	}
	if len(awg.switches) != 0 {
		t.Fatalf("AWG mark reused after cleanup failed: %v", awg.switches)
	}
	stops := backend.stops
	s = step()
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "reserve" || !backend.alive || backend.stops != stops || len(awg.switches) != 0 {
		t.Fatalf("ongoing AWG cleanup failure disturbed the reserve: active=%v switches=%v", s.ActiveConnection, awg.switches)
	}
	s = step()
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "main" || !backend.alive || backend.stops != stops {
		t.Fatalf("AWG failed to recover without disturbing the reserve: active=%v reserve alive=%v", s.ActiveConnection, backend.alive)
	}
}
