package transport

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/diagnostic"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
)

// warmFixture drives StepConnections and StepWarmReserve in the same order as
// a controller round, with a fake native AWG and a fake proxy backend.
type warmFixture struct {
	m       *Manager
	b       *fakeBackend
	awg     *fakeAWG
	r       *connection.Registry
	order   connection.Order
	sel     connection.Selection
	gen     uint64
	now     time.Time
	names   map[string]string // profile ID -> connection ID
	probes  map[string]int
	fail    map[string]bool
	onProbe func(id string)
	events  []diagnostic.Decision
	cleaned []contract.Channel
	// async leaves a standby admission running after a round instead of
	// waiting for its worker (tests of an admission in flight).
	async bool
}

func newWarmFixture(t *testing.T, items ...connection.Connection) *warmFixture {
	return newWarmFixtureOn(t, &fakeBackend{}, items...)
}

func newWarmFixtureOn(t *testing.T, backend Backend, items ...connection.Connection) *warmFixture {
	t.Helper()
	f := &warmFixture{awg: &fakeAWG{good: map[string]bool{"a": true}}, gen: 1, now: time.Unix(1000, 0), names: map[string]string{}, probes: map[string]int{}, fail: map[string]bool{}}
	f.b, _ = backend.(*fakeBackend)
	f.r = &connection.Registry{Version: 2, Connections: items}
	for _, c := range items {
		if c.Profile != nil {
			f.names[c.Profile.ID] = c.ID
		}
	}
	f.order = connection.DefaultOrder(f.r)
	f.sel = connection.Selection{Mode: "auto"}
	f.m = New(backend, func(_ context.Context, p profile.Profile) health.Result {
		id := f.names[p.ID]
		f.probes[id]++
		if f.onProbe != nil {
			f.onProbe(id)
		}
		if f.fail[id] {
			return health.Result{Measured: true}
		}
		return health.Result{Measured: true, TCP: true, UDP: true}
	}, nil)
	f.m.SetAWGBackend(f.awg)
	f.m.SetChannelCleanup(func(ch contract.Channel, _ string) error { f.cleaned = append(f.cleaned, ch); return nil })
	f.m.SetDecisionRecorder(func(d diagnostic.Decision) { f.events = append(f.events, d) })
	if err := f.m.SetWarmReserve(WarmPolicy{Enabled: true, Interval: 30 * time.Second}); err != nil {
		t.Fatal(err)
	}
	return f
}

// round advances the clock, then runs one controller-ordered round. Unless
// async is set, a standby admission it launched is waited for, so the next
// round adopts or stops it deterministically.
func (f *warmFixture) round(advance time.Duration) (Snapshot, bool) {
	f.now = f.now.Add(advance)
	f.m.StepConnections(context.Background(), f.now, f.r, f.sel, f.order, f.gen)
	s, changed := f.m.StepWarmReserve(context.Background(), f.now, f.r, f.sel, f.order, f.gen)
	if !f.async {
		f.settle()
	}
	return s, changed
}

// admission returns the standby admission in flight, if any.
func (f *warmFixture) admission() *warmAdmission {
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	if f.m.connections == nil {
		return nil
	}
	return f.m.connections.admission
}

// settle waits for the worker of an admission in flight to return.
func (f *warmFixture) settle() {
	if adm := f.admission(); adm != nil {
		<-adm.done
	}
}

// admit runs the round that launches the standby and the round that adopts it.
func (f *warmFixture) admit() Snapshot {
	f.round(0)
	s, _ := f.round(0)
	return s
}

func (f *warmFixture) starts() string {
	ids := []string{}
	for _, id := range f.b.starts {
		ids = append(ids, f.names[id])
	}
	return strings.Join(ids, ",")
}

func tcpOnlyConnection(t *testing.T, id string) connection.Connection {
	t.Helper()
	raw, err := os.ReadFile("../profile/testdata/shadowtls.json")
	if err != nil {
		t.Fatal(err)
	}
	items, err := connection.ParseImport(raw)
	if err != nil {
		t.Fatal(err)
	}
	c := items[0]
	c.ID = id
	if c.Profile == nil || c.Profile.Capabilities.UDP || c.Family == "hy2" {
		t.Fatal("fixture is not a TCP-only proxy")
	}
	return c
}

func TestWarmReserveStartsFirstUDPProxyWithoutChangingDefault(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	tcp := tcpOnlyConnection(t, "t")
	h1 := managedConnection(t, "hy2", "h1", 20)
	h2 := managedConnection(t, "hy2", "h2", 21)
	f := newWarmFixture(t, a, tcp, h1, h2)
	// The TCP-only family ranks before HY2; games never use a TCP carrier.
	families := []string{"awg", tcp.Family}
	for _, family := range connection.Families {
		if family != "awg" && family != tcp.Family {
			families = append(families, family)
		}
	}
	f.order.Families = families
	before := f.m.StepConnections(context.Background(), f.now, f.r, f.sel, f.order, f.gen)
	if before.ActiveConnection == nil || before.ActiveConnection.ID != "a" || len(f.b.starts) != 0 {
		t.Fatal("fixture did not settle on native AWG", before)
	}
	f.cleaned, f.events = nil, nil
	// The start runs in the background: nothing changes until it qualified.
	s, changed := f.m.StepWarmReserve(context.Background(), f.now, f.r, f.sel, f.order, f.gen)
	if changed || s.ReserveConnection != nil || s.Selection != (contract.Selection{General: contract.AWG, Games: contract.AWG}) {
		t.Fatal("launching the standby published a change", s)
	}
	f.settle()
	if f.starts() != "h1" || !f.b.alive {
		t.Fatal("first UDP proxy was not started as a standby", f.starts())
	}
	// The next round adopts it.
	s = f.m.StepConnections(context.Background(), f.now, f.r, f.sel, f.order, f.gen)
	if s.Selection != (contract.Selection{General: contract.AWG, Games: contract.AWG}) || s.ActiveConnection == nil || s.ActiveConnection.ID != "a" || s.Active != nil || s.Generation != before.Generation || s.Pending {
		t.Fatal("warm start changed the default for new flows", s)
	}
	if s.ReserveConnection == nil || s.ReserveConnection.ID != "h1" || !s.ReserveWarm || !s.Slot.Up || !s.Slot.LastCheck.Equal(f.now) {
		t.Fatal("standby not reported as a probed warm reserve", s)
	}
	if len(f.cleaned) != 0 || strings.Join(f.awg.switches, ",") != "a" {
		t.Fatal("warm start cleaned flows or touched native AWG", f.cleaned, f.awg.switches)
	}
	if len(f.events) != 1 || f.events[0].Reason != "warm_reserve" || f.events[0].Outcome != "applied" || f.events[0].To.ID != "h1" || f.events[0].Channel != contract.Gecko {
		t.Fatal("warm admission decision missing", f.events)
	}
	if _, changed = f.m.StepWarmReserve(context.Background(), f.now.Add(40*time.Second), f.r, f.sel, f.order, f.gen); changed || len(f.b.starts) != 1 {
		t.Fatal("existing standby was restarted or replaced")
	}
}

func TestWarmReserveCadenceSlowWhenSettledFastWhenUnsettled(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	h := managedConnection(t, "hy2", "h", 20)
	f := newWarmFixture(t, a, h)
	if s := f.admit(); !s.ReserveWarm || f.probes["h"] != 1 {
		t.Fatal("fixture did not admit the standby")
	}
	for i := 0; i < 5; i++ {
		s, _ := f.round(5 * time.Second)
		if s.ReserveConnection == nil || s.Selection.General != contract.AWG {
			t.Fatal("skipped measurement lost the standby", s)
		}
	}
	if f.probes["h"] != 1 {
		t.Fatal("settled standby was probed every round", f.probes["h"])
	}
	if s, _ := f.round(5 * time.Second); f.probes["h"] != 2 || !s.Slot.LastCheck.Equal(f.now) {
		t.Fatal("standby measurement not taken after the warm interval", f.probes["h"])
	}
	// One failed native sample leaves impairment evidence for the whole
	// window: the standby is measured every round until it settles again.
	f.awg.good["a"] = false
	f.round(5 * time.Second)
	f.awg.good["a"] = true
	before := f.probes["h"]
	for i := 0; i < 4; i++ {
		f.round(5 * time.Second)
	}
	if f.probes["h"] != before+4 {
		t.Fatal("unsettled native did not restore per-round standby probes", f.probes["h"]-before)
	}

	// A dead standby is caught by the liveness check in the next round, even
	// while its measurement is skipped, and is retired without a cool-down.
	f = newWarmFixture(t, a, h)
	f.admit()
	f.round(5 * time.Second)
	f.cleaned = nil
	f.b.alive = false
	s, _ := f.round(5 * time.Second)
	if f.probes["h"] != 1 || f.b.stops != 1 || s.ReserveConnection != nil || s.ReserveWarm || s.Selection.General != contract.AWG {
		t.Fatal("dead standby not retired in the next round", f.probes["h"], f.b.stops, s)
	}
	// It never carried flows: no conntrack cleanup on any channel.
	if len(f.cleaned) != 0 {
		t.Fatal("standby retirement cleaned flows it never carried", f.cleaned)
	}
	key := connectionKey(h)
	if _, cooled := f.m.retries[key]; cooled || f.m.connections.warmRetries[key].failures != 1 {
		t.Fatal("standby failure fed the failover cool-down instead of the warm backoff")
	}
}

func TestWarmReserveFailoverReusesWarmSlotWithoutStartOrStop(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	h := managedConnection(t, "hy2", "h", 20)
	f := newWarmFixture(t, a, h)
	f.admit()
	f.round(5 * time.Second)
	starts, stops := len(f.b.starts), f.b.stops
	f.cleaned, f.events = nil, nil
	f.awg.good["a"] = false
	var s Snapshot
	for i := 0; i < 3; i++ {
		s, _ = f.round(5 * time.Second)
	}
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "h" || s.Selection != (contract.Selection{General: contract.Gecko, Games: contract.Gecko}) {
		t.Fatal("failover did not move new flows to the warm reserve", s)
	}
	if len(f.b.starts) != starts || f.b.stops != stops || !f.b.alive || len(f.cleaned) != 0 {
		t.Fatal("failover started, stopped or cleaned the warm slot", f.starts(), f.b.stops-stops, f.cleaned)
	}
	if s.ReserveConnection != nil || s.ReserveWarm {
		t.Fatal("the default was still reported as a warm reserve", s)
	}
	found := false
	for _, e := range f.events {
		found = found || (e.Reason == "fallback" && e.To.ID == "h")
	}
	if !found {
		t.Fatal("fallback decision missing", f.events)
	}
}

func TestWarmReserveRetainedAfterFailback(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	h := managedConnection(t, "hy2", "h", 20)
	f := newWarmFixture(t, a, h)
	f.admit()
	f.awg.good["a"] = false
	for i := 0; i < 3; i++ {
		f.round(5 * time.Second)
	}
	starts, stops := len(f.b.starts), f.b.stops
	f.awg.good["a"] = true
	var s Snapshot
	for i := 0; i < 14; i++ {
		s, _ = f.round(5 * time.Second)
	}
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "a" || s.Selection.General != contract.AWG {
		t.Fatal("qualified AWG recovery did not fail back", s)
	}
	if s.ReserveConnection == nil || s.ReserveConnection.ID != "h" || s.ReserveWarm || !f.b.alive || f.b.stops != stops {
		t.Fatal("failback tore down the reserve or called it sessionless", s)
	}
	for i := 0; i < 20; i++ {
		s, _ = f.round(35 * time.Second)
	}
	if len(f.b.starts) != starts || f.b.stops != stops || s.ReserveConnection == nil || s.ReserveConnection.ID != "h" {
		t.Fatal("warm step restarted or replaced the retained reserve", f.starts())
	}
	// The next native failure reuses the same process again.
	f.awg.good["a"] = false
	for i := 0; i < 3; i++ {
		s, _ = f.round(5 * time.Second)
	}
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "h" || len(f.b.starts) != starts || f.b.stops != stops {
		t.Fatal("repeat failure restarted the retained reserve")
	}
}

func TestWarmReserveFailureBacksOffWithoutBlockingFailover(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	h := managedConnection(t, "hy2", "h", 20)
	f := newWarmFixture(t, a, h)
	f.fail["h"] = true
	f.round(0)
	s, _ := f.round(0)
	key := connectionKey(h)
	if s.ReserveConnection != nil || f.b.alive || f.b.stops != 1 || f.starts() != "h" {
		t.Fatal("failed standby admission was kept", s)
	}
	for _, ch := range f.cleaned {
		if ch == contract.Gecko {
			t.Fatal("failed standby admission cleaned slot flows it never carried", f.cleaned)
		}
	}
	if _, cooled := f.m.retries[key]; cooled {
		t.Fatal("warm failure fed the failover cool-down")
	}
	if r := f.m.connections.warmRetries[key]; r.failures != 1 || !r.after.Equal(f.now.Add(time.Minute)) {
		t.Fatal("first warm backoff is not 60 s", r)
	}
	last := f.events[len(f.events)-1]
	if last.Reason != "warm_reserve" || last.Outcome != "failed" || last.Stage != "selection" {
		t.Fatal("failed warm admission not recorded", last)
	}
	if f.round(35 * time.Second); len(f.b.starts) != 1 {
		t.Fatal("warm attempt repeated inside its backoff")
	}
	if f.round(30 * time.Second); len(f.b.starts) != 2 {
		t.Fatal("warm attempt not repeated after its backoff")
	}
	if f.round(0); f.m.connections.admission != nil {
		t.Fatal("finished admission not harvested")
	}
	if r := f.m.connections.warmRetries[key]; r.failures != 2 || !r.after.Equal(f.now.Add(2*time.Minute)) {
		t.Fatal("repeated warm failure did not double the backoff", r)
	}
	// The native path fails while the candidate is in warm backoff: the
	// failover sweep still starts it cold, exactly as without a warm reserve.
	f.fail["h"] = false
	f.awg.good["a"] = false
	for i := 0; i < 3; i++ {
		s, _ = f.round(5 * time.Second)
	}
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "h" || f.starts() != "h,h,h" || s.Selection.General != contract.Gecko {
		t.Fatal("warm backoff blocked the failover sweep", s, f.starts())
	}
}

func TestWarmReserveBackoffCapsAndDecays(t *testing.T) {
	m := New(&fakeBackend{}, nil, nil)
	now := time.Unix(1000, 0)
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 15 * time.Minute, 15 * time.Minute}
	for _, delay := range want {
		m.warmBackoff("h", now)
		if r := m.connectionState().warmRetries["h"]; !r.after.Equal(now.Add(delay)) {
			t.Fatal("warm backoff schedule", r.after.Sub(now), delay)
		}
		now = m.connectionState().warmRetries["h"].after
	}
	m.warmBackoff("h", now.Add(16*time.Minute))
	if r := m.connectionState().warmRetries["h"]; r.failures != 1 {
		t.Fatal("isolated failure inherited an old backoff", r)
	}
}

func TestWarmReserveOnlyInAutoMode(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	h := managedConnection(t, "hy2", "h", 20)
	for _, selection := range []connection.Selection{{Mode: "connection", ID: "a"}, {Mode: "transport", Family: "awg"}} {
		f := newWarmFixture(t, a, h)
		f.sel = selection
		var s Snapshot
		for i := 0; i < 4; i++ {
			s, _ = f.round(35 * time.Second)
		}
		if len(f.b.starts) != 0 || s.ReserveConnection != nil || s.ActiveConnection == nil || s.ActiveConnection.ID != "a" {
			t.Fatal("manual mode started a warm reserve", selection, f.starts())
		}
	}
	// An explicit choice away from auto retires the standby with the other
	// resources of the previous intent, and nothing is warmed again.
	f := newWarmFixture(t, a, h)
	if s := f.admit(); s.ReserveConnection == nil {
		t.Fatal("fixture did not admit the standby")
	}
	f.sel, f.gen = connection.Selection{Mode: "connection", ID: "a"}, 2
	var s Snapshot
	for i := 0; i < 3; i++ {
		s, _ = f.round(35 * time.Second)
	}
	if f.b.alive || len(f.b.starts) != 1 || s.ReserveConnection != nil || s.ActiveConnection == nil || s.ActiveConnection.ID != "a" {
		t.Fatal("standby survived or returned after a manual choice", s, f.starts())
	}
}

func TestWarmReserveNeverReplacesRetainedSlot(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	h := managedConnection(t, "hy2", "h", 20)
	h0 := managedConnection(t, "hy2", "h0", 21)
	f := newWarmFixture(t, a, h, h0)
	f.order.Connections["hy2"] = []string{"h", "h0"}
	f.awg.good["a"] = false
	if s, _ := f.round(0); s.ActiveConnection == nil || s.ActiveConnection.ID != "h" {
		t.Fatal("fixture did not fall back to h", s)
	}
	f.awg.good["a"] = true
	var s Snapshot
	for i := 0; i < 14; i++ {
		s, _ = f.round(5 * time.Second)
	}
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "a" || s.ReserveConnection == nil || s.ReserveConnection.ID != "h" || s.ReserveWarm {
		t.Fatal("fixture has no retained reserve", s)
	}
	// A higher-ranked UDP proxy appears in the order: the retained reserve
	// and its sessions stay; the warm step never replaces an existing slot.
	f.order.Connections["hy2"] = []string{"h0", "h"}
	for i := 0; i < 10; i++ {
		s, _ = f.round(35 * time.Second)
	}
	if f.starts() != "h" || f.b.stops != 0 || s.ReserveConnection == nil || s.ReserveConnection.ID != "h" {
		t.Fatal("retained reserve was replaced", f.starts(), f.b.stops)
	}
}

func TestWarmReserveDisableRetiresOnlyWarmSlot(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	h := managedConnection(t, "hy2", "h", 20)
	f := newWarmFixture(t, a, h)
	f.admit()
	f.cleaned, f.events = nil, nil
	f.m.SetWarmReserve(WarmPolicy{})
	s, changed := f.round(5 * time.Second)
	if !changed || f.b.alive || f.b.stops != 1 || s.ReserveConnection != nil || s.ReserveWarm || s.Selection != (contract.Selection{General: contract.AWG, Games: contract.AWG}) {
		t.Fatal("disabling did not retire the sessionless standby alone", s)
	}
	if len(f.cleaned) != 0 {
		t.Fatal("standby retirement cleaned flows it never carried", f.cleaned)
	}
	for _, e := range f.events {
		if (e.Stage == "cleanup" || e.Stage == "stop") && e.Reason != "warm_reserve" {
			t.Fatal("retirement not attributed to the warm reserve", e)
		}
	}
	if f.round(5 * time.Minute); len(f.b.starts) != 1 {
		t.Fatal("disabled warm reserve started again")
	}

	// A reserve retained after failback carries older sessions: disabling the
	// warm reserve must keep it.
	f = newWarmFixture(t, a, h)
	f.awg.good["a"] = false
	f.round(0)
	f.awg.good["a"] = true
	for i := 0; i < 14; i++ {
		s, _ = f.round(5 * time.Second)
	}
	if s.ReserveConnection == nil || s.ReserveWarm {
		t.Fatal("fixture has no retained reserve", s)
	}
	f.m.SetWarmReserve(WarmPolicy{})
	for i := 0; i < 3; i++ {
		s, _ = f.round(5 * time.Second)
	}
	if !f.b.alive || f.b.stops != 0 || s.ReserveConnection == nil || s.ReserveConnection.ID != "h" {
		t.Fatal("disabling the warm reserve retired a retained reserve", s)
	}
}

func TestWarmReserveStaleGenerationRetiresWithoutPublishing(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	h := managedConnection(t, "hy2", "h", 20)
	f := newWarmFixture(t, a, h)
	f.m.StepConnections(context.Background(), f.now, f.r, f.sel, f.order, f.gen)
	f.events = nil
	// A newer user choice arrives while the standby is being measured.
	f.onProbe = func(id string) {
		if id == "h" {
			f.m.RequestGeneration(f.gen + 1)
		}
	}
	s, changed := f.m.StepWarmReserve(context.Background(), f.now, f.r, f.sel, f.order, f.gen)
	f.settle()
	if changed || s.ReserveConnection != nil || s.ReserveWarm {
		t.Fatal("superseded standby was published", changed, s)
	}
	if s.Generation != f.gen || s.Pending || s.Selection.General != contract.AWG || s.ActiveConnection == nil || s.ActiveConnection.ID != "a" {
		t.Fatal("superseded warm step changed the published default", s)
	}
	// The stale generation is never acted on again.
	if _, changed = f.m.StepWarmReserve(context.Background(), f.now.Add(time.Minute), f.r, f.sel, f.order, f.gen); changed || len(f.b.starts) != 1 {
		t.Fatal("stale generation started another standby")
	}
	// Not even a late round of the stale generation adopts it: the newer intent
	// retires its process as an unpublished standby.
	s = f.m.StepConnections(context.Background(), f.now, f.r, f.sel, f.order, f.gen)
	if f.b.alive || f.b.stops == 0 || s.ReserveConnection != nil || s.ReserveWarm || f.m.connections.admission != nil {
		t.Fatal("superseded standby was kept or adopted", s)
	}
	if _, backoff := f.m.connections.warmRetries[connectionKey(h)]; backoff {
		t.Fatal("superseded admission counted as a candidate failure")
	}
	superseded := false
	for _, e := range f.events {
		if e.Stage == "selection" && e.Reason == "warm_reserve" {
			if e.Outcome != "superseded" {
				t.Fatal("superseded standby recorded as a selection", e)
			}
			superseded = true
		}
	}
	if !superseded {
		t.Fatal("superseded admission not recorded", f.events)
	}
}

func TestWarmPolicyBounds(t *testing.T) {
	m := New(&fakeBackend{}, nil, nil)
	for _, interval := range []time.Duration{0, 29 * time.Second, 301 * time.Second} {
		if m.SetWarmReserve(WarmPolicy{Enabled: true, Interval: interval}) == nil || m.warm.Enabled {
			t.Fatal("invalid warm interval accepted", interval)
		}
	}
	for _, p := range []WarmPolicy{{}, {Enabled: true, Interval: MinWarmInterval}, {Enabled: true, Interval: MaxWarmInterval}} {
		if err := m.SetWarmReserve(p); err != nil || m.warm != p {
			t.Fatal("valid warm policy rejected", p, err)
		}
	}
}

// slotBackend is a goroutine-safe proxy backend for admissions that run in the
// background. Its first `blocking` starts spawn the process and then wait for
// release, honouring their context unless ignoreCtx (a step such as a firewall
// restart that cannot be cancelled). Any Start or Stop that overlaps a running
// Start is recorded: the single slot must never be raced.
type slotBackend struct {
	mu        sync.Mutex
	blocking  int
	ignoreCtx bool
	release   chan struct{}
	stopFail  bool
	starts    int
	stops     int
	alive     bool
	inStart   int
	overlap   bool
}

func (b *slotBackend) Start(ctx context.Context, _ profile.Profile) error {
	b.mu.Lock()
	b.overlap = b.overlap || b.inStart > 0
	b.inStart++
	b.starts++
	b.alive = true // spawned; it waits for its TUN next
	block := b.starts <= b.blocking
	b.mu.Unlock()
	defer func() { b.mu.Lock(); b.inStart--; b.mu.Unlock() }()
	if !block {
		return nil
	}
	if b.ignoreCtx {
		<-b.release
		return nil
	}
	select {
	case <-b.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (b *slotBackend) Stop() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.overlap = b.overlap || b.inStart > 0
	b.stops++
	if b.stopFail {
		return errors.New("public test stop failure")
	}
	b.alive = false
	return nil
}
func (b *slotBackend) Alive() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.alive }
func (b *slotBackend) counts() (starts, stops int, alive, overlap bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.starts, b.stops, b.alive, b.overlap
}
func (b *slotBackend) setStopFail(fail bool) { b.mu.Lock(); b.stopFail = fail; b.mu.Unlock() }
func (b *slotBackend) waitStarted(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if starts, _, _, _ := b.counts(); starts >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("standby start never began")
		}
		time.Sleep(time.Millisecond)
	}
}

// countingAWG counts native probes. They run on the round's goroutines only.
type countingAWG struct {
	*fakeAWG
	probes int
}

func (a *countingAWG) Probe(ctx context.Context) health.Result {
	a.probes++
	return a.fakeAWG.Probe(ctx)
}

// A5: a standby that never carried flows is retired without conntrack
// cleanup, and a Stop that keeps failing quarantines it instead of returning
// every round early. Native probes, the spare AWG and finally the proxy (once
// its Stop succeeds) all still run.
func TestWarmStandbyFailedCleanupNeverBlocksAWGFailover(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	a2 := managedConnection(t, "awg", "a2", 11)
	h := managedConnection(t, "hy2", "h", 20)
	b := &slotBackend{stopFail: true}
	f := newWarmFixtureOn(t, b, a, a2, h)
	f.order.Connections["awg"] = []string{"a", "a2"}
	f.awg.good["a2"] = true
	awg := &countingAWG{fakeAWG: f.awg}
	f.m.SetAWGBackend(awg)
	// The slot's conntrack cleanup fails as well; native cleanup works.
	f.m.SetChannelCleanup(func(ch contract.Channel, _ string) error {
		f.cleaned = append(f.cleaned, ch)
		if ch == contract.Gecko {
			return errors.New("public test slot cleanup failure")
		}
		return nil
	})
	f.fail["h"] = true
	f.round(0)
	s, _ := f.round(5 * time.Second)
	if !f.m.connections.quarantine || f.m.slotCleanupPending || f.m.cleanupPending || s.Pending || s.ReserveConnection != nil {
		t.Fatal("failed standby stop not quarantined apart from flow cleanup", s)
	}
	gecko := func() bool {
		for _, ch := range f.cleaned {
			if ch == contract.Gecko {
				return true
			}
		}
		return false
	}
	if gecko() {
		t.Fatal("unpublished standby ran slot conntrack cleanup")
	}
	for i := 0; i < 3; i++ {
		before := awg.probes
		s, _ = f.round(5 * time.Second)
		if awg.probes != before+1 || s.Pending || s.ActiveConnection == nil || s.ActiveConnection.ID != "a" || s.Selection.General != contract.AWG {
			t.Fatal("quarantined standby held up native monitoring", awg.probes-before, s)
		}
	}
	if starts, _, _, _ := b.counts(); starts != 1 {
		t.Fatal("standby restarted while its process was quarantined", starts)
	}
	// The primary dies: the spare AWG is tried and selected.
	f.awg.good["a"] = false
	for i := 0; i < 8 && (s.ActiveConnection == nil || s.ActiveConnection.ID != "a2"); i++ {
		before := awg.probes
		s, _ = f.round(5 * time.Second)
		if awg.probes <= before {
			t.Fatal("native AWG not probed during failover")
		}
	}
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "a2" || s.Selection.General != contract.AWG {
		t.Fatal("quarantined standby blocked failover to the spare AWG", s)
	}
	// Both AWG down: the proxy cannot reuse the quarantined slot...
	f.awg.good["a2"] = false
	f.fail["h"] = false
	for i := 0; i < 8 && s.Selection.General != contract.Down; i++ {
		s, _ = f.round(5 * time.Second)
	}
	if starts, _, _, _ := b.counts(); s.Selection.General != contract.Down || starts != 1 {
		t.Fatal("proxy started in a quarantined slot", s, starts)
	}
	// ...until its Stop succeeds; then it is started cold in the same round.
	b.setStopFail(false)
	s, _ = f.round(5 * time.Second)
	starts, _, alive, overlap := b.counts()
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "h" || s.Selection.General != contract.Gecko || starts != 2 || !alive || overlap || f.m.connections.quarantine {
		t.Fatal("released quarantine did not let the proxy start", s, starts, overlap)
	}
	if gecko() {
		t.Fatal("unpublished standby ran slot conntrack cleanup")
	}
}

// A6: a standby start that hangs (here in a step that ignores cancellation)
// runs outside the round; native AWG is probed every round meanwhile, and the
// standby is adopted once it qualifies for the unchanged intent.
func TestWarmAdmissionInFlightKeepsNativeCadence(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	h := managedConnection(t, "hy2", "h", 20)
	b := &slotBackend{blocking: 1, ignoreCtx: true, release: make(chan struct{})}
	f := newWarmFixtureOn(t, b, a, h)
	f.async = true
	f.m.StepTimeout = time.Minute // the test, not the start budget, ends the start
	awg := &countingAWG{fakeAWG: f.awg}
	f.m.SetAWGBackend(awg)
	f.round(0)
	b.waitStarted(t, 1)
	for i := 0; i < 5; i++ {
		before := awg.probes
		begin := time.Now()
		s, _ := f.round(health.Interval)
		if elapsed := time.Since(begin); elapsed > time.Second {
			t.Fatal("round waited for the standby admission", elapsed)
		}
		if awg.probes != before+1 || s.Pending || s.Selection.General != contract.AWG || s.ReserveConnection != nil {
			t.Fatal("native AWG not probed every round while the standby starts", awg.probes-before, s)
		}
	}
	if starts, stops, _, _ := b.counts(); f.admission() == nil || starts != 1 || stops != 0 {
		t.Fatal("admission not left running in the background", starts, stops)
	}
	close(b.release)
	f.settle()
	s, _ := f.round(health.Interval)
	if _, _, alive, overlap := b.counts(); s.ReserveConnection == nil || s.ReserveConnection.ID != "h" || !s.ReserveWarm || !alive || overlap {
		t.Fatal("qualified standby not adopted for the unchanged intent", s)
	}
}

// A6: failover, a new choice, disabling and shutdown each cancel an admission
// in flight; nothing races it for the slot and no process outlives it.
func TestWarmAdmissionInFlightIsCancelledWithoutLeak(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	h := managedConnection(t, "hy2", "h", 20)
	launch := func(t *testing.T, ignoreCtx bool) (*warmFixture, *slotBackend) {
		t.Helper()
		b := &slotBackend{blocking: 1, ignoreCtx: ignoreCtx, release: make(chan struct{})}
		f := newWarmFixtureOn(t, b, a, h)
		f.async = true
		f.m.StepTimeout = time.Minute
		f.round(0)
		b.waitStarted(t, 1)
		return f, b
	}
	// A cancelled admission is never adopted and is not the candidate's failure.
	notAdopted := func(t *testing.T, f *warmFixture) {
		t.Helper()
		for _, e := range f.events {
			if e.Reason == "warm_reserve" && e.Stage == "selection" && e.Outcome != "superseded" {
				t.Fatal("cancelled admission recorded as", e.Outcome)
			}
		}
		if _, backoff := f.m.connections.warmRetries[connectionKey(h)]; backoff {
			t.Fatal("cancelled admission counted as a candidate failure")
		}
	}
	// The failover sweep starts another proxy first (a TCP-only one ranked
	// before HY2; the standby is the first UDP proxy): the standby start is
	// cancelled and nothing races it for the slot. (A standby start for the
	// first proxy the sweep would start is kept instead; see
	// TestFailoverKeepsAdmissionOfFirstProxyCandidate.)
	t.Run("failover-other-candidate", func(t *testing.T) {
		tcp := tcpOnlyConnection(t, "t")
		b := &slotBackend{blocking: 1, release: make(chan struct{})}
		f := newWarmFixtureOn(t, b, a, tcp, h)
		families := []string{"awg", tcp.Family}
		for _, family := range connection.Families {
			if family != "awg" && family != tcp.Family {
				families = append(families, family)
			}
		}
		f.order.Families = families
		f.async = true
		f.m.StepTimeout = time.Minute
		f.round(0)
		b.waitStarted(t, 1)
		if adm := f.admission(); adm == nil || adm.item.ID != "h" {
			t.Fatal("standby start is not for the first UDP proxy")
		}
		f.awg.good["a"] = false
		var s Snapshot
		for i := 0; i < 8 && (s.ActiveConnection == nil || s.ActiveConnection.ID != "t"); i++ {
			begin := time.Now()
			s, _ = f.round(5 * time.Second)
			if elapsed := time.Since(begin); elapsed > 2*time.Second {
				t.Fatal("failover round not bounded", elapsed)
			}
		}
		starts, stops, alive, overlap := b.counts()
		if s.ActiveConnection == nil || s.ActiveConnection.ID != "t" || s.Selection.General != contract.Gecko {
			t.Fatal("failover did not reach the first proxy", s)
		}
		if starts != 2 || stops != 1 || !alive || overlap || f.admission() != nil {
			t.Fatal("cancelled standby leaked or raced the cold start", starts, stops, overlap)
		}
		if _, cooled := f.m.retries[connectionKey(h)]; cooled {
			t.Fatal("cancelled standby fed the failover cool-down")
		}
		notAdopted(t, f)
	})
	t.Run("reselect", func(t *testing.T) {
		f, b := launch(t, false)
		f.sel, f.gen = connection.Selection{Mode: "connection", ID: "a"}, 2
		s, _ := f.round(5 * time.Second)
		if _, _, alive, overlap := b.counts(); alive || overlap || f.admission() != nil || s.Pending || s.ActiveConnection == nil || s.ActiveConnection.ID != "a" || s.ReserveConnection != nil {
			t.Fatal("new choice did not retire the standby start", s)
		}
		notAdopted(t, f)
	})
	// A new choice waits (finitely) for a start that cannot be cancelled, as
	// the synchronous admission did, and then retires it.
	t.Run("reselect-uncancellable", func(t *testing.T) {
		f, b := launch(t, true)
		f.sel, f.gen = connection.Selection{Mode: "connection", ID: "a"}, 2
		go func() { time.Sleep(50 * time.Millisecond); close(b.release) }()
		s, _ := f.round(5 * time.Second)
		if _, _, alive, overlap := b.counts(); alive || overlap || f.admission() != nil || s.Pending || s.ActiveConnection == nil || s.ActiveConnection.ID != "a" {
			t.Fatal("new choice did not retire the uncancellable start", s)
		}
		notAdopted(t, f)
	})
	t.Run("manual-test-uncancellable", func(t *testing.T) {
		f, b := launch(t, true)
		go func() { time.Sleep(50 * time.Millisecond); close(b.release) }()
		if err := f.m.RetireGeneration(f.gen); err != nil {
			t.Fatal(err)
		}
		if _, _, alive, overlap := b.counts(); alive || overlap || f.admission() != nil {
			t.Fatal("manual test retirement left the standby start running")
		}
	})
	// Past its bound the teardown is retried by the next round; the running
	// start is never stopped under it.
	t.Run("reselect-teardown-bound", func(t *testing.T) {
		f, b := launch(t, true)
		f.m.teardownWait = 20 * time.Millisecond
		f.sel, f.gen = connection.Selection{Mode: "connection", ID: "a"}, 2
		begin := time.Now()
		s, _ := f.round(5 * time.Second)
		if elapsed := time.Since(begin); elapsed > time.Second {
			t.Fatal("new choice waited beyond the admission bound", elapsed)
		}
		if _, stops, _, overlap := b.counts(); stops != 0 || overlap || f.admission() == nil || s.Selection.General != contract.Down || s.LastError == "" {
			t.Fatal("running start was stopped under it or forgotten", s)
		}
		// Reported as pending, so the controller publishes nothing from it,
		// and retried by the next round.
		if !s.Pending || !f.m.cleanupPending {
			t.Fatal("bounded teardown not reported as pending", s)
		}
		close(b.release)
		f.settle()
		s, _ = f.round(5 * time.Second)
		if _, _, alive, overlap := b.counts(); alive || overlap || f.admission() != nil || s.Pending || s.ActiveConnection == nil || s.ActiveConnection.ID != "a" {
			t.Fatal("finished start was not retired for the new choice", s)
		}
		notAdopted(t, f)
	})
	t.Run("disable", func(t *testing.T) {
		f, b := launch(t, false)
		f.m.SetWarmReserve(WarmPolicy{})
		f.round(5 * time.Second)
		f.settle()
		s, _ := f.round(5 * time.Second)
		if starts, _, alive, overlap := b.counts(); alive || overlap || starts != 1 || f.admission() != nil || s.ReserveConnection != nil || s.Selection.General != contract.AWG {
			t.Fatal("disabling did not retire the standby start", s)
		}
		for i := 0; i < 3; i++ {
			f.round(time.Minute)
		}
		if starts, _, _, _ := b.counts(); starts != 1 {
			t.Fatal("disabled warm reserve started again")
		}
		notAdopted(t, f)
	})
	t.Run("shutdown", func(t *testing.T) {
		f, b := launch(t, false)
		if err := f.m.Shutdown(); err != nil {
			t.Fatal(err)
		}
		if _, _, alive, overlap := b.counts(); alive || overlap || f.admission() != nil {
			t.Fatal("shutdown left the standby start running")
		}
	})
	t.Run("shutdown-uncancellable", func(t *testing.T) {
		f, b := launch(t, true)
		go func() { time.Sleep(50 * time.Millisecond); close(b.release) }()
		if err := f.m.Shutdown(); err != nil {
			t.Fatal(err)
		}
		if _, _, alive, overlap := b.counts(); alive || overlap || f.admission() != nil {
			t.Fatal("shutdown did not wait for the start to stop its process")
		}
	})
}

// A8: a reserve retained after failback still carries older sessions, so it
// is measured every round, not at the slow standby pace.
func TestRetainedReserveIsProbedEveryRound(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	h := managedConnection(t, "hy2", "h", 20)
	f := newWarmFixture(t, a, h)
	f.awg.good["a"] = false
	if s, _ := f.round(0); s.ActiveConnection == nil || s.ActiveConnection.ID != "h" {
		t.Fatal("fixture did not fall back to h", s)
	}
	f.awg.good["a"] = true
	var s Snapshot
	for i := 0; i < 30; i++ {
		s, _ = f.round(5 * time.Second)
	}
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "a" || s.ReserveConnection == nil || s.ReserveConnection.ID != "h" || s.ReserveWarm {
		t.Fatal("fixture has no retained reserve", s)
	}
	before := f.probes["h"]
	for i := 1; i <= 6; i++ {
		s, _ = f.round(5 * time.Second)
		if f.probes["h"] != before+i || !s.Slot.LastCheck.Equal(f.now) {
			t.Fatal("retained reserve skipped a measurement", f.probes["h"]-before, i)
		}
	}
}

// slowProbe is a goroutine-safe probe: its first `hold` calls for the
// connection named `slow` wait for release (or their context), its first
// `fail` calls for it fail, and every other call succeeds.
type slowProbe struct {
	mu      sync.Mutex
	names   map[string]string
	slow    string
	hold    int
	fail    int
	calls   int
	release chan struct{}
}

func (p *slowProbe) probe(ctx context.Context, profile profile.Profile) health.Result {
	p.mu.Lock()
	id := p.names[profile.ID]
	call := 0
	if id == p.slow {
		p.calls++
		call = p.calls
	}
	hold, fail := call > 0 && call <= p.hold, call > 0 && call <= p.fail
	p.mu.Unlock()
	if hold {
		select {
		case <-p.release:
		case <-ctx.Done():
			return health.Result{}
		}
	}
	if fail {
		return health.Result{Measured: true}
	}
	return health.Result{Measured: true, TCP: true, UDP: true}
}

func (p *slowProbe) count() int { p.mu.Lock(); defer p.mu.Unlock(); return p.calls }

// Finding 3: native AWG fails while the standby start of the first proxy the
// failover sweep would start is still in flight and slower than the
// cancellation wait (AdmissionWait). The failover keeps it (no cancellation,
// no second Start of the same connection), waits for it within the round's
// step budget and adopts it; Start and Stop never overlap.
func TestFailoverKeepsAdmissionOfFirstProxyCandidate(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	h := managedConnection(t, "hy2", "h", 20)
	h2 := managedConnection(t, "hy2", "h2", 21)
	// failing runs the two rounds in which the native path still counts as up
	// (three consecutive failures take it down) and checks each has a path.
	failing := func(t *testing.T, f *warmFixture) {
		t.Helper()
		f.awg.good["a"] = false
		for i := 0; i < 2; i++ {
			s, _ := f.round(5 * time.Second)
			if s.ActiveConnection == nil || s.ActiveConnection.ID != "a" || s.Selection.General != contract.AWG || s.Pending {
				t.Fatal("native path left before its third failure", i, s)
			}
		}
		if adm := f.admission(); adm == nil || adm.item.ID != "h" {
			t.Fatal("standby start not in flight at failover")
		}
	}
	adopted := func(t *testing.T, f *warmFixture, s Snapshot) {
		t.Helper()
		if s.ActiveConnection == nil || s.ActiveConnection.ID != "h" || s.Selection != (contract.Selection{General: contract.Gecko, Games: contract.Gecko}) || s.Pending || f.admission() != nil {
			t.Fatal("kept standby not adopted as the default", s)
		}
		if _, cooled := f.m.retries[connectionKey(h)]; cooled {
			t.Fatal("kept standby fed the failover cool-down")
		}
		applied, fallback := false, false
		for _, e := range f.events {
			applied = applied || (e.Reason == "warm_reserve" && e.Stage == "selection" && e.Outcome == "applied" && e.To.ID == "h")
			fallback = fallback || (e.Reason == "fallback" && e.To.ID == "h")
			if e.Reason == "warm_reserve" && e.Stage == "selection" && e.Outcome == "superseded" {
				t.Fatal("kept standby recorded as superseded")
			}
		}
		if !applied || !fallback {
			t.Fatal("adoption or fallback decision missing", f.events)
		}
	}

	// The start hangs in a step that ignores cancellation (as MigrateSlot's
	// firewall restart does) and ends 1.5 s into the failover round.
	t.Run("adopted-in-failover-round", func(t *testing.T) {
		b := &slotBackend{blocking: 1, ignoreCtx: true, release: make(chan struct{})}
		f := newWarmFixtureOn(t, b, a, h)
		f.async = true
		if f.m.AdmissionWait != time.Second || f.m.StepTimeout != health.RoundDeadline {
			t.Fatal("fixture does not use the production bounds")
		}
		f.round(0)
		b.waitStarted(t, 1)
		failing(t, f)
		go func() { time.Sleep(1500 * time.Millisecond); close(b.release) }()
		begin := time.Now()
		s, _ := f.round(5 * time.Second)
		elapsed := time.Since(begin)
		if elapsed <= f.m.AdmissionWait || elapsed >= f.m.StepTimeout {
			t.Fatal("failover did not wait for the standby within the round budget", elapsed)
		}
		adopted(t, f, s)
		if starts, stops, alive, overlap := b.counts(); starts != 1 || stops != 0 || !alive || overlap {
			t.Fatal("same connection started twice, stopped or raced", starts, stops, overlap)
		}
	})

	// The start finished but its probe is still running when the failover
	// round's budget ends: that round has no path, the standby is neither
	// cancelled nor replaced by the next proxy in a further round, and the
	// first round after it qualified adopts it without a second Start.
	t.Run("pending-past-round-budget", func(t *testing.T) {
		b := &slotBackend{}
		f := newWarmFixtureOn(t, b, a, h, h2)
		f.order.Connections["hy2"] = []string{"h", "h2"}
		probe := &slowProbe{names: f.names, slow: "h", hold: 1, release: make(chan struct{})}
		f.m.probe = probe.probe
		f.async = true
		f.m.StepTimeout = 300 * time.Millisecond
		f.m.ProbeTimeout = time.Minute
		f.round(0)
		b.waitStarted(t, 1)
		failing(t, f)
		for i := 0; i < 2; i++ {
			begin := time.Now()
			s, _ := f.round(5 * time.Second)
			if elapsed := time.Since(begin); elapsed < f.m.StepTimeout || elapsed > f.m.StepTimeout+time.Second {
				t.Fatal("failover round not bounded by its step budget", elapsed)
			}
			adm := f.admission()
			if adm == nil || adm.cancelled || adm.abandoned || s.Selection.General != contract.Down || s.Pending {
				t.Fatal("pending standby cancelled, or a path invented", i, s)
			}
			if starts, stops, _, overlap := b.counts(); starts != 1 || stops != 0 || overlap {
				t.Fatal("slot used while the standby start ran", starts, stops, overlap)
			}
		}
		close(probe.release)
		f.settle()
		s, _ := f.round(5 * time.Second)
		adopted(t, f, s)
		// Probes: the admission's own, then this round's slot measurement.
		if starts, stops, alive, overlap := b.counts(); starts != 1 || stops != 0 || !alive || overlap || probe.count() != 2 {
			t.Fatal("qualified standby not reused as is", starts, stops, alive, overlap, probe.count())
		}
	})

	// The kept standby fails its probe: it is stopped as a sessionless standby
	// (warm backoff only), and the same candidate is started cold within the
	// remaining budget of the same round, strictly after that Stop.
	t.Run("failed-standby-then-cold-start", func(t *testing.T) {
		b := &slotBackend{blocking: 1, ignoreCtx: true, release: make(chan struct{})}
		f := newWarmFixtureOn(t, b, a, h)
		probe := &slowProbe{names: f.names, slow: "h", fail: 1}
		f.m.probe = probe.probe
		f.async = true
		f.round(0)
		b.waitStarted(t, 1)
		failing(t, f)
		go func() { time.Sleep(200 * time.Millisecond); close(b.release) }()
		s, _ := f.round(5 * time.Second)
		if s.ActiveConnection == nil || s.ActiveConnection.ID != "h" || s.Selection.General != contract.Gecko || f.admission() != nil {
			t.Fatal("failover did not reach the proxy in the same round", s)
		}
		if starts, stops, alive, overlap := b.counts(); starts != 2 || stops != 1 || !alive || overlap || probe.count() != 2 {
			t.Fatal("failed standby not stopped before the cold start", starts, stops, overlap)
		}
		if f.m.connections.warmRetries[connectionKey(h)].failures != 1 {
			t.Fatal("failed standby not backed off as a warm attempt")
		}
	})
}

// Finding 4: a reserve restored after a manual test is a warm standby only
// while the warm policy is on; otherwise it stays an ordinary reserve that the
// warm step does not retire (no pointless start, probe and stop).
func TestRestoredReserveWarmOnlyWithWarmPolicy(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	h := managedConnection(t, "hy2", "h", 20)
	for _, warm := range []bool{false, true} {
		f := newWarmFixture(t, a, h)
		f.m.SetWarmReserve(WarmPolicy{})
		if s, _ := f.round(0); s.ActiveConnection == nil || s.ActiveConnection.ID != "a" || len(f.b.starts) != 0 {
			t.Fatal("fixture did not settle on native AWG alone", s)
		}
		if warm {
			f.m.SetWarmReserve(WarmPolicy{Enabled: true, Interval: 30 * time.Second})
		}
		if err := f.m.RestoreReserve(context.Background(), f.now, f.r, f.sel, f.order, h.ID, h.Revision, f.gen); err != nil {
			t.Fatal(err)
		}
		s := f.m.Snapshot()
		if s.ReserveConnection == nil || s.ReserveConnection.ID != "h" || s.ReserveWarm != warm || f.m.connections.warm != warm {
			t.Fatal("restored reserve warm flag does not follow the policy", warm, s)
		}
		for i := 0; i < 3; i++ {
			s, _ = f.round(5 * time.Second)
		}
		if f.b.stops != 0 || !f.b.alive || len(f.b.starts) != 1 || s.ReserveConnection == nil || s.ReserveConnection.ID != "h" || s.Selection.General != contract.AWG {
			t.Fatal("restored reserve retired or restarted by the warm step", warm, f.b.stops, f.starts(), s)
		}
	}
}

// Finding 5: the teardown wait for a standby start is short.
func TestTeardownAdmissionWaitBounded(t *testing.T) {
	if m := New(&fakeBackend{}, nil, nil); m.teardownWait > 10*time.Second || m.teardownWait < m.AdmissionWait {
		t.Fatal("teardown wait", m.teardownWait)
	}
}
