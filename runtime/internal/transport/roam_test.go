package transport

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
)

// roamAWG is a fake native AWG whose traffic depends on the live endpoint
// port: blocked ports stall, as a per-port or per-flow filter would. It keeps
// the live listen (source) port the way the kernel device does.
type roamAWG struct {
	*fakeAWG
	port      uint16
	listen    uint16
	sets      []roamUpdate
	attempts  int
	setErr    error
	bindFail  map[uint16]bool
	listenErr error
	handshake time.Time
	hsErr     error
	blocked   map[uint16]bool
}
type roamUpdate struct {
	listen   uint16
	endpoint netip.AddrPort
}

// kernelListen is the port the fake kernel picks when the interface is
// (re)created from the stored configuration, which sets no listen port.
const kernelListen = 51871

func (a *roamAWG) Switch(ctx context.Context, c connection.Connection) error {
	a.port, a.listen = 0, kernelListen
	return a.fakeAWG.Switch(ctx, c)
}
func (a *roamAWG) Probe(ctx context.Context) health.Result {
	port := a.port
	if port == 0 {
		port = 51820
	}
	if a.blocked[port] {
		return health.Result{Measured: true}
	}
	return a.fakeAWG.Probe(ctx)
}
func (a *roamAWG) SetPorts(_ context.Context, _ connection.Connection, listen uint16, endpoint netip.AddrPort) error {
	a.attempts++
	if a.setErr != nil {
		return a.setErr
	}
	if a.bindFail[listen] {
		return errors.New("public test: address in use")
	}
	a.sets = append(a.sets, roamUpdate{listen, endpoint})
	a.port, a.listen = endpoint.Port(), listen
	if a.port == 51820 {
		a.port = 0
	}
	return nil
}
func (a *roamAWG) ListenPort(context.Context) (uint16, error) { return a.listen, a.listenErr }
func (a *roamAWG) LatestHandshake(context.Context, connection.Connection) (time.Time, error) {
	return a.handshake, a.hsErr
}

// roamFixture: one roaming AWG connection (stored endpoint 192.0.2.10:51820,
// range 40000-40009, default interval), settled as the default. The random
// source picks the middle: no jitter, and the middle port of the choices.
func roamFixture(t *testing.T, ports string, extra ...connection.Connection) (*warmFixture, *roamAWG) {
	t.Helper()
	a := managedConnection(t, "awg", "a", 10)
	if ports != "" {
		if err := a.SetRoam(ports, 0); err != nil {
			t.Fatal(err)
		}
	}
	f := newWarmFixture(t, append([]connection.Connection{a}, extra...)...)
	awg := &roamAWG{fakeAWG: f.awg, blocked: map[uint16]bool{}, bindFail: map[uint16]bool{}}
	f.m.SetAWGBackend(awg)
	f.m.roamRandom = func(n int64) int64 { return n / 2 }
	f.round(0)
	s, _ := f.round(5 * time.Second)
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "a" || s.Selection.General != contract.AWG {
		t.Fatal("fixture did not settle on AWG", s)
	}
	awg.handshake = f.now.Add(-30 * time.Second)
	return f, awg
}

func roamDecisions(f *warmFixture) (applied, failed int) {
	for _, e := range f.events {
		if e.Reason == "roam" && e.Stage == "native" && e.Channel == contract.AWG {
			if e.Outcome == "applied" {
				applied++
			} else {
				failed++
			}
		}
	}
	return
}

func TestAWGRoamOffByDefault(t *testing.T) {
	f, awg := roamFixture(t, "")
	for i := 0; i < 30; i++ {
		s, _ := f.round(10 * time.Minute)
		if s.Roam != nil {
			t.Fatal("roam state published for a connection without roam_ports", s.Roam)
		}
	}
	if len(awg.sets) != 0 {
		t.Fatal("endpoint moved without roam_ports", awg.sets)
	}
}

func TestAWGRoamScheduledRotationKeepsTunnelAndSessions(t *testing.T) {
	f, awg := roamFixture(t, "40000-40009")
	f.cleaned, f.events = nil, nil
	switches := len(awg.switches)
	s := f.m.Snapshot()
	if s.Roam == nil || s.Roam.ConnectionID != "a" || s.Roam.Ports != "40000-40009" || s.Roam.IntervalSeconds != 600 || s.Roam.Port != 51820 || s.Roam.Roamed || s.Roam.NextRotation.IsZero() {
		t.Fatal("roam state not published after settling", s.Roam)
	}
	next := s.Roam.NextRotation
	if next.Sub(f.now) < 7*time.Minute || next.Sub(f.now) > 13*time.Minute {
		t.Fatal("first rotation outside the jittered interval", next.Sub(f.now))
	}
	// Not due yet.
	s, _ = f.round(5 * time.Second)
	if len(awg.sets) != 0 {
		t.Fatal("rotated before the schedule", awg.sets)
	}
	f.now = next.Add(-5 * time.Second)
	s, _ = f.round(5 * time.Second)
	if len(awg.sets) != 1 || awg.sets[0].endpoint != netip.MustParseAddrPort("192.0.2.10:40005") {
		t.Fatal("scheduled rotation did not move to a port of the range", awg.sets)
	}
	if s.Roam == nil || s.Roam.Port != 40005 || !s.Roam.Roamed || s.Roam.Rotations != 1 || s.Roam.LastReason != "schedule" || !s.Roam.LastRotation.Equal(f.now) || !s.Roam.NextRotation.After(f.now) {
		t.Fatal("rotation not reflected in the snapshot", s.Roam)
	}
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "a" || s.Selection != (contract.Selection{General: contract.AWG, Games: contract.AWG}) || s.Pending {
		t.Fatal("rotation changed the default", s)
	}
	if len(awg.switches) != switches || len(f.cleaned) != 0 {
		t.Fatal("rotation reconfigured the interface or retired flows", awg.switches, f.cleaned)
	}
	if applied, failed := roamDecisions(f); applied != 1 || failed != 0 {
		t.Fatal("roam decision not recorded", f.events)
	}
	// The next rotation never reuses the current port.
	f.now = s.Roam.NextRotation
	s, _ = f.round(0)
	if len(awg.sets) != 2 || awg.sets[1].endpoint.Port() == 40005 || awg.sets[1].endpoint.Port() < 40000 || awg.sets[1].endpoint.Port() > 40009 {
		t.Fatal("second rotation reused the current port or left the range", awg.sets)
	}
}

func TestAWGRoamPickNeverCurrentAndJitterBounds(t *testing.T) {
	m := New(&fakeBackend{}, nil, nil)
	r := connection.Roam{Start: 40000, End: 40002, Interval: 10 * time.Minute}
	for _, current := range []uint16{40000, 40001, 40002, 51820} {
		seen := map[uint16]bool{}
		for i := int64(0); i < 3; i++ {
			m.roamRandom = func(n int64) int64 { return min(i, n-1) }
			port, ok := m.roamPick(r, current)
			if !ok || port == current || !r.Contains(port) {
				t.Fatal("bad port pick", current, port, ok)
			}
			seen[port] = true
		}
		if want := 2; current == 51820 {
			if len(seen) != 3 {
				t.Fatal("out-of-range current cannot reach every port", seen)
			}
		} else if len(seen) != want {
			t.Fatal("pick does not cover the other ports", current, seen)
		}
	}
	if _, ok := m.roamPick(connection.Roam{Start: 40000, End: 40000}, 40000); ok {
		t.Fatal("single-port range rotated onto itself")
	}
	m.roamRandom = nil
	for i := 0; i < 1000; i++ {
		d := m.roamJitter(10 * time.Minute)
		if d < 7*time.Minute || d > 13*time.Minute {
			t.Fatal("jitter outside ±30 %", d)
		}
	}
}

// A stall (failing sample, recent handshake) rotates once, before the
// health policy reaches its failover threshold; the new port works and the
// tunnel stays the default without any failover.
func TestAWGRoamStallRotatesBeforeFailover(t *testing.T) {
	h := managedConnection(t, "hy2", "h", 20)
	f, awg := roamFixture(t, "40000-40009", h)
	f.events = nil
	starts := len(f.b.starts)
	awg.blocked[51820] = true
	s, _ := f.round(5 * time.Second)
	if len(awg.sets) != 0 || s.AWG.Failures != 1 || s.ActiveConnection.ID != "a" {
		t.Fatal("stall not observed first", s.AWG.Failures, awg.sets)
	}
	awg.handshake = f.now.Add(-20 * time.Second)
	s, _ = f.round(5 * time.Second)
	if len(awg.sets) != 1 || awg.sets[0].endpoint.Port() != 40005 {
		t.Fatal("stall did not rotate before the next probe", awg.sets)
	}
	if s.AWG.Failures != 0 || !s.AWG.Healthy() || s.ActiveConnection == nil || s.ActiveConnection.ID != "a" || s.Selection.General != contract.AWG || s.Roam.LastReason != "stall" {
		t.Fatal("rotated port not measured clean in the same round", s.AWG, s.Roam)
	}
	for _, e := range f.events {
		if e.Reason == "fallback" {
			t.Fatal("stall rotation still failed over", f.events)
		}
	}
	if len(f.b.starts) != starts {
		t.Fatal("stall rotation touched the proxy slot")
	}
}

// If the rotated port stalls too, there is exactly one stall rotation and the
// health policy's normal failover proceeds.
func TestAWGRoamStallThenNormalFailover(t *testing.T) {
	h := managedConnection(t, "hy2", "h", 20)
	f, awg := roamFixture(t, "40000-40009", h)
	for p := uint16(40000); p <= 40009; p++ {
		awg.blocked[p] = true
	}
	awg.blocked[51820] = true
	var s Snapshot
	for i := 0; i < 4 && (s.ActiveConnection == nil || s.ActiveConnection.ID == "a"); i++ {
		awg.handshake = f.now
		s, _ = f.round(5 * time.Second)
	}
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "h" || s.Selection.General != contract.Gecko {
		t.Fatal("failover did not proceed after a failed rotation", s)
	}
	if len(awg.sets) != 1 {
		t.Fatal("more than one stall rotation per failure episode", awg.sets)
	}
	// While the reserve is the default, the AWG endpoint is not rotated.
	for i := 0; i < 20; i++ {
		s, _ = f.round(time.Minute)
	}
	if len(awg.sets) != 1 || (s.Roam != nil && !s.Roam.NextRotation.IsZero()) {
		t.Fatal("rotated while AWG was not the default", awg.sets, s.Roam)
	}
}

func TestAWGRoamStallNeedsRecentHandshake(t *testing.T) {
	f, awg := roamFixture(t, "40000-40009")
	awg.blocked[51820] = true
	awg.handshake = f.now.Add(-10 * time.Minute)
	for i := 0; i < 3; i++ {
		f.round(5 * time.Second)
	}
	if len(awg.sets) != 0 {
		t.Fatal("rotated on a stale handshake", awg.sets)
	}
	// Unknown handshake age: the failing probe is the evidence.
	g, awg2 := roamFixture(t, "40000-40009")
	awg2.blocked[51820] = true
	awg2.hsErr = errors.New("public test: no awg tool")
	g.round(5 * time.Second)
	g.round(5 * time.Second)
	if len(awg2.sets) != 1 {
		t.Fatal("unknown handshake age blocked the stall rotation", awg2.sets)
	}
}

func TestAWGRoamSuspendedDuringManualTest(t *testing.T) {
	f, awg := roamFixture(t, "40000-40009")
	f.m.SetRoamSuspended(true)
	for i := 0; i < 5; i++ {
		s, _ := f.round(15 * time.Minute)
		if s.Roam == nil || !s.Roam.Suspended || !s.Roam.NextRotation.IsZero() {
			t.Fatal("suspension not reported", s.Roam)
		}
	}
	awg.blocked[51820] = true
	awg.handshake = f.now
	f.round(5 * time.Second)
	f.round(5 * time.Second)
	if len(awg.sets) != 0 {
		t.Fatal("rotated during a manual test", awg.sets)
	}
	awg.blocked[51820] = false
	f.round(5 * time.Second)
	f.m.SetRoamSuspended(false)
	s, _ := f.round(5 * time.Second)
	if len(awg.sets) != 0 || s.Roam.Suspended || !s.Roam.NextRotation.After(f.now.Add(6*time.Minute)) {
		t.Fatal("resume rotated at once instead of re-arming the schedule", awg.sets, s.Roam)
	}
}

func TestAWGRoamNotDuringNewIntent(t *testing.T) {
	f, awg := roamFixture(t, "40000-40009")
	f.now = f.now.Add(time.Hour)
	f.gen = 2
	s, _ := f.round(0)
	if len(awg.sets) != 0 {
		t.Fatal("rotated in the round of a new selection", awg.sets)
	}
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "a" {
		t.Fatal("new intent not settled", s)
	}
}

func TestAWGRoamDisableRestoresStoredPortAndRangeChangeMoves(t *testing.T) {
	f, awg := roamFixture(t, "40000-40009")
	f.round(time.Hour)
	if len(awg.sets) != 1 || awg.sets[0].endpoint.Port() != 40005 {
		t.Fatal("fixture did not rotate", awg.sets)
	}
	// A new range moves a roamed port into it at once.
	if err := f.r.Connections[0].SetRoam("41000-41009", 120); err != nil {
		t.Fatal(err)
	}
	s, _ := f.round(5 * time.Second)
	if len(awg.sets) != 2 || awg.sets[1].endpoint.Port() != 41005 || s.Roam.LastReason != "range" || s.Roam.IntervalSeconds != 120 {
		t.Fatal("range change did not move the endpoint", awg.sets, s.Roam)
	}
	// Turning roaming off returns to the stored endpoint.
	if err := f.r.Connections[0].SetRoam("", 0); err != nil {
		t.Fatal(err)
	}
	s, _ = f.round(5 * time.Second)
	if len(awg.sets) != 3 || awg.sets[2].endpoint != netip.MustParseAddrPort("192.0.2.10:51820") || awg.sets[2].listen != kernelListen || s.Roam != nil {
		t.Fatal("disabling roam did not restore the stored endpoint", awg.sets, s.Roam)
	}
	for i := 0; i < 5; i++ {
		f.round(time.Hour)
	}
	if len(awg.sets) != 3 {
		t.Fatal("roam continued after it was turned off", awg.sets)
	}
}

func TestAWGRoamCommandFailureKeepsPort(t *testing.T) {
	f, awg := roamFixture(t, "40000-40009")
	awg.setErr = errors.New("public test failure")
	s, _ := f.round(time.Hour)
	if s.Roam == nil || s.Roam.Port != 51820 || s.Roam.Roamed || s.Roam.LastError == "" || s.Roam.Rotations != 0 {
		t.Fatal("failed rotation misreported", s.Roam)
	}
	if _, failed := roamDecisions(f); failed != 1 {
		t.Fatal("failed rotation not recorded", f.events)
	}
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "a" || s.Selection.General != contract.AWG {
		t.Fatal("failed rotation disturbed the default", s)
	}
}

// A native switch reloads the stored endpoint: the roam state starts again.
func TestAWGRoamResetByNativeSwitch(t *testing.T) {
	a2 := managedConnection(t, "awg", "a2", 11)
	f, awg := roamFixture(t, "40000-40009", a2)
	f.round(time.Hour)
	if len(awg.sets) != 1 {
		t.Fatal("fixture did not rotate")
	}
	f.awg.good["a"] = false
	f.awg.good["a2"] = true
	var s Snapshot
	for i := 0; i < 4 && (s.ActiveConnection == nil || s.ActiveConnection.ID != "a2"); i++ {
		s, _ = f.round(5 * time.Second)
	}
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "a2" || s.Roam != nil {
		t.Fatal("native switch kept a stale roam state", s.ActiveConnection, s.Roam)
	}
}

func TestSnapshotRoamJSONShape(t *testing.T) {
	f, _ := roamFixture(t, "40000-40009")
	s, _ := f.round(time.Hour)
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var shape struct {
		Roam map[string]any `json:"roam"`
	}
	if err := json.Unmarshal(raw, &shape); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"connection_id", "ports", "interval_seconds", "port", "listen_port", "roamed", "next_rotation", "last_rotation", "last_reason", "rotations"} {
		if _, ok := shape.Roam[key]; !ok {
			t.Fatal("snapshot roam field missing", key, shape.Roam)
		}
	}
	// Without roaming the field is absent.
	g, _ := roamFixture(t, "")
	s, _ = g.round(0)
	raw, _ = json.Marshal(s)
	var plain map[string]any
	json.Unmarshal(raw, &plain)
	if _, ok := plain["roam"]; ok {
		t.Fatal("roam field present without roaming")
	}
	// Snapshot copies are independent.
	c := f.m.Snapshot()
	c.Roam.Port = 1
	if f.m.Snapshot().Roam.Port == 1 {
		t.Fatal("snapshot shares roam state")
	}
}

// Every rotation is a distinct 5-tuple on both sides: the source port and the
// endpoint port both change, the source port comes from the dynamic range,
// and recent source ports (whose flows may still hold conntrack state) and
// the original one are not reused.
func TestAWGRoamEveryRotationChangesBothPorts(t *testing.T) {
	for _, deterministic := range []bool{true, false} {
		f, awg := roamFixture(t, "40000-40009")
		if !deterministic {
			f.m.roamRandom = nil
		}
		prev := roamUpdate{listen: kernelListen, endpoint: netip.MustParseAddrPort("192.0.2.10:51820")}
		var s Snapshot
		for i := 0; i < 24; i++ {
			s, _ = f.round(time.Hour)
			if len(awg.sets) != i+1 {
				t.Fatal("rotation missing", i, awg.sets)
			}
			next := awg.sets[i]
			if next.listen == prev.listen || next.endpoint.Port() == prev.endpoint.Port() || next.endpoint.Addr() != prev.endpoint.Addr() {
				t.Fatal("rotation did not change both ports", prev, next)
			}
			if next.listen < roamListenMin || next.listen == kernelListen {
				t.Fatal("source port outside the dynamic range or the original one", next.listen)
			}
			for j := i - 1; j >= 0 && j >= i-roamRecentPorts; j-- {
				if awg.sets[j].listen == next.listen {
					t.Fatal("recent source port reused", i, j, next.listen)
				}
			}
			if s.Roam == nil || s.Roam.ListenPort != next.listen || s.Roam.Port != next.endpoint.Port() || !s.Roam.Roamed {
				t.Fatal("snapshot does not show both ports", s.Roam, next)
			}
			prev = next
		}
		if deterministic && (awg.sets[0].listen != 57344 || awg.sets[1].listen != 57345) {
			t.Fatal("unexpected deterministic picks", awg.sets[:2])
		}
		if s.ActiveConnection == nil || s.ActiveConnection.ID != "a" || s.Selection.General != contract.AWG {
			t.Fatal("rotations disturbed the default", s)
		}
	}
}

// A source port another socket holds fails the bind: the update is retried
// with another source port and the endpoint still moves in the same round.
func TestAWGRoamRetriesTakenSourcePort(t *testing.T) {
	f, awg := roamFixture(t, "40000-40009")
	awg.bindFail[57344] = true
	s, _ := f.round(time.Hour)
	if awg.attempts != 2 || len(awg.sets) != 1 || awg.sets[0].listen != 57345 || awg.sets[0].endpoint.Port() != 40005 {
		t.Fatal("taken source port not retried", awg.attempts, awg.sets)
	}
	if s.Roam == nil || s.Roam.LastError != "" || s.Roam.ListenPort != 57345 {
		t.Fatal("retried update misreported", s.Roam)
	}
	// Every attempt failing leaves both ports as they were.
	for p := uint16(roamListenMin); ; p++ {
		awg.bindFail[p] = true
		if p == roamListenMax {
			break
		}
	}
	awg.attempts = 0
	s, _ = f.round(time.Hour)
	if awg.attempts != roamListenAttempts || len(awg.sets) != 1 || awg.listen != 57345 || awg.port != 40005 || s.Roam.LastError == "" {
		t.Fatal("failed update changed a port or retried without bound", awg.attempts, awg.listen, awg.port, s.Roam)
	}
}

// Turning roaming off restores both ports; after a reset (the interface was
// reloaded from its stored configuration, here by the controller's restore
// after a connection test) the new kernel port becomes the original one.
func TestAWGRoamDisableAndResetRestoreBothPorts(t *testing.T) {
	f, awg := roamFixture(t, "40000-40009")
	f.round(time.Hour)
	f.round(time.Hour)
	if len(awg.sets) != 2 {
		t.Fatal("fixture did not rotate", awg.sets)
	}
	// Reset: the interface was reloaded, the kernel picked a new port.
	a := f.r.Connections[0]
	f.m.RestoreNativeIdentity(&a)
	awg.port, awg.listen = 0, kernelListen+1
	if s := f.m.Snapshot(); s.Roam != nil {
		t.Fatal("reset kept the roam state", s.Roam)
	}
	s, _ := f.round(5 * time.Second)
	if s.Roam == nil || s.Roam.Roamed || s.Roam.Port != 51820 {
		t.Fatal("reset state not republished from the stored endpoint", s.Roam)
	}
	f.round(time.Hour)
	if len(awg.sets) != 3 || awg.sets[2].listen == kernelListen+1 {
		t.Fatal("rotation after reset kept the source port", awg.sets)
	}
	if err := f.r.Connections[0].SetRoam("", 0); err != nil {
		t.Fatal(err)
	}
	s, _ = f.round(5 * time.Second)
	if len(awg.sets) != 4 || awg.sets[3] != (roamUpdate{kernelListen + 1, netip.MustParseAddrPort("192.0.2.10:51820")}) || s.Roam != nil {
		t.Fatal("disable did not restore both ports", awg.sets, s.Roam)
	}
	for i := 0; i < 3; i++ {
		f.round(time.Hour)
	}
	if len(awg.sets) != 4 {
		t.Fatal("restore repeated", awg.sets)
	}
}

// If the original source port could not be read, turning roaming off still
// restores the stored endpoint, from a fresh source port (never the roamed
// one), so the outer flow is again a new 5-tuple.
func TestAWGRoamDisableWithUnknownOriginalListenPort(t *testing.T) {
	f, awg := roamFixture(t, "40000-40009")
	awg.listenErr = errors.New("public test: no awg tool")
	f.round(time.Hour)
	if len(awg.sets) != 1 {
		t.Fatal("unknown original port blocked rotation", awg.sets)
	}
	if err := f.r.Connections[0].SetRoam("", 0); err != nil {
		t.Fatal(err)
	}
	f.round(5 * time.Second)
	last := awg.sets[len(awg.sets)-1]
	if len(awg.sets) != 2 || last.endpoint.Port() != 51820 || last.listen == awg.sets[0].listen || last.listen < roamListenMin {
		t.Fatal("disable without original port did not restore the endpoint from a fresh source port", awg.sets)
	}
}
