package transport

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
)

// spareFixture: AWG main a, AWG spare a2, warm Hysteria2 reserve h, in auto
// mode, settled on a with h admitted as the warm standby.
func spareFixture(t *testing.T) *warmFixture {
	t.Helper()
	a := managedConnection(t, "awg", "a", 10)
	a2 := managedConnection(t, "awg", "a2", 11)
	h := managedConnection(t, "hy2", "h", 20)
	f := newWarmFixture(t, a, a2, h)
	f.order.Connections["awg"] = []string{"a", "a2"}
	if s := f.admit(); s.ActiveConnection == nil || s.ActiveConnection.ID != "a" || !s.ReserveWarm {
		t.Fatal("fixture did not settle on AWG main with a warm standby", s)
	}
	return f
}

// failMain makes AWG main fail until the warm standby carries new flows.
func failMain(t *testing.T, f *warmFixture) Snapshot {
	t.Helper()
	f.awg.good["a"] = false
	var s Snapshot
	for i := 0; i < 3; i++ {
		s, _ = f.round(5 * time.Second)
	}
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "h" || s.Selection != (contract.Selection{General: contract.Gecko, Games: contract.Gecko}) {
		t.Fatal("AWG failure did not move new flows to the warm standby", s)
	}
	return s
}

// Task 1: while the warm reserve carries new flows because AWG main failed,
// the AWG spare is tried on the normal cadence and, once it passes TCP+UDP,
// new flows return to AWG. The reserve keeps its process and flows.
func TestReadvanceMovesNewFlowsToAWGSpareWhileReserveKeepsFlows(t *testing.T) {
	f := spareFixture(t)
	f.awg.good["a2"] = true
	failMain(t, f)
	starts, stops := len(f.b.starts), f.b.stops
	f.cleaned, f.events = nil, nil
	s, _ := f.round(5 * time.Second)
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "a2" || s.Selection != (contract.Selection{General: contract.AWG, Games: contract.AWG}) {
		t.Fatal("AWG spare was not re-advanced while the reserve was the default", s)
	}
	if strings.Join(f.awg.switches, ",") != "a,a2" {
		t.Fatal("unexpected native switches", f.awg.switches)
	}
	if s.ReserveConnection == nil || s.ReserveConnection.ID != "h" || s.ReserveWarm || !f.b.alive || len(f.b.starts) != starts || f.b.stops != stops {
		t.Fatal("re-advance disturbed the reserve that carries existing flows", s, f.starts(), f.b.stops-stops)
	}
	for _, ch := range f.cleaned {
		if ch != contract.AWG {
			t.Fatal("re-advance retired reserve flows", f.cleaned)
		}
	}
	found := false
	for _, e := range f.events {
		if e.Stage == "stop" || (e.Stage == "cleanup" && e.Channel == contract.Gecko) {
			t.Fatal("re-advance recorded a reserve teardown", e)
		}
		found = found || (e.Reason == "failback" && e.From.ID == "h" && e.To.ID == "a2" && e.ReserveRetained)
	}
	if !found {
		t.Fatal("failback decision to the AWG spare missing", f.events)
	}
	// The spare stays the default; the retained reserve is not replaced.
	for i := 0; i < 10; i++ {
		s, _ = f.round(5 * time.Second)
	}
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "a2" || len(f.b.starts) != starts || f.b.stops != stops || strings.Join(f.awg.switches, ",") != "a,a2" {
		t.Fatal("spare default or retained reserve did not settle", s, f.awg.switches)
	}
}

// Main is preferred over the spare, both are paced by the failover cool-down,
// and a recovering main is never displaced: once main qualifies under the
// health policy, new flows move back to it.
func TestReadvanceTriesMainBeforeSpareWithBackoffAndHysteresis(t *testing.T) {
	f := spareFixture(t)
	failMain(t, f)
	starts, stops := len(f.b.starts), f.b.stops
	// Both AWG connections are down for ten minutes: the proxy stays the
	// default and the native identity is switched only at the cool-down pace.
	for i := 0; i < 120; i++ {
		s, _ := f.round(5 * time.Second)
		if s.ActiveConnection == nil || s.ActiveConnection.ID != "h" || s.Selection.General != contract.Gecko {
			t.Fatal("reserve default lost while AWG was down", s)
		}
	}
	switches := f.awg.switches
	if len(switches) < 4 || len(switches) > 14 || switches[1] != "a2" || switches[2] != "a" {
		t.Fatal("AWG candidates not retried in order at the cool-down pace", switches)
	}
	if len(f.b.starts) != starts || f.b.stops != stops || !f.b.alive {
		t.Fatal("re-advance attempts touched the reserve")
	}
	// Main comes back. Whichever identity is configured, main is the next one
	// tried after its cool-down, and it is selected only after a qualified
	// recovery.
	f.awg.good["a"] = true
	var s Snapshot
	selectedAt := -1
	for i := 0; i < 200 && selectedAt < 0; i++ {
		s, _ = f.round(5 * time.Second)
		if s.ActiveConnection != nil && s.ActiveConnection.ID == "a" {
			selectedAt = i
		}
	}
	if selectedAt < 0 || s.Selection != (contract.Selection{General: contract.AWG, Games: contract.AWG}) {
		t.Fatal("recovered AWG main never re-advanced", s, f.awg.switches)
	}
	if last := f.awg.switches[len(f.awg.switches)-1]; last != "a" {
		t.Fatal("spare displaced the recovering main", f.awg.switches)
	}
	if state := f.m.connections.health[connectionKey(f.r.Connections[0])]; !state.Healthy() || state.LastChange.IsZero() {
		t.Fatal("main selected without qualifying under the health policy", state)
	}
	if s.ReserveConnection == nil || s.ReserveConnection.ID != "h" || len(f.b.starts) != starts || f.b.stops != stops {
		t.Fatal("main re-advance disturbed the reserve", s)
	}
}

// A configured main whose samples are clean again is recovering: the spare is
// never switched in over it, and main returns after its recovery window.
func TestReadvanceNeverDisplacesRecoveringMain(t *testing.T) {
	f := spareFixture(t)
	f.awg.good["a2"] = true
	f.awg.good["a"] = false
	var s Snapshot
	for i := 0; i < 2; i++ {
		s, _ = f.round(5 * time.Second)
	}
	// The third failing sample marks main down; the reserve takes new flows in
	// the same round, then main is clean from the next sample on.
	f.round(5 * time.Second)
	f.awg.good["a"] = true
	for i := 0; i < 30; i++ {
		s, _ = f.round(5 * time.Second)
		if strings.Contains(strings.Join(f.awg.switches, ","), "a2") {
			t.Fatal("spare displaced a recovering main", f.awg.switches)
		}
	}
	if s.ActiveConnection == nil || s.ActiveConnection.ID != "a" || s.ReserveConnection == nil || s.ReserveConnection.ID != "h" {
		t.Fatal("recovered main did not fail back with the reserve retained", s)
	}
}

// A proxy chosen by order alone (no AWG identity was ever configured) keeps
// its affinity: re-advance follows only a fallback from AWG.
func TestReadvanceOnlyAfterFallback(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	h := managedConnection(t, "hy2", "h", 20)
	r := &connection.Registry{Version: 2, Connections: []connection.Connection{a, h}}
	order := connection.DefaultOrder(r)
	order.Families[0], order.Families[1] = "hy2", "awg"
	awg := &fakeAWG{good: map[string]bool{"a": true}}
	m := New(&fakeBackend{}, func(context.Context, profile.Profile) health.Result { return health.Result{TCP: true, UDP: true} }, nil)
	m.SetAWGBackend(awg)
	now := time.Unix(100, 0)
	m.StepConnections(context.Background(), now, r, connection.Selection{Mode: "auto"}, order, 1)
	order = connection.DefaultOrder(r)
	for i := 1; i < 20; i++ {
		s := m.StepConnections(context.Background(), now.Add(time.Duration(i)*5*time.Second), r, connection.Selection{Mode: "auto"}, order, 1)
		if s.ActiveConnection == nil || s.ActiveConnection.ID != "h" || len(awg.switches) != 0 {
			t.Fatal("order edit moved new flows away from the proxy", s, awg.switches)
		}
	}
}

// Task 2: Games never go to a TCP-carried family automatically.
func TestGamesNeverOnTCPCarriedFamilyAutomatically(t *testing.T) {
	links := map[string]string{
		"reality": "vless://00000000-0000-4000-8000-000000000000@example.com:443?security=reality&pbk=PUBLIC_TEST_KEY&sid=abcd&fp=chrome&sni=example.com&type=tcp&flow=xtls-rprx-vision&spx=%2F",
		"vless":   "vless://00000000-0000-4000-8000-000000000000@example.com:443?security=tls&sni=example.com&type=ws&host=example.com&path=%2Fpublic&alpn=h2,http%2F1.1",
	}
	for name, link := range links {
		items, err := connection.ParseImport([]byte(link))
		if err != nil {
			t.Fatal(name, err)
		}
		c := items[0]
		c.ID = "tcp-lane"
		if connection.GameSafe(c.Family) || !c.Profile.Capabilities.UDP {
			t.Fatal(name, "fixture is not a UDP-capable TCP-carried lane", c.Family)
		}
		h := managedConnection(t, "hy2", "h", 20)
		r := &connection.Registry{Version: 2, Connections: []connection.Connection{c, h}}
		order := connection.DefaultOrder(r)
		// The TCP lane ranks first.
		families := []string{c.Family}
		for _, family := range connection.Families {
			if family != c.Family {
				families = append(families, family)
			}
		}
		order.Families = families
		for _, tc := range []struct {
			selection connection.Selection
			games     contract.Channel
		}{
			{connection.Selection{Mode: "auto"}, contract.Down},
			{connection.Selection{Mode: "transport", Family: c.Family}, contract.Down},
			// An explicit choice of this connection keeps today's behaviour.
			{connection.Selection{Mode: "connection", ID: "tcp-lane"}, contract.Gecko},
		} {
			m := New(&fakeBackend{}, func(context.Context, profile.Profile) health.Result { return health.Result{TCP: true, UDP: true} }, nil)
			s := m.StepConnections(context.Background(), time.Unix(100, 0), r, tc.selection, order, 1)
			if s.ActiveConnection == nil || s.ActiveConnection.ID != "tcp-lane" || s.Selection != (contract.Selection{General: contract.Gecko, Games: tc.games}) {
				t.Fatal(name, tc.selection, "wrong selection map", s.Selection, s.ActiveConnection)
			}
		}
	}
	// A UDP-carried proxy still carries Games automatically.
	h := managedConnection(t, "hy2", "h", 20)
	r := &connection.Registry{Version: 2, Connections: []connection.Connection{h}}
	m := New(&fakeBackend{}, func(context.Context, profile.Profile) health.Result { return health.Result{TCP: true, UDP: true} }, nil)
	if s := m.StepConnections(context.Background(), time.Unix(100, 0), r, connection.Selection{Mode: "auto"}, connection.DefaultOrder(r), 1); s.Selection != (contract.Selection{General: contract.Gecko, Games: contract.Gecko}) {
		t.Fatal("Hysteria2 lost its Games path", s.Selection)
	}
}

func TestGameSafeFamilies(t *testing.T) {
	for _, family := range connection.Families {
		want := family == "awg" || family == "hy2"
		if connection.GameSafe(family) != want {
			t.Fatal("wrong game-safe classification", family)
		}
	}
	if connection.GameSafe("") || connection.GameSafe("unknown") {
		t.Fatal("unknown family treated as game-safe")
	}
}

// The legacy profile path follows the same rule: auto fails closed for a
// TCP-carried family, a profile chosen by ID keeps its Games path.
func TestLegacyGamesNeverOnTCPCarriedFamilyAutomatically(t *testing.T) {
	for _, mode := range []string{"auto", "reality"} {
		b := &fakeBackend{}
		m := New(b, func(context.Context, profile.Profile) health.Result { return health.Result{TCP: true, UDP: true} }, nil)
		r := &profile.Registry{Version: 1, Profiles: []profile.Profile{candidate("reality", "reality", "", true)}}
		s := m.Step(context.Background(), time.Unix(1000, 0), health.Result{}, false, r, "", mode)
		want := contract.Down
		if mode != "auto" {
			want = contract.Gecko
		}
		if s.Active == nil || s.Selection != (contract.Selection{General: contract.Gecko, Games: want}) {
			t.Fatal(mode, "wrong legacy selection map", s.Selection)
		}
	}
}
