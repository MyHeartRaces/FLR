package control

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/lan"
)

func TestMalformedCommandAndForeignClientRejected(t *testing.T) {
	lan := lan.Legacy()
	for _, b := range []string{`{"command":"direct-session","client":"8.8.8.8","ttl":"15m"}`, `{"command":"direct-session","client":"192.168.8.1","ttl":"15m"}`, `{"command":"direct-session","client":"192.168.8.126","ttl":"16m"}`, `{"command":"games","value":"evil"}`, `{"command":"status","private_key":"secret"}`, `{"command":"status"} {"command":"games","value":"vless"}`} {
		if _, e := Parse([]byte(b), lan); e == nil {
			t.Fatal("malformed request accepted", b)
		}
	}
	if _, e := Parse([]byte(`{"command":"direct-session","client":"192.168.8.126","ttl":"15m"}`), lan); e != nil {
		t.Fatal(e)
	}
}

func TestParseClientsFollowRouterLAN(t *testing.T) {
	for _, tc := range []struct {
		cidr    string
		ok, bad []string
	}{
		{"192.168.1.1/24", []string{"192.168.1.2", "192.168.1.254"}, []string{"192.168.1.1", "192.168.1.0", "192.168.1.255", "192.168.8.126", "8.8.8.8"}},
		{"10.10.0.1/24", []string{"10.10.0.50"}, []string{"10.10.0.1", "10.10.0.255", "192.168.1.2"}},
		{"192.168.8.1/24", []string{"192.168.8.126"}, []string{"192.168.8.1", "192.168.8.255", "192.168.1.2"}},
	} {
		p := netip.MustParsePrefix(tc.cidr)
		router, e := lan.New(p.Addr(), p.Bits())
		if e != nil {
			t.Fatal(e)
		}
		for _, ip := range tc.ok {
			for _, cmd := range []string{"direct-session", "profile"} {
				body := `{"command":"` + cmd + `","client":"` + ip + `","ttl":"15m"}`
				if cmd == "profile" {
					body = `{"command":"profile","client":"` + ip + `","value":"games"}`
				}
				if _, e := Parse([]byte(body), router); e != nil {
					t.Fatalf("%s %s: %v", tc.cidr, ip, e)
				}
			}
		}
		for _, ip := range tc.bad {
			if _, e := Parse([]byte(`{"command":"direct-session","client":"`+ip+`","ttl":"15m"}`), router); e == nil {
				t.Fatalf("%s accepted %s", tc.cidr, ip)
			}
		}
	}
}

func TestDeviceAPIValidationUsesDiscoveredLAN(t *testing.T) {
	useLAN(t, "192.168.1.1/24")
	if _, e := ParseAPI([]byte(`{"operation":"device","client":"192.168.1.20","value":"direct"}`), false, false); e != nil {
		t.Fatal(e)
	}
	for _, ip := range []string{"192.168.8.20", "192.168.1.1", "192.168.1.255"} {
		if _, e := ParseAPI([]byte(`{"operation":"device","client":"`+ip+`","value":"direct"}`), false, false); e == nil {
			t.Fatal("accepted", ip)
		}
	}
}

type backend struct{ started, stopped []string }

func (b *backend) Start(_ context.Context, s Session) error {
	b.started = append(b.started, s.ID)
	return nil
}
func (b *backend) Stop(s Session) error { b.stopped = append(b.stopped, s.ID); return nil }
func TestSessionExpiryStopsOnlyItsOwnWorkerAndRestartRevokes(t *testing.T) {
	now := time.Unix(1000, 0)
	b := &backend{}
	m := NewManager(b)
	s, e := m.Start(context.Background(), now, "192.168.8.126", "00:e0:4c:33:7b:c0", 15*time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	m.Tick(now.Add(14*time.Minute), s.Client, s.MAC)
	if len(b.stopped) != 0 {
		t.Fatal("session expired early")
	}
	m.Tick(now.Add(15*time.Minute), s.Client, s.MAC)
	if len(b.stopped) != 1 || b.stopped[0] != s.ID {
		t.Fatal("expiry stopped unrelated worker")
	}
	if NewManager(b).Current() != nil {
		t.Fatal("session restored automatically on restart")
	}
}
func TestClientAddressOrMACChangeRevokesListener(t *testing.T) {
	now := time.Now()
	for _, change := range []struct{ ip, mac string }{{"192.168.8.127", "aa:bb:cc:dd:ee:ff"}, {"192.168.8.126", "ff:ee:dd:cc:bb:aa"}} {
		b := &backend{}
		m := NewManager(b)
		s, e := m.Start(context.Background(), now, "192.168.8.126", "aa:bb:cc:dd:ee:ff", 15*time.Minute)
		if e != nil {
			t.Fatal(e)
		}
		m.Tick(now.Add(time.Second), change.ip, change.mac)
		if m.Current() != nil || len(b.stopped) != 1 || b.stopped[0] != s.ID {
			t.Fatal("changed client retained direct listener")
		}
	}
}
func TestStatusContainsNoCredentials(t *testing.T) {
	b, e := json.Marshal(Session{ID: "session-1", Client: "192.168.8.126", MAC: "aa:bb:cc:dd:ee:ff", Expires: time.Now()})
	if e != nil {
		t.Fatal(e)
	}
	for _, key := range []string{"password", "private_key", "uuid", "preshared_key"} {
		if strings.Contains(string(b), key) {
			t.Fatal("status leaks credential", key)
		}
	}
}

func TestWorkerRejectsClientOutsideRouterLAN(t *testing.T) {
	useLAN(t, "192.168.1.1/24")
	s := Session{ID: "s", Client: "192.168.8.2", Expires: time.Now().Add(time.Minute), Port: 1088}
	if e := Worker(context.Background(), s, "eth1"); e == nil || !strings.Contains(e.Error(), "192.168.1.1/24") {
		t.Fatal(e)
	}
}

func TestProfileRemovalOutsideLANAccepted(t *testing.T) {
	router, _ := lan.New(netip.MustParseAddr("192.168.1.1"), 24)
	if _, e := Parse([]byte(`{"command":"profile","client":"192.168.8.50","value":"auto"}`), router); e != nil {
		t.Fatalf("stale profile cannot be removed: %v", e)
	}
	for _, b := range []string{
		`{"command":"profile","client":"192.168.8.50","value":"games"}`,
		`{"command":"profile","client":"8.8.8.8","value":"auto"}`,
		`{"command":"profile","client":"fd00::2","value":"auto"}`,
		`{"command":"direct-session","client":"192.168.8.50","ttl":"15m"}`,
	} {
		if _, e := Parse([]byte(b), router); e == nil {
			t.Fatal("accepted", b)
		}
	}
	if _, e := Parse([]byte(`{"command":"profile","client":"192.168.1.20","value":"games"}`), lan.LAN{}); e == nil || !strings.Contains(e.Error(), "unknown") {
		t.Fatalf("unknown LAN accepted a new profile: %v", e)
	}
}

func TestDeviceAPIRejectsNewProfilesWhileLANUnknown(t *testing.T) {
	old := lan.Source
	lan.Source = func(string) ([]net.Addr, error) { return nil, errors.New("no IPv4 on br-lan") }
	t.Cleanup(func() { lan.Source = old })
	if _, e := ParseAPI([]byte(`{"operation":"device","client":"192.168.8.20","value":"direct"}`), false, false); e == nil {
		t.Fatal("new profile accepted against the legacy fallback")
	}
	if _, e := ParseAPI([]byte(`{"operation":"device","client":"192.168.8.20","value":"auto"}`), false, false); e != nil {
		t.Fatal(e)
	}
}

func controlCall(t *testing.T, router RouterLAN, body string) Reply {
	t.Helper()
	a, b := net.Pipe()
	defer b.Close()
	b.SetDeadline(time.Now().Add(2 * time.Second))
	go serveControl(a, router, func(r Request) (any, error) { return r.Client, nil })
	if _, e := b.Write([]byte(body + "\n")); e != nil {
		t.Fatal(e)
	}
	var reply Reply
	if e := json.NewDecoder(b).Decode(&reply); e != nil {
		t.Fatal(e)
	}
	return reply
}

// Regression (e): the control socket reads the LAN per request, so a client
// is accepted once br-lan gets its address after the controller started.
func TestControlSocketFollowsLANAppearingAfterStart(t *testing.T) {
	old := lan.Source
	t.Cleanup(func() { lan.Source = old })
	lan.Source = func(string) ([]net.Addr, error) { return nil, errors.New("no IPv4 on br-lan yet") }
	now := time.Unix(1000, 0)
	cache := lan.NewCache()
	cache.Now = func() time.Time { return now }
	router := func() (lan.LAN, error) { return cache.Resolve(lan.Interface) }
	body := `{"command":"profile","client":"192.168.1.20","value":"games"}`
	if r := controlCall(t, router, body); r.OK || !strings.Contains(r.Error, "unknown") {
		t.Fatalf("accepted with unknown LAN: %+v", r)
	}
	lan.Source = lan.FixedSource("192.168.1.1/24")
	if r := controlCall(t, router, body); r.OK {
		t.Fatal("cache TTL not honoured")
	}
	now = now.Add(lan.CacheTTL)
	if r := controlCall(t, router, body); !r.OK || r.Data != "192.168.1.20" {
		t.Fatalf("client rejected after the LAN appeared: %+v", r)
	}
	if r := controlCall(t, router, `{"command":"direct-session","client":"192.168.8.20","ttl":"15m"}`); r.OK {
		t.Fatal("client outside the new LAN accepted")
	}
}
