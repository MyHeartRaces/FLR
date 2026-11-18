package controller

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/control"
	"github.com/MyHeartRaces/FLR/runtime/internal/dataplane"
	"github.com/MyHeartRaces/FLR/runtime/internal/lan"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
)

func lanSettings(bind, profiles string) string {
	return `{"version":1,"enabled":true,"direct_proxy":{"enabled":true,"bind":"` + bind + `","port":1080},"options":{"lan":"br-lan","wan":"eth1","selection":{"general":"down","games":"down"},"manual_games":false` + profiles + `},"dns_port":"1054","local_dns_port":"53","profile_selection":"auto"}`
}

func privateSettingsDir(t *testing.T, settings string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(settings), 0600); e != nil {
		t.Fatal(e)
	}
	return dir
}

// fakeDirect records the listener's binds and guard calls without sockets on
// router addresses or nft.
type fakeDirect struct {
	mu       sync.Mutex
	listened []string
	stopped  int
}

func (f *fakeDirect) deps() control.DirectDeps {
	return control.DirectDeps{
		Listen: func(_, address string) (net.Listener, error) {
			f.mu.Lock()
			f.listened = append(f.listened, address)
			f.mu.Unlock()
			return net.Listen("tcp4", "127.0.0.1:0")
		},
		ListenPacket: func(string, string) (net.PacketConn, error) { return net.ListenPacket("udp4", "127.0.0.1:0") },
		Guard: func(_ control.DirectConfig, start bool) error {
			if !start {
				f.mu.Lock()
				f.stopped++
				f.mu.Unlock()
			}
			return nil
		},
	}
}

func (f *fakeDirect) binds() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.listened...)
}

type lanHarness struct {
	c        *Controller
	direct   *fakeDirect
	rendered []map[string]contract.Class
	now      time.Time
}

func newLANHarness(t *testing.T, s Settings, dir string) *lanHarness {
	t.Helper()
	h := &lanHarness{direct: &fakeDirect{}, now: time.Unix(1000, 0)}
	h.c = New(s)
	h.c.stateDir = dir
	h.c.directDeps = h.direct.deps()
	h.c.lanCache.Now = func() time.Time { return h.now }
	h.c.renderProfiles = func(p map[string]contract.Class) error {
		h.rendered = append(h.rendered, p)
		return nil
	}
	t.Cleanup(func() {
		if h.c.direct != nil {
			h.c.direct.Stop()
		}
	})
	return h
}

// tick runs the LAN-dependent part of one Run iteration.
func (h *lanHarness) tick() {
	h.c.refreshLAN()
	h.c.reconcileDirect(context.Background())
	if h.c.vpnStarted {
		h.c.syncProfiles()
	}
}

func mustControllerPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	p, e := policy.Load("../policy/testdata/split")
	if e != nil {
		t.Fatal(e)
	}
	return p
}

// Regression (g) for (a)-(c): every step of Run that depends on the stored
// settings or the LAN succeeds, so Run does not exit and procd does not
// restart it under the boot guard. Run itself needs root paths and native
// commands; this drives the same functions with the native effects faked.
func TestRunStepsSurviveLANMismatch(t *testing.T) {
	p := mustControllerPolicy(t)
	for _, tc := range []struct {
		name     string
		settings string
		lan      func(*testing.T)
		check    func(*testing.T, *lanHarness, Settings, dataplane.Batch)
	}{
		// (a) a profile saved for 192.168.8.0/24 on a router now at 192.168.1.1.
		{"stale-profile", lanSettings("192.168.8.1", `,"profiles":{"192.168.8.50":"games","192.168.1.20":"direct"}`), func(t *testing.T) { useLAN(t, "192.168.1.1/24") },
			func(t *testing.T, h *lanHarness, s Settings, b dataplane.Batch) {
				status := h.c.Status()
				want := []dataplane.IgnoredProfile{{Client: "192.168.8.50", Class: contract.Games, Reason: "outside LAN 192.168.1.0/24"}}
				if !reflect.DeepEqual(status.IgnoredProfiles, want) {
					t.Fatalf("ignored %+v", status.IgnoredProfiles)
				}
				if strings.Contains(b.Nft, "192.168.8.50") || !strings.Contains(b.Nft, "elements = { 192.168.1.20 }") {
					t.Fatal("ignored profile rendered or LAN profile lost")
				}
				if !reflect.DeepEqual(h.direct.binds(), []string{"192.168.1.1:1080"}) || !status.DirectProxy.Running || status.DirectProxy.LAN != "192.168.1.1/24" || status.DirectProxy.LANError != "" {
					t.Fatalf("%v %+v", h.direct.binds(), status.DirectProxy)
				}
				if status.Profiles["192.168.8.50"] != contract.Games {
					t.Fatal("stored profile dropped from status")
				}
			}},
		// (b) bind 192.168.1.1 was saved, then the LAN moved to 10.0.0.1/24.
		{"lan-moved", lanSettings("192.168.1.1", `,"profiles":{"192.168.1.20":"direct"}`), func(t *testing.T) { useLAN(t, "10.0.0.1/24") },
			func(t *testing.T, h *lanHarness, s Settings, b dataplane.Batch) {
				status := h.c.Status()
				// The stored bind is kept; the listener uses the discovered address.
				if s.DirectProxy != (control.DirectConfig{Enabled: true, Bind: "192.168.1.1", Port: 1080}) || h.c.settings.DirectProxy != s.DirectProxy || status.DirectProxy.Config != (control.DirectConfig{Enabled: true, Bind: "10.0.0.1", Port: 1080}) {
					t.Fatalf("%+v %+v", s.DirectProxy, status.DirectProxy)
				}
				if !reflect.DeepEqual(h.direct.binds(), []string{"10.0.0.1:1080"}) || !status.DirectProxy.Running {
					t.Fatal(h.direct.binds())
				}
				if len(status.IgnoredProfiles) != 1 || status.IgnoredProfiles[0].Client != "192.168.1.20" || strings.Contains(b.Nft, "192.168.1.20") {
					t.Fatalf("%+v", status.IgnoredProfiles)
				}
			}},
		// (c) br-lan has no IPv4 yet when the controller starts.
		{"no-lan-yet", lanSettings("192.168.1.1", `,"profiles":{"192.168.1.20":"direct"}`), failLAN,
			func(t *testing.T, h *lanHarness, s Settings, b dataplane.Batch) {
				status := h.c.Status()
				if s.DirectProxy.Bind != "192.168.1.1" || len(h.direct.binds()) != 0 {
					t.Fatalf("bound on an unknown LAN: %+v %v", s.DirectProxy, h.direct.binds())
				}
				if status.DirectProxy.Running || status.DirectProxy.LANError == "" || !strings.Contains(status.DirectProxy.Error, "unknown") || !strings.Contains(status.LastError, "discovery failed") {
					t.Fatalf("%+v %q", status.DirectProxy, status.LastError)
				}
				if len(status.IgnoredProfiles) != 0 || !b.LAN.IsZero() || !strings.Contains(b.Nft, "192.168.1.20") {
					t.Fatal("profile dropped while the LAN is unknown")
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.lan(t)
			dir := privateSettingsDir(t, tc.settings)
			lock, s, e := readOwnedSettings(filepath.Join(t.TempDir(), "controller.lock"), func() (Settings, error) { return readSettingsAt(dir) })
			if e != nil {
				t.Fatalf("Run would exit at settings load: %v", e)
			}
			defer lock.Close()
			h := newLANHarness(t, s, dir)
			h.tick()
			b, e := h.c.vpnBatch(p, false)
			if e != nil {
				t.Fatalf("Run would exit at VPN start: %v", e)
			}
			h.c.renderedLAN, h.c.vpnStarted = b.LAN, true
			h.tick()
			if e = WriteJSON(filepath.Join(dir, "status.json"), h.c.Status()); e != nil {
				t.Fatalf("Run would exit at status write: %v", e)
			}
			raw, _ := json.Marshal(h.c.Status())
			if !strings.Contains(string(raw), `"direct_proxy"`) {
				t.Fatal(string(raw))
			}
			tc.check(t, h, s, b)
		})
	}
}

// Finding 2: discovery failure at start is not sticky. Once br-lan has its
// address the listener binds it, the stale fallback is gone and the profile
// sets are re-rendered once for the discovered LAN.
func TestLANAppearingAfterStartHeals(t *testing.T) {
	failLAN(t)
	dir := privateSettingsDir(t, lanSettings("192.168.8.1", `,"profiles":{"192.168.8.50":"games","192.168.1.20":"direct"}`))
	s, e := readSettingsAt(dir)
	if e != nil {
		t.Fatal(e)
	}
	h := newLANHarness(t, s, dir)
	h.tick()
	b, e := h.c.vpnBatch(mustControllerPolicy(t), false)
	if e != nil || !b.LAN.IsZero() {
		t.Fatal(e)
	}
	h.c.renderedLAN, h.c.vpnStarted = b.LAN, true
	if _, e := h.c.socketLAN(); e == nil {
		t.Fatal("control socket LAN known")
	}
	useLAN(t, "192.168.1.1/24")
	h.now = h.now.Add(time.Second)
	h.tick()
	if len(h.direct.binds()) != 0 || len(h.rendered) != 0 {
		t.Fatal("cache TTL not honoured")
	}
	h.now = h.now.Add(lan.CacheTTL)
	h.tick()
	status := h.c.Status()
	if !reflect.DeepEqual(h.direct.binds(), []string{"192.168.1.1:1080"}) || !status.DirectProxy.Running || status.DirectProxy.LANError != "" || status.DirectProxy.Config.Bind != "192.168.1.1" {
		t.Fatalf("%v %+v", h.direct.binds(), status.DirectProxy)
	}
	if len(h.rendered) != 1 || !reflect.DeepEqual(h.rendered[0], map[string]contract.Class{"192.168.1.20": contract.Direct}) {
		t.Fatalf("profiles not re-rendered for the LAN: %v", h.rendered)
	}
	if l, e := h.c.socketLAN(); e != nil || l.String() != "192.168.1.1/24" {
		t.Fatalf("control socket LAN %v %v", l, e)
	}
	if len(status.IgnoredProfiles) != 1 || status.IgnoredProfiles[0].Client != "192.168.8.50" {
		t.Fatalf("%+v", status.IgnoredProfiles)
	}
	// A stable LAN never restarts the listener or re-renders the profile sets.
	for i := 0; i < 5; i++ {
		h.now = h.now.Add(lan.CacheTTL)
		h.tick()
	}
	if len(h.direct.binds()) != 1 || len(h.rendered) != 1 || h.direct.stopped != 0 {
		t.Fatalf("stable LAN churned: %v %d %d", h.direct.binds(), len(h.rendered), h.direct.stopped)
	}
}

// Regression (b) at runtime: the listener moves with the LAN, and a transient
// read failure afterwards keeps the running listener and its sessions.
func TestDirectListenerFollowsLANChange(t *testing.T) {
	useLAN(t, "192.168.1.1/24")
	dir := privateSettingsDir(t, lanSettings("192.168.1.1", `,"profiles":{"192.168.1.20":"direct","10.0.0.20":"games"}`))
	s, e := readSettingsAt(dir)
	if e != nil {
		t.Fatal(e)
	}
	h := newLANHarness(t, s, dir)
	h.tick()
	h.c.renderedLAN, h.c.vpnStarted = h.c.router, true
	useLAN(t, "10.0.0.1/24")
	h.now = h.now.Add(lan.CacheTTL)
	h.tick()
	status := h.c.Status()
	if !reflect.DeepEqual(h.direct.binds(), []string{"192.168.1.1:1080", "10.0.0.1:1080"}) || h.direct.stopped != 1 || status.DirectProxy.Config.Bind != "10.0.0.1" || status.DirectProxy.LAN != "10.0.0.1/24" {
		t.Fatalf("%v %d %+v", h.direct.binds(), h.direct.stopped, status.DirectProxy)
	}
	if len(h.rendered) != 1 || !reflect.DeepEqual(h.rendered[0], map[string]contract.Class{"10.0.0.20": contract.Games}) {
		t.Fatalf("%v", h.rendered)
	}
	failLAN(t)
	h.now = h.now.Add(lan.CacheTTL)
	h.tick()
	status = h.c.Status()
	if len(h.direct.binds()) != 2 || h.direct.stopped != 1 || !status.DirectProxy.Running || status.DirectProxy.LANError == "" || status.DirectProxy.Config.Bind != "10.0.0.1" {
		t.Fatalf("transient discovery failure restarted the listener: %v %+v", h.direct.binds(), status.DirectProxy)
	}
}

func lanAdmin(t *testing.T, settings string) *Controller {
	t.Helper()
	dir := privateSettingsDir(t, settings)
	s, e := readSettingsAt(dir)
	if e != nil {
		t.Fatal(e)
	}
	c := New(s)
	c.stateDir = dir
	c.registry = &profile.Registry{Version: 1}
	c.available = map[string]bool{"sing-box": true}
	c.validateEngine = func(context.Context, profile.Profile) error { return nil }
	return c
}

// Regression (d): changes through the API and the control socket keep the
// strict LAN check; a stale stored profile blocks nothing and can be removed.
func TestAPIRejectsNewProfileOutsideLAN(t *testing.T) {
	useLAN(t, "192.168.1.1/24")
	c := lanAdmin(t, lanSettings("192.168.1.1", `,"profiles":{"192.168.8.50":"games"}`))
	for _, ip := range []string{"192.168.8.20", "192.168.1.1", "192.168.1.0", "192.168.1.255", "8.8.8.8"} {
		if _, e := c.HandleAPI(control.APIRequest{Operation: "device", Client: ip, Value: "direct"}); e == nil {
			t.Fatalf("API accepted new profile %s", ip)
		}
	}
	c.deviceOps = &devicePolicyOps{
		block:  func(string, bool) error { t.Fatal("rejected change reached the dataplane"); return nil },
		update: func(map[string]contract.Class) error { return nil },
		clear:  func(string) error { return nil },
		save:   func(string, any) error { return nil },
	}
	for _, ip := range []string{"192.168.8.20", "192.168.1.1"} {
		if _, e := c.Handle(control.Request{Command: "profile", Client: ip, Value: "games"}); e == nil {
			t.Fatalf("control socket accepted new profile %s", ip)
		}
	}
	if _, e := c.HandleAPI(control.APIRequest{Operation: "device", Client: "192.168.1.20", Value: "games"}); e != nil {
		t.Fatal(e)
	}
	if _, e := c.HandleAPI(control.APIRequest{Operation: "settings", Settings: json.RawMessage(`{"direct_proxy":{"enabled":true,"bind":"192.168.1.1","port":1090}}`)}); e != nil {
		t.Fatalf("stale stored profile blocked an unrelated change: %v", e)
	}
	persisted, e := readSettingsAt(c.stateDir)
	if e != nil || persisted.Options.Profiles["192.168.1.20"] != contract.Games || persisted.Options.Profiles["192.168.8.50"] != contract.Games || persisted.DirectProxy.Port != 1090 {
		t.Fatalf("%+v %v", persisted.Options.Profiles, e)
	}
	if _, e := c.HandleAPI(control.APIRequest{Operation: "device", Client: "192.168.8.50", Value: "auto"}); e != nil {
		t.Fatalf("stale profile cannot be removed: %v", e)
	}
	if persisted, e = readSettingsAt(c.stateDir); e != nil || len(persisted.Options.Profiles) != 1 {
		t.Fatalf("%+v %v", persisted.Options.Profiles, e)
	}
}

// While the LAN is unknown no new profile or bind is accepted against the
// legacy fallback, but the direct proxy can still be switched off.
func TestAPIChangesWhileLANUnknown(t *testing.T) {
	failLAN(t)
	c := lanAdmin(t, lanSettings("192.168.1.1", ""))
	if _, e := c.HandleAPI(control.APIRequest{Operation: "device", Client: "192.168.8.20", Value: "games"}); e == nil {
		t.Fatal("profile accepted against the fallback LAN")
	}
	if _, e := c.HandleAPI(control.APIRequest{Operation: "settings", Settings: json.RawMessage(`{"direct_proxy":{"enabled":true,"bind":"192.168.8.1","port":1080}}`)}); e == nil {
		t.Fatal("bind changed while the LAN is unknown")
	}
	if _, e := c.HandleAPI(control.APIRequest{Operation: "settings", Settings: json.RawMessage(`{"direct_proxy":{"enabled":false,"bind":"192.168.1.1","port":1090}}`)}); e != nil {
		t.Fatal(e)
	}
	persisted, e := readSettingsAt(c.stateDir)
	if e != nil || persisted.DirectProxy != (control.DirectConfig{Enabled: false, Bind: "192.168.1.1", Port: 1090}) {
		t.Fatalf("%+v %v", persisted.DirectProxy, e)
	}
	status, e := c.HandleAPI(control.APIRequest{Operation: "status"})
	raw, _ := json.Marshal(status)
	if e != nil || !strings.Contains(string(raw), `"lan_error"`) {
		t.Fatalf("status lacks lan_error: %s %v", raw, e)
	}
}
