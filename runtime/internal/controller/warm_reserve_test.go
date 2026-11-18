package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/control"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
	"github.com/MyHeartRaces/FLR/runtime/internal/transport"
)

func TestWarmReserveSettingsDefaultOmittedCompletePatchNoChoiceAdvance(t *testing.T) {
	c := connectionAdmin(t)
	c.deactivate = func(string) error { t.Fatal("warm reserve patch reached native deactivation"); return nil }
	path := filepath.Join(c.stateDir, "settings.json")
	stored := func() []byte {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	effective := func() WarmReserve {
		data, err := c.HandleAPI(control.APIRequest{Operation: "settings"})
		if err != nil {
			t.Fatal(err)
		}
		s := data.(Settings)
		if s.WarmReserve == nil {
			t.Fatal("effective warm reserve not reported")
		}
		return *s.WarmReserve
	}
	patch := func(raw string) error {
		_, err := c.HandleAPI(control.APIRequest{Operation: "settings", Settings: json.RawMessage(raw)})
		return err
	}
	epoch := func() uint64 { c.mu.RLock(); defer c.mu.RUnlock(); return c.choiceEpoch }
	if bytes.Contains(stored(), []byte("warm_reserve")) || c.settings.WarmReserve != nil || effective() != DefaultWarmReserve() {
		t.Fatal("default warm reserve is not the omitted, effective default")
	}
	start := epoch()
	custom := WarmReserve{Enabled: false, IntervalSeconds: 60}
	if err := patch(`{"warm_reserve":{"enabled":false,"interval_seconds":60}}`); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(stored(), []byte(`"warm_reserve"`)) || effective() != custom {
		t.Fatal("non-default warm reserve not stored")
	}
	before := stored()
	for _, bad := range []string{
		`{"warm_reserve":{"enabled":true,"interval_seconds":5}}`,
		`{"warm_reserve":{"enabled":true,"interval_seconds":301}}`,
		`{"warm_reserve":null}`,
		`{"warm_reserve":{"enabled":true,"interval_seconds":30,"unknown":1}}`,
		`{"warm_reserve":{"enabled":true}}`,
		`{"warm_reserve":{"interval_seconds":30}}`,
		`{"warm_reserve":{"enabled":null,"interval_seconds":30}}`,
		`{"warm_reserve":{"enabled":true,"interval_seconds":30.5}}`,
		`{"enabled":false,"warm_reserve":{"enabled":true,"interval_seconds":5}}`,
	} {
		if patch(bad) == nil {
			t.Fatal("invalid warm reserve accepted", bad)
		}
		if !bytes.Equal(before, stored()) || effective() != custom || !c.settings.Enabled {
			t.Fatal("rejected warm reserve patch changed settings", bad)
		}
	}
	if err := patch(`{"warm_reserve":{"enabled":true,"interval_seconds":30}}`); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored(), []byte("warm_reserve")) || c.settings.WarmReserve != nil || effective() != DefaultWarmReserve() {
		t.Fatal("default warm reserve left a stored key")
	}
	if epoch() != start {
		t.Fatal("warm reserve change advanced the choice epoch and would retire live paths")
	}
	explicit := bytes.Replace(stored(), []byte(`"version": 2,`), []byte(`"warm_reserve": {"enabled": true, "interval_seconds": 30}, "version": 2,`), 1)
	if bytes.Equal(explicit, stored()) {
		t.Fatal("fixture did not insert an explicit default")
	}
	if decoded, err := DecodeSettings(explicit); err != nil || decoded.WarmReserve != nil {
		t.Fatal("explicit default not normalized to the omitted form", err)
	}

	legacy := testAdmin(t)
	if data, err := legacy.HandleAPI(control.APIRequest{Operation: "settings"}); err != nil || data.(Settings).WarmReserve != nil {
		t.Fatal("legacy settings report a warm reserve", err)
	}
	if _, err := legacy.HandleAPI(control.APIRequest{Operation: "settings", Settings: json.RawMessage(`{"warm_reserve":{"enabled":false,"interval_seconds":60}}`)}); err == nil {
		t.Fatal("legacy settings accepted a warm reserve")
	}
}

func TestRoundWarmsReserveWithoutPublishingOrClearing(t *testing.T) {
	c := connectionProbeAdmin(t, nil)
	b := &connectionTestBackend{}
	m := transport.New(b, func(context.Context, profile.Profile) health.Result {
		return health.Result{Measured: true, TCP: true, UDP: true}
	}, func() error { t.Error("warm reserve used the full quiesce"); return nil })
	m.SetAWGBackend(&continuityAWG{good: true})
	m.SetChannelCleanup(c.quiesceChannel)
	m.SetDecisionRecorder(c.recordDecision)
	c.transports = m
	c.vpnStarted = true
	published := []contract.Selection{}
	c.publishSelection = func(s contract.Selection) error { published = append(published, s); return nil }
	clears := []string{}
	c.clearAWG = func() error { clears = append(clears, "awg"); return nil }
	c.clearSlot = func() error { clears = append(clears, "slot"); return nil }
	native := contract.Selection{General: contract.AWG, Games: contract.AWG}

	// Install the native default with the warm reserve off: the cold behaviour.
	c.settings.WarmReserve = &WarmReserve{Enabled: false, IntervalSeconds: 30}
	c.round(c.ctx)
	s := c.Status()
	if s.ActiveConnection == nil || s.ActiveConnection.Family != "awg" || s.Proxy.ReserveConnection != nil || b.Alive() {
		t.Fatal("fixture did not settle on native AWG alone", s.Proxy)
	}
	if len(published) != 1 || published[0] != native {
		t.Fatal("fixture published an unexpected route", published)
	}
	published, clears = nil, nil
	decisions := len(c.history.Export().Decisions)

	c.settings.WarmReserve = nil // effective default: on, 30 s
	// The standby starts in the background; a later round adopts and publishes it.
	roundsUntilReserve(t, c)
	for i := 0; i < 2; i++ {
		c.round(c.ctx)
	}
	candidates, err := connection.Candidates(c.connections, c.settings.Selection, c.settings.Order)
	if err != nil {
		t.Fatal(err)
	}
	want := ""
	for _, item := range candidates {
		if item.Family != "awg" && item.Profile != nil && item.Profile.Capabilities.UDP {
			want = item.ID
			break
		}
	}
	s = c.Status()
	if !b.Alive() || s.Proxy.ReserveConnection == nil || s.Proxy.ReserveConnection.ID != want || !s.Proxy.ReserveWarm {
		t.Fatal("round did not keep the first UDP proxy as a warm reserve", s.Proxy)
	}
	if s.Selection != native || s.ActiveConnection == nil || s.ActiveConnection.Family != "awg" || s.Proxy.Pending {
		t.Fatal("warm reserve changed the published default", s.Selection, s.Proxy)
	}
	if len(published) != 0 || len(clears) != 0 {
		t.Fatal("warm reserve republished routes or cleared flows", published, clears)
	}
	if gecko := s.Channels[contract.Gecko]; !gecko.Up || gecko.LastCheck.IsZero() {
		t.Fatal("warm reserve measurement not visible", gecko)
	}
	added := c.history.Export().Decisions[decisions:]
	if len(added) != 1 || added[0].Reason != "warm_reserve" || added[0].Outcome != "applied" || added[0].To.ID != want {
		t.Fatal("warm reserve decision missing or accompanied by route changes", added)
	}

	// Turning it off retires only the sessionless standby: no route change and
	// no flow cleanup at all, since it never carried flows.
	c.settings.WarmReserve = &WarmReserve{Enabled: false, IntervalSeconds: 30}
	c.round(c.ctx)
	s = c.Status()
	if b.Alive() || s.Proxy.ReserveConnection != nil || s.Proxy.ReserveWarm || s.Selection != native || len(published) != 0 {
		t.Fatal("disabling the warm reserve disturbed the default", s.Proxy, published)
	}
	if len(clears) != 0 {
		t.Fatal("standby retirement cleared flows it never carried", clears)
	}
}

// roundsUntilReserve runs rounds until the background standby admission has
// been adopted and published.
func roundsUntilReserve(t *testing.T, c *Controller) Status {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		c.round(c.ctx)
		if s := c.Status(); s.Proxy.ReserveConnection != nil {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatal("warm reserve never published", c.Status().Proxy)
		}
		time.Sleep(time.Millisecond)
	}
}

// blockingStartBackend hangs in Start until released, ignoring cancellation
// like a firewall restart would.
type blockingStartBackend struct {
	connectionTestBackend
	release chan struct{}
	started chan struct{}
	once    sync.Once
}

func (b *blockingStartBackend) Start(ctx context.Context, p profile.Profile) error {
	b.once.Do(func() { close(b.started) })
	<-b.release
	return b.connectionTestBackend.Start(ctx, p)
}

type countingContinuityAWG struct {
	*continuityAWG
	probes int
}

func (a *countingContinuityAWG) Probe(ctx context.Context) health.Result {
	a.probes++
	return a.continuityAWG.Probe(ctx)
}

// A standby start that hangs does not hold the round: native AWG is probed
// every round and the published default is unchanged until the standby
// qualifies, after which it is published as a warm reserve.
func TestRoundDoesNotWaitForWarmAdmission(t *testing.T) {
	c := connectionProbeAdmin(t, nil)
	b := &blockingStartBackend{release: make(chan struct{}), started: make(chan struct{})}
	m := transport.New(b, func(context.Context, profile.Profile) health.Result {
		return health.Result{Measured: true, TCP: true, UDP: true}
	}, func() error { return nil })
	m.StepTimeout = time.Minute // the test, not the start budget, ends the start
	awg := &countingContinuityAWG{continuityAWG: &continuityAWG{good: true}}
	m.SetAWGBackend(awg)
	m.SetChannelCleanup(c.quiesceChannel)
	m.SetDecisionRecorder(c.recordDecision)
	c.transports = m
	c.vpnStarted = true
	c.clearAWG = func() error { return nil }
	c.clearSlot = func() error { return nil }
	native := contract.Selection{General: contract.AWG, Games: contract.AWG}
	c.round(c.ctx)
	select {
	case <-b.started:
	case <-time.After(2 * time.Second):
		t.Fatal("standby start never began")
	}
	for i := 0; i < 3; i++ {
		before := awg.probes
		begin := time.Now()
		c.round(c.ctx)
		if elapsed := time.Since(begin); elapsed > time.Second {
			t.Fatal("round waited for the standby start", elapsed)
		}
		s := c.Status()
		if awg.probes != before+1 || s.Selection != native || s.Proxy.ReserveConnection != nil || s.Proxy.Pending {
			t.Fatal("native AWG not probed every round while the standby starts", awg.probes-before, s.Proxy)
		}
	}
	close(b.release)
	s := roundsUntilReserve(t, c)
	if !s.Proxy.ReserveWarm || s.Selection != native || !b.Alive() {
		t.Fatal("qualified standby not published as a warm reserve", s.Proxy)
	}
	if err := m.Shutdown(); err != nil || b.Alive() {
		t.Fatal("shutdown left the standby running", err)
	}
}

// The published flag never outlives the reserve it describes, including when
// the controller drops a reserve that is the actual default or clears the slot.
func TestPublishedReserveWarmFollowsReserve(t *testing.T) {
	c := New(Settings{Version: 2})
	c.publishSelection = func(contract.Selection) error { return nil }
	h := &connection.Summary{ID: "h", Family: "hy2", Revision: "r"}
	next := transport.Snapshot{Generation: c.choiceEpoch, Selection: contract.Selection{General: contract.Gecko, Games: contract.Gecko}, ActiveConnection: h, ReserveConnection: h, ReserveWarm: true}
	c.publishTransport(transport.Snapshot{}, next)
	if s := c.Status(); s.Proxy.ReserveConnection != nil || s.Proxy.ReserveWarm {
		t.Fatal("default still reported as a warm reserve", s.Proxy)
	}
	c.vpnStarted = true
	c.clearSlot = func() error { return nil }
	c.selection = contract.Selection{General: contract.AWG, Games: contract.AWG}
	c.transportState.ReserveConnection, c.transportState.ReserveWarm = h, true
	if err := c.quiesceChannel(contract.Gecko, "warm_reserve"); err != nil {
		t.Fatal(err)
	}
	if s := c.Status(); s.Proxy.ReserveConnection != nil || s.Proxy.ReserveWarm || s.Selection.General != contract.AWG {
		t.Fatal("slot cleanup left a warm reserve flag or changed the default", s.Proxy)
	}
}
