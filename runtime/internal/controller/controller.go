package controller

import (
	"context"
	"fmt"
	"github.com/MyHeartRaces/FLR/runtime/internal/bypass"
	"github.com/MyHeartRaces/FLR/runtime/internal/config"
	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/control"
	"github.com/MyHeartRaces/FLR/runtime/internal/dataplane"
	"github.com/MyHeartRaces/FLR/runtime/internal/diagnostic"
	dnsbroker "github.com/MyHeartRaces/FLR/runtime/internal/dns"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"github.com/MyHeartRaces/FLR/runtime/internal/lan"
	"github.com/MyHeartRaces/FLR/runtime/internal/native"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
	"github.com/MyHeartRaces/FLR/runtime/internal/qos"
	"github.com/MyHeartRaces/FLR/runtime/internal/transport"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Transition struct {
	Selection contract.Selection
	Failed    []contract.Channel
}

func PlanTransition(old, next map[contract.Channel]health.State, manual contract.Channel) Transition {
	t := Transition{Selection: health.Select(next, manual)}
	for _, c := range []contract.Channel{contract.AWG, contract.Gecko, contract.VLESS} {
		a, b := old[c], next[c]
		if (a.Healthy() && !b.Healthy()) || (a.Failures < 3 && b.Failures >= 3) {
			t.Failed = append(t.Failed, c)
		}
	}
	return t
}

type Status struct {
	Diagnostics         diagnostic.Summary        `json:"diagnostics"`
	ConnectionTest      *ConnectionTestResult     `json:"connection_test,omitempty"`
	Requested           connection.Selection      `json:"requested"`
	ActiveConnection    *connection.Summary       `json:"active_connection,omitempty"`
	Proxy               transport.Snapshot        `json:"proxy"`
	DirectBypassRunning bool                      `json:"direct_bypass_running"`
	Version             string                    `json:"version"`
	Selection           contract.Selection        `json:"selection"`
	ManualGames         string                    `json:"manual_games"`
	Generation          uint64                    `json:"generation"`
	TestClient          string                    `json:"test_client,omitempty"`
	DNSPort             string                    `json:"dns_port"`
	Profiles            map[string]contract.Class `json:"profiles,omitempty"`
	// IgnoredProfiles are stored device profiles that are not rendered because
	// their address is not a client of the router's current LAN.
	IgnoredProfiles []dataplane.IgnoredProfile        `json:"ignored_profiles,omitempty"`
	DirectProxy     control.DirectStatus              `json:"direct_proxy"`
	DirectSession   *control.Session                  `json:"direct_session,omitempty"`
	Channels        map[contract.Channel]health.State `json:"channels"`
	Updated         time.Time                         `json:"updated"`
	LastError       string                            `json:"last_error,omitempty"`
}
type Controller struct {
	history               *diagnostic.History
	wan                   *diagnostic.WAN
	historyPath           string
	diagnosticSavePending atomic.Bool

	mu                    sync.RWMutex
	adminMu               sync.Mutex
	stateDir              string
	registry              *profile.Registry
	connections           *connection.Registry
	available             map[string]bool
	validateEngine        func(context.Context, profile.Profile) error
	deviceOps             *devicePolicyOps
	deactivate            func(string) error
	deactivationPending   bool
	recoveryPending       func() bool
	transports            *transport.Manager
	activeProfile         *profile.Summary
	activeConnection      *connection.Summary
	transportState        transport.Snapshot
	choiceEpoch           uint64
	writeConnectionState  func(string, []byte) error
	activateVPN           func(context.Context, Settings, *connection.Connection) error
	captureTestAWG        func(context.Context) (config.AWGOwnedState, error)
	restoreTestAWG        func(context.Context, config.AWGOwnedState) error
	connectionTestTimeout time.Duration
	testOverride          *connection.Selection
	testCancel            context.CancelFunc
	testStatus            *ConnectionTestResult
	testGuard             *connectionTestGuard
	testWorkers           sync.WaitGroup
	live                  bool
	vpnStarted            bool
	vpnRestart            bool
	vpnDone               chan struct{}
	vpnCancel             context.CancelFunc
	settings              Settings
	states                map[contract.Channel]health.State
	selection             contract.Selection
	generation            uint64
	manual                contract.Channel
	lastError             string
	awgCleanupPending     bool
	publishSelection      func(contract.Selection) error
	clearAWG              func() error
	clearSlot             func() error
	policy                *policy.Policy
	bypass                *bypass.Manager
	bypassRunning         bool
	direct                *control.DirectServer
	directConfig          control.DirectConfig
	directLAN             lan.LAN
	// directDeps are the listener hooks; WAN and LAN are filled per reconcile.
	directDeps control.DirectDeps
	// lanCache bounds br-lan reads. router is the last discovered LAN (zero
	// until discovery first succeeds) and routerErr the current discovery
	// failure. renderedLAN is the LAN the device profile sets were rendered for.
	lanCache       *lan.Cache
	router         lan.LAN
	routerErr      string
	renderedLAN    lan.LAN
	renderProfiles func(map[string]contract.Class) error
	broker         *dnsbroker.Broker
	// basePolicy is the installed policy; policy is its view for appliedMode
	// (Settings.RoutingMode). applyStaticSets is replaced in tests.
	basePolicy      *policy.Policy
	appliedMode     string
	applyStaticSets func(*policy.Policy) error
	// roamSuspended mirrors what was last passed to SetRoamSuspended (held
	// while a connection test runs). Guarded by adminMu.
	roamSuspended bool
	// queueing keeps CAKE on the AWG tunnel (Settings.TunnelQoS).
	queueing *qos.Manager
	sessions *control.Manager
	ctx      context.Context
	refresh  chan struct{}
}

func New(s Settings) *Controller {
	generation := uint64(1)
	if s.Version == 2 && s.SavedGeneration > 0 {
		generation = s.SavedGeneration
	}
	c := &Controller{history: newHistory(), settings: s, states: map[contract.Channel]health.State{}, selection: contract.Selection{General: contract.Down, Games: contract.Down}, generation: generation, choiceEpoch: 1, manual: contract.Down, refresh: make(chan struct{}, 1), lanCache: lan.NewCache(), renderProfiles: dataplane.UpdateProfiles}
	c.deviceOps = &devicePolicyOps{dataplane.BlockDevice, c.updateProfiles, dataplane.ClearDevice, WriteJSON}
	c.initializeWAN()
	return c
}

// resolveLAN returns the router LAN through the controller's cache. A non-nil
// error means discovery failed; the LAN is then zero, never the legacy
// fallback, so callers cannot mistake it for the real LAN.
func (c *Controller) resolveLAN(o dataplane.Options) (lan.LAN, error) {
	if !o.Net.IsZero() {
		return o.Net, o.Net.Validate()
	}
	var l lan.LAN
	var e error
	if c.lanCache != nil {
		l, e = c.lanCache.Resolve(o.LAN)
	} else {
		l, e = lan.Resolve(o.LAN)
	}
	if e != nil {
		return lan.LAN{}, e
	}
	return l, nil
}

// socketLAN is the per-request LAN of the control socket, which serves
// outside the admin lock.
func (c *Controller) socketLAN() (lan.LAN, error) {
	c.mu.RLock()
	o := c.settings.Options
	c.mu.RUnlock()
	return c.resolveLAN(o)
}

// refreshLAN re-reads the router LAN (through the cache). A successful read
// becomes the controller's LAN and so the direct proxy bind in use, which
// always follows the router's own address (effectiveDirect). The stored
// settings are not touched. A failure is reported and the last discovered
// LAN, if any, stays in use, so a transient read error restarts nothing.
// Callers hold adminMu.
func (c *Controller) refreshLAN() {
	router, err := c.resolveLAN(c.settings.Options)
	c.mu.Lock()
	if err != nil {
		c.routerErr = err.Error()
	} else {
		c.router, c.routerErr = router, ""
	}
	known := c.router
	c.mu.Unlock()
	if c.broker != nil && !known.IsZero() {
		c.broker.SetRouter(known.Addr)
	}
}

// effectiveDirect is the direct proxy configuration in use: the stored one
// with its bind replaced by the router's discovered LAN address, once known.
// The stored bind stays as loaded from disk (see storedDirectDefault); no
// save, a direct_proxy change included, persists the discovered address.
// Callers hold c.mu (read or write) or adminMu.
func (c *Controller) effectiveDirect() control.DirectConfig {
	d := c.settings.DirectProxy
	if !c.router.IsZero() {
		d.Bind = c.router.Addr.String()
	}
	return d
}

// updateProfiles renders the device profiles of the current LAN and records
// that LAN; profiles outside it are skipped (see Status.IgnoredProfiles).
// Callers hold c.mu.
func (c *Controller) updateProfiles(profiles map[string]contract.Class) error {
	active, _ := dataplane.ActiveProfiles(profiles, c.router)
	render := c.renderProfiles
	if render == nil {
		render = dataplane.UpdateProfiles
	}
	if e := render(active); e != nil {
		return e
	}
	c.renderedLAN = c.router
	return nil
}

// syncProfiles re-renders the device profile sets when the router LAN differs
// from the LAN they were rendered for, i.e. only after the LAN appeared or
// changed; on a stable LAN it does nothing. Failures retry on later ticks.
func (c *Controller) syncProfiles() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.router.IsZero() || c.router == c.renderedLAN {
		return
	}
	if e := c.updateProfiles(c.settings.Options.Profiles); e != nil {
		c.lastError = "device profiles not updated for router LAN " + c.router.String() + "; retrying"
	}
}

// checkDeviceChange is the strict LAN check for a requested device profile:
// a new class needs a client of the current LAN (never the router, network or
// broadcast address). Removal needs only a private IPv4 address, so a profile
// left outside the LAN by a LAN change can still be deleted.
func (c *Controller) checkDeviceChange(client, value string) error {
	ip, e := netip.ParseAddr(client)
	if e != nil || !ip.Is4() || !ip.IsPrivate() {
		return fmt.Errorf("device needs a private LAN IPv4 address")
	}
	if value == "auto" {
		return nil
	}
	c.mu.RLock()
	router, routerErr := c.router, c.routerErr
	c.mu.RUnlock()
	if routerErr != "" || router.IsZero() {
		return fmt.Errorf("router LAN unknown; device profile not changed (%s)", routerErr)
	}
	if !router.IsClient(ip) {
		return fmt.Errorf("device %s is not a host of router LAN %s", client, router)
	}
	return nil
}

// checkDirectChange is the strict check for a direct proxy configuration sent
// through the API: the bind must be the router's own LAN address. While the
// LAN is unknown only enabled and port may change; the bind must then be the
// one in use (the last discovered address, or the stored one).
func (c *Controller) checkDirectChange(next control.DirectConfig) error {
	c.mu.RLock()
	router, routerErr, current := c.router, c.routerErr, c.effectiveDirect()
	c.mu.RUnlock()
	if routerErr == "" && !router.IsZero() {
		return control.ValidateDirect(next, router)
	}
	if next.Bind != current.Bind {
		return fmt.Errorf("router LAN unknown; the direct proxy bind cannot change until it is discovered (%s)", routerErr)
	}
	return control.ValidateDirectShape(next)
}
func (c *Controller) DNSRoute(_ contract.Class) (contract.Channel, uint64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.selection.General, c.generation
}
func (c *Controller) ClientView(client, name string) (dnsbroker.View, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	profile, ok := c.settings.Options.Profiles[client]
	if !ok {
		return dnsbroker.View{}, false
	}
	class, source := c.policy.DomainDecision(name)
	if class != contract.Local {
		switch profile {
		case contract.Direct, contract.General:
			class = profile
			source = "device-profile"
		case contract.Games:
			if source != "vpn-required" && source != "direct-essential" {
				class = contract.Games
				source = "device-profile"
			}
		}
	}
	return dnsbroker.View{ID: "device:" + client + ":" + string(class), Class: class, Source: source, Channel: c.selection.General, Generation: c.generation}, true
}
func (c *Controller) Status() Status {
	c.mu.RLock()
	channels := map[contract.Channel]health.State{}
	for k, v := range c.states {
		channels[k] = v
	}
	profiles := map[string]contract.Class{}
	for k, v := range c.settings.Options.Profiles {
		profiles[k] = v
	}
	manual := "auto"
	if c.manual == contract.VLESS {
		manual = "vless"
	}
	s := Status{DirectBypassRunning: c.bypassRunning, Version: "0.7-runtime", Selection: c.selection, ManualGames: manual, Generation: c.generation, TestClient: c.settings.Options.TestClient, DNSPort: c.settings.DNSPort, Profiles: profiles, Channels: channels, Updated: time.Now(), LastError: c.lastError}
	s.Requested = c.settings.Selection
	s.Proxy = c.transportState
	if c.history != nil {
		s.Diagnostics = c.history.Summary(c.wan.Snapshot())
		s.Diagnostics.SnapshotPending = c.diagnosticSavePending.Load()
	}
	if c.testStatus != nil {
		copy := *c.testStatus
		s.ConnectionTest = &copy
	}
	if c.activeConnection != nil {
		copy := *c.activeConnection
		copy.Capabilities.RequiredComponents = append([]string{}, copy.Capabilities.RequiredComponents...)
		s.ActiveConnection = &copy
	}
	_, s.IgnoredProfiles = dataplane.ActiveProfiles(c.settings.Options.Profiles, c.router)
	s.DirectProxy = control.DirectStatus{Config: c.effectiveDirect()}
	if c.direct != nil {
		s.DirectProxy = c.direct.Status()
	}
	if s.DirectProxy.LAN == "" && !c.router.IsZero() {
		s.DirectProxy.LAN = c.router.String()
	}
	if c.routerErr != "" {
		s.DirectProxy.LANError = c.routerErr
		if c.direct == nil && s.DirectProxy.Config.Enabled && s.DirectProxy.Error == "" {
			s.DirectProxy.Error = "router LAN unknown; the direct listener waits for LAN discovery"
		}
	}
	c.mu.RUnlock()
	if c.sessions != nil {
		s.DirectSession = c.sessions.Current()
	}
	return s
}
func (c *Controller) Handle(r control.Request) (any, error) {
	switch r.Command {
	case "status":
		return c.Status(), nil
	case "refresh":
		select {
		case c.refresh <- struct{}{}:
		default:
		}
		return map[string]bool{"scheduled": true}, nil
	case "games":
		return nil, fmt.Errorf("use API select for managed profiles")
	case "profile":
		c.refreshLAN()
		if e := c.checkDeviceChange(r.Client, r.Value); e != nil {
			return nil, e
		}
		return c.handleDevice(r.Client, r.Value)
	case "direct-session":
		mac, e := control.Lease(r.Client)
		if e != nil {
			return nil, e
		}
		ttl, e := time.ParseDuration(r.TTL)
		if e != nil {
			return nil, e
		}
		return c.sessions.Start(c.ctx, time.Now(), r.Client, mac, ttl)
	case "direct-stop":
		e := c.sessions.Stop()
		return map[string]bool{"closed": e == nil}, e
	}
	return nil, fmt.Errorf("unknown command")
}

// quiesceSlot runs before every replacement. Old AWG connection marks are
// unaffected; only the reusable imported slot is invalidated.
func (c *Controller) quiesceSlot() error {
	if !c.vpnStarted {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	down := contract.Selection{General: contract.Down, Games: contract.Down}
	if e := dataplane.UpdateSelection(down, false); e != nil {
		return e
	}
	c.selection = down
	c.activeProfile = nil
	c.generation++
	return dataplane.ClearSlot()
}

func (c *Controller) quiesceConnections() error {
	if !c.vpnStarted {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	from := c.activeConnection
	down := contract.Selection{General: contract.Down, Games: contract.Down}
	publish := c.publishSelection
	if publish == nil {
		publish = func(s contract.Selection) error { return dataplane.UpdateSelection(s, false) }
	}
	err := publish(down)
	if err == nil {
		c.selection = down
		c.activeProfile = nil
		c.activeConnection = nil
		c.transportState.Selection = down
		c.transportState.ActiveConnection = nil
		c.transportState.Active = nil
		c.transportState.Pending = true
		c.transportState.Reason = "connection transition pending"
		c.generation++
	}
	c.recordCleanup("selection", "nft", contract.Down, from, err)
	if err != nil {
		return err
	}
	clear := c.clearAWG
	if clear == nil {
		clear = dataplane.ClearAWG
	}
	err = clear()
	c.recordCleanup("selection", "conntrack", contract.AWG, from, err)
	if err != nil {
		return err
	}
	clear = c.clearSlot
	if clear == nil {
		clear = dataplane.ClearSlot
	}
	err = clear()
	c.recordCleanup("selection", "conntrack", contract.Gecko, from, err)
	return err
}

func (c *Controller) quiesceChannel(channel contract.Channel, reason string) error {
	if !c.vpnStarted {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	next := c.selection
	affected := next.General == channel || next.Games == channel
	if next.General == channel {
		next.General = contract.Down
	}
	if next.Games == channel {
		next.Games = contract.Down
	}
	if next != c.selection {
		publish := c.publishSelection
		if publish == nil {
			publish = func(s contract.Selection) error { return dataplane.UpdateSelection(s, false) }
		}
		err := publish(next)
		c.recordDecision(diagnostic.Decision{At: time.Now(), Epoch: c.choiceEpoch, From: summaryIdentity(c.activeConnection), Reason: reason, Stage: "nft", Channel: channel, Outcome: operationOutcome(err)})
		if err != nil {
			return err
		}
		c.selection = next
	}
	c.generation++
	if affected {
		c.activeProfile = nil
		c.activeConnection = nil
		c.transportState.Active = nil
		c.transportState.ActiveConnection = nil
		c.transportState.Pending = true
		c.transportState.Reason = reason
	}
	c.transportState.Selection = next
	if channel == contract.Gecko {
		c.transportState.ReserveConnection = nil
		c.transportState.ReserveWarm = false
		clear := c.clearSlot
		if clear == nil {
			clear = dataplane.ClearSlot
		}
		err := clear()
		c.recordDecision(diagnostic.Decision{At: time.Now(), Epoch: c.choiceEpoch, Reason: reason, Stage: "conntrack", Channel: channel, Outcome: operationOutcome(err)})
		return err
	}
	if channel == contract.AWG {
		clear := c.clearAWG
		if clear == nil {
			clear = dataplane.ClearAWG
		}
		err := clear()
		c.recordDecision(diagnostic.Decision{At: time.Now(), Epoch: c.choiceEpoch, Reason: reason, Stage: "conntrack", Channel: channel, Outcome: operationOutcome(err)})
		return err
	}
	return fmt.Errorf("unsupported cleanup channel")
}
func (c *Controller) round(ctx context.Context) {
	c.adminMu.Lock()
	defer c.adminMu.Unlock()
	if !c.settings.Enabled || c.transports == nil {
		return
	}
	if c.testOverride != nil || (c.testStatus != nil && c.testStatus.Phase == "recovery-pending") {
		return
	}
	if e := c.transports.SetHealthPolicy(c.settings.HealthPolicy); e != nil {
		return
	}
	// Settings validation bounds the interval; a rejected policy only turns the
	// warm reserve off, which is the cold-start behaviour.
	c.transports.SetWarmReserve(c.settings.warmPolicy())
	if c.historyPath != "" {
		lifetime := c.ctx
		if lifetime == nil {
			lifetime = ctx
		}
		c.wan.Start(lifetime)
	}
	before := c.transports.Snapshot()
	var next transport.Snapshot
	if c.settings.Version == 2 {
		c.mu.RLock()
		testing := c.testGuard != nil
		c.mu.RUnlock()
		if testing != c.roamSuspended {
			c.transports.SetRoamSuspended(testing)
			c.roamSuspended = testing
		}
		next = c.transports.StepConnections(ctx, time.Now(), c.connections, c.settings.Selection, c.settings.Order, c.choiceEpoch)
	} else {
		result := health.Result{}
		present := health.Present(contract.AWG)
		if present {
			result = health.Probe(ctx, contract.AWG)
		}
		next = c.transports.Step(ctx, time.Now(), result, present, c.registry, c.settings.PrimaryGroup, c.settings.ProfileSelection)
	}
	c.publishTransport(before, next)
	c.recordRound(next)
	// The warm reserve runs only after the default has been published. It only
	// launches a standby start in the background (a later StepConnections adopts
	// it; a failover whose first proxy candidate it is waits for it within the
	// round's budget; a failover to another proxy, a new choice, disable or
	// shutdown cancels it) or retires a standby, so a round with a healthy
	// default never waits for a reserve start or probe and AWG keeps its probe
	// cadence. It never changes the selection, so the second publication is
	// map-only bookkeeping.
	if c.settings.Version == 2 {
		c.mu.RLock()
		published := !c.transportState.Pending
		c.mu.RUnlock()
		if published {
			if warmed, changed := c.transports.StepWarmReserve(ctx, time.Now(), c.connections, c.settings.Selection, c.settings.Order, c.choiceEpoch); changed {
				c.publishTransport(next, warmed)
				next = warmed
			}
		}
	}
	if before.AWG.Up != next.AWG.Up || before.AWG.Reason != next.AWG.Reason || before.Slot.Up != next.Slot.Up || before.LastError != next.LastError {
		c.saveDiagnostics()
	}
}

// warmPolicy is the effective warm reserve for the transport manager; the
// legacy (v1) step has no reserve slot and always runs cold.
func (s Settings) warmPolicy() transport.WarmPolicy {
	w := s.EffectiveWarmReserve()
	return transport.WarmPolicy{Enabled: s.Version == 2 && w.Enabled, Interval: time.Duration(w.IntervalSeconds) * time.Second}
}

// A lost AWG must retire its old flows before publishing a backup. Remember
// partial failures independently of the manager's health transition for retry.
func (c *Controller) publishTransport(before, next transport.Snapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.settings.Version == 2 && next.Generation != c.choiceEpoch {
		return
	}
	from := c.activeConnection
	c.transportState = next
	defer func() {
		c.transportState.Selection = c.selection
		c.transportState.ActiveConnection = c.activeConnection
		c.transportState.Active = c.activeProfile
		if c.transportState.ReserveConnection != nil && c.activeConnection != nil && c.transportState.ReserveConnection.ID == c.activeConnection.ID && c.transportState.ReserveConnection.Revision == c.activeConnection.Revision {
			c.transportState.ReserveConnection = nil
		}
		if c.transportState.ReserveConnection == nil {
			c.transportState.ReserveWarm = false
		}
		if c.transportState.Pending {
			c.transportState.DesiredConnection = next.ActiveConnection
			desired := next.Selection
			c.transportState.DesiredSelection = &desired
		}
	}()
	c.states = map[contract.Channel]health.State{contract.AWG: next.AWG, contract.Gecko: next.Slot}
	if next.Pending {
		c.lastError = next.LastError
		return
	}
	soft := c.settings.Version == 2 && next.AWG.Degraded
	if (before.AWG.Healthy() && !next.AWG.Healthy() && !soft) || (before.AWG.Failures < 3 && next.AWG.Failures >= 3) {
		c.awgCleanupPending = true
	}
	publish := c.publishSelection
	if publish == nil {
		publish = func(s contract.Selection) error { return dataplane.UpdateSelection(s, false) }
	}
	set := func(s contract.Selection) error {
		if s == c.selection {
			return nil
		}
		if e := publish(s); e != nil {
			return e
		}
		c.selection = s
		c.generation++
		return nil
	}
	if c.awgCleanupPending {
		down := c.selection
		if down.General == contract.AWG {
			down.General = contract.Down
		}
		if down.Games == contract.AWG {
			down.Games = contract.Down
		}
		if e := set(down); e != nil {
			c.lastError = "selection update failed; AWG cleanup pending"
			c.transportState.Pending = true
			c.transportState.Reason = "publication_pending"
			c.recordPublication(from, next, "nft", "failed")
			return
		}
		if c.selection.General == contract.Down {
			c.activeProfile = nil
			c.activeConnection = nil
		}
		clear := c.clearAWG
		if clear == nil {
			clear = dataplane.ClearAWG
		}
		if e := clear(); e != nil {
			c.lastError = "AWG cleanup failed; retry pending"
			c.transportState.Pending = true
			c.transportState.Reason = "cleanup_pending"
			c.recordPublication(from, next, "conntrack", "failed")
			return
		}
		c.recordPublication(from, next, "conntrack", "applied")
		c.awgCleanupPending = false
	}
	if e := set(next.Selection); e != nil {
		c.lastError = "selection update failed"
		c.transportState.Pending = true
		c.transportState.Reason = "publication_pending"
		c.recordPublication(from, next, "nft", "failed")
		return
	}
	c.activeProfile = next.Active
	c.activeConnection = next.ActiveConnection
	if summaryIdentity(from) != summaryIdentity(next.ActiveConnection) || before.Selection != next.Selection {
		c.recordPublication(from, next, "nft", "applied")
	}
	c.lastError = next.LastError
}

// startVPN is separate from the controller API lifetime. A clean-image direct
// listener can use the controller without installing VPN guards or DNS redirects.
func (c *Controller) startVPN(ctx context.Context, p *policy.Policy, done chan<- error) error {
	// The VPN starts with the view of the stored routing mode.
	if p != nil {
		mode := c.settings.EffectiveRoutingMode()
		if c.basePolicy == nil {
			c.basePolicy = p
		}
		p = c.basePolicy.ForMode(mode)
		c.mu.Lock()
		c.policy, c.appliedMode = p, mode
		c.mu.Unlock()
	}
	if e := dataplane.ClearSession(); e != nil {
		return e
	}
	snap, e := dataplane.CurrentSnapshot()
	if e != nil {
		return e
	}
	b, e := c.vpnBatch(p, snap.TableExists)
	if e != nil {
		return e
	}
	if e = dataplane.Apply(b); e != nil {
		return e
	}
	c.mu.Lock()
	c.renderedLAN = b.LAN
	c.mu.Unlock()
	o := b.Options
	if e = dataplane.ConfigureDNS(c.settings.DNSPort, o.TestClient); e != nil {
		return e
	}
	broker := dnsbroker.New(p, c, dnsbroker.NewKernelMappings())
	broker.LocalPort = c.settings.LocalDNSPort
	broker.WAN = o.WAN
	if !c.router.IsZero() {
		broker.Router = c.router.Addr
	}
	c.broker = broker
	vpnCtx, cancel := context.WithCancel(ctx)
	c.vpnCancel = cancel
	c.vpnDone = make(chan struct{})
	address := "0.0.0.0:" + c.settings.DNSPort
	go func() {
		err := broker.Serve(vpnCtx, address)
		close(c.vpnDone)
		if err != nil && vpnCtx.Err() == nil {
			done <- err
		}
	}()
	quiesce := c.quiesceSlot
	if c.settings.Version == 2 {
		quiesce = c.quiesceConnections
	}
	c.transports = transport.New(&transport.ProcessBackend{WAN: o.WAN}, func(ctx context.Context, p profile.Profile) health.Result {
		return health.ProbeCapabilities(ctx, contract.Gecko, p.Capabilities.UDP)
	}, quiesce)
	c.roamSuspended = false
	if c.settings.Version == 2 {
		c.transports.SetAWGBackend(transport.NativeAWG{WAN: o.WAN})
		c.transports.SetChannelCleanup(c.quiesceChannel)
		c.transports.SetDecisionRecorder(c.recordDecision)
	}
	c.vpnStarted = true
	return nil
}

// vpnBatch renders the VPN dataplane for the current settings and router LAN.
// Device profiles outside the LAN are skipped, never an error.
func (c *Controller) vpnBatch(p *policy.Policy, replace bool) (dataplane.Batch, error) {
	o := c.settings.Options
	o.Replace = replace
	o.Selection = c.selection
	o.ManualGames = false
	if o.Net.IsZero() {
		o.Net = c.router
	}
	return dataplane.Build(p, o)
}

func (c *Controller) Run(ctx context.Context, p *policy.Policy) error {
	lock, settings, e := readOwnedSettings("/var/run/flr-runtime/controller.lock", ReadSettings)
	if e != nil {
		return e
	}
	defer lock.Close()
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	c.settings = settings
	c.generation = 1
	if settings.Version == 2 && settings.SavedGeneration > 0 {
		c.generation = settings.SavedGeneration
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	c.ctx = ctx
	c.basePolicy = p
	c.appliedMode = c.settings.EffectiveRoutingMode()
	c.policy = p.ForMode(c.appliedMode)
	c.stateDir = StateDir
	c.historyPath = "/var/run/flr-runtime/history.json"
	defer func() { cancel(); c.wan.Wait() }()
	c.sessions = control.NewManager(&control.ProcessBackend{WAN: c.settings.Options.WAN})
	defer c.sessions.Stop()
	if e = config.RetireLegacy(); e != nil {
		return e
	}
	if e = transport.CleanupStalePins(); e != nil {
		return e
	}
	e = func() error {
		admin, err := lockPrivateAdmin(StateDir)
		if err != nil {
			return err
		}
		defer admin.Close()
		return c.initializeAdmin(true)
	}()
	if e != nil {
		return e
	}
	if e = c.recoverConnectionTest(ctx); e != nil {
		return e
	}
	c.bypass = &bypass.Manager{}
	defer c.bypass.Stop(context.Background())
	c.live = true
	defer func() {
		cancel()
		c.adminMu.Lock()
		c.live = false
		if c.testCancel != nil {
			c.testCancel()
		}
		if c.transports != nil {
			c.transports.Shutdown()
		}
		if c.vpnCancel != nil {
			c.vpnCancel()
		}
		c.adminMu.Unlock()
		c.testWorkers.Wait()
	}()
	defer func() {
		c.mu.RLock()
		d := c.direct
		c.mu.RUnlock()
		if d != nil {
			d.Stop()
		}
	}()
	done := make(chan error, 4)
	go func() { done <- control.ServeAPI(ctx, c.HandleAPI) }()
	go func() {
		done <- control.Serve(ctx, c.socketLAN, func(r control.Request) (any, error) { c.adminMu.Lock(); defer c.adminMu.Unlock(); return c.Handle(r) })
	}()
	ticker := time.NewTicker(health.Interval)
	defer ticker.Stop()
	for {
		e = nil
		c.adminMu.Lock()
		// The LAN is re-read every tick so the direct bind, device profiles and
		// DNS broker follow a LAN that appears or changes after start.
		c.refreshLAN()
		c.reconcileDirect(ctx)
		bypassError := c.bypass.Reconcile(ctx, c.settings.DirectBypass, c.settings.Options.WAN)
		c.mu.Lock()
		c.bypassRunning = c.settings.DirectBypass.Enabled && bypassError == nil
		if bypassError != nil {
			c.lastError = bypassError.Error()
		}
		c.mu.Unlock()
		enabled := c.settings.Enabled
		if enabled && c.vpnStarted && c.vpnRestart {
			if c.transports != nil {
				e = c.transports.Shutdown()
			}
			if c.vpnCancel != nil {
				c.vpnCancel()
				<-c.vpnDone
			}
			c.vpnStarted = false
			c.transports = nil
			c.vpnRestart = false
		}
		if e == nil && enabled && c.vpnStarted {
			c.reconcileRoutingMode()
			c.reconcileQueueing(true)
		} else if !enabled {
			c.reconcileQueueing(false)
		}
		if e == nil && enabled && !c.vpnStarted {
			e = c.startVPN(ctx, p, done)
		} else if !enabled {
			if c.vpnStarted {
				if c.transports != nil {
					e = c.transports.Shutdown()
				}
				if c.vpnCancel != nil {
					c.vpnCancel()
					<-c.vpnDone
				}
				c.sessions.Stop()
				c.vpnStarted = false
				c.transports = nil
				c.mu.Lock()
				c.selection = contract.Selection{General: contract.Down, Games: contract.Down}
				c.activeProfile = nil
				c.activeConnection = nil
				c.transportState = transport.Snapshot{Requested: c.settings.Selection, Selection: c.selection}
				c.states = map[contract.Channel]health.State{}
				c.generation++
				c.mu.Unlock()
			}
			// Retry an interrupted disable after a controller crash. A clean image
			// without an owner or rollback checkpoint needs no VPN dataplane action.
			if c.restorationPending() && e == nil {
				c.deactivationPending = true
				e = c.deactivate("/etc/flr-runtime/backup")
				if e == nil {
					c.deactivationPending = false
				}
			}
		}
		if e == nil && c.vpnStarted {
			c.syncProfiles()
		}
		c.adminMu.Unlock()
		if e != nil {
			return e
		}
		if enabled {
			if e = dataplane.EnsureRoutes(); e != nil {
				c.mu.Lock()
				c.lastError = "route refresh blocked"
				c.mu.Unlock()
			} else {
				c.round(ctx)
			}
		}
		if s := c.sessions.Current(); s != nil {
			ip, mac := control.LeaseAddress(s.MAC)
			c.sessions.Tick(time.Now(), ip, mac)
		}
		if e = WriteJSON("/var/run/flr-runtime/status.json", c.Status()); e != nil {
			return e
		}
		select {
		case <-ctx.Done():
			return nil
		case e = <-done:
			// Closing a disabled VPN broker is expected. Control/API socket failures
			// remain fatal; context cancellation is handled by the main stop path.
			if e != nil {
				return e
			}
		case <-ticker.C:
		case <-c.refresh:
		}
	}
}

// Reconcile independently of VPN activation. Listener failures remain visible
// and refresh/settings retries them; there is no fallback to a wildcard bind.
// The listener binds the router's LAN address as discovered on this tick, and
// it is not started on the legacy fallback while the LAN is unknown.
func (c *Controller) reconcileDirect(ctx context.Context) {
	c.mu.RLock()
	config := c.effectiveDirect()
	old := c.direct
	router, routerErr := c.router, c.routerErr
	c.mu.RUnlock()
	if old != nil && c.directConfig == config && c.directLAN == router && (!config.Enabled || old.Status().Running) {
		return
	}
	if old != nil {
		if e := old.Stop(); e != nil {
			c.mu.Lock()
			c.lastError = "direct listener cleanup failed"
			c.mu.Unlock()
			return
		}
	}
	if router.IsZero() {
		c.mu.Lock()
		c.direct = nil
		c.directConfig = config
		c.directLAN = router
		if config.Enabled {
			c.lastError = "direct listener unavailable; router LAN discovery failed: " + routerErr
		}
		c.mu.Unlock()
		return
	}
	deps := c.directDeps
	deps.WAN = c.settings.Options.WAN
	deps.LAN = router
	next := control.NewDirectServer(config, deps)
	e := next.Start(ctx)
	c.mu.Lock()
	c.direct = next
	c.directConfig = config
	c.directLAN = router
	if e != nil {
		c.lastError = "direct listener unavailable; verify LAN address/port and retry refresh"
	}
	c.mu.Unlock()
}

// reconcileRoutingMode applies a stored routing mode change to the running
// VPN without a restart: the static direct set is rewritten, and the DNS
// broker classifies new answers with the new view and rebinds the addresses
// it already issued. Only new flows are classified, so
// no established session changes channel. A failure retries on the next tick.
// Callers hold adminMu.
func (c *Controller) reconcileRoutingMode() {
	mode := c.settings.EffectiveRoutingMode()
	if c.basePolicy == nil || mode == c.appliedMode {
		return
	}
	view := c.basePolicy.ForMode(mode)
	apply := c.applyStaticSets
	if apply == nil {
		apply = dataplane.UpdateStaticSets
	}
	if e := apply(view); e != nil {
		c.mu.Lock()
		c.lastError = "routing mode " + mode + " not applied yet; retrying"
		c.mu.Unlock()
		return
	}
	if c.broker != nil {
		if e := c.broker.SetPolicy(view); e != nil {
			c.mu.Lock()
			c.policy = view
			c.lastError = "routing mode " + mode + ": DNS bindings not rewritten yet; retrying"
			c.mu.Unlock()
			return
		}
	}
	c.mu.Lock()
	c.policy, c.appliedMode = view, mode
	c.mu.Unlock()
}

// reconcileQueueing keeps the owner's tunnel queueing on flr_awg while the VPN
// runs and removes FLR's qdiscs when it is turned off or the VPN stops.
// Callers hold adminMu.
func (c *Controller) reconcileQueueing(vpn bool) {
	if c.queueing == nil {
		c.queueing = &qos.Manager{Run: func(name string, args ...string) ([]byte, error) {
			r := native.Execute(context.Background(), native.Limit(name), "", name, args...)
			return append(r.Stdout, r.Stderr...), r.Err
		}}
	}
	cfg := c.settings.effectiveTunnelQoS()
	if !vpn {
		cfg = qos.Config{}
	}
	_, statErr := os.Stat("/sys/class/net/" + qos.Device)
	if e := c.queueing.Reconcile(cfg, statErr == nil); e != nil {
		c.mu.Lock()
		c.lastError = e.Error()
		c.mu.Unlock()
	}
}
