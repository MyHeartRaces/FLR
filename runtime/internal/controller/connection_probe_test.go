package controller

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/config"
	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/control"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"github.com/MyHeartRaces/FLR/runtime/internal/privatefile"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
	"github.com/MyHeartRaces/FLR/runtime/internal/transport"
)

type connectionTestBackend struct {
	mu    sync.Mutex
	alive bool
}

func (b *connectionTestBackend) Start(context.Context, profile.Profile) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.alive = true
	return nil
}
func (b *connectionTestBackend) Stop() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.alive = false
	return nil
}
func (b *connectionTestBackend) Alive() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.alive }
func connectionProbeAdmin(t *testing.T, probe transport.Probe) *Controller {
	c := connectionAdmin(t)
	c.live = true
	c.ctx = context.Background()
	c.publishSelection = func(contract.Selection) error { return nil }
	c.captureTestAWG = func(context.Context) (config.AWGOwnedState, error) { return config.AWGOwnedState{}, nil }
	c.restoreTestAWG = func(context.Context, config.AWGOwnedState) error { return nil }
	c.transports = transport.New(&connectionTestBackend{}, probe, func() error { return nil })
	c.connectionTestTimeout = 30 * time.Millisecond
	return c
}
func TestConnectionProbeMeasuresAndRestoresOriginalIntent(t *testing.T) {
	c := connectionProbeAdmin(t, func(context.Context, profile.Profile) health.Result {
		return health.Result{Measured: true, TCP: true, UDP: true}
	})
	id := c.connections.Connections[0].ID
	before := c.settings.Selection
	result, err := c.testConnection(context.Background(), id, c.Status().Generation)
	if err != nil || !result.TCP || !result.UDP || !result.Restored || c.settings.Selection != before {
		t.Fatal("test did not measure and restore original choice", err)
	}
}
func TestConnectionProbeWatchdogCancellationRestoresChoice(t *testing.T) {
	c := connectionProbeAdmin(t, func(ctx context.Context, _ profile.Profile) health.Result { <-ctx.Done(); return health.Result{} })
	id := c.connections.Connections[0].ID
	before := c.settings.Selection
	_, _ = c.testConnection(context.Background(), id, c.Status().Generation)
	if c.settings.Selection != before || c.testOverride != nil || c.transports.Snapshot().ActiveConnection != nil {
		t.Fatal("watchdog left temporary path or selection")
	}
}
func TestConnectionProbeNewAdminChoiceWinsOverLateTest(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	c := connectionProbeAdmin(t, func(context.Context, profile.Profile) health.Result {
		close(started)
		<-release
		return health.Result{Measured: true, TCP: true, UDP: true}
	})
	c.connectionTestTimeout = time.Second
	id := c.connections.Connections[0].ID
	done := make(chan struct{})
	go func() { c.testConnection(context.Background(), id, c.Status().Generation); close(done) }()
	<-started
	if _, err := c.HandleAPI(control.APIRequest{Operation: "select", ID: c.connections.Connections[1].ID}); err != nil {
		t.Fatal(err)
	}
	chosen := c.connections.Connections[1].ID
	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("test did not terminate")
	}
	if c.settings.Selection != (connection.Selection{Mode: "connection", ID: chosen}) || c.testOverride != nil || c.transports.Snapshot().ActiveConnection != nil {
		t.Fatal("late test overwrote new user choice")
	}
}

func TestConnectionProbeFailureIsReportedAsMeasuredFailure(t *testing.T) {
	c := connectionProbeAdmin(t, func(context.Context, profile.Profile) health.Result { return health.Result{Measured: true} })
	result, err := c.testConnection(context.Background(), c.connections.Connections[0].ID, c.Status().Generation)
	if err != nil || !result.Measured || result.TCP || result.UDP || !result.Restored {
		t.Fatal("failed real probe was reported as missing measurement", err)
	}
}

func TestConnectionProbeRecoveryFailureRemainsVisibleAndBlocksRound(t *testing.T) {
	c := connectionProbeAdmin(t, func(context.Context, profile.Profile) health.Result {
		return health.Result{Measured: true, TCP: true, UDP: true}
	})
	c.restoreTestAWG = func(context.Context, config.AWGOwnedState) error { return context.DeadlineExceeded }
	result, err := c.testConnection(context.Background(), c.connections.Connections[0].ID, c.Status().Generation)
	if err == nil || result.Phase != "recovery-pending" || result.Restored {
		t.Fatal("failed restoration was reported as complete")
	}
	c.round(context.Background())
	if c.transports.Snapshot().ActiveConnection != nil {
		t.Fatal("normal round ran before test recovery completed")
	}
}

func TestConnectionProbeCannotOverwriteUnrecoveredMarker(t *testing.T) {
	c := connectionProbeAdmin(t, func(context.Context, profile.Profile) health.Result {
		return health.Result{Measured: true, TCP: true, UDP: true}
	})
	c.restoreTestAWG = func(context.Context, config.AWGOwnedState) error { return context.DeadlineExceeded }
	id := c.connections.Connections[0].ID
	c.testConnection(context.Background(), id, c.Status().Generation)
	marker := filepath.Join(c.stateDir, "connection-test.json")
	before, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.testConnection(context.Background(), id, c.Status().Generation); err == nil {
		t.Fatal("unrecovered marker overwritten")
	}
	after, _ := os.ReadFile(marker)
	if string(before) != string(after) {
		t.Fatal("original watchdog lost")
	}
}

func TestConnectionProbeRestartRecoveryUsesPersistentUserIntent(t *testing.T) {
	for _, newChoice := range []bool{false, true} {
		c := connectionProbeAdmin(t, func(context.Context, profile.Profile) health.Result {
			return health.Result{Measured: true, TCP: true, UDP: true}
		})
		requested := c.settings.Selection
		if newChoice {
			c.settings.Selection = connection.Selection{Mode: "connection", ID: c.connections.Connections[0].ID}
		}
		marker := connectionTestGuard{Version: 1, Epoch: 9, ID: c.connections.Connections[0].ID, Requested: requested, AWG: config.AWGOwnedState{}}
		if err := privatefile.Write(filepath.Join(c.stateDir, "connection-test.json"), mustJSON(marker)); err != nil {
			t.Fatal(err)
		}
		restores := 0
		c.restoreTestAWG = func(context.Context, config.AWGOwnedState) error { restores++; return nil }
		if err := c.recoverConnectionTest(context.Background()); err != nil {
			t.Fatal(err)
		}
		if (restores == 1) == newChoice {
			t.Fatal("restart restored over newer persistent user intent")
		}
		if _, err := os.Stat(filepath.Join(c.stateDir, "connection-test.json")); !os.IsNotExist(err) {
			t.Fatal("recovered marker retained")
		}
	}
}

type connectionLifetimeBackend struct {
	connectionTestBackend
	lifetime context.Context
}

func (b *connectionLifetimeBackend) StartBudget(lifetime, budget context.Context, p profile.Profile) error {
	b.lifetime = lifetime
	return b.Start(budget, p)
}
func (b *connectionLifetimeBackend) Alive() bool {
	return b.connectionTestBackend.Alive() && b.lifetime != nil && b.lifetime.Err() == nil
}
func TestConnectionProbeRestoredProcessKeepsServiceLifetime(t *testing.T) {
	c := connectionProbeAdmin(t, func(context.Context, profile.Profile) health.Result {
		return health.Result{Measured: true, TCP: true, UDP: true}
	})
	backend := &connectionLifetimeBackend{}
	c.transports = transport.New(backend, func(context.Context, profile.Profile) health.Result {
		return health.Result{Measured: true, TCP: true, UDP: true}
	}, func() error { return nil })
	c.round(c.ctx)
	before := c.transports.Snapshot().ActiveConnection
	if before == nil {
		t.Fatal("missing original connection")
	}
	target := c.connections.Connections[1].ID
	result, err := c.testConnection(c.ctx, target, c.Status().Generation)
	after := c.transports.Snapshot().ActiveConnection
	if err != nil || !result.Restored || after == nil || after.ID != before.ID || !backend.Alive() {
		t.Fatal("restored process died with temporary restore context", err)
	}
}

func TestConnectionProbeReactivationSupersedesTemporaryTest(t *testing.T) {
	started := make(chan struct{})
	c := connectionProbeAdmin(t, func(ctx context.Context, _ profile.Profile) health.Result {
		close(started)
		<-ctx.Done()
		return health.Result{}
	})
	c.vpnStarted = true
	c.connectionTestTimeout = 2 * time.Second
	done := make(chan struct{})
	go func() { c.testConnection(c.ctx, c.connections.Connections[0].ID, c.Status().Generation); close(done) }()
	<-started
	c.mu.RLock()
	epoch := c.choiceEpoch
	c.mu.RUnlock()
	if _, err := c.HandleAPI(connectionRequest(t, c, "vpn-activate", map[string]any{"accepted": true})); err != nil {
		t.Fatal(err)
	}
	c.mu.RLock()
	superseded := c.choiceEpoch > epoch
	c.mu.RUnlock()
	if !superseded {
		t.Error("VPN restart did not supersede temporary test")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("VPN restart left test running")
	}
}
