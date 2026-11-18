package controller

import (
	"context"
	"encoding/json"
	"github.com/MyHeartRaces/FLR/runtime/internal/config"
	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/control"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"github.com/MyHeartRaces/FLR/runtime/internal/privatefile"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
	"github.com/MyHeartRaces/FLR/runtime/internal/transport"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type continuityAWG struct {
	good   bool
	active string
}

func (a *continuityAWG) Switch(_ context.Context, c connection.Connection) error {
	a.active = c.ID
	return nil
}
func (a *continuityAWG) Present() bool { return a.active != "" }
func (a *continuityAWG) Probe(context.Context) health.Result {
	r := health.Result{Measured: true, TCP: a.good, UDP: a.good}
	if a.good {
		for i := range r.Targets {
			r.Targets[i] = health.TargetResult{TCP: true, UDP: true, TCPDurationMS: 100, UDPDurationMS: 100}
		}
	}
	return r
}
func warmProbeAdmin(t *testing.T) (*Controller, *connectionLifetimeBackend) {
	return warmProbeAdminWith(t, nil)
}
func warmProbeAdminWith(t *testing.T, probe transport.Probe) (*Controller, *connectionLifetimeBackend) {
	t.Helper()
	c := connectionProbeAdmin(t, func(context.Context, profile.Profile) health.Result {
		return health.Result{Measured: true, TCP: true, UDP: true}
	})
	if probe == nil {
		probe = func(context.Context, profile.Profile) health.Result {
			return health.Result{Measured: true, TCP: true, UDP: true}
		}
	}
	b := &connectionLifetimeBackend{}
	m := transport.New(b, probe, func() error { return nil })
	a := &continuityAWG{}
	m.SetAWGBackend(a)
	c.transports = m
	now := time.Unix(100, 0)
	m.StepConnections(c.ctx, now, c.connections, c.settings.Selection, c.settings.Order, c.choiceEpoch)
	a.good = true
	for i := 1; i <= 13; i++ {
		s := m.StepConnections(c.ctx, now.Add(time.Duration(i)*5*time.Second), c.connections, c.settings.Selection, c.settings.Order, c.choiceEpoch)
		c.publishTransport(transport.Snapshot{}, s)
	}
	s := m.Snapshot()
	if s.ActiveConnection == nil || s.ActiveConnection.Family != "awg" || s.ReserveConnection == nil {
		t.Fatal("fixture missing warm native/default and proxy reserve", s)
	}
	return c, b
}
func TestConnectionProbeRestoresDefaultAndReserveWithServiceLifetime(t *testing.T) {
	c, b := warmProbeAdmin(t)
	before := c.transports.Snapshot()
	target := ""
	for _, v := range c.connections.Connections {
		if v.Family != "awg" && v.ID != before.ReserveConnection.ID {
			target = v.ID
			break
		}
	}
	result, err := c.testConnection(c.ctx, target, c.Status().Generation)
	after := c.transports.Snapshot()
	if err != nil || !result.Restored || after.ActiveConnection == nil || after.ActiveConnection.ID != before.ActiveConnection.ID || after.ReserveConnection == nil || after.ReserveConnection.ID != before.ReserveConnection.ID || after.ReserveConnection.Revision != before.ReserveConnection.Revision || !b.Alive() {
		t.Fatal("test lost default or retained reserve after restoration", err, after)
	}
}
func TestConnectionTestGuardCapturesReserveIdentity(t *testing.T) {
	started := make(chan struct{})
	var blocking atomic.Bool
	c, _ := warmProbeAdminWith(t, func(ctx context.Context, _ profile.Profile) health.Result {
		if blocking.CompareAndSwap(true, false) {
			close(started)
			<-ctx.Done()
		}
		return health.Result{Measured: true, TCP: true, UDP: true}
	})
	before := c.transports.Snapshot()
	target := ""
	for _, v := range c.connections.Connections {
		if v.Family != "awg" && v.ID != before.ReserveConnection.ID {
			target = v.ID
			break
		}
	}
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	blocking.Store(true)
	done := make(chan struct{})
	go func() { c.testConnection(ctx, target, c.Status().Generation); close(done) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("temporary test never started")
	}
	raw, err := os.ReadFile(filepath.Join(c.stateDir, "connection-test.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	json.Unmarshal(raw, &fields)
	var id, revision string
	json.Unmarshal(fields["reserve_id"], &id)
	json.Unmarshal(fields["reserve_revision"], &revision)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("test restoration did not finish")
	}
	if id != before.ReserveConnection.ID || revision != before.ReserveConnection.Revision {
		t.Fatal("watchdog omitted retained reserve identity")
	}
}
func TestConnectionProbeRestartNeverRestoresChangedNativeRevision(t *testing.T) {
	for _, change := range []string{"revision", "disabled", "deleted"} {
		t.Run(change, func(t *testing.T) {
			c := connectionProbeAdmin(t, func(context.Context, profile.Profile) health.Result { return health.Result{} })
			var native connection.Connection
			for _, v := range c.connections.Connections {
				if v.Family == "awg" {
					native = v
				}
			}
			guard := connectionTestGuard{Version: 1, Epoch: 9, ID: c.connections.Connections[0].ID, Requested: c.settings.Selection, NativeID: native.ID, NativeRevision: native.Revision, AWG: config.AWGOwnedState{}}
			if err := privatefile.Write(filepath.Join(c.stateDir, "connection-test.json"), mustJSON(guard)); err != nil {
				t.Fatal(err)
			}
			for i, v := range c.connections.Connections {
				if v.ID == native.ID {
					switch change {
					case "revision":
						c.connections.Connections[i].Revision = "different"
					case "disabled":
						c.connections.Connections[i].Enabled = false
					case "deleted":
						c.connections.Connections = append(c.connections.Connections[:i], c.connections.Connections[i+1:]...)
					}
					break
				}
			}
			restores := 0
			c.restoreTestAWG = func(context.Context, config.AWGOwnedState) error { restores++; return nil }
			if err := c.recoverConnectionTest(context.Background()); err != nil {
				t.Fatal(err)
			}
			if restores != 0 {
				t.Fatal("restored stale or disabled native snapshot")
			}
			if _, err := os.Stat(filepath.Join(c.stateDir, "connection-test.json")); !os.IsNotExist(err) {
				t.Fatal("superseded recovery marker retained")
			}
		})
	}
}

func TestReserveChangesSupersedeInFlightConnectionTest(t *testing.T) {
	for _, change := range []string{"disabled", "deleted", "revision"} {
		t.Run(change, func(t *testing.T) {
			started := make(chan struct{})
			release := make(chan struct{})
			var blocking atomic.Bool
			c, _ := warmProbeAdminWith(t, func(ctx context.Context, _ profile.Profile) health.Result {
				if blocking.CompareAndSwap(true, false) {
					close(started)
					select {
					case <-release:
					case <-ctx.Done():
					}
				}
				return health.Result{Measured: true, TCP: true, UDP: true}
			})
			c.connectionTestTimeout = 2 * time.Second
			before := c.transports.Snapshot()
			reserve := before.ReserveConnection
			target := ""
			for _, v := range c.connections.Connections {
				if v.Family != "awg" && v.ID != reserve.ID {
					target = v.ID
					break
				}
			}
			blocking.Store(true)
			done := make(chan struct{})
			go func() { c.testConnection(c.ctx, target, c.Status().Generation); close(done) }()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("test never started")
			}
			c.mu.RLock()
			epoch := c.choiceEpoch
			c.mu.RUnlock()
			operation := "connection-update"
			fields := map[string]any{"id": reserve.ID, "metadata": map[string]any{"enabled": false}}
			switch change {
			case "deleted":
				operation = "connection-delete"
				fields = map[string]any{"id": reserve.ID}
			case "revision":
				operation = "connection-replace"
				fields = map[string]any{"id": reserve.ID, "data": publicConnectionURI}
			}
			_, err := c.HandleAPI(connectionRequest(t, c, operation, fields))
			close(release)
			if err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("test did not terminate")
			}
			c.mu.RLock()
			advanced := c.choiceEpoch > epoch
			phase := c.testStatus.Phase
			c.mu.RUnlock()
			if !advanced || phase != "cancelled" {
				t.Fatal("reserve edit did not supersede temporary probe", change, advanced, phase)
			}
		})
	}
}
func TestDiagnosticManualTestHasPreparedAndFinalOutcomes(t *testing.T) {
	c := connectionProbeAdmin(t, func(context.Context, profile.Profile) health.Result {
		return health.Result{Measured: true, TCP: true, UDP: true}
	})
	c.testConnection(c.ctx, c.connections.Connections[0].ID, c.Status().Generation)
	raw, err := c.HandleAPI(control.APIRequest{Operation: "diagnostics-export", Value: "0"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(raw)
	var page struct {
		Decisions []struct{ Reason, Outcome string }
	}
	json.Unmarshal(encoded, &page)
	prepared, applied := false, false
	for _, d := range page.Decisions {
		if d.Reason == "manual_test" {
			prepared = prepared || d.Outcome == "prepared"
			applied = applied || d.Outcome == "applied"
		}
	}
	if !prepared || !applied {
		t.Fatal("manual test missing prepared or final outcome")
	}
}

func TestConnectionProbeRejectsUnpublishedDefaultBeforeMarker(t *testing.T) {
	c := connectionProbeAdmin(t, func(context.Context, profile.Profile) health.Result {
		return health.Result{Measured: true, TCP: true, UDP: true}
	})
	c.round(c.ctx)
	c.transportState.Pending = true
	c.lastError = "selection update failed"
	_, err := c.testConnection(c.ctx, c.connections.Connections[0].ID, c.Status().Generation)
	if err == nil {
		t.Fatal("intrusive probe admitted while actual default publication pending")
	}
	if _, err := os.Stat(filepath.Join(c.stateDir, "connection-test.json")); !os.IsNotExist(err) {
		t.Fatal("pending default probe created recovery marker")
	}
}

func unnamedOwnedAWG() config.AWGOwnedState {
	return config.AWGOwnedState{"flr_awg": {".type": "interface", "proto": "amneziawg"}}
}
func TestConnectionProbeRefusesNonemptyUnnamedNativeBeforeMutation(t *testing.T) {
	probes := 0
	c := connectionProbeAdmin(t, func(context.Context, profile.Profile) health.Result {
		probes++
		return health.Result{Measured: true, TCP: true, UDP: true}
	})
	c.captureTestAWG = func(context.Context) (config.AWGOwnedState, error) { return unnamedOwnedAWG(), nil }
	_, err := c.testConnection(c.ctx, c.connections.Connections[0].ID, c.Status().Generation)
	if err == nil || probes != 0 {
		t.Fatal("unnamed owned native was tested without a revision fence", err)
	}
	if _, err := os.Stat(filepath.Join(c.stateDir, "connection-test.json")); !os.IsNotExist(err) {
		t.Fatal("unsafe unnamed test saved a watchdog")
	}
}
func TestRestartRefusesNonemptyUnnamedAWGAfterRegistryChanges(t *testing.T) {
	for _, change := range []string{"revision", "disabled", "deleted"} {
		t.Run(change, func(t *testing.T) {
			c := connectionProbeAdmin(t, nil)
			guard := connectionTestGuard{Version: 1, Epoch: 9, ID: c.connections.Connections[0].ID, Requested: c.settings.Selection, AWG: unnamedOwnedAWG()}
			for i, item := range c.connections.Connections {
				if item.Family != "awg" {
					continue
				}
				switch change {
				case "revision":
					c.connections.Connections[i].Revision = "changed"
				case "disabled":
					c.connections.Connections[i].Enabled = false
				case "deleted":
					c.connections.Connections = append(c.connections.Connections[:i], c.connections.Connections[i+1:]...)
				}
				break
			}
			if err := privatefile.Write(filepath.Join(c.stateDir, "connection-test.json"), mustJSON(guard)); err != nil {
				t.Fatal(err)
			}
			restores := 0
			c.restoreTestAWG = func(context.Context, config.AWGOwnedState) error { restores++; return nil }
			if err := c.recoverConnectionTest(context.Background()); err != nil {
				t.Fatal(err)
			}
			if restores != 0 {
				t.Fatal("unnamed snapshot restored stale owned AWG after registry change")
			}
		})
	}
}
