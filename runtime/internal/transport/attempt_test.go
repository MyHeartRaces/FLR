package transport

import (
	"context"
	"testing"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/diagnostic"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
)

func TestSweepRecordsFailedCandidateBeforeFallback(t *testing.T) {
	main := managedConnection(t, "awg", "main", 10)
	spare := managedConnection(t, "awg", "spare", 11)
	registry := &connection.Registry{Version: 2, Connections: []connection.Connection{main, spare}}
	awg := &qualifyingAWG{fakeAWG: fakeAWG{good: map[string]bool{"spare": true}}, mainReadyAt: 3}
	manager := New(&fakeBackend{}, nil, nil)
	manager.SetAWGBackend(awg)
	var attempts []diagnostic.Attempt
	manager.SetAttemptRecorder(func(a diagnostic.Attempt) {
		attempts = append(attempts, a)
		if a.Candidate.ID == "main" && len(awg.switches) != 1 {
			t.Fatalf("the main attempt was recorded after fallback started: %v", awg.switches)
		}
	})
	snapshot := manager.StepConnections(context.Background(), time.Now(), registry, connection.Selection{Mode: "auto"}, connection.DefaultOrder(registry), 1)
	if len(attempts) != 2 || attempts[0].Candidate.ID != "main" || attempts[1].Candidate.ID != "spare" {
		t.Fatalf("expected main and spare evidence in order, got %+v", attempts)
	}
	failed, applied := attempts[0], attempts[1]
	if failed.Outcome != "failed" || failed.Apply.Outcome != "ok" ||
		failed.Probes[0].Outcome != "failed" || failed.Probes[1].Outcome != "failed" ||
		failed.DurationMS < 300 {
		t.Fatalf("native startup retry evidence was lost: %+v", failed)
	}
	if applied.Outcome != "ok" || applied.Probes[0].Outcome != "ok" || applied.Probes[1].Outcome != "" ||
		snapshot.ActiveConnection == nil || snapshot.ActiveConnection.ID != "spare" || snapshot.AttemptSequence != applied.AttemptSequence {
		t.Fatalf("selection was not linked to its successful attempt: %+v %+v", applied, snapshot)
	}
}

type observedAWG struct {
	fakeAWG
	probed bool
}

func (a *observedAWG) Probe(ctx context.Context) health.Result {
	a.probed = true
	return a.fakeAWG.Probe(ctx)
}

func (*observedAWG) LatestHandshake(context.Context, connection.Connection) (time.Time, error) {
	return time.Time{}, nil
}

func (a *observedAWG) readTraffic(_ context.Context, c connection.Connection) nativeTrafficSample {
	sample := nativeTrafficSample{ifindex: 7, rx: 400, tx: 500, valid: c.ID == "main"}
	if a.probed {
		sample.rx += 20
		sample.tx += 40
	}
	return sample
}

func TestSweepAttachesAWGTelemetryToTheMeasuredCandidate(t *testing.T) {
	main := managedConnection(t, "awg", "main", 10)
	registry := &connection.Registry{Version: 2, Connections: []connection.Connection{main}}
	manager := New(&fakeBackend{}, nil, nil)
	manager.SetAWGBackend(&observedAWG{fakeAWG: fakeAWG{good: map[string]bool{"main": true}}})
	var attempts []diagnostic.Attempt
	manager.SetAttemptRecorder(func(a diagnostic.Attempt) { attempts = append(attempts, a) })
	snapshot := manager.StepConnections(context.Background(), time.Now(), registry, connection.Selection{Mode: "auto"}, connection.DefaultOrder(registry), 1)
	if len(attempts) != 1 || attempts[0].AttemptSequence != snapshot.AttemptSequence {
		t.Fatalf("expected the selected candidate's attempt: %+v", attempts)
	}
	a := attempts[0]
	if a.Outcome != "ok" || a.Handshake != "none" || a.Traffic != "measured" || a.RXDeltaBytes != 20 || a.TXDeltaBytes != 40 {
		t.Fatalf("expected qualification unchanged with telemetry from its measurement: %+v", a)
	}
}

type supersedingAWG struct {
	fakeAWG
	duringProbe func()
}

func (a *supersedingAWG) Probe(ctx context.Context) health.Result {
	a.duringProbe()
	return a.fakeAWG.Probe(ctx)
}

func TestSupersededNativeAttemptKeepsEvidenceWithoutChangingHealth(t *testing.T) {
	main := managedConnection(t, "awg", "main", 10)
	registry := &connection.Registry{Version: 2, Connections: []connection.Connection{main}}
	manager := New(&fakeBackend{}, nil, nil)
	awg := &supersedingAWG{
		fakeAWG:     fakeAWG{good: map[string]bool{"main": true}},
		duringProbe: func() { manager.RequestGeneration(2) },
	}
	manager.SetAWGBackend(awg)
	var attempts []diagnostic.Attempt
	manager.SetAttemptRecorder(func(a diagnostic.Attempt) { attempts = append(attempts, a) })
	snapshot := manager.StepConnections(context.Background(), time.Now(), registry, connection.Selection{Mode: "auto"}, connection.DefaultOrder(registry), 1)
	if len(attempts) != 1 || attempts[0].Epoch != 1 || attempts[0].Outcome != "superseded" || attempts[0].Probes[0].Outcome != "ok" {
		t.Fatalf("superseded candidate must retain its own evidence: %+v", attempts)
	}
	if snapshot.ActiveConnection != nil || snapshot.AttemptSequence != 0 || manager.connections.health[connectionKey(main)].Initialized {
		t.Fatalf("superseded probe reached selection or health: %+v", snapshot)
	}
}

func TestSupersededStandbyAttemptKeepsItsOriginalGeneration(t *testing.T) {
	main := managedConnection(t, "awg", "a", 10)
	reserve := managedConnection(t, "hy2", "h", 20)
	fixture := newWarmFixture(t, main, reserve)
	var warm []diagnostic.Attempt
	fixture.m.SetAttemptRecorder(func(a diagnostic.Attempt) {
		if a.Reason == "warm_reserve" {
			warm = append(warm, a)
		}
	})
	fixture.round(0)
	fixture.gen++
	fixture.sel = connection.Selection{Mode: "connection", ID: main.ID}
	snapshot, _ := fixture.round(time.Second)
	if len(warm) != 1 || warm[0].Epoch != 1 || warm[0].Outcome != "superseded" || warm[0].Probes[0].Outcome != "ok" {
		t.Fatalf("abandoned standby evidence was lost or relabeled: %+v", warm)
	}
	if snapshot.ReserveConnection != nil || fixture.b.alive {
		t.Fatalf("superseded standby became an owner: %+v", snapshot)
	}
}
