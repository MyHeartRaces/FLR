package transport

import (
	"context"
	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/diagnostic"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
	"testing"
	"time"
)

func TestFailbackDecisionRecordsRetainedReserveWithoutTeardown(t *testing.T) {
	a := managedConnection(t, "awg", "a", 10)
	h := managedConnection(t, "hy2", "h", 20)
	r := &connection.Registry{Version: 2, Connections: []connection.Connection{a, h}}
	awg := &fakeAWG{good: map[string]bool{}}
	m := New(&fakeBackend{}, func(context.Context, profile.Profile) health.Result {
		return health.Result{Measured: true, TCP: true, UDP: true}
	}, nil)
	m.SetAWGBackend(awg)
	events := []diagnostic.Decision{}
	m.SetDecisionRecorder(func(d diagnostic.Decision) { events = append(events, d) })
	now := time.Unix(100, 0)
	m.StepConnections(context.Background(), now, r, connection.Selection{Mode: "auto"}, connection.DefaultOrder(r), 1)
	events = nil
	awg.good["a"] = true
	for i := 1; i <= 13; i++ {
		m.StepConnections(context.Background(), now.Add(time.Duration(i)*5*time.Second), r, connection.Selection{Mode: "auto"}, connection.DefaultOrder(r), 1)
	}
	found := false
	for _, e := range events {
		if e.Reason == "failback" {
			found = e.Outcome == "prepared" && e.ReserveRetained && e.From.ID == "h" && e.To.ID == "a"
		}
		if e.Stage == "stop" || e.Stage == "conntrack" {
			t.Fatal("failback recorded destructive retirement")
		}
	}
	if !found {
		t.Fatal("retained failback decision absent")
	}
}
