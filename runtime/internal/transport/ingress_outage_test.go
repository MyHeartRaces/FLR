package transport

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/diagnostic"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
)

const (
	primaryIngress   = "192.0.2.10"
	alternateIngress = "192.0.2.20"
	lastIngress      = "192.0.2.30"
)

func ingressFixture(t *testing.T) *connection.Registry {
	t.Helper()
	gecko, err := connection.ParseImport([]byte("hy2://PUBLIC_TEST_AUTH@192.0.2.10:443/?obfs=gecko&obfs-password=PUBLIC_TEST_OBFS&obfs-min-packet-size=600&obfs-max-packet-size=1300"))
	if err != nil {
		t.Fatal(err)
	}
	gecko[0].ID = "colocated"
	items := []connection.Connection{
		managedConnection(t, "awg", "main", 10),
		gecko[0],
		managedConnection(t, "hy2", "alternate", 20),
		managedConnection(t, "hy2", "last", 30),
	}
	for i, want := range []string{primaryIngress, primaryIngress, alternateIngress, lastIngress} {
		var host string
		if items[i].Profile != nil {
			host, _ = items[i].Profile.Outbound["server"].(string)
		} else {
			host, _, _ = net.SplitHostPort(items[i].AWG["Endpoint"])
		}
		if host != want {
			t.Fatalf("fixture %s uses ingress %q, want %q", items[i].ID, host, want)
		}
	}
	return &connection.Registry{Version: 2, Connections: items}
}

func ingressProbe(reachable map[string]bool) Probe {
	return func(_ context.Context, p profile.Profile) health.Result {
		host, _ := p.Outbound["server"].(string)
		up := reachable[host]
		return health.Result{Measured: true, TCP: up, UDP: up}
	}
}

func expectIngressOwner(t *testing.T, snapshot Snapshot, id string, channel contract.Channel) {
	t.Helper()
	var active string
	if snapshot.ActiveConnection != nil {
		active = snapshot.ActiveConnection.ID
	}
	if active != id || snapshot.Selection.General != channel || snapshot.Selection.Games != channel || snapshot.Pending {
		t.Fatalf("new-flow owner = %q, channels = %+v, pending = %v, reason = %q; want %q on %s",
			active, snapshot.Selection, snapshot.Pending, snapshot.Reason, id, channel)
	}
}

func TestIngressOutageOnlySelectsQualifiedPaths(t *testing.T) {
	registry := ingressFixture(t)
	for _, tc := range []struct {
		name, survivingIngress, want string
		nativeReady                  bool
		channel                      contract.Channel
	}{
		{"primary site only", primaryIngress, "main", true, contract.AWG},
		{"primary proxy only", primaryIngress, "colocated", false, contract.Gecko},
		{"first independent ingress only", alternateIngress, "alternate", false, contract.Gecko},
		{"last independent ingress only", lastIngress, "last", false, contract.Gecko},
		{"all ingresses down", "", "", false, contract.Down},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reachable := make(map[string]bool)
			if tc.survivingIngress != "" {
				reachable[tc.survivingIngress] = true
			}
			backend := &fakeBackend{}
			manager := New(backend, ingressProbe(reachable), nil)
			manager.SetAWGBackend(&fakeAWG{good: map[string]bool{"main": tc.nativeReady}})
			snapshot := manager.StepConnections(context.Background(), time.Unix(100, 0), registry,
				connection.Selection{Mode: "auto"}, connection.DefaultOrder(registry), 1)
			expectIngressOwner(t, snapshot, tc.want, tc.channel)
			if tc.channel == contract.Down && backend.Alive() {
				t.Fatal("an unqualified proxy retained the slot after the sweep")
			}
		})
	}
}

func TestSharedIngressFailureRetiresProxyBeforeIndependentOwner(t *testing.T) {
	registry := ingressFixture(t)
	for _, start := range []struct {
		name string
		id   string
		lane contract.Channel
	}{
		{"native active", "main", contract.AWG},
		{"colocated proxy active", "colocated", contract.Gecko},
	} {
		t.Run(start.name, func(t *testing.T) {
			reachable := map[string]bool{primaryIngress: true, alternateIngress: true}
			backend := &fakeBackend{}
			awg := &fakeAWG{good: map[string]bool{"main": start.lane == contract.AWG}}
			manager := New(backend, ingressProbe(reachable), nil)
			manager.SetAWGBackend(awg)
			var decisions []diagnostic.Decision
			manager.SetDecisionRecorder(func(d diagnostic.Decision) { decisions = append(decisions, d) })
			cleanupBlocked := start.lane == contract.Gecko
			manager.SetChannelCleanup(func(channel contract.Channel, reason string) error {
				if cleanupBlocked && channel == contract.Gecko {
					return errors.New("test slot cleanup blocked")
				}
				return nil
			})
			now := time.Unix(100, 0)
			step := func() Snapshot {
				now = now.Add(health.Interval)
				return manager.StepConnections(context.Background(), now, registry, connection.Selection{Mode: "auto"}, connection.DefaultOrder(registry), 1)
			}
			expectIngressOwner(t, step(), start.id, start.lane)
			reachable[primaryIngress] = false
			awg.good["main"] = false
			beforeStarts, beforeStops := len(backend.starts), backend.stops
			var snapshot Snapshot
			for i := 0; i < 3; i++ {
				snapshot = step()
			}
			if cleanupBlocked {
				if !snapshot.Pending || len(backend.starts) != beforeStarts || backend.stops != beforeStops || !backend.Alive() {
					t.Fatalf("same-slot fallback before old proxy retirement: snapshot=%+v starts=%v", snapshot, backend.starts)
				}
				cleanupBlocked = false
				snapshot = step()
			}
			expectIngressOwner(t, snapshot, "alternate", contract.Gecko)
			if start.lane != contract.Gecko {
				return
			}
			var cleaned, stopped bool
			for _, d := range decisions {
				if d.From.ID == "colocated" && d.Channel == contract.Gecko && d.Outcome == "applied" {
					if d.Stage == "cleanup" {
						cleaned = true
					}
					if d.Stage == "stop" && cleaned {
						stopped = true
					}
				}
				if d.Stage == "selection" && d.To.ID == "alternate" {
					if !stopped {
						t.Fatal("independent ingress selected before old proxy cleanup and stop")
					}
					return
				}
			}
			t.Fatal("independent ingress selection has no decision record")
		})
	}
}
