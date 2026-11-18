package dataplane

import "testing"

func TestConnectionRouteRefreshRejectsForeignStateBeforeCommands(t *testing.T) {
	for _, snapshot := range []Snapshot{
		{},
		{Own: true, Routes: []Route{{Table: 770, Destination: "192.0.2.0/24", Device: "eth9", Metric: 100}}},
		{Own: true, Routes: []Route{{Table: 770, Destination: "default", Device: "eth9", Metric: 100}}},
	} {
		called := false
		err := ensureRoutesWith(snapshot, func(string, ...string) ([]byte, error) { called = true; return nil, nil }, func(string, ...string) error { called = true; return nil })
		if err == nil || called {
			t.Fatal("foreign route state reached native mutation")
		}
	}
}
