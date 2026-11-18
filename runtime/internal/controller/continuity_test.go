package controller

import (
	"context"
	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"github.com/MyHeartRaces/FLR/runtime/internal/transport"
	"testing"
)

func TestAWGSoftDegradationPreservesExistingNativeAffinity(t *testing.T) {
	c := New(Settings{Version: 2})
	c.selection = contract.Selection{General: contract.AWG, Games: contract.AWG}
	clears := 0
	c.clearAWG = func() error { clears++; return nil }
	c.publishSelection = func(contract.Selection) error { return nil }
	before := transport.Snapshot{AWG: health.State{Up: true}}
	next := transport.Snapshot{Generation: c.choiceEpoch, AWG: health.State{Degraded: true, Reason: "sustained_latency"}, Selection: contract.Selection{General: contract.Gecko, Games: contract.Gecko}}
	c.publishTransport(before, next)
	if clears != 0 || c.selection != next.Selection {
		t.Fatal("soft degradation deleted still-working native sessions", clears, c.selection)
	}
}

func TestFailedPublicationReportsActualRouteAndPendingDesired(t *testing.T) {
	c := New(Settings{Version: 2})
	old := contract.Selection{General: contract.Gecko, Games: contract.Gecko}
	c.selection = old
	c.activeConnection = &connection.Summary{ID: "h", Family: "hy2"}
	c.transportState = transport.Snapshot{Generation: c.choiceEpoch, Selection: old, ActiveConnection: c.activeConnection}
	c.publishSelection = func(contract.Selection) error { return context.Canceled }
	next := transport.Snapshot{Generation: c.choiceEpoch, Selection: contract.Selection{General: contract.AWG, Games: contract.AWG}, AWG: health.State{Up: true}, ActiveConnection: &connection.Summary{ID: "a", Family: "awg"}, ReserveConnection: &connection.Summary{ID: "h", Family: "hy2"}}
	c.publishTransport(c.transportState, next)
	s := c.Status()
	if s.Selection != old || s.ActiveConnection == nil || s.ActiveConnection.ID != "h" || s.Proxy.Selection != old || s.Proxy.ActiveConnection == nil || s.Proxy.ActiveConnection.ID != "h" || !s.Proxy.Pending {
		t.Fatal("failed nft publication reported desired route as actual")
	}
}
func TestPendingChannelCleanupIsVisibleWithoutClaimingDesiredSelection(t *testing.T) {
	c := New(Settings{Version: 2})
	old := contract.Selection{General: contract.AWG, Games: contract.AWG}
	c.selection = old
	c.activeConnection = &connection.Summary{ID: "a", Family: "awg"}
	c.transportState = transport.Snapshot{Generation: c.choiceEpoch, Selection: old, ActiveConnection: c.activeConnection}
	next := transport.Snapshot{Generation: c.choiceEpoch, Selection: old, ActiveConnection: c.activeConnection, Pending: true, LastError: "slot cleanup failed"}
	c.publishTransport(c.transportState, next)
	s := c.Status()
	if !s.Proxy.Pending || s.LastError != "slot cleanup failed" || s.Proxy.Selection != old {
		t.Fatal("cleanup failure hidden by pending snapshot suppression")
	}
}
