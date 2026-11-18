package controller

import (
	"encoding/json"
	"errors"
	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"github.com/MyHeartRaces/FLR/runtime/internal/transport"
	"testing"
)

func TestDiagnosticDecisionRecordsActualPublicationFailure(t *testing.T) {
	c := New(Settings{Version: 2})
	c.selection = contract.Selection{General: contract.Gecko, Games: contract.Gecko}
	c.activeConnection = &connection.Summary{ID: "h", Family: "hy2"}
	c.publishSelection = func(contract.Selection) error { return errors.New("SECRET native stderr") }
	next := transport.Snapshot{Generation: c.choiceEpoch, AWG: health.State{Up: true}, Selection: contract.Selection{General: contract.AWG, Games: contract.AWG}, ActiveConnection: &connection.Summary{ID: "a", Family: "awg"}, ReserveConnection: &connection.Summary{ID: "h", Family: "hy2"}}
	c.publishTransport(transport.Snapshot{}, next)
	raw, _ := json.Marshal(c.Status())
	var public map[string]json.RawMessage
	json.Unmarshal(raw, &public)
	var d struct {
		LastDecision struct {
			From           struct{ ID string }
			To             struct{ ID string }
			Stage, Outcome string `json:"-"`
		}
	}
	// Decode explicit fixed fields without relying on future private controller fields.
	var summary map[string]json.RawMessage
	json.Unmarshal(public["diagnostics"], &summary)
	var decision map[string]json.RawMessage
	json.Unmarshal(summary["last_decision"], &decision)
	var outcome, stage string
	json.Unmarshal(decision["outcome"], &outcome)
	json.Unmarshal(decision["stage"], &stage)
	json.Unmarshal(decision["from"], &d.LastDecision.From)
	json.Unmarshal(decision["to"], &d.LastDecision.To)
	if outcome != "failed" || stage != "nft" || d.LastDecision.From.ID != "h" || d.LastDecision.To.ID != "a" {
		t.Fatal("publication failure missing from prepared decision history")
	}
}

func TestDiagnosticSuccessfulPublicationRecordsNewActualIdentity(t *testing.T) {
	c := New(Settings{Version: 2})
	c.selection = contract.Selection{General: contract.Gecko, Games: contract.Gecko}
	c.activeConnection = &connection.Summary{ID: "h", Family: "hy2"}
	c.publishSelection = func(contract.Selection) error { return nil }
	next := transport.Snapshot{Generation: c.choiceEpoch, AWG: health.State{Up: true}, Selection: contract.Selection{General: contract.AWG, Games: contract.AWG}, ActiveConnection: &connection.Summary{ID: "a", Family: "awg"}, ReserveConnection: &connection.Summary{ID: "h", Family: "hy2"}}
	c.publishTransport(transport.Snapshot{}, next)
	d := c.Status().Diagnostics.LastDecision
	if d == nil || !d.ActualKnown || d.Actual.ID != "a" || d.ActualSelection != next.Selection || d.From.ID != "h" || d.Outcome != "applied" {
		t.Fatal("successful publication recorded stale actual identity", d)
	}
}

func TestDiagnosticBulkCleanupRecordsActualFailedPublication(t *testing.T) {
	c := New(Settings{Version: 2})
	c.vpnStarted = true
	c.selection = contract.Selection{General: contract.Gecko, Games: contract.Gecko}
	c.activeConnection = &connection.Summary{ID: "h", Family: "hy2"}
	c.publishSelection = func(contract.Selection) error { return errors.New("SECRET cleanup stderr") }
	if err := c.quiesceConnections(); err == nil {
		t.Fatal("bulk cleanup ignored publication error")
	}
	d := c.Status().Diagnostics.LastDecision
	if d == nil || d.Stage != "nft" || d.Outcome != "failed" || !d.ActualKnown || d.Actual.ID != "h" || d.ActualSelection != c.selection {
		t.Fatal("bulk cleanup hid actual failed publication", d)
	}
}
