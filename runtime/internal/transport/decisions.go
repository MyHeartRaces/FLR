package transport

import (
	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/diagnostic"
	"time"
)

func (m *Manager) SetDecisionRecorder(record func(diagnostic.Decision)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recordDecision = record
}
func connectionIdentity(c *connection.Connection) diagnostic.Identity {
	if c == nil {
		return diagnostic.Identity{}
	}
	return diagnostic.Identity{ID: c.ID, Revision: c.Revision}
}
func (m *Manager) recordOperation(reason, stage string, channel contract.Channel, owner *connection.Connection, err error) {
	if m.recordDecision == nil {
		return
	}
	outcome := "applied"
	if err != nil {
		outcome = "failed"
	}
	m.recordDecision(diagnostic.Decision{At: time.Now(), Epoch: m.state.Generation, From: connectionIdentity(owner), Reason: reason, Stage: stage, Channel: channel, Outcome: outcome})
}
