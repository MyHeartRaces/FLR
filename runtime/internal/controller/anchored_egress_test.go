package controller

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/continuity"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
	"github.com/MyHeartRaces/FLR/runtime/internal/transport"
)

type testContinuityBridge struct {
	selected continuity.Path
	err      error
}

func (b *testContinuityBridge) Select(p continuity.Path) error {
	if b.err != nil {
		p = continuity.Path{Channel: contract.Down}
	}
	b.selected = p
	return b.err
}

func (b *testContinuityBridge) Pause(channel contract.Channel) {
	if b.selected.Channel == channel {
		b.selected = continuity.Path{Channel: contract.Down}
	}
}

func (b *testContinuityBridge) Close() {}

func TestContinuitySwitchPreservesStableEgress(t *testing.T) {
	c := New(DefaultSettings())
	c.settings.Version = 2
	c.choiceEpoch = 6
	c.vpnStarted = true
	bridge := &testContinuityBridge{}
	c.continuity = continuityState{bridge: bridge, path: continuity.Path{Channel: contract.Down}}
	c.publishSelection = func(contract.Selection) error {
		t.Fatal("carrier change touched the installed egress map")
		return nil
	}
	c.clearAWG = func() error { return nil }
	c.clearSlot = func() error { return nil }
	owner := func(family, revision string) *connection.Summary {
		return &connection.Summary{ID: family, Revision: revision, Family: family, Capabilities: profile.Capabilities{UDP: true}}
	}
	before := transport.Snapshot{Generation: 6, Selection: contract.Selection{General: contract.AWG, Games: contract.AWG},
		ActiveConnection: owner("awg", "a"), AWG: health.State{Up: true}}
	c.publishTransport(transport.Snapshot{}, before)
	if bridge.selected != (continuity.Path{Channel: contract.AWG, Identity: "awg/a"}) {
		t.Fatalf("native carrier not selected: %+v", bridge.selected)
	}
	next := transport.Snapshot{Generation: 6, Selection: contract.Selection{General: contract.Gecko, Games: contract.Gecko},
		ActiveConnection: owner("hy2", "b"), Slot: health.State{Up: true}}
	c.publishTransport(before, next)
	if bridge.selected != (continuity.Path{Channel: contract.Gecko, Identity: "hy2/b"}) {
		t.Fatalf("reserve did not take over: %+v", bridge.selected)
	}
	if ch, _ := c.DNSRoute(contract.Games); ch != contract.Continuity {
		t.Fatalf("DNS bypassed the stable egress: %s", ch)
	}
	stale := before
	stale.Generation--
	c.publishTransport(next, stale)
	if bridge.selected.Channel != contract.Gecko {
		t.Fatal("obsolete generation replaced the carrier")
	}
	if err := c.quiesceChannel(contract.Gecko, "test"); err != nil || bridge.selected.Channel != contract.Down {
		t.Fatalf("retired carrier remained usable: %+v, %v", bridge.selected, err)
	}
	next.ActiveConnection = owner("hy2", "different-revision")
	bridge.err = errors.New("dial failed")
	c.publishTransport(next, next)
	if c.continuity.path.Channel != contract.Down {
		t.Fatal("unopened carrier reported as selected")
	}
	bridge.err = nil
	c.publishTransport(next, next)
	if bridge.selected != (continuity.Path{Channel: contract.Gecko, Identity: "hy2/different-revision"}) {
		t.Fatal("same channel was not retried with the new owner")
	}
	next.ActiveConnection = owner("vless", "c")
	c.publishTransport(next, next)
	if bridge.selected.Channel != contract.Down {
		t.Fatal("unsupported carrier forwarded anchored packets")
	}
}

func TestContinuityInterfaceChecks(t *testing.T) {
	if !continuityEndpointMatches([]byte("fixture\t127.0.0.1:41000\n"), 41000) ||
		continuityEndpointMatches([]byte("fixture\t203.0.113.5:41000\n"), 41000) ||
		continuityEndpointMatches([]byte("first 127.0.0.1:41000\nsecond 127.0.0.1:41000\n"), 41000) {
		t.Fatal("expected exactly one peer configured for the loopback bridge endpoint")
	}
	if !continuityKeepaliveEnabled([]byte("fixture\t5\n")) || continuityKeepaliveEnabled([]byte("fixture\toff\n")) {
		t.Fatal("expected the peer to provide idle traffic for endpoint migration")
	}
}

func TestContinuityUsesQualifiedReserveBeforeFailedNativeCleanup(t *testing.T) {
	c := New(Settings{Version: 2})
	bridge := &testContinuityBridge{}
	c.continuity = continuityState{bridge: bridge, path: continuity.Path{Channel: contract.Down}}
	before := transport.Snapshot{
		Selection:        contract.Selection{General: contract.AWG, Games: contract.AWG},
		AWG:              health.State{Up: true},
		ActiveConnection: &connection.Summary{ID: "a", Revision: "first", Family: "awg", Capabilities: profile.Capabilities{UDP: true}},
	}
	c.publishTransport(transport.Snapshot{}, before)
	reserve := transport.Snapshot{
		Selection:        contract.Selection{General: contract.Gecko, Games: contract.Gecko},
		AWG:              health.State{Failures: 3},
		Slot:             health.State{Up: true},
		ActiveConnection: &connection.Summary{ID: "h", Revision: "second", Family: "hy2", Capabilities: profile.Capabilities{UDP: true}},
	}
	c.clearAWG = func() error {
		if bridge.selected.Channel != contract.Gecko {
			t.Fatal("independent reserve was not carrying anchored traffic before native cleanup")
		}
		return errors.New("cleanup failed")
	}
	c.publishTransport(before, reserve)
	if !c.awgCleanupPending || c.Status().Proxy.Pending || c.Status().Selection != reserve.Selection {
		t.Fatal("cleanup failure left the independent reserve unavailable")
	}
	c.publishTransport(reserve, before)
	if bridge.selected.Channel != contract.Gecko || !c.Status().Proxy.Pending {
		t.Fatal("native carrier was reused before successful native cleanup")
	}
	c.clearAWG = func() error { return nil }
	c.publishTransport(before, before)
	if bridge.selected.Channel != contract.AWG || c.awgCleanupPending {
		t.Fatal("successful cleanup did not unblock native reuse")
	}
}

func TestDeferredContinuityKeepsDirectOnInvalidConfig(t *testing.T) {
	c := New(DefaultSettings())
	c.basePolicy = mustControllerPolicy(t)
	c.appliedMode = policy.ModeDirect
	c.policy = c.basePolicy.ForMode(c.appliedMode)
	c.settings.RoutingMode = policy.ModeTunnel
	c.continuityDeferred = true
	var err error
	c.stateDir, err = filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.stateDir, "continuity.json")
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	applied := false
	c.applyRoutingPolicy = func(*policy.Policy) error {
		applied = true
		return nil
	}
	c.reconcileRoutingMode()
	if applied || c.appliedMode != policy.ModeDirect || !c.continuityDeferred {
		t.Fatal("invalid anchor configuration disturbed native routing")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	c.reconcileRoutingMode()
	if !applied || c.appliedMode != policy.ModeTunnel || c.continuityDeferred {
		t.Fatal("ordinary policy routing did not resume after removing the optional config")
	}
}
