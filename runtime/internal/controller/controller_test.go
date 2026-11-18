package controller

import (
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/dataplane"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
	"testing"
	"time"
)

func healthy() health.State {
	var s health.State
	s.Update(time.Now(), health.Result{TCP: true, UDP: true}, true)
	return s
}
func TestTransitionOnlyClearsFailedChannels(t *testing.T) {
	old := map[contract.Channel]health.State{contract.AWG: healthy(), contract.Gecko: healthy()}
	next := map[contract.Channel]health.State{contract.Gecko: healthy()}
	change := PlanTransition(old, next, contract.Down)
	if change.Selection.Games != contract.Gecko || len(change.Failed) != 1 || change.Failed[0] != contract.AWG {
		t.Fatal("healthy flows were cleared or game backup wrong", change)
	}
	recovered := PlanTransition(next, old, contract.Down)
	if len(recovered.Failed) != 0 || recovered.Selection.Games != contract.AWG {
		t.Fatal("recovery resets healthy backup flows", recovered)
	}
}
func TestFailureOfNonPreferredStickyChannelStillClearsOnlyIt(t *testing.T) {
	old := map[contract.Channel]health.State{contract.AWG: healthy(), contract.Gecko: healthy()}
	next := map[contract.Channel]health.State{contract.AWG: healthy()}
	change := PlanTransition(old, next, contract.Down)
	if len(change.Failed) != 1 || change.Failed[0] != contract.Gecko {
		t.Fatal("failed sticky backup connections never cleaned", change)
	}
}
func TestFailedInitialStateClearsStaleChannelFlows(t *testing.T) {
	next := map[contract.Channel]health.State{}
	var s health.State
	s.Update(time.Now(), health.Result{}, false)
	next[contract.AWG] = s
	change := PlanTransition(map[contract.Channel]health.State{}, next, contract.Down)
	if len(change.Failed) != 1 || change.Failed[0] != contract.AWG {
		t.Fatal("restart retained stale failed-channel flows", change)
	}
}

func TestDeviceDNSViewKeepsBanksDirectAndLocalDNS(t *testing.T) {
	p, e := policy.Load("../policy/testdata/split")
	if e != nil {
		t.Fatal(e)
	}
	c := New(Settings{Options: dataplane.Options{Profiles: map[string]contract.Class{"192.168.8.126": contract.Games}}})
	c.policy = p
	for _, tt := range []struct {
		name  string
		class contract.Class
	}{{"ozon.ru", contract.Direct}, {"router.lan", contract.Local}, {"apple.com", contract.Games}} {
		v, ok := c.ClientView("192.168.8.126", tt.name)
		if !ok || v.Class != tt.class {
			t.Fatal(tt.name, v, ok)
		}
	}
	c.settings.Options.Profiles["192.168.8.126"] = contract.Direct
	v, ok := c.ClientView("192.168.8.126", "apple.com")
	if !ok || v.Class != contract.Direct {
		t.Fatal("explicit device direct ignored")
	}
	if _, ok = c.ClientView("192.168.8.228", "apple.com"); ok {
		t.Fatal("profile leaks to another client")
	}
}
