package health

import (
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"testing"
	"time"
)

func good() Result { return Result{TCP: true, UDP: true, RTT: 100 * time.Millisecond} }
func TestThreeFailuresAndSixtySecondRecovery(t *testing.T) {
	now := time.Unix(1000, 0)
	var s State
	s.Update(now, good(), true)
	if !s.Healthy() {
		t.Fatal("initial successful round not usable")
	}
	for i := 1; i <= 3; i++ {
		s.Update(now.Add(time.Duration(i)*5*time.Second), Result{TCP: true}, true)
		if s.Healthy() != (i < 3) {
			t.Fatal("incorrect failure threshold", i)
		}
	}
	start := now.Add(20 * time.Second)
	s.Update(start, good(), true)
	s.Update(start.Add(59*time.Second), good(), true)
	if s.Healthy() {
		t.Fatal("unstable recovery promoted early")
	}
	s.Update(start.Add(60*time.Second), good(), true)
	if !s.Healthy() {
		t.Fatal("stable recovery not promoted")
	}
}
func TestMissingInterfaceImmediateDownAndSpikeIgnored(t *testing.T) {
	now := time.Now()
	var s State
	s.Update(now, good(), true)
	r := good()
	r.RTT = 3 * time.Second
	s.Update(now.Add(5*time.Second), r, true)
	if !s.Healthy() {
		t.Fatal("RTT spike triggered failover")
	}
	s.Update(now.Add(10*time.Second), r, false)
	if s.Healthy() {
		t.Fatal("missing interface remained healthy")
	}
	if Interval != 5*time.Second || RoundDeadline != 4*time.Second {
		t.Fatal("probe deadlines exceed health cadence")
	}
}
func TestGamesDoNotAutomaticallyUseVLESS(t *testing.T) {
	states := map[contract.Channel]State{}
	var s State
	s.Update(time.Now(), good(), true)
	states[contract.VLESS] = s
	got := Select(states, contract.Down)
	if got.General != contract.VLESS || got.Games != contract.Down {
		t.Fatal("games silently fell back to VLESS", got)
	}
	got = Select(states, contract.VLESS)
	if got.Games != contract.VLESS {
		t.Fatal("explicit VLESS games ignored")
	}
}
