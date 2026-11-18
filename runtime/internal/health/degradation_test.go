package health

import (
	"testing"
	"time"
)

func measured(ms int64) Result {
	r := Result{TCP: true, UDP: true, Measured: true}
	for i := range r.Targets {
		r.Targets[i] = TargetResult{TCP: true, UDP: true, TCPDurationMS: ms, UDPDurationMS: ms}
	}
	return r
}
func advance(s *State, now *time.Time, r Result, p Policy) {
	s.UpdatePolicy(*now, r, true, p)
	*now = now.Add(Interval)
}
func warm(s *State, now *time.Time, p Policy) {
	for i := 0; i < p.BaselineSamples; i++ {
		advance(s, now, measured(100), p)
	}
}
func TestSustainedSlowSuccessAndQualifiedRecovery(t *testing.T) {
	p := DefaultPolicy()
	now := time.Unix(1000, 0)
	var s State
	warm(&s, &now, p)
	for i := 0; i < 20; i++ {
		advance(&s, &now, measured(2000), p)
	}
	if s.Healthy() || s.Reason != "sustained_latency" || !s.Degraded {
		t.Fatalf("slow success did not degrade: %+v", s)
	}
	if s.Baselines[0].TCPMS != 100 || s.Baselines[1].UDPMS != 100 {
		t.Fatal("slow path contaminated baseline")
	}
	for i := 0; i < 12; i++ {
		advance(&s, &now, measured(100), p)
	}
	if s.Healthy() {
		t.Fatal("recovery completed before 60 seconds")
	}
	advance(&s, &now, measured(100), p)
	if !s.Healthy() || s.Degraded {
		t.Fatal("full clean interval did not recover")
	}
}
func TestWarmupAndSingleOutlier(t *testing.T) {
	p := DefaultPolicy()
	now := time.Unix(1000, 0)
	var s State
	for i := 0; i < p.MinSamples-1; i++ {
		advance(&s, &now, measured(2000), p)
		if !s.Healthy() {
			t.Fatal("degraded before minimum evidence")
		}
	}
	if s.Baselines[0].TCPMS != 0 {
		t.Fatal("learned initially slow path")
	}
	advance(&s, &now, measured(2000), p)
	if s.Healthy() {
		t.Fatal("cold persistent slow path not detected")
	}
	s = State{}
	warm(&s, &now, p)
	advance(&s, &now, measured(3000), p)
	if !s.Healthy() {
		t.Fatal("single outlier switched")
	}
}
func TestIsolatedProviderOutageOrSlownessNeverDegrades(t *testing.T) {
	for _, outage := range []bool{true, false} {
		p := DefaultPolicy()
		now := time.Unix(1000, 0)
		var s State
		warm(&s, &now, p)
		r := measured(100)
		if outage {
			r.Targets[0] = TargetResult{}
		} else {
			r.Targets[0].TCPDurationMS = 3000
			r.Targets[0].UDPDurationMS = 3000
		}
		for i := 0; i < 60; i++ {
			advance(&s, &now, r, p)
		}
		if !s.Healthy() || s.Window.Failed[1] != 0 || s.Window.TCPSlow[1] != 0 || s.Window.UDPSlow[1] != 0 {
			t.Fatal("one target caused network verdict", s.Reason)
		}
	}
}
func TestIntermittentSharedFailuresAndDisabledDetection(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		p := DefaultPolicy()
		p.Enabled = enabled
		now := time.Unix(1000, 0)
		var s State
		warm(&s, &now, p)
		for i := 0; i < 30; i++ {
			r := measured(100)
			if i%3 != 2 {
				r = Result{Measured: true}
			}
			advance(&s, &now, r, p)
		}
		if s.Healthy() == enabled {
			t.Fatal("intermittent degradation/disabled policy mismatch", enabled, s.Reason)
		}
		for i := 0; i < 3; i++ {
			advance(&s, &now, Result{}, p)
		}
		if s.Healthy() {
			t.Fatal("disabled detector bypassed complete failure")
		}
	}
}
func TestRecoveryInterruptedBySlowErrorMissingTimingOrGap(t *testing.T) {
	for _, kind := range []string{"slow", "error", "missing-timing", "gap", "target-outage"} {
		t.Run(kind, func(t *testing.T) {
			p := DefaultPolicy()
			now := time.Unix(1000, 0)
			var s State
			warm(&s, &now, p)
			s.UpdatePolicy(now, Result{}, false, p)
			now = now.Add(Interval)
			for i := 0; i < 10; i++ {
				advance(&s, &now, measured(100), p)
			}
			r := measured(100)
			switch kind {
			case "slow":
				r = measured(1000)
			case "error":
				r = Result{Measured: true}
			case "missing-timing":
				r = good()
			case "gap":
				now = now.Add(time.Duration(p.MaxGapSeconds)*time.Second + Interval)
			case "target-outage":
				r.Targets[0] = TargetResult{}
			}
			advance(&s, &now, r, p)
			for i := 0; i < 11; i++ {
				advance(&s, &now, measured(100), p)
			}
			if s.Healthy() {
				t.Fatal("interrupted qualification recovered early")
			}
			for i := 0; i < 2; i++ {
				advance(&s, &now, measured(100), p)
			}
			if !s.Healthy() {
				t.Fatal("fresh clean interval failed")
			}
		})
	}
}
func TestPolicyRejectsInvalidBoundsAndRelationships(t *testing.T) {
	if err := DefaultPolicy().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Policy){func(p *Policy) { p.WindowSeconds = 301 }, func(p *Policy) { p.MinSamples = 2 }, func(p *Policy) { p.MinSamples = 60 }, func(p *Policy) { p.FailurePercent = 24 }, func(p *Policy) { p.SlowPercent = 101 }, func(p *Policy) { p.TCPFloorMS = 4000 }, func(p *Policy) { p.TCPRecoveryMS = p.TCPFloorMS }, func(p *Policy) { p.RecoveryMultiplier = p.LatencyMultiplier }, func(p *Policy) { p.BaselineSamples = 61 }, func(p *Policy) { p.RecoverySeconds = 59 }, func(p *Policy) { p.MaxGapSeconds = 61 }} {
		p := DefaultPolicy()
		change(&p)
		if p.Validate() == nil {
			t.Fatalf("accepted invalid policy %+v", p)
		}
	}
}
func TestWindowExpiresAndRefreshCannotInflateEvidence(t *testing.T) {
	p := DefaultPolicy()
	now := time.Unix(1000, 0)
	var s State
	warm(&s, &now, p)
	for i := 0; i < 100; i++ {
		s.UpdatePolicy(now, measured(2000), true, p)
	}
	if !s.Healthy() {
		t.Fatal("refresh burst inflated evidence")
	}
	now = now.Add(2 * time.Minute)
	advance(&s, &now, measured(2000), p)
	if s.Window.Samples != 1 || !s.Healthy() {
		t.Fatal("stale evidence survived window", s.Window)
	}
}

func TestProviderOffsetFailuresDegradeButOneOutlierDoesNot(t *testing.T) {
	p := DefaultPolicy()
	now := time.Unix(1000, 0)
	var s State
	warm(&s, &now, p)
	r := measured(100)
	r.Targets[0] = TargetResult{}
	advance(&s, &now, r, p)
	r = measured(100)
	r.Targets[1] = TargetResult{}
	advance(&s, &now, r, p)
	if !s.Healthy() {
		t.Fatal("one failure per provider degraded")
	}
	for i := 0; i < 20; i++ {
		r = measured(100)
		r.Targets[i%2] = TargetResult{}
		advance(&s, &now, r, p)
	}
	if s.Healthy() || s.Reason != "sustained_failures" || s.Failures != 0 {
		t.Fatal("offset failures not detected", s.Reason)
	}
}
func TestSlowUDPWithFastTCPDegradesAndDoesNotLearnSlowBaseline(t *testing.T) {
	p := DefaultPolicy()
	now := time.Unix(1000, 0)
	var s State
	r := measured(100)
	for i := range r.Targets {
		r.Targets[i].UDPDurationMS = 500
	}
	for i := 0; i < 20; i++ {
		advance(&s, &now, r, p)
	}
	if s.Healthy() || s.Reason != "sustained_latency" || s.Baselines[0].UDPMS != 0 {
		t.Fatal("slow UDP missed", s)
	}
	for i := 0; i < 20; i++ {
		advance(&s, &now, r, p)
	}
	if !s.RecoverySince.IsZero() {
		t.Fatal("slow UDP qualified recovery")
	}
}

func TestPolicyChangeRequalifiesWithoutPromotingDownPath(t *testing.T) {
	p := DefaultPolicy()
	now := time.Unix(1000, 0)
	var s State
	warm(&s, &now, p)
	s.UpdatePolicy(now, Result{}, false, p)
	now = now.Add(Interval)
	for i := 0; i < 10; i++ {
		advance(&s, &now, measured(100), p)
	}
	p.Enabled = false
	advance(&s, &now, measured(100), p)
	if s.Healthy() || s.RecoveryCleanSamples != 1 || s.Baselines[0].TCPMS != 0 {
		t.Fatal("policy edit bypassed recovery or retained baseline")
	}
	for i := 0; i < 12; i++ {
		advance(&s, &now, measured(100), p)
	}
	if !s.Healthy() {
		t.Fatal("disabled degradation blocked qualified recovery")
	}
}
func TestProtocolBaselineAndRelativeThresholds(t *testing.T) {
	p := DefaultPolicy()
	now := time.Unix(1000, 0)
	var s State
	r := measured(100)
	r.Targets[0].TCPDurationMS = 500
	r.Targets[1].TCPDurationMS = 600
	for i := 0; i < 12; i++ {
		advance(&s, &now, r, p)
	}
	if s.Baselines[0].TCPMS != 500 || s.Baselines[1].TCPMS != 600 || s.Baselines[0].UDPMS != 100 {
		t.Fatal("per-provider protocol baseline lost")
	}
	r.Targets[0].TCPDurationMS = 1900
	r.Targets[1].TCPDurationMS = 2300
	for i := 0; i < 20; i++ {
		advance(&s, &now, r, p)
	}
	if !s.Healthy() {
		t.Fatal("absolute floor bypassed baseline multiplier")
	}
	r.Targets[0].TCPDurationMS = 2100
	r.Targets[1].TCPDurationMS = 2500
	for i := 0; i < 20; i++ {
		advance(&s, &now, r, p)
	}
	if s.Healthy() {
		t.Fatal("relative persistent slowness missed")
	}
}
