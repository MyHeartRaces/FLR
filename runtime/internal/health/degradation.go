package health

import (
	"sort"
	"time"
)

type Baseline struct {
	TCPMS int64 `json:"tcp_ms"`
	UDPMS int64 `json:"udp_ms"`
}
type EvidenceWindow struct {
	Samples int    `json:"samples"`
	Failed  [2]int `json:"failed"`
	TCPSlow [2]int `json:"tcp_slow"`
	UDPSlow [2]int `json:"udp_slow"`
}
type evidenceRound struct {
	at      time.Time
	failed  [2]bool
	tcpSlow [2]bool
	udpSlow [2]bool
}

func threshold(floor int, baseline int64, multiplier int) int64 {
	value := baseline * int64(multiplier)
	if value < int64(floor) {
		return int64(floor)
	}
	return value
}
func validTiming(ok bool, ms int64) bool { return ok && ms > 0 && ms <= RoundDeadline.Milliseconds() }

// UpdatePolicy is the AWG evaluator. The imported slot keeps the availability-
// only Update method. Missing measurements never count as clean recovery.
func (s *State) UpdatePolicy(now time.Time, r Result, present bool, p Policy) {
	if p.Validate() != nil {
		p = DefaultPolicy()
	} // defensive internal callers; API rejects before persistence
	if s.policy != p {
		s.policy = p
		s.evidenceCount = 0
		s.Window = EvidenceWindow{}
		s.lastEvidence = time.Time{}
		s.Baselines = [2]Baseline{}
		s.BaselineSamples = 0
		s.RecoverySince = time.Time{}
		s.RecoveryCleanSamples = 0
	}
	if present && r.NotMeasured != "" {
		s.Last = r
		s.RecoverySince = time.Time{}
		s.RecoveryCleanSamples = 0
		if s.BaselineSamples < p.BaselineSamples {
			s.BaselineSamples = 0
		}
		return
	}
	before := s.Up
	previous := s.LastCheck
	s.Last = r
	s.LastCheck = now
	if !previous.IsZero() && (now.Before(previous) || now.Sub(previous) > time.Duration(p.MaxGapSeconds)*time.Second) {
		s.RecoverySince = time.Time{}
		s.RecoveryCleanSamples = 0
		if s.BaselineSamples < p.BaselineSamples {
			s.BaselineSamples = 0
		}
	}
	eligible := s.lastEvidence.IsZero() || now.Sub(s.lastEvidence) >= Interval
	clean := r.Measured && r.TCP && r.UDP && present
	round := evidenceRound{at: now}
	admission := clean
	for i, t := range r.Targets {
		b := s.Baselines[i]
		tcpValid, udpValid := validTiming(t.TCP, t.TCPDurationMS), validTiming(t.UDP, t.UDPDurationMS)
		round.failed[i] = !t.TCP || !t.UDP
		round.tcpSlow[i] = tcpValid && t.TCPDurationMS > threshold(p.TCPFloorMS, b.TCPMS, p.LatencyMultiplier)
		round.udpSlow[i] = udpValid && t.UDPDurationMS > threshold(p.UDPFloorMS, b.UDPMS, p.LatencyMultiplier)
		clean = clean && tcpValid && udpValid && t.TCPDurationMS <= threshold(p.TCPRecoveryMS, b.TCPMS, p.RecoveryMultiplier) && t.UDPDurationMS <= threshold(p.UDPRecoveryMS, b.UDPMS, p.RecoveryMultiplier)
		admission = admission && tcpValid && udpValid && t.TCPDurationMS <= int64(p.TCPRecoveryMS) && t.UDPDurationMS <= int64(p.UDPRecoveryMS)
	}
	// Compact a fixed array by age. No sample history or refresh burst can grow it.
	n := 0
	for i := 0; i < s.evidenceCount; i++ {
		v := s.evidence[i]
		if !now.Before(v.at) && now.Sub(v.at) <= time.Duration(p.WindowSeconds)*time.Second {
			s.evidence[n] = v
			n++
		}
	}
	s.evidenceCount = n
	if eligible {
		s.lastEvidence = now
		if present && r.Measured && n < len(s.evidence) {
			s.evidence[n] = round
			s.evidenceCount++
		}
	}
	s.Window = EvidenceWindow{Samples: s.evidenceCount}
	for i := 0; i < s.evidenceCount; i++ {
		v := s.evidence[i]
		for j := 0; j < 2; j++ {
			if v.failed[j] {
				s.Window.Failed[j]++
			}
			if v.tcpSlow[j] {
				s.Window.TCPSlow[j]++
			}
			if v.udpSlow[j] {
				s.Window.UDPSlow[j]++
			}
		}
	}
	sufficient := s.Window.Samples >= p.MinSamples
	// Both providers must independently meet the threshold in this same window.
	// Their failures need not occur in the same round.
	both := func(counts [2]int, percent int) bool {
		return sufficient && counts[0] >= 2 && counts[1] >= 2 && counts[0]*100 >= s.Window.Samples*percent && counts[1]*100 >= s.Window.Samples*percent
	}
	impairedReason := ""
	if p.Enabled && both(s.Window.Failed, p.FailurePercent) {
		impairedReason = "sustained_failures"
	} else if p.Enabled && (both(s.Window.TCPSlow, p.SlowPercent) || both(s.Window.UDPSlow, p.SlowPercent)) {
		impairedReason = "sustained_latency"
	}
	if !present {
		s.Initialized = true
		s.Up = false
		s.Failures = 3
		s.Reason = "interface_absent"
		s.Degraded = false
	} else if !r.TCP || !r.UDP {
		s.Initialized = true
		s.Failures++
		if s.Failures >= 3 {
			s.Up = false
			s.Reason = "consecutive_failures"
			s.Degraded = false
		}
	} else {
		s.Failures = 0
		if !s.Initialized {
			s.Up = true
			s.Initialized = true
			s.Reason = "healthy"
		}
	}
	if s.Up && impairedReason != "" {
		s.Up = false
		s.Degraded = true
		s.Reason = impairedReason
	}
	if !s.Up {
		if !clean {
			s.RecoverySince = time.Time{}
			s.RecoveryCleanSamples = 0
		} else if eligible {
			if s.RecoverySince.IsZero() {
				s.RecoverySince = now
			}
			s.RecoveryCleanSamples++
			if now.Sub(s.RecoverySince) >= time.Duration(p.RecoverySeconds)*time.Second && s.RecoveryCleanSamples >= p.RecoverySeconds/5+1 {
				s.Up = true
				s.Degraded = false
				s.Reason = "healthy"
				// Qualified clean recovery supersedes stale impairment observations.
				s.evidenceCount = 0
				s.Window = EvidenceWindow{}
			}
		}
	}
	// Learn one fixed median from consecutive, fully clean cadence samples only.
	// Admission ceilings prevent a slow cold path from becoming its own normal.
	// Once learned it never rises; policy change/restart explicitly requalifies it.
	noEvidence := s.Window.Failed == [2]int{} && s.Window.TCPSlow == [2]int{} && s.Window.UDPSlow == [2]int{}
	if s.BaselineSamples < p.BaselineSamples {
		if !s.Up || !admission || !noEvidence {
			s.BaselineSamples = 0
		} else if eligible {
			for i, t := range r.Targets {
				s.baselineValues[i][0][s.BaselineSamples] = t.TCPDurationMS
				s.baselineValues[i][1][s.BaselineSamples] = t.UDPDurationMS
			}
			s.BaselineSamples++
			if s.BaselineSamples == p.BaselineSamples {
				for i := 0; i < 2; i++ {
					for j := 0; j < 2; j++ {
						v := s.baselineValues[i][j][:p.BaselineSamples]
						sort.Slice(v, func(a, b int) bool { return v[a] < v[b] })
					}
					s.Baselines[i] = Baseline{TCPMS: s.baselineValues[i][0][p.BaselineSamples/2], UDPMS: s.baselineValues[i][1][p.BaselineSamples/2]}
				}
			}
		}
	}
	if before != s.Up {
		s.LastChange = now
	}
	if s.Up {
		s.RecoverySince = time.Time{}
		s.RecoveryCleanSamples = 0
	}
}
