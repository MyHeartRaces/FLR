package health

import (
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"time"
)

const Interval = 5 * time.Second
const RoundDeadline = 4 * time.Second

type TargetResult struct {
	TCP           bool  `json:"tcp"`
	UDP           bool  `json:"udp"`
	TCPDurationMS int64 `json:"tcp_duration_ms"`
	UDPDurationMS int64 `json:"udp_duration_ms"`
}
type Result struct {
	NotMeasured string          `json:"not_measured,omitempty"`
	Measured    bool            `json:"measured"`
	Targets     [2]TargetResult `json:"targets"`
	TCP         bool            `json:"tcp"`
	UDP         bool            `json:"udp"`
	RTT         time.Duration   `json:"round_duration_ns"`
}
type State struct {
	Reason               string         `json:"reason"`
	Degraded             bool           `json:"degraded"`
	Window               EvidenceWindow `json:"window"`
	Baselines            [2]Baseline    `json:"baselines"`
	BaselineSamples      int            `json:"baseline_samples"`
	RecoveryCleanSamples int            `json:"recovery_clean_samples"`
	policy               Policy
	evidence             [64]evidenceRound
	evidenceCount        int
	lastEvidence         time.Time
	baselineValues       [2][2][60]int64
	Up                   bool      `json:"healthy"`
	Initialized          bool      `json:"-"`
	Failures             int       `json:"consecutive_failures"`
	RecoverySince        time.Time `json:"recovery_since,omitzero"`
	LastCheck            time.Time `json:"last_check"`
	LastChange           time.Time `json:"last_change"`
	Last                 Result    `json:"probe"`
}

func (s *State) Healthy() bool { return s.Up }
func (s *State) Update(now time.Time, r Result, present bool) {
	s.Last = r
	if present && r.NotMeasured != "" {
		s.RecoverySince = time.Time{}
		s.RecoveryCleanSamples = 0
		return
	}
	s.LastCheck = now
	before := s.Up
	if !present {
		s.Up = false
		s.Initialized = true
		s.Failures = 3
		s.RecoverySince = time.Time{}
	} else if r.TCP && r.UDP {
		s.Failures = 0
		if !s.Initialized {
			s.Initialized = true
			s.Up = true
		} else if !s.Up {
			if s.RecoverySince.IsZero() {
				s.RecoverySince = now
			}
			if now.Sub(s.RecoverySince) >= 60*time.Second {
				s.Up = true
			}
		}
	} else {
		s.Initialized = true
		s.Failures++
		s.RecoverySince = time.Time{}
		if s.Failures >= 3 {
			s.Up = false
		}
	}
	if before != s.Up {
		s.LastChange = now
	}
	if s.Up {
		s.RecoverySince = time.Time{}
	}
}
func Select(states map[contract.Channel]State, manual contract.Channel) contract.Selection {
	s := contract.Selection{General: contract.Down, Games: contract.Down}
	for _, c := range []contract.Channel{contract.AWG, contract.Gecko, contract.VLESS} {
		v := states[c]
		if v.Healthy() {
			s.General = c
			break
		}
	}
	if manual == contract.VLESS {
		v := states[manual]
		if v.Healthy() {
			s.Games = manual
		}
		return s
	}
	for _, c := range []contract.Channel{contract.AWG, contract.Gecko} {
		v := states[c]
		if v.Healthy() {
			s.Games = c
			break
		}
	}
	return s
}
