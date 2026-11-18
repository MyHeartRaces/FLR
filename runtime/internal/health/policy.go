package health

import "fmt"

// Policy units are explicit in JSON. Bounds also cap the in-memory evidence.
// These conservative defaults need separate installed-router qualification.
type Policy struct {
	Enabled            bool `json:"enabled"`
	WindowSeconds      int  `json:"window_seconds"`
	MinSamples         int  `json:"min_samples"`
	FailurePercent     int  `json:"failure_percent"`
	SlowPercent        int  `json:"slow_percent"`
	TCPFloorMS         int  `json:"tcp_floor_ms"`
	UDPFloorMS         int  `json:"udp_floor_ms"`
	TCPRecoveryMS      int  `json:"tcp_recovery_ms"`
	UDPRecoveryMS      int  `json:"udp_recovery_ms"`
	LatencyMultiplier  int  `json:"latency_multiplier"`
	RecoveryMultiplier int  `json:"recovery_multiplier"`
	BaselineSamples    int  `json:"baseline_samples"`
	RecoverySeconds    int  `json:"recovery_seconds"`
	MaxGapSeconds      int  `json:"max_gap_seconds"`
}

func DefaultPolicy() Policy {
	return Policy{Enabled: true, WindowSeconds: 60, MinSamples: 8, FailurePercent: 25, SlowPercent: 75, TCPFloorMS: 1500, UDPFloorMS: 400, TCPRecoveryMS: 750, UDPRecoveryMS: 200, LatencyMultiplier: 4, RecoveryMultiplier: 2, BaselineSamples: 12, RecoverySeconds: 60, MaxGapSeconds: 30}
}
func (p Policy) Validate() error {
	if p.WindowSeconds < 30 || p.WindowSeconds > 300 || p.MinSamples < 6 || p.MinSamples > 60 || p.MinSamples > p.WindowSeconds/5+1 ||
		p.FailurePercent < 25 || p.FailurePercent > 100 || p.SlowPercent < 50 || p.SlowPercent > 100 ||
		p.TCPFloorMS < 500 || p.TCPFloorMS > 3500 || p.UDPFloorMS < 100 || p.UDPFloorMS > 2000 ||
		p.TCPRecoveryMS < 100 || p.TCPRecoveryMS >= p.TCPFloorMS || p.UDPRecoveryMS < 25 || p.UDPRecoveryMS >= p.UDPFloorMS ||
		p.LatencyMultiplier < 2 || p.LatencyMultiplier > 10 || p.RecoveryMultiplier < 1 || p.RecoveryMultiplier >= p.LatencyMultiplier ||
		p.BaselineSamples < 6 || p.BaselineSamples > 60 || p.RecoverySeconds < 60 || p.RecoverySeconds > 600 || p.MaxGapSeconds < 10 || p.MaxGapSeconds > 60 {
		return fmt.Errorf("invalid health policy bounds or hysteresis")
	}
	return nil
}
