package health

import (
	"encoding/json"
	"testing"
	"time"
)

func TestUnmeasuredRoundsDoNotCountFailuresOrRecovery(t *testing.T) {
	for _, policy := range []bool{false, true} {
		t.Run(map[bool]string{false: "slot", true: "native"}[policy], func(t *testing.T) {
			var state State
			now := time.Unix(100, 0)
			update := func(at time.Time, r Result) {
				if policy {
					state.UpdatePolicy(at, r, true, DefaultPolicy())
				} else {
					state.Update(at, r, true)
				}
			}
			update(now, measured(100))
			var canceled Result
			if err := json.Unmarshal([]byte(`{"not_measured":"cancelled"}`), &canceled); err != nil {
				t.Fatal(err)
			}
			for i := 1; i <= 3; i++ {
				update(now.Add(time.Duration(i)*5*time.Second), canceled)
			}
			if !state.Healthy() || state.Failures != 0 || !state.LastCheck.Equal(now) {
				t.Fatal("unmeasured round fabricated path failure or freshness", state.Healthy(), state.Failures, state.LastCheck)
			}
			for i := 4; i <= 6; i++ {
				update(now.Add(time.Duration(i)*5*time.Second), Result{Measured: true})
			}
			update(now.Add(35*time.Second), measured(100))
			if state.RecoverySince.IsZero() {
				t.Fatal("recovery was not started")
			}
			update(now.Add(40*time.Second), canceled)
			if !state.RecoverySince.IsZero() || state.RecoveryCleanSamples != 0 || !state.LastCheck.Equal(now.Add(35*time.Second)) {
				t.Fatal("unmeasured round qualified recovery")
			}
		})
	}
}
