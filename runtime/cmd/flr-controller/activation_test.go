package main

import (
	"errors"
	"github.com/MyHeartRaces/FLR/runtime/internal/control"
	"reflect"
	"testing"
)

func TestOfflineActivationHandsOffAfterUnlock(t *testing.T) {
	for _, fail := range []bool{false, true} {
		calls := []string{}
		data, e := finishOfflineActivation(control.APIRequest{Operation: "primary-awg", Activate: true}, map[string]any{"configured": true}, nil, func() error { calls = append(calls, "unlock"); return nil }, func() error {
			calls = append(calls, "start")
			if fail {
				return errors.New("private stderr")
			}
			return nil
		})
		if !reflect.DeepEqual(calls, []string{"unlock", "start"}) {
			t.Fatal(calls)
		}
		result := data.(map[string]any)
		if result["activated"] != false || result["service_start_requested"] == fail {
			t.Fatal(result)
		}
		if fail {
			if e == nil || result["activation_state"] != "error" {
				t.Fatal(result, e)
			}
		} else {
			if e != nil || result["activation_state"] != "pending" {
				t.Fatal(result, e)
			}
		}
	}
}
func TestOfflineActivationDoesNotLaunchOnFailure(t *testing.T) {
	original := errors.New("rollback remains pending")
	for _, unlockFails := range []bool{false, true} {
		starts := 0
		_, e := finishOfflineActivation(control.APIRequest{Operation: "primary-awg", Activate: true}, nil, original, func() error {
			if unlockFails {
				return errors.New("lock")
			}
			return nil
		}, func() error { starts++; return nil })
		if e == nil || starts != 0 {
			t.Fatal("failed activation launched controller")
		}
		if !unlockFails && e != original {
			t.Fatal("activation failure lost")
		}
	}
}

func TestOfflineConnectionActivationHandsOffAfterUnlock(t *testing.T) {
	calls := []string{}
	data, err := finishOfflineActivation(control.APIRequest{Operation: "vpn-activate", Accepted: true}, map[string]any{"configured": true}, nil, func() error { calls = append(calls, "unlock"); return nil }, func() error { calls = append(calls, "start"); return nil })
	if err != nil || !reflect.DeepEqual(calls, []string{"unlock", "start"}) || data.(map[string]any)["service_start_requested"] != true {
		t.Fatal("unified activation did not start runtime after releasing singleton", err)
	}
}
