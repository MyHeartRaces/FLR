package config

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestSwitchAWGRestoresOnlyOwnedStateAtEveryFailure(t *testing.T) {
	fields, err := ParseAWG([]byte(publicAWG()))
	if err != nil {
		t.Fatal(err)
	}
	for fail := 1; fail <= 4; fail++ {
		before := awgOwnedState{"flr_awg": {".type": "interface", "proto": "amneziawg", "private_key": dummyKey}, "flr_peer": {".type": "amneziawg_flr_awg", "endpoint_host": "192.0.2.99"}}
		step := 0
		restored := false
		check := func() error {
			step++
			if step == fail {
				return errors.New("public native failure")
			}
			return nil
		}
		ops := awgSwitchOps{
			Snapshot: func(context.Context) (awgOwnedState, error) { return before, check() },
			Down:     func(context.Context) error { return check() },
			Apply:    func(context.Context, map[string]string, string) error { return check() },
			Reload:   func(context.Context) error { return check() },
			Restore: func(ctx context.Context, old awgOwnedState) error {
				if ctx.Err() != nil || !reflect.DeepEqual(before, old) {
					t.Fatal("restore used canceled context or lost previous owned fields")
				}
				restored = true
				return nil
			},
		}
		if err := switchAWGWith(context.Background(), fields, "eth1", ops); err == nil {
			t.Fatal("native failure reported success")
		}
		if fail > 1 && !restored {
			t.Fatal("partial switch did not restore owned AWG")
		}
		if fail == 1 && restored {
			t.Fatal("failed snapshot mutated native state")
		}
	}
}

func TestSwitchAWGCancellationStillRestoresAndInvalidInputDoesNothing(t *testing.T) {
	fields, _ := ParseAWG([]byte(publicAWG()))
	ctx, cancel := context.WithCancel(context.Background())
	restored := false
	ops := awgSwitchOps{
		Snapshot: func(context.Context) (awgOwnedState, error) { return awgOwnedState{}, nil },
		Down:     func(context.Context) error { return nil },
		Apply:    func(context.Context, map[string]string, string) error { cancel(); return context.Canceled },
		Reload:   func(context.Context) error { return nil },
		Restore:  func(ctx context.Context, old awgOwnedState) error { restored = ctx.Err() == nil; return nil },
	}
	if err := switchAWGWith(ctx, fields, "eth1", ops); err == nil || !restored {
		t.Fatal("canceled switch skipped bounded recovery")
	}
	ops.Snapshot = func(context.Context) (awgOwnedState, error) {
		t.Fatal("invalid fields reached native command")
		return nil, nil
	}
	if err := switchAWGWith(context.Background(), map[string]string{"PrivateKey": "bad"}, "eth1", ops); err == nil {
		t.Fatal("invalid AWG accepted")
	}
}
