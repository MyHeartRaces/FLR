package config

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/dataplane"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"github.com/MyHeartRaces/FLR/runtime/internal/native"
)

type awgOwnedState map[string]map[string]any

// AWGOwnedState is private restart evidence, never a public API DTO.
type AWGOwnedState = awgOwnedState

func SnapshotAWG(ctx context.Context) (AWGOwnedState, error) { return nativeAWGOps.Snapshot(ctx) }
func RestoreAWG(ctx context.Context, state AWGOwnedState) error {
	if err := ValidateAWGOwnedState(state); err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := nativeAWGOps.Snapshot(bounded); err != nil {
		return fmt.Errorf("current owned AWG rejected")
	}
	if err := nativeAWGOps.Down(bounded); err != nil {
		return fmt.Errorf("owned AWG down failed")
	}
	if err := nativeAWGOps.Restore(bounded, state); err != nil {
		return fmt.Errorf("owned AWG restore failed")
	}
	if err := nativeAWGOps.Reload(bounded); err != nil {
		return fmt.Errorf("owned AWG reload failed")
	}
	return nil
}
func ValidateAWGOwnedState(state AWGOwnedState) error {
	for section, values := range state {
		kind := "interface"
		if section == "flr_peer" {
			kind = "amneziawg_flr_awg"
		} else if section != "flr_awg" {
			return fmt.Errorf("foreign AWG checkpoint section")
		}
		if values[".type"] != kind || (section == "flr_awg" && values["proto"] != "amneziawg") {
			return fmt.Errorf("AWG checkpoint type rejected")
		}
		for key, value := range values {
			if key != ".type" && !regexp.MustCompile(`^[a-zA-Z0-9_]+$`).MatchString(key) {
				return fmt.Errorf("AWG checkpoint field rejected")
			}
			switch value := value.(type) {
			case string:
				if strings.ContainsAny(value, "\r\n\x00") {
					return fmt.Errorf("AWG checkpoint scalar rejected")
				}
			case []any:
				for _, item := range value {
					text, ok := item.(string)
					if !ok || strings.ContainsAny(text, "\r\n\x00") {
						return fmt.Errorf("AWG checkpoint list rejected")
					}
				}
			default:
				return fmt.Errorf("AWG checkpoint value rejected")
			}
		}
	}
	return nil
}

type awgSwitchOps struct {
	Snapshot       func(context.Context) (awgOwnedState, error)
	Down           func(context.Context) error
	Apply          func(context.Context, map[string]string, string) error
	Reload         func(context.Context) error
	Restore        func(context.Context, awgOwnedState) error
	observedReload func(context.Context, AWGSwitchObserver) error
}

// AWGSwitchObserver reports the candidate's existing readiness and route
// operations. It is never called for the rollback of the previous owner.
type AWGSwitchObserver func(stage string, started time.Time, err error)

func SwitchAWG(ctx context.Context, fields map[string]string, wan string) error {
	return switchAWGWith(ctx, fields, wan, nativeAWGOps)
}
func SwitchAWGObserved(ctx context.Context, fields map[string]string, wan string, observe AWGSwitchObserver) error {
	return switchAWGWith(ctx, fields, wan, nativeAWGOps, observe)
}
func switchAWGWith(ctx context.Context, fields map[string]string, wan string, ops awgSwitchOps, observe ...AWGSwitchObserver) error {
	if _, err := AWGText(fields); err != nil || !regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`).MatchString(wan) {
		return fmt.Errorf("invalid native AWG or WAN input")
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	old, err := ops.Snapshot(bounded)
	if err != nil {
		return fmt.Errorf("cannot snapshot owned AWG state")
	}
	if err = ops.Down(bounded); err == nil {
		err = ops.Apply(bounded, fields, wan)
	}
	if err == nil {
		if len(observe) != 0 && ops.observedReload != nil {
			err = ops.observedReload(bounded, observe[0])
		} else {
			err = ops.Reload(bounded)
		}
	}
	if err == nil {
		return nil
	}
	// Restore only the previous owned sections, even after caller cancellation.
	recovery, stop := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer stop()
	downErr := ops.Down(recovery)
	restoreErr := ops.Restore(recovery, old)
	reloadErr := ops.Reload(recovery)
	if downErr != nil || restoreErr != nil || reloadErr != nil {
		return fmt.Errorf("native AWG switch failed; owned recovery pending")
	}
	return fmt.Errorf("native AWG switch failed; previous owned state restored")
}
func awgCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	result := native.Execute(ctx, native.Limit(name), "", name, args...)
	return result.Stdout, result.Err
}

type awgCommandFunc func(context.Context, string, ...string) ([]byte, error)

var nativeAWGOps = nativeAWGOpsWith(awgCommand, dataplane.EnsureRoutesContext, func() bool { return health.Present(contract.AWG) })

func nativeAWGOpsWith(command awgCommandFunc, routes func(context.Context) error, present func() bool) awgSwitchOps {
	ops := awgSwitchOps{
		Snapshot: func(ctx context.Context) (awgOwnedState, error) {
			state := awgOwnedState{}
			for _, section := range []string{"flr_awg", "flr_peer"} {
				typeRaw, err := command(ctx, "uci", "-q", "get", "network."+section)
				if native.Exit(err, 1) {
					continue
				}
				if err != nil {
					return nil, fmt.Errorf("owned section unavailable")
				}
				kind := strings.TrimSpace(string(typeRaw))
				if (section == "flr_awg" && kind != "interface") || (section == "flr_peer" && kind != "amneziawg_flr_awg") {
					return nil, fmt.Errorf("owned section type mismatch")
				}
				request, _ := json.Marshal(map[string]string{"config": "network", "section": section})
				raw, err := command(ctx, "ubus", "call", "uci", "get", string(request))
				var reply struct {
					Values map[string]any `json:"values"`
				}
				if err != nil || json.Unmarshal(raw, &reply) != nil || reply.Values == nil {
					return nil, fmt.Errorf("owned section snapshot rejected")
				}
				values := map[string]any{".type": kind}
				for key, value := range reply.Values {
					if strings.HasPrefix(key, ".") {
						continue
					}
					if !regexp.MustCompile(`^[a-zA-Z0-9_]+$`).MatchString(key) {
						return nil, fmt.Errorf("invalid owned field")
					}
					values[key] = value
				}
				if section == "flr_awg" && values["proto"] != "amneziawg" {
					return nil, fmt.Errorf("owned AWG protocol mismatch")
				}
				state[section] = values
			}
			return state, nil
		},
		Down: func(ctx context.Context) error {
			// ifdown addresses only the managed interface and also tolerates its first
			// activation. Subsequent reload applies the two owned UCI sections.
			_, err := command(ctx, "uci", "-q", "get", "network.flr_awg")
			if native.Exit(err, 1) {
				return nil
			}
			if err != nil {
				return err
			}
			_, err = command(ctx, "ifdown", "flr_awg")
			return err
		},
		Apply: func(ctx context.Context, fields map[string]string, wan string) error {
			return configureAWGWith(fields, func(name string, args ...string) error {
				_, err := command(ctx, name, args...)
				return err
			})
		},
		observedReload: func(ctx context.Context, observe AWGSwitchObserver) error {
			if _, err := command(ctx, "uci", "commit", "network"); err != nil {
				return err
			}
			if _, err := command(ctx, "ubus", "call", "network", "reload"); err != nil {
				return err
			}
			_, err := command(ctx, "uci", "-q", "get", "network.flr_awg")
			if native.Exit(err, 1) {
				return nil
			}
			if err != nil {
				return err
			}
			_, err = command(ctx, "ifup", "flr_awg")
			if err != nil {
				return err
			}
			ready := time.Now()
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for !present() {
				select {
				case <-ctx.Done():
					if observe != nil {
						observe("ready", ready, ctx.Err())
					}
					return ctx.Err()
				case <-ticker.C:
				}
			}
			if observe != nil {
				observe("ready", ready, nil)
			}
			start := time.Now()
			err = routes(ctx)
			if observe != nil {
				observe("routes", start, err)
			}
			return err
		},
		Restore: func(ctx context.Context, state awgOwnedState) error { return restoreOwnedAWGWith(ctx, state, command) },
	}
	reload := ops.observedReload
	ops.Reload = func(ctx context.Context) error { return reload(ctx, nil) }
	return ops
}

func restoreOwnedAWGWith(ctx context.Context, state awgOwnedState, command awgCommandFunc) error {
	for _, section := range []string{"flr_peer", "flr_awg"} {
		_, err := command(ctx, "uci", "-q", "delete", "network."+section)
		if err != nil && !native.Exit(err, 1) {
			return err
		}
	}
	for _, section := range []string{"flr_awg", "flr_peer"} {
		values, exists := state[section]
		if !exists {
			continue
		}
		kind, ok := values[".type"].(string)
		if !ok || (section == "flr_awg" && kind != "interface") || (section == "flr_peer" && kind != "amneziawg_flr_awg") {
			return fmt.Errorf("owned restore type rejected")
		}
		if _, err := command(ctx, "uci", "set", "network."+section+"="+kind); err != nil {
			return err
		}
		keys := []string{}
		for key := range values {
			if key != ".type" {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		for _, key := range keys {
			if !regexp.MustCompile(`^[a-zA-Z0-9_]+$`).MatchString(key) {
				return fmt.Errorf("owned restore field rejected")
			}
			var list []string
			operation := "set"
			switch value := values[key].(type) {
			case string:
				list = []string{value}
			case []any:
				operation = "add_list"
				for _, item := range value {
					text, ok := item.(string)
					if !ok {
						return fmt.Errorf("owned restore list rejected")
					}
					list = append(list, text)
				}
			default:
				return fmt.Errorf("owned restore value rejected")
			}
			for _, value := range list {
				if _, err := command(ctx, "uci", operation, "network."+section+"."+key+"="+value); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
