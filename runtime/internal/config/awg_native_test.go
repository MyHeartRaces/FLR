package config

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type testUCI struct {
	sections awgOwnedState
	calls    int
	fail     int
}

func newTestUCI() *testUCI {
	return &testUCI{sections: awgOwnedState{
		"flr_awg":  {".type": "interface", "proto": "amneziawg", "private_key": dummyKey, "addresses": []any{"10.77.0.2/32"}},
		"flr_peer": {".type": "amneziawg_flr_awg", "endpoint_host": "192.0.2.99", "endpoint_port": "51820"},
		"lan":      {".type": "interface", "proto": "static", "ipaddr": "192.168.8.1"},
	}}
}
func (u *testUCI) command(_ context.Context, name string, args ...string) ([]byte, error) {
	u.calls++
	if u.calls == u.fail {
		return nil, errors.New("injected public native failure")
	}
	if name == "ifdown" || name == "ifup" {
		if len(args) != 1 || args[0] != "flr_awg" {
			return nil, errors.New("foreign interface mutation")
		}
		return nil, nil
	}
	if name == "ubus" {
		if len(args) == 3 && args[1] == "network" && args[2] == "reload" {
			return nil, nil
		}
		var query map[string]string
		if len(args) != 4 || args[0] != "call" || args[1] != "uci" || args[2] != "get" || json.Unmarshal([]byte(args[3]), &query) != nil || query["config"] != "network" {
			return nil, errors.New("unexpected ubus command")
		}
		return json.Marshal(map[string]any{"values": u.sections[query["section"]]})
	}
	if name != "uci" {
		return nil, errors.New("unexpected native executable")
	}
	if args[0] == "-q" {
		args = args[1:]
	}
	if args[0] == "commit" && args[1] == "network" {
		return nil, nil
	}
	path, value, _ := strings.Cut(args[1], "=")
	parts := strings.Split(path, ".")
	if len(parts) < 2 || parts[0] != "network" || (parts[1] != "flr_awg" && parts[1] != "flr_peer") {
		return nil, errors.New("foreign UCI mutation")
	}
	section := parts[1]
	field := ".type"
	if len(parts) == 3 {
		field = parts[2]
	}
	switch args[0] {
	case "get":
		text, _ := u.sections[section][field].(string)
		return []byte(text), nil
	case "delete":
		if len(parts) == 2 {
			delete(u.sections, section)
		} else {
			delete(u.sections[section], field)
		}
	case "set", "add_list":
		if u.sections[section] == nil {
			u.sections[section] = map[string]any{}
		}
		if args[0] == "add_list" {
			list, _ := u.sections[section][field].([]any)
			u.sections[section][field] = append(list, value)
		} else {
			u.sections[section][field] = value
		}
	default:
		return nil, errors.New("unexpected UCI operation")
	}
	return nil, nil
}
func TestSwitchAWGEveryNativeCommandPreservesForeignState(t *testing.T) {
	fields, _ := ParseAWG([]byte(publicAWG()))
	baseline := newTestUCI()
	ops := nativeAWGOpsWith(baseline.command, func(context.Context) error { return nil }, func() bool { return true })
	if err := switchAWGWith(context.Background(), fields, "eth1", ops); err != nil {
		t.Fatal(err)
	}
	if baseline.sections["flr_peer"]["endpoint_host"] != "192.0.2.10" {
		t.Fatal("native transaction did not apply new endpoint")
	}
	for fail := 1; fail <= baseline.calls; fail++ {
		u := newTestUCI()
		before, _ := json.Marshal(u.sections)
		u.fail = fail
		ops := nativeAWGOpsWith(u.command, func(context.Context) error { return nil }, func() bool { return true })
		if err := switchAWGWith(context.Background(), fields, "eth1", ops); err == nil {
			t.Fatalf("command %d failure reported success", fail)
		}
		var expected awgOwnedState
		json.Unmarshal(before, &expected)
		if !reflect.DeepEqual(u.sections, expected) {
			t.Fatalf("command %d failure changed old owned or foreign state", fail)
		}
	}
}
