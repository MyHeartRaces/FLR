package control

import (
	"encoding/json"
	"testing"
)

func TestConnectionOperationSchemasAndReadACL(t *testing.T) {
	requests := []string{
		`{"operation":"connection-list"}`,
		`{"operation":"connection-import","data":"public-input","expected_generation":1}`,
		`{"operation":"connection-update","id":"conn-test","metadata":{"name":"Main","group":"srvmain","enabled":true},"expected_generation":1}`,
		`{"operation":"connection-replace","id":"conn-test","data":"public-input","expected_generation":1}`,
		`{"operation":"connection-delete","id":"conn-test","selection":{"mode":"auto"},"expected_generation":1}`,
		`{"operation":"selection","selection":{"mode":"transport","family":"awg"},"expected_generation":1}`,
		`{"operation":"connection-order","order":{"families":[],"connections":{}},"reselect":true,"expected_generation":1}`,
		`{"operation":"connection-test","id":"conn-test","expected_generation":1}`,
		`{"operation":"vpn-activate","accepted":true,"expected_generation":1}`,
	}
	for _, raw := range requests {
		request, err := ParseAPI([]byte(raw), false, false)
		if err != nil {
			t.Fatalf("new operation rejected: %s: %v", raw, err)
		}
		_, readErr := ParseAPI([]byte(raw), false, true)
		if request.Operation == "connection-list" {
			if request.Write() || readErr != nil {
				t.Fatal("list requires write permission")
			}
		} else if !request.Write() || readErr == nil {
			t.Fatal("read ACL accepted mutation")
		}
		var object map[string]any
		json.Unmarshal([]byte(raw), &object)
		object["command"] = "sh"
		bad, _ := json.Marshal(object)
		if _, err := ParseAPI(bad, false, false); err == nil {
			t.Fatal("foreign operation argument accepted")
		}
	}
	for _, raw := range []string{
		`{"operation":"connection-import","data":"x","url":"https://example.com","expected_generation":1}`,
		`{"operation":"selection","selection":null,"expected_generation":1}`,
		`{"operation":"selection","selection":{"mode":"auto","mode":"connection"},"expected_generation":1}`,
		`{"operation":"connection-order","order":null,"expected_generation":1}`,
		`{"operation":"connection-update","id":"conn-test","metadata":null,"expected_generation":1}`,
		`{"operation":"connection-update","id":"conn-test","metadata":{},"expected_generation":1}`,
		`{"operation":"connection-test","id":"conn-test"}`,
		`{"operation":"connection-test","id":"conn-test","expected_generation":null}`,
		`{"operation":"connection-test","id":"conn-test","expected_generation":0}`,
		`{"operation":"connection-test","id":"conn-test","expected_generation":1,"data":"private-input"}`,
		`{"operation":"vpn-activate","accepted":false,"expected_generation":1}`,
	} {
		if _, err := ParseAPI([]byte(raw), false, false); err == nil {
			t.Fatalf("invalid operation accepted: %s", raw)
		}
	}
}
