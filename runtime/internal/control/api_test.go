package control

import (
	"encoding/json"
	"strings"
	"testing"
)

// uhttpd injects this field into authenticated ubus requests before rpcd
// forwards the envelope to the exec plugin. It is transport metadata, never
// part of the operation sent to the controller.
func TestAuthenticatedRPCEnvelopePreservesOperationAndReadOnlyBoundary(t *testing.T) {
	for _, operation := range []string{"status", "profiles", "settings", "primary-awg", "help", "capabilities"} {
		t.Run(operation, func(t *testing.T) {
			raw, err := json.Marshal(map[string]string{"ubus_rpc_session": "0123456789abcdef0123456789abcdef", "request": `{"operation":"` + operation + `"}`})
			if err != nil {
				t.Fatal(err)
			}
			request, err := ParseAPI(raw, true, true)
			if err != nil || request.Operation != operation || request.Write() {
				t.Fatalf("authenticated LuCI read failed: operation=%q error=%v", request.Operation, err)
			}
		})
	}
	write := []byte(`{"ubus_rpc_session":"0123456789abcdef0123456789abcdef","request":"{\"operation\":\"refresh\"}"}`)
	if _, err := ParseAPI(write, true, true); err == nil {
		t.Fatal("session metadata bypassed read-only dispatch")
	}
	request, err := ParseAPI(write, true, false)
	if err != nil || request.Operation != "refresh" || !request.Write() {
		t.Fatalf("authenticated LuCI write failed: operation=%q error=%v", request.Operation, err)
	}
}

func TestRPCSessionMetadataDoesNotRelaxOperationOrEnvelopeValidation(t *testing.T) {
	for _, raw := range []string{
		`{"request":"{\"operation\":\"status\"}","ubus_rpc_session":"test","path":"/etc/shadow"}`,
		`{"request":"{\"operation\":\"status\"}","ubus_rpc_session":123}`,
		`{"request":"{\"operation\":\"status\",\"ubus_rpc_session\":\"test\"}","ubus_rpc_session":"test"}`,
		`{"request":"{\"operation\":\"status\"}","ubus_rpc_session":"a","ubus_rpc_session":"b"}`,
	} {
		if _, err := ParseAPI([]byte(raw), true, true); err == nil {
			t.Fatal("malformed authenticated RPC request accepted")
		}
	}
	if _, err := ParseAPI([]byte(`{"operation":"status","ubus_rpc_session":"test"}`), false, true); err == nil {
		t.Fatal("RPC-only metadata accepted as a direct controller argument")
	}
}

func TestAPIReadOnlyCannotForgeWritesOrArguments(t *testing.T) {
	for _, raw := range []string{`{"operation":"import","content":"x"}`, `{"operation":"select","id":"auto"}`, `{"operation":"settings","settings":{}}`, `{"operation":"refresh"}`, `{"operation":"primary-awg","activate":true}`} {
		if _, e := ParseAPI([]byte(raw), false, true); e == nil {
			t.Fatalf("write accepted: %s", raw)
		}
	}
	for _, raw := range []string{`{"operation":"status","content":"x"}`, `{"operation":"status","path":"/etc/shadow"}`, `{"operation":"status"} {}`, `{"operation":"device","client":"127.0.0.1","value":"direct"}`} {
		if _, e := ParseAPI([]byte(raw), false, false); e == nil {
			t.Fatalf("invalid request accepted: %s", raw)
		}
	}
	if _, e := ParseAPI([]byte(`{"request":"{\"operation\":\"status\"}"}`), true, true); e != nil {
		t.Fatal(e)
	}
	if _, e := ParseAPI([]byte(`{"request":"{\"operation\":\"refresh\"}"}`), true, true); e == nil {
		t.Fatal("wrapped forged write accepted")
	}
	if _, e := ParseAPI([]byte(strings.Repeat("x", MaxAPIBytes+1)), false, false); e == nil {
		t.Fatal("oversize accepted")
	}
}

func TestAPIDuplicateJSONFieldsRejected(t *testing.T) {
	for _, raw := range []string{`{"operation":"status","operation":"profiles"}`, `{"operation":"settings","settings":{"enabled":true,"enabled":false}}`, `null`, `[]`} {
		if _, e := ParseAPI([]byte(raw), false, false); e == nil {
			t.Fatalf("ambiguous JSON accepted: %s", raw)
		}
	}
}

func TestRollbackConfirmRequiresExplicitAcceptanceAndWriteMethod(t *testing.T) {
	for _, raw := range []string{`{"operation":"rollback-confirm"}`, `{"operation":"rollback-confirm","accepted":false}`, `{"operation":"rollback-confirm","accepted":true,"path":"/tmp/file"}`} {
		if _, e := ParseAPI([]byte(raw), false, false); e == nil {
			t.Fatal("invalid rollback confirmation accepted")
		}
	}
	if _, e := ParseAPI([]byte(`{"operation":"rollback-confirm","accepted":true}`), false, true); e == nil {
		t.Fatal("read-only confirmation accepted")
	}
}

// Export returns private credentials, so only the write method may run it.
func TestConnectionExportIsWriteOnlyAndStrict(t *testing.T) {
	for _, raw := range []string{
		`{"request":"{\"operation\":\"connection-export\",\"id\":\"conn-a\"}"}`,
		`{"request":"{\"operation\":\"connection-export\",\"id\":\"conn-a\",\"expected_generation\":3}"}`,
		`{"ubus_rpc_session":"0123456789abcdef0123456789abcdef","request":"{\"operation\":\"connection-export\",\"id\":\"conn-a\"}"}`,
	} {
		if _, err := ParseAPI([]byte(raw), true, true); err == nil {
			t.Fatalf("read-only RPC accepted credential export: %s", raw)
		}
		request, err := ParseAPI([]byte(raw), true, false)
		if err != nil || request.Operation != "connection-export" || request.ID != "conn-a" || !request.Write() {
			t.Fatalf("write RPC export rejected: %v", err)
		}
	}
	if _, err := ParseAPI([]byte(`{"operation":"connection-export","id":"conn-a"}`), false, true); err == nil {
		t.Fatal("read-only CLI accepted credential export")
	}
	for _, raw := range []string{
		`{"operation":"connection-export"}`,
		`{"operation":"connection-export","id":"auto"}`,
		`{"operation":"connection-export","id":"../conn"}`,
		`{"operation":"connection-export","id":"conn-a","expected_generation":0}`,
		`{"operation":"connection-export","id":"conn-a","data":"x"}`,
		`{"operation":"connection-export","id":"conn-a","selection":{"mode":"auto"}}`,
		`{"operation":"connection-export","id":"conn-a","path":"/etc/flr-runtime/connections.json"}`,
	} {
		if _, err := ParseAPI([]byte(raw), false, false); err == nil {
			t.Fatalf("invalid export request accepted: %s", raw)
		}
	}
	// Other generation-checked operations still require a generation.
	if _, err := ParseAPI([]byte(`{"operation":"connection-test","id":"conn-a"}`), false, false); err == nil {
		t.Fatal("generation became optional for a mutating operation")
	}
}
