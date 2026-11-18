package profile

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func xrayWSInput(t *testing.T, settings map[string]any) []byte {
	t.Helper()
	p := one(t, fixture(t, "xhttp.json"))
	o := clone(p.Outbound)
	stream := object(o["streamSettings"])
	stream["network"] = "ws"
	stream["security"] = "tls"
	delete(stream, "realitySettings")
	stream["tlsSettings"] = map[string]any{"serverName": "example.com", "fingerprint": "chrome"}
	delete(stream, "xhttpSettings")
	stream["wsSettings"] = settings
	b, err := json.Marshal(map[string]any{"outbounds": []any{o}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func renderedXrayWS(t *testing.T, p Profile) map[string]any {
	t.Helper()
	r, err := Render(p, "eth1", "/run/flr")
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err = json.Unmarshal(r.Xray, &config); err != nil {
		t.Fatal(err)
	}
	o := object(array(config["outbounds"])[0])
	stream := object(o["streamSettings"])
	original := object(clone(p.Outbound)["streamSettings"])
	for _, field := range []string{"security", "tlsSettings", "realitySettings"} {
		if !reflect.DeepEqual(stream[field], original[field]) {
			t.Fatal("early-data adapter changed required security", field)
		}
	}
	if !reflect.DeepEqual(o["settings"], clone(p.Outbound)["settings"]) {
		t.Fatal("early-data adapter changed required server/user settings")
	}
	return object(stream["wsSettings"])
}

func TestXrayWebSocketNativeEarlyDataPreservesOwnedProfile(t *testing.T) {
	settings := map[string]any{"path": "/public?a=1&b=x%2Fy#fragment", "maxEarlyData": 2048, "earlyDataHeaderName": "sec-websocket-protocol", "headers": map[string]any{"Host": "example.com", "X-Public": "value"}}
	p := one(t, xrayWSInput(t, settings))
	before := clone(p.Outbound)
	w := renderedXrayWS(t, p)
	if w["path"] != "/public?a=1&b=x%2Fy&ed=2048#fragment" || !reflect.DeepEqual(w["headers"], settings["headers"]) {
		t.Fatal("native ed adaptation lost path, query, fragment or headers", w)
	}
	if _, exists := w["maxEarlyData"]; exists {
		t.Fatal("ignored native JSON early-data field remains")
	}
	if _, exists := w["earlyDataHeaderName"]; exists {
		t.Fatal("ignored native JSON header field remains")
	}
	if !reflect.DeepEqual(before, clone(p.Outbound)) {
		t.Fatal("render mutated stored input")
	}
}

func TestXrayWebSocketEarlyDataZeroBoundaryAndExistingQuery(t *testing.T) {
	for _, tc := range []struct {
		path string
		max  any
		want string
	}{
		{"/public", 0, "/public"},
		{"/public?b=2&a=1", 0, "/public?b=2&a=1"},
		{"/public?token=x%20y", nil, "/public?token=x%20y"},
		{"/public?a=1&ed=2048#fragment", 2048, "/public?a=1&ed=2048#fragment"},
		{"/public?ed=0", 0, "/public?ed=0"},
		{"/public?z=1&ed=2048", 2048, "/public?z=1&ed=2048"},
		{"/public", 2147483647, "/public?ed=2147483647"},
		{"/public?ed=32", nil, "/public?ed=32"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			settings := map[string]any{"path": tc.path}
			if tc.max != nil {
				settings["maxEarlyData"] = tc.max
			}
			w := renderedXrayWS(t, one(t, xrayWSInput(t, settings)))
			if w["path"] != tc.want {
				t.Fatal("early-data value changed", w)
			}
		})
	}
}

func TestXrayWebSocketUnsupportedSemanticsRejectAtImport(t *testing.T) {
	for _, settings := range []map[string]any{
		{"path": "/public", "maxEarlyData": 2048, "earlyDataHeaderName": "X-Custom"},
		{"path": "/public", "earlyDataHeaderName": ""},
		{"path": "/public", "maxEarlyData": -1},
		{"path": "/public", "maxEarlyData": 2147483648},
		{"path": "/public", "maxEarlyData": nil},
		{"path": "/public?ed=4", "maxEarlyData": 0},
		{"path": "/public?ed=4", "maxEarlyData": 8},
		{"path": "/public?ed=4&ed=4"},
		{"path": "/public?ed=bad"},
		{"path": "/public?ed=-1"},
		{"path": "/public?ed=2147483648"},
		{"path": "/public?ed="},
		{"path": "/public?b=2&a=1", "maxEarlyData": 4},
		{"path": "/public?token=x%20y", "maxEarlyData": 4},
		{"path": "/public?broken=%ZZ", "maxEarlyData": 4},
		{"path": "/public", "maxEarlyData": 4, "headers": map[string]any{"sec-websocket-protocol": "required-other-value"}},
	} {
		input := xrayWSInput(t, settings)
		if _, err := Parse(input); err == nil {
			t.Fatalf("unsupported native WS semantics accepted: %s", input)
		}
	}
}

func TestXrayWebSocketMalformedReservedEDRejectsAtImport(t *testing.T) {
	for _, path := range []string{
		"/public?ed=%ZZ",
		"/public?%65d=%ZZ",
		"/public?%65%64=%ZZ",
		"/public?ed=1;other=2",
		"/public?%65d=1;other=2",
		"/public?other=2;ed=1",
		"/public?other=2;%65d=1",
	} {
		for _, mode := range []struct {
			name string
			max  any
		}{{"absent", nil}, {"zero", 0}} {
			t.Run(mode.name+path, func(t *testing.T) {
				settings := map[string]any{"path": path}
				if mode.max != nil {
					settings["maxEarlyData"] = mode.max
				}
				if _, err := Parse(xrayWSInput(t, settings)); err == nil {
					t.Fatal("malformed reserved ed accepted before effects", settings)
				}
			})
		}
	}
}

func TestXrayWebSocketOpaqueQueryWithoutEDRemainsUnchanged(t *testing.T) {
	for _, path := range []string{
		"/public?token=%ZZ",
		"/public?opaque=1;other=2",
		"/public?%ZZ=opaque",
		"/public?%65dExtra=%ZZ",
		"/public?token=has%3Bed%3D1",
		"/public?b=2&a=x%20y#fragment",
	} {
		for _, mode := range []struct {
			name string
			max  any
		}{{"absent", nil}, {"zero", 0}} {
			t.Run(mode.name+path, func(t *testing.T) {
				settings := map[string]any{"path": path}
				if mode.max != nil {
					settings["maxEarlyData"] = mode.max
				}
				w := renderedXrayWS(t, one(t, xrayWSInput(t, settings)))
				if w["path"] != path {
					t.Fatal("unrelated opaque query changed", w)
				}
			})
		}
	}
}

func TestNativeXrayRealitySupportedNetworksAndExplicitRejection(t *testing.T) {
	for _, network := range []string{"", "raw", "tcp", "xhttp", "splithttp", "grpc", "ws", "http"} {
		t.Run(network, func(t *testing.T) {
			o := clone(one(t, fixture(t, "xhttp.json")).Outbound)
			stream := object(o["streamSettings"])
			stream["network"] = network
			if network != "xhttp" && network != "splithttp" {
				delete(stream, "xhttpSettings")
			}
			if network == "grpc" {
				stream["grpcSettings"] = map[string]any{"serviceName": "public"}
			}
			if network == "ws" {
				stream["wsSettings"] = map[string]any{"path": "/public", "maxEarlyData": 2048}
			}
			b, err := json.Marshal(map[string]any{"outbounds": []any{o}})
			if err != nil {
				t.Fatal(err)
			}
			profiles, err := Parse(b)
			if network == "ws" || network == "http" {
				if err == nil || !strings.Contains(err.Error(), "Xray REALITY only supports RAW, XHTTP and gRPC") {
					t.Fatal("unsupported native REALITY transport was not explicitly rejected at import", network, err)
				}
				return
			}
			if err != nil || len(profiles) != 1 || profiles[0].Engine != "xray" {
				t.Fatal("supported native REALITY transport rejected", network, err)
			}
		})
	}
}

func TestSingBoxWebSocketCustomEarlyDataHeaderRemainsSupported(t *testing.T) {
	input := []byte(`{"outbounds":[{"type":"vless","server":"example.com","server_port":443,"uuid":"00000000-0000-4000-8000-000000000000","tls":{"enabled":true,"server_name":"example.com"},"transport":{"type":"ws","path":"/public","max_early_data":2048,"early_data_header_name":"X-Custom"}}]}`)
	p := one(t, input)
	r, err := Render(p, "eth1", "/run/flr")
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err = json.Unmarshal(r.SingBox, &config); err != nil {
		t.Fatal(err)
	}
	w := object(object(array(config["outbounds"])[0])["transport"])
	if w["max_early_data"] != float64(2048) || w["early_data_header_name"] != "X-Custom" {
		t.Fatal("sing-box custom early-data header lost", w)
	}
}
