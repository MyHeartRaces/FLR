package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestExportCompleteSyntheticContracts(t *testing.T) {
	directory := t.TempDir()
	if e := export(directory, "../../internal/profile/testdata"); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if e != nil {
		t.Fatal(e)
	}
	var manifest struct {
		Cases []caseRecord `json:"cases"`
	}
	if e = json.Unmarshal(b, &manifest); e != nil {
		t.Fatal(e)
	}
	found := map[string]bool{}
	for _, c := range manifest.Cases {
		if c.ID == "xray-reality-ws" || c.ID == "xray-reality-ws-nondefault" {
			t.Fatal("invalid native REALITY+WS positive contract emitted", c.ID)
		}
		found[c.ID] = true
		if c.WAN != "eth1" || len(c.Outer) != 1 {
			t.Fatal("renderer owned WAN/endpoint contract missing", c.ID)
		}
		if _, e = os.Stat(filepath.Join(directory, c.SingBox)); e != nil {
			t.Fatal(e)
		}
	}
	for _, c := range manifest.Cases {
		var expected map[string]any
		var key string
		switch c.ID {
		case "xray-tls-ws-nondefault":
			key = "wsSettings"
			expected = map[string]any{"path": "/public?ed=2048"}
		case "xray-tls-grpc-nondefault", "xray-reality-grpc-nondefault":
			key = "grpcSettings"
			expected = map[string]any{"serviceName": "public", "authority": "example.com", "multiMode": true, "idle_timeout": float64(45), "health_check_timeout": float64(15), "permit_without_stream": true, "initial_windows_size": float64(65536)}
		default:
			continue
		}
		b, e := os.ReadFile(filepath.Join(directory, c.Xray))
		if e != nil {
			t.Fatal(e)
		}
		var config map[string]any
		if e = json.Unmarshal(b, &config); e != nil {
			t.Fatal(e)
		}
		outbound := config["outbounds"].([]any)[0].(map[string]any)
		stream := outbound["streamSettings"].(map[string]any)
		settings := stream[key].(map[string]any)
		if key == "wsSettings" {
			if _, exists := settings["maxEarlyData"]; exists {
				t.Fatal("ignored native early-data field remains")
			}
			if _, exists := settings["earlyDataHeaderName"]; exists {
				t.Fatal("ignored native header field remains")
			}
		}
		for field, value := range expected {
			if settings[field] != value {
				t.Fatal("nondefault supported transport field lost", c.ID, field, settings[field])
			}
		}
	}

	for _, name := range []string{"bundle-json", "gecko-json", "gecko-bounds", "salamander-uri", "xhttp-json", "tls-xhttp", "reality-xhttp", "tls-raw", "reality-raw", "tls-ws", "reality-grpc", "shadowtls-json", "wgws-json", "wgws-compact", "xray-tls-raw", "xray-tls-ws", "xray-reality-raw", "xray-reality-xhttp", "xray-reality-grpc", "xray-tls-grpc", "xray-reality-splithttp", "tls-vision", "reality-vision", "xray-tls-ws-nondefault", "xray-tls-grpc-nondefault", "xray-reality-grpc-nondefault"} {
		if !found[name] {
			t.Fatal("supported contract missing", name)
		}
	}
}
