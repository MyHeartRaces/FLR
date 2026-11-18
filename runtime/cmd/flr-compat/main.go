// flr-compat exports public synthetic inputs through the production import/render
// paths. It performs no network, router or native engine operations.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/MyHeartRaces/FLR/runtime/internal/bypass"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
)

type caseRecord struct {
	ID          string   `json:"id"`
	Family      string   `json:"family"`
	Engine      string   `json:"engine"`
	SingBox     string   `json:"sing_box"`
	Xray        string   `json:"xray,omitempty"`
	SidecarArgs []string `json:"sidecar_args,omitempty"`
	WAN         string   `json:"wan"`
	Outer       []string `json:"outer_endpoints"`
}

func export(directory, fixtures string) error {
	if e := os.MkdirAll(directory, 0700); e != nil {
		return e
	}
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	reality := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	ss := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16))
	replace := strings.NewReplacer("PUBLIC_TEST_PRIVATE", key, "PUBLIC_TEST_PEER", key, "PUBLIC_TEST_REALITY", reality, "PUBLIC_TEST_SS_KEY", ss)
	inputs := map[string][]byte{}
	for _, name := range []string{"bundle.json", "gecko.json", "salamander.uri", "xhttp.json", "xhttp.uri", "shadowtls.json", "wgws.json"} {
		b, e := os.ReadFile(filepath.Join(fixtures, name))
		if e != nil {
			return e
		}
		inputs[strings.ReplaceAll(name, ".", "-")] = []byte(replace.Replace(string(b)))
	}
	gecko := strings.ReplaceAll(string(inputs["gecko-json"]), "600", "512")
	gecko = strings.ReplaceAll(gecko, "1300", "2048")
	inputs["gecko-bounds"] = []byte(gecko)
	for _, method := range []string{"2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		b := strings.ReplaceAll(string(inputs["shadowtls-json"]), "2022-blake3-aes-128-gcm", method)
		inputs[method] = []byte(strings.ReplaceAll(b, ss, key))
	}
	for _, security := range []string{"tls", "reality"} {
		for _, network := range []string{"raw", "ws", "grpc", "xhttp", "splithttp"} {
			uri := "vless://00000000-0000-4000-8000-000000000000@example.com:443?security=" + security + "&sni=example.com&type=" + network
			if security == "reality" {
				uri += "&pbk=" + reality + "&sid=abcd&fp=chrome"
			}
			switch network {
			case "ws":
				uri += "&path=%2Fpublic&host=example.com"
			case "grpc":
				uri += "&serviceName=public"
			case "xhttp", "splithttp":
				uri += "&path=%2Fpublic&mode=auto"
			}
			inputs[security+"-"+network] = []byte(uri)
		}
	}
	for _, security := range []string{"tls", "reality"} {
		profiles, e := profile.Parse(inputs[security+"-raw"])
		if e != nil {
			return e
		}
		outbound := profiles[0].Outbound
		outbound["transport"] = map[string]any{"type": "http", "path": "/public", "host": []string{"example.com"}}
		b, e := json.Marshal(map[string]any{"outbounds": []any{outbound}})
		if e != nil {
			return e
		}
		inputs[security+"-http-json"] = b
	}
	// Native Xray JSON can select transports that URI import routes to sing-box.
	// Reimport each synthetic variant so the same supported-field checks apply.
	for _, security := range []string{"tls", "reality"} {
		inputs[security+"-vision"] = []byte(string(inputs[security+"-raw"]) + "&flow=xtls-rprx-vision")
		for _, network := range []string{"raw", "ws", "grpc", "xhttp", "splithttp"} {
			if security == "reality" && network == "ws" {
				continue // Native Xray rejects this combination before import.
			}
			var config map[string]any
			if e := json.Unmarshal(inputs["xhttp-json"], &config); e != nil {
				return e
			}
			outbound := config["outbounds"].([]any)[0].(map[string]any)
			stream := outbound["streamSettings"].(map[string]any)
			stream["network"] = network
			stream["security"] = security
			if security == "tls" {
				delete(stream, "realitySettings")
				stream["tlsSettings"] = map[string]any{"serverName": "example.com", "fingerprint": "chrome"}
			}
			if network != "xhttp" && network != "splithttp" {
				delete(stream, "xhttpSettings")
			}
			switch network {
			case "ws":
				stream["wsSettings"] = map[string]any{"path": "/public", "headers": map[string]any{"Host": "example.com"}}
			case "grpc":
				stream["grpcSettings"] = map[string]any{"serviceName": "public", "authority": "example.com"}
			}
			b, e := json.Marshal(config)
			if e != nil {
				return e
			}
			inputs["xray-"+security+"-"+network] = b
			if network == "ws" || network == "grpc" {
				if network == "ws" {
					stream["wsSettings"] = map[string]any{"path": "/public", "headers": map[string]any{"Host": "example.com"}, "maxEarlyData": 2048, "earlyDataHeaderName": "Sec-WebSocket-Protocol"}
				} else {
					stream["grpcSettings"] = map[string]any{"serviceName": "public", "authority": "example.com", "multiMode": true, "idle_timeout": 45, "health_check_timeout": 15, "permit_without_stream": true, "initial_windows_size": 65536}
				}
				b, e = json.Marshal(config)
				if e != nil {
					return e
				}
				inputs["xray-"+security+"-"+network+"-nondefault"] = b
			}
		}
	}
	for _, mode := range []string{"packet-up", "stream-up", "stream-one"} {
		inputs["xhttp-"+mode] = []byte(strings.ReplaceAll(string(inputs["xhttp-json"]), `"mode":"auto"`, `"mode":"`+mode+`"`))
	}
	compact, _ := json.Marshal(map[string]any{"wg": map[string]any{"private_key": key, "peer_public_key": key, "address": []string{"10.10.0.2/32"}}, "ws": map[string]any{"server": "example.com", "path": "/wgws"}})
	inputs["wgws-compact"] = []byte("wgws://" + base64.RawURLEncoding.EncodeToString(compact))
	cases := []caseRecord{}
	names := []string{}
	for name := range inputs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		input := inputs[name]
		profiles, e := profile.Parse(input)
		if e != nil || len(profiles) != 1 {
			return fmt.Errorf("compatibility input %s rejected: %v", name, e)
		}
		r, e := profile.Render(profiles[0], "eth1", "/run/flr-compat")
		if e != nil {
			return e
		}
		folder := filepath.Join(directory, name)
		if e = os.MkdirAll(folder, 0700); e != nil {
			return e
		}
		c := caseRecord{ID: name, Family: profiles[0].Family, Engine: profiles[0].Engine, SingBox: name + "/sing-box.json", SidecarArgs: r.SidecarArgs, WAN: r.BindInterface, Outer: r.OuterEndpoints}
		if e = os.WriteFile(filepath.Join(directory, c.SingBox), r.SingBox, 0600); e != nil {
			return e
		}
		if len(r.Xray) != 0 {
			c.Xray = name + "/xray.json"
			if e = os.WriteFile(filepath.Join(directory, c.Xray), r.Xray, 0600); e != nil {
				return e
			}
		}
		cases = append(cases, c)
	}
	args, e := bypass.Arguments(bypass.Config{Enabled: true, TCP: "fake", QUIC: "fake"})
	if e != nil {
		return e
	}
	b, e := json.MarshalIndent(map[string]any{"format": "flr-engine-contracts-v1", "cases": cases, "bypass_args": args, "hardware_tested": false}, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(filepath.Join(directory, "manifest.json"), b, 0600)
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: flr-compat OUTPUT FIXTURES")
		os.Exit(2)
	}
	if e := export(os.Args[1], os.Args[2]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
