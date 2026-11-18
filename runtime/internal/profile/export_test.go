package profile

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// payload is the identity-bearing part of a profile; equal payloads mean the
// re-imported profile renders the same engine configuration.
func payload(t *testing.T, p Profile) string {
	t.Helper()
	raw, e := json.Marshal([]any{p.Family, p.Engine, p.Outbound, p.Detour, p.WGWS})
	if e != nil {
		t.Fatal(e)
	}
	return string(raw)
}

func roundTrip(t *testing.T, input []byte, format string) Exported {
	t.Helper()
	original := one(t, input)
	exported, e := Export(original)
	if e != nil {
		t.Fatalf("export: %v", e)
	}
	if exported.Format != format || exported.Engine != original.Engine {
		t.Fatalf("format %s/%s, want %s/%s: %s", exported.Format, exported.Engine, format, original.Engine, exported.Config)
	}
	if format == ExportJSON && exported.Note == "" {
		t.Fatal("JSON fallback does not say why")
	}
	again := one(t, []byte(exported.Config))
	if again.ID != original.ID || again.Family != original.Family || payload(t, again) != payload(t, original) {
		t.Fatalf("round trip changed profile\nexport: %s\nwant: %s\ngot:  %s", exported.Config, payload(t, original), payload(t, again))
	}
	second, e := Export(again)
	if e != nil || !reflect.DeepEqual(second, exported) {
		t.Fatal("export is not stable")
	}
	return exported
}

func TestExportRoundTripPerFamily(t *testing.T) {
	compact, _ := json.Marshal(map[string]any{"wg": map[string]any{"private_key": "PUBLIC_TEST_PRIVATE", "peer_public_key": "PUBLIC_TEST_PEER", "address": []any{"10.10.0.2/32"}, "pre_shared_key": "PUBLIC_TEST_PSK"}, "ws": map[string]any{"server": "example.com", "path": "/tunnel", "headers": map[string]any{"Authorization": "Bearer PUBLIC_TEST_TOKEN"}}})
	for _, tc := range []struct {
		name, input, format, prefix string
	}{
		{"hy2-salamander", string(fixture(t, "salamander.uri")), ExportURL, "hysteria2://"},
		{"hy2-gecko-hopping", "hy2://PUBLIC%3ATEST@203.0.113.10:443/?obfs=gecko&obfs-password=PUBLIC_TEST_OBFS&obfs-min-packet-size=600&obfs-max-packet-size=1300&sni=vpn.example.com&alpn=h3&mport=20000-20999,443&hop-interval=45", ExportURL, "hysteria2://"},
		{"hy2-gecko-json", string(fixture(t, "gecko.json")), ExportURL, "hysteria2://"},
		{"hy2-random-sni", `{"type":"hysteria2","server":"203.0.113.10","server_port":443,"password":"PUBLIC_TEST_AUTH","obfs":{"type":"gecko","password":"PUBLIC_TEST_OBFS"},"tls":{"enabled":true,"server_name":"seed.pace.example.com"},"flr_random_sni_suffix":"pace.example.com"}`, ExportJSON, "{"},
		{"hy2-singbox-1.14", `{"type":"hysteria2","server":"example.com","server_port":443,"password":"PUBLIC_TEST_AUTH","obfs":{"type":"gecko","password":"PUBLIC_TEST_OBFS"},"tls":{"enabled":true,"server_name":"example.com"},"server_ports":["20000:20999"],"hop_interval":"10s","hop_interval_max":"40s","bbr_profile":"standard","disable_chrome_parrot":true}`, ExportJSON, "{"},
		{"hy2-minute-hop", `{"type":"hysteria2","server":"example.com","server_port":443,"password":"PUBLIC_TEST_AUTH","obfs":{"type":"salamander","password":"PUBLIC_TEST_OBFS"},"tls":{"enabled":true,"server_name":"example.com"},"hop_interval":"1m"}`, ExportJSON, "{"},
		{"reality", "vless://00000000-0000-4000-8000-000000000000@example.com:443?security=reality&pbk=PUBLIC_TEST_KEY&sid=abcd&fp=chrome&sni=example.com&type=tcp&flow=xtls-rprx-vision&spx=%2F", ExportURL, "vless://"},
		{"vless-ws", "vless://00000000-0000-4000-8000-000000000000@example.com:443?security=tls&sni=example.com&type=ws&host=example.com&path=%2Fpublic&alpn=h2,http%2F1.1", ExportURL, "vless://"},
		{"vless-grpc", "vless://00000000-0000-4000-8000-000000000000@example.com:443?security=tls&sni=example.com&type=grpc&serviceName=public&mode=gun", ExportURL, "vless://"},
		{"vless-packet-encoding", `{"type":"vless","server":"example.com","server_port":443,"uuid":"00000000-0000-4000-8000-000000000000","packet_encoding":"xudp","tls":{"enabled":true,"server_name":"example.com"}}`, ExportJSON, "{"},
		{"reality-xhttp", string(fixture(t, "xhttp.uri")), ExportURL, "vless://"},
		{"reality-xhttp-extra", string(fixture(t, "xhttp.json")), ExportJSON, "{"},
		{"xray-ws", `{"protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"00000000-0000-4000-8000-000000000000","encryption":"none"}]}]},"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"example.com"},"wsSettings":{"path":"/public"}}}`, ExportJSON, "{"},
		{"ss2022-uri", "ss://" + base64.RawURLEncoding.EncodeToString([]byte("2022-blake3-aes-128-gcm:PUBLIC_TEST_SS_KEY")) + "@example.com:443?plugin=" + "shadow-tls%3Bhost%3Dcover.example.com%3Bpassword%3DPUBLIC%3DTEST%3Bversion%3D3", ExportURL, "ss://"},
		{"ss2022-utls", string(fixture(t, "shadowtls.json")), ExportJSON, "{"},
		{"wgws-native", string(fixture(t, "wgws.json")), ExportURL, "wgws://"},
		{"wgws-compact", "wgws://" + base64.RawURLEncoding.EncodeToString(compact), ExportURL, "wgws://"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exported := roundTrip(t, []byte(tc.input), tc.format)
			if !strings.HasPrefix(exported.Config, tc.prefix) {
				t.Fatalf("unexpected export shape: %s", exported.Config)
			}
		})
	}
}

func TestExportRefusesInvalidStoredProfile(t *testing.T) {
	p := one(t, fixture(t, "salamander.uri"))
	p.Outbound = clone(p.Outbound)
	p.Outbound["password"] = ""
	if _, e := Export(p); e == nil {
		t.Fatal("invalid stored profile exported")
	}
	if _, e := Export(Profile{Family: "hy2", Engine: "unknown"}); e == nil {
		t.Fatal("unknown engine exported")
	}
}

func TestHysteria2SingBox114Options(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"type": "hysteria2", "server": "example.com", "server_port": 443, "password": "PUBLIC_TEST_AUTH", "obfs": map[string]any{"type": "salamander", "password": "PUBLIC_TEST_OBFS"}, "tls": map[string]any{"enabled": true, "server_name": "example.com"}}
	}
	for _, valid := range []map[string]any{
		{"hop_interval_max": "90s"},
		{"hop_interval": "30s", "hop_interval_max": "30s"},
		{"hop_interval": "10s", "hop_interval_max": "1m30s"},
		{"bbr_profile": "standard"},
		{"bbr_profile": "aggressive"},
		{"disable_chrome_parrot": true},
		{"disable_chrome_parrot": false},
	} {
		o := base()
		for k, v := range valid {
			o[k] = v
		}
		raw, _ := json.Marshal(o)
		p := one(t, raw)
		rendered, e := Render(p, "eth1", "/run/flr")
		if e != nil {
			t.Fatal(e)
		}
		var cfg map[string]any
		json.Unmarshal(rendered.SingBox, &cfg)
		out := object(array(cfg["outbounds"])[0])
		for k, v := range valid {
			if !reflect.DeepEqual(out[k], v) {
				t.Fatalf("%s not rendered: %v", k, out[k])
			}
		}
	}
	for name, invalid := range map[string]map[string]any{
		"max-below-min":        {"hop_interval": "30s", "hop_interval_max": "10s"},
		"max-not-duration":     {"hop_interval_max": "soon"},
		"max-number":           {"hop_interval_max": 30},
		"max-zero":             {"hop_interval_max": "0s"},
		"max-negative":         {"hop_interval_max": "-5s"},
		"max-too-long":         {"hop_interval_max": "25h"},
		"min-invalid-with-max": {"hop_interval": "later", "hop_interval_max": "30s"},
		"bbr-number":           {"bbr_profile": 1},
		"bbr-empty":            {"bbr_profile": ""},
		"bbr-shell":            {"bbr_profile": "standard;reboot"},
		"bbr-upper":            {"bbr_profile": "Standard"},
		"parrot-string":        {"disable_chrome_parrot": "true"},
	} {
		o := base()
		for k, v := range invalid {
			o[k] = v
		}
		raw, _ := json.Marshal(o)
		if _, e := Parse(raw); e == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	vless := `{"type":"vless","server":"example.com","server_port":443,"uuid":"00000000-0000-4000-8000-000000000000","tls":{"enabled":true,"server_name":"example.com"},"disable_chrome_parrot":true}`
	if _, e := Parse([]byte(vless)); e == nil {
		t.Fatal("Hysteria2-only option accepted on VLESS")
	}
}
