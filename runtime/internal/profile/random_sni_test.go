package profile

import (
	"encoding/json"
	"strings"
	"testing"
)

func rotatingInput() map[string]any {
	return map[string]any{"type": "hysteria2", "server": "192.0.2.10", "server_port": 443, "password": "PUBLIC_TEST_AUTH", "obfs": map[string]any{"type": "gecko", "password": "PUBLIC_TEST_OBFS"}, "tls": map[string]any{"enabled": true, "insecure": false, "server_name": "seed.e-connect.example.com"}, "flr_random_sni_suffix": "e-connect.example.com"}
}
func TestRandomSNIImportAndRenderRemainDeclarative(t *testing.T) {
	raw, _ := json.Marshal(rotatingInput())
	p, e := Parse(raw)
	if e != nil || len(p) != 1 {
		t.Fatalf("rotation import rejected: %v", e)
	}
	first, e := Render(p[0], "eth1", "/run/flr")
	if e != nil {
		t.Fatal(e)
	}
	second, e := Render(p[0], "eth1", "/run/flr")
	if e != nil {
		t.Fatal(e)
	}
	if string(first.SingBox) != string(second.SingBox) {
		t.Fatal("render randomized session identity")
	}
	var config map[string]any
	json.Unmarshal(first.SingBox, &config)
	out := config["outbounds"].([]any)[0].(map[string]any)
	if out["flr_random_sni_suffix"] != "e-connect.example.com" || out["server"] != "192.0.2.10" || out["tls"].(map[string]any)["server_name"] != "seed.e-connect.example.com" {
		t.Fatal("declarative rotation or fixed endpoint lost")
	}
}
func TestRandomSNIRejectsUnsafeInputs(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"empty", func(o map[string]any) { o["flr_random_sni_suffix"] = "" }},
		{"wildcard", func(o map[string]any) { o["flr_random_sni_suffix"] = "*.example.com" }},
		{"trailing-dot", func(o map[string]any) { o["flr_random_sni_suffix"] = "example.com." }},
		{"ip", func(o map[string]any) { o["flr_random_sni_suffix"] = "192.0.2.10" }},
		{"uppercase", func(o map[string]any) { o["flr_random_sni_suffix"] = "Example.com" }},
		{"long", func(o map[string]any) {
			o["flr_random_sni_suffix"] = strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 30)
		}},
		{"empty-label", func(o map[string]any) { o["flr_random_sni_suffix"] = "a..com" }},
		{"bad-label", func(o map[string]any) { o["flr_random_sni_suffix"] = "-a.com" }},
		{"one-label", func(o map[string]any) { o["flr_random_sni_suffix"] = "com" }},
		{"percent", func(o map[string]any) { o["flr_random_sni_suffix"] = "a%b.com" }},
		{"newline", func(o map[string]any) { o["flr_random_sni_suffix"] = "a\nb.com" }},
		{"space", func(o map[string]any) { o["flr_random_sni_suffix"] = "a b.com" }},
		{"type", func(o map[string]any) { o["flr_random_sni_suffix"] = true }},
		{"dns-endpoint", func(o map[string]any) { o["server"] = "vpn.example.com" }},
		{"apex-seed", func(o map[string]any) { o["tls"].(map[string]any)["server_name"] = "e-connect.example.com" }},
		{"deep-seed", func(o map[string]any) { o["tls"].(map[string]any)["server_name"] = "a.b.e-connect.example.com" }},
		{"overlong-seed", func(o map[string]any) {
			suffix := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 28)
			o["flr_random_sni_suffix"] = suffix
			o["tls"].(map[string]any)["server_name"] = strings.Repeat("s", 63) + "." + suffix
		}},
		{"utls", func(o map[string]any) {
			o["tls"].(map[string]any)["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
		}},
		{"ech", func(o map[string]any) { o["tls"].(map[string]any)["ech"] = map[string]any{"enabled": true} }},
		{"engine", func(o map[string]any) { o["tls"].(map[string]any)["engine"] = "apple" }},
		{"disable-sni", func(o map[string]any) { o["tls"].(map[string]any)["disable_sni"] = true }},
		{"reality", func(o map[string]any) { o["tls"].(map[string]any)["reality"] = map[string]any{"enabled": true} }},
		{"insecure", func(o map[string]any) { o["tls"].(map[string]any)["insecure"] = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := rotatingInput()
			tc.mutate(o)
			raw, _ := json.Marshal(o)
			if _, e := Parse(raw); e == nil {
				t.Fatal("unsafe rotation input accepted")
			}
		})
	}
}
