package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/control"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
	"github.com/MyHeartRaces/FLR/runtime/internal/validation"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDeletedLegacyRegistryStaysEmptyAcrossStartupAndOfflineWrite(t *testing.T) {
	c := testAdmin(t)
	c.registry = nil
	if e := os.MkdirAll(c.stateDir, 0700); e != nil {
		t.Fatal(e)
	}
	legacy := `{"outbounds":[{"type":"hysteria2","server":"example.com","server_port":443,"password":"PUBLIC_TEST_PASSWORD","obfs":{"type":"salamander","password":"PUBLIC_TEST_OBFS"},"tls":{"enabled":true,"server_name":"example.com"}}]}`
	source := filepath.Join(c.stateDir, "gecko.json")
	os.WriteFile(source, []byte(legacy), 0600)
	if e := c.initializeAdmin(true); e != nil || len(c.registry.Profiles) != 1 {
		t.Fatal("first migration failed", e)
	}
	id := c.registry.Profiles[0].ID
	if _, e := c.HandleAPI(control.APIRequest{Operation: "profile-delete", ID: id}); e != nil {
		t.Fatal(e)
	}
	for _, offline := range []bool{false, true} {
		next := testAdmin(t)
		next.stateDir = c.stateDir
		next.registry = nil
		var e error
		if offline {
			_, e = next.HandleAPI(control.APIRequest{Operation: "settings", Settings: json.RawMessage(`{"primary_group":"test"}`)})
		} else {
			e = next.initializeAdmin(true)
		}
		if e != nil || len(next.registry.Profiles) != 0 {
			t.Fatal("deleted profile resurrected", offline, e)
		}
	}
	if b, e := os.ReadFile(source); e != nil || string(b) != legacy {
		t.Fatal("legacy source modified")
	}
}
func TestExplicitBypassEmptyRejectedButAbsentLegacyDefaultsWork(t *testing.T) {
	for _, raw := range []string{`{"enabled":false,"tcp":"","quic":""}`, `{"enabled":true,"tcp":"fake","quic":""}`, `{"enabled":true,"tcp":"","quic":"fake"}`} {
		if _, e := decodeBypass([]byte(raw)); e == nil {
			t.Fatal("explicit empty accepted", raw)
		}
	}
	legacy := `{"options":{"lan":"br-lan","wan":"eth1","selection":{"general":"down","games":"down"}},"dns_port":"1054","local_dns_port":"53"}`
	s, e := DecodeSettings([]byte(legacy))
	if e != nil {
		t.Fatal("absent legacy bypass rejected", e)
	}
	raw, _ := json.Marshal(s)
	if s.DirectBypass.TCP != "off" || s.DirectBypass.QUIC != "off" {
		t.Fatal("legacy defaults were not normalized")
	}
	if _, e = DecodeSettings(raw); e != nil {
		t.Fatal("legacy settings cannot be saved and reloaded", e)
	}
	raw, _ = json.Marshal(DefaultSettings())
	if _, e = DecodeSettings(raw); e != nil {
		t.Fatal("default settings cannot round-trip", e)
	}
}
func TestDevicePolicyTransactionBothDirectionsAndRetry(t *testing.T) {
	for _, target := range []string{"direct", "general", "auto", "games"} {
		for _, failure := range []string{"", "block", "update", "clear", "save", "unblock"} {
			t.Run(target+"/"+failure, func(t *testing.T) {
				c := testAdmin(t)
				c.settings.Options.Profiles = map[string]contract.Class{"192.168.8.2": contract.Direct, "192.168.8.3": contract.Games}
				if target == "direct" {
					c.settings.Options.Profiles["192.168.8.2"] = contract.General
				}
				original := c.settings.Options.Profiles["192.168.8.2"]
				calls := []string{}
				blocked := false
				step := func(s string) error {
					calls = append(calls, s)
					if s == failure {
						return fmt.Errorf("failure")
					}
					return nil
				}
				c.deviceOps = &devicePolicyOps{
					block: func(ip string, b bool) error {
						if ip != "192.168.8.2" {
							t.Fatal(ip)
						}
						s := "unblock"
						if b {
							s = "block"
						}
						if e := step(s); e != nil {
							return e
						}
						blocked = b
						return nil
					},
					update: func(p map[string]contract.Class) error {
						if !blocked || p["192.168.8.3"] != contract.Games {
							t.Fatal("unquiesced update or other device changed")
						}
						return step("update")
					},
					clear: func(ip string) error {
						if !blocked || ip != "192.168.8.2" {
							t.Fatal("unquiesced cleanup")
						}
						return step("clear")
					},
					save: func(_ string, _ any) error {
						if !blocked {
							t.Fatal("unquiesced persistence")
						}
						return step("save")
					},
				}
				_, e := c.handleDevice("192.168.8.2", target)
				if failure == "" {
					if e != nil || blocked || !reflect.DeepEqual(calls, []string{"block", "update", "clear", "save", "unblock"}) {
						t.Fatal(calls, e)
					}
				} else {
					if e == nil {
						t.Fatal("failed transition acknowledged")
					}
					if failure != "block" && !blocked {
						t.Fatal("failure reopened traffic")
					}
					if failure != "unblock" && c.settings.Options.Profiles["192.168.8.2"] != original {
						t.Fatal("unpersisted policy published")
					}
					failure = ""
					if _, e = c.handleDevice("192.168.8.2", target); e != nil || blocked {
						t.Fatal("retry failed", e)
					}
				}
			})
		}
	}
}
func TestImportSafeCategoriesAndNativeRedaction(t *testing.T) {
	c := testAdmin(t)
	good := `hysteria2://PUBLIC_TEST_PASSWORD@example.com:443/?obfs=salamander&obfs-password=PUBLIC_TEST_OBFS&sni=example.com`
	if _, e := c.HandleAPI(control.APIRequest{Operation: "import", Content: good}); e != nil {
		t.Fatal(e)
	}
	cases := []struct {
		content, code string
		item          int
	}{
		{good, "duplicate_profile", 1},
		{"not JSON PUBLIC_TEST_SECRET", "invalid_format", 0},
		{good + "\nunsupported://PUBLIC_TEST_SECRET@example.com", "unsupported_transport", 2},
		{`{"protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"00000000-0000-4000-8000-000000000000","encryption":"none"}]}]},"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"example.com"},"wsSettings":{"path":"/ws","earlyDataHeaderName":"PUBLIC_TEST_SECRET"}}}`, "unsupported_field", 0},
	}
	for _, tc := range cases {
		_, e := c.HandleAPI(control.APIRequest{Operation: "import", Content: tc.content})
		d := validation.Detail(e)
		if d == nil || d.Code != tc.code || d.Item != tc.item || strings.Contains(e.Error(), "PUBLIC_TEST") {
			t.Fatalf("wrong safe reason: %#v %v", d, e)
		}
	}
	c.validateEngine = func(context.Context, profile.Profile) error { return fmt.Errorf("stderr PUBLIC_TEST_SECRET") }
	_, e := c.HandleAPI(control.APIRequest{Operation: "import", Content: strings.Replace(good, "example.com", "other.example.com", 1)})
	d := validation.Detail(e)
	if d == nil || d.Code != "engine_validation" || d.Component != "sing-box" || !strings.Contains(e.Error(), "sing-box") || strings.Contains(e.Error(), "PUBLIC_TEST") {
		t.Fatal(d, e)
	}
	c.registry.Profiles = make([]profile.Profile, profile.MaxProfiles)
	_, e = c.HandleAPI(control.APIRequest{Operation: "import", Content: strings.Replace(good, "example.com", "third.example.com", 1)})
	if d = validation.Detail(e); d == nil || d.Code != "registry_capacity" {
		t.Fatal(d, e)
	}
	_, e = c.HandleAPI(control.APIRequest{Operation: "primary-awg", Content: "[Interface]\nPrivateKey=PUBLIC_TEST_SECRET\nAddress=10.77.0.2/32\n[Peer]\nPublicKey=PUBLIC_TEST_SECRET\nEndpoint=192.0.2.10:51820\n"})
	if d = validation.Detail(e); d == nil || d.Code != "invalid_awg" || strings.Contains(e.Error(), "PUBLIC_TEST") {
		t.Fatal(d, e)
	}
}
func TestImportedMetadataRoundTripsThroughAPIEdit(t *testing.T) {
	for _, priority := range []int{-1000000, -1, 1000000} {
		c := testAdmin(t)
		raw, e := os.ReadFile("../profile/testdata/bundle.json")
		if e != nil {
			t.Fatal(e)
		}
		var bundle map[string]any
		json.Unmarshal(raw, &bundle)
		record := bundle["profiles"].([]any)[0].(map[string]any)
		record["priority"] = priority
		record["server_group"] = "Сервер / A"
		delete(record, "tracegate")
		raw, _ = json.Marshal(bundle)
		if _, e = c.HandleAPI(control.APIRequest{Operation: "import", Content: string(raw)}); e != nil {
			t.Fatal(e)
		}
		p := c.registry.Profiles[0]
		enabled := false
		group := p.ServerGroup
		if p.Priority != priority || group != "Сервер / A" {
			t.Fatal("metadata lost")
		}
		if _, e = c.HandleAPI(control.APIRequest{Operation: "profile-update", ID: p.ID, Priority: &priority, ServerGroup: &group, Enabled: &enabled}); e != nil {
			t.Fatal(e)
		}
		if _, e = c.HandleAPI(control.APIRequest{Operation: "settings", Settings: json.RawMessage(`{"primary_group":"Сервер / A"}`)}); e != nil {
			t.Fatal(e)
		}
		if c.registry.Profiles[0].Enabled || c.registry.Profiles[0].Priority != priority {
			t.Fatal("edit lost metadata")
		}
	}
	for _, group := range []string{strings.Repeat("a", 80), strings.Repeat("Ж", 40)} {
		s := DefaultSettings()
		s.PrimaryGroup = group
		if e := ValidateSettings(s); e != nil {
			t.Fatal(e)
		}
		s.PrimaryGroup = group + "x"
		if e := ValidateSettings(s); e == nil {
			t.Fatal("overlength primary group accepted")
		}
	}
}
