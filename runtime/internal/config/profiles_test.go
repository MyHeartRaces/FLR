package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProfilesProduceIndependentTunnelsAndProtectOuterTraffic(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "awg.conf"), []byte(publicAWG()), 0600)
	os.WriteFile(filepath.Join(d, "sing-box-outbounds.json"), []byte(`{"outbounds":[{"type":"hysteria2","tag":"hy-gecko","server":"192.0.2.10","server_port":443,"password":"PUBLIC_TEST_SECRET","tls":{"enabled":true,"server_name":"example.com"}},{"type":"vless","tag":"vless-reality","server":"192.0.2.10","server_port":443,"uuid":"PUBLIC_TEST_SECRET"}]}`), 0600)
	p, e := LoadProfiles(d, "eth1")
	if e != nil {
		t.Fatal(e)
	}
	if p.AWG["HeaderProtectionKey"] != dummyKey {
		t.Fatal("AWG3 header protection lost")
	}
	for _, name := range []string{"gecko", "vless"} {
		var c map[string]any
		if e = json.Unmarshal(p.Tunnels[name], &c); e != nil {
			t.Fatal(e)
		}
		in := c["inbounds"].([]any)[0].(map[string]any)
		if in["auto_route"] != false {
			t.Fatal("TUN changes main routing")
		}
		out := c["outbounds"].([]any)[0].(map[string]any)
		if out["bind_interface"] != "eth1" || out["routing_mark"] != float64(0x80000000) {
			t.Fatal("outer transport can loop into VPN")
		}
		if !strings.Contains(string(p.Tunnels[name]), "127.0.0.1") {
			t.Fatal("health SOCKS not restricted to loopback")
		}
	}
}

func TestMissingProfilesFailBeforeApplyingNetwork(t *testing.T) {
	if _, e := LoadProfiles(t.TempDir(), "eth1"); e == nil {
		t.Fatal("missing credentials accepted")
	}
}
func TestIncompleteBackupRejectedBeforeRollback(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "network"), []byte("config interface"), 0600)
	if e := ValidateBackup(d); e == nil {
		t.Fatal("partial backup would be applied before missing files noticed")
	}
}
