package controller

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyGeckoStandardBBRMigratesWithoutChangingSource(t *testing.T) {
	c := testAdmin(t)
	c.registry = nil
	if e := os.MkdirAll(c.stateDir, 0700); e != nil {
		t.Fatal(e)
	}
	legacy := `{"outbounds":[{"type":"hysteria2","server":"192.0.2.40","server_port":443,"password":"PUBLIC_TEST_PASSWORD","bbr_profile":"standard","obfs":{"type":"gecko","password":"PUBLIC_TEST_OBFS","min_packet_size":512,"max_packet_size":1200},"tls":{"enabled":true,"server_name":"example.com"},"bind_interface":"eth1","routing_mark":2147483648}]}`
	path := filepath.Join(c.stateDir, "gecko.json")
	if e := os.WriteFile(path, []byte(legacy), 0600); e != nil {
		t.Fatal(e)
	}
	if e := c.initializeAdmin(true); e != nil {
		t.Fatal("legacy sing-box default BBR profile must migrate", e)
	}
	if len(c.registry.Profiles) != 1 || c.registry.Profiles[0].Family != "hy2" {
		t.Fatal("legacy Gecko profile lost")
	}
	got, e := os.ReadFile(path)
	if e != nil || string(got) != legacy {
		t.Fatal("migration changed original legacy credentials/config", e)
	}
	c.registry = nil
	if e = c.initializeAdmin(true); e != nil || len(c.registry.Profiles) != 1 {
		t.Fatal("checkpointed migration did not survive restart", e)
	}
}
