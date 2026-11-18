package controller

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/control"
)

// Fake credentials only. Each entry covers one family the importer accepts.
var exportFixtures = []string{
	"vless://00000000-0000-4000-8000-000000000000@example.com:443?security=reality&pbk=PUBLIC_TEST_KEY&sid=abcd&fp=chrome&sni=example.com&type=tcp&flow=xtls-rprx-vision",
	"vless://00000000-0000-4000-8000-000000000001@example.com:443?security=tls&sni=example.com&type=ws&host=example.com&path=%2Fpublic",
	"vless://00000000-0000-4000-8000-000000000002@example.com:443?security=reality&pbk=PUBLIC_TEST_REALITY&sid=abcd&fp=chrome&sni=example.com&type=xhttp&path=%2Fpublic&mode=auto",
	`{"type":"hysteria2","server":"203.0.113.10","server_port":443,"password":"PUBLIC_TEST_AUTH","obfs":{"type":"gecko","password":"PUBLIC_TEST_OBFS"},"tls":{"enabled":true,"server_name":"seed.pace.example.com"},"flr_random_sni_suffix":"pace.example.com","hop_interval_max":"40s","disable_chrome_parrot":false}`,
	"ss://" + base64.RawURLEncoding.EncodeToString([]byte("2022-blake3-aes-128-gcm:PUBLIC_TEST_SS_KEY")) + "@example.com:443?plugin=shadow-tls%3Bhost%3Dcover.example.com%3Bpassword%3DPUBLIC_TEST_SHADOWTLS%3Bversion%3D3",
	`{"type":"wgws","websocket":{"server":"example.com","server_port":443,"tls":true,"path":"/wgws","headers":{"Authorization":"Bearer PUBLIC_TEST_TOKEN"}},"wstunnel":{"mode":"wireguard-over-websocket","remote_udp_endpoint":"127.0.0.1:51820"},"singbox":{"endpoints":[{"type":"wireguard","address":["10.10.0.2/32"],"private_key":"PUBLIC_TEST_PRIVATE","peers":[{"address":"127.0.0.1","port":51820,"public_key":"PUBLIC_TEST_PEER","allowed_ips":["0.0.0.0/0"]}]}]}}`,
}

func exportRequest(t *testing.T, c *Controller, id string) control.APIRequest {
	t.Helper()
	return connectionRequest(t, c, "connection-export", map[string]any{"id": id})
}

func TestConnectionExportRoundTripsEveryStoredFamily(t *testing.T) {
	c := connectionAdmin(t)
	for _, fixture := range exportFixtures {
		if _, err := c.HandleAPI(connectionRequest(t, c, "connection-import", map[string]any{"data": fixture})); err != nil {
			t.Fatalf("fixture import: %v", err)
		}
	}
	families, formats := map[string]bool{}, map[string]bool{}
	for _, item := range c.connections.Connections {
		generation := c.Status().Generation
		result, err := c.HandleAPI(exportRequest(t, c, item.ID))
		if err != nil {
			t.Fatalf("export %s: %v", item.Family, err)
		}
		if c.Status().Generation != generation {
			t.Fatal("export changed state generation")
		}
		exported := result.(map[string]any)
		text, format := exported["config"].(string), exported["format"].(string)
		if exported["id"] != item.ID || exported["family"] != item.Family || exported["generation"] != generation || exported["filename"] == "" {
			t.Fatalf("export metadata wrong: %v", exported["id"])
		}
		switch format {
		case "awg-conf":
			if item.Family != "awg" || !strings.HasPrefix(text, "[Interface]\n") {
				t.Fatal("AWG export is not a configuration file")
			}
		case "url":
			if !strings.Contains(text, "://") || strings.Contains(text, "\n") {
				t.Fatalf("URL export malformed: %s", item.Family)
			}
		case "json":
			if !json.Valid([]byte(text)) || exported["note"] == nil {
				t.Fatal("JSON export malformed or unexplained")
			}
		default:
			t.Fatalf("unknown export format %q", format)
		}
		families[item.Family], formats[format] = true, true
		// The exported text is accepted by the importer and yields the same
		// stored payload: same revision, same native AWG fields or profile.
		items, err := connection.ParseImport([]byte(text))
		if err != nil || len(items) != 1 {
			t.Fatalf("%s export (%s) not re-importable: %v", item.Family, format, err)
		}
		again := items[0]
		if again.Family != item.Family || again.Revision != item.Revision || !reflect.DeepEqual(again.AWG, item.AWG) {
			t.Fatalf("%s export changed configuration", item.Family)
		}
		if item.Profile != nil {
			want, _ := json.Marshal([]any{item.Profile.Outbound, item.Profile.Detour, item.Profile.WGWS})
			got, _ := json.Marshal([]any{again.Profile.Outbound, again.Profile.Detour, again.Profile.WGWS})
			if string(want) != string(got) {
				t.Fatalf("%s export changed proxy payload", item.Family)
			}
		}
		// Importing the export again is recognized as the same connection.
		if _, err := c.connections.Clone().Import([]byte(text)); err == nil || !strings.Contains(err.Error(), "already exists: "+item.ID) {
			t.Fatalf("%s export not recognized as the stored connection: %v", item.Family, err)
		}
	}
	for _, family := range connection.Families {
		if !families[family] {
			t.Fatalf("family %s not covered", family)
		}
	}
	for _, format := range []string{"url", "json", "awg-conf"} {
		if !formats[format] {
			t.Fatalf("format %s not covered", format)
		}
	}
}

func TestConnectionExportGuards(t *testing.T) {
	c := connectionAdmin(t)
	id := c.connections.Connections[0].ID
	list, err := c.HandleAPI(connectionRequest(t, c, "connection-list", nil))
	encoded, _ := json.Marshal(list)
	if err != nil || strings.Contains(string(encoded), "PUBLIC_TEST_PASSWORD") {
		t.Fatal("list exposed credentials")
	}
	exported, err := c.HandleAPI(exportRequest(t, c, id))
	encoded, _ = json.Marshal(exported)
	if err != nil || !strings.Contains(string(encoded), "PUBLIC_TEST_") {
		t.Fatalf("write export omitted the configuration: %v", err)
	}
	// Without a generation the export still works (CLI use).
	if _, err := c.HandleAPI(apiRequest(t, `{"operation":"connection-export","id":"`+id+`"}`)); err != nil {
		t.Fatal(err)
	}
	stale := c.Status().Generation + 5
	if _, err := c.HandleAPI(control.APIRequest{Operation: "connection-export", ID: id, ExpectedGeneration: &stale}); err == nil || !strings.Contains(err.Error(), "state changed") {
		t.Fatal("stale generation exported")
	}
	if _, err := c.HandleAPI(exportRequest(t, c, "conn-missing")); err == nil || err.Error() != "connection not found" {
		t.Fatal("missing connection exported")
	}
	raw, _ := json.Marshal(map[string]string{"request": `{"operation":"connection-export","id":"` + id + `"}`})
	if _, err := control.ParseAPI(raw, true, true); err == nil {
		t.Fatal("read-only rpcd method accepted credential export")
	}
}
