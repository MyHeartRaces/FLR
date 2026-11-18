package connection

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func roamAWGConnection(t *testing.T, id string, octet int) Connection {
	t.Helper()
	key := "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	raw := fmt.Sprintf("[Interface]\nPrivateKey=%s\nHeaderProtectionKey=%s\nAddress=10.77.0.2/32\nS1=12\nS2=12\nS3=12\nS4=12\n[Peer]\nPublicKey=%s\nPresharedKey=%s\nEndpoint=192.0.2.%d:51820\nAllowedIPs=0.0.0.0/0\n", key, key, key, key, octet)
	items, err := ParseImport([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	c := items[0]
	c.ID = id
	return c
}

func TestParseRoamPortsBounds(t *testing.T) {
	for _, ok := range []string{"40000-40999", "1024-11023", "65535", "65535-65535", "1024-1024"} {
		if _, _, err := ParseRoamPorts(ok); err != nil {
			t.Fatal("valid range rejected", ok, err)
		}
	}
	for _, bad := range []string{"", "-", "1023-2000", "40000-65536", "41000-40000", "1024-11024", "40000-", "-40000", "4e4-40001", "040000-40001", " 40000-40001", "40000-40001-40002", "+40000-40001"} {
		if _, _, err := ParseRoamPorts(bad); err == nil {
			t.Fatal("invalid range accepted", bad)
		}
	}
	start, end, _ := ParseRoamPorts("40000-40999")
	if start != 40000 || end != 40999 || (Roam{Start: start, End: end}).Size() != 1000 {
		t.Fatal("range parsed wrong", start, end)
	}
}

func TestRoamSettingValidationAndDefaults(t *testing.T) {
	c := roamAWGConnection(t, "a", 10)
	if _, on := c.RoamSetting(); on {
		t.Fatal("roam on without roam_ports")
	}
	revision := c.Revision
	if err := c.SetRoam("40000-40999", 0); err != nil {
		t.Fatal(err)
	}
	r, on := c.RoamSetting()
	if !on || r.Start != 40000 || r.End != 40999 || r.Interval != DefaultRoamInterval {
		t.Fatal("default interval not applied", r, on)
	}
	if c.Revision != revision || c.Validate() != nil {
		t.Fatal("roam setting changed the payload revision or failed validation")
	}
	if err := c.SetRoam("40000-40999", 3600); err != nil {
		t.Fatal(err)
	}
	if r, _ = c.RoamSetting(); r.Interval != time.Hour {
		t.Fatal("interval not applied", r)
	}
	for _, bad := range []struct {
		ports    string
		interval int
	}{{"40000-40999", 59}, {"40000-40999", 86401}, {"40000-40999", -1}, {"", 600}, {"1000-2000", 0}} {
		before := c
		if err := c.SetRoam(bad.ports, bad.interval); err == nil {
			t.Fatal("invalid roam setting accepted", bad)
		}
		if c.RoamPorts != before.RoamPorts || c.RoamInterval != before.RoamInterval {
			t.Fatal("rejected setting changed the connection")
		}
	}
	if err := c.SetRoam("", 0); err != nil || c.RoamPorts != "" || c.RoamInterval != 0 {
		t.Fatal("roam could not be turned off")
	}
	// Only AWG roams.
	items, err := ParseImport([]byte("hy2://public-test@192.0.2.20:443?obfs=salamander&obfs-password=public-obfs"))
	if err != nil {
		t.Fatal(err)
	}
	h := items[0]
	h.ID = "h"
	if h.SetRoam("40000-40999", 0) == nil {
		t.Fatal("proxy accepted a roam setting")
	}
	h.RoamPorts = "40000-40999"
	if h.Validate() == nil {
		t.Fatal("stored proxy roam setting passed validation")
	}
	if _, on := h.RoamSetting(); on {
		t.Fatal("proxy roams")
	}
}

func TestRegistryRoamBackwardCompatibleAndPreservedOnReplace(t *testing.T) {
	a := roamAWGConnection(t, "a", 10)
	r := &Registry{Version: 2, Connections: []Connection{a}}
	plain, _ := json.Marshal(r)
	if strings.Contains(string(plain), "roam") {
		t.Fatal("registry without roaming gained roam fields", string(plain))
	}
	if _, err := Decode(plain); err != nil {
		t.Fatal("registry without roam fields rejected", err)
	}
	if err := r.Connections[0].SetRoam("40000-40999", 900); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(r)
	decoded, err := Decode(raw)
	if err != nil || decoded.Version != 2 || decoded.Connections[0].RoamPorts != "40000-40999" || decoded.Connections[0].RoamInterval != 900 {
		t.Fatal("roam setting did not round-trip", err)
	}
	if s := decoded.Connections[0].Summary(); s.RoamPorts != "40000-40999" || s.RoamInterval != 900 {
		t.Fatal("summary misses the roam setting", s)
	}
	bad := strings.Replace(string(raw), `"roam_interval":900`, `"roam_interval":5`, 1)
	if _, err := Decode([]byte(bad)); err == nil {
		t.Fatal("invalid stored roam interval accepted")
	}
	// Replacing the AWG payload keeps the server's roaming setting.
	replacement := roamAWGConnection(t, "x", 11)
	text := fmt.Sprintf("[Interface]\nPrivateKey=%s\nHeaderProtectionKey=%s\nAddress=10.77.0.2/32\nS1=12\nS2=12\nS3=12\nS4=12\n[Peer]\nPublicKey=%s\nPresharedKey=%s\nEndpoint=%s\nAllowedIPs=0.0.0.0/0\n", replacement.AWG["PrivateKey"], replacement.AWG["HeaderProtectionKey"], replacement.AWG["PublicKey"], replacement.AWG["PresharedKey"], replacement.AWG["Endpoint"])
	if err := decoded.Replace("a", []byte(text)); err != nil {
		t.Fatal(err)
	}
	if c := decoded.Connections[0]; c.RoamPorts != "40000-40999" || c.RoamInterval != 900 || c.Revision == a.Revision {
		t.Fatal("replace dropped the roam setting", c.RoamPorts, c.RoamInterval)
	}
	// Replacing with a proxy drops it (it would be invalid there).
	if err := decoded.Replace("a", []byte("hy2://public-test@192.0.2.20:443?obfs=salamander&obfs-password=public-obfs")); err != nil {
		t.Fatal(err)
	}
	if c := decoded.Connections[0]; c.RoamPorts != "" || c.RoamInterval != 0 {
		t.Fatal("proxy replacement kept an AWG roam setting")
	}
}
