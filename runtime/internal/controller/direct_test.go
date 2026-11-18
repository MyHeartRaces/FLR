package controller

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/control"
	"github.com/MyHeartRaces/FLR/runtime/internal/lan"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestSettingsPermanentDirectValidation(t *testing.T) {
	s := DefaultSettings()
	if s.DirectProxy != control.DefaultDirectConfigFor(lan.Legacy()) {
		t.Fatal("missing direct defaults")
	}
	s.DirectProxy.Bind = "0.0.0.0"
	if ValidateSettings(s) == nil {
		t.Fatal("WAN bind accepted")
	}
	s.DirectProxy = control.DefaultDirectConfigFor(lan.Legacy())
	s.DirectProxy.Port = 1088
	if ValidateSettings(s) == nil {
		t.Fatal("legacy conflict accepted")
	}
}
func TestLegacySettingsReceivePermanentDirectDefaults(t *testing.T) {
	s, e := DecodeSettings([]byte(`{"version":1,"enabled":false,"options":{"lan":"br-lan","wan":"eth1","selection":{"general":"down","games":"down"},"manual_games":false},"dns_port":"1054","local_dns_port":"53","profile_selection":"auto"}`))
	if e != nil || s.DirectProxy.Bind != "192.168.8.1" || s.DirectProxy.Port != 1080 || !s.DirectProxy.Enabled {
		t.Fatalf("migration %+v %v", s.DirectProxy, e)
	}
}
func TestMissingNetworkSettingsRemainRejected(t *testing.T) {
	if _, e := DecodeSettings([]byte(`{}`)); e == nil {
		t.Fatal("incomplete settings unexpectedly valid")
	}
}

func TestDirectAPIPatchPersistsAndRejectsInvalidConfig(t *testing.T) {
	c := New(DefaultSettings())
	c.stateDir = t.TempDir()
	// Administrative fixtures use the existing private state directory mode.
	if e := os.Chmod(c.stateDir, 0700); e != nil {
		t.Fatal(e)
	}
	raw := json.RawMessage(`{"direct_proxy":{"enabled":true,"bind":"192.168.8.1","port":1090}}`)
	if _, e := c.HandleAPI(control.APIRequest{Operation: "settings", Settings: raw}); e != nil {
		t.Fatal(e)
	}
	persisted, e := readSettingsAt(c.stateDir)
	if e != nil || persisted.DirectProxy.Port != 1090 {
		t.Fatalf("persistent listener %+v %v", persisted, e)
	}
	bad := json.RawMessage(`{"direct_proxy":{"enabled":true,"bind":"0.0.0.0","port":1091}}`)
	if _, e := c.HandleAPI(control.APIRequest{Operation: "settings", Settings: bad}); e == nil {
		t.Fatal("unsafe bind accepted")
	}
	persisted, e = readSettingsAt(c.stateDir)
	if e != nil || persisted.DirectProxy.Port != 1090 {
		t.Fatal("invalid patch changed stored settings")
	}
	status := c.Status()
	if status.DirectProxy.Running || status.DirectProxy.Config.Port != 1090 {
		t.Fatalf("offline status %+v", status.DirectProxy)
	}
}

func TestDirectAPIPatchRequiresAllNonNullFields(t *testing.T) {
	cases := []struct {
		name  string
		proxy string
	}{
		{"missing-enabled", `{"bind":"192.168.8.1","port":1091}`},
		{"null-enabled", `{"enabled":null,"bind":"192.168.8.1","port":1091}`},
		{"missing-bind", `{"enabled":false,"port":1091}`},
		{"null-bind", `{"enabled":false,"bind":null,"port":1091}`},
		{"missing-port", `{"enabled":false,"bind":"192.168.8.1"}`},
		{"null-port", `{"enabled":false,"bind":"192.168.8.1","port":null}`},
		{"null-object", `null`},
	}
	for _, live := range []bool{false, true} {
		mode := "offline"
		if live {
			mode = "live"
		}
		for _, tc := range cases {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				c := testAdmin(t)
				c.live = live
				initial := json.RawMessage(`{"direct_proxy":{"enabled":true,"bind":"192.168.8.1","port":1090}}`)
				if _, e := c.HandleAPI(control.APIRequest{Operation: "settings", Settings: initial}); e != nil {
					t.Fatal(e)
				}
				before, e := os.ReadFile(filepath.Join(c.stateDir, "settings.json"))
				if e != nil {
					t.Fatal(e)
				}
				generation := c.Status().Generation
				<-c.refresh
				bad := json.RawMessage(`{"primary_group":"changed","direct_proxy":` + tc.proxy + `}`)
				if _, e := c.HandleAPI(control.APIRequest{Operation: "settings", Settings: bad}); e == nil {
					t.Fatal("incomplete direct configuration accepted")
				}
				after, e := os.ReadFile(filepath.Join(c.stateDir, "settings.json"))
				if e != nil || !bytes.Equal(before, after) {
					t.Fatalf("rejected patch changed persisted settings: %v", e)
				}
				status := c.Status()
				if c.settings.PrimaryGroup != "" || !status.DirectProxy.Config.Enabled || status.DirectProxy.Config.Bind != "192.168.8.1" || status.DirectProxy.Config.Port != 1090 || status.Generation != generation {
					t.Fatalf("rejected patch changed controller settings: %+v", status)
				}
				select {
				case <-c.refresh:
					t.Fatal("rejected patch notified live reconciliation")
				default:
				}
			})
		}
	}
}

func TestDirectAPIPatchExplicitFalseDisables(t *testing.T) {
	c := testAdmin(t)
	c.live = true
	raw := json.RawMessage(`{"direct_proxy":{"enabled":false,"bind":"192.168.8.1","port":1090}}`)
	if _, e := c.HandleAPI(control.APIRequest{Operation: "settings", Settings: raw}); e != nil {
		t.Fatal(e)
	}
	persisted, e := readSettingsAt(c.stateDir)
	if e != nil || persisted.DirectProxy.Enabled || persisted.DirectProxy.Port != 1090 {
		t.Fatalf("explicit disable did not persist: %+v %v", persisted.DirectProxy, e)
	}
	if c.Status().DirectProxy.Config.Enabled {
		t.Fatal("explicit disable did not update live controller settings")
	}
	select {
	case <-c.refresh:
	default:
		t.Fatal("explicit disable did not notify reconciliation")
	}
}

const storedOptions = `"options":{"lan":"br-lan","wan":"eth1","selection":{"general":"down","games":"down"},"manual_games":false},"dns_port":"1054","local_dns_port":"53","profile_selection":"auto"`

func TestDefaultSettingsUseDiscoveredLAN(t *testing.T) {
	useLAN(t, "192.168.1.1/24")
	s := DefaultSettings()
	// The stored default is the 0.6 one; the bind in use is the discovered LAN.
	if s.DirectProxy != (control.DirectConfig{Enabled: true, Bind: "192.168.8.1", Port: 1080}) || ValidateSettings(s) != nil {
		t.Fatalf("%+v", s.DirectProxy)
	}
	c := New(s)
	c.refreshLAN()
	if d := c.effectiveDirect(); d != (control.DirectConfig{Enabled: true, Bind: "192.168.1.1", Port: 1080}) || c.Status().DirectProxy.Config != d {
		t.Fatalf("%+v %+v", d, c.Status().DirectProxy)
	}
	s.Options.Profiles = map[string]contract.Class{"192.168.1.20": contract.Games}
	if ValidateSettings(s) != nil {
		t.Fatal("device on the discovered LAN rejected")
	}
	// Settings validation is structural: a stored profile outside the LAN is
	// valid settings (it is ignored when rendering, and the API refuses to add one).
	s.Options.Profiles = map[string]contract.Class{"192.168.8.20": contract.Games}
	if ValidateSettings(s) != nil {
		t.Fatal("stored device outside the discovered LAN rejected")
	}
	s.Options.Profiles = map[string]contract.Class{"8.8.8.8": contract.Games}
	if ValidateSettings(s) == nil {
		t.Fatal("public device address accepted")
	}
}

// The saved bind is kept as loaded (rollback to 0.6 needs 192.168.8.1); the
// bind in use is the discovered router address.
func TestSavedOldDefaultBindKeptAndDiscoveredLANUsed(t *testing.T) {
	useLAN(t, "192.168.1.1/24")
	inUse := func(s Settings) control.DirectConfig {
		c := New(s)
		c.refreshLAN()
		return c.effectiveDirect()
	}
	s, e := DecodeSettings([]byte(`{"version":1,"enabled":false,"direct_proxy":{"enabled":true,"bind":"192.168.8.1","port":1090},` + storedOptions + `}`))
	if e != nil || s.DirectProxy != (control.DirectConfig{Enabled: true, Bind: "192.168.8.1", Port: 1090}) || inUse(s) != (control.DirectConfig{Enabled: true, Bind: "192.168.1.1", Port: 1090}) {
		t.Fatalf("%+v %v", s.DirectProxy, e)
	}
	s, e = DecodeSettings([]byte(`{"version":1,"enabled":false,"direct_proxy":{"enabled":false,"bind":"192.168.8.1","port":1091},` + storedOptions + `}`))
	if e != nil || s.DirectProxy != (control.DirectConfig{Enabled: false, Bind: "192.168.8.1", Port: 1091}) || inUse(s) != (control.DirectConfig{Enabled: false, Bind: "192.168.1.1", Port: 1091}) {
		t.Fatalf("disabled flag or port lost: %+v %v", s.DirectProxy, e)
	}
	// Settings without a direct_proxy section get the 0.6 default, not the LAN.
	s, e = DecodeSettings([]byte(`{"version":1,"enabled":false,` + storedOptions + `}`))
	if e != nil || s.DirectProxy.Bind != "192.168.8.1" || inUse(s).Bind != "192.168.1.1" {
		t.Fatalf("%+v %v", s.DirectProxy, e)
	}
	// The stored bind survives the normal save and reload path.
	dir := t.TempDir()
	if e = os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if e = WriteJSON(filepath.Join(dir, "settings.json"), s); e != nil {
		t.Fatal(e)
	}
	if again, e := readSettingsAt(dir); e != nil || again.DirectProxy.Bind != "192.168.8.1" {
		t.Fatalf("%+v %v", again.DirectProxy, e)
	}
}

func TestSavedOldDefaultBindUnchangedOnLegacyLAN(t *testing.T) {
	s, e := DecodeSettings([]byte(`{"version":1,"enabled":false,"direct_proxy":{"enabled":true,"bind":"192.168.8.1","port":1090},` + storedOptions + `}`))
	if e != nil || s.DirectProxy.Bind != "192.168.8.1" || s.DirectProxy.Port != 1090 {
		t.Fatalf("%+v %v", s.DirectProxy, e)
	}
}

// Whatever bind was saved, the bind in use is the router's own address; the
// bind is never a free choice. A private saved bind is kept as stored; one
// that is not a private IPv4 address is replaced by the 0.6 default so the
// file still loads.
func TestSavedBindsFollowDiscoveredLAN(t *testing.T) {
	useLAN(t, "192.168.1.1/24")
	for bind, stored := range map[string]string{"0.0.0.0": "192.168.8.1", "192.168.1.2": "192.168.1.2", "192.168.8.2": "192.168.8.2", "10.0.0.1": "10.0.0.1", "203.0.113.10": "192.168.8.1", "": "192.168.8.1"} {
		s, e := DecodeSettings([]byte(`{"version":1,"enabled":false,"direct_proxy":{"enabled":true,"bind":"` + bind + `","port":1090},` + storedOptions + `}`))
		if e != nil || s.DirectProxy != (control.DirectConfig{Enabled: true, Bind: stored, Port: 1090}) {
			t.Fatalf("saved bind %q: %+v %v", bind, s.DirectProxy, e)
		}
		c := New(s)
		c.refreshLAN()
		if d := c.effectiveDirect(); d != (control.DirectConfig{Enabled: true, Bind: "192.168.1.1", Port: 1090}) {
			t.Fatalf("saved bind %q in use as %+v", bind, d)
		}
	}
	if _, e := DecodeSettings([]byte(`{"version":1,"enabled":false,"direct_proxy":{"enabled":true,"bind":"192.168.1.1","port":1088},` + storedOptions + `}`)); e == nil {
		t.Fatal("reserved port accepted")
	}
}

// Without a discovered LAN the stored bind is checked for structure only.
func TestSavedBindStructureWhenDiscoveryFails(t *testing.T) {
	failLAN(t)
	for bind, ok := range map[string]bool{"10.0.0.1": true, "192.168.1.1": true, "0.0.0.0": false, "203.0.113.10": false, "": false} {
		s, e := DecodeSettings([]byte(`{"version":1,"enabled":false,"direct_proxy":{"enabled":true,"bind":"` + bind + `","port":1090},` + storedOptions + `}`))
		if (e == nil) != ok || (ok && s.DirectProxy.Bind != bind) {
			t.Fatalf("saved bind %q: %+v %v", bind, s.DirectProxy, e)
		}
	}
}

func TestMigrationKeepsLegacyBindWhenDiscoveryFails(t *testing.T) {
	old := lan.Source
	defer func() { lan.Source = old }()
	lan.Source = func(string) ([]net.Addr, error) { return nil, errors.New("no such network interface") }
	s, e := DecodeSettings([]byte(`{"version":1,"enabled":false,"direct_proxy":{"enabled":true,"bind":"192.168.8.1","port":1090},` + storedOptions + `}`))
	if e != nil || s.DirectProxy.Bind != "192.168.8.1" {
		t.Fatalf("%+v %v", s.DirectProxy, e)
	}
}

func TestDirectAPIPatchAcceptsDiscoveredLANAndRejectsOthers(t *testing.T) {
	useLAN(t, "192.168.1.1/24")
	c := New(DefaultSettings())
	c.stateDir = t.TempDir()
	if e := os.Chmod(c.stateDir, 0700); e != nil {
		t.Fatal(e)
	}
	good := json.RawMessage(`{"direct_proxy":{"enabled":true,"bind":"192.168.1.1","port":1090}}`)
	if _, e := c.HandleAPI(control.APIRequest{Operation: "settings", Settings: good}); e != nil {
		t.Fatal(e)
	}
	// Enabled and port are persisted; the stored bind keeps the 0.6 default so
	// a rollback still loads settings.json, and the listener uses the LAN.
	persisted, e := readSettingsAt(c.stateDir)
	if e != nil || persisted.DirectProxy != (control.DirectConfig{Enabled: true, Bind: "192.168.8.1", Port: 1090}) {
		t.Fatalf("%+v %v", persisted.DirectProxy, e)
	}
	if in := c.Status().DirectProxy.Config; in != (control.DirectConfig{Enabled: true, Bind: "192.168.1.1", Port: 1090}) {
		t.Fatalf("config in use %+v", in)
	}
	for _, bind := range []string{"192.168.8.1", "192.168.1.2", "0.0.0.0"} {
		bad := json.RawMessage(`{"direct_proxy":{"enabled":true,"bind":"` + bind + `","port":1091}}`)
		if _, e := c.HandleAPI(control.APIRequest{Operation: "settings", Settings: bad}); e == nil {
			t.Fatalf("bind %s accepted", bind)
		}
	}
}
