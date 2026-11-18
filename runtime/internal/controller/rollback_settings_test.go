package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	"github.com/MyHeartRaces/FLR/runtime/internal/bypass"
	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/control"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
)

// headEraSettings is the settings schema of the 0.6 controller (HEAD, image
// #152): no warm_reserve key, and options without later fields.
type headEraSettings struct {
	DirectBypass    bypass.Config `json:"direct_bypass"`
	HealthPolicy    health.Policy `json:"health_policy"`
	Version         int           `json:"version"`
	SavedGeneration uint64        `json:"saved_generation,omitempty"`
	DirectProxy     struct {
		Enabled bool   `json:"enabled"`
		Bind    string `json:"bind"`
		Port    int    `json:"port"`
	} `json:"direct_proxy"`
	Enabled bool `json:"enabled"`
	Options struct {
		LAN         string                    `json:"lan"`
		WAN         string                    `json:"wan"`
		TestClient  string                    `json:"test_client,omitempty"`
		Selection   contract.Selection        `json:"selection"`
		ManualGames bool                      `json:"manual_games"`
		Profiles    map[string]contract.Class `json:"profiles,omitempty"`
	} `json:"options"`
	DNSPort          string               `json:"dns_port"`
	LocalDNSPort     string               `json:"local_dns_port"`
	ProfileSelection string               `json:"profile_selection"`
	PrimaryGroup     string               `json:"primary_group,omitempty"`
	FamilyOrder      []string             `json:"family_order,omitempty"`
	Selection        connection.Selection `json:"selection"`
	Order            connection.Order     `json:"order"`
	MigrationNotice  string               `json:"migration_notice,omitempty"`
}

// headEraAcceptsSettings repeats the 0.6 controller's settings load
// (DecodeSettings and validateSettings at HEAD): a strict decode that rejects
// unknown keys, the fixed direct proxy bind 192.168.8.1 and device profiles
// only inside 192.168.8.0/24. An error here means a rolled-back 0.6 controller
// refuses the file and stops at start.
func headEraAcceptsSettings(b []byte) error {
	if len(b) > 1<<20 {
		return fmt.Errorf("settings too large")
	}
	if e := control.CheckJSON(b); e != nil {
		return e
	}
	s := headEraSettings{DirectBypass: bypass.Config{TCP: "off", QUIC: "off"}, HealthPolicy: health.DefaultPolicy()}
	s.DirectProxy.Enabled, s.DirectProxy.Bind, s.DirectProxy.Port = true, "192.168.8.1", 1080
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(&s); e != nil {
		return fmt.Errorf("invalid settings schema: %v", e)
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return fmt.Errorf("trailing settings")
	}
	var fields map[string]json.RawMessage
	if e := json.Unmarshal(b, &fields); e != nil {
		return e
	}
	if raw, ok := fields["health_policy"]; ok {
		if _, e := decodeHealthPolicy(raw); e != nil {
			return e
		}
	}
	if raw, ok := fields["direct_bypass"]; ok {
		var e error
		if s.DirectBypass, e = decodeBypassWith(raw, true); e != nil {
			return e
		}
	}
	if raw, ok := fields["primary_group"]; ok && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("invalid primary group")
	}
	if s.Version == 0 {
		s.Version = 1
	}
	if s.ProfileSelection == "" {
		s.ProfileSelection = "auto"
	}
	if e := s.DirectBypass.Validate(); e != nil {
		return e
	}
	if e := s.HealthPolicy.Validate(); e != nil {
		return e
	}
	if p := s.DirectProxy; p.Bind != "192.168.8.1" || p.Port < 1024 || p.Port > 65535 || p.Port == 1088 {
		return fmt.Errorf("direct proxy requires router LAN 192.168.8.1 and port 1024..65535 except1088")
	}
	if s.DirectProxy.Port == portNumber(s.DNSPort) || s.DirectProxy.Port == portNumber(s.LocalDNSPort) {
		return fmt.Errorf("direct proxy port collides with DNS")
	}
	if s.Version != 1 && s.Version != 2 {
		return fmt.Errorf("unsupported settings version")
	}
	if s.SavedGeneration > (1<<53)-1 {
		return fmt.Errorf("invalid saved generation")
	}
	iface := regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)
	if o := s.Options; !iface.MatchString(o.LAN) || !iface.MatchString(o.WAN) || o.LAN == o.WAN {
		return fmt.Errorf("invalid network settings")
	}
	for client, class := range s.Options.Profiles {
		ip, e := netip.ParseAddr(client)
		if e != nil || !ip.Is4() || !netip.MustParsePrefix("192.168.8.0/24").Contains(ip) || ip.As4()[3] < 2 || ip.As4()[3] == 255 {
			return fmt.Errorf("invalid network settings: profile %s needs a 192.168.8.0/24 host", client)
		}
		if class != contract.Direct && class != contract.General && class != contract.Games {
			return fmt.Errorf("invalid network settings")
		}
	}
	for _, port := range []string{s.DNSPort, s.LocalDNSPort} {
		if n, e := strconv.Atoi(port); e != nil || n < 1 || n > 65535 {
			return fmt.Errorf("invalid DNS port")
		}
	}
	if s.DNSPort == s.LocalDNSPort {
		return fmt.Errorf("DNS ports collide")
	}
	if !regexp.MustCompile(`^[a-z0-9_-]{1,80}$`).MatchString(s.ProfileSelection) {
		return fmt.Errorf("invalid profile selection")
	}
	if profile.ValidateGroup(s.PrimaryGroup) != nil && !(len(s.PrimaryGroup) <= 128 && legacyPrimaryGroup.MatchString(s.PrimaryGroup)) {
		return fmt.Errorf("invalid primary group")
	}
	if s.Version == 2 {
		if e := connection.ValidateSelection(s.Selection); e != nil {
			return e
		}
		if e := connection.ValidateFamilies(s.Order.Families); e != nil {
			return e
		}
		if len(s.MigrationNotice) > 512 {
			return fmt.Errorf("invalid migration notice")
		}
		return validateFamilyOrder(s.FamilyOrder, false)
	}
	return validateFamilyOrder(s.FamilyOrder, true)
}

// Finding 1: on a router whose LAN is not 192.168.8.0/24, LAN discovery, LAN
// changes and every kind of settings save keep the stored bind as loaded
// (192.168.8.1) and write no warm_reserve key, so the 0.6 controller still
// accepts settings.json after a rollback. A direct_proxy change through the
// API (what LuCI "Save direct" sends) persists enabled and port and also keeps
// the stored bind.
func TestSavedSettingsStayAcceptableToRollbackController(t *testing.T) {
	useLAN(t, "192.168.1.1/24")
	c := connectionAdmin(t)
	path := filepath.Join(c.stateDir, "settings.json")
	stored := func() []byte {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if err := headEraAcceptsSettings(stored()); err != nil {
		t.Fatalf("fixture not a 0.6 settings file: %v", err)
	}
	direct := &fakeDirect{}
	c.directDeps = direct.deps()
	t.Cleanup(func() {
		if c.direct != nil {
			c.direct.Stop()
		}
	})
	tick := func() {
		c.refreshLAN()
		c.reconcileDirect(context.Background())
	}
	api := func(raw string) {
		t.Helper()
		if _, err := c.HandleAPI(control.APIRequest{Operation: "settings", Settings: json.RawMessage(raw)}); err != nil {
			t.Fatal(raw, err)
		}
	}
	check := func(step, inUse string) {
		t.Helper()
		raw := stored()
		if err := headEraAcceptsSettings(raw); err != nil {
			t.Fatalf("%s: the 0.6 controller would refuse settings.json: %v\n%s", step, err, raw)
		}
		if bytes.Contains(raw, []byte("warm_reserve")) {
			t.Fatalf("%s: warm_reserve key stored", step)
		}
		s, err := readSettingsAt(c.stateDir)
		if err != nil || s.DirectProxy.Bind != "192.168.8.1" || c.settings.DirectProxy.Bind != "192.168.8.1" {
			t.Fatalf("%s: stored bind changed: %+v %v", step, s.DirectProxy, err)
		}
		status := c.Status()
		if status.DirectProxy.Config.Bind != inUse {
			t.Fatalf("%s: bind in use %+v, want %s", step, status.DirectProxy, inUse)
		}
		data, err := c.HandleAPI(control.APIRequest{Operation: "settings"})
		if err != nil || data.(Settings).DirectProxy.Bind != inUse {
			t.Fatalf("%s: settings API does not report the bind in use: %v", step, err)
		}
	}

	tick()
	if binds := direct.binds(); len(binds) != 1 || binds[0] != "192.168.1.1:1080" {
		t.Fatalf("listener not on the discovered LAN: %v", binds)
	}
	api(`{"health_policy":` + string(mustJSON(health.DefaultPolicy())) + `}`)
	check("health policy save", "192.168.1.1")
	api(`{"direct_bypass":{"enabled":false,"tcp":"off","quic":"off"}}`)
	check("direct bypass save", "192.168.1.1")
	api(`{"warm_reserve":{"enabled":false,"interval_seconds":60}}`)
	api(`{"warm_reserve":{"enabled":true,"interval_seconds":30}}`)
	check("warm reserve back to default", "192.168.1.1")
	if _, err := c.HandleAPI(connectionRequest(t, c, "selection", map[string]any{"selection": map[string]string{"mode": "auto"}})); err != nil {
		t.Fatal(err)
	}
	check("connection selection save", "192.168.1.1")

	// The LAN moves; the listener follows, the stored bind does not.
	useLAN(t, "10.0.0.1/24")
	c.lanCache.Flush()
	tick()
	if binds := direct.binds(); len(binds) != 2 || binds[1] != "10.0.0.1:1080" {
		t.Fatalf("listener did not follow the LAN: %v", binds)
	}
	api(`{"health_policy":` + string(mustJSON(health.DefaultPolicy())) + `}`)
	check("save after LAN change", "10.0.0.1")

	// A direct_proxy change (LuCI sends the bind in use) persists enabled and
	// port; the stored bind stays, so the file is still a 0.6 settings file.
	api(`{"direct_proxy":{"enabled":true,"bind":"10.0.0.1","port":1090}}`)
	s, err := readSettingsAt(c.stateDir)
	if err != nil || s.DirectProxy != (control.DirectConfig{Enabled: true, Bind: "192.168.8.1", Port: 1090}) {
		t.Fatalf("direct_proxy change: stored %+v %v, want enabled, bind 192.168.8.1, port 1090", s.DirectProxy, err)
	}
	if err := headEraAcceptsSettings(stored()); err != nil {
		t.Fatalf("direct_proxy change: the 0.6 controller would refuse settings.json: %v", err)
	}
	tick()
	if binds := direct.binds(); len(binds) != 3 || binds[2] != "10.0.0.1:1090" {
		t.Fatalf("direct_proxy change: listener not moved to 10.0.0.1:1090: %v", binds)
	}
	status := c.Status()
	if status.DirectProxy.Config != (control.DirectConfig{Enabled: true, Bind: "10.0.0.1", Port: 1090}) {
		t.Fatalf("direct_proxy change: in use %+v, want 10.0.0.1:1090", status.DirectProxy.Config)
	}
	data, err := c.HandleAPI(control.APIRequest{Operation: "settings"})
	if err != nil || data.(Settings).DirectProxy != (control.DirectConfig{Enabled: true, Bind: "10.0.0.1", Port: 1090}) {
		t.Fatalf("direct_proxy change: settings API does not report the config in use: %v", err)
	}
	// A bind other than the router's own address is still refused.
	if _, err := c.HandleAPI(control.APIRequest{Operation: "settings", Settings: json.RawMessage(`{"direct_proxy":{"enabled":true,"bind":"192.168.8.1","port":1080}}`)}); err == nil {
		t.Fatal("direct_proxy change to a bind outside the router LAN accepted")
	}
}

// The copied validator is a faithful gate: it refuses each thing the 0.6
// controller refuses and that the rollback note tells the owner to fix.
func TestHeadEraValidatorRefusesWhatRollbackNoteFixes(t *testing.T) {
	base := `{"version":1,"enabled":true,"direct_proxy":{"enabled":true,"bind":"192.168.8.1","port":1080},` + storedOptions + `}`
	if err := headEraAcceptsSettings([]byte(base)); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"bind":    `{"version":1,"enabled":true,"direct_proxy":{"enabled":true,"bind":"192.168.1.1","port":1080},` + storedOptions + `}`,
		"warm":    `{"version":1,"enabled":true,"warm_reserve":{"enabled":false,"interval_seconds":60},"direct_proxy":{"enabled":true,"bind":"192.168.8.1","port":1080},` + storedOptions + `}`,
		"profile": `{"version":1,"enabled":true,"direct_proxy":{"enabled":true,"bind":"192.168.8.1","port":1080},"options":{"lan":"br-lan","wan":"eth1","selection":{"general":"down","games":"down"},"manual_games":false,"profiles":{"192.168.1.20":"games"}},"dns_port":"1054","local_dns_port":"53","profile_selection":"auto"}`,
	} {
		if headEraAcceptsSettings([]byte(raw)) == nil {
			t.Fatalf("%s: accepted", name)
		}
		// This controller loads each of them.
		if _, err := DecodeSettings([]byte(raw)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
