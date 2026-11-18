package controller

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/control"
	dnsbroker "github.com/MyHeartRaces/FLR/runtime/internal/dns"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
)

type classifierRecorder struct{ set []dnsbroker.Classifier }

func (d *classifierRecorder) Replace(dnsbroker.View, string, []dnsbroker.AddressTTL) error {
	return nil
}
func (d *classifierRecorder) SetClassifier(f dnsbroker.Classifier) error {
	d.set = append(d.set, f)
	return nil
}

func TestRoutingModeSettingAppliesWithoutRestart(t *testing.T) {
	useLAN(t, "192.168.1.1/24")
	c := connectionAdmin(t)
	base, err := policy.Load("../policy/testdata/split")
	if err != nil {
		t.Fatal(err)
	}
	c.basePolicy, c.policy, c.appliedMode = base, base, policy.ModeSplit
	mappings := &classifierRecorder{}
	c.broker = dnsbroker.New(base, dnsbroker.StaticRoute{Channel: contract.AWG}, mappings)
	var applied []*policy.Policy
	fail := false
	c.applyStaticSets = func(p *policy.Policy) error {
		if fail {
			return os.ErrPermission
		}
		applied = append(applied, p)
		return nil
	}
	api := func(raw string) (Settings, error) {
		data, err := c.HandleAPI(control.APIRequest{Operation: "settings", Settings: json.RawMessage(raw)})
		if err != nil {
			return Settings{}, err
		}
		return data.(Settings), nil
	}
	read, err := c.HandleAPI(control.APIRequest{Operation: "settings"})
	if err != nil || read.(Settings).RoutingMode != policy.ModeSplit {
		t.Fatalf("default routing mode: %v %v", read, err)
	}
	for _, bad := range []string{`{"routing_mode":"FULL"}`, `{"routing_mode":""}`, `{"routing_mode":1}`} {
		if _, err := api(bad); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	s, err := api(`{"routing_mode":"full"}`)
	if err != nil || s.RoutingMode != policy.ModeFull || c.settings.RoutingMode != policy.ModeFull {
		t.Fatalf("full: %+v %v", s.RoutingMode, err)
	}
	if c.appliedMode != policy.ModeSplit || len(applied) != 0 {
		t.Fatal("mode applied before the controller round")
	}
	fail = true
	c.reconcileRoutingMode()
	if c.appliedMode != policy.ModeSplit || c.Status().LastError == "" {
		t.Fatal("failed apply must keep the old mode and report a retry")
	}
	fail = false
	c.reconcileRoutingMode()
	if c.appliedMode != policy.ModeFull || len(applied) != 1 || len(applied[0].CIDRs("roscom-direct-ips")) != 0 {
		t.Fatalf("full not applied: %d", len(applied))
	}
	if c.policy.ClassifyDomain("api.ozon.ru") != contract.General || base.ClassifyDomain("api.ozon.ru") != contract.Direct {
		t.Fatal("full view wrong or base policy changed")
	}
	if len(mappings.set) != 1 {
		t.Fatal("DNS bindings not reclassified")
	}
	if v, _ := mappings.set[0]("api.ozon.ru", dnsbroker.View{}, netip.MustParseAddr("198.51.100.1")); v.Class != contract.General {
		t.Fatal("full mode classifier keeps a direct binding")
	}
	c.reconcileRoutingMode()
	if len(applied) != 1 {
		t.Fatal("unchanged mode re-applied")
	}
	if _, err = api(`{"routing_mode":"split"}`); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(c.stateDir, "settings.json"))
	if err != nil || bytes.Contains(raw, []byte("routing_mode")) {
		t.Fatal("default split mode must not be stored")
	}
	if err := headEraAcceptsSettings(raw); err != nil {
		t.Fatalf("split settings must stay loadable by 0.6: %v", err)
	}
	c.reconcileRoutingMode()
	if c.appliedMode != policy.ModeSplit || c.policy.ClassifyDomain("api.ozon.ru") != contract.Direct || len(mappings.set) != 2 {
		t.Fatal("split not restored")
	}
}

func TestStoredRoutingModeLoads(t *testing.T) {
	s := DefaultSettings()
	s.RoutingMode = "full_domestic"
	if err := validateSettings(s, false); err != nil {
		t.Fatal(err)
	}
	s.RoutingMode = "split"
	if validateSettings(s, false) == nil {
		t.Fatal("split must be stored as the empty default")
	}
	s.RoutingMode = "everything"
	if validateSettings(s, false) == nil {
		t.Fatal("unknown mode accepted")
	}
}

func TestTunnelQoSSetting(t *testing.T) {
	useLAN(t, "192.168.1.1/24")
	c := connectionAdmin(t)
	set := func(raw string) error {
		_, err := c.HandleAPI(control.APIRequest{Operation: "settings", Settings: json.RawMessage(raw)})
		return err
	}
	for _, bad := range []string{`{"tunnel_qos":{"enabled":true}}`, `{"tunnel_qos":{"enabled":true,"upload_kbit":0,"download_kbit":0}}`, `{"tunnel_qos":{"enabled":true,"upload_kbit":10,"download_kbit":0}}`, `{"tunnel_qos":{"enabled":true,"upload_kbit":45000,"download_kbit":0,"x":1}}`} {
		if set(bad) == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	if err := set(`{"tunnel_qos":{"enabled":true,"upload_kbit":45000,"download_kbit":90000}}`); err != nil {
		t.Fatal(err)
	}
	if q := c.settings.TunnelQoS; q == nil || q.UploadKbit != 45000 || q.DownloadKbit != 90000 {
		t.Fatalf("%+v", q)
	}
	if err := set(`{"tunnel_qos":{"enabled":false,"upload_kbit":0,"download_kbit":0}}`); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(c.stateDir, "settings.json"))
	if c.settings.TunnelQoS != nil || bytes.Contains(raw, []byte("tunnel_qos")) {
		t.Fatal("disabled queueing must be stored as absent")
	}
	read, err := c.HandleAPI(control.APIRequest{Operation: "settings"})
	if err != nil || read.(Settings).TunnelQoS == nil || read.(Settings).TunnelQoS.Enabled {
		t.Fatal("settings read must report the effective queueing")
	}
}
