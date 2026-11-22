package controller

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/control"
	dnsbroker "github.com/MyHeartRaces/FLR/runtime/internal/dns"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
)

type classifierRecorder struct{ set []dnsbroker.Classifier }

func TestRoutingModePassesThroughNativeDNSOnlyForDirect(t *testing.T) {
	base, err := policy.Load("../policy/testdata/split")
	if err != nil {
		t.Fatal(err)
	}
	tunnel, direct := base.ForMode(policy.ModeTunnel), base.ForMode(policy.ModeDirect)
	for _, tc := range []struct {
		name       string
		from, to   *policy.Policy
		failure    string
		operations []string
	}{
		{"rule based", base, tunnel, "", []string{"publish rules"}},
		{"enter Direct", tunnel, direct, "", []string{"guard DNS", "stop broker", "native DNS", "publish direct"}},
		{"leave Direct", direct, base, "", []string{"guard DNS", "stop broker", "local DNS", "start broker", "publish rules"}},
		{"failed guard", base, direct, "guard DNS", []string{"guard DNS"}},
		{"failed Direct publication", base, direct, "publish direct", []string{"guard DNS", "stop broker", "native DNS", "publish direct", "guard DNS", "fence rules", "stop broker", "local DNS", "start broker", "publish rules"}},
		{"failed native resolver", tunnel, direct, "native DNS", []string{"guard DNS", "stop broker", "native DNS", "stop broker", "local DNS", "start broker", "publish rules"}},
		{"failed return to policy", direct, tunnel, "publish rules", []string{"guard DNS", "stop broker", "local DNS", "start broker", "publish rules", "guard DNS", "fence direct", "stop broker", "native DNS", "publish direct"}},
		{"failed broker restart", direct, tunnel, "start broker", []string{"guard DNS", "stop broker", "local DNS", "start broker", "stop broker", "native DNS", "publish direct"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var operations []string
			record := func(op string) error {
				operations = append(operations, op)
				if op == tc.failure {
					return os.ErrPermission
				}
				return nil
			}
			ops := routingModeOps{
				guardDNS: func() error { return record("guard DNS") },
				publish: func(p *policy.Policy, keepGuard bool) error {
					verb, mode := "publish", "rules"
					if keepGuard {
						verb = "fence"
					}
					if p.Bypass() {
						mode = "direct"
					}
					return record(verb + " " + mode)
				},
				nativeDNS: func(direct bool) error {
					if direct {
						return record("native DNS")
					}
					return record("local DNS")
				},
				startDNS: func() error { return record("start broker") },
				stopDNS:  func() { _ = record("stop broker") },
			}
			var pending bool
			err := ops.apply(tc.from, tc.to, &pending)
			if (err != nil) != (tc.failure != "") || pending != (tc.failure == "guard DNS") || !slices.Equal(operations, tc.operations) {
				t.Fatalf("apply: %v, operations %v, want %v", err, operations, tc.operations)
			}
		})
	}
}

func TestRoutingModeKeepsPreviousForwardingWhenDNSRollbackFails(t *testing.T) {
	base, err := policy.Load("../policy/testdata/split")
	if err != nil {
		t.Fatal(err)
	}
	direct := base.ForMode(policy.ModeDirect)
	for _, tc := range []struct {
		name     string
		from, to *policy.Policy
		cancel   bool
	}{
		{"retry Direct", base, direct, false},
		{"cancel Direct", base, direct, true},
		{"retry Tunnel", direct, base, false},
		{"cancel Tunnel", direct, base, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			active := tc.from
			guarded, pending, dnsFault := false, false, true
			ops := routingModeOps{
				guardDNS: func() error { guarded = true; return nil },
				publish: func(view *policy.Policy, keepGuard bool) error {
					if !guarded {
						t.Fatal("published routing policy without guarding DNS")
					}
					active, guarded = view, keepGuard
					return nil
				},
				nativeDNS: func(bool) error {
					if !guarded || active != tc.from {
						t.Fatal("DNS changed with its guard absent or the previous forwarding mode retired")
					}
					if dnsFault {
						return os.ErrPermission
					}
					return nil
				},
				startDNS: func() error { return nil },
				stopDNS:  func() {},
			}
			if err := ops.apply(tc.from, tc.to, &pending); err == nil || !pending || !guarded || active != tc.from {
				t.Fatalf("failed handoff retired previous forwarding or left DNS unguarded: %v", err)
			}
			dnsFault = false
			want := tc.to
			if tc.cancel {
				want = tc.from
			}
			if err := ops.apply(tc.from, want, &pending); err != nil || pending || guarded || active != want {
				t.Fatalf("handoff could not recover: %v", err)
			}
		})
	}
}

func TestRoutingModeRefencesBeforeDNSRollbackOnUnconfirmedPublish(t *testing.T) {
	base, err := policy.Load("../policy/testdata/split")
	if err != nil {
		t.Fatal(err)
	}
	direct := base.ForMode(policy.ModeDirect)
	for _, tc := range []struct {
		name         string
		rollbackFail bool
	}{{"rollback succeeds", false}, {"guard holds on failed rollback", true}} {
		t.Run(tc.name, func(t *testing.T) {
			active, guarded, pending := base, false, false
			rollbackFail := tc.rollbackFail
			ops := routingModeOps{
				guardDNS: func() error { guarded = true; return nil },
				publish: func(view *policy.Policy, keepGuard bool) error {
					if keepGuard && rollbackFail {
						return os.ErrPermission
					}
					active, guarded = view, keepGuard
					if view == direct {
						return os.ErrDeadlineExceeded // command lost its reply after changing nft
					}
					return nil
				},
				nativeDNS: func(bool) error {
					if active != base || !guarded {
						t.Fatal("reconfigured DNS before reasserting the guarded policy")
					}
					return nil
				},
				startDNS: func() error { return nil },
				stopDNS:  func() {},
			}
			if err := ops.apply(base, direct, &pending); err == nil || pending != rollbackFail || guarded != rollbackFail {
				t.Fatalf("unexpected result after unconfirmed publish: %v", err)
			}
			rollbackFail = false
			if err := ops.apply(base, base, &pending); err != nil || pending || guarded || active != base {
				t.Fatalf("could not reconcile previous mode: %v", err)
			}
		})
	}
}

func (d *classifierRecorder) Replace(dnsbroker.View, string, []dnsbroker.AddressTTL) error {
	return nil
}
func (d *classifierRecorder) ApplyPolicy(f dnsbroker.Classifier, _ string) error {
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
	c.applyRoutingPolicy = func(p *policy.Policy) error {
		if fail {
			return os.ErrPermission
		}
		applied = append(applied, p)
		return c.broker.ApplyPolicy(p, "")
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
