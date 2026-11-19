package controller

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/control"
	dnsbroker "github.com/MyHeartRaces/FLR/runtime/internal/dns"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
)

// Synthetic policies only: documentation addresses and example names.
func writeRoutingPolicy(t *testing.T, dir, status string, rulesets map[string]string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "rulesets"), 0700); err != nil {
		t.Fatal(err)
	}
	meta := fmt.Sprintf(`{"format":"flint2-home-vpn-routing-policy","version":3,"status":%q,"default_class":"vpn-general"}`, status)
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(meta), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range policy.RulesetNames() {
		body, ok := rulesets[name]
		if !ok {
			body = `{"version":3,"rules":[]}`
		}
		if err := os.WriteFile(filepath.Join(dir, "rulesets", name+".json"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

var imageRulesets = map[string]string{
	"local-ips":     `{"version":3,"rules":[{"ip_cidr":["10.0.0.0/8","192.168.0.0/16"]}]}`,
	"local-domains": `{"version":3,"rules":[{"domain_suffix":["lan"]}]}`,
}

func overlayRulesets(services int) map[string]string {
	hosts := []string{}
	for i := 0; i < services; i++ {
		hosts = append(hosts, fmt.Sprintf("%q", fmt.Sprintf("host%d.example.org", i)))
	}
	return map[string]string{
		"local-ips":         imageRulesets["local-ips"],
		"local-domains":     imageRulesets["local-domains"],
		"vpn-required":      `{"version":3,"rules":[{"domain_suffix":["example.com"]}]}`,
		"direct-essential":  `{"version":3,"source":"synthetic","rules":[{"domain_suffix":["example.net"]}]}`,
		"roscom-direct-ips": `{"version":3,"rules":[{"ip_cidr":["198.51.100.0/24"]}]}`,
		"vpn-services":      `{"version":3,"rules":[{"domain":[` + strings.Join(hosts, ",") + `]}]}`,
	}
}

func routingAdmin(t *testing.T) *Controller {
	t.Helper()
	useLAN(t, "192.168.1.1/24")
	c := connectionAdmin(t)
	image := filepath.Join(t.TempDir(), "image")
	writeRoutingPolicy(t, image, "public-image-default", imageRulesets)
	oldImage, oldStaging := routingImageDir, routingStagingRoot
	routingImageDir, routingStagingRoot = image, filepath.Join(t.TempDir(), "staging")
	t.Cleanup(func() { routingImageDir, routingStagingRoot = oldImage, oldStaging })
	return c
}

// liveRouting makes c behave like a running controller with the VPN up and
// records what reaches the dataplane and the DNS broker.
func liveRouting(t *testing.T, c *Controller) (*[]*policy.Policy, *classifierRecorder, *bool) {
	t.Helper()
	base, _, _, err := policy.LoadInstalledAt(c.overlayDir(), routingImageDir)
	if err != nil {
		t.Fatal(err)
	}
	c.live, c.vpnStarted = true, true
	c.basePolicy, c.policy, c.appliedMode = base, base, c.settings.EffectiveRoutingMode()
	mappings := &classifierRecorder{}
	c.broker = dnsbroker.New(base, dnsbroker.StaticRoute{Channel: contract.AWG}, mappings)
	applied := []*policy.Policy{}
	fail := false
	c.applyStaticSets = func(p *policy.Policy) error {
		if fail {
			return os.ErrPermission
		}
		applied = append(applied, p)
		return nil
	}
	return &applied, mappings, &fail
}

func routingCall(t *testing.T, c *Controller, op string, args map[string]any) (map[string]any, error) {
	t.Helper()
	fields := map[string]any{"operation": op}
	if args != nil {
		fields["routing"] = args
	}
	raw, _ := json.Marshal(fields)
	r, err := control.ParseAPI(raw, false, false)
	if err != nil {
		return nil, err
	}
	out, err := c.HandleAPI(r)
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(out)
	var m map[string]any
	if err = json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m, nil
}

func mustRouting(t *testing.T, c *Controller, op string, args map[string]any) map[string]any {
	t.Helper()
	m, err := routingCall(t, c, op, args)
	if err != nil {
		t.Fatalf("%s: %v", op, err)
	}
	return m
}

func revision(t *testing.T, c *Controller) string {
	t.Helper()
	return mustRouting(t, c, "routing-rules", nil)["revision"].(string)
}

func TestRoutingOperationsReadOnlyClassification(t *testing.T) {
	for _, op := range []string{"routing-policy", "routing-entries", "routing-rules"} {
		raw := `{"request":"{\"operation\":\"` + op + `\",\"routing\":{\"limit\":5}}"}`
		if _, err := control.ParseAPI([]byte(raw), true, true); err != nil {
			t.Fatalf("%s must work read-only: %v", op, err)
		}
	}
	for _, op := range []string{"routing-rule-add", "routing-rule-update", "routing-rule-delete", "routing-apply", "routing-export", "routing-import-begin", "routing-import-chunk", "routing-import-commit", "routing-import-abort", "routing-reset", "routing-restore-backup"} {
		raw := `{"request":"{\"operation\":\"` + op + `\"}"}`
		if _, err := control.ParseAPI([]byte(raw), true, true); err == nil {
			t.Fatalf("read-only method accepted %s", op)
		}
		if _, err := control.ParseAPI([]byte(raw), true, false); err != nil {
			t.Fatalf("write method refused %s: %v", op, err)
		}
	}
	for _, raw := range []string{`{"operation":"routing-policy","id":"x"}`, `{"operation":"routing-policy","routing":[1]}`, `{"operation":"routing-policy","routing":{"a":1,"a":2}}`} {
		if _, err := control.ParseAPI([]byte(raw), false, false); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	c := routingAdmin(t)
	if _, err := routingCall(t, c, "routing-rules", map[string]any{"unknown": true}); err == nil {
		t.Fatal("unknown routing argument accepted")
	}
}

func TestRoutingOverviewEntriesAndOverlayFallback(t *testing.T) {
	c := routingAdmin(t)
	ov := mustRouting(t, c, "routing-policy", nil)
	if ov["source"] != "image" || ov["overlay_present"] != false || ov["mode"] != "split" || len(ov["rulesets"].([]any)) != len(policy.RulesetNames()) {
		t.Fatalf("image overview: %v", ov)
	}
	writeRoutingPolicy(t, c.overlayDir(), "synthetic-overlay", overlayRulesets(2500))
	ov = mustRouting(t, c, "routing-policy", nil)
	if ov["source"] != "overlay" || ov["policy"].(map[string]any)["status"] != "synthetic-overlay" || ov["overlay_error"] != "" {
		t.Fatalf("overlay overview: %v", ov)
	}
	byName := map[string]map[string]any{}
	for _, item := range ov["rulesets"].([]any) {
		rs := item.(map[string]any)
		byName[rs["name"].(string)] = rs
	}
	if rs := byName["vpn-services"]; rs["total"] != float64(2500) || rs["class"] != "general" || rs["counts"].(map[string]any)["domain"] != float64(2500) {
		t.Fatalf("counts: %v", rs)
	}
	if rs := byName["direct-essential"]; rs["class"] != "direct" || rs["meta"].(map[string]any)["source"] != "synthetic" || rs["active"] != true {
		t.Fatalf("direct-essential: %v", rs)
	}
	if _, err := c.HandleAPI(control.APIRequest{Operation: "settings", Settings: json.RawMessage(`{"routing_mode":"full"}`)}); err != nil {
		t.Fatal(err)
	}
	for _, item := range mustRouting(t, c, "routing-policy", nil)["rulesets"].([]any) {
		rs := item.(map[string]any)
		if want := rs["name"] != "direct-essential" && !strings.HasPrefix(rs["name"].(string), "roscom-"); rs["active"] != want {
			t.Fatalf("full mode activity: %v", rs)
		}
	}
	if _, err := c.HandleAPI(control.APIRequest{Operation: "settings", Settings: json.RawMessage(`{"routing_mode":"split"}`)}); err != nil {
		t.Fatal(err)
	}
	page := mustRouting(t, c, "routing-entries", map[string]any{"ruleset": "vpn-services", "offset": 2400, "limit": 200})
	if page["total"] != float64(2500) || page["matched"] != float64(2500) || len(page["entries"].([]any)) != 100 {
		t.Fatalf("paging: %v %v", page["total"], len(page["entries"].([]any)))
	}
	page = mustRouting(t, c, "routing-entries", map[string]any{"ruleset": "vpn-services", "query": "HOST12"})
	if page["matched"] != float64(111) || page["entries"].([]any)[0].(map[string]any)["value"] != "host12.example.org" {
		t.Fatalf("search: %v", page["matched"])
	}
	for _, args := range []map[string]any{{"ruleset": "../policy"}, {"ruleset": "vpn-services", "limit": 201}, {"ruleset": "vpn-services", "offset": -1}} {
		if _, err := routingCall(t, c, "routing-entries", args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	// A refused overlay falls back to the image policy and says why.
	if err := os.WriteFile(filepath.Join(c.overlayDir(), "rulesets", "vpn-required.json"), []byte(`{"version":2,"rules":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	ov = mustRouting(t, c, "routing-policy", nil)
	if ov["source"] != "image" || ov["overlay_present"] != true || ov["overlay_error"] == "" {
		t.Fatalf("broken overlay: %v", ov)
	}
}

func TestCustomRuleEditsApplyLiveWithoutRestart(t *testing.T) {
	c := routingAdmin(t)
	applied, mappings, fail := liveRouting(t, c)
	rev0 := revision(t, c)
	add := func(rev string, rule map[string]any) (map[string]any, error) {
		return routingCall(t, c, "routing-rule-add", map[string]any{"revision": rev, "rule": rule})
	}
	res, err := add(rev0, map[string]any{"value": "Example.COM", "mode": "vpn", "comment": "synthetic", "enabled": true})
	if err != nil {
		t.Fatal(err)
	}
	if res["apply"].(map[string]any)["applied"] != true || len(*applied) != 1 || len(mappings.set) != 1 {
		t.Fatalf("not applied live: %v", res)
	}
	rule := res["rule"].(map[string]any)
	if rule["type"] != "domain" || rule["value"] != "example.com" || rule["id"] == "" {
		t.Fatalf("rule not normalized: %v", rule)
	}
	if class, source := c.policy.DomainDecision("www.example.com"); class != contract.General || source != "vpn-required" {
		t.Fatalf("custom vpn not in force: %s %s", class, source)
	}
	if _, err = add(rev0, map[string]any{"value": "203.0.113.0/24", "mode": "direct", "enabled": true}); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("stale revision accepted: %v", err)
	}
	rev1 := res["revision"].(string)
	for _, bad := range []map[string]any{
		{"value": "192.168.1.0/25", "mode": "vpn", "enabled": true}, {"value": "0.0.0.0/0", "mode": "direct", "enabled": true},
		{"value": "2001:db8::/48", "mode": "vpn", "enabled": true}, {"value": "example.com", "mode": "direct", "enabled": true},
		{"value": "exa mple.org", "mode": "vpn", "enabled": true},
	} {
		if _, err = add(rev1, bad); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
	res, err = add(rev1, map[string]any{"value": "203.0.113.0/24", "mode": "direct", "enabled": true})
	if err != nil {
		t.Fatal(err)
	}
	direct := res["rule"].(map[string]any)
	last := (*applied)[len(*applied)-1]
	if got := last.CIDRs(policy.CustomDirectSource); len(got) != 1 || got[0].String() != "203.0.113.0/24" || c.policy.ClassifyIP(netip.MustParseAddr("203.0.113.9")) != contract.Direct {
		t.Fatalf("custom direct set: %v", got)
	}
	// A local destination is accepted but reported as shadowed.
	res = mustRouting(t, c, "routing-rule-add", map[string]any{"revision": res["revision"], "rule": map[string]any{"value": "10.20.0.0/16", "mode": "direct", "enabled": true}})
	listed := mustRouting(t, c, "routing-rules", map[string]any{"query": "10.20"})
	if listed["matched"] != float64(1) || listed["rules"].([]any)[0].(map[string]any)["local"] != true {
		t.Fatalf("local shadow not reported: %v", listed)
	}
	// A failed kernel update keeps the previous view and retries.
	*fail = true
	res = mustRouting(t, c, "routing-rule-update", map[string]any{"revision": res["revision"], "id": direct["id"], "rule": map[string]any{"value": "203.0.113.0/24", "mode": "direct", "enabled": false}})
	if res["apply"].(map[string]any)["applied"] != false || c.Status().LastError == "" || c.policy.ClassifyIP(netip.MustParseAddr("203.0.113.9")) != contract.Direct {
		t.Fatalf("failed apply: %v", res)
	}
	*fail = false
	c.reconcileRoutingMode()
	if c.appliedMode != policy.ModeSplit || c.policy.ClassifyIP(netip.MustParseAddr("203.0.113.9")) != contract.General {
		t.Fatal("retry did not converge")
	}
	res = mustRouting(t, c, "routing-rule-delete", map[string]any{"revision": res["revision"], "id": direct["id"]})
	if res["total"] != float64(2) {
		t.Fatalf("delete: %v", res)
	}
	if _, err = routingCall(t, c, "routing-rule-delete", map[string]any{"revision": res["revision"], "id": direct["id"]}); err == nil {
		t.Fatal("deleted twice")
	}
	info, err := os.Lstat(c.customRulesPath())
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("custom rules file: %v", err)
	}
	// The full mode drops custom direct rules and keeps custom vpn rules.
	if _, err = c.HandleAPI(control.APIRequest{Operation: "settings", Settings: json.RawMessage(`{"routing_mode":"full"}`)}); err != nil {
		t.Fatal(err)
	}
	c.reconcileRoutingMode()
	if class, _ := c.policy.DomainDecision("www.example.com"); class != contract.General || c.policy.ClassifyIP(netip.MustParseAddr("10.20.1.1")) != contract.Local {
		t.Fatal("full mode view wrong")
	}
	// The startup path reads the same file.
	restarted := New(c.settings)
	base, _, _, _ := policy.LoadInstalledAt(c.overlayDir(), routingImageDir)
	if class, source := restarted.withCustomRules(base, c.stateDir).DomainDecision("www.example.com"); class != contract.General || source != "vpn-required" {
		t.Fatal("startup ignores custom rules")
	}
	if err = os.WriteFile(c.customRulesPath(), []byte(`{"format":"flr-custom-routing-rules","version":1,"rules":[{"id":"x","type":"cidr","value":"0.0.0.0/0","mode":"direct","enabled":true}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if p := restarted.withCustomRules(base, c.stateDir); p.ClassifyIP(netip.MustParseAddr("203.0.113.9")) != contract.General || restarted.Status().LastError == "" {
		t.Fatal("invalid custom rules must be ignored and reported")
	}
	if _, err = routingCall(t, c, "routing-rule-add", map[string]any{"revision": rev0, "rule": map[string]any{"value": "example.org", "mode": "vpn", "enabled": true}}); err == nil {
		t.Fatal("edit accepted over an invalid rules file")
	}
}

func TestRoutingWritesOfflineWaitForStart(t *testing.T) {
	c := routingAdmin(t)
	// Discovery fails from the first request on (the LAN cache is empty).
	failLAN(t)
	res := mustRouting(t, c, "routing-rule-add", map[string]any{"revision": revision(t, c), "rule": map[string]any{"value": "example.org", "mode": "direct", "enabled": true}})
	apply := res["apply"].(map[string]any)
	if apply["applied"] != false || !strings.Contains(apply["pending"].(string), "next start") || c.basePolicy != nil {
		t.Fatalf("offline apply: %v", apply)
	}
	if _, err := routingCall(t, c, "routing-rule-add", map[string]any{"revision": res["revision"], "rule": map[string]any{"value": "203.0.113.0/24", "mode": "vpn", "enabled": true}}); err == nil || !strings.Contains(err.Error(), "LAN unknown") {
		t.Fatalf("vpn address rule without a known LAN: %v", err)
	}
	mustRouting(t, c, "routing-rule-add", map[string]any{"revision": res["revision"], "rule": map[string]any{"value": "203.0.113.0/24", "mode": "direct", "enabled": true}})
}

func exportAll(t *testing.T, c *Controller) ([]byte, string) {
	t.Helper()
	first := mustRouting(t, c, "routing-export", nil)
	sum := first["sha256"].(string)
	var out []byte
	page := first
	for i := 0; ; i++ {
		chunk, err := base64.StdEncoding.DecodeString(page["data"].(string))
		if err != nil || len(chunk) > routingChunkBytes {
			t.Fatal("bad export chunk")
		}
		out = append(out, chunk...)
		if page["more"] != true {
			break
		}
		if i > 100 {
			t.Fatal("export does not end")
		}
		page = mustRouting(t, c, "routing-export", map[string]any{"offset": page["next"], "sha256": sum})
	}
	got := sha256.Sum256(out)
	if hex.EncodeToString(got[:]) != sum || float64(len(out)) != first["size"] {
		t.Fatal("export reassembly mismatch")
	}
	return out, sum
}

func routingImport(t *testing.T, c *Controller, data []byte, sum string, chunk int) (map[string]any, error) {
	t.Helper()
	if sum == "" {
		digest := sha256.Sum256(data)
		sum = hex.EncodeToString(digest[:])
	}
	begin, err := routingCall(t, c, "routing-import-begin", map[string]any{"size": len(data), "sha256": sum})
	if err != nil {
		return nil, err
	}
	id := begin["staging_id"].(string)
	for off := 0; off < len(data); off += chunk {
		end := min(off+chunk, len(data))
		if _, err = routingCall(t, c, "routing-import-chunk", map[string]any{"staging_id": id, "offset": off, "data": base64.StdEncoding.EncodeToString(data[off:end])}); err != nil {
			return nil, err
		}
	}
	return routingCall(t, c, "routing-import-commit", map[string]any{"staging_id": id})
}

func TestRoutingExportImportResetRestore(t *testing.T) {
	c := routingAdmin(t)
	writeRoutingPolicy(t, c.overlayDir(), "synthetic-overlay", overlayRulesets(2500))
	mustRouting(t, c, "routing-rule-add", map[string]any{"revision": revision(t, c), "rule": map[string]any{"value": "example.org", "mode": "vpn", "enabled": true}})
	if _, err := routingCall(t, c, "routing-export", map[string]any{"offset": 10}); err == nil {
		t.Fatal("later export chunk without checksum accepted")
	}
	data, sum := exportAll(t, c)
	if len(data) <= 2*routingChunkBytes {
		t.Fatalf("fixture too small for chunking: %d", len(data))
	}
	var bundle routingBundle
	if err := json.Unmarshal(data, &bundle); err != nil || bundle.Format != routingBundleFormat || bundle.Source != "overlay" || len(bundle.Rulesets) != 8 || bundle.CustomRules == nil || len(bundle.CustomRules.Rules) != 1 {
		t.Fatalf("bundle: %v %+v", err, bundle.Source)
	}
	// Any change between chunks restarts the export.
	mustRouting(t, c, "routing-rule-add", map[string]any{"revision": revision(t, c), "rule": map[string]any{"value": "example.edu", "mode": "direct", "enabled": true}})
	if _, err := routingCall(t, c, "routing-export", map[string]any{"offset": routingChunkBytes, "sha256": sum}); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("stale export continued: %v", err)
	}
	applied, _, _ := liveRouting(t, c)
	// Re-import the earlier bundle with a changed status: the overlay is
	// replaced, the previous one kept as the backup, the rules replaced.
	var raw map[string]json.RawMessage
	json.Unmarshal(data, &raw)
	raw["policy"] = json.RawMessage(`{"format":"flint2-home-vpn-routing-policy","version":3,"status":"imported","default_class":"vpn-general"}`)
	changed, _ := json.Marshal(raw)
	res, err := routingImport(t, c, changed, "", 20000)
	if err != nil {
		t.Fatal(err)
	}
	if res["imported"].(map[string]any)["policy"] != true || res["imported"].(map[string]any)["custom_rules"] != float64(1) || res["apply"].(map[string]any)["applied"] != true || len(*applied) != 1 {
		t.Fatalf("import: %v", res)
	}
	ov := mustRouting(t, c, "routing-policy", nil)
	if ov["policy"].(map[string]any)["status"] != "imported" || ov["backup_present"] != true || ov["custom_rules"].(map[string]any)["summary"].(map[string]any)["total"] != float64(1) {
		t.Fatalf("after import: %v", ov)
	}
	if entries, _ := os.ReadDir(routingStagingRoot); len(entries) != 0 {
		t.Fatal("staging not cleaned")
	}
	backup, err := os.ReadFile(filepath.Join(c.overlayBackupDir(), "policy.json"))
	if err != nil || !strings.Contains(string(backup), "synthetic-overlay") {
		t.Fatal("previous overlay not kept")
	}
	// Refused imports change nothing.
	before, _ := os.ReadFile(filepath.Join(c.overlayDir(), "policy.json"))
	beforeRules, _ := os.ReadFile(c.customRulesPath())
	missing := map[string]json.RawMessage{}
	json.Unmarshal(changed, &missing)
	var rulesets map[string]json.RawMessage
	json.Unmarshal(missing["rulesets"], &rulesets)
	delete(rulesets, "game-platforms")
	missing["rulesets"], _ = json.Marshal(rulesets)
	missingRaw, _ := json.Marshal(missing)
	badVersion := strings.Replace(string(changed), `"version":3,"status":"imported"`, `"version":4,"status":"imported"`, 1)
	lanRule := `{"format":"flr-custom-routing-rules","version":1,"rules":[{"id":"a","type":"cidr","value":"192.168.1.0/24","mode":"vpn","enabled":true}]}`
	for name, body := range map[string][]byte{"missing ruleset": missingRaw, "bad policy version": []byte(badVersion), "LAN vpn rule": []byte(lanRule), "not JSON": []byte("{"), "unknown format": []byte(`{"format":"other"}`), "unknown field": []byte(`{"format":"flr-routing-bundle","version":1,"extra":1}`)} {
		if _, err = routingImport(t, c, body, "", 20000); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, err = routingImport(t, c, changed, strings.Repeat("0", 64), 20000); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("checksum: %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(c.overlayDir(), "policy.json"))
	afterRules, _ := os.ReadFile(c.customRulesPath())
	if string(before) != string(after) || string(beforeRules) != string(afterRules) {
		t.Fatal("refused import changed the configuration")
	}
	// Chunks must arrive in order and within the announced size.
	digest := sha256.Sum256(changed)
	begin := mustRouting(t, c, "routing-import-begin", map[string]any{"size": len(changed), "sha256": hex.EncodeToString(digest[:])})
	id := begin["staging_id"]
	if _, err = routingCall(t, c, "routing-import-chunk", map[string]any{"staging_id": id, "offset": 5, "data": base64.StdEncoding.EncodeToString(changed[5:10])}); err == nil {
		t.Fatal("out-of-order chunk accepted")
	}
	if _, err = routingCall(t, c, "routing-import-chunk", map[string]any{"staging_id": id, "offset": 0, "data": base64.StdEncoding.EncodeToString(make([]byte, routingChunkBytes+1))}); err == nil {
		t.Fatal("oversized chunk accepted")
	}
	if _, err = routingCall(t, c, "routing-import-commit", map[string]any{"staging_id": id}); err == nil {
		t.Fatal("incomplete import committed")
	}
	if _, err = routingCall(t, c, "routing-import-chunk", map[string]any{"staging_id": id, "offset": 0, "data": "AAAA"}); err == nil {
		t.Fatal("commit must end the staged import")
	}
	// A bare custom rules file replaces only the rules.
	res, err = routingImport(t, c, []byte(`{"format":"flr-custom-routing-rules","version":1,"rules":[{"id":"","type":"","value":"example.info","mode":"direct","enabled":true},{"id":"","type":"","value":"203.0.113.7","mode":"vpn","enabled":true}]}`), "", 1000)
	if err != nil || res["imported"].(map[string]any)["policy"] != false || res["imported"].(map[string]any)["custom_rules"] != float64(2) {
		t.Fatalf("rules import: %v %v", res, err)
	}
	if c.policy.ClassifyIP(netip.MustParseAddr("203.0.113.7")) != contract.General || c.policy.ClassifyDomain("a.example.info") != contract.Direct {
		t.Fatal("imported rules not live")
	}
	// Reset to the image default keeps the overlay as the backup; restore
	// swaps it back.
	if _, err = routingCall(t, c, "routing-reset", nil); err == nil {
		t.Fatal("reset without confirmation")
	}
	mustRouting(t, c, "routing-reset", map[string]any{"accepted": true})
	ov = mustRouting(t, c, "routing-policy", nil)
	if ov["source"] != "image" || ov["overlay_present"] != false || ov["backup_present"] != true || c.policy.ClassifyDomain("www.example.com") != contract.General {
		t.Fatalf("reset: %v", ov)
	}
	if _, err = routingCall(t, c, "routing-reset", map[string]any{"accepted": true}); err == nil {
		t.Fatal("reset without an overlay")
	}
	mustRouting(t, c, "routing-restore-backup", map[string]any{"accepted": true})
	ov = mustRouting(t, c, "routing-policy", nil)
	if ov["source"] != "overlay" || ov["policy"].(map[string]any)["status"] != "imported" || ov["backup_present"] != false {
		t.Fatalf("restore: %v", ov)
	}
	if c.policy.ClassifyDomain("www.example.net") != contract.Direct {
		t.Fatal("restored overlay not live")
	}
	var noBackup *os.PathError
	if _, err = os.Stat(c.overlayBackupDir()); !errors.As(err, &noBackup) {
		t.Fatal("restore without a previous overlay must leave no backup")
	}
}
