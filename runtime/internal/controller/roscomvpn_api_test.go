package controller

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/control"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
)

// Synthetic RoscomVPN profile and data files: example names and
// documentation addresses only.

func pb(num int, data []byte) []byte {
	var b []byte
	put := func(v uint64) {
		for v >= 0x80 {
			b = append(b, byte(v)|0x80)
			v >>= 7
		}
		b = append(b, byte(v))
	}
	put(uint64(num)<<3 | 2)
	put(uint64(len(data)))
	return append(b, data...)
}

func pbInt(num int, v byte) []byte { return []byte{byte(num << 3), v} }

func synthSites() []byte {
	suffix := func(v string) []byte { return pb(2, append(pbInt(1, 2), pb(2, []byte(v))...)) }
	cat := func(code string, values ...string) []byte {
		b := pb(1, []byte(code))
		for _, v := range values {
			b = append(b, suffix(v)...)
		}
		return pb(1, b)
	}
	return append(append(cat("PRIVATE", "lan"), cat("RU", "ru.example")...), cat("VIDEO", "video.example")...)
}

func synthIPs() []byte {
	cidr := func(a, b, c, d, bits byte) []byte { return pb(2, append(pb(1, []byte{a, b, c, d}), pbInt(2, bits)...)) }
	cat := func(code string, cidrs ...[]byte) []byte {
		b := pb(1, []byte(code))
		for _, c := range cidrs {
			b = append(b, c...)
		}
		return pb(1, b)
	}
	return append(cat("PRIVATE", cidr(192, 168, 0, 0, 16)), cat("DIRECT", cidr(198, 51, 100, 0, 24))...)
}

const synthProfile = `{"Name":"Synthetic RoscomVPN","GlobalProxy":"true","Geositeurl":"https://cdn.example.com/geosite.dat","Geoipurl":"https://cdn.example.com/geoip.dat","LastUpdated":"1795001644","DnsHosts":{"a.example.net":"192.0.2.1"},"RouteOrder":"block-proxy-direct","DirectSites":["geosite:private","geosite:ru","domain:bank.example"],"DirectIp":["geoip:private","geoip:direct","2001:db8::/32"],"ProxySites":["geosite:video"],"ProxyIp":["203.0.113.0/24"],"BlockSites":["domain:ads.example"],"BlockIp":[],"DomainStrategy":"IPIfNonMatch","FakeDNS":"false"}`

type fakeFetch struct {
	mu     sync.Mutex
	files  map[string][]byte
	calls  []string
	routes []string
	limits map[string]int64
	gate   chan struct{}
	inside chan struct{}
}

func newFakeFetch() *fakeFetch {
	return &fakeFetch{files: map[string][]byte{
		"https://profiles.example.com/DEFAULT.JSON": []byte(synthProfile),
		"https://cdn.example.com/geosite.dat":       synthSites(),
		"https://cdn.example.com/geoip.dat":         synthIPs(),
	}, limits: map[string]int64{}}
}

func (f *fakeFetch) fetch(ctx context.Context, route downloadRoute, rawURL string, limit int64) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, rawURL)
	f.routes = append(f.routes, route.Path)
	f.limits[rawURL] = limit
	gate, inside := f.gate, f.inside
	data, ok := f.files[rawURL]
	f.mu.Unlock()
	if gate != nil {
		inside <- struct{}{}
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if !ok {
		return nil, fmt.Errorf("HTTP status 404")
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("larger than %d bytes", limit)
	}
	return data, nil
}

func roscomAdmin(t *testing.T) (*Controller, *fakeFetch) {
	t.Helper()
	c := routingAdmin(t)
	f := newFakeFetch()
	c.routingFetch = f.fetch
	return c, f
}

func overlayStatus(t *testing.T, dir string) string {
	t.Helper()
	info, err := policy.Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := info.Meta["status"].(string)
	return s
}

func TestRoscomVPNDryRunChangesNothing(t *testing.T) {
	c, f := roscomAdmin(t)
	writeRoutingPolicy(t, c.overlayDir(), "synthetic-overlay", overlayRulesets(2))
	before := c.routingFingerprint()
	res := mustRouting(t, c, "routing-roscomvpn-import", map[string]any{"url": "https://profiles.example.com/DEFAULT.JSON", "dry_run": true})
	if res["installed"] != false || res["dry_run"] != true || res["pending"] != false || res["download_path"] != "wan" || res["apply"] != nil {
		t.Fatalf("dry run: %v", res)
	}
	if strings.Join(f.calls, " ") != "https://profiles.example.com/DEFAULT.JSON https://cdn.example.com/geosite.dat https://cdn.example.com/geoip.dat" {
		t.Fatalf("downloads %v", f.calls)
	}
	if f.limits["https://cdn.example.com/geoip.dat"] != roscomDataLimit || f.limits["https://profiles.example.com/DEFAULT.JSON"] != 1<<20 {
		t.Fatalf("limits %v", f.limits)
	}
	report := res["report"].(map[string]any)
	rulesets := report["rulesets"].(map[string]any)
	if rulesets["roscom-direct-ips"].(map[string]any)["total"] != float64(1) || rulesets["vpn-services"].(map[string]any)["total"] != float64(1) || rulesets["vpn-required"].(map[string]any)["total"] != float64(1) {
		t.Fatalf("report rulesets %v", rulesets)
	}
	if len(report["not_applied"].([]any)) < 3 || len(report["skipped"].([]any)) != 1 {
		t.Fatalf("report issues %v / %v", report["not_applied"], report["skipped"])
	}
	if c.routingFingerprint() != before || overlayStatus(t, c.overlayDir()) != "synthetic-overlay" || exists(c.overlayBackupDir()) {
		t.Fatal("a dry run changed the installed policy")
	}
	if _, err := routingCall(t, c, "routing-roscomvpn-import", map[string]any{"url": "https://profiles.example.com/DEFAULT.JSON"}); err == nil || !strings.Contains(err.Error(), "confirmation") {
		t.Fatalf("install without confirmation: %v", err)
	}
	if c.routingFingerprint() != before {
		t.Fatal("refused import changed files")
	}
}

func TestRoscomVPNImportInstallsLiveKeepsBackupAndCustomRules(t *testing.T) {
	c, f := roscomAdmin(t)
	writeRoutingPolicy(t, c.overlayDir(), "synthetic-overlay", overlayRulesets(2))
	applied, _, _ := liveRouting(t, c)
	c.selection.General = contract.AWG
	if _, err := routingCall(t, c, "routing-rule-add", map[string]any{"revision": revision(t, c), "rule": map[string]any{"value": "custom.example.org", "mode": "direct", "enabled": true}}); err != nil {
		t.Fatal(err)
	}
	rules, _ := c.readCustomRules()
	res := mustRouting(t, c, "routing-roscomvpn-import", map[string]any{"url": "https://profiles.example.com/DEFAULT.JSON", "accepted": true})
	if res["installed"] != true || res["download_path"] != "vpn-awg" || res["backup_present"] != true || res["apply"].(map[string]any)["applied"] != true {
		t.Fatalf("import: %v", res)
	}
	for _, route := range f.routes {
		if route != "vpn-awg" {
			t.Fatalf("download left the VPN: %v", f.routes)
		}
	}
	if overlayStatus(t, c.overlayDir()) != "imported-roscomvpn" || overlayStatus(t, c.overlayBackupDir()) != "synthetic-overlay" {
		t.Fatal("overlay or backup wrong")
	}
	after, _ := c.readCustomRules()
	if after.Revision() != rules.Revision() {
		t.Fatal("custom rules changed")
	}
	if len(*applied) < 2 {
		t.Fatal("not applied live")
	}
	for name, want := range map[string]contract.Class{"www.ru.example": contract.Direct, "video.example": contract.General, "printer.lan": contract.Local, "custom.example.org": contract.Direct, "unlisted.example.org": contract.General} {
		if got, _ := c.policy.DomainDecision(name); got != want {
			t.Errorf("%s: %s, want %s", name, got, want)
		}
	}
	// The overview shows the imported overlay like any other.
	ov := mustRouting(t, c, "routing-policy", nil)
	if ov["source"] != "overlay" || ov["policy"].(map[string]any)["status"] != "imported-roscomvpn" || ov["backup_present"] != true {
		t.Fatalf("overview %v", ov)
	}
	// The previous overlay comes back with Restore backup.
	mustRouting(t, c, "routing-restore-backup", map[string]any{"accepted": true})
	if overlayStatus(t, c.overlayDir()) != "synthetic-overlay" {
		t.Fatal("restore did not bring the previous overlay back")
	}
}

func TestRoscomVPNStagedDeepLinkAndRefusals(t *testing.T) {
	c, f := roscomAdmin(t)
	link := []byte("happ://routing/onadd/" + base64.StdEncoding.EncodeToString([]byte(synthProfile)))
	sum := sha256.Sum256(link)
	begin := mustRouting(t, c, "routing-import-begin", map[string]any{"size": len(link), "sha256": hex.EncodeToString(sum[:])})
	id := begin["staging_id"].(string)
	mustRouting(t, c, "routing-import-chunk", map[string]any{"staging_id": id, "offset": 0, "data": base64.StdEncoding.EncodeToString(link)})
	res := mustRouting(t, c, "routing-roscomvpn-import", map[string]any{"staging_id": id, "accepted": true})
	if res["installed"] != true || res["source"] != "uploaded file" || res["backup_present"] != false {
		t.Fatalf("staged import: %v", res)
	}
	if f.calls[0] != "https://cdn.example.com/geosite.dat" {
		t.Fatalf("an uploaded profile is not downloaded: %v", f.calls)
	}
	if meta, _ := filepath.Glob(filepath.Join(routingStagingRoot, id+"*")); len(meta) != 0 {
		t.Fatalf("staging kept: %v", meta)
	}
	for _, args := range []map[string]any{
		{"url": "http://profiles.example.com/DEFAULT.JSON", "dry_run": true},
		{"url": "https://user:secret@profiles.example.com/x", "dry_run": true},
		{"url": "https://profiles.example.com:8443/x", "dry_run": true},
		{"url": "https://profiles.example.com/x", "staging_id": "0123456789abcdef", "dry_run": true},
		{"dry_run": true},
		{"url": "https://profiles.example.com/x", "dry_run": true, "query": "x"},
	} {
		if _, err := routingCall(t, c, "routing-roscomvpn-import", args); err == nil {
			t.Errorf("accepted %v", args)
		}
	}
	if _, err := routingCall(t, c, "routing-apply", map[string]any{"dry_run": true}); err == nil {
		t.Error("dry_run accepted by another operation")
	}
	// A failed download changes nothing and is reported.
	before := c.routingFingerprint()
	delete(f.files, "https://cdn.example.com/geoip.dat")
	if _, err := routingCall(t, c, "routing-roscomvpn-import", map[string]any{"url": "https://profiles.example.com/DEFAULT.JSON", "accepted": true}); err == nil || !strings.Contains(err.Error(), "geoip download failed (wan)") {
		t.Fatalf("failed download: %v", err)
	}
	if c.routingFingerprint() != before {
		t.Fatal("a failed import changed files")
	}
	st := mustRouting(t, c, "routing-roscomvpn-status", nil)["job"].(map[string]any)
	if st["phase"] != "failed" || !strings.Contains(st["error"].(string), "geoip") {
		t.Fatalf("status %v", st)
	}
	// A running VPN without a channel refuses rather than using the WAN.
	liveRouting(t, c)
	if _, err := routingCall(t, c, "routing-roscomvpn-import", map[string]any{"url": "https://profiles.example.com/DEFAULT.JSON", "dry_run": true}); err == nil || !strings.Contains(err.Error(), "no channel") {
		t.Fatalf("no channel: %v", err)
	}
}

func TestRoscomVPNOperationsPermissions(t *testing.T) {
	status := `{"request":"{\"operation\":\"routing-roscomvpn-status\"}"}`
	if _, err := control.ParseAPI([]byte(status), true, true); err != nil {
		t.Fatalf("status must be a read: %v", err)
	}
	imp := `{"request":"{\"operation\":\"routing-roscomvpn-import\",\"routing\":{\"dry_run\":true,\"url\":\"https://profiles.example.com/x\"}}"}`
	if _, err := control.ParseAPI([]byte(imp), true, true); err == nil {
		t.Fatal("read-only method accepted the import (even a dry run downloads)")
	}
	if _, err := control.ParseAPI([]byte(imp), true, false); err != nil {
		t.Fatalf("write method refused the import: %v", err)
	}
	c, _ := roscomAdmin(t)
	if job := mustRouting(t, c, "routing-roscomvpn-status", nil)["job"]; job != nil {
		t.Fatalf("no job yet: %v", job)
	}
}

// With the controller running the import is a job: downloads hold no
// adminMu, so rounds and other API calls go on meanwhile.
func TestRoscomVPNJobDoesNotHoldAdminLockWhileDownloading(t *testing.T) {
	c, f := roscomAdmin(t)
	liveRouting(t, c)
	c.selection.General = contract.Gecko
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.ctx = ctx
	f.gate, f.inside = make(chan struct{}), make(chan struct{}, 4)
	res := mustRouting(t, c, "routing-roscomvpn-import", map[string]any{"url": "https://profiles.example.com/DEFAULT.JSON", "accepted": true})
	if res["pending"] != true || res["download_path"] != "vpn-gecko" {
		t.Fatalf("job start %v", res)
	}
	<-f.inside
	done := make(chan struct{})
	go func() {
		c.adminMu.Lock()
		c.adminMu.Unlock()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("adminMu held during the download")
	}
	if _, err := routingCall(t, c, "routing-roscomvpn-import", map[string]any{"url": "https://profiles.example.com/DEFAULT.JSON", "dry_run": true}); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("second job: %v", err)
	}
	if st := mustRouting(t, c, "routing-roscomvpn-status", nil)["job"].(map[string]any); st["pending"] != true || !strings.HasPrefix(st["phase"].(string), "downloading") {
		t.Fatalf("status while downloading %v", st)
	}
	close(f.gate)
	c.testWorkers.Wait()
	st := mustRouting(t, c, "routing-roscomvpn-status", nil)["job"].(map[string]any)
	if st["pending"] != false || st["phase"] != "done" || st["result"].(map[string]any)["installed"] != true {
		t.Fatalf("job result %v", st)
	}
	if overlayStatus(t, c.overlayDir()) != "imported-roscomvpn" {
		t.Fatal("job did not install")
	}
}

// The import runs only when the owner starts it: no start, upgrade or
// migration path of the runtime calls it.
func TestRoscomVPNImportOnlyFromTheAPI(t *testing.T) {
	root := filepath.Join("..", "..")
	allowed := map[string]bool{
		filepath.Join("internal", "controller", "roscomvpn_api.go"): true,
		filepath.Join("internal", "controller", "policy_api.go"):    true,
	}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if strings.HasPrefix(rel, filepath.Join("internal", "geodata")) {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(raw)
		for _, needle := range []string{"roscomImport(", "runRoscom(", "geodata.Convert(", "installRoutingPolicy("} {
			if strings.Contains(text, needle) && !allowed[rel] {
				t.Errorf("%s calls %s; the RoscomVPN import must only run from routing-roscomvpn-import", rel, needle)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("policy_api.go")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(raw), "roscomImport("); n != 1 {
		t.Fatalf("policy_api.go must call roscomImport once (the API dispatch), found %d", n)
	}
}
