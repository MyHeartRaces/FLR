package controller

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/control"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
	mdns "github.com/miekg/dns"
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

// Through a proxy channel the name is resolved through the tunnel (DNS over
// TCP via the channel's SOCKS listener), checked as public IPv4, and only
// the numeric address goes to SOCKS: the VPN server cannot be made to
// reach its own loopback or private networks.
func TestRoscomVPNSocksDownloadsResolveThroughTheTunnel(t *testing.T) {
	answers := map[string]string{"private.example.": "127.0.0.1", "lan.example.": "192.168.1.1", "public.example.": "8.8.4.4"}
	var mu sync.Mutex
	var targets []string
	oldDial, oldProxies := socksDial, socksProxies
	t.Cleanup(func() { socksDial, socksProxies = oldDial, oldProxies })
	socksProxies = map[string]string{"vpn-gecko": "proxy-gecko", "vpn-vless": "proxy-vless"}
	socksDial = func(ctx context.Context, proxy, target string) (net.Conn, error) {
		mu.Lock()
		targets = append(targets, proxy+" "+target)
		mu.Unlock()
		if target != tunnelDNS {
			return nil, fmt.Errorf("connect %s", target)
		}
		client, server := net.Pipe()
		go serveTCPDNS(server, answers)
		return client, nil
	}
	for _, path := range []string{"vpn-gecko", "vpn-vless"} {
		dial, err := routeDialer(downloadRoute{Path: path})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		for _, host := range []string{"private.example", "lan.example", "127.0.0.1", "10.0.0.1"} {
			mu.Lock()
			targets = nil
			mu.Unlock()
			if _, err := dial(ctx, host, "443"); err == nil || !strings.Contains(err.Error(), "not a public IPv4") {
				t.Errorf("%s %s: %v", path, host, err)
			}
			mu.Lock()
			for _, target := range targets {
				if !strings.HasSuffix(target, " "+tunnelDNS) {
					t.Errorf("%s %s reached SOCKS target %s", path, host, target)
				}
			}
			mu.Unlock()
		}
		mu.Lock()
		targets = nil
		mu.Unlock()
		if _, err := dial(ctx, "public.example", "443"); err == nil || !strings.Contains(err.Error(), "connect 8.8.4.4:443") {
			t.Errorf("%s public: %v", path, err)
		}
		mu.Lock()
		want := socksProxies[path] + " 8.8.4.4:443"
		if len(targets) == 0 || targets[len(targets)-1] != want {
			t.Errorf("%s connected %v, want the numeric address %s", path, targets, want)
		}
		for _, target := range targets {
			if strings.Contains(target, "public.example") {
				t.Errorf("a hostname went to SOCKS: %s", target)
			}
		}
		mu.Unlock()
		cancel()
	}
}

// serveTCPDNS answers A queries on one DNS-over-TCP stream.
func serveTCPDNS(conn net.Conn, answers map[string]string) {
	defer conn.Close()
	for {
		var head [2]byte
		if _, err := io.ReadFull(conn, head[:]); err != nil {
			return
		}
		msg := make([]byte, int(head[0])<<8|int(head[1]))
		if _, err := io.ReadFull(conn, msg); err != nil {
			return
		}
		q := new(mdns.Msg)
		if q.Unpack(msg) != nil || len(q.Question) != 1 {
			return
		}
		r := new(mdns.Msg)
		r.SetReply(q)
		name := strings.ToLower(q.Question[0].Name)
		if ip, ok := answers[name]; ok && q.Question[0].Qtype == mdns.TypeA {
			r.Answer = append(r.Answer, &mdns.A{Hdr: mdns.RR_Header{Name: q.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60}, A: net.ParseIP(ip).To4()})
		} else if !ok {
			r.Rcode = mdns.RcodeNameError
		}
		out, err := r.Pack()
		if err != nil {
			return
		}
		if _, err := conn.Write(append([]byte{byte(len(out) >> 8), byte(len(out))}, out...)); err != nil {
			return
		}
	}
}

// Published provenance (job status, result, policy.json) never carries a
// query string, user information or fragment of the URLs.
func TestRoscomVPNProvenanceDropsURLSecrets(t *testing.T) {
	c, f := roscomAdmin(t)
	profileURL := "https://profiles.example.com/DEFAULT.JSON?token=profilesecret"
	f.files[profileURL] = []byte(strings.ReplaceAll(strings.ReplaceAll(synthProfile,
		"https://cdn.example.com/geosite.dat", "https://cdn.example.com/geosite.dat?sig=sitesecret"),
		"https://cdn.example.com/geoip.dat", "https://cdn.example.com/geoip.dat#ipsecret"))
	f.files["https://cdn.example.com/geosite.dat?sig=sitesecret"] = f.files["https://cdn.example.com/geosite.dat"]
	f.files["https://cdn.example.com/geoip.dat#ipsecret"] = f.files["https://cdn.example.com/geoip.dat"]
	res := mustRouting(t, c, "routing-roscomvpn-import", map[string]any{"url": profileURL, "accepted": true})
	if res["installed"] != true || res["source"] != "https://profiles.example.com/DEFAULT.JSON" || len(res["source_sha256"].(string)) != 64 {
		t.Fatalf("result %v", res)
	}
	status, _ := json.Marshal(mustRouting(t, c, "routing-roscomvpn-status", nil))
	policyJSON, err := os.ReadFile(filepath.Join(c.overlayDir(), "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	overview, _ := json.Marshal(mustRouting(t, c, "routing-policy", nil))
	for _, text := range []string{string(status), string(policyJSON), string(overview)} {
		for _, secret := range []string{"profilesecret", "sitesecret", "ipsecret", "token=", "sig="} {
			if strings.Contains(text, secret) {
				t.Errorf("published %q: %.300s", secret, text)
			}
		}
	}
	var meta map[string]any
	if err := json.Unmarshal(policyJSON, &meta); err != nil {
		t.Fatal(err)
	}
	if meta["geosite"] != "https://cdn.example.com/geosite.dat" || len(meta["geosite_sha256"].(string)) != 64 || len(meta["source_sha256"].(string)) != 64 {
		t.Fatalf("policy.json provenance %v", meta)
	}
	// The full URLs were still used to fetch.
	if strings.Join(f.calls, " ") != profileURL+" https://cdn.example.com/geosite.dat?sig=sitesecret https://cdn.example.com/geoip.dat#ipsecret" {
		t.Fatalf("fetched %v", f.calls)
	}
}
