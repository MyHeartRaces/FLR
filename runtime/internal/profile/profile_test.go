package profile

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, e := os.ReadFile(filepath.Join("testdata", name))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func one(t *testing.T, b []byte) Profile {
	t.Helper()
	p, e := Parse(b)
	if e != nil || len(p) != 1 {
		t.Fatalf("parse: %v (%d profiles)", e, len(p))
	}
	return p[0]
}
func TestNaiveImportRejectedAtomically(t *testing.T) {
	good := fixture(t, "salamander.uri")
	inputs := []string{
		"naive+https://public-user:PUBLIC_TEST_PASSWORD@example.com:443",
		`{"type":"naive","server":"example.com","server_port":443,"username":"public-user","password":"PUBLIC_TEST_PASSWORD","tls":{"enabled":true,"server_name":"example.com"}}`,
		`{"proxy":"https://public-user:PUBLIC_TEST_PASSWORD@example.com:443"}`,
		string(good) + "\nnaive+https://public-user:PUBLIC_TEST_PASSWORD@example.org:443",
	}
	for _, input := range inputs {
		profiles, err := Parse([]byte(input))
		if err == nil || len(profiles) != 0 {
			t.Fatal("removed Naive protocol accepted or partial batch returned")
		}
		registry := &Registry{Version: 1, Profiles: []Profile{one(t, good)}}
		before, _ := json.Marshal(registry)
		if _, err = registry.Import([]byte(input)); err == nil {
			t.Fatal("Naive registry import accepted")
		}
		after, _ := json.Marshal(registry)
		if !bytes.Equal(before, after) {
			t.Fatal("rejected Naive batch changed registry")
		}
		if strings.Contains(err.Error(), "PUBLIC_TEST_PASSWORD") {
			t.Fatal("rejection exposed password")
		}
	}
}

// These cases catch loss of credentials, obfuscation, transport selection and detour wiring.
func TestImportContracts(t *testing.T) {
	for _, tc := range []struct {
		name, file, family, engine string
		udp                        bool
	}{
		{"bundle", "bundle.json", "hy2", "sing-box", true},
		{"gecko", "gecko.json", "hy2", "sing-box", true},
		{"salamander", "salamander.uri", "hy2", "sing-box", true},
		{"xhttp-json", "xhttp.json", "reality", "xray", true},
		{"xhttp-uri", "xhttp.uri", "reality", "xray", true},
		{"shadowtls", "shadowtls.json", "ss2022", "sing-box", false},
		{"wgws", "wgws.json", "wgws", "wstunnel", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := one(t, fixture(t, tc.file))
			if p.Family != tc.family || p.Engine != tc.engine || p.Capabilities.UDP != tc.udp {
				t.Fatalf("unexpected metadata: %+v", p.Summary())
			}
			if tc.engine != "sing-box" && (p.Enabled || !strings.Contains(p.DisabledReason, "missing-component")) {
				t.Fatal("native dependency must default disabled")
			}
		})
	}
	p := one(t, fixture(t, "gecko.json"))
	r, e := Render(p, "eth1", "/run/flr")
	if e != nil {
		t.Fatal(e)
	}
	var cfg map[string]any
	if e = json.Unmarshal(r.SingBox, &cfg); e != nil {
		t.Fatal(e)
	}
	out := cfg["outbounds"].([]any)[0].(map[string]any)
	obfs := out["obfs"].(map[string]any)
	if obfs["min_packet_size"] != float64(600) || obfs["max_packet_size"] != float64(1300) {
		t.Fatal("Gecko padding lost")
	}
	compact := `{"wg":{"private_key":"PUBLIC_TEST_PRIVATE","peer_public_key":"PUBLIC_TEST_PEER","address":["10.10.0.2/32"]},"ws":{"server":"example.com","path":"/wgws"}}`
	p = one(t, []byte("wgws://"+base64.RawURLEncoding.EncodeToString([]byte(compact))))
	if p.Family != "wgws" {
		t.Fatal("compact WGWS not expanded")
	}
}

// These cases catch partial batch commits, unsafe file references and unsupported silent downgrades.
func TestRejectUntrustedImports(t *testing.T) {
	good := string(fixture(t, "salamander.uri"))
	for _, tc := range []struct{ name, input string }{
		{"oversize", strings.Repeat("x", (1<<20)+1)},
		{"unknown-version", `{"schema":"tracegate.client-config-bundle.v2","version":2,"profiles":[]}`},
		{"bad-version", `{"schema":"tracegate.client-config-bundle.v1","version":2,"profiles":[]}`},
		{"selector", `{"outbounds":[{"type":"selector","tag":"p","outbounds":["direct"]}]}`},
		{"file-reference", `{"type":"hysteria2","server":"example.com","server_port":443,"password":"test","tls":{"enabled":true,"certificate_path":"/etc/shadow"}}`},
		{"unknown-field", `{"type":"hysteria2","server":"example.com","server_port":443,"password":"test","mystery_transport":true}`},
		{"hostile-bundle-path", `{"schema":"tracegate.client-config-bundle.v1","profiles":[{"artifacts":[{"kind":"sing-box-config","filename":"../../secret","json":{"type":"naive"}}]}]}`},
		{"partial-batch", good + "\nvless://broken"},
		{"source-url", "https://example.com/subscription?token=PRIVATE_TOKEN"},
		{"unsupported-transport", "vless://public-test@example.com:443?type=kcp&security=tls"},
		{"unsupported-obfs", "hy2://public-test@example.com:443?obfs=unknown&obfs-password=test"},
		{"gecko-band", "hy2://public-test@example.com:443?obfs=gecko&obfs-password=test&obfs-min-packet-size=1500&obfs-max-packet-size=600"},
		{"duplicate-identity", good + "\n" + good},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, e := Parse([]byte(tc.input))
			if e == nil || len(p) != 0 {
				t.Fatal("invalid batch accepted or partial result returned")
			}
			if e != nil && (strings.Contains(e.Error(), "PRIVATE_TOKEN") || strings.Contains(e.Error(), "public-test")) {
				t.Fatal("error leaks credentials")
			}
		})
	}
}

// Imported inbound/routing control must never affect the generated proxy slot.
func TestRenderOwnsNetworkAndDoesNotMutate(t *testing.T) {
	for _, name := range []string{"gecko.json", "shadowtls.json", "xhttp.json", "wgws.json"} {
		t.Run(name, func(t *testing.T) {
			p := one(t, fixture(t, name))
			before, _ := json.Marshal(p)
			r, e := Render(p, "eth1", "/run/flr")
			if e != nil {
				t.Fatal(e)
			}
			after, _ := json.Marshal(p)
			if !bytes.Equal(before, after) {
				t.Fatal("render mutated stored profile")
			}
			var cfg map[string]any
			if e = json.Unmarshal(r.SingBox, &cfg); e != nil {
				t.Fatal(e)
			}
			ins := cfg["inbounds"].([]any)
			if len(ins) != 2 {
				t.Fatal("imported inbound survived")
			}
			tun := ins[0].(map[string]any)
			health := ins[1].(map[string]any)
			if tun["address"].([]any)[0] != "198.18.0.1/30" || tun["interface_name"] != "flr-hy" || tun["auto_route"] != false || health["listen"] != "127.0.0.1" || health["listen_port"] != float64(1081) {
				t.Fatal("uncontrolled slot")
			}
			if bytes.Contains(r.SingBox, []byte("198.51.100.66")) || bytes.Contains(r.Xray, []byte("198.51.100.66")) {
				t.Fatal("imported routes or listeners retained")
			}
			if name == "xhttp.json" {
				var x map[string]any
				json.Unmarshal(r.Xray, &x)
				in := x["inbounds"].([]any)[0].(map[string]any)
				if in["port"] != float64(1083) || in["listen"] != "127.0.0.1" {
					t.Fatal("Xray listener uncontrolled")
				}
				if !bytes.Contains(r.Xray, []byte(`"mark":-2147483648`)) || !bytes.Contains(r.Xray, []byte(`"interface":"eth1"`)) {
					t.Fatal("Xray WAN mark/bind missing")
				}
			}
			if name == "wgws.json" {
				args := strings.Join(r.SidecarArgs, " ")
				if strings.Contains(args, "IMPORTED_COMMAND") || !strings.Contains(args, "127.0.0.1:51821") {
					t.Fatal("WGWS command not reconstructed")
				}
				if !strings.Contains(args, "--socket-so-mark 2147483648") || r.BindInterface != "eth1" {
					t.Fatal("wstunnel WAN mark/route metadata missing")
				}
				if !strings.Contains(args, "--tls-verify-certificate") {
					t.Fatal("wstunnel TLS verification missing")
				}
			}
			if name == "shadowtls.json" {
				if r.Capabilities.UDP || !bytes.Contains(r.SingBox, []byte(`"network":"udp"`)) || !bytes.Contains(r.SingBox, []byte(`"action":"reject"`)) {
					t.Fatal("TCP-only profile must reject UDP")
				}
			}
		})
	}
	for _, v := range []struct{ wan, dir string }{{"eth1;evil", "/run/flr"}, {"eth1", "relative"}, {"eth1", "/run/../etc"}} {
		if _, e := Render(one(t, fixture(t, "gecko.json")), v.wan, v.dir); e == nil {
			t.Fatal("unsafe render context accepted")
		}
	}
}

func TestRegistryPrivateTransactionalAndRedacted(t *testing.T) {
	p := one(t, fixture(t, "salamander.uri"))
	reg := &Registry{Version: 1, Profiles: []Profile{p}}
	dir := filepath.Join(t.TempDir(), "private")
	path := filepath.Join(dir, "profiles.json")
	if e := reg.Save(path); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		p    string
		mode os.FileMode
	}{{dir, 0700}, {path, 0600}} {
		s, e := os.Stat(tc.p)
		if e != nil || s.Mode().Perm() != tc.mode {
			t.Fatalf("private permissions: %v", e)
		}
	}
	saved, _ := os.ReadFile(path)
	if _, e := reg.Import([]byte(string(fixture(t, "gecko.json")) + "\nBAD")); e == nil {
		t.Fatal("invalid batch accepted")
	}
	now, _ := os.ReadFile(path)
	if !bytes.Equal(saved, now) || len(reg.Profiles) != 1 {
		t.Fatal("failed import changed registry")
	}
	loaded, e := Load(path)
	if e != nil || len(loaded.Profiles) != 1 {
		t.Fatalf("load: %v", e)
	}
	b, _ := json.Marshal(loaded.Summaries())
	for _, secret := range []string{"PUBLIC_TEST_PASSWORD", "PUBLIC_TEST_OBFS", "password", "private_key", "source_url"} {
		if bytes.Contains(b, []byte(secret)) {
			t.Fatalf("summary leaks %s", secret)
		}
	}
	if _, e := reg.Import(fixture(t, "salamander.uri")); e == nil {
		t.Fatal("duplicate import accepted")
	}
	loaded.Profiles = append(loaded.Profiles, loaded.Profiles[0])
	if e := loaded.Save(path); e == nil {
		t.Fatal("duplicate IDs persisted")
	}
	now, _ = os.ReadFile(path)
	if !bytes.Equal(saved, now) {
		t.Fatal("invalid save replaced valid registry")
	}
	link := filepath.Join(t.TempDir(), "link")
	if e = os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	if _, e = Load(link); e == nil {
		t.Fatal("loaded registry symlink")
	}
	if e = reg.Save(link); e == nil {
		t.Fatal("saved through symlink")
	}
	p.ID = "../hostile"
	reg.Profiles = []Profile{p}
	if e = reg.Save(path); e == nil {
		t.Fatal("unsafe ID accepted")
	}
}

func TestCandidatesExhaustFamiliesDeterministically(t *testing.T) {
	reg := &Registry{Version: 1}
	for _, p := range []Profile{
		{ID: "hy-external", Family: "hy2", ServerGroup: "other", Priority: -100, Enabled: true},
		{ID: "reality", Family: "reality", Priority: -1000, Enabled: true},
		{ID: "hy-primary", Family: "hy2", ServerGroup: "primary", Priority: 100, Enabled: true},
		{ID: "hy-tie-b", Family: "hy2", Priority: 5, Enabled: true},
		{ID: "hy-tie-a", Family: "hy2", Priority: 5, Enabled: true},
		{ID: "disabled", Family: "hy2", Priority: -200, Enabled: false},
	} {
		reg.Profiles = append(reg.Profiles, p)
	}
	got := []string{}
	for _, p := range reg.Candidates("primary") {
		got = append(got, p.ID)
	}
	want := []string{"hy-primary", "hy-external", "hy-tie-a", "hy-tie-b", "reality"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestStableIdentityAndAvailability(t *testing.T) {
	a := one(t, fixture(t, "salamander.uri"))
	b := one(t, []byte(strings.ReplaceAll(string(fixture(t, "salamander.uri")), "#public-fixture", "#other-name")))
	if a.ID != b.ID {
		t.Fatal("display name changed identity")
	}
	c := one(t, []byte(strings.ReplaceAll(string(fixture(t, "salamander.uri")), "PUBLIC_TEST_PASSWORD", "OTHER_TEST_PASSWORD")))
	if a.ID == c.ID {
		t.Fatal("different credentials collided")
	}
	x := one(t, fixture(t, "xhttp.json"))
	reg := &Registry{Version: 1, Profiles: []Profile{x}}
	reg.ApplyAvailability(map[string]bool{"sing-box": true, "xray": true})
	if !reg.Profiles[0].Enabled || reg.Profiles[0].DisabledReason != "" {
		t.Fatal("available native component remains disabled")
	}
	reg.Profiles[0].Enabled = false
	reg.ApplyAvailability(map[string]bool{"sing-box": true, "xray": true})
	if reg.Profiles[0].Enabled {
		t.Fatal("availability overrode manual disable")
	}
}

func TestProfileBound(t *testing.T) {
	lines := []string{}
	for i := 0; i < 65; i++ {
		lines = append(lines, "hy2://test"+strings.Repeat("x", i)+"@example.com:443?obfs=salamander&obfs-password=test")
	}
	if _, e := Parse([]byte(strings.Join(lines, "\n"))); e == nil {
		t.Fatal("profile limit ignored")
	}
}

func TestConfiguredFamilyOrderAndSnapshotIsolation(t *testing.T) {
	p := one(t, fixture(t, "salamander.uri"))
	r := &Registry{Version: 1, FamilyOrder: []string{"wgws", "ss2022", "reality", "vless"}, Profiles: []Profile{p, {ID: "native", Family: "wgws", Priority: -100, Enabled: true}}}
	c := r.Candidates("")
	if len(c) != 2 || c[0].Family != "hy2" || c[1].Family != "wgws" {
		t.Fatal("HY2 must precede configured family order")
	}
	c[0].Outbound["server"] = "changed.example.com"
	if r.Profiles[0].Outbound["server"] != "example.com" {
		t.Fatal("candidate endpoint pin mutated private registry")
	}
	x := one(t, fixture(t, "xhttp.json"))
	r = &Registry{Version: 1, Profiles: []Profile{x}}
	if e := r.SetEnabled(x.ID, false); e != nil {
		t.Fatal(e)
	}
	r.ApplyAvailability(map[string]bool{"sing-box": true, "xray": true})
	if r.Profiles[0].Enabled {
		t.Fatal("missing-component recovery undid explicit user disable")
	}
}

func TestStrictTransportOptionsAndSecretlessPersistence(t *testing.T) {
	for _, s := range []string{
		`hy2://test@example.com:443?obfs=gecko&obfs-password=test&insecure=1`,
		`vless://test@example.com:443?security=tls&type=grpc&mode=unexpected`,
		`vless://test@example.com:443?security=tls&type=ws&serviceName=ignored`,
		`vless://test@example.com:443?security=reality&pbk=test&type=xhttp&extra=ignored`,
		`{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"public-test","encryption":"none"}]}]},"streamSettings":{"security":"tls","tlsSettings":{},"network":"xhttp","xhttpSettings":{"extra":{"downloadSettings":{"address":"evil.example.com"}}}}}]}`,
		`{"type":"hysteria2","server":"example.com","server_port":443,"password":"test","obfs":{"type":"gecko","password":"test","min_packet_size":"nonnumeric"},"tls":{"enabled":true}}`,
	} {
		if _, e := Parse([]byte(s)); e == nil {
			t.Fatal("unsupported or unsafe option accepted")
		}
	}
	p := one(t, fixture(t, "bundle.json"))
	r := &Registry{Version: 1, Profiles: []Profile{p}}
	path := filepath.Join(t.TempDir(), "private", "profiles.json")
	if e := r.Save(path); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(b, []byte("SOURCE_TOKEN_MUST_NOT_PERSIST")) || bytes.Contains(b, []byte("subscription")) {
		t.Fatal("source subscription persisted")
	}
	data := base64.StdEncoding.EncodeToString(fixture(t, "salamander.uri"))
	if p := one(t, []byte(data)); p.Family != "hy2" {
		t.Fatal("base64 subscription rejected")
	}
}

func TestSummaryRedactsCredentialsRepeatedInMetadata(t *testing.T) {
	p := one(t, fixture(t, "salamander.uri"))
	p.ServerGroup = "group-PUBLIC_TEST_PASSWORD"
	p.DisabledReason = "engine error with PUBLIC_TEST_OBFS"
	b, e := json.Marshal(p.Summary())
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(b, []byte("PUBLIC_TEST_PASSWORD")) || bytes.Contains(b, []byte("PUBLIC_TEST_OBFS")) {
		t.Fatal("metadata repeated credentials in list output")
	}
}

func TestBundleGeckoPreservesNativeArtifactPadding(t *testing.T) {
	link := "hy2://PUBLIC_TEST_PASSWORD@example.com:443?obfs=gecko&obfs-password=PUBLIC_TEST_OBFS&sni=example.com"
	yaml := "server: example.com:443\nauth: PUBLIC_TEST_PASSWORD\ntls:\n  sni: example.com\n  insecure: false\nobfs:\n  type: gecko\n  gecko:\n    password: PUBLIC_TEST_OBFS\n    minPacketSize: 600\n    maxPacketSize: 1300\nbandwidth:\n  up: 10 mbps\n  down: 20 mbps\nsocks5:\n  listen: 127.0.0.1:20000\n  username: public-user\n  password: public-inbound-password\n  disableUDP: false\n"
	bundle := map[string]any{"schema": "tracegate.client-config-bundle.v1", "profiles": []any{map[string]any{"links": []any{map[string]any{"url": link}}, "artifacts": []any{map[string]any{"kind": "file", "filename": "public.hysteria.yaml", "contentBase64": base64.StdEncoding.EncodeToString([]byte(yaml))}}}}}
	b, _ := json.Marshal(bundle)
	p := one(t, b)
	r, e := Render(p, "eth1", "/run/flr")
	if e != nil {
		t.Fatal(e)
	}
	var cfg map[string]any
	json.Unmarshal(r.SingBox, &cfg)
	out := cfg["outbounds"].([]any)[0].(map[string]any)
	obfs := out["obfs"].(map[string]any)
	if obfs["min_packet_size"] != float64(600) || obfs["max_packet_size"] != float64(1300) || out["up_mbps"] != float64(10) || out["down_mbps"] != float64(20) {
		t.Fatal("native Gecko padding/bandwidth discarded")
	}
	yaml += "tls_extra:\n  certificate_path: /etc/shadow\n"
	artifact := bundle["profiles"].([]any)[0].(map[string]any)["artifacts"].([]any)[0].(map[string]any)
	artifact["contentBase64"] = base64.StdEncoding.EncodeToString([]byte(yaml))
	b, _ = json.Marshal(bundle)
	if _, e := Parse(b); e == nil {
		t.Fatal("unknown native YAML options ignored")
	}
}

func TestOrdinaryVLESSURIUsesExistingSingBox(t *testing.T) {
	for _, link := range []string{
		"vless://00000000-0000-4000-8000-000000000000@example.com:443?security=reality&pbk=PUBLIC_TEST_KEY&sid=abcd&fp=chrome&sni=example.com&type=tcp&flow=xtls-rprx-vision&spx=%2F",
		"vless://00000000-0000-4000-8000-000000000000@example.com:443?security=tls&sni=example.com&type=ws&host=example.com&path=%2Fpublic",
		"vless://00000000-0000-4000-8000-000000000000@example.com:443?security=tls&sni=example.com&type=grpc&serviceName=public&mode=gun",
	} {
		p := one(t, []byte(link))
		if p.Engine != "sing-box" || !p.Enabled {
			t.Fatal("ordinary VLESS unnecessarily requires missing Xray")
		}
		if _, e := Render(p, "eth1", "/run/flr"); e != nil {
			t.Fatal(e)
		}
	}
	p := one(t, fixture(t, "shadowtls.json"))
	if p.Capabilities.UDP || !p.Capabilities.TCPOnly {
		t.Fatal("ShadowTLS detour incorrectly advertises UDP")
	}
}

func TestAvailabilityPreservesValidationFailure(t *testing.T) {
	p := one(t, fixture(t, "salamander.uri"))
	p.Enabled = false
	p.DisabledReason = "engine-validation-failed"
	r := &Registry{Version: 1, Profiles: []Profile{p}}
	r.ApplyAvailability(map[string]bool{"sing-box": true})
	if r.Profiles[0].Enabled || r.Profiles[0].DisabledReason != "engine-validation-failed" {
		t.Fatal("component availability erased config-validation failure")
	}
}

// Distinct inner and bearer destinations catch WAN pinning the wrong socket.
func TestShadowTLSOuterEndpointUsesDetour(t *testing.T) {
	input := []byte(`{"outbounds":[{"type":"shadowsocks","tag":"proxy","server":"example.com","server_port":443,"method":"2022-blake3-aes-128-gcm","password":"PUBLIC_TEST_SS_KEY","detour":"shadowtls-out"},{"type":"shadowtls","tag":"shadowtls-out","server":"other.example.com","server_port":8443,"version":3,"password":"PUBLIC_TEST_SHADOWTLS","tls":{"enabled":true,"server_name":"example.com"}}]}`)
	p := one(t, input)
	rendered, err := Render(p, "eth1", "/run/flr")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rendered.OuterEndpoints, []string{"other.example.com:8443"}) {
		t.Fatalf("wrong outer endpoints: %v", rendered.OuterEndpoints)
	}
	var cfg map[string]any
	if err := json.Unmarshal(rendered.SingBox, &cfg); err != nil {
		t.Fatal(err)
	}
	outbounds := cfg["outbounds"].([]any)
	inner := outbounds[0].(map[string]any)
	detour := outbounds[1].(map[string]any)
	if inner["server"] != "example.com" || inner["server_port"] != float64(443) {
		t.Fatal("inner Shadowsocks destination changed")
	}
	if detour["server"] != "other.example.com" || detour["server_port"] != float64(8443) || detour["bind_interface"] != "eth1" || detour["routing_mark"] != float64(0x80000000) {
		t.Fatal("actual ShadowTLS bearer lost destination, WAN bind or mark")
	}
	if inner["bind_interface"] != nil || inner["routing_mark"] != nil {
		t.Fatal("WAN dial settings belong only on the outer detour")
	}
}

func TestSummaryRedactsProxyPasswords(t *testing.T) {
	p := one(t, fixture(t, "gecko.json"))
	for _, group := range []string{"team-PUBLIC_TEST_OBFS", "team-PUBLIC_TEST_PASSWORD", "unrelated-control"} {
		p.ServerGroup = group
		r := &Registry{Version: 1, Profiles: []Profile{p}}
		for _, summary := range []any{p.Summary(), r.Summaries()} {
			data, e := json.Marshal(summary)
			if e != nil {
				t.Fatal(e)
			}
			for _, credential := range []string{"PUBLIC_TEST_OBFS", "PUBLIC_TEST_PASSWORD"} {
				if bytes.Contains(data, []byte(credential)) {
					t.Fatal("proxy credential exposed")
				}
			}
			if group == "unrelated-control" && !bytes.Contains(data, []byte(group)) {
				t.Fatal("unrelated metadata redacted")
			}
		}
		if p.ServerGroup != group || object(p.Outbound["obfs"])["password"] != "PUBLIC_TEST_OBFS" || p.Outbound["password"] != "PUBLIC_TEST_PASSWORD" {
			t.Fatal("summary mutated private profile")
		}
	}
}

func TestSummaryRedactsAuthenticatedHeadersButRenderRetainsThem(t *testing.T) {
	inputs := []struct {
		name  string
		input []byte
	}{
		{"vless-ws", []byte(`{"type":"vless","server":"example.com","server_port":443,"uuid":"00000000-0000-4000-8000-000000000000","tls":{"enabled":true,"server_name":"example.com"},"transport":{"type":"ws","path":"/public","headers":{"Authorization":"Bearer PUBLIC_TEST_HEADER_TOKEN","Cookie":"session=PUBLIC_TEST_COOKIE_TOKEN","X-Api-Key":"PUBLIC_TEST_API_TOKEN","Host":"example.com"}}}`)},
		{"wgws", fixture(t, "wgws.json")},
	}
	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			p := one(t, tc.input)
			if p.WGWS != nil {
				p.WGWS.Websocket["headers"] = map[string]any{"Authorization": "Bearer PUBLIC_TEST_HEADER_TOKEN", "Cookie": "session=PUBLIC_TEST_COOKIE_TOKEN", "X-Api-Key": "PUBLIC_TEST_API_TOKEN", "Host": "example.com"}
			}
			for _, group := range []string{"team-Bearer PUBLIC_TEST_HEADER_TOKEN", "team-PUBLIC_TEST_HEADER_TOKEN", "team-PUBLIC_TEST_COOKIE_TOKEN", "team-PUBLIC_TEST_API_TOKEN"} {
				p.ServerGroup = group
				r := &Registry{Version: 1, Profiles: []Profile{p}}
				for _, summary := range []any{p.Summary(), r.Summaries()} {
					data, err := json.Marshal(summary)
					if err != nil {
						t.Fatal(err)
					}
					for _, credential := range []string{"Bearer PUBLIC_TEST_HEADER_TOKEN", "PUBLIC_TEST_HEADER_TOKEN", "PUBLIC_TEST_COOKIE_TOKEN", "PUBLIC_TEST_API_TOKEN"} {
						if bytes.Contains(data, []byte(credential)) {
							t.Fatalf("summary exposes header credential %s", credential)
						}
					}
				}
			}
			rendered, err := Render(p, "eth1", "/run/flr")
			if err != nil {
				t.Fatal(err)
			}
			privateConfig := rendered.SingBox
			if p.WGWS != nil {
				privateConfig = rendered.Sidecar
			}
			if !bytes.Contains(privateConfig, []byte("Bearer PUBLIC_TEST_HEADER_TOKEN")) || !bytes.Contains(privateConfig, []byte("session=PUBLIC_TEST_COOKIE_TOKEN")) || !bytes.Contains(privateConfig, []byte("PUBLIC_TEST_API_TOKEN")) {
				t.Fatal("summary redaction removed required private headers")
			}
		})
	}
}

func TestXraySockoptUsesSignedNativeSchemaAndPreservesKernelBits(t *testing.T) {
	r, err := Render(one(t, fixture(t, "xhttp.json")), "eth1", "/run/flr")
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Outbounds []struct {
			StreamSettings struct {
				Sockopt struct {
					Mark      int32  `json:"mark"`
					Interface string `json:"interface"`
				} `json:"sockopt"`
			} `json:"streamSettings"`
		} `json:"outbounds"`
	}
	// Match the pinned native Xray SocketConfig.Mark type. A positive 2^31
	// cannot decode here even though its untyped JSON looked plausible.
	if err = json.Unmarshal(r.Xray, &config); err != nil {
		t.Fatal(err)
	}
	mark := config.Outbounds[0].StreamSettings.Sockopt
	if mark.Mark != int32(-2147483648) || uint32(mark.Mark) != uint32(0x80000000) || mark.Interface != "eth1" {
		t.Fatal("Xray native mark lost owned WAN/kernel bits", mark)
	}
}

func TestCompactWGWSHeadersSurviveParseSaveRender(t *testing.T) {
	compact := `{"wg":{"private_key":"PUBLIC_TEST_PRIVATE","peer_public_key":"PUBLIC_TEST_PEER","address":["10.10.0.2/32"]},"ws":{"server":"example.com","path":"/wgws","host":"virtual.example.com","headers":{"Authorization":"Bearer PUBLIC_TEST_HEADER_TOKEN","Cookie":"session=PUBLIC_TEST_COOKIE_TOKEN","X-Api-Key":"PUBLIC_TEST_API_TOKEN"}}}`
	var input map[string]any
	json.Unmarshal([]byte(compact), &input)
	ws := input["ws"].(map[string]any)
	h := ws["headers"].(map[string]any)
	for _, hostKey := range []string{"", "host", "HOST", "HoSt"} {
		for k := range h {
			if strings.EqualFold(k, "host") {
				delete(h, k)
			}
		}
		if hostKey != "" {
			h[hostKey] = "virtual.example.com"
		}
		raw, _ := json.Marshal(input)
		uri := []byte("wgws://" + base64.RawURLEncoding.EncodeToString(raw))
		r := &Registry{Version: 1}
		if _, e := r.Import(uri); e != nil {
			t.Fatal(e)
		}
		path := filepath.Join(t.TempDir(), "private", "profiles.json")
		if e := r.Save(path); e != nil {
			t.Fatal(e)
		}
		saved, e := Load(path)
		if e != nil {
			t.Fatal(e)
		}
		p := saved.Profiles[0]
		p.ServerGroup = "PUBLIC_TEST_HEADER_TOKEN"
		summary, _ := json.Marshal(p.Summary())
		if bytes.Contains(summary, []byte("PUBLIC_TEST_HEADER_TOKEN")) {
			t.Fatal("summary leaked credential")
		}
		rendered, e := Render(p, "eth1", "/run/flr")
		if e != nil {
			t.Fatal(e)
		}
		hostHeaders := 0
		for _, arg := range rendered.SidecarArgs {
			if strings.HasPrefix(strings.ToLower(arg), "host: ") {
				hostHeaders++
			}
		}
		if hostHeaders != 1 {
			t.Fatal("case-insensitive Host duplicated in native arguments")
		}
		if !strings.Contains(strings.Join(rendered.SidecarArgs, "\n"), "Authorization: Bearer PUBLIC_TEST_HEADER_TOKEN") {
			t.Fatal("native args lost authentication")
		}
		for _, required := range []string{"Bearer PUBLIC_TEST_HEADER_TOKEN", "session=PUBLIC_TEST_COOKIE_TOKEN", "PUBLIC_TEST_API_TOKEN", "virtual.example.com"} {
			if !bytes.Contains(rendered.Sidecar, []byte(required)) {
				t.Fatal("required header discarded", hostKey)
			}
		}
	}
	for _, headers := range []map[string]any{{"host": "other.example.com"}, {"Host": "virtual.example.com", "HOST": "virtual.example.com"}, {"Authorization": "bad\r\nheader"}} {
		ws["headers"] = headers
		raw, _ := json.Marshal(input)
		if _, e := Parse([]byte("wgws://" + base64.RawURLEncoding.EncodeToString(raw))); e == nil {
			t.Fatal("conflicting or unsafe header accepted")
		}
	}
}
