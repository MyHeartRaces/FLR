package policy

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePolicy(t *testing.T, dir string, direct []string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "rulesets"), 0o755); err != nil {
		t.Fatal(err)
	}
	meta := `{"format":"flint2-home-vpn-routing-policy","version":3,"default_class":"vpn-general"}`
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(meta), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range sources {
		rules := `{"version":3,"rules":[]}`
		if name == "roscom-direct-ips" && len(direct) > 0 {
			rules = `{"version":3,"rules":[{"ip_cidr":["` + strings.Join(direct, `","`) + `"]}]}`
		}
		if err := os.WriteFile(filepath.Join(dir, "rulesets", name+".json"), []byte(rules), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLoadInstalledPrefersValidOverlay(t *testing.T) {
	root := t.TempDir()
	image, overlay := filepath.Join(root, "image"), filepath.Join(root, "overlay")
	writePolicy(t, image, nil)
	p, dir, oerr, err := loadInstalled(overlay, image)
	if err != nil || oerr != nil || dir != image || p.ClassifyIP(netip.MustParseAddr("198.51.100.1")) != General {
		t.Fatalf("no overlay: %v %v %s", err, oerr, dir)
	}
	writePolicy(t, overlay, []string{"198.51.100.0/24"})
	p, dir, oerr, err = loadInstalled(overlay, image)
	if err != nil || oerr != nil || dir != overlay || p.ClassifyIP(netip.MustParseAddr("198.51.100.1")) != Direct {
		t.Fatalf("overlay: %v %v %s", err, oerr, dir)
	}
	if err := os.WriteFile(filepath.Join(overlay, "rulesets", "vpn-required.json"), []byte(`{"version":2}`), 0o644); err != nil {
		t.Fatal(err)
	}
	p, dir, oerr, err = loadInstalled(overlay, image)
	if err != nil || oerr == nil || dir != image || p.ClassifyIP(netip.MustParseAddr("198.51.100.1")) != General {
		t.Fatalf("broken overlay must fall back to the image policy: %v %v %s", err, oerr, dir)
	}
}

func TestShippedPolicyIsPublicDefault(t *testing.T) {
	p, err := Load("../../../policy")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"vpn-required", "direct-essential", "game-platforms", "vpn-services", "roscom-direct-domains", "roscom-direct-ips"} {
		m := p.sources[name]
		if len(m.exact)+len(m.suffix)+len(m.keywords)+len(m.regex)+len(m.prefixes) != 0 {
			t.Fatalf("public image policy must not ship routing lists: %s is not empty", name)
		}
	}
	if p.ClassifyDomain("router.lan") != Local || p.ClassifyIP(netip.MustParseAddr("192.168.1.10")) != Local {
		t.Fatal("local destinations must stay local")
	}
	if p.ClassifyDomain("example.ru") != General || p.ClassifyIP(netip.MustParseAddr("8.8.8.8")) != General {
		t.Fatal("everything else goes through the VPN")
	}
}

func TestRoutingModesSwitchDirectListsOff(t *testing.T) {
	p, err := Load("testdata/split")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		mode             string
		bank, broad, app Class
		broadIP          Class
	}{
		{ModeSplit, Direct, Direct, General, Direct},
		{"", Direct, Direct, General, Direct},
		{ModeFullDomestic, Direct, General, General, General},
		{ModeFull, General, General, General, General},
	} {
		v := p.ForMode(c.mode)
		if got := v.ClassifyDomain("api.ozon.ru"); got != c.bank {
			t.Errorf("%q bank: %s", c.mode, got)
		}
		if got := v.ClassifyDomain("music.yandex.ru"); got != c.broad {
			t.Errorf("%q broad: %s", c.mode, got)
		}
		if got := v.ClassifyIP(netip.MustParseAddr("5.255.255.5")); got != c.broadIP {
			t.Errorf("%q broad ip: %s", c.mode, got)
		}
		if v.ClassifyDomain("printer.lan") != Local || v.ClassifyDomain("api.steampowered.com") != Games || v.ClassifyDomain("updates.apple.com") != c.app {
			t.Errorf("%q: local/games/service lists must not change", c.mode)
		}
		if len(v.CIDRs("roscom-direct-ips")) != map[bool]int{true: 1, false: 0}[c.broadIP == Direct] {
			t.Errorf("%q: static broad direct CIDRs", c.mode)
		}
	}
	if p.ClassifyDomain("music.yandex.ru") != Direct {
		t.Fatal("a mode view changed the base policy")
	}
	for _, m := range []string{"split", "full", "full_domestic"} {
		if !ValidMode(m) {
			t.Fatal(m)
		}
	}
	if ValidMode("") || ValidMode("FULL") {
		t.Fatal("invalid mode accepted")
	}
}
