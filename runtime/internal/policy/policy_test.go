package policy

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// These cases catch priority inversion, suffix-boundary mistakes, and WAN fallback.
func TestHomePolicy(t *testing.T) {
	p, err := Load("testdata/split")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		want Class
	}{
		{"api.ozon.ru", Direct}, {"sberbank.ru", Direct}, {"updates.apple.com", General},
		{"archive.ubuntu.com", General}, {"mirror.yandex.ru", General}, {"twitch.tv", General},
		{"unknown.flr-test.invalid", General}, {"api.steampowered.com", Games},
		{"API.OZON.RU.", Direct}, {"evilozon.ru", General}, {"printer.lan", Local},
	} {
		if got := p.ClassifyDomain(c.name); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
	for _, c := range []struct {
		ip   string
		want Class
	}{
		{"192.168.8.10", Local}, {"1.1.1.1", General}, {"17.0.0.1", General},
	} {
		if got := p.ClassifyIP(netip.MustParseAddr(c.ip)); got != c.want {
			t.Errorf("%s: got %s want %s", c.ip, got, c.want)
		}
	}
}

func fixture(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	for _, f := range []string{"policy.json", "rulesets/local-domains.json", "rulesets/local-ips.json", "rulesets/vpn-required.json", "rulesets/direct-essential.json", "rulesets/game-platforms.json", "rulesets/vpn-services.json", "rulesets/roscom-direct-domains.json", "rulesets/roscom-direct-ips.json"} {
		b, e := os.ReadFile(filepath.Join("testdata/split", f))
		if e != nil {
			t.Fatal(e)
		}
		target := filepath.Join(dir, f)
		if e = os.MkdirAll(filepath.Dir(target), 0700); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(target, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "rulesets/vpn-required.json"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRejectInvalidPolicy(t *testing.T) {
	for _, c := range []string{
		`{"version":3,"rules":[{"unsupported_domain_match":["bank.ru"]}]}`,
		`{"version":3,"rules":[{"domain_regex":["["]}]}`,
		`{"version":3,"rules":[{"ip_cidr":["999.0.0.1/24"]}]}`,
	} {
		if _, e := Load(fixture(t, c)); e == nil {
			t.Errorf("accepted invalid rule %s", c)
		}
	}
	dir := fixture(t, `{"version":3,"rules":[]}`)
	os.Remove(filepath.Join(dir, "rulesets/direct-essential.json"))
	if _, e := Load(dir); e == nil {
		t.Fatal("accepted missing rule source")
	}
}

func TestNativeMatchTypes(t *testing.T) {
	dir := fixture(t, `{"version":3,"rules":[{"domain":["exact.flr-test.invalid"],"domain_suffix":["suffix.flr-test.invalid"],"domain_keyword":["flr-keyword"],"domain_regex":["^regex[0-9]+\\.flr-test\\.invalid$"],"ip_cidr":["8.8.8.0/24"]}]}`)
	p, e := Load(dir)
	if e != nil {
		t.Fatal(e)
	}
	// A match in vpn-required must win over the broad direct suffix .ru.
	for _, name := range []string{"exact.flr-test.invalid", "a.suffix.flr-test.invalid", "flr-keyword.ru", "regex12.flr-test.invalid"} {
		if !p.IsRequiredVPN(name) {
			t.Errorf("native match missed %s", name)
		}
	}
	if p.IsRequiredVPN("evilsuffix.flr-test.invalid") {
		t.Fatal("suffix lacks label boundary")
	}
	// Force a competing broad-direct CIDR to exercise required-VPN priority.
	if e = os.WriteFile(filepath.Join(dir, "rulesets/roscom-direct-ips.json"), []byte(`{"version":3,"rules":[{"ip_cidr":["8.8.8.0/24"]}]}`), 0600); e != nil {
		t.Fatal(e)
	}
	p, e = Load(dir)
	if e != nil {
		t.Fatal(e)
	}
	if p.ClassifyIP(netip.MustParseAddr("8.8.8.8")) != General {
		t.Fatal("required CIDR did not select VPN")
	}
}
