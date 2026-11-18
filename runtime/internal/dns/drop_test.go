package dns

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
)

func TestRoutingModeReclassifiesBindingsBothWays(t *testing.T) {
	base, err := policy.Load("../policy/testdata/split")
	if err != nil {
		t.Fatal(err)
	}
	var last string
	k := &KernelMappings{bindings: NewBindings(), apply: func(req string) error { last = req; return nil }}
	bank, broadIP, vpn := netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("5.255.255.5"), netip.MustParseAddr("198.51.100.3")
	split := ClassifierFor(base)
	add := func(c Classifier, name string, ip netip.Addr) {
		t.Helper()
		v, ok := c(name, View{Generation: 1}, ip)
		if !ok {
			t.Fatal("no binding for", name)
		}
		if err := k.Replace(v, name, []AddressTTL{{IP: ip, TTL: time.Hour}}); err != nil {
			t.Fatal(err)
		}
	}
	add(split, "api.ozon.ru", bank)
	add(split, "unlisted.example", broadIP)
	add(split, "mirror.yandex.ru", vpn)
	for _, want := range []string{"essential4 { 198.51.100.1", "direct_domains4 { 5.255.255.5", "required4 { 198.51.100.3"} {
		if !strings.Contains(last, want) {
			t.Fatalf("split: missing %q in\n%s", want, last)
		}
	}
	if err := k.SetClassifier(ClassifierFor(base.ForMode(policy.ModeFull))); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(last, "essential4 {") || strings.Contains(last, "direct_domains4 {") || !strings.Contains(last, "required4 { 198.51.100.3") || !strings.Contains(last, "services4 {") {
		t.Fatalf("full: direct bindings must move to the VPN sets:\n%s", last)
	}
	// An answer resolved under the old policy cannot reinstall a direct binding.
	add(split, "api.ozon.ru", bank)
	if strings.Contains(last, "essential4 {") {
		t.Fatalf("late split answer reinstalled a direct binding:\n%s", last)
	}
	if err := k.SetClassifier(ClassifierFor(base)); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"essential4 { 198.51.100.1", "direct_domains4 { 5.255.255.5"} {
		if !strings.Contains(last, want) {
			t.Fatalf("back to split: missing %q in\n%s", want, last)
		}
	}
	if v, ok := split("printer.lan", View{}, bank); ok || v.Class == contract.Local {
		t.Fatal("local names get no binding")
	}
}
