package dns

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
	mdns "github.com/miekg/dns"
)

func TestTunnelProtectsDNSRewritesAndAddresslessAliases(t *testing.T) {
	base, err := policy.Load("../policy/testdata/split")
	if err != nil {
		t.Fatal(err)
	}
	rules := policy.EmptyCustomRules()
	rules.Rules = []policy.CustomRule{{Type: policy.RuleDomain, Value: "search.example", Mode: policy.RuleVPN, Enabled: true}}
	var batch string
	k := &KernelMappings{bindings: NewBindings(), apply: func(req string) error { batch = req; return nil }}
	b := New(base, StaticRoute{Channel: contract.AWG}, k)
	if err := b.ApplyPolicy(base.WithCustom(rules).ForMode(policy.ModeTunnel), ""); err != nil {
		t.Fatal(err)
	}
	b.SetFilter(testFilter(t))
	q := new(mdns.Msg)
	for _, qtype := range []uint16{mdns.TypeHTTPS, mdns.TypeSVCB, mdns.TypeCNAME, mdns.TypeAAAA, mdns.TypeANY} {
		q.SetQuestion("search.example.", qtype)
		if r, err := b.ResolveClient(context.Background(), q, View{}); err != nil || len(r.Answer) != 0 {
			t.Fatalf("protected query type %d returned an unbound alias: %v %v", qtype, r, err)
		}
	}
	q.SetQuestion("safe.search.example.", mdns.TypeA)
	target := new(mdns.Msg)
	target.SetReply(q)
	target.Answer = []mdns.RR{rr("safe.search.example. 2 IN A 8.8.4.4")}
	b.cache.Put(View{ID: string(contract.General), Generation: 1}, q, target, time.Now())
	q.SetQuestion("search.example.", mdns.TypeA)
	r, err := b.ResolveClient(context.Background(), q, View{})
	if err != nil || len(r.Answer) != 2 || r.Answer[0].Header().Ttl > 2 || !strings.Contains(batch, "required4 { 8.8.4.4") {
		t.Fatalf("protected rewrite was not bound through the VPN: %v %v\n%s", r, err, batch)
	}
	q.SetQuestion("safe.search.example.", mdns.TypeA)
	target.SetReply(q)
	target.Answer = []mdns.RR{rr("safe.search.example. 60 IN CNAME other.example.")}
	b.cache.Put(View{ID: string(contract.General), Generation: 1}, q, target, time.Now())
	q.SetQuestion("search.example.", mdns.TypeA)
	r, err = b.ResolveClient(context.Background(), q, View{})
	if err != nil || len(r.Answer) != 0 {
		t.Fatalf("unbound rewrite alias returned to client: %v %v", r, err)
	}
}

func TestProtectedAddressCanBeBoundWithZeroDNSLifetime(t *testing.T) {
	q := new(mdns.Msg)
	q.SetQuestion("vpn.example.", mdns.TypeA)
	q.Answer = []mdns.RR{rr("vpn.example. 0 IN CNAME alias.example."), rr("alias.example. 180 IN A 8.8.4.4")}
	if records, err := AnswerRecords(q); err != nil || len(records) != 0 {
		t.Fatalf("legacy path retained a zero-TTL answer: %v %v", records, err)
	}
	if records, err := answerRecords(q, 5); err != nil || len(records) != 1 || records[0].TTL != 5*time.Second {
		t.Fatalf("protected answer lost its short binding: %v %v", records, err)
	}
}

func TestRoutingPolicyTransactionKeepsPriorBindingsOnFailure(t *testing.T) {
	base, err := policy.Load("../policy/testdata/split")
	if err != nil {
		t.Fatal(err)
	}
	var last string
	rejected := errors.New("nft transaction rejected")
	fail := false
	k := &KernelMappings{bindings: NewBindings(), apply: func(req string) error {
		last = req
		if fail {
			return rejected
		}
		return nil
	}}
	b := New(base, StaticRoute{Channel: contract.Down}, k)
	ip := netip.MustParseAddr("198.51.100.21")
	oldView, _ := ClassifierFor(base)("unlisted.example", View{}, ip)
	records := []AddressTTL{{IP: ip, TTL: time.Minute}}
	if err := k.Replace(oldView, "unlisted.example", records); err != nil {
		t.Fatal(err)
	}
	const static = "flush chain inet flr routing_default\n"
	fail = true
	if err := b.ApplyPolicy(base.ForMode(policy.ModeTunnel), static); !errors.Is(err, rejected) {
		t.Fatalf("wanted rejection, got %v", err)
	}
	if b.pol.Load() != base || !strings.HasPrefix(last, static) || !strings.Contains(last, "direct_domains4 { 198.51.100.21") {
		t.Fatalf("failed publication changed the broker or was not transactional: %s", last)
	}
	fail = false
	if err := k.Replace(oldView, "unlisted.example", records); err != nil || !strings.Contains(last, "services4 { 198.51.100.21") {
		t.Fatalf("failed publication altered installed classifier: %v\n%s", err, last)
	}
	if err := b.ApplyPolicy(base.ForMode(policy.ModeTunnel), static); err != nil {
		t.Fatal(err)
	}
	if err := k.Replace(oldView, "unlisted.example", records); err != nil || !strings.Contains(last, "direct_domains4 { 198.51.100.21") {
		t.Fatalf("late answer did not use the committed classifier: %v\n%s", err, last)
	}
}

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
	if err := k.ApplyPolicy(ClassifierFor(base.ForMode(policy.ModeFull)), ""); err != nil {
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
	if err := k.ApplyPolicy(ClassifierFor(base), ""); err != nil {
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
