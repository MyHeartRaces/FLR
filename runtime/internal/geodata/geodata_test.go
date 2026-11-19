package geodata

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// A tiny protobuf writer for synthetic geosite.dat and geoip.dat files.

func pbVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func pbBytes(b []byte, num int, data []byte) []byte {
	b = pbVarint(b, uint64(num)<<3|2)
	b = pbVarint(b, uint64(len(data)))
	return append(b, data...)
}

func pbUint(b []byte, num int, v uint64) []byte {
	return pbVarint(pbVarint(b, uint64(num)<<3), v)
}

func dom(t DomainType, value string, attrs ...string) []byte {
	var b []byte
	if t != Plain {
		b = pbUint(b, 1, uint64(t))
	}
	b = pbBytes(b, 2, []byte(value))
	for _, a := range attrs {
		b = pbBytes(b, 3, pbUint(pbBytes(nil, 1, []byte(a)), 2, 1))
	}
	return b
}

func site(code string, domains ...[]byte) []byte {
	b := pbBytes(nil, 1, []byte(code))
	for _, d := range domains {
		b = pbBytes(b, 2, d)
	}
	return b
}

func cidr(prefix string) []byte {
	p := netip.MustParsePrefix(prefix)
	return pbUint(pbBytes(nil, 1, p.Addr().AsSlice()), 2, uint64(p.Bits()))
}

func geoip(code string, reverse bool, cidrs ...[]byte) []byte {
	b := pbBytes(nil, 1, []byte(code))
	for _, c := range cidrs {
		b = pbBytes(b, 2, c)
	}
	if reverse {
		b = pbUint(b, 3, 1)
	}
	return b
}

func list(entries ...[]byte) []byte {
	var b []byte
	for _, e := range entries {
		b = pbBytes(b, 1, e)
	}
	return b
}

func values(ds []Domain) []string {
	var out []string
	for _, d := range ds {
		out = append(out, string(d.Value))
	}
	return out
}

// lookup collects a category through Each, copying the values.
func lookup(s *Sites, spec string) ([]Domain, bool, error) {
	var out []Domain
	ok, err := s.Each(context.Background(), spec, func(d Domain) error {
		out = append(out, Domain{Type: d.Type, Value: append([]byte(nil), d.Value...)})
		return nil
	})
	return out, ok, err
}

func lookupIPs(s *IPs, code string) ([]netip.Prefix, bool, bool, error) {
	var out []netip.Prefix
	reverse, ok, err := s.Each(context.Background(), code, func(p netip.Prefix) error {
		out = append(out, p)
		return nil
	})
	return out, reverse, ok, err
}

func TestSitesLookup(t *testing.T) {
	// Unknown fields of every skippable wire type must be ignored.
	extra := pbUint(nil, 4, 7)
	extra = append(pbVarint(extra, 5<<3|5), 1, 2, 3, 4)
	extra = append(pbVarint(extra, 6<<3|1), 1, 2, 3, 4, 5, 6, 7, 8)
	data := list(
		append(site("EXAMPLE",
			dom(RootDomain, "example.com"),
			dom(Full, "www.example.net", "cn"),
			dom(Plain, "tracker", "ads", "cn"),
			dom(RootDomain, "bang.example", "!cn"),
			dom(Regex, `^ad[0-9]+\.example\.org$`)), extra...),
		site("example", dom(RootDomain, "duplicate.example")),
		site("Other", dom(RootDomain, "other.example")),
	)
	s, err := ParseSites(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	if s.Len() != 2 {
		t.Fatalf("categories %d, want 2 (duplicate code: first wins)", s.Len())
	}
	got, ok, err := lookup(s, "example")
	if err != nil || !ok || len(got) != 5 {
		t.Fatalf("lookup: %v %v %v", got, ok, err)
	}
	if got[0].Type != RootDomain || got[1].Type != Full || got[2].Type != Plain || got[4].Type != Regex {
		t.Fatalf("types: %+v", got)
	}
	if got, _, _ := lookup(s, "Example@cn"); strings.Join(values(got), ",") != "www.example.net,tracker" {
		t.Fatalf("@cn: %v", values(got))
	}
	// Xray (common/geodata): "!" is part of the attribute key, not a
	// negation, and every attribute must be present.
	if got, _, _ := lookup(s, "example@!cn"); strings.Join(values(got), ",") != "bang.example" {
		t.Fatalf("@!cn must select the literal key !cn: %v", values(got))
	}
	if got, _, _ := lookup(s, "example@cn@ADS"); strings.Join(values(got), ",") != "tracker" {
		t.Fatalf("@cn@ads (conjunction, case-insensitive): %v", values(got))
	}
	if got, _, _ := lookup(s, "example@cn@!ads"); len(got) != 0 {
		t.Fatalf("@cn@!ads: %v", values(got))
	}
	if _, ok, err := lookup(s, "missing"); ok || err != nil {
		t.Fatalf("missing category: %v %v", ok, err)
	}
	if _, _, err := lookup(s, "example@"); err == nil {
		t.Fatal("empty attribute accepted")
	}
}

func TestIPsLookup(t *testing.T) {
	mapped := pbUint(pbBytes(nil, 1, netip.MustParseAddr("::ffff:192.0.2.0").AsSlice()), 2, 120)
	data := list(
		geoip("DIRECT", false, cidr("198.51.100.7/24"), cidr("2001:db8::/32"), mapped),
		geoip("NOT", true, cidr("203.0.113.0/24")),
	)
	s, err := ParseIPs(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	got, reverse, ok, err := lookupIPs(s, "direct")
	if err != nil || !ok || reverse {
		t.Fatalf("lookup: %v %v %v", ok, reverse, err)
	}
	want := []string{"198.51.100.0/24", "2001:db8::/32", "192.0.2.0/24"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if _, reverse, ok, _ := lookupIPs(s, "not"); !ok || !reverse {
		t.Fatal("reverse_match lost")
	}
	if _, _, ok, _ := lookupIPs(s, "missing"); ok {
		t.Fatal("missing category found")
	}
}

func TestMalformedData(t *testing.T) {
	good := list(site("X", dom(RootDomain, "example.com")))
	badIP := pbBytes(nil, 1, []byte{192, 0, 2, 1, 9})
	cases := map[string][]byte{
		"empty":            nil,
		"truncated varint": {0x0a, 0x80},
		"length past end":  {0x0a, 0x7f, 1, 2},
		"overlong varint":  append([]byte{0x08}, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}...),
		"varint overflow":  append([]byte{0x08}, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02}...),
		"group wire type":  {0x0b, 0x0c},
		"field zero":       {0x02, 0x00},
		"no categories":    pbUint(nil, 2, 1),
		"truncated inner":  good[:len(good)-2],
		"domain type":      list(site("X", pbUint(pbBytes(nil, 2, []byte("example.com")), 1, 9))),
		"domain no value":  list(site("X", pbUint(nil, 1, 2))),
		"invalid utf8":     list(site("X\xff", dom(RootDomain, "example.com"))),
		"truncated fixed":  {0x0d, 1, 2},
	}
	for name, data := range cases {
		if _, err := ParseSites(context.Background(), data); err == nil {
			t.Errorf("geosite %s accepted", name)
		}
	}
	ipCases := map[string][]byte{
		"empty":         nil,
		"address bytes": list(geoip("X", false, badIP)),
		"no address":    list(geoip("X", false, pbUint(nil, 2, 24))),
		"prefix":        list(geoip("X", false, pbUint(pbBytes(nil, 1, []byte{192, 0, 2, 0}), 2, 33))),
		"truncated":     list(geoip("X", false, cidr("192.0.2.0/24")))[:5],
	}
	for name, data := range ipCases {
		if _, err := ParseIPs(context.Background(), data); err == nil {
			t.Errorf("geoip %s accepted", name)
		}
	}
	if _, err := ParseSites(context.Background(), good); err != nil {
		t.Fatal(err)
	}
}

func TestDecoderCaps(t *testing.T) {
	oldEntries, oldCategories := maxEntries, maxCategories
	t.Cleanup(func() { maxEntries, maxCategories = oldEntries, oldCategories })
	maxEntries, maxCategories = 3, 2
	if _, err := ParseSites(context.Background(), list(site("A", dom(RootDomain, "a.example")), site("B", dom(RootDomain, "b.example")))); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSites(context.Background(), list(site("A", dom(RootDomain, "a.example"), dom(RootDomain, "b.example")), site("B", dom(RootDomain, "c.example"), dom(RootDomain, "d.example")))); err == nil || !strings.Contains(err.Error(), "entries") {
		t.Fatalf("entry cap: %v", err)
	}
	if _, err := ParseSites(context.Background(), list(site("A"), site("B"), site("C"))); err == nil || !strings.Contains(err.Error(), "categories") {
		t.Fatalf("category cap: %v", err)
	}
	if _, err := ParseIPs(context.Background(), list(geoip("A", false, cidr("192.0.2.0/24"), cidr("198.51.100.0/24"), cidr("203.0.113.0/24"), cidr("192.0.2.128/25")))); err == nil {
		t.Fatal("geoip entry cap not enforced")
	}
}

func TestEachStopsOnCallbackErrorAndCancel(t *testing.T) {
	var doms [][]byte
	for i := 0; i < 3*ctxEvery; i++ {
		doms = append(doms, dom(RootDomain, "a.example"))
	}
	s, err := ParseSites(context.Background(), list(site("BIG", doms...)))
	if err != nil {
		t.Fatal(err)
	}
	stop := errors.New("stop")
	n := 0
	if _, err := s.Each(context.Background(), "big", func(Domain) error { n++; return stop }); err != stop || n != 1 {
		t.Fatalf("callback error: %v after %d", err, n)
	}
	ctx, cancel := context.WithCancel(context.Background())
	n = 0
	_, err = s.Each(ctx, "big", func(Domain) error {
		if n++; n == 10 {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) || n > ctxEvery {
		t.Fatalf("cancel: %v after %d entries", err, n)
	}
	if _, err := ParseSites(ctx, list(site("X", dom(RootDomain, "a.example")))); !errors.Is(err, context.Canceled) {
		t.Fatalf("parse with a cancelled context: %v", err)
	}
}
