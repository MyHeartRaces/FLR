package lan

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func src(cidrs ...string) AddrSource { return FixedSource(cidrs...) }

func TestDiscoverFirstPrivateIPv4(t *testing.T) {
	l, e := DiscoverFrom(src("fe80::1/64", "100.65.1.2/10", "192.168.1.1/24", "10.0.0.1/24"), "br-lan")
	if e != nil || l.Addr.String() != "192.168.1.1" || l.Prefix.String() != "192.168.1.0/24" {
		t.Fatalf("%v %v", l, e)
	}
	l, e = DiscoverFrom(src("10.10.0.1/24"), "br-lan")
	if e != nil || l.String() != "10.10.0.1/24" || l.Prefix.String() != "10.10.0.0/24" {
		t.Fatalf("%v %v", l, e)
	}
}

func TestDiscoverFailures(t *testing.T) {
	for name, s := range map[string]AddrSource{
		"missing":    func(string) ([]net.Addr, error) { return nil, errors.New("no such network interface") },
		"empty":      src(),
		"public":     src("8.8.8.8/24"),
		"cgnat":      src("100.65.1.2/24"),
		"too-wide":   src("10.0.0.1/8"),
		"point":      src("192.168.1.1/31"),
		"ipv6":       src("fd00::1/64"),
		"network":    src("192.168.1.0/24"),
		"broadcast":  src("192.168.1.255/24"),
		"host-route": src("192.168.1.1/32"),
	} {
		if _, e := DiscoverFrom(s, "br-lan"); e == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestResolveFallbackIsVisible(t *testing.T) {
	old := Source
	defer func() { Source = old }()
	Source = func(string) ([]net.Addr, error) { return nil, errors.New("no such network interface") }
	l, e := Resolve("br-lan")
	if e == nil || !strings.Contains(e.Error(), "legacy") || l != Legacy() {
		t.Fatalf("%v %v", l, e)
	}
	Source = src("192.168.1.1/24")
	if l, e = Resolve("br-lan"); e != nil || l.Addr.String() != "192.168.1.1" {
		t.Fatalf("%v %v", l, e)
	}
}

// Regression (f): the cache serves one read per TTL, then reads br-lan again,
// so a LAN that appears or changes is picked up within the TTL.
func TestCacheHonoursTTL(t *testing.T) {
	old := Source
	defer func() { Source = old }()
	reads := 0
	current := []string{}
	Source = func(string) ([]net.Addr, error) {
		reads++
		if len(current) == 0 {
			return nil, errors.New("no IPv4 on br-lan yet")
		}
		return FixedSource(current...)("br-lan")
	}
	now := time.Unix(1000, 0)
	c := NewCache()
	c.Now = func() time.Time { return now }
	if c.TTL != 5*time.Second {
		t.Fatalf("TTL %v", c.TTL)
	}
	if l, e := c.Resolve("br-lan"); e == nil || l != Legacy() || reads != 1 {
		t.Fatalf("%v %v %d", l, e, reads)
	}
	current = []string{"192.168.1.1/24"}
	now = now.Add(4 * time.Second)
	if _, e := c.Resolve("br-lan"); e == nil || reads != 1 {
		t.Fatalf("cached failure not reused within TTL: %v %d", e, reads)
	}
	now = now.Add(time.Second)
	if l, e := c.Resolve("br-lan"); e != nil || l.String() != "192.168.1.1/24" || reads != 2 {
		t.Fatalf("not re-read at TTL: %v %v %d", l, e, reads)
	}
	current = []string{"10.0.0.1/24"}
	for i := 0; i < 10; i++ {
		if l, _ := c.Resolve("br-lan"); l.String() != "192.168.1.1/24" {
			t.Fatal("cached LAN changed within TTL")
		}
	}
	if reads != 2 {
		t.Fatalf("reads %d", reads)
	}
	if _, e := c.Resolve("eth0"); e != nil || reads != 3 {
		t.Fatal("interfaces share a cache entry")
	}
	now = now.Add(-time.Minute)
	if l, _ := c.Resolve("br-lan"); l.String() != "10.0.0.1/24" || reads != 4 {
		t.Fatal("clock moving backwards kept a stale entry")
	}
	c.Flush()
	c.Resolve("br-lan")
	if reads != 5 {
		t.Fatal("flush kept an entry")
	}
	c.TTL = 0
	c.Resolve("br-lan")
	c.Resolve("br-lan")
	if reads != 7 {
		t.Fatalf("zero TTL cached: %d", reads)
	}
}

func TestValidate(t *testing.T) {
	if Legacy().Validate() != nil || Legacy().String() != "192.168.8.1/24" {
		t.Fatal("legacy invalid")
	}
	p := netip.MustParsePrefix
	a := netip.MustParseAddr
	bad := []LAN{
		{},
		{a("8.8.8.1"), p("8.8.8.0/24")},
		{a("192.168.1.1"), p("192.168.1.0/15")},
		{a("192.168.1.1"), p("192.168.1.0/31")},
		{a("192.168.2.1"), p("192.168.1.0/24")},
		{a("192.168.1.0"), p("192.168.1.0/24")},
		{a("192.168.1.255"), p("192.168.1.0/24")},
		{a("192.168.1.1"), p("192.168.1.1/24")},
		{a("fd00::1"), p("fd00::/64")},
	}
	for _, l := range bad {
		if l.Validate() == nil {
			t.Fatalf("accepted %v", l)
		}
	}
	for _, c := range []string{"192.168.1.1/24", "10.10.0.1/24", "172.16.0.254/16", "10.0.0.1/30"} {
		pp := netip.MustParsePrefix(c)
		if _, e := New(pp.Addr(), pp.Bits()); e != nil {
			t.Fatalf("%s: %v", c, e)
		}
	}
}

func TestClientHelpers(t *testing.T) {
	l, _ := New(netip.MustParseAddr("192.168.1.1"), 24)
	for ip, want := range map[string]bool{
		"192.168.1.2": true, "192.168.1.254": true, "192.168.1.1": false, "192.168.1.0": false,
		"192.168.1.255": false, "192.168.8.2": false, "8.8.8.8": false, "::1": false,
	} {
		if got := l.IsClient(netip.MustParseAddr(ip)); got != want {
			t.Fatalf("%s: %v", ip, got)
		}
	}
	if !l.Contains(netip.MustParseAddr("192.168.1.1")) || l.Contains(netip.MustParseAddr("192.168.2.1")) {
		t.Fatal("contains")
	}
	w, _ := New(netip.MustParseAddr("10.1.0.1"), 22)
	if w.Broadcast().String() != "10.1.3.255" || w.Network().String() != "10.1.0.0" {
		t.Fatal(w.Broadcast())
	}
}

func TestParseUCI(t *testing.T) {
	for _, tc := range []struct{ ip, mask, want string }{
		{"192.168.1.1", "255.255.255.0", "192.168.1.1/24"},
		{"192.168.1.1/24", "", "192.168.1.1/24"},
		{"10.10.0.1", "255.255.255.0", "10.10.0.1/24"},
	} {
		l, e := ParseUCI(tc.ip, tc.mask)
		if e != nil || l.String() != tc.want {
			t.Fatalf("%v %v", l, e)
		}
	}
	for _, tc := range [][2]string{{"x", "255.255.255.0"}, {"192.168.1.1", ""}, {"192.168.1.1", "255.0.255.0"}, {"8.8.8.8", "255.255.255.0"}} {
		if _, e := ParseUCI(tc[0], tc[1]); e == nil {
			t.Fatalf("accepted %v", tc)
		}
	}
}
