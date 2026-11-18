package dns

import (
	"errors"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/lan"
)

// Finding 6: while the controller has not set the router address, direct DNS
// queries read the LAN interface at most once per cache TTL, and an unknown
// LAN excludes nothing instead of the legacy 192.168.8.1.
func TestRouterAddrCachedAndNothingExcludedWhileLANUnknown(t *testing.T) {
	oldSource, oldCache := lan.Source, routerLAN
	t.Cleanup(func() { lan.Source, routerLAN = oldSource, oldCache })
	now := time.Unix(1000, 0)
	routerLAN = &lan.Cache{TTL: lan.CacheTTL, Now: func() time.Time { return now }}
	reads := 0
	lan.Source = func(string) ([]net.Addr, error) {
		reads++
		return nil, errors.New("LAN interface br-lan has no private IPv4 address")
	}
	b := New(nil, StaticRoute{}, nil)
	for i := 0; i < 100; i++ {
		if a := b.routerAddr(); a.IsValid() {
			t.Fatal("legacy fallback used as the router address", a)
		}
	}
	if reads != 1 {
		t.Fatal("LAN interface read on every query", reads)
	}
	conf := []byte("nameserver 192.168.8.1\nnameserver 10.0.0.53\nnameserver 127.0.0.1\nnameserver ::1\n")
	if got := parseResolvers(conf, b.routerAddr()); !reflect.DeepEqual(got, []string{"192.168.8.1:53", "10.0.0.53:53"}) {
		t.Fatal("unknown LAN excluded a resolver", got)
	}
	// The LAN appears: it is picked up after the TTL and its address excluded.
	lan.Source = func(name string) ([]net.Addr, error) {
		reads++
		return lan.FixedSource("192.168.1.1/24")(name)
	}
	now = now.Add(time.Second)
	if a := b.routerAddr(); a.IsValid() || reads != 1 {
		t.Fatal("cache TTL not honoured", a, reads)
	}
	now = now.Add(lan.CacheTTL)
	if a := b.routerAddr(); a != netip.MustParseAddr("192.168.1.1") || reads != 2 {
		t.Fatal("discovered LAN not used", a, reads)
	}
	if got := parseResolvers([]byte("nameserver 192.168.1.1\nnameserver 10.0.0.53\n"), b.routerAddr()); !reflect.DeepEqual(got, []string{"10.0.0.53:53"}) {
		t.Fatal("router address not excluded", got)
	}
	// Once the controller sets the address, the interface is not read at all.
	b.SetRouter(netip.MustParseAddr("10.0.0.1"))
	now = now.Add(time.Hour)
	if a := b.routerAddr(); a != netip.MustParseAddr("10.0.0.1") || reads != 2 {
		t.Fatal("controller address not preferred", a, reads)
	}
}
