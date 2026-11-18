// Package lan describes the router's IPv4 LAN (address and prefix) as read
// from the live system, so the controller does not assume a fixed subnet.
package lan

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Interface is the LAN bridge on the supported router image.
const Interface = "br-lan"

// legacyCIDR is the former built-in LAN. It is used only by Resolve when
// discovery fails, and that failure is always returned to the caller.
const legacyCIDR = "192.168.8.1/24"

// LAN is the router's own address on its LAN together with the LAN prefix.
type LAN struct {
	Addr   netip.Addr
	Prefix netip.Prefix
}

// Legacy returns the historical 192.168.8.1/24 LAN.
func Legacy() LAN {
	p := netip.MustParsePrefix(legacyCIDR)
	return LAN{Addr: p.Addr(), Prefix: p.Masked()}
}

// New builds a LAN from the router address and prefix length and validates it.
func New(addr netip.Addr, bits int) (LAN, error) {
	l := LAN{Addr: addr, Prefix: netip.PrefixFrom(addr, bits).Masked()}
	return l, l.Validate()
}

// IsZero reports whether the LAN is unset.
func (l LAN) IsZero() bool { return !l.Addr.IsValid() && !l.Prefix.IsValid() }

func (l LAN) String() string {
	if l.IsZero() {
		return ""
	}
	return fmt.Sprintf("%s/%d", l.Addr, l.Prefix.Bits())
}

// Validate requires a private IPv4 LAN of /16../30 whose router address is a
// usable host inside the prefix.
func (l LAN) Validate() error {
	if !l.Addr.IsValid() || !l.Addr.Is4() || !l.Prefix.IsValid() || !l.Prefix.Addr().Is4() {
		return fmt.Errorf("LAN must be IPv4")
	}
	if !l.Addr.IsPrivate() {
		return fmt.Errorf("LAN address %s is not private (RFC 1918)", l.Addr)
	}
	if b := l.Prefix.Bits(); b < 16 || b > 30 {
		return fmt.Errorf("LAN prefix length /%d outside /16../30", l.Prefix.Bits())
	}
	if l.Prefix != l.Prefix.Masked() || !l.Prefix.Contains(l.Addr) {
		return fmt.Errorf("LAN address %s is not inside %s", l.Addr, l.Prefix)
	}
	if l.Addr == l.Network() || l.Addr == l.Broadcast() {
		return fmt.Errorf("LAN address %s is the network or broadcast address", l.Addr)
	}
	return nil
}

// Network returns the all-zero host address of the prefix.
func (l LAN) Network() netip.Addr { return l.Prefix.Masked().Addr() }

// Broadcast returns the all-ones host address of the prefix.
func (l LAN) Broadcast() netip.Addr {
	a := l.Prefix.Masked().Addr().As4()
	host := 32 - l.Prefix.Bits()
	for i := 3; i >= 0 && host > 0; i-- {
		n := host
		if n > 8 {
			n = 8
		}
		a[i] |= byte(0xff >> (8 - n))
		host -= n
	}
	return netip.AddrFrom4(a)
}

// Contains reports whether ip is inside the LAN prefix.
func (l LAN) Contains(ip netip.Addr) bool {
	return ip.IsValid() && ip.Is4() && l.Prefix.IsValid() && l.Prefix.Contains(ip)
}

// IsClient reports whether ip can be a LAN client: inside the prefix and not
// the router, network or broadcast address.
func (l LAN) IsClient(ip netip.Addr) bool {
	return l.Contains(ip) && ip != l.Addr && ip != l.Network() && ip != l.Broadcast()
}

// AddrSource lists the addresses of a network interface.
type AddrSource func(ifname string) ([]net.Addr, error)

// Source is the production address source; tests replace it.
var Source AddrSource = func(ifname string) ([]net.Addr, error) {
	ifc, e := net.InterfaceByName(ifname)
	if e != nil {
		return nil, e
	}
	return ifc.Addrs()
}

// Discover returns the first valid private IPv4 address and prefix on ifname.
func Discover(ifname string) (LAN, error) { return DiscoverFrom(Source, ifname) }

// DiscoverFrom is Discover with an explicit address source.
func DiscoverFrom(src AddrSource, ifname string) (LAN, error) {
	addrs, e := src(ifname)
	if e != nil {
		return LAN{}, fmt.Errorf("LAN interface %s: %w", ifname, e)
	}
	var first error
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if !ip.Is4() || !ip.IsPrivate() {
			continue
		}
		ones, bits := n.Mask.Size()
		if bits != 32 {
			continue
		}
		l, err := New(ip, ones)
		if err == nil {
			return l, nil
		}
		if first == nil {
			first = err
		}
	}
	if first != nil {
		return LAN{}, fmt.Errorf("LAN interface %s: %w", ifname, first)
	}
	return LAN{}, fmt.Errorf("LAN interface %s has no private IPv4 address", ifname)
}

// Resolve discovers the LAN on ifname. When discovery fails it returns the
// legacy LAN together with a non-nil error: callers must surface the error and
// must not treat the fallback as a confirmed configuration.
func Resolve(ifname string) (LAN, error) {
	l, e := Discover(ifname)
	if e != nil {
		return Legacy(), fmt.Errorf("%w; using legacy %s", e, legacyCIDR)
	}
	return l, nil
}

// CacheTTL is how long a Cache reuses a result before it reads the interface
// again. It bounds both the netlink load of per-request callers and the time
// it takes them to notice a LAN that appeared or changed.
const CacheTTL = 5 * time.Second

// Cache memoizes Resolve per interface for TTL. Failures are cached as well,
// so a LAN interface without an address is not re-read on every request. A
// zero TTL disables caching. Set TTL and Now before first use.
type Cache struct {
	TTL time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time

	mu      sync.Mutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	at  time.Time
	lan LAN
	err error
}

// NewCache returns a Cache with CacheTTL.
func NewCache() *Cache { return &Cache{TTL: CacheTTL} }

// Resolve is lan.Resolve through the cache: a non-nil error means discovery
// failed and the returned LAN is the legacy fallback.
func (c *Cache) Resolve(ifname string) (LAN, error) {
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[ifname]; ok && !now.Before(e.at) && now.Sub(e.at) < c.TTL {
		return e.lan, e.err
	}
	l, err := Resolve(ifname)
	if c.entries == nil {
		c.entries = map[string]cacheEntry{}
	}
	c.entries[ifname] = cacheEntry{at: now, lan: l, err: err}
	return l, err
}

// Flush drops every cached result.
func (c *Cache) Flush() {
	c.mu.Lock()
	c.entries = nil
	c.mu.Unlock()
}

// ParseUCI builds a LAN from UCI network.lan.ipaddr and netmask. ipaddr may be
// plain (with a dotted netmask) or CIDR ("192.168.1.1/24").
func ParseUCI(ipaddr, netmask string) (LAN, error) {
	ipaddr = strings.TrimSpace(ipaddr)
	if i := strings.IndexByte(ipaddr, '/'); i >= 0 {
		p, e := netip.ParsePrefix(ipaddr)
		if e != nil {
			return LAN{}, fmt.Errorf("invalid UCI LAN address: %w", e)
		}
		return New(p.Addr(), p.Bits())
	}
	ip, e := netip.ParseAddr(ipaddr)
	if e != nil {
		return LAN{}, fmt.Errorf("invalid UCI LAN address: %w", e)
	}
	m := net.ParseIP(strings.TrimSpace(netmask)).To4()
	if m == nil {
		return LAN{}, fmt.Errorf("invalid UCI LAN netmask")
	}
	ones, bits := net.IPMask(m).Size()
	if bits != 32 {
		return LAN{}, fmt.Errorf("invalid UCI LAN netmask")
	}
	return New(ip, ones)
}

// FixedSource returns an AddrSource that reports the given CIDRs (host address
// plus prefix length, e.g. "192.168.1.1/24") on any interface. It is meant for
// tests of packages that read the LAN through Source.
func FixedSource(cidrs ...string) AddrSource {
	return func(string) ([]net.Addr, error) {
		var out []net.Addr
		for _, c := range cidrs {
			ip, n, e := net.ParseCIDR(c)
			if e != nil {
				return nil, e
			}
			n.IP = ip
			out = append(out, n)
		}
		return out, nil
	}
}
