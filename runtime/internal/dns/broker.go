package dns

import (
	"context"
	"fmt"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/lan"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
	mdns "github.com/miekg/dns"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

type RouteProvider interface {
	DNSRoute(contract.Class) (contract.Channel, uint64)
}
type StaticRoute struct{ Channel contract.Channel }

func (s StaticRoute) DNSRoute(_ contract.Class) (contract.Channel, uint64) { return s.Channel, 1 }

type Broker struct {
	pol       atomic.Pointer[policy.Policy]
	routes    RouteProvider
	mappings  MappingWriter
	cache     *Cache
	LocalPort string
	WAN       string
	// Router is the router's own LAN address, excluded from the upstream
	// resolvers. Set it before Serve; while serving use SetRouter. When neither
	// is set it is read from the LAN interface.
	Router netip.Addr
	router atomic.Pointer[netip.Addr]
	sem    chan struct{}
}

// SetRouter updates the router's LAN address while the broker is serving. An
// invalid address is ignored, so the last known address or the fallback stays.
func (b *Broker) SetRouter(a netip.Addr) {
	if a.IsValid() {
		b.router.Store(&a)
	}
}

// SetPolicy switches the policy used for new answers (a routing mode change)
// and rebinds every outstanding address under it, in both directions, so the
// direct and VPN sets follow the new mode for new flows. Established flows
// keep their marks. A failed kernel rewrite is returned; the in-memory
// bindings are already reclassified, so the next rewrite converges.
func (b *Broker) SetPolicy(p *policy.Policy) error {
	if p == nil {
		return nil
	}
	b.pol.Store(p)
	if c, ok := b.mappings.(interface{ SetClassifier(Classifier) error }); ok {
		return c.SetClassifier(ClassifierFor(p))
	}
	return nil
}

// ClassifierFor classifies issued addresses exactly like Resolve does for the
// global view: the domain decision, and for unlisted domains the static
// direct CIDRs per address. Local names get no binding.
func ClassifierFor(p *policy.Policy) Classifier {
	return func(name string, v View, ip netip.Addr) (View, bool) {
		class, source := p.DomainDecision(name)
		if class == contract.Local {
			return View{}, false
		}
		id := string(class)
		if class == contract.General && source == "" && p.ClassifyIP(ip) == contract.Direct {
			id, class, source = string(contract.General)+"-ip-direct", contract.Direct, "roscom-direct-ips"
		}
		return View{ID: id, Generation: v.Generation, Class: class, Source: source, Channel: v.Channel}, true
	}
}

func New(p *policy.Policy, r RouteProvider, m MappingWriter) *Broker {
	b := &Broker{routes: r, mappings: m, cache: NewCache(), LocalPort: "1053", WAN: "eth1", sem: make(chan struct{}, 64)}
	if p != nil {
		b.pol.Store(p)
	}
	return b
}
func Decode(b []byte) (*mdns.Msg, error) {
	if len(b) < 12 || len(b) > 65535 {
		return nil, fmt.Errorf("invalid DNS size")
	}
	q := new(mdns.Msg)
	if e := q.Unpack(b); e != nil {
		return nil, e
	}
	if q.Response || q.Opcode != mdns.OpcodeQuery || len(q.Question) != 1 {
		return nil, fmt.Errorf("invalid DNS question")
	}
	return q, nil
}

// routerLAN bounds the LAN interface reads of routerAddr to one per
// lan.CacheTTL while the controller has not set the router address yet.
var routerLAN = lan.NewCache()

// routerAddr is the router's own LAN address to exclude from the upstream
// resolvers. Until the controller sets it, the LAN interface is read through
// routerLAN; while discovery fails the address is invalid and nothing is
// excluded (the legacy fallback is never mistaken for the router).
func (b *Broker) routerAddr() netip.Addr {
	if a := b.router.Load(); a != nil {
		return *a
	}
	if b.Router.IsValid() {
		return b.Router
	}
	l, e := routerLAN.Resolve(lan.Interface)
	if e != nil {
		return netip.Addr{}
	}
	return l.Addr
}
func wanResolvers(router netip.Addr) []string {
	b, e := os.ReadFile("/tmp/resolv.conf.d/resolv.conf.auto")
	if e != nil {
		return nil
	}
	return parseResolvers(b, router)
}

// parseResolvers lists the IPv4 nameservers of a resolv.conf, skipping
// loopback and the router's own LAN address (none when router is invalid).
func parseResolvers(b []byte, router netip.Addr) []string {
	out := []string{}
	for _, line := range strings.Split(string(b), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 && parts[0] == "nameserver" {
			if a, e := netip.ParseAddr(parts[1]); e == nil && a.Is4() && !a.IsLoopback() && a != router {
				out = append(out, parts[1]+":53")
			}
		}
	}
	return out
}
func (b *Broker) Resolve(ctx context.Context, q *mdns.Msg, view View) (*mdns.Msg, error) {
	if q.Response || len(q.Question) != 1 || q.Opcode != mdns.OpcodeQuery {
		return nil, fmt.Errorf("invalid query")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	q = q.Copy()
	q.CheckingDisabled = false
	if opt := q.IsEdns0(); opt != nil {
		clean := []mdns.EDNS0{}
		for _, v := range opt.Option {
			if v.Option() != mdns.EDNS0SUBNET {
				clean = append(clean, v)
			}
		}
		opt.Option = clean
	}
	name := strings.ToLower(q.Question[0].Name)
	class, source := view.Class, view.Source
	if view.ID == "" {
		pol := b.pol.Load()
		if pol == nil {
			return nil, fmt.Errorf("missing DNS policy")
		}
		class, source = pol.DomainDecision(name)
	}
	if view.ID == "" {
		channel, gen := b.routes.DNSRoute(class)
		view = View{ID: string(class), Generation: gen, Class: class, Source: source, Channel: channel}
	}
	var r *mdns.Msg
	var e error
	r, hit := b.cache.Get(view, q, time.Now())
	if !hit {
		var list []Exchange
		switch view.Class {
		case contract.Local:
			list = append(list, func(ctx context.Context, m *mdns.Msg) (*mdns.Msg, error) {
				return Plain(ctx, m, "127.0.0.1:"+b.LocalPort, 0, "")
			})
		case contract.Direct:
			for _, server := range wanResolvers(b.routerAddr()) {
				addr := server
				mark := contract.OuterMark
				if strings.HasPrefix(view.ID, "session:") {
					mark |= contract.ProbeMark
				}
				list = append(list, func(ctx context.Context, m *mdns.Msg) (*mdns.Msg, error) {
					return Plain(ctx, m, addr, mark, b.WAN)
				})
			}
		default:
			if view.Channel == contract.Down {
				return nil, fmt.Errorf("no healthy VPN DNS route")
			}
			for _, provider := range []struct{ ip, host string }{{"1.1.1.1", "cloudflare-dns.com"}, {"9.9.9.10", "dns10.quad9.net"}, {"1.0.0.1", "cloudflare-dns.com"}, {"149.112.112.10", "dns10.quad9.net"}} {
				pr := provider
				list = append(list, func(ctx context.Context, m *mdns.Msg) (*mdns.Msg, error) {
					return DoH(ctx, m, view.Channel, pr.ip, pr.host)
				})
			}
		}
		r, e = Fallback(ctx, q, list)
		if e != nil {
			return nil, e
		}
	}
	ClampReply(r)
	rs, e := AnswerRecords(r)
	if e != nil {
		return nil, e
	}
	if q.Question[0].Qtype == mdns.TypeA && view.Class != contract.Local && !strings.HasPrefix(view.ID, "session:") && view.Source != "device-profile" && b.mappings != nil {
		if source == "" && view.Class == contract.General {
			var direct, vpn []AddressTTL
			for _, record := range rs {
				if b.pol.Load().ClassifyIP(record.IP) == contract.Direct {
					direct = append(direct, record)
				} else {
					vpn = append(vpn, record)
				}
			}
			if e = b.mappings.Replace(view, name, vpn); e != nil {
				return nil, e
			}
			v := view
			v.ID += "-ip-direct"
			v.Class = contract.Direct
			// Named after the static list it came from, so a routing mode that
			// switches that list off can drop these bindings (SetPolicy).
			v.Source = "roscom-direct-ips"
			if e = b.mappings.Replace(v, name, direct); e != nil {
				return nil, e
			}
		} else if e = b.mappings.Replace(view, name, rs); e != nil {
			return nil, e
		}
	}
	if !hit {
		b.cache.Put(view, q, r, time.Now())
	}
	r.Id = q.Id
	return r, nil
}
func (b *Broker) Serve(ctx context.Context, addr string) error {
	handler := mdns.HandlerFunc(func(w mdns.ResponseWriter, q *mdns.Msg) {
		select {
		case b.sem <- struct{}{}:
			defer func() { <-b.sem }()
		default:
			r := new(mdns.Msg)
			r.SetRcode(q, mdns.RcodeServerFailure)
			w.WriteMsg(r)
			return
		}
		view := View{}
		if provider, ok := b.routes.(interface {
			ClientView(string, string) (View, bool)
		}); ok && len(q.Question) == 1 {
			client, _, _ := net.SplitHostPort(w.RemoteAddr().String())
			if v, yes := provider.ClientView(client, q.Question[0].Name); yes {
				view = v
			}
		}
		r, e := b.Resolve(ctx, q, view)
		if e != nil {
			r = new(mdns.Msg)
			r.SetRcode(q, mdns.RcodeServerFailure)
		}
		w.WriteMsg(r)
	})
	servers := []*mdns.Server{{Addr: addr, Net: "udp4", Handler: handler, UDPSize: 4096, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}, {Addr: addr, Net: "tcp4", Handler: handler, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}}
	done := make(chan error, 2)
	for _, s := range servers {
		go func(s *mdns.Server) { done <- s.ListenAndServe() }(s)
	}
	var e error
	select {
	case <-ctx.Done():
		e = ctx.Err()
	case e = <-done:
	}
	for _, s := range servers {
		s.Shutdown()
	}
	return e
}
