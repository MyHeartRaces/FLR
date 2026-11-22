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
	"sync"
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
	policyMu  sync.RWMutex
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
	// FilterPath is an optional hashed name filter (see Filter) applied to
	// client queries. Set it before Serve; the file is reloaded when it
	// changes and a removed file disables the filter.
	FilterPath string
	filter     atomic.Pointer[Filter]
}

// SetFilter replaces the client query filter; nil disables it.
func (b *Broker) SetFilter(f *Filter) { b.filter.Store(f) }

// filterReload is how often Serve checks the filter file for changes.
var filterReload = 30 * time.Second

// watchFilter loads the filter file and reloads it when it changes. A file
// that fails to parse keeps the previous filter; a removed file clears it.
func (b *Broker) watchFilter(ctx context.Context, path string) {
	var last filterStamp
	load := func() {
		st := statFilter(path)
		if st == last {
			return
		}
		f, e := LoadFilter(path)
		if e != nil {
			return
		}
		last = st
		b.SetFilter(f)
	}
	load()
	go func() {
		t := time.NewTicker(filterReload)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				load()
			}
		}
	}()
}

// ResolveClient answers a client query: the filter first, then Resolve.
// Blocked names get NXDOMAIN; a rewritten name is answered as a CNAME to its
// target followed by the target's records for the same type.
func (b *Broker) ResolveClient(ctx context.Context, q *mdns.Msg, view View) (*mdns.Msg, error) {
	if p := b.pol.Load(); p != nil && p.Bypass() {
		return nil, fmt.Errorf("FLR DNS is suspended in Direct mode")
	}
	f := b.filter.Load()
	if f == nil || len(q.Question) != 1 {
		return b.Resolve(ctx, q, view)
	}
	act, target := f.Decide(q.Question[0].Name)
	switch act {
	case FilterBlock:
		r := new(mdns.Msg)
		r.SetRcode(q, mdns.RcodeNameError)
		r.RecursionAvailable = true
		return r, nil
	case FilterRewrite:
		name := q.Question[0].Name
		if q.Question[0].Qtype != mdns.TypeA && routingNeedsAddress(b.pol.Load(), name, view) {
			return emptyReply(q), nil
		}
		cname := &mdns.CNAME{Hdr: mdns.RR_Header{Name: q.Question[0].Name, Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: 300}, Target: mdns.Fqdn(target)}
		if q.Question[0].Qtype == mdns.TypeCNAME {
			r := new(mdns.Msg)
			r.SetReply(q)
			r.RecursionAvailable = true
			r.Answer = []mdns.RR{cname}
			return r, nil
		}
		q2 := q.Copy()
		q2.Question[0].Name = mdns.Fqdn(target)
		r2, e := b.resolve(ctx, q2, view, name)
		if e != nil {
			return nil, e
		}
		r := r2.Copy()
		if len(r.Answer) == 0 && routingNeedsAddress(b.pol.Load(), name, view) {
			r.Question, r.Id = q.Question, q.Id
			return r, nil
		}
		// The CNAME is ours, not signed or served by an authority.
		for _, rr := range r.Answer {
			cname.Hdr.Ttl = min(cname.Hdr.Ttl, rr.Header().Ttl)
		}
		r.AuthenticatedData = false
		r.Authoritative = false
		r.Question = q.Question
		r.Answer = append([]mdns.RR{cname}, r.Answer...)
		r.Id = q.Id
		return r, nil
	}
	return b.Resolve(ctx, q, view)
}

// DohServer is a DNS-over-HTTPS upstream: its address and TLS name.
type DohServer struct{ IP, Host string }

// DirectDoH resolves names that leave through the ISP: Yandex DNS (basic
// mode) over HTTPS, which works from Russian networks and keeps answers
// local for domestic services.
var DirectDoH = []DohServer{{"77.88.8.8", "common.dot.dns.yandex.net"}, {"77.88.8.1", "common.dot.dns.yandex.net"}}

// SetRouter updates the router's LAN address while the broker is serving. An
// invalid address is ignored, so the last known address or the fallback stays.
func (b *Broker) SetRouter(a netip.Addr) {
	if a.IsValid() {
		b.router.Store(&a)
	}
}

// ApplyPolicy publishes the static policy and DNS bindings together before new
// answers use the new policy. In-flight answers retry if the policy changes.
func (b *Broker) ApplyPolicy(p *policy.Policy, static string) error {
	c, ok := b.mappings.(interface {
		ApplyPolicy(Classifier, string) error
	})
	if !ok {
		return fmt.Errorf("DNS mappings cannot publish routing policy")
	}
	b.policyMu.Lock()
	defer b.policyMu.Unlock()
	if err := c.ApplyPolicy(ClassifierFor(p), static); err != nil {
		return err
	}
	b.pol.Store(p)
	return nil
}

// ClassifierFor classifies issued addresses exactly like Resolve does for the
// global view: the domain decision, and for unlisted domains the static
// direct CIDRs per address. Local names get no binding.
func ClassifierFor(p *policy.Policy) Classifier {
	return func(name string, v View, ip netip.Addr) (View, bool) {
		class, source := domainDecision(p, name, v.Alias)
		if class == contract.Local {
			return View{}, false
		}
		id := string(class)
		if class == contract.General && source == "" && p.ClassifyIP(ip) == contract.Direct {
			id, class, source = string(contract.General)+"-ip-direct", contract.Direct, "roscom-direct-ips"
		}
		return View{ID: id, Generation: v.Generation, Class: class, Source: source, Channel: v.Channel, Alias: v.Alias}, true
	}
}

func domainDecision(p *policy.Policy, name, alias string) (contract.Class, string) {
	class, source := p.DomainDecision(name)
	if alias == "" || class == contract.Local {
		return class, source
	}
	targetClass, targetSource := p.DomainDecision(alias)
	if targetClass != contract.Local && source != "" && (class == contract.General || class == contract.Games) {
		return class, source
	}
	return targetClass, targetSource
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
	return b.resolve(ctx, q, view, "")
}

func aliasQuery(qtype uint16) bool {
	switch qtype {
	case mdns.TypeHTTPS, mdns.TypeSVCB, mdns.TypeCNAME, mdns.TypeDNAME, mdns.TypeAAAA, mdns.TypeANY:
		return true
	}
	return false
}

func routingNeedsAddress(p *policy.Policy, name string, view View) bool {
	if p == nil || p.DefaultClass() != contract.Direct || view.Source == "device-profile" || strings.HasPrefix(view.ID, "session:") {
		return false
	}
	class := view.Class
	if view.ID == "" {
		class = p.ClassifyDomain(name)
	}
	return class == contract.General || class == contract.Games
}

func emptyReply(q *mdns.Msg) *mdns.Msg {
	r := new(mdns.Msg)
	r.SetReply(q)
	r.RecursionAvailable = true
	return r
}

// rewrittenFrom keeps protected names protected when the DNS filter rewrites
// them to another host. The query still asks upstream for the rewrite target.
func (b *Broker) resolve(ctx context.Context, q *mdns.Msg, view View, rewrittenFrom string) (*mdns.Msg, error) {
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
	name, alias := strings.ToLower(q.Question[0].Name), ""
	pol := b.pol.Load()
	if rewrittenFrom != "" {
		name, alias = strings.ToLower(rewrittenFrom), name
	}
	class, source := view.Class, view.Source
	if view.ID == "" {
		if pol == nil {
			return nil, fmt.Errorf("missing DNS policy")
		}
		class, source = domainDecision(pol, name, alias)
	}
	if view.ID == "" {
		channel, gen := b.routes.DNSRoute(class)
		view = View{ID: string(class), Generation: gen, Class: class, Source: source, Channel: channel}
	}
	view.Alias = alias
	protectedName := routingNeedsAddress(pol, name, view)
	if protectedName && aliasQuery(q.Question[0].Qtype) {
		// Clients must obtain an A record so the broker can install the VPN
		// binding before an IPv4 connection. Service bindings can skip that lookup.
		return emptyReply(q), nil
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
			mark := contract.OuterMark
			if strings.HasPrefix(view.ID, "session:") {
				mark |= contract.ProbeMark
			}
			// Encrypted DNS over the WAN first, so the ISP can neither see
			// nor rewrite direct names; the ISP resolvers stay as fallback.
			for _, provider := range DirectDoH {
				pr := provider
				list = append(list, func(ctx context.Context, m *mdns.Msg) (*mdns.Msg, error) {
					return DoHDirect(ctx, m, pr.IP, pr.Host, mark, b.WAN)
				})
			}
			for _, server := range wanResolvers(b.routerAddr()) {
				addr := server
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
	var minTTL uint32
	if protectedName {
		// A zero-TTL answer can still be used immediately for one connection.
		minTTL = 5
	}
	rs, e := answerRecords(r, minTTL)
	if e != nil {
		return nil, e
	}
	b.policyMu.RLock()
	defer b.policyMu.RUnlock()
	if pol != b.pol.Load() {
		return nil, fmt.Errorf("routing policy changed during DNS lookup")
	}
	if protectedName {
		var ipv4 bool
		for _, record := range rs {
			ipv4 = ipv4 || record.IP.Is4()
		}
		unboundAlias := false
		for _, rr := range r.Answer {
			kind := rr.Header().Rrtype
			unboundAlias = unboundAlias || kind == mdns.TypeCNAME || kind == mdns.TypeDNAME
		}
		if !ipv4 && unboundAlias {
			// Do not send a standalone alias that could lead to a direct A lookup.
			code := r.Rcode
			r = emptyReply(q)
			r.Rcode = code
		}
	}
	if (q.Question[0].Qtype == mdns.TypeA || protectedName) && view.Class != contract.Local && !strings.HasPrefix(view.ID, "session:") && view.Source != "device-profile" && b.mappings != nil {
		if source == "" && view.Class == contract.General {
			var direct, vpn []AddressTTL
			for _, record := range rs {
				if pol != nil && pol.ClassifyIP(record.IP) == contract.Direct {
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
			// Publication reclassifies bindings that came from a disabled list.
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
	done, err := b.Start(ctx, addr)
	if err != nil {
		return err
	}
	return <-done
}

// Start binds both DNS sockets before returning. Cancel ctx and wait for the
// returned channel before starting another resolver on the same port.
func (b *Broker) Start(ctx context.Context, addr string) (<-chan error, error) {
	udp, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return nil, err
	}
	tcp, err := net.Listen("tcp4", udp.LocalAddr().String())
	if err != nil {
		udp.Close()
		return nil, err
	}
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
		r, e := b.ResolveClient(ctx, q, view)
		if e != nil {
			r = new(mdns.Msg)
			r.SetRcode(q, mdns.RcodeServerFailure)
		}
		w.WriteMsg(r)
	})
	ready := make(chan struct{}, 2)
	started := func() { ready <- struct{}{} }
	servers := []*mdns.Server{
		{PacketConn: udp, Handler: handler, UDPSize: 4096, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, NotifyStartedFunc: started},
		{Listener: tcp, Handler: handler, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, NotifyStartedFunc: started},
	}
	stopped := make(chan error, len(servers))
	for _, s := range servers {
		go func() { stopped <- s.ActivateAndServe() }()
	}
	for range servers {
		select {
		case <-ready:
		case err := <-stopped:
			udp.Close()
			tcp.Close()
			if err == nil {
				err = fmt.Errorf("DNS listener exited during startup")
			}
			return nil, err
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	if b.FilterPath != "" {
		b.watchFilter(ctx, b.FilterPath)
	}
	done := make(chan error, 1)
	go func() {
		var err error
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case err = <-stopped:
		}
		cancel()
		for _, s := range servers {
			s.Shutdown()
		}
		done <- err
		close(done)
	}()
	return done, nil
}
