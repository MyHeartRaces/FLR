package dns

import (
	"context"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
	mdns "github.com/miekg/dns"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func rr(s string) mdns.RR {
	r, e := mdns.NewRR(s)
	if e != nil {
		panic(e)
	}
	return r
}
func TestCNAMEUsesMinimumTTLAndRejectsUnrelatedAnswers(t *testing.T) {
	m := new(mdns.Msg)
	m.SetQuestion("a.example.", mdns.TypeA)
	m.Response = true
	m.Answer = []mdns.RR{rr("a.example. 20 IN CNAME b.example."), rr("b.example. 300 IN A 8.8.8.8"), rr("unrelated.example. 1 IN A 9.9.9.9")}
	records, e := AnswerRecords(m)
	if e != nil {
		t.Fatal(e)
	}
	if len(records) != 1 || records[0].TTL != 20*time.Second || records[0].IP.String() != "8.8.8.8" {
		t.Fatalf("unsafe CNAME mapping: %+v", records)
	}
	m.Answer[0].Header().Ttl = 0
	records, e = AnswerRecords(m)
	if e != nil {
		t.Fatal(e)
	}
	if len(records) != 0 {
		t.Fatal("TTL0 retained beyond response")
	}
}
func TestCompressedPointerLoopAndInvalidQuestionsRejected(t *testing.T) {
	packet := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1}
	if _, e := Decode(packet); e == nil {
		t.Fatal("compression loop accepted")
	}
	m := new(mdns.Msg)
	m.SetQuestion("example.com.", mdns.TypeA)
	m.Question = append(m.Question, m.Question[0])
	b, _ := m.Pack()
	if _, e := Decode(b); e == nil {
		t.Fatal("ambiguous multi-question request accepted")
	}
}
func TestSharedIPVPNBindingWinsAndRenewalSurvivesOldExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	s := NewBindings()
	ip := netip.MustParseAddr("8.8.8.8")
	s.Replace(now, View{ID: "direct", Class: contract.Direct}, "bank.example", []AddressTTL{{IP: ip, TTL: 10 * time.Second}})
	s.Replace(now, View{ID: "vpn", Class: contract.General}, "vpn.example", []AddressTTL{{IP: ip, TTL: 5 * time.Second}})
	if got := s.Snapshot(now)[ip].Class; got != contract.General {
		t.Fatal("direct CDN binding overrode VPN", got)
	}
	s.Replace(now.Add(4*time.Second), View{ID: "vpn", Class: contract.General}, "vpn.example", []AddressTTL{{IP: ip, TTL: 20 * time.Second}})
	if got := s.Snapshot(now.Add(6 * time.Second))[ip].Class; got != contract.General {
		t.Fatal("old expiry deleted renewed binding", got)
	}
	if _, ok := s.Snapshot(now.Add(30 * time.Second))[ip]; ok {
		t.Fatal("expired mappings retained")
	}
}
func TestNegativeAnswerDoesNotFallBackAndSERVFAILDoes(t *testing.T) {
	q := new(mdns.Msg)
	q.SetQuestion("missing.example.", mdns.TypeA)
	for _, code := range []int{mdns.RcodeNameError, mdns.RcodeSuccess, mdns.RcodeServerFailure} {
		calls := 0
		out, e := Fallback(context.Background(), q, []Exchange{func(ctx context.Context, m *mdns.Msg) (*mdns.Msg, error) {
			calls++
			r := new(mdns.Msg)
			r.SetReply(m)
			r.Rcode = code
			return r, nil
		}, func(ctx context.Context, m *mdns.Msg) (*mdns.Msg, error) {
			calls++
			r := new(mdns.Msg)
			r.SetReply(m)
			return r, nil
		}})
		if e != nil || out == nil {
			t.Fatal(e)
		}
		want := 1
		if code == mdns.RcodeServerFailure {
			want = 2
		}
		if calls != want {
			t.Fatalf("rcode%d calls%d want%d", code, calls, want)
		}
	}
}
func TestExplicitVPNAndUnknownRUCIDRHaveDifferentDecisions(t *testing.T) {
	p, e := policy.Load("../policy/testdata/split")
	if e != nil {
		t.Fatal(e)
	}
	c, source := p.DomainDecision("apple.com")
	if c != contract.General || source == "" {
		t.Fatal("explicit service override lost")
	}
	_, source = p.DomainDecision("unlisted.example")
	if source != "" {
		t.Fatal("unknown domain became explicit VPN binding")
	}
}
func TestCacheSeparatesViewsGenerationsAndAgesTTL(t *testing.T) {
	now := time.Unix(1000, 0)
	q := new(mdns.Msg)
	q.SetQuestion("a.example.", mdns.TypeA)
	r := new(mdns.Msg)
	r.SetReply(q)
	r.Answer = []mdns.RR{rr("a.example. 20 IN A 8.8.8.8")}
	c := NewCache()
	v := View{ID: "vpn", Generation: 1}
	c.Put(v, q, r, now)
	if _, ok := c.Get(View{ID: "direct", Generation: 1}, q, now); ok {
		t.Fatal("direct shared VPN cache")
	}
	if _, ok := c.Get(View{ID: "vpn", Generation: 2}, q, now); ok {
		t.Fatal("new generation shared old cache")
	}
	q.Id++
	got, ok := c.Get(v, q, now.Add(5*time.Second))
	if !ok || got.Id != q.Id || got.Answer[0].Header().Ttl != 15 {
		t.Fatal("cache returned old ID/TTL")
	}
	if _, ok = c.Get(v, q, now.Add(21*time.Second)); ok {
		t.Fatal("expired DNS cache returned")
	}
}

func TestTruncatedUDPResponseRetriesOverTCP(t *testing.T) {
	packet, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	tcp, e := net.Listen("tcp", packet.LocalAddr().String())
	if e != nil {
		t.Fatal(e)
	}
	var calls atomic.Int32
	handler := mdns.HandlerFunc(func(w mdns.ResponseWriter, q *mdns.Msg) {
		calls.Add(1)
		r := new(mdns.Msg)
		r.SetReply(q)
		if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
			r.Truncated = true
		} else {
			r.Answer = []mdns.RR{rr("example.com. 60 IN A 8.8.8.8")}
		}
		w.WriteMsg(r)
	})
	udpServer := &mdns.Server{PacketConn: packet, Handler: handler}
	tcpServer := &mdns.Server{Listener: tcp, Handler: handler}
	go udpServer.ActivateAndServe()
	go tcpServer.ActivateAndServe()
	defer udpServer.Shutdown()
	defer tcpServer.Shutdown()
	q := new(mdns.Msg)
	q.SetQuestion("example.com.", mdns.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, e := Plain(ctx, q, packet.LocalAddr().String(), 0, "")
	if e != nil || len(r.Answer) != 1 || calls.Load() != 2 {
		t.Fatal("TCP truncation fallback failed", e, calls.Load())
	}
}
func TestCNAMECycleRejected(t *testing.T) {
	m := new(mdns.Msg)
	m.SetQuestion("a.example.", mdns.TypeA)
	m.Response = true
	m.Answer = []mdns.RR{rr("a.example. 20 IN CNAME b.example."), rr("b.example. 20 IN CNAME a.example.")}
	if _, e := AnswerRecords(m); e == nil {
		t.Fatal("CNAME cycle accepted")
	}
}
func TestDNSSECRequestDoesNotShareUnsignedCache(t *testing.T) {
	now := time.Now()
	q := new(mdns.Msg)
	q.SetQuestion("example.com.", mdns.TypeA)
	r := new(mdns.Msg)
	r.SetReply(q)
	r.Answer = []mdns.RR{rr("example.com. 60 IN A 8.8.8.8")}
	c := NewCache()
	v := View{ID: "vpn", Generation: 1}
	c.Put(v, q, r, now)
	signed := q.Copy()
	signed.SetEdns0(4096, true)
	if _, ok := c.Get(v, signed, now); ok {
		t.Fatal("DNSSEC request reused response without DNSSEC records")
	}
}
func TestReturnedTTLNeverOutlivesBoundedMappings(t *testing.T) {
	m := new(mdns.Msg)
	m.SetQuestion("example.com.", mdns.TypeA)
	m.Response = true
	m.Answer = []mdns.RR{rr("example.com. 86400 IN A 8.8.8.8")}
	ClampReply(m)
	if m.Answer[0].Header().Ttl != 3600 {
		t.Fatal("client DNS cache can outlive policy mapping")
	}
}

func TestRequiredAndServiceMappingsKeepDeviceGamingPriority(t *testing.T) {
	if MappingSet(Binding{Class: contract.General, Source: "vpn-required"}) != "required4" {
		t.Fatal("mandatory VPN override lost")
	}
	if MappingSet(Binding{Class: contract.General, Source: "vpn-services"}) != "services4" {
		t.Fatal("service override wrongly bypasses gaming profile")
	}
	if MappingSet(Binding{Class: contract.Direct, Source: "direct-essential"}) != "essential4" {
		t.Fatal("bank priority lost")
	}
}

func TestMandatorySharedIPBindingWinsOverServiceRegardlessOfOrder(t *testing.T) {
	now := time.Now()
	ip := netip.MustParseAddr("104.16.124.96")
	for _, reverse := range []bool{false, true} {
		s := NewBindings()
		views := []View{{ID: "service", Class: contract.General, Source: "vpn-services"}, {ID: "required", Class: contract.General, Source: "vpn-required"}}
		if reverse {
			views[0], views[1] = views[1], views[0]
		}
		for _, v := range views {
			s.Replace(now, v, v.ID, []AddressTTL{{IP: ip, TTL: time.Minute}})
		}
		if MappingSet(s.Snapshot(now)[ip]) != "required4" {
			t.Fatal("mandatory binding downgraded by shared CDN service", reverse)
		}
	}
}

func TestOutstandingIPv4BindingsSurviveOtherAnswersAndRotation(t *testing.T) {
	now := time.Now()
	a := netip.MustParseAddr("203.0.113.10")
	b := netip.MustParseAddr("203.0.113.11")
	s := NewBindings()
	vpn := View{ID: "general", Class: contract.General, Source: "vpn-required"}
	direct := View{ID: "direct", Class: contract.Direct}
	s.Replace(now, direct, "direct.ru", []AddressTTL{{IP: a, TTL: time.Hour}})
	s.Replace(now, vpn, "mirror.ru", []AddressTTL{{IP: a, TTL: time.Minute}})
	s.Replace(now.Add(time.Second), vpn, "mirror.ru", nil)
	if s.Snapshot(now.Add(2 * time.Second))[a].Class != contract.General {
		t.Fatal("AAAA/NODATA erased issued IPv4 VPN binding")
	}
	s.Replace(now.Add(5*time.Second), vpn, "mirror.ru", []AddressTTL{{IP: a, TTL: time.Second}, {IP: b, TTL: 10 * time.Second}})
	if s.Snapshot(now.Add(8 * time.Second))[a].Class != contract.General {
		t.Fatal("shortened TTL erased outstanding client answer")
	}
	s.Replace(now.Add(10*time.Second), vpn, "mirror.ru", []AddressTTL{{IP: b, TTL: time.Minute}})
	if s.Snapshot(now.Add(20 * time.Second))[a].Class != contract.General {
		t.Fatal("rotated A RRset erased old cached address")
	}
	if s.Snapshot(now.Add(61 * time.Second))[a].Class != contract.Direct {
		t.Fatal("expired binding retained indefinitely")
	}
}
