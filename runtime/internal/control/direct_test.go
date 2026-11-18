package control

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/lan"
)

func TestDirectConfigRejectsWANAndLegacyPort(t *testing.T) {
	legacy := lan.Legacy()
	for _, c := range []DirectConfig{{true, "0.0.0.0", 1080}, {true, "1.2.3.4", 1080}, {true, "192.168.8.1", 1088}, {true, "::", 1080}, {true, "192.168.8.2", 1081}} {
		if ValidateDirect(c, legacy) == nil {
			t.Fatalf("accepted unsafe config %+v", c)
		}
	}
	if ValidateDirect(DefaultDirectConfig(), legacy) != nil {
		t.Fatal("default rejected")
	}
}

func TestDirectConfigFollowsRouterLAN(t *testing.T) {
	router, e := lan.New(netip.MustParseAddr("192.168.1.1"), 24)
	if e != nil {
		t.Fatal(e)
	}
	def := DefaultDirectConfigFor(router)
	if def != (DirectConfig{true, "192.168.1.1", 1080}) || ValidateDirect(def, router) != nil {
		t.Fatalf("default %+v", def)
	}
	for _, c := range []DirectConfig{
		{true, "192.168.8.1", 1080}, {true, "192.168.1.2", 1080}, {true, "0.0.0.0", 1080},
		{true, "192.168.1.1", 1088}, {true, "192.168.1.1", 80}, {true, "", 1080},
	} {
		if ValidateDirect(c, router) == nil {
			t.Fatalf("accepted %+v on 192.168.1.1", c)
		}
	}
	if ValidateDirect(def, lan.Legacy()) == nil {
		t.Fatal("192.168.1.1 accepted on a 192.168.8.1 router")
	}
	if ValidateDirect(def, lan.LAN{}) == nil {
		t.Fatal("unset LAN accepted")
	}
}

func TestDirectServerBindsDiscoveredLAN(t *testing.T) {
	useLAN(t, "192.168.1.1/24")
	var listened, guarded string
	guard := func(c DirectConfig, start bool) error {
		if start {
			guarded = c.Bind
		}
		return nil
	}
	s := NewDirectServer(DefaultDirectConfig(), DirectDeps{
		Listen: func(n, a string) (net.Listener, error) {
			listened = a
			return net.Listen("tcp4", "127.0.0.1:0")
		},
		ListenPacket: func(string, string) (net.PacketConn, error) { return net.ListenPacket("udp4", "127.0.0.1:0") },
		Guard:        guard,
	})
	if e := s.Start(context.Background()); e != nil {
		t.Fatal(e)
	}
	defer s.Stop()
	st := s.Status()
	if listened != "192.168.1.1:1080" || guarded != "192.168.1.1" || !st.Running || st.LAN != "192.168.1.1/24" || st.LANError != "" {
		t.Fatalf("%s %s %+v", listened, guarded, st)
	}
}

func TestDirectServerReportsLANDiscoveryFailure(t *testing.T) {
	old := lan.Source
	defer func() { lan.Source = old }()
	lan.Source = func(string) ([]net.Addr, error) { return nil, errors.New("no such network interface") }
	s := NewDirectServer(DefaultDirectConfig(), DirectDeps{Guard: func(DirectConfig, bool) error { return nil }, Listen: func(string, string) (net.Listener, error) { return nil, errors.New("cannot assign requested address") }})
	if e := s.Start(context.Background()); e == nil {
		t.Fatal("listener started")
	}
	st := s.Status()
	if st.LANError == "" || st.LAN != "192.168.8.1/24" || st.Running {
		t.Fatalf("fallback not visible: %+v", st)
	}
}
func TestDirectDatagramValidation(t *testing.T) {
	valid := []byte{0, 0, 0, 1, 8, 8, 8, 8, 0, 53, 42}
	target, payload, e := parseDirectDatagram(valid)
	if e != nil || target != "8.8.8.8:53" || !bytes.Equal(payload, []byte{42}) {
		t.Fatalf("%s %v %v", target, payload, e)
	}
	for _, b := range [][]byte{{0, 1, 0, 1, 8, 8, 8, 8, 0, 53}, {0, 0, 1, 1, 8, 8, 8, 8, 0, 53}, {0, 0, 0, 4}, make([]byte, MaxDirectDatagram+1)} {
		if _, _, e := parseDirectDatagram(b); e == nil {
			t.Fatalf("accepted invalid packet")
		}
	}
}
func TestDirectCONNECTUsesResolverAndRelays(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, b := net.Pipe()
	defer b.Close()
	b.SetDeadline(time.Now().Add(2 * time.Second))
	upstream, echo := net.Pipe()
	defer echo.Close()
	resolved := false
	server := &DirectServer{Config: DefaultDirectConfig(), Deps: DirectDeps{
		Resolve: func(_ context.Context, host string) (net.IP, error) {
			if host != "example.org" {
				t.Errorf("host %s", host)
			}
			resolved = true
			return net.IPv4(8, 8, 8, 8), nil
		},
		Dial: func(_ context.Context, n, target string) (net.Conn, error) {
			if n != "tcp4" || target != "8.8.8.8:443" {
				t.Errorf("dial %s %s", n, target)
			}
			return upstream, nil
		},
	}}
	go server.serveConn(ctx, a, "192.168.8.2")
	b.Write([]byte{5, 1, 0})
	r := make([]byte, 2)
	io.ReadFull(b, r)
	request := append([]byte{5, 1, 0, 3, 11}, []byte("example.org")...)
	request = append(request, 1, 187)
	b.Write(request)
	reply := make([]byte, 10)
	io.ReadFull(b, reply)
	if reply[1] != 0 || !resolved {
		t.Fatalf("connect %v", reply)
	}
	go func() { io.Copy(echo, echo) }()
	b.Write([]byte("hi"))
	got := make([]byte, 2)
	if _, e := io.ReadFull(b, got); e != nil || string(got) != "hi" {
		t.Fatalf("relay %q %v", got, e)
	}
	cancel()
	if _, e := b.Read(got); e == nil {
		t.Fatal("cancel did not close TCP")
	}
}
func TestDirectIPv6ReturnsUnsupported(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	b.SetDeadline(time.Now().Add(time.Second))
	s := &DirectServer{Config: DefaultDirectConfig()}
	go s.serveConn(context.Background(), a, "192.168.8.2")
	b.Write([]byte{5, 1, 0})
	io.ReadFull(b, make([]byte, 2))
	b.Write(append([]byte{5, 1, 0, 4}, make([]byte, 18)...))
	r := make([]byte, 10)
	io.ReadFull(b, r)
	if r[1] != 8 {
		t.Fatalf("IPv6 reply %v", r)
	}
}
func TestDirectUDPRejectsForgedPeerAndOwnerCloses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pc, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer pc.Close()
	s := &DirectServer{Config: DefaultDirectConfig(), packet: pc, associations: map[string]*directAssociation{}}
	a, b := net.Pipe()
	b.SetDeadline(time.Now().Add(time.Second))
	go s.serveConn(ctx, a, "192.168.8.2")
	b.Write([]byte{5, 1, 0})
	io.ReadFull(b, make([]byte, 2))
	b.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	r := make([]byte, 10)
	io.ReadFull(b, r)
	if r[1] != 0 {
		t.Fatalf("associate %v", r)
	}
	if s.associationFor(&net.UDPAddr{IP: net.IPv4(192, 168, 8, 3), Port: 5}) != nil {
		t.Fatal("forged peer accepted")
	}
	assoc := s.associationFor(&net.UDPAddr{IP: net.IPv4(192, 168, 8, 2), Port: 5})
	if assoc == nil {
		t.Fatal("owner missing")
	}
	upstream, other := net.Pipe()
	defer other.Close()
	assoc.mu.Lock()
	assoc.destinations["8.8.8.8:53"] = upstream
	assoc.mu.Unlock()
	b.Close()
	other.SetReadDeadline(time.Now().Add(time.Second))
	if _, e := other.Read(make([]byte, 1)); e == nil {
		t.Fatal("owner close did not free UDP destination")
	}
}
func TestDirectStartListenFailureIsReported(t *testing.T) {
	s := NewDirectServer(DefaultDirectConfig(), DirectDeps{Listen: func(string, string) (net.Listener, error) { return nil, errors.New("busy") }, Guard: func(DirectConfig, bool) error { return nil }})
	if s.Start(context.Background()) == nil || s.Status().Running || s.Status().Error == "" {
		t.Fatal("listen failure hidden")
	}
}
func TestDirectStartCancellationFreesSockets(t *testing.T) {
	var l net.Listener
	var p net.PacketConn
	s := NewDirectServer(DefaultDirectConfig(), DirectDeps{
		Listen: func(string, string) (net.Listener, error) {
			var e error
			l, e = net.Listen("tcp4", "127.0.0.1:0")
			return l, e
		},
		ListenPacket: func(string, string) (net.PacketConn, error) {
			var e error
			p, e = net.ListenPacket("udp4", "127.0.0.1:0")
			return p, e
		},
		Guard: func(DirectConfig, bool) error { return nil },
	})
	ctx, cancel := context.WithCancel(context.Background())
	if e := s.Start(ctx); e != nil {
		t.Fatal(e)
	}
	cancel()
	s.Stop()
	if _, e := l.Accept(); e == nil {
		t.Fatal("TCP socket remains")
	}
	if _, _, e := p.ReadFrom(make([]byte, 1)); e == nil {
		t.Fatal("UDP socket remains")
	}
}

func TestDirectUDPAssociateRelaysAndRejectsPortForgery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	echo, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 100)
		for {
			n, peer, e := echo.ReadFrom(buf)
			if e != nil {
				return
			}
			echo.WriteTo(buf[:n], peer)
		}
	}()
	relay, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer relay.Close()
	client, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	forged, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer forged.Close()
	s := &DirectServer{Config: DefaultDirectConfig(), packet: relay, associations: map[string]*directAssociation{}, Deps: DirectDeps{
		Dial: func(ctx context.Context, n, target string) (net.Conn, error) {
			if n != "udp4" || target != "8.8.8.8:53" {
				t.Errorf("unexpected UDP target %s %s", n, target)
			}
			return (&net.Dialer{}).DialContext(ctx, n, echo.LocalAddr().String())
		},
	}}
	s.wg.Add(1)
	go func() { defer s.wg.Done(); s.receive(ctx, relay) }()
	owner, tcp := net.Pipe()
	tcp.SetDeadline(time.Now().Add(2 * time.Second))
	done := make(chan struct{})
	go func() { s.serveConn(ctx, owner, "127.0.0.1"); close(done) }()
	tcp.Write([]byte{5, 1, 0})
	io.ReadFull(tcp, make([]byte, 2))
	source := client.LocalAddr().(*net.UDPAddr).Port
	request := []byte{5, 3, 0, 1, 0, 0, 0, 0, byte(source >> 8), byte(source)}
	tcp.Write(request)
	response := make([]byte, 10)
	io.ReadFull(tcp, response)
	if response[1] != 0 {
		t.Fatalf("associate %v", response)
	}
	datagram := []byte{0, 0, 0, 1, 8, 8, 8, 8, 0, 53, 104, 105}
	client.WriteTo(datagram, relay.LocalAddr())
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, 100)
	n, _, e := client.ReadFrom(got)
	if e != nil || !bytes.Equal(got[:n], datagram) {
		t.Fatalf("UDP response %v %v", got[:n], e)
	}
	forged.WriteTo(datagram, relay.LocalAddr())
	forged.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, e = forged.ReadFrom(got); e == nil {
		t.Fatal("forged source port relayed")
	}
	tcp.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("owner did not close")
	}
	client.WriteTo(datagram, relay.LocalAddr())
	client.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, e = client.ReadFrom(got); e == nil {
		t.Fatal("UDP survived owner disconnect")
	}
	cancel()
	relay.Close()
	s.wg.Wait()
}
func TestDirectTCPReservedByteIsRejected(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	b.SetDeadline(time.Now().Add(time.Second))
	s := &DirectServer{Config: DefaultDirectConfig()}
	go s.serveConn(context.Background(), a, "192.168.8.2")
	b.Write([]byte{5, 1, 0})
	io.ReadFull(b, make([]byte, 2))
	b.Write([]byte{5, 1, 1})
	if _, e := b.Read(make([]byte, 1)); e == nil {
		t.Fatal("invalid RSV accepted")
	}
}

type directTestConn struct{ net.Conn }

func (c directTestConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(192, 168, 8, 2), Port: 5000}
}

type directTestListener struct {
	connections chan net.Conn
	closed      chan struct{}
}

func (l *directTestListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.connections:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *directTestListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}
func (l *directTestListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(192, 168, 8, 1), Port: 1080}
}
func TestDirectTCPConcurrencyIsBounded(t *testing.T) {
	l := &directTestListener{connections: make(chan net.Conn, 65), closed: make(chan struct{})}
	clients := make([]net.Conn, 65)
	for i := range clients {
		a, b := net.Pipe()
		l.connections <- directTestConn{a}
		clients[i] = b
		defer b.Close()
	}
	s := NewDirectServer(DefaultDirectConfig(), DirectDeps{
		Listen:       func(string, string) (net.Listener, error) { return l, nil },
		ListenPacket: func(string, string) (net.PacketConn, error) { return net.ListenPacket("udp4", "127.0.0.1:0") },
		Guard:        func(DirectConfig, bool) error { return nil },
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if e := s.Start(ctx); e != nil {
		t.Fatal(e)
	}
	defer s.Stop()
	clients[64].SetReadDeadline(time.Now().Add(time.Second))
	if _, e := clients[64].Read(make([]byte, 1)); e != io.EOF {
		t.Fatalf("65th connection must close, got %v", e)
	}
}

func TestDirectShapeIsStructural(t *testing.T) {
	for _, c := range []DirectConfig{{true, "192.168.1.1", 1080}, {false, "10.0.0.1", 1090}, {true, "192.168.8.1", 65535}} {
		if e := ValidateDirectShape(c); e != nil {
			t.Fatalf("%+v: %v", c, e)
		}
	}
	for _, c := range []DirectConfig{{true, "0.0.0.0", 1080}, {true, "203.0.113.10", 1080}, {true, "", 1080}, {true, "fd00::1", 1080}, {true, "192.168.1.1", 1088}, {true, "192.168.1.1", 80}, {true, "192.168.1.1", 70000}} {
		if ValidateDirectShape(c) == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
}

type peerConn struct {
	net.Conn
	peer net.Addr
}

func (c peerConn) RemoteAddr() net.Addr { return c.peer }

type queueListener struct{ conns chan net.Conn }

func (l queueListener) Accept() (net.Conn, error) {
	c, ok := <-l.conns
	if !ok {
		return nil, errors.New("closed")
	}
	return c, nil
}
func (l queueListener) Close() error   { return nil }
func (l queueListener) Addr() net.Addr { return &net.TCPAddr{} }

// The permanent listener admits clients of the router's LAN, not a fixed
// 192.168.8.0/24.
func TestDirectAcceptFollowsRouterLAN(t *testing.T) {
	router, _ := lan.New(netip.MustParseAddr("192.168.1.1"), 24)
	s := &DirectServer{Config: DirectConfig{true, "192.168.1.1", 1080}, Deps: DirectDeps{LAN: router}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := queueListener{conns: make(chan net.Conn)}
	done := make(chan struct{})
	go func() { s.accept(ctx, l); close(done) }()
	try := func(peer string) bool {
		a, b := net.Pipe()
		defer b.Close()
		b.SetDeadline(time.Now().Add(time.Second))
		l.conns <- peerConn{a, &net.TCPAddr{IP: net.ParseIP(peer), Port: 40000}}
		if _, e := b.Write([]byte{5, 1, 0}); e != nil {
			return false
		}
		r := make([]byte, 2)
		_, e := io.ReadFull(b, r)
		return e == nil && r[0] == 5 && r[1] == 0
	}
	for peer, want := range map[string]bool{"192.168.1.20": true, "192.168.1.254": true, "192.168.8.20": false, "192.168.1.1": false, "192.168.1.255": false, "8.8.8.8": false} {
		if got := try(peer); got != want {
			t.Fatalf("peer %s admitted=%v", peer, got)
		}
	}
	cancel()
	close(l.conns)
	<-done
	s.wg.Wait()
}

func TestDirectTargetRejectsRouterLAN(t *testing.T) {
	router, _ := lan.New(netip.MustParseAddr("192.168.1.1"), 24)
	s := &DirectServer{Deps: DirectDeps{LAN: router}}
	for _, target := range []string{"192.168.1.1:80", "192.168.1.20:22", "192.168.8.1:80"} {
		if _, e := s.target(context.Background(), target); e == nil {
			t.Fatalf("LAN target %s accepted", target)
		}
	}
	if got, e := s.target(context.Background(), "10.20.0.5:443"); e != nil || got != "10.20.0.5:443" {
		t.Fatalf("%s %v", got, e)
	}
}
