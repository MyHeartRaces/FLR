package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/dataplane"
	dnsbroker "github.com/MyHeartRaces/FLR/runtime/internal/dns"
	"github.com/MyHeartRaces/FLR/runtime/internal/lan"
)

// PermanentDirectMark is distinct from the temporary session's 0x80800000.
const PermanentDirectMark uint32 = 0x80400000
const MaxDirectDatagram = 4096
const maxDirectConnections = 64
const maxDirectDestinations = 32

type DirectConfig struct {
	Enabled bool   `json:"enabled"`
	Bind    string `json:"bind"`
	Port    int    `json:"port"`
}

// DefaultDirectConfig binds to the router's discovered LAN address.
func DefaultDirectConfig() DirectConfig {
	router, _ := lan.Resolve(lan.Interface)
	return DefaultDirectConfigFor(router)
}
func DefaultDirectConfigFor(router lan.LAN) DirectConfig {
	return DirectConfig{true, router.Addr.String(), 1080}
}
func ValidateDirect(c DirectConfig, router lan.LAN) error {
	// Only the router's own LAN address is accepted; accepting an arbitrary LAN
	// host risks listening on a future WAN assignment. Interface changes need a
	// separately verified network migration, not an administrative API field.
	if e := router.Validate(); e != nil {
		return fmt.Errorf("direct proxy needs a valid router LAN: %w", e)
	}
	if c.Bind != router.Addr.String() || c.Port < 1024 || c.Port > 65535 || c.Port == 1088 {
		return fmt.Errorf("direct proxy requires router LAN %s and port 1024..65535 except 1088", router.Addr)
	}
	return nil
}

// ValidateDirectShape checks a stored direct proxy configuration for structure
// only: a private IPv4 bind and a usable port. The bind is not compared with
// the live LAN; the controller replaces it with the router's own LAN address
// once the LAN is known, and ValidateDirect checks new binds.
func ValidateDirectShape(c DirectConfig) error {
	ip, e := netip.ParseAddr(c.Bind)
	if e != nil || !ip.Is4() || !ip.IsPrivate() || c.Port < 1024 || c.Port > 65535 || c.Port == 1088 {
		return fmt.Errorf("direct proxy requires a private LAN IPv4 bind and port 1024..65535 except 1088")
	}
	return nil
}

type DirectDeps struct {
	Listen       func(string, string) (net.Listener, error)
	ListenPacket func(string, string) (net.PacketConn, error)
	Dial         func(context.Context, string, string) (net.Conn, error)
	Resolve      func(context.Context, string) (net.IP, error)
	Guard        func(DirectConfig, bool) error
	WAN          string
	// LAN is the router's LAN. When unset it is read from br-lan; a failed
	// discovery falls back to the legacy LAN and is reported in the status.
	LAN lan.LAN
}
type DirectStatus struct {
	Config  DirectConfig `json:"config"`
	Running bool         `json:"running"`
	Error   string       `json:"error,omitempty"`
	// LAN is the router LAN the listener is bound to (CIDR); LANError is set
	// when discovery failed and the legacy default is in use.
	LAN      string `json:"lan,omitempty"`
	LANError string `json:"lan_error,omitempty"`
}
type DirectServer struct {
	Config       DirectConfig
	Deps         DirectDeps
	mu           sync.Mutex
	listener     net.Listener
	packet       net.PacketConn
	cancel       context.CancelFunc
	running      bool
	lastError    string
	lanError     string
	associations map[string]*directAssociation
	wg           sync.WaitGroup
}
type directAssociation struct {
	mu           sync.Mutex
	peer         *net.UDPAddr
	closed       bool
	destinations map[string]net.Conn
}

func NewDirectServer(c DirectConfig, d DirectDeps) *DirectServer {
	lanError := ""
	if d.LAN.IsZero() {
		var e error
		if d.LAN, e = lan.Resolve(lan.Interface); e != nil {
			lanError = e.Error()
		}
	}
	if d.Listen == nil {
		d.Listen = net.Listen
	}
	if d.ListenPacket == nil {
		d.ListenPacket = net.ListenPacket
	}
	if d.Guard == nil {
		d.Guard = func(c DirectConfig, start bool) error {
			return dataplane.PermanentDirectGuard(d.LAN, c.Bind, c.Port, d.WAN, start)
		}
	}
	if d.Dial == nil {
		d.Dial = func(ctx context.Context, n, a string) (net.Conn, error) {
			return dnsbroker.DialMarked(ctx, n, a, PermanentDirectMark, d.WAN)
		}
	}
	if d.Resolve == nil {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, n, _ string) (net.Conn, error) { return d.Dial(ctx, n, "1.1.1.1:53") }}
		d.Resolve = func(ctx context.Context, h string) (net.IP, error) {
			ips, e := r.LookupIP(ctx, "ip4", h)
			if e != nil || len(ips) == 0 {
				return nil, fmt.Errorf("direct DNS failed")
			}
			return ips[0], nil
		}
	}
	return &DirectServer{Config: c, Deps: d, lanError: lanError, associations: map[string]*directAssociation{}}
}
func (s *DirectServer) Status() DirectStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return DirectStatus{Config: s.Config, Running: s.running, Error: s.lastError, LAN: s.Deps.LAN.String(), LANError: s.lanError}
}
func (s *DirectServer) Start(parent context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fail := func(e error) error { s.lastError = "direct listener unavailable"; return e }
	if s.Deps.LAN.IsZero() {
		s.Deps.LAN, _ = lan.Resolve(lan.Interface)
	}
	if e := ValidateDirect(s.Config, s.Deps.LAN); e != nil {
		return fail(e)
	}
	if !s.Config.Enabled {
		return nil
	}
	if s.running {
		return fmt.Errorf("direct listener already started")
	}
	if e := s.Deps.Guard(s.Config, true); e != nil {
		return fail(e)
	}
	address := net.JoinHostPort(s.Config.Bind, strconv.Itoa(s.Config.Port))
	l, e := s.Deps.Listen("tcp4", address)
	if e != nil {
		s.Deps.Guard(s.Config, false)
		return fail(e)
	}
	p, e := s.Deps.ListenPacket("udp4", address)
	if e != nil {
		l.Close()
		s.Deps.Guard(s.Config, false)
		return fail(e)
	}
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	s.listener = l
	s.packet = p
	s.running = true
	s.lastError = ""
	s.wg.Add(2)
	go func() { defer s.wg.Done(); s.accept(ctx, l) }()
	go func() { defer s.wg.Done(); s.receive(ctx, p) }()
	go func() { <-ctx.Done(); l.Close(); p.Close() }()
	return nil
}
func (s *DirectServer) Stop() error {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	if s.listener != nil {
		s.listener.Close()
	}
	if s.packet != nil {
		s.packet.Close()
	}
	s.running = false
	s.mu.Unlock()
	s.wg.Wait()
	return s.Deps.Guard(s.Config, false)
}
func (s *DirectServer) failed(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	s.mu.Lock()
	s.lastError = "direct listener stopped unexpectedly; retry settings or refresh"
	s.running = false
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
}
func (s *DirectServer) accept(ctx context.Context, l net.Listener) {
	slots := make(chan struct{}, maxDirectConnections)
	for {
		c, e := l.Accept()
		if e != nil {
			s.failed(ctx)
			return
		}
		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		if ip, e := netip.ParseAddr(host); e != nil || !s.Deps.LAN.IsClient(ip.Unmap()) {
			c.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
			s.wg.Add(1)
			go func() { defer s.wg.Done(); defer func() { <-slots }(); s.serveConn(ctx, c, host) }()
		default:
			c.Close()
		}
	}
}
func directAddress(r io.Reader) (string, error) {
	var typ [1]byte
	if _, e := io.ReadFull(r, typ[:]); e != nil {
		return "", e
	}
	var host string
	switch typ[0] {
	case 1:
		b := make([]byte, 4)
		if _, e := io.ReadFull(r, b); e != nil {
			return "", e
		}
		host = net.IP(b).String()
	case 3:
		var n [1]byte
		if _, e := io.ReadFull(r, n[:]); e != nil || n[0] == 0 {
			return "", fmt.Errorf("invalid domain")
		}
		b := make([]byte, int(n[0]))
		if _, e := io.ReadFull(r, b); e != nil {
			return "", e
		}
		host = string(b)
	case 4:
		var discarded [18]byte
		io.ReadFull(r, discarded[:])
		return "", fmt.Errorf("unsupported IPv6/address type")
	default:
		return "", fmt.Errorf("unsupported address type")
	}
	var p [2]byte
	if _, e := io.ReadFull(r, p[:]); e != nil {
		return "", e
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(p[:])))), nil
}
func (s *DirectServer) target(ctx context.Context, address string) (string, error) {
	host, port, e := net.SplitHostPort(address)
	if e != nil || port == "0" {
		return "", fmt.Errorf("invalid target")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		if s.Deps.Resolve == nil {
			return "", fmt.Errorf("resolver unavailable")
		}
		ip, e = s.Deps.Resolve(ctx, host)
		if e != nil {
			return "", e
		}
	}
	if ip.To4() == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return "", fmt.Errorf("unsupported target")
	}
	// Prevent using the proxy as an alternate router/LAN management path. The
	// former built-in LAN stays rejected on any router.
	v := ip.To4()
	if a := netip.AddrFrom4([4]byte(v)); s.Deps.LAN.Contains(a) || lan.Legacy().Contains(a) {
		return "", fmt.Errorf("LAN target rejected")
	}
	return net.JoinHostPort(v.String(), port), nil
}
func directReply(c net.Conn, code byte, ip net.IP, port int) error {
	v := ip.To4()
	if v == nil {
		v = net.IPv4zero.To4()
	}
	b := append([]byte{5, code, 0, 1}, v...)
	b = binary.BigEndian.AppendUint16(b, uint16(port))
	_, e := c.Write(b)
	return e
}
func (s *DirectServer) serveConn(parent context.Context, c net.Conn, peer string) {
	defer c.Close()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	go func() { <-ctx.Done(); c.Close() }()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	var h [2]byte
	if _, e := io.ReadFull(c, h[:]); e != nil || h[0] != 5 || h[1] == 0 {
		return
	}
	methods := make([]byte, int(h[1]))
	if _, e := io.ReadFull(c, methods); e != nil {
		return
	}
	if !bytes.Contains(methods, []byte{0}) {
		c.Write([]byte{5, 255})
		return
	}
	if _, e := c.Write([]byte{5, 0}); e != nil {
		return
	}
	var request [3]byte
	if _, e := io.ReadFull(c, request[:]); e != nil || request[0] != 5 || request[2] != 0 {
		return
	}
	address, e := directAddress(c)
	if e != nil {
		directReply(c, 8, nil, 0)
		return
	}
	switch request[1] {
	case 1:
		dialCtx, stop := context.WithTimeout(ctx, 5*time.Second)
		target, e := s.target(dialCtx, address)
		var remote net.Conn
		if e == nil {
			remote, e = s.Deps.Dial(dialCtx, "tcp4", target)
		}
		stop()
		if e != nil {
			directReply(c, 5, nil, 0)
			return
		}
		defer remote.Close()
		if directReply(c, 0, nil, 0) != nil {
			return
		}
		c.SetDeadline(time.Time{})
		done := make(chan struct{}, 2)
		go func() { io.Copy(remote, c); done <- struct{}{} }()
		go func() { io.Copy(c, remote); done <- struct{}{} }()
		select {
		case <-ctx.Done():
		case <-done:
		}
		c.Close()
		remote.Close()
		<-done
	case 3:
		host, port, _ := net.SplitHostPort(address)
		if host != "0.0.0.0" && host != peer {
			directReply(c, 2, nil, 0)
			return
		}
		n, _ := strconv.Atoi(port)
		assoc := &directAssociation{destinations: map[string]net.Conn{}}
		if n != 0 {
			assoc.peer = &net.UDPAddr{IP: net.ParseIP(peer), Port: n}
		}
		s.mu.Lock()
		if s.associations == nil {
			s.associations = map[string]*directAssociation{}
		}
		_, exists := s.associations[peer]
		if !exists && s.packet != nil {
			s.associations[peer] = assoc
		}
		s.mu.Unlock()
		if exists || s.packet == nil {
			directReply(c, 1, nil, 0)
			return
		}
		defer func() {
			s.mu.Lock()
			delete(s.associations, peer)
			s.mu.Unlock()
			assoc.mu.Lock()
			assoc.closed = true
			for _, d := range assoc.destinations {
				d.Close()
			}
			assoc.mu.Unlock()
		}()
		local, _, _ := net.SplitHostPort(s.packet.LocalAddr().String())
		_, p, _ := net.SplitHostPort(s.packet.LocalAddr().String())
		pn, _ := strconv.Atoi(p)
		if directReply(c, 0, net.ParseIP(local), pn) != nil {
			return
		}
		c.SetDeadline(time.Time{})
		io.Copy(io.Discard, c)
	default:
		directReply(c, 7, nil, 0)
	}
}
func parseDirectDatagram(b []byte) (string, []byte, error) {
	if len(b) > MaxDirectDatagram || len(b) < 4 || b[0] != 0 || b[1] != 0 || b[2] != 0 {
		return "", nil, fmt.Errorf("invalid UDP RSV/FRAG/size")
	}
	r := bytes.NewReader(b[3:])
	target, e := directAddress(r)
	if e != nil {
		return "", nil, e
	}
	payload := b[len(b)-r.Len():]
	return target, payload, nil
}
func (s *DirectServer) associationFor(peer *net.UDPAddr) *directAssociation {
	s.mu.Lock()
	a := s.associations[peer.IP.String()]
	s.mu.Unlock()
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	if a.peer == nil {
		copyPeer := *peer
		a.peer = &copyPeer
	}
	if !a.peer.IP.Equal(peer.IP) || a.peer.Port != peer.Port {
		return nil
	}
	return a
}
func (s *DirectServer) receive(ctx context.Context, p net.PacketConn) {
	b := make([]byte, MaxDirectDatagram+1)
	for {
		n, peer, e := p.ReadFrom(b)
		if e != nil {
			s.failed(ctx)
			return
		}
		u, ok := peer.(*net.UDPAddr)
		if !ok {
			continue
		}
		address, payload, e := parseDirectDatagram(b[:n])
		if e != nil {
			continue
		}
		a := s.associationFor(u)
		if a == nil {
			continue
		}
		// Only the bounded receiver creates destinations; each connected UDP socket
		// accepts replies exclusively from its target. A slow destination cannot
		// create an unbounded goroutine/queue.
		child, cancel := context.WithTimeout(ctx, 3*time.Second)
		target, e := s.target(child, address)
		if e != nil {
			cancel()
			continue
		}
		a.mu.Lock()
		remote := a.destinations[target]
		if a.closed {
			a.mu.Unlock()
			cancel()
			continue
		}
		if remote == nil && len(a.destinations) < maxDirectDestinations {
			remote, e = s.Deps.Dial(child, "udp4", target)
			if e == nil {
				a.destinations[target] = remote
				s.wg.Add(1)
				go s.udpReplies(ctx, p, a, target, remote)
			}
		}
		a.mu.Unlock()
		cancel()
		if remote != nil {
			remote.SetWriteDeadline(time.Now().Add(2 * time.Second))
			remote.Write(payload)
		}
	}
}
func (s *DirectServer) udpReplies(ctx context.Context, p net.PacketConn, a *directAssociation, target string, c net.Conn) {
	defer s.wg.Done()
	defer c.Close()
	defer func() { a.mu.Lock(); delete(a.destinations, target); a.mu.Unlock() }()
	host, port, _ := net.SplitHostPort(target)
	n, _ := strconv.Atoi(port)
	head := append([]byte{0, 0, 0, 1}, net.ParseIP(host).To4()...)
	head = binary.BigEndian.AppendUint16(head, uint16(n))
	b := make([]byte, MaxDirectDatagram+1)
	for {
		c.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, e := c.Read(b)
		if e != nil || ctx.Err() != nil {
			return
		}
		if len(head)+n > MaxDirectDatagram {
			continue
		}
		a.mu.Lock()
		peer := a.peer
		closed := a.closed
		a.mu.Unlock()
		if closed {
			return
		}
		p.WriteTo(append(append([]byte{}, head...), b[:n]...), peer)
	}
}
