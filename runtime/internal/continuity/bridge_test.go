package continuity

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
)

var testConfig = Config{
	BridgePort:     40500,
	TunnelPort:     40501,
	Anchor:         netip.MustParseAddrPort("203.0.113.1:51820"),
	AnchorTunnelIP: netip.MustParseAddr("198.51.100.2"),
}

var testKernel = netip.MustParseAddrPort("127.0.0.1:40501")

func TestBridgeDropsRepliesFromRetiredCarrier(t *testing.T) {
	native, nativePeer := testCarrier(t)
	reserve, reservePeer := testCarrier(t)
	delayed := &delayedRead{Conn: native, received: make(chan struct{}), resume: make(chan struct{})}
	t.Cleanup(delayed.release)
	bridge, local := testBridge(t, func(_ context.Context, channel contract.Channel, address string) (net.Conn, error) {
		if address != "203.0.113.1:51820" {
			return nil, errors.New("unexpected anchor destination")
		}
		switch channel {
		case contract.AWG:
			return delayed, nil
		case contract.Gecko:
			return reserve, nil
		default:
			return nil, errors.New("unexpected carrier")
		}
	})
	a := Path{Channel: contract.AWG, Identity: "primary"}
	b := Path{Channel: contract.Gecko, Identity: "reserve"}

	selectTestPath(t, bridge, a)
	selectTestPath(t, bridge, a)
	bridge.Pause(contract.Gecko)
	local.send(testKernel, "first packet")
	readCarrier(t, nativePeer, "first packet")
	replyFromCarrier(t, nativePeer, "late response from retired path")
	select {
	case <-delayed.received:
	case <-time.After(time.Second):
		t.Fatal("retiring carrier never received the queued response")
	}

	bridge.Pause(contract.AWG)
	selectTestPath(t, bridge, b)
	delayed.release()
	local.send(testKernel, "packet after failure")
	readCarrier(t, reservePeer, "packet after failure")
	replyFromCarrier(t, reservePeer, "response after failure")
	local.expectReply(t, "response after failure")
	select {
	case unexpected := <-local.out:
		t.Fatalf("unexpected reply after carrier change: %q", unexpected.payload)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestBridgeDropsUntrustedLoopbackPackets(t *testing.T) {
	carrier, peer := testCarrier(t)
	bridge, local := testBridge(t, func(context.Context, contract.Channel, string) (net.Conn, error) {
		return carrier, nil
	})
	selectTestPath(t, bridge, Path{Channel: contract.AWG, Identity: "primary"})
	local.send(netip.MustParseAddrPort("127.0.0.1:40502"), "foreign source port")
	local.send(netip.MustParseAddrPort("127.0.0.2:40501"), "foreign source address")
	local.send(testKernel, "configured loopback source")
	readCarrier(t, peer, "configured loopback source")
}

func TestBridgePausesOnFailedReplacementAndAllowsRetry(t *testing.T) {
	primary, primaryPeer := testCarrier(t)
	replacement, replacementPeer := testCarrier(t)
	dialFailure := errors.New("cannot bind selected carrier")
	dialResult := primary
	var dialErr error
	bridge, local := testBridge(t, func(context.Context, contract.Channel, string) (net.Conn, error) {
		return dialResult, dialErr
	})
	selectTestPath(t, bridge, Path{Channel: contract.AWG, Identity: "before"})
	local.send(testKernel, "before")
	readCarrier(t, primaryPeer, "before")

	dialResult, dialErr = nil, dialFailure
	next := Path{Channel: contract.AWG, Identity: "after"}
	if err := bridge.Select(next); !errors.Is(err, dialFailure) {
		t.Fatalf("replacement error = %v", err)
	}
	expectCarrierClosed(t, primaryPeer)

	dialResult, dialErr = replacement, nil
	selectTestPath(t, bridge, next)
	local.send(testKernel, "after")
	readCarrier(t, replacementPeer, "after")

	selectTestPath(t, bridge, Path{Channel: contract.Down})
	expectCarrierClosed(t, replacementPeer)
}

func TestBridgeCannotPublishCarrierAfterClose(t *testing.T) {
	carrier, peer := testCarrier(t)
	dialStarted := make(chan struct{})
	bridge, _ := testBridge(t, func(ctx context.Context, _ contract.Channel, _ string) (net.Conn, error) {
		close(dialStarted)
		<-ctx.Done()
		return carrier, nil
	})
	result := make(chan error, 1)
	go func() {
		result <- bridge.Select(Path{Channel: contract.AWG, Identity: "primary"})
	}()
	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		t.Fatal("bridge did not begin dialing the carrier")
	}
	bridge.Close()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("selection returned %v after bridge closed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("closing the bridge did not cancel selection")
	}
	expectCarrierClosed(t, peer)
}

func TestBridgeRejectsInvalidConfig(t *testing.T) {
	if err := testConfig.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, alter := range map[string]func(*Config){
		"zero bridge port":      func(c *Config) { c.BridgePort = 0 },
		"zero tunnel port":      func(c *Config) { c.TunnelPort = 0 },
		"same port":             func(c *Config) { c.TunnelPort = c.BridgePort },
		"zero anchor port":      func(c *Config) { c.Anchor = netip.MustParseAddrPort("203.0.113.1:0") },
		"loopback anchor":       func(c *Config) { c.Anchor = netip.MustParseAddrPort("127.0.0.1:51820") },
		"IPv6 anchor":           func(c *Config) { c.Anchor = netip.MustParseAddrPort("[2001:db8::2]:51820") },
		"absent anchor IP":      func(c *Config) { c.AnchorTunnelIP = netip.Addr{} },
		"IPv6 anchor IP":        func(c *Config) { c.AnchorTunnelIP = netip.MustParseAddr("2001:db8::2") },
		"loopback anchor IP":    func(c *Config) { c.AnchorTunnelIP = netip.MustParseAddr("127.0.0.1") },
		"unspecified anchor IP": func(c *Config) { c.AnchorTunnelIP = netip.MustParseAddr("0.0.0.0") },
	} {
		t.Run(name, func(t *testing.T) {
			config := testConfig
			alter(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("accepted an invalid bridge configuration")
			}
		})
	}
}

func TestStartKeepsSameLoopbackEndpointAfterSwitch(t *testing.T) {
	kernel, portProbe := listenTestUDP(t), listenTestUDP(t)
	endpoint := portProbe.LocalAddr().(*net.UDPAddr).AddrPort()
	if err := portProbe.Close(); err != nil {
		t.Fatal(err)
	}
	native, nativePeer := testCarrier(t)
	reserve, reservePeer := testCarrier(t)
	config := testConfig
	config.BridgePort = endpoint.Port()
	config.TunnelPort = kernel.LocalAddr().(*net.UDPAddr).AddrPort().Port()
	bridge, err := Start(t.Context(), config, func(_ context.Context, channel contract.Channel, _ string) (net.Conn, error) {
		if channel == contract.AWG {
			return native, nil
		}
		return reserve, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bridge.Close)
	for _, item := range []struct {
		path Path
		peer net.Conn
	}{
		{Path{Channel: contract.AWG, Identity: "primary"}, nativePeer},
		{Path{Channel: contract.Gecko, Identity: "reserve"}, reservePeer},
	} {
		selectTestPath(t, bridge, item.path)
		if _, err := kernel.WriteToUDPAddrPort([]byte("outbound"), endpoint); err != nil {
			t.Fatal(err)
		}
		readCarrier(t, item.peer, "outbound")
		replyFromCarrier(t, item.peer, "inbound")
		if err := kernel.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		var payload [128]byte
		n, from, err := kernel.ReadFromUDPAddrPort(payload[:])
		if err != nil {
			t.Fatal(err)
		}
		if from != endpoint || string(payload[:n]) != "inbound" {
			t.Fatalf("received %q from %v, want inbound from %v", string(payload[:n]), from, endpoint)
		}
	}
}

func listenTestUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skipf("loopback socket bind unavailable: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func testCarrier(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	socket, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close(); _ = socket.Close() })
	return socket, peer
}

func readCarrier(t *testing.T, conn net.Conn, want string) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var payload [128]byte
	n, err := conn.Read(payload[:])
	if err != nil {
		t.Fatal(err)
	}
	if got := string(payload[:n]); got != want {
		t.Fatalf("received %q, want %q", got, want)
	}
}

func expectCarrierClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	var payload [128]byte
	n, err := conn.Read(payload[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("expected the carrier to close, got %q with %v", string(payload[:n]), err)
	}
}

func replyFromCarrier(t *testing.T, conn net.Conn, payload string) {
	t.Helper()
	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
}

type delayedRead struct {
	net.Conn
	received chan struct{}
	resume   chan struct{}
}

func (d *delayedRead) Read(data []byte) (int, error) {
	n, err := d.Conn.Read(data)
	if err == nil {
		close(d.received)
		<-d.resume
	}
	return n, err
}

func (d *delayedRead) release() {
	select {
	case <-d.resume:
	default:
		close(d.resume)
	}
}

type testPacket struct {
	address netip.AddrPort
	payload string
}

type testPacketSocket struct {
	in   chan testPacket
	out  chan testPacket
	done chan struct{}
}

func testBridge(t *testing.T, dial Dialer) (*Bridge, *testPacketSocket) {
	t.Helper()
	packets := &testPacketSocket{
		in:   make(chan testPacket, 4),
		out:  make(chan testPacket, 4),
		done: make(chan struct{}),
	}
	bridge := newBridge(t.Context(), testConfig, dial, packets)
	t.Cleanup(bridge.Close)
	return bridge, packets
}

func selectTestPath(t *testing.T, bridge *Bridge, path Path) {
	t.Helper()
	if err := bridge.Select(path); err != nil {
		t.Fatal(err)
	}
}

func (s *testPacketSocket) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	select {
	case packet := <-s.in:
		return copy(b, packet.payload), packet.address, nil
	case <-s.done:
		return 0, netip.AddrPort{}, net.ErrClosed
	}
}

func (s *testPacketSocket) WriteToUDPAddrPort(b []byte, address netip.AddrPort) (int, error) {
	select {
	case s.out <- testPacket{address: address, payload: string(b)}:
		return len(b), nil
	case <-s.done:
		return 0, net.ErrClosed
	}
}

func (s *testPacketSocket) Close() error {
	close(s.done)
	return nil
}

func (s *testPacketSocket) send(address netip.AddrPort, payload string) {
	s.in <- testPacket{address: address, payload: payload}
}

func (s *testPacketSocket) expectReply(t *testing.T, want string) {
	t.Helper()
	select {
	case packet := <-s.out:
		if packet.payload != want || packet.address != testKernel {
			t.Fatalf("received %q for %v, want %q for %v", packet.payload, packet.address, want, testKernel)
		}
	case <-time.After(time.Second):
		t.Fatalf("did not receive %q", want)
	}
}
