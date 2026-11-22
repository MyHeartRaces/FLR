// Package continuity forwards an existing tunnel's UDP datagrams through the
// current carrier while keeping the tunnel's local endpoint fixed.
package continuity

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
)

var loopback = netip.AddrFrom4([4]byte{127, 0, 0, 1})

type Config struct {
	BridgePort     uint16         `json:"bridge_port"`
	TunnelPort     uint16         `json:"tunnel_port"`
	Anchor         netip.AddrPort `json:"anchor"`
	AnchorTunnelIP netip.Addr     `json:"anchor_tunnel_ip"`
}

func (c Config) Validate() error {
	if c.BridgePort == 0 || c.TunnelPort == 0 || c.BridgePort == c.TunnelPort {
		return errors.New("continuity needs distinct nonzero bridge and tunnel ports")
	}
	if !unicastIPv4(c.Anchor.Addr()) || c.Anchor.Port() == 0 {
		return errors.New("continuity anchor needs a unicast IPv4 address and nonzero UDP port")
	}
	if !unicastIPv4(c.AnchorTunnelIP) {
		return errors.New("continuity anchor tunnel address must be unicast IPv4")
	}
	return nil
}

func unicastIPv4(addr netip.Addr) bool {
	return addr.Is4() && addr.IsGlobalUnicast()
}

type Path struct {
	Channel  contract.Channel
	Identity string
}

// Dialer opens a connected UDP socket routed through the requested carrier.
type Dialer func(context.Context, contract.Channel, string) (net.Conn, error)

type packetSocket interface {
	ReadFromUDPAddrPort([]byte) (int, netip.AddrPort, error)
	WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error)
	Close() error
}

type carrierSocket struct {
	path Path
	conn net.Conn
}

type Bridge struct {
	ctx    context.Context
	cancel context.CancelFunc
	local  packetSocket
	peer   netip.AddrPort
	anchor string
	dial   Dialer

	changeMu sync.Mutex
	mu       sync.Mutex
	active   *carrierSocket
	close    sync.Once
}

func Start(ctx context.Context, config Config, dial Dialer) (*Bridge, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if dial == nil {
		return nil, errors.New("continuity bridge requires a carrier dialer")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	addr := netip.AddrPortFrom(loopback, config.BridgePort)
	local, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(addr))
	if err != nil {
		return nil, fmt.Errorf("bind continuity loopback bridge: %w", err)
	}
	return newBridge(ctx, config, dial, local), nil
}

func newBridge(ctx context.Context, config Config, dial Dialer, local packetSocket) *Bridge {
	run, cancel := context.WithCancel(ctx)
	b := &Bridge{
		ctx:    run,
		cancel: cancel,
		local:  local,
		peer:   netip.AddrPortFrom(loopback, config.TunnelPort),
		anchor: config.Anchor.String(),
		dial:   dial,
	}
	context.AfterFunc(run, b.Close)
	go b.forwardToCarrier()
	return b
}

// Select replaces the carrier socket when the channel or its owner changes.
// A failed replacement leaves the bridge paused until the next selection.
func (b *Bridge) Select(path Path) error {
	b.changeMu.Lock()
	defer b.changeMu.Unlock()

	b.mu.Lock()
	if err := b.ctx.Err(); err != nil {
		b.mu.Unlock()
		return err
	}
	if b.active != nil && b.active.path == path {
		b.mu.Unlock()
		return nil
	}
	b.retireCarrierLocked()
	b.mu.Unlock()

	switch path.Channel {
	case "", contract.Down:
		return nil
	case contract.AWG, contract.Gecko:
	default:
		return errors.New("continuity requires a UDP carrier")
	}
	if path.Identity == "" {
		return errors.New("continuity carrier has no owner")
	}
	conn, err := b.dial(b.ctx, path.Channel, b.anchor)
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return err
	}
	if conn == nil {
		return errors.New("continuity dialer returned no carrier socket")
	}
	socket := &carrierSocket{path: path, conn: conn}

	b.mu.Lock()
	if err := b.ctx.Err(); err != nil {
		b.mu.Unlock()
		_ = conn.Close()
		return err
	}
	b.active = socket
	b.mu.Unlock()
	go b.forwardToTunnel(socket)
	return nil
}

// Pause retires the selected socket before its carrier is dismantled.
func (b *Bridge) Pause(channel contract.Channel) {
	b.changeMu.Lock()
	defer b.changeMu.Unlock()

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.active != nil && b.active.path.Channel == channel {
		b.retireCarrierLocked()
	}
}

func (b *Bridge) Close() {
	b.close.Do(func() {
		b.cancel()
		_ = b.local.Close()
		b.mu.Lock()
		defer b.mu.Unlock()
		b.retireCarrierLocked()
	})
}

func (b *Bridge) retireCarrierLocked() {
	if socket := b.active; socket != nil {
		b.active = nil
		_ = socket.conn.Close()
	}
}

func (b *Bridge) forwardToCarrier() {
	buffer := make([]byte, 65535)
	for {
		n, sender, err := b.local.ReadFromUDPAddrPort(buffer)
		if err != nil {
			b.Close()
			return
		}
		if sender != b.peer || n == 0 {
			continue
		}
		b.mu.Lock()
		socket := b.active
		b.mu.Unlock()
		if socket != nil {
			// Closing the retired socket interrupts a concurrent write.
			_, _ = socket.conn.Write(buffer[:n])
		}
	}
}

func (b *Bridge) forwardToTunnel(socket *carrierSocket) {
	buffer := make([]byte, 65535)
	for {
		n, err := socket.conn.Read(buffer)
		b.mu.Lock()
		if b.active != socket {
			b.mu.Unlock()
			return
		}
		if err != nil {
			b.retireCarrierLocked()
			b.mu.Unlock()
			return
		}
		if n > 0 {
			_, _ = b.local.WriteToUDPAddrPort(buffer[:n], b.peer)
		}
		b.mu.Unlock()
	}
}
