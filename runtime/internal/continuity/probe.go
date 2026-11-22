package continuity

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"time"
)

const (
	anchorProbeTimeout = 850 * time.Millisecond
	echoRequest        = 8
	echoReply          = 0
	echoSize           = 24
)

// ProbeAnchor sends one IPv4 echo through the existing inner tunnel. Dial must
// open a connected raw ICMP socket routed exclusively through that tunnel.
func ProbeAnchor(ctx context.Context, target netip.Addr, dial func(context.Context, string, string) (net.Conn, error)) bool {
	if !unicastIPv4(target) || dial == nil || ctx.Err() != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, anchorProbeTimeout)
	defer cancel()
	conn, err := dial(ctx, "ip4:icmp", target.String())
	if conn != nil {
		defer conn.Close()
	}
	if err != nil || conn == nil {
		return false
	}
	// Closing on cancellation also handles a parent canceled before its deadline.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return false
	}

	var request [echoSize]byte
	request[0] = echoRequest
	if _, err := rand.Read(request[4:]); err != nil {
		return false
	}
	binary.BigEndian.PutUint16(request[2:4], icmpChecksum(request[:]))
	if n, err := conn.Write(request[:]); err != nil || n != len(request) {
		return false
	}

	// ReadFromIP strips the IPv4 header on raw sockets. Leave room for a
	// maximal header and one excess byte to distinguish truncated messages.
	var buf [60 + echoSize + 1]byte
	for ctx.Err() == nil {
		n, err := readICMP(conn, target, buf[:])
		if err != nil {
			return false
		}
		if n == len(request) && buf[0] == echoReply && buf[1] == 0 &&
			bytes.Equal(buf[4:n], request[4:]) && icmpChecksum(buf[:n]) == 0 {
			return ctx.Err() == nil
		}
	}
	return false
}

func readICMP(conn net.Conn, target netip.Addr, buf []byte) (int, error) {
	if raw, ok := conn.(interface {
		ReadFromIP([]byte) (int, *net.IPAddr, error)
	}); ok {
		n, from, err := raw.ReadFromIP(buf)
		if err != nil {
			return 0, err
		}
		if from == nil || !from.IP.Equal(net.IP(target.AsSlice())) {
			return 0, nil
		}
		return n, nil
	}
	return conn.Read(buf)
}

func icmpChecksum(packet []byte) uint16 {
	var sum uint32
	for len(packet) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[:2]))
		packet = packet[2:]
	}
	if len(packet) == 1 {
		sum += uint32(packet[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
