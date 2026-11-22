package continuity

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestProbeAnchorAcceptsOnlyMatchingEcho(t *testing.T) {
	for name, modify := range map[string]func([]byte) []byte{
		"valid":           func(b []byte) []byte { return b },
		"wrong source":    func(b []byte) []byte { return b },
		"bad checksum":    func(b []byte) []byte { return b },
		"wrong type":      func(b []byte) []byte { b[0] = 8; return b },
		"wrong code":      func(b []byte) []byte { b[1] = 1; return b },
		"wrong ID":        func(b []byte) []byte { b[4] ^= 1; return b },
		"wrong sequence":  func(b []byte) []byte { b[6] ^= 1; return b },
		"wrong nonce":     func(b []byte) []byte { b[len(b)-1] ^= 1; return b },
		"truncated reply": func(b []byte) []byte { return b[:len(b)-1] },
		"oversized reply": func(b []byte) []byte { return append(b, 1) },
	} {
		t.Run(name, func(t *testing.T) {
			target := netip.MustParseAddr("198.51.100.2")
			socket, peer := testCarrier(t)
			result := make(chan error, 1)
			go func() {
				defer peer.Close()
				var buf [128]byte
				n, err := peer.Read(buf[:])
				if err != nil {
					result <- err
					return
				}
				if n != 24 || buf[0] != 8 || buf[1] != 0 || icmpChecksum(buf[:n]) != 0 {
					result <- errors.New("unexpected ICMP echo request")
					return
				}
				buf[0], buf[2], buf[3] = 0, 0, 0
				packet := modify(buf[:n])
				binary.BigEndian.PutUint16(packet[2:4], icmpChecksum(packet))
				if name == "bad checksum" {
					packet[2] ^= 1
				}
				_, err = peer.Write(packet)
				result <- err
			}()
			got := ProbeAnchor(t.Context(), target, func(_ context.Context, network, address string) (net.Conn, error) {
				if network != "ip4:icmp" || address != "198.51.100.2" {
					return nil, errors.New("incorrect network or anchor destination")
				}
				source := net.IP(target.AsSlice())
				if name == "wrong source" {
					source = net.IP{198, 51, 100, 3}
				}
				return testIPConn{socket, net.IPAddr{IP: source}}, nil
			})
			if want := name == "valid"; got != want {
				t.Fatalf("ProbeAnchor = %v, want %v", got, want)
			}
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("probe did not exchange the echo packet")
			}
		})
	}
}

type testIPConn struct {
	net.Conn
	from net.IPAddr
}

func (c testIPConn) ReadFromIP(buf []byte) (int, *net.IPAddr, error) {
	n, err := c.Read(buf)
	return n, &c.from, err
}

func TestProbeAnchorStopsAtCallerDeadline(t *testing.T) {
	target := netip.MustParseAddr("198.51.100.2")
	socket, _ := testCarrier(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	got := ProbeAnchor(ctx, target, func(context.Context, string, string) (net.Conn, error) {
		return socket, nil
	})
	if elapsed := time.Since(start); got || elapsed > 500*time.Millisecond {
		t.Fatalf("unresponsive probe returned %v after %v", got, elapsed)
	}
}

func TestICMPChecksum(t *testing.T) {
	request := []byte{0x08, 0, 0, 0, 0, 0x01, 0, 0x02, 'b', 'o', 'b'}
	if got := icmpChecksum(request); got != 0x338d {
		t.Fatalf("odd-length checksum = %04x, want 338d", got)
	}
}
