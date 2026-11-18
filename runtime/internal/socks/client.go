package socks

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

func address(target string) ([]byte, error) {
	host, port, e := net.SplitHostPort(target)
	if e != nil {
		return nil, e
	}
	n, e := strconv.ParseUint(port, 10, 16)
	if e != nil {
		return nil, e
	}
	b := []byte{}
	if ip := net.ParseIP(host).To4(); ip != nil {
		b = append([]byte{1}, ip...)
	} else if ip := net.ParseIP(host).To16(); ip != nil {
		b = append([]byte{4}, ip...)
	} else {
		if len(host) < 1 || len(host) > 255 {
			return nil, fmt.Errorf("invalid SOCKS target")
		}
		b = append([]byte{3, byte(len(host))}, []byte(host)...)
	}
	return append(b, byte(n>>8), byte(n)), nil
}
func ReadAddress(r io.Reader) (string, error) {
	one := make([]byte, 1)
	if _, e := io.ReadFull(r, one); e != nil {
		return "", e
	}
	var host string
	switch one[0] {
	case 1:
		b := make([]byte, 4)
		if _, e := io.ReadFull(r, b); e != nil {
			return "", e
		}
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		if _, e := io.ReadFull(r, b); e != nil {
			return "", e
		}
		host = net.IP(b).String()
	case 3:
		if _, e := io.ReadFull(r, one); e != nil {
			return "", e
		}
		if one[0] == 0 {
			return "", fmt.Errorf("empty SOCKS host")
		}
		b := make([]byte, int(one[0]))
		if _, e := io.ReadFull(r, b); e != nil {
			return "", e
		}
		host = string(b)
	default:
		return "", fmt.Errorf("invalid SOCKS address type")
	}
	port := make([]byte, 2)
	if _, e := io.ReadFull(r, port); e != nil {
		return "", e
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port)))), nil
}
func request(ctx context.Context, proxy, target string, command byte) (net.Conn, string, error) {
	c, e := (&net.Dialer{}).DialContext(ctx, "tcp", proxy)
	if e != nil {
		return nil, "", e
	}
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()
	deadline := time.Now().Add(4 * time.Second)
	if d, present := ctx.Deadline(); present && d.Before(deadline) {
		deadline = d
	}
	c.SetDeadline(deadline)
	if _, e = c.Write([]byte{5, 1, 0}); e != nil {
		return nil, "", e
	}
	b := make([]byte, 2)
	if _, e = io.ReadFull(c, b); e != nil {
		return nil, "", e
	}
	if b[0] != 5 || b[1] != 0 {
		return nil, "", fmt.Errorf("SOCKS authentication rejected")
	}
	addr, e := address(target)
	if e != nil {
		return nil, "", e
	}
	if _, e = c.Write(append([]byte{5, command, 0}, addr...)); e != nil {
		return nil, "", e
	}
	head := make([]byte, 3)
	if _, e = io.ReadFull(c, head); e != nil {
		return nil, "", e
	}
	if head[0] != 5 || head[1] != 0 || head[2] != 0 {
		return nil, "", fmt.Errorf("SOCKS request rejected code %d", head[1])
	}
	bound, e := ReadAddress(c)
	if e != nil {
		return nil, "", e
	}
	ok = true
	return c, bound, nil
}
func DialContext(ctx context.Context, proxy, target string) (net.Conn, error) {
	c, _, e := request(ctx, proxy, target, 1)
	if e == nil {
		c.SetDeadline(time.Time{})
	}
	return c, e
}
func DecodeUDP(packet []byte) (string, []byte, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return "", nil, fmt.Errorf("invalid/fragmented SOCKS UDP frame")
	}
	r := newReader(packet[3:])
	a, e := ReadAddress(r)
	if e != nil {
		return "", nil, e
	}
	return a, packet[len(packet)-r.remaining():], nil
}

type reader struct {
	data []byte
	pos  int
}

func newReader(b []byte) *reader { return &reader{data: b} }
func (r *reader) Read(b []byte) (int, error) {
	if r.pos == len(r.data) {
		return 0, io.EOF
	}
	n := copy(b, r.data[r.pos:])
	r.pos += n
	return n, nil
}
func (r *reader) remaining() int { return len(r.data) - r.pos }
func UDPExchange(ctx context.Context, proxy, target string, payload []byte) ([]byte, error) {
	control, bound, e := request(ctx, proxy, "0.0.0.0:0", 3)
	if e != nil {
		return nil, e
	}
	defer control.Close()
	host, port, e := net.SplitHostPort(bound)
	if e != nil {
		return nil, e
	}
	if host == "0.0.0.0" || host == "::" {
		host, _, e = net.SplitHostPort(proxy)
		if e != nil {
			return nil, e
		}
	}
	c, e := (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(host, port))
	if e != nil {
		return nil, e
	}
	defer c.Close()
	if d, ok := ctx.Deadline(); ok {
		c.SetDeadline(d)
	} else {
		c.SetDeadline(time.Now().Add(4 * time.Second))
	}
	addr, e := address(target)
	if e != nil {
		return nil, e
	}
	frame := append(append([]byte{0, 0, 0}, addr...), payload...)
	if _, e = c.Write(frame); e != nil {
		return nil, e
	}
	b := make([]byte, 65535)
	n, e := c.Read(b)
	if e != nil {
		return nil, e
	}
	from, result, e := DecodeUDP(b[:n])
	if e != nil {
		return nil, e
	}
	if from != target {
		return nil, fmt.Errorf("unexpected SOCKS UDP source")
	}
	return result, nil
}
