package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/socks"
	mdns "github.com/miekg/dns"
	"io"
	"net"
	"net/http"
	"syscall"
	"time"
)

type Exchange func(context.Context, *mdns.Msg) (*mdns.Msg, error)

func DialMarked(ctx context.Context, network, target string, mark uint32, device string) (net.Conn, error) {
	d := net.Dialer{Timeout: 2 * time.Second}
	if mark != 0 || device != "" {
		d.Control = func(_, _ string, c syscall.RawConn) error {
			var err error
			e := c.Control(func(fd uintptr) {
				if mark != 0 {
					err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark))
				}
				if err == nil && device != "" {
					err = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, device)
				}
			})
			if e != nil {
				return e
			}
			return err
		}
	}
	return d.DialContext(ctx, network, target)
}
func validReply(q, r *mdns.Msg) error {
	if r == nil || !r.Response || r.Id != q.Id || len(r.Question) != 1 || len(q.Question) != 1 || r.Question[0] != q.Question[0] {
		return fmt.Errorf("DNS response mismatch")
	}
	return nil
}
func Plain(ctx context.Context, q *mdns.Msg, server string, mark uint32, device string) (*mdns.Msg, error) {
	for _, network := range []string{"udp", "tcp"} {
		c, e := DialMarked(ctx, network, server, mark, device)
		if e != nil {
			return nil, e
		}
		client := &mdns.Client{Net: network, Timeout: 2 * time.Second}
		r, _, e := client.ExchangeWithConnContext(ctx, q, &mdns.Conn{Conn: c, UDPSize: 4096})
		c.Close()
		if e != nil {
			return nil, e
		}
		if e = validReply(q, r); e != nil {
			return nil, e
		}
		if !r.Truncated {
			return r, nil
		}
	}
	return nil, fmt.Errorf("truncated TCP DNS")
}
func Fallback(ctx context.Context, q *mdns.Msg, list []Exchange) (*mdns.Msg, error) {
	var last error = fmt.Errorf("no DNS upstream available")
	for _, exchange := range list {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		child, cancel := context.WithTimeout(ctx, 2*time.Second)
		r, e := exchange(child, q)
		cancel()
		if e == nil {
			e = validReply(q, r)
		}
		if e == nil && r.Rcode != mdns.RcodeServerFailure && !r.Truncated {
			return r, nil
		}
		if e == nil {
			e = fmt.Errorf("DNS upstream SERVFAIL/truncated")
		}
		last = e
	}
	return nil, last
}
func DoH(ctx context.Context, q *mdns.Msg, channel contract.Channel, ip, hostname string) (*mdns.Msg, error) {
	if channel == contract.Down {
		return nil, fmt.Errorf("VPN DNS unavailable")
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{ServerName: hostname, MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: true, DisableKeepAlives: true, ResponseHeaderTimeout: 2 * time.Second}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		target := net.JoinHostPort(ip, "443")
		switch channel {
		case contract.AWG:
			return DialMarked(ctx, "tcp", target, contract.ChannelMark(channel)|contract.ClassMark(contract.General), "flr_awg")
		case contract.Gecko:
			return socks.DialContext(ctx, "127.0.0.1:1081", target)
		case contract.VLESS:
			return socks.DialContext(ctx, "127.0.0.1:1082", target)
		}
		return nil, fmt.Errorf("invalid DNS channel")
	}
	defer transport.CloseIdleConnections()
	b, e := q.Pack()
	if e != nil {
		return nil, e
	}
	request, e := http.NewRequestWithContext(ctx, "POST", "https://"+hostname+"/dns-query", bytes.NewReader(b))
	if e != nil {
		return nil, e
	}
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return fmt.Errorf("DoH redirect rejected") }}
	response, e := client.Do(request)
	if e != nil {
		return nil, e
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("DoH HTTP status%d", response.StatusCode)
	}
	b, e = io.ReadAll(io.LimitReader(response.Body, 65536))
	if e != nil {
		return nil, e
	}
	if len(b) > 65535 {
		return nil, fmt.Errorf("oversized DNS response")
	}
	r := new(mdns.Msg)
	if e = r.Unpack(b); e != nil {
		return nil, e
	}
	if e = validReply(q, r); e != nil {
		return nil, e
	}
	return r, nil
}
