package control

import (
	"context"
	"fmt"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	dnsbroker "github.com/MyHeartRaces/FLR/runtime/internal/dns"
	"github.com/MyHeartRaces/FLR/runtime/internal/lan"
	"github.com/MyHeartRaces/FLR/runtime/internal/socks"
	mdns "github.com/miekg/dns"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

func Worker(ctx context.Context, s Session, wan string) error {
	if s.ID == "" || !s.Expires.After(time.Now()) {
		return fmt.Errorf("expired/invalid session")
	}
	ctx, cancel := context.WithDeadline(ctx, s.Expires)
	defer cancel()
	// On a failed discovery Resolve returns the legacy LAN; the failure is
	// reported if binding it does not work.
	router, lanErr := lan.Resolve(lan.Interface)
	if ip, err := netip.ParseAddr(s.Client); err != nil || !router.IsClient(ip) {
		return fmt.Errorf("direct session client is not a host of LAN %s", router)
	}
	l, e := net.Listen("tcp4", net.JoinHostPort(router.Addr.String(), "1088"))
	if e != nil {
		if lanErr != nil {
			return fmt.Errorf("%w (%v)", e, lanErr)
		}
		return e
	}
	defer l.Close()
	ready := os.NewFile(3, "ready")
	if ready != nil {
		ready.Write([]byte("ready"))
		ready.Close()
	}
	var connections = make(chan struct{}, 32)
	go func() { <-ctx.Done(); l.Close() }()
	broker := dnsbroker.New(nil, dnsbroker.StaticRoute{Channel: contract.Down}, nil)
	broker.WAN = wan
	broker.Router = router.Addr
	for {
		c, e := l.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		if host != s.Client {
			c.Close()
			continue
		}
		select {
		case connections <- struct{}{}:
			go func() { defer func() { <-connections }(); defer c.Close(); workerConn(ctx, c, s, wan, broker) }()
		default:
			c.Close()
		}
	}
}
func workerConn(ctx context.Context, c net.Conn, s Session, wan string, broker *dnsbroker.Broker) {
	c.SetDeadline(time.Now().Add(3 * time.Second))
	head := make([]byte, 2)
	if _, e := io.ReadFull(c, head); e != nil || head[0] != 5 || head[1] == 0 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, e := io.ReadFull(c, methods); e != nil {
		return
	}
	allowed := false
	for _, m := range methods {
		if m == 0 {
			allowed = true
		}
	}
	if !allowed {
		c.Write([]byte{5, 255})
		return
	}
	c.Write([]byte{5, 0})
	h := make([]byte, 3)
	if _, e := io.ReadFull(c, h); e != nil || h[0] != 5 || h[2] != 0 {
		return
	}
	if h[1] != 1 {
		c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	target, e := socks.ReadAddress(c)
	if e != nil {
		return
	}
	host, port, e := net.SplitHostPort(target)
	if e != nil || port == "0" {
		return
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		if net.ParseIP(host) != nil {
			c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		q := new(mdns.Msg)
		q.SetQuestion(mdns.Fqdn(strings.ToLower(host)), mdns.TypeA)
		r, e := broker.Resolve(ctx, q, dnsbroker.View{ID: "session:" + s.ID, Class: contract.Direct})
		if e != nil {
			return
		}
		records, e := dnsbroker.AnswerRecords(r)
		if e != nil {
			return
		}
		for _, r := range records {
			if r.IP.Is4() {
				ip = net.IP(r.IP.AsSlice())
				break
			}
		}
		if ip == nil {
			return
		}
	}
	if _, e = strconv.ParseUint(port, 10, 16); e != nil {
		return
	}
	remote, e := dnsbroker.DialMarked(ctx, "tcp", net.JoinHostPort(ip.String(), port), contract.OuterMark|contract.ProbeMark, wan)
	if e != nil {
		c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	c.SetDeadline(s.Expires)
	remote.SetDeadline(s.Expires)
	done := make(chan struct{}, 2)
	go func() { io.Copy(remote, c); done <- struct{}{} }()
	go func() { io.Copy(c, remote); done <- struct{}{} }()
	select {
	case <-ctx.Done():
	case <-done:
	}
	c.Close()
	remote.Close()
}
