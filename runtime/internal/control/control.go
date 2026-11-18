package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/MyHeartRaces/FLR/runtime/internal/lan"
	"github.com/MyHeartRaces/FLR/runtime/internal/validation"
	"io"
	"net"
	"net/netip"
	"os"
	"time"
)

const Socket = "/var/run/flr-runtime/control.sock"

type Request struct {
	Command string `json:"command"`
	Client  string `json:"client,omitempty"`
	TTL     string `json:"ttl,omitempty"`
	Value   string `json:"value,omitempty"`
}

func Parse(b []byte, router lan.LAN) (Request, error) {
	var r Request
	if len(b) > 4096 {
		return r, fmt.Errorf("request too large")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(&r); e != nil {
		return r, e
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return r, fmt.Errorf("trailing request data")
	}
	// A new profile or session needs a client of the current LAN. Removing a
	// profile ("auto") needs only a private IPv4 address, so a stored profile
	// left outside the LAN by a LAN change can still be deleted.
	client := func(removal bool) error {
		ip, e := netip.ParseAddr(r.Client)
		if e == nil && removal && ip.Is4() && ip.IsPrivate() {
			return nil
		}
		if e != nil || !router.IsClient(ip) {
			if router.IsZero() {
				return fmt.Errorf("client must be a LAN host; router LAN unknown")
			}
			return fmt.Errorf("client must be a LAN host")
		}
		return nil
	}
	switch r.Command {
	case "status", "refresh", "direct-stop":
		if r.Client != "" || r.TTL != "" || r.Value != "" {
			return r, fmt.Errorf("unexpected command argument")
		}
	case "games":
		if r.Client != "" || r.TTL != "" || (r.Value != "auto" && r.Value != "vless") {
			return r, fmt.Errorf("games needs auto or vless")
		}
	case "profile":
		if e := client(r.Value == "auto"); e != nil {
			return r, e
		}
		if r.TTL != "" || (r.Value != "auto" && r.Value != "games" && r.Value != "direct" && r.Value != "general") {
			return r, fmt.Errorf("invalid device profile")
		}
	case "direct-session":
		if e := client(false); e != nil {
			return r, e
		}
		if r.Value != "" {
			return r, fmt.Errorf("unexpected value")
		}
		if r.TTL == "" {
			r.TTL = "15m"
		}
		ttl, e := time.ParseDuration(r.TTL)
		if e != nil || ttl <= 0 || ttl > 15*time.Minute {
			return r, fmt.Errorf("direct TTL must be positive and at most15m")
		}
	default:
		return r, fmt.Errorf("unknown command")
	}
	return r, nil
}

type Reply struct {
	OK          bool              `json:"ok"`
	Data        any               `json:"data"`
	Error       string            `json:"error"`
	ErrorDetail *validation.Error `json:"error_detail,omitempty"`
}

// RouterLAN returns the router LAN; a non-nil error means it is unknown.
type RouterLAN func() (lan.LAN, error)

// Serve answers the control socket. The router LAN is resolved for every
// request (callers pass a cached resolver), so a LAN that appears or changes
// after start is used without a restart.
func Serve(ctx context.Context, router RouterLAN, handler func(Request) (any, error)) error {
	if e := os.MkdirAll("/var/run/flr-runtime", 0700); e != nil {
		return e
	}
	_ = os.Remove(Socket)
	l, e := net.Listen("unix", Socket)
	if e != nil {
		return e
	}
	defer l.Close()
	defer os.Remove(Socket)
	if e = os.Chmod(Socket, 0600); e != nil {
		return e
	}
	go func() { <-ctx.Done(); l.Close() }()
	for {
		c, e := l.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		go serveControl(c, router, handler)
	}
}

func serveControl(c net.Conn, router RouterLAN, handler func(Request) (any, error)) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	raw, e := bufio.NewReader(io.LimitReader(c, 4097)).ReadBytes('\n')
	var value any
	if e == nil {
		current, err := router()
		if err != nil {
			current = lan.LAN{}
		}
		r, err := Parse(raw, current)
		e = err
		if e == nil {
			value, e = handler(r)
		}
	}
	reply := Reply{OK: e == nil, Data: value}
	if e != nil {
		reply.Error = e.Error()
	}
	json.NewEncoder(c).Encode(reply)
}
func Call(r Request) (any, error) {
	c, e := net.DialTimeout("unix", Socket, 2*time.Second)
	if e != nil {
		return nil, e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if e = json.NewEncoder(c).Encode(r); e != nil {
		return nil, e
	}
	var reply Reply
	if e = json.NewDecoder(io.LimitReader(c, 65536)).Decode(&reply); e != nil {
		return nil, e
	}
	if !reply.OK {
		return nil, fmt.Errorf("%s", reply.Error)
	}
	return reply.Data, nil
}
