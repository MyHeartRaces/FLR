package engineupdate

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/socks"
)

// Target is one connection in scope. Config is the production sing-box
// config exactly as the production renderer produced it (private; never
// logged). Server is the resolved bearer IPv4.
type Target struct {
	ID     string
	Name   string
	Server string
	UDP    bool
	Config []byte
	// ConfigError records a known bearer whose isolated config cannot be rendered.
	ConfigError error
}

// Scope lists the enabled auto-eligible connections that use an engine.
type Scope interface {
	Connections(ctx context.Context, engine string) ([]Target, error)
}

// CanaryParams are the acceptance thresholds.
type CanaryParams struct {
	Port     int
	Seconds  int
	MinBytes int64
}

// CanaryResult describes the first failing probe, if any.
type CanaryResult struct {
	OK           bool
	Probe        string // "start", "listen", "https", "udp", "alive"
	Detail       string
	Inconclusive bool
}

// Canary starts the candidate on a transformed config and measures through it.
type Canary interface {
	Run(ctx context.Context, bin string, t Target, cfgPath string, p CanaryParams) CanaryResult
}

// TransformConfig turns a production sing-box config into a canary config.
// Keys changed: "log" (replaced with level warn) and "inbounds" (replaced by a
// single SOCKS inbound on 127.0.0.1:port; production TUN and SOCKS 1081 are
// dropped). Everything else, outbounds and route included, is kept verbatim.
func TransformConfig(production []byte, port int) ([]byte, error) {
	d := json.NewDecoder(bytes.NewReader(production))
	d.UseNumber()
	var cfg map[string]any
	if err := d.Decode(&cfg); err != nil || cfg == nil || d.Decode(new(any)) != io.EOF {
		return nil, errors.New("production config is not a JSON object")
	}
	if _, ok := cfg["outbounds"]; !ok {
		if _, ok = cfg["endpoints"]; !ok {
			return nil, errors.New("production config has no outbounds")
		}
	}
	cfg["log"] = map[string]any{"level": "warn"}
	cfg["inbounds"] = []any{map[string]any{"type": "socks", "tag": "canary", "listen": "127.0.0.1", "listen_port": port}}
	return json.Marshal(cfg)
}

// SocksCanary is the production Canary.
type SocksCanary struct {
	DownURL   string      // default https://speed.cloudflare.com/__down
	TLS       *tls.Config // tests only
	DNSServer string      // default 1.1.1.1:53
	// StartWait bounds the wait for the listening port (default 10 s).
	StartWait time.Duration
	// UDPTimeout bounds each DNS attempt (default 4 s).
	UDPTimeout time.Duration
}

func (c *SocksCanary) Run(ctx context.Context, bin string, t Target, cfgPath string, p CanaryParams) CanaryResult {
	if err := ctx.Err(); err != nil {
		return CanaryResult{Probe: "start", Detail: err.Error(), Inconclusive: true}
	}
	proxy := net.JoinHostPort("127.0.0.1", strconv.Itoa(p.Port))
	free, err := net.Listen("tcp4", proxy)
	if err != nil {
		return CanaryResult{Probe: "listen", Detail: "canary port unavailable", Inconclusive: true}
	}
	if err := free.Close(); err != nil {
		return CanaryResult{Probe: "listen", Detail: err.Error(), Inconclusive: true}
	}
	cmd := exec.Command(bin, "run", "-c", cfgPath)
	cmd.Dir = filepath.Dir(cfgPath)
	hardenChild(cmd)
	if err := cmd.Start(); err != nil {
		return CanaryResult{Probe: "start", Detail: "cannot start candidate: " + err.Error()}
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	exited := false
	defer func() {
		if exited {
			return
		}
		cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			cmd.Process.Kill()
			<-done
		}
	}()
	wait := c.StartWait
	if wait == 0 {
		wait = 10 * time.Second
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for ready := false; !ready; {
		select {
		case err := <-done:
			exited = true
			return CanaryResult{Probe: "listen", Detail: fmt.Sprintf("candidate exited before listening: %v", err)}
		case <-ctx.Done():
			return CanaryResult{Probe: "listen", Detail: ctx.Err().Error(), Inconclusive: true}
		case <-deadline.C:
			return CanaryResult{Probe: "listen", Detail: fmt.Sprintf("port %d not listening within %s", p.Port, wait), Inconclusive: true}
		case <-time.After(100 * time.Millisecond):
			if conn, err := net.DialTimeout("tcp", proxy, 200*time.Millisecond); err == nil {
				conn.Close()
				ready = true
			}
		}
	}
	inode, err := listenerInode(cmd.Process.Pid, p.Port)
	if err != nil {
		return CanaryResult{Probe: "listen", Detail: err.Error(), Inconclusive: true}
	}
	if got, err := c.probeHTTPS(ctx, proxy, p); err != nil {
		return CanaryResult{Probe: "https", Detail: fmt.Sprintf("%d/%d bytes: %v", got, p.MinBytes, err), Inconclusive: interrupted(ctx, err)}
	}
	if t.UDP {
		if n, err := c.probeUDP(ctx, proxy, 3); err != nil {
			return CanaryResult{Probe: "udp", Detail: fmt.Sprintf("%d/3 DNS answers: %v", n, err), Inconclusive: interrupted(ctx, err)}
		}
	}
	// Recheck the same listener after the last byte/answer. A zombie has
	// already dropped its file descriptors even if Wait has not returned yet.
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		return CanaryResult{Probe: "alive", Detail: "candidate exited during probes"}
	}
	after, err := listenerInode(cmd.Process.Pid, p.Port)
	if err != nil || after != inode {
		return CanaryResult{Probe: "alive", Detail: "candidate lost its listener during probes", Inconclusive: true}
	}
	select {
	case <-ctx.Done():
		return CanaryResult{Probe: "alive", Detail: ctx.Err().Error(), Inconclusive: true}
	case err := <-done:
		exited = true
		return CanaryResult{Probe: "alive", Detail: fmt.Sprintf("candidate exited during probes: %v", err)}
	default:
	}
	return CanaryResult{OK: true}
}

func (c *SocksCanary) probeHTTPS(parent context.Context, proxy string, p CanaryParams) (n int64, err error) {
	ctx, cancel := context.WithTimeout(parent, time.Duration(p.Seconds)*time.Second)
	defer func() {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		cancel()
	}()
	base := c.DownURL
	if base == "" {
		base = "https://speed.cloudflare.com/__down"
	}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: c.TLS,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return socks.DialContext(ctx, proxy, addr)
		}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	req, err := http.NewRequestWithContext(ctx, "GET", base+"?bytes="+strconv.FormatInt(p.MinBytes, 10), nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	n, err = io.Copy(io.Discard, io.LimitReader(resp.Body, p.MinBytes+1))
	if err != nil {
		return n, err
	}
	if n != p.MinBytes {
		return n, errors.New("short or oversized body")
	}
	return n, nil
}

func (c *SocksCanary) probeUDP(parent context.Context, proxy string, need int) (int, error) {
	server := c.DNSServer
	servers := []string{server}
	if server == "" {
		servers = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	ok := 0
	var last, transient error
	for attempt := 0; attempt < need*2 && ok < need; attempt++ {
		to := c.UDPTimeout
		if to == 0 {
			to = 4 * time.Second
		}
		if err := parent.Err(); err != nil {
			return ok, err
		}
		ctx, cancel := context.WithTimeout(parent, to)
		q, id := dnsQuery("example.com")
		b, err := socks.UDPExchange(ctx, proxy, servers[attempt%len(servers)], q)
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		cancel()
		if err == nil {
			err = dnsValidAnswer(b, id)
		}
		if err != nil {
			last = err
			if interrupted(parent, err) {
				transient = err
			}
			continue
		}
		ok++
	}
	if ok < need {
		if transient != nil {
			return ok, transient
		}
		return ok, last
	}
	return ok, nil
}

// dnsQuery builds a minimal A query for name.
func dnsQuery(name string) ([]byte, uint16) {
	var idb [2]byte
	rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	b := []byte{idb[0], idb[1], 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			b = append(b, byte(i-start))
			b = append(b, name[start:i]...)
			start = i + 1
		}
	}
	b = append(b, 0, 0, 1, 0, 1)
	return b, id
}

// dnsValidAnswer accepts a response with matching id, RCODE 0 and >= 1 answer.
func dnsValidAnswer(b []byte, id uint16) error {
	if len(b) < 12 || binary.BigEndian.Uint16(b[0:2]) != id || b[2]&0x80 == 0 {
		return errors.New("not a matching DNS response")
	}
	if b[3]&0x0f != 0 {
		return fmt.Errorf("DNS rcode %d", b[3]&0x0f)
	}
	if binary.BigEndian.Uint16(b[6:8]) == 0 {
		return errors.New("DNS response without answers")
	}
	return nil
}

// interrupted also recognizes socket deadlines which may expire just before
// their associated context timer fires.
func interrupted(ctx context.Context, err error) bool {
	var timeout net.Error
	return ctx.Err() != nil || errors.Is(err, exec.ErrWaitDelay) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		(errors.As(err, &timeout) && timeout.Timeout())
}
