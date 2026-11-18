package engineupdate

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/socks"
)

// miniSOCKS5 supports CONNECT (forwarded to forward) and UDP ASSOCIATE with a
// canned DNS answer.
type miniSOCKS5 struct {
	l       net.Listener
	forward string
	dnsOK   bool
	targets chan string
}

func newMiniSOCKS(t *testing.T, addr, forward string, dnsOK bool) *miniSOCKS5 {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	s := &miniSOCKS5{l: l, forward: forward, dnsOK: dnsOK, targets: make(chan string, 16)}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *miniSOCKS5) serve(c net.Conn) {
	defer c.Close()
	h := make([]byte, 3)
	if _, err := io.ReadFull(c, h); err != nil {
		return
	}
	c.Write([]byte{5, 0})
	req := make([]byte, 3)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	target, err := socks.ReadAddress(c)
	if err != nil {
		return
	}
	select {
	case s.targets <- target:
	default:
	}
	switch req[1] {
	case 1:
		up, err := net.Dial("tcp", s.forward)
		if err != nil {
			c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		defer up.Close()
		c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
		go io.Copy(up, c)
		io.Copy(c, up)
	case 3:
		u, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return
		}
		defer u.Close()
		port := u.LocalAddr().(*net.UDPAddr).Port
		c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)})
		go func() {
			buf := make([]byte, 2048)
			for {
				n, from, err := u.ReadFrom(buf)
				if err != nil {
					return
				}
				dst, payload, err := socks.DecodeUDP(buf[:n])
				if err != nil || !s.dnsOK || len(payload) < 12 {
					continue
				}
				host, p, _ := net.SplitHostPort(dst)
				ip := net.ParseIP(host).To4()
				pn, _ := strconv.Atoi(p)
				resp := append([]byte{}, payload...)
				resp[2] |= 0x80
				binary.BigEndian.PutUint16(resp[6:], 1)
				resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34)
				frame := append([]byte{0, 0, 0, 1}, ip...)
				frame = append(frame, byte(pn>>8), byte(pn))
				u.WriteTo(append(frame, resp...), from)
			}
		}()
		io.Copy(io.Discard, c)
	}
}

func freeAddr(t *testing.T) string {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	a := l.Addr().String()
	l.Close()
	return a
}

func downServer(t *testing.T, short bool) *httptest.Server {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("bytes"))
		if short {
			n /= 2
		}
		w.Header().Set("Content-Length", strconv.Itoa(n))
		w.Write(bytes.Repeat([]byte{'z'}, n))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestCanaryChild runs in a separate copy of the test executable. The shell
// wrapper execs it so the PID observed by SocksCanary owns the socket.
func TestCanaryChild(t *testing.T) {
	if os.Getenv("FLR_TEST_CANARY") != "1" {
		return
	}
	raw, err := os.ReadFile(os.Args[len(os.Args)-1])
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Inbounds []struct {
			Listen string `json:"listen"`
			Port   int    `json:"listen_port"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil || len(cfg.Inbounds) != 1 {
		t.Fatal("invalid canary config")
	}
	addr := net.JoinHostPort(cfg.Inbounds[0].Listen, strconv.Itoa(cfg.Inbounds[0].Port))
	l, err := net.Listen("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	s := &miniSOCKS5{l: l, forward: os.Getenv("FLR_TEST_FORWARD"), dnsOK: os.Getenv("FLR_TEST_DNS") == "true"}
	for accepted := 1; ; accepted++ {
		conn, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		// The first connection is readiness. Close only the listener once the
		// HTTPS connection is accepted, then serve the complete download.
		if accepted == 2 && os.Getenv("FLR_TEST_DROP_LISTENER") == "true" {
			l.Close()
			s.serve(conn)
			time.Sleep(time.Minute)
			return
		}
		go s.serve(conn)
	}
}

func canaryRun(t *testing.T, srv *httptest.Server, dnsOK, udp bool, script string) CanaryResult {
	t.Helper()
	addr := freeAddr(t)
	_, port, _ := net.SplitHostPort(addr)
	pn, _ := strconv.Atoi(port)
	dir := t.TempDir()
	bin := filepath.Join(dir, "sb")
	body := "#!/bin/sh\nexec sleep 30\n"
	switch script {
	case "listen", "drop-listener", "https-timeout":
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("FLR_TEST_CANARY", "1")
		t.Setenv("FLR_TEST_EXE", exe)
		t.Setenv("FLR_TEST_DROP_LISTENER", strconv.FormatBool(script == "drop-listener"))
		t.Setenv("FLR_TEST_FORWARD", srv.Listener.Addr().String())
		t.Setenv("FLR_TEST_DNS", strconv.FormatBool(dnsOK))
		body = "#!/bin/sh\nexec \"$FLR_TEST_EXE\" -test.run='^TestCanaryChild$' -- \"$3\"\n"
	case "occupied":
		newMiniSOCKS(t, addr, srv.Listener.Addr().String(), dnsOK)
		body = "#!/bin/sh\ntouch started\nexec sleep 30\n"
	case "exit":
		body = "#!/bin/sh\nexit 3\n"
	}
	if err := os.WriteFile(bin, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "c.json")
	raw, err := TransformConfig(prodCfg, pn)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, raw, 0600); err != nil {
		t.Fatal(err)
	}
	c := &SocksCanary{DownURL: srv.URL + "/__down", TLS: &tls.Config{InsecureSkipVerify: true}, DNSServer: "192.0.2.1:53", StartWait: 2 * time.Second, UDPTimeout: 300 * time.Millisecond}
	params := CanaryParams{Port: pn, Seconds: 10, MinBytes: 1 << 20}
	if script == "https-timeout" {
		params.Seconds = 1
	}
	res := c.Run(context.Background(), bin, Target{UDP: udp}, cfg, params)
	if script == "occupied" {
		if _, err := os.Stat(filepath.Join(dir, "started")); !os.IsNotExist(err) {
			t.Fatal("candidate started on occupied port")
		}
	}
	return res
}

func TestSocksCanary(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("listener ownership requires Linux procfs")
	}
	srv := downServer(t, false)
	if r := canaryRun(t, srv, true, true, "occupied"); r.OK || !r.Inconclusive || r.Probe != "listen" {
		t.Fatalf("unrelated server: %+v", r)
	}
	if r := canaryRun(t, srv, true, true, "listen"); !r.OK {
		t.Fatalf("%+v", r)
	}
	if r := canaryRun(t, srv, true, false, "drop-listener"); r.OK || r.Probe != "alive" {
		t.Fatalf("child lost its listener during the download: %+v", r)
	}
	if r := canaryRun(t, srv, false, true, "listen"); r.OK || !r.Inconclusive || r.Probe != "udp" || !strings.Contains(r.Detail, "0/3") {
		t.Fatalf("%+v", r)
	}
	if r := canaryRun(t, srv, false, false, "listen"); !r.OK {
		t.Fatalf("%+v", r)
	}
	if r := canaryRun(t, downServer(t, true), true, true, "listen"); r.OK || r.Inconclusive || r.Probe != "https" || !strings.Contains(r.Detail, "/1048576 bytes") {
		t.Fatalf("%+v", r)
	}
	slow := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		<-req.Context().Done()
	}))
	t.Cleanup(slow.Close)
	if r := canaryRun(t, slow, true, false, "https-timeout"); r.OK || !r.Inconclusive || r.Probe != "https" {
		t.Fatalf("HTTPS deadline: %+v", r)
	}
	if r := canaryRun(t, srv, true, true, "sleep"); r.OK || !r.Inconclusive || r.Probe != "listen" {
		t.Fatalf("%+v", r)
	}
	if r := canaryRun(t, srv, true, true, "exit"); r.OK || r.Probe != "listen" || !strings.Contains(r.Detail, "exited") {
		t.Fatalf("%+v", r)
	}
}

type fakeStatus struct {
	st  RouteStatus
	err error
}

func (f fakeStatus) RouteStatus(context.Context) (RouteStatus, error) { return f.st, f.err }

func TestTunnelFetcher(t *testing.T) {
	var gotAuth atomic.Value
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		if r.URL.Path == "/big" {
			w.Write(bytes.Repeat([]byte{'a'}, 5000))
			return
		}
		fmt.Fprint(w, "hello")
	}))
	defer srv.Close()
	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	fetch := func(f *TunnelFetcher, path string, limit int64) (string, error) {
		var b bytes.Buffer
		err := f.Fetch(context.Background(), srv.URL+path, &b, limit)
		return b.String(), err
	}
	// Neither path healthy: refuse, never dial.
	dialed := false
	f := &TunnelFetcher{ChannelURL: srv.URL, Status: fakeStatus{}, TLS: tlsCfg, DialAWG: func(context.Context, string) (net.Conn, error) { dialed = true; return nil, errors.New("no") }}
	if _, err := fetch(f, "/", 100); !errors.Is(err, ErrNoRoute) || dialed {
		t.Fatalf("%v dialed=%v", err, dialed)
	}
	f.Status = fakeStatus{err: errors.New("controller down")}
	if _, err := fetch(f, "/", 100); !errors.Is(err, ErrNoRoute) {
		t.Fatal(err)
	}
	// AWG preferred over the slot.
	var awgAddr string
	f = &TunnelFetcher{ChannelURL: srv.URL, Status: fakeStatus{st: RouteStatus{true, true}}, TLS: tlsCfg, Token: "tok123", SOCKSAddr: "127.0.0.1:1",
		DialAWG: func(ctx context.Context, a string) (net.Conn, error) {
			awgAddr = a
			return (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
		}}
	if body, err := fetch(f, "/", 100); err != nil || body != "hello" || awgAddr == "" || gotAuth.Load() != "Bearer tok123" {
		t.Fatal(body, err, awgAddr)
	}
	if _, err := fetch(f, "/big", 100); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v", err)
	}
	// Slot SOCKS when AWG is down.
	sock := newMiniSOCKS(t, freeAddr(t), srv.Listener.Addr().String(), false)
	f = &TunnelFetcher{ChannelURL: srv.URL, Status: fakeStatus{st: RouteStatus{false, true}}, TLS: tlsCfg, SOCKSAddr: sock.l.Addr().String()}
	if body, err := fetch(f, "/", 100); err != nil || body != "hello" {
		t.Fatal(body, err)
	}
	// http:// refused.
	var b bytes.Buffer
	if err := f.Fetch(context.Background(), "http://x/y", &b, 10); err == nil {
		t.Fatal("plain http accepted")
	}
}

func TestFirstA(t *testing.T) {
	q, id := dnsQuery("example.com")
	resp := append([]byte{}, q...)
	resp[2] |= 0x80
	binary.BigEndian.PutUint16(resp[6:], 1)
	resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4)
	if err := dnsValidAnswer(resp, id); err != nil {
		t.Fatal(err)
	}
	if ip, ok := firstA(resp); !ok || ip != "1.2.3.4" {
		t.Fatal(ip, ok)
	}
	if dnsValidAnswer(resp, id+1) == nil {
		t.Fatal("wrong id accepted")
	}
}

func TestFetchOriginsAndRedirects(t *testing.T) {
	const origin = "https://channel.test"
	const github = "https://github.com/owner/repo/releases/download/tag/asset"
	const objects = "https://objects.githubusercontent.com/asset"
	const assets = "https://release-assets.githubusercontent.com/asset"
	for _, tc := range []struct {
		name      string
		channel   string
		chain     []string
		auth      []string
		wantError bool
	}{
		{"same origin", origin, []string{origin + "/one", origin + "/two"}, []string{"Bearer test", "Bearer test"}, false},
		{"public release", origin, []string{github, objects}, []string{"", ""}, false},
		{"release redirect", origin, []string{origin + "/one", github, assets}, []string{"Bearer test", "", ""}, false},
		{"different github port", "https://github.com:8443/channel", []string{"https://github.com:8443/channel", github}, []string{"Bearer test", ""}, false},
		{"github channel", github, []string{github, assets}, []string{"Bearer test", ""}, false},
		{"return to channel", origin, []string{origin + "/one", github, origin + "/two", origin + "/three"}, []string{"Bearer test", "", "", ""}, false},
		{"CDN channel", assets, []string{assets}, []string{""}, false},
		{"untrusted direct asset", origin, []string{"https://other.test/asset"}, nil, true},
		{"untrusted redirect", origin, []string{origin + "/one", "https://sub.channel.test/asset"}, []string{"Bearer test"}, true},
		{"wrong port", origin, []string{origin + ":8443/asset"}, nil, true},
		{"redirect downgrade", origin, []string{origin + "/one", "http://channel.test/asset"}, []string{"Bearer test"}, true},
		{"redirect userinfo", origin, []string{origin + "/one", "https://user@channel.test/asset"}, []string{"Bearer test"}, true},
		{"unrelated github path", origin, []string{"https://github.com/login"}, nil, true},
		{"direct CDN", origin, []string{assets}, nil, true},
		{"CDN lookalike", origin, []string{github, "https://release-assets.githubusercontent.com.evil.test/a"}, []string{""}, true},
		{"CDN port", origin, []string{github, "https://objects.githubusercontent.com:9443/a"}, []string{""}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				i := int(requests.Add(1)) - 1
				if i >= len(tc.auth) {
					t.Errorf("unexpected request to %s", req.Host)
					w.WriteHeader(http.StatusForbidden)
					return
				}
				if req.Header.Get("Authorization") != tc.auth[i] || "https://"+req.Host+req.URL.Path != tc.chain[i] {
					t.Errorf("incorrect origin or credentials on hop %d to %s", i, req.Host)
				}
				if i+1 < len(tc.chain) {
					http.Redirect(w, req, tc.chain[i+1], http.StatusFound)
				}
			}))
			defer srv.Close()
			f := TunnelFetcher{ChannelURL: tc.channel, Token: "test", Status: fakeStatus{st: RouteStatus{AWGHealthy: true}},
				TLS: &tls.Config{InsecureSkipVerify: true}, DialAWG: func(ctx context.Context, addr string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
				}}
			err := f.Fetch(context.Background(), tc.chain[0], io.Discard, 1024)
			if (err != nil) != tc.wantError || int(requests.Load()) != len(tc.auth) {
				t.Fatalf("requests=%d err=%v", requests.Load(), err)
			}
		})
	}
}
