package engineupdate

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	dnsbroker "github.com/MyHeartRaces/FLR/runtime/internal/dns"
	"github.com/MyHeartRaces/FLR/runtime/internal/socks"
)

// ErrNoRoute means neither native AWG nor the proxy slot is healthy. The
// updater then skips the cycle; it never falls back to the plain WAN.
var ErrNoRoute = errors.New("no healthy tunnel route")

// ErrTooLarge is returned when a body exceeds its bound.
var ErrTooLarge = errors.New("response exceeds size bound")

// Fetcher retrieves an https URL into w, refusing bodies above limit bytes.
type Fetcher interface {
	Fetch(ctx context.Context, rawURL string, w io.Writer, limit int64) error
}

// RouteStatus is what the controller reports about the tunnel.
type RouteStatus struct{ AWGHealthy, SlotHealthy bool }

// StatusProvider reads controller health.
type StatusProvider interface {
	RouteStatus(ctx context.Context) (RouteStatus, error)
}

// APIStatus runs `flr-controller api --read-only` with {"operation":"status"}.
type APIStatus struct {
	Binary string // default /usr/sbin/flr-controller
}

type statusReply struct {
	OK   bool `json:"ok"`
	Data struct {
		Status struct {
			Proxy struct {
				AWG struct {
					Healthy bool `json:"healthy"`
				} `json:"awg"`
				Slot struct {
					Healthy bool `json:"healthy"`
				} `json:"slot"`
			} `json:"proxy"`
		} `json:"status"`
	} `json:"data"`
}

func (a APIStatus) RouteStatus(ctx context.Context) (RouteStatus, error) {
	bin := a.Binary
	if bin == "" {
		bin = "/usr/sbin/flr-controller"
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := execCommand(ctx, bin, "api", "--read-only")
	cmd.Stdin = strings.NewReader(`{"operation":"status"}`)
	out := &limitedBuffer{limit: 2 << 20}
	cmd.Stdout = out
	if err := cmd.Run(); err != nil {
		return RouteStatus{}, fmt.Errorf("controller status unavailable: %v", err)
	}
	return ParseRouteStatus(out.buf.Bytes())
}

// ParseRouteStatus extracts health from the controller reply.
func ParseRouteStatus(b []byte) (RouteStatus, error) {
	var r statusReply
	if err := json.Unmarshal(b, &r); err != nil || !r.OK {
		return RouteStatus{}, errors.New("controller status reply rejected")
	}
	return RouteStatus{AWGHealthy: r.Data.Status.Proxy.AWG.Healthy, SlotHealthy: r.Data.Status.Proxy.Slot.Healthy}, nil
}

// TunnelFetcher dials only through the tunnel: SO_BINDTODEVICE flr_awg with the
// probe mark when AWG is healthy, otherwise the proxy slot SOCKS.
type TunnelFetcher struct {
	Status     StatusProvider
	ChannelURL string // configured origin for authenticated requests
	Token      string // bearer token, never logged
	SOCKSAddr  string // default 127.0.0.1:1081
	TLS        *tls.Config
	// DialAWG overrides the AWG dialer (tests). It receives host:port.
	DialAWG func(ctx context.Context, addr string) (net.Conn, error)
}

const (
	awgDevice = "flr_awg"
	awgDNS    = "1.1.1.1:53"
)

func (f *TunnelFetcher) awgMark() uint32 {
	return contract.ChannelMark(contract.AWG) | contract.ClassMark(contract.General) | contract.ProbeMark
}

func (f *TunnelFetcher) dialer(ctx context.Context) (func(context.Context, string, string) (net.Conn, error), error) {
	st, err := f.Status.RouteStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoRoute, err)
	}
	switch {
	case st.AWGHealthy:
		return func(ctx context.Context, _, addr string) (net.Conn, error) {
			if f.DialAWG != nil {
				return f.DialAWG(ctx, addr)
			}
			return f.dialAWG(ctx, addr)
		}, nil
	case st.SlotHealthy:
		proxy := f.SOCKSAddr
		if proxy == "" {
			proxy = "127.0.0.1:1081"
		}
		return func(ctx context.Context, _, addr string) (net.Conn, error) {
			return socks.DialContext(ctx, proxy, addr)
		}, nil
	}
	return nil, ErrNoRoute
}

func (f *TunnelFetcher) dialAWG(ctx context.Context, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(host) == nil {
		ip, err := f.resolveAWG(ctx, host)
		if err != nil {
			return nil, err
		}
		host = ip
	}
	return dnsbroker.DialMarked(ctx, "tcp", net.JoinHostPort(host, port), f.awgMark(), awgDevice)
}

// resolveAWG resolves A records through the tunnel (UDP DNS to 1.1.1.1 bound
// to flr_awg, exactly as the AWG health probe sends its DNS).
func (f *TunnelFetcher) resolveAWG(ctx context.Context, host string) (string, error) {
	c, err := dnsbroker.DialMarked(ctx, "udp", awgDNS, contract.ChannelMark(contract.AWG)|contract.ProbeMark, awgDevice)
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(4 * time.Second))
	q, id := dnsQuery(host)
	if _, err = c.Write(q); err != nil {
		return "", err
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		return "", err
	}
	if err = dnsValidAnswer(buf[:n], id); err != nil {
		return "", err
	}
	ip, ok := firstA(buf[:n])
	if !ok {
		return "", errors.New("no A record through tunnel")
	}
	return ip, nil
}

func skipName(b []byte, i int) (int, bool) {
	for i < len(b) {
		l := int(b[i])
		switch {
		case l == 0:
			return i + 1, true
		case l&0xc0 == 0xc0:
			return i + 2, i+2 <= len(b)
		default:
			i += l + 1
		}
	}
	return 0, false
}

func firstA(b []byte) (string, bool) {
	if len(b) < 12 {
		return "", false
	}
	i := 12
	for q := 0; q < int(binary.BigEndian.Uint16(b[4:6])); q++ {
		var ok bool
		if i, ok = skipName(b, i); !ok {
			return "", false
		}
		i += 4
	}
	for a := 0; a < int(binary.BigEndian.Uint16(b[6:8])); a++ {
		var ok bool
		if i, ok = skipName(b, i); !ok || i+10 > len(b) {
			return "", false
		}
		typ, rdlen := binary.BigEndian.Uint16(b[i:]), int(binary.BigEndian.Uint16(b[i+8:]))
		i += 10
		if i+rdlen > len(b) {
			return "", false
		}
		if typ == 1 && rdlen == 4 {
			return net.IP(b[i : i+4]).String(), true
		}
		i += rdlen
	}
	return "", false
}

func httpsPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	return "443"
}

func sameOrigin(a, b *url.URL) bool {
	return a.Scheme == b.Scheme && strings.EqualFold(a.Hostname(), b.Hostname()) && httpsPort(a) == httpsPort(b)
}

func githubRelease(u *url.URL) bool {
	if !strings.EqualFold(u.Hostname(), "github.com") || httpsPort(u) != "443" || path.Clean(u.Path) != u.Path || strings.Contains(strings.ToLower(u.EscapedPath()), "%2f") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	return len(parts) == 6 && parts[2] == "releases" &&
		(parts[3] == "download" || (parts[3] == "latest" && parts[4] == "download"))
}

func releaseCDN(u *url.URL) bool {
	host := strings.TrimSuffix(u.Hostname(), ".")
	return strings.EqualFold(host, "objects.githubusercontent.com") || strings.EqualFold(host, "release-assets.githubusercontent.com")
}

// fetchURL validates the request before dialing and reports whether it may
// carry channel credentials. GitHub's storage hosts are redirect-only unless
// explicitly configured as the channel, and never receive a bearer token.
func fetchURL(channelURL, rawURL string, from *url.URL) (bool, error) {
	origin, err := parseHTTPS(channelURL)
	if err != nil {
		return false, err
	}
	to, err := parseHTTPS(rawURL)
	if err != nil {
		return false, err
	}
	if sameOrigin(origin, to) {
		return !releaseCDN(to) && (from == nil || sameOrigin(from, to)), nil
	}
	if githubRelease(to) {
		return false, nil
	}
	if from != nil && releaseCDN(to) && httpsPort(to) == "443" {
		switch {
		case githubRelease(from), sameOrigin(from, to):
			return false, nil
		case sameOrigin(origin, from) && apiAssetRE.MatchString(from.String()):
			return false, nil
		}
	}
	return false, errors.New("update URL outside allowed origins")
}

func (f *TunnelFetcher) Fetch(ctx context.Context, rawURL string, w io.Writer, limit int64) error {
	allowToken, err := fetchURL(f.ChannelURL, rawURL, nil)
	if err != nil {
		return err
	}
	dial, err := f.dialer(ctx)
	if err != nil {
		return err
	}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: dial, TLSClientConfig: f.TLS,
		TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("redirect refused")
		}
		previous := via[len(via)-1]
		allowToken, err := fetchURL(f.ChannelURL, req.URL.String(), previous.URL)
		if err != nil {
			return err
		}
		if !allowToken || previous.Header.Get("Authorization") == "" {
			req.Header.Del("Authorization")
		}
		if !sameOrigin(previous.URL, req.URL) {
			req.Header.Del("Referer")
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return err
	}
	if allowToken && f.Token != "" {
		req.Header.Set("Authorization", "Bearer "+f.Token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return redactURLError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if n > limit {
		return ErrTooLarge
	}
	return nil
}

// redactURLError drops the URL (which may carry tokens) from client errors.
func redactURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %v", ue.Op, ue.Err)
	}
	return err
}
