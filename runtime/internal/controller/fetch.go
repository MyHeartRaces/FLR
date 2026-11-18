package controller

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	dnsbroker "github.com/MyHeartRaces/FLR/runtime/internal/dns"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
)

type Fetcher struct {
	WAN    string
	Lookup func(context.Context, string) ([]net.IP, error)
}

func publicIP(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	if !a.Is4() || !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range []string{"0.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"} {
		if netip.MustParsePrefix(prefix).Contains(a) {
			return false
		}
	}
	return true
}
func (f Fetcher) resolve(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if !publicIP(ip) {
			return nil, fmt.Errorf("subscription destination is not public IPv4")
		}
		return []net.IP{ip}, nil
	}
	lookup := f.Lookup
	if lookup == nil {
		resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dnsbroker.DialMarked(ctx, network, "1.1.1.1:53", contract.OuterMark, f.WAN)
		}}
		// net.Resolver.LookupIP accepts a network argument; use an explicit IPv4
		// adapter instead of allowing an uncontrolled system resolver.
		lookup = func(ctx context.Context, host string) ([]net.IP, error) { return resolver.LookupIP(ctx, "ip4", host) }
	}
	ips, e := lookup(ctx, host)
	if e != nil || len(ips) == 0 {
		return nil, fmt.Errorf("subscription DNS failed")
	}
	for _, ip := range ips {
		if !publicIP(ip) {
			return nil, fmt.Errorf("subscription DNS contains non-public address")
		}
	}
	return ips, nil
}
func subscriptionURL(raw string) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || len(raw) > 8192 || (u.Port() != "" && u.Port() != "443") || strings.ContainsAny(raw, "\r\n\x00") {
		return nil, fmt.Errorf("subscription needs HTTPS public host on port443")
	}
	return u, nil
}
func (f Fetcher) Fetch(ctx context.Context, raw string) ([]byte, error) {
	u, e := subscriptionURL(raw)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if _, e = f.resolve(ctx, u.Hostname()); e != nil {
		return nil, e
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 32768}
	defer transport.CloseIdleConnections()
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil || port != "443" {
			return nil, fmt.Errorf("invalid subscription endpoint")
		}
		ips, e := f.resolve(ctx, host)
		if e != nil {
			return nil, e
		}
		// The actual connection uses the validated answer. TLS still validates the
		// original URL host, preventing DNS rebinding and preserving certificate checks.
		return dnsbroker.DialMarked(ctx, "tcp", net.JoinHostPort(ips[0].String(), port), contract.OuterMark, f.WAN)
	}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return fmt.Errorf("subscription redirect limit")
		}
		if _, e := subscriptionURL(r.URL.String()); e != nil {
			return e
		}
		_, e := f.resolve(ctx, r.URL.Hostname())
		return e
	}}
	request, e := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if e != nil {
		return nil, fmt.Errorf("subscription request failed")
	}
	response, e := client.Do(request)
	if e != nil {
		return nil, fmt.Errorf("subscription fetch failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("subscription HTTP status rejected")
	}
	data, e := io.ReadAll(io.LimitReader(response.Body, profile.MaxImportBytes+1))
	if e != nil {
		return nil, fmt.Errorf("subscription read failed")
	}
	if len(data) > profile.MaxImportBytes {
		return nil, fmt.Errorf("subscription too large")
	}
	return data, nil
}
