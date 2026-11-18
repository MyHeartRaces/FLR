package health

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	dnsbroker "github.com/MyHeartRaces/FLR/runtime/internal/dns"
	"github.com/MyHeartRaces/FLR/runtime/internal/socks"
	mdns "github.com/miekg/dns"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func Device(c contract.Channel) string {
	return map[contract.Channel]string{contract.AWG: "flr_awg", contract.Gecko: "flr-hy", contract.VLESS: "flr-vless"}[c]
}
func Present(c contract.Channel) bool {
	b, e := os.ReadFile("/sys/class/net/" + Device(c) + "/flags")
	if e != nil {
		return false
	}
	flags, e := strconv.ParseUint(strings.TrimSpace(string(b)), 0, 32)
	return e == nil && flags&1 != 0
}
func Proxy(c contract.Channel) string {
	if c == contract.Gecko {
		return "127.0.0.1:1081"
	}
	if c == contract.VLESS {
		return "127.0.0.1:1082"
	}
	return ""
}
func Probe(ctx context.Context, channel contract.Channel) Result {
	return ProbeCapabilities(ctx, channel, true)
}

// Independent provider sockets are literal and never resolved through the path
// under test. Hostname/SNI and application response validation remain fixed.
type probeTarget struct{ name, host, tcpAddress, udpAddress, url string }

var probeProviders = [2]probeTarget{
	{"cloudflare", "www.cloudflare.com", "104.16.124.96:443", "1.1.1.1:53", "https://www.cloudflare.com/cdn-cgi/trace"},
	{"google", "dns.google", "8.8.8.8:443", "8.8.8.8:53", "https://dns.google/resolve?name=example.com&type=A"},
}

type targetProbe func(context.Context, probeTarget) (bool, int64)

func probeHTTPClient(t *http.Transport) *http.Client {
	return &http.Client{Transport: t, Timeout: RoundDeadline, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return fmt.Errorf("probe redirect") }}
}
func ProbeCapabilities(ctx context.Context, channel contract.Channel, probeUDP bool) Result {
	return probeRoute(ctx, channel, probeUDP, "")
}

// WAN is diagnostic-only and binds literal provider sockets to the physical WAN.
func ProbeWAN(ctx context.Context, device string) Result {
	return probeRoute(ctx, contract.Down, true, device)
}
func probeRoute(ctx context.Context, channel contract.Channel, probeUDP bool, wan string) Result {
	return probeTargets(ctx, probeUDP, func(ctx context.Context, target probeTarget) (bool, int64) {
		start := time.Now()
		t := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{ServerName: target.host, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
		defer t.CloseIdleConnections()
		t.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			if wan != "" {
				return dnsbroker.DialMarked(ctx, "tcp", target.tcpAddress, contract.OuterMark|contract.ClassMark(contract.Direct)|contract.ProbeMark, wan)
			}
			if channel == contract.AWG {
				return dnsbroker.DialMarked(ctx, "tcp", target.tcpAddress, contract.ChannelMark(channel)|contract.ClassMark(contract.General)|contract.ProbeMark, Device(channel))
			}
			if proxy := Proxy(channel); proxy != "" {
				return socks.DialContext(ctx, proxy, target.tcpAddress)
			}
			return nil, fmt.Errorf("invalid channel")
		}
		q, e := http.NewRequestWithContext(ctx, "GET", target.url, nil)
		if e != nil {
			return false, 0
		}
		r, e := probeHTTPClient(t).Do(q)
		if e != nil {
			return false, 0
		}
		defer r.Body.Close()
		body, e := io.ReadAll(io.LimitReader(r.Body, 8193))
		if e != nil || len(body) > 8192 || r.StatusCode != 200 {
			return false, 0
		}
		valid := strings.Contains(string(body), "ip=")
		if target.name == "google" {
			var answer struct {
				Status *int
				Answer []json.RawMessage
			}
			valid = json.Unmarshal(body, &answer) == nil && answer.Status != nil && *answer.Status == 0 && len(answer.Answer) > 0
		}
		return valid, elapsedMS(start)
	}, func(ctx context.Context, target probeTarget) (bool, int64) {
		start := time.Now()
		q := new(mdns.Msg)
		q.SetQuestion("example.com.", mdns.TypeA)
		var r *mdns.Msg
		var e error
		if wan != "" {
			r, e = dnsbroker.Plain(ctx, q, target.udpAddress, contract.OuterMark|contract.ClassMark(contract.Direct)|contract.ProbeMark, wan)
		} else if channel == contract.AWG {
			r, e = dnsbroker.Plain(ctx, q, target.udpAddress, contract.ChannelMark(channel)|contract.ProbeMark, Device(channel))
		} else {
			if Proxy(channel) == "" {
				return false, 0
			}
			wire, err := q.Pack()
			if err != nil {
				return false, 0
			}
			b, err := socks.UDPExchange(ctx, Proxy(channel), target.udpAddress, wire)
			if err != nil {
				return false, 0
			}
			r = new(mdns.Msg)
			e = r.Unpack(b)
		}
		valid := e == nil && r != nil && r.Response && r.Id == q.Id && r.Rcode == mdns.RcodeSuccess && len(r.Answer) > 0
		return valid, elapsedMS(start)
	})
}
func elapsedMS(start time.Time) int64 {
	return int64((time.Since(start) + time.Millisecond - 1) / time.Millisecond)
}

// At most four workers share one deadline. Successful request elapsed time is
// distinct from aggregate round duration (which may include a target timeout).
func probeTargets(ctx context.Context, probeUDP bool, tcp, udp targetProbe) Result {
	ctx, cancel := context.WithTimeout(ctx, RoundDeadline)
	defer cancel()
	start := time.Now()
	result := Result{Measured: true}
	var wg sync.WaitGroup
	for i, target := range probeProviders {
		wg.Add(1)
		go func(i int, t probeTarget) {
			defer wg.Done()
			ok, ms := tcp(ctx, t)
			result.Targets[i].TCP = ok
			if ok {
				result.Targets[i].TCPDurationMS = ms
			}
		}(i, target)
		if probeUDP {
			wg.Add(1)
			go func(i int, t probeTarget) {
				defer wg.Done()
				ok, ms := udp(ctx, t)
				result.Targets[i].UDP = ok
				if ok {
					result.Targets[i].UDPDurationMS = ms
				}
			}(i, target)
		}
	}
	wg.Wait()
	for _, t := range result.Targets {
		result.TCP = result.TCP || t.TCP
		result.UDP = result.UDP || t.UDP
	}
	result.RTT = time.Since(start)
	return result
}
