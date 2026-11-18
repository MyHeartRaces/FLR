package hysteria2

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	sbTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common/logger"
	aTLS "github.com/sagernet/sing/common/tls"
)

func flrSuffix(s string) *string { return &s }
func flrTestOptions() option.Hysteria2OutboundOptions {
	return option.Hysteria2OutboundOptions{ServerOptions: option.ServerOptions{Server: "192.0.2.10", ServerPort: 443}, FLRRandomSNISuffix: flrSuffix("e-connect.example.com"), OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true, ServerName: "seed.e-connect.example.com"}}}
}
func flrTestConfig(t *testing.T, reader io.Reader) *flrRandomSNIConfig {
	t.Helper()
	o := flrTestOptions()
	base, e := sbTLS.NewClient(context.Background(), logger.NOP(), o.Server, *o.TLS)
	if e != nil {
		t.Fatal(e)
	}
	config, e := newFLRRandomSNIConfig(base, o, reader)
	if e != nil {
		t.Fatal(e)
	}
	return config.(*flrRandomSNIConfig)
}
func TestFLRActualQUICDialBoundaryRotatesAndClones(t *testing.T) {
	c := flrTestConfig(t, bytes.NewReader(append(bytes.Repeat([]byte{0x11}, 16), bytes.Repeat([]byte{0x22}, 16)...)))
	base := &tls.Config{ServerName: "seed.e-connect.example.com", NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13}
	sentinel := errors.New("terminal dial deliberately stopped")
	var names []string
	terminal := func(_ context.Context, addr string, config *tls.Config, _ *quic.Config) (*quic.Conn, error) {
		if addr != "192.0.2.10:443" || config == base || config.InsecureSkipVerify || config.MinVersion != tls.VersionTLS13 || config.NextProtos[0] != "h3" {
			t.Fatal("dial isolation or TLS settings changed")
		}
		names = append(names, config.ServerName)
		return nil, sentinel
	}
	transport := &http3.Transport{Dial: terminal}
	c.wrapTransport(transport)
	for i := 0; i < 2; i++ {
		if _, e := transport.Dial(context.Background(), "192.0.2.10:443", base, &quic.Config{}); !errors.Is(e, sentinel) {
			t.Fatal(e)
		}
	}
	if names[0] != "11111111111111111111111111111111.e-connect.example.com" || names[1] != "22222222222222222222222222222222.e-connect.example.com" || base.ServerName != "seed.e-connect.example.com" {
		t.Fatal("SNI was chosen before the real dial, repeated, or mutated base")
	}
	cert := &x509.Certificate{DNSNames: []string{"*.e-connect.example.com"}}
	for _, name := range names {
		if e := cert.VerifyHostname(name); e != nil {
			t.Fatal(e)
		}
	}
	if cert.VerifyHostname("a.b.e-connect.example.com") == nil {
		t.Fatal("wildcard unexpectedly accepted deeper name")
	}
}
func TestFLREntropyFailureNeverReachesTerminal(t *testing.T) {
	c := flrTestConfig(t, strings.NewReader("short"))
	called := false
	tr := &http3.Transport{Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
		called = true
		return nil, nil
	}}
	c.wrapTransport(tr)
	if _, e := tr.Dial(context.Background(), "192.0.2.10:443", &tls.Config{}, nil); e == nil || called {
		t.Fatal("entropy failure did not fail closed")
	}
}
func TestFLRTransportHooksAndClonePreservePolicy(t *testing.T) {
	c := flrTestConfig(t, bytes.NewReader(bytes.Repeat([]byte{0x33}, 64)))
	clone := c.Clone()
	if _, ok := clone.(qtls.Config); !ok {
		t.Fatal("Clone lost QUIC hook")
	}
	var pointer *quic.Conn
	for _, tr := range []http.RoundTripper{c.CreateTransport(nil, &pointer, &quic.Config{}), c.CreatePacketTransport(nil, &net.UDPAddr{}, &pointer, &quic.Config{})} {
		h, ok := tr.(*http3.Transport)
		if !ok || h.Dial == nil {
			t.Fatal("real transport hook absent")
		}
	}
}
func TestFLRRejectUnsupportedOrInvalidPolicy(t *testing.T) {
	for _, suffix := range []string{"", "*.example.com", "example.com.", "192.0.2.10", "Example.com", "a..com", "-a.com", "com", "a%b.com", "a\nb.com", "a\rb.com", "a b.com", strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 30)} {
		o := flrTestOptions()
		o.FLRRandomSNISuffix = flrSuffix(suffix)
		if validateFLRRandomSNI(o) == nil {
			t.Fatalf("invalid suffix accepted: %q", suffix)
		}
	}
	for _, mutate := range []func(*option.Hysteria2OutboundOptions){
		func(o *option.Hysteria2OutboundOptions) {
			suffix := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 28)
			o.FLRRandomSNISuffix = flrSuffix(suffix)
			o.TLS.ServerName = strings.Repeat("s", 63) + "." + suffix
		},
		func(o *option.Hysteria2OutboundOptions) { o.Server = "vpn.example.com" },
		func(o *option.Hysteria2OutboundOptions) { o.TLS.ServerName = "a.b.e-connect.example.com" },
		func(o *option.Hysteria2OutboundOptions) { o.TLS.ServerName = "e-connect.example.com" },
		func(o *option.Hysteria2OutboundOptions) { o.TLS.Insecure = true },
		func(o *option.Hysteria2OutboundOptions) { o.TLS.UTLS = &option.OutboundUTLSOptions{Enabled: true} },
		func(o *option.Hysteria2OutboundOptions) { o.TLS.ECH = &option.OutboundECHOptions{Enabled: true} },
		func(o *option.Hysteria2OutboundOptions) {
			o.TLS.Reality = &option.OutboundRealityOptions{Enabled: true}
		},
		func(o *option.Hysteria2OutboundOptions) { o.TLS.Engine = "apple" },
		func(o *option.Hysteria2OutboundOptions) { o.TLS.DisableSNI = true },
	} {
		o := flrTestOptions()
		mutate(&o)
		if validateFLRRandomSNI(o) == nil {
			t.Fatal("unsupported rotation combination accepted")
		}
	}
}

func TestFLRWireDeclarationRejectsEmptyAndWrongType(t *testing.T) {
	for _, raw := range []string{
		`{"flr_random_sni_suffix":""}`,
		`{"flr_random_sni_suffix":true}`,
		`{"flr_random_sni_suffix":"*.example.com"}`,
	} {
		options := flrTestOptions()
		if err := json.Unmarshal([]byte(raw), &options); err == nil && validateFLRRandomSNI(options) == nil {
			t.Fatal("invalid public wire field accepted")
		}
	}
	options := flrTestOptions()
	if err := json.Unmarshal([]byte(`{"flr_random_sni_suffix":"e-connect.example.com"}`), &options); err != nil || validateFLRRandomSNI(options) != nil {
		t.Fatal("public wire field was not declared")
	}
}
func TestFLRRepeatedEntropyFailsClosedAndClonesShareHistory(t *testing.T) {
	c := flrTestConfig(t, bytes.NewReader(bytes.Repeat([]byte{0x44}, 16*10)))
	first, err := c.nextConfig()
	if err != nil {
		t.Fatal(err)
	}
	if first.ServerName() != "44444444444444444444444444444444.e-connect.example.com" || first == c.Config {
		t.Fatal("direct Dial path lost random name or clone")
	}
	clone := c.Clone().(*flrRandomSNIConfig)
	if _, err = clone.nextConfig(); err == nil {
		t.Fatal("Clone repeated previous identity instead of failing closed")
	}
}
func TestFLRRejectsForeignTLSEngineBeforeMutation(t *testing.T) {
	o := flrTestOptions()
	if validateFLRRandomSNI(o) != nil {
		t.Fatal("valid rotation contract rejected; only the engine check must fire")
	}
	foreign := struct{ aTLS.Config }{}
	if _, e := newFLRRandomSNIConfig(foreign, o, bytes.NewReader(bytes.Repeat([]byte{0x55}, 16))); e == nil {
		t.Fatal("non-STD TLS engine accepted for random SNI")
	}
}
func TestFLRRetryEntropyThenSucceeds(t *testing.T) {
	entropy := bytes.Join([][]byte{
		bytes.Repeat([]byte{0x66}, 16),
		bytes.Repeat([]byte{0x66}, 16), // collides with previous, must retry
		bytes.Repeat([]byte{0x77}, 16),
	}, nil)
	c := flrTestConfig(t, bytes.NewReader(entropy))
	want := []string{
		"66666666666666666666666666666666.e-connect.example.com",
		"77777777777777777777777777777777.e-connect.example.com",
	}
	for i, expected := range want {
		config, e := c.nextConfig()
		if e != nil {
			t.Fatal(e)
		}
		if config.ServerName() != expected {
			t.Fatalf("attempt %d: retry did not produce the next distinct name: %q", i, config.ServerName())
		}
	}
}

type flrCounterEntropy struct {
	mu sync.Mutex
	n  byte
}

func (r *flrCounterEntropy) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range p {
		r.n++
		p[i] = r.n
	}
	return len(p), nil
}
func TestFLRConcurrentDialsProduceDistinctNames(t *testing.T) {
	c := flrTestConfig(t, &flrCounterEntropy{})
	base := &tls.Config{ServerName: "seed.e-connect.example.com", NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13}
	sentinel := errors.New("terminal dial deliberately stopped")
	var mu sync.Mutex
	var names []string
	terminal := func(_ context.Context, _ string, config *tls.Config, _ *quic.Config) (*quic.Conn, error) {
		mu.Lock()
		names = append(names, config.ServerName)
		mu.Unlock()
		return nil, sentinel
	}
	transport := &http3.Transport{Dial: terminal}
	c.wrapTransport(transport)
	const goroutines, dials = 8, 2
	var wait sync.WaitGroup
	errs := make(chan error, goroutines*dials)
	for g := 0; g < goroutines; g++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for i := 0; i < dials; i++ {
				if _, e := transport.Dial(context.Background(), "192.0.2.10:443", base, &quic.Config{}); !errors.Is(e, sentinel) {
					errs <- e
				}
			}
		}()
	}
	wait.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	if len(names) != goroutines*dials {
		t.Fatalf("expected %d dials, saw %d", goroutines*dials, len(names))
	}
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			t.Fatalf("duplicate concurrent identity: %q", name)
		}
		seen[name] = true
		cert := &x509.Certificate{DNSNames: []string{"*.e-connect.example.com"}}
		if e := cert.VerifyHostname(name); e != nil {
			t.Fatal(e)
		}
	}
	if base.ServerName != "seed.e-connect.example.com" || len(base.NextProtos) != 1 {
		t.Fatal("concurrent dials mutated the original TLS config")
	}
}
