package hysteria2

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	sbTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	qtls "github.com/sagernet/sing-quic"
	aTLS "github.com/sagernet/sing/common/tls"
)

// The wrapper is installed only for the opt-in Hysteria field. No entropy is
// consumed until an actual QUIC dial callback runs. Existing QUIC connection
// reuse and port hopping remain owned by the upstream Hysteria client.
type flrRandomSNIConfig struct {
	aTLS.Config
	suffix string
	state  *flrRandomSNIState
}
type flrRandomSNIState struct {
	sync.Mutex
	entropy  io.Reader
	previous string
}

var _ qtls.Config = (*flrRandomSNIConfig)(nil)

func flrDNSLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, c := range []byte(label) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
func validateFLRRandomSNI(o option.Hysteria2OutboundOptions) error {
	if o.FLRRandomSNISuffix == nil {
		return fmt.Errorf("missing random SNI suffix")
	}
	suffix := *o.FLRRandomSNISuffix
	labels := strings.Split(suffix, ".")
	if len(suffix) > 220 || len(labels) < 2 || net.ParseIP(suffix) != nil {
		return fmt.Errorf("invalid random SNI suffix")
	}
	for _, label := range labels {
		if !flrDNSLabel(label) {
			return fmt.Errorf("invalid random SNI suffix")
		}
	}
	ip := net.ParseIP(o.Server)
	if ip == nil || ip.To4() == nil || o.Realm != nil {
		return fmt.Errorf("random SNI requires a fixed IPv4 endpoint")
	}
	t := o.TLS
	if t == nil || !t.Enabled || t.Insecure || t.DisableSNI || t.UTLS != nil || t.Reality != nil || t.ECH != nil || t.Engine != "" {
		return fmt.Errorf("unsupported random SNI TLS configuration")
	}
	seed := strings.TrimSuffix(t.ServerName, "."+suffix)
	if seed == t.ServerName || len(t.ServerName) > 253 || !flrDNSLabel(seed) {
		return fmt.Errorf("random SNI requires a verified one-label seed name")
	}
	return nil
}
func newFLRRandomSNIConfig(base aTLS.Config, o option.Hysteria2OutboundOptions, entropy io.Reader) (aTLS.Config, error) {
	if err := validateFLRRandomSNI(o); err != nil {
		return nil, err
	}
	// Reject engines with additional verification/name semantics until audited.
	if _, ok := base.(*sbTLS.STDClientConfig); !ok {
		return nil, fmt.Errorf("random SNI requires the audited Go TLS engine")
	}
	return &flrRandomSNIConfig{Config: base, suffix: *o.FLRRandomSNISuffix, state: &flrRandomSNIState{entropy: entropy}}, nil
}
func (c *flrRandomSNIConfig) Clone() aTLS.Config {
	return &flrRandomSNIConfig{Config: c.Config.Clone(), suffix: c.suffix, state: c.state}
}
func (c *flrRandomSNIConfig) nextName() (string, error) {
	c.state.Lock()
	defer c.state.Unlock()
	for attempts := 0; attempts < 8; attempts++ {
		var random [16]byte
		if _, err := io.ReadFull(c.state.entropy, random[:]); err != nil {
			return "", fmt.Errorf("random SNI entropy unavailable")
		}
		name := hex.EncodeToString(random[:]) + "." + c.suffix
		if name != c.state.previous {
			c.state.previous = name
			return name, nil
		}
	}
	return "", fmt.Errorf("random SNI entropy repeated")
}
func (c *flrRandomSNIConfig) nextConfig() (aTLS.Config, error) {
	name, err := c.nextName()
	if err != nil {
		return nil, err
	}
	config := c.Config.Clone()
	config.SetServerName(name)
	return config, nil
}
func (c *flrRandomSNIConfig) Dial(ctx context.Context, conn net.Conn, config *quic.Config) (*quic.Conn, error) {
	tlsConfig, err := c.nextConfig()
	if err != nil {
		return nil, err
	}
	return qtls.Dial(ctx, conn, tlsConfig, config)
}
func (c *flrRandomSNIConfig) DialEarly(ctx context.Context, conn net.Conn, config *quic.Config) (*quic.Conn, error) {
	tlsConfig, err := c.nextConfig()
	if err != nil {
		return nil, err
	}
	return qtls.DialEarly(ctx, conn, tlsConfig, config)
}
func (c *flrRandomSNIConfig) wrapTransport(transport *http3.Transport) {
	terminal := transport.Dial
	transport.Dial = func(ctx context.Context, addr string, base *tls.Config, config *quic.Config) (*quic.Conn, error) {
		name, err := c.nextName()
		if err != nil {
			return nil, err
		}
		tlsConfig := base.Clone()
		tlsConfig.ServerName = name
		return terminal(ctx, addr, tlsConfig, config)
	}
}

type flrFailedTransport struct{ err error }

func (t flrFailedTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, t.err }
func (c *flrRandomSNIConfig) transport(result http.RoundTripper, err error) http.RoundTripper {
	if err != nil {
		return flrFailedTransport{err}
	}
	transport, ok := result.(*http3.Transport)
	if !ok || transport.Dial == nil {
		return flrFailedTransport{fmt.Errorf("unsupported random SNI QUIC transport")}
	}
	c.wrapTransport(transport)
	return transport
}
func (c *flrRandomSNIConfig) CreateTransport(conn net.Conn, pointer **quic.Conn, config *quic.Config) http.RoundTripper {
	return c.transport(qtls.CreateTransport(conn, pointer, c.Config, config))
}
func (c *flrRandomSNIConfig) CreatePacketTransport(conn net.PacketConn, addr net.Addr, pointer **quic.Conn, config *quic.Config) http.RoundTripper {
	return c.transport(qtls.CreatePacketTransport(conn, addr, pointer, c.Config, config))
}
