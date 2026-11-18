package config

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// awgRoamInterface is the managed native interface (health.Device(AWG)).
const awgRoamInterface = "flr_awg"

func validPeerKey(key string) bool {
	decoded, err := base64.StdEncoding.Strict().DecodeString(key)
	return err == nil && len(decoded) == 32 && !bytes.Equal(decoded, make([]byte, 32))
}

// SetAWGRoamPorts moves both ends of the outer UDP flow in one command:
// `awg set flr_awg listen-port <lp> peer <key> endpoint <ip>:<port>`. The
// kernel applies it as one device update: the socket is rebound first and,
// if the bind fails (port in use), nothing else changes. Changing only the
// endpoint port would keep the router's source port, so the server's
// redirect would map successive flows onto the same reply tuple while the
// previous conntrack entry is alive (a NAT clash); a fresh source port gives
// every rotation a distinct 5-tuple on both sides. Only the kernel device is
// changed, never UCI: the next interface reload returns to the stored
// endpoint and a kernel-chosen listen port. The socket mark (fwmark) that the
// dataplane uses to recognise outer AWG packets is unchanged by a rebind.
func SetAWGRoamPorts(ctx context.Context, publicKey string, listenPort uint16, endpoint netip.AddrPort) error {
	return setAWGRoamPortsWith(ctx, awgCommand, publicKey, listenPort, endpoint)
}

func setAWGRoamPortsWith(ctx context.Context, command awgCommandFunc, publicKey string, listenPort uint16, endpoint netip.AddrPort) error {
	if !validPeerKey(publicKey) || listenPort == 0 || !endpoint.Addr().Is4() || endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() || endpoint.Port() == 0 {
		return fmt.Errorf("invalid AWG roam ports")
	}
	if _, err := command(ctx, "awg", "set", awgRoamInterface, "listen-port", strconv.Itoa(int(listenPort)), "peer", publicKey, "endpoint", endpoint.String()); err != nil {
		return fmt.Errorf("AWG port update failed")
	}
	return nil
}

// AWGListenPort reads the live listen (source) port of the managed interface
// with `awg show flr_awg listen-port`.
func AWGListenPort(ctx context.Context) (uint16, error) {
	return awgListenPortWith(ctx, awgCommand)
}

func awgListenPortWith(ctx context.Context, command awgCommandFunc) (uint16, error) {
	raw, err := command(ctx, "awg", "show", awgRoamInterface, "listen-port")
	if err != nil {
		return 0, fmt.Errorf("AWG listen port unavailable")
	}
	text := strings.TrimSpace(string(raw))
	port, err := strconv.Atoi(text)
	if err != nil || port < 1 || port > 65535 || text != strconv.Itoa(port) {
		return 0, fmt.Errorf("AWG listen port rejected")
	}
	return uint16(port), nil
}

// AWGLatestHandshake reads the peer's latest handshake from
// `awg show flr_awg latest-handshakes`. A zero time means no handshake yet.
func AWGLatestHandshake(ctx context.Context, publicKey string) (time.Time, error) {
	return awgLatestHandshakeWith(ctx, awgCommand, publicKey)
}

func awgLatestHandshakeWith(ctx context.Context, command awgCommandFunc, publicKey string) (time.Time, error) {
	if !validPeerKey(publicKey) {
		return time.Time{}, fmt.Errorf("invalid AWG peer key")
	}
	raw, err := command(ctx, "awg", "show", awgRoamInterface, "latest-handshakes")
	if err != nil {
		return time.Time{}, fmt.Errorf("AWG handshake unavailable")
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != publicKey {
			continue
		}
		seconds, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || seconds < 0 {
			return time.Time{}, fmt.Errorf("AWG handshake rejected")
		}
		if seconds == 0 {
			return time.Time{}, nil
		}
		return time.Unix(seconds, 0), nil
	}
	return time.Time{}, fmt.Errorf("AWG peer not found")
}
