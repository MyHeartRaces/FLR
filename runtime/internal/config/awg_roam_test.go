package config

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

const roamTestKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="

func TestSetAWGRoamPortsChangesBothPortsInOneCommand(t *testing.T) {
	var calls []string
	command := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	}
	if err := setAWGRoamPortsWith(context.Background(), command, roamTestKey, 50123, netip.MustParseAddrPort("192.0.2.10:40123")); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0] != "awg set flr_awg listen-port 50123 peer "+roamTestKey+" endpoint 192.0.2.10:40123" {
		t.Fatal("unexpected roam command", calls)
	}
	for _, bad := range []struct {
		key    string
		listen uint16
		ep     string
	}{{"", 50123, "192.0.2.10:40123"}, {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", 50123, "192.0.2.10:40123"}, {roamTestKey, 0, "192.0.2.10:40123"}, {roamTestKey, 50123, "[2001:db8::1]:40123"}, {roamTestKey, 50123, "0.0.0.0:40123"}, {roamTestKey, 50123, "192.0.2.10:0"}} {
		if setAWGRoamPortsWith(context.Background(), command, bad.key, bad.listen, netip.MustParseAddrPort(bad.ep)) == nil {
			t.Fatal("invalid roam input accepted", bad)
		}
	}
	if len(calls) != 1 {
		t.Fatal("invalid input reached the command", calls)
	}
	failing := func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("exit 1") }
	if setAWGRoamPortsWith(context.Background(), failing, roamTestKey, 50123, netip.MustParseAddrPort("192.0.2.10:40123")) == nil {
		t.Fatal("command failure hidden")
	}
}

func TestAWGListenPortParse(t *testing.T) {
	output := "51871\n"
	command := func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "awg" || strings.Join(args, " ") != "show flr_awg listen-port" {
			t.Fatal("unexpected command", name, args)
		}
		return []byte(output), nil
	}
	if port, err := awgListenPortWith(context.Background(), command); err != nil || port != 51871 {
		t.Fatal("listen port not parsed", port, err)
	}
	for _, bad := range []string{"", "0\n", "65536", "05187", "x"} {
		output = bad
		if _, err := awgListenPortWith(context.Background(), command); err == nil {
			t.Fatal("bad listen port accepted", bad)
		}
	}
}

func TestAWGLatestHandshakeParsesOwnPeer(t *testing.T) {
	other := "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
	output := other + "\t1700000000\n" + roamTestKey + "\t1700000100\n"
	command := func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "awg" || strings.Join(args, " ") != "show flr_awg latest-handshakes" {
			t.Fatal("unexpected command", name, args)
		}
		return []byte(output), nil
	}
	at, err := awgLatestHandshakeWith(context.Background(), command, roamTestKey)
	if err != nil || !at.Equal(time.Unix(1700000100, 0)) {
		t.Fatal("wrong handshake", at, err)
	}
	output = roamTestKey + "\t0\n"
	if at, err = awgLatestHandshakeWith(context.Background(), command, roamTestKey); err != nil || !at.IsZero() {
		t.Fatal("no handshake not reported as zero", at, err)
	}
	output = other + "\t1\n"
	if _, err = awgLatestHandshakeWith(context.Background(), command, roamTestKey); err == nil {
		t.Fatal("missing peer accepted")
	}
	output = roamTestKey + "\tsoon\n"
	if _, err = awgLatestHandshakeWith(context.Background(), command, roamTestKey); err == nil {
		t.Fatal("malformed handshake accepted")
	}
}
