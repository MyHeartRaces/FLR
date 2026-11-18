package controller

import (
	"errors"
	"net"
	"os"
	"testing"

	"github.com/MyHeartRaces/FLR/runtime/internal/lan"
)

// Tests run against a router whose LAN is 192.168.8.1/24 unless they replace
// lan.Source themselves, so results never depend on the build host's network.
func TestMain(m *testing.M) {
	lan.Source = lan.FixedSource("192.168.8.1/24")
	os.Exit(m.Run())
}

func useLAN(t *testing.T, cidr string) {
	t.Helper()
	old := lan.Source
	lan.Source = lan.FixedSource(cidr)
	t.Cleanup(func() { lan.Source = old })
}

// failLAN makes LAN discovery fail, as when br-lan has no IPv4 address yet.
func failLAN(t *testing.T) {
	t.Helper()
	old := lan.Source
	lan.Source = func(string) ([]net.Addr, error) {
		return nil, errors.New("LAN interface br-lan has no private IPv4 address")
	}
	t.Cleanup(func() { lan.Source = old })
}
