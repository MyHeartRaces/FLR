package controller

import (
	"context"
	"net"
	"testing"
)

func TestSubscriptionSSRFRejectsPrivateSpecialAndMixedDNS(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "192.168.8.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "198.18.0.1", "::1", "2001:db8::1"} {
		if publicIP(net.ParseIP(s)) {
			t.Fatalf("special address accepted: %s", s)
		}
	}
	f := Fetcher{Lookup: func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("10.0.0.1")}, nil
	}}
	if _, e := f.resolve(context.Background(), "example.com"); e == nil {
		t.Fatal("mixed DNS accepted")
	}
	for _, url := range []string{"http://example.com", "https://user:token@example.com", "https://127.0.0.1", "https://example.com:444"} {
		if _, e := f.Fetch(context.Background(), url); e == nil {
			t.Fatalf("unsafe subscription accepted: %s", url)
		}
	}
}
