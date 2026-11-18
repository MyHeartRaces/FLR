package transport

import (
	"context"
	"os"
	"testing"

	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
)

type fakeWAN struct{ host, wan string }

func (w *fakeWAN) Resolve(_ context.Context, wan, host string) (string, error) {
	w.host = host
	w.wan = wan
	return "192.0.2.40", nil
}
func (w *fakeWAN) Pin(context.Context, string, string) (func() error, error) {
	return func() error { return nil }, nil
}
func TestPinnedWGWSUsesWANAddressAndPreservesTLSHost(t *testing.T) {
	raw, e := os.ReadFile("../profile/testdata/wgws.json")
	if e != nil {
		t.Fatal(e)
	}
	r := &profile.Registry{Version: 1}
	if _, e = r.Import(raw); e != nil {
		t.Fatal(e)
	}
	r.ApplyAvailability(map[string]bool{"sing-box": true, "wstunnel": true})
	p := r.Candidates("")[0]
	original, _ := p.WGWS.Websocket["server"].(string)
	w := &fakeWAN{}
	pinned, addresses, e := pinnedProfile(context.Background(), p, "eth1", w)
	if e != nil {
		t.Fatal(e)
	}
	if w.wan != "eth1" || w.host != original || len(addresses) != 1 || addresses[0] != "192.0.2.40" {
		t.Fatal("WAN adapter not used")
	}
	if pinned.WGWS.Websocket["server"] != "192.0.2.40" || r.Profiles[0].WGWS.Websocket["server"] != original {
		t.Fatal("pin mutated private registry")
	}
	rendered, e := profile.Render(pinned, "eth1", "/var/run/flr-runtime/transport")
	if e != nil {
		t.Fatal(e)
	}
	if rendered.OuterEndpoints[0] != "192.0.2.40:443" {
		t.Fatal("child can resolve uncontrolled bearer")
	}
}
