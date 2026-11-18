package transport

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
)

func rotationProfile(t *testing.T) profile.Profile {
	t.Helper()
	p, e := profile.Parse([]byte(`{"type":"hysteria2","server":"192.0.2.10","server_port":443,"password":"PUBLIC_TEST_AUTH","obfs":{"type":"gecko","password":"PUBLIC_TEST_OBFS"},"tls":{"enabled":true,"server_name":"seed.e-connect.example.com"},"flr_random_sni_suffix":"e-connect.example.com"}`))
	if e != nil {
		t.Fatal(e)
	}
	return p[0]
}
func engineScript(t *testing.T, capability string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\ncase \"$1\" in\n flr-capabilities) printf '%s\\n' '" + capability + "';;\n check) exit 0;;\n *) exit 23;;\nesac\n"
	if e := os.WriteFile(filepath.Join(dir, "sing-box"), []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	t.Setenv("PATH", dir)
}
func TestRandomSNIValidateRequiresExplicitEngineCapability(t *testing.T) {
	for _, output := range []string{"", `{}`, `{"version":1,"capabilities":["random-sni-at-export"]}`, `{"version":1,"capabilities":["hysteria2-random-sni-per-quic-dial-v1"]} trailing`} {
		t.Run(fmt.Sprint(len(output)), func(t *testing.T) {
			engineScript(t, output)
			if e := Validate(context.Background(), rotationProfile(t), "eth1"); e == nil {
				t.Fatal("unpatched or malformed capability accepted")
			}
		})
	}
	t.Run("patched", func(t *testing.T) {
		engineScript(t, `{"version":1,"capabilities":["hysteria2-random-sni-per-quic-dial-v1"]}`)
		if e := Validate(context.Background(), rotationProfile(t), "eth1"); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("absent", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		if e := Validate(context.Background(), rotationProfile(t), "eth1"); e == nil {
			t.Fatal("missing engine accepted")
		}
	})
}

type untouchedWAN struct{ called bool }

func (w *untouchedWAN) Resolve(context.Context, string, string) (string, error) {
	w.called = true
	return "", fmt.Errorf("WAN touched")
}
func (w *untouchedWAN) Pin(context.Context, string, string) (func() error, error) {
	w.called = true
	return nil, fmt.Errorf("WAN touched")
}
func TestRandomSNIStartChecksCapabilityBeforeWANMutation(t *testing.T) {
	engineScript(t, `{}`)
	wan := &untouchedWAN{}
	backend := &ProcessBackend{WAN: "eth1", Adapter: wan}
	e := backend.StartBudget(context.Background(), context.Background(), rotationProfile(t))
	if e == nil || !strings.Contains(e.Error(), "capability") || wan.called {
		t.Fatalf("gate missing before WAN preparation: %v touched=%v", e, wan.called)
	}
}
