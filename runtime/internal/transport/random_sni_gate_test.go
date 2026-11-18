package transport

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
)

func TestRandomSNICapabilityGateFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		out    string
		accept bool
	}{
		{`{}`, false},
		{`{"version":1,"capabilities":["random-sni-at-export"]}`, false},
		{`{"version":1,"capabilities":["hysteria2-random-sni-per-quic-dial-v1"]} trailing`, false},
		{`{"version":1,"capabilities":["hysteria2-random-sni-per-quic-dial-v1"]}`, true},
	} {
		t.Run(tc.out, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("PATH", dir)
			script := "#!/bin/sh\n[ \"$1\" = flr-capabilities ] || exit 42\nprintf '%s\\n' '" + tc.out + "'\n"
			if e := os.WriteFile(filepath.Join(dir, "sing-box"), []byte(script), 0700); e != nil {
				t.Fatal(e)
			}
			p := profile.Profile{Engine: "sing-box", Outbound: map[string]any{"flr_random_sni_suffix": "e-connect.example.com"}}
			e := requireRandomSNICapability(context.Background(), p)
			if (e == nil) != tc.accept {
				t.Fatalf("unexpected capability decision: %v", e)
			}
		})
	}
}
func TestOrdinaryProfileDoesNotRequireCustomCapability(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if e := requireRandomSNICapability(context.Background(), profile.Profile{Engine: "sing-box"}); e != nil {
		t.Fatal(e)
	}
	if e := requireRandomSNICapability(context.Background(), profile.Profile{Engine: "sing-box", Outbound: map[string]any{"flr_random_sni_suffix": "e-connect.example.com"}}); e == nil {
		t.Fatal("missing binary accepted")
	}
}
