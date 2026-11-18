package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
)

func TestEngineScopeRequiresKnownRegistry(t *testing.T) {
	scope := engineScope{registryPath: filepath.Join(t.TempDir(), "registry.json")}
	if targets, err := scope.Connections(context.Background(), "sing-box"); err == nil || len(targets) != 0 {
		t.Fatalf("missing registry produced %d targets, err=%v", len(targets), err)
	}
}

func TestEngineScopeFailsClosed(t *testing.T) {
	const uri = "hysteria2://fixture@192.0.2.10:443/?obfs=salamander&obfs-password=fixture&sni=example.test"
	items, err := connection.ParseImport([]byte(uri))
	if err != nil {
		t.Fatal(err)
	}
	good := items[0]
	for _, tc := range []struct {
		name string
		edit func(*connection.Connection)
	}{
		{"missing profile", func(c *connection.Connection) { c.Profile = nil }},
		{"unknown engine", func(c *connection.Connection) { c.Profile.Engine = "unknown" }},
		{"unresolved bearer", func(c *connection.Connection) { c.Profile.Outbound["server"] = "::1" }},
		{"unrenderable outbound", func(c *connection.Connection) { c.Profile.Outbound["type"] = "unknown" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := good.Clone()
			bad.ID = "bad"
			tc.edit(&bad)
			targets, err := engineTargets(context.Background(), []connection.Connection{good, bad}, "sing-box")
			if err == nil || len(targets) != 0 {
				t.Fatalf("accepted partial scope: targets=%d err=%v", len(targets), err)
			}
		})
	}
	disabled := connection.Connection{ID: "off", Family: "hy2"}
	native := connection.Connection{ID: "native", Enabled: true, Family: "awg"}
	targets, err := engineTargets(context.Background(), []connection.Connection{disabled, native, good}, "sing-box")
	if err != nil || len(targets) != 1 || targets[0].ID != good.ID || targets[0].Server != "192.0.2.10" || len(targets[0].Config) == 0 {
		t.Fatalf("scope: %d targets, err=%v", len(targets), err)
	}
}

func TestEngineScopeIncludesSidecarDependency(t *testing.T) {
	const uri = "vless://fixture@192.0.2.11:443?security=tls&sni=example.test&type=xhttp&mode=auto"
	items, err := connection.ParseImport([]byte(uri))
	if err != nil {
		t.Fatal(err)
	}
	targets, err := engineTargets(context.Background(), items, "sing-box")
	if err != nil || len(targets) != 1 || targets[0].Server != "192.0.2.11" || targets[0].ConfigError == nil {
		t.Fatalf("unmeasurable sidecar: %d targets, err=%v", len(targets), err)
	}
}
