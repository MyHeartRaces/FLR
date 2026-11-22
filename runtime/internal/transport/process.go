package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/config"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/dataplane"
	"github.com/MyHeartRaces/FLR/runtime/internal/diagnostic"
	dnsbroker "github.com/MyHeartRaces/FLR/runtime/internal/dns"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
)

const RuntimeDir = "/var/run/flr-runtime/transport"

// WANAdapter provides bounded WAN-only DNS resolution plus owned route pinning.
// This is required for wstunnel, which has SO_MARK but no interface-bind flag.
type WANAdapter interface {
	Resolve(context.Context, string, string) (string, error)
	Pin(context.Context, string, string) (func() error, error)
}
type KernelWAN struct{}

func (KernelWAN) Resolve(ctx context.Context, wan, host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			return "", fmt.Errorf("outer endpoint requires IPv4")
		}
		return ip.String(), nil
	}
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dnsbroker.DialMarked(ctx, network, "1.1.1.1:53", contract.OuterMark, wan)
	}}
	ips, e := resolver.LookupIP(ctx, "ip4", host)
	if e != nil || len(ips) == 0 {
		return "", fmt.Errorf("outer WAN DNS failed")
	}
	return ips[0].String(), nil
}
func (KernelWAN) Pin(ctx context.Context, wan, address string) (func() error, error) {
	// Never replace a foreign exact host route. netifd may already pin the
	// shared AWG/HY2 VPS to WAN; that route can be borrowed without ownership.
	raw, e := exec.CommandContext(ctx, "ip", "-N", "-j", "-4", "route", "show", "exact", address+"/32").Output()
	if e != nil {
		return nil, fmt.Errorf("cannot inspect WAN host route")
	}
	var existing []map[string]any
	if json.Unmarshal(raw, &existing) != nil || len(existing) > 1 {
		return nil, fmt.Errorf("invalid outer host route")
	}
	if len(existing) == 1 && existing[0]["dev"] != wan {
		return nil, fmt.Errorf("outer host route is not WAN")
	}
	if len(existing) == 1 && fmt.Sprint(existing[0]["protocol"]) == "186" {
		return nil, fmt.Errorf("pre-existing owned WAN pin must be recovered first")
	}
	raw, e = exec.CommandContext(ctx, "ip", "-N", "-j", "-4", "route", "get", address, "mark", "2147483648").Output()
	if e != nil {
		return nil, fmt.Errorf("outer WAN route unavailable")
	}
	var routes []struct {
		Device  string `json:"dev"`
		Gateway string `json:"gateway"`
	}
	if json.Unmarshal(raw, &routes) != nil || len(routes) != 1 || routes[0].Device != wan {
		return nil, fmt.Errorf("outer route is not WAN")
	}
	if len(existing) == 1 {
		return func() error { return nil }, nil
	}
	args := []string{"-4", "route", "add", address + "/32"}
	if routes[0].Gateway != "" {
		if net.ParseIP(routes[0].Gateway) == nil {
			return nil, fmt.Errorf("invalid WAN gateway")
		}
		args = append(args, "via", routes[0].Gateway)
	}
	args = append(args, "dev", wan, "proto", "186")
	if e = exec.CommandContext(ctx, "ip", args...).Run(); e != nil {
		return nil, fmt.Errorf("cannot pin outer WAN route")
	}
	return func() error { return releasePin(wan, address) }, nil
}

type child struct {
	cancel context.CancelFunc
	done   chan struct{}
	exited atomic.Bool
}
type ProcessBackend struct {
	WAN      string
	Adapter  WANAdapter
	mu       sync.Mutex
	children []*child
	releases []func() error
}

func Available() map[string]bool {
	result := map[string]bool{}
	for _, name := range []string{"sing-box", "xray", "wstunnel", "awg"} {
		_, e := exec.LookPath(name)
		result[name] = e == nil
	}
	return result
}
func privateDir(dir string) error {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	info, e := os.Lstat(dir)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return fmt.Errorf("runtime directory must be private")
	}
	return nil
}
func writeRendered(dir string, r profile.Rendered) error {
	for name, data := range map[string][]byte{"proxy-sing-box.json": r.SingBox, "proxy-xray.json": r.Xray, "proxy-sidecar.json": r.Sidecar} {
		if len(data) == 0 {
			continue
		}
		path := filepath.Join(dir, name)
		if info, e := os.Lstat(path); e == nil && (!info.Mode().IsRegular() || info.Mode().Perm() != 0600) {
			return fmt.Errorf("unsafe engine configuration path")
		}
		if e := os.WriteFile(path, data, 0600); e != nil {
			return fmt.Errorf("cannot write private engine configuration")
		}
	}
	return nil
}

// Validate executes only installed fixed engine check commands. A missing
// optional component is represented as disabled by Registry.ApplyAvailability.
func Validate(ctx context.Context, p profile.Profile, wan string) error {
	if e := requireRandomSNICapability(ctx, p); e != nil {
		return e
	}
	dir, e := os.MkdirTemp("", "flr-engine-check-")
	if e != nil {
		return fmt.Errorf("cannot create validation directory")
	}
	defer os.RemoveAll(dir)
	r, e := profile.Render(p, wan, dir)
	if e != nil {
		return fmt.Errorf("profile render rejected")
	}
	if e = writeRendered(dir, r); e != nil {
		return e
	}
	checks := [][]string{{"sing-box", "check", "-c", filepath.Join(dir, "proxy-sing-box.json")}}
	if len(r.Xray) > 0 {
		checks = append(checks, []string{"xray", "run", "-test", "-config", filepath.Join(dir, "proxy-xray.json")})
	}
	for _, args := range checks {
		if _, e = exec.LookPath(args[0]); e != nil {
			continue
		}
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		e = exec.CommandContext(bounded, args[0], args[1:]...).Run()
		cancel()
		if e != nil {
			return fmt.Errorf("engine configuration rejected")
		}
	}
	return nil
}

// pinnedProfile works on the manager's cloned candidate. Registry payloads are
// never mutated. TLS SNI and HTTP Host continue to use the original hostname.
func pinnedProfile(ctx context.Context, p profile.Profile, wan string, a WANAdapter) (profile.Profile, []string, error) {
	var bearer map[string]any
	key := "server"
	switch p.Engine {
	case "sing-box":
		bearer = p.Outbound
		if p.Detour != nil {
			bearer = p.Detour
		}
	case "xray":
		settings, _ := p.Outbound["settings"].(map[string]any)
		servers, _ := settings["vnext"].([]any)
		if len(servers) != 1 {
			return p, nil, fmt.Errorf("invalid native endpoint")
		}
		bearer, _ = servers[0].(map[string]any)
		key = "address"
	case "wstunnel":
		bearer = p.WGWS.Websocket
	default:
		return p, nil, fmt.Errorf("unsupported engine")
	}
	host, _ := bearer[key].(string)
	address, e := a.Resolve(ctx, wan, host)
	if e != nil {
		return p, nil, e
	}
	if net.ParseIP(address) == nil || net.ParseIP(address).To4() == nil {
		return p, nil, fmt.Errorf("outer resolution must be IPv4")
	}
	if net.ParseIP(host) == nil {
		if p.Engine == "wstunnel" {
			if sni, _ := bearer["sni"].(string); sni == "" {
				bearer["sni"] = host
			}
			if h, _ := bearer["host"].(string); h == "" {
				bearer["host"] = host
			}
		} else if p.Engine == "xray" {
			stream, _ := p.Outbound["streamSettings"].(map[string]any)
			for _, kind := range []string{"tlsSettings", "realitySettings"} {
				if tls, _ := stream[kind].(map[string]any); tls != nil {
					if name, _ := tls["serverName"].(string); name == "" {
						tls["serverName"] = host
					}
				}
			}
		} else if p.Engine == "sing-box" {
			if tls, _ := bearer["tls"].(map[string]any); tls != nil {
				if name, _ := tls["server_name"].(string); name == "" {
					tls["server_name"] = host
				}
			}
			if transport, _ := bearer["transport"].(map[string]any); transport != nil {
				if transport["type"] == "ws" {
					headers, _ := transport["headers"].(map[string]any)
					if headers == nil {
						headers = map[string]any{}
						transport["headers"] = headers
					}
					if headers["Host"] == nil {
						headers["Host"] = host
					}
				}
			}
		}
	}
	bearer[key] = address
	return p, []string{address}, nil
}
func (b *ProcessBackend) Start(ctx context.Context, p profile.Profile) error {
	return b.StartBudget(ctx, ctx, p)
}
func (b *ProcessBackend) StartBudget(lifetime, ctx context.Context, p profile.Profile) error {
	return b.startBudget(lifetime, ctx, p, nil)
}
func (b *ProcessBackend) startBudget(lifetime, ctx context.Context, p profile.Profile, a *diagnostic.Attempt) (err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	start := time.Now()
	defer func() {
		if a != nil && a.Apply.Outcome == "" {
			stageErr := err
			if err != nil && ctx.Err() != nil {
				stageErr = ctx.Err()
			}
			a.Apply = operationStage(start, stageErr)
		}
	}()
	if len(b.children) > 0 {
		return fmt.Errorf("proxy slot already running")
	}
	if e := requireRandomSNICapability(ctx, p); e != nil {
		return e
	}
	if b.Adapter == nil {
		b.Adapter = KernelWAN{}
	}
	bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	p, addresses, e := pinnedProfile(bounded, p, b.WAN, b.Adapter)
	if e != nil {
		return fmt.Errorf("outer WAN preparation failed")
	}
	if e = savePins(b.WAN, addresses); e != nil {
		return fmt.Errorf("cannot journal WAN pins")
	}
	cleanup := func() {
		failed := false
		for _, release := range b.releases {
			if release() != nil {
				failed = true
			}
		}
		if !failed {
			b.releases = nil
			os.Remove(pinJournal)
		}
	}
	for _, address := range addresses {
		release, err := b.Adapter.Pin(bounded, b.WAN, address)
		if err != nil {
			cleanup()
			return fmt.Errorf("outer WAN pin failed")
		}
		b.releases = append(b.releases, release)
	}
	if e = config.MigrateSlot(); e != nil {
		cleanup()
		return fmt.Errorf("slot firewall migration failed")
	}
	if e = privateDir(RuntimeDir); e != nil {
		cleanup()
		return e
	}
	rendered, e := profile.Render(p, b.WAN, RuntimeDir)
	if e != nil {
		cleanup()
		return fmt.Errorf("candidate render failed")
	}
	if e = writeRendered(RuntimeDir, rendered); e != nil {
		cleanup()
		return e
	}
	commands := [][]string{}
	if len(rendered.Xray) > 0 {
		commands = append(commands, append([]string{"xray"}, rendered.XrayArgs...))
	}
	if len(rendered.SidecarArgs) > 0 {
		commands = append(commands, append([]string{"wstunnel"}, rendered.SidecarArgs...))
	}
	commands = append(commands, append([]string{"sing-box"}, rendered.SingBoxArgs...))
	for _, args := range commands {
		if ctx.Err() != nil {
			return fmt.Errorf("engine startup cancelled")
		}
		childCtx, childCancel := context.WithCancel(lifetime)
		cmd := exec.CommandContext(childCtx, args[0], args[1:]...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
		if e = cmd.Start(); e != nil {
			childCancel()
			for _, c := range b.children {
				c.cancel()
			}
			for _, c := range b.children {
				<-c.done
			}
			b.children = nil
			cleanup()
			return fmt.Errorf("engine start failed")
		}
		c := &child{cancel: childCancel, done: make(chan struct{})}
		b.children = append(b.children, c)
		go func(c *child) { cmd.Wait(); c.exited.Store(true); close(c.done) }(c)
	}
	// Wait for the owned TUN to be created before installing its policy route.
	if a != nil {
		a.Apply = attemptStage(start, "ok")
	}
	ready := time.Now()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for !health.Present(contract.Gecko) {
		select {
		case <-ctx.Done():
			if a != nil {
				a.Ready = operationStage(ready, ctx.Err())
			}
			return fmt.Errorf("engine startup cancelled")
		case <-deadline.C:
			if a != nil {
				a.Ready = attemptStage(ready, "timeout")
			}
			return fmt.Errorf("engine TUN startup timeout")
		case <-time.After(25 * time.Millisecond):
		}
	}
	// The slot route must exist before health probes or LAN selection can use it.
	if a != nil {
		a.Ready = attemptStage(ready, "ok")
	}
	routes := time.Now()
	e = dataplane.EnsureRoutes()
	if a != nil {
		a.Routes = operationStage(routes, e)
	}
	if e != nil {
		for _, c := range b.children {
			c.cancel()
		}
		return fmt.Errorf("slot route unavailable")
	}
	return nil
}
func (b *ProcessBackend) Alive() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.children) == 0 {
		return false
	}
	for _, c := range b.children {
		if c.exited.Load() {
			return false
		}
	}
	return true
}
func (b *ProcessBackend) Stop() error {
	b.mu.Lock()
	children := b.children
	for _, c := range children {
		c.cancel()
	}
	b.mu.Unlock()
	for _, c := range children {
		select {
		case <-c.done:
		case <-time.After(5 * time.Second):
			return fmt.Errorf("engine shutdown timeout")
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.children = nil
	var failure error
	for _, release := range b.releases {
		if e := release(); e != nil {
			failure = fmt.Errorf("WAN pin cleanup failed")
		}
	}
	if failure == nil {
		b.releases = nil
		os.Remove(pinJournal)
	}
	for _, name := range []string{"proxy-sing-box.json", "proxy-xray.json", "proxy-sidecar.json"} {
		os.Remove(filepath.Join(RuntimeDir, name))
	}
	return failure
}
