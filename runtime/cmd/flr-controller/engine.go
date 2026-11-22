package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/engineupdate"
	"github.com/MyHeartRaces/FLR/runtime/internal/privatefile"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
	"github.com/MyHeartRaces/FLR/runtime/internal/transport"
)

// Exit codes of `flr-controller engine`:
//
//	0 success, including "nothing to do", skipped cycles and would-promote
//	1 runtime error (I/O, network, lock, config unreadable)
//	2 usage or configuration error
//	3 a candidate was rejected (check/run; blocked in apply mode)
//	4 another engine update operation holds the lock
const (
	engineOK       = 0
	engineError    = 1
	engineUsage    = 2
	engineRejected = 3
	engineBusy     = 4
)

const engineWAN = "eth1"

func engineMain(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: flr-controller engine status|check|run|hold|unhold|unblock|rollback|loop|qualify-relay")
		return engineUsage
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "root required")
		return engineError
	}
	env := engineupdate.DefaultEnv()
	if args[0] == "qualify-relay" {
		return qualifyRelayCLI(args[1:], env)
	}
	cfg, cerr := engineupdate.LoadConfig(env.ConfigPath())
	noConfig := errors.Is(cerr, engineupdate.ErrNoConfig)
	if cerr != nil && !noConfig {
		fmt.Fprintln(os.Stderr, cerr)
		return engineUsage
	}
	logger := log.New(os.Stderr, "engine-update: ", 0)
	base := &engineupdate.Updater{Cfg: cfg, Env: env, Exec: engineupdate.OSExec{}, Logf: logger.Printf}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	finish := func(err error) int {
		switch {
		case err == nil:
			return engineOK
		case errors.Is(err, engineupdate.ErrBusy):
			fmt.Fprintln(os.Stderr, err)
			return engineBusy
		default:
			fmt.Fprintln(os.Stderr, err)
			return engineError
		}
	}
	switch args[0] {
	case "status":
		r, err := base.Status(ctx, !noConfig)
		if err != nil {
			return finish(err)
		}
		return finish(json.NewEncoder(os.Stdout).Encode(r))
	case "check", "run":
		if noConfig || !cfg.Enabled {
			fmt.Fprintln(os.Stderr, "engine updates are disabled (no engine-update.json or enabled=false)")
			return engineUsage
		}
		mode := cfg.Mode
		if args[0] == "check" {
			mode = engineupdate.ModeCheck
		}
		up, err := buildEngineUpdater(cfg, env, logger)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return engineError
		}
		rep, err := up.Cycle(ctx, mode)
		if rep != nil {
			json.NewEncoder(os.Stdout).Encode(rep)
		}
		if err != nil {
			return finish(err)
		}
		if rep.Rejected() {
			return engineRejected
		}
		return engineOK
	case "hold", "unhold":
		if len(args) != 2 {
			return engineUsageMsg("hold|unhold needs <engine>")
		}
		return finish(base.SetHold(args[1], args[0] == "hold"))
	case "unblock":
		if len(args) != 3 {
			return engineUsageMsg("unblock needs <engine> <version>")
		}
		return finish(base.Unblock(args[1], args[2]))
	case "rollback":
		if len(args) != 2 {
			return engineUsageMsg("rollback needs <engine>")
		}
		return finish(base.Rollback(args[1]))
	case "loop":
		// Disabled or absent config: exit 0 at once (procd respawn throttles).
		err := base.Loop(ctx,
			func() (engineupdate.Config, error) { return engineupdate.LoadConfig(env.ConfigPath()) },
			func(c engineupdate.Config) *engineupdate.Updater {
				up, err := buildEngineUpdater(c, env, logger)
				if err != nil {
					logger.Printf("cannot build updater: %v", err)
					return &engineupdate.Updater{Cfg: c, Env: env, Fetcher: failFetcher{err}, Exec: engineupdate.OSExec{}, Logf: logger.Printf, Scope: engineScope{}, Canary: &engineupdate.SocksCanary{}}
				}
				return up
			})
		return finish(err)
	}
	return engineUsageMsg("unknown engine command")
}

func engineUsageMsg(m string) int {
	fmt.Fprintln(os.Stderr, m)
	return engineUsage
}

type failFetcher struct{ err error }

func (f failFetcher) Fetch(context.Context, string, io.Writer, int64) error { return f.err }

func buildEngineUpdater(cfg engineupdate.Config, env engineupdate.Env, logger *log.Logger) (*engineupdate.Updater, error) {
	token := ""
	if cfg.AuthTokenFile != "" {
		b, err := os.ReadFile(cfg.AuthTokenFile)
		if err != nil {
			return nil, errors.New("auth_token_file unreadable")
		}
		token = strings.TrimSpace(string(b))
	}
	return &engineupdate.Updater{
		Cfg: cfg, Env: env, Exec: engineupdate.OSExec{}, Logf: logger.Printf,
		Fetcher: &engineupdate.TunnelFetcher{Status: engineupdate.APIStatus{}, ChannelURL: cfg.ChannelURL, Token: token},
		Canary:  &engineupdate.SocksCanary{},
		Scope:   engineScope{registryPath: filepath.Join(env.ConfigDir, "registry.json")},
	}, nil
}

// engineScope renders the production sing-box config of every enabled
// connection that uses the engine. It reads the registry only; it does not
// start, stop or reconfigure anything.
type engineScope struct{ registryPath string }

func (s engineScope) Connections(ctx context.Context, engine string) ([]engineupdate.Target, error) {
	// connection.Load treats a missing registry as empty for initial setup.
	// An updater cannot use that as evidence that an engine is unused.
	raw, err := privatefile.Read(s.registryPath, connection.MaxRegistryBytes)
	if err != nil {
		return nil, errors.New("cannot read connection registry")
	}
	reg, err := connection.Decode(raw)
	if err != nil {
		return nil, err
	}
	return engineTargets(ctx, reg.Connections, engine)
}

// engineTargets owns the freshly decoded connections and may pin their
// in-memory endpoint addresses. No changes are written to the registry.
func engineTargets(ctx context.Context, connections []connection.Connection, engine string) ([]engineupdate.Target, error) {
	if engine != "sing-box" {
		return nil, fmt.Errorf("unsupported canary engine %q", engine)
	}
	var out []engineupdate.Target
	for _, c := range connections {
		if !c.Enabled || c.Family == "awg" {
			continue
		}
		p := c.Profile
		if p == nil {
			return nil, fmt.Errorf("%s: missing proxy profile", c.ID)
		}
		t := engineupdate.Target{ID: c.ID, Name: c.Summary().Name, UDP: p.Capabilities.UDP}
		switch p.Engine {
		case "sing-box":
			server, err := pinBearerForCanary(ctx, p)
			if err != nil {
				return nil, fmt.Errorf("%s: cannot resolve bearer", c.ID)
			}
			t.Server = server
			r, err := profile.Render(*p, engineWAN, transport.RuntimeDir)
			if err != nil {
				return nil, fmt.Errorf("%s: cannot render sing-box config", c.ID)
			}
			t.Config = r.SingBox
		case "xray", "wstunnel":
			// Both also use sing-box. Determine their bearer for scope_servers,
			// but a canary must never borrow a sidecar from the production slot.
			r, err := profile.Render(*p, engineWAN, transport.RuntimeDir)
			if err != nil || len(r.OuterEndpoints) != 1 {
				return nil, fmt.Errorf("%s: cannot classify sidecar bearer", c.ID)
			}
			host, _, err := net.SplitHostPort(r.OuterEndpoints[0])
			if err != nil {
				return nil, fmt.Errorf("%s: invalid sidecar bearer", c.ID)
			}
			t.Server, err = transport.KernelWAN{}.Resolve(ctx, engineWAN, host)
			if err != nil {
				return nil, fmt.Errorf("%s: cannot resolve sidecar bearer", c.ID)
			}
			t.ConfigError = fmt.Errorf("canary requires an isolated %s sidecar", p.Engine)
		default:
			return nil, fmt.Errorf("%s: unknown proxy engine", c.ID)
		}
		out = append(out, t)
	}
	return out, nil
}

// pinBearerForCanary resolves the bearer hostname over the WAN with the outer
// mark (same resolver production uses) and substitutes the IPv4, keeping TLS
// server_name and WS Host on the original name. No route is added.
func pinBearerForCanary(ctx context.Context, p *profile.Profile) (string, error) {
	bearer := p.Outbound
	if p.Detour != nil {
		bearer = p.Detour
	}
	host, _ := bearer["server"].(string)
	if host == "" {
		return "", errors.New("no server in profile")
	}
	addr, err := transport.KernelWAN{}.Resolve(ctx, engineWAN, host)
	if err != nil {
		return "", err
	}
	if net.ParseIP(host) != nil {
		return addr, nil
	}
	if tls, _ := bearer["tls"].(map[string]any); tls != nil {
		if n, _ := tls["server_name"].(string); n == "" {
			tls["server_name"] = host
		}
	}
	if tr, _ := bearer["transport"].(map[string]any); tr != nil && tr["type"] == "ws" {
		h, _ := tr["headers"].(map[string]any)
		if h == nil {
			h = map[string]any{}
			tr["headers"] = h
		}
		if h["Host"] == nil {
			h["Host"] = host
		}
	}
	bearer["server"] = addr
	return addr, nil
}
