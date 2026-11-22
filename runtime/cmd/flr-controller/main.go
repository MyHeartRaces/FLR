package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/MyHeartRaces/FLR/runtime/internal/bypass"
	"github.com/MyHeartRaces/FLR/runtime/internal/config"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/control"
	"github.com/MyHeartRaces/FLR/runtime/internal/controller"
	"github.com/MyHeartRaces/FLR/runtime/internal/dataplane"
	dnsbroker "github.com/MyHeartRaces/FLR/runtime/internal/dns"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
	"github.com/MyHeartRaces/FLR/runtime/internal/validation"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

const version = contract.RuntimeVersion

func fail(e error) {
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func show(v any) { fail(json.NewEncoder(os.Stdout).Encode(v)) }
func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Println("flr-controller", version)
		return
	}
	if len(os.Args) < 2 {
		fail(fmt.Errorf("usage: flr-controller status|validate|prepare|apply|rollback|games|profile|direct-session"))
	}
	command := os.Args[1]
	switch command {
	case "enable-home":
		// The old direct settings snapshot bypassed serialized v2 administration.
		// Reject before parsing legacy flags, loading policy or recovering state.
		fail(fmt.Errorf("enable-home is retired in 0.6; use Proxy management guarded activation"))
		return
	case "rollback-token":
		if len(os.Args) < 3 || len(os.Args) > 4 {
			fail(fmt.Errorf("rollback-token needs action and optional generation"))
		}
		expected := ""
		if len(os.Args) == 4 {
			expected = os.Args[3]
		}
		token, e := config.RollbackToken(os.Args[2], expected)
		fail(e)
		if token != "" {
			fmt.Println(token)
		}
		return
	case "api":
		apiMain(os.Args[2:])
		return
	case "engine":
		os.Exit(engineMain(os.Args[2:]))
	case "status", "refresh":
		v, e := control.Call(control.Request{Command: command})
		fail(e)
		show(v)
		return
	case "games":
		if len(os.Args) != 3 {
			fail(fmt.Errorf("games needs auto or vless"))
		}
		v, e := control.Call(control.Request{Command: command, Value: os.Args[2]})
		fail(e)
		show(v)
		return
	case "profile":
		if len(os.Args) != 4 {
			fail(fmt.Errorf("profile needs LAN_IP auto|games|general|direct"))
		}
		v, e := control.Call(control.Request{Command: command, Client: os.Args[2], Value: os.Args[3]})
		fail(e)
		show(v)
		return
	case "direct-session":
		if len(os.Args) == 3 && os.Args[2] == "stop" {
			v, e := control.Call(control.Request{Command: "direct-stop"})
			fail(e)
			show(v)
			return
		}
		f := flag.NewFlagSet(command, flag.ExitOnError)
		client := f.String("client", "", "LAN client IPv4")
		ttl := f.String("ttl", "15m", "duration, max15m")
		f.Parse(os.Args[2:])
		if f.NArg() != 0 {
			fail(fmt.Errorf("unexpected direct argument"))
		}
		v, e := control.Call(control.Request{Command: command, Client: *client, TTL: *ttl})
		fail(e)
		show(v)
		return
	case "direct-worker":
		f := flag.NewFlagSet(command, flag.ExitOnError)
		client := f.String("client", "", "")
		mac := f.String("mac", "", "")
		id := f.String("session-id", "", "")
		expires := f.String("expires", "", "")
		wan := f.String("wan", "eth1", "")
		f.Parse(os.Args[2:])
		end, e := time.Parse(time.RFC3339Nano, *expires)
		fail(e)
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
		defer cancel()
		fail(control.Worker(ctx, control.Session{ID: *id, Client: *client, MAC: *mac, Expires: end, Port: 1088}, *wan))
		return
	}
	flags := flag.NewFlagSet(command, flag.ExitOnError)
	dir := flags.String("policy", "", "policy directory (default: the private overlay "+policy.OverlayDir+" when valid, else "+policy.ImageDir+")")
	profiles := flags.String("profiles", "/etc/flint-vpn/clients/home", "private profiles")
	backup := flags.String("backup", "/etc/flr-runtime/backup", "backup directory")
	test := flags.String("test-client", "", "limit to one LAN IPv4")
	channel := flags.String("channel", "awg", "general/games channel")
	manual := flags.Bool("manual-games", false, "allow manual VLESS games")
	port := flags.String("port", "1054", "DNS port")
	localPort := flags.String("local-port", "53", "local DNS port")
	flags.Parse(os.Args[2:])
	if flags.NArg() != 0 {
		fail(fmt.Errorf("unexpected argument"))
	}
	switch command {
	case "backup":
		fail(config.Backup(*backup))
		show(map[string]bool{"saved": true})
		return
	case "rollback":
		fail(controller.ManualRollback(*backup))
		show(map[string]bool{"restored": true})
		return
	case "prepare":
		fail(config.Backup(*backup))
		fail(config.Prepare(*profiles, "eth1"))
		return
	}
	var p *policy.Policy
	var e error
	if *dir == "" {
		var overlayErr error
		p, *dir, overlayErr, e = policy.LoadInstalled()
		if overlayErr != nil {
			fmt.Fprintln(os.Stderr, overlayErr)
		}
	} else {
		p, e = policy.Load(*dir)
	}
	fail(e)
	if command == "validate" {
		show(map[string]any{"valid": true, "version": version})
		return
	}
	if command == "run" {
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
		defer cancel()
		// Run owns singleton exclusion before reading/recovering private state.
		e = controller.New(controller.DefaultSettings()).Run(ctx, p)
		if e != nil && !errors.Is(e, context.Canceled) {
			fail(e)
		}
		return
	}
	if command == "dns-test" {
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
		defer cancel()
		broker := dnsbroker.New(p, dnsbroker.StaticRoute{Channel: contract.Channel(*channel)}, dnsbroker.NewKernelMappings())
		broker.LocalPort = *localPort
		if e = broker.Serve(ctx, "0.0.0.0:"+*port); e != nil && !errors.Is(e, context.Canceled) {
			fail(e)
		}
		return
	}
	if command != "apply" && command != "render" {
		fail(fmt.Errorf("unknown command"))
	}
	var legacyLock *os.File
	if command == "apply" {
		legacyLock, e = controller.BeginLegacyApply(controller.StateDir)
		fail(e)
		defer legacyLock.Close()
	}
	snap, e := dataplane.CurrentSnapshot()
	fail(e)
	fail(dataplane.Preflight(snap))
	o := dataplane.Options{LAN: "br-lan", WAN: "eth1", TestClient: *test, Selection: contract.Selection{General: contract.Channel(*channel), Games: contract.Channel(*channel)}, ManualGames: *manual, Replace: snap.TableExists}
	b, e := dataplane.Build(p, o)
	fail(e)
	if command == "render" {
		fmt.Print(b.Nft)
		return
	}
	if *test == "" {
		fail(fmt.Errorf("legacy apply requires --test-client; use Proxy management for 0.6 activation"))
	}
	for _, v := range []string{*port, *localPort} {
		n, e := strconv.Atoi(v)
		if e != nil || n < 1 || n > 65535 {
			fail(fmt.Errorf("invalid DNS port"))
		}
	}
	fail(config.Backup(*backup))
	fail(dataplane.Run("/usr/sbin/flr-rollback", "arm"))
	fail(dataplane.Apply(b))
	// The stored direct proxy default (192.168.8.1:1080), not the live LAN: the
	// controller binds the discovered LAN address at runtime, and a stored
	// legacy bind keeps settings.json loadable by the 0.6 controller.
	s := controller.Settings{DirectBypass: bypass.Config{TCP: "off", QUIC: "off"}, HealthPolicy: health.DefaultPolicy(), DirectProxy: controller.DefaultSettings().DirectProxy, Options: o, DNSPort: *port, LocalDNSPort: *localPort}
	s.Options.Replace = false
	fail(controller.WriteJSON("/etc/flr-runtime/settings.json", s))
	// The child reads settings under admin.lock; release before init restart.
	fail(legacyLock.Close())
	fail(dataplane.Run("/etc/init.d/flr-runtime", "restart"))
	show(map[string]any{"applied": true, "scope": *test})
}

// apiMain accepts bounded stdin only. Root CLI execution is the OS boundary;
// rpcd provides the authenticated FLR ACL and chooses the forced read-only flag.
func apiMain(args []string) {
	reply := control.Reply{}
	respond := func(data any, e error) {
		reply.OK = e == nil
		reply.Data = data
		if e != nil {
			reply.Error = e.Error()
			reply.ErrorDetail = validation.Detail(e)
		}
		json.NewEncoder(os.Stdout).Encode(reply)
	}
	if os.Geteuid() != 0 {
		respond(nil, fmt.Errorf("root authentication required"))
		return
	}
	f := flag.NewFlagSet("api", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	rpc := f.Bool("rpc", false, "")
	readOnly := f.Bool("read-only", false, "")
	if e := f.Parse(args); e != nil || f.NArg() != 0 {
		respond(nil, fmt.Errorf("invalid API arguments"))
		return
	}
	raw, e := io.ReadAll(io.LimitReader(os.Stdin, control.MaxAPIBytes+1))
	if e != nil {
		respond(nil, fmt.Errorf("cannot read API request"))
		return
	}
	request, e := control.ParseAPI(raw, *rpc, *readOnly)
	if e != nil {
		respond(nil, e)
		return
	}
	staleSocket := false
	if _, e = os.Lstat(control.APISocket); e == nil {
		data, err := control.CallAPI(request)
		var connectionError *net.OpError
		if err == nil || !errors.As(err, &connectionError) || connectionError.Op != "dial" {
			respond(data, err)
			return
		}
		// Only a failed dial can safely retry offline. A reply/read error might
		// follow an already committed write and is never replayed.
		staleSocket = true
	} else if !os.IsNotExist(e) {
		respond(nil, fmt.Errorf("controller socket unavailable"))
		return
	}
	if e = os.MkdirAll("/var/run/flr-runtime", 0700); e != nil {
		respond(nil, fmt.Errorf("runtime lock unavailable"))
		return
	}
	// Offline dispatch holds the singleton lock through read/mutate publication.
	// A live process can hold this before api.sock appears: never fall back into
	// concurrent offline state during that startup window.
	lock, e := os.OpenFile("/var/run/flr-runtime/controller.lock", os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		respond(nil, fmt.Errorf("runtime lock unavailable"))
		return
	}
	defer lock.Close()
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		respond(nil, fmt.Errorf("controller is starting; retry API operation"))
		return
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if staleSocket {
		if e = os.Remove(control.APISocket); e != nil {
			respond(nil, fmt.Errorf("stale controller socket unavailable"))
			return
		}
	}
	settings, e := controller.ReadSettings()
	if e != nil {
		respond(nil, e)
		return
	}
	c := controller.New(settings)
	data, e := c.HandleAPI(request)
	data, e = finishOfflineActivation(request, data, e, func() error { return syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }, func() error { return dataplane.Run("/etc/init.d/flr-runtime", "start") })
	respond(data, e)
}

// Keep the handoff after singleton exclusion is released. procd accepting a
// start request does not establish VPN/DNS readiness or acceptance.
func finishOfflineActivation(request control.APIRequest, data any, err error, unlock func() error, start func() error) (any, error) {
	if e := unlock(); e != nil {
		return data, fmt.Errorf("runtime handoff lock release failed; rollback remains armed")
	}
	activation := (request.Operation == "primary-awg" && request.Activate) || (request.Operation == "vpn-activate" && request.Accepted)
	if err != nil || !activation {
		return data, err
	}
	result, ok := data.(map[string]any)
	if !ok {
		return data, fmt.Errorf("activation handoff state unavailable; rollback remains armed")
	}
	result["activated"] = false
	result["activation_state"] = "pending"
	result["service_start_requested"] = false
	if e := start(); e != nil {
		result["activation_state"] = "error"
		return result, fmt.Errorf("runtime service start failed; retry activation, rollback remains armed")
	}
	result["service_start_requested"] = true
	return result, nil
}
