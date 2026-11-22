package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/controller"
	"github.com/MyHeartRaces/FLR/runtime/internal/engineupdate"
	"github.com/MyHeartRaces/FLR/runtime/internal/privatefile"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
	"github.com/MyHeartRaces/FLR/runtime/internal/transport"
)

type relayAttempt struct {
	Format          string `json:"format"`
	Nonce           string `json:"nonce"`
	RouterBuild     string `json:"router_build"`
	CandidateSHA256 string `json:"candidate_sha256"`
	ProfileRevision string `json:"profile_revision"`
	RelayID         string `json:"relay_id"`
	Listener        string `json:"listener"`
	Address         string `json:"address"`
	Port            uint16 `json:"port"`
	ExpiresAt       string `json:"expires_at"`
}

var relayHex256 = regexp.MustCompile(`^[a-f0-9]{64}$`)
var relayBuildID = regexp.MustCompile(`^[a-f0-9]{40}$`)
var relayName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func readRelayAttempt(r io.Reader, now time.Time, build, relay string, candidatePort uint16) (relayAttempt, error) {
	const limit = 4096
	raw, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil || len(raw) > limit {
		return relayAttempt{}, errors.New("invalid relay attempt size")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var a relayAttempt
	if d.Decode(&a) != nil || d.Decode(new(any)) != io.EOF {
		return relayAttempt{}, errors.New("invalid relay attempt JSON")
	}
	addr, addrErr := netip.ParseAddr(a.Address)
	deadline, timeErr := time.Parse(time.RFC3339, a.ExpiresAt)
	if a.Format != "flr-relay-attempt-v1" || !relayName.MatchString(relay) || !relayBuildID.MatchString(build) || a.RouterBuild != build || a.RelayID != relay ||
		!relayHex256.MatchString(a.Nonce) || !relayHex256.MatchString(a.CandidateSHA256) || !relayHex256.MatchString(a.ProfileRevision) ||
		addrErr != nil || !addr.Is4() || !addr.IsGlobalUnicast() || timeErr != nil || !deadline.After(now) || deadline.Sub(now) > 2*time.Minute {
		return relayAttempt{}, errors.New("relay attempt identity or expiration mismatch")
	}
	if a.Port == 0 || (a.Listener != "production" && (a.Listener != "candidate" || a.Port != candidatePort)) {
		return relayAttempt{}, errors.New("relay attempt listener is outside the configured scope")
	}
	return a, nil
}

func currentBuild() string {
	info, ok := debug.ReadBuildInfo()
	var revision string
	if ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.modified" && s.Value != "false" {
				return ""
			}
			if s.Key == "vcs.revision" {
				revision = s.Value
			}
		}
	}
	return revision
}

func loadRelayProfile(dir, id string) (connection.Connection, string, error) {
	raw, err := privatefile.Read(filepath.Join(dir, "registry.json"), connection.MaxRegistryBytes)
	if err != nil {
		return connection.Connection{}, "", errors.New("cannot read relay profile registry")
	}
	reg, err := connection.Decode(raw)
	if err != nil {
		return connection.Connection{}, "", errors.New("cannot decode relay profile registry")
	}
	raw, err = privatefile.Read(filepath.Join(dir, "settings.json"), 1<<20)
	if err != nil {
		return connection.Connection{}, "", errors.New("cannot read relay WAN settings")
	}
	settings, err := controller.DecodeSettings(raw)
	if err != nil {
		return connection.Connection{}, "", errors.New("cannot decode relay WAN settings")
	}
	for _, c := range reg.Connections {
		if c.ID == id {
			return c, settings.Options.WAN, nil
		}
	}
	return connection.Connection{}, "", errors.New("relay profile is unavailable")
}

func renderRelayTarget(c connection.Connection, a relayAttempt, wan, dir string) (engineupdate.Target, string, error) {
	p := c.Clone().Profile
	if !c.Enabled || c.Revision != a.ProfileRevision || c.Family != "hy2" || p == nil || p.Engine != "sing-box" || p.Detour != nil || !p.Capabilities.UDP || p.Outbound["type"] != "hysteria2" {
		return engineupdate.Target{}, "", errors.New("relay qualification requires the approved native Hysteria2 profile revision")
	}
	if p.Outbound["server_ports"] != nil || p.Outbound["hop_interval"] != nil {
		return engineupdate.Target{}, "", errors.New("relay qualification requires a fixed-port profile")
	}
	host, _ := p.Outbound["server"].(string)
	tls, _ := p.Outbound["tls"].(map[string]any)
	if tls["enabled"] != true || tls["insecure"] == true {
		return engineupdate.Target{}, "", errors.New("qualification requires the saved profile to verify the relay certificate")
	}
	if a.Listener == "production" && p.Outbound["server_port"] != float64(a.Port) {
		return engineupdate.Target{}, "", errors.New("production listener differs from the saved profile")
	}
	if net.ParseIP(host) == nil {
		if sni, _ := tls["server_name"].(string); sni == "" {
			tls["server_name"] = host
		}
	}
	p.Outbound["server"], p.Outbound["server_port"] = a.Address, int(a.Port)
	rendered, err := profile.Render(*p, wan, dir)
	if host == "" || err != nil {
		return engineupdate.Target{}, "", errors.New("cannot render isolated relay profile")
	}
	return engineupdate.Target{ID: c.ID, Server: a.Address, UDP: true, Config: rendered.SingBox}, host, nil
}

func qualifyRelayCLI(args []string, env engineupdate.Env) int {
	if len(args) != 3 {
		return engineUsageMsg("qualify-relay requires <connection-id> <relay-id> <candidate-port>")
	}
	port, err := strconv.ParseUint(args[2], 10, 16)
	if err != nil || port == 0 {
		return engineUsageMsg("invalid configured candidate port")
	}
	a, err := readRelayAttempt(os.Stdin, time.Now(), currentBuild(), args[1], uint16(port))
	if err != nil {
		return engineUsageMsg(err.Error())
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	deadline, _ := time.Parse(time.RFC3339, a.ExpiresAt)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	result := qualifyRelay(ctx, a, args[0], env)
	if err := json.NewEncoder(os.Stdout).Encode(struct {
		Attempt relayAttempt `json:"attempt"`
		engineupdate.RelayQualificationResult
	}{a, result}); err != nil {
		return engineError
	}
	return engineOK
}

func qualifyRelay(ctx context.Context, a relayAttempt, id string, env engineupdate.Env) engineupdate.RelayQualificationResult {
	inconclusive := engineupdate.RelayQualificationResult{Outcome: "inconclusive"}
	c, wan, err := loadRelayProfile(env.ConfigDir, id)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return inconclusive
	}
	target, host, err := renderRelayTarget(c, a, wan, env.TmpDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return inconclusive
	}
	addr, err := (transport.KernelWAN{}).Resolve(ctx, wan, host)
	if err != nil || addr != a.Address {
		fmt.Fprintln(os.Stderr, "attempt address does not match the profile on WAN")
		return inconclusive
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return inconclusive
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	r := engineupdate.RunRelayQualification(ctx, env.BinPath("sing-box"), target, env.TmpDir, port)
	current, currentWAN, err := loadRelayProfile(env.ConfigDir, id)
	if ctx.Err() != nil || err != nil || !current.Enabled || current.Revision != c.Revision || currentWAN != wan {
		return inconclusive
	}
	return r
}
