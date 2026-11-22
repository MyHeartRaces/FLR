package controller

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/continuity"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/dataplane"
	dnsbroker "github.com/MyHeartRaces/FLR/runtime/internal/dns"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"github.com/MyHeartRaces/FLR/runtime/internal/native"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
	"github.com/MyHeartRaces/FLR/runtime/internal/privatefile"
	"github.com/MyHeartRaces/FLR/runtime/internal/transport"
)

type continuityStatus struct {
	Active  bool             `json:"active"`
	Carrier contract.Channel `json:"carrier"`
}

type continuityBridge interface {
	Select(continuity.Path) error
	Pause(contract.Channel)
	Close()
}

// Writes hold both adminMu and mu. Status and DNS readers hold mu.
type continuityState struct {
	bridge       continuityBridge
	path         continuity.Path
	anchorTunnel netip.Addr
}

func (c *Controller) startContinuity() error {
	raw, err := privatefile.Read(filepath.Join(c.stateDir, "continuity.json"), 4096)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("private continuity configuration rejected")
	}
	var cfg continuity.Config
	if err := decodeStrict(raw, &cfg); err != nil || cfg.Validate() != nil {
		return fmt.Errorf("invalid private continuity configuration")
	}
	if c.settings.Version != 2 {
		return fmt.Errorf("continuity requires the unified connection registry")
	}
	ctx, cancel := context.WithTimeout(c.ctx, time.Second)
	defer cancel()
	if err := checkContinuityInterface(ctx, cfg); err != nil {
		return err
	}
	bridge, err := continuity.Start(c.ctx, cfg, dialContinuityCarrier)
	if err != nil {
		return fmt.Errorf("continuity bridge could not start")
	}
	c.mu.Lock()
	c.continuity = continuityState{bridge: bridge, path: continuity.Path{Channel: contract.Down}, anchorTunnel: cfg.AnchorTunnelIP}
	c.mu.Unlock()
	return nil
}

// A Direct boot can load even when the optional anchor is offline. When the
// owner later requests policy routing, first stage the stable route under the
// still-applied Direct policy. The normal mode transaction enables it next.
func (c *Controller) enableDeferredContinuity() error {
	if err := c.startContinuity(); err != nil {
		return err
	}
	if c.continuity.bridge != nil {
		if err := c.installContinuityWhileDirect(); err != nil {
			c.stopContinuity()
			return fmt.Errorf("protected routing pending; continuity dataplane unavailable")
		}
		c.configureContinuityProbes()
	}
	c.continuityDeferred = false
	return nil
}

func (c *Controller) installContinuityWhileDirect() error {
	snap, err := dataplane.CurrentSnapshot()
	if err != nil {
		return err
	}
	batch, err := c.vpnBatch(c.policy, snap.TableExists)
	if err != nil {
		return err
	}
	return dataplane.Apply(batch)
}

func (c *Controller) configureContinuityProbes() {
	if c.continuity.bridge != nil {
		c.transports.SetStableEgress(true)
		c.transports.SetStableEgressProbe(c.probeContinuity)
	}
}

func (c *Controller) probeContinuity(ctx context.Context, owner connection.Summary) (measured, reachable bool) {
	c.mu.RLock()
	state, mode := c.continuity, c.appliedMode
	c.mu.RUnlock()
	if state.bridge == nil || mode == policy.ModeDirect || state.path.Identity != owner.ID+"/"+owner.Revision || ctx.Err() != nil {
		return false, false
	}
	reachable = continuity.ProbeAnchor(ctx, state.anchorTunnel, func(ctx context.Context, network, target string) (net.Conn, error) {
		mark := contract.ChannelMark(contract.Continuity) | contract.ClassMark(contract.General)
		return dnsbroker.DialMarked(ctx, network, target, mark, contract.ContinuityDevice)
	})
	return ctx.Err() == nil, reachable
}

// The link is managed by the operator. Never apply a profile, fetch a key or
// add a peer here. Reject endpoints that would send tunnel packets outside the
// loopback bridge, even if the local port matches.
func checkContinuityInterface(ctx context.Context, cfg continuity.Config) error {
	link, err := net.InterfaceByName(contract.ContinuityDevice)
	if err != nil || link.Flags&net.FlagUp == 0 {
		return fmt.Errorf("continuity requires an existing up flr_cont interface")
	}
	addrs, err := link.Addrs()
	if err != nil || !hasDistinctIPv4(addrs, cfg.AnchorTunnelIP) {
		return fmt.Errorf("flr_cont requires an IPv4 address")
	}
	query := func(field string) ([]byte, error) {
		result := native.Execute(ctx, native.Limit("awg"), "", "awg", "show", contract.ContinuityDevice, field)
		return result.Stdout, result.Err
	}
	port, err := query("listen-port")
	if err != nil || strings.TrimSpace(string(port)) != strconv.Itoa(int(cfg.TunnelPort)) {
		return fmt.Errorf("flr_cont listen port does not match continuity configuration")
	}
	endpoints, err := query("endpoints")
	if err != nil || !continuityEndpointMatches(endpoints, cfg.BridgePort) {
		return fmt.Errorf("flr_cont must have one peer pointing to the continuity bridge")
	}
	keepalive, err := query("persistent-keepalive")
	if err != nil || !continuityKeepaliveEnabled(keepalive) {
		return fmt.Errorf("flr_cont requires persistent keepalive for idle and receive-only sessions")
	}
	return nil
}

func hasDistinctIPv4(addrs []net.Addr, remote netip.Addr) bool {
	hasIPv4 := false
	for _, addr := range addrs {
		if ip, ok := addr.(*net.IPNet); ok && ip.IP.To4() != nil {
			if ip.IP.Equal(net.IP(remote.AsSlice())) {
				return false
			}
			hasIPv4 = true
		}
	}
	return hasIPv4
}

func continuityEndpointMatches(raw []byte, port uint16) bool {
	fields := strings.Fields(string(raw))
	return len(fields) == 2 && fields[1] == "127.0.0.1:"+strconv.Itoa(int(port))
}

func continuityKeepaliveEnabled(raw []byte) bool {
	fields := strings.Fields(string(raw))
	if len(fields) != 2 {
		return false
	}
	seconds, err := strconv.ParseUint(fields[1], 10, 16)
	return err == nil && seconds > 0
}

func dialContinuityCarrier(ctx context.Context, channel contract.Channel, addr string) (net.Conn, error) {
	if channel != contract.AWG && channel != contract.Gecko {
		return nil, fmt.Errorf("invalid continuity carrier")
	}
	mark := contract.ChannelMark(channel) | contract.ClassMark(contract.General) | contract.ProbeMark
	return dnsbroker.DialMarked(ctx, "udp4", addr, mark, health.Device(channel))
}

func (c *Controller) stopContinuity() {
	c.mu.Lock()
	bridge := c.continuity.bridge
	c.continuity = continuityState{}
	c.mu.Unlock()
	if bridge != nil {
		bridge.Close()
	}
}

func (c *Controller) pauseContinuityLocked(channel contract.Channel) {
	if c.continuity.bridge != nil && c.continuity.path.Channel == channel {
		c.continuity.bridge.Pause(channel)
		c.continuity.path = continuity.Path{Channel: contract.Down}
	}
}

func (c *Controller) publishEgressLocked(selection contract.Selection) error {
	// The stable mark and route are installed with the batch. Replacing the
	// carrier must not reclassify packets or change existing NAT mappings.
	if c.continuity.bridge != nil {
		return nil
	}
	if c.publishSelection != nil {
		return c.publishSelection(selection)
	}
	return dataplane.UpdateSelection(selection, false)
}

func (c *Controller) dnsChannelLocked() contract.Channel {
	if c.continuity.bridge != nil {
		return contract.Continuity
	}
	return c.selection.General
}

func continuityPath(s transport.Snapshot) continuity.Path {
	owner := s.ActiveConnection
	if owner == nil || owner.ID == "" || owner.Revision == "" || !owner.Capabilities.UDP {
		return continuity.Path{Channel: contract.Down}
	}
	channel := s.Selection.General
	switch {
	case channel == contract.AWG && owner.Family == "awg" && s.AWG.Healthy():
	case channel == contract.Gecko && owner.Family == "hy2" && s.Slot.Healthy():
	default:
		return continuity.Path{Channel: contract.Down}
	}
	return continuity.Path{Channel: channel, Identity: owner.ID + "/" + owner.Revision}
}

func (c *Controller) selectContinuityLocked(s transport.Snapshot) error {
	path := continuityPath(s)
	if err := c.continuity.bridge.Select(path); err != nil {
		c.lastError = "continuity carrier unavailable; retrying"
		// Keep the attempted owner's identity so the next bounded anchor
		// probe can count a path that failed to open as unavailable.
		c.continuity.path = continuity.Path{Channel: contract.Down, Identity: path.Identity}
		return err
	}
	c.continuity.path = path
	return nil
}

func (c *Controller) continuityCandidates() (*connection.Registry, connection.Order) {
	registry, order := c.connections, c.settings.Order
	if c.continuity.bridge == nil || registry == nil || c.settings.Selection.Mode != "auto" {
		return registry, order
	}
	filtered := &connection.Registry{Version: registry.Version}
	for _, entry := range registry.Connections {
		if entry.Family == "awg" || (entry.Family == "hy2" && entry.Profile != nil && entry.Profile.Capabilities.UDP) {
			filtered.Connections = append(filtered.Connections, entry)
		}
	}
	return filtered, connection.ReconcileOrder(filtered, order)
}
