package transport

import (
	"context"
	"math/rand/v2"
	"net/netip"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/diagnostic"
)

// AWGRoamer is optional on an AWGBackend (NativeAWG implements it). Without
// it, endpoint roaming stays off.
//
// Every rotation changes both ends of the outer UDP flow: the router's listen
// (source) port and the peer endpoint port, in one device update. With the
// server redirecting the range to its listen port, a new destination port
// alone would map onto the reply tuple of the previous flow while its
// conntrack entry lives (a NAT clash that drops packets); a fresh source port
// makes every rotation a distinct 5-tuple on both sides.
type AWGRoamer interface {
	// SetPorts rebinds the interface to listenPort and moves the peer endpoint
	// of the configured connection in one update. If the bind fails, nothing
	// changes.
	SetPorts(ctx context.Context, c connection.Connection, listenPort uint16, endpoint netip.AddrPort) error
	// ListenPort reads the live listen port.
	ListenPort(context.Context) (uint16, error)
	// LatestHandshake reports the peer's latest handshake; zero means none.
	LatestHandshake(context.Context, connection.Connection) (time.Time, error)
}

// RoamStatus is the public roaming state of the configured native AWG
// connection (Snapshot.Roam). Port is the endpoint port in use; Roamed means
// it or the source port was moved by roaming. ListenPort is the router's source
// port in use when known (before the first rotation it is read once from the
// device; the stored configuration leaves it to the kernel). NextRotation is set only while a
// rotation is scheduled (the connection is the healthy default for new flows).
type RoamStatus struct {
	ConnectionID    string    `json:"connection_id"`
	Ports           string    `json:"ports"`
	IntervalSeconds int       `json:"interval_seconds"`
	Port            uint16    `json:"port"`
	ListenPort      uint16    `json:"listen_port,omitempty"`
	Roamed          bool      `json:"roamed"`
	NextRotation    time.Time `json:"next_rotation,omitzero"`
	LastRotation    time.Time `json:"last_rotation,omitzero"`
	LastReason      string    `json:"last_reason,omitempty"`
	Rotations       uint64    `json:"rotations"`
	LastError       string    `json:"last_error,omitempty"`
	Suspended       bool      `json:"suspended,omitempty"`
}

// roamHandshakeRecent: WireGuard rekeys every 2 min under traffic (the probes
// alone are traffic) and rejects a session after 3 min.
const roamHandshakeRecent = 3 * time.Minute

// Source ports are drawn from the IANA dynamic range. A port another socket
// holds fails the bind; the update is then retried with another port.
const (
	roamListenMin      = 49152
	roamListenMax      = 65535
	roamListenAttempts = 3
	roamRecentPorts    = 8
)

type roamState struct {
	key     string
	setting connection.Roam
	// port is the roamed endpoint port in use; 0 means the stored one.
	port uint16
	// listen is the roamed source port in use; 0 means the original one,
	// origListen, read before the first rotation (0 if unknown). recent holds
	// source ports used lately, never picked again while their flows may
	// still have conntrack state.
	listen     uint16
	origListen uint16
	recent     []uint16
	armed      bool
	next       time.Time
	last       time.Time
	lastReason string
	rotations  uint64
	lastError  string
	// A failing sample of the roaming default schedules one stall rotation
	// (stallDue) per failure episode (episode); a clean sample ends it.
	stallDue bool
	episode  bool
}

// SetRoamSuspended holds endpoint roaming (no rotation, no restore) while the
// controller runs a manual connection test. Applies from the next round.
func (m *Manager) SetRoamSuspended(suspended bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roamSuspended = suspended
	m.connectionState().roam.armed = false
	if m.state.Roam != nil {
		v := *m.state.Roam
		v.Suspended, v.NextRotation = suspended, time.Time{}
		m.state.Roam = &v
	}
}

// resetRoam forgets the roaming state after the native interface was
// (re)configured from its stored endpoint, or lost.
func (m *Manager) resetRoam() {
	m.connectionState().roam = roamState{}
	m.state.Roam = nil
}

func (m *Manager) roamInt64N(n int64) int64 {
	if n <= 1 {
		return 0
	}
	if m.roamRandom != nil {
		return m.roamRandom(n)
	}
	return rand.Int64N(n)
}

// roamJitter returns interval ±30 %.
func (m *Manager) roamJitter(interval time.Duration) time.Duration {
	spread := int64(interval) * 3 / 10
	return interval - time.Duration(spread) + time.Duration(m.roamInt64N(2*spread+1))
}

// roamPick returns a random port of the range other than current.
func (m *Manager) roamPick(r connection.Roam, current uint16) (uint16, bool) {
	size := int64(r.Size())
	if !r.Contains(current) {
		return r.Start + uint16(m.roamInt64N(size)), true
	}
	if size < 2 {
		return 0, false
	}
	port := r.Start + uint16(m.roamInt64N(size-1))
	if port >= current {
		port++
	}
	return port, true
}

func storedEndpoint(c connection.Connection) (netip.AddrPort, bool) {
	endpoint, err := netip.ParseAddrPort(c.AWG["Endpoint"])
	return endpoint, err == nil && endpoint.Addr().Is4() && endpoint.Port() != 0
}

// roamBeforeProbe runs in StepConnections before the round's probes, so the
// probe of the same round measures a new port at once. It rotates the
// endpoint of the configured native AWG connection only while that
// connection is the healthy default for new flows and no switch, cleanup,
// newer intent or manual test is pending: on schedule (jittered interval,
// only with no failure in progress), once per failure episode on a stall
// (the previous sample failed while the handshake is recent, or its age is
// unknown), and at once when a roamed port left a changed range. Each
// rotation moves the endpoint port and the router's source port together
// (roamSet). When roaming is turned off, the stored endpoint port and the
// original source port are restored.
// A failed command leaves both ports unchanged and is retried at the next due
// time; the health policy, never roaming, decides failover.
func (m *Manager) roamBeforeProbe(ctx context.Context, now time.Time, available map[string]connection.Connection, generation uint64, changed bool) {
	s := m.connectionState()
	defer m.publishRoam(available)
	if s.native == nil {
		if s.roam.key != "" {
			m.resetRoam()
		}
		return
	}
	key := connectionKey(*s.native)
	if s.roam.key != key {
		s.roam = roamState{key: key}
	}
	item, listed := available[key]
	roamer, capable := s.awg.(AWGRoamer)
	stored, valid := storedEndpoint(item)
	if !listed || !capable || !valid {
		s.roam.armed, s.roam.stallDue = false, false
		return
	}
	blocked := m.roamSuspended || changed || m.state.Pending || m.cleanupPending || m.slotCleanupPending || ctx.Err() != nil || m.requestedGeneration.Load() != generation
	setting, on := item.RoamSetting()
	if !on {
		s.roam.setting, s.roam.armed, s.roam.stallDue, s.roam.episode = connection.Roam{}, false, false, false
		if (s.roam.port != 0 || s.roam.listen != 0) && !blocked {
			m.roamSet(ctx, roamer, item, stored, stored.Port(), "disabled", now)
		}
		return
	}
	if s.roam.setting != setting {
		s.roam.setting, s.roam.armed = setting, false
	}
	state := s.health[key]
	if blocked || s.active == nil || connectionKey(*s.active) != key || !state.Healthy() {
		s.roam.armed, s.roam.stallDue = false, false
		return
	}
	current := stored.Port()
	if s.roam.port != 0 {
		current = s.roam.port
	}
	reason := ""
	switch {
	case s.roam.stallDue:
		s.roam.stallDue = false
		if m.roamHandshakeRecent(ctx, roamer, item, now) {
			reason = "stall"
		}
	case s.roam.port != 0 && !setting.Contains(s.roam.port):
		reason = "range"
	case !s.roam.armed:
		s.roam.armed, s.roam.next = true, now.Add(m.roamJitter(setting.Interval))
	case !now.Before(s.roam.next) && state.Failures == 0:
		reason = "schedule"
	}
	if reason == "" {
		return
	}
	s.roam.armed, s.roam.next = true, now.Add(m.roamJitter(setting.Interval))
	port, ok := m.roamPick(setting, current)
	if !ok {
		return
	}
	if s.roam.port == 0 && s.roam.listen == 0 && s.roam.origListen == 0 {
		// Before the first rotation: remember the kernel's listen port, which
		// turning roaming off restores.
		bounded, cancel := context.WithTimeout(ctx, m.ProbeTimeout)
		if listen, err := roamer.ListenPort(bounded); err == nil {
			s.roam.origListen = listen
		}
		cancel()
	}
	m.roamSet(ctx, roamer, item, stored, port, reason, now)
}

func (m *Manager) roamHandshakeRecent(ctx context.Context, roamer AWGRoamer, item connection.Connection, now time.Time) bool {
	bounded, cancel := context.WithTimeout(ctx, m.ProbeTimeout)
	defer cancel()
	at, err := roamer.LatestHandshake(bounded, item)
	if err != nil {
		// Unknown age: the failing probe is the only evidence; one rotation is
		// harmless to the tunnel.
		return true
	}
	return !at.IsZero() && now.Sub(at) <= roamHandshakeRecent
}

// roamSet moves both ports. reason "disabled" restores the stored endpoint
// port and the original listen port (a fresh one if that is unknown or
// taken); any other reason picks a fresh source port. A failed update is
// retried with other source ports; a final failure leaves both ports as they
// were.
func (m *Manager) roamSet(ctx context.Context, roamer AWGRoamer, item connection.Connection, stored netip.AddrPort, port uint16, reason string, now time.Time) {
	s := m.connectionState()
	previous := s.roam.listen
	if previous == 0 {
		previous = s.roam.origListen
	}
	tried := []uint16{}
	listen := uint16(0)
	if reason == "disabled" && s.roam.origListen != 0 {
		listen = s.roam.origListen
	}
	var err error
	for attempt := 0; attempt < roamListenAttempts; attempt++ {
		if listen == 0 {
			listen = m.roamPickListen(append(append([]uint16{previous, s.roam.origListen}, s.roam.recent...), tried...))
		}
		bounded, cancel := context.WithTimeout(ctx, m.ProbeTimeout)
		err = roamer.SetPorts(bounded, item, listen, netip.AddrPortFrom(stored.Addr(), port))
		cancel()
		if err == nil || ctx.Err() != nil {
			break
		}
		tried, listen = append(tried, listen), 0
	}
	if err != nil {
		s.roam.lastError = "port update failed"
	} else {
		if previous != 0 && previous != listen {
			s.roam.recent = append(s.roam.recent, previous)
			if len(s.roam.recent) > roamRecentPorts {
				s.roam.recent = s.roam.recent[len(s.roam.recent)-roamRecentPorts:]
			}
		}
		if reason == "disabled" {
			// Back to the stored endpoint: this source port is the new original.
			s.roam.port, s.roam.listen, s.roam.origListen = 0, 0, listen
		} else {
			s.roam.port, s.roam.listen = port, listen
			if port == stored.Port() {
				s.roam.port = 0
			}
		}
		s.roam.last, s.roam.lastReason, s.roam.lastError = now, reason, ""
		s.roam.rotations++
	}
	if m.recordDecision != nil {
		outcome := "applied"
		if err != nil {
			outcome = "failed"
		}
		m.recordDecision(diagnostic.Decision{At: time.Now(), Epoch: m.state.Generation, From: connectionIdentity(&item), To: connectionIdentity(&item), Reason: "roam", Stage: "native", Channel: contract.AWG, Outcome: outcome, ReserveRetained: m.state.ReserveConnection != nil})
	}
}

// roamPickListen draws a source port from the dynamic range that is not in
// exclude; a drawn port that is excluded moves to the next free one.
func (m *Manager) roamPickListen(exclude []uint16) uint16 {
	excluded := map[uint16]bool{}
	for _, port := range exclude {
		excluded[port] = true
	}
	size := int64(roamListenMax - roamListenMin + 1)
	offset := m.roamInt64N(size)
	for i := int64(0); i < size; i++ {
		port := uint16(roamListenMin + (offset+i)%size)
		if !excluded[port] {
			return port
		}
	}
	return roamListenMin
}

// roamAfterProbe marks a stall of the roaming default: its first failed
// measured sample of an episode schedules one rotation for the next round,
// before the health policy reaches its failover threshold.
func (m *Manager) roamAfterProbe(sample connectionSample) {
	s := m.connectionState()
	if s.native == nil || s.roam.key != connectionKey(*s.native) || s.roam.setting == (connection.Roam{}) || !sample.valid || !sample.present || sample.result.NotMeasured != "" {
		return
	}
	if s.active == nil || connectionKey(*s.active) != s.roam.key {
		return
	}
	if sample.result.TCP && sample.result.UDP {
		s.roam.stallDue, s.roam.episode = false, false
		return
	}
	if !s.roam.episode {
		s.roam.stallDue, s.roam.episode = true, true
	}
}

func (m *Manager) publishRoam(available map[string]connection.Connection) {
	s := m.connectionState()
	if s.native == nil || s.roam.key == "" || s.roam.key != connectionKey(*s.native) {
		m.state.Roam = nil
		return
	}
	item := available[s.roam.key]
	setting, on := item.RoamSetting()
	stored, valid := storedEndpoint(item)
	if !valid || (!on && s.roam.port == 0 && s.roam.listen == 0) {
		m.state.Roam = nil
		return
	}
	status := &RoamStatus{ConnectionID: item.ID, Ports: item.RoamPorts, IntervalSeconds: int(setting.Interval / time.Second), Port: stored.Port(), Roamed: s.roam.port != 0 || s.roam.listen != 0, LastRotation: s.roam.last, LastReason: s.roam.lastReason, Rotations: s.roam.rotations, LastError: s.roam.lastError, Suspended: m.roamSuspended}
	if s.roam.port != 0 {
		status.Port = s.roam.port
	}
	status.ListenPort = s.roam.origListen
	if s.roam.listen != 0 {
		status.ListenPort = s.roam.listen
	}
	if s.roam.armed {
		status.NextRotation = s.roam.next
	}
	m.state.Roam = status
}
