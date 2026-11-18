package connection

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// AWG endpoint port roaming (lane A3, docs/MAX-PACKAGE.md). The server
// redirects a UDP port range to its AWG listen port; the controller moves the
// router's peer endpoint port inside that range. WireGuard re-learns the peer
// from any authenticated packet, so the tunnel and its inner sessions survive.
// The setting is stored with the connection and is off when absent. It is
// metadata, not payload: it never changes the connection revision.
const (
	MinRoamPort            = 1024
	MaxRoamPort            = 65535
	MaxRoamPorts           = 10000
	DefaultRoamInterval    = 10 * time.Minute
	MinRoamInterval        = time.Minute
	MaxRoamInterval        = 24 * time.Hour
	defaultRoamIntervalSec = int(DefaultRoamInterval / time.Second)
)

// Roam is the parsed, validated roaming setting of one AWG connection.
type Roam struct {
	Start    uint16
	End      uint16
	Interval time.Duration
}

// Size is the number of ports in the range.
func (r Roam) Size() int { return int(r.End) - int(r.Start) + 1 }

// Contains reports whether port is inside the range.
func (r Roam) Contains(port uint16) bool { return port >= r.Start && port <= r.End }

// ParseRoamPorts accepts "start-end" (or a single port) inside 1024..65535,
// start <= end, at most MaxRoamPorts ports.
func ParseRoamPorts(value string) (uint16, uint16, error) {
	low, high, ranged := strings.Cut(value, "-")
	if !ranged {
		high = low
	}
	start, err1 := strconv.Atoi(low)
	end, err2 := strconv.Atoi(high)
	if err1 != nil || err2 != nil || low != strconv.Itoa(start) || high != strconv.Itoa(end) {
		return 0, 0, fmt.Errorf("invalid AWG roam port range")
	}
	if start < MinRoamPort || end > MaxRoamPort || start > end || end-start+1 > MaxRoamPorts {
		return 0, 0, fmt.Errorf("AWG roam port range must be within 1024-65535, ordered, at most 10000 ports")
	}
	return uint16(start), uint16(end), nil
}

func validRoamInterval(seconds int) bool {
	return seconds == 0 || (seconds >= int(MinRoamInterval/time.Second) && seconds <= int(MaxRoamInterval/time.Second))
}

// RoamSetting returns the roaming setting and whether roaming is on. A
// connection without roam_ports, or with an invalid setting, does not roam.
func (c Connection) RoamSetting() (Roam, bool) {
	if c.Family != "awg" || c.RoamPorts == "" || !validRoamInterval(c.RoamInterval) {
		return Roam{}, false
	}
	start, end, err := ParseRoamPorts(c.RoamPorts)
	if err != nil {
		return Roam{}, false
	}
	seconds := c.RoamInterval
	if seconds == 0 {
		seconds = defaultRoamIntervalSec
	}
	return Roam{Start: start, End: end, Interval: time.Duration(seconds) * time.Second}, true
}

func (c Connection) validateRoam() error {
	if c.RoamPorts == "" && c.RoamInterval == 0 {
		return nil
	}
	if c.Family != "awg" {
		return fmt.Errorf("endpoint roaming is only for AWG connections")
	}
	if c.RoamPorts == "" {
		return fmt.Errorf("AWG roam interval requires a roam port range")
	}
	if _, _, err := ParseRoamPorts(c.RoamPorts); err != nil {
		return err
	}
	if !validRoamInterval(c.RoamInterval) {
		return fmt.Errorf("AWG roam interval must be 60..86400 seconds")
	}
	return nil
}

// SetRoam validates and stores the roaming setting. Empty ports with a zero
// interval turn roaming off. intervalSeconds 0 means the default (10 min).
func (c *Connection) SetRoam(ports string, intervalSeconds int) error {
	next := *c
	next.RoamPorts, next.RoamInterval = ports, intervalSeconds
	if err := next.validateRoam(); err != nil {
		return err
	}
	c.RoamPorts, c.RoamInterval = ports, intervalSeconds
	return nil
}
