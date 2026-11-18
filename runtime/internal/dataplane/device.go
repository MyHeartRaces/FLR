package dataplane

import (
	"context"
	"errors"
	"fmt"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/native"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// validateDevice checks structure (a private IPv4 address). The controller
// checks LAN membership for new profiles; removing a stored profile whose
// address is no longer on the LAN must still pass through the device gate.
func validateDevice(client string) error {
	return ValidateOptions(Options{LAN: "br-lan", WAN: "eth1", Selection: contract.Selection{General: contract.Down, Games: contract.Down}, Profiles: map[string]contract.Class{client: contract.Direct}})
}
func BlockDevice(client string, block bool) error {
	if e := validateDevice(client); e != nil {
		return e
	}
	action := "delete"
	if block {
		action = "add"
	}
	return Nft(fmt.Sprintf("%s element inet flr profile_pending4 { %s }\n", action, client))
}

// Retire both LAN-originated and already-DNATed incoming affinity. Keep outer
// marks and unclassified local sessions. NAT-only unclassified public flows
// need cleanup as well, including connections established before FLR startup.
func ClearDevice(client string) error {
	return clearDeviceWith(client, conntrackCleanup)
}

func conntrackCleanup(args ...string) error {
	r := native.Execute(context.Background(), 2*time.Second, "", "conntrack", args...)
	var exit *exec.ExitError
	if r.Err == nil || (errors.As(r.Err, &exit) && exit.ExitCode() == 1 && emptyDeviceCleanup.MatchString(strings.TrimSpace(r.Stderr))) {
		return nil
	}
	return fmt.Errorf("conntrack cleanup failed: %w", r.Err)
}

// conntrack exit 1 also represents real operational errors. Only its exact
// zero-deletion summary is an empty success; never swallow unchecked stderr.
var emptyDeviceCleanup = regexp.MustCompile(`^conntrack v[0-9.]+ \(conntrack-tools\): 0 flow entries have been deleted\.$`)

func deviceCleanupResult(status int, diagnostics string, timedOut bool) error {
	if !timedOut && (status == 0 || (status == 1 && emptyDeviceCleanup.MatchString(strings.TrimSpace(diagnostics)))) {
		return nil
	}
	return fmt.Errorf("device conntrack cleanup failed")
}

type deviceDiagnostics struct {
	text      string
	truncated bool
}

func (d *deviceDiagnostics) Write(b []byte) (int, error) {
	n := len(b)
	remaining := 1024 - len(d.text)
	if len(b) > remaining {
		d.truncated = true
		b = b[:remaining]
	}
	d.text += string(b)
	return n, nil
}
func clearDeviceWith(client string, run func(...string) error) error {
	if e := validateDevice(client); e != nil {
		return e
	}
	for _, direction := range []string{"--orig-src", "--reply-src"} {
		for _, class := range []string{"0x01000000", "0x02000000", "0x03000000"} {
			if e := run("-D", "-f", "ipv4", direction, client, "--mark", class+"/0x8f000000"); e != nil {
				return fmt.Errorf("device conntrack cleanup failed")
			}
		}
		nat := "--src-nat"
		if direction == "--reply-src" {
			nat = "--dst-nat"
		}
		if e := run("-D", "-f", "ipv4", direction, client, "--mark", "0x00000000/0xff800000", nat); e != nil {
			return fmt.Errorf("device conntrack cleanup failed")
		}
	}
	return nil
}
