package diagnostic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

var devicePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)

type boundedOutput struct{ bytes.Buffer }

func (w *boundedOutput) Write(p []byte) (int, error) {
	if w.Len()+len(p) > 8192 {
		return 0, fmt.Errorf("bounded local diagnosis")
	}
	return w.Buffer.Write(p)
}
func number(path string) (uint64, bool) {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 80 {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 0, 64)
	return n, err == nil
}

// Only prepared flags/counters escape this function; raw route output is discarded.
func ProbeWAN(ctx context.Context, device string) WANResult {
	r := WANResult{}
	if !devicePattern.MatchString(device) {
		r.Probe.NotMeasured = "unavailable"
		return r
	}
	flags, known := number("/sys/class/net/" + device + "/flags")
	r.LinkKnown, r.LinkUp = known, flags&1 != 0
	carrier, known := number("/sys/class/net/" + device + "/carrier")
	r.CarrierKnown, r.Carrier = known, carrier == 1
	rx, rxKnown := number("/sys/class/net/flr_awg/statistics/rx_bytes")
	tx, txKnown := number("/sys/class/net/flr_awg/statistics/tx_bytes")
	r.AWGCountersKnown = rxKnown && txKnown
	r.AWGRX, r.AWGTX = rx, tx
	var output boundedOutput
	cmd := exec.CommandContext(ctx, "ip", "-j", "route", "show", "default", "dev", device)
	cmd.Stdout = &output
	if cmd.Run() == nil {
		var routes []struct {
			Gateway string `json:"gateway"`
		}
		if json.Unmarshal(output.Bytes(), &routes) == nil {
			r.RouteKnown = true
			r.DefaultRoute = len(routes) > 0
			for _, route := range routes {
				r.Gateway = r.Gateway || route.Gateway != ""
			}
		}
	}
	if ctx.Err() != nil {
		r.Probe.NotMeasured = "budget_exhausted"
		return r
	}
	r.Probe = health.ProbeWAN(ctx, device)
	return r
}
