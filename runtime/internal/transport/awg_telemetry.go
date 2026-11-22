package transport

import (
	"strconv"
	"strings"
)

type nativeTrafficSample struct {
	ifindex int
	rx, tx  uint64
	valid   bool
}

// Parse only the expected peer from `awg show <interface> transfer`. Its
// machine-readable output contains no private or preshared keys.
func parseAWGTransfer(raw []byte, peer string) nativeTrafficSample {
	var sample nativeTrafficSample
	if peer == "" {
		return sample
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != peer {
			continue
		}
		if len(fields) != 3 || sample.valid {
			return nativeTrafficSample{}
		}
		rx, rxErr := strconv.ParseUint(fields[1], 10, 64)
		tx, txErr := strconv.ParseUint(fields[2], 10, 64)
		if rxErr != nil || txErr != nil {
			return nativeTrafficSample{}
		}
		sample = nativeTrafficSample{rx: rx, tx: tx, valid: true}
	}
	return sample
}

func nativeTrafficDelta(before, after nativeTrafficSample) (rx, tx uint64, available bool) {
	if !before.valid || !after.valid || before.ifindex <= 0 || before.ifindex != after.ifindex || after.rx < before.rx || after.tx < before.tx {
		return 0, 0, false
	}
	return after.rx - before.rx, after.tx - before.tx, true
}
