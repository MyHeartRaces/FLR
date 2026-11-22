package diagnostic

import "golang.org/x/sys/unix"

func wallClockStatus() string {
	var sample unix.Timex
	state, err := unix.Adjtimex(&sample)
	if err != nil {
		return "unknown"
	}
	if state == unix.TIME_ERROR || sample.Status&unix.STA_UNSYNC != 0 {
		return "suspect"
	}
	return "sane"
}
