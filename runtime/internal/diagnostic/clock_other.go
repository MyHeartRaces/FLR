//go:build !linux

package diagnostic

func wallClockStatus() string { return "unknown" }
