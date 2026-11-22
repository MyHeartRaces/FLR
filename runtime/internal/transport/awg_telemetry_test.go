package transport

import "testing"

func TestTransferCountersRequireUnambiguousMatchingPeer(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want nativeTrafficSample
	}{
		{"matching peer", "other-peer\t1\t2\ncurrent-peer\t9000000000\t0\n", nativeTrafficSample{rx: 9000000000, valid: true}},
		{"unrelated peer", "other-peer\t5\t15\n", nativeTrafficSample{}},
		{"ambiguous peer", "current-peer\t30\t31\ncurrent-peer\t35\t36\n", nativeTrafficSample{}},
		{"malformed peer", "current-peer\tNaN\t15\n", nativeTrafficSample{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseAWGTransfer([]byte(tc.raw), "current-peer"); got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestTrafficDeltaRequiresBothCountersFromSameInterface(t *testing.T) {
	before := nativeTrafficSample{ifindex: 7, rx: 12, tx: 8, valid: true}
	for _, tc := range []struct {
		name      string
		after     nativeTrafficSample
		rx, tx    uint64
		available bool
	}{
		{"sample delta", nativeTrafficSample{ifindex: 7, rx: 17, tx: 11, valid: true}, 5, 3, true},
		{"no traffic", before, 0, 0, true},
		{"reset", nativeTrafficSample{ifindex: 7, rx: 2, tx: 11, valid: true}, 0, 0, false},
		{"replacement", nativeTrafficSample{ifindex: 8, rx: 17, tx: 11, valid: true}, 0, 0, false},
		{"missing", nativeTrafficSample{}, 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rx, tx, available := nativeTrafficDelta(before, tc.after)
			if rx != tc.rx || tx != tc.tx || available != tc.available {
				t.Fatalf("got (%d, %d, %t), want (%d, %d, %t)", rx, tx, available, tc.rx, tc.tx, tc.available)
			}
		})
	}
}
