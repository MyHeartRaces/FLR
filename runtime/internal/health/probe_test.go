package health

import (
	"context"
	"testing"
	"time"
)

func TestProbeAggregatesIndependentTargetsAndKeepsProtocolTiming(t *testing.T) {
	calls := make(chan string, 4)
	tcp := func(_ context.Context, t probeTarget) (bool, int64) {
		calls <- t.name + "/tcp"
		return t.name == "google", 120
	}
	udp := func(_ context.Context, t probeTarget) (bool, int64) {
		calls <- t.name + "/udp"
		return t.name == "cloudflare", 35
	}
	r := probeTargets(context.Background(), true, tcp, udp)
	if !r.TCP || !r.UDP || r.Targets[1].TCPDurationMS != 120 || r.Targets[0].UDPDurationMS != 35 {
		t.Fatal("aggregation/timing", r)
	}
	if r.Targets[0].TCPDurationMS != 0 || r.Targets[1].UDPDurationMS != 0 {
		t.Fatal("failure published success timing")
	}
	if r.Targets[0].TCPObservation.Outcome != "failed" || r.Targets[1].UDPObservation.Outcome != "failed" ||
		r.Targets[1].TCPObservation.Outcome != "ok" || r.Targets[1].TCPObservation.DurationMS != 120 {
		t.Fatalf("diagnostic probe observations were lost: %+v", r.Targets)
	}
	if len(calls) != 4 {
		t.Fatal("not exactly two providers/protocol")
	}
	for i := 0; i < 4; i++ {
		<-calls
	}
	r = probeTargets(context.Background(), false, tcp, func(context.Context, probeTarget) (bool, int64) { t.Error("TCP-only probed UDP"); return false, 0 })
	if !r.TCP || r.UDP || r.Targets[0].UDPObservation.Outcome != "" {
		t.Fatal("capability result", r)
	}
}
func TestProbeUsesSharedDeadlineAndFixedIndependentSockets(t *testing.T) {
	for _, target := range probeProviders {
		if target.tcpAddress == "" || target.udpAddress == "" {
			t.Fatal("missing fixed socket")
		}
	}
	if probeProviders[0].tcpAddress == probeProviders[1].tcpAddress || probeProviders[0].udpAddress == probeProviders[1].udpAddress {
		t.Fatal("targets not independent")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := func(ctx context.Context, _ probeTarget) (bool, int64) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > RoundDeadline {
			t.Error("unbounded probe")
		}
		<-ctx.Done()
		return false, 0
	}
	r := probeTargets(ctx, true, f, f)
	if r.TCP || r.UDP || r.Targets[0].TCPObservation.Outcome != "cancelled" {
		t.Fatal("cancelled success")
	}
	if probeHTTPClient(nil).CheckRedirect(nil, nil) == nil {
		t.Fatal("redirect accepted")
	}
}
