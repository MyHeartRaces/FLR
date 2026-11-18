package diagnostic

import (
	"context"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"sync/atomic"
	"testing"
	"time"
)

func TestWANCollectorDoesNotBlockOrRunOverlappingRounds(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	w := NewWAN(func(ctx context.Context) WANResult {
		calls.Add(1)
		entered <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return WANResult{Probe: health.Result{Measured: true, TCP: true, UDP: true}}
	})
	if !w.Start(context.Background()) {
		t.Fatal("first diagnostic refused")
	}
	<-entered
	start := time.Now()
	if w.Start(context.Background()) || time.Since(start) > 50*time.Millisecond {
		t.Fatal("WAN diagnosis blocked or overlapped")
	}
	if w.Snapshot().Probe.Measured {
		t.Fatal("in-flight diagnostic fabricated result")
	}
	close(release)
	w.Wait()
	if calls.Load() != 1 || !w.Snapshot().Probe.TCP {
		t.Fatal("lost independent diagnostic")
	}
}
func TestWANCollectorCancellationIsUnknownNotPathFailure(t *testing.T) {
	entered := make(chan struct{}, 1)
	w := NewWAN(func(ctx context.Context) WANResult {
		entered <- struct{}{}
		<-ctx.Done()
		return WANResult{Probe: health.Result{Measured: true}}
	})
	ctx, cancel := context.WithCancel(context.Background())
	w.Start(ctx)
	<-entered
	cancel()
	w.Wait()
	result := w.Snapshot()
	if result.Probe.Measured || result.Probe.NotMeasured != "cancelled" {
		t.Fatal("canceled WAN diagnosis reported measured outage")
	}
}
