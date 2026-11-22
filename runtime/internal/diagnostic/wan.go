package diagnostic

import (
	"context"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"sync"
	"time"
)

type WANResult struct {
	At               time.Time `json:"at"`
	sampledAt        time.Time
	Probe            health.Result `json:"probe"`
	LinkKnown        bool          `json:"link_known"`
	LinkUp           bool          `json:"link_up"`
	CarrierKnown     bool          `json:"carrier_known"`
	Carrier          bool          `json:"carrier"`
	RouteKnown       bool          `json:"route_known"`
	DefaultRoute     bool          `json:"default_route"`
	Gateway          bool          `json:"gateway"`
	AWGCountersKnown bool          `json:"awg_counters_known"`
	AWGRX            uint64        `json:"awg_rx_bytes"`
	AWGTX            uint64        `json:"awg_tx_bytes"`
}
type WAN struct {
	mu      sync.Mutex
	busy    bool
	result  WANResult
	probe   func(context.Context) WANResult
	workers sync.WaitGroup
}

func NewWAN(probe func(context.Context) WANResult) *WAN { return &WAN{probe: probe} }
func (w *WAN) Start(ctx context.Context) bool {
	w.mu.Lock()
	if w.busy {
		w.mu.Unlock()
		return false
	}
	w.busy = true
	w.workers.Add(1)
	w.mu.Unlock()
	go func() {
		defer w.workers.Done()
		bounded, cancel := context.WithTimeout(ctx, health.RoundDeadline)
		defer cancel()
		r := w.probe(bounded)
		if ctx.Err() != nil {
			r.Probe = health.Result{NotMeasured: "cancelled"}
		} else if bounded.Err() != nil {
			r.Probe = health.Result{NotMeasured: "timeout"}
		}
		r.Probe = probe(r.Probe)
		r.sampledAt = time.Now()
		r.At = r.sampledAt.UTC()
		w.mu.Lock()
		w.result = r
		w.busy = false
		w.mu.Unlock()
	}()
	return true
}
func (w *WAN) Snapshot() WANResult { w.mu.Lock(); defer w.mu.Unlock(); return w.result }
func (w *WAN) Wait()               { w.workers.Wait() }
