package transport

import (
	"context"
	"net/netip"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/config"
	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
)

type NativeAWG struct{ WAN string }

func (a NativeAWG) Switch(ctx context.Context, c connection.Connection) error {
	return config.SwitchAWG(ctx, c.AWG, a.WAN)
}
func (NativeAWG) Probe(ctx context.Context) health.Result { return health.Probe(ctx, contract.AWG) }
func (NativeAWG) Present() bool                           { return health.Present(contract.AWG) }

// SetPorts, ListenPort and LatestHandshake implement AWGRoamer (roam.go).
func (NativeAWG) SetPorts(ctx context.Context, c connection.Connection, listenPort uint16, endpoint netip.AddrPort) error {
	return config.SetAWGRoamPorts(ctx, c.AWG["PublicKey"], listenPort, endpoint)
}
func (NativeAWG) ListenPort(ctx context.Context) (uint16, error) { return config.AWGListenPort(ctx) }
func (NativeAWG) LatestHandshake(ctx context.Context, c connection.Connection) (time.Time, error) {
	return config.AWGLatestHandshake(ctx, c.AWG["PublicKey"])
}
