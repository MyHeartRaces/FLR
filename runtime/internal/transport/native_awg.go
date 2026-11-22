package transport

import (
	"context"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/config"
	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/diagnostic"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"github.com/MyHeartRaces/FLR/runtime/internal/native"
)

type NativeAWG struct{ WAN string }

func (a NativeAWG) Switch(ctx context.Context, c connection.Connection) error {
	return config.SwitchAWG(ctx, c.AWG, a.WAN)
}
func (a NativeAWG) switchObserved(ctx context.Context, c connection.Connection, attempt *diagnostic.Attempt) error {
	start := time.Now()
	err := config.SwitchAWGObserved(ctx, c.AWG, a.WAN, func(stage string, began time.Time, err error) {
		switch stage {
		case "ready":
			attempt.Apply = diagnostic.AttemptStage{Outcome: "ok", DurationMS: began.Sub(start).Milliseconds()}
			attempt.Ready = operationStage(began, err)
		case "routes":
			attempt.Routes = operationStage(began, err)
		}
	})
	if attempt.Apply.Outcome == "" {
		attempt.Apply = operationStage(start, err)
	}
	return err
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

func (NativeAWG) readTraffic(ctx context.Context, c connection.Connection) nativeTrafficSample {
	device := health.Device(contract.AWG)
	index := awgIfindex(device)
	if index == 0 || ctx.Err() != nil {
		return nativeTrafficSample{}
	}
	result := native.Execute(ctx, nativeTelemetryReadLimit, "", "awg", "show", device, "transfer")
	if result.Err != nil || ctx.Err() != nil || awgIfindex(device) != index {
		return nativeTrafficSample{}
	}
	sample := parseAWGTransfer(result.Stdout, c.AWG["PublicKey"])
	sample.ifindex = index
	return sample
}

func awgIfindex(device string) int {
	raw, err := os.ReadFile("/sys/class/net/" + device + "/ifindex")
	if err != nil {
		return 0
	}
	index, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || index < 1 {
		return 0
	}
	return index
}
