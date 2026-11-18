package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/native"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
)

const randomSNICapability = "hysteria2-random-sni-per-quic-dial-v1"

// Require the installed engine to affirm the actual dial-boundary behavior.
// The bounded fixed command never receives a profile or any credentials.
func requireRandomSNICapability(ctx context.Context, p profile.Profile) error {
	if p.Engine != "sing-box" {
		return nil
	}
	if _, enabled := p.Outbound["flr_random_sni_suffix"]; !enabled {
		return nil
	}
	result := native.Execute(ctx, 2*time.Second, "", "sing-box", "flr-capabilities")
	if result.Err != nil || len(result.Stdout) > 4096 {
		return fmt.Errorf("required random SNI engine capability unavailable")
	}
	var receipt struct {
		Version      int      `json:"version"`
		Capabilities []string `json:"capabilities"`
	}
	decoder := json.NewDecoder(bytes.NewReader(result.Stdout))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil || receipt.Version != 1 || decoder.Decode(new(any)) != io.EOF {
		return fmt.Errorf("invalid random SNI engine capability response")
	}
	for _, capability := range receipt.Capabilities {
		if capability == randomSNICapability {
			return nil
		}
	}
	return fmt.Errorf("required random SNI engine capability missing")
}
