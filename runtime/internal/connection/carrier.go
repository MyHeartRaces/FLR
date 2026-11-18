package connection

// GameSafe reports whether a family is carried over UDP end to end and may
// therefore carry the Games class automatically (docs/MAX-PACKAGE.md,
// section 5). AWG and Hysteria2 (QUIC) are; VLESS, Reality, SS2022 and
// WireGuard-over-WebSocket ride on TCP and never carry Games unless the owner
// selected that connection explicitly. An unknown family is not game-safe.
func GameSafe(family string) bool {
	return family == "awg" || family == "hy2"
}
