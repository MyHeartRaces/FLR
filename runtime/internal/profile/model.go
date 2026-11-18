// Package profile owns private imported credentials and generated proxy configs.
// Only Summary is suitable for status/list API responses.
package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
)

const (
	DefaultPath    = "/etc/flr-runtime/profiles.json"
	MaxImportBytes = 1 << 20
	MaxProfiles    = 64
)

var idPattern = regexp.MustCompile(`^[a-z0-9_-]{1,80}$`)
var interfacePattern = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)

type Capabilities struct {
	TCP                bool     `json:"tcp"`
	UDP                bool     `json:"udp"`
	TCPOnly            bool     `json:"tcp_only"`
	RequiredComponents []string `json:"required_components"`
}

// Profile contains secrets. Persist it privately; never expose it via list/status.
type Profile struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	Family         string         `json:"family"`
	ServerGroup    string         `json:"server_group"`
	Priority       int            `json:"priority"`
	Enabled        bool           `json:"enabled"`
	UserDisabled   bool           `json:"user_disabled,omitempty"`
	DisabledReason string         `json:"disabled_reason,omitempty"`
	Engine         string         `json:"engine"`
	Capabilities   Capabilities   `json:"capabilities"`
	Outbound       map[string]any `json:"outbound,omitempty"`
	Detour         map[string]any `json:"detour,omitempty"`
	WGWS           *WGWS          `json:"wgws,omitempty"`
}

type WGWS struct {
	Websocket map[string]any `json:"websocket"`
	Endpoint  map[string]any `json:"endpoint"`
	RemoteUDP string         `json:"remote_udp"`
}

type Summary struct {
	ID             string       `json:"id"`
	Name           string       `json:"name"`
	Family         string       `json:"family"`
	ServerGroup    string       `json:"server_group"`
	Priority       int          `json:"priority"`
	Enabled        bool         `json:"enabled"`
	DisabledReason string       `json:"disabled_reason,omitempty"`
	Engine         string       `json:"engine"`
	Capabilities   Capabilities `json:"capabilities"`
}

func (p Profile) Summary() Summary {
	// Names are importer-owned descriptive metadata, never source links or tags.
	reason := p.DisabledReason
	switch reason {
	case "", "missing-component:sing-box", "missing-component:xray", "missing-component:wstunnel":
	default:
		reason = "engine-validation-failed"
	}
	return Summary{
		ID:             p.ID,
		Name:           redactMetadata(p.Name, p),
		Family:         p.Family,
		ServerGroup:    redactMetadata(p.ServerGroup, p),
		Priority:       p.Priority,
		Enabled:        p.Enabled,
		DisabledReason: reason,
		Engine:         p.Engine,
		Capabilities:   p.Capabilities,
	}
}

func redactMetadata(value string, p Profile) string {
	secretKeys := map[string]bool{
		"username":       true,
		"password":       true,
		"uuid":           true,
		"id":             true,
		"private_key":    true,
		"public_key":     true,
		"publicKey":      true,
		"pre_shared_key": true,
		"short_id":       true,
		"shortId":        true,
	}
	var walk func(any)
	walk = func(v any) {
		switch fields := v.(type) {
		case map[string]any:
			for key, field := range fields {
				if secretKeys[key] {
					if secret, ok := field.(string); ok {
						value = redactCredential(value, secret)
					}
				}
				if key == "headers" {
					value = redactHeaderMetadata(value, object(field))
				}
				walk(field)
			}
		case []any:
			for _, item := range fields {
				walk(item)
			}
		}
	}
	walk(p.Outbound)
	walk(p.Detour)
	if p.WGWS != nil {
		walk(p.WGWS.Websocket)
		walk(p.WGWS.Endpoint)
	}
	return value
}

func redactCredential(value, secret string) string {
	if secret != "" && strings.Contains(value, secret) {
		return "[redacted]"
	}
	return value
}

func redactHeaderMetadata(value string, headers map[string]any) string {
	for name, field := range headers {
		// Host is public routing metadata. Treat every other accepted header as
		// private: deployments may authenticate with custom header names.
		if strings.EqualFold(name, "Host") {
			continue
		}
		header, ok := field.(string)
		if !ok {
			continue
		}
		value = redactCredential(value, header)
		// Authorization credentials may be repeated without their scheme, e.g.
		// "team-TOKEN" rather than "team-Bearer TOKEN".
		for _, token := range strings.Fields(header) {
			if !strings.EqualFold(token, "Bearer") && !strings.EqualFold(token, "Basic") {
				value = redactCredential(value, token)
			}
		}
		// Cookie credentials may be repeated without the cookie's name.
		if strings.EqualFold(name, "Cookie") || strings.EqualFold(name, "Set-Cookie") {
			for _, cookie := range strings.Split(header, ";") {
				_, token, ok := strings.Cut(strings.TrimSpace(cookie), "=")
				if ok {
					value = redactCredential(value, strings.Trim(token, "\""))
				}
			}
		}
	}
	return value
}

func finish(p Profile) (Profile, error) {
	identity := struct {
		Engine           string
		Outbound, Detour map[string]any
		WGWS             *WGWS
	}{p.Engine, p.Outbound, p.Detour, p.WGWS}
	b, e := json.Marshal(identity)
	if e != nil {
		return Profile{}, fmt.Errorf("invalid profile identity")
	}
	hash := sha256.Sum256(b)
	p.ID = p.Family + "-" + hex.EncodeToString(hash[:])
	p.Name = p.Family + "-" + hostOf(p)
	udp := p.Family != "ss2022"
	p.Capabilities = Capabilities{TCP: true, UDP: udp, TCPOnly: !udp, RequiredComponents: []string{"sing-box"}}
	p.Enabled = true
	if p.Engine != "sing-box" {
		p.Capabilities.RequiredComponents = append(p.Capabilities.RequiredComponents, p.Engine)
		p.Enabled = false
		p.DisabledReason = "missing-component:" + p.Engine
	}
	return p, nil
}
func hostOf(p Profile) string {
	if p.WGWS != nil {
		return str(p.WGWS.Websocket, "server")
	}
	if p.Engine == "xray" {
		s := object(p.Outbound["settings"])
		v := array(s["vnext"])
		if len(v) > 0 {
			return str(object(v[0]), "address")
		}
	}
	return str(p.Outbound, "server")
}
func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }
func object(v any) map[string]any           { m, _ := v.(map[string]any); return m }
func array(v any) []any                     { a, _ := v.([]any); return a }
func integer(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		if n >= -2147483648 && n <= 2147483647 && n == float64(int(n)) {
			return int(n), true
		}
	case int:
		return n, true
	case json.Number:
		i, e := n.Int64()
		if e == nil && i >= -2147483648 && i <= 2147483647 {
			return int(i), true
		}
	}
	return 0, false
}
func number(m map[string]any, k string, def int) int {
	if v, ok := integer(m[k]); ok {
		return v
	}
	return def
}
func clone(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}
func allowed(m map[string]any, keys ...string) error {
	known := map[string]bool{}
	for _, k := range keys {
		known[k] = true
	}
	for k := range m {
		if !known[k] {
			return fmt.Errorf("unsupported configuration field")
		}
	}
	return nil
}
func require(m map[string]any, keys ...string) error {
	for _, k := range keys {
		if strings.TrimSpace(str(m, k)) == "" {
			return fmt.Errorf("missing required %s", k)
		}
	}
	return nil
}
func hostPort(m map[string]any, host, port string) error {
	h := str(m, host)
	if h == "" || len(h) > 253 || strings.ContainsAny(h, " /\\\r\n\t@?#") || strings.HasPrefix(h, "-") {
		return fmt.Errorf("invalid server address")
	}
	if ip := net.ParseIP(h); ip != nil {
		if ip.To4() == nil || ip.IsLoopback() || ip.IsUnspecified() {
			return fmt.Errorf("server requires non-loopback IPv4")
		}
	} else if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$`).MatchString(h) || strings.EqualFold(h, "localhost") {
		return fmt.Errorf("invalid server hostname")
	}
	n, ok := integer(m[port])
	if !ok || n < 1 || n > 65535 {
		return fmt.Errorf("invalid server port")
	}
	return nil
}
