// Package engineupdate keeps proxy engines on the newest version proven
// compatible with the router's live connections. See docs/ENGINE-UPDATES.md.
//
// Safety properties enforced here: the updater never restarts or signals a
// running engine, never touches nft/rules/routes/firewall, never dials outside
// the tunnel, and never writes a binary that has not passed every gate.
package engineupdate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
)

const (
	ModeCheck = "check"
	ModeApply = "apply"
	// MaxConfigBytes bounds engine-update.json.
	MaxConfigBytes = 64 << 10
)

// Config is /etc/flr-runtime/engine-update.json. Absent file means disabled.
type Config struct {
	Enabled          bool     `json:"enabled"`
	Mode             string   `json:"mode"`
	ChannelURL       string   `json:"channel_url"`
	AuthTokenFile    string   `json:"auth_token_file"`
	RequireSignature bool     `json:"require_signature"`
	PublicKey        string   `json:"public_key"`
	IntervalHours    int      `json:"interval_hours"`
	SoakHours        int      `json:"soak_hours"`
	CanarySeconds    int      `json:"canary_seconds"`
	CanaryMinBytes   int64    `json:"canary_min_bytes"`
	CanaryPort       int      `json:"canary_port"`
	ScopeServers     []string `json:"scope_servers"`
	Engines          []string `json:"engines"`
	UpdateUnused     bool     `json:"update_unused"`
}

// DefaultConfig returns the documented defaults.
func DefaultConfig() Config {
	return Config{Mode: ModeCheck, IntervalHours: 24, SoakHours: 72, CanarySeconds: 60,
		CanaryMinBytes: 8 << 20, CanaryPort: 10891, ScopeServers: []string{}, Engines: []string{"sing-box"}}
}

var enginePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// ErrNoConfig is returned by LoadConfig when the file does not exist.
var ErrNoConfig = errors.New("engine update config absent")

// LoadConfig decodes strictly (unknown keys rejected). A missing file returns
// ErrNoConfig together with a disabled default config.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	raw, err := readBounded(path, MaxConfigBytes)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, ErrNoConfig
	}
	if err != nil {
		return cfg, fmt.Errorf("engine update config unreadable: %w", err)
	}
	return ParseConfig(raw)
}

// ParseConfig is LoadConfig for bytes.
func ParseConfig(raw []byte) (Config, error) {
	cfg := DefaultConfig()
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("engine update config rejected: %v", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return cfg, errors.New("engine update config has trailing data")
	}
	return cfg, cfg.Validate()
}

// Validate checks ranges. Disabled configs only need to be well formed.
func (c Config) Validate() error {
	if c.Mode != ModeCheck && c.Mode != ModeApply {
		return fmt.Errorf("mode must be %q or %q", ModeCheck, ModeApply)
	}
	if c.IntervalHours < 1 || c.IntervalHours > 720 {
		return errors.New("interval_hours must be 1..720")
	}
	if c.SoakHours < 0 || c.SoakHours > 8760 {
		return errors.New("soak_hours must be 0..8760")
	}
	if c.CanarySeconds < 10 || c.CanarySeconds > 600 {
		return errors.New("canary_seconds must be 10..600")
	}
	if c.CanaryMinBytes < 1024 || c.CanaryMinBytes > 256<<20 {
		return errors.New("canary_min_bytes must be 1 KiB..256 MiB")
	}
	if c.CanaryPort < 1024 || c.CanaryPort > 65535 || (c.CanaryPort >= 1081 && c.CanaryPort <= 1083) || c.CanaryPort == 1088 {
		return errors.New("canary_port invalid or reserved by production")
	}
	for _, s := range c.ScopeServers {
		if ip := net.ParseIP(s); ip == nil || ip.To4() == nil {
			return errors.New("scope_servers must be IPv4 addresses")
		}
	}
	if len(c.Engines) == 0 {
		return errors.New("engines must not be empty")
	}
	seen := map[string]bool{}
	for _, e := range c.Engines {
		if !enginePattern.MatchString(e) || seen[e] {
			return errors.New("invalid or repeated engine name")
		}
		if e != "sing-box" {
			return fmt.Errorf("engine %q: only sing-box is supported", e)
		}
		seen[e] = true
	}
	if c.PublicKey != "" {
		if _, err := c.PublicKeyBytes(); err != nil {
			return err
		}
	}
	if c.RequireSignature && c.PublicKey == "" {
		return errors.New("require_signature needs public_key")
	}
	if c.AuthTokenFile != "" && !pathAbs(c.AuthTokenFile) {
		return errors.New("auth_token_file must be an absolute path")
	}
	if c.Enabled {
		if err := validHTTPS(c.ChannelURL); err != nil {
			return fmt.Errorf("channel_url: %v", err)
		}
	}
	return nil
}

func pathAbs(p string) bool { return len(p) > 0 && p[0] == '/' }

// PublicKeyBytes decodes the base64 raw ed25519 public key.
func (c Config) PublicKeyBytes() (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(c.PublicKey)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("public_key must be base64 of a raw 32-byte ed25519 key")
	}
	return ed25519.PublicKey(b), nil
}

func validHTTPS(s string) error {
	_, err := parseHTTPS(s)
	return err
}

func parseHTTPS(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("must be an https URL without credentials")
	}
	return u, nil
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("file exceeds size bound")
	}
	return b, nil
}
