// Package connection owns logical connections; only Summary is public.
package connection

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/MyHeartRaces/FLR/runtime/internal/config"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
)

var Families = []string{"awg", "hy2", "reality", "vless", "ss2022", "wgws"}
var identityPattern = regexp.MustCompile(`^[a-z0-9_-]{1,80}$`)

type Connection struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Family   string            `json:"family"`
	Group    string            `json:"group"`
	Enabled  bool              `json:"enabled"`
	Revision string            `json:"revision"`
	Profile  *profile.Profile  `json:"profile,omitempty"`
	AWG      map[string]string `json:"awg,omitempty"`
	// Endpoint port roaming (roam.go): AWG only, off when absent, outside the
	// payload revision.
	RoamPorts    string `json:"roam_ports,omitempty"`
	RoamInterval int    `json:"roam_interval,omitempty"`
}
type Summary struct {
	ID           string               `json:"id"`
	Name         string               `json:"name"`
	Family       string               `json:"family"`
	Group        string               `json:"group"`
	Endpoint     string               `json:"endpoint"`
	Enabled      bool                 `json:"enabled"`
	Revision     string               `json:"revision"`
	Capabilities profile.Capabilities `json:"capabilities"`
	RoamPorts    string               `json:"roam_ports,omitempty"`
	RoamInterval int                  `json:"roam_interval,omitempty"`
}

func KnownFamily(family string) bool {
	for _, known := range Families {
		if family == known {
			return true
		}
	}
	return false
}
func NewID() (string, error) {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", fmt.Errorf("cannot allocate connection identity")
	}
	return "conn-" + hex.EncodeToString(data[:]), nil
}
func (c Connection) payloadRevision() (string, error) {
	if c.Family == "awg" {
		if c.Profile != nil || c.AWG == nil {
			return "", fmt.Errorf("AWG requires exactly one native payload")
		}
		if _, err := config.AWGText(c.AWG); err != nil {
			return "", fmt.Errorf("invalid native AWG payload")
		}
	} else {
		if c.Profile == nil || c.AWG != nil || c.Profile.Family != c.Family {
			return "", fmt.Errorf("proxy requires exactly one matching payload")
		}
		if err := profile.ValidateStored(*c.Profile); err != nil {
			return "", fmt.Errorf("invalid stored proxy payload")
		}
		return strings.TrimPrefix(c.Profile.ID, c.Profile.Family+"-"), nil
	}
	raw, err := json.Marshal(c.AWG)
	if err != nil {
		return "", fmt.Errorf("invalid native payload encoding")
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}
func FromProfile(p profile.Profile, id string) (Connection, error) {
	c := Connection{ID: id, Name: p.Name, Family: p.Family, Group: p.ServerGroup, Enabled: !p.UserDisabled && (p.Enabled || strings.HasPrefix(p.DisabledReason, "missing-component:")), Profile: &p}
	var err error
	c.Revision, err = c.payloadRevision()
	return c, err
}
func (c Connection) Validate() error {
	if !identityPattern.MatchString(c.ID) || !KnownFamily(c.Family) || c.Name == "" || len(c.Name) > 512 || !utf8.ValidString(c.Name) || strings.ContainsAny(c.Name, "\r\n\x00") || profile.ValidateGroup(c.Group) != nil {
		return fmt.Errorf("invalid connection identity or metadata")
	}
	revision, err := c.payloadRevision()
	if err != nil || revision != c.Revision {
		return fmt.Errorf("connection payload or revision rejected")
	}
	return c.validateRoam()
}
func (c Connection) redact(value string) string {
	if c.Profile != nil {
		copy := *c.Profile
		copy.Name = value
		return copy.Summary().Name
	}
	for _, field := range []string{"PrivateKey", "PublicKey", "PresharedKey", "HeaderProtectionKey"} {
		if key := c.AWG[field]; key != "" {
			value = strings.ReplaceAll(value, key, "[redacted]")
		}
	}
	return value
}
func (c Connection) Summary() Summary {
	capabilities := profile.Capabilities{TCP: true, UDP: true, RequiredComponents: []string{"awg"}}
	endpoint := c.AWG["Endpoint"]
	if c.Profile != nil {
		capabilities = c.Profile.Summary().Capabilities
		capabilities.RequiredComponents = append([]string{}, capabilities.RequiredComponents...)
		// The canonical importer name contains the outer server without URI tags.
		endpoint = strings.TrimPrefix(c.Profile.Name, c.Profile.Family+"-")
	}
	return Summary{ID: c.ID, Name: c.redact(c.Name), Family: c.Family, Group: c.redact(c.Group), Endpoint: c.redact(endpoint), Enabled: c.Enabled, Revision: c.Revision, Capabilities: capabilities, RoamPorts: c.RoamPorts, RoamInterval: c.RoamInterval}
}
func (c Connection) Clone() Connection {
	raw, _ := json.Marshal(c)
	var copy Connection
	json.Unmarshal(raw, &copy)
	return copy
}
