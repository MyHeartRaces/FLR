package engineupdate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

const (
	ChannelFormat   = "flr-engine-channel-v1"
	MaxChannelBytes = 256 << 10
	MinBinarySize   = 1 << 10
	MaxBinarySize   = 128 << 20
)

// Channel is channel.json.
type Channel struct {
	Format       string                   `json:"format"`
	Channel      string                   `json:"channel"`
	GeneratedAt  string                   `json:"generated_at"`
	PublishedAt  string                   `json:"published_at"`
	SourceCommit string                   `json:"source_commit"`
	Engines      map[string]ChannelEngine `json:"engines"`
}

// ChannelEngine is one engine entry of the manifest.
type ChannelEngine struct {
	Version        string   `json:"version"`
	PackageVersion string   `json:"package_version"`
	Asset          string   `json:"asset"`
	URL            string   `json:"url"`
	SHA256         string   `json:"sha256"`
	Size           int64    `json:"size"`
	Capabilities   []string `json:"capabilities"`
	MinController  string   `json:"min_controller"`
	ContractSHA256 string   `json:"contract_sha256"`
	// APIURL is the GitHub REST asset URL that private-repository clients fetch
	// with "Accept: application/octet-stream". Optional; v1 downloads URL only,
	// but the field must be accepted because CI publishes it.
	APIURL string `json:"api_url,omitempty"`
}

var (
	hex64      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hex40      = regexp.MustCompile(`^[0-9a-f]{40}$`)
	versionRE  = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._+-]{0,127}$`)
	assetRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$`)
	capRE      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	controlRE  = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)
	pkgVersion = regexp.MustCompile(`^[0-9]+(\.[0-9]+){1,5}$`)
	apiAssetRE = regexp.MustCompile(`^https://api\.github\.com/repos/[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}/releases/assets/[1-9][0-9]{0,18}$`)
)

// ParseChannel strictly decodes and validates the manifest bytes.
func ParseChannel(raw []byte) (*Channel, error) {
	if len(raw) > MaxChannelBytes {
		return nil, errors.New("channel manifest too large")
	}
	var c Channel
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return nil, fmt.Errorf("channel manifest rejected: %v", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, errors.New("channel manifest has trailing data")
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate enforces the manifest contract.
func (c *Channel) Validate() error {
	if c.Format != ChannelFormat {
		return errors.New("channel manifest format rejected")
	}
	if c.Channel == "" || len(c.Channel) > 64 {
		return errors.New("channel name rejected")
	}
	gen, err := time.Parse(time.RFC3339, c.GeneratedAt)
	if err != nil {
		return errors.New("generated_at is not RFC3339")
	}
	pub, err := time.Parse(time.RFC3339, c.PublishedAt)
	if err != nil {
		return errors.New("published_at is not RFC3339")
	}
	if pub.Before(gen) {
		return errors.New("published_at precedes generated_at")
	}
	if !hex40.MatchString(c.SourceCommit) {
		return errors.New("source_commit must be 40 hex")
	}
	if len(c.Engines) == 0 || len(c.Engines) > 16 {
		return errors.New("channel engines rejected")
	}
	for name, e := range c.Engines {
		if !enginePattern.MatchString(name) {
			return fmt.Errorf("engine name %q rejected", name)
		}
		if !versionRE.MatchString(e.Version) {
			return fmt.Errorf("%s: version rejected", name)
		}
		if !pkgVersion.MatchString(e.PackageVersion) {
			return fmt.Errorf("%s: package_version rejected", name)
		}
		if !assetRE.MatchString(e.Asset) {
			return fmt.Errorf("%s: asset rejected", name)
		}
		if err := validHTTPS(e.URL); err != nil {
			return fmt.Errorf("%s: url %v", name, err)
		}
		if e.APIURL != "" && !apiAssetRE.MatchString(e.APIURL) {
			return fmt.Errorf("%s: api_url rejected", name)
		}
		if !hex64.MatchString(e.SHA256) || !hex64.MatchString(e.ContractSHA256) {
			return fmt.Errorf("%s: sha256 must be 64 lowercase hex", name)
		}
		if e.Size < MinBinarySize || e.Size > MaxBinarySize {
			return fmt.Errorf("%s: size outside 1 KiB..128 MiB", name)
		}
		if !controlRE.MatchString(e.MinController) {
			return fmt.Errorf("%s: min_controller rejected", name)
		}
		if len(e.Capabilities) > 32 {
			return fmt.Errorf("%s: too many capabilities", name)
		}
		seen := map[string]bool{}
		for _, cp := range e.Capabilities {
			if !capRE.MatchString(cp) || seen[cp] {
				return fmt.Errorf("%s: capability list rejected", name)
			}
			seen[cp] = true
		}
	}
	return nil
}

// PublishedTime returns published_at (valid after Validate).
func (c *Channel) PublishedTime() time.Time {
	t, _ := time.Parse(time.RFC3339, c.PublishedAt)
	return t
}

// VerifySignature checks sig (base64 of a raw 64-byte ed25519 signature)
// over the exact manifest bytes.
func VerifySignature(pub ed25519.PublicKey, manifest, sig []byte) error {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(b) != ed25519.SignatureSize {
		return errors.New("signature is not base64 of 64 bytes")
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, manifest, b) {
		return errors.New("channel signature verification failed")
	}
	return nil
}
