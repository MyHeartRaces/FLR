package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"

	"github.com/MyHeartRaces/FLR/runtime/internal/bypass"
	"github.com/MyHeartRaces/FLR/runtime/internal/connection"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/control"
	"github.com/MyHeartRaces/FLR/runtime/internal/dataplane"
	"github.com/MyHeartRaces/FLR/runtime/internal/health"
	"github.com/MyHeartRaces/FLR/runtime/internal/lan"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
	"github.com/MyHeartRaces/FLR/runtime/internal/profile"
	"github.com/MyHeartRaces/FLR/runtime/internal/qos"
)

const StateDir = "/etc/flr-runtime"

type Settings struct {
	DirectBypass bypass.Config `json:"direct_bypass"`
	HealthPolicy health.Policy `json:"health_policy"`
	WarmReserve  *WarmReserve  `json:"warm_reserve,omitempty"`
	// RoutingMode selects which direct lists of the installed policy apply
	// (policy.ForMode). Stored empty for the default "split", so settings stay
	// loadable by a 0.6 controller after a rollback.
	RoutingMode string `json:"routing_mode,omitempty"`
	// TunnelQoS is CAKE on the AWG tunnel (internal/qos); absent means off.
	TunnelQoS       *qos.Config          `json:"tunnel_qos,omitempty"`
	Version         int                  `json:"version"`
	SavedGeneration uint64               `json:"saved_generation,omitempty"`
	DirectProxy     control.DirectConfig `json:"direct_proxy"`
	// Enabled controls VPN policy activation independently of the controller's
	// administrative socket and the optional direct listener added by Task3.
	Enabled          bool                 `json:"enabled"`
	Options          dataplane.Options    `json:"options"`
	DNSPort          string               `json:"dns_port"`
	LocalDNSPort     string               `json:"local_dns_port"`
	ProfileSelection string               `json:"profile_selection"`
	PrimaryGroup     string               `json:"primary_group,omitempty"`
	FamilyOrder      []string             `json:"family_order,omitempty"`
	Selection        connection.Selection `json:"selection"`
	Order            connection.Order     `json:"order"`
	MigrationNotice  string               `json:"migration_notice,omitempty"`
}

func DefaultSettings() Settings {
	options := dataplane.Options{LAN: lan.Interface, WAN: "eth1", Selection: contract.Selection{General: contract.Down, Games: contract.Down}}
	return Settings{DirectBypass: bypass.Config{TCP: "off", QUIC: "off"}, HealthPolicy: health.DefaultPolicy(), Version: 1, DirectProxy: storedDirectDefault(), Enabled: false, Options: options, DNSPort: "1054", LocalDNSPort: "53", ProfileSelection: "auto"}
}

// storedDirectDefault is the direct proxy configuration stored when none was
// saved: the 0.6 default (192.168.8.1:1080, enabled). The stored bind is not
// the address the listener uses; the controller always binds the router's
// discovered LAN address (Controller.effectiveDirect). It is kept as loaded
// and API saves keep it too, because the 0.6 controller refuses settings
// whose bind is not 192.168.8.1 and a rollback must find settings it accepts.
func storedDirectDefault() control.DirectConfig {
	return control.DefaultDirectConfigFor(lan.Legacy())
}

// WarmReserve keeps the first UDP proxy connection started and probed beside a
// healthy AWG default in auto mode (unified connections only). Nil means the
// default and is not stored: earlier controllers decode settings strictly and
// would reject the key.
type WarmReserve struct {
	Enabled         bool `json:"enabled"`
	IntervalSeconds int  `json:"interval_seconds"`
}

func DefaultWarmReserve() WarmReserve { return WarmReserve{Enabled: true, IntervalSeconds: 30} }
func (w WarmReserve) Validate() error {
	if w.IntervalSeconds < 30 || w.IntervalSeconds > 300 {
		return fmt.Errorf("warm reserve interval must be 30-300 seconds")
	}
	return nil
}
func (s Settings) EffectiveWarmReserve() WarmReserve {
	if s.WarmReserve == nil {
		return DefaultWarmReserve()
	}
	return *s.WarmReserve
}

// storedWarmReserve is the persisted form: nil for the default.
func storedWarmReserve(w WarmReserve) *WarmReserve {
	if w == DefaultWarmReserve() {
		return nil
	}
	return &w
}

// decodeWarmReserve requires a complete object, like the health policy.
func decodeWarmReserve(raw []byte) (WarmReserve, error) {
	var value struct {
		Enabled         *bool `json:"enabled"`
		IntervalSeconds *int  `json:"interval_seconds"`
	}
	if e := decodeStrict(raw, &value); e != nil {
		return WarmReserve{}, e
	}
	if value.Enabled == nil || value.IntervalSeconds == nil {
		return WarmReserve{}, fmt.Errorf("warm reserve requires explicit enabled and interval_seconds")
	}
	w := WarmReserve{Enabled: *value.Enabled, IntervalSeconds: *value.IntervalSeconds}
	return w, w.Validate()
}

// repairDirectBind keeps the stored bind as loaded (see storedDirectDefault).
// Only a bind that is not a private IPv4 address at all, which no controller
// writes, is replaced by the 0.6 default once the LAN is discovered, so such a
// file still loads instead of stopping the controller. The listener never uses
// the stored bind. Enabled and port are kept; nothing changes when discovery
// fails, and settings validation then rejects the bind as before.
func repairDirectBind(s *Settings) {
	if control.ValidateDirectShape(control.DirectConfig{Bind: s.DirectProxy.Bind, Port: 1080}) == nil {
		return
	}
	if _, e := s.Options.ResolveLAN(); e == nil {
		s.DirectProxy.Bind = storedDirectDefault().Bind
	}
}
func decodeStrict(b []byte, v any) error {
	if e := control.CheckJSON(b); e != nil {
		return e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return fmt.Errorf("invalid settings schema")
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return fmt.Errorf("trailing settings")
	}
	return nil
}

// ValidateSettings checks structure only (addresses, ports, class names and
// so on), never membership in the live LAN: settings must load whatever the
// LAN is now. New device profiles and direct proxy binds are checked against
// the current LAN where they are requested (checkDeviceChange,
// checkDirectChange).
func ValidateSettings(s Settings) error { return validateSettings(s, false) }

// The legacy exception belongs only to persisted metadata, never to profile
// imports or an explicitly supplied new primary group.
var legacyPrimaryGroup = regexp.MustCompile(`^[a-zA-Z0-9_. -]*$`)

func validateSettings(s Settings, storedGroup bool) error {
	if e := s.DirectBypass.Validate(); e != nil {
		return e
	}
	if e := s.HealthPolicy.Validate(); e != nil {
		return e
	}
	if s.WarmReserve != nil {
		if e := s.WarmReserve.Validate(); e != nil {
			return e
		}
	}
	if s.TunnelQoS != nil {
		if e := s.TunnelQoS.Validate(); e != nil {
			return e
		}
	}
	if s.RoutingMode != "" && (s.RoutingMode == policy.ModeSplit || !policy.ValidMode(s.RoutingMode)) {
		return fmt.Errorf("invalid routing mode")
	}
	if e := control.ValidateDirectShape(s.DirectProxy); e != nil {
		return e
	}
	if s.DirectProxy.Port == portNumber(s.DNSPort) || s.DirectProxy.Port == portNumber(s.LocalDNSPort) {
		return fmt.Errorf("direct proxy port collides with DNS")
	}
	if s.Version != 1 && s.Version != 2 {
		return fmt.Errorf("unsupported settings version")
	}
	if s.SavedGeneration > (1<<53)-1 {
		return fmt.Errorf("invalid saved generation")
	}
	if e := dataplane.ValidateOptions(s.Options); e != nil {
		return fmt.Errorf("invalid network settings")
	}
	for _, port := range []string{s.DNSPort, s.LocalDNSPort} {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return fmt.Errorf("invalid DNS port")
		}
	}
	if s.DNSPort == s.LocalDNSPort {
		return fmt.Errorf("DNS ports collide")
	}
	if !regexp.MustCompile(`^[a-z0-9_-]{1,80}$`).MatchString(s.ProfileSelection) {
		return fmt.Errorf("invalid profile selection")
	}
	if profile.ValidateGroup(s.PrimaryGroup) != nil && !(storedGroup && len(s.PrimaryGroup) <= 128 && legacyPrimaryGroup.MatchString(s.PrimaryGroup)) {
		return fmt.Errorf("invalid primary group")
	}
	if s.Version == 2 {
		if err := connection.ValidateSelection(s.Selection); err != nil {
			return err
		}
		if err := connection.ValidateFamilies(s.Order.Families); err != nil {
			return err
		}
		if len(s.MigrationNotice) > 512 {
			return fmt.Errorf("invalid migration notice")
		}
		return validateFamilyOrder(s.FamilyOrder, false)
	}
	return validateFamilyOrder(s.FamilyOrder, storedGroup)
}
func validateFamilyOrder(order []string, legacy bool) error {
	allowed := map[string]bool{"reality": true, "vless": true, "ss2022": true, "wgws": true}
	if legacy {
		allowed["naive"] = true
	}
	for _, family := range order {
		if !allowed[family] {
			return fmt.Errorf("invalid or repeated family order")
		}
		allowed[family] = false
	}
	return nil
}
func DecodeSettings(b []byte) (Settings, error) {
	s := Settings{DirectBypass: bypass.Config{TCP: "off", QUIC: "off"}, HealthPolicy: health.DefaultPolicy(), DirectProxy: storedDirectDefault()}
	if len(b) > 1<<20 {
		return s, fmt.Errorf("settings too large")
	}
	if e := decodeStrict(b, &s); e != nil {
		return s, e
	}
	var fields map[string]json.RawMessage
	if e := json.Unmarshal(b, &fields); e != nil {
		return s, e
	}
	if raw, ok := fields["health_policy"]; ok {
		var e error
		s.HealthPolicy, e = decodeHealthPolicy(raw)
		if e != nil {
			return s, e
		}
	}
	if raw, ok := fields["warm_reserve"]; ok {
		w, e := decodeWarmReserve(raw)
		if e != nil {
			return s, e
		}
		s.WarmReserve = storedWarmReserve(w)
	}
	if raw, ok := fields["direct_bypass"]; ok {
		var e error
		s.DirectBypass, e = decodeBypassWith(raw, true)
		if e != nil {
			return s, e
		}
	}
	if raw, ok := fields["primary_group"]; ok && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return s, fmt.Errorf("invalid primary group")
	}
	// Existing settings only exist after prepare/apply. Preserve that explicit
	// legacy activation; clean images use DefaultSettings and stay disabled.
	if s.Version == 0 {
		s.Version = 1
		s.Enabled = true
	}
	if s.ProfileSelection == "" {
		s.ProfileSelection = "auto"
	}
	repairDirectBind(&s)
	return s, validateSettings(s, true)
}
func readSettingsAt(dir string) (Settings, error) {
	path := filepath.Join(dir, "settings.json")
	info, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return DefaultSettings(), nil
	}
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 1<<20 {
		return Settings{}, fmt.Errorf("private settings file rejected")
	}
	f, e := os.Open(path)
	if e != nil {
		return Settings{}, fmt.Errorf("cannot read private settings")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if e != nil {
		return Settings{}, fmt.Errorf("cannot read private settings")
	}
	return DecodeSettings(b)
}
func ReadSettings() (Settings, error) {
	lock, err := lockPrivateAdmin(StateDir)
	if err != nil {
		return Settings{}, err
	}
	defer lock.Close()
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if err := recoverConnectionState(StateDir); err != nil {
		return Settings{}, err
	}
	if err := migrateState(StateDir); err != nil {
		return Settings{}, err
	}
	return readSettingsAt(StateDir)
}

// WriteJSON atomically persists private state. It rejects symlink targets,
// syncs bytes before rename and syncs the directory after publication.
func WriteJSON(path string, v any) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("invalid state path")
	}
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	dir := filepath.Dir(path)
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	info, e := os.Lstat(dir)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return fmt.Errorf("state directory must be private")
	}
	if info, e = os.Lstat(path); e == nil && (!info.Mode().IsRegular() || info.Mode().Perm() != 0600) {
		return fmt.Errorf("unsafe state file")
	}
	f, e := os.CreateTemp(dir, ".state-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	if e = os.Rename(tmp, path); e != nil {
		return e
	}
	d, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}

func portNumber(p string) int { n, _ := strconv.Atoi(p); return n }

// Updates require a complete object, including an explicit enabled boolean.
// Every numeric field is mandatory because zero is outside its valid bounds.
func decodeHealthPolicy(raw []byte) (health.Policy, error) {
	var p health.Policy
	if e := decodeStrict(raw, &p); e != nil {
		return p, e
	}
	var fields map[string]json.RawMessage
	if e := json.Unmarshal(raw, &fields); e != nil {
		return p, e
	}
	enabled, ok := fields["enabled"]
	if !ok || bytes.Equal(bytes.TrimSpace(enabled), []byte("null")) {
		return p, fmt.Errorf("health policy requires explicit enabled and all thresholds")
	}
	return p, p.Validate()
}

func decodeBypass(raw []byte) (bypass.Config, error) { return decodeBypassWith(raw, false) }

func decodeBypassWith(raw []byte, stored bool) (bypass.Config, error) {
	var value struct {
		Enabled *bool   `json:"enabled"`
		TCP     *string `json:"tcp"`
		QUIC    *string `json:"quic"`
	}
	if e := decodeStrict(raw, &value); e != nil {
		return bypass.Config{}, e
	}
	if value.Enabled == nil || value.TCP == nil || value.QUIC == nil {
		return bypass.Config{}, fmt.Errorf("direct bypass requires explicit enabled, tcp and quic")
	}
	c := bypass.Config{Enabled: *value.Enabled, TCP: *value.TCP, QUIC: *value.QUIC}
	if stored {
		if c.TCP == "" {
			c.TCP = "off"
		}
		if c.QUIC == "" {
			c.QUIC = "off"
		}
	}
	if c.TCP == "" || c.QUIC == "" {
		return c, fmt.Errorf("direct bypass requires explicit enabled, tcp and quic")
	}
	return c, c.Validate()
}

// loadInstalledPolicy is the policy the router runs when the controller was
// started without one: the private overlay when valid, else the image policy.
func loadInstalledPolicy() (*policy.Policy, error) {
	p, _, _, e := policy.LoadInstalled()
	return p, e
}

// EffectiveRoutingMode is the routing mode in force: the stored mode or
// "split" (the installed policy as is).
func (s Settings) EffectiveRoutingMode() string {
	if s.RoutingMode == "" {
		return policy.ModeSplit
	}
	return s.RoutingMode
}

// storedRoutingMode is the persisted form: empty for the default.
func storedRoutingMode(mode string) (string, error) {
	if !policy.ValidMode(mode) {
		return "", fmt.Errorf("routing mode must be split, full_domestic or full")
	}
	if mode == policy.ModeSplit {
		return "", nil
	}
	return mode, nil
}

// decodeTunnelQoS requires a complete object; a disabled setting is stored
// as absent.
func decodeTunnelQoS(raw []byte) (*qos.Config, error) {
	var v struct {
		Enabled      *bool `json:"enabled"`
		UploadKbit   *int  `json:"upload_kbit"`
		DownloadKbit *int  `json:"download_kbit"`
	}
	if e := decodeStrict(raw, &v); e != nil {
		return nil, e
	}
	if v.Enabled == nil || v.UploadKbit == nil || v.DownloadKbit == nil {
		return nil, fmt.Errorf("tunnel queueing requires enabled, upload_kbit and download_kbit")
	}
	c := qos.Config{Enabled: *v.Enabled, UploadKbit: *v.UploadKbit, DownloadKbit: *v.DownloadKbit}
	if e := c.Validate(); e != nil {
		return nil, e
	}
	if !c.Enabled {
		return nil, nil
	}
	return &c, nil
}

func (s Settings) effectiveTunnelQoS() qos.Config {
	if s.TunnelQoS == nil {
		return qos.Config{}
	}
	return *s.TunnelQoS
}
