package controller

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/control"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
	"github.com/MyHeartRaces/FLR/runtime/internal/privatefile"
)

// Routing policy API (docs/ROUTER-API.md, "Routing policy"). It shows the
// installed policy (the image default or the owner's private overlay), keeps
// the owner's custom rules in <state>/custom-rules.json, imports and exports
// the whole routing configuration in chunks that fit the LuCI request limit,
// and applies every change live through the routing-mode reconcile path:
// effective policy = installed policy + custom rules, rendered into the
// static nft sets and handed to the DNS broker. Only new flows are
// classified, so no established session changes channel and the VPN is not
// restarted.

var (
	// routingImageDir and routingStagingRoot are replaced in tests.
	routingImageDir    = policy.ImageDir
	routingStagingRoot = "/var/run/flr-runtime/routing-import"
)

const (
	customRulesFile      = "custom-rules.json"
	overlayBackupName    = "policy.backup"
	routingBundleFormat  = "flr-routing-bundle"
	routingBundleVersion = 1
	maxRoutingBundle     = 16 << 20
	routingChunkBytes    = 32 << 10
	maxRoutingPage       = 200
	routingStagingTTL    = time.Hour
	maxCustomRulesBytes  = 1 << 20
)

var (
	stagingIDRE = regexp.MustCompile(`^[0-9a-f]{16}$`)
	sha256RE    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	ruleIDArgRE = regexp.MustCompile(`^[a-z0-9_-]{1,40}$`)
)

// routingState is what the controller knows about the routing configuration
// it runs. Guarded by adminMu.
type routingState struct {
	lastApply    time.Time
	lastSource   string
	customErr    string
	exportKey    string
	exportData   []byte
	exportSum    string
	exportSource string
	// installedKey caches which directory LoadInstalled would use, keyed by
	// routingFingerprint, so reads do not reload a large overlay each time.
	installedKey string
	installedDir string
	overlayLoad  string
}

type routingArgs struct {
	Ruleset  string             `json:"ruleset,omitempty"`
	Query    string             `json:"query,omitempty"`
	Offset   int64              `json:"offset,omitempty"`
	Limit    int                `json:"limit,omitempty"`
	ID       string             `json:"id,omitempty"`
	Revision string             `json:"revision,omitempty"`
	Rule     *policy.CustomRule `json:"rule,omitempty"`
	Size     int64              `json:"size,omitempty"`
	SHA256   string             `json:"sha256,omitempty"`
	Staging  string             `json:"staging_id,omitempty"`
	Data     string             `json:"data,omitempty"`
	Accepted bool               `json:"accepted,omitempty"`
	// RoscomVPN import (roscomvpn_api.go).
	URL    string `json:"url,omitempty"`
	DryRun bool   `json:"dry_run,omitempty"`
}

// routingBundle is the import/export document. A bundle may carry the policy
// (policy.json and every ruleset), the custom rules, or both.
type routingBundle struct {
	Format      string                     `json:"format"`
	Version     int                        `json:"version"`
	Source      string                     `json:"source,omitempty"`
	Policy      json.RawMessage            `json:"policy,omitempty"`
	Rulesets    map[string]json.RawMessage `json:"rulesets,omitempty"`
	CustomRules *policy.CustomRules        `json:"custom_rules,omitempty"`
}

type routingApply struct {
	Applied      bool   `json:"applied"`
	Pending      string `json:"pending,omitempty"`
	Source       string `json:"source"`
	Mode         string `json:"mode"`
	OverlayError string `json:"overlay_error,omitempty"`
	CustomError  string `json:"custom_rules_error,omitempty"`
}

type stagingMeta struct {
	Size    int64     `json:"size"`
	SHA256  string    `json:"sha256"`
	Created time.Time `json:"created"`
}

// decodeRoutingJSON is strict: no duplicate keys, no unknown fields, no
// trailing data.
func decodeRoutingJSON(raw []byte, v any) error {
	if e := control.CheckJSON(raw); e != nil {
		return e
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return fmt.Errorf("invalid JSON (%v)", e)
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}

func (c *Controller) overlayDir() string       { return filepath.Join(c.stateDir, "policy") }
func (c *Controller) overlayBackupDir() string { return filepath.Join(c.stateDir, overlayBackupName) }
func (c *Controller) customRulesPath() string  { return filepath.Join(c.stateDir, customRulesFile) }

func (c *Controller) sourceName(dir string) string {
	if dir == c.overlayDir() {
		return "overlay"
	}
	return "image"
}

func errText(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}

func exists(path string) bool { _, e := os.Lstat(path); return e == nil }

// readCustomRulesAt returns the stored rules, or the empty list when none are
// stored. On error the empty list is returned beside it: a broken file never
// stops routing, it only stops applying the custom rules.
func readCustomRulesAt(dir string) (*policy.CustomRules, error) {
	path := filepath.Join(dir, customRulesFile)
	if _, e := os.Lstat(path); os.IsNotExist(e) {
		return policy.EmptyCustomRules(), nil
	}
	raw, e := privatefile.Read(path, maxCustomRulesBytes)
	if e != nil {
		return policy.EmptyCustomRules(), fmt.Errorf("custom rules file unreadable: %v", e)
	}
	var rules policy.CustomRules
	if e = decodeRoutingJSON(raw, &rules); e != nil {
		return policy.EmptyCustomRules(), fmt.Errorf("custom rules file rejected: %v", e)
	}
	if e = rules.Normalize(netip.Prefix{}); e != nil {
		return policy.EmptyCustomRules(), fmt.Errorf("custom rules file rejected: %v", e)
	}
	return &rules, nil
}

func (c *Controller) readCustomRules() (*policy.CustomRules, error) {
	return readCustomRulesAt(c.stateDir)
}

func (c *Controller) writeCustomRules(rules *policy.CustomRules) error {
	raw, e := json.MarshalIndent(rules, "", " ")
	if e != nil {
		return e
	}
	// The reader refuses larger files, so a larger list must not be saved.
	if len(raw)+1 > maxCustomRulesBytes {
		return fmt.Errorf("custom rules exceed %d bytes; shorten comments or remove rules", maxCustomRulesBytes)
	}
	if e = privatefile.Write(c.customRulesPath(), append(raw, '\n')); e != nil {
		return fmt.Errorf("custom rules could not be saved: %v", e)
	}
	return nil
}

// normalizeCustomRules validates rules against the router LAN as it is now.
// A VPN address rule needs the LAN to be known, so it cannot hide the LAN.
func (c *Controller) normalizeCustomRules(rules *policy.CustomRules) error {
	c.mu.RLock()
	prefix, routerErr := c.router.Prefix, c.routerErr
	c.mu.RUnlock()
	// Like checkDirectChange: the LAN counts as known only while discovery
	// currently succeeds.
	if routerErr != "" {
		prefix = netip.Prefix{}
	}
	if e := rules.Normalize(prefix); e != nil {
		return e
	}
	if !prefix.IsValid() {
		for _, rule := range rules.Rules {
			if rule.Mode == policy.RuleVPN && rule.Type != policy.RuleDomain {
				return fmt.Errorf("router LAN unknown (%s); vpn address rules cannot be checked against it yet", routerErr)
			}
		}
	}
	return nil
}

// withCustomRules is the base policy the controller starts with: the
// installed policy plus the stored custom rules. Invalid custom rules are
// ignored and reported; they never stop the router.
func (c *Controller) withCustomRules(p *policy.Policy, stateDir string) *policy.Policy {
	if p == nil {
		return nil
	}
	rules, e := readCustomRulesAt(stateDir)
	c.routing.customErr = errText(e)
	if e != nil {
		c.mu.Lock()
		c.lastError = e.Error() + "; custom routing rules ignored"
		c.mu.Unlock()
	}
	return p.WithCustom(rules)
}

// applyRouting reloads the installed policy and the custom rules and applies
// them: at once when the VPN runs (static sets, DNS classifier and bindings),
// otherwise at the next VPN start. Callers hold adminMu.
func (c *Controller) applyRouting() (routingApply, error) {
	mode := c.settings.EffectiveRoutingMode()
	base, dir, overlayErr, err := policy.LoadInstalledAt(c.overlayDir(), routingImageDir)
	if err != nil {
		return routingApply{}, fmt.Errorf("installed routing policy unavailable: %v", err)
	}
	rules, customErr := c.readCustomRules()
	result := routingApply{Source: c.sourceName(dir), Mode: mode, OverlayError: errText(overlayErr), CustomError: errText(customErr)}
	c.routing.lastApply, c.routing.lastSource = time.Now().UTC(), result.Source
	c.routing.customErr = result.CustomError
	if !c.live {
		result.Pending = "controller not running; the next start uses this configuration"
		return result, nil
	}
	c.mu.Lock()
	c.basePolicy = base.WithCustom(rules)
	if c.vpnStarted {
		// Re-render through the routing mode reconcile path even though the
		// mode itself is unchanged.
		c.appliedMode = ""
	}
	c.mu.Unlock()
	if !c.vpnStarted {
		result.Pending = "VPN not running; it starts with this configuration"
		return result, nil
	}
	c.reconcileRoutingMode()
	c.mu.RLock()
	result.Applied = c.appliedMode == mode
	c.mu.RUnlock()
	if !result.Applied {
		result.Pending = "not applied yet; the controller retries every round"
	}
	return result, nil
}

// installedDir is the directory the installed policy loads from (overlay or
// image) and the overlay error, if the overlay was refused.
func (c *Controller) installedDir() (string, string, error) {
	key := c.routingFingerprint()
	if key == c.routing.installedKey && c.routing.installedDir != "" {
		return c.routing.installedDir, c.routing.overlayLoad, nil
	}
	_, dir, overlayErr, err := policy.LoadInstalledAt(c.overlayDir(), routingImageDir)
	if err != nil {
		return "", "", fmt.Errorf("installed routing policy unavailable: %v", err)
	}
	c.routing.installedKey, c.routing.installedDir, c.routing.overlayLoad = key, dir, errText(overlayErr)
	return dir, c.routing.overlayLoad, nil
}

// handleRoutingAPI serves the routing-* operations. Callers hold adminMu.
func (c *Controller) handleRoutingAPI(r control.APIRequest) (any, bool, error) {
	if !strings.HasPrefix(r.Operation, "routing-") {
		return nil, false, nil
	}
	var args routingArgs
	if len(r.Routing) > 0 {
		if e := decodeRoutingJSON(r.Routing, &args); e != nil {
			return nil, true, fmt.Errorf("invalid routing arguments: %v", e)
		}
	}
	if (args.URL != "" || args.DryRun) && r.Operation != "routing-roscomvpn-import" {
		return nil, true, fmt.Errorf("invalid routing arguments: url and dry_run belong to routing-roscomvpn-import")
	}
	var result any
	var err error
	switch r.Operation {
	case "routing-policy":
		result, err = c.routingOverview()
	case "routing-entries":
		result, err = c.routingEntries(args)
	case "routing-rules":
		result, err = c.routingRules(args)
	case "routing-rule-add", "routing-rule-update", "routing-rule-delete":
		result, err = c.routingRuleEdit(r.Operation, args)
	case "routing-apply":
		apply, e := c.applyRouting()
		result, err = map[string]any{"apply": apply}, e
	case "routing-export":
		result, err = c.routingExport(args)
	case "routing-import-begin":
		result, err = c.routingImportBegin(args)
	case "routing-import-chunk":
		result, err = c.routingImportChunk(args)
	case "routing-import-commit":
		result, err = c.routingImportCommit(args)
	case "routing-import-abort":
		if !stagingIDRE.MatchString(args.Staging) {
			return nil, true, fmt.Errorf("invalid staging ID")
		}
		removeStaging(args.Staging)
		result = map[string]bool{"aborted": true}
	case "routing-reset", "routing-restore-backup":
		result, err = c.routingOverlaySwap(r.Operation, args)
	case "routing-roscomvpn-import":
		result, err = c.roscomImport(args)
	case "routing-roscomvpn-status":
		result, err = c.roscomStatus()
	default:
		err = fmt.Errorf("unknown operation")
	}
	if err != nil {
		return nil, true, err
	}
	return result, true, nil
}

func (c *Controller) routingOverview() (any, error) {
	mode := c.settings.EffectiveRoutingMode()
	dir, overlayErr, err := c.installedDir()
	if err != nil {
		return nil, err
	}
	info, err := policy.Inspect(dir)
	if err != nil {
		return nil, fmt.Errorf("installed routing policy unreadable: %v", err)
	}
	rulesets := []map[string]any{}
	for _, rs := range info.Rulesets {
		rulesets = append(rulesets, map[string]any{"name": rs.Name, "class": rs.Class, "counts": rs.Counts, "total": rs.Total, "bytes": rs.Bytes, "meta": rs.Meta, "error": rs.Error, "active": policy.ActiveInMode(rs.Name, mode)})
	}
	rules, customErr := c.readCustomRules()
	summary := map[string]int{"total": len(rules.Rules), "enabled": 0, "vpn": 0, "direct": 0}
	for _, rule := range rules.Rules {
		if rule.Enabled {
			summary["enabled"]++
			summary[rule.Mode]++
		}
	}
	c.mu.RLock()
	live := map[string]any{"controller": c.live, "vpn": c.vpnStarted, "applied_mode": c.appliedMode}
	c.mu.RUnlock()
	if !c.routing.lastApply.IsZero() {
		live["last_apply"] = c.routing.lastApply
		live["last_apply_source"] = c.routing.lastSource
	}
	if c.routing.customErr != "" {
		live["custom_rules_error"] = c.routing.customErr
	}
	return map[string]any{
		"mode":            mode,
		"source":          c.sourceName(dir),
		"overlay_present": exists(filepath.Join(c.overlayDir(), "policy.json")),
		"overlay_error":   overlayErr,
		"backup_present":  exists(filepath.Join(c.overlayBackupDir(), "policy.json")),
		"policy":          info.Meta,
		"rulesets":        rulesets,
		"custom_rules":    map[string]any{"summary": summary, "revision": rules.Revision(), "error": errText(customErr)},
		"live":            live,
		"limits":          map[string]int{"max_rules": policy.MaxCustomRules, "max_comment": policy.MaxCustomComment, "chunk_bytes": routingChunkBytes, "max_bundle_bytes": maxRoutingBundle, "page_limit": maxRoutingPage},
	}, nil
}

func pageBounds(args routingArgs) (int, int, string, error) {
	limit := args.Limit
	if limit == 0 {
		limit = 100
	}
	if limit < 1 || limit > maxRoutingPage || args.Offset < 0 || args.Offset > 1<<30 {
		return 0, 0, "", fmt.Errorf("page offset or limit out of range (limit 1-%d)", maxRoutingPage)
	}
	query := strings.ToLower(strings.TrimSpace(args.Query))
	if len(query) > 200 {
		return 0, 0, "", fmt.Errorf("search text too long")
	}
	return int(args.Offset), limit, query, nil
}

func (c *Controller) routingEntries(args routingArgs) (any, error) {
	if !policy.ValidRuleset(args.Ruleset) {
		return nil, fmt.Errorf("unknown ruleset")
	}
	offset, limit, query, err := pageBounds(args)
	if err != nil {
		return nil, err
	}
	dir, _, err := c.installedDir()
	if err != nil {
		return nil, err
	}
	entries, err := policy.RulesetEntries(dir, args.Ruleset)
	if err != nil {
		return nil, fmt.Errorf("ruleset unreadable: %v", err)
	}
	matched := entries
	if query != "" {
		matched = nil
		for _, entry := range entries {
			if strings.Contains(strings.ToLower(entry.Value), query) {
				matched = append(matched, entry)
			}
		}
	}
	page := []policy.Entry{}
	if offset < len(matched) {
		page = matched[offset:min(offset+limit, len(matched))]
	}
	return map[string]any{"ruleset": args.Ruleset, "source": c.sourceName(dir), "total": len(entries), "matched": len(matched), "offset": offset, "entries": page}, nil
}

// routingBase is the installed policy for annotations: the running base when
// the controller runs, otherwise the policy on disk.
func (c *Controller) routingBase() *policy.Policy {
	if c.basePolicy != nil {
		return c.basePolicy
	}
	p, _, _, e := policy.LoadInstalledAt(c.overlayDir(), routingImageDir)
	if e != nil {
		return nil
	}
	return p
}

// ruleIsLocal reports a custom rule that local destinations shadow wholly
// or partly; local destinations always stay local.
func ruleIsLocal(base *policy.Policy, rule policy.CustomRule) bool {
	if base == nil {
		return false
	}
	if rule.Type == policy.RuleDomain {
		class, _ := base.DomainDecision(rule.Value)
		return class == policy.Local
	}
	for _, p := range rule.Prefixes() {
		for _, local := range base.CIDRs("local-ips") {
			if p.Overlaps(local) {
				return true
			}
		}
	}
	return false
}

func (c *Controller) routingRules(args routingArgs) (any, error) {
	offset, limit, query, err := pageBounds(args)
	if err != nil {
		return nil, err
	}
	rules, readErr := c.readCustomRules()
	base := c.routingBase()
	type listed struct {
		policy.CustomRule
		Local bool `json:"local,omitempty"`
	}
	var matched []policy.CustomRule
	for _, rule := range rules.Rules {
		if query == "" || strings.Contains(rule.Value, query) || strings.Contains(strings.ToLower(rule.Comment), query) {
			matched = append(matched, rule)
		}
	}
	page := []listed{}
	for i := offset; i < len(matched) && i < offset+limit; i++ {
		page = append(page, listed{matched[i], ruleIsLocal(base, matched[i])})
	}
	return map[string]any{"revision": rules.Revision(), "total": len(rules.Rules), "matched": len(matched), "offset": offset, "rules": page, "error": errText(readErr)}, nil
}

func (c *Controller) routingRuleEdit(op string, args routingArgs) (any, error) {
	rules, err := c.readCustomRules()
	if err != nil {
		return nil, fmt.Errorf("%v; replace the file with a custom rules import", err)
	}
	if args.Revision != rules.Revision() {
		return nil, fmt.Errorf("routing rules changed; refresh before repeating the action")
	}
	var saved *policy.CustomRule
	switch op {
	case "routing-rule-add":
		if args.Rule == nil || args.ID != "" {
			return nil, fmt.Errorf("a new rule is required")
		}
		rule := *args.Rule
		if e := rule.Normalize(netip.Prefix{}); e != nil {
			return nil, e
		}
		rule.ID = rules.NewRuleID(rule)
		rules.Rules = append(rules.Rules, rule)
	case "routing-rule-update":
		i := rules.Find(args.ID)
		if !ruleIDArgRE.MatchString(args.ID) || i < 0 || args.Rule == nil {
			return nil, fmt.Errorf("rule not found")
		}
		rule := *args.Rule
		rule.ID = args.ID
		rules.Rules[i] = rule
	case "routing-rule-delete":
		i := rules.Find(args.ID)
		if !ruleIDArgRE.MatchString(args.ID) || i < 0 || args.Rule != nil {
			return nil, fmt.Errorf("rule not found")
		}
		rules.Rules = append(rules.Rules[:i], rules.Rules[i+1:]...)
	}
	if e := c.normalizeCustomRules(rules); e != nil {
		return nil, e
	}
	if op != "routing-rule-delete" {
		id := args.ID
		if op == "routing-rule-add" {
			id = rules.Rules[len(rules.Rules)-1].ID
		}
		if i := rules.Find(id); i >= 0 {
			saved = &rules.Rules[i]
		}
	}
	if e := c.writeCustomRules(rules); e != nil {
		return nil, e
	}
	apply, e := c.applyRouting()
	if e != nil {
		return nil, fmt.Errorf("rules saved, but not applied: %v", e)
	}
	return map[string]any{"revision": rules.Revision(), "rule": saved, "total": len(rules.Rules), "apply": apply}, nil
}

// routingFingerprint changes whenever a file the export reads changes.
func (c *Controller) routingFingerprint() string {
	h := sha256.New()
	paths := []string{c.customRulesPath()}
	for _, dir := range []string{c.overlayDir(), routingImageDir} {
		paths = append(paths, filepath.Join(dir, "policy.json"))
		for _, name := range policy.RulesetNames() {
			paths = append(paths, filepath.Join(dir, "rulesets", name+".json"))
		}
	}
	for _, path := range paths {
		if info, e := os.Lstat(path); e == nil {
			fmt.Fprintf(h, "%s|%d|%d|%v\n", path, info.Size(), info.ModTime().UnixNano(), info.Mode())
		} else {
			fmt.Fprintf(h, "%s|missing\n", path)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// routingBundleBytes builds the export of the effective configuration: the
// installed policy in use (overlay or image) and the custom rules.
func (c *Controller) routingBundleBytes() ([]byte, string, string, error) {
	key := c.routingFingerprint()
	if key == c.routing.exportKey && c.routing.exportData != nil {
		return c.routing.exportData, c.routing.exportSum, c.routing.exportSource, nil
	}
	dir, _, err := c.installedDir()
	if err != nil {
		return nil, "", "", err
	}
	rules, err := c.readCustomRules()
	if err != nil {
		return nil, "", "", err
	}
	bundle := routingBundle{Format: routingBundleFormat, Version: routingBundleVersion, Source: c.sourceName(dir), Rulesets: map[string]json.RawMessage{}, CustomRules: rules}
	read := func(path string) (json.RawMessage, error) {
		info, e := os.Lstat(path)
		if e != nil || !info.Mode().IsRegular() || info.Size() > policy.MaxPolicyFileBytes {
			return nil, fmt.Errorf("%s unreadable", filepath.Base(path))
		}
		raw, e := os.ReadFile(path)
		if e != nil || !json.Valid(raw) {
			return nil, fmt.Errorf("%s unreadable", filepath.Base(path))
		}
		return raw, nil
	}
	if bundle.Policy, err = read(filepath.Join(dir, "policy.json")); err != nil {
		return nil, "", "", err
	}
	for _, name := range policy.RulesetNames() {
		if bundle.Rulesets[name], err = read(filepath.Join(dir, "rulesets", name+".json")); err != nil {
			return nil, "", "", err
		}
	}
	data, err := json.MarshalIndent(bundle, "", " ")
	if err != nil {
		return nil, "", "", err
	}
	data = append(data, '\n')
	if len(data) > maxRoutingBundle {
		return nil, "", "", fmt.Errorf("routing configuration exceeds the %d byte bundle limit", maxRoutingBundle)
	}
	sum := sha256.Sum256(data)
	c.routing.exportKey, c.routing.exportData, c.routing.exportSum, c.routing.exportSource = key, data, hex.EncodeToString(sum[:]), bundle.Source
	return data, c.routing.exportSum, bundle.Source, nil
}

func (c *Controller) routingExport(args routingArgs) (any, error) {
	if args.SHA256 != "" && !sha256RE.MatchString(args.SHA256) {
		return nil, fmt.Errorf("invalid export checksum")
	}
	data, sum, source, err := c.routingBundleBytes()
	if err != nil {
		return nil, err
	}
	if args.SHA256 != "" && args.SHA256 != sum {
		return nil, fmt.Errorf("routing configuration changed during export; start the export again")
	}
	if args.Offset < 0 || args.Offset > int64(len(data)) || args.Offset > 0 && args.SHA256 == "" {
		return nil, fmt.Errorf("export offset out of range")
	}
	end := min(int(args.Offset)+routingChunkBytes, len(data))
	chunk := data[args.Offset:end]
	return map[string]any{"format": routingBundleFormat, "source": source, "size": len(data), "sha256": sum, "offset": args.Offset, "next": end, "more": end < len(data), "data": base64.StdEncoding.EncodeToString(chunk), "filename": "flr-routing.json"}, nil
}

func stagingPaths(id string) (string, string) {
	return filepath.Join(routingStagingRoot, id+".json"), filepath.Join(routingStagingRoot, id+".part")
}

func removeStaging(id string) {
	meta, part := stagingPaths(id)
	os.Remove(meta)
	os.Remove(part)
}

// prepareStagingRoot keeps a private staging directory and drops anything
// left in it: one import is staged at a time.
func prepareStagingRoot() error {
	if info, e := os.Lstat(routingStagingRoot); e == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
		return fmt.Errorf("import staging path unusable")
	}
	if e := os.MkdirAll(routingStagingRoot, 0700); e != nil {
		return fmt.Errorf("import staging unavailable")
	}
	// The directory must be ours: a directory another user created could
	// let that user read or swap the staged file.
	for _, dir := range []string{filepath.Dir(routingStagingRoot), routingStagingRoot} {
		info, e := os.Lstat(dir)
		if e != nil || !info.IsDir() {
			return fmt.Errorf("import staging path unusable")
		}
		if st, ok := info.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Geteuid() {
			return fmt.Errorf("import staging path unusable")
		}
	}
	if e := os.Chmod(routingStagingRoot, 0700); e != nil {
		return fmt.Errorf("import staging unavailable")
	}
	entries, _ := os.ReadDir(routingStagingRoot)
	for _, entry := range entries {
		os.RemoveAll(filepath.Join(routingStagingRoot, entry.Name()))
	}
	return nil
}

func (c *Controller) routingImportBegin(args routingArgs) (any, error) {
	if args.Size < 1 || args.Size > maxRoutingBundle {
		return nil, fmt.Errorf("import size must be 1 to %d bytes", maxRoutingBundle)
	}
	if !sha256RE.MatchString(args.SHA256) {
		return nil, fmt.Errorf("import needs the SHA-256 of the file")
	}
	if e := prepareStagingRoot(); e != nil {
		return nil, e
	}
	var random [8]byte
	if _, e := rand.Read(random[:]); e != nil {
		return nil, fmt.Errorf("import staging unavailable")
	}
	id := hex.EncodeToString(random[:])
	metaPath, partPath := stagingPaths(id)
	meta, _ := json.Marshal(stagingMeta{Size: args.Size, SHA256: args.SHA256, Created: time.Now().UTC()})
	if e := privatefile.Write(metaPath, meta); e != nil {
		return nil, fmt.Errorf("import staging unavailable")
	}
	f, e := os.OpenFile(partPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		removeStaging(id)
		return nil, fmt.Errorf("import staging unavailable")
	}
	f.Close()
	return map[string]any{"staging_id": id, "size": args.Size, "chunk_bytes": routingChunkBytes}, nil
}

// staged returns the metadata and current size of a staged import.
func staged(id string) (stagingMeta, int64, error) {
	var meta stagingMeta
	if !stagingIDRE.MatchString(id) {
		return meta, 0, fmt.Errorf("invalid staging ID")
	}
	metaPath, partPath := stagingPaths(id)
	raw, e := privatefile.Read(metaPath, 4096)
	if e != nil || json.Unmarshal(raw, &meta) != nil {
		return meta, 0, fmt.Errorf("import not found; start it again")
	}
	if time.Since(meta.Created) > routingStagingTTL {
		removeStaging(id)
		return meta, 0, fmt.Errorf("import expired; start it again")
	}
	info, e := os.Lstat(partPath)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return meta, 0, fmt.Errorf("import not found; start it again")
	}
	return meta, info.Size(), nil
}

func (c *Controller) routingImportChunk(args routingArgs) (any, error) {
	meta, size, err := staged(args.Staging)
	if err != nil {
		return nil, err
	}
	if args.Offset != size {
		return nil, fmt.Errorf("chunk out of order: the router holds %d bytes", size)
	}
	data, err := base64.StdEncoding.DecodeString(args.Data)
	if err != nil || len(data) == 0 || len(data) > routingChunkBytes {
		return nil, fmt.Errorf("chunk must be base64 of 1 to %d bytes", routingChunkBytes)
	}
	if size+int64(len(data)) > meta.Size {
		return nil, fmt.Errorf("chunk exceeds the announced import size")
	}
	_, partPath := stagingPaths(args.Staging)
	f, err := os.OpenFile(partPath, os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("import staging unavailable")
	}
	_, err = f.Write(data)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		removeStaging(args.Staging)
		return nil, fmt.Errorf("import staging write failed; start it again")
	}
	return map[string]any{"received": size + int64(len(data)), "size": meta.Size}, nil
}

// parseRoutingImport accepts a routing bundle or a bare custom rules file.
func parseRoutingImport(raw []byte) (*routingBundle, error) {
	var head struct {
		Format string `json:"format"`
	}
	if json.Unmarshal(raw, &head) != nil {
		return nil, fmt.Errorf("import is not a valid JSON object")
	}
	var b routingBundle
	switch head.Format {
	case routingBundleFormat:
		if e := decodeRoutingJSON(raw, &b); e != nil {
			return nil, fmt.Errorf("routing bundle rejected: %v", e)
		}
		if b.Version != routingBundleVersion {
			return nil, fmt.Errorf("unsupported routing bundle version")
		}
	case policy.CustomRulesFormat:
		var rules policy.CustomRules
		if e := decodeRoutingJSON(raw, &rules); e != nil {
			return nil, fmt.Errorf("custom rules rejected: %v", e)
		}
		b = routingBundle{Format: routingBundleFormat, Version: routingBundleVersion, CustomRules: &rules}
	default:
		return nil, fmt.Errorf("unknown import format; expected %s or %s", routingBundleFormat, policy.CustomRulesFormat)
	}
	if len(b.Policy) == 0 && len(b.Rulesets) > 0 {
		return nil, fmt.Errorf("rulesets need their policy.json")
	}
	if len(b.Policy) > 0 {
		if !bytes.HasPrefix(bytes.TrimSpace(b.Policy), []byte("{")) {
			return nil, fmt.Errorf("policy must be an object")
		}
		if len(b.Rulesets) != len(policy.RulesetNames()) {
			return nil, fmt.Errorf("a policy needs exactly the rulesets %s", strings.Join(policy.RulesetNames(), ", "))
		}
		for _, name := range policy.RulesetNames() {
			raw, ok := b.Rulesets[name]
			if !ok || !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
				return nil, fmt.Errorf("ruleset %s missing or not an object", name)
			}
		}
	}
	if len(b.Policy) == 0 && b.CustomRules == nil {
		return nil, fmt.Errorf("import holds neither a policy nor custom rules")
	}
	return &b, nil
}

// stageOverlay writes a candidate overlay next to the live one and loads it
// with the controller's own loader.
func (c *Controller) stageOverlay(b *routingBundle) (string, error) {
	leftovers, _ := filepath.Glob(filepath.Join(c.stateDir, ".policy-import-*"))
	for _, path := range leftovers {
		os.RemoveAll(path)
	}
	dir, err := os.MkdirTemp(c.stateDir, ".policy-import-")
	if err != nil {
		return "", fmt.Errorf("cannot stage the policy overlay")
	}
	write := func(path string, raw json.RawMessage) error {
		var out bytes.Buffer
		if e := json.Indent(&out, raw, "", "  "); e != nil {
			return e
		}
		out.WriteByte('\n')
		return privatefile.Write(path, out.Bytes())
	}
	err = write(filepath.Join(dir, "policy.json"), b.Policy)
	for _, name := range policy.RulesetNames() {
		if err == nil {
			err = write(filepath.Join(dir, "rulesets", name+".json"), b.Rulesets[name])
		}
	}
	if err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("cannot stage the policy overlay: %v", err)
	}
	if _, err = policy.Load(dir); err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("policy rejected: %v", err)
	}
	return dir, nil
}

// installOverlay replaces the overlay with candidate and keeps the previous
// overlay as the backup. It returns an undo function for a later failure.
func (c *Controller) installOverlay(candidate string) (func(), func(), error) {
	overlay, backup := c.overlayDir(), c.overlayBackupDir()
	for _, path := range []string{overlay, backup} {
		if e := privatefile.SafePath(path); e != nil {
			return nil, nil, e
		}
	}
	had := exists(overlay)
	// The old backup is set aside, not deleted, until the whole import has
	// succeeded (keep), so a failed import loses no recovery point.
	old := backup + ".old"
	hadBackup := false
	if had {
		if e := os.RemoveAll(old); e != nil {
			return nil, nil, fmt.Errorf("cannot replace the overlay backup")
		}
		if exists(backup) {
			if e := os.Rename(backup, old); e != nil {
				return nil, nil, fmt.Errorf("cannot replace the overlay backup")
			}
			hadBackup = true
		}
		if e := os.Rename(overlay, backup); e != nil {
			if hadBackup {
				os.Rename(old, backup)
			}
			return nil, nil, fmt.Errorf("cannot keep the previous overlay as a backup")
		}
	}
	if e := os.Rename(candidate, overlay); e != nil {
		if had {
			os.Rename(backup, overlay)
			if hadBackup {
				os.Rename(old, backup)
			}
		}
		return nil, nil, fmt.Errorf("cannot install the policy overlay")
	}
	privatefile.SyncDir(c.stateDir)
	undo := func() {
		os.RemoveAll(overlay)
		if had {
			os.Rename(backup, overlay)
			if hadBackup {
				os.Rename(old, backup)
			}
		}
		privatefile.SyncDir(c.stateDir)
	}
	keep := func() {
		os.RemoveAll(old)
		privatefile.SyncDir(c.stateDir)
	}
	return undo, keep, nil
}

func (c *Controller) routingImportCommit(args routingArgs) (any, error) {
	meta, size, err := staged(args.Staging)
	if err != nil {
		return nil, err
	}
	defer removeStaging(args.Staging)
	if size != meta.Size {
		return nil, fmt.Errorf("import incomplete: %d of %d bytes received", size, meta.Size)
	}
	_, partPath := stagingPaths(args.Staging)
	raw, err := privatefile.Read(partPath, maxRoutingBundle)
	if err != nil {
		return nil, fmt.Errorf("import staging unreadable")
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != meta.SHA256 {
		return nil, fmt.Errorf("import checksum mismatch; start it again")
	}
	bundle, err := parseRoutingImport(raw)
	if err != nil {
		return nil, err
	}
	// Validate everything before anything changes.
	if bundle.CustomRules != nil {
		if err = c.normalizeCustomRules(bundle.CustomRules); err != nil {
			return nil, fmt.Errorf("custom rules rejected: %v", err)
		}
	}
	candidate := ""
	if len(bundle.Policy) > 0 {
		if candidate, err = c.stageOverlay(bundle); err != nil {
			return nil, err
		}
		defer os.RemoveAll(candidate)
	}
	imported := map[string]any{"policy": candidate != ""}
	if candidate != "" {
		undo, keep, e := c.installOverlay(candidate)
		if e != nil {
			return nil, e
		}
		if bundle.CustomRules != nil {
			if e = c.writeCustomRules(bundle.CustomRules); e != nil {
				undo()
				return nil, e
			}
		}
		keep()
	} else if err = c.writeCustomRules(bundle.CustomRules); err != nil {
		return nil, err
	}
	if bundle.CustomRules != nil {
		imported["custom_rules"] = len(bundle.CustomRules.Rules)
	}
	apply, err := c.applyRouting()
	if err != nil {
		return nil, fmt.Errorf("import saved, but not applied: %v", err)
	}
	return map[string]any{"imported": imported, "apply": apply}, nil
}

// routingOverlaySwap removes the overlay (reset: the image default applies,
// the overlay becomes the backup) or brings the backup back (restore: the
// current overlay, if any, becomes the backup).
func (c *Controller) routingOverlaySwap(op string, args routingArgs) (any, error) {
	if !args.Accepted {
		return nil, fmt.Errorf("explicit confirmation required")
	}
	overlay, backup := c.overlayDir(), c.overlayBackupDir()
	for _, path := range []string{overlay, backup} {
		if e := privatefile.SafePath(path); e != nil {
			return nil, e
		}
	}
	if op == "routing-reset" {
		if !exists(overlay) {
			return nil, fmt.Errorf("no private policy overlay is installed")
		}
		if e := os.RemoveAll(backup); e != nil {
			return nil, fmt.Errorf("cannot replace the overlay backup")
		}
		if e := os.Rename(overlay, backup); e != nil {
			return nil, fmt.Errorf("cannot move the overlay to the backup")
		}
	} else {
		if !exists(backup) {
			return nil, fmt.Errorf("no overlay backup exists")
		}
		if _, e := policy.Load(backup); e != nil {
			return nil, fmt.Errorf("overlay backup rejected: %v", e)
		}
		if exists(overlay) {
			swap, e := os.MkdirTemp(c.stateDir, ".policy-swap-")
			if e != nil {
				return nil, fmt.Errorf("cannot restore the overlay backup")
			}
			os.Remove(swap)
			if e = os.Rename(overlay, swap); e != nil {
				return nil, fmt.Errorf("cannot restore the overlay backup")
			}
			if e = os.Rename(backup, overlay); e != nil {
				os.Rename(swap, overlay)
				return nil, fmt.Errorf("cannot restore the overlay backup")
			}
			if e = os.Rename(swap, backup); e != nil {
				return nil, fmt.Errorf("overlay restored, but the replaced overlay stays in %s", filepath.Base(swap))
			}
		} else if e := os.Rename(backup, overlay); e != nil {
			return nil, fmt.Errorf("cannot restore the overlay backup")
		}
	}
	privatefile.SyncDir(c.stateDir)
	apply, err := c.applyRouting()
	if err != nil {
		return nil, fmt.Errorf("overlay changed, but not applied: %v", err)
	}
	return map[string]any{"apply": apply, "backup_present": exists(backup)}, nil
}
