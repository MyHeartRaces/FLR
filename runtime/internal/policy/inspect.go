package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"unicode/utf8"
)

// Read-only views of an installed policy directory for the routing API. They
// read the files as they are on disk; Load stays the only loader that decides
// whether a directory is usable.

// MaxPolicyFileBytes bounds one policy or ruleset file read for inspection.
const MaxPolicyFileBytes = 16 << 20

// Matchers is the fixed order of ruleset matcher kinds.
var Matchers = []string{"domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr"}

// RulesetNames are the rulesets every policy directory holds, in load order.
func RulesetNames() []string { return append([]string(nil), sources...) }

// ValidRuleset reports whether name is one of RulesetNames.
func ValidRuleset(name string) bool {
	for _, s := range sources {
		if s == name {
			return true
		}
	}
	return false
}

// SourceClass is the traffic class a ruleset assigns.
func SourceClass(source string) Class {
	switch source {
	case "local-domains", "local-ips":
		return Local
	case "direct-essential", "roscom-direct-domains", "roscom-direct-ips", CustomDirectSource:
		return Direct
	case "game-platforms":
		return Games
	}
	return General
}

// ActiveInMode reports whether a routing mode uses a source.
func ActiveInMode(source, mode string) bool {
	if mode == ModeDirect {
		return false
	}
	for _, off := range modeOff(mode) {
		if off == source {
			return false
		}
	}
	return true
}

// LoadInstalledAt is LoadInstalled for explicit overlay and image directories.
func LoadInstalledAt(overlay, image string) (p *Policy, dir string, overlayErr error, err error) {
	return loadInstalled(overlay, image)
}

type RulesetInfo struct {
	Name   string         `json:"name"`
	Class  Class          `json:"class"`
	Counts map[string]int `json:"counts"`
	Total  int            `json:"total"`
	Bytes  int64          `json:"bytes"`
	// Meta holds short top-level text fields of the file besides version
	// and rules (for example a source note), if any.
	Meta  map[string]string `json:"meta,omitempty"`
	Error string            `json:"error,omitempty"`
}

type DirInfo struct {
	Meta     map[string]any `json:"policy"`
	Rulesets []RulesetInfo  `json:"rulesets"`
}

func readBounded(path string) ([]byte, int64, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return nil, 0, e
	}
	if !info.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("not a regular file")
	}
	if info.Size() > MaxPolicyFileBytes {
		return nil, info.Size(), fmt.Errorf("file larger than %d bytes", MaxPolicyFileBytes)
	}
	b, e := os.ReadFile(path)
	return b, info.Size(), e
}

func shortText(raw json.RawMessage) (string, bool) {
	var s string
	if json.Unmarshal(raw, &s) != nil || !utf8.ValidString(s) {
		return "", false
	}
	if utf8.RuneCountInString(s) > 300 {
		s = string([]rune(s)[:300]) + "…"
	}
	return s, true
}

// Inspect summarizes a policy directory: the policy.json fields and, per
// ruleset, its class and entry counts per matcher kind. A broken ruleset is
// reported in its own entry rather than failing the summary.
func Inspect(dir string) (DirInfo, error) {
	out := DirInfo{Meta: map[string]any{}}
	b, _, e := readBounded(filepath.Join(dir, "policy.json"))
	if e != nil {
		return out, fmt.Errorf("policy.json: %w", e)
	}
	var meta map[string]json.RawMessage
	if e = json.Unmarshal(b, &meta); e != nil {
		return out, fmt.Errorf("policy.json: invalid JSON")
	}
	for key, raw := range meta {
		if len(out.Meta) >= 16 || len(key) > 64 {
			break
		}
		if s, ok := shortText(raw); ok {
			out.Meta[key] = s
			continue
		}
		var n json.Number
		if json.Unmarshal(raw, &n) == nil {
			out.Meta[key] = n
		}
	}
	for _, name := range sources {
		info := RulesetInfo{Name: name, Class: SourceClass(name), Counts: map[string]int{}}
		entries, size, meta, e := readRuleset(dir, name)
		info.Bytes = size
		if e != nil {
			info.Error = e.Error()
		}
		for _, entry := range entries {
			info.Counts[entry.Kind]++
		}
		info.Total = len(entries)
		if len(meta) > 0 {
			info.Meta = meta
		}
		out.Rulesets = append(out.Rulesets, info)
	}
	return out, nil
}

// Entry is one matcher value of a ruleset.
type Entry struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

func knownMatcher(kind string) bool {
	for _, m := range Matchers {
		if m == kind {
			return true
		}
	}
	return false
}

// RulesetEntries lists the entries of one ruleset: rules in file order, and
// within a rule its matcher kinds in Matchers order.
func RulesetEntries(dir, name string) ([]Entry, error) {
	if !ValidRuleset(name) {
		return nil, fmt.Errorf("unknown ruleset")
	}
	entries, _, _, e := readRuleset(dir, name)
	return entries, e
}

func readRuleset(dir, name string) ([]Entry, int64, map[string]string, error) {
	b, size, e := readBounded(filepath.Join(dir, "rulesets", name+".json"))
	if e != nil {
		return nil, size, nil, e
	}
	var top map[string]json.RawMessage
	if e = json.Unmarshal(b, &top); e != nil {
		return nil, size, nil, fmt.Errorf("invalid JSON")
	}
	meta := map[string]string{}
	for key, raw := range top {
		if key == "version" || key == "rules" || len(meta) >= 8 || len(key) > 64 {
			continue
		}
		if s, ok := shortText(raw); ok {
			meta[key] = s
		}
	}
	var rules []map[string]json.RawMessage
	if raw, ok := top["rules"]; ok {
		if e = json.Unmarshal(raw, &rules); e != nil {
			return nil, size, meta, fmt.Errorf("invalid rules")
		}
	}
	var entries []Entry
	for _, rule := range rules {
		for _, kind := range Matchers {
			raw, ok := rule[kind]
			if !ok {
				continue
			}
			var values []string
			if e = json.Unmarshal(raw, &values); e != nil {
				return entries, size, meta, fmt.Errorf("%s: invalid values", kind)
			}
			for _, v := range values {
				entries = append(entries, Entry{Kind: kind, Value: v})
			}
		}
		for kind := range rule {
			if !knownMatcher(kind) {
				return entries, size, meta, fmt.Errorf("unsupported matcher %s", short(kind))
			}
		}
	}
	return entries, size, meta, nil
}
