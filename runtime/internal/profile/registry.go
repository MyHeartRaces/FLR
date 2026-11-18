package profile

import (
	"encoding/json"
	"fmt"
	"github.com/MyHeartRaces/FLR/runtime/internal/validation"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Registry struct {
	Version     int       `json:"version"`
	FamilyOrder []string  `json:"family_order,omitempty"`
	Profiles    []Profile `json:"profiles"`
}

// ValidateStored validates a private payload including its derived identity.
func ValidateStored(p Profile) error {
	return validateRegistry(&Registry{Version: 1, Profiles: []Profile{p}})
}

func Load(path string) (*Registry, error) {
	if path == "" {
		path = DefaultPath
	}
	if e := safePath(path); e != nil {
		return nil, e
	}
	f, e := os.Open(path)
	if os.IsNotExist(e) {
		return &Registry{Version: 1, Profiles: []Profile{}}, nil
	}
	if e != nil {
		return nil, fmt.Errorf("cannot open private profile registry")
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		return nil, fmt.Errorf("registry must be a regular 0600 file")
	}
	ds, e := os.Stat(filepath.Dir(path))
	if e != nil || ds.Mode().Perm() != 0700 {
		return nil, fmt.Errorf("registry directory must be 0700")
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(MaxImportBytes*MaxProfiles)+1))
	if e != nil || len(b) > MaxImportBytes*MaxProfiles {
		return nil, fmt.Errorf("registry exceeds size bound")
	}
	var r Registry
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if e = d.Decode(&r); e != nil {
		return nil, fmt.Errorf("invalid private profile registry")
	}
	if e = d.Decode(new(any)); e != io.EOF {
		return nil, fmt.Errorf("trailing registry data")
	}
	if e = validateRegistry(&r); e != nil {
		return nil, e
	}
	return &r, nil
}

// Save validates the complete registry before atomically replacing its private file.
func (r *Registry) Save(path string) error {
	if e := validateRegistry(r); e != nil {
		return e
	}
	if path == "" {
		path = DefaultPath
	}
	if e := safePath(path); e != nil {
		return e
	}
	b, e := json.Marshal(r)
	if e != nil || len(b) > MaxImportBytes*MaxProfiles {
		return fmt.Errorf("registry exceeds size bound")
	}
	dir := filepath.Dir(path)
	if e = os.MkdirAll(dir, 0700); e != nil {
		return fmt.Errorf("cannot create private registry directory")
	}
	if e = os.Chmod(dir, 0700); e != nil {
		return fmt.Errorf("cannot protect registry directory")
	}
	f, e := os.CreateTemp(dir, ".profiles-")
	if e != nil {
		return fmt.Errorf("cannot create private registry temporary file")
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
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return fmt.Errorf("cannot write private registry")
	}
	if e = os.Rename(tmp, path); e != nil {
		return fmt.Errorf("cannot replace private registry")
	}
	d, e := os.Open(dir)
	if e != nil {
		return fmt.Errorf("cannot sync registry directory")
	}
	defer d.Close()
	if e = d.Sync(); e != nil {
		return fmt.Errorf("cannot sync registry directory")
	}
	return nil
}

func safePath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("registry path must be clean and absolute")
	}
	for p := path; ; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		if e != nil && !os.IsNotExist(e) {
			return fmt.Errorf("cannot inspect registry path")
		}
		if e == nil && st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("registry path cannot contain symlinks")
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	return nil
}

func validateRegistry(r *Registry) error {
	if r == nil || r.Version != 1 || len(r.Profiles) > MaxProfiles {
		return fmt.Errorf("invalid registry version or profile count")
	}
	seen := map[string]bool{}
	families := map[string]bool{"reality": true, "vless": true, "ss2022": true, "wgws": true}
	for _, family := range r.FamilyOrder {
		if !families[family] {
			return fmt.Errorf("invalid or duplicate family order")
		}
		delete(families, family)
	}
	for _, p := range r.Profiles {
		if !idPattern.MatchString(p.ID) || seen[p.ID] {
			return fmt.Errorf("invalid or duplicate profile ID")
		}
		seen[p.ID] = true
		if ValidateGroup(p.ServerGroup) != nil {
			return fmt.Errorf("invalid server group")
		}
		if ValidatePriority(p.Priority) != nil {
			return fmt.Errorf("priority out of range")
		}
		if e := validateProfile(p); e != nil {
			return e
		}
		canonical, e := finish(p)
		if e != nil || canonical.ID != p.ID {
			return fmt.Errorf("profile content identity mismatch")
		}
		if p.Name != canonical.Name || p.Engine != canonical.Engine || p.Family != canonical.Family {
			return fmt.Errorf("invalid derived profile metadata")
		}
		b, _ := json.Marshal(p.Capabilities)
		c, _ := json.Marshal(canonical.Capabilities)
		if string(b) != string(c) {
			return fmt.Errorf("invalid capability metadata")
		}
	}
	return nil
}

// Import is an in-memory all-or-nothing transaction. The caller calls Save only
// after any engine validation, and publishes the registry only after Save succeeds.
func (r *Registry) Import(data []byte) ([]Summary, error) {
	parsed, e := Parse(data)
	if e != nil {
		return nil, e
	}
	if r.Version != 1 || len(r.Profiles)+len(parsed) > MaxProfiles {
		return nil, fmt.Errorf("registry profile limit exceeded")
	}
	seen := map[string]bool{}
	for _, p := range r.Profiles {
		seen[p.ID] = true
	}
	for index, p := range parsed {
		if seen[p.ID] {
			return nil, validation.At(fmt.Errorf("duplicate profile identity"), index+1)
		}
		seen[p.ID] = true
	}
	next := append(append([]Profile{}, r.Profiles...), parsed...)
	candidate := &Registry{Version: 1, FamilyOrder: r.FamilyOrder, Profiles: next}
	if e = validateRegistry(candidate); e != nil {
		return nil, e
	}
	r.Profiles = next
	summaries := make([]Summary, 0, len(parsed))
	for _, p := range parsed {
		summaries = append(summaries, p.Summary())
	}
	return summaries, nil
}
func (r *Registry) Summaries() []Summary {
	result := make([]Summary, 0, len(r.Profiles))
	for _, p := range r.Profiles {
		result = append(result, p.Summary())
	}
	return result
}
func (r *Registry) SetEnabled(id string, enabled bool) error {
	for i := range r.Profiles {
		p := &r.Profiles[i]
		if p.ID == id {
			p.UserDisabled = !enabled
			p.Enabled = enabled && p.DisabledReason == ""
			return nil
		}
	}
	return fmt.Errorf("profile not found")
}
func (r *Registry) Delete(id string) error {
	for i, p := range r.Profiles {
		if p.ID == id {
			r.Profiles = append(r.Profiles[:i], r.Profiles[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("profile not found")
}
func (r *Registry) ApplyAvailability(available map[string]bool) {
	for i := range r.Profiles {
		p := &r.Profiles[i]
		wasMissing := strings.HasPrefix(p.DisabledReason, "missing-component:")
		if p.DisabledReason != "" && !wasMissing {
			p.Enabled = false
			continue
		}
		p.DisabledReason = ""
		for _, component := range p.Capabilities.RequiredComponents {
			if !available[component] {
				p.DisabledReason = "missing-component:" + component
				break
			}
		}
		if p.DisabledReason != "" {
			p.Enabled = false
		} else if wasMissing && !p.UserDisabled {
			p.Enabled = true
		}
		if p.UserDisabled {
			p.Enabled = false
		}
	}
}
