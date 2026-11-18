package engineupdate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const LockFormat = "flr-compat-lock-v1"

// Installed describes a binary: current and last_good entries.
type Installed struct {
	Version     string `json:"version"`
	SHA256      string `json:"sha256"`
	InstalledAt string `json:"installed_at"`
}

// Candidate is a version under evaluation. Stage is informational.
type Candidate struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Stage   string `json:"stage"`
}

// Blocked is a permanently rejected version.
type Blocked struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Reason  string `json:"reason"`
	At      string `json:"at"`
}

// EngineLock is the per-engine record.
type EngineLock struct {
	Current   Installed  `json:"current"`
	LastGood  *Installed `json:"last_good"`
	Candidate *Candidate `json:"candidate"`
	Blocked   []Blocked  `json:"blocked"`
	Hold      bool       `json:"hold"`
}

// Lock is /etc/flr-runtime/engines.lock.json.
type Lock struct {
	Format  string                 `json:"format"`
	Engines map[string]*EngineLock `json:"engines"`
}

func NewLock() *Lock { return &Lock{Format: LockFormat, Engines: map[string]*EngineLock{}} }

// LoadLock reads the lock; a missing file yields an empty lock.
func LoadLock(path string) (*Lock, error) {
	raw, err := readBounded(path, 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return NewLock(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("engine lock unreadable: %w", err)
	}
	var l Lock
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&l); err != nil {
		return nil, fmt.Errorf("engine lock rejected: %v", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, errors.New("engine lock has trailing data")
	}
	if l.Format != LockFormat {
		return nil, errors.New("engine lock format rejected")
	}
	if l.Engines == nil {
		l.Engines = map[string]*EngineLock{}
	}
	for name, e := range l.Engines {
		if e == nil || !enginePattern.MatchString(name) {
			return nil, errors.New("engine lock entry rejected")
		}
		if e.Blocked == nil {
			e.Blocked = []Blocked{}
		}
	}
	return &l, nil
}

// Save writes atomically (tmp, fsync, rename, fsync dir) with mode 0600.
func (l *Lock) Save(path string) error {
	raw, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, append(raw, '\n'), 0600)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(name)
		}
	}()
	if err = tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// IsBlocked reports whether version (or sha) is on the blocked list.
func (e *EngineLock) IsBlocked(version, sha string) *Blocked {
	for i := range e.Blocked {
		if e.Blocked[i].Version == version || (sha != "" && e.Blocked[i].SHA256 == sha) {
			return &e.Blocked[i]
		}
	}
	return nil
}

// Block records a permanent rejection (idempotent per version+sha).
func (e *EngineLock) Block(version, sha, reason string, at time.Time) {
	for _, b := range e.Blocked {
		if b.Version == version && b.SHA256 == sha {
			return
		}
	}
	if len(reason) > 512 {
		reason = reason[:512]
	}
	e.Blocked = append(e.Blocked, Blocked{Version: version, SHA256: sha, Reason: reason, At: ts(at)})
	e.Candidate = nil
}

// Unblock removes every entry for version; reports whether anything changed.
func (e *EngineLock) Unblock(version string) bool {
	kept := e.Blocked[:0:0]
	for _, b := range e.Blocked {
		if b.Version != version {
			kept = append(kept, b)
		}
	}
	changed := len(kept) != len(e.Blocked)
	e.Blocked = kept
	return changed
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339) }
