package engineupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Env holds filesystem locations so tests can use temp dirs.
type Env struct {
	BinDir    string // /usr/bin
	ConfigDir string // /etc/flr-runtime
	TmpDir    string // existing parent for private per-cycle staging
	RunDir    string // /var/run/flr-runtime (flock file)
	// ELF checks a candidate binary; nil means CheckELF.
	ELF func(path string) error
}

func DefaultEnv() Env {
	return Env{BinDir: "/usr/bin", ConfigDir: "/etc/flr-runtime", TmpDir: "/tmp", RunDir: "/var/run/flr-runtime"}
}
func (e Env) ConfigPath() string { return filepath.Join(e.ConfigDir, "engine-update.json") }
func (e Env) LockPath() string   { return filepath.Join(e.ConfigDir, "engines.lock.json") }
func (e Env) BinPath(engine string) string {
	return filepath.Join(e.BinDir, engine)
}
func (e Env) LastGoodPath(engine string) string { return e.BinPath(engine) + ".last-good" }
func (e Env) flockPath() string                 { return filepath.Join(e.RunDir, "engine-update.lock") }

// ErrBusy means another run holds the lock.
var ErrBusy = errors.New("another engine update operation is running")

// Updater runs update cycles and owner operations.
type Updater struct {
	Cfg     Config
	Env     Env
	Fetcher Fetcher
	Exec    Exec
	Canary  Canary
	Scope   Scope
	Now     func() time.Time
	Logf    func(format string, args ...any)
}

// Report is the outcome of one cycle (no secrets).
type Report struct {
	Mode    string                   `json:"mode"`
	At      string                   `json:"at"`
	Skipped string                   `json:"skipped,omitempty"`
	Engines map[string]*EngineReport `json:"engines"`
}

// EngineReport describes one engine. Action: none, skipped, blocked,
// inconclusive, would-promote, promoted, error.
type EngineReport struct {
	Current     string       `json:"current,omitempty"`
	Candidate   string       `json:"candidate,omitempty"`
	Action      string       `json:"action"`
	Reason      string       `json:"reason,omitempty"`
	Connections []ConnReport `json:"connections,omitempty"`
}

type ConnReport struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Result string `json:"result"`
}

// Rejected reports whether any engine's candidate was blocked.
func (r *Report) Rejected() bool {
	for _, e := range r.Engines {
		if e.Action == "blocked" {
			return true
		}
	}
	return false
}

func (u *Updater) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now()
}
func (u *Updater) logf(f string, a ...any) {
	if u.Logf != nil {
		u.Logf(f, a...)
	}
}
func (u *Updater) elf(p string) error {
	if u.Env.ELF != nil {
		return u.Env.ELF(p)
	}
	return CheckELF(p)
}

// acquire takes the exclusive non-blocking flock shared by every operation.
func (u *Updater) acquire() (func(), error) {
	if err := os.MkdirAll(u.Env.RunDir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(u.Env.flockPath(), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, ErrBusy
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

func (u *Updater) installedNow(ctx context.Context, engine string) (Installed, error) {
	bin := u.Env.BinPath(engine)
	v, err := BinaryVersion(ctx, u.Exec, bin)
	if err != nil {
		return Installed{}, err
	}
	sha, err := FileSHA256(bin)
	if err != nil {
		return Installed{}, err
	}
	return Installed{Version: v, SHA256: sha}, nil
}

// reconcile makes lock.current follow the installed binary. It returns true
// when the lock changed.
func (u *Updater) reconcile(ctx context.Context, l *Lock, engine string) (bool, error) {
	inst, err := u.installedNow(ctx, engine)
	if err != nil {
		return false, fmt.Errorf("installed %s unreadable: %v", engine, err)
	}
	now := ts(u.now())
	e := l.Engines[engine]
	if e == nil {
		l.Engines[engine] = &EngineLock{Current: Installed{inst.Version, inst.SHA256, now}, Blocked: []Blocked{}}
		return true, nil
	}
	if e.Current.SHA256 == inst.SHA256 && e.Current.Version == inst.Version {
		return false, nil
	}
	old := e.Current
	promotedByUs := e.Candidate != nil && e.Candidate.SHA256 == inst.SHA256
	e.Current = Installed{inst.Version, inst.SHA256, now}
	e.Candidate = nil
	lg, err := FileSHA256(u.Env.LastGoodPath(engine))
	switch {
	case promotedByUs && err == nil && lg == old.SHA256:
		e.LastGood = &Installed{old.Version, old.SHA256, old.InstalledAt}
	case e.LastGood != nil && err == nil && lg == e.LastGood.SHA256:
		// still valid after an image change
	default:
		e.LastGood = nil
	}
	u.logf("engine %s: lock current reconciled to installed %s", engine, inst.Version)
	return true, nil
}

// Cycle performs one update cycle in the given mode ("check" or "apply").
func (u *Updater) Cycle(ctx context.Context, mode string) (*Report, error) {
	if mode != ModeCheck && mode != ModeApply {
		return nil, errors.New("invalid mode")
	}
	unlock, err := u.acquire()
	if err != nil {
		return nil, err
	}
	defer unlock()
	rep := &Report{Mode: mode, At: ts(u.now()), Engines: map[string]*EngineReport{}}
	lock, err := LoadLock(u.Env.LockPath())
	if err != nil {
		return rep, err
	}
	dirty := false
	active := []string{}
	for _, name := range u.Cfg.Engines {
		er := &EngineReport{}
		rep.Engines[name] = er
		changed, err := u.reconcile(ctx, lock, name)
		if err != nil {
			er.Action, er.Reason = "error", err.Error()
			continue
		}
		dirty = dirty || changed
		el := lock.Engines[name]
		er.Current = el.Current.Version
		if el.Hold {
			er.Action, er.Reason = "skipped", "hold"
			continue
		}
		active = append(active, name)
	}
	if dirty {
		if err = lock.Save(u.Env.LockPath()); err != nil {
			return rep, fmt.Errorf("cannot save engine lock: %v", err)
		}
	}
	if len(active) == 0 {
		return rep, nil
	}
	stageDir, err := os.MkdirTemp(u.Env.TmpDir, "flr-engine-")
	if err != nil {
		return rep, err
	}
	defer os.RemoveAll(stageDir)

	ch, err := u.fetchChannel(ctx)
	if errors.Is(err, ErrNoRoute) {
		rep.Skipped = "no healthy tunnel route"
		return rep, nil
	}
	if err != nil {
		return rep, err
	}
	for _, name := range active {
		er := rep.Engines[name]
		u.updateEngine(ctx, mode, lock, name, stageDir, ch, er)
	}
	return rep, nil
}

func (u *Updater) fetchChannel(ctx context.Context) (*Channel, error) {
	fctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var buf limitedBuffer
	buf.limit = MaxChannelBytes + 1
	if err := u.Fetcher.Fetch(fctx, u.Cfg.ChannelURL, &buf, MaxChannelBytes); err != nil {
		return nil, fmt.Errorf("channel fetch failed: %w", err)
	}
	raw := buf.buf.Bytes()
	if u.Cfg.PublicKey != "" {
		pub, err := u.Cfg.PublicKeyBytes()
		if err != nil {
			return nil, err
		}
		var sig limitedBuffer
		sig.limit = 4096
		if err = u.Fetcher.Fetch(fctx, u.Cfg.ChannelURL+".sig", &sig, 4096); err != nil {
			return nil, fmt.Errorf("channel signature fetch failed: %w", err)
		}
		if err = VerifySignature(pub, raw, sig.buf.Bytes()); err != nil {
			return nil, err
		}
	} else if u.Cfg.RequireSignature {
		return nil, errors.New("signature required but no public key configured")
	}
	return ParseChannel(raw)
}

func (u *Updater) setAction(er *EngineReport, action, reason string) {
	er.Action, er.Reason = action, reason
}

// block records a failure in apply mode and reports it in both modes.
func (u *Updater) block(mode string, l *Lock, engine string, e ChannelEngine, er *EngineReport, reason string) {
	u.setAction(er, "blocked", reason)
	u.logf("engine %s %s rejected: %s", engine, e.Version, reason)
	if mode != ModeApply {
		return
	}
	l.Engines[engine].Block(e.Version, e.SHA256, reason, u.now())
	if err := l.Save(u.Env.LockPath()); err != nil {
		er.Reason += " (lock save failed: " + err.Error() + ")"
	}
}

func (u *Updater) setStage(mode string, l *Lock, engine string, e ChannelEngine, stage string) {
	if mode != ModeApply {
		return
	}
	l.Engines[engine].Candidate = &Candidate{Version: e.Version, SHA256: e.SHA256, Stage: stage}
	if err := l.Save(u.Env.LockPath()); err != nil {
		u.logf("lock stage save failed: %v", err)
	}
}

func (u *Updater) updateEngine(ctx context.Context, mode string, l *Lock, engine, stageDir string, ch *Channel, er *EngineReport) {
	el := l.Engines[engine]
	entry, ok := ch.Engines[engine]
	if !ok {
		u.setAction(er, "none", "engine not in channel")
		return
	}
	er.Candidate = entry.Version
	switch {
	case entry.SHA256 == el.Current.SHA256 || entry.Version == el.Current.Version:
		u.setAction(er, "none", "up to date")
		return
	case versionOlder(entry.Version, el.Current.Version):
		u.setAction(er, "none", "channel version is older than current")
		return
	}
	if b := el.IsBlocked(entry.Version, entry.SHA256); b != nil {
		u.setAction(er, "skipped", "blocked: "+b.Reason)
		return
	}
	soak := time.Duration(u.Cfg.SoakHours) * time.Hour
	if age := u.now().Sub(ch.PublishedTime()); age < soak {
		u.setAction(er, "skipped", fmt.Sprintf("soak: %s remaining", (soak-age).Round(time.Minute)))
		return
	}
	defer func() {
		if mode == ModeApply && er.Action == "inconclusive" && el.Candidate != nil {
			el.Candidate = nil
			if err := l.Save(u.Env.LockPath()); err != nil {
				er.Action, er.Reason = "error", "cannot clear candidate stage: "+err.Error()
			}
		}
	}()
	targets, err := u.scoped(ctx, engine)
	if err != nil {
		u.setAction(er, "inconclusive", "scope: "+err.Error())
		return
	}
	if len(targets) == 0 && !u.Cfg.UpdateUnused {
		u.setAction(er, "skipped", "no connection uses this engine in scope")
		return
	}
	// Prepare every scoped config before drawing any conclusion about the binary.
	cfgs := make([]string, len(targets))
	for i, t := range targets {
		if t.ConfigError != nil {
			u.setAction(er, "inconclusive", fmt.Sprintf("scope: %s: %v", label(t), t.ConfigError))
			return
		}
		raw, err := TransformConfig(t.Config, u.Cfg.CanaryPort)
		if err != nil {
			u.setAction(er, "inconclusive", fmt.Sprintf("canary config for %s: %v", label(t), err))
			return
		}
		dir := filepath.Join(stageDir, fmt.Sprintf("%s-canary-%d", engine, i))
		if err := os.Mkdir(dir, 0700); err != nil {
			u.setAction(er, "error", err.Error())
			return
		}
		cfgs[i] = filepath.Join(dir, "canary.json")
		if err := writeCanaryConfig(cfgs[i], raw); err != nil {
			u.setAction(er, "error", err.Error())
			return
		}
	}

	current := u.Env.BinPath(engine)
	curCaps, ok := BinaryCapabilities(ctx, u.Exec, current)
	if !ok {
		u.setAction(er, "inconclusive", "cannot determine installed capabilities")
		return
	}
	cand := filepath.Join(stageDir, engine+".candidate")
	if err = u.download(ctx, entry, cand); err != nil {
		u.setAction(er, "error", "download: "+err.Error())
		return
	}
	u.setStage(mode, l, engine, entry, "downloaded")
	// Static checks.
	if err = u.elf(cand); err != nil {
		u.block(mode, l, engine, entry, er, "elf: "+err.Error())
		return
	}
	if v, err := BinaryVersion(ctx, u.Exec, cand); err != nil {
		if interrupted(ctx, err) {
			u.setAction(er, "inconclusive", "version: "+err.Error())
			return
		}
		u.block(mode, l, engine, entry, er, "version: "+err.Error())
		return
	} else if v != entry.Version {
		u.block(mode, l, engine, entry, er, fmt.Sprintf("version: candidate reports %q, manifest says %q", v, entry.Version))
		return
	}
	candCaps, err := readCapabilities(ctx, u.Exec, cand)
	if interrupted(ctx, err) {
		u.setAction(er, "inconclusive", "cannot determine candidate capabilities")
		return
	}
	if m := MissingCapabilities(candCaps, append(append([]string{}, curCaps...), entry.Capabilities...)); len(m) > 0 {
		u.block(mode, l, engine, entry, er, "capabilities: candidate lacks "+strings.Join(m, ","))
		return
	}
	if err != nil {
		u.setAction(er, "inconclusive", "cannot determine candidate capabilities")
		return
	}
	u.setStage(mode, l, engine, entry, "static")
	for i, t := range targets {
		result := compareCandidate(ctx, cand, current, func(bin string) CanaryResult {
			_, err := u.Exec.Run(ctx, bin, "check", "-c", cfgs[i])
			if err != nil {
				return CanaryResult{Probe: "check -c", Detail: err.Error(), Inconclusive: interrupted(ctx, err)}
			}
			return CanaryResult{OK: true}
		})
		if !result.OK {
			reason := fmt.Sprintf("check -c: %s: %s", label(t), result.Detail)
			if result.Inconclusive {
				u.setAction(er, "inconclusive", reason)
			} else {
				u.block(mode, l, engine, entry, er, reason)
			}
			return
		}
	}
	u.setStage(mode, l, engine, entry, "canary")
	params := CanaryParams{Port: u.Cfg.CanaryPort, Seconds: u.Cfg.CanarySeconds, MinBytes: u.Cfg.CanaryMinBytes}
	for i, t := range targets {
		result := compareCandidate(ctx, cand, current, func(bin string) CanaryResult {
			return u.Canary.Run(ctx, bin, t, cfgs[i], params)
		})
		if result.OK {
			er.Connections = append(er.Connections, ConnReport{t.ID, t.Name, "pass"})
			continue
		}
		reason := fmt.Sprintf("canary: %s: %s: %s", label(t), result.Probe, result.Detail)
		if result.Inconclusive {
			er.Connections = append(er.Connections, ConnReport{t.ID, t.Name, "inconclusive: " + result.Probe})
			u.setAction(er, "inconclusive", reason)
		} else {
			er.Connections = append(er.Connections, ConnReport{t.ID, t.Name, "fail: " + result.Probe})
			u.block(mode, l, engine, entry, er, reason)
		}
		return
	}
	if err := ctx.Err(); err != nil {
		u.setAction(er, "inconclusive", err.Error())
		return
	}
	if mode != ModeApply {
		u.setAction(er, "would-promote", fmt.Sprintf("all %d scoped connection(s) passed", len(targets)))
		return
	}
	if err = u.promote(l, engine, entry, cand); err != nil {
		u.setAction(er, "error", "promote: "+err.Error())
		return
	}
	u.setAction(er, "promoted", fmt.Sprintf("all %d scoped connection(s) passed", len(targets)))
}

// A permanent rejection needs two measured failures separated by a successful
// control on the same config. Mixed candidate results defer the whole cycle.
func compareCandidate(ctx context.Context, candidate, current string, run func(string) CanaryResult) CanaryResult {
	attempt := func(bin string) CanaryResult {
		var r CanaryResult
		if ctx.Err() == nil {
			r = run(bin)
		}
		if err := ctx.Err(); err != nil {
			return CanaryResult{Probe: r.Probe, Detail: err.Error(), Inconclusive: true}
		}
		return r
	}
	first := attempt(candidate)
	if first.OK || first.Inconclusive {
		return first
	}
	if control := attempt(current); !control.OK {
		first.Inconclusive = true
		first.Detail += " (current binary: " + control.Detail + ")"
		return first
	}
	retry := attempt(candidate)
	if retry.OK {
		first.Inconclusive = true
		first.Detail += " (candidate passed on retry)"
		return first
	}
	return retry
}

func writeCanaryConfig(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}

func label(t Target) string { return fmt.Sprintf("%s (%s)", t.Name, t.ID) }

func (u *Updater) scoped(ctx context.Context, engine string) ([]Target, error) {
	all, err := u.Scope.Connections(ctx, engine)
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, s := range u.Cfg.ScopeServers {
		want[net.ParseIP(s).String()] = true
	}
	var out []Target
	for _, t := range all {
		ip := net.ParseIP(t.Server).To4()
		if ip == nil {
			return nil, fmt.Errorf("cannot determine IPv4 bearer for %s", label(t))
		}
		if len(want) == 0 || want[ip.String()] {
			out = append(out, t)
		}
	}
	return out, nil
}

func (u *Updater) download(ctx context.Context, e ChannelEngine, dst string) error {
	if _, err := fetchURL(u.Cfg.ChannelURL, e.URL, nil); err != nil {
		return err
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0700)
	if err != nil {
		return err
	}
	h := sha256.New()
	dctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	if err := u.Fetcher.Fetch(dctx, e.URL, io.MultiWriter(f, h), e.Size); err != nil {
		f.Close()
		return err
	}
	st, err := f.Stat()
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if st.Size() != e.Size {
		return fmt.Errorf("size mismatch: got %d, manifest %d", st.Size(), e.Size)
	}
	if hex.EncodeToString(h.Sum(nil)) != e.SHA256 {
		return errors.New("sha256 mismatch against manifest")
	}
	return nil
}

// promote swaps the binary atomically. The running engine keeps its old inode.
func (u *Updater) promote(l *Lock, engine string, e ChannelEngine, cand string) error {
	el := l.Engines[engine]
	bin := u.Env.BinPath(engine)
	if err := installFile(bin, filepath.Join(u.Env.BinDir, "."+engine+".last-good.new"), u.Env.LastGoodPath(engine)); err != nil {
		return fmt.Errorf("cannot save last-good: %v", err)
	}
	old := el.Current
	el.Candidate = &Candidate{Version: e.Version, SHA256: e.SHA256, Stage: "promoting"}
	if err := l.Save(u.Env.LockPath()); err != nil {
		return err
	}
	if err := installFile(cand, filepath.Join(u.Env.BinDir, "."+engine+".new"), bin); err != nil {
		return fmt.Errorf("cannot install candidate: %v", err)
	}
	el.LastGood = &Installed{old.Version, old.SHA256, old.InstalledAt}
	el.Current = Installed{e.Version, e.SHA256, ts(u.now())}
	el.Candidate = nil
	return l.Save(u.Env.LockPath())
}
