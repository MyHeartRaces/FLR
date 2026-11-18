package engineupdate

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"path/filepath"
	"time"
)

// StatusReport is the JSON printed by `engine status`. It contains no
// secrets: no token path, no public key, no query string of the channel URL.
type StatusReport struct {
	Configured bool                    `json:"configured"`
	Enabled    bool                    `json:"enabled"`
	Mode       string                  `json:"mode,omitempty"`
	Channel    string                  `json:"channel,omitempty"`
	Signature  string                  `json:"signature,omitempty"`
	Engines    map[string]EngineStatus `json:"engines"`
}

type EngineStatus struct {
	Installed *Installed  `json:"installed,omitempty"`
	Error     string      `json:"error,omitempty"`
	Lock      *EngineLock `json:"lock,omitempty"`
}

// Status reads (never writes) lock and installed binaries.
func (u *Updater) Status(ctx context.Context, configured bool) (*StatusReport, error) {
	l, err := LoadLock(u.Env.LockPath())
	if err != nil {
		return nil, err
	}
	r := &StatusReport{Configured: configured, Enabled: u.Cfg.Enabled, Mode: u.Cfg.Mode, Engines: map[string]EngineStatus{}}
	if u.Cfg.ChannelURL != "" {
		if cu, err := url.Parse(u.Cfg.ChannelURL); err == nil {
			r.Channel = cu.Scheme + "://" + cu.Host + cu.Path
		}
	}
	switch {
	case u.Cfg.RequireSignature:
		r.Signature = "required"
	case u.Cfg.PublicKey != "":
		r.Signature = "verified-when-present"
	default:
		r.Signature = "off"
	}
	names := map[string]bool{}
	for _, n := range u.Cfg.Engines {
		names[n] = true
	}
	for n := range l.Engines {
		names[n] = true
	}
	for n := range names {
		st := EngineStatus{Lock: l.Engines[n]}
		if inst, err := u.installedNow(ctx, n); err != nil {
			st.Error = err.Error()
		} else {
			inst.InstalledAt = ""
			st.Installed = &inst
		}
		r.Engines[n] = st
	}
	return r, nil
}

func (u *Updater) mutate(engine string, f func(*EngineLock) error) error {
	if !enginePattern.MatchString(engine) {
		return errors.New("invalid engine name")
	}
	unlock, err := u.acquire()
	if err != nil {
		return err
	}
	defer unlock()
	l, err := LoadLock(u.Env.LockPath())
	if err != nil {
		return err
	}
	e := l.Engines[engine]
	if e == nil {
		return fmt.Errorf("engine %s is not in the lock; run a cycle first", engine)
	}
	if err = f(e); err != nil {
		return err
	}
	return l.Save(u.Env.LockPath())
}

// SetHold freezes or releases an engine.
func (u *Updater) SetHold(engine string, hold bool) error {
	return u.mutate(engine, func(e *EngineLock) error { e.Hold = hold; return nil })
}

// Unblock is the owner's override of a blocked version.
func (u *Updater) Unblock(engine, version string) error {
	return u.mutate(engine, func(e *EngineLock) error {
		if !e.Unblock(version) {
			return fmt.Errorf("version %s is not blocked", version)
		}
		return nil
	})
}

// Rollback restores the last-good binary. The version rolled back from is
// blocked so the next cycle does not reinstall it. Running engines are not
// touched; they keep their inode.
func (u *Updater) Rollback(engine string) error {
	return u.mutate(engine, func(e *EngineLock) error {
		if e.LastGood == nil {
			return errors.New("no last_good recorded")
		}
		lg := u.Env.LastGoodPath(engine)
		sha, err := FileSHA256(lg)
		if err != nil || sha != e.LastGood.SHA256 {
			return errors.New("last-good binary missing or does not match the lock")
		}
		bin := u.Env.BinPath(engine)
		if err = installFile(lg, filepath.Join(u.Env.BinDir, "."+engine+".new"), bin); err != nil {
			return fmt.Errorf("cannot restore last-good: %v", err)
		}
		e.Block(e.Current.Version, e.Current.SHA256, "manual rollback", u.now())
		e.Current = Installed{e.LastGood.Version, e.LastGood.SHA256, ts(u.now())}
		e.LastGood, e.Candidate = nil, nil
		return nil
	})
}

// Loop runs cycles until ctx ends: first after 10 minutes, then every
// interval_hours +-10%. Returns nil immediately when disabled or absent.
// The config is re-read before every cycle.
func (u *Updater) Loop(ctx context.Context, load func() (Config, error), build func(Config) *Updater) error {
	cfg, err := load()
	if errors.Is(err, ErrNoConfig) || (err == nil && !cfg.Enabled) {
		return nil
	}
	wait := 10 * time.Minute
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		cfg, err = load()
		if err != nil {
			if errors.Is(err, ErrNoConfig) {
				return nil
			}
			u.logf("engine update config error: %v", err)
		} else if !cfg.Enabled {
			return nil
		} else {
			up := build(cfg)
			rep, cerr := up.Cycle(ctx, cfg.Mode)
			if cerr != nil {
				u.logf("engine update cycle: %v", cerr)
			} else {
				for n, e := range rep.Engines {
					u.logf("engine %s: %s %s", n, e.Action, e.Reason)
				}
			}
		}
		hours := 24
		if err == nil {
			hours = cfg.IntervalHours
		}
		wait = Jitter(time.Duration(hours)*time.Hour, rand.Float64())
	}
}

// Jitter scales d by 0.9 + 0.2*r (r in [0,1)).
func Jitter(d time.Duration, r float64) time.Duration {
	return time.Duration(float64(d) * (0.9 + 0.2*r))
}
