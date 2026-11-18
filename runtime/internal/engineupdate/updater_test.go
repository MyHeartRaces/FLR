package engineupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

const cap1 = "hysteria2-random-sni-per-quic-dial-v1"

func fakeBin(t *testing.T, path, version string, caps []string, checkOK bool) []byte {
	t.Helper()
	if caps == nil {
		caps = []string{}
	}
	capsJSON, _ := json.Marshal(map[string]any{"version": 1, "capabilities": caps})
	check := "exit 0"
	if !checkOK {
		check = "echo 'bad option' >&2; exit 1"
	}
	body := fmt.Sprintf("#!/bin/sh\ncase \"$1\" in\nversion) echo 'sing-box version %s'; echo; echo 'Environment: go'; exit 0;;\nflr-capabilities) echo '%s'; exit 0;;\ncheck) %s;;\nrun) exec sleep 30;;\nesac\nexit 0\n# pad %s\n", version, capsJSON, check, strings.Repeat("x", 1100))
	if err := os.WriteFile(path, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	return []byte(body)
}

type fakeFetcher struct {
	files map[string][]byte
	err   error
	calls []string
}

func (f *fakeFetcher) Fetch(_ context.Context, u string, w io.Writer, limit int64) error {
	f.calls = append(f.calls, u)
	if f.err != nil {
		return f.err
	}
	b, ok := f.files[u]
	if !ok {
		return errors.New("404")
	}
	if int64(len(b)) > limit {
		return ErrTooLarge
	}
	_, err := w.Write(b)
	return err
}

type fakeScope struct{ targets []Target }

func (s fakeScope) Connections(context.Context, string) ([]Target, error) { return s.targets, nil }

type fakeCanary struct {
	fn    func(bin string, t Target) CanaryResult
	calls []string
}

func (c *fakeCanary) Run(_ context.Context, bin string, tg Target, cfg string, _ CanaryParams) CanaryResult {
	c.calls = append(c.calls, tg.ID+"@"+filepath.Base(bin))
	if _, err := os.Stat(cfg); err != nil {
		return CanaryResult{Probe: "cfg", Detail: "config missing"}
	}
	if c.fn != nil {
		return c.fn(bin, tg)
	}
	return CanaryResult{OK: true}
}

type rig struct {
	t       *testing.T
	env     Env
	u       *Updater
	fetch   *fakeFetcher
	canary  *fakeCanary
	candSHA string
	manif   []byte
	now     time.Time
}

const chanURL = "https://example.test/channel.json"
const binURL = "https://example.test/sing-box-2"

var prodCfg = []byte(`{"log":{"level":"info"},"inbounds":[{"type":"tun","tag":"lan-tun"},{"type":"socks","tag":"health","listen":"127.0.0.1","listen_port":1081}],"outbounds":[{"type":"hysteria2","tag":"proxy","server":"203.0.113.5","server_port":443,"routing_mark":2147483648,"bind_interface":"eth1"}],"route":{"final":"proxy"}}`)

func manifestFor(version string, bin []byte, caps []string, published time.Time) []byte {
	sum := sha256.Sum256(bin)
	m := map[string]any{"format": ChannelFormat, "channel": "stable", "generated_at": ts(published), "published_at": ts(published),
		"source_commit": strings.Repeat("a", 40),
		"engines": map[string]any{"sing-box": map[string]any{"version": version, "package_version": "1.14.4.1", "asset": "sing-box-" + version + "-linux-arm64",
			"url": binURL, "sha256": hex.EncodeToString(sum[:]), "size": len(bin), "capabilities": caps, "min_controller": "0.7", "contract_sha256": strings.Repeat("c", 64)}}}
	b, _ := json.Marshal(m)
	return b
}

// newRig installs current 1.14.4-flr-random-sni.1 and offers candidate .2.
func newRig(t *testing.T, mutate func(r *rig)) *rig {
	dir := t.TempDir()
	r := &rig{t: t, now: t0}
	r.env = Env{BinDir: filepath.Join(dir, "usr/bin"), ConfigDir: filepath.Join(dir, "etc/flr-runtime"), TmpDir: t.TempDir(), RunDir: filepath.Join(dir, "run"), ELF: func(string) error { return nil }}
	os.MkdirAll(r.env.BinDir, 0755)
	os.MkdirAll(r.env.ConfigDir, 0700)
	fakeBin(t, r.env.BinPath("sing-box"), "1.14.4-flr-random-sni.1", []string{cap1}, true)
	candPath := filepath.Join(dir, "cand")
	cand := fakeBin(t, candPath, "1.14.4-flr-random-sni.2", []string{cap1}, true)
	sum := sha256.Sum256(cand)
	r.candSHA = hex.EncodeToString(sum[:])
	r.manif = manifestFor("1.14.4-flr-random-sni.2", cand, []string{cap1}, t0.Add(-100*time.Hour))
	r.fetch = &fakeFetcher{files: map[string][]byte{binURL: cand}}
	r.canary = &fakeCanary{}
	cfg := DefaultConfig()
	cfg.Enabled, cfg.Mode, cfg.ChannelURL = true, ModeApply, chanURL
	r.u = &Updater{Cfg: cfg, Env: r.env, Fetcher: r.fetch, Exec: OSExec{}, Canary: r.canary,
		Scope: fakeScope{[]Target{{ID: "conn-a", Name: "Main Hysteria2", Server: "203.0.113.5", UDP: true, Config: prodCfg}}},
		Now:   func() time.Time { return r.now }}
	if mutate != nil {
		mutate(r)
	}
	r.fetch.files[chanURL] = r.manif
	return r
}

func (r *rig) cycle(mode string) *Report {
	r.t.Helper()
	rep, err := r.u.Cycle(context.Background(), mode)
	if err != nil {
		r.t.Fatalf("cycle: %v", err)
	}
	return rep
}
func (r *rig) lock() *EngineLock {
	r.t.Helper()
	l, err := LoadLock(r.env.LockPath())
	if err != nil {
		r.t.Fatal(err)
	}
	return l.Engines["sing-box"]
}
func (r *rig) binSHA() string {
	s, err := FileSHA256(r.env.BinPath("sing-box"))
	if err != nil {
		r.t.Fatal(err)
	}
	return s
}

func TestApplyPromotesAtomicallyAndKeepsLastGood(t *testing.T) {
	r := newRig(t, nil)
	before := r.binSHA()
	inode := func() uint64 { return inodeOf(t, r.env.BinPath("sing-box")) }
	oldInode := inode()
	rep := r.cycle(ModeApply)
	e := rep.Engines["sing-box"]
	if e.Action != "promoted" {
		t.Fatalf("action %s %s", e.Action, e.Reason)
	}
	if r.binSHA() != r.candSHA {
		t.Fatal("binary not replaced")
	}
	if inode() == oldInode {
		t.Fatal("binary rewritten in place: running engine would be disturbed")
	}
	if lg, _ := FileSHA256(r.env.LastGoodPath("sing-box")); lg != before {
		t.Fatal("last-good file wrong")
	}
	if _, err := os.Stat(filepath.Join(r.env.BinDir, ".sing-box.new")); err == nil {
		t.Fatal("temporary file left behind")
	}
	l := r.lock()
	if l.Current.Version != "1.14.4-flr-random-sni.2" || l.Current.SHA256 != r.candSHA || l.LastGood == nil || l.LastGood.SHA256 != before || l.Candidate != nil {
		t.Fatalf("lock %+v", l)
	}
	if len(r.canary.calls) != 1 || r.canary.calls[0] != "conn-a@sing-box.candidate" {
		t.Fatalf("canary calls %v", r.canary.calls)
	}
	// Next cycle: up to date.
	if got := r.cycle(ModeApply).Engines["sing-box"].Action; got != "none" {
		t.Fatalf("second cycle %s", got)
	}
}

func TestCheckModeChangesNothing(t *testing.T) {
	r := newRig(t, nil)
	r.cycle(ModeCheck) // first run records the reconciled lock
	lockBefore, _ := os.ReadFile(r.env.LockPath())
	binBefore := r.binSHA()
	rep := r.cycle(ModeCheck)
	if a := rep.Engines["sing-box"].Action; a != "would-promote" {
		t.Fatalf("action %s", a)
	}
	lockAfter, _ := os.ReadFile(r.env.LockPath())
	if string(lockBefore) != string(lockAfter) || r.binSHA() != binBefore {
		t.Fatal("check mode modified state")
	}
	if _, err := os.Stat(r.env.LastGoodPath("sing-box")); err == nil {
		t.Fatal("last-good created in check mode")
	}
	if entries, err := os.ReadDir(r.env.TmpDir); err != nil || len(entries) != 0 {
		t.Fatalf("staging parent after cleanup: %v, %v", entries, err)
	}
}

func TestCheckModeReportsFailureWithoutBlocking(t *testing.T) {
	r := newRig(t, func(r *rig) { r.canary.fn = failFor("conn-a@sing-box.candidate") })
	rep := r.cycle(ModeCheck)
	if rep.Engines["sing-box"].Action != "blocked" || !rep.Rejected() {
		t.Fatalf("%+v", rep.Engines["sing-box"])
	}
	if len(r.lock().Blocked) != 0 {
		t.Fatal("check mode wrote the block list")
	}
}

func failFor(id string) func(string, Target) CanaryResult {
	return func(bin string, tg Target) CanaryResult {
		if tg.ID+"@"+filepath.Base(bin) == id {
			return CanaryResult{Probe: "https", Detail: "0/8388608 bytes: short body"}
		}
		return CanaryResult{OK: true}
	}
}

func TestCanaryFailureBlocksWithPreciseReason(t *testing.T) {
	r := newRig(t, func(r *rig) { r.canary.fn = failFor("conn-a@sing-box.candidate") })
	rep := r.cycle(ModeApply)
	e := rep.Engines["sing-box"]
	want := "canary: Main Hysteria2 (conn-a): https: 0/8388608 bytes: short body"
	if e.Action != "blocked" || e.Reason != want {
		t.Fatalf("%s %q", e.Action, e.Reason)
	}
	l := r.lock()
	if len(l.Blocked) != 1 || l.Blocked[0].Version != "1.14.4-flr-random-sni.2" || l.Blocked[0].Reason != want || l.Candidate != nil {
		t.Fatalf("%+v", l)
	}
	if r.binSHA() == r.candSHA {
		t.Fatal("blocked candidate was installed")
	}
	// Permanent: never retried, no new download.
	n := len(r.fetch.calls)
	r.canary.calls = nil
	if got := r.cycle(ModeApply).Engines["sing-box"]; got.Action != "skipped" || !strings.HasPrefix(got.Reason, "blocked") {
		t.Fatalf("%+v", got)
	}
	if len(r.canary.calls) != 0 || len(r.fetch.calls) != n+1 { // only channel.json refetched
		t.Fatalf("retried blocked version: %v", r.fetch.calls)
	}
}

func TestInconclusiveWhenCurrentFailsToo(t *testing.T) {
	r := newRig(t, func(r *rig) {
		r.canary.fn = func(string, Target) CanaryResult { return CanaryResult{Probe: "listen", Detail: "VPS down"} }
	})
	e := r.cycle(ModeApply).Engines["sing-box"]
	if e.Action != "inconclusive" || len(r.lock().Blocked) != 0 {
		t.Fatalf("%+v", e)
	}
}

func TestSecondConnectionFailureStopsAndNamesIt(t *testing.T) {
	r := newRig(t, func(r *rig) {
		r.u.Scope = fakeScope{[]Target{{ID: "a", Name: "A", Server: "203.0.113.5", UDP: true, Config: prodCfg}, {ID: "b", Name: "B", Server: "203.0.113.6", UDP: true, Config: prodCfg}}}
		r.canary.fn = failFor("b@sing-box.candidate")
	})
	e := r.cycle(ModeApply).Engines["sing-box"]
	if e.Action != "blocked" || !strings.Contains(e.Reason, "B (b)") || len(e.Connections) != 2 {
		t.Fatalf("%+v", e)
	}
}

func TestSelection(t *testing.T) {
	t.Run("soak", func(t *testing.T) {
		r := newRig(t, func(r *rig) {
			r.manif = manifestFor("1.14.4-flr-random-sni.2", r.fetch.files[binURL], []string{cap1}, t0.Add(-10*time.Hour))
		})
		e := r.cycle(ModeApply).Engines["sing-box"]
		if e.Action != "skipped" || !strings.HasPrefix(e.Reason, "soak") || len(r.fetch.calls) != 1 {
			t.Fatalf("%+v calls=%v", e, r.fetch.calls)
		}
		r.now = t0.Add(63 * time.Hour) // 73 h old
		r.fetch.calls = nil
		if a := r.cycle(ModeApply).Engines["sing-box"].Action; a != "promoted" {
			t.Fatalf("after soak: %s", a)
		}
	})
	t.Run("hold", func(t *testing.T) {
		r := newRig(t, nil)
		r.cycle(ModeCheck)
		if err := r.u.SetHold("sing-box", true); err != nil {
			t.Fatal(err)
		}
		r.fetch.calls = nil
		e := r.cycle(ModeApply).Engines["sing-box"]
		if e.Action != "skipped" || e.Reason != "hold" || len(r.fetch.calls) != 0 {
			t.Fatalf("%+v", e)
		}
		r.u.SetHold("sing-box", false)
		if a := r.cycle(ModeApply).Engines["sing-box"].Action; a != "promoted" {
			t.Fatal(a)
		}
	})
	t.Run("same version", func(t *testing.T) {
		r := newRig(t, nil)
		r.cycle(ModeApply)
		if a := r.cycle(ModeApply).Engines["sing-box"]; a.Action != "none" {
			t.Fatal(a)
		}
	})
	t.Run("older than current", func(t *testing.T) {
		r := newRig(t, func(r *rig) {
			r.manif = manifestFor("1.14.3", r.fetch.files[binURL], []string{cap1}, t0.Add(-1000*time.Hour))
		})
		if e := r.cycle(ModeApply).Engines["sing-box"]; e.Action != "none" || !strings.Contains(e.Reason, "older") {
			t.Fatalf("%+v", e)
		}
	})
	t.Run("no scope", func(t *testing.T) {
		r := newRig(t, func(r *rig) { r.u.Scope = fakeScope{} })
		e := r.cycle(ModeApply).Engines["sing-box"]
		if e.Action != "skipped" || r.binSHA() == r.candSHA {
			t.Fatalf("%+v", e)
		}
		r.u.Cfg.UpdateUnused = true
		if a := r.cycle(ModeApply).Engines["sing-box"].Action; a != "promoted" {
			t.Fatal(a)
		}
	})
	t.Run("scope_servers filter", func(t *testing.T) {
		r := newRig(t, func(r *rig) {
			r.u.Cfg.ScopeServers = []string{"198.51.100.1"}
			r.u.Scope = fakeScope{[]Target{{ID: "a", Name: "A", Server: "203.0.113.5", ConfigError: errors.New("isolated sidecar required")}, {ID: "x", Name: "Main", Server: "198.51.100.1", Config: prodCfg}}}
		})
		r.cycle(ModeApply)
		if len(r.canary.calls) != 1 || !strings.HasPrefix(r.canary.calls[0], "x@") {
			t.Fatalf("%v", r.canary.calls)
		}
	})
}

func TestSHAAndSizeMismatchAreErrorsNotBlocks(t *testing.T) {
	r := newRig(t, nil)
	bad := append([]byte{}, r.fetch.files[binURL]...)
	bad[10] ^= 0xff
	r.fetch.files[binURL] = bad
	e := r.cycle(ModeApply).Engines["sing-box"]
	if e.Action != "error" || !strings.Contains(e.Reason, "sha256") {
		t.Fatalf("%+v", e)
	}
	if len(r.lock().Blocked) != 0 || r.binSHA() == r.candSHA || len(r.canary.calls) != 0 {
		t.Fatal("tampered download advanced")
	}
	r.fetch.files[binURL] = bad[:len(bad)-5]
	if e = r.cycle(ModeApply).Engines["sing-box"]; e.Action != "error" {
		t.Fatalf("%+v", e)
	}
}

func TestCapabilityRegressionRejected(t *testing.T) {
	r := newRig(t, func(r *rig) {
		bin := fakeBin(t, filepath.Join(t.TempDir(), "c"), "1.14.4-flr-random-sni.2", []string{"other"}, true)
		r.fetch.files[binURL] = bin
		r.manif = manifestFor("1.14.4-flr-random-sni.2", bin, []string{"other"}, t0.Add(-100*time.Hour))
	})
	e := r.cycle(ModeApply).Engines["sing-box"]
	if e.Action != "blocked" || !strings.Contains(e.Reason, "capabilities: candidate lacks "+cap1) {
		t.Fatalf("%+v", e)
	}
	if len(r.canary.calls) != 0 {
		t.Fatal("canary ran after static failure")
	}
}

func TestStaticChecks(t *testing.T) {
	t.Run("elf", func(t *testing.T) {
		r := newRig(t, func(r *rig) { r.env.ELF = nil; r.u.Env.ELF = nil })
		e := r.cycle(ModeApply).Engines["sing-box"]
		if e.Action != "blocked" || !strings.HasPrefix(e.Reason, "elf:") {
			t.Fatalf("%+v", e)
		}
	})
	t.Run("version mismatch", func(t *testing.T) {
		r := newRig(t, func(r *rig) {
			bin := fakeBin(t, filepath.Join(t.TempDir(), "c"), "1.14.4-flr-random-sni.20", []string{cap1}, true)
			r.fetch.files[binURL] = bin
			r.manif = manifestFor("1.14.4-flr-random-sni.2", bin, []string{cap1}, t0.Add(-100*time.Hour))
		})
		if e := r.cycle(ModeApply).Engines["sing-box"]; e.Action != "blocked" || !strings.HasPrefix(e.Reason, "version:") {
			t.Fatalf("%+v", e)
		}
	})
	t.Run("check -c rejected", func(t *testing.T) {
		r := newRig(t, func(r *rig) {
			bin := fakeBin(t, filepath.Join(t.TempDir(), "c"), "1.14.4-flr-random-sni.2", []string{cap1}, false)
			r.fetch.files[binURL] = bin
			r.manif = manifestFor("1.14.4-flr-random-sni.2", bin, []string{cap1}, t0.Add(-100*time.Hour))
		})
		e := r.cycle(ModeApply).Engines["sing-box"]
		if e.Action != "blocked" || !strings.Contains(e.Reason, "check -c: Main Hysteria2 (conn-a)") {
			t.Fatalf("%+v", e)
		}
	})
}

func TestReconcileAfterSysupgrade(t *testing.T) {
	r := newRig(t, func(r *rig) { r.u.Cfg.SoakHours = 100000 })
	r.cycle(ModeApply)
	// Block something, then simulate sysupgrade: image ships another binary and
	// /usr/bin loses the last-good file; /etc keeps the lock.
	l, _ := LoadLock(r.env.LockPath())
	l.Engines["sing-box"].Block("1.15.0", strings.Repeat("d", 64), "canary: x", t0)
	l.Engines["sing-box"].LastGood = &Installed{"old", strings.Repeat("e", 64), "x"}
	l.Save(r.env.LockPath())
	fakeBin(t, r.env.BinPath("sing-box"), "1.14.5-flr-random-sni.1", []string{cap1}, true)
	r.cycle(ModeCheck)
	e := r.lock()
	if e.Current.Version != "1.14.5-flr-random-sni.1" || e.Current.SHA256 != r.binSHA() || e.LastGood != nil || len(e.Blocked) != 1 {
		t.Fatalf("%+v", e)
	}
}

func TestRollbackAndUnblock(t *testing.T) {
	r := newRig(t, nil)
	before := r.binSHA()
	r.cycle(ModeApply)
	if err := r.u.Rollback("sing-box"); err != nil {
		t.Fatal(err)
	}
	if r.binSHA() != before {
		t.Fatal("binary not restored")
	}
	l := r.lock()
	if l.Current.SHA256 != before || l.LastGood != nil || len(l.Blocked) != 1 || l.Blocked[0].Reason != "manual rollback" {
		t.Fatalf("%+v", l)
	}
	// Rolled-back version is not reinstalled.
	if a := r.cycle(ModeApply).Engines["sing-box"].Action; a != "skipped" {
		t.Fatal(a)
	}
	if err := r.u.Rollback("sing-box"); err == nil {
		t.Fatal("rollback without last_good accepted")
	}
	if err := r.u.Unblock("sing-box", "nope"); err == nil {
		t.Fatal("unblock of unknown version accepted")
	}
	if err := r.u.Unblock("sing-box", "1.14.4-flr-random-sni.2"); err != nil {
		t.Fatal(err)
	}
	if a := r.cycle(ModeApply).Engines["sing-box"].Action; a != "promoted" {
		t.Fatal(a)
	}
}

func TestRollbackRejectsTamperedLastGood(t *testing.T) {
	r := newRig(t, nil)
	r.cycle(ModeApply)
	os.WriteFile(r.env.LastGoodPath("sing-box"), []byte("tampered"), 0755)
	if err := r.u.Rollback("sing-box"); err == nil {
		t.Fatal("tampered last-good restored")
	}
}

func TestLockFormatAndMode(t *testing.T) {
	r := newRig(t, nil)
	r.cycle(ModeApply)
	st, _ := os.Stat(r.env.LockPath())
	if st.Mode().Perm() != 0600 {
		t.Fatalf("mode %v", st.Mode())
	}
	raw, _ := os.ReadFile(r.env.LockPath())
	var generic map[string]any
	json.Unmarshal(raw, &generic)
	eng := generic["engines"].(map[string]any)["sing-box"].(map[string]any)
	for _, k := range []string{"current", "last_good", "candidate", "blocked", "hold"} {
		if _, ok := eng[k]; !ok {
			t.Fatalf("missing %s in %s", k, raw)
		}
	}
	if generic["format"] != "flr-compat-lock-v1" || eng["candidate"] != nil {
		t.Fatal(string(raw))
	}
	if ents, _ := os.ReadDir(r.env.ConfigDir); len(ents) != 1 {
		t.Fatalf("temp files left: %v", ents)
	}
	os.WriteFile(r.env.LockPath(), []byte(`{"format":"x","engines":{}}`), 0600)
	if _, err := LoadLock(r.env.LockPath()); err == nil {
		t.Fatal("bad format accepted")
	}
	os.WriteFile(r.env.LockPath(), []byte(`{"format":"flr-compat-lock-v1","engines":{},"extra":1}`), 0600)
	if _, err := LoadLock(r.env.LockPath()); err == nil {
		t.Fatal("unknown key accepted")
	}
}

func TestConcurrentRunIsRefused(t *testing.T) {
	r := newRig(t, nil)
	unlock, err := r.u.acquire()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.u.Cycle(context.Background(), ModeApply); !errors.Is(err, ErrBusy) {
		t.Fatalf("got %v", err)
	}
	if err := r.u.SetHold("sing-box", true); !errors.Is(err, ErrBusy) {
		t.Fatalf("got %v", err)
	}
	unlock()
	if _, err := r.u.Cycle(context.Background(), ModeCheck); err != nil {
		t.Fatal(err)
	}
}

func TestNoTunnelSkipsCycle(t *testing.T) {
	r := newRig(t, func(r *rig) { r.fetch.err = ErrNoRoute })
	rep := r.cycle(ModeApply)
	if rep.Skipped == "" || r.binSHA() == r.candSHA {
		t.Fatalf("%+v", rep)
	}
}

func TestSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	var r *rig
	r = newRig(t, func(x *rig) {
		x.u.Cfg.PublicKey = base64.StdEncoding.EncodeToString(pub)
		x.fetch.files[chanURL+".sig"] = nil
	})
	sign := func(msg []byte) []byte {
		return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)) + "\n")
	}
	r.fetch.files[chanURL+".sig"] = sign(r.manif)
	if a := r.cycle(ModeCheck).Engines["sing-box"].Action; a != "would-promote" {
		t.Fatal(a)
	}
	// Signature over different bytes, then missing signature.
	r.fetch.files[chanURL+".sig"] = sign(append([]byte{' '}, r.manif...))
	if _, err := r.u.Cycle(context.Background(), ModeCheck); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("got %v", err)
	}
	delete(r.fetch.files, chanURL+".sig")
	if _, err := r.u.Cycle(context.Background(), ModeCheck); err == nil {
		t.Fatal("missing signature accepted with key configured")
	}
	if err := VerifySignature(pub, []byte("m"), []byte("!!!")); err == nil {
		t.Fatal("garbage signature accepted")
	}
}

func TestStatusHasNoSecrets(t *testing.T) {
	r := newRig(t, func(r *rig) {
		r.u.Cfg.AuthTokenFile = "/etc/secret-token"
		r.u.Cfg.ChannelURL = chanURL + "?token=hunter2"
		r.fetch.files[chanURL+"?token=hunter2"] = r.manif
	})
	r.cycle(ModeCheck)
	s, err := r.u.Status(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(s)
	for _, bad := range []string{"hunter2", "secret-token", "token"} {
		if strings.Contains(string(raw), bad) {
			t.Fatalf("%q leaked: %s", bad, raw)
		}
	}
	if s.Engines["sing-box"].Installed == nil || s.Engines["sing-box"].Lock == nil {
		t.Fatal(string(raw))
	}
}

func TestLoopExitsWhenDisabled(t *testing.T) {
	u := &Updater{}
	err := u.Loop(context.Background(), func() (Config, error) { return DefaultConfig(), nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = u.Loop(context.Background(), func() (Config, error) { return DefaultConfig(), ErrNoConfig }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d := Jitter(100*time.Hour, 0); d != 90*time.Hour {
		t.Fatal(d)
	}
	if d := Jitter(100*time.Hour, 0.999999); d < 109*time.Hour || d > 110*time.Hour {
		t.Fatal(d)
	}
}

func TestVersionOlder(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.14.3", "1.14.4-flr-random-sni.1", true},
		{"1.14.4-flr-random-sni.1", "1.14.4-flr-random-sni.2", true},
		{"1.14.4-flr-random-sni.2", "1.14.4-flr-random-sni.1", false},
		{"1.15.0-flr-random-sni.1", "1.14.4-flr-random-sni.9", false},
		{"1.14.4-other", "1.14.4-flr-random-sni.1", false},
	}
	for _, c := range cases {
		if got := versionOlder(c.a, c.b); got != c.want {
			t.Errorf("versionOlder(%s,%s)=%v", c.a, c.b, got)
		}
	}
}

type execFunc func(context.Context, string, ...string) ([]byte, error)

func (f execFunc) Run(ctx context.Context, bin string, args ...string) ([]byte, error) {
	return f(ctx, bin, args...)
}

func TestUnprovenCompatibility(t *testing.T) {
	bad := errors.New("incompatible")
	for _, gate := range []string{"check", "canary"} {
		for _, tc := range []struct {
			name   string
			errors []error
			action string
		}{
			{"shared failure", []error{bad, bad}, "inconclusive"},
			{"retry passes", []error{bad, nil, nil}, "inconclusive"},
			{"retry fails", []error{bad, nil, bad}, "blocked"},
			{"cancelled", []error{context.Canceled}, "inconclusive"},
			{"timeout", []error{context.DeadlineExceeded}, "inconclusive"},
			{"control timeout", []error{bad, context.DeadlineExceeded}, "inconclusive"},
			{"retry timeout", []error{bad, nil, context.DeadlineExceeded}, "inconclusive"},
		} {
			t.Run(gate+"/"+tc.name, func(t *testing.T) {
				r := newRig(t, nil)
				before := r.binSHA()
				calls := 0
				var config string
				outcome := func(bin, path string) error {
					t.Helper()
					if calls >= len(tc.errors) || (bin == r.env.BinPath("sing-box")) != (calls == 1) {
						t.Fatalf("unexpected call %d to %s", calls+1, bin)
					}
					if calls == 0 {
						config = path
					} else if path != config {
						t.Fatalf("changed config or connection: %q -> %q", config, path)
					}
					calls++
					return tc.errors[calls-1]
				}
				if gate == "check" {
					r.u.Exec = execFunc(func(ctx context.Context, bin string, args ...string) ([]byte, error) {
						if args[0] == "check" {
							return nil, outcome(bin, args[2])
						}
						return OSExec{}.Run(ctx, bin, args...)
					})
				} else {
					r.canary.fn = func(bin string, tg Target) CanaryResult {
						if err := outcome(bin, tg.ID); err != nil {
							return CanaryResult{Probe: "https", Detail: err.Error(), Inconclusive: err != bad}
						}
						return CanaryResult{OK: true}
					}
				}
				e := r.cycle(ModeApply).Engines["sing-box"]
				l := r.lock()
				if e.Action != tc.action || calls != len(tc.errors) || r.binSHA() != before ||
					(len(l.Blocked) == 1) != (tc.action == "blocked") || l.Candidate != nil {
					t.Fatalf("report=%+v lock=%+v calls=%d", e, l, calls)
				}
			})
		}
	}
}

func TestCancelledAfterSuccessfulCanary(t *testing.T) {
	r := newRig(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.canary.fn = func(string, Target) CanaryResult {
		cancel()
		return CanaryResult{OK: true}
	}
	rep, err := r.u.Cycle(ctx, ModeApply)
	if err != nil || rep.Engines["sing-box"].Action != "inconclusive" || len(r.lock().Blocked) != 0 || r.binSHA() == r.candSHA {
		t.Fatalf("report=%+v err=%v", rep, err)
	}
}

func TestCommandTimeoutRetainsCause(t *testing.T) {
	p := filepath.Join(t.TempDir(), "slow")
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexec sleep 30\n"), 0700); err != nil {
		t.Fatal(err)
	}
	_, err := (OSExec{Timeout: 50 * time.Millisecond}).Run(context.Background(), p, "check", "-c", "config")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("check timeout: %v", err)
	}
}

func TestInstalledCapabilitiesUnavailable(t *testing.T) {
	for _, output := range []string{"command failed", "bad json", `{"version":1}`, `{"version":1,"capabilities":[null]}`, `{"version":1,"capabilities":[]} {}`} {
		t.Run(output, func(t *testing.T) {
			r := newRig(t, nil)
			r.u.Exec = execFunc(func(ctx context.Context, bin string, args ...string) ([]byte, error) {
				if bin == r.env.BinPath("sing-box") && args[0] == "flr-capabilities" {
					if output == "command failed" {
						return nil, errors.New("capabilities unavailable")
					}
					return []byte(output), nil
				}
				return OSExec{}.Run(ctx, bin, args...)
			})
			e := r.cycle(ModeApply).Engines["sing-box"]
			if e.Action != "inconclusive" || r.binSHA() == r.candSHA || len(r.lock().Blocked) != 0 || len(r.canary.calls) != 0 {
				t.Fatalf("%+v", e)
			}
		})
	}
}

type incompleteScope struct{ targets []Target }

func (s incompleteScope) Connections(context.Context, string) ([]Target, error) {
	return s.targets, errors.New("unresolved bearer")
}

func TestIncompleteScopeCannotDecide(t *testing.T) {
	valid := Target{ID: "good", Server: "192.0.2.1", Config: prodCfg}
	for _, scope := range []Scope{
		incompleteScope{[]Target{valid}},
		fakeScope{[]Target{valid, {ID: "unknown", Server: "unresolved.test", Config: prodCfg}}},
		fakeScope{[]Target{valid, {ID: "sidecar", Server: valid.Server, ConfigError: errors.New("isolated sidecar required")}}},
		fakeScope{[]Target{valid, {ID: "bad-config", Server: valid.Server, Config: []byte("{}")}}},
	} {
		r := newRig(t, nil)
		r.u.Scope = scope
		r.u.Cfg.ScopeServers = []string{valid.Server}
		r.u.Cfg.UpdateUnused = true
		r.u.Env.ELF = func(string) error { return errors.New("must not block before scope is complete") }
		e := r.cycle(ModeApply).Engines["sing-box"]
		if e.Action != "inconclusive" || len(r.lock().Blocked) != 0 || r.binSHA() == r.candSHA || len(r.canary.calls) != 0 {
			t.Fatalf("%+v", e)
		}
	}
}

func TestCycleOwnsOnlyItsTemporaryDirectory(t *testing.T) {
	r := newRig(t, nil)
	parent := r.env.TmpDir
	sibling := filepath.Join(parent, "flr-engine")
	if err := os.WriteFile(sibling, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	var dirs []string
	r.u.Env.ELF = func(bin string) error {
		dir := filepath.Dir(bin)
		st, err := os.Lstat(dir)
		if err != nil || filepath.Dir(dir) != parent || !st.IsDir() || st.Mode().Perm() != 0700 ||
			int(st.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() {
			t.Fatalf("unsafe staging directory: %s, %v, %v", dir, st, err)
		}
		dirs = append(dirs, dir)
		return nil
	}
	for range 2 {
		if e := r.cycle(ModeCheck).Engines["sing-box"]; e.Action != "would-promote" {
			t.Fatalf("%+v", e)
		}
	}
	if len(dirs) != 2 || dirs[0] == dirs[1] {
		t.Fatalf("staging paths %v", dirs)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(sibling) {
		t.Fatalf("unexpected cleanup: %v, %v", entries, err)
	}
}

func TestStageWritersRefuseSymlinks(t *testing.T) {
	r := newRig(t, nil)
	ch, err := ParseChannel(r.manif)
	if err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(t.TempDir(), "original")
	if err := os.WriteFile(original, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(original, link); err != nil {
		t.Fatal(err)
	}
	if err := r.u.download(context.Background(), ch.Engines["sing-box"], link); err == nil {
		t.Fatal("staged binary followed symlink")
	}
	if err := writeCanaryConfig(link, prodCfg); err == nil {
		t.Fatal("canary config followed symlink")
	}
	if b, err := os.ReadFile(original); err != nil || string(b) != "keep" {
		t.Fatalf("symlink target changed: %q, %v", b, err)
	}
}

func TestManifestAssetRejectedBeforeFetch(t *testing.T) {
	r := newRig(t, nil)
	r.fetch.files[chanURL] = []byte(strings.Replace(string(r.manif), binURL, "https://untrusted.test/asset", 1))
	e := r.cycle(ModeApply).Engines["sing-box"]
	if e.Action != "error" || len(r.fetch.calls) != 1 || len(r.lock().Blocked) != 0 || r.binSHA() == r.candSHA {
		t.Fatalf("report=%+v fetched=%v", e, r.fetch.calls)
	}
}

func TestVersionRequiresOneSingBoxVersionLine(t *testing.T) {
	for _, s := range []string{"other version 1.2.3", "version 1.2.3", "sing-box version 1.2.3 extra", "sing-box version 1.2.3\nsing-box version 2.0.0"} {
		x := execFunc(func(context.Context, string, ...string) ([]byte, error) { return []byte(s), nil })
		if v, err := BinaryVersion(context.Background(), x, "candidate"); err == nil {
			t.Errorf("accepted %q from %q", v, s)
		}
	}
}

func TestCandidateCapabilityQueryFailure(t *testing.T) {
	for _, tc := range []struct {
		err    error
		action string
	}{
		{errors.New("unknown flr-capabilities command"), "blocked"},
		{context.DeadlineExceeded, "inconclusive"},
	} {
		r := newRig(t, nil)
		r.u.Exec = execFunc(func(ctx context.Context, bin string, args ...string) ([]byte, error) {
			if bin != r.env.BinPath("sing-box") && args[0] == "flr-capabilities" {
				return nil, tc.err
			}
			return OSExec{}.Run(ctx, bin, args...)
		})
		e := r.cycle(ModeApply).Engines["sing-box"]
		if e.Action != tc.action || r.binSHA() == r.candSHA || len(r.canary.calls) != 0 {
			t.Fatalf("%+v", e)
		}
	}
}
