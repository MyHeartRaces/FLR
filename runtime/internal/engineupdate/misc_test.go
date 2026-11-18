package engineupdate

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return statIno(st)
}

func TestConfigStrict(t *testing.T) {
	if _, err := ParseConfig([]byte(`{"enabled":true,"channel_url":"https://x/c.json"}`)); err != nil {
		t.Fatal(err)
	}
	c, _ := ParseConfig([]byte(`{}`))
	if c.Enabled || c.Mode != "check" || c.IntervalHours != 24 || c.SoakHours != 72 || c.CanarySeconds != 60 || c.CanaryMinBytes != 8388608 || c.CanaryPort != 10891 || c.UpdateUnused {
		t.Fatalf("defaults %+v", c)
	}
	bad := []string{
		`{"bogus":1}`, `{"mode":"yolo"}`, `{"enabled":true,"channel_url":"http://x/c"}`, `{"enabled":true}`,
		`{"canary_port":1081}`, `{"canary_port":1088}`, `{"scope_servers":["example.com"]}`, `{"scope_servers":["::1"]}`,
		`{"engines":["xray"]}`, `{"require_signature":true}`, `{"public_key":"AAAA"}`, `{"interval_hours":0}`,
		`{} {}`, `{"auth_token_file":"rel"}`, `{"canary_min_bytes":10}`,
	}
	for _, b := range bad {
		if _, err := ParseConfig([]byte(b)); err == nil {
			t.Errorf("accepted %s", b)
		}
	}
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "nope.json")); err != ErrNoConfig {
		t.Fatal(err)
	}
}

func goodChannel() map[string]any {
	var m map[string]any
	json.Unmarshal(manifestFor("1.14.4-flr-random-sni.2", []byte(strings.Repeat("a", 2000)), []string{cap1}, t0), &m)
	return m
}

func TestChannelValidation(t *testing.T) {
	enc := func(m map[string]any) []byte { b, _ := json.Marshal(m); return b }
	if _, err := ParseChannel(enc(goodChannel())); err != nil {
		t.Fatal(err)
	}
	eng := func(m map[string]any) map[string]any {
		return m["engines"].(map[string]any)["sing-box"].(map[string]any)
	}
	mut := map[string]func(map[string]any){
		"format":    func(m map[string]any) { m["format"] = "v2" },
		"http url":  func(m map[string]any) { eng(m)["url"] = "http://example.test/x" },
		"userinfo":  func(m map[string]any) { eng(m)["url"] = "https://u:p@example.test/x" },
		"short sha": func(m map[string]any) { eng(m)["sha256"] = "abc" },
		"upper sha": func(m map[string]any) { eng(m)["sha256"] = strings.Repeat("A", 64) },
		"tiny":      func(m map[string]any) { eng(m)["size"] = 100 },
		"huge":      func(m map[string]any) { eng(m)["size"] = 129 << 20 },
		"extra key": func(m map[string]any) { m["evil"] = 1 },
		"eng extra": func(m map[string]any) { eng(m)["cmd"] = "rm" },
		"time":      func(m map[string]any) { m["published_at"] = "yesterday" },
		"commit":    func(m map[string]any) { m["source_commit"] = "xyz" },
		"dup caps":  func(m map[string]any) { eng(m)["capabilities"] = []string{"a", "a"} },
		"no engine": func(m map[string]any) { m["engines"] = map[string]any{} },
	}
	for name, f := range mut {
		m := goodChannel()
		f(m)
		if _, err := ParseChannel(enc(m)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := ParseChannel([]byte(`{"format":"flr-engine-channel-v1"} x`)); err == nil {
		t.Error("trailing data accepted")
	}
}

// CI's publish job adds api_url to every engine entry (ci/engine_channel.py);
// the router must accept a well-formed one and reject anything else.
func TestChannelAcceptsCIAPIURL(t *testing.T) {
	enc := func(m map[string]any) []byte { b, _ := json.Marshal(m); return b }
	eng := func(m map[string]any) map[string]any {
		return m["engines"].(map[string]any)["sing-box"].(map[string]any)
	}
	m := goodChannel()
	eng(m)["api_url"] = "https://api.github.com/repos/MyHeartRaces/FLR/releases/assets/123456"
	c, err := ParseChannel(enc(m))
	if err != nil {
		t.Fatalf("CI manifest with api_url rejected: %v", err)
	}
	if c.Engines["sing-box"].APIURL == "" {
		t.Fatal("api_url not decoded")
	}
	for _, bad := range []string{
		"http://api.github.com/repos/o/r/releases/assets/1",
		"https://example.test/repos/o/r/releases/assets/1",
		"https://api.github.com/repos/o/r/releases/assets/0",
		"https://api.github.com/repos/o/r/releases/assets/x",
		"https://api.github.com/repos/o/r/../assets/1",
	} {
		m := goodChannel()
		eng(m)["api_url"] = bad
		if _, err := ParseChannel(enc(m)); err == nil {
			t.Errorf("api_url %q accepted", bad)
		}
	}
}

func writeELF(t *testing.T, machine elf.Machine, class byte, interp bool) string {
	t.Helper()
	h := make([]byte, 64+56)
	copy(h, []byte{0x7f, 'E', 'L', 'F', class, 1, 1})
	le := binary.LittleEndian
	le.PutUint16(h[16:], uint16(elf.ET_EXEC))
	le.PutUint16(h[18:], uint16(machine))
	le.PutUint32(h[20:], 1)
	if interp {
		le.PutUint64(h[32:], 64)
		le.PutUint16(h[52:], 64)
		le.PutUint16(h[54:], 56)
		le.PutUint16(h[56:], 1)
		le.PutUint32(h[64:], uint32(elf.PT_INTERP))
	}
	p := filepath.Join(t.TempDir(), "bin")
	os.WriteFile(p, h, 0755)
	return p
}

func TestCheckELF(t *testing.T) {
	if err := CheckELF(writeELF(t, elf.EM_AARCH64, 2, false)); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]string{
		"x86":     writeELF(t, elf.EM_X86_64, 2, false),
		"dynamic": writeELF(t, elf.EM_AARCH64, 2, true),
		"script": func() string {
			p := filepath.Join(t.TempDir(), "s")
			os.WriteFile(p, []byte("#!/bin/sh\n"), 0755)
			return p
		}(),
	} {
		if CheckELF(p) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestTransformConfigChangesOnlyLogAndInbounds(t *testing.T) {
	out, err := TransformConfig(prodCfg, 10891)
	if err != nil {
		t.Fatal(err)
	}
	var before, after map[string]any
	json.Unmarshal(prodCfg, &before)
	json.Unmarshal(out, &after)
	changed := []string{}
	for k := range before {
		if b, _ := json.Marshal(before[k]); string(b) != mustJSON(after[k]) {
			changed = append(changed, k)
		}
	}
	if len(after) != len(before) || len(changed) != 2 {
		t.Fatalf("changed %v", changed)
	}
	if mustJSON(after["inbounds"]) != `[{"listen":"127.0.0.1","listen_port":10891,"tag":"canary","type":"socks"}]` || mustJSON(after["log"]) != `{"level":"warn"}` {
		t.Fatal(string(out))
	}
	if !strings.Contains(string(out), `"routing_mark":2147483648`) {
		t.Fatalf("outbound routing mark not preserved exactly: %s", out)
	}
	if _, err := TransformConfig([]byte(`[]`), 1); err == nil {
		t.Fatal("non-object accepted")
	}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestParseRouteStatus(t *testing.T) {
	s, err := ParseRouteStatus([]byte(`{"ok":true,"data":{"status":{"proxy":{"awg":{"healthy":true},"slot":{"healthy":false}}}}}`))
	if err != nil || !s.AWGHealthy || s.SlotHealthy {
		t.Fatal(s, err)
	}
	if _, err = ParseRouteStatus([]byte(`{"ok":false}`)); err == nil {
		t.Fatal("not ok accepted")
	}
}

func TestBinaryVersionParsing(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sb")
	fakeBin(t, p, "1.2.3-x.4", nil, true)
	v, err := BinaryVersion(context.Background(), OSExec{}, p)
	if err != nil || v != "1.2.3-x.4" {
		t.Fatal(v, err)
	}
	if caps, ok := BinaryCapabilities(context.Background(), OSExec{}, p); !ok || len(caps) != 0 {
		t.Fatal(caps, ok)
	}
}
