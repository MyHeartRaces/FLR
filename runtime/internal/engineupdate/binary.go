package engineupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Exec runs a finite engine command and returns bounded stdout. The error
// carries the exit status and a short stderr head.
type Exec interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// OSExec is the production Exec.
type OSExec struct{ Timeout time.Duration }

type limitedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.limit - b.buf.Len(); room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
		} else {
			b.buf.Write(p)
		}
	}
	return len(p), nil
}

func (o OSExec) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	t := o.Timeout
	if t == 0 {
		t = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, t)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = 500 * time.Millisecond
	out, errb := &limitedBuffer{limit: 64 << 10}, &limitedBuffer{limit: 512}
	cmd.Stdout, cmd.Stderr = out, errb
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return out.buf.Bytes(), fmt.Errorf("%w: %s", err, firstLine(errb.buf.String(), 160))
	}
	return out.buf.Bytes(), nil
}

func firstLine(s string, max int) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > max {
		s = s[:max]
	}
	return s
}

var versionLine = regexp.MustCompile(`(?m)^sing-box[ \t]+version[ \t]+([0-9A-Za-z][0-9A-Za-z._+-]{0,127})[ \t]*\r?$`)

// BinaryVersion runs `<bin> version` and extracts the version token.
func BinaryVersion(ctx context.Context, x Exec, bin string) (string, error) {
	out, err := x.Run(ctx, bin, "version")
	if err != nil {
		return "", fmt.Errorf("version command failed: %w", err)
	}
	lines := versionLine.FindAllSubmatch(out, 2)
	if len(lines) != 1 {
		return "", errors.New("version output not recognised")
	}
	return string(lines[0][1]), nil
}

// BinaryCapabilities runs `<bin> flr-capabilities`. A binary without the
// command (stock sing-box) reports no capabilities and ok=false.
func BinaryCapabilities(ctx context.Context, x Exec, bin string) (caps []string, ok bool) {
	caps, err := readCapabilities(ctx, x, bin)
	return caps, err == nil
}

func readCapabilities(ctx context.Context, x Exec, bin string) ([]string, error) {
	out, err := x.Run(ctx, bin, "flr-capabilities")
	if err != nil {
		return nil, err
	}
	if len(out) > 4096 {
		return nil, errors.New("capability reply too large")
	}
	var r struct {
		Version      int      `json:"version"`
		Capabilities []string `json:"capabilities"`
	}
	d := json.NewDecoder(bytes.NewReader(out))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || r.Version != 1 || r.Capabilities == nil {
		return nil, errors.New("invalid capability reply")
	}
	sort.Strings(r.Capabilities)
	for i, capability := range r.Capabilities {
		if !capRE.MatchString(capability) || (i > 0 && r.Capabilities[i-1] == capability) {
			return nil, errors.New("invalid reported capability")
		}
	}
	return r.Capabilities, nil
}

// MissingCapabilities returns the members of need absent from have.
func MissingCapabilities(have, need []string) []string {
	set := map[string]bool{}
	for _, h := range have {
		set[h] = true
	}
	var missing []string
	for _, n := range need {
		if !set[n] {
			missing = append(missing, n)
		}
	}
	sort.Strings(missing)
	return missing
}

// FileSHA256 returns the lowercase hex digest of a file.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// CheckELF requires an ELF64 little-endian AArch64 executable without PT_INTERP.
func CheckELF(path string) error {
	f, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("not an ELF file: %v", err)
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB {
		return errors.New("not ELF64 little-endian")
	}
	if f.Machine != elf.EM_AARCH64 {
		return fmt.Errorf("machine %v is not AArch64", f.Machine)
	}
	if f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
		return errors.New("ELF is not an executable")
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return errors.New("dynamically linked (PT_INTERP present)")
		}
	}
	return nil
}

// copyFileSynced copies src to dst (created 0755 via tmp name in dst's dir
// supplied as tmpName), fsyncs, then renames over dst.
func installFile(src, tmpName, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	os.Remove(tmpName)
	out, err := os.OpenFile(tmpName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			out.Close()
			os.Remove(tmpName)
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	if err = out.Chmod(0755); err != nil {
		return err
	}
	if err = out.Sync(); err != nil {
		return err
	}
	if err = out.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmpName, dst); err != nil {
		return err
	}
	ok = true
	return syncDir(filepath.Dir(dst))
}

// versionOlder reports whether candidate is strictly older than current by
// the numeric X.Y.Z core and, when the cores and suffix stems match, by the
// trailing numeric suffix (1.14.4-flr-random-sni.1 vs .2).
func versionOlder(candidate, current string) bool {
	cc, cs := splitVersion(candidate)
	uc, us := splitVersion(current)
	for i := 0; i < 3; i++ {
		if cc[i] != uc[i] {
			return cc[i] < uc[i]
		}
	}
	cs0, cn := suffixStem(cs)
	us0, un := suffixStem(us)
	if cs0 == us0 && cn >= 0 && un >= 0 {
		return cn < un
	}
	return false
}

func splitVersion(v string) ([3]int, string) {
	var n [3]int
	core, suffix := v, ""
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		core, suffix = v[:i], v[i+1:]
	}
	for i, p := range strings.SplitN(core, ".", 3) {
		n[i], _ = strconv.Atoi(p)
	}
	return n, suffix
}

func suffixStem(s string) (string, int) {
	i := strings.LastIndex(s, ".")
	if i < 0 {
		return s, -1
	}
	n, err := strconv.Atoi(s[i+1:])
	if err != nil {
		return s, -1
	}
	return s[:i], n
}

func execCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = 500 * time.Millisecond
	return cmd
}
