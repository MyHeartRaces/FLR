package dns

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	mdns "github.com/miekg/dns"
	"io"
	"os"
	"slices"
	"strings"
	"time"
)

// DefaultFilterPath is where an optional local DNS filter lives on the
// router. The image ships no filter. The file holds only salted name hashes,
// so its contents cannot be read back as a list.
const DefaultFilterPath = "/etc/flr-runtime/dnsfilter"

const filterMagic = "FLRDNSF1"

// filterMaxBytes bounds the file read into memory (about two million names).
const filterMaxBytes = 16 << 20

// FilterAction is the decision for one query name.
type FilterAction int

const (
	FilterPass FilterAction = iota
	FilterBlock
	FilterRewrite
)

// Filter is a hashed DNS name filter. Names are lower case without the
// trailing dot. A name is hashed as the first eight bytes of
// SHA-256(salt || name), big endian.
//
//   - allow: suffix rules ("example.com" covers its subdomains) and
//     "label.*" rules (that label under any public suffix, with its
//     subdomains); an allowed name is never blocked or rewritten.
//   - rewrite: exact names and prefix rules ("www.example.*": exactly that
//     name under any public suffix) answered as a CNAME to a target that is
//     resolved normally.
//   - block: suffix rules, "label.*" rules and keywords (substrings of one
//     label, of the lengths listed in the file).
type Filter struct {
	salt     []byte
	allow    []uint64
	block    []uint64
	keywords []uint64
	kwLens   []int
	rewrite  map[uint64]string
}

func (f *Filter) hash(s string) uint64 {
	h := sha256.New()
	h.Write(f.salt)
	io.WriteString(h, s)
	return binary.BigEndian.Uint64(h.Sum(nil))
}

func has(set []uint64, v uint64) bool {
	_, ok := slices.BinarySearch(set, v)
	return ok
}

func normalizeName(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
}

// secondLevel lists the common second-level labels of country suffixes
// (example.co.uk, example.com.tr), so "label.*" means a registrable name
// under any public suffix, not any name that has the label somewhere.
var secondLevel = map[string]bool{"co": true, "com": true, "net": true, "org": true, "gov": true, "edu": true, "ac": true, "or": true, "ne": true, "go": true, "gen": true, "biz": true, "info": true, "nom": true}

// publicSuffixLike reports whether rest looks like a public suffix: one
// label, or a known second-level label followed by a country code.
func publicSuffixLike(rest []string) bool {
	switch len(rest) {
	case 1:
		return true
	case 2:
		return secondLevel[rest[0]] && len(rest[1]) == 2
	}
	return false
}

// suffixMatch reports whether any suffix of name, or a "label.*" form of a
// suffix that is a label under a public suffix, is in set.
func (f *Filter) suffixMatch(set []uint64, labels []string) bool {
	if len(set) == 0 {
		return false
	}
	for i := range labels {
		if has(set, f.hash(strings.Join(labels[i:], "."))) {
			return true
		}
		if publicSuffixLike(labels[i+1:]) && has(set, f.hash(labels[i]+".*")) {
			return true
		}
	}
	return false
}

// Decide returns the action for a query name and, for a rewrite, the target.
func (f *Filter) Decide(name string) (FilterAction, string) {
	if f == nil {
		return FilterPass, ""
	}
	name = normalizeName(name)
	if name == "" {
		return FilterPass, ""
	}
	labels := strings.Split(name, ".")
	if f.suffixMatch(f.allow, labels) {
		return FilterPass, ""
	}
	if len(f.rewrite) > 0 {
		if t, ok := f.rewrite[f.hash(name)]; ok && t != name {
			return FilterRewrite, t
		}
		for k := 1; k < len(labels); k++ {
			if !publicSuffixLike(labels[k:]) {
				continue
			}
			if t, ok := f.rewrite[f.hash(strings.Join(labels[:k], ".")+".*")]; ok && t != name {
				return FilterRewrite, t
			}
		}
	}
	if f.suffixMatch(f.block, labels) {
		return FilterBlock, ""
	}
	if len(f.keywords) > 0 {
		for _, l := range labels {
			for _, n := range f.kwLens {
				for i := 0; i+n <= len(l); i++ {
					if has(f.keywords, f.hash("~"+l[i:i+n])) {
						return FilterBlock, ""
					}
				}
			}
		}
	}
	return FilterPass, ""
}

// Size is the number of hashed rules, for logs.
func (f *Filter) Size() int {
	if f == nil {
		return 0
	}
	return len(f.allow) + len(f.block) + len(f.keywords) + len(f.rewrite)
}

// ParseFilter decodes a filter file:
//
//	"FLRDNSF1" | u8 saltLen | salt
//	u32 n | n×u64 allow   (sorted)
//	u32 n | n×u64 block   (sorted)
//	u32 n | n×u64 keyword (sorted, hash of "~"+substring)
//	u8 n  | n×u8 keyword lengths
//	u32 n | n×(u64 hash, u8 len, target)
func ParseFilter(b []byte) (*Filter, error) {
	r := bytes.NewReader(b)
	magic := make([]byte, len(filterMagic))
	if _, e := io.ReadFull(r, magic); e != nil || string(magic) != filterMagic {
		return nil, fmt.Errorf("dns filter: bad header")
	}
	f := &Filter{rewrite: map[uint64]string{}}
	n8, e := r.ReadByte()
	if e != nil || n8 < 8 {
		return nil, fmt.Errorf("dns filter: bad salt")
	}
	f.salt = make([]byte, n8)
	if _, e = io.ReadFull(r, f.salt); e != nil {
		return nil, fmt.Errorf("dns filter: bad salt")
	}
	readSet := func() ([]uint64, error) {
		var n uint32
		if e := binary.Read(r, binary.BigEndian, &n); e != nil {
			return nil, e
		}
		if int64(n)*8 > int64(r.Len()) {
			return nil, fmt.Errorf("truncated")
		}
		out := make([]uint64, n)
		if e := binary.Read(r, binary.BigEndian, out); e != nil {
			return nil, e
		}
		if !slices.IsSorted(out) {
			return nil, fmt.Errorf("unsorted")
		}
		return out, nil
	}
	for _, dst := range []*[]uint64{&f.allow, &f.block, &f.keywords} {
		if *dst, e = readSet(); e != nil {
			return nil, fmt.Errorf("dns filter: %v", e)
		}
	}
	kn, e := r.ReadByte()
	if e != nil {
		return nil, fmt.Errorf("dns filter: truncated")
	}
	for i := 0; i < int(kn); i++ {
		l, e := r.ReadByte()
		if e != nil || l == 0 || l > 63 {
			return nil, fmt.Errorf("dns filter: bad keyword length")
		}
		f.kwLens = append(f.kwLens, int(l))
	}
	var rn uint32
	if e = binary.Read(r, binary.BigEndian, &rn); e != nil || int64(rn)*10 > int64(r.Len()) {
		return nil, fmt.Errorf("dns filter: bad rewrite table")
	}
	for i := uint32(0); i < rn; i++ {
		var h uint64
		if e = binary.Read(r, binary.BigEndian, &h); e != nil {
			return nil, fmt.Errorf("dns filter: truncated")
		}
		l, e := r.ReadByte()
		if e != nil || l == 0 {
			return nil, fmt.Errorf("dns filter: bad rewrite target")
		}
		t := make([]byte, l)
		if _, e = io.ReadFull(r, t); e != nil {
			return nil, fmt.Errorf("dns filter: truncated")
		}
		target := normalizeName(string(t))
		if _, ok := mdns.IsDomainName(target); !ok {
			return nil, fmt.Errorf("dns filter: bad rewrite target")
		}
		f.rewrite[h] = target
	}
	if r.Len() != 0 {
		return nil, fmt.Errorf("dns filter: trailing data")
	}
	return f, nil
}

// LoadFilter reads a filter file. A missing file is no filter and no error.
func LoadFilter(path string) (*Filter, error) {
	fh, e := os.Open(path)
	if os.IsNotExist(e) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	defer fh.Close()
	b, e := io.ReadAll(io.LimitReader(fh, filterMaxBytes+1))
	if e != nil {
		return nil, e
	}
	if len(b) > filterMaxBytes {
		return nil, fmt.Errorf("dns filter: file too large")
	}
	return ParseFilter(b)
}

// filterStamp identifies one version of the filter file.
type filterStamp struct {
	exists bool
	size   int64
	mod    time.Time
}

func statFilter(path string) filterStamp {
	st, e := os.Stat(path)
	if e != nil {
		return filterStamp{}
	}
	return filterStamp{exists: true, size: st.Size(), mod: st.ModTime()}
}
