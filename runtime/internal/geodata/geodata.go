// Package geodata reads the V2Ray/Xray geosite.dat and geoip.dat files and
// converts a RoscomVPN (Happ/INCY) routing profile into an FLR policy
// overlay (roscomvpn.go).
//
// The files are protobuf messages:
//
//	GeoSiteList{repeated GeoSite entry = 1}
//	GeoSite{string country_code = 1; repeated Domain domain = 2}
//	Domain{Type type = 1; string value = 2; repeated Attribute attribute = 3}
//	Attribute{string key = 1; oneof {bool bool_value = 2; int64 int_value = 3}}
//	GeoIPList{repeated GeoIP entry = 1}
//	GeoIP{string country_code = 1; repeated CIDR cidr = 2; bool reverse_match = 3}
//	CIDR{bytes ip = 1; uint32 prefix = 2}
//
// The decoder is a small hand-written wire reader: no protobuf library. It
// checks every varint and length against the remaining bytes, skips unknown
// fields of the known wire types, refuses groups, and caps the number of
// categories and entries, so a hostile or truncated file fails cleanly.
package geodata

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf8"
)

const (
	// MaxCategories bounds the categories of one file.
	MaxCategories = 65536
	// MaxEntries bounds the domains or CIDRs of one file, all categories
	// together.
	MaxEntries = 8 << 20
	// MaxValueBytes bounds one domain value or category name.
	MaxValueBytes = 4096
	// MaxAttributes bounds the attributes of one domain.
	MaxAttributes = 64
)

// maxEntries and maxCategories are the caps in force (lowered in tests).
var maxEntries, maxCategories = MaxEntries, MaxCategories

// ctxEvery is how many entries a walk handles between context checks.
const ctxEvery = 4096

// DomainType is the geosite match kind.
type DomainType int

const (
	Plain      DomainType = 0 // substring (keyword)
	Regex      DomainType = 1 // regular expression
	RootDomain DomainType = 2 // the domain and its subdomains (suffix)
	Full       DomainType = 3 // exactly this name
)

// Domain is one geosite entry as Sites.Each hands it over. Value aliases
// the file data and is valid only during the callback: nothing is copied
// unless the caller keeps it.
type Domain struct {
	Type  DomainType
	Value []byte
}

var errTruncated = errors.New("truncated data")

// wire reads protobuf fields from b.
type wire struct {
	b []byte
	i int
}

func (w *wire) more() bool { return w.i < len(w.b) }

func (w *wire) varint() (uint64, error) {
	var v uint64
	for shift := uint(0); shift < 64; shift += 7 {
		if w.i >= len(w.b) {
			return 0, errTruncated
		}
		c := w.b[w.i]
		w.i++
		if shift == 63 && c > 1 {
			return 0, errors.New("varint overflow")
		}
		v |= uint64(c&0x7f) << shift
		if c < 0x80 {
			return v, nil
		}
	}
	return 0, errors.New("varint overflow")
}

// field reads the next field. For wire type 2 it returns the payload; for
// wire type 0 the value. Fixed-size fields are skipped (data nil, value 0).
func (w *wire) field() (num uint64, typ int, value uint64, data []byte, err error) {
	key, err := w.varint()
	if err != nil {
		return 0, 0, 0, nil, err
	}
	num, typ = key>>3, int(key&7)
	if num == 0 || num > 1<<29-1 {
		return 0, 0, 0, nil, errors.New("invalid field number")
	}
	switch typ {
	case 0:
		value, err = w.varint()
	case 1, 5:
		n := 8
		if typ == 5 {
			n = 4
		}
		if len(w.b)-w.i < n {
			return 0, 0, 0, nil, errTruncated
		}
		w.i += n
	case 2:
		var l uint64
		if l, err = w.varint(); err != nil {
			return 0, 0, 0, nil, err
		}
		if l > uint64(len(w.b)-w.i) {
			return 0, 0, 0, nil, errTruncated
		}
		data = w.b[w.i : w.i+int(l)]
		w.i += int(l)
	default:
		return 0, 0, 0, nil, fmt.Errorf("unsupported wire type %d", typ)
	}
	return num, typ, value, data, err
}

func text(b []byte, what string) (string, error) {
	if len(b) > MaxValueBytes || !utf8.Valid(b) {
		return "", fmt.Errorf("invalid %s", what)
	}
	return string(b), nil
}

// category is one named entry of a list: its raw message and the code.
type category struct {
	code string
	raw  []byte
}

// index walks a GeoSiteList or GeoIPList, validates every entry with check
// (which allocates nothing per entry) and returns the categories by
// upper-case code. The first of duplicate codes wins, as in Xray.
func index(ctx context.Context, data []byte, kind string, check func(raw []byte, entries *int) error) (map[string]category, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%s: empty file", kind)
	}
	out := map[string]category{}
	w := wire{b: data}
	entries, count := 0, 0
	for w.more() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		num, typ, _, raw, err := w.field()
		if err != nil {
			return nil, fmt.Errorf("%s: %v", kind, err)
		}
		if num != 1 || typ != 2 {
			continue
		}
		if count++; count > maxCategories {
			return nil, fmt.Errorf("%s: more than %d categories", kind, maxCategories)
		}
		code := ""
		inner := wire{b: raw}
		for inner.more() {
			n, t, _, d, err := inner.field()
			if err != nil {
				return nil, fmt.Errorf("%s: %v", kind, err)
			}
			if n == 1 && t == 2 {
				if code, err = text(d, "category name"); err != nil {
					return nil, fmt.Errorf("%s: %v", kind, err)
				}
			}
		}
		if err := check(raw, &entries); err != nil {
			return nil, fmt.Errorf("%s %s: %v", kind, short(code), err)
		}
		if entries > maxEntries {
			return nil, fmt.Errorf("%s: more than %d entries", kind, maxEntries)
		}
		key := strings.ToUpper(code)
		if _, seen := out[key]; !seen && code != "" {
			out[key] = category{code: code, raw: raw}
		}
	}
	if count == 0 {
		return nil, fmt.Errorf("%s: no categories", kind)
	}
	return out, nil
}

func short(s string) string {
	if len(s) > 64 {
		return s[:64] + "…"
	}
	return s
}

func checkText(b []byte, what string) error {
	if len(b) > MaxValueBytes || !utf8.Valid(b) {
		return fmt.Errorf("invalid %s", what)
	}
	return nil
}

// Sites is a parsed geosite.dat. Categories are walked on demand.
type Sites struct{ cats map[string]category }

// ParseSites validates a geosite.dat file and indexes its categories.
func ParseSites(ctx context.Context, data []byte) (*Sites, error) {
	cats, err := index(ctx, data, "geosite", func(raw []byte, entries *int) error {
		var keys [MaxAttributes][]byte
		return walkSite(nil, raw, entries, keys[:0], nil)
	})
	if err != nil {
		return nil, err
	}
	return &Sites{cats: cats}, nil
}

// Len is the number of categories.
func (s *Sites) Len() int { return len(s.cats) }

// walkSite validates the domains of a GeoSite message and hands each to
// visit (nil: validate only) with its attribute keys. keys is scratch space
// with capacity MaxAttributes; nothing is allocated per domain.
func walkSite(ctx context.Context, raw []byte, entries *int, keys [][]byte, visit func(Domain, [][]byte) error) error {
	w := wire{b: raw}
	n := 0
	for w.more() {
		num, typ, _, data, err := w.field()
		if err != nil {
			return err
		}
		if num != 2 || typ != 2 {
			continue
		}
		if *entries++; *entries > maxEntries {
			return fmt.Errorf("more than %d entries", maxEntries)
		}
		if n++; ctx != nil && n%ctxEvery == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		d := Domain{}
		keys = keys[:0]
		valueSeen := false
		dw := wire{b: data}
		for dw.more() {
			fn, ft, v, b, err := dw.field()
			if err != nil {
				return err
			}
			switch {
			case fn == 1 && ft == 0:
				if v > uint64(Full) {
					return fmt.Errorf("unknown domain type %d", v)
				}
				d.Type = DomainType(v)
			case fn == 2 && ft == 2:
				if err := checkText(b, "domain value"); err != nil {
					return err
				}
				d.Value, valueSeen = b, true
			case fn == 3 && ft == 2:
				if len(keys) >= MaxAttributes {
					return fmt.Errorf("more than %d attributes", MaxAttributes)
				}
				aw := wire{b: b}
				var key []byte
				for aw.more() {
					an, at, _, ab, err := aw.field()
					if err != nil {
						return err
					}
					if an == 1 && at == 2 {
						if err := checkText(ab, "attribute"); err != nil {
							return err
						}
						key = ab
					}
				}
				if len(key) > 0 {
					keys = append(keys, key)
				}
			}
		}
		if !valueSeen || len(d.Value) == 0 {
			return fmt.Errorf("domain without value")
		}
		if visit != nil {
			if err := visit(d, keys); err != nil {
				return err
			}
		}
	}
	return nil
}

// Each hands fn every domain of a category spec "name[@attr]…", as Xray's
// geosite loader reads it: the name compares case-insensitively, and every
// "@attr" keeps only domains carrying the attribute key attr (compared
// case-insensitively; a leading "!" is part of the key, as in Xray). found
// is false when the category does not exist. ctx is checked while walking.
func (s *Sites) Each(ctx context.Context, spec string, fn func(Domain) error) (found bool, err error) {
	parts := strings.Split(spec, "@")
	name := strings.TrimSpace(parts[0])
	if name == "" {
		return false, fmt.Errorf("empty geosite category")
	}
	var filters [][]byte
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		if p == "" {
			return true, fmt.Errorf("empty geosite attribute in %s", short(spec))
		}
		filters = append(filters, []byte(p))
	}
	cat, ok := s.cats[strings.ToUpper(name)]
	if !ok {
		return false, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var buf [MaxAttributes][]byte
	n := 0
	err = walkSite(ctx, cat.raw, &n, buf[:0], func(d Domain, keys [][]byte) error {
		for _, f := range filters {
			has := false
			for _, k := range keys {
				if bytes.EqualFold(k, f) {
					has = true
					break
				}
			}
			if !has {
				return nil
			}
		}
		return fn(d)
	})
	return true, err
}

// IPs is a parsed geoip.dat.
type IPs struct{ cats map[string]category }

// ParseIPs validates a geoip.dat file and indexes its categories.
func ParseIPs(ctx context.Context, data []byte) (*IPs, error) {
	cats, err := index(ctx, data, "geoip", func(raw []byte, entries *int) error {
		return walkIP(nil, raw, entries, nil)
	})
	if err != nil {
		return nil, err
	}
	return &IPs{cats: cats}, nil
}

// Len is the number of categories.
func (s *IPs) Len() int { return len(s.cats) }

// reverseMatch reads reverse_match of a GeoIP message without its CIDRs.
func reverseMatch(raw []byte) (bool, error) {
	reverse := false
	w := wire{b: raw}
	for w.more() {
		num, typ, v, _, err := w.field()
		if err != nil {
			return false, err
		}
		if num == 3 && typ == 0 {
			reverse = v != 0
		}
	}
	return reverse, nil
}

// walkIP validates the CIDRs of a GeoIP message and hands each to visit
// (nil: validate only).
func walkIP(ctx context.Context, raw []byte, entries *int, visit func(netip.Prefix) error) error {
	w := wire{b: raw}
	n := 0
	for w.more() {
		num, typ, _, data, err := w.field()
		if err != nil {
			return err
		}
		if num != 2 || typ != 2 {
			continue
		}
		if *entries++; *entries > maxEntries {
			return fmt.Errorf("more than %d entries", maxEntries)
		}
		if n++; ctx != nil && n%ctxEvery == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		var ip []byte
		var bits uint64
		ipSeen := false
		cw := wire{b: data}
		for cw.more() {
			cn, ct, cv, cb, err := cw.field()
			if err != nil {
				return err
			}
			switch {
			case cn == 1 && ct == 2:
				ip, ipSeen = cb, true
			case cn == 2 && ct == 0:
				bits = cv
			}
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ipSeen || !ok {
			return fmt.Errorf("CIDR address must be 4 or 16 bytes")
		}
		if bits > uint64(addr.BitLen()) {
			return fmt.Errorf("CIDR prefix out of range")
		}
		if addr.Is4In6() && bits >= 96 {
			addr, bits = addr.Unmap(), bits-96
		}
		prefix, err := addr.Prefix(int(bits))
		if err != nil {
			return err
		}
		if visit != nil {
			if err := visit(prefix); err != nil {
				return err
			}
		}
	}
	return nil
}

// Each hands fn every CIDR of a category (case-insensitive). A category
// marked reverse_match (every address outside its CIDRs) is reported with
// reverse true and not walked. found is false when the category does not
// exist. ctx is checked while walking.
func (s *IPs) Each(ctx context.Context, code string, fn func(netip.Prefix) error) (reverse, found bool, err error) {
	cat, ok := s.cats[strings.ToUpper(strings.TrimSpace(code))]
	if !ok {
		return false, false, nil
	}
	if reverse, err = reverseMatch(cat.raw); err != nil || reverse {
		return reverse, true, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	n := 0
	return false, true, walkIP(ctx, cat.raw, &n, fn)
}
