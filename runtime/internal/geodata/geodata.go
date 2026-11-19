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

// DomainType is the geosite match kind.
type DomainType int

const (
	Plain      DomainType = 0 // substring (keyword)
	Regex      DomainType = 1 // regular expression
	RootDomain DomainType = 2 // the domain and its subdomains (suffix)
	Full       DomainType = 3 // exactly this name
)

// Domain is one geosite entry.
type Domain struct {
	Type  DomainType
	Value string
	Attrs []string
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
// and returns the categories by upper-case code. The first of duplicate
// codes wins, as in Xray.
func index(data []byte, kind string, check func(raw []byte, entries *int) error) (map[string]category, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%s: empty file", kind)
	}
	out := map[string]category{}
	w := wire{b: data}
	entries, count := 0, 0
	for w.more() {
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

// Sites is a parsed geosite.dat. Categories are decoded on lookup.
type Sites struct{ cats map[string]category }

// ParseSites validates a geosite.dat file and indexes its categories.
func ParseSites(data []byte) (*Sites, error) {
	cats, err := index(data, "geosite", func(raw []byte, entries *int) error {
		_, err := decodeSite(raw, entries, false)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &Sites{cats: cats}, nil
}

// Len is the number of categories.
func (s *Sites) Len() int { return len(s.cats) }

// decodeSite decodes (collect) or only validates the domains of a GeoSite.
func decodeSite(raw []byte, entries *int, collect bool) ([]Domain, error) {
	var out []Domain
	w := wire{b: raw}
	for w.more() {
		num, typ, _, data, err := w.field()
		if err != nil {
			return nil, err
		}
		if num != 2 || typ != 2 {
			continue
		}
		if *entries++; *entries > maxEntries {
			return nil, fmt.Errorf("more than %d entries", maxEntries)
		}
		d := Domain{}
		valueSeen := false
		dw := wire{b: data}
		for dw.more() {
			n, t, v, b, err := dw.field()
			if err != nil {
				return nil, err
			}
			switch {
			case n == 1 && t == 0:
				if v > uint64(Full) {
					return nil, fmt.Errorf("unknown domain type %d", v)
				}
				d.Type = DomainType(v)
			case n == 2 && t == 2:
				if d.Value, err = text(b, "domain value"); err != nil {
					return nil, err
				}
				valueSeen = true
			case n == 3 && t == 2:
				if len(d.Attrs) >= MaxAttributes {
					return nil, fmt.Errorf("more than %d attributes", MaxAttributes)
				}
				aw := wire{b: b}
				key := ""
				for aw.more() {
					an, at, _, ab, err := aw.field()
					if err != nil {
						return nil, err
					}
					if an == 1 && at == 2 {
						if key, err = text(ab, "attribute"); err != nil {
							return nil, err
						}
					}
				}
				if key != "" && collect {
					d.Attrs = append(d.Attrs, strings.ToLower(key))
				}
			}
		}
		if !valueSeen || d.Value == "" {
			return nil, fmt.Errorf("domain without value")
		}
		if collect {
			out = append(out, d)
		}
	}
	return out, nil
}

// Lookup returns the domains of a category spec "name[@attr][@!attr]…":
// the name compares case-insensitively; every "@attr" keeps only domains
// carrying that attribute and every "@!attr" drops domains carrying it.
// ok is false when the category does not exist.
func (s *Sites) Lookup(spec string) (domains []Domain, ok bool, err error) {
	parts := strings.Split(spec, "@")
	name := strings.TrimSpace(parts[0])
	if name == "" {
		return nil, false, fmt.Errorf("empty geosite category")
	}
	type filter struct {
		key  string
		want bool
	}
	var filters []filter
	for _, p := range parts[1:] {
		p = strings.ToLower(strings.TrimSpace(p))
		want := !strings.HasPrefix(p, "!")
		p = strings.TrimPrefix(p, "!")
		if p == "" {
			return nil, true, fmt.Errorf("empty geosite attribute in %s", short(spec))
		}
		filters = append(filters, filter{p, want})
	}
	cat, found := s.cats[strings.ToUpper(name)]
	if !found {
		return nil, false, nil
	}
	n := 0
	all, err := decodeSite(cat.raw, &n, true)
	if err != nil {
		return nil, true, err
	}
	for _, d := range all {
		keep := true
		for _, f := range filters {
			has := false
			for _, a := range d.Attrs {
				if a == f.key {
					has = true
					break
				}
			}
			if has != f.want {
				keep = false
				break
			}
		}
		if keep {
			domains = append(domains, d)
		}
	}
	return domains, true, nil
}

// IPs is a parsed geoip.dat.
type IPs struct{ cats map[string]category }

// ParseIPs validates a geoip.dat file and indexes its categories.
func ParseIPs(data []byte) (*IPs, error) {
	cats, err := index(data, "geoip", func(raw []byte, entries *int) error {
		_, _, err := decodeIP(raw, entries, false)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &IPs{cats: cats}, nil
}

// Len is the number of categories.
func (s *IPs) Len() int { return len(s.cats) }

// decodeIP decodes (collect) or only validates the CIDRs of a GeoIP.
func decodeIP(raw []byte, entries *int, collect bool) ([]netip.Prefix, bool, error) {
	var out []netip.Prefix
	reverse := false
	w := wire{b: raw}
	for w.more() {
		num, typ, v, data, err := w.field()
		if err != nil {
			return nil, false, err
		}
		switch {
		case num == 3 && typ == 0:
			reverse = v != 0
		case num == 2 && typ == 2:
			if *entries++; *entries > maxEntries {
				return nil, false, fmt.Errorf("more than %d entries", maxEntries)
			}
			var ip []byte
			var bits uint64
			ipSeen := false
			cw := wire{b: data}
			for cw.more() {
				n, t, cv, cb, err := cw.field()
				if err != nil {
					return nil, false, err
				}
				switch {
				case n == 1 && t == 2:
					ip, ipSeen = cb, true
				case n == 2 && t == 0:
					bits = cv
				}
			}
			addr, ok := netip.AddrFromSlice(ip)
			if !ipSeen || !ok {
				return nil, false, fmt.Errorf("CIDR address must be 4 or 16 bytes")
			}
			if bits > uint64(addr.BitLen()) {
				return nil, false, fmt.Errorf("CIDR prefix out of range")
			}
			if addr.Is4In6() && bits >= 96 {
				addr, bits = addr.Unmap(), bits-96
			}
			prefix, err := addr.Prefix(int(bits))
			if err != nil {
				return nil, false, err
			}
			if collect {
				out = append(out, prefix)
			}
		}
	}
	return out, reverse, nil
}

// Lookup returns the CIDRs of a category (case-insensitive) and whether the
// category is marked reverse_match (it then means every address outside
// them). ok is false when the category does not exist.
func (s *IPs) Lookup(code string) (prefixes []netip.Prefix, reverse, ok bool, err error) {
	cat, found := s.cats[strings.ToUpper(strings.TrimSpace(code))]
	if !found {
		return nil, false, false, nil
	}
	n := 0
	prefixes, reverse, err = decodeIP(cat.raw, &n, true)
	return prefixes, reverse, true, err
}
