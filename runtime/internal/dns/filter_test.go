package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	mdns "github.com/miekg/dns"
)

func encodeFilter(salt string, allow, block, keywords []string, kwLens []int, rewrite map[string]string) []byte {
	f := &Filter{salt: []byte(salt)}
	var b bytes.Buffer
	b.WriteString(filterMagic)
	b.WriteByte(byte(len(salt)))
	b.WriteString(salt)
	set := func(names []string, prefix string) {
		hs := []uint64{}
		for _, n := range names {
			hs = append(hs, f.hash(prefix+n))
		}
		slices.Sort(hs)
		binary.Write(&b, binary.BigEndian, uint32(len(hs)))
		binary.Write(&b, binary.BigEndian, hs)
	}
	set(allow, "")
	set(block, "")
	set(keywords, "~")
	b.WriteByte(byte(len(kwLens)))
	for _, l := range kwLens {
		b.WriteByte(byte(l))
	}
	keys := make([]string, 0, len(rewrite))
	for k := range rewrite {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	binary.Write(&b, binary.BigEndian, uint32(len(keys)))
	for _, k := range keys {
		binary.Write(&b, binary.BigEndian, f.hash(k))
		b.WriteByte(byte(len(rewrite[k])))
		b.WriteString(rewrite[k])
	}
	return b.Bytes()
}

func testFilter(t *testing.T) *Filter {
	t.Helper()
	raw := encodeFilter("0123456789abcdef",
		[]string{"good-blocked.example.org", "fine.*"},
		[]string{"blocked.example", "badsite.*", "example.net"},
		[]string{"zzzz", "qwerty"}, []int{4, 6},
		map[string]string{"search.example": "safe.search.example", "www.search.*": "safe.search.example"})
	f, e := ParseFilter(raw)
	if e != nil {
		t.Fatal(e)
	}
	return f
}

func TestFilterDecide(t *testing.T) {
	f := testFilter(t)
	cases := []struct {
		name   string
		act    FilterAction
		target string
	}{
		{"blocked.example.", FilterBlock, ""},
		{"WWW.Blocked.Example.", FilterBlock, ""},
		{"notblocked.example.", FilterPass, ""},
		{"badsite.com.", FilterBlock, ""},
		{"cdn.badsite.co.uk.", FilterBlock, ""},
		{"badsite.", FilterPass, ""},
		{"badsite.example.org.", FilterPass, ""},
		{"x.badsite.com.tr.", FilterBlock, ""},
		{"badsite.mycompany.co.uk.", FilterPass, ""},
		{"www.search.evil.example.", FilterPass, ""},
		{"a.example.net.", FilterBlock, ""},
		{"good-blocked.example.org.", FilterPass, ""},
		{"x.zzzzy.example.com.", FilterBlock, ""},
		{"myqwertyz.example.", FilterBlock, ""},
		{"zz.zz.example.", FilterPass, ""},
		{"fine.zzzz.", FilterPass, ""},
		{"zzzz.fine.org.", FilterPass, ""},
		{"search.example.", FilterRewrite, "safe.search.example"},
		{"www.search.co.uk.", FilterRewrite, "safe.search.example"},
		{"mail.search.example.", FilterPass, ""},
		{"safe.search.example.", FilterPass, ""},
		{"", FilterPass, ""},
	}
	for _, c := range cases {
		act, target := f.Decide(c.name)
		if act != c.act || target != c.target {
			t.Errorf("%q: got %v %q, want %v %q", c.name, act, target, c.act, c.target)
		}
	}
	var none *Filter
	if a, _ := none.Decide("blocked.example."); a != FilterPass {
		t.Fatal("nil filter must pass")
	}
}

func TestParseFilterRejectsDamage(t *testing.T) {
	raw := encodeFilter("0123456789abcdef", nil, []string{"a.example"}, nil, nil, nil)
	for i := 0; i < len(raw); i++ {
		if _, e := ParseFilter(raw[:i]); e == nil {
			t.Fatalf("truncation at %d accepted", i)
		}
	}
	if _, e := ParseFilter(append(append([]byte{}, raw...), 0)); e == nil {
		t.Fatal("trailing data accepted")
	}
	bad := append([]byte{}, raw...)
	copy(bad, "XXXXXXXX")
	if _, e := ParseFilter(bad); e == nil {
		t.Fatal("bad magic accepted")
	}
	short := encodeFilter("short", nil, nil, nil, nil, nil)
	if _, e := ParseFilter(short); e == nil {
		t.Fatal("short salt accepted")
	}
}

func TestLoadFilterMissingIsNone(t *testing.T) {
	f, e := LoadFilter(filepath.Join(t.TempDir(), "none"))
	if f != nil || e != nil {
		t.Fatalf("missing file: %v %v", f, e)
	}
}

type filterUpstreamRoute struct{}

func (filterUpstreamRoute) DNSRoute(contract.Class) (contract.Channel, uint64) {
	return contract.Down, 1
}

func TestResolveClientBlocksAndRewrites(t *testing.T) {
	b := New(nil, filterUpstreamRoute{}, nil)
	b.SetFilter(testFilter(t))
	q := new(mdns.Msg)
	q.SetQuestion("www.blocked.example.", mdns.TypeA)
	r, e := b.ResolveClient(context.Background(), q, View{})
	if e != nil || r.Rcode != mdns.RcodeNameError || len(r.Answer) != 0 || r.Id != q.Id {
		t.Fatalf("block: %v %v", r, e)
	}
	q.SetQuestion("search.example.", mdns.TypeCNAME)
	r, e = b.ResolveClient(context.Background(), q, View{})
	if e != nil || len(r.Answer) != 1 || r.Answer[0].(*mdns.CNAME).Target != "safe.search.example." {
		t.Fatalf("rewrite: %v %v", r, e)
	}
	// The rewrite target is resolved through the normal path: with no policy
	// that path fails, which proves the target, not the name, was resolved.
	q.SetQuestion("search.example.", mdns.TypeA)
	if _, e = b.ResolveClient(context.Background(), q, View{}); e == nil {
		t.Fatal("rewrite target was not resolved through Resolve")
	}
}

func TestWatchFilterReloadsAndClears(t *testing.T) {
	old := filterReload
	filterReload = 10 * time.Millisecond
	defer func() { filterReload = old }()
	path := filepath.Join(t.TempDir(), "dnsfilter")
	b := New(nil, filterUpstreamRoute{}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.watchFilter(ctx, path)
	if b.filter.Load() != nil {
		t.Fatal("filter without file")
	}
	os.WriteFile(path, encodeFilter("0123456789abcdef", nil, []string{"a.example"}, nil, nil, nil), 0o600)
	wait := func(want bool) {
		for i := 0; i < 300; i++ {
			if (b.filter.Load() != nil) == want {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("filter loaded=%v not reached", want)
	}
	wait(true)
	os.WriteFile(path, []byte("garbage"), 0o600)
	time.Sleep(50 * time.Millisecond)
	if b.filter.Load() == nil {
		t.Fatal("damaged file cleared the filter")
	}
	os.Remove(path)
	wait(false)
}
