package dns

import (
	"fmt"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"github.com/MyHeartRaces/FLR/runtime/internal/dataplane"
	mdns "github.com/miekg/dns"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type AddressTTL struct {
	IP  netip.Addr
	TTL time.Duration
}
type View struct {
	ID         string
	Generation uint64
	Class      contract.Class
	Source     string
	Channel    contract.Channel
}
type Binding struct {
	Class   contract.Class
	Expires time.Time
	Source  string
}
type namedBinding struct {
	Name    string
	View    View
	Records map[netip.Addr]time.Time
}
type Bindings struct{ names map[string]namedBinding }

func NewBindings() *Bindings { return &Bindings{names: map[string]namedBinding{}} }
func (s *Bindings) Replace(now time.Time, v View, name string, rs []AddressTTL) {
	key := v.ID + "/" + name
	b := namedBinding{Name: name, View: v, Records: map[netip.Addr]time.Time{}}
	// Clients may still use addresses issued by an earlier answer until its TTL expires.
	for ip, expiry := range s.names[key].Records {
		if expiry.After(now) {
			b.Records[ip] = expiry
		}
	}
	for _, r := range rs {
		if r.TTL > 0 && r.IP.Is4() {
			ttl := r.TTL
			if ttl > time.Hour {
				ttl = time.Hour
			}
			expiry := now.Add(ttl)
			if expiry.After(b.Records[r.IP]) {
				b.Records[r.IP] = expiry
			}
		}
	}
	if len(b.Records) == 0 {
		delete(s.names, key)
	} else {
		s.names[key] = b
	}
}

// Classifier maps one issued address of an answer for name to the view its
// binding belongs to under the current policy; false means no binding.
type Classifier func(name string, v View, ip netip.Addr) (View, bool)

// Reclassify rebinds every outstanding address under f (a routing mode
// change), keeping each address's expiry.
func (s *Bindings) Reclassify(now time.Time, f Classifier) {
	old := s.names
	s.names = map[string]namedBinding{}
	for _, b := range old {
		for ip, expiry := range b.Records {
			if !expiry.After(now) {
				continue
			}
			if v, ok := f(b.Name, b.View, ip); ok {
				s.Replace(now, v, b.Name, []AddressTTL{{IP: ip, TTL: expiry.Sub(now)}})
			}
		}
	}
}

func priority(c contract.Class) int {
	switch c {
	case contract.General:
		return 3
	case contract.Games:
		return 2
	case contract.Direct:
		return 1
	}
	return 0
}
func (s *Bindings) Snapshot(now time.Time) map[netip.Addr]Binding {
	out := map[netip.Addr]Binding{}
	for name, b := range s.names {
		for ip, expiry := range b.Records {
			if !expiry.After(now) {
				delete(b.Records, ip)
				continue
			}
			old, ok := out[ip]
			if !ok || bindingPriority(b.View.Class, b.View.Source) > bindingPriority(old.Class, old.Source) {
				out[ip] = Binding{Class: b.View.Class, Expires: expiry, Source: b.View.Source}
			} else if old.Class == b.View.Class && expiry.After(old.Expires) {
				old.Expires = expiry
				out[ip] = old
			}
		}
		if len(b.Records) == 0 {
			delete(s.names, name)
		}
	}
	return out
}
func AnswerRecords(m *mdns.Msg) ([]AddressTTL, error) {
	if len(m.Question) != 1 {
		return nil, fmt.Errorf("DNS response must have one question")
	}
	edges := map[string]string{}
	for _, r := range m.Answer {
		if c, ok := r.(*mdns.CNAME); ok {
			edges[strings.ToLower(c.Hdr.Name)] = strings.ToLower(c.Target)
		}
	}
	seen := map[string]bool{}
	for node := strings.ToLower(m.Question[0].Name); edges[node] != ""; node = edges[node] {
		if seen[node] {
			return nil, fmt.Errorf("CNAME cycle")
		}
		seen[node] = true
	}
	names := map[string]uint32{strings.ToLower(m.Question[0].Name): ^uint32(0)}
	for rounds := 0; rounds <= len(m.Answer); rounds++ {
		changed := false
		for _, r := range m.Answer {
			if c, ok := r.(*mdns.CNAME); ok {
				ttl, present := names[strings.ToLower(c.Hdr.Name)]
				if !present {
					continue
				}
				if c.Hdr.Ttl < ttl {
					ttl = c.Hdr.Ttl
				}
				target := strings.ToLower(c.Target)
				if old, yes := names[target]; !yes || ttl < old {
					names[target] = ttl
					changed = true
				}
			}
		}
		if !changed {
			break
		}
		if rounds == len(m.Answer) {
			return nil, fmt.Errorf("CNAME cycle")
		}
	}
	out := []AddressTTL{}
	for _, r := range m.Answer {
		ttl, ok := names[strings.ToLower(r.Header().Name)]
		if !ok {
			continue
		}
		if r.Header().Ttl < ttl {
			ttl = r.Header().Ttl
		}
		if ttl == 0 {
			continue
		}
		var ip netip.Addr
		switch a := r.(type) {
		case *mdns.A:
			ip, _ = netip.AddrFromSlice(a.A)
		case *mdns.AAAA:
			ip, _ = netip.AddrFromSlice(a.AAAA)
		default:
			continue
		}
		if ip.IsValid() {
			out = append(out, AddressTTL{IP: ip.Unmap(), TTL: time.Duration(ttl) * time.Second})
		}
	}
	return out, nil
}

type MappingWriter interface {
	Replace(View, string, []AddressTTL) error
}
type KernelMappings struct {
	mu       sync.Mutex
	bindings *Bindings
	pending  []chan error
	flushing bool
	apply    func(string) error
	// classify, once set by a routing mode change, decides the view of every
	// new binding, so an answer resolved under the previous policy cannot
	// reinstall a binding the new policy does not make.
	classify Classifier
}

func NewKernelMappings() *KernelMappings {
	return &KernelMappings{bindings: NewBindings(), apply: dataplane.Nft}
}
func (k *KernelMappings) Replace(v View, name string, rs []AddressTTL) error {
	// Empty/negative answers cannot remove outstanding issued bindings.
	positive := false
	for _, r := range rs {
		if r.IP.Is4() && r.TTL > 0 {
			positive = true
			break
		}
	}
	if !positive {
		return nil
	}
	k.mu.Lock()
	now := time.Now()
	k.bindings.Snapshot(now)
	if len(k.bindings.names) >= 4096 {
		k.mu.Unlock()
		return fmt.Errorf("DNS mapping capacity reached")
	}
	if k.classify == nil {
		k.bindings.Replace(now, v, name, rs)
	} else {
		groups := map[string][]AddressTTL{}
		views := map[string]View{}
		for _, r := range rs {
			if nv, ok := k.classify(name, v, r.IP); ok {
				groups[nv.ID] = append(groups[nv.ID], r)
				views[nv.ID] = nv
			}
		}
		for id, group := range groups {
			k.bindings.Replace(now, views[id], name, group)
		}
	}
	committed := make(chan error, 1)
	k.pending = append(k.pending, committed)
	if !k.flushing {
		k.flushing = true
		go k.flush()
	}
	k.mu.Unlock()
	return <-committed
}

// SetClassifier installs f for every later binding, rebinds the outstanding
// ones under it and rewrites the kernel sets, like an answer would.
func (k *KernelMappings) SetClassifier(f Classifier) error {
	k.mu.Lock()
	k.classify = f
	k.bindings.Reclassify(time.Now(), f)
	committed := make(chan error, 1)
	k.pending = append(k.pending, committed)
	if !k.flushing {
		k.flushing = true
		go k.flush()
	}
	k.mu.Unlock()
	return <-committed
}

func (k *KernelMappings) flush() {
	for {
		// Coalesce simultaneous DNS answers into one atomic kernel transaction.
		time.Sleep(5 * time.Millisecond)
		k.mu.Lock()
		waiters := k.pending
		k.pending = nil
		now := time.Now()
		var req strings.Builder
		for _, set := range []string{"required4", "essential4", "games4", "services4", "direct_domains4"} {
			fmt.Fprintf(&req, "flush set inet flr %s\n", set)
		}
		for ip, b := range k.bindings.Snapshot(now) {
			ttl := b.Expires.Sub(now).Milliseconds()
			if ttl > 0 {
				fmt.Fprintf(&req, "add element inet flr %s { %s timeout %dms }\n", MappingSet(b), ip, ttl)
			}
		}
		k.mu.Unlock()
		err := k.apply(req.String())
		for _, waiter := range waiters {
			waiter <- err
		}
		k.mu.Lock()
		if len(k.pending) == 0 {
			k.flushing = false
			k.mu.Unlock()
			return
		}
		k.mu.Unlock()
	}
}

func MappingSet(b Binding) string {
	switch b.Class {
	case contract.Games:
		return "games4"
	case contract.Direct:
		if b.Source == "direct-essential" {
			return "essential4"
		}
		return "direct_domains4"
	default:
		if b.Source == "vpn-required" {
			return "required4"
		}
		return "services4"
	}
}

func bindingPriority(c contract.Class, source string) int {
	n := priority(c) * 10
	if source == "vpn-required" {
		n += 2
	}
	if source == "direct-essential" {
		n++
	}
	return n
}
