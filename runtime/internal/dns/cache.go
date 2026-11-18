package dns

import (
	"fmt"
	mdns "github.com/miekg/dns"
	"sync"
	"time"
)

type cacheEntry struct {
	message          *mdns.Msg
	created, expires time.Time
}
type Cache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
}

func NewCache() *Cache { return &Cache{entries: map[string]cacheEntry{}} }
func cacheKey(v View, q *mdns.Msg) string {
	if len(q.Question) != 1 {
		return ""
	}
	do := false
	if opt := q.IsEdns0(); opt != nil {
		do = opt.Do()
	}
	return fmt.Sprintf("%s/%d/%v/%v/%v/%v", v.ID, v.Generation, q.Question, q.CheckingDisabled, q.AuthenticatedData, do)
}
func (c *Cache) Put(v View, q, r *mdns.Msg, now time.Time) {
	ttl := uint32(3600)
	found := false
	for _, rr := range r.Answer {
		found = true
		if rr.Header().Ttl < ttl {
			ttl = rr.Header().Ttl
		}
	}
	if !found {
		for _, rr := range r.Ns {
			if soa, ok := rr.(*mdns.SOA); ok {
				found = true
				n := soa.Minttl
				if soa.Hdr.Ttl < n {
					n = soa.Hdr.Ttl
				}
				if n < ttl {
					ttl = n
				}
			}
		}
	}
	if !found || ttl == 0 || r.Truncated || r.Rcode == mdns.RcodeServerFailure {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= 4096 {
		c.entries = map[string]cacheEntry{}
	}
	c.entries[cacheKey(v, q)] = cacheEntry{message: r.Copy(), created: now, expires: now.Add(time.Duration(ttl) * time.Second)}
}
func (c *Cache) Get(v View, q *mdns.Msg, now time.Time) (*mdns.Msg, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := cacheKey(v, q)
	e, ok := c.entries[key]
	if !ok || !e.expires.After(now) {
		delete(c.entries, key)
		return nil, false
	}
	r := e.message.Copy()
	r.Id = q.Id
	age := uint32(now.Sub(e.created) / time.Second)
	for _, section := range [][]mdns.RR{r.Answer, r.Ns, r.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype == mdns.TypeOPT {
				continue
			}
			if rr.Header().Ttl <= age {
				rr.Header().Ttl = 0
			} else {
				rr.Header().Ttl -= age
			}
		}
	}
	return r, true
}

// Keep the client cache, broker cache and nft timeout under the same bound.
// DNSSEC-signed RDATA (including SOA Minttl) is deliberately untouched.
func ClampReply(r *mdns.Msg) {
	for _, section := range [][]mdns.RR{r.Answer, r.Ns, r.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype != mdns.TypeOPT && rr.Header().Ttl > 3600 {
				rr.Header().Ttl = 3600
			}
		}
	}
}
