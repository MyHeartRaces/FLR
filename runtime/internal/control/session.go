package control

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Session struct {
	ID      string    `json:"id"`
	Client  string    `json:"client"`
	MAC     string    `json:"mac"`
	Expires time.Time `json:"expires"`
	Port    int       `json:"port"`
}
type Backend interface {
	Start(context.Context, Session) error
	Stop(Session) error
}
type Manager struct {
	mu      sync.Mutex
	backend Backend
	current *Session
}

func NewManager(b Backend) *Manager { return &Manager{backend: b} }
func (m *Manager) Start(ctx context.Context, now time.Time, client, mac string, ttl time.Duration) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ttl <= 0 || ttl > 15*time.Minute {
		return Session{}, fmt.Errorf("invalid direct session TTL")
	}
	if m.current != nil {
		if e := m.backend.Stop(*m.current); e != nil {
			return Session{}, e
		}
		m.current = nil
	}
	nonce := make([]byte, 12)
	if _, e := rand.Read(nonce); e != nil {
		return Session{}, e
	}
	s := Session{ID: hex.EncodeToString(nonce), Client: client, MAC: mac, Expires: now.Add(ttl), Port: 1088}
	if e := m.backend.Start(ctx, s); e != nil {
		return s, e
	}
	m.current = &s
	return s, nil
}
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current == nil {
		return nil
	}
	e := m.backend.Stop(*m.current)
	m.current = nil
	return e
}
func (m *Manager) Tick(now time.Time, client, mac string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current != nil && (!now.Before(m.current.Expires) || client != m.current.Client || !strings.EqualFold(mac, m.current.MAC)) {
		_ = m.backend.Stop(*m.current)
		m.current = nil
	}
}
func (m *Manager) Current() *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current == nil {
		return nil
	}
	s := *m.current
	return &s
}
func Lease(client string) (string, error) {
	b, e := os.ReadFile("/tmp/dhcp.leases")
	if e != nil {
		return "", e
	}
	for _, line := range strings.Split(string(b), "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 3 && parts[2] == client {
			if validLease(parts, time.Now()) {
				return strings.ToLower(parts[1]), nil
			}
		}
	}
	return "", fmt.Errorf("client needs an active DHCP lease")
}
func LeaseAddress(mac string) (string, string) {
	b, e := os.ReadFile("/tmp/dhcp.leases")
	if e != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		p := strings.Fields(line)
		if len(p) >= 3 && strings.EqualFold(p[1], mac) {
			if validLease(p, time.Now()) {
				return p[2], strings.ToLower(p[1])
			}
		}
	}
	return "", ""
}

func validLease(parts []string, now time.Time) bool {
	if len(parts) < 3 {
		return false
	}
	mac, e := net.ParseMAC(parts[1])
	if e != nil || len(mac) != 6 {
		return false
	}
	expiry, e := strconv.ParseInt(parts[0], 10, 64)
	return e == nil && (expiry == 0 || expiry > now.Unix())
}
