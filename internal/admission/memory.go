package admission

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Memory is a Store held in memory, shared by the tunnels of one client.
type Memory struct {
	mu      sync.Mutex
	records []Record
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b) // crypto/rand.Read does not fail on supported platforms
	return hex.EncodeToString(b)
}

func (m *Memory) Reserve(domain, remote string, p Policy, now time.Time) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !Allowed(filter(m.records, domain), p, now) {
		return "", fmt.Errorf("%w: domain %s", ErrRefused, domain)
	}
	id := newID()
	m.records = append(m.records, Record{ID: id, Domain: domain, Time: now, Remote: remote, Outcome: Pending})
	return id, nil
}

func (m *Memory) Complete(id string, o Outcome) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.records {
		if m.records[i].ID == id {
			m.records[i].Outcome = o
			return nil
		}
	}
	return fmt.Errorf("admission: no record %s", id)
}

func (m *Memory) Records(domain string) ([]Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return filter(m.records, domain), nil
}

func filter(rs []Record, domain string) []Record {
	var out []Record
	for _, r := range rs {
		if r.Domain == domain {
			out = append(out, r)
		}
	}
	return out
}
