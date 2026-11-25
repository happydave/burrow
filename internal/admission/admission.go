// Package admission keeps burrow under a server's ban on refused connects:
// it classifies each attempt's outcome, decides whether another may start,
// and keeps the history in a store that records an attempt before it is
// made.
package admission

import (
	"errors"
	"net"
	"time"

	"github.com/happydave/burrow/internal/api"
)

// Outcome is how a connection attempt ended, as the guard counts it.
type Outcome string

// Outcomes.
const (
	Pending     Outcome = "pending" // reserved, not yet completed; counts as refused
	Established Outcome = "established"
	Refused     Outcome = "refused"
	NotCounted  Outcome = "not counted"
)

// Classify maps a connect result to an Outcome. It is broad on purpose: an
// attempt the server answered that did not become a session counts as
// refused, whatever the reason, since a slower retry costs less than a ban.
func Classify(err error) Outcome {
	if err == nil {
		return Established
	}
	var e *api.Error
	if !errors.As(err, &e) {
		return NotCounted // no stage: it failed before anything was sent
	}
	if e.Kind == api.KindAdmissionRefused {
		return NotCounted
	}
	switch e.Stage {
	case api.StageLink, api.StageHardReset:
		if e.Kind == api.KindUnreachable || e.Kind == api.KindCanceled {
			return NotCounted
		}
	}
	return Refused
}

// Policy says how many attempts a domain may make in a window.
type Policy struct {
	Limit  int
	Window time.Duration
	// CountEstablished counts every attempt, not only refused ones.
	CountEstablished bool
}

// DefaultPolicy allows three refused attempts per domain in any hour, under
// a server that bans an address after five rejected connects an hour.
var DefaultPolicy = Policy{Limit: 3, Window: time.Hour}

// LivePolicy is the live check's: two attempts in total (decision of
// 2026-11-24).
var LivePolicy = Policy{Limit: 2, Window: 24 * time.Hour, CountEstablished: true}

// Record is one attempt in a domain's history.
type Record struct {
	ID      string    `json:"id"`
	Domain  string    `json:"domain"`
	Time    time.Time `json:"time"`
	Remote  string    `json:"remote"`
	Outcome Outcome   `json:"outcome"`
}

// Allowed is the guard's decision: whether another attempt may start, given
// the domain's records, the policy and the time. A pending record counts as
// refused; a record exactly a window old still counts; a record dated after
// now (the clock stepped back) has a negative age, so it counts too.
func Allowed(records []Record, p Policy, now time.Time) bool {
	n := 0
	for _, r := range records {
		if now.Sub(r.Time) > p.Window {
			continue
		}
		switch r.Outcome {
		case Refused, Pending:
			n++
		case Established:
			if p.CountEstablished {
				n++
			}
		}
	}
	return n < p.Limit
}

// Domain is the ban domain of an attempt to remote: the configured domain
// when there is one, otherwise the remote's host, so that two ports on one
// host share a count.
func Domain(configured, remote string) string {
	if configured != "" {
		return configured
	}
	if host, _, err := net.SplitHostPort(remote); err == nil {
		return host
	}
	return remote
}

// Store keeps attempt histories. Reserve checks and records in one step.
type Store interface {
	// Reserve applies Allowed to the domain's records under the store's
	// lock, and either refuses or adds a pending record.
	Reserve(domain, remote string, p Policy, now time.Time) (id string, err error)
	// Complete sets a reserved attempt's outcome.
	Complete(id string, o Outcome) error
	// Records returns a domain's history.
	Records(domain string) ([]Record, error)
}

// ErrRefused is returned by Reserve when the policy forbids another attempt.
var ErrRefused = errors.New("admission: attempt refused by policy")

// ErrFileStoreUnsupported is returned by the file store where flock is not
// available.
var ErrFileStoreUnsupported = errors.New("admission: the file store needs flock, which this platform lacks")
