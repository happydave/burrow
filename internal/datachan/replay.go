package datachan

import "time"

// Replay is the receive window (spec notes 12): a packet ID higher than any
// accepted is new; a lower one is accepted only if within Window of the
// highest, not seen before, and no more than Age after the highest arrived.
type Replay struct {
	now     func() time.Time
	highest uint32
	seen    uint64 // bit i: highest-i has been accepted
	at      time.Time
	started bool
}

// Window and Age are the man page's --replay-window defaults.
const (
	Window = 64
	Age    = 15 * time.Second
)

// NewReplay returns an empty window reading the time from now.
func NewReplay(now func() time.Time) *Replay { return &Replay{now: now} }

// Check reports whether pid may be accepted; it changes nothing.
func (r *Replay) Check(pid uint32) bool {
	if !r.started || pid > r.highest {
		return true
	}
	back := r.highest - pid
	if back >= Window {
		return false
	}
	if r.seen&(1<<back) != 0 {
		return false
	}
	return r.now().Sub(r.at) <= Age
}

// Accept records pid, which Check allowed and whose tag verified.
func (r *Replay) Accept(pid uint32) {
	if !r.started {
		r.started, r.highest, r.seen, r.at = true, pid, 1, r.now()
		return
	}
	if pid > r.highest {
		shift := pid - r.highest
		if shift >= Window {
			r.seen = 0
		} else {
			r.seen <<= shift
		}
		r.seen |= 1
		r.highest, r.at = pid, r.now()
		return
	}
	r.seen |= 1 << (r.highest - pid)
}
