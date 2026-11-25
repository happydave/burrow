package reliable

import (
	"net"
	"os"
	"sync"
	"time"

	"github.com/happydave/burrow/internal/clock"
)

// Conn presents one State's byte stream as a net.Conn for crypto/tls. It
// moves no packets itself: a driver feeds the State through Do and sends
// what Poll returns. Kick is called after a Write so the driver polls.
type Conn struct {
	mu            sync.Mutex
	st            *State
	clk           clock.Clock
	kick          func()
	wake          chan struct{}
	closed        bool
	waiters       int // Reads and Writes blocked in wait; tests read it
	rdl, wdl      time.Time
	local, remote net.Addr
}

// NewConn wraps st. kick may be nil.
func NewConn(st *State, clk clock.Clock, kick func(), local, remote net.Addr) *Conn {
	if kick == nil {
		kick = func() {}
	}
	return &Conn{st: st, clk: clk, kick: kick, wake: make(chan struct{}), local: local, remote: remote}
}

// Do runs f on the State under the Conn's lock, then wakes blocked readers
// and writers so they look again.
func (c *Conn) Do(f func(*State)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f(c.st)
	c.broadcastLocked()
}

func (c *Conn) broadcastLocked() {
	close(c.wake)
	c.wake = make(chan struct{})
}

// wait blocks until a broadcast or the deadline. It is called without the
// lock held; w and dl were read under it.
func (c *Conn) wait(w <-chan struct{}, dl time.Time) {
	if dl.IsZero() {
		<-w
		return
	}
	t := c.clk.NewTimer(dl.Sub(c.clk.Now()))
	defer t.Stop()
	select {
	case <-w:
	case <-t.C():
	}
}

// Read blocks until delivered bytes exist, the Conn is closed, the State
// fails, or the read deadline passes.
func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		c.mu.Lock()
		if n := c.st.Read(p); n > 0 {
			c.mu.Unlock()
			return n, nil
		}
		if c.closed {
			c.mu.Unlock()
			return 0, net.ErrClosed
		}
		if err := c.st.Err(); err != nil {
			c.mu.Unlock()
			return 0, err
		}
		if !c.rdl.IsZero() && !c.clk.Now().Before(c.rdl) {
			c.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
		w, dl := c.wake, c.rdl
		c.waiters++
		c.mu.Unlock()
		c.wait(w, dl)
		c.mu.Lock()
		c.waiters--
		c.mu.Unlock()
	}
}

// Write queues p, blocking while the send buffer is full.
func (c *Conn) Write(p []byte) (int, error) {
	total := 0
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return total, net.ErrClosed
		}
		n, _ := c.st.Write(p[total:])
		total += n
		if err := c.st.Err(); err != nil {
			c.mu.Unlock()
			return total, err
		}
		if total == len(p) {
			c.mu.Unlock()
			c.kick()
			return total, nil
		}
		if !c.wdl.IsZero() && !c.clk.Now().Before(c.wdl) {
			c.mu.Unlock()
			return total, os.ErrDeadlineExceeded
		}
		w, dl := c.wake, c.wdl
		c.waiters++
		c.mu.Unlock()
		if n > 0 {
			c.kick()
		}
		c.wait(w, dl)
		c.mu.Lock()
		c.waiters--
		c.mu.Unlock()
	}
}

// Close wakes blocked readers and writers; later calls fail with
// net.ErrClosed. It is safe to call twice.
func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.broadcastLocked()
	return nil
}

func (c *Conn) LocalAddr() net.Addr  { return c.local }
func (c *Conn) RemoteAddr() net.Addr { return c.remote }

func (c *Conn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rdl, c.wdl = t, t
	c.broadcastLocked()
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rdl = t
	c.broadcastLocked()
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wdl = t
	c.broadcastLocked()
	return nil
}
