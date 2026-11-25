//go:build interop

package interop

import (
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/happydave/burrow/internal/api"
	"github.com/happydave/burrow/internal/session"
)

// TestObserveSoftReset logs the server's control packets under key IDs
// other than 0, with their plain headers, over the reneg variant's first
// server renegotiation (spec notes O13). Kept as the record of how O13
// was observed: now that burrow answers the soft reset, so it logs
// only packets for keys that are not live.
func TestObserveSoftReset(t *testing.T) {
	variant(t, "reneg")
	if os.Getenv("BURROW_INTEROP_LONG") == "" {
		t.Skip("observation run; BURROW_INTEROP_LONG=1 runs it")
	}
	var mu sync.Mutex
	var seen []string
	start := time.Now()
	cfg := config(t, "123456")
	cfg.Events = func(e api.Event) {
		if e.Kind == api.EventPacketDropped && strings.HasPrefix(e.Reason, "other key") {
			mu.Lock()
			seen = append(seen, time.Since(start).Round(time.Millisecond).String()+" "+e.Reason)
			mu.Unlock()
		}
	}
	s := connect(t, cfg)
	t.Logf("server session ID from the hard reset: %x", s.ServerSession())
	time.Sleep(30 * time.Second)
	mu.Lock()
	defer mu.Unlock()
	for _, l := range seen {
		t.Log(l)
	}
}

// renegWatch records a session's renegotiation events and signals each
// finished one.
type renegWatch struct {
	mu       sync.Mutex
	log      []string
	finished chan uint8
	start    time.Time
}

func watchRenegotiations(cfg *session.Config) *renegWatch {
	w := &renegWatch{finished: make(chan uint8, 16), start: time.Now()}
	cfg.Events = func(e api.Event) {
		switch e.Kind {
		case api.EventRenegotiationStarted, api.EventRenegotiationFinished, api.EventKeyTransition:
		default:
			return
		}
		w.mu.Lock()
		w.log = append(w.log, time.Since(w.start).Round(time.Millisecond).String()+" "+string(e.Kind)+": "+e.Reason)
		w.mu.Unlock()
		if e.Kind == api.EventRenegotiationFinished {
			w.finished <- e.KeyID
		}
	}
	return w
}

func (w *renegWatch) dump(t *testing.T) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, l := range w.log {
		t.Log(l)
	}
}

// waitKey waits for a renegotiation to key id to finish, then for traffic
// to move to it, checking an echo is answered at each step.
func waitKey(t *testing.T, s *session.Session, w *renegWatch, id uint8, within time.Duration, seq *uint16) {
	t.Helper()
	select {
	case got := <-w.finished:
		if got != id {
			w.dump(t)
			t.Fatalf("renegotiated to key %d, want %d", got, id)
		}
	case <-s.Ended():
		w.dump(t)
		t.Fatalf("the session ended: %v", s.Err())
	case <-time.After(within):
		w.dump(t)
		t.Fatalf("no renegotiation to key %d within %v", id, within)
	}
	*seq++
	echo(t, s, *seq)
	// The server sends under the new key once it has it; that, or the
	// 60 s promotion, moves burrow's sealing to it. Echo until it has.
	deadline := time.Now().Add(65 * time.Second)
	for s.Stats().ActiveKey != id {
		if time.Now().After(deadline) {
			t.Fatalf("still sealing with key %d", s.Stats().ActiveKey)
		}
		*seq++
		echo(t, s, *seq)
		time.Sleep(200 * time.Millisecond)
	}
	if n := s.Stats().LiveKeys; n > 2 {
		t.Fatalf("%d keys live", n)
	}
	*seq++
	echo(t, s, *seq)
}

// TestServerRenegotiation: the reneg variant's server renegotiates every
// 20 s; the tunnel moves to key 1, then key 2, answering echoes all along.
func TestServerRenegotiation(t *testing.T) {
	variant(t, "reneg")
	cfg := config(t, "123456")
	w := watchRenegotiations(&cfg)
	s := connect(t, cfg)
	var seq uint16
	waitKey(t, s, w, 1, 30*time.Second, &seq)
	waitKey(t, s, w, 2, 30*time.Second, &seq)
	w.dump(t)
	st := s.Stats()
	t.Logf("renegotiations %d, server key-method-2 messages on renegotiation %d, soft resets dropped %d, live keys %d, echoes %d",
		st.Renegotiations, st.RenegKeyMessages, st.SoftResetsDropped, st.LiveKeys, seq)
}

// TestClientRenegotiation: burrow renegotiates at 10 s against a server
// whose own interval is an hour.
func TestClientRenegotiation(t *testing.T) {
	variant(t, "plain")
	cfg := config(t, "123456")
	cfg.RenegInterval = 10 * time.Second
	w := watchRenegotiations(&cfg)
	s := connect(t, cfg)
	var seq uint16
	waitKey(t, s, w, 1, 20*time.Second, &seq)
	w.dump(t)
	w.mu.Lock()
	started := w.log[0]
	w.mu.Unlock()
	if !strings.Contains(started, "started by burrow") {
		t.Fatalf("first event %q, want burrow's own renegotiation", started)
	}
}

// TestSimultaneous (opt-in, BURROW_INTEROP_LONG=1): burrow and the server
// both renegotiate every 20 s, so their soft resets cross (spec notes 15.8,
// O15). The tunnel survives each one.
func TestSimultaneous(t *testing.T) {
	variant(t, "reneg")
	if os.Getenv("BURROW_INTEROP_LONG") == "" {
		t.Skip("long run; BURROW_INTEROP_LONG=1 runs it")
	}
	cfg := config(t, "123456")
	cfg.RenegInterval = 20 * time.Second
	w := watchRenegotiations(&cfg)
	s := connect(t, cfg)
	var seq uint16
	for id := uint8(1); id <= 4; id++ {
		waitKey(t, s, w, id, 40*time.Second, &seq)
	}
	w.dump(t)
	st := s.Stats()
	t.Logf("renegotiations %d, soft resets dropped %d", st.Renegotiations, st.SoftResetsDropped)
}
