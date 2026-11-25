package session

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/happydave/burrow/internal/api"
	"github.com/happydave/burrow/internal/clock"
	"github.com/happydave/burrow/internal/datachan"
	"github.com/happydave/burrow/internal/fakeserver"
	"github.com/happydave/burrow/internal/wire"
)

// Tests for the fixes from the independent review (WI 2769's findings).

// TestForgedSoftResetChangesNothing (finding 1): a soft reset with a wrong
// session ID, or a wrong peer session ID beside ACKs, starts no
// negotiation and touches no key; a genuine one still does.
func TestForgedSoftResetChangesNothing(t *testing.T) {
	r := startReneg(t, fakeserver.Options{}, nil)
	forge := func(c wire.Control) []byte {
		b, err := wire.AppendControl(nil, c)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	wrong := wire.SessionID{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4}
	for _, c := range []wire.Control{
		{Op: wire.SoftResetV1, KeyID: 1, Session: wrong},
		{Op: wire.SoftResetV1, KeyID: 1, Session: r.s.serverSession, Acks: []uint32{0}, PeerSession: wrong},
	} {
		r.s.route(forge(c))
	}
	time.Sleep(100 * time.Millisecond)
	if n := len(r.times(api.EventRenegotiationStarted)); n != 0 {
		t.Fatalf("%d negotiations started by forged soft resets", n)
	}
	if st := r.s.Stats(); st.LiveKeys != 1 || st.ActiveKey != 0 || st.SoftResetsDropped != 2 {
		t.Fatalf("live keys %d, active %d, soft resets dropped %d; want 1, 0, 2", st.LiveKeys, st.ActiveKey, st.SoftResetsDropped)
	}
	// The genuine article, under the server's session ID, is still acted on.
	r.s.route(forge(wire.Control{Op: wire.SoftResetV1, KeyID: 1, Session: r.s.serverSession}))
	deadline := time.Now().Add(2 * time.Second)
	for len(r.times(api.EventRenegotiationStarted)) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("a soft reset with the server's session ID started nothing")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// failingConn returns err from its next Read once armed.
type failingConn struct {
	net.Conn
	armed atomic.Bool
	err   error
}

func (c *failingConn) Read(b []byte) (int, error) {
	if c.armed.CompareAndSwap(true, false) {
		return 0, c.err
	}
	return c.Conn.Read(b)
}

type connDialer struct {
	mu   sync.Mutex
	conn *failingConn
	err  error
}

func (d *connDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var nd net.Dialer
	c, err := nd.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	fc := &failingConn{Conn: c, err: d.err}
	d.mu.Lock()
	d.conn = fc
	d.mu.Unlock()
	return fc, nil
}

// TestLinkErrors (finding 2): an ICMP-derived read error leaves the session
// up; any other read error ends it at once, with the cause.
func TestLinkErrors(t *testing.T) {
	for _, c := range []struct {
		name    string
		err     error
		survive bool
	}{
		{"host unreachable", syscall.EHOSTUNREACH, true},
		{"anything else", errors.New("socket gone"), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := &connDialer{err: c.err}
			r := startReneg(t, fakeserver.Options{}, func(cfg *Config) { cfg.Dialer = d })
			r.echoes(t, 1, 0)
			d.mu.Lock()
			d.conn.armed.Store(true)
			d.mu.Unlock()
			// The armed read fires on the next datagram in: the echo's reply.
			_ = r.s.WritePacket([]byte{0x45, 7, 7, 7})
			select {
			case <-r.s.Ended():
				if c.survive {
					t.Fatalf("the session ended on %v: %v", c.err, r.s.Err())
				}
				if err := r.s.Err(); !errors.Is(err, api.KindUnreachable) || !strings.Contains(err.Error(), "socket gone") {
					t.Fatalf("ended with %v, want unreachable naming the cause", err)
				}
			case <-time.After(time.Second):
				if !c.survive {
					t.Fatal("the session did not end within 1 s of its link failing")
				}
				for { // drain the armed packet's echo, if it came back
					ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
					_, err := r.s.ReadPacket(ctx)
					cancel()
					if err != nil {
						break
					}
				}
				r.echoes(t, 2, 0) // still carries traffic
			}
		})
	}
}

// countingClock counts Now calls.
type countingClock struct {
	clock.Clock
	n atomic.Int64
}

func (c *countingClock) Now() time.Time { c.n.Add(1); return c.Clock.Now() }

// TestNoBusyLoopAfterExpiry (finding 3): once the keepalive has expired,
// the driver waits instead of spinning.
func TestNoBusyLoopAfterExpiry(t *testing.T) {
	clk := &countingClock{Clock: clock.Real()}
	push := strings.Replace(fakeserver.Push, "ping 10,ping-restart 60", "ping 0,ping-restart 1", 1)
	srv := fakeserver.Start(t, fakeserver.Options{Push: push})
	s, err := Connect(context.Background(), Config{Remote: srv.Addr(), CAs: srv.Pool, Version: "test",
		PushTimeout: 2 * time.Second, HandshakeWindow: 3 * time.Second, Clock: clk, RenegInterval: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	select {
	case <-s.Ended():
	case <-time.After(5 * time.Second):
		t.Fatal("no keepalive expiry with ping-restart 1")
	}
	if !errors.Is(s.Err(), api.KindKeepaliveTimeout) {
		t.Fatalf("ended with %v", s.Err())
	}
	before := clk.n.Load()
	time.Sleep(500 * time.Millisecond)
	if n := clk.n.Load() - before; n > 1000 {
		t.Fatalf("%d clock reads in 500 ms after expiry: the driver is spinning", n)
	}
}

// TestHaltKind (finding 5): HALT ends with its own kind.
func TestHaltKind(t *testing.T) {
	s := &Session{}
	if err := s.endFailure(api.StageEstablished, serverEnd("HALT")); !errors.Is(err, api.KindHalted) {
		t.Fatalf("HALT gives %v", err)
	}
	if err := s.endFailure(api.StageEstablished, serverEnd("RESTART")); !errors.Is(err, api.KindClosedByServer) {
		t.Fatalf("RESTART gives %v", err)
	}
}

// TestTLS12Refused (finding 6): a server offering only TLS 1.2 fails at the
// TLS stage.
func TestTLS12Refused(t *testing.T) {
	srv := fakeserver.Start(t, fakeserver.Options{Push: fakeserver.Push, TLS12Only: true})
	_, err := Connect(context.Background(), Config{Remote: srv.Addr(), CAs: srv.Pool, Version: "test", HandshakeWindow: 3 * time.Second})
	var e *api.Error
	if !errors.As(err, &e) || e.Stage != api.StageTLS {
		t.Fatalf("err %v, want a failure at the TLS stage", err)
	}
}

// TestPushPastTheWindowIsNotAdmitted (finding 7).
func TestPushPastTheWindowIsNotAdmitted(t *testing.T) {
	srv := fakeserver.StartSilent(t)
	cfg := silentConfig(srv)
	cfg.HandshakeWindow, cfg.PushTimeout = time.Second, 3*time.Second
	_, err := Connect(context.Background(), cfg)
	if !errors.Is(err, api.KindNotAdmitted) {
		t.Fatalf("err %v, want not admitted", err)
	}
}

// TestExitOnlyWithCCExit (finding 12): Close sends EXIT only to a server
// that pushed cc-exit.
func TestExitOnlyWithCCExit(t *testing.T) {
	push := strings.Replace(fakeserver.Push, "protocol-flags cc-exit tls-ekm", "protocol-flags tls-ekm", 1)
	srv := fakeserver.Start(t, fakeserver.Options{Push: push})
	s, err := Connect(context.Background(), Config{Remote: srv.Addr(), CAs: srv.Pool, Version: "test", HandshakeWindow: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	time.Sleep(100 * time.Millisecond)
	if slices.Contains(srv.Received(0), "EXIT") {
		t.Fatal("EXIT sent to a server that did not push cc-exit")
	}
}

// TestDropEventsAreRateLimited (finding 23): 100 replays give at most the
// second's allowance of events, and all 100 are counted.
func TestDropEventsAreRateLimited(t *testing.T) {
	ekm := make([]byte, 256)
	for i := range ekm {
		ekm[i] = byte(i)
	}
	srv := make([]byte, 256)
	copy(srv[0:128], ekm[128:256])
	copy(srv[128:256], ekm[0:128])
	srvSend, _, _ := datachan.KeysFromEKM(srv, "AES-256-GCM")
	_, recv, _ := datachan.KeysFromEKM(ekm, "AES-256-GCM")
	fake := clock.NewFake(time.Unix(1_000_000, 0))
	events := 0
	s := &Session{cfg: Config{Clock: fake, Events: func(e api.Event) {
		if e.Kind == api.EventPacketDropped {
			events++
		}
	}}, received: make(chan []byte, 4), base: fake.Now()}
	k := &key{id: 0, phase: active, opener: datachan.NewOpener(recv, 0, fake.Now)}
	s.keys, s.active = []*key{k}, k
	p, _, _ := datachan.NewSealer(srvSend, 0, 0).Seal(datachan.Frame([]byte{0x45, 1}))
	s.openData(p, 0)
	for range 100 {
		s.openData(p, 0)
	}
	if events > dropEventsPerSecond || s.dataReplay.Load() != 100 {
		t.Fatalf("%d drop events and %d replays counted; want at most %d and 100", events, s.dataReplay.Load(), dropEventsPerSecond)
	}
}

// TestCrossingSoftResets (finding 17): burrow and the server each send a
// soft reset for key 1 before either has seen the other's. Each takes the
// other's as its answer (spec notes 15.8, rule 2), and one negotiation
// reaches key 1.
func TestCrossingSoftResets(t *testing.T) {
	r := startReneg(t, fakeserver.Options{SendOnNewKey: true}, nil)
	r.s.keyMu.Lock()
	r.s.startNegotiationLocked(1, true)
	r.s.keyMu.Unlock()
	r.srv.Renegotiate()
	r.waitActive(t, 1, 3*time.Second)
	if n := len(r.times(api.EventRenegotiationStarted)); n != 1 {
		t.Fatalf("%d negotiations started, want 1", n)
	}
	r.echoes(t, 2, 0)
}
