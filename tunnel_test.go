package burrow

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/happydave/burrow/internal/admission"
	"github.com/happydave/burrow/internal/session"
)

// fakeConn stands in for a session: what is written goes to the peer's
// inbox, as a datagram network would carry it, dropping when full.
type fakeConn struct {
	in, peer  chan []byte
	ended     chan struct{}
	stop      chan struct{}
	err       error
	closeOnce sync.Once
	closes    int
	mu        sync.Mutex
}

func newFakePair() (*fakeConn, *fakeConn) {
	a, b := make(chan []byte, 1024), make(chan []byte, 1024)
	return &fakeConn{in: a, peer: b, ended: make(chan struct{}), stop: make(chan struct{})},
		&fakeConn{in: b, peer: a, ended: make(chan struct{}), stop: make(chan struct{})}
}

func (f *fakeConn) WritePacket(ip []byte) error {
	select {
	case <-f.stop:
		return net.ErrClosed
	default:
	}
	select {
	case f.peer <- bytes.Clone(ip):
	default:
	}
	return nil
}

func (f *fakeConn) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case ip := <-f.in:
		return ip, nil
	case <-f.stop:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (f *fakeConn) Ended() <-chan struct{} { return f.ended }
func (f *fakeConn) Err() error             { return f.err }
func (f *fakeConn) Stats() session.Stats   { return session.Stats{} }
func (f *fakeConn) Close() error {
	f.mu.Lock()
	f.closes++
	f.mu.Unlock()
	f.closeOnce.Do(func() { close(f.stop) })
	return nil
}

var (
	addrA = netip.MustParseAddr("10.88.0.6")
	addrB = netip.MustParseAddr("10.88.0.5")
)

// tunnelPair joins two tunnels with network stacks through a fake network.
func tunnelPair(t *testing.T, mtu int) (*Tunnel, *Tunnel) {
	t.Helper()
	ca, cb := newFakePair()
	ta, tb := newTunnel(nil), newTunnel(nil)
	if err := ta.start(ca, session.Push{Local: addrA, Remote: addrB}, nil, mtu); err != nil {
		t.Fatal(err)
	}
	if err := tb.start(cb, session.Push{Local: addrB, Remote: addrA}, nil, mtu); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeWithin(t, ta); closeWithin(t, tb) })
	return ta, tb
}

// closeWithin closes a tunnel and fails the test if Close does not return,
// which it cannot while a pump is stuck.
func closeWithin(t *testing.T, tn *Tunnel) {
	t.Helper()
	done := make(chan struct{})
	go func() { tn.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Error("Close did not return within 10 s: a pump did not exit")
	}
}

// within runs f and fails the test if it does not finish in d. A stack
// whose device goes unread wedges, ignoring socket deadlines, so
// only a watchdog outside it can name the failure.
func within(t *testing.T, d time.Duration, what string, f func() error) {
	t.Helper()
	errc := make(chan error, 1)
	go func() { errc <- f() }()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	case <-time.After(d):
		t.Fatalf("%s stalled for %v: a pump stopped moving packets", what, d)
	}
}

func TestLinkMTU(t *testing.T) {
	for _, c := range []struct {
		tun, mssfix int
		payload, v6 bool
		want        int
	}{
		{1500, 1492, false, false, 1439},
		{1500, 1492, false, true, 1419},
		{1400, 1492, false, false, 1400},
		{1500, 0, false, false, 1500},
		{0, 1492, false, false, 1439},
		{1450, 1410, true, false, 1385}, // the target profile's low-MTU variant (spec notes 18.3)
		{1500, 1410, true, true, 1385},  // payload semantics do not depend on the outer family
	} {
		if got := linkMTU(c.tun, c.mssfix, c.payload, c.v6); got != c.want {
			t.Errorf("linkMTU(%d, %d, payload=%v, v6=%v) = %d, want %d", c.tun, c.mssfix, c.payload, c.v6, got, c.want)
		}
	}
}

func TestConfigValidate(t *testing.T) {
	pool := x509.NewCertPool()
	for _, c := range []struct {
		name string
		cfg  Config
		want string
	}{
		{"no remote", Config{RootCAs: pool}, "Remotes"},
		{"no CA pool", Config{Remotes: []string{"127.0.0.1:1"}}, "RootCAs"},
		{"negative push timeout", Config{Remotes: []string{"127.0.0.1:1"}, RootCAs: pool, PushTimeout: -1}, "negative"},
		{"negative window", Config{Remotes: []string{"127.0.0.1:1"}, RootCAs: pool, HandshakeWindow: -1}, "negative"},
		{"no port", Config{Remotes: []string{"127.0.0.1"}, RootCAs: pool}, "127.0.0.1"},
		{"port 0", Config{Remotes: []string{"127.0.0.1:0"}, RootCAs: pool}, "65535"},
		{"tun-mtu 500", Config{Remotes: []string{"127.0.0.1:1"}, RootCAs: pool, TunMTU: 500}, "TunMTU"},
	} {
		// A dialer that fails the test shows nothing was sent.
		c.cfg.Dialer = failDialer{t}
		_, err := Connect(context.Background(), c.cfg)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want one naming %q", c.name, err, c.want)
		}
	}
}

type failDialer struct{ t *testing.T }

func (d failDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.t.Error("dialled despite an invalid config")
	return nil, errors.New("unreachable")
}

// TestDefaultGuard shows Connect guards attempts with no store configured:
// after three refused attempts to one host, the fourth is refused before
// it dials.
func TestDefaultGuard(t *testing.T) {
	saved := processStore
	processStore = &admission.Memory{}
	t.Cleanup(func() { processStore = saved })
	dials := 0
	d := dialFunc(func(context.Context, string, string) (net.Conn, error) {
		dials++
		return nil, errors.New("no route")
	})
	// Unreachable is not counted, so the history comes from records that
	// count: three refusals within the hour.
	for range 3 {
		id, err := processStore.Reserve("192.0.2.1", "192.0.2.1:1193", DefaultAdmissionPolicy, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := processStore.Complete(id, admission.Refused); err != nil {
			t.Fatal(err)
		}
	}
	_, err := Connect(context.Background(), Config{Remotes: []string{"192.0.2.1:1181"}, RootCAs: x509.NewCertPool(), Dialer: d})
	if !errors.Is(err, KindAdmissionRefused) {
		t.Fatalf("err = %v, want admission refused", err)
	}
	if dials != 0 {
		t.Fatalf("dialled %d times after the guard refused", dials)
	}
}

type dialFunc func(context.Context, string, string) (net.Conn, error)

func (f dialFunc) DialContext(ctx context.Context, n, a string) (net.Conn, error) {
	return f(ctx, n, a)
}

func TestTCPThroughStacks(t *testing.T) {
	ta, tb := tunnelPair(t, 1439)
	ln, err := tb.ListenTCP(netip.AddrPortFrom(addrB, 8080))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const size = 256 << 10
	up, down := make([]byte, size), make([]byte, size)
	rand.Read(up)
	rand.Read(down)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	serverErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(30 * time.Second))
		got := make([]byte, size)
		if _, err := io.ReadFull(c, got); err != nil {
			serverErr <- err
			return
		}
		if !bytes.Equal(got, up) {
			serverErr <- errors.New("server received different bytes")
			return
		}
		_, err = c.Write(down)
		serverErr <- err
	}()

	within(t, 30*time.Second, "the 256 KiB exchange", func() error {
		c, err := ta.DialContext(ctx, "tcp", "10.88.0.5:8080")
		if err != nil {
			return err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(30 * time.Second))
		if _, err := c.Write(up); err != nil {
			return fmt.Errorf("writing: %w", err)
		}
		got := make([]byte, size)
		if _, err := io.ReadFull(c, got); err != nil {
			return fmt.Errorf("reading back: %w", err)
		}
		if !bytes.Equal(got, down) {
			return errors.New("client received different bytes")
		}
		if err := <-serverErr; err != nil {
			return fmt.Errorf("server: %w", err)
		}
		return nil
	})
	if st := ta.Stats(); st.StackSent == 0 || st.StackReceived == 0 {
		t.Fatalf("stack counters did not move: %+v", st)
	}
}

func TestUDPThroughStacks(t *testing.T) {
	ta, tb := tunnelPair(t, 1439)
	pc, err := tb.ListenUDP(netip.AddrPortFrom(addrB, 5353))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	c, err := ta.DialContext(context.Background(), "udp", "10.88.0.5:5353")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 2048)
	for i := range 5 {
		msg := []byte{'d', byte('0' + i)}
		if _, err := c.Write(msg); err != nil {
			t.Fatal(err)
		}
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("datagram %d: %v", i, err)
		}
		if want := "echo:" + string(msg); string(buf[:n]) != want {
			t.Fatalf("datagram %d: got %q, want %q", i, buf[:n], want)
		}
	}
}

func TestRawMode(t *testing.T) {
	ca, cb := newFakePair()
	tr := newTunnel(nil)
	if err := tr.start(ca, session.Push{Local: addrA}, nil, 0); err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	pkt := []byte{0x45, 1, 2, 3}
	if err := tr.WritePacket(pkt); err != nil {
		t.Fatal(err)
	}
	if got := <-cb.in; !bytes.Equal(got, pkt) {
		t.Fatalf("peer got % x", got)
	}
	cb.peer <- []byte{0x45, 9}
	got, err := tr.ReadPacket(context.Background())
	if err != nil || !bytes.Equal(got, []byte{0x45, 9}) {
		t.Fatalf("ReadPacket = % x, %v", got, err)
	}
	if _, err := tr.DialContext(context.Background(), "tcp", "10.88.0.5:80"); !errors.Is(err, ErrRawMode) {
		t.Fatalf("DialContext in raw mode: %v", err)
	}
	if _, err := tr.ListenTCP(netip.AddrPortFrom(addrA, 80)); !errors.Is(err, ErrRawMode) {
		t.Fatalf("ListenTCP in raw mode: %v", err)
	}

	ts, _ := tunnelPair(t, 1439)
	if _, err := ts.ReadPacket(context.Background()); !errors.Is(err, ErrStackMode) {
		t.Fatalf("ReadPacket with a stack: %v", err)
	}
	if err := ts.WritePacket(pkt); !errors.Is(err, ErrStackMode) {
		t.Fatalf("WritePacket with a stack: %v", err)
	}
}

func TestEventsNeverBlock(t *testing.T) {
	tn := newTunnel(nil)
	done := make(chan struct{})
	go func() {
		for i := range 300 {
			tn.emit(Event{Kind: EventRetransmit, PacketID: uint32(i)})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("emit blocked with no reader")
	}
	if n := len(tn.events); n != EventQueue {
		t.Fatalf("queued %d, want %d", n, EventQueue)
	}
	for range EventQueue {
		if e := <-tn.events; e.Lost != 0 {
			t.Fatalf("event %d reports Lost %d before any loss", e.PacketID, e.Lost)
		}
	}
	tn.emit(Event{Kind: EventRetransmit, PacketID: 300})
	if e := <-tn.events; e.Lost != 44 {
		t.Fatalf("next event Lost = %d, want 44", e.Lost)
	}
	tn.emit(Event{Kind: EventRetransmit})
	if e := <-tn.events; e.Lost != 0 {
		t.Fatalf("Lost = %d after it was reported, want 0", e.Lost)
	}
}

func TestCloseAndEnd(t *testing.T) {
	ta, tb := tunnelPair(t, 1439)
	if err := ta.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ta.Done():
	default:
		t.Fatal("Done open after Close returned")
	}
	if ta.Err() != nil {
		t.Fatalf("Err after a clean Close = %v", ta.Err())
	}
	ta.Close() // idempotent
	if _, err := ta.DialContext(context.Background(), "tcp", "10.88.0.5:80"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("DialContext after Close: %v", err)
	}
	if _, err := tb.DialContext(context.Background(), "unix", "/x"); err == nil || !strings.Contains(err.Error(), "unix") {
		t.Fatalf("unix dial: %v, want an error naming it", err)
	}

	// The session ending on its own ends the tunnel with its error.
	ca, _ := newFakePair()
	tn := newTunnel(nil)
	if err := tn.start(ca, session.Push{Local: addrA}, nil, 1439); err != nil {
		t.Fatal(err)
	}
	ca.err = &Error{Stage: StageEstablished, Kind: KindKeepaliveTimeout}
	close(ca.ended)
	select {
	case <-tn.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("tunnel did not end with its session")
	}
	if !errors.Is(tn.Err(), KindKeepaliveTimeout) {
		t.Fatalf("Err = %v, want keepalive timeout", tn.Err())
	}
	tn.Close()
	if !errors.Is(tn.Err(), KindKeepaliveTimeout) {
		t.Fatalf("Close replaced the ending error: %v", tn.Err())
	}
}
