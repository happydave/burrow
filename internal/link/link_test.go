package link

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// peer is a UDP socket on loopback standing in for a server.
func peer(t *testing.T) net.PacketConn {
	t.Helper()
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	return pc
}

func dial(t *testing.T, d Dialer, addr string) *Link {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	l, err := Dial(ctx, d, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func recv(t *testing.T, l *Link) []byte {
	t.Helper()
	select {
	case b := <-l.Packets():
		return b
	case <-time.After(5 * time.Second):
		t.Fatal("no datagram within 5 s")
		return nil
	}
}

// hello sends one datagram from the link so the peer learns its address.
func hello(t *testing.T, l *Link, pc net.PacketConn) net.Addr {
	t.Helper()
	if err := l.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if err := pc.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, from, err := pc.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("peer read %q, %v", buf[:n], err)
	}
	return from
}

func TestRoundTrip(t *testing.T) {
	pc := peer(t)
	l := dial(t, nil, pc.LocalAddr().String())
	from := hello(t, l, pc)
	if _, err := pc.WriteTo([]byte("world"), from); err != nil {
		t.Fatal(err)
	}
	if got := recv(t, l); string(got) != "world" {
		t.Fatalf("got %q", got)
	}
}

func TestOversizeDatagramDropped(t *testing.T) {
	pc := peer(t)
	l := dial(t, nil, pc.LocalAddr().String())
	from := hello(t, l, pc)
	if _, err := pc.WriteTo(make([]byte, 2049), from); err != nil {
		t.Fatal(err)
	}
	if _, err := pc.WriteTo(bytes.Repeat([]byte("k"), 2048), from); err != nil {
		t.Fatal(err)
	}
	if got := recv(t, l); len(got) != 2048 {
		t.Fatalf("first delivered datagram is %d bytes; the 2049-byte one should have been dropped", len(got))
	}
	if s := l.Stats(); s.Oversize != 1 {
		t.Fatalf("oversize count %d, want 1", s.Oversize)
	}
}

func TestFullQueueCountsDrops(t *testing.T) {
	pc := peer(t)
	l := dial(t, nil, pc.LocalAddr().String())
	from := hello(t, l, pc)
	// One datagram at a time, each waited for until it is queued or counted
	// as dropped, so the kernel's own socket buffer never drops any.
	deadline := time.Now().Add(10 * time.Second)
	for i := 0; l.Stats().QueueFull == 0; i++ {
		if time.Now().After(deadline) {
			t.Fatalf("after %d datagrams, none counted as dropped (queue holds %d)", i, len(l.Packets()))
		}
		before, dropped := len(l.Packets()), l.Stats().QueueFull
		if _, err := pc.WriteTo([]byte{byte(i)}, from); err != nil {
			t.Fatal(err)
		}
		for len(l.Packets()) == before && l.Stats().QueueFull == dropped && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond) // polling the link's counters, bounded by the deadline
		}
	}
	if len(l.Packets()) != QueueSize {
		t.Fatalf("queue holds %d when the first drop is counted, want %d", len(l.Packets()), QueueSize)
	}
}

func TestCloseStopsTheReader(t *testing.T) {
	pc := peer(t)
	l := dial(t, nil, pc.LocalAddr().String())
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-l.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the reader did not exit after Close")
	}
	if err := l.Err(); err != nil {
		t.Errorf("Close should end the reader without an error, got %v", err)
	}
	if err := l.Close(); err != nil {
		t.Errorf("a second Close returned %v", err)
	}
}

type recordingDialer struct {
	mu    sync.Mutex
	addrs []string
}

func (r *recordingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	r.mu.Lock()
	r.addrs = append(r.addrs, network+" "+address)
	r.mu.Unlock()
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

func TestInjectedDialer(t *testing.T) {
	pc := peer(t)
	d := &recordingDialer{}
	dial(t, d, pc.LocalAddr().String())
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.addrs) != 1 || d.addrs[0] != "udp "+pc.LocalAddr().String() {
		t.Fatalf("dialer saw %v", d.addrs)
	}
}
