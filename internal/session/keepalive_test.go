package session

import (
	"slices"
	"testing"
	"time"

	"github.com/happydave/burrow/internal/api"
	"github.com/happydave/burrow/internal/clock"
	"github.com/happydave/burrow/internal/datachan"
)

func TestKeepaliveDecision(t *testing.T) {
	t0 := time.Unix(1_000_000, 0)
	ping, restart := 10*time.Second, 60*time.Second
	cases := []struct {
		name              string
		now, send, auth   time.Duration
		wantPing, wantExp bool
		wantNext          time.Duration
	}{
		{"just sent", 0, 0, 0, false, false, 10 * time.Second},
		{"idle 9.9 s", 9900 * time.Millisecond, 0, 0, false, false, 10 * time.Second},
		{"idle 10 s: ping", 10 * time.Second, 0, 0, true, false, 20 * time.Second},
		{"recent traffic defers the ping", 15 * time.Second, 12 * time.Second, 12 * time.Second, false, false, 22 * time.Second},
		{"59.9 s without an authenticated packet", 59900 * time.Millisecond, 59 * time.Second, 0, false, false, 60 * time.Second},
		{"60 s without one: expired", 60 * time.Second, 59 * time.Second, 0, false, true, 60 * time.Second},
		{"an authenticated packet at 50 s resets it", 100 * time.Second, 95 * time.Second, 50 * time.Second, false, false, 105 * time.Second},
	}
	for _, c := range cases {
		p, exp, next := keepalive(t0.Add(c.now), t0.Add(c.send), t0.Add(c.auth), ping, restart)
		if p != c.wantPing || exp != c.wantExp || !next.Equal(t0.Add(c.wantNext)) {
			t.Errorf("%s: ping=%v expired=%v next=+%v; want %v %v +%v", c.name, p, exp, next.Sub(t0), c.wantPing, c.wantExp, c.wantNext)
		}
	}
}

func TestOnlyAuthenticatedPacketsCountAsAlive(t *testing.T) {
	ekm := make([]byte, 256)
	for i := range ekm {
		ekm[i] = byte(i)
	}
	// The server's sealer uses the halves mirrored: its send half is ours to receive.
	srv := make([]byte, 256)
	copy(srv[0:128], ekm[128:256])
	copy(srv[128:256], ekm[0:128])
	srvSend, _, _ := datachan.KeysFromEKM(srv, "AES-256-GCM")
	_, recv, _ := datachan.KeysFromEKM(ekm, "AES-256-GCM")
	fake := clock.NewFake(time.Unix(1_000_000, 0))
	s := &Session{cfg: Config{Clock: fake}, received: make(chan []byte, 4), base: fake.Now()}
	k := &key{id: 0, phase: active, opener: datachan.NewOpener(recv, 0, fake.Now)}
	s.keys, s.active = []*key{k}, k
	s.mark(&s.lastAuth)
	sealer := datachan.NewSealer(srvSend, 0, 0)
	ping, _, _ := sealer.Seal(datachan.Frame(datachan.PingPayload))

	fake.Advance(30 * time.Second)
	forged := append([]byte(nil), ping...)
	forged[len(forged)-1] ^= 1
	s.openData(forged, 0)
	if got := s.stamp(&s.lastAuth); !got.Equal(time.Unix(1_000_000, 0)) {
		t.Fatal("a forged packet reset the keepalive")
	}
	s.openData(ping, 0)
	if got := s.stamp(&s.lastAuth); !got.Equal(fake.Now()) {
		t.Fatal("an authenticated ping did not reset the keepalive")
	}
	if s.pingsReceived.Load() != 1 || len(s.received) != 0 {
		t.Fatalf("the ping should be consumed, not delivered: pings %d, queued %d", s.pingsReceived.Load(), len(s.received))
	}
	if s.dataAuthFailed.Load() != 1 {
		t.Errorf("the forged packet was not counted")
	}
}

func TestDropEventsCarryTheReason(t *testing.T) {
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
	var reasons []string
	s := &Session{cfg: Config{Clock: fake, Events: func(e api.Event) {
		if e.Kind == api.EventPacketDropped {
			reasons = append(reasons, e.Reason)
		}
	}}, received: make(chan []byte, 1), base: fake.Now()}
	k := &key{id: 0, phase: active, opener: datachan.NewOpener(recv, 0, fake.Now)}
	s.keys, s.active = []*key{k}, k
	sealer := datachan.NewSealer(srvSend, 0, 0)
	p1, _, _ := sealer.Seal(datachan.Frame([]byte{0x45, 1}))
	p2, _, _ := sealer.Seal(datachan.Frame([]byte{0x45, 2}))
	forged := append([]byte(nil), p2...)
	forged[len(forged)-1] ^= 1
	s.openData(p1, 0)     // queued
	s.openData(p1, 0)     // replayed
	s.openData(forged, 0) // fails authentication
	s.openData(p2, 0)     // the queue of one is full
	want := []string{"replay", "authentication failed", "receive queue full"}
	if !slices.Equal(reasons, want) {
		t.Fatalf("drop reasons %q, want %q", reasons, want)
	}
	if got := s.bytesReceived.Load(); got != 2 {
		t.Fatalf("bytes received %d, want 2 (one IP packet of 2 bytes delivered)", got)
	}
}
