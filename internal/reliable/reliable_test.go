package reliable

import (
	"bytes"
	"errors"
	"math"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/happydave/burrow/internal/wire"
)

var (
	sidC = wire.SessionID{0xc, 1, 2, 3, 4, 5, 6, 7}
	sidS = wire.SessionID{0x5, 9, 9, 9, 9, 9, 9, 9}
	t0   = time.Unix(1_000_000, 0)
)

func decode(t *testing.T, b []byte) wire.Control {
	t.Helper()
	c, err := wire.DecodeControl(b)
	if err != nil {
		t.Fatalf("Poll produced an undecodable packet: %v", err)
	}
	return c
}

// learned returns a client state that has learned the server's session ID
// from the server's hard reset, as it does after the first exchange.
func learned(t *testing.T) *State {
	t.Helper()
	s := New(Config{Own: sidC, ResetOp: wire.HardResetClientV2})
	s.Poll(t0) // sends the client reset, packet 0
	s.Receive(wire.Control{Op: wire.HardResetServerV2, Session: sidS, Acks: []uint32{0}, PeerSession: sidC, PacketID: 0})
	if _, ok := s.Peer(); !ok || !s.ResetReceived() {
		t.Fatal("the server's reset was not learned from")
	}
	s.Poll(t0) // flush the ACK of the server's reset
	return s
}

func ctl(id uint32, payload string) wire.Control {
	return wire.Control{Op: wire.ControlV1, Session: sidS, PacketID: id, Payload: []byte(payload)}
}

func read(s *State) string {
	b := make([]byte, ReadBufferSize)
	return string(b[:s.Read(b)])
}

func TestInOrderDelivery(t *testing.T) {
	s := learned(t)
	s.Receive(ctl(1, "a"))
	s.Receive(ctl(2, "b"))
	s.Receive(ctl(3, "c"))
	if got := read(s); got != "abc" {
		t.Fatalf("delivered %q, want abc", got)
	}
}

func TestReordering(t *testing.T) {
	s := learned(t)
	s.Receive(ctl(3, "c"))
	s.Receive(ctl(1, "a"))
	if got := read(s); got != "a" {
		t.Fatalf("with 2 missing, delivered %q, want a", got)
	}
	s.Receive(ctl(2, "b"))
	if got := read(s); got != "bc" {
		t.Fatalf("after the gap filled, delivered %q, want bc", got)
	}
	s.Receive(ctl(4+ReorderWindow, "far"))
	if got := read(s); got != "" || s.Stats().Drops[DropOutOfWindow] != 1 {
		t.Fatalf("a packet %d ahead was not dropped: %q, drops %v", ReorderWindow, got, s.Stats().Drops)
	}
}

func TestDuplicateIsAckedAgain(t *testing.T) {
	s := learned(t)
	s.Receive(ctl(1, "a"))
	s.Poll(t0)
	s.Receive(ctl(1, "a"))
	if got := read(s); got != "a" {
		t.Fatalf("delivered %q, want a once", got)
	}
	out := s.Poll(t0)
	if len(out) != 1 {
		t.Fatalf("want one ACK_V1 for the duplicate, got %d packets", len(out))
	}
	if c := decode(t, out[0]); c.Op != wire.AckV1 || len(c.Acks) != 1 || c.Acks[0] != 1 {
		t.Fatalf("want ACK_V1 of packet 1, got %+v", c)
	}
	if s.Stats().Drops[DropDuplicate] != 1 {
		t.Errorf("duplicate not counted: %v", s.Stats().Drops)
	}
}

func TestRetransmissionSchedule(t *testing.T) {
	s := learned(t)
	if _, err := s.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	first := s.Poll(t0)
	if len(first) != 1 {
		t.Fatalf("want one packet, got %d", len(first))
	}
	id := decode(t, first[0]).PacketID
	var resent []time.Duration
	for at := time.Duration(0); at <= 20*time.Second; at += 100 * time.Millisecond {
		for _, b := range s.Poll(t0.Add(at)) {
			c := decode(t, b)
			if c.PacketID != id || string(c.Payload) != "hello" {
				t.Fatalf("resent a different packet: %+v", c)
			}
			resent = append(resent, at)
		}
	}
	want := []time.Duration{2 * time.Second, 6 * time.Second, 14 * time.Second}
	if len(resent) != len(want) {
		t.Fatalf("resent at %v, want %v", resent, want)
	}
	for i := range want {
		if resent[i] != want[i] {
			t.Fatalf("resent at %v, want %v", resent, want)
		}
	}
	s.Receive(wire.Control{Op: wire.AckV1, Session: sidS, Acks: []uint32{id}, PeerSession: sidC})
	if out := s.Poll(t0.Add(time.Hour)); len(out) != 0 {
		t.Fatalf("resent %d packets after the ACK", len(out))
	}
}

func TestPiggybackedAndStandaloneAcks(t *testing.T) {
	s := learned(t)
	for id := uint32(1); id <= 6; id++ {
		s.Receive(ctl(id, "x"))
	}
	if _, err := s.Write([]byte("w")); err != nil {
		t.Fatal(err)
	}
	out := s.Poll(t0)
	if len(out) != 2 {
		t.Fatalf("want a CONTROL_V1 and an ACK_V1, got %d packets", len(out))
	}
	a, b := decode(t, out[0]), decode(t, out[1])
	// The server has ACKed none of our packets above 0, so the CONTROL_V1
	// repeats the ACK of its reset in one of its 4 slots (spec notes 4.4).
	if a.Op != wire.ControlV1 || len(a.Acks) != 4 || a.Acks[0] != 0 {
		t.Fatalf("first packet %+v, want CONTROL_V1 with ACK 0 and 3 more", a)
	}
	if b.Op != wire.AckV1 || len(b.Acks) != 3 {
		t.Fatalf("second packet %+v, want ACK_V1 with the other 3 ACKs", b)
	}
	if a.PeerSession != sidS || b.PeerSession != sidS {
		t.Error("ACKs must carry the server's session ID as peer")
	}
}

func TestFragmentation(t *testing.T) {
	s := learned(t)
	if _, err := s.Write(make([]byte, 3000)); err != nil {
		t.Fatal(err)
	}
	var sizes []int
	for _, b := range s.Poll(t0) {
		if len(b) > wire.MaxSend {
			t.Fatalf("packet of %d bytes over the %d limit", len(b), wire.MaxSend)
		}
		sizes = append(sizes, len(decode(t, b).Payload))
	}
	if len(sizes) != 3 || sizes[0] != 1184 || sizes[1] != 1184 || sizes[2] != 632 {
		t.Fatalf("payload sizes %v, want [1184 1184 632]", sizes)
	}
}

func TestWindowAndSendBuffer(t *testing.T) {
	s := learned(t)
	// Packet 0 (the reset) is acknowledged; 8 more fill the window.
	s.Receive(wire.Control{Op: wire.AckV1, Session: sidS, Acks: []uint32{0}, PeerSession: sidC})
	if _, err := s.Write(make([]byte, 9*wire.MaxControlPayload)); err != nil {
		t.Fatal(err)
	}
	if n := len(s.Poll(t0)); n != MaxInFlight {
		t.Fatalf("sent %d packets, want the window of %d", n, MaxInFlight)
	}
	if out := s.Poll(t0); len(out) != 0 {
		t.Fatalf("a ninth packet was sent with the window full")
	}
	s.Receive(wire.Control{Op: wire.AckV1, Session: sidS, Acks: []uint32{1}, PeerSession: sidC})
	if n := len(s.Poll(t0)); n != 1 {
		t.Fatalf("after one ACK, sent %d packets, want 1", n)
	}
	room := s.SendRoom()
	n, err := s.Write(make([]byte, room+10))
	if n != room || !errors.Is(err, ErrSendBufferFull) {
		t.Fatalf("Write past the buffer: %d, %v; want %d, ErrSendBufferFull", n, err, room)
	}
}

func TestSessionIDChecks(t *testing.T) {
	s := New(Config{Own: sidC, ResetOp: wire.HardResetClientV2})
	s.Poll(t0)
	forged := wire.SessionID{6, 6, 6, 6, 6, 6, 6, 6}
	// Before learning: a well-formed packet without our session ID in its
	// ACKs is refused, and the genuine reset that follows is learned from.
	s.Receive(wire.Control{Op: wire.ControlV1, Session: forged, PacketID: 0, Payload: []byte("x")})
	if _, ok := s.Peer(); ok || s.Stats().Drops[DropUnlearned] != 1 {
		t.Fatalf("learned from a packet that did not ACK our session ID: %v", s.Stats().Drops)
	}
	s.Receive(wire.Control{Op: wire.HardResetServerV2, Session: sidS, Acks: []uint32{0}, PeerSession: sidC})
	if p, ok := s.Peer(); !ok || p != sidS {
		t.Fatal("the genuine reset was not learned from")
	}
	s.Receive(wire.Control{Op: wire.ControlV1, Session: forged, PacketID: 1, Payload: []byte("evil")})
	s.Receive(wire.Control{Op: wire.ControlV1, Session: sidS, Acks: []uint32{0}, PeerSession: forged, PacketID: 1, Payload: []byte("evil")})
	if got := read(s); got != "" {
		t.Fatalf("delivered %q from forged packets", got)
	}
	d := s.Stats().Drops
	if d[DropBadSession] != 1 || d[DropBadPeerSession] != 1 {
		t.Fatalf("drops %v, want one bad session and one bad peer session", d)
	}
}

func TestBackpressure(t *testing.T) {
	s := learned(t)
	chunk := bytes.Repeat([]byte("z"), 1000)
	id := uint32(1)
	for s.Buffered()+len(chunk) <= ReadBufferSize {
		s.Receive(wire.Control{Op: wire.ControlV1, Session: sidS, PacketID: id, Payload: chunk})
		id++
	}
	s.Poll(t0)
	s.Receive(wire.Control{Op: wire.ControlV1, Session: sidS, PacketID: id, Payload: chunk})
	if s.Stats().Drops[DropReadBufferFull] != 1 {
		t.Fatalf("an overflowing packet was accepted: %v", s.Stats().Drops)
	}
	for _, b := range s.Poll(t0) {
		for _, a := range decode(t, b).Acks {
			if a == id {
				t.Fatal("the refused packet was ACKed")
			}
		}
	}
	read(s)
	s.Receive(wire.Control{Op: wire.ControlV1, Session: sidS, PacketID: id, Payload: chunk})
	if got := read(s); got != string(chunk) {
		t.Fatal("the retransmission was not accepted after the reader drained")
	}
}

func TestPacketIDLimit(t *testing.T) {
	s := learned(t)
	s.nextSend = math.MaxUint32 + 1
	if _, err := s.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if out := s.Poll(t0); len(out) != 0 {
		t.Fatalf("sent %d packets past the packet ID limit", len(out))
	}
	if s.Err() == nil {
		t.Fatal("no error at the packet ID limit")
	}
	if _, err := s.Write([]byte("y")); err == nil {
		t.Fatal("Write succeeded after the limit")
	}
}

// simLink is a simulated lossy datagram link between two States.
type simLink struct {
	rng                *rand.Rand
	loss, dup          float64
	reorder            int
	toServer, toClient [][]byte
}

func (l *simLink) send(q *[][]byte, b []byte) {
	if l.rng.Float64() < l.loss {
		return
	}
	*q = append(*q, b)
	if l.rng.Float64() < l.dup {
		*q = append(*q, b)
	}
	if n := len(*q); n > 1 && l.reorder > 1 {
		j := n - 1 - l.rng.IntN(min(l.reorder, n))
		(*q)[n-1], (*q)[j] = (*q)[j], (*q)[n-1]
	}
}

func deliver(t *testing.T, s *State, q *[][]byte) int {
	n := len(*q)
	for _, b := range *q {
		s.Receive(decode(t, b))
	}
	*q = nil
	return n
}

// transfer runs both sides to completion on simulated time and returns the
// simulated duration.
func transfer(t *testing.T, seed uint64, size int) time.Duration {
	rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	cli := New(Config{Own: sidC, ResetOp: wire.HardResetClientV2})
	srv := New(Config{Own: sidS, Peer: sidC, PeerKnown: true, ResetOp: wire.HardResetServerV2})
	l := &simLink{rng: rng, loss: 0.20, dup: 0.10, reorder: 5}
	cliData, srvData := make([]byte, size), make([]byte, size)
	for i := range cliData {
		cliData[i], srvData[i] = byte(rng.Uint32()), byte(rng.Uint32())
	}
	var cliGot, srvGot []byte
	var cliSent, srvSent int
	buf := make([]byte, ReadBufferSize)
	now := t0
	for step := 0; ; step++ {
		if step > 2_000_000 {
			t.Fatalf("seed %d: no completion after %d steps (client got %d, server got %d)", seed, step, len(cliGot), len(srvGot))
		}
		n, _ := cli.Write(cliData[cliSent:])
		cliSent += n
		if srv.ResetReceived() {
			n, _ = srv.Write(srvData[srvSent:])
			srvSent += n
		}
		moved := 0
		for _, b := range cli.Poll(now) {
			l.send(&l.toServer, b)
			moved++
		}
		if srv.ResetReceived() {
			for _, b := range srv.Poll(now) {
				l.send(&l.toClient, b)
				moved++
			}
		}
		moved += deliver(t, srv, &l.toServer) + deliver(t, cli, &l.toClient)
		cliGot = append(cliGot, buf[:cli.Read(buf)]...)
		srvGot = append(srvGot, buf[:srv.Read(buf)]...)
		if len(cliGot) == size && len(srvGot) == size && cli.Idle() && srv.Idle() {
			break
		}
		if moved == 0 {
			// The simulated server sends nothing until the client's reset
			// arrives, so until then only the client's timers move time.
			active := []*State{cli}
			if srv.ResetReceived() {
				active = append(active, srv)
			}
			next, ok := earliest(now, active...)
			if !ok {
				t.Fatalf("seed %d: stalled with nothing scheduled", seed)
			}
			now = next
		}
	}
	if !bytes.Equal(cliGot, srvData) || !bytes.Equal(srvGot, cliData) {
		t.Fatalf("seed %d: delivered streams differ from what was written", seed)
	}
	return now.Sub(t0)
}

func earliest(now time.Time, states ...*State) (time.Time, bool) {
	var at time.Time
	found := false
	for _, s := range states {
		if next, ok := s.NextPoll(); ok {
			if !next.After(now) {
				return now, true
			}
			if !found || next.Before(at) {
				at, found = next, true
			}
		}
	}
	return at, found
}

func TestTransferUnderLossDuplicationAndReordering(t *testing.T) {
	for seed := uint64(1); seed <= 20; seed++ {
		d := transfer(t, seed, 200<<10)
		t.Logf("seed %d: 200 KiB each way in %v of simulated time", seed, d)
	}
}

func FuzzReliableInput(f *testing.F) {
	reset, _ := wire.AppendControl(nil, wire.Control{Op: wire.HardResetServerV2, Session: sidS, Acks: []uint32{0}, PeerSession: sidC})
	data, _ := wire.AppendControl(nil, wire.Control{Op: wire.ControlV1, Session: sidS, PacketID: 1, Payload: []byte("hello")})
	f.Add(append([]byte{byte(len(reset))}, append(reset, append([]byte{byte(len(data))}, data...)...)...))
	f.Fuzz(func(t *testing.T, in []byte) {
		s := New(Config{Own: sidC, ResetOp: wire.HardResetClientV2})
		now := t0
		s.Poll(now)
		for len(in) > 0 {
			n := int(in[0])
			in = in[1:]
			n = min(n, len(in))
			pkt := in[:n]
			in = in[n:]
			if c, err := wire.DecodeControl(pkt); err == nil {
				s.Receive(c)
			}
			now = now.Add(time.Second)
			s.Poll(now)
			if s.Buffered()+s.heldBytes > ReadBufferSize || len(s.held) > ReorderWindow ||
				len(s.pendingAcks) > maxPendingAcks || len(s.flight) > MaxInFlight {
				t.Fatalf("a bound was exceeded: buffered %d held %d/%d acks %d flight %d",
					s.Buffered(), s.heldBytes, len(s.held), len(s.pendingAcks), len(s.flight))
			}
		}
	})
}

// TestFirstAckRepeatsUntilAnswered: until the server ACKs one of burrow's
// packets above 0, every CONTROL_V1, retransmissions included, carries the
// ACK of the server's reset, so a server that keeps no state until the
// third packet can still match them if the first ACK_V1 was lost (spec
// notes 4.4). It stops once the server ACKs packet 1.
func TestFirstAckRepeatsUntilAnswered(t *testing.T) {
	s := learned(t)                                                             // the lone ACK_V1 of the server's reset has gone
	if _, err := s.Write(make([]byte, wire.MaxControlPayload+10)); err != nil { // packets 1 and 2
		t.Fatal(err)
	}
	check := func(when string, out [][]byte, want bool) {
		t.Helper()
		n := 0
		for _, b := range out {
			c := decode(t, b)
			if c.Op != wire.ControlV1 {
				continue
			}
			n++
			if got := slices.Contains(c.Acks, 0); got != want || (len(c.Acks) > 0 && c.PeerSession != sidS) {
				t.Fatalf("%s: packet %d acks %v (peer %x), want ACK 0 %v", when, c.PacketID, c.Acks, c.PeerSession, want)
			}
		}
		if n == 0 {
			t.Fatalf("%s: no CONTROL_V1 sent", when)
		}
	}
	check("first send", s.Poll(t0), true)
	check("retransmission", s.Poll(t0.Add(InitialRetransmit)), true)
	s.Receive(wire.Control{Op: wire.AckV1, Session: sidS, Acks: []uint32{1}, PeerSession: sidC})
	check("after the server ACKed packet 1", s.Poll(t0.Add(time.Hour)), false)
}
