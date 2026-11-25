// Package reliable is the control channel's reliability layer for one key ID
// (spec notes sections 2 to 4). State is a pure state machine: a driver hands
// it received packets and the time, and sends the datagrams it returns. Conn
// presents its byte stream to crypto/tls.
package reliable

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
	"time"

	"github.com/happydave/burrow/internal/wire"
)

// Bounds and timings.
const (
	// MaxInFlight is how many packets may be unacknowledged at once.
	MaxInFlight = 8
	// ReorderWindow is how far ahead of the next expected packet ID a
	// packet may arrive and be held.
	ReorderWindow = 16
	// SendBufferSize bounds bytes written but not yet packetised.
	SendBufferSize = 64 << 10
	// ReadBufferSize bounds delivered bytes not yet read, plus held ones.
	ReadBufferSize = 64 << 10
	// maxPendingAcks bounds ACKs owed; past it the oldest are forgotten,
	// and the peer's retransmission earns a fresh one.
	maxPendingAcks = 64
	// InitialRetransmit and MaxRetransmit set the resend schedule: the
	// interval doubles from the first to the second (spec notes 3.4).
	InitialRetransmit = 2 * time.Second
	MaxRetransmit     = 16 * time.Second
)

// Errors.
var (
	ErrSendBufferFull = errors.New("reliable: send buffer full")
	ErrPacketIDLimit  = errors.New("reliable: packet ID limit reached")
	ErrClosed         = errors.New("reliable: closed")
)

// Drop reasons, counted in Stats.
const (
	DropBadSession = iota
	DropBadPeerSession
	DropUnlearned
	DropOutOfWindow
	DropDuplicate
	DropReadBufferFull
	DropAckUnsent
	DropMalformed
	numDrops
)

// DropNames names the drop reasons, indexed by the constants above.
var DropNames = [numDrops]string{"bad session", "bad peer session", "before peer learned",
	"out of window", "duplicate", "read buffer full", "ACK for unsent packet", "malformed"}

// Stats counts what a State has done.
type Stats struct {
	Sent, Resent, Received int
	Drops                  [numDrops]int
}

// Config sets up a State.
type Config struct {
	KeyID uint8
	Own   wire.SessionID
	// Peer is known for a renegotiated key ID; for key 0 it is learned from
	// the server's hard reset.
	Peer      wire.SessionID
	PeerKnown bool
	// ResetOp is the opcode of packet 0: HardResetClientV2 for key 0,
	// SoftResetV1 otherwise. Zero sends no reset.
	ResetOp wire.Opcode
	// Retransmit timings; zero means the defaults above.
	InitialRetransmit, MaxRetransmit time.Duration
}

type inflight struct {
	op       wire.Opcode
	payload  []byte
	lastSent time.Time
	interval time.Duration
	sent     bool
}

// State is the reliability state of one key ID. It is not safe for
// concurrent use; Conn serialises access.
type State struct {
	cfg       Config
	peer      wire.SessionID
	peerKnown bool

	nextSend uint64
	resetDue bool
	sendBuf  []byte
	flight   map[uint32]*inflight

	nextRecv      uint32
	held          map[uint32][]byte
	heldBytes     int
	readBuf       []byte
	resetReceived bool
	pendingAcks   []uint32
	// peerAckedOne is set once the peer has ACKed one of our packets with
	// ID 1 or higher. Until then every control packet repeats the ACK of
	// the peer's packet 0 (spec notes 4.4): a server that keeps no state
	// until the third packet matches it only by that ACK.
	peerAckedOne bool

	err   error
	stats Stats
}

// New returns a State for one key ID.
func New(cfg Config) *State {
	if cfg.InitialRetransmit == 0 {
		cfg.InitialRetransmit = InitialRetransmit
	}
	if cfg.MaxRetransmit == 0 {
		cfg.MaxRetransmit = MaxRetransmit
	}
	return &State{
		cfg:       cfg,
		peer:      cfg.Peer,
		peerKnown: cfg.PeerKnown,
		resetDue:  cfg.ResetOp != 0,
		flight:    map[uint32]*inflight{},
		held:      map[uint32][]byte{},
	}
}

// Write queues p for sending. It accepts what fits in the send buffer and
// returns ErrSendBufferFull with the count accepted when not all of p fits.
func (s *State) Write(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	room := SendBufferSize - len(s.sendBuf)
	n := min(room, len(p))
	s.sendBuf = append(s.sendBuf, p[:n]...)
	if n < len(p) {
		return n, ErrSendBufferFull
	}
	return n, nil
}

// SendRoom is how many bytes Write would accept now.
func (s *State) SendRoom() int { return SendBufferSize - len(s.sendBuf) }

// Read moves delivered bytes into p and returns how many.
func (s *State) Read(p []byte) int {
	n := copy(p, s.readBuf)
	s.readBuf = s.readBuf[n:]
	if len(s.readBuf) == 0 {
		s.readBuf = nil
	}
	return n
}

// Buffered is the number of delivered bytes not yet read.
func (s *State) Buffered() int { return len(s.readBuf) }

// ResetReceived reports whether the peer's reset (packet 0) has arrived.
func (s *State) ResetReceived() bool { return s.resetReceived }

// Peer returns the peer's session ID once known.
func (s *State) Peer() (wire.SessionID, bool) { return s.peer, s.peerKnown }

// Err returns the error that ended this key ID, if any.
func (s *State) Err() error { return s.err }

// Stats returns the counters.
func (s *State) Stats() Stats { return s.stats }

// Idle reports whether nothing is unacknowledged, queued or owed.
func (s *State) Idle() bool {
	return len(s.flight) == 0 && len(s.sendBuf) == 0 && !s.resetDue && len(s.pendingAcks) == 0
}

func (s *State) drop(reason int) { s.stats.Drops[reason]++ }

// Receive processes one decoded control packet of this key ID.
func (s *State) Receive(c wire.Control) {
	if s.peerKnown && c.Session != s.peer {
		s.drop(DropBadSession)
		return
	}
	if len(c.Acks) > 0 && c.PeerSession != s.cfg.Own {
		s.drop(DropBadPeerSession)
		return
	}
	if !s.peerKnown {
		if len(c.Acks) == 0 {
			s.drop(DropUnlearned)
			return
		}
		s.peer, s.peerKnown = c.Session, true
	}
	if c.Op == wire.AckV1 && len(c.Acks) == 0 {
		s.drop(DropMalformed)
		return
	}
	s.stats.Received++
	for _, a := range c.Acks {
		if a >= 1 {
			s.peerAckedOne = true
		}
		if _, ok := s.flight[a]; ok {
			delete(s.flight, a)
		} else if uint64(a) >= s.nextSend {
			s.drop(DropAckUnsent)
		}
		// An ACK for a packet already acknowledged is the peer repeating
		// recent ACKs (spec notes 2.4), and is not counted.
	}
	if c.Op == wire.AckV1 {
		return
	}
	id := c.PacketID
	switch {
	case id < s.nextRecv:
		s.drop(DropDuplicate)
		s.owe(id)
		return
	case uint64(id) >= uint64(s.nextRecv)+ReorderWindow:
		s.drop(DropOutOfWindow)
		return
	}
	if _, dup := s.held[id]; dup {
		s.drop(DropDuplicate)
		s.owe(id)
		return
	}
	isReset := c.Op == wire.HardResetServerV2 || c.Op == wire.HardResetClientV2 || c.Op == wire.SoftResetV1
	payload := c.Payload
	if isReset {
		payload = nil // a reset's payload is ignored (spec notes 4.2)
	}
	if len(s.readBuf)+s.heldBytes+len(payload) > ReadBufferSize {
		s.drop(DropReadBufferFull)
		return // not ACKed: the peer retransmits once the reader drains
	}
	if isReset {
		s.resetReceived = true
	}
	s.held[id] = append([]byte{}, payload...)
	s.heldBytes += len(payload)
	s.owe(id)
	for {
		p, ok := s.held[s.nextRecv]
		if !ok {
			break
		}
		delete(s.held, s.nextRecv)
		s.heldBytes -= len(p)
		s.readBuf = append(s.readBuf, p...)
		s.nextRecv++
	}
}

func (s *State) owe(id uint32) {
	for _, a := range s.pendingAcks {
		if a == id {
			return
		}
	}
	s.pendingAcks = append(s.pendingAcks, id)
	if len(s.pendingAcks) > maxPendingAcks {
		s.pendingAcks = s.pendingAcks[len(s.pendingAcks)-maxPendingAcks:]
	}
}

func (s *State) takeAcks(n int) []uint32 {
	n = min(n, len(s.pendingAcks))
	if n == 0 {
		return nil
	}
	a := append([]uint32(nil), s.pendingAcks[:n]...)
	s.pendingAcks = s.pendingAcks[n:]
	return a
}

// Poll returns the datagrams to send at now: new packets the window allows,
// retransmissions that are due, and ACK_V1s for ACKs still owed.
func (s *State) Poll(now time.Time) [][]byte {
	var out [][]byte
	s.fill()
	ids := make([]uint32, 0, len(s.flight))
	for id := range s.flight {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		f := s.flight[id]
		if f.sent && now.Before(f.lastSent.Add(f.interval)) {
			continue
		}
		if f.sent {
			f.interval = min(2*f.interval, s.cfg.MaxRetransmit)
			s.stats.Resent++
		} else {
			f.interval = s.cfg.InitialRetransmit
			f.sent = true
		}
		f.lastSent = now
		s.stats.Sent++
		out = append(out, s.encode(wire.Control{Op: f.op, PacketID: id, Payload: f.payload}, wire.MaxAcksPiggyback, f.op == wire.ControlV1))
	}
	for len(s.pendingAcks) > 0 && s.peerKnown {
		out = append(out, s.encode(wire.Control{Op: wire.AckV1}, wire.MaxAcksAck, false))
	}
	return out
}

// fill moves the reset and queued bytes into packets while the window allows.
func (s *State) fill() {
	for len(s.flight) < MaxInFlight && s.err == nil && (s.resetDue || len(s.sendBuf) > 0) {
		if s.nextSend > math.MaxUint32 {
			s.err = fmt.Errorf("%w: key ID %d", ErrPacketIDLimit, s.cfg.KeyID)
			return
		}
		id := uint32(s.nextSend)
		s.nextSend++
		if s.resetDue {
			s.resetDue = false
			s.flight[id] = &inflight{op: s.cfg.ResetOp}
			continue
		}
		n := min(len(s.sendBuf), wire.MaxControlPayload)
		p := append([]byte(nil), s.sendBuf[:n]...)
		s.sendBuf = s.sendBuf[n:]
		if len(s.sendBuf) == 0 {
			s.sendBuf = nil
		}
		s.flight[id] = &inflight{op: wire.ControlV1, payload: p}
	}
}

func (s *State) encode(c wire.Control, maxAcks int, repeatFirst bool) []byte {
	c.KeyID = s.cfg.KeyID
	c.Session = s.cfg.Own
	if s.peerKnown {
		if repeatFirst && s.resetReceived && !s.peerAckedOne && !slices.Contains(s.pendingAcks, 0) {
			// The repeat takes one slot; the owed ACKs keep their order.
			c.Acks = append([]uint32{0}, s.takeAcks(maxAcks-1)...)
		} else {
			c.Acks = s.takeAcks(maxAcks)
		}
		c.PeerSession = s.peer
	}
	b, err := wire.AppendControl(nil, c)
	if err != nil {
		// The sizes above are chosen so this cannot happen; a failure is a
		// bug in this package, not in the peer's input.
		panic(fmt.Sprintf("reliable: encoding a packet failed: %v", err))
	}
	return b
}

// NextPoll returns when Poll next has work, and false when it has none until
// new input arrives. A time not after now means immediately.
func (s *State) NextPoll() (time.Time, bool) {
	if (len(s.pendingAcks) > 0 && s.peerKnown) || ((s.resetDue || len(s.sendBuf) > 0) && len(s.flight) < MaxInFlight && s.err == nil) {
		return time.Time{}, true
	}
	var at time.Time
	found := false
	for _, f := range s.flight {
		if !f.sent {
			return time.Time{}, true
		}
		due := f.lastSent.Add(f.interval)
		if !found || due.Before(at) {
			at, found = due, true
		}
	}
	return at, found
}
