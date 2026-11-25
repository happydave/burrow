package session

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/happydave/burrow/internal/api"
	"github.com/happydave/burrow/internal/datachan"
	"github.com/happydave/burrow/internal/reliable"
	"github.com/happydave/burrow/internal/wire"
)

// Renegotiation defaults (spec notes 15.6 and 15.7).
const (
	DefaultRenegInterval = 3600 * time.Second
	defaultPromotion     = 60 * time.Second
	defaultTranWindow    = 3600 * time.Second
)

// phase is where a key ID is in its life (spec notes 15.7).
type phase int

const (
	negotiating phase = iota // TLS and key method 2 under way
	pending                  // installed: opens, does not yet seal
	active                   // seals and opens
	retiring                 // opens only, until the transition window ends
)

func (p phase) String() string {
	return [...]string{"negotiating", "pending", "active", "retiring"}[p]
}

// nextKeyID follows id: 0, then 1 to 7, and 7 is followed by 1 (spec notes
// 15.5).
func nextKeyID(id uint8) uint8 {
	if id >= 7 {
		return 1
	}
	return id + 1
}

// keyView is what the decisions below read of a live key. since is when
// the key's negotiation began, or for a retiring key, when the
// renegotiation that retired it began.
type keyView struct {
	id        uint8
	phase     phase
	since     time.Time
	installed time.Time
}

// schedule holds the renegotiation timings.
type schedule struct {
	renegInterval, promotion, tranWindow, handWindow time.Duration
}

// due is what the schedule says to do now.
type due struct {
	start, promote, dropRetiring, fail bool
	next                               time.Time
}

// decide is the renegotiation schedule: from the time, the live keys, and
// whether a sealer asked for a renegotiation, what is due now and when to
// look again. Each limit is reached at exactly its duration.
func (sc schedule) decide(now time.Time, keys []keyView, requested bool) due {
	d := due{next: now.Add(time.Hour)}
	at := func(t time.Time) bool {
		if !now.Before(t) {
			return true
		}
		if t.Before(d.next) {
			d.next = t
		}
		return false
	}
	var negotiatingKey, pendingKey bool
	for _, k := range keys {
		switch k.phase {
		case negotiating:
			negotiatingKey = true
			if at(k.since.Add(sc.handWindow)) {
				d.fail = true
			}
		case pending:
			pendingKey = true
			if at(k.installed.Add(sc.promotion)) {
				d.promote = true
			}
		case retiring:
			if at(k.since.Add(sc.tranWindow)) {
				d.dropRetiring = true
			}
		}
	}
	if negotiatingKey || pendingKey {
		return d
	}
	for _, k := range keys {
		if k.phase != active {
			continue
		}
		if requested {
			d.start = true
		} else if sc.renegInterval > 0 && at(k.since.Add(sc.renegInterval)) {
			d.start = true
		}
	}
	return d
}

// resetAction is what to do with a soft reset for a key ID that has no
// state yet.
type resetAction int

const (
	resetDrop resetAction = iota
	resetRespond
)

// softResetAction decides a server's soft reset for key id (spec notes
// 15.8): answer one for the key after the newest installed key, drop any
// other. One for the key burrow is negotiating never reaches here: it goes
// to that key's state as the answer to burrow's own (rule 2). So while a
// negotiation runs, every soft reset that reaches here is dropped (rule 4).
func softResetAction(id uint8, keys []keyView) resetAction {
	newest := -1
	for _, k := range keys {
		switch k.phase {
		case pending:
			newest = int(k.id)
		case active:
			if newest < 0 {
				newest = int(k.id)
			}
		}
	}
	if newest >= 0 && id == nextKeyID(uint8(newest)) {
		return resetRespond
	}
	return resetDrop
}

// makeRoom says how to bring the live keys down to one before a negotiation
// starts, so at most two are ever live: drop a retiring key; otherwise
// promote a pending key and drop the active one without retiring it (spec
// notes 15.7, last paragraph).
func makeRoom(keys []keyView) (drop []uint8, promote int) {
	promote = -1
	for _, k := range keys {
		if k.phase == retiring {
			drop = append(drop, k.id)
		}
	}
	if len(drop) > 0 {
		return drop, -1
	}
	for _, k := range keys {
		if k.phase == pending {
			promote = int(k.id)
		}
	}
	if promote >= 0 {
		for _, k := range keys {
			if k.phase == active {
				drop = append(drop, k.id)
			}
		}
	}
	return drop, promote
}

// key is one key ID's state.
type key struct {
	id        uint8
	st        *reliable.State
	conn      *reliable.Conn
	tc        *tls.Conn
	resetSeen chan struct{} // closed by the driver once the peer's reset is in
	resetOnce bool          // driver-owned

	// Guarded by Session.keyMu.
	phase     phase
	since     time.Time
	installed time.Time
	sealer    *datachan.Sealer
	opener    *datachan.Opener
	asked     bool   // this key's sealer asked for a renegotiation
	ekm       []byte // the key's exporter block, zeroed when it goes
}

// wipe zeroes the key's material, best effort. The
// caller holds keyMu.
func (k *key) wipe() {
	clear(k.ekm)
	if k.sealer != nil {
		k.sealer.Wipe()
	}
	if k.opener != nil {
		k.opener.Wipe()
	}
}

func (k *key) view() keyView {
	return keyView{id: k.id, phase: k.phase, since: k.since, installed: k.installed}
}

func (s *Session) newKey(id uint8, resetOp wire.Opcode, peer wire.SessionID, peerKnown bool, now time.Time) *key {
	st := reliable.New(reliable.Config{KeyID: id, Own: s.own, Peer: peer, PeerKnown: peerKnown, ResetOp: resetOp})
	return &key{id: id, st: st, conn: reliable.NewConn(st, s.cfg.Clock, s.wake, s.lk.LocalAddr(), s.lk.RemoteAddr()),
		resetSeen: make(chan struct{}), phase: negotiating, since: now}
}

// views returns the live keys' views; the caller holds keyMu.
func (s *Session) viewsLocked() []keyView {
	vs := make([]keyView, 0, len(s.keys))
	for _, k := range s.keys {
		vs = append(vs, k.view())
	}
	return vs
}

func (s *Session) findLocked(id uint8) *key {
	for _, k := range s.keys {
		if k.id == id {
			return k
		}
	}
	return nil
}

// dropLocked removes a key and closes its reliability state, which ends
// its TLS session and reader. The caller holds keyMu.
func (s *Session) dropLocked(k *key) {
	s.keys = slices.DeleteFunc(s.keys, func(x *key) bool { return x == k })
	k.conn.Do(func(st *reliable.State) { addReliable(&s.droppedReliable, st.Stats()) })
	k.conn.Close()
	k.wipe()
}

// promoteLocked makes the pending key active and retires the old active
// one, from when the new key's negotiation began. The caller holds keyMu.
func (s *Session) promoteLocked(k *key) {
	old := s.active
	k.phase = active
	s.active = k
	if old != nil && old != k {
		old.phase = retiring
		old.since = k.since
	}
	from := "none"
	if old != nil {
		from = fmt.Sprint(old.id)
	}
	s.event(api.Event{Kind: api.EventKeyTransition, Stage: api.StageEstablished, KeyID: k.id, Reason: fmt.Sprintf("key %s → %d", from, k.id)})
}

// startNegotiationLocked makes room and starts negotiating key id. The
// caller holds keyMu. A responder's first packet, the server's soft reset,
// is handed to the new state by the caller.
func (s *Session) startNegotiationLocked(id uint8, initiator bool) *key {
	drop, promote := makeRoom(s.viewsLocked())
	if promote >= 0 {
		s.promoteLocked(s.findLocked(uint8(promote)))
	}
	for _, d := range drop {
		if k := s.findLocked(d); k != nil {
			s.dropLocked(k)
		}
	}
	k := s.newKey(id, wire.SoftResetV1, s.serverSession, true, s.cfg.Clock.Now())
	s.keys = append(s.keys, k)
	side := "server"
	if initiator {
		side = "burrow"
	}
	s.event(api.Event{Kind: api.EventRenegotiationStarted, Stage: api.StageRenegotiation, KeyID: id, Reason: fmt.Sprintf("key %d, started by %s", id, side)})
	go s.negotiate(k)
	s.wake()
	return k
}

// negotiate runs one renegotiation: the peer's reset, TLS with the same
// verification as the first session, the key export, and key method 2. It
// runs off the driver. On success the key is installed as pending.
func (s *Session) negotiate(k *key) {
	err := s.renegotiate(k)
	if err == nil {
		return
	}
	select {
	case <-s.stop:
		return // the session is closing; not a failure
	default:
	}
	s.keyMu.Lock()
	live := s.findLocked(k.id) == k
	s.keyMu.Unlock()
	if !live {
		return // dropped by a newer negotiation
	}
	s.end(fail(api.StageRenegotiation, api.KindRenegotiationFailed, fmt.Errorf("key %d: %w", k.id, err)))
}

func (s *Session) renegotiate(k *key) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-s.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	deadline := k.since.Add(s.cfg.HandshakeWindow)
	if err := s.wait(ctx, k.resetSeen, deadline.Sub(s.cfg.Clock.Now())); err != nil {
		return fmt.Errorf("no soft reset from the server: %w", err)
	}
	if err := k.conn.SetDeadline(deadline); err != nil {
		return err
	}
	cfg := tlsConfig(s.cfg.CAs, s.cfg.Cert, s.cfg.Clock.Now)
	cfg.KeyLogWriter = s.cfg.KeyLog
	k.tc = tls.Client(k.conn, cfg)
	if err := k.tc.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("TLS: %w", err)
	}
	cs := k.tc.ConnectionState()
	ekm, err := cs.ExportKeyingMaterial("EXPORTER-OpenVPN-datakeys", nil, 256)
	if err != nil {
		return fmt.Errorf("exporting key material: %w", err)
	}
	if err := s.exchangeKeys(k.tc); err != nil {
		return err
	}
	send, recv, err := datachan.KeysFromEKM(ekm, s.Push.Cipher)
	if err != nil {
		return err
	}
	if err := k.conn.SetDeadline(time.Time{}); err != nil {
		return err
	}
	s.keyMu.Lock()
	select {
	case <-s.stop:
		// Teardown has wiped the keys; installing now would leave this
		// key's material behind.
		s.keyMu.Unlock()
		clear(ekm)
		return errors.New("session closing")
	default:
	}
	if s.findLocked(k.id) != k {
		s.keyMu.Unlock()
		clear(ekm)
		return errors.New("dropped while negotiating")
	}
	k.ekm = ekm
	k.sealer = datachan.NewSealer(send, k.id, s.Push.PeerID)
	k.opener = datachan.NewOpener(recv, k.id, s.cfg.Clock.Now)
	k.phase = pending
	k.installed = s.cfg.Clock.Now()
	s.keyMu.Unlock()
	s.renegotiations.Add(1)
	s.event(api.Event{Kind: api.EventRenegotiationFinished, Stage: api.StageRenegotiation, KeyID: k.id})
	go s.readMessages(k)
	s.wake()
	return nil
}
