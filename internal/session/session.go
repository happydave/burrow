// Package session is burrow's control session: hard reset, TLS, key method
// 2, push and the server's control messages, over the reliability layer and
// the UDP link.
package session

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/happydave/burrow/internal/admission"
	"github.com/happydave/burrow/internal/api"
	"github.com/happydave/burrow/internal/clock"
	"github.com/happydave/burrow/internal/datachan"
	"github.com/happydave/burrow/internal/link"
	"github.com/happydave/burrow/internal/reliable"
	"github.com/happydave/burrow/internal/wire"
)

// Defaults (spec notes 15.6: hand-window).
const (
	DefaultPushTimeout     = 60 * time.Second
	DefaultHandshakeWindow = 60 * time.Second
	pushRepeat             = 2 * time.Second
	exitWait               = 2 * time.Second
)

// Config is what a session needs.
type Config struct {
	Remote          string // host:port, UDP
	CAs             *x509.CertPool
	Cert            tls.Certificate
	PushTimeout     time.Duration
	HandshakeWindow time.Duration
	// ResetTimeout bounds the wait for the server's answer to the hard
	// reset (server-poll-timeout); zero, or a value beyond the handshake
	// window, means the window.
	ResetTimeout time.Duration
	Clock        clock.Clock
	Dialer       link.Dialer
	Events       func(api.Event) // called synchronously, sometimes under the session's locks: must not block or call back into the session
	Version      string          // for IV_VER
	// Guard, when set, decides whether the attempt may start and records
	// its outcome (internal/admission).
	Guard *Guard
	// RenegInterval is how long a key lasts before burrow renegotiates; zero
	// means DefaultRenegInterval, negative disables burrow's own (the server's
	// still run).
	RenegInterval time.Duration

	// ExitWait bounds Close's wait for EXIT to be acknowledged; zero means
	// 2 s.
	ExitWait time.Duration
	// KeyLog, when set, receives every TLS session's secrets in the NSS
	// key-log format. It defeats the encryption of anything captured, and is
	// for debugging burrow's own sessions only.
	KeyLog io.Writer

	// Test settings; zero means the spec notes' defaults.
	promotion, tranWindow time.Duration
}

// Guard is the admission guard a connect goes through.
type Guard struct {
	Store  admission.Store
	Policy admission.Policy
	Domain string // empty: the remote's host
}

// Session is an established control session.
type Session struct {
	cfg  Config
	lk   *link.Link
	kick chan struct{}
	stop chan struct{}
	own  wire.SessionID
	// serverSession is learned from the hard reset, then fixed for the
	// session's life: soft resets keep it (spec notes 15.3, O13).
	serverSession wire.SessionID
	k0            *key // the first key, which carries the handshake and push

	driverDone chan struct{}
	msgs       chan message
	seenLink   link.Stats // the driver's last look at the link's drops

	dropEventsMu     sync.Mutex
	dropEventsSecond int64
	dropEvents       map[string]int

	// Set once Connect returns.
	Push Push
	EKM  []byte
	TLS  tls.ConnectionState
	// ServerKeyLength and ServerKeyPreMaster describe the server's
	// key-method-2 message, which spec notes 6.4 leaves to observation.
	ServerKeyLength    int
	ServerKeyPreMaster bool

	closeOnce sync.Once
	ended     chan struct{} // closed when the server ends the session
	endErr    error
	mu        sync.Mutex

	dataDropped, otherKeyDropped, undecodable atomic.Int64

	// The live keys, at most two (keys.go). keyMu guards them, their
	// phases, sealers and openers; the driver opens, writers seal.
	keyMu      sync.Mutex
	keys       []*key
	active     *key
	renegAsked atomic.Bool
	sched      schedule

	renegotiations, softResetsDropped, renegKeyMessages atomic.Int64
	bytesSent, bytesReceived                            atomic.Int64
	droppedReliable                                     reliable.Stats // dropped keys' counts; guarded by keyMu

	received                                                        chan []byte
	base                                                            time.Time    // the clock at connect; lastAuth and lastSend count from it
	lastAuth                                                        atomic.Int64 // since base, the last authenticated data packet
	lastSend                                                        atomic.Int64
	dataOpened, dataAuthFailed, dataReplay, unframed, recvQueueFull atomic.Int64
	pingsSent, pingsReceived                                        atomic.Int64
	established                                                     atomic.Bool
}

// defaultPingRestart applies until a server pushes its own (spec notes 14.4).
const defaultPingRestart = 120 * time.Second

// keepalive is the keepalive decision, from the times of the last send and
// the last authenticated packet: whether to send a ping now, whether the
// tunnel has expired, and when to look again. A zero interval disables its
// half.
func keepalive(now, lastSend, lastAuth time.Time, ping, restart time.Duration) (sendPing, expired bool, next time.Time) {
	far := now.Add(time.Hour)
	next = far
	if restart > 0 {
		at := lastAuth.Add(restart)
		if !now.Before(at) {
			return false, true, now
		}
		next = at
	}
	if ping > 0 {
		at := lastSend.Add(ping)
		if !now.Before(at) {
			sendPing, at = true, now.Add(ping)
		}
		if at.Before(next) {
			next = at
		}
	}
	return sendPing, false, next
}

// receiveQueue bounds opened IP packets waiting for the reader.
const receiveQueue = 256

func fail(stage api.Stage, kind api.Kind, err error) error {
	return &api.Error{Stage: stage, Kind: kind, Err: err}
}

func (s *Session) event(e api.Event) {
	if s.cfg.Events != nil {
		e.Time = s.cfg.Clock.Now()
		s.cfg.Events(e)
	}
}

// Connect runs the connect sequence up to an established session. ctx
// bounds the whole sequence. With a guard, the attempt is reserved before
// anything is sent, and its classified outcome is recorded on every return.
func Connect(ctx context.Context, cfg Config) (*Session, error) {
	if cfg.Clock == nil {
		cfg.Clock = clock.Real()
	}
	if cfg.Guard == nil {
		return connect(ctx, cfg)
	}
	g := cfg.Guard
	id, err := g.Store.Reserve(admission.Domain(g.Domain, cfg.Remote), cfg.Remote, g.Policy, cfg.Clock.Now())
	if err != nil {
		return nil, fail(api.StageLink, api.KindAdmissionRefused, err)
	}
	s, err := connect(ctx, cfg)
	if cerr := g.Store.Complete(id, admission.Classify(err)); cerr != nil && err == nil {
		// The attempt succeeded but its record could not be completed; it
		// stays pending, which counts against the domain until it ages out.
		s.event(api.Event{Kind: api.EventControlMessage, Stage: api.StageEstablished, Reason: "admission record: " + cerr.Error()})
	}
	return s, err
}

func connect(ctx context.Context, cfg Config) (*Session, error) {
	if cfg.PushTimeout == 0 {
		cfg.PushTimeout = DefaultPushTimeout
	}
	if cfg.HandshakeWindow == 0 {
		cfg.HandshakeWindow = DefaultHandshakeWindow
	}
	if cfg.ExitWait == 0 {
		cfg.ExitWait = exitWait
	}
	if cfg.RenegInterval == 0 {
		cfg.RenegInterval = DefaultRenegInterval
	}
	if cfg.promotion == 0 {
		cfg.promotion = defaultPromotion
	}
	if cfg.tranWindow == 0 {
		cfg.tranWindow = defaultTranWindow
	}
	s := &Session{cfg: cfg, kick: make(chan struct{}, 1), stop: make(chan struct{}),
		driverDone: make(chan struct{}),
		msgs:       make(chan message, 16), ended: make(chan struct{}), received: make(chan []byte, receiveQueue),
		sched: schedule{renegInterval: cfg.RenegInterval, promotion: cfg.promotion, tranWindow: cfg.tranWindow, handWindow: cfg.HandshakeWindow},
		base:  cfg.Clock.Now()}

	s.event(api.Event{Kind: api.EventStageEntered, Stage: api.StageLink})
	lk, err := link.Dial(ctx, cfg.Dialer, cfg.Remote)
	if err != nil {
		return nil, fail(api.StageLink, api.KindUnreachable, err)
	}
	s.lk = lk
	s.done(api.StageLink)
	if _, err := rand.Read(s.own[:]); err != nil {
		lk.Close()
		return nil, fail(api.StageLink, api.KindInternalFailure, err)
	}
	s.k0 = s.newKey(0, wire.HardResetClientV2, wire.SessionID{}, false, cfg.Clock.Now())
	s.keys = []*key{s.k0}
	go s.drive()
	s.wake()

	if err := s.handshake(ctx); err != nil {
		// A session that ended on its own (its link failed, say) reports
		// that cause, not the step it interrupted.
		if e := s.Err(); e != nil {
			err = e
		}
		s.teardown()
		return nil, err
	}
	return s, nil
}

func (s *Session) wake() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// drive is the session's one goroutine for packets and timers.
func (s *Session) drive() {
	defer close(s.driverDone)
	timer := s.cfg.Clock.NewTimer(time.Hour)
	defer timer.Stop()
	linkDone := s.lk.Done()
	for {
		select {
		case <-s.stop:
			return
		case b := <-s.lk.Packets():
			s.route(b)
		case <-linkDone:
			// The reader has stopped on an error it cannot get past: the
			// session cannot receive, so it ends with the cause.
			linkDone = nil
			s.end(fail(s.currentStage(), api.KindUnreachable, fmt.Errorf("link: %w", s.lk.Err())))
		case <-s.kick:
		case <-timer.C():
		}
		s.keyMu.Lock()
		keys := slices.Clone(s.keys)
		s.keyMu.Unlock()
		now := s.cfg.Clock.Now()
		wait := time.Hour
		for _, k := range keys {
			var pkts [][]byte
			var next time.Time
			var due, reset bool
			var resent int
			k.conn.Do(func(st *reliable.State) {
				before := st.Stats().Resent
				pkts = st.Poll(now)
				resent = st.Stats().Resent - before
				next, due = st.NextPoll()
				reset = st.ResetReceived()
			})
			if resent > 0 {
				s.event(api.Event{Kind: api.EventRetransmit, Stage: s.currentStage(), KeyID: k.id, Reason: fmt.Sprintf("%d control packets resent", resent)})
			}
			for _, b := range pkts {
				_ = s.lk.Write(b) // a lost datagram is retransmitted
			}
			if reset && !k.resetOnce {
				k.resetOnce = true
				close(k.resetSeen)
			}
			if due {
				wait = min(wait, max(next.Sub(now), 0))
			}
		}
		s.linkDrops()
		// After the session has ended, nothing is scheduled: a keepalive
		// that has expired would otherwise rearm a zero wait for ever.
		running := s.established.Load() && !s.hasEnded()
		if running {
			wait = min(wait, s.applySchedule(now))
		}
		if running {
			restart := s.Push.PingRestart
			if !s.Push.PingRestartSet {
				restart = defaultPingRestart
			}
			ping, expired, at := keepalive(now, s.stamp(&s.lastSend), s.stamp(&s.lastAuth), s.Push.Ping, restart)
			if expired {
				s.end(fail(api.StageEstablished, api.KindKeepaliveTimeout, fmt.Errorf("no authenticated data packet for %v", restart)))
			} else if ping {
				if err := s.sendPing(); err == nil {
					s.pingsSent.Add(1)
				}
			}
			wait = min(wait, max(at.Sub(now), 0))
		}
		timer.Reset(wait)
	}
}

// fromServer reports whether a control packet carries this session's IDs:
// the server's session ID, and burrow's as the peer when it ACKs anything
// (spec notes 2.5). Nothing acts on a packet before this holds; the
// reliability state checks it again for the packets it takes.
func (s *Session) fromServer(c wire.Control) bool {
	return c.Session == s.serverSession && (len(c.Acks) == 0 || c.PeerSession == s.own)
}

// currentStage is the stage events report from the driver: established
// once the push is done, the handshake before.
func (s *Session) currentStage() api.Stage {
	if s.established.Load() {
		return api.StageEstablished
	}
	return api.StageHardReset
}

// linkDrops reports datagrams the link dropped since the driver last
// looked. It runs on the driver only.
func (s *Session) linkDrops() {
	ls := s.lk.Stats()
	if d := ls.Oversize - s.seenLink.Oversize; d > 0 {
		s.event(api.Event{Kind: api.EventPacketDropped, Stage: s.currentStage(), Reason: fmt.Sprintf("oversize datagram (%d)", d)})
	}
	if d := ls.QueueFull - s.seenLink.QueueFull; d > 0 {
		s.event(api.Event{Kind: api.EventPacketDropped, Stage: s.currentStage(), Reason: fmt.Sprintf("link queue full (%d)", d)})
	}
	s.seenLink = ls
}

func (s *Session) route(b []byte) {
	op, key, err := wire.Header(b)
	switch {
	case err != nil:
		s.undecodable.Add(1)
	case wire.IsData(op):
		s.openData(b, key)
	default:
		c, err := wire.DecodeControl(b)
		if err != nil {
			s.undecodable.Add(1)
			return
		}
		s.keyMu.Lock()
		k := s.findLocked(key)
		if k == nil && op == wire.SoftResetV1 && s.established.Load() && s.fromServer(c) && softResetAction(key, s.viewsLocked()) == resetRespond {
			k = s.startNegotiationLocked(key, false)
		}
		s.keyMu.Unlock()
		if k == nil {
			s.otherKeyDropped.Add(1)
			if op == wire.SoftResetV1 {
				s.softResetsDropped.Add(1)
			}
			if s.allowDropEvent("other key") {
				s.event(api.Event{Kind: api.EventPacketDropped, Stage: api.StageEstablished, KeyID: key, PacketID: c.PacketID,
					Reason: fmt.Sprintf("other key: op %d key %d session %x peer %x packet %d acks %v payload %d bytes",
						c.Op, c.KeyID, c.Session, c.PeerSession, c.PacketID, c.Acks, len(c.Payload))})
			}
			return
		}
		k.conn.Do(func(st *reliable.State) { st.Receive(c) })
	}
}

func (s *Session) stage(st api.Stage) {
	s.event(api.Event{Kind: api.EventStageEntered, Stage: st})
}

func (s *Session) done(st api.Stage) {
	s.event(api.Event{Kind: api.EventStageCompleted, Stage: st})
}

// wait blocks on ch, the context, or a timeout on the session's clock.
func (s *Session) wait(ctx context.Context, ch <-chan struct{}, d time.Duration) error {
	t := s.cfg.Clock.NewTimer(d)
	defer t.Stop()
	select {
	case <-ch:
		return nil
	case <-s.ended:
		return errEnded
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C():
		return errTimeout
	}
}

// errEnded is a wait cut short because the session ended; Err says why.
var errEnded = errors.New("session ended")

var errTimeout = errors.New("timed out")

func (s *Session) handshake(ctx context.Context) error {
	window := s.cfg.HandshakeWindow
	resetWait := window
	if t := s.cfg.ResetTimeout; t > 0 && t < window {
		resetWait = t
	}
	s.stage(api.StageHardReset)
	if err := s.wait(ctx, s.k0.resetSeen, resetWait); err != nil {
		if errors.Is(err, errTimeout) {
			return fail(api.StageHardReset, api.KindUnreachable, fmt.Errorf("no answer to the hard reset within %v", resetWait))
		}
		return fail(api.StageHardReset, api.KindCanceled, err)
	}
	s.k0.conn.Do(func(st *reliable.State) { s.serverSession, _ = st.Peer() })
	s.done(api.StageHardReset)

	s.stage(api.StageTLS)
	cfg := tlsConfig(s.cfg.CAs, s.cfg.Cert, s.cfg.Clock.Now)
	cfg.KeyLogWriter = s.cfg.KeyLog
	s.k0.tc = tls.Client(s.k0.conn, cfg)
	if err := s.k0.conn.SetDeadline(s.cfg.Clock.Now().Add(window)); err != nil {
		return fail(api.StageTLS, api.KindInternalFailure, err)
	}
	if err := s.k0.tc.HandshakeContext(ctx); err != nil {
		if errors.Is(err, errCertRejected) {
			return fail(api.StageTLS, api.KindCertRejected, err)
		}
		if ctx.Err() != nil {
			return fail(api.StageTLS, api.KindCanceled, err)
		}
		return fail(api.StageTLS, api.KindTLS, err)
	}
	s.TLS = s.k0.tc.ConnectionState()
	ekm, err := s.TLS.ExportKeyingMaterial("EXPORTER-OpenVPN-datakeys", nil, 256)
	if err != nil {
		s.sendExit()
		return fail(api.StageTLS, api.KindTLS, fmt.Errorf("exporting key material: %w", err))
	}
	s.EKM = ekm
	s.k0.ekm = ekm
	s.done(api.StageTLS)

	if err := s.keyExchange(); err != nil {
		s.sendExit()
		return err
	}
	if err := s.push(ctx); err != nil {
		s.sendExit()
		return err
	}
	if err := s.setupData(); err != nil {
		s.sendExit()
		return err
	}
	s.established.Store(true)
	s.wake()
	// Established: the push deadline no longer applies.
	if err := s.k0.conn.SetDeadline(time.Time{}); err != nil {
		return fail(api.StageEstablished, api.KindInternalFailure, err)
	}
	go s.monitor()
	return nil
}

func (s *Session) keyExchange() error {
	s.stage(api.StageKeyExchange)
	km, err := s.exchangeKeysMessage(s.k0.tc)
	if err != nil {
		var e *api.Error
		if errors.As(err, &e) {
			return err
		}
		return fail(api.StageKeyExchange, api.KindKeyExchange, err)
	}
	s.ServerKeyLength, s.ServerKeyPreMaster = km.length, km.preMaster
	s.done(api.StageKeyExchange)
	go s.readMessages(s.k0)
	return nil
}

// exchangeKeys runs key method 2 on a renegotiated key's TLS session.
func (s *Session) exchangeKeys(tc *tls.Conn) error {
	if _, err := s.exchangeKeysMessage(tc); err != nil {
		return fmt.Errorf("key method 2: %w", err)
	}
	s.renegKeyMessages.Add(1)
	return nil
}

// exchangeKeysMessage sends burrow's key-method-2 message and reads the
// server's.
func (s *Session) exchangeKeysMessage(tc *tls.Conn) (serverKeyMessage, error) {
	msg, err := clientKeyMessage(s.cfg.Version)
	if err != nil {
		return serverKeyMessage{}, fail(api.StageKeyExchange, api.KindInternalFailure, err)
	}
	if _, err := tc.Write(msg); err != nil {
		return serverKeyMessage{}, err
	}
	buf := make([]byte, maxKeyMessage+1)
	n, err := tc.Read(buf)
	if err != nil {
		return serverKeyMessage{}, err
	}
	return parseServerKeyMessage(buf[:n])
}

// message is one control message from a key's TLS session, or the error
// that ended that key's reader.
type message struct {
	k   *key
	m   string
	err error
}

// readMessages hands one key's control messages over until its TLS session
// ends.
func (s *Session) readMessages(k *key) {
	r := &messageReader{r: k.tc}
	for {
		m, err := r.next()
		select {
		case s.msgs <- message{k: k, m: m, err: err}:
		case <-s.stop:
			return
		}
		if err != nil {
			return
		}
	}
}

func (s *Session) writeMessage(m string) error {
	s.keyMu.Lock()
	k := s.active
	s.keyMu.Unlock()
	if k == nil {
		k = s.k0
	}
	_, err := k.tc.Write(append([]byte(m), 0))
	return err
}

func (s *Session) push(ctx context.Context) error {
	s.stage(api.StagePush)
	if err := s.writeMessage("PUSH_REQUEST"); err != nil {
		return fail(api.StagePush, api.KindClosedByServer, err)
	}
	deadline := s.cfg.Clock.NewTimer(s.cfg.PushTimeout)
	defer deadline.Stop()
	repeat := s.cfg.Clock.NewTimer(pushRepeat)
	defer repeat.Stop()
	var asm pushAssembler
	started := false
	for {
		select {
		case <-ctx.Done():
			return fail(api.StagePush, api.KindCanceled, ctx.Err())
		case <-deadline.C():
			return fail(api.StagePush, api.KindNotAdmitted, fmt.Errorf("no PUSH_REPLY within %v", s.cfg.PushTimeout))
		case <-repeat.C():
			if !started {
				if err := s.writeMessage("PUSH_REQUEST"); err != nil {
					return fail(api.StagePush, api.KindClosedByServer, err)
				}
			}
			repeat.Reset(pushRepeat)
		case it := <-s.msgs:
			if it.err != nil {
				if errors.Is(it.err, errMessageTooLong) {
					return fail(api.StagePush, api.KindMessageTooLong, it.err)
				}
				if errors.Is(it.err, os.ErrDeadlineExceeded) {
					return fail(api.StagePush, api.KindNotAdmitted, fmt.Errorf("no PUSH_REPLY within the handshake window of %v", s.cfg.HandshakeWindow))
				}
				return fail(api.StagePush, api.KindClosedByServer, it.err)
			}
			m := it.m
			if end := serverEnd(m); end != nil {
				return s.endFailure(api.StagePush, end)
			}
			if messageName(m) != "PUSH_REPLY" {
				s.otherMessage(m)
				continue
			}
			started = true
			complete, err := asm.add(m)
			if err != nil {
				return fail(api.StagePush, api.KindUnsupportedPush, err)
			}
			if !complete {
				continue
			}
			p, err := parsePush(asm.options)
			if err != nil {
				return fail(api.StagePush, api.KindUnsupportedPush, err)
			}
			s.Push = p
			s.done(api.StagePush)
			return nil
		}
	}
}

func (s *Session) endFailure(stage api.Stage, end *endError) error {
	kind := api.KindClosedByServer
	switch end.kind {
	case endAuthFailed:
		kind = api.KindAuthFailed
	case endHalted:
		kind = api.KindHalted
	}
	return fail(stage, kind, end)
}

func (s *Session) otherMessage(m string) {
	kind := api.EventUnknownMessage
	if messageName(m) == "INFO" || messageName(m) == "INFO_PRE" || messageName(m) == "PUSH_REPLY" {
		kind = api.EventControlMessage
	}
	s.event(api.Event{Kind: kind, Stage: api.StageEstablished, Reason: m})
}

// monitor handles control messages once established.
func (s *Session) monitor() {
	for {
		var it message
		select {
		case it = <-s.msgs:
		case <-s.stop:
			return
		}
		if it.err != nil {
			// A dropped key's session ends when its state closes; only the
			// active key's ending ends the session.
			s.keyMu.Lock()
			current := it.k == s.active
			s.keyMu.Unlock()
			if !current {
				continue
			}
			select {
			case <-s.stop:
			default:
				s.end(fail(api.StageEstablished, api.KindClosedByServer, it.err))
			}
			return
		}
		if end := serverEnd(it.m); end != nil {
			s.end(s.endFailure(api.StageEstablished, end))
			return
		}
		s.otherMessage(it.m)
	}
}

func (s *Session) end(err error) {
	s.mu.Lock()
	if s.endErr == nil {
		s.endErr = err
		close(s.ended)
	}
	s.mu.Unlock()
}

// ServerSession is the server's session ID, learned from its hard reset.
func (s *Session) ServerSession() wire.SessionID {
	return s.serverSession
}

// dropEventsPerSecond bounds the drop events of each reason that a packet
// from anyone can cause. The counters count every drop.
const dropEventsPerSecond = 10

// allowDropEvent reports whether one more drop event for reason fits in
// this second's allowance.
func (s *Session) allowDropEvent(reason string) bool {
	sec := s.cfg.Clock.Now().Unix()
	s.dropEventsMu.Lock()
	defer s.dropEventsMu.Unlock()
	if sec != s.dropEventsSecond || s.dropEvents == nil {
		s.dropEventsSecond, s.dropEvents = sec, map[string]int{}
	}
	s.dropEvents[reason]++
	return s.dropEvents[reason] <= dropEventsPerSecond
}

// hasEnded reports whether the session has ended.
func (s *Session) hasEnded() bool {
	select {
	case <-s.ended:
		return true
	default:
		return false
	}
}

// mark records now in t as a duration from the session's base, which
// keeps the clock's monotonic reading: a step of the wall clock moves
// neither the ping nor the expiry.
func (s *Session) mark(t *atomic.Int64) { t.Store(int64(s.cfg.Clock.Now().Sub(s.base))) }

// stamp is the time mark recorded.
func (s *Session) stamp(t *atomic.Int64) time.Time { return s.base.Add(time.Duration(t.Load())) }

// RemoteAddr is the server's address on the link.
func (s *Session) RemoteAddr() net.Addr { return s.lk.RemoteAddr() }

// Ended is closed when the server ends the session; Err then says how.
func (s *Session) Ended() <-chan struct{} { return s.ended }

// Err is the error that ended the session, if the server ended it.
func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.endErr
}

// sendExit sends EXIT and waits, bounded, for its acknowledgement.
func (s *Session) sendExit() {
	s.keyMu.Lock()
	k := s.active
	s.keyMu.Unlock()
	if k == nil {
		k = s.k0
	}
	if k.tc == nil {
		return
	}
	_ = k.conn.SetWriteDeadline(s.cfg.Clock.Now().Add(s.cfg.ExitWait))
	if _, err := k.tc.Write([]byte("EXIT\x00")); err != nil {
		return
	}
	deadline := s.cfg.Clock.Now().Add(s.cfg.ExitWait)
	for s.cfg.Clock.Now().Before(deadline) {
		idle := false
		k.conn.Do(func(st *reliable.State) { idle = st.Idle() })
		if idle {
			return
		}
		t := s.cfg.Clock.NewTimer(20 * time.Millisecond)
		<-t.C()
	}
}

// Close sends EXIT, if the server pushed cc-exit (spec notes 16), waits up
// to ExitWait for it to be acknowledged, and tears the session down. It is
// safe to call twice.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		if slices.Contains(s.Push.Flags, "cc-exit") {
			s.sendExit()
		}
		s.teardown()
	})
	return nil
}

func (s *Session) teardown() {
	select {
	case <-s.stop:
		return
	default:
	}
	close(s.stop)
	s.keyMu.Lock()
	keys := slices.Clone(s.keys)
	s.keyMu.Unlock()
	for _, k := range keys {
		k.conn.Close()
	}
	<-s.driverDone
	s.keyMu.Lock()
	for _, k := range s.keys {
		k.wipe()
	}
	s.keyMu.Unlock()
	clear(s.EKM)
	// The connection state holds the exporter, which could derive the
	// zeroed keys again. What the tls.Conn values keep inside crypto/tls
	// is out of reach.
	s.TLS = tls.ConnectionState{}
	s.lk.Close()
}

// Stats counts what the session dropped outside the reliability layer.
type Stats struct {
	Reliable                                  reliable.Stats
	DataDropped, OtherKeyDropped, Undecodable int64
	DataOpened, DataAuthFailed, DataReplay    int64
	Unframed, ReceiveQueueFull                int64
	PingsSent, PingsReceived                  int64
	DataV1, FirstDataID                       int64
	// Renegotiation: completed, soft resets dropped (spec notes 15.8 rule
	// 4), server key-method-2 messages read on renegotiation (O14), and
	// the active key ID.
	Renegotiations, SoftResetsDropped, RenegKeyMessages int64
	ActiveKey                                           uint8
	LiveKeys                                            int
	// IP bytes through the data channel, each way.
	BytesSent, BytesReceived int64
	// Datagrams the link dropped: over the size bound, or with its queue
	// full.
	LinkOversize, LinkQueueFull int64
}

func addReliable(dst *reliable.Stats, src reliable.Stats) {
	dst.Sent += src.Sent
	dst.Resent += src.Resent
	dst.Received += src.Received
	for i := range dst.Drops {
		dst.Drops[i] += src.Drops[i]
	}
}

// Stats returns the counters, including those of keys already dropped.
func (s *Session) Stats() Stats {
	s.keyMu.Lock()
	r := s.droppedReliable
	keys := slices.Clone(s.keys)
	s.keyMu.Unlock()
	for _, k := range keys {
		k.conn.Do(func(st *reliable.State) { addReliable(&r, st.Stats()) })
	}
	st := Stats{Reliable: r, DataDropped: s.dataDropped.Load(), OtherKeyDropped: s.otherKeyDropped.Load(), Undecodable: s.undecodable.Load(),
		DataOpened: s.dataOpened.Load(), DataAuthFailed: s.dataAuthFailed.Load(), DataReplay: s.dataReplay.Load(),
		Unframed: s.unframed.Load(), ReceiveQueueFull: s.recvQueueFull.Load(),
		PingsSent: s.pingsSent.Load(), PingsReceived: s.pingsReceived.Load()}
	st.Renegotiations, st.SoftResetsDropped, st.RenegKeyMessages = s.renegotiations.Load(), s.softResetsDropped.Load(), s.renegKeyMessages.Load()
	st.BytesSent, st.BytesReceived = s.bytesSent.Load(), s.bytesReceived.Load()
	ls := s.lk.Stats()
	st.LinkOversize, st.LinkQueueFull = ls.Oversize, ls.QueueFull
	s.keyMu.Lock()
	if o := s.k0.opener; o != nil {
		st.DataV1, st.FirstDataID = int64(o.V1), int64(o.FirstID)
	}
	if s.active != nil {
		st.ActiveKey = s.active.id
	}
	st.LiveKeys = len(s.keys)
	s.keyMu.Unlock()
	return st
}

func (s *Session) setupData() error {
	send, recv, err := datachan.KeysFromEKM(s.EKM, s.Push.Cipher)
	if err != nil {
		return fail(api.StagePush, api.KindUnsupportedPush, err)
	}
	s.keyMu.Lock()
	s.k0.sealer = datachan.NewSealer(send, 0, s.Push.PeerID)
	s.k0.opener = datachan.NewOpener(recv, 0, s.cfg.Clock.Now)
	s.k0.phase, s.active = active, s.k0
	s.keyMu.Unlock()
	s.mark(&s.lastAuth)
	s.mark(&s.lastSend)
	return nil
}

// openData authenticates one data packet under its key ID and hands its IP
// packet over. It runs on the driver and never blocks: a full receive queue
// drops. The first packet that authenticates under a pending key promotes
// it: a server that seals with a key has installed it (spec notes 15.7).
func (s *Session) openData(b []byte, id uint8) {
	s.keyMu.Lock()
	k := s.findLocked(id)
	var o *datachan.Opener
	if k != nil {
		o = k.opener
	}
	var pt []byte
	var err error
	if o != nil {
		pt, err = o.Open(b)
		if err == nil && k.phase == pending {
			s.promoteLocked(k)
		}
	}
	s.keyMu.Unlock()
	switch {
	case o == nil:
		s.dataDropped.Add(1) // before keys exist, or for a key not live
		return
	case errors.Is(err, datachan.ErrReplay):
		s.dataReplay.Add(1)
		if s.allowDropEvent("replay") {
			s.event(api.Event{Kind: api.EventPacketDropped, Stage: api.StageEstablished, KeyID: id, Reason: "replay"})
		}
		return
	case err != nil:
		s.dataAuthFailed.Add(1)
		if s.allowDropEvent("authentication failed") {
			s.event(api.Event{Kind: api.EventPacketDropped, Stage: api.StageEstablished, KeyID: id, Reason: "authentication failed"})
		}
		return
	}
	s.dataOpened.Add(1)
	s.mark(&s.lastAuth)
	ip, ok := datachan.Unframe(pt)
	if ok && datachan.IsPing(ip) {
		s.pingsReceived.Add(1)
		return // consumed: it reset lastAuth above
	}
	if !ok {
		s.unframed.Add(1)
		s.event(api.Event{Kind: api.EventPacketDropped, Stage: api.StageEstablished, Reason: fmt.Sprintf("unframed data plaintext % x", pt[:min(len(pt), 64)])})
		return
	}
	select {
	case s.received <- ip:
		s.bytesReceived.Add(int64(len(ip)))
	default:
		s.recvQueueFull.Add(1)
		if s.allowDropEvent("receive queue full") {
			s.event(api.Event{Kind: api.EventPacketDropped, Stage: api.StageEstablished, KeyID: id, Reason: "receive queue full"})
		}
	}
}

// seal seals a plaintext with the active key. A key that reports it is
// near its limit asks the driver for a renegotiation, once.
func (s *Session) seal(pt []byte) ([]byte, error) {
	s.keyMu.Lock()
	k := s.active
	if k == nil || k.sealer == nil {
		s.keyMu.Unlock()
		return nil, fail(api.StageEstablished, api.KindInternalFailure, errors.New("no data channel yet"))
	}
	pkt, renegotiate, err := k.sealer.Seal(pt)
	ask := renegotiate && !k.asked
	if ask {
		k.asked = true
	}
	s.keyMu.Unlock()
	if ask {
		s.renegAsked.Store(true)
		s.wake()
	}
	switch {
	case errors.Is(err, datachan.ErrPacketIDLimit):
		return nil, fail(api.StageEstablished, api.KindPacketIDLimit, err)
	case err != nil:
		return nil, fail(api.StageEstablished, api.KindInternalFailure, err)
	}
	return pkt, nil
}

func (s *Session) sendPing() error {
	pkt, err := s.seal(datachan.Frame(datachan.PingPayload))
	if err != nil {
		return err
	}
	s.mark(&s.lastSend)
	return s.lk.Write(pkt)
}

// WritePacket seals one IP packet and sends it.
func (s *Session) WritePacket(ip []byte) error {
	pkt, err := s.seal(datachan.Frame(ip))
	if err != nil {
		return err
	}
	s.bytesSent.Add(int64(len(ip)))
	s.mark(&s.lastSend)
	return s.lk.Write(pkt)
}

// ReadPacket returns the next IP packet from the tunnel.
func (s *Session) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case ip := <-s.received:
		return ip, nil
	case <-s.ended:
		return nil, s.Err()
	case <-s.stop:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// applySchedule runs the renegotiation schedule on the driver and returns
// how long until it is due again.
func (s *Session) applySchedule(now time.Time) time.Duration {
	s.keyMu.Lock()
	d := s.sched.decide(now, s.viewsLocked(), s.renegAsked.Load())
	var failed *key
	for _, k := range slices.Clone(s.keys) {
		switch {
		case d.fail && k.phase == negotiating:
			failed = k
		case d.promote && k.phase == pending && !now.Before(k.installed.Add(s.sched.promotion)):
			s.promoteLocked(k)
		case d.dropRetiring && k.phase == retiring && !now.Before(k.since.Add(s.sched.tranWindow)):
			s.dropLocked(k)
		}
	}
	if d.start && s.active != nil {
		s.renegAsked.Store(false)
		s.startNegotiationLocked(nextKeyID(s.active.id), true)
	}
	s.keyMu.Unlock()
	if failed != nil {
		s.end(fail(api.StageRenegotiation, api.KindRenegotiationFailed,
			fmt.Errorf("key %d: not complete within the handshake window of %v", failed.id, s.sched.handWindow)))
	}
	return max(d.next.Sub(now), 0)
}
