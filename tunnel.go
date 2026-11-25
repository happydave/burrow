package burrow

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/happydave/burrow/internal/admission"
	"github.com/happydave/burrow/internal/reliable"
	"github.com/happydave/burrow/internal/session"
	"github.com/happydave/burrow/internal/wire"
)

// EventQueue is how many events Events buffers for a slow reader.
const EventQueue = 256

var (
	// ErrRawMode is returned by the stack methods of a raw-packet tunnel.
	ErrRawMode = errors.New("burrow: tunnel is in raw-packet mode")
	// ErrStackMode is returned by the raw-packet methods of a tunnel with a
	// network stack.
	ErrStackMode = errors.New("burrow: tunnel has a network stack; raw packets are unavailable")
)

// Pushed is the configuration the server pushed.
type Pushed struct {
	Local, Remote netip.Addr // the tunnel's two ends (topology p2p)
	Ping          time.Duration
	PingRestart   time.Duration
	PeerID        uint32
	Cipher        string
	TunMTU        int // zero when not pushed
	// Flags are the pushed protocol-flags.
	Flags []string
	// Recorded options are accepted and kept but not acted on: routes,
	// DNS and the like.
	Recorded []string
	// Unrecognised options are ones burrow does not know, kept verbatim so
	// a caller can see what the server asked for.
	Unrecognised []string
}

// Stats counts traffic and drops.
type Stats struct {
	// Control channel.
	ControlSent, ControlResent, ControlReceived int
	ControlDropped                              map[string]int
	// Data channel.
	DataOpened, DataAuthFailed, DataReplay int64
	DataDropped, Unframed, ReceiveFull     int64
	PingsSent, PingsReceived               int64
	// Renegotiation: completed, the key ID in use, and soft resets dropped
	// (a second negotiation while one runs).
	Renegotiations    int64
	ActiveKey         uint8
	SoftResetsDropped int64
	// Network stack: packets moved between the stack and the tunnel, and
	// those that failed.
	StackSent, StackReceived, StackSendErrors, StackInjectErrors int64
	// EventsLost counts events no reader took in time.
	EventsLost int64
	// IP bytes through the tunnel, each way.
	BytesSent, BytesReceived int64
	// Datagrams the link dropped: over the size bound, or with its queue
	// full.
	LinkOversize, LinkQueueFull int64
}

// counters is a Stats as a counters event carries it.
func (st Stats) counters() map[string]int64 {
	m := map[string]int64{
		"control sent": int64(st.ControlSent), "control resent": int64(st.ControlResent), "control received": int64(st.ControlReceived),
		"data opened": st.DataOpened, "data authentication failed": st.DataAuthFailed, "data replay": st.DataReplay,
		"data dropped": st.DataDropped, "unframed": st.Unframed, "receive queue full": st.ReceiveFull,
		"pings sent": st.PingsSent, "pings received": st.PingsReceived,
		"renegotiations": st.Renegotiations, "active key": int64(st.ActiveKey), "soft resets dropped": st.SoftResetsDropped,
		"stack sent": st.StackSent, "stack received": st.StackReceived,
		"stack send errors": st.StackSendErrors, "stack inject errors": st.StackInjectErrors,
		"events lost": st.EventsLost, "bytes sent": st.BytesSent, "bytes received": st.BytesReceived,
		"link oversize": st.LinkOversize, "link queue full": st.LinkQueueFull,
	}
	for reason, n := range st.ControlDropped {
		m["control dropped: "+reason] = int64(n)
	}
	return m
}

// conn is what a tunnel needs of a session; tests substitute a fake.
type conn interface {
	packetPath
	Ended() <-chan struct{}
	Err() error
	Close() error
	Stats() session.Stats
}

// Tunnel is an established connection.
type Tunnel struct {
	sess   conn
	stack  *stack // nil in raw mode
	remote netip.AddrPort
	mtu    int
	// established and ended bound the tunnel's life, for the Redialer's
	// flapping rule; ended is set before Done closes.
	established, ended time.Time
	now                func() time.Time
	statsEvery         time.Duration
	pushed             Pushed
	log                *slog.Logger

	events     chan Event
	evMu       sync.Mutex
	lost       int // since the last delivered event
	lostTotal  int64
	closed     chan struct{}
	done       chan struct{}
	closeOnce  sync.Once
	errMu      sync.Mutex
	err        error
	cleanClose bool
}

// Connect connects to the first of cfg.Remotes that answers and returns an
// established tunnel. It moves to the next remote only while no server has
// answered; any answered failure is returned as it is. Its errors are
// *Error, with the stage and kind of the failure, except that an invalid
// Config is a plain error before anything is sent. The admission guard is
// always on: without a store, attempts are counted in this process's
// memory, in one domain for all of the configuration's remotes.
func Connect(ctx context.Context, cfg Config) (*Tunnel, error) {
	return connect(ctx, cfg, nil)
}

// connect is Connect with a hook that lets tests adjust the walk.
func connect(ctx context.Context, cfg Config, adjust func(*dialer)) (*Tunnel, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	t := newTunnel(cfg.Logger)
	if cfg.AdmissionStore == nil {
		cfg.AdmissionStore = processStore
	}
	if cfg.AdmissionPolicy == nil {
		p := admission.DefaultPolicy
		cfg.AdmissionPolicy = &p
	}
	d := &dialer{cfg: cfg, domain: banDomain(cfg.AdmissionDomain, cfg.Remotes), timeout: cfg.ConnectTimeout,
		resolver: net.DefaultResolver, resolveEvery: time.Second, connect: session.Connect, emit: t.emit}
	if d.timeout == 0 {
		d.timeout = DefaultConnectTimeout
	}
	if adjust != nil {
		adjust(d)
	}
	sess, remote, err := d.walk(ctx)
	if err != nil {
		t.warn("connect failed", err)
		return nil, err
	}
	t.remote = remote
	t.mtu = stackMTU(cfg, sess.Push.TunMTU, remote.Addr().Is6())
	if t.mtu < minMTU {
		_ = sess.Close()
		err := &Error{Stage: StagePush, Kind: KindUnsupportedPush,
			Err: fmt.Errorf("tun-mtu and mssfix leave an MTU of %d, below %d", t.mtu, minMTU)}
		t.warn("connect failed", err)
		return nil, err
	}
	mtu := t.mtu
	if cfg.RawPackets {
		mtu = 0
	}
	t.statsEvery = cfg.StatsInterval
	if t.statsEvery == 0 {
		t.statsEvery = DefaultStatsInterval
	}
	if err := t.start(sess, sess.Push, cfg.DNS, mtu); err != nil {
		_ = sess.Close()
		t.warn("connect failed", err)
		return nil, err
	}
	return t, nil
}

// stackMTU applies the configuration to linkMTU: a pushed tun-mtu wins over
// the configured one, and an unset mssfix is the default, with mtu
// semantics.
func stackMTU(cfg Config, pushedTunMTU int, ipv6Outer bool) int {
	tun := pushedTunMTU
	if tun == 0 {
		tun = cfg.TunMTU
	}
	mssfix, payload := cfg.MSSFix, cfg.MSSFixPayload
	if mssfix == 0 {
		mssfix, payload = DefaultMSSFix, false
	}
	return min(linkMTU(tun, mssfix, payload, ipv6Outer), maxMTU)
}

// The MTU's bounds: IPv4's minimum, and the largest inner packet whose
// sealed datagram fits the receive bound (spec notes 18.4).
const (
	minMTU = 576
	maxMTU = wire.MaxDatagram - dataOverhead
)

func newTunnel(log *slog.Logger) *Tunnel {
	return &Tunnel{log: log, events: make(chan Event, EventQueue),
		closed: make(chan struct{}), done: make(chan struct{}), now: time.Now}
}

// start joins the tunnel to an established session: with a network stack
// of the given MTU, or in raw mode when mtu is zero.
func (t *Tunnel) start(c conn, p session.Push, dns []netip.Addr, mtu int) error {
	t.sess = c
	t.pushed = pushedFrom(p)
	t.established = t.now()
	if mtu > 0 {
		st, err := newStack(c, p.Local, dns, mtu)
		if err != nil {
			return &Error{Stage: StageEstablished, Kind: KindInternalFailure, Err: fmt.Errorf("network stack: %w", err)}
		}
		t.stack = st
	}
	go t.watch()
	return nil
}

func pushedFrom(p session.Push) Pushed {
	return Pushed{Local: p.Local, Remote: p.Remote, Ping: p.Ping, PingRestart: p.PingRestart,
		PeerID: p.PeerID, Cipher: p.Cipher, TunMTU: p.TunMTU, Flags: slices.Clone(p.Flags),
		Recorded: slices.Clone(p.Recorded), Unrecognised: slices.Clone(p.Unrecognised)}
}

// DefaultStatsInterval is how often a tunnel sends a counters event.
const DefaultStatsInterval = 60 * time.Second

// watch ends the tunnel when the session ends or Close is called, and sends
// the periodic counters events until then.
func (t *Tunnel) watch() {
	var tick <-chan time.Time
	if t.statsEvery > 0 {
		tk := time.NewTicker(t.statsEvery)
		defer tk.Stop()
		tick = tk.C
	}
	reason, stage := "closed", Stage("")
loop:
	for {
		select {
		case <-tick:
			t.emit(Event{Kind: EventCounters, Time: time.Now(), Counters: t.Stats().counters()})
		case <-t.sess.Ended():
			err := t.sess.Err()
			t.setErr(err)
			t.warn("tunnel ended", err)
			reason = err.Error()
			var e *Error
			if errors.As(err, &e) {
				stage = e.Stage
			}
			break loop
		case <-t.closed:
			break loop
		}
	}
	_ = t.sess.Close()
	if t.stack != nil {
		t.stack.close()
	}
	t.ended = t.now()
	t.emit(Event{Kind: EventEnded, Time: time.Now(), Stage: stage, Reason: reason, Counters: t.Stats().counters()})
	close(t.done)
}

func (t *Tunnel) setErr(err error) {
	t.errMu.Lock()
	if t.err == nil && !t.cleanClose {
		t.err = err
	}
	t.errMu.Unlock()
}

// emit delivers an event without blocking. A full queue drops it; the next
// delivered event reports how many were dropped.
func (t *Tunnel) emit(e Event) {
	if t.log != nil && (e.Kind == EventStageEntered || e.Kind == EventStageCompleted) {
		t.log.Debug("burrow", "event", string(e.Kind), "stage", string(e.Stage))
	}
	t.evMu.Lock()
	defer t.evMu.Unlock()
	e.Lost = t.lost
	select {
	case t.events <- e:
		t.lost = 0
	default:
		t.lost++
		t.lostTotal++
	}
}

func (t *Tunnel) warn(msg string, err error) {
	if t.log != nil && err != nil {
		t.log.Warn("burrow: "+msg, "err", err)
	}
}

// Events returns the tunnel's events. The channel holds EventQueue events;
// when it is full, events are dropped rather than slowing the tunnel, and
// the next one delivered carries the count in Lost. It is never closed:
// watch Done for the end.
func (t *Tunnel) Events() <-chan Event { return t.events }

// RemoteAddr is the server address the tunnel connected to.
func (t *Tunnel) RemoteAddr() netip.AddrPort { return t.remote }

// LocalAddr is the tunnel's own address, as pushed.
func (t *Tunnel) LocalAddr() netip.Addr { return t.pushed.Local }

// Pushed returns a copy of the pushed configuration.
func (t *Tunnel) Pushed() Pushed {
	p := t.pushed
	p.Recorded = slices.Clone(p.Recorded)
	return p
}

func (t *Tunnel) usable() error {
	select {
	case <-t.done:
		return net.ErrClosed
	default:
	}
	if t.stack == nil {
		return ErrRawMode
	}
	return nil
}

// DialContext connects to address through the tunnel. network is tcp, udp
// or ping, each optionally suffixed 4 or 6; names resolve through
// Config.DNS. It fits http.Transport.DialContext.
func (t *Tunnel) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := t.usable(); err != nil {
		return nil, err
	}
	return t.stack.net.DialContext(ctx, network, address)
}

// ListenTCP listens for TCP connections on the tunnel side.
func (t *Tunnel) ListenTCP(addr netip.AddrPort) (net.Listener, error) {
	if err := t.usable(); err != nil {
		return nil, err
	}
	return t.stack.net.ListenTCPAddrPort(addr)
}

// ListenUDP opens a UDP socket on the tunnel side.
func (t *Tunnel) ListenUDP(addr netip.AddrPort) (net.PacketConn, error) {
	if err := t.usable(); err != nil {
		return nil, err
	}
	return t.stack.net.ListenUDPAddrPort(addr)
}

// ReadPacket returns the next IP packet from the server. Raw mode only.
func (t *Tunnel) ReadPacket(ctx context.Context) ([]byte, error) {
	if t.stack != nil {
		return nil, ErrStackMode
	}
	return t.sess.ReadPacket(ctx)
}

// MTU is the largest IP packet the tunnel carries: the network stack's MTU,
// or in raw mode the bound WritePacket holds packets to.
func (t *Tunnel) MTU() int { return t.mtu }

// WritePacket sends one IP packet to the server. Raw mode only; a packet
// over MTU is refused.
func (t *Tunnel) WritePacket(ip []byte) error {
	if t.stack != nil {
		return ErrStackMode
	}
	if t.mtu > 0 && len(ip) > t.mtu {
		return fmt.Errorf("burrow: a %d-byte packet is over the tunnel MTU of %d", len(ip), t.mtu)
	}
	select {
	case <-t.done:
		return net.ErrClosed
	default:
	}
	return t.sess.WritePacket(ip)
}

// Stats returns the tunnel's counters.
func (t *Tunnel) Stats() Stats {
	ss := t.sess.Stats()
	st := Stats{ControlSent: ss.Reliable.Sent, ControlResent: ss.Reliable.Resent, ControlReceived: ss.Reliable.Received,
		ControlDropped: map[string]int{},
		DataOpened:     ss.DataOpened, DataAuthFailed: ss.DataAuthFailed, DataReplay: ss.DataReplay,
		DataDropped: ss.DataDropped + ss.OtherKeyDropped + ss.Undecodable, Unframed: ss.Unframed, ReceiveFull: ss.ReceiveQueueFull,
		PingsSent: ss.PingsSent, PingsReceived: ss.PingsReceived,
		Renegotiations: ss.Renegotiations, ActiveKey: ss.ActiveKey, SoftResetsDropped: ss.SoftResetsDropped,
		BytesSent: ss.BytesSent, BytesReceived: ss.BytesReceived,
		LinkOversize: ss.LinkOversize, LinkQueueFull: ss.LinkQueueFull}
	for i, n := range ss.Reliable.Drops {
		if n > 0 {
			st.ControlDropped[reliable.DropNames[i]] = n
		}
	}
	if t.stack != nil {
		st.StackSent, st.StackReceived = t.stack.sent.Load(), t.stack.received.Load()
		st.StackSendErrors, st.StackInjectErrors = t.stack.sendErrors.Load(), t.stack.injectErrors.Load()
	}
	t.evMu.Lock()
	st.EventsLost = t.lostTotal
	t.evMu.Unlock()
	return st
}

// Done is closed when the tunnel has ended and its goroutines have exited.
func (t *Tunnel) Done() <-chan struct{} { return t.done }

// Err says why the tunnel ended: nil after Close, or the *Error the
// session ended with.
func (t *Tunnel) Err() error {
	t.errMu.Lock()
	defer t.errMu.Unlock()
	return t.err
}

// Close tells the server the tunnel is ending, waits up to 2 s for it to
// acknowledge, and tears everything down. It is safe to call more than
// once.
func (t *Tunnel) Close() error {
	t.closeOnce.Do(func() {
		t.errMu.Lock()
		if t.err == nil {
			t.cleanClose = true
		}
		t.errMu.Unlock()
		close(t.closed)
	})
	<-t.done
	return nil
}
