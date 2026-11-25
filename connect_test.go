package burrow

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/happydave/burrow/internal/admission"
	"github.com/happydave/burrow/internal/api"
	"github.com/happydave/burrow/internal/fakeserver"
)

// silentSocket receives datagrams and never answers.
type silentSocket struct {
	pc      net.PacketConn
	packets atomic.Int64
}

func listenSilent(t *testing.T, addr string) *silentSocket {
	t.Helper()
	s, err := tryListenSilent(t, addr)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// tryListenSilent is listenSilent for an address the host may lack.
func tryListenSilent(t *testing.T, addr string) (*silentSocket, error) {
	t.Helper()
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(context.Background(), "udp", addr)
	if err != nil {
		return nil, err
	}
	s := &silentSocket{pc: pc}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			s.packets.Add(1)
		}
	}()
	t.Cleanup(func() { pc.Close(); <-done })
	return s, nil
}

func (s *silentSocket) addr() string { return s.pc.LocalAddr().String() }

// recorder collects the events of a Connect, whatever its result.
type recorder struct {
	mu     sync.Mutex
	events []Event
}

func (r *recorder) emit(e Event) {
	r.mu.Lock()
	r.events = append(r.events, e)
	r.mu.Unlock()
}

func (r *recorder) of(kind EventKind) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, e := range r.events {
		if e.Kind == kind {
			out = append(out, e.Reason)
		}
	}
	return out
}

func walkConfig(srv *fakeserver.Silent, remotes ...string) Config {
	return Config{Remotes: remotes, RootCAs: srv.Pool, AdmissionStore: NewMemoryStore(),
		ConnectTimeout: 200 * time.Millisecond, PushTimeout: 300 * time.Millisecond,
		// The window also bounds the reset wait; 5 s makes a walk that
		// ignores ConnectTimeout fail the timing checks by name.
		HandshakeWindow: 5 * time.Second}
}

type resolverFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(ctx context.Context, n, h string) ([]netip.Addr, error) {
	return f(ctx, n, h)
}

// tryConnect runs connect with a recorder and optional dialer changes.
func tryConnect(t *testing.T, ctx context.Context, cfg Config, adjust func(*dialer)) (*recorder, error) {
	t.Helper()
	rec := &recorder{}
	tn, err := connect(ctx, cfg, func(d *dialer) {
		d.emit = rec.emit
		if adjust != nil {
			adjust(d)
		}
	})
	if tn != nil {
		tn.Close()
	}
	return rec, err
}

func TestFailoverBothSilent(t *testing.T) {
	srv := fakeserver.StartSilent(t)
	a, b := listenSilent(t, "127.0.0.1:0"), listenSilent(t, "127.0.0.1:0")
	start := time.Now()
	rec, err := tryConnect(t, context.Background(), walkConfig(srv, a.addr(), b.addr()), nil)
	if !errors.Is(err, KindUnreachable) || !strings.Contains(err.Error(), a.addr()) || !strings.Contains(err.Error(), b.addr()) {
		t.Fatalf("err %v, want unreachable naming both remotes", err)
	}
	if got := rec.of(EventRemoteChosen); len(got) != 2 || got[0] != a.addr() || got[1] != b.addr() {
		t.Fatalf("remotes chosen %q, want A then B", got)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("took %v: the 200 ms connect timeout did not bound the wait", d)
	}
	if a.packets.Load() == 0 || b.packets.Load() == 0 {
		t.Fatalf("packets to A %d, B %d: both should have been tried", a.packets.Load(), b.packets.Load())
	}
}

func TestFailoverReachesAnsweringServer(t *testing.T) {
	srv := fakeserver.StartSilent(t)
	a := listenSilent(t, "127.0.0.1:0")
	_, aPort, _ := net.SplitHostPort(a.addr())
	// The silent remote goes by a name, so the two remotes are two hosts in
	// the ban domain while every socket stays on 127.0.0.1, the one
	// loopback address every platform has.
	res := resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})
	cfg := walkConfig(srv, "silent.test:"+aPort, srv.Addr())
	rec, err := tryConnect(t, context.Background(), cfg, func(d *dialer) { d.resolver = res })
	var e *Error
	if !errors.As(err, &e) || e.Stage != StagePush || !errors.Is(err, KindNotAdmitted) {
		t.Fatalf("err %v, want not admitted at the push stage", err)
	}
	if len(rec.of(EventFailover)) != 1 || srv.Resets() != 1 {
		t.Fatalf("failovers %q, server resets %d; want one each", rec.of(EventFailover), srv.Resets())
	}
	// Both attempts are in the configuration's one domain: not counted for
	// the silent remote, refused for the server.
	rs, err := cfg.AdmissionStore.Records("127.0.0.1,silent.test")
	if err != nil || len(rs) != 2 || rs[0].Outcome != admission.NotCounted || rs[1].Outcome != admission.Refused {
		t.Fatalf("records %+v, %v; want not counted then refused, in one domain", rs, err)
	}
}

func TestNoFailoverAfterAnswer(t *testing.T) {
	srv := fakeserver.StartSilent(t)
	b := listenSilent(t, "127.0.0.1:0")
	rec, err := tryConnect(t, context.Background(), walkConfig(srv, srv.Addr(), b.addr()), nil)
	if !errors.Is(err, KindNotAdmitted) {
		t.Fatalf("err %v, want not admitted", err)
	}
	if n := b.packets.Load(); n != 0 || len(rec.of(EventRemoteChosen)) != 1 {
		t.Fatalf("the second remote got %d packets after the first answered; remotes chosen %q", n, rec.of(EventRemoteChosen))
	}
}

func TestFailoverAcrossAddresses(t *testing.T) {
	srv := fakeserver.StartSilent(t)
	_, port, _ := net.SplitHostPort(srv.Addr())
	// A second loopback address on the fake server's port: ::1, or
	// 127.0.0.2 where IPv6 is off. macOS configures only 127.0.0.1 of the
	// IPv4 loopback range.
	var other *silentSocket
	var second netip.Addr
	for _, a := range []string{"::1", "127.0.0.2"} {
		if s, err := tryListenSilent(t, net.JoinHostPort(a, port)); err == nil {
			other, second = s, netip.MustParseAddr(a)
			break
		}
	}
	if other == nil {
		t.Skipf("no second loopback address (::1 or 127.0.0.2) can be bound on port %s", port)
	}
	res := resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{second, netip.MustParseAddr("127.0.0.1")}, nil
	})
	rec, err := tryConnect(t, context.Background(), walkConfig(srv, "vpn.example:"+port), func(d *dialer) { d.resolver = res })
	if !errors.Is(err, KindNotAdmitted) {
		t.Fatalf("err %v, want not admitted from the second address", err)
	}
	want := []string{net.JoinHostPort(second.String(), port), "127.0.0.1:" + port}
	if got := rec.of(EventRemoteChosen); len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("addresses tried %q, want %q", got, want)
	}
	if other.packets.Load() == 0 {
		t.Fatal("the first address was not tried")
	}
}

func TestResolveRetriesThenFailsOver(t *testing.T) {
	srv := fakeserver.StartSilent(t)
	var calls atomic.Int64
	res := resolverFunc(func(_ context.Context, _, host string) ([]netip.Addr, error) {
		calls.Add(1)
		return nil, &net.DNSError{Err: "no such host", Name: host}
	})
	_, err := tryConnect(t, context.Background(), walkConfig(srv, "never.example:1194", srv.Addr()),
		func(d *dialer) { d.resolver, d.resolveEvery = res, 20*time.Millisecond })
	if !errors.Is(err, KindNotAdmitted) {
		t.Fatalf("err %v, want the second remote reached", err)
	}
	// 200 ms of retries every 20 ms: about ten lookups; one lookup means
	// no retrying, and an unbounded loop never reaches the server.
	if n := calls.Load(); n < 5 {
		t.Fatalf("%d lookups in the 200 ms connect timeout, want about 10", n)
	}

	calls.Store(0)
	cfg := walkConfig(srv, "never.example:1194", srv.Addr())
	cfg.ResolveRetry = -1
	if _, err := tryConnect(t, context.Background(), cfg, func(d *dialer) { d.resolver, d.resolveEvery = res, 20*time.Millisecond }); !errors.Is(err, KindNotAdmitted) {
		t.Fatalf("one try: err %v", err)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("ResolveRetry < 0 made %d lookups, want 1", n)
	}
}

func TestCancelStopsTheWalk(t *testing.T) {
	srv := fakeserver.StartSilent(t)
	a, b := listenSilent(t, "127.0.0.1:0"), listenSilent(t, "127.0.0.1:0")
	cfg := walkConfig(srv, a.addr(), b.addr())
	cfg.ConnectTimeout = 10 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := tryConnect(t, ctx, cfg, nil)
	if !errors.Is(err, KindCanceled) {
		t.Fatalf("err %v, want canceled", err)
	}
	if n := b.packets.Load(); n != 0 {
		t.Fatalf("the second remote got %d packets after cancellation", n)
	}
}

func TestFailoverPredicate(t *testing.T) {
	e := func(s api.Stage, k api.Kind) error { return &api.Error{Stage: s, Kind: k} }
	for _, c := range []struct {
		name    string
		err     error
		move    bool
		outcome admission.Outcome
	}{
		{"link unreachable", e(api.StageLink, api.KindUnreachable), true, admission.NotCounted},
		{"no answer to the reset", e(api.StageHardReset, api.KindUnreachable), true, admission.NotCounted},
		{"canceled", e(api.StageHardReset, api.KindCanceled), false, admission.NotCounted},
		{"guard refusal", e(api.StageLink, api.KindAdmissionRefused), false, admission.NotCounted},
		{"TLS failure", e(api.StageTLS, api.KindTLS), false, admission.Refused},
		{"not admitted", e(api.StagePush, api.KindNotAdmitted), false, admission.Refused},
		{"AUTH_FAILED", e(api.StagePush, api.KindAuthFailed), false, admission.Refused},
		{"unsupported push", e(api.StagePush, api.KindUnsupportedPush), false, admission.Refused},
		{"no stage", errors.New("plain"), false, admission.NotCounted},
	} {
		if got := failOver(c.err); got != c.move {
			t.Errorf("%s: failOver = %v, want %v", c.name, got, c.move)
		}
		if got := admission.Classify(c.err); got != c.outcome {
			t.Errorf("%s: classified %s, want %s", c.name, got, c.outcome)
		}
		if c.move && admission.Classify(c.err) != admission.NotCounted {
			t.Errorf("%s: failover on an error that counts against the domain", c.name)
		}
	}
}

func TestBanDomain(t *testing.T) {
	rs := []string{"192.0.2.48:1181", "198.51.100.147:1193", "198.51.100.147:1181"}
	rev := []string{rs[2], rs[1], rs[0]}
	for _, l := range [][]string{rs, rev} {
		if got := banDomain("", l); got != "192.0.2.48,198.51.100.147" {
			t.Errorf("banDomain(%q) = %q", l, got)
		}
	}
	if got := banDomain("example", rs); got != "example" {
		t.Errorf("configured domain lost: %q", got)
	}
}

func TestSharedDomainAcrossPorts(t *testing.T) {
	p, q := fakeserver.StartSilent(t), fakeserver.StartSilent(t)
	cfg := walkConfig(p, p.Addr(), q.Addr())
	for i := range 3 {
		if _, err := tryConnect(t, context.Background(), cfg, nil); !errors.Is(err, KindNotAdmitted) {
			t.Fatalf("attempt %d: %v, want not admitted", i+1, err)
		}
	}
	if _, err := tryConnect(t, context.Background(), cfg, nil); !errors.Is(err, KindAdmissionRefused) {
		t.Fatalf("fourth attempt: %v, want admission refused", err)
	}
	if p.Resets() != 3 || q.Resets() != 0 {
		t.Fatalf("resets: first port %d, second %d; want 3 and 0", p.Resets(), q.Resets())
	}
	rs, err := cfg.AdmissionStore.Records("127.0.0.1")
	if err != nil || len(rs) != 3 {
		t.Fatalf("records %+v, %v: want three in the one domain", rs, err)
	}
}
