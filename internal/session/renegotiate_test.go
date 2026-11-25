package session

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/happydave/burrow/internal/api"
	"github.com/happydave/burrow/internal/fakeserver"
)

func TestNextKeyID(t *testing.T) {
	for in, want := range map[uint8]uint8{0: 1, 1: 2, 6: 7, 7: 1} {
		if got := nextKeyID(in); got != want {
			t.Errorf("nextKeyID(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestScheduleDecide(t *testing.T) {
	t0 := time.Unix(1_000_000, 0)
	at := func(d time.Duration) time.Time { return t0.Add(d) }
	sc := schedule{renegInterval: 3600 * time.Second, promotion: 60 * time.Second, tranWindow: 3600 * time.Second, handWindow: 60 * time.Second}
	act := keyView{id: 0, phase: active, since: t0}
	cases := []struct {
		name      string
		sc        schedule
		now       time.Duration
		keys      []keyView
		requested bool
		want      due
	}{
		{"active 3599 s: nothing", sc, 3599 * time.Second, []keyView{act}, false, due{}},
		{"active 3600 s: start", sc, 3600 * time.Second, []keyView{act}, false, due{start: true}},
		{"interval negative: never", schedule{renegInterval: -1, handWindow: 60 * time.Second}, 100 * time.Hour, []keyView{act}, false, due{}},
		{"interval negative, sealer asks: start", schedule{renegInterval: -1}, time.Second, []keyView{act}, true, due{start: true}},
		{"pending 59 s: not promoted", sc, 59 * time.Second,
			[]keyView{act, {id: 1, phase: pending, since: t0, installed: t0}}, false, due{}},
		{"pending 60 s: promoted", sc, 60 * time.Second,
			[]keyView{act, {id: 1, phase: pending, since: t0, installed: t0}}, false, due{promote: true}},
		{"pending blocks burrow's own start", sc, 7200 * time.Second,
			[]keyView{act, {id: 1, phase: pending, since: at(7200 * time.Second), installed: at(7200 * time.Second)}}, false, due{}},
		{"retiring at the transition window: dropped", sc, 3600 * time.Second,
			[]keyView{{id: 1, phase: active, since: t0}, {id: 0, phase: retiring, since: t0}}, false, due{dropRetiring: true, start: true}},
		{"retiring 3599 s: kept", sc, 3599 * time.Second,
			[]keyView{{id: 1, phase: active, since: at(time.Second)}, {id: 0, phase: retiring, since: t0}}, false, due{}},
		{"negotiating for the handshake window: fail", sc, 60 * time.Second,
			[]keyView{act, {id: 1, phase: negotiating, since: t0}}, false, due{fail: true}},
		{"negotiating 59 s: no fail, no second start", sc, 3659 * time.Second,
			[]keyView{act, {id: 1, phase: negotiating, since: at(3600 * time.Second)}}, false, due{}},
	}
	for _, c := range cases {
		got := c.sc.decide(at(c.now), c.keys, c.requested)
		got.next = time.Time{}
		if got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
	// next is the earliest limit: a pending key installed now is promoted
	// in 60 s, sooner than the hour's renegotiation.
	d := sc.decide(t0, []keyView{act, {id: 1, phase: pending, installed: t0}}, false)
	if !d.next.Equal(at(60 * time.Second)) {
		t.Errorf("next = +%v, want +60s", d.next.Sub(t0))
	}
}

func TestSoftResetAction(t *testing.T) {
	t0 := time.Unix(1_000_000, 0)
	cases := []struct {
		name string
		id   uint8
		keys []keyView
		want resetAction
	}{
		{"next after the active key", 1, []keyView{{id: 0, phase: active}}, resetRespond},
		{"two ahead", 2, []keyView{{id: 0, phase: active}}, resetDrop},
		{"the active key's own ID", 0, []keyView{{id: 0, phase: active}}, resetDrop},
		// Inside the transition window: key 0 retiring, 2000 s in.
		{"next while one retires", 2, []keyView{{id: 1, phase: active}, {id: 0, phase: retiring, since: t0}}, resetRespond},
		{"while negotiating another", 3, []keyView{{id: 1, phase: active}, {id: 2, phase: negotiating}}, resetDrop},
		{"next after a pending key", 3, []keyView{{id: 1, phase: active}, {id: 2, phase: pending}}, resetRespond},
		{"wrap from 7", 1, []keyView{{id: 7, phase: active}}, resetRespond},
	}
	for _, c := range cases {
		if got := softResetAction(c.id, c.keys); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestMakeRoom(t *testing.T) {
	// A server renegotiation inside the transition window: the retiring key
	// goes, leaving the active key and the new one.
	drop, promote := makeRoom([]keyView{{id: 1, phase: active}, {id: 0, phase: retiring}})
	if len(drop) != 1 || drop[0] != 0 || promote != -1 {
		t.Errorf("retiring case: drop %v promote %d, want [0] -1", drop, promote)
	}
	// Active and pending: promote the pending key, drop the active one.
	drop, promote = makeRoom([]keyView{{id: 1, phase: active}, {id: 2, phase: pending}})
	if len(drop) != 1 || drop[0] != 1 || promote != 2 {
		t.Errorf("pending case: drop %v promote %d, want [1] 2", drop, promote)
	}
	if drop, promote = makeRoom([]keyView{{id: 0, phase: active}}); len(drop) != 0 || promote != -1 {
		t.Errorf("one key: drop %v promote %d, want none", drop, promote)
	}
}

// reneg connects to a fake server with short renegotiation settings and
// records the session's renegotiation events.
type reneg struct {
	srv *fakeserver.Server
	s   *Session

	mu     sync.Mutex
	events []api.Event
	at     map[api.EventKind][]time.Time
}

func startReneg(t *testing.T, opts fakeserver.Options, mod func(*Config)) *reneg {
	t.Helper()
	opts.Push = fakeserver.Push
	r := &reneg{srv: fakeserver.Start(t, opts), at: map[api.EventKind][]time.Time{}}
	cfg := Config{Remote: r.srv.Addr(), CAs: r.srv.Pool, Version: "test", PushTimeout: 2 * time.Second,
		HandshakeWindow: time.Second, RenegInterval: -1, promotion: 200 * time.Millisecond}
	cfg.Events = func(e api.Event) {
		switch e.Kind {
		case api.EventRenegotiationStarted, api.EventRenegotiationFinished, api.EventKeyTransition:
			r.mu.Lock()
			r.events = append(r.events, e)
			r.at[e.Kind] = append(r.at[e.Kind], time.Now())
			r.mu.Unlock()
		}
	}
	if mod != nil {
		mod(&cfg)
	}
	s, err := Connect(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.s = s
	t.Cleanup(func() { s.Close() })
	return r
}

func (r *reneg) times(k api.EventKind) []time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]time.Time(nil), r.at[k]...)
}

// waitActive waits until the session seals with key id.
func (r *reneg) waitActive(t *testing.T, id uint8, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for r.s.Stats().ActiveKey != id {
		select {
		case <-r.s.Ended():
			t.Fatalf("session ended: %v", r.s.Err())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("not sealing with key %d after %v (stats %+v)", id, within, r.s.Stats())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// echoes writes n packets apart and reads each back from the fake's echo.
func (r *reneg) echoes(t *testing.T, n int, apart time.Duration) {
	t.Helper()
	for i := range n {
		pkt := []byte{0x45, 0, byte(i), byte(i >> 8)}
		if err := r.s.WritePacket(pkt); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		got, err := r.s.ReadPacket(ctx)
		cancel()
		if err != nil || len(got) != 4 || got[2] != byte(i) {
			t.Fatalf("echo %d: % x, %v", i, got, err)
		}
		time.Sleep(apart)
	}
}

func TestServerRenegotiationSwitchesOnNewKeyPacket(t *testing.T) {
	r := startReneg(t, fakeserver.Options{SendOnNewKey: true}, func(c *Config) { c.promotion = time.Hour })
	r.echoes(t, 3, 0)
	if !r.srv.Renegotiate() {
		t.Fatal("no client")
	}
	// 20 echoes, 50 ms apart, across the switch: none lost.
	r.echoes(t, 20, 50*time.Millisecond)
	r.waitActive(t, 1, 2*time.Second)
	sent, ok := r.srv.NewKeySent(1)
	if !ok {
		t.Fatal("the fake never sent under key 1")
	}
	for _, a := range r.srv.Arrivals() {
		if a.Key == 1 && a.Time.Before(sent) {
			t.Fatalf("burrow sealed with key 1 at %v, before the server's first key-1 packet at %v", a.Time, sent)
		}
	}
	r.echoes(t, 3, 0)
	var after1 int
	for _, a := range r.srv.Arrivals() {
		if a.Key == 1 {
			after1++
		}
	}
	if after1 < 3 {
		t.Fatalf("only %d packets under key 1 after the switch", after1)
	}
}

func TestPromotionByTimer(t *testing.T) {
	r := startReneg(t, fakeserver.Options{}, nil) // the fake sends nothing under key 1
	r.srv.Renegotiate()
	done := time.Now().Add(3 * time.Second)
	for len(r.times(api.EventRenegotiationFinished)) == 0 {
		if time.Now().After(done) {
			t.Fatal("renegotiation did not finish")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Keep writing so the arrival times show when sealing switched.
	go func() {
		for range 40 {
			_ = r.s.WritePacket([]byte{0x45, 1})
			time.Sleep(10 * time.Millisecond)
		}
	}()
	r.waitActive(t, 1, 2*time.Second)
	finished := r.times(api.EventRenegotiationFinished)[0]
	switched := r.times(api.EventKeyTransition)[0]
	if d := switched.Sub(finished); d < 190*time.Millisecond {
		t.Fatalf("switched %v after finishing, want the 200 ms promotion", d)
	}
	for _, a := range r.srv.Arrivals() {
		if a.Key == 1 && a.Time.Before(finished.Add(190*time.Millisecond)) {
			t.Fatalf("a key-1 packet %v after finishing, before the promotion", a.Time.Sub(finished))
		}
	}
}

func TestClientRenegotiation(t *testing.T) {
	r := startReneg(t, fakeserver.Options{}, func(c *Config) { c.RenegInterval = 300 * time.Millisecond })
	r.waitActive(t, 1, 3*time.Second)
	r.mu.Lock()
	first := r.events[0]
	r.mu.Unlock()
	if first.Kind != api.EventRenegotiationStarted || first.KeyID != 1 || first.Reason != "key 1, started by burrow" {
		t.Fatalf("first event %+v, want burrow starting key 1", first)
	}
	r.echoes(t, 3, 0)
}

func TestTwoRenegotiationsKeepTwoKeys(t *testing.T) {
	r := startReneg(t, fakeserver.Options{SendOnNewKey: true}, nil)
	for id := uint8(1); id <= 2; id++ {
		r.srv.Renegotiate()
		r.waitActive(t, id, 3*time.Second)
		if n := r.s.Stats().LiveKeys; n > 2 {
			t.Fatalf("after key %d: %d keys live", id, n)
		}
		r.echoes(t, 2, 0)
	}
	r.s.keyMu.Lock()
	k0 := r.s.findLocked(0)
	r.s.keyMu.Unlock()
	if k0 != nil {
		t.Fatal("key 0 is still live after the second renegotiation")
	}
	if st := r.s.Stats(); st.Renegotiations != 2 || st.LiveKeys != 2 {
		t.Fatalf("renegotiations %d, live keys %d; want 2 and 2", st.Renegotiations, st.LiveKeys)
	}
}

func TestStalledRenegotiationFails(t *testing.T) {
	r := startReneg(t, fakeserver.Options{StallRenegotiation: true}, nil)
	start := time.Now()
	r.srv.Renegotiate()
	select {
	case <-r.s.Ended():
	case <-time.After(3 * time.Second):
		t.Fatal("the session survived a renegotiation that never completed")
	}
	var e *api.Error
	if err := r.s.Err(); !errors.As(err, &e) || e.Stage != api.StageRenegotiation || !errors.Is(err, api.KindRenegotiationFailed) {
		t.Fatalf("err %v, want renegotiation failed at the renegotiation stage", err)
	}
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Fatalf("ended after %v; the handshake window is 1 s", d)
	}
}

func TestRenegotiationChecksTheCertificate(t *testing.T) {
	r := startReneg(t, fakeserver.Options{BadCertOnRenegotiation: true}, nil)
	r.srv.Renegotiate()
	select {
	case <-r.s.Ended():
	case <-time.After(3 * time.Second):
		t.Fatal("the session accepted a renegotiation with a clientAuth-only server certificate")
	}
	if err := r.s.Err(); !errors.Is(err, api.KindRenegotiationFailed) || !errors.Is(err, errCertRejected) {
		t.Fatalf("err %v, want renegotiation failed wrapping the certificate rejection", err)
	}
}

func TestPacketLimitStartsOneRenegotiation(t *testing.T) {
	r := startReneg(t, fakeserver.Options{}, nil)
	r.s.keyMu.Lock()
	r.s.active.sealer.Skip(1<<28 - 1) // the next seal reports "renegotiate"
	r.s.keyMu.Unlock()
	// Keep sealing through the negotiation and the 200 ms promotion: the
	// old key reports on every seal until the new one takes over.
	stop := make(chan struct{})
	wrote := make(chan struct{})
	go func() {
		defer close(wrote)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = r.s.WritePacket([]byte{0x45, 2})
			time.Sleep(5 * time.Millisecond)
		}
	}()
	r.waitActive(t, 1, 3*time.Second)
	time.Sleep(300 * time.Millisecond)
	close(stop)
	<-wrote
	if n := len(r.times(api.EventRenegotiationStarted)); n != 1 {
		t.Fatalf("%d renegotiations started, want 1", n)
	}
}

func TestExitOnTheActiveKey(t *testing.T) {
	r := startReneg(t, fakeserver.Options{SendOnNewKey: true}, nil)
	r.srv.Renegotiate()
	r.waitActive(t, 1, 3*time.Second)
	r.s.Close()
	deadline := time.Now().Add(2 * time.Second)
	for !slices.Contains(r.srv.Received(1), "EXIT") {
		if time.Now().After(deadline) {
			t.Fatalf("no EXIT on key 1; key 0 got %q, key 1 %q", r.srv.Received(0), r.srv.Received(1))
		}
		time.Sleep(10 * time.Millisecond)
	}
	if slices.Contains(r.srv.Received(0), "EXIT") {
		t.Fatal("EXIT went on the retiring key 0")
	}
}

func TestServerMessageOnRenegotiatedKey(t *testing.T) {
	r := startReneg(t, fakeserver.Options{SendOnNewKey: true}, nil)
	r.srv.Renegotiate()
	r.waitActive(t, 1, 3*time.Second)
	if !r.srv.Message(1, "RESTART") {
		t.Fatal("the fake could not write on key 1")
	}
	select {
	case <-r.s.Ended():
	case <-time.After(2 * time.Second):
		t.Fatal("a RESTART on key 1's TLS session did not end the session")
	}
	if err := r.s.Err(); !errors.Is(err, api.KindClosedByServer) {
		t.Fatalf("err %v, want closed by server", err)
	}
}

func TestKeyLogCoversEveryKey(t *testing.T) {
	var log syncBuffer
	r := startReneg(t, fakeserver.Options{SendOnNewKey: true}, func(c *Config) { c.KeyLog = &log })
	r.srv.Renegotiate()
	r.waitActive(t, 1, 3*time.Second)
	if n := strings.Count(log.String(), "CLIENT_HANDSHAKE_TRAFFIC_SECRET "); n != 2 {
		t.Fatalf("%d sets of key-log lines, want 2 (key 0 and key 1)", n)
	}
}

// syncBuffer is a bytes.Buffer safe for TLS's writer and the test's reader.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func TestCloseWipesKeys(t *testing.T) {
	r := startReneg(t, fakeserver.Options{SendOnNewKey: true}, nil)
	r.srv.Renegotiate()
	r.waitActive(t, 1, 3*time.Second)
	r.s.keyMu.Lock()
	keys := slices.Clone(r.s.keys)
	r.s.keyMu.Unlock()
	r.s.Close()
	if !allZero(r.s.EKM) {
		t.Fatal("the first key's EKM block survived Close")
	}
	for _, k := range keys {
		if !allZero(k.ekm) {
			t.Fatalf("key %d's EKM block survived Close", k.id)
		}
		if _, _, err := k.sealer.Seal([]byte{0xfa, 0x45}); err == nil {
			t.Fatalf("key %d's sealer still seals after Close", k.id)
		}
	}
}

func allZero(b []byte) bool {
	if len(b) == 0 {
		return false // nothing to have wiped means the test looked at the wrong slice
	}
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func TestCloseDuringNegotiation(t *testing.T) {
	r := startReneg(t, fakeserver.Options{StallRenegotiation: true}, func(c *Config) { c.HandshakeWindow = 5 * time.Second })
	r.srv.Renegotiate()
	deadline := time.Now().Add(2 * time.Second)
	for len(r.times(api.EventRenegotiationStarted)) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no negotiation started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	start := time.Now()
	r.s.Close()
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("Close took %v during a negotiation", d)
	}
	if err := r.s.Err(); err != nil {
		t.Fatalf("Err after Close = %v, want nil: a close is not a failure", err)
	}
}

func TestStatsKeepDroppedKeys(t *testing.T) {
	r := startReneg(t, fakeserver.Options{SendOnNewKey: true}, nil)
	r.srv.Renegotiate()
	r.waitActive(t, 1, 3*time.Second)
	before := r.s.Stats().Reliable.Sent // keys 0 and 1, both live
	r.srv.Renegotiate()
	r.waitActive(t, 2, 3*time.Second) // key 0 dropped
	if after := r.s.Stats().Reliable.Sent; after < before {
		t.Fatalf("control packets sent fell from %d to %d when key 0 was dropped", before, after)
	}
}
