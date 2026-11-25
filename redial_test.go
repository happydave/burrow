package burrow

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/happydave/burrow/internal/session"
)

func TestBackoff(t *testing.T) {
	for _, c := range []struct {
		failures    int
		base, limit time.Duration
		want        time.Duration
	}{
		{0, time.Second, 300 * time.Second, 0},
		{1, time.Second, 300 * time.Second, time.Second},
		{5, time.Second, 300 * time.Second, time.Second},
		{6, time.Second, 300 * time.Second, 2 * time.Second},
		{7, time.Second, 300 * time.Second, 4 * time.Second},
		{13, time.Second, 300 * time.Second, 256 * time.Second},
		{14, time.Second, 300 * time.Second, 300 * time.Second},
		{9, 5 * time.Second, 60 * time.Second, 60 * time.Second},
		{8, 5 * time.Second, 60 * time.Second, 40 * time.Second},
	} {
		if got := backoff(c.failures, c.base, c.limit); got != c.want {
			t.Errorf("backoff(%d, %v, %v) = %v, want %v", c.failures, c.base, c.limit, got, c.want)
		}
	}
}

// scripted is a Redialer whose connections and waits are recorded.
type scripted struct {
	r       *Redialer
	results []error // nil gives a tunnel
	calls   int
	waits   []time.Duration
	lives   []time.Duration // how long each returned tunnel lasts
}

func newScripted(results ...error) *scripted {
	s := &scripted{results: results}
	s.r = &Redialer{cfg: Config{Remotes: []string{"192.0.2.1:1194"}}}
	s.r.sleep = func(_ context.Context, d time.Duration) error {
		s.waits = append(s.waits, d)
		return nil
	}
	s.r.connect = func(context.Context, Config) (*Tunnel, error) {
		i := s.calls
		s.calls++
		if s.calls > 50 {
			return nil, errors.New("scripted: 50 calls, the Redialer did not stop")
		}
		if i >= len(s.results) || s.results[i] != nil {
			if i >= len(s.results) {
				return nil, &Error{Stage: StageHardReset, Kind: KindUnreachable}
			}
			return nil, s.results[i]
		}
		// An ended tunnel whose life is the next scripted one.
		tn := newTunnel(nil)
		start := time.Unix(1_000_000, 0)
		life := time.Duration(0)
		if len(s.lives) > 0 {
			life, s.lives = s.lives[0], s.lives[1:]
		}
		tn.established, tn.ended = start, start.Add(life)
		close(tn.done)
		return tn, nil
	}
	return s
}

func unreachable() error { return &Error{Stage: StageHardReset, Kind: KindUnreachable} }

func TestRedialerWaits(t *testing.T) {
	s := newScripted(unreachable(), unreachable(), unreachable(), nil)
	if _, err := s.r.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The first attempt waits nothing; each of the next three waits the base.
	want := []time.Duration{time.Second, time.Second, time.Second}
	if s.calls != 4 || len(s.waits) != 3 || s.waits[0] != want[0] || s.waits[2] != want[2] {
		t.Fatalf("calls %d, waits %v; want 4 calls after waits %v", s.calls, s.waits, want)
	}
}

func TestRedialerStopsOnPermanent(t *testing.T) {
	for _, err := range []error{
		&Error{Stage: StagePush, Kind: KindAuthFailed},
		&Error{Stage: StageTLS, Kind: KindCertRejected},
		&Error{Stage: StagePush, Kind: KindUnsupportedPush},
		errors.New("burrow: Config.Remotes is empty"),
	} {
		s := newScripted(err)
		if _, got := s.r.Next(context.Background()); !errors.Is(got, err) || s.calls != 1 {
			t.Errorf("%v: returned %v after %d calls, want it after 1", err, got, s.calls)
		}
	}
	s := newScripted(&Error{Stage: StageLink, Kind: KindAdmissionRefused}, nil)
	if _, err := s.r.Next(context.Background()); err != nil || s.calls != 2 {
		t.Fatalf("a guard refusal is retried: %v after %d calls", err, s.calls)
	}
}

func TestRedialerFlapping(t *testing.T) {
	// The first tunnel lasts 10 s: a flap, so the next attempt waits the
	// base. The second lasts 61 s: stable, so the third waits nothing.
	s := newScripted(nil, nil, nil)
	s.lives = []time.Duration{10 * time.Second, 61 * time.Second}
	for i := range 3 {
		if _, err := s.r.Next(context.Background()); err != nil {
			t.Fatalf("Next %d: %v", i+1, err)
		}
	}
	if len(s.waits) != 1 || s.waits[0] != time.Second {
		t.Fatalf("waits %v, want one of 1s, after the 10 s tunnel only", s.waits)
	}
}

func TestRedialerCancelDuringWait(t *testing.T) {
	s := newScripted()
	s.r.sleep = sleep
	s.r.failures = 14 // a 300 s wait
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := s.r.Next(ctx)
	if !errors.Is(err, KindCanceled) || s.calls != 0 {
		t.Fatalf("err %v after %d calls, want canceled with none", err, s.calls)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("returned after %v", d)
	}
}

func TestRedialerClosesPrevious(t *testing.T) {
	s := newScripted(nil, nil)
	ca, _ := newFakePair()
	first := newTunnel(nil)
	if err := first.start(ca, session.Push{Local: addrA}, nil, 0); err != nil {
		t.Fatal(err)
	}
	s.r.prev = first
	if _, err := s.r.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-first.Done():
	default:
		t.Fatal("the previous tunnel is still open")
	}
}
