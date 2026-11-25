package burrow

import (
	"context"
	"errors"
	"time"

	"github.com/happydave/burrow/internal/admission"
)

// Backoff defaults, from the man page's connect-retry.
const (
	DefaultConnectRetry    = time.Second
	DefaultConnectRetryCap = 300 * time.Second
)

// stableFor is how long a tunnel must last for the Redialer to count it a
// success; one that ends sooner counts as a failure, so a server that drops
// every tunnel meets a growing backoff.
const stableFor = 60 * time.Second

// backoff is the wait before an attempt after failures consecutive
// failures: none for the first attempt, base for the next five, then
// doubling each time, never above maxWait (the man page's connect-retry
// rule, counted per configuration rather than per remote).
func backoff(failures int, base, maxWait time.Duration) time.Duration {
	if failures <= 0 {
		return 0
	}
	d := base
	for i := 5; i < failures && d < maxWait; i++ {
		d *= 2
	}
	return min(d, maxWait)
}

// permanent reports whether retrying cannot fix a connect error: the
// server refused this client or its configuration, or the Config is
// invalid.
func permanent(err error) bool {
	var e *Error
	if !errors.As(err, &e) {
		return true
	}
	if errors.Is(err, KindAdmissionRefused) {
		// A policy refusal passes with time; a store that cannot work
		// (no flock, a corrupt or unreadable history) does not.
		return !errors.Is(err, admission.ErrRefused)
	}
	return errors.Is(err, KindAuthFailed) || errors.Is(err, KindCertRejected) || errors.Is(err, KindUnsupportedPush) ||
		errors.Is(err, KindHalted)
}

// Redialer keeps one configuration connected: each Next returns a new
// tunnel, after a backoff that grows with consecutive failures. Every
// attempt goes through Connect, so the admission guard sees all of them.
// A Redialer is not safe for concurrent use.
type Redialer struct {
	cfg      Config
	sleep    func(context.Context, time.Duration) error
	connect  func(context.Context, Config) (*Tunnel, error)
	failures int
	prev     *Tunnel
}

// NewRedialer returns a Redialer for cfg.
func NewRedialer(cfg Config) *Redialer {
	return &Redialer{cfg: cfg, sleep: sleep, connect: Connect}
}

// sleep waits d, or until ctx ends.
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Next returns a newly established tunnel. It closes the tunnel it
// returned last if that is still open, waits as the backoff requires, and
// connects, repeating until a tunnel is established, ctx ends, or the
// error is one retrying cannot fix (AUTH_FAILED, a rejected server
// certificate, an unsupported pushed option, a HALT, an admission store
// that cannot work, an invalid Config), which it returns. It also returns,
// without connecting, a HALT that ended the previous tunnel.
func (r *Redialer) Next(ctx context.Context) (*Tunnel, error) {
	if p := r.prev; p != nil {
		r.prev = nil
		_ = p.Close()
		if err := p.Err(); errors.Is(err, KindHalted) {
			// The server asked this client not to reconnect (spec notes 9).
			return nil, err
		}
		if p.ended.Sub(p.established) < stableFor {
			r.failures++
		} else {
			r.failures = 0
		}
	}
	base, maxWait := r.cfg.ConnectRetry, r.cfg.ConnectRetryCap
	if base == 0 {
		base = DefaultConnectRetry
	}
	if maxWait == 0 {
		maxWait = DefaultConnectRetryCap
	}
	for {
		if d := backoff(r.failures, base, maxWait); d > 0 {
			if err := r.sleep(ctx, d); err != nil {
				return nil, &Error{Stage: StageLink, Kind: KindCanceled, Err: err}
			}
		}
		tn, err := r.connect(ctx, r.cfg)
		if err == nil {
			r.prev = tn
			return tn, nil
		}
		if permanent(err) || ctx.Err() != nil {
			return nil, err
		}
		r.failures++
	}
}
