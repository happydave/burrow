package burrow

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/happydave/burrow/internal/api"
	"github.com/happydave/burrow/internal/session"
)

// DefaultConnectTimeout is the wait for one remote's answer to the hard
// reset (the man page's server-poll-timeout default).
const DefaultConnectTimeout = 120 * time.Second

// resolver looks up a remote's host name.
type resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// banDomain is the admission domain of a configuration: the configured
// one, or all of its remote hosts, sorted, so every attempt the
// configuration makes shares one count whatever the remotes' order.
func banDomain(configured string, remotes []string) string {
	if configured != "" {
		return configured
	}
	var hosts []string
	for _, r := range remotes {
		h, _, err := net.SplitHostPort(r)
		if err != nil {
			h = r
		}
		hosts = append(hosts, h)
	}
	slices.Sort(hosts)
	return strings.Join(slices.Compact(hosts), ",")
}

// failOver reports whether a failed attempt lets Connect try the next
// address: only when nothing answered. Every error it accepts is one the
// admission classifier does not count, so failing over spends none of the
// domain's allowance.
func failOver(err error) bool {
	var e *api.Error
	if !errors.As(err, &e) || e.Kind != api.KindUnreachable {
		return false
	}
	return e.Stage == api.StageLink || e.Stage == api.StageHardReset
}

func splitRemote(r string) (string, uint16, error) {
	host, port, err := net.SplitHostPort(r)
	if err != nil {
		return "", 0, fmt.Errorf("burrow: remote %q: %w", r, err)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 || host == "" {
		return "", 0, fmt.Errorf("burrow: remote %q: want host:port with a port from 1 to 65535", r)
	}
	return host, uint16(p), nil
}

// dialer carries what one Connect needs to walk the remotes.
type dialer struct {
	cfg          Config
	domain       string
	timeout      time.Duration
	resolver     resolver
	resolveEvery time.Duration
	connect      func(ctx context.Context, cfg session.Config) (*session.Session, error)
	emit         func(Event)
}

// resolve returns a remote's addresses, retrying a failed lookup every
// resolveEvery for the ResolveRetry budget, bounded by the remote's
// connect timeout and the context.
func (d *dialer) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a.Unmap()}, nil
	}
	budget := d.timeout
	if r := d.cfg.ResolveRetry; r > 0 && r < budget {
		budget = r
	}
	deadline := time.Now().Add(budget)
	for {
		addrs, err := d.resolver.LookupNetIP(ctx, "ip", host)
		if err == nil && len(addrs) > 0 {
			for i := range addrs {
				addrs[i] = addrs[i].Unmap()
			}
			return addrs, nil
		}
		if err == nil {
			err = errors.New("no addresses")
		}
		if d.cfg.ResolveRetry < 0 || ctx.Err() != nil || !time.Now().Add(d.resolveEvery).Before(deadline) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(d.resolveEvery):
		}
	}
}

// walk tries the remotes in order, each of a host's addresses in turn, and
// returns the first established session. It moves on only while no server
// has answered (failOver).
func (d *dialer) walk(ctx context.Context) (*session.Session, netip.AddrPort, error) {
	var tried []string
	var last error
	for _, r := range d.cfg.Remotes {
		host, port, err := splitRemote(r)
		if err != nil {
			return nil, netip.AddrPort{}, err
		}
		addrs, err := d.resolve(ctx, host)
		if err != nil {
			if ctx.Err() != nil {
				return nil, netip.AddrPort{}, &Error{Stage: StageLink, Kind: KindCanceled, Err: ctx.Err()}
			}
			last = &Error{Stage: StageLink, Kind: KindUnreachable, Err: fmt.Errorf("resolving %s: %w", host, err)}
			tried = append(tried, fmt.Sprintf("%s (%v)", r, err))
			d.emit(Event{Kind: EventFailover, Stage: StageLink, Reason: last.Error()})
			continue
		}
		for _, a := range addrs {
			ap := netip.AddrPortFrom(a, port)
			d.emit(Event{Kind: EventRemoteChosen, Stage: StageLink, Reason: ap.String()})
			sc := session.Config{
				Remote: ap.String(), CAs: d.cfg.RootCAs, Cert: d.cfg.Certificate,
				PushTimeout: d.cfg.PushTimeout, HandshakeWindow: d.cfg.HandshakeWindow, ResetTimeout: d.timeout,
				RenegInterval: d.cfg.RenegInterval, KeyLog: d.cfg.InsecureKeyLog, ExitWait: d.cfg.CloseWait,
				Dialer: d.cfg.Dialer, Events: d.emit, Version: Version,
				Guard: &session.Guard{Store: d.cfg.AdmissionStore, Policy: *d.cfg.AdmissionPolicy, Domain: d.domain},
			}
			sess, err := d.connect(ctx, sc)
			if err == nil {
				return sess, ap, nil
			}
			if !failOver(err) {
				return nil, netip.AddrPort{}, err
			}
			last = err
			tried = append(tried, fmt.Sprintf("%s (%v)", ap, err))
			d.emit(Event{Kind: EventFailover, Stage: StageHardReset, Reason: err.Error()})
		}
	}
	stage := StageLink
	var e *api.Error
	if errors.As(last, &e) {
		stage = e.Stage
	}
	return nil, netip.AddrPort{}, &Error{Stage: stage, Kind: KindUnreachable,
		Err: fmt.Errorf("no remote answered: %s", strings.Join(tried, "; "))}
}
