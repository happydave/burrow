package burrow

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/happydave/burrow/internal/admission"
)

// Version is burrow's version, sent to servers as IV_VER=burrow-<Version>.
const Version = "0.0.0-dev"

// Config is everything a connection needs.
type Config struct {
	// Remotes are the servers, host:port over UDP, tried in order. A host
	// name is resolved, and each of its addresses tried in turn.
	Remotes []string
	// RootCAs verifies the server's certificate; Certificate is the client's.
	RootCAs     *x509.CertPool
	Certificate tls.Certificate
	// PushTimeout and HandshakeWindow default to 60 s each.
	PushTimeout     time.Duration
	HandshakeWindow time.Duration
	// ConnectTimeout bounds the wait for one remote's answer before the
	// next is tried (server-poll-timeout); zero means 120 s. The handshake
	// window bounds it too.
	ConnectTimeout time.Duration
	// ResolveRetry is how long a failed name lookup is retried, once a
	// second: zero means for the remote's whole connect timeout, negative
	// means one try.
	ResolveRetry time.Duration
	// RenegInterval is how long a data key lasts before burrow renegotiates
	// (reneg-sec); zero means an hour, negative leaves renegotiation to the
	// server.
	RenegInterval time.Duration
	// ConnectRetry and ConnectRetryMax are the Redialer's backoff base and
	// cap; zero means 1 s and 300 s.
	ConnectRetry, ConnectRetryMax time.Duration
	// Dialer opens the UDP socket; nil means a net.Dialer.
	Dialer Dialer
	// AdmissionStore keeps attempt history for the admission guard. Nil
	// means a store in this process's memory, shared by all Connect calls
	// that leave it nil. AdmissionPolicy nil means DefaultAdmissionPolicy.
	// AdmissionDomain names the ban domain; empty means one domain for all
	// of the configuration's remote hosts.
	AdmissionStore  AdmissionStore
	AdmissionPolicy *AdmissionPolicy
	AdmissionDomain string
	// DNS servers answer name lookups made through the tunnel.
	DNS []netip.Addr
	// TunMTU is the tunnel MTU when the server pushes none; zero means
	// 1500.
	TunMTU int
	// MSSFix bounds the outer IP packet (mtu semantics), or with
	// MSSFixPayload the UDP payload, as mssfix without the mtu keyword.
	// Zero means DefaultMSSFix; negative disables the bound.
	MSSFix        int
	MSSFixPayload bool
	// CloseWait bounds Close's wait for the server to acknowledge EXIT;
	// zero means 2 s.
	CloseWait time.Duration
	// InsecureKeyLog, when set, receives every TLS session's secrets in the
	// NSS key-log format, which decrypts anything captured from the
	// tunnel's control channel. For debugging burrow's own sessions only.
	InsecureKeyLog io.Writer
	// StatsInterval is how often a counters event is sent; zero means
	// 60 s, negative none.
	StatsInterval time.Duration
	// Logger, if set, receives stage events at Debug and errors at Warn.
	Logger *slog.Logger
	// RawPackets gives the caller IP packets through ReadPacket and
	// WritePacket instead of a network stack.
	RawPackets bool
}

// Dialer opens the link's UDP socket.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Admission guard types, re-exported.
type (
	AdmissionStore   = admission.Store
	AdmissionPolicy  = admission.Policy
	AdmissionRecord  = admission.Record
	AdmissionOutcome = admission.Outcome
)

// DefaultAdmissionPolicy allows three refused attempts per domain an hour.
var DefaultAdmissionPolicy = admission.DefaultPolicy

// NewMemoryStore returns an in-memory admission store.
func NewMemoryStore() AdmissionStore { return &admission.Memory{} }

// NewFileStore returns an admission store in one file, shared by
// processes on one host. It uses flock, so it works on Unix systems; on
// others every attempt is refused with the store's error.
func NewFileStore(path string) AdmissionStore { return &admission.File{Path: path} }

var processStore AdmissionStore = &admission.Memory{}

func (c Config) validate() error {
	switch {
	case len(c.Remotes) == 0:
		return errors.New("burrow: Config.Remotes is empty")
	case c.RootCAs == nil:
		return errors.New("burrow: Config.RootCAs is nil; the server's certificate cannot be verified")
	case c.TunMTU != 0 && (c.TunMTU < 576 || c.TunMTU > 65535):
		return errors.New("burrow: Config.TunMTU must be from 576 to 65535")
	case c.PushTimeout < 0 || c.HandshakeWindow < 0 || c.ConnectTimeout < 0 || c.ConnectRetry < 0 || c.ConnectRetryMax < 0:
		return errors.New("burrow: negative timeout")
	}
	for _, r := range c.Remotes {
		if _, _, err := splitRemote(r); err != nil {
			return err
		}
	}
	return nil
}
