//go:build interop

package interop

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/happydave/burrow/internal/admission"
	"github.com/happydave/burrow/internal/api"
	"github.com/happydave/burrow/internal/session"
)

func variant(t *testing.T, want string) {
	t.Helper()
	if v := os.Getenv("BURROW_INTEROP_VARIANT"); v != want {
		t.Skipf("needs the %s variant; this run is %q", want, v)
	}
}

func config(t *testing.T, cn string) session.Config {
	t.Helper()
	dir := os.Getenv("BURROW_INTEROP_PKI")
	ca, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("no CA certificate in ca.crt")
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, cn+".crt"), filepath.Join(dir, cn+".key"))
	if err != nil {
		t.Fatal(err)
	}
	return session.Config{Remote: server(t), CAs: pool, Cert: cert, Version: "interop", HandshakeWindow: 30 * time.Second}
}

func connect(t *testing.T, cfg session.Config) *session.Session {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	s, err := session.Connect(ctx, cfg)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestCleanConnect is the item's acceptance run: hard reset, TLS 1.3, key
// method 2, a classified push, then EXIT on Close.
func TestCleanConnect(t *testing.T) {
	variant(t, "plain")
	s := connect(t, config(t, "123456"))
	if s.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("negotiated TLS %x, want 1.3", s.TLS.Version)
	}
	p := s.Push
	if p.Cipher != "AES-256-GCM" || !p.Local.IsValid() || len(s.EKM) != 256 {
		t.Fatalf("push %+v, EKM %d bytes", p, len(s.EKM))
	}
	for _, f := range p.Flags {
		if f == "dyn-tls-crypt" {
			t.Fatal("the server pushed dyn-tls-crypt, which burrow did not advertise")
		}
	}
	t.Logf("TLS %s %s; push: local %s remote %s ping %v restart %v peer-id %d cipher %s flags %v tun-mtu %d recorded %d unrecognised %q",
		tls.VersionName(s.TLS.Version), tls.CipherSuiteName(s.TLS.CipherSuite), p.Local, p.Remote, p.Ping, p.PingRestart,
		p.PeerID, p.Cipher, p.Flags, p.TunMTU, len(p.Recorded), p.Unrecognised)
	t.Logf("server key-method-2 message: %d bytes, pre-master field present: %v", s.ServerKeyLength, s.ServerKeyPreMaster)
	st := s.Stats()
	t.Logf("control packets sent %d, resent %d, received %d; data dropped %d", st.Reliable.Sent, st.Reliable.Resent, st.Reliable.Received, st.DataDropped)
	start := time.Now()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	t.Logf("Close (EXIT acknowledged or 2 s) took %v", time.Since(start).Round(time.Millisecond))
}

// TestNotAdmitted connects with a CN the allowlist refuses. The server stays
// silent (the TLS spike, spec notes 9.1), so the push timeout ends it as "not admitted".
func TestNotAdmitted(t *testing.T) {
	variant(t, "plain")
	cfg := config(t, "999999")
	cfg.PushTimeout = 15 * time.Second
	if os.Getenv("BURROW_INTEROP_LONG") == "1" {
		cfg.PushTimeout = 75 * time.Second // past the server's 60 s hand-window (O11)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	start := time.Now()
	s, err := session.Connect(ctx, cfg)
	if err == nil {
		s.Close()
		t.Fatal("a refused CN connected")
	}
	var e *api.Error
	if !errors.As(err, &e) || e.Stage != api.StagePush {
		t.Fatalf("error %v, want one at the push stage", err)
	}
	if !errors.Is(err, api.KindNotAdmitted) && !errors.Is(err, api.KindAuthFailed) {
		t.Fatalf("error %v, want not admitted or AUTH_FAILED", err)
	}
	t.Logf("after %v: %v", time.Since(start).Round(time.Second), err)
}

// TestRoutesPush: 400 routes arrive as a continued push and are recorded.
func TestRoutesPush(t *testing.T) {
	variant(t, "routes")
	s := connect(t, config(t, "123456"))
	routes := 0
	for _, r := range s.Push.Recorded {
		if strings.HasPrefix(r, "route ") {
			routes++
		}
	}
	if routes != 400 {
		t.Fatalf("recorded %d routes, want 400", routes)
	}
	t.Logf("400 routes recorded; cipher %s, peer-id %d", s.Push.Cipher, s.Push.PeerID)
}

// TestGuardCapsRefusals: with a file-store guard at the default policy,
// three refused attempts are made and the fourth is stopped before sending.
func TestGuardCapsRefusals(t *testing.T) {
	variant(t, "plain")
	cfg := config(t, "999999")
	cfg.PushTimeout = 15 * time.Second
	store := &admission.File{Path: filepath.Join(t.TempDir(), "history.json")}
	cfg.Guard = &session.Guard{Store: store, Policy: admission.DefaultPolicy}
	for i := range 3 {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		_, err := session.Connect(ctx, cfg)
		cancel()
		if !errors.Is(err, api.KindAuthFailed) && !errors.Is(err, api.KindNotAdmitted) {
			t.Fatalf("attempt %d: %v, want a refusal", i+1, err)
		}
	}
	_, err := session.Connect(context.Background(), cfg)
	if !errors.Is(err, api.KindAdmissionRefused) {
		t.Fatalf("fourth attempt: %v, want admission refused", err)
	}
	rs, err := store.Records("127.0.0.1")
	if err != nil || len(rs) != 3 {
		t.Fatalf("records %+v, %v; want three", rs, err)
	}
	for _, r := range rs {
		if r.Outcome != admission.Refused {
			t.Fatalf("record %+v, want refused", r)
		}
	}
	t.Logf("three attempts refused by the server and recorded; the fourth stopped by the guard")
}
