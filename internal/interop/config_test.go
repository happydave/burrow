//go:build interop

package interop

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/happydave/burrow"
)

// writeOVPN writes a configuration for the harness PKI and the given
// remotes, in the target configuration's shape.
func writeOVPN(t *testing.T, cn string, remotes ...string) string {
	t.Helper()
	pki := os.Getenv("BURROW_INTEROP_PKI")
	var b strings.Builder
	fmt.Fprintf(&b, "client\ndev tun0\nnobind\nresolv-retry infinite\nca %s\ncert %s\nkey %s\n",
		filepath.Join(pki, "ca.crt"), filepath.Join(pki, cn+".crt"), filepath.Join(pki, cn+".key"))
	b.WriteString("comp-lzo no\ncomp-noadapt\nremote-cert-tls server\nconnect-timeout 3\nverb 2\n")
	for _, r := range remotes {
		host, port, err := net.SplitHostPort(r)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, "<connection>\nremote %s %s udp\n</connection>\n", host, port)
	}
	path := filepath.Join(t.TempDir(), "client.ovpn")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLoadAndFailover loads a configuration whose first remote is a closed
// port, fails over to the harness server, and fetches through the tunnel.
func TestLoadAndFailover(t *testing.T) {
	variant(t, "plain")
	cfg, ignored, err := burrow.LoadConfig(writeOVPN(t, "123456", "127.0.0.1:1", server(t)))
	if err != nil {
		t.Fatal(err)
	}
	if len(ignored) != 2 {
		t.Fatalf("ignored %+v, want dev and verb", ignored)
	}
	cfg.HandshakeWindow = 30 * time.Second
	cfg.AdmissionStore = burrow.NewMemoryStore()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	start := time.Now()
	tn, err := burrow.Connect(ctx, cfg)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer tn.Close()
	t.Logf("connected to %s after %v", tn.RemoteAddr(), time.Since(start).Round(time.Millisecond))
	if got := tn.RemoteAddr().String(); got != server(t) {
		t.Fatalf("connected to %s, want the harness server %s", got, server(t))
	}
	var chosen, failovers []string
	for len(tn.Events()) > 0 {
		e := <-tn.Events()
		switch e.Kind {
		case burrow.EventRemoteChosen:
			chosen = append(chosen, e.Reason)
		case burrow.EventFailover:
			failovers = append(failovers, e.Reason)
		}
	}
	if len(chosen) != 2 || chosen[0] != "127.0.0.1:1" || len(failovers) != 1 {
		t.Fatalf("remotes chosen %q, failovers %q; want port 1 then the server, one failover", chosen, failovers)
	}
	body := get(t, tn, "http://10.88.0.1:8080/hello.txt")
	if got := strings.TrimSpace(string(body)); got != "burrow through the tunnel" {
		t.Fatalf("body %q", got)
	}
}

// TestRefusedDoesNotFailOver: a refused attempt is not retried on the next
// remote, even the same server again.
func TestRefusedDoesNotFailOver(t *testing.T) {
	variant(t, "plain")
	cfg, _, err := burrow.LoadConfig(writeOVPN(t, "999999", server(t), server(t)))
	if err != nil {
		t.Fatal(err)
	}
	cfg.HandshakeWindow = 30 * time.Second
	store := burrow.NewMemoryStore()
	cfg.AdmissionStore = store
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	tn, err := burrow.Connect(ctx, cfg)
	if err == nil {
		tn.Close()
		t.Fatal("connected with a certificate the allowlist refuses")
	}
	if !errors.Is(err, burrow.KindAuthFailed) {
		t.Fatalf("err %v, want AUTH_FAILED", err)
	}
	host, _, _ := net.SplitHostPort(server(t))
	rs, err := store.Records(host)
	if err != nil || len(rs) != 1 || rs[0].Outcome != "refused" {
		t.Fatalf("records %+v, %v; want exactly one, refused: a second would mean a failover after the answer", rs, err)
	}
}
