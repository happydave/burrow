//go:build interop

package interop

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/happydave/burrow"
)

// tunnel connects through the public API, with a network stack.
func tunnel(t *testing.T) *burrow.Tunnel {
	t.Helper()
	sc := config(t, "123456")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	tn, err := burrow.Connect(ctx, burrow.Config{Remotes: []string{sc.Remote}, RootCAs: sc.CAs, Certificate: sc.Cert,
		HandshakeWindow: sc.HandshakeWindow, AdmissionStore: burrow.NewMemoryStore()})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { tn.Close() })
	return tn
}

func get(t *testing.T, tn *burrow.Tunnel, url string) []byte {
	t.Helper()
	c := &http.Client{Transport: &http.Transport{DialContext: tn.DialContext}, Timeout: 120 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("GET %s: reading the body: %v", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %s", url, resp.Status)
	}
	return body
}

// TestHTTPThroughTunnel fetches the server's known text through the
// userspace stack, from a container with no TUN device.
func TestHTTPThroughTunnel(t *testing.T) {
	variant(t, "plain")
	tn := tunnel(t)
	body := get(t, tn, "http://10.88.0.1:8080/hello.txt")
	if got := strings.TrimSpace(string(body)); got != "burrow through the tunnel" {
		t.Fatalf("body %q", got)
	}
	st := tn.Stats()
	t.Logf("local %s; stack sent %d received %d, send errors %d, inject errors %d; data auth failures %d",
		tn.LocalAddr(), st.StackSent, st.StackReceived, st.StackSendErrors, st.StackInjectErrors, st.DataAuthFailed)
}

// TestLargeDownload fetches 4 MiB of random bytes and checks their hash
// against the one run.sh computed from the served file.
func TestLargeDownload(t *testing.T) {
	variant(t, "plain")
	want := os.Getenv("BURROW_INTEROP_LARGE_SHA256")
	if want == "" {
		t.Fatal("BURROW_INTEROP_LARGE_SHA256 is not set; run through interop/run.sh")
	}
	tn := tunnel(t)
	start := time.Now()
	body := get(t, tn, "http://10.88.0.1:8080/large.bin")
	elapsed := time.Since(start)
	sum := sha256.Sum256(body)
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("%d bytes with SHA-256 %s, want %s", len(body), got, want)
	}
	st := tn.Stats()
	t.Logf("4 MiB in %v (%.1f MiB/s); stack sent %d received %d; receive queue full %d; inject errors %d",
		elapsed.Round(time.Millisecond), 4/elapsed.Seconds(), st.StackSent, st.StackReceived, st.ReceiveFull, st.StackInjectErrors)
}
