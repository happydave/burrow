//go:build interop

package interop

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"
)

func server(t *testing.T) string {
	t.Helper()
	addr := os.Getenv("BURROW_INTEROP_SERVER")
	if addr == "" {
		t.Fatal("BURROW_INTEROP_SERVER is unset: run through interop/run.sh")
	}
	return addr
}

// TestHardResetAnswered sends a hand-built CONTROL_HARD_RESET_CLIENT_V2 and
// expects the server's reset to ACK packet 0 under the test's session ID
// (spec notes 2.1, 4.1, 4.2).
func TestHardResetAnswered(t *testing.T) {
	var sid [8]byte
	if _, err := rand.Read(sid[:]); err != nil {
		t.Fatal(err)
	}
	reset := make([]byte, 0, 14)
	reset = append(reset, 7<<3) // opcode 7, key ID 0
	reset = append(reset, sid[:]...)
	reset = append(reset, 0)          // no ACKs
	reset = append(reset, 0, 0, 0, 0) // packet ID 0

	var d net.Dialer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "udp", server(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(reset); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("no answer to the hard reset within 5 s: %v", err)
	}
	p := buf[:n]
	if len(p) < 26 || p[0] != 8<<3 {
		t.Fatalf("want CONTROL_HARD_RESET_SERVER_V2 (0x40) of at least 26 bytes, got % x", p)
	}
	acks := int(p[9])
	if acks < 1 {
		t.Fatalf("the server's reset should ACK packet 0; it carries %d ACKs", acks)
	}
	if len(p) < 22+4*acks {
		t.Fatalf("a reset with %d ACKs needs at least %d bytes, got %d: % x", acks, 22+4*acks, len(p), p)
	}
	if got := binary.BigEndian.Uint32(p[10:14]); got != 0 {
		t.Errorf("first ACK is packet %d, want 0", got)
	}
	peer := p[10+4*acks : 18+4*acks]
	if !bytes.Equal(peer, sid[:]) {
		t.Errorf("peer session ID % x, want the test's % x", peer, sid)
	}
	t.Logf("server session %x answered with %d bytes", p[1:9], n)
}
