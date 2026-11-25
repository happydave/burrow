//go:build interop

package interop

import (
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/happydave/burrow/internal/session"
)

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// echoRequest builds an IPv4 ICMP echo request from src to dst.
func echoRequest(src, dst netip.Addr, id, seq uint16) []byte {
	icmp := make([]byte, 8+16)
	icmp[0] = 8 // echo request
	binary.BigEndian.PutUint16(icmp[4:], id)
	binary.BigEndian.PutUint16(icmp[6:], seq)
	copy(icmp[8:], "burrow-echo-test")
	binary.BigEndian.PutUint16(icmp[2:], checksum(icmp))
	ip := make([]byte, 20, 20+len(icmp))
	ip[0], ip[8], ip[9] = 0x45, 64, 1
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(icmp)))
	s4, d4 := src.As4(), dst.As4()
	copy(ip[12:], s4[:])
	copy(ip[16:], d4[:])
	binary.BigEndian.PutUint16(ip[10:], checksum(ip))
	return append(ip, icmp...)
}

// echo sends one echo request through the tunnel and waits for its reply.
func echo(t *testing.T, s *session.Session, seq uint16) {
	t.Helper()
	const id = 0xb0b0
	if err := s.WritePacket(echoRequest(s.Push.Local, s.Push.Remote, id, seq)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		ip, err := s.ReadPacket(ctx)
		if err != nil {
			t.Fatalf("no echo reply for seq %d: %v", seq, err)
		}
		if len(ip) < 28 || ip[0]>>4 != 4 || ip[9] != 1 {
			continue // other traffic, such as the server's IPv6 router solicitations
		}
		icmp := ip[(ip[0]&15)*4:]
		if icmp[0] == 0 && binary.BigEndian.Uint16(icmp[4:]) == id && binary.BigEndian.Uint16(icmp[6:]) == seq {
			if src := netip.AddrFrom4([4]byte(ip[12:16])); src != s.Push.Remote {
				t.Fatalf("reply from %s, want %s", src, s.Push.Remote)
			}
			return
		}
	}
}

// TestEchoThroughTunnel sends ICMP echo requests to the server's tunnel
// address through the data channel and reads the replies: both directions,
// before any network stack exists.
func TestEchoThroughTunnel(t *testing.T) {
	variant(t, "plain")
	s := connect(t, config(t, "123456"))
	for seq := uint16(1); seq <= 3; seq++ {
		echo(t, s, seq)
	}
	st := s.Stats()
	t.Logf("3 echoes answered; data opened %d, DATA_V1 %d, first server data packet ID %d, pings received %d", st.DataOpened, st.DataV1, st.FirstDataID, st.PingsReceived)
}

// TestIdleTunnelSurvives (opt-in, BURROW_INTEROP_LONG=1) idles past the
// server's own 120 s ping-restart: only valid pings from burrow keep the
// server's side alive, and an echo afterwards proves it is.
func TestIdleTunnelSurvives(t *testing.T) {
	variant(t, "plain")
	if os.Getenv("BURROW_INTEROP_LONG") != "1" {
		t.Skip("set BURROW_INTEROP_LONG=1: this test idles for 130 s")
	}
	s := connect(t, config(t, "123456"))
	select {
	case <-s.Ended():
		t.Fatalf("the session ended while idle: %v", s.Err())
	case <-time.After(130 * time.Second): // the scenario: past the server's 120 s ping-restart
	}
	echo(t, s, 1)
	st := s.Stats()
	t.Logf("idle 130 s, then an echo answered; pings sent %d, received %d", st.PingsSent, st.PingsReceived)
}
