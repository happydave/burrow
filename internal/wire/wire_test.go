package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

var (
	sidA = SessionID{1, 2, 3, 4, 5, 6, 7, 8}
	sidB = SessionID{0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11}
)

func acks(n int) []uint32 {
	if n == 0 {
		return nil
	}
	a := make([]uint32, n)
	for i := range a {
		a[i] = uint32(100 + i)
	}
	return a
}

func TestControlRoundTrip(t *testing.T) {
	var cases []Control
	for _, op := range []Opcode{HardResetClientV2, HardResetServerV2, SoftResetV1, ControlV1} {
		for _, n := range []int{0, 1, 4} {
			cases = append(cases, Control{Op: op, KeyID: 3, Session: sidA, Acks: acks(n), PeerSession: sidB, PacketID: 0xdeadbeef, Payload: []byte("tls bytes")})
		}
	}
	for _, n := range []int{1, 4, 8} {
		cases = append(cases, Control{Op: AckV1, KeyID: 1, Session: sidA, Acks: acks(n), PeerSession: sidB})
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("op%d-acks%d", c.Op, len(c.Acks)), func(t *testing.T) {
			b, err := AppendControl(nil, c)
			if err != nil {
				t.Fatal(err)
			}
			want := 10 + 4*len(c.Acks) + len(c.Payload)
			if len(c.Acks) > 0 {
				want += 8
			}
			if c.Op != AckV1 {
				want += 4
			}
			if len(b) != want {
				t.Fatalf("encoded %d bytes, want %d", len(b), want)
			}
			got, err := DecodeControl(b)
			if err != nil {
				t.Fatal(err)
			}
			if len(c.Acks) == 0 {
				c.PeerSession = SessionID{} // not on the wire without ACKs
			}
			if c.Payload == nil {
				c.Payload = []byte{}
			}
			if !reflect.DeepEqual(got, c) {
				t.Fatalf("decoded %+v, want %+v", got, c)
			}
			again, err := AppendControl(nil, got)
			if err != nil || !bytes.Equal(again, b) {
				t.Fatalf("re-encoding differs: % x vs % x (%v)", again, b, err)
			}
		})
	}
}

func TestEncoderLimits(t *testing.T) {
	if _, err := AppendControl(nil, Control{Op: ControlV1, Acks: acks(5)}); !errors.Is(err, ErrTooManyAcks) {
		t.Errorf("5 ACKs on CONTROL_V1: %v, want ErrTooManyAcks", err)
	}
	if _, err := AppendControl(nil, Control{Op: AckV1, Acks: acks(9)}); !errors.Is(err, ErrTooManyAcks) {
		t.Errorf("9 ACKs on ACK_V1: %v, want ErrTooManyAcks", err)
	}
	full := Control{Op: ControlV1, Acks: acks(4), Payload: make([]byte, MaxControlPayload)}
	if b, err := AppendControl(nil, full); err != nil || len(b) != MaxSend {
		t.Errorf("a full CONTROL_V1 should be exactly %d bytes: %d, %v", MaxSend, len(b), err)
	}
	full.Payload = append(full.Payload, 0)
	if _, err := AppendControl(nil, full); !errors.Is(err, ErrTooLarge) {
		t.Errorf("one byte over: %v, want ErrTooLarge", err)
	}
}

func TestMalformed(t *testing.T) {
	good, err := AppendControl(nil, Control{Op: ControlV1, Session: sidA, Acks: acks(4), PeerSession: sidB, PacketID: 7, Payload: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	// Every truncation inside the header is an error: first byte, session
	// ID, ACK count, ACK entries, peer session ID, packet ID.
	for n := 0; n < len(good)-1; n++ {
		if _, err := DecodeControl(good[:n]); err == nil {
			t.Errorf("truncated to %d bytes decoded without error", n)
		}
	}
	lying := append([]byte(nil), good[:10]...)
	lying[9] = 200 // claims 200 ACKs
	if _, err := DecodeControl(lying); !errors.Is(err, ErrTooShort) {
		t.Errorf("ACK count beyond the packet: %v, want ErrTooShort", err)
	}
	if _, _, err := Header(make([]byte, MaxDatagram+1)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("2049-byte datagram: %v, want ErrTooLarge", err)
	}
	if _, _, err := Header([]byte{2 << 3}); !errors.Is(err, ErrUnknownOpcode) {
		t.Errorf("opcode 2: %v, want ErrUnknownOpcode", err)
	}
	if _, err := DecodeControl([]byte{byte(DataV2) << 3, 0, 0, 0}); err == nil {
		t.Error("a data packet decoded as control")
	}
}

// TestCapturedPackets decodes every key-ID-0 packet a stock 2.7.0 client and
// server exchanged (interop/captures) and checks it against the capture's
// summary, written independently by interop/pcapsummary.py.
func TestCapturedPackets(t *testing.T) {
	dir := filepath.Join("..", "..", "interop", "captures")
	payloads := readPcap(t, filepath.Join(dir, "stock-2.7.0-reneg.pcap"))
	summary, err := os.ReadFile(filepath.Join(dir, "stock-2.7.0-reneg.txt"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(summary)), "\n")
	if len(lines) != len(payloads) {
		t.Fatalf("%d packets in the pcap, %d summary lines", len(payloads), len(lines))
	}
	checked := 0
	for i, p := range payloads {
		f := strings.Fields(lines[i])
		op, key, err := Header(p)
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		if key != 0 {
			continue // renegotiations here are wrapped by dynamic tls-crypt
		}
		if !strings.Contains(lines[i], "key=0") {
			t.Fatalf("packet %d: key 0 here, summary says %q", i, lines[i])
		}
		if IsData(op) {
			if !strings.Contains(lines[i], fmt.Sprintf("len=%d", len(p))) {
				t.Errorf("packet %d: data length %d, summary %q", i, len(p), lines[i])
			}
			checked++
			continue
		}
		c, err := DecodeControl(p)
		if err != nil {
			t.Fatalf("packet %d (%s): %v", i, lines[i], err)
		}
		want := map[string]string{}
		for _, kv := range f[3:] {
			if k, v, ok := strings.Cut(kv, "="); ok {
				want[k] = v
			}
		}
		if got := fmt.Sprintf("%x", c.Session[:]); got != want["sid"] {
			t.Errorf("packet %d: session %s, summary %s", i, got, want["sid"])
		}
		gotAcks := fmt.Sprint(c.Acks)
		if c.Acks == nil {
			gotAcks = "[]"
		}
		wantAcks := strings.ReplaceAll(strings.SplitN(strings.SplitN(lines[i], "acks=", 2)[1], " peer=", 2)[0], ",", "")
		if gotAcks != wantAcks {
			t.Errorf("packet %d: acks %s, summary %s", i, gotAcks, wantAcks)
		}
		if len(c.Acks) > 0 {
			if got := fmt.Sprintf("%x", c.PeerSession[:]); got != want["peer"] {
				t.Errorf("packet %d: peer %s, summary %s", i, got, want["peer"])
			}
		}
		if c.Op != AckV1 {
			if got := strconv.FormatUint(uint64(c.PacketID), 10); got != want["pid"] {
				t.Errorf("packet %d: pid %s, summary %s", i, got, want["pid"])
			}
		}
		if got := strconv.Itoa(len(c.Payload)); got != want["payload"] {
			t.Errorf("packet %d: payload %s, summary %s", i, got, want["payload"])
		}
		checked++
	}
	if checked < 20 {
		t.Fatalf("only %d key-0 packets checked; the capture should hold more", checked)
	}
	t.Logf("%d key-0 packets checked against the summary", checked)
}

// readPcap returns the UDP payloads of a classic little-endian Ethernet pcap.
func readPcap(t *testing.T, path string) [][]byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 24 || !bytes.Equal(b[:4], []byte{0xd4, 0xc3, 0xb2, 0xa1}) || binary.LittleEndian.Uint32(b[20:]) != 1 {
		t.Fatal("expected a little-endian Ethernet pcap")
	}
	var out [][]byte
	for i := 24; i+16 <= len(b); {
		incl := int(binary.LittleEndian.Uint32(b[i+8:]))
		frame := b[i+16 : i+16+incl]
		i += 16 + incl
		ip := frame[14:]
		if ip[0]>>4 != 4 || ip[9] != 17 {
			continue
		}
		ihl := int(ip[0]&15) * 4
		out = append(out, ip[ihl+8:])
	}
	return out
}

func FuzzDecodeControl(f *testing.F) {
	seed, _ := AppendControl(nil, Control{Op: ControlV1, Session: sidA, Acks: acks(2), PeerSession: sidB, PacketID: 9, Payload: []byte("hi")})
	f.Add(seed)
	f.Add([]byte{byte(AckV1) << 3, 1, 2, 3, 4, 5, 6, 7, 8, 1, 0, 0, 0, 1, 1, 2, 3, 4, 5, 6, 7, 8})
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := DecodeControl(b)
		if err != nil {
			return
		}
		if len(c.Acks) > MaxAcksPiggyback && (c.Op != AckV1 || len(c.Acks) > MaxAcksAck) {
			return // decodable, but more ACKs than burrow sends
		}
		enc, err := AppendControl(nil, c)
		if err != nil {
			return // too large to send, though decodable
		}
		again, err := DecodeControl(enc)
		if err != nil {
			t.Fatalf("re-encoded packet does not decode: %v", err)
		}
		if again.Op != c.Op || again.Session != c.Session || again.PacketID != c.PacketID ||
			!reflect.DeepEqual(again.Acks, c.Acks) || !bytes.Equal(again.Payload, c.Payload) {
			t.Fatalf("round trip changed the packet: %+v vs %+v", again, c)
		}
	})
}
