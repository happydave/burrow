package datachan

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func indexBlock() []byte {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// mirror returns the server's view of the same block: its send half is
// burrow's receive half, and the reverse.
func mirror(ekm []byte) []byte {
	m := make([]byte, 256)
	copy(m[0:128], ekm[128:256])
	copy(m[128:256], ekm[0:128])
	return m
}

func TestKeyOffsets(t *testing.T) {
	for _, c := range []struct {
		name string
		n    int
	}{{"AES-256-GCM", 32}, {"AES-128-GCM", 16}} {
		send, recv, err := KeysFromEKM(indexBlock(), c.name)
		if err != nil {
			t.Fatal(err)
		}
		if send.iv != [8]byte{64, 65, 66, 67, 68, 69, 70, 71} || recv.iv != [8]byte{192, 193, 194, 195, 196, 197, 198, 199} {
			t.Fatalf("%s: implicit IVs %v / %v", c.name, send.iv, recv.iv)
		}
		// The keys are checked by sealing with a cipher built from the
		// expected bytes and opening with ours.
		blk, _ := aes.NewCipher(indexBlock()[0:c.n])
		want, _ := cipher.NewGCM(blk)
		if !bytes.Equal(want.Seal(nil, make([]byte, 12), []byte("x"), nil), send.aead.Seal(nil, make([]byte, 12), []byte("x"), nil)) {
			t.Errorf("%s: send key is not bytes 0-%d", c.name, c.n-1)
		}
		blk, _ = aes.NewCipher(indexBlock()[128 : 128+c.n])
		want, _ = cipher.NewGCM(blk)
		if !bytes.Equal(want.Seal(nil, make([]byte, 12), []byte("x"), nil), recv.aead.Seal(nil, make([]byte, 12), []byte("x"), nil)) {
			t.Errorf("%s: receive key is not bytes 128-%d", c.name, 128+c.n-1)
		}
	}
	if _, _, err := KeysFromEKM(indexBlock(), "AES-256-CBC"); !errors.Is(err, ErrCipher) {
		t.Errorf("CBC: %v", err)
	}
	if _, _, err := KeysFromEKM(make([]byte, 255), "AES-256-GCM"); !errors.Is(err, ErrCipher) {
		t.Errorf("short block: %v", err)
	}
}

func pair(t *testing.T, cipherName string) (*Sealer, *Opener) {
	t.Helper()
	send, _, err := KeysFromEKM(indexBlock(), cipherName)
	if err != nil {
		t.Fatal(err)
	}
	_, srvRecv, err := KeysFromEKM(mirror(indexBlock()), cipherName)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(0, 0)
	return NewSealer(send, 0, 7), NewOpener(srvRecv, 0, func() time.Time { return clock })
}

func TestRoundTrip(t *testing.T) {
	for _, c := range []string{"AES-256-GCM", "AES-128-GCM"} {
		s, o := pair(t, c)
		pkt, _, err := s.Seal([]byte("an IP packet"))
		if err != nil {
			t.Fatal(err)
		}
		pt, err := o.Open(pkt)
		if err != nil || string(pt) != "an IP packet" {
			t.Fatalf("%s: %q, %v", c, pt, err)
		}
	}
	s, _ := pair(t, "AES-256-GCM")
	pkt, _, _ := s.Seal([]byte("x"))
	_, recv, _ := KeysFromEKM(mirror(indexBlock()), "AES-256-GCM")
	other := NewOpener(recv, 1, time.Now)
	if _, err := other.Open(pkt); !errors.Is(err, ErrKeyID) {
		t.Fatalf("a key-0 packet opened under key 1: %v", err)
	}
}

// TestKnownAnswer builds the expected packet directly from the spec notes'
// layout and checks Seal produces the same bytes.
func TestKnownAnswer(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	iv := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	ekm := make([]byte, 256)
	copy(ekm[0:], key)
	copy(ekm[64:], iv)
	send, _, err := KeysFromEKM(ekm, "AES-256-GCM")
	if err != nil {
		t.Fatal(err)
	}
	s := NewSealer(send, 2, 0x010203)
	pt := []byte{NoCompression, 0x45, 0, 0, 20}
	got, _, err := s.Seal(pt)
	if err != nil {
		t.Fatal(err)
	}
	hdr := []byte{9<<3 | 2, 0x01, 0x02, 0x03, 0, 0, 0, 1}
	nonce := append([]byte{0, 0, 0, 1}, iv...)
	blk, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(blk)
	sealed := g.Seal(nil, nonce, pt, hdr)
	want := append(append(append([]byte{}, hdr...), sealed[len(pt):]...), sealed[:len(pt)]...)
	if !bytes.Equal(got, want) {
		t.Fatalf("sealed\n% x\nwant\n% x", got, want)
	}
}

func TestTamperIsRefusedAndDoesNotAdvance(t *testing.T) {
	regions := map[string]int{"opcode byte": 0, "peer ID": 2, "packet ID": 7, "tag": 12, "ciphertext": 26}
	for name, off := range regions {
		s, o := pair(t, "AES-256-GCM")
		good, _, _ := s.Seal([]byte("payload bytes"))
		bad := append([]byte(nil), good...)
		bad[off] ^= 0x01
		if _, err := o.Open(bad); err == nil {
			t.Fatalf("%s: a flipped bit was accepted", name)
		}
		if pt, err := o.Open(good); err != nil || string(pt) != "payload bytes" {
			t.Fatalf("%s: the genuine packet was refused after the forgery: %v", name, err)
		}
	}
}

func TestReplayWindow(t *testing.T) {
	now := time.Unix(1000, 0)
	r := NewReplay(func() time.Time { return now })
	accept := func(pid uint32) bool {
		if !r.Check(pid) {
			return false
		}
		r.Accept(pid)
		return true
	}
	for _, pid := range []uint32{1, 2, 3, 70} {
		if !accept(pid) {
			t.Fatalf("in-order %d refused", pid)
		}
	}
	if !accept(10) {
		t.Fatal("10, within 64 of 70, refused")
	}
	if accept(10) {
		t.Fatal("a repeat of 10 accepted")
	}
	if accept(6) {
		t.Fatal("6, 64 below 70, accepted")
	}
	now = now.Add(16 * time.Second)
	if accept(20) {
		t.Fatal("an out-of-order packet 16 s after the highest accepted")
	}
	if !accept(71) {
		t.Fatal("a new highest refused after the delay")
	}
}

func TestForgeryDoesNotMoveTheWindow(t *testing.T) {
	s, o := pair(t, "AES-256-GCM")
	var pkts [][]byte
	for range 3 {
		p, _, _ := s.Seal([]byte("x"))
		pkts = append(pkts, p)
	}
	forged := append([]byte(nil), pkts[0]...)
	binary.BigEndian.PutUint32(forged[4:], 1000) // a high packet ID with a tag that cannot verify
	if _, err := o.Open(forged); !errors.Is(err, ErrAuth) {
		t.Fatalf("forged packet: %v", err)
	}
	for i, p := range pkts {
		if _, err := o.Open(p); err != nil {
			t.Fatalf("genuine packet %d refused after a forgery claimed ID 1000: %v", i+1, err)
		}
	}
}

func TestPacketIDThresholds(t *testing.T) {
	s, _ := pair(t, "AES-256-GCM")
	s.next = RenegotiateAt - 1
	if _, ren, err := s.Seal([]byte("x")); err != nil || ren {
		t.Fatalf("packet %d: renegotiate=%v err=%v", RenegotiateAt-1, ren, err)
	}
	if _, ren, err := s.Seal([]byte("x")); err != nil || !ren {
		t.Fatalf("packet %d: renegotiate=%v err=%v, want the renegotiation report", RenegotiateAt, ren, err)
	}
	s.next = MaxPackets - 1
	if _, _, err := s.Seal([]byte("x")); err != nil {
		t.Fatalf("last packet: %v", err)
	}
	if _, _, err := s.Seal([]byte("x")); !errors.Is(err, ErrPacketIDLimit) {
		t.Fatalf("packet %d: %v, want the limit", MaxPackets, err)
	}
}

func TestFraming(t *testing.T) {
	ip := []byte{0x45, 0, 0, 20}
	got, ok := Unframe(Frame(ip))
	if !ok || !bytes.Equal(got, ip) {
		t.Fatalf("round trip: % x, %v", got, ok)
	}
	if _, ok := Unframe([]byte{0x66, 0x45}); ok {
		t.Error("a compressed frame was accepted")
	}
	if _, ok := Unframe([]byte{NoCompression}); ok {
		t.Error("an empty frame was accepted")
	}
}

func TestOpenerRefusesAReplayedPacket(t *testing.T) {
	s, o := pair(t, "AES-256-GCM")
	pkt, _, _ := s.Seal([]byte("once"))
	if _, err := o.Open(pkt); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Open(pkt); !errors.Is(err, ErrReplay) {
		t.Fatalf("the same genuine packet opened twice: %v", err)
	}
}
