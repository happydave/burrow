// Package datachan seals and opens OpenVPN data packets: AES-GCM keyed from
// the TLS exporter, in the DATA_V2 layout, with a replay window and the
// no-compression framing byte (spec notes sections 10 to 13).
package datachan

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/happydave/burrow/internal/wire"
)

// Sizes and limits.
const (
	tagSize = 16
	// RenegotiateAt and MaxPackets bound a key's use (spec notes 11.7):
	// past the first, renegotiation is due; at the second, sealing stops.
	RenegotiateAt = 1 << 28
	MaxPackets    = 1 << 29
	// Overhead is DATA_V2's bytes around the IP packet: header and peer ID,
	// packet ID, tag, and the framing byte (spec notes 11.8).
	Overhead = 4 + 4 + tagSize + 1
	// NoCompression frames every payload under comp-lzo no (spec notes 13.1).
	NoCompression = 0xFA
)

// Errors.
var (
	ErrCipher        = errors.New("datachan: unsupported cipher or key material")
	ErrPacketIDLimit = errors.New("datachan: packet ID limit reached for this key")
	ErrMalformed     = errors.New("datachan: malformed data packet")
	ErrKeyID         = errors.New("datachan: packet for another key ID")
	ErrReplay        = errors.New("datachan: replayed or too old")
	ErrAuth          = errors.New("datachan: authentication failed")
)

// Keys is one direction's AEAD and implicit IV.
type Keys struct {
	aead cipher.AEAD
	iv   [8]byte
}

// KeysFromEKM splits the 256-byte exporter block into burrow's send and
// receive keys (spec notes 10.5): burrow is the TLS client, so it sends
// with the client-to-server half.
func KeysFromEKM(ekm []byte, cipherName string) (send, recv Keys, err error) {
	var n int
	switch cipherName {
	case "AES-256-GCM":
		n = 32
	case "AES-128-GCM":
		n = 16
	default:
		return send, recv, fmt.Errorf("%w: %q", ErrCipher, cipherName)
	}
	if len(ekm) != 256 {
		return send, recv, fmt.Errorf("%w: %d bytes of key material", ErrCipher, len(ekm))
	}
	mk := func(key, iv []byte) (Keys, error) {
		b, err := aes.NewCipher(key)
		if err != nil {
			return Keys{}, err
		}
		g, err := cipher.NewGCM(b)
		if err != nil {
			return Keys{}, err
		}
		k := Keys{aead: g}
		copy(k.iv[:], iv)
		return k, nil
	}
	if send, err = mk(ekm[0:n], ekm[64:72]); err != nil {
		return send, recv, err
	}
	recv, err = mk(ekm[128:128+n], ekm[192:200])
	return send, recv, err
}

func nonce(k Keys, pid uint32) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint32(n, pid)
	copy(n[4:], k.iv[:])
	return n
}

// Sealer seals outgoing packets for one key ID.
type Sealer struct {
	keys   Keys
	keyID  uint8
	peerID uint32
	next   uint64 // next packet ID; starts at 1 (spec notes 11.7)
}

// NewSealer returns a sealer for keyID with the pushed peer ID.
func NewSealer(k Keys, keyID uint8, peerID uint32) *Sealer {
	return &Sealer{keys: k, keyID: keyID, peerID: peerID, next: 1}
}

// Wipe zeroes the implicit IV and drops the AEAD; Seal then refuses. The
// AES implementation's expanded key is outside reach, so this is best
// effort.
func (s *Sealer) Wipe() { s.keys.wipe() }

// Wipe zeroes the implicit IV and drops the AEAD; Open then refuses.
func (o *Opener) Wipe() { o.keys.wipe() }

func (k *Keys) wipe() {
	clear(k.iv[:])
	k.aead = nil
}

// Skip moves the next packet ID n forward. The skipped IDs are never sent,
// so skipping cannot reuse a nonce; tests use it to reach the limits.
func (s *Sealer) Skip(n uint64) { s.next += n }

// Seal frames plaintext as one DATA_V2 packet. renegotiate reports that the
// key has reached RenegotiateAt packets.
func (s *Sealer) Seal(plaintext []byte) (pkt []byte, renegotiate bool, err error) {
	if s.keys.aead == nil {
		return nil, false, ErrCipher
	}
	if s.next >= MaxPackets {
		return nil, true, ErrPacketIDLimit
	}
	pid := uint32(s.next)
	s.next++
	hdr := make([]byte, 8, 8+tagSize+len(plaintext)+tagSize)
	hdr[0] = byte(wire.DataV2)<<3 | s.keyID
	hdr[1], hdr[2], hdr[3] = byte(s.peerID>>16), byte(s.peerID>>8), byte(s.peerID)
	binary.BigEndian.PutUint32(hdr[4:], pid)
	sealed := s.keys.aead.Seal(nil, nonce(s.keys, pid), plaintext, hdr)
	// Go appends the tag; DATA_V2 carries it before the ciphertext (11.1).
	ct, tag := sealed[:len(plaintext)], sealed[len(plaintext):]
	pkt = append(hdr, tag...)
	pkt = append(pkt, ct...)
	return pkt, s.next > RenegotiateAt, nil
}

// Opener opens incoming packets for one key ID.
type Opener struct {
	keys   Keys
	keyID  uint8
	replay *Replay
	// V1 counts DATA_V1 packets opened (the server should send DATA_V2).
	V1 int
	// FirstID is the first packet ID opened, zero until one is.
	FirstID uint32
}

// NewOpener returns an opener for keyID whose replay window reads now.
func NewOpener(k Keys, keyID uint8, now func() time.Time) *Opener {
	return &Opener{keys: k, keyID: keyID, replay: NewReplay(now)}
}

// Open authenticates and decrypts pkt. The replay check runs first, and the
// window advances only after the tag verifies.
func (o *Opener) Open(pkt []byte) ([]byte, error) {
	if o.keys.aead == nil {
		return nil, ErrCipher
	}
	if len(pkt) < 1 {
		return nil, ErrMalformed
	}
	op, key := wire.Opcode(pkt[0]>>3), pkt[0]&7
	var aadLen int
	switch op {
	case wire.DataV2:
		aadLen = 8
	case wire.DataV1:
		aadLen = 5 // first byte and packet ID; the AAD is the packet ID alone
	default:
		return nil, fmt.Errorf("%w: opcode %d", ErrMalformed, op)
	}
	if key != o.keyID {
		return nil, fmt.Errorf("%w: %d, want %d", ErrKeyID, key, o.keyID)
	}
	if len(pkt) < aadLen+tagSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrMalformed, len(pkt))
	}
	pid := binary.BigEndian.Uint32(pkt[aadLen-4:])
	if !o.replay.Check(pid) {
		return nil, ErrReplay
	}
	aad := pkt[:aadLen]
	if op == wire.DataV1 {
		aad = pkt[1:5]
	}
	tag, ct := pkt[aadLen:aadLen+tagSize], pkt[aadLen+tagSize:]
	sealed := make([]byte, 0, len(ct)+tagSize)
	sealed = append(append(sealed, ct...), tag...)
	pt, err := o.keys.aead.Open(nil, nonce(o.keys, pid), sealed, aad)
	if err != nil {
		return nil, ErrAuth
	}
	o.replay.Accept(pid)
	if o.FirstID == 0 {
		o.FirstID = pid
	}
	if op == wire.DataV1 {
		o.V1++
	}
	return pt, nil
}

// PingPayload is the keepalive's payload after the framing byte, as the
// 2.7.0 and 2.6.19 harness servers send it (spec notes 14.1, O1: observed
// by decrypting our own session; spec notes 14.1).
var PingPayload = []byte{0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48}

// IsPing reports whether an unframed payload is the keepalive.
func IsPing(payload []byte) bool { return string(payload) == string(PingPayload) }

// Frame prepends the no-compression byte to an IP packet.
func Frame(ip []byte) []byte { return append([]byte{NoCompression}, ip...) }

// Unframe strips the no-compression byte; any other first byte, or nothing
// after it, is not a frame burrow handles.
func Unframe(pt []byte) ([]byte, bool) {
	if len(pt) < 2 || pt[0] != NoCompression {
		return nil, false
	}
	return pt[1:], true
}
