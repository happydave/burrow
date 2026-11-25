// Package wire encodes and decodes OpenVPN packet headers in the plain form
// (no tls-auth, no tls-crypt). Layouts are from docs/spec-notes.md: the first
// byte (section 1.1), the control packet (2.1) and the size limits (18.1, 18.4).
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Opcode is the high five bits of a packet's first byte.
type Opcode uint8

// The opcodes burrow handles (spec notes 1.2).
const (
	SoftResetV1       Opcode = 3
	ControlV1         Opcode = 4
	AckV1             Opcode = 5
	DataV1            Opcode = 6
	HardResetClientV2 Opcode = 7
	HardResetServerV2 Opcode = 8
	DataV2            Opcode = 9
)

// Size limits.
const (
	// MaxDatagram is the largest datagram burrow accepts (spec notes 18.4).
	MaxDatagram = 2048
	// MaxSend is the largest control packet burrow sends: 1250 bytes of IP
	// datagram less 28 of IPv4 and UDP headers (spec notes 18.1).
	MaxSend = 1222
	// MaxAcksPiggyback and MaxAcksAck bound the ACKs burrow puts in one
	// packet (spec notes 2.4).
	MaxAcksPiggyback = 4
	MaxAcksAck       = 8
	// MaxControlPayload is the TLS data one CONTROL_V1 carries with a full
	// piggyback: MaxSend less a header of 1 + 8 + 1 + 4*4 + 8 + 4 bytes.
	MaxControlPayload = MaxSend - 38
)

// IsControl reports whether op is a control-channel opcode.
func IsControl(op Opcode) bool {
	switch op {
	case SoftResetV1, ControlV1, AckV1, HardResetClientV2, HardResetServerV2:
		return true
	}
	return false
}

// IsData reports whether op is a data-channel opcode.
func IsData(op Opcode) bool { return op == DataV1 || op == DataV2 }

// SessionID is a peer's 8-byte session identifier.
type SessionID [8]byte

// Errors.
var (
	ErrTooShort      = errors.New("wire: packet too short")
	ErrTooLarge      = errors.New("wire: packet too large")
	ErrUnknownOpcode = errors.New("wire: unknown opcode")
	ErrTooManyAcks   = errors.New("wire: too many ACKs")
)

// Header splits a packet's first byte into its opcode and key ID.
func Header(b []byte) (Opcode, uint8, error) {
	if len(b) == 0 {
		return 0, 0, fmt.Errorf("%w: no first byte", ErrTooShort)
	}
	if len(b) > MaxDatagram {
		return 0, 0, fmt.Errorf("%w: %d bytes", ErrTooLarge, len(b))
	}
	op, key := Opcode(b[0]>>3), b[0]&7
	if !IsControl(op) && !IsData(op) {
		return op, key, fmt.Errorf("%w %d", ErrUnknownOpcode, op)
	}
	return op, key, nil
}

// Control is a decoded control packet. Payload aliases the decoded bytes.
type Control struct {
	Op          Opcode
	KeyID       uint8
	Session     SessionID
	Acks        []uint32
	PeerSession SessionID // meaningful only when Acks is non-empty
	PacketID    uint32    // absent on the wire for AckV1
	Payload     []byte
}

// DecodeControl decodes a control packet.
func DecodeControl(b []byte) (Control, error) {
	op, key, err := Header(b)
	if err != nil {
		return Control{}, err
	}
	if !IsControl(op) {
		return Control{}, fmt.Errorf("wire: opcode %d is not a control opcode", op)
	}
	c := Control{Op: op, KeyID: key}
	if len(b) < 10 {
		return Control{}, fmt.Errorf("%w: session ID and ACK count need 10 bytes, have %d", ErrTooShort, len(b))
	}
	copy(c.Session[:], b[1:9])
	n := int(b[9])
	i := 10
	if len(b) < i+4*n {
		return Control{}, fmt.Errorf("%w: %d ACKs need %d bytes, have %d", ErrTooShort, n, i+4*n, len(b))
	}
	if n > 0 {
		c.Acks = make([]uint32, n)
		for k := range c.Acks {
			c.Acks[k] = binary.BigEndian.Uint32(b[i:])
			i += 4
		}
		if len(b) < i+8 {
			return Control{}, fmt.Errorf("%w: peer session ID", ErrTooShort)
		}
		copy(c.PeerSession[:], b[i:i+8])
		i += 8
	}
	if op != AckV1 {
		if len(b) < i+4 {
			return Control{}, fmt.Errorf("%w: packet ID", ErrTooShort)
		}
		c.PacketID = binary.BigEndian.Uint32(b[i:])
		i += 4
	}
	c.Payload = b[i:]
	return c, nil
}

// AppendControl appends the encoding of c to dst.
func AppendControl(dst []byte, c Control) ([]byte, error) {
	if !IsControl(c.Op) || c.KeyID > 7 {
		return dst, fmt.Errorf("wire: cannot encode opcode %d key %d as control", c.Op, c.KeyID)
	}
	limit := MaxAcksPiggyback
	if c.Op == AckV1 {
		limit = MaxAcksAck
	}
	if len(c.Acks) > limit {
		return dst, fmt.Errorf("%w: %d on opcode %d, limit %d", ErrTooManyAcks, len(c.Acks), c.Op, limit)
	}
	size := 10 + 4*len(c.Acks) + len(c.Payload)
	if len(c.Acks) > 0 {
		size += 8
	}
	if c.Op != AckV1 {
		size += 4
	}
	if size > MaxSend {
		return dst, fmt.Errorf("%w: %d bytes, limit %d", ErrTooLarge, size, MaxSend)
	}
	dst = append(dst, byte(c.Op)<<3|c.KeyID)
	dst = append(dst, c.Session[:]...)
	dst = append(dst, byte(len(c.Acks)))
	for _, a := range c.Acks {
		dst = binary.BigEndian.AppendUint32(dst, a)
	}
	if len(c.Acks) > 0 {
		dst = append(dst, c.PeerSession[:]...)
	}
	if c.Op != AckV1 {
		dst = binary.BigEndian.AppendUint32(dst, c.PacketID)
	}
	return append(dst, c.Payload...), nil
}
