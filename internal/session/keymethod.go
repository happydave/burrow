package session

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"strings"
)

// Key method 2 (spec notes section 6).

const maxKeyMessage = 4096

var errKeyExchange = errors.New("key exchange failed")

// peerInfo is everything burrow advertises (spec notes 7.2 and 7.3): no more,
// since every capability claimed must be implemented.
func peerInfo(version string) string {
	return "IV_VER=burrow-" + version + "\n" +
		"IV_PLAT=" + platform() + "\n" +
		"IV_PROTO=142\n" +
		"IV_CIPHERS=AES-256-GCM:AES-128-GCM\n"
}

// platform maps GOOS to the IV_PLAT values the man page lists.
func platform() string {
	switch runtime.GOOS {
	case "darwin", "ios":
		return "mac"
	case "windows":
		return "win"
	case "linux", "solaris", "openbsd", "netbsd", "freebsd":
		return runtime.GOOS
	}
	return "linux"
}

func appendString(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(s)+1))
	b = append(b, s...)
	return append(b, 0)
}

// clientKeyMessage builds burrow's key-method-2 message.
func clientKeyMessage(version string) ([]byte, error) {
	b := []byte{0, 0, 0, 0, 2}
	random := make([]byte, 48+32+32)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	b = append(b, random...)
	b = appendString(b, "") // options string
	b = appendString(b, "") // username
	b = appendString(b, "") // password
	return appendString(b, peerInfo(version)), nil
}

// serverKeyMessage is what burrow keeps of the server's reply: its options
// string, for logging, and which layout it had.
type serverKeyMessage struct {
	options   string
	preMaster bool // true if it carried the draft's 48-byte pre-master field
	length    int
}

// parseServerKeyMessage reads the server's key-method-2 message. It tries
// miragevpn-spec's layout (no pre-master) first and the draft's second
// (spec notes 6.4); strings may be absent at the end.
func parseServerKeyMessage(m []byte) (serverKeyMessage, error) {
	if len(m) > maxKeyMessage {
		return serverKeyMessage{}, fmt.Errorf("%w: %d-byte message, limit %d", errKeyExchange, len(m), maxKeyMessage)
	}
	if len(m) < 5 || !bytes.Equal(m[:4], []byte{0, 0, 0, 0}) || m[4] != 2 {
		return serverKeyMessage{}, fmt.Errorf("%w: not a key-method-2 message", errKeyExchange)
	}
	for _, pre := range []bool{false, true} {
		off := 5 + 64
		if pre {
			off += 48
		}
		if strs, ok := parseStrings(m, off); ok {
			return serverKeyMessage{options: strs[0], preMaster: pre, length: len(m)}, nil
		}
	}
	return serverKeyMessage{}, fmt.Errorf("%w: %d-byte message fits neither layout", errKeyExchange, len(m))
}

// parseStrings reads up to four length-prefixed strings from m[off:], which
// must end exactly at the end of m.
func parseStrings(m []byte, off int) ([4]string, bool) {
	var out [4]string
	if off > len(m) {
		return out, false
	}
	for i := 0; i < 4 && off < len(m); i++ {
		if off+2 > len(m) {
			return out, false
		}
		n := int(binary.BigEndian.Uint16(m[off:]))
		off += 2
		if off+n > len(m) {
			return out, false
		}
		out[i] = strings.TrimRight(string(m[off:off+n]), "\x00")
		off += n
	}
	return out, off == len(m)
}
