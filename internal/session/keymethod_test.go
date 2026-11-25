package session

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"testing"
)

func tlsCertForTest() tls.Certificate { return tls.Certificate{} }

// draftStrings reads burrow's own message with the draft's layout: 4 zero
// bytes, method, 48 + 32 + 32 random bytes, then four strings.
func draftStrings(t *testing.T, m []byte) [4]string {
	t.Helper()
	if !bytes.Equal(m[:5], []byte{0, 0, 0, 0, 2}) {
		t.Fatalf("message starts % x", m[:5])
	}
	off := 5 + 112
	var out [4]string
	for i := range out {
		n := int(binary.BigEndian.Uint16(m[off:]))
		s := m[off+2 : off+2+n]
		if n == 0 || s[n-1] != 0 {
			t.Fatalf("string %d is not NUL-terminated with its NUL counted: % x", i, s)
		}
		out[i] = string(s[:n-1])
		off += 2 + n
	}
	if off != len(m) {
		t.Fatalf("%d trailing bytes", len(m)-off)
	}
	return out
}

func TestClientKeyMessage(t *testing.T) {
	m, err := clientKeyMessage("0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	s := draftStrings(t, m)
	if s[0] != "" || s[1] != "" || s[2] != "" {
		t.Errorf("options, username, password = %q %q %q, want all empty", s[0], s[1], s[2])
	}
	want := "IV_VER=burrow-0.0.1\nIV_PLAT=" + platform() + "\nIV_PROTO=142\nIV_CIPHERS=AES-256-GCM:AES-128-GCM\n"
	if s[3] != want {
		t.Errorf("peer-info %q, want %q", s[3], want)
	}
	m2, _ := clientKeyMessage("0.0.1")
	if bytes.Equal(m[5:117], m2[5:117]) {
		t.Error("two messages carry the same random bytes")
	}
}

func serverMessage(pre bool, strs ...string) []byte {
	m := []byte{0, 0, 0, 0, 2}
	n := 64
	if pre {
		n += 48
	}
	m = append(m, make([]byte, n)...)
	for _, s := range strs {
		m = appendString(m, s)
	}
	return m
}

func TestParseServerKeyMessage(t *testing.T) {
	for _, pre := range []bool{false, true} {
		got, err := parseServerKeyMessage(serverMessage(pre, "V4,dev-type tun", "", "", ""))
		if err != nil {
			t.Fatalf("layout pre=%v: %v", pre, err)
		}
		if got.options != "V4,dev-type tun" || got.preMaster != pre {
			t.Errorf("layout pre=%v parsed as %+v", pre, got)
		}
	}
	if _, err := parseServerKeyMessage(serverMessage(false, "V4")); err != nil {
		t.Errorf("a message ending after the options string: %v", err)
	}
	bad := [][]byte{
		serverMessage(false, "V4", "", "", "")[:79],        // cut inside the third string
		append([]byte{0, 0, 0, 1, 2}, make([]byte, 70)...), // nonzero leading byte
		append([]byte{0, 0, 0, 0, 1}, make([]byte, 70)...), // key method 1
		make([]byte, maxKeyMessage+1),                      // over the bound
	}
	for i, m := range bad {
		if _, err := parseServerKeyMessage(m); !errors.Is(err, errKeyExchange) {
			t.Errorf("bad message %d: %v, want errKeyExchange", i, err)
		}
	}
}
