package session

import (
	"errors"
	"strings"
	"testing"
)

// FuzzPush drives the push assembler and parser with arbitrary server
// messages, split at NULs into a sequence.
func FuzzPush(f *testing.F) {
	f.Add([]byte(targetPush))
	f.Add([]byte("PUSH_REPLY,route 10.0.0.1,push-continuation 2\x00PUSH_REPLY," + strings.TrimPrefix(targetPush, "PUSH_REPLY,") + ",push-continuation 1"))
	f.Add([]byte("PUSH_REPLY,ifconfig 1.2.3.4 1.2.3.5,peer-id 99999999,cipher AES-256-GCM"))
	f.Add([]byte("PUSH_REPLY,,,,tun-mtu 575"))
	f.Fuzz(func(t *testing.T, data []byte) {
		var a pushAssembler
		for _, m := range strings.Split(string(data), "\x00") {
			done, err := a.add(m)
			if err != nil {
				return
			}
			if !done {
				continue
			}
			p, err := parsePush(a.options)
			if err != nil {
				return
			}
			if !p.Local.IsValid() {
				t.Fatalf("accepted a push with no local address: %+v", p)
			}
			return
		}
	})
}

// FuzzServerKeyMessage drives the parser of the server's key-method-2
// message.
func FuzzServerKeyMessage(f *testing.F) {
	ok := append([]byte{0, 0, 0, 0, 2}, make([]byte, 64)...)
	ok = appendString(ok, "V4,dev-type tun")
	f.Add(ok)
	f.Add(serverMessage(true, "V4,dev-type tun", "", "", ""))
	f.Add([]byte{0, 0, 0, 0, 2})
	f.Add(append(append([]byte{0, 0, 0, 0, 2}, make([]byte, 64)...), 0xff, 0xff))
	f.Fuzz(func(t *testing.T, data []byte) {
		km, err := parseServerKeyMessage(data)
		if err != nil && !errors.Is(err, errKeyExchange) {
			t.Fatalf("error %v is not a key-exchange error", err)
		}
		if err == nil && km.length != len(data) {
			t.Fatalf("parsed length %d of %d bytes", km.length, len(data))
		}
	})
}
