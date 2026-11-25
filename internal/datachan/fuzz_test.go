package datachan

import (
	"bytes"
	"testing"
	"time"
)

// FuzzOpen drives the opener with arbitrary datagrams. Without the key,
// nothing but a genuine packet may open, and nothing may panic.
func FuzzOpen(f *testing.F) {
	ekm := make([]byte, 256)
	for i := range ekm {
		ekm[i] = byte(i * 7)
	}
	send, _, err := KeysFromEKM(ekm, "AES-256-GCM")
	if err != nil {
		f.Fatal(err)
	}
	s := NewSealer(send, 0, 5)
	var genuine [][]byte
	for _, pt := range [][]byte{Frame([]byte{0x45, 1, 2, 3}), Frame(PingPayload)} {
		p, _, err := s.Seal(pt)
		if err != nil {
			f.Fatal(err)
		}
		genuine = append(genuine, p)
		f.Add(p)
	}
	f.Add([]byte{0x48})
	f.Add([]byte{0x30, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		// The sealer's own keys open its packets: the opener is built from
		// the same direction's keys.
		o := NewOpener(send, 0, time.Now)
		if _, err := o.Open(data); err == nil {
			for _, g := range genuine {
				if bytes.Equal(g, data) {
					return
				}
			}
			t.Fatalf("opened a packet the sealer did not make: % x", data)
		}
	})
}
