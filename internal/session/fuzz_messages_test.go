package session

import (
	"bytes"
	"testing"
)

// FuzzMessages drives the control-message reader and the server-message
// classifier with an arbitrary TLS byte stream.
func FuzzMessages(f *testing.F) {
	f.Add([]byte("PUSH_REPLY,ping 10\x00AUTH_FAILED,not allowed\x00EXIT\x00"))
	f.Add([]byte("INFO,hello\x00RESTART,[0]\x00HALT"))
	f.Add(bytes.Repeat([]byte{'A'}, maxMessage+10))
	f.Fuzz(func(t *testing.T, data []byte) {
		r := &messageReader{r: bytes.NewReader(data)}
		for {
			m, err := r.next()
			if err != nil {
				return
			}
			if len(m) > maxMessage {
				t.Fatalf("a message of %d bytes, over the %d bound", len(m), maxMessage)
			}
			_ = serverEnd(m)
		}
	})
}
