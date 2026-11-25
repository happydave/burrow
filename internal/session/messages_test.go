package session

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// chunks returns its pieces one Read at a time.
type chunks struct{ parts [][]byte }

func (c *chunks) Read(p []byte) (int, error) {
	if len(c.parts) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.parts[0])
	c.parts[0] = c.parts[0][n:]
	if len(c.parts[0]) == 0 {
		c.parts = c.parts[1:]
	}
	return n, nil
}

func TestMessageReader(t *testing.T) {
	r := &messageReader{r: &chunks{parts: [][]byte{[]byte("PUSH_REP"), []byte("LY,a,b\x00INFO,x"), []byte("\x00")}}}
	for _, want := range []string{"PUSH_REPLY,a,b", "INFO,x"} {
		got, err := r.next()
		if err != nil || got != want {
			t.Fatalf("got %q, %v; want %q", got, err, want)
		}
	}
	if _, err := r.next(); !errors.Is(err, io.EOF) {
		t.Fatalf("end of stream: %v", err)
	}
	long := &messageReader{r: bytes.NewReader([]byte(strings.Repeat("x", maxMessage+4097)))}
	if _, err := long.next(); !errors.Is(err, errMessageTooLong) {
		t.Fatalf("an unterminated 20 KiB message: %v", err)
	}
}

func TestServerEnd(t *testing.T) {
	cases := []struct {
		msg    string
		kind   endKind
		ends   bool
		reason string
	}{
		{"AUTH_FAILED", endAuthFailed, true, ""},
		{"AUTH_FAILED,cipher negotiation failed", endAuthFailed, true, "cipher negotiation failed"},
		{"RESTART,[N]server restarting", endClosedByServer, true, ""},
		{"HALT", endClosedByServer, true, ""},
		{"EXIT", endClosedByServer, true, ""},
		{"INFO,something", 0, false, ""},
		{"NEW_THING,1", 0, false, ""},
	}
	for _, c := range cases {
		e := serverEnd(c.msg)
		if (e != nil) != c.ends {
			t.Fatalf("%q: ends=%v", c.msg, e != nil)
		}
		if e != nil && (e.kind != c.kind || e.reason != c.reason) {
			t.Errorf("%q: %+v", c.msg, e)
		}
	}
}
