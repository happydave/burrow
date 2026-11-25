package session

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Control messages travel as NUL-terminated text, one per TLS record (spec
// notes 5.2 and 5.3).

const maxMessage = 16 << 10

var errMessageTooLong = errors.New("control message too long")

// messageReader splits a TLS byte stream into NUL-terminated messages.
type messageReader struct {
	r   io.Reader
	buf []byte
}

// next returns the next complete message, without its NUL.
func (m *messageReader) next() (string, error) {
	for {
		if i := bytes.IndexByte(m.buf, 0); i >= 0 {
			msg := string(m.buf[:i])
			m.buf = m.buf[i+1:]
			return msg, nil
		}
		if len(m.buf) > maxMessage {
			return "", fmt.Errorf("%w: over %d bytes without a terminator", errMessageTooLong, maxMessage)
		}
		chunk := make([]byte, 4096)
		n, err := m.r.Read(chunk)
		m.buf = append(m.buf, chunk[:n]...)
		if err != nil && n == 0 {
			return "", err
		}
	}
}

// messageName is the text before the first comma (spec notes section 9).
func messageName(msg string) string {
	name, _, _ := strings.Cut(msg, ",")
	return name
}

// serverEnd maps a server message that ends a session to its error, and
// returns nil for messages that do not (INFO, unknown ones).
func serverEnd(msg string) *endError {
	switch name := messageName(msg); name {
	case "AUTH_FAILED":
		_, reason, _ := strings.Cut(msg, ",")
		return &endError{kind: endAuthFailed, msg: msg, reason: reason}
	case "HALT":
		return &endError{kind: endHalted, msg: name}
	case "RESTART", "EXIT":
		return &endError{kind: endClosedByServer, msg: name}
	}
	return nil
}

type endKind int

const (
	endAuthFailed endKind = iota
	endClosedByServer
	endHalted // the server asks the client not to reconnect (spec notes 9)
)

// endError is a server message that ended the session.
type endError struct {
	kind   endKind
	msg    string
	reason string
}

func (e *endError) Error() string {
	if e.kind == endAuthFailed {
		if e.reason != "" {
			return "AUTH_FAILED: " + e.reason
		}
		return "AUTH_FAILED"
	}
	return "closed by server (" + e.msg + ")"
}
