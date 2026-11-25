// Package api holds the error and event types burrow returns, so internal
// packages and the public root package share them without an import cycle.

package api

import "fmt"

// Stage names where in a connection something happened.
type Stage string

// Stages, in connect order.
const (
	StageLink          Stage = "link"
	StageHardReset     Stage = "hard reset"
	StageTLS           Stage = "TLS handshake"
	StageKeyExchange   Stage = "key exchange"
	StagePush          Stage = "push"
	StageEstablished   Stage = "established"
	StageControl       Stage = "control channel"
	StageRenegotiation Stage = "renegotiation"
)

// Kind classifies an Error. Kinds are sentinels for errors.Is.
type Kind string

func (k Kind) Error() string { return string(k) }

// Kinds.
const (
	KindUnreachable         Kind = "unreachable"
	KindSendBufferFull      Kind = "send buffer full"
	KindPacketIDLimit       Kind = "packet ID limit"
	KindInternalFailure     Kind = "internal failure"
	KindTLS                 Kind = "TLS failure"
	KindCertRejected        Kind = "server certificate rejected"
	KindKeyExchange         Kind = "key exchange failed"
	KindNotAdmitted         Kind = "not admitted"
	KindAuthFailed          Kind = "AUTH_FAILED"
	KindUnsupportedPush     Kind = "unsupported pushed option"
	KindClosedByServer      Kind = "closed by server"
	KindHalted              Kind = "halted by server"
	KindCanceled            Kind = "canceled"
	KindMessageTooLong      Kind = "control message too long"
	KindAdmissionRefused    Kind = "admission refused"
	KindKeepaliveTimeout    Kind = "keepalive timeout"
	KindRenegotiationFailed Kind = "renegotiation failed"
)

// Error is a connection error: where it happened, what kind it is, and why.
type Error struct {
	Stage Stage
	Kind  Kind
	Err   error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("burrow: %s: %s", e.Stage, e.Kind)
	}
	return fmt.Sprintf("burrow: %s: %s: %v", e.Stage, e.Kind, e.Err)
}

// Unwrap returns the cause.
func (e *Error) Unwrap() error { return e.Err }

// Is reports whether target is this error's Kind.
func (e *Error) Is(target error) bool {
	k, ok := target.(Kind)
	return ok && k == e.Kind
}
