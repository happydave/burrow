package burrow

import "github.com/happydave/burrow/internal/api"

// Error is a connection error: where it happened, what kind it is, and why.
type Error = api.Error

// Stage names where in a connection something happened.
type Stage = api.Stage

// Kind classifies an Error; kinds are sentinels for errors.Is.
type Kind = api.Kind

// Stages, in connect order.
const (
	StageLink          = api.StageLink
	StageHardReset     = api.StageHardReset
	StageTLS           = api.StageTLS
	StageKeyExchange   = api.StageKeyExchange
	StagePush          = api.StagePush
	StageEstablished   = api.StageEstablished
	StageControl       = api.StageControl
	StageRenegotiation = api.StageRenegotiation
)

// Kinds.
const (
	KindUnreachable         = api.KindUnreachable
	KindSendBufferFull      = api.KindSendBufferFull
	KindPacketIDLimit       = api.KindPacketIDLimit
	KindInternalFailure     = api.KindInternalFailure
	KindTLS                 = api.KindTLS
	KindCertRejected        = api.KindCertRejected
	KindKeyExchange         = api.KindKeyExchange
	KindNotAdmitted         = api.KindNotAdmitted
	KindAuthFailed          = api.KindAuthFailed
	KindUnsupportedPush     = api.KindUnsupportedPush
	KindClosedByServer      = api.KindClosedByServer
	KindHalted              = api.KindHalted
	KindCanceled            = api.KindCanceled
	KindMessageTooLong      = api.KindMessageTooLong
	KindAdmissionRefused    = api.KindAdmissionRefused
	KindKeepaliveTimeout    = api.KindKeepaliveTimeout
	KindRenegotiationFailed = api.KindRenegotiationFailed
)
