package api

import "time"

// EventKind classifies an Event.
type EventKind string

// Event kinds.
const (
	EventRetransmit            EventKind = "retransmit"
	EventPacketDropped         EventKind = "packet dropped"
	EventStageEntered          EventKind = "stage entered"
	EventStageCompleted        EventKind = "stage completed"
	EventControlMessage        EventKind = "control message received"
	EventUnknownMessage        EventKind = "unknown control message"
	EventRemoteChosen          EventKind = "remote chosen"
	EventFailover              EventKind = "failover"
	EventRenegotiationStarted  EventKind = "renegotiation started"
	EventRenegotiationFinished EventKind = "renegotiation finished"
	EventKeyTransition         EventKind = "key transition"
	EventCounters              EventKind = "counters"
	EventEnded                 EventKind = "ended"
)

// Event is one thing that happened in a connection, for observers. Fields
// not meaningful for a kind are zero.
type Event struct {
	Kind     EventKind
	Time     time.Time // from the connection's clock
	Stage    Stage
	KeyID    uint8
	PacketID uint32
	Reason   string // why a packet was dropped, or the message text
	// Lost is how many events were dropped, for a slow subscriber, since
	// the last one it received.
	Lost int
	// Counters is the tunnel's counters, by name, on a counters event.
	Counters map[string]int64
}
