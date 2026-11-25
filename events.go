package burrow

import "github.com/happydave/burrow/internal/api"

// Event is one thing that happened in a connection, for observers.
type Event = api.Event

// EventKind classifies an Event.
type EventKind = api.EventKind

// Event kinds.
const (
	EventRetransmit            = api.EventRetransmit
	EventPacketDropped         = api.EventPacketDropped
	EventStageEntered          = api.EventStageEntered
	EventStageCompleted        = api.EventStageCompleted
	EventControlMessage        = api.EventControlMessage
	EventUnknownMessage        = api.EventUnknownMessage
	EventRemoteChosen          = api.EventRemoteChosen
	EventFailover              = api.EventFailover
	EventRenegotiationStarted  = api.EventRenegotiationStarted
	EventRenegotiationFinished = api.EventRenegotiationFinished
	EventKeyTransition         = api.EventKeyTransition
	EventCounters              = api.EventCounters
	EventEnded                 = api.EventEnded
)
