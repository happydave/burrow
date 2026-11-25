package burrow

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/happydave/burrow/internal/fakeserver"
)

func TestCountersAndEndedEvents(t *testing.T) {
	srv := fakeserver.Start(t, fakeserver.Options{Push: fakeserver.Push})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tn, err := Connect(ctx, Config{Remotes: []string{srv.Addr()}, RootCAs: srv.Pool, AdmissionStore: NewMemoryStore(),
		RawPackets: true, StatsInterval: 100 * time.Millisecond, HandshakeWindow: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer tn.Close()
	var counters []map[string]int64
	next := func(kind EventKind) Event {
		t.Helper()
		for {
			select {
			case e := <-tn.Events():
				if e.Kind == EventCounters {
					counters = append(counters, e.Counters)
				}
				if e.Kind == kind {
					return e
				}
			case <-time.After(3 * time.Second):
				t.Fatalf("no %s event", kind)
			}
		}
	}
	next(EventCounters)
	for i := range 5 {
		if err := tn.WritePacket([]byte{0x45, byte(i), 0, 0}); err != nil {
			t.Fatal(err)
		}
		if _, err := tn.ReadPacket(ctx); err != nil {
			t.Fatal(err)
		}
	}
	next(EventCounters)
	first, last := counters[0], counters[len(counters)-1]
	if last["bytes sent"] < first["bytes sent"]+20 || last["bytes received"] < first["bytes received"]+20 {
		t.Fatalf("byte counters did not grow by the 20 bytes each way: first %v, last %v", first, last)
	}

	if !srv.Message(0, "EXIT") {
		t.Fatal("the fake could not send EXIT")
	}
	e := next(EventEnded)
	if e.Stage != StageEstablished || !strings.Contains(e.Reason, "closed by server") || e.Counters == nil {
		t.Fatalf("ended event %+v, want closed by server at the established stage, with counters", e)
	}
	<-tn.Done()
	for len(tn.Events()) > 0 {
		if e := <-tn.Events(); e.Kind == EventEnded {
			t.Fatal("a second ended event")
		}
	}
}
