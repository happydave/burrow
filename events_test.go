package burrow

import (
	"context"
	"crypto/x509"
	"slices"
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

// TestMTUBounds (review finding 8): the stack MTU is capped so a sealed
// packet fits the receive bound, and an mssfix that leaves it under 576 is
// refused before anything is sent.
func TestMTUBounds(t *testing.T) {
	if got := stackMTU(Config{MSSFix: -1}, 9000, false); got != maxMTU {
		t.Fatalf("pushed tun-mtu 9000 with mssfix off: %d, want the cap %d", got, maxMTU)
	}
	for _, c := range []Config{{MSSFix: 20}, {MSSFix: 60}, {MSSFix: 600, MSSFixPayload: true}} {
		c.Remotes, c.RootCAs = []string{"192.0.2.1:1194"}, x509.NewCertPool()
		if err := c.validate(); err == nil || !strings.Contains(err.Error(), "MSSFix") {
			t.Errorf("mssfix %d (payload %v): %v, want a refusal", c.MSSFix, c.MSSFixPayload, err)
		}
	}
}

// TestRawModeMTU (finding 15) and the pushed flags (finding 20), through
// Connect to the fake server.
func TestRawModeMTU(t *testing.T) {
	srv := fakeserver.Start(t, fakeserver.Options{Push: fakeserver.Push})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tn, err := Connect(ctx, Config{Remotes: []string{srv.Addr()}, RootCAs: srv.Pool, AdmissionStore: NewMemoryStore(),
		RawPackets: true, HandshakeWindow: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer tn.Close()
	if tn.MTU() != 1439 {
		t.Fatalf("MTU %d, want 1439 (1492 mtu over IPv4)", tn.MTU())
	}
	big := make([]byte, tn.MTU()+1)
	big[0] = 0x45
	if err := tn.WritePacket(big); err == nil {
		t.Fatal("a packet over the MTU was sent")
	}
	if err := tn.WritePacket(big[:tn.MTU()]); err != nil {
		t.Fatalf("a packet at the MTU: %v", err)
	}
	if p := tn.Pushed(); !slices.Contains(p.Flags, "cc-exit") {
		t.Fatalf("pushed flags %q, want cc-exit among them", p.Flags)
	}
}
