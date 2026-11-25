package session

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/happydave/burrow/internal/api"
	"github.com/happydave/burrow/internal/wire"
)

// TestRetransmitAndLinkDropEvents: a server that never answers the hard
// reset, but sends one datagram over the size bound, gives a retransmit
// event and an oversize drop event.
func TestRetransmitAndLinkDropEvents(t *testing.T) {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 2048)
		_, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo(make([]byte, wire.MaxDatagram+100), from)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	var mu sync.Mutex
	var events []api.Event
	cfg := Config{Remote: pc.LocalAddr().String(), CAs: x509.NewCertPool(), Version: "test",
		HandshakeWindow: 3 * time.Second, Events: func(e api.Event) {
			mu.Lock()
			events = append(events, e)
			mu.Unlock()
		}}
	_, err = Connect(context.Background(), cfg)
	if !errors.Is(err, api.KindUnreachable) {
		t.Fatalf("err %v, want unreachable", err)
	}
	mu.Lock()
	defer mu.Unlock()
	var retransmit, oversize bool
	for _, e := range events {
		switch {
		case e.Kind == api.EventRetransmit && e.KeyID == 0 && e.Stage == api.StageHardReset:
			retransmit = true
		case e.Kind == api.EventPacketDropped && strings.HasPrefix(e.Reason, "oversize datagram"):
			oversize = true
		}
	}
	if !retransmit || !oversize {
		t.Fatalf("retransmit event %v, oversize drop event %v; events %+v", retransmit, oversize, events)
	}
}
