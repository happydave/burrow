//go:build interop

package interop

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/happydave/burrow/internal/api"
	"github.com/happydave/burrow/internal/session"
)

// TestObserveServerData records what the server sends on an idle tunnel
// (spec notes O1-O4): it pings every 10 s, so 25 s shows two pings.
func TestObserveServerData(t *testing.T) {
	variant(t, "plain")
	if testing.Short() {
		t.Skip("observation run")
	}
	var mu sync.Mutex
	var notes []string
	cfg := config(t, "123456")
	cfg.Events = func(e api.Event) {
		if e.Kind == api.EventPacketDropped && strings.HasPrefix(e.Reason, "unframed") {
			mu.Lock()
			notes = append(notes, e.Time.Format("15:04:05.000")+" "+e.Reason)
			mu.Unlock()
		}
	}
	s := connect(t, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second) // two server ping intervals
	defer cancel()
	for {
		ip, err := s.ReadPacket(ctx)
		if err != nil {
			break
		}
		mu.Lock()
		notes = append(notes, fmt.Sprintf("%s delivered %d bytes after the framing byte: % x", time.Now().Format("15:04:05.000"), len(ip), ip[:min(len(ip), 64)]))
		mu.Unlock()
	}
	st := s.Stats()
	mu.Lock()
	defer mu.Unlock()
	t.Logf("data opened %d, auth failed %d, replay %d, unframed %d, V1 dropped-before-keys %d", st.DataOpened, st.DataAuthFailed, st.DataReplay, st.Unframed, st.DataDropped)
	for _, n := range notes {
		t.Log(n)
	}
	if st.DataOpened == 0 {
		t.Fatal("no server data packet authenticated: the keys, nonce or AAD are wrong")
	}
}

var _ = session.Config{}
