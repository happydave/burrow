package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/happydave/burrow/internal/admission"
	"github.com/happydave/burrow/internal/api"
	"github.com/happydave/burrow/internal/fakeserver"
)

func silentConfig(s *fakeserver.Silent) Config {
	return Config{Remote: s.Addr(), CAs: s.Pool, Version: "test", PushTimeout: 300 * time.Millisecond, HandshakeWindow: 5 * time.Second}
}

func TestPushTimeoutIsNotAdmitted(t *testing.T) {
	srv := fakeserver.StartSilent(t)
	start := time.Now()
	s, err := Connect(context.Background(), silentConfig(srv))
	if err == nil {
		s.Close()
		t.Fatal("connected to a server that never pushes")
	}
	var e *api.Error
	if !errors.As(err, &e) || e.Stage != api.StagePush || !errors.Is(err, api.KindNotAdmitted) {
		t.Fatalf("got %v, want not admitted at the push stage", err)
	}
	if d := time.Since(start); d > 6*time.Second {
		t.Fatalf("took %v; the push timeout is 300 ms and EXIT waits at most 2 s", d)
	}
}

func TestGuardStopsTheFourthRefusedAttempt(t *testing.T) {
	srv := fakeserver.StartSilent(t)
	cfg := silentConfig(srv)
	store := &admission.Memory{}
	cfg.Guard = &Guard{Store: store, Policy: admission.DefaultPolicy}
	for i := range 3 {
		_, err := Connect(context.Background(), cfg)
		if !errors.Is(err, api.KindNotAdmitted) {
			t.Fatalf("attempt %d: %v, want not admitted", i+1, err)
		}
	}
	_, err := Connect(context.Background(), cfg)
	if !errors.Is(err, api.KindAdmissionRefused) {
		t.Fatalf("fourth attempt: %v, want admission refused", err)
	}
	if n := srv.Resets(); n != 3 {
		t.Fatalf("the server saw %d hard resets, want 3: the guard must refuse before sending", n)
	}
	rs, _ := store.Records("127.0.0.1")
	refused := 0
	for _, r := range rs {
		if r.Outcome == admission.Refused {
			refused++
		}
	}
	if refused != 3 || len(rs) != 3 {
		t.Fatalf("records %+v, want three refused", rs)
	}
}
