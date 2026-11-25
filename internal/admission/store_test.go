package admission

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fixedNow is the wall clock the file store prunes against, held at the
// tests' fixed time.
func fixedNow() time.Time { return now }

func stores(t *testing.T) map[string]func() Store {
	path := filepath.Join(t.TempDir(), "history.json")
	m := map[string]func() Store{"memory": func() Store { return &Memory{} }}
	if fileLocking {
		m["file"] = func() Store { return &File{Path: path, Now: fixedNow} }
	}
	return m
}

// needFileLock skips a file-store test where the store refuses for want
// of flock.
func needFileLock(t *testing.T) {
	t.Helper()
	if !fileLocking {
		t.Skip("the file store needs flock, which this platform lacks")
	}
}

func TestReserveCompleteAndRefuse(t *testing.T) {
	for name, mk := range stores(t) {
		t.Run(name, func(t *testing.T) {
			s := mk()
			for i := range 3 {
				id, err := s.Reserve("d", "127.0.0.1:1193", DefaultPolicy, now)
				if err != nil {
					t.Fatalf("attempt %d: %v", i+1, err)
				}
				if err := s.Complete(id, Refused); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.Reserve("d", "127.0.0.1:1193", DefaultPolicy, now); !errors.Is(err, ErrRefused) {
				t.Fatalf("fourth attempt: %v, want ErrRefused", err)
			}
			if _, err := s.Reserve("other", "127.0.0.2:1193", DefaultPolicy, now); err != nil {
				t.Fatalf("another domain is independent: %v", err)
			}
			rs, _ := s.Records("d")
			if len(rs) != 3 {
				t.Fatalf("%d records, want 3 (a refused reservation adds none)", len(rs))
			}
		})
	}
}

func TestNotCountedFreesTheSlot(t *testing.T) {
	s := &Memory{}
	for range 3 {
		id, _ := s.Reserve("d", "r", DefaultPolicy, now)
		_ = s.Complete(id, NotCounted)
	}
	if _, err := s.Reserve("d", "r", DefaultPolicy, now); err != nil {
		t.Fatalf("not-counted attempts should not use the limit: %v", err)
	}
}

func TestFileStoreSurvivesRestartAndKilledAttempts(t *testing.T) {
	needFileLock(t)
	path := filepath.Join(t.TempDir(), "history.json")
	a := &File{Path: path, Now: fixedNow}
	id, err := a.Reserve("d", "r", DefaultPolicy, now)
	if err != nil {
		t.Fatal(err)
	}
	_ = a.Complete(id, Refused)
	_, _ = a.Reserve("d", "r", DefaultPolicy, now) // never completed: the process was killed
	b := &File{Path: path, Now: fixedNow}          // a new process
	if _, err := b.Reserve("d", "r", DefaultPolicy, now); err != nil {
		t.Fatalf("third attempt: %v", err)
	}
	if _, err := b.Reserve("d", "r", DefaultPolicy, now); !errors.Is(err, ErrRefused) {
		t.Fatalf("the killed attempt was not counted: %v", err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("history file mode %v, %v; want 0600", fi.Mode().Perm(), err)
	}
}

func TestFileStoreLockAllowsOneOfManyForTheLastSlot(t *testing.T) {
	needFileLock(t)
	for round := range 10 {
		path := filepath.Join(t.TempDir(), "history.json")
		seed := &File{Path: path, Now: fixedNow}
		for range 2 {
			id, _ := seed.Reserve("d", "r", DefaultPolicy, now)
			_ = seed.Complete(id, Refused)
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		won := 0
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s := &File{Path: path, Now: fixedNow} // each its own instance, as separate processes would be
				if _, err := s.Reserve("d", "r", DefaultPolicy, now); err == nil {
					mu.Lock()
					won++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if won != 1 {
			t.Fatalf("round %d: %d reservations took the one slot left", round, won)
		}
	}
}

func TestCorruptHistoryRefuses(t *testing.T) {
	needFileLock(t)
	path := filepath.Join(t.TempDir(), "history.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &File{Path: path, Now: fixedNow}
	if _, err := s.Reserve("d", "r", DefaultPolicy, now); err == nil {
		t.Fatal("a corrupt history allowed an attempt")
	}
	if data, _ := os.ReadFile(path); string(data) != "{not json" {
		t.Errorf("the corrupt file was changed: %q", data)
	}
}

func TestMissingDirectoryRefuses(t *testing.T) {
	needFileLock(t)
	s := &File{Path: filepath.Join(t.TempDir(), "absent", "history.json")}
	if _, err := s.Reserve("d", "r", DefaultPolicy, now); err == nil {
		t.Fatal("reserve succeeded with no directory for the history")
	}
}

func TestFileStorePrunesByItsClock(t *testing.T) {
	needFileLock(t)
	for _, c := range []struct {
		age  time.Duration
		kept int
	}{{23 * time.Hour, 1}, {25 * time.Hour, 0}} {
		path := filepath.Join(t.TempDir(), "history.json")
		writer := &File{Path: path, Now: fixedNow}
		id, err := writer.Reserve("d", "r", DefaultPolicy, now)
		if err != nil {
			t.Fatal(err)
		}
		_ = writer.Complete(id, Refused)
		later := &File{Path: path, Now: func() time.Time { return now.Add(c.age) }}
		if _, err := later.Reserve("other", "r", DefaultPolicy, now.Add(c.age)); err != nil { // a write prunes
			t.Fatal(err)
		}
		if rs, _ := later.Records("d"); len(rs) != c.kept {
			t.Errorf("a refused record %v old: %d kept, want %d", c.age, len(rs), c.kept)
		}
	}
}

// TestFileStoreClampsAndPrunes (review finding 14): a record dated after
// the store's clock is brought to it, and a pending record ages out like
// any other.
func TestFileStoreClampsAndPrunes(t *testing.T) {
	needFileLock(t)
	path := filepath.Join(t.TempDir(), "history.json")
	future := []Record{{ID: "f", Domain: "d", Time: now.Add(30 * 24 * time.Hour), Outcome: Refused},
		{ID: "p", Domain: "d", Time: now.Add(-25 * time.Hour), Outcome: Pending}}
	data, _ := json.Marshal(future)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	s := &File{Path: path, Now: fixedNow}
	if _, err := s.Reserve("other", "r", DefaultPolicy, now); err != nil { // a write
		t.Fatal(err)
	}
	rs, _ := s.Records("d")
	if len(rs) != 1 || rs[0].ID != "f" || !rs[0].Time.Equal(now) {
		t.Fatalf("records %+v, want only the future record, brought to now", rs)
	}
}

// TestMemoryStorePrunes (finding 22).
func TestMemoryStorePrunes(t *testing.T) {
	m := &Memory{}
	if _, err := m.Reserve("d", "r", DefaultPolicy, now.Add(-25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Reserve("d", "r", DefaultPolicy, now); err != nil {
		t.Fatal(err)
	}
	if rs, _ := m.Records("d"); len(rs) != 1 {
		t.Fatalf("%d records, want the 25-hour-old one pruned", len(rs))
	}
}
