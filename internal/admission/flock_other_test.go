//go:build !unix

package admission

import (
	"errors"
	"path/filepath"
	"testing"
)

// fileLocking says the file store refuses here.
const fileLocking = false

func TestFileStoreRefusesWithoutFlock(t *testing.T) {
	s := &File{Path: filepath.Join(t.TempDir(), "history.json")}
	if _, err := s.Reserve("d", "r", DefaultPolicy, now); !errors.Is(err, ErrFileStoreUnsupported) {
		t.Fatalf("Reserve: %v, want ErrFileStoreUnsupported", err)
	}
}
