package repocheck

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/happydave/burrow/internal/modlicense"
)

func root(t *testing.T) string {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), "go", "env", "GOMOD").Output()
	if err != nil {
		t.Fatalf("go env GOMOD: %v", err)
	}
	return filepath.Dir(strings.TrimSpace(string(out)))
}

func read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root(t), name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestDualLicence: burrow is MIT/Apache-2.0 dual licensed, and each file
// names burrow's contributors as the holder.
func TestDualLicence(t *testing.T) {
	for name, want := range map[string]modlicense.Family{"LICENSE-MIT": modlicense.MIT, "LICENSE-APACHE": modlicense.Apache2} {
		text := read(t, name)
		if got := modlicense.Detect(text); got != want {
			t.Errorf("%s is %s, want %s", name, got, want)
		}
		if !strings.Contains(text, "Copyright 2026 burrow contributors") {
			t.Errorf("%s does not name burrow contributors as the holder", name)
		}
	}
}

// TestReadmeNotices: the README carries the trademark notice the OpenVPN
// terms of use ask for, and the non-affiliation line.
func TestReadmeNotices(t *testing.T) {
	readme := read(t, "README.md")
	for _, want := range []string{
		"OpenVPN® is a registered trademark of OpenVPN Inc.",
		"burrow is not affiliated with or endorsed by",
		"[LICENSE-MIT](LICENSE-MIT)",
		"[LICENSE-APACHE](LICENSE-APACHE)",
	} {
		if !strings.Contains(strings.Join(strings.Fields(readme), " "), want) {
			t.Errorf("README.md lacks %q", want)
		}
	}
}
