package cleanroomguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func hookPath(t *testing.T) string {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), "go", "env", "GOMOD").Output()
	if err != nil {
		t.Fatalf("go env GOMOD: %v", err)
	}
	return filepath.Join(filepath.Dir(strings.TrimSpace(string(out))), ".claude", "hooks", "cleanroom-guard")
}

// run feeds stdin to the hook and returns its exit code and stderr.
func run(t *testing.T, hook string, stdin []byte) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", hook)
	cmd.Stdin = bytes.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, stderr.String()
	case errors.As(err, &exit):
		return exit.ExitCode(), stderr.String()
	default:
		t.Fatalf("running the hook: %v", err)
		return -1, ""
	}
}

func call(t *testing.T, tool string, input map[string]string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"tool_name": tool, "tool_input": input})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestHookDecisions(t *testing.T) {
	hook := hookPath(t)
	const refused, allowed = 2, 0
	cases := []struct {
		name  string
		tool  string
		input map[string]string
		want  int
	}{
		{"clone minivpn", "Bash", map[string]string{"command": "git clone https://github.com/ooni/minivpn"}, refused},
		{"curl by program path", "Bash", map[string]string{"command": "/usr/bin/curl -s https://raw.githubusercontent.com/OpenVPN/openvpn/master/src/openvpn/ssl.c"}, refused},
		{"url in a variable", "Bash", map[string]string{"command": "U=https://github.com/ooni/minivpn; curl $U"}, refused},
		{"sh -c wget openvpn3", "Bash", map[string]string{"command": "sh -c 'wget https://github.com/OpenVPN/openvpn3/archive/master.zip'"}, refused},
		{"fetch openvpn2 source", "WebFetch", map[string]string{"url": "https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/ssl.h", "prompt": "x"}, refused},
		{"fetch openvpn2 repo root", "WebFetch", map[string]string{"url": "https://github.com/OpenVPN/openvpn", "prompt": "x"}, refused},
		{"fetch openvpn2 doc", "WebFetch", map[string]string{"url": "https://github.com/OpenVPN/openvpn/blob/master/doc/tls-crypt-v2.txt", "prompt": "x"}, allowed},
		{"fetch openvpn2 source via doc/..", "WebFetch", map[string]string{"url": "https://github.com/OpenVPN/openvpn/blob/master/doc/../src/openvpn/ssl.c", "prompt": "x"}, refused},
		{"fetch openvpn2 source via encoded doc/..", "WebFetch", map[string]string{"url": "https://github.com/OpenVPN/openvpn/blob/master/doc/%2E%2E/src/openvpn/ssl.c", "prompt": "x"}, refused},
		{"fetch openvpn-rfc", "WebFetch", map[string]string{"url": "https://openvpn.github.io/openvpn-rfc/openvpn-wire-protocol.html", "prompt": "x"}, allowed},
		{"fetch openvpn-rfc repo", "WebFetch", map[string]string{"url": "https://github.com/OpenVPN/openvpn-rfc", "prompt": "x"}, allowed},
		{"read module cache", "Read", map[string]string{"file_path": "/home/user/go/pkg/mod/github.com/ooni/minivpn@v0.0.7/README.md"}, refused},
		{"grep module cache", "Grep", map[string]string{"pattern": "Handshake", "path": "/home/user/go/pkg/mod/github.com/ooni/minivpn@v0.0.7"}, refused},
		{"glob kernel driver", "Glob", map[string]string{"pattern": "**/drivers/net/ovpn/*.c"}, refused},
		{"fetch dissector", "WebFetch", map[string]string{"url": "https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-openvpn.c", "prompt": "x"}, refused},
		{"go test", "Bash", map[string]string{"command": "go test ./..."}, allowed},
		{"fetch netstack docs", "WebFetch", map[string]string{"url": "https://pkg.go.dev/golang.zx2c4.com/wireguard/tun/netstack", "prompt": "x"}, allowed},
		{"edit is not inspected", "Edit", map[string]string{"file_path": "x.go", "old_string": "ooni/minivpn", "new_string": "y"}, allowed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, stderr := run(t, hook, call(t, c.tool, c.input))
			if got != c.want {
				t.Fatalf("exit %d, want %d (stderr %q)", got, c.want, stderr)
			}
			if got == refused && !strings.Contains(stderr, "cleanroom-guard: refused") {
				t.Errorf("refusal without its reason: %q", stderr)
			}
		})
	}
}

func TestHookRefusesUnreadableInput(t *testing.T) {
	got, stderr := run(t, hookPath(t), []byte(`{"tool_name": "Bash", "tool_input": `))
	if got != 2 || !strings.Contains(stderr, "cannot read the tool call") {
		t.Fatalf("exit %d, stderr %q: unreadable input must be refused", got, stderr)
	}
}
