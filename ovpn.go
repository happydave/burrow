package burrow

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Limits on a configuration file.
const (
	maxConfigSize = 1 << 20
	maxLineLength = 64 << 10
)

// Ignored is a directive LoadConfig accepted without acting on it: a host
// or device setting with no meaning for an unprivileged library.
type Ignored struct {
	Directive string
	Line      int
}

// ignoredDirectives are accepted with any arguments and reported.
var ignoredDirectives = map[string]bool{
	"dev": true, "daemon": true, "writepid": true, "log-append": true, "verb": true, "mute": true,
	"mute-replay-warnings": true, "passtos": true, "txqueuelen": true, "fast-io": true,
	"socket-flags": true, "tcp-queue-limit": true,
}

// directive is one line of a configuration file, split into words.
type directive struct {
	name       string
	args       []string
	line       int
	connection int // the <connection> block it is in, from 1; 0 outside
}

func (d directive) errorf(format string, a ...any) error {
	return fmt.Errorf("burrow: line %d: %s: %s", d.line, d.name, fmt.Sprintf(format, a...))
}

// profile is what a configuration file says, before any file it names is
// read.
type profile struct {
	remotes                     []string
	ca, cert, key               string
	resolveRetry                time.Duration
	tunMTU, mssfix              int
	mssfixPayload               bool
	connectTimeout              time.Duration
	connectRetry, connectRetryM time.Duration
	ignored                     []Ignored
}

// splitLine splits one line into words. Quotes enclose a word with
// whitespace; outside single quotes, a backslash escapes a backslash, a
// double quote, a space or a tab, and is kept before anything else.
func splitLine(s string) ([]string, error) {
	var words []string
	var w strings.Builder
	inWord := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ' ' || c == '\t':
			if inWord {
				words = append(words, w.String())
				w.Reset()
				inWord = false
			}
		case c == '\'':
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				return nil, errors.New("unterminated single quote")
			}
			w.WriteString(s[i+1 : i+1+end])
			i += end + 1
			inWord = true
		case c == '"':
			i++
			for ; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '\\' || s[i+1] == '"') {
					i++
				}
				w.WriteByte(s[i])
			}
			if i >= len(s) {
				return nil, errors.New("unterminated double quote")
			}
			inWord = true
		case c == '\\' && i+1 < len(s) && strings.IndexByte("\\\" \t", s[i+1]) >= 0:
			i++
			w.WriteByte(s[i])
			inWord = true
		default:
			w.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		words = append(words, w.String())
	}
	return words, nil
}

// directives splits a file into directives. A line whose first non-blank
// character is # or ; is a comment (the man page names only that form, so
// a # later on a line is an ordinary character). <connection> blocks are
// the only inline blocks.
func directives(data []byte) ([]directive, error) {
	if len(data) > maxConfigSize {
		return nil, fmt.Errorf("burrow: configuration is over %d bytes", maxConfigSize)
	}
	var out []directive
	block, blocks, blockLine := 0, 0, 0
	for i, raw := range strings.Split(string(data), "\n") {
		n := i + 1
		if len(raw) > maxLineLength {
			return nil, fmt.Errorf("burrow: line %d is over %d bytes", n, maxLineLength)
		}
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") {
			tag := line[1 : len(line)-1]
			switch tag {
			case "connection":
				if block != 0 {
					return nil, fmt.Errorf("burrow: line %d: <connection> inside another <connection>", n)
				}
				blocks++
				block, blockLine = blocks, n
			case "/connection":
				if block == 0 {
					return nil, fmt.Errorf("burrow: line %d: </connection> without <connection>", n)
				}
				block = 0
			default:
				return nil, fmt.Errorf("burrow: line %d: inline block %s is not supported; name a file instead", n, line)
			}
			continue
		}
		words, err := splitLine(line)
		if err != nil {
			return nil, fmt.Errorf("burrow: line %d: %w", n, err)
		}
		out = append(out, directive{name: words[0], args: words[1:], line: n, connection: block})
	}
	if block != 0 {
		return nil, fmt.Errorf("burrow: line %d: <connection> is not closed", blockLine)
	}
	return out, nil
}

func seconds(d directive, s string, minimum int) (time.Duration, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < minimum {
		return 0, d.errorf("%q is not a whole number of seconds from %d", s, minimum)
	}
	return time.Duration(n) * time.Second, nil
}

func (d directive) want(minArgs, maxArgs int) error {
	if len(d.args) < minArgs || len(d.args) > maxArgs {
		return d.errorf("takes %d to %d arguments, got %d (%q)", minArgs, maxArgs, len(d.args), strings.Join(d.args, " "))
	}
	return nil
}

// parseOVPN reads the first release's subset of the .ovpn format (README,
// "Configuration files"). An unknown directive, an out-of-profile value or a
// missing requirement is an error naming it; nothing that could weaken
// the connection is skipped.
func parseOVPN(data []byte) (*profile, error) {
	ds, err := directives(data)
	if err != nil {
		return nil, err
	}
	p := &profile{}
	seen := map[string]int{}
	inBlocks, outside := 0, 0
	blockRemotes := map[int]int{}
	for _, d := range ds {
		if ignoredDirectives[d.name] {
			if d.connection != 0 {
				return nil, d.errorf("not supported inside <connection>")
			}
			p.ignored = append(p.ignored, Ignored{Directive: d.name, Line: d.line})
			continue
		}
		if d.connection != 0 && d.name != "remote" && d.name != "nobind" {
			return nil, d.errorf("not supported inside <connection>; only remote and nobind are")
		}
		if d.name != "remote" && d.name != "nobind" {
			if prev, dup := seen[d.name]; dup {
				return nil, d.errorf("given twice (first at line %d)", prev)
			}
			seen[d.name] = d.line
		}
		switch d.name {
		case "client", "pull", "tls-client", "nobind", "comp-noadapt":
			if err := d.want(0, 0); err != nil {
				return nil, err
			}
		case "remote":
			if err := d.want(1, 3); err != nil {
				return nil, err
			}
			port := "1194"
			if len(d.args) > 1 {
				port = d.args[1]
			}
			if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
				return nil, d.errorf("port %q is not from 1 to 65535", port)
			}
			if len(d.args) > 2 && d.args[2] != "udp" {
				return nil, d.errorf("protocol %q is not supported; the first release is UDP only", d.args[2])
			}
			if d.args[0] == "" {
				return nil, d.errorf("no host")
			}
			p.remotes = append(p.remotes, net.JoinHostPort(d.args[0], port))
			if d.connection != 0 {
				inBlocks++
				blockRemotes[d.connection]++
			} else {
				outside++
			}
		case "resolv-retry":
			if err := d.want(1, 1); err != nil {
				return nil, err
			}
			switch d.args[0] {
			case "infinite":
				p.resolveRetry = 0
			case "0":
				p.resolveRetry = -1
			default:
				if p.resolveRetry, err = seconds(d, d.args[0], 1); err != nil {
					return nil, err
				}
			}
		case "ca", "cert", "key":
			if err := d.want(1, 1); err != nil {
				return nil, err
			}
			switch d.name {
			case "ca":
				p.ca = d.args[0]
			case "cert":
				p.cert = d.args[0]
			default:
				p.key = d.args[0]
			}
		case "remote-cert-tls":
			if err := d.want(1, 1); err != nil {
				return nil, err
			}
			if d.args[0] != "server" {
				return nil, d.errorf("%q: a client checks the server, so only \"server\" applies", d.args[0])
			}
		case "comp-lzo":
			if len(d.args) != 1 || d.args[0] != "no" {
				return nil, d.errorf("%q: only \"comp-lzo no\" is supported; compression is out of profile", strings.Join(d.args, " "))
			}
		case "tun-mtu":
			if err := d.want(1, 1); err != nil {
				return nil, err
			}
			n, err := strconv.Atoi(d.args[0])
			if err != nil || n < 576 || n > 65535 {
				return nil, d.errorf("%q is not from 576 to 65535", d.args[0])
			}
			p.tunMTU = n
		case "mssfix":
			if err := d.want(0, 2); err != nil {
				return nil, err
			}
			if len(d.args) == 0 {
				break // the default
			}
			n, err := strconv.Atoi(d.args[0])
			if err != nil || n < 0 || n > 65535 {
				return nil, d.errorf("%q is not a size", d.args[0])
			}
			switch {
			case n == 0:
				p.mssfix = -1
			case len(d.args) == 1:
				p.mssfix, p.mssfixPayload = n, true
			case d.args[1] == "mtu":
				p.mssfix = n
			default:
				return nil, d.errorf("%q is not supported; use mtu or no keyword", d.args[1])
			}
		case "connect-timeout":
			if err := d.want(1, 1); err != nil {
				return nil, err
			}
			if p.connectTimeout, err = seconds(d, d.args[0], 1); err != nil {
				return nil, err
			}
		case "connect-retry":
			if err := d.want(1, 2); err != nil {
				return nil, err
			}
			if p.connectRetry, err = seconds(d, d.args[0], 1); err != nil {
				return nil, err
			}
			if len(d.args) == 2 {
				if p.connectRetryM, err = seconds(d, d.args[1], 1); err != nil {
					return nil, err
				}
				if p.connectRetryM < p.connectRetry {
					return nil, d.errorf("the maximum %s is below the wait %s", d.args[1], d.args[0])
				}
			}
		default:
			return nil, d.errorf("unknown or unsupported directive")
		}
	}
	for b, n := range blockRemotes {
		if n != 1 {
			return nil, fmt.Errorf("burrow: <connection> block %d has %d remotes, want 1", b, n)
		}
	}
	switch {
	case inBlocks > 0 && outside > 0:
		return nil, errors.New("burrow: remote given both inside and outside <connection> blocks")
	case len(p.remotes) == 0:
		return nil, errors.New("burrow: no remote")
	}
	for _, req := range []string{"client", "ca", "cert", "key"} {
		if _, ok := seen[req]; !ok {
			return nil, fmt.Errorf("burrow: no %s directive", req)
		}
	}
	return p, nil
}

func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxConfigSize+1))
	if err == nil && len(b) > maxConfigSize {
		err = fmt.Errorf("%s is over %d bytes", path, maxConfigSize)
	}
	return b, err
}

// LoadConfig reads an .ovpn file of the first release's subset and returns
// a Config the caller may adjust before Connect, and the directives it
// accepted without acting on. Files it names resolve against the file's
// directory. Keys must be unencrypted PEM: PKCS#1, PKCS#8 or SEC 1.
func LoadConfig(path string) (Config, []Ignored, error) {
	data, err := readLimited(path)
	if err != nil {
		return Config{}, nil, fmt.Errorf("burrow: %w", err)
	}
	p, err := parseOVPN(data)
	if err != nil {
		return Config{}, nil, err
	}
	dir := filepath.Dir(path)
	rel := func(f string) string {
		if filepath.IsAbs(f) {
			return f
		}
		return filepath.Join(dir, f)
	}
	pool, err := loadCAs(rel(p.ca))
	if err != nil {
		return Config{}, nil, err
	}
	cert, err := loadPair(rel(p.cert), rel(p.key))
	if err != nil {
		return Config{}, nil, err
	}
	return Config{
		Remotes: p.remotes, RootCAs: pool, Certificate: cert,
		ResolveRetry: p.resolveRetry, TunMTU: p.tunMTU, MSSFix: p.mssfix, MSSFixPayload: p.mssfixPayload,
		ConnectTimeout: p.connectTimeout, ConnectRetry: p.connectRetry, ConnectRetryMax: p.connectRetryM,
	}, p.ignored, nil
}

func loadCAs(path string) (*x509.CertPool, error) {
	data, err := readLimited(path)
	if err != nil {
		return nil, fmt.Errorf("burrow: ca: %w", err)
	}
	pool := x509.NewCertPool()
	n := 0
	for rest := data; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("burrow: ca %s: certificate %d: %w", path, n+1, err)
		}
		pool.AddCert(c)
		n++
	}
	if n == 0 {
		return nil, fmt.Errorf("burrow: ca %s holds no PEM certificate", path)
	}
	return pool, nil
}

func loadPair(certPath, keyPath string) (tls.Certificate, error) {
	certPEM, err := readLimited(certPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("burrow: cert: %w", err)
	}
	keyPEM, err := readLimited(keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("burrow: key: %w", err)
	}
	for rest := keyPEM; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type == "ENCRYPTED PRIVATE KEY" || strings.Contains(b.Headers["Proc-Type"], "ENCRYPTED") {
			return tls.Certificate{}, fmt.Errorf("burrow: key %s is encrypted; burrow reads unencrypted keys only", keyPath)
		}
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("burrow: cert %s and key %s: %w", certPath, keyPath, err)
	}
	return pair, nil
}
