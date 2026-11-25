package burrow

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type keyFormat int

const (
	pkcs1 keyFormat = iota
	pkcs8
	sec1
)

// writePKI writes keys/ca.crt (two CA certificates, the issuer second) and
// a client pair into dir, the key in the given format.
func writePKI(t *testing.T, dir string, format keyFormat) {
	t.Helper()
	keys := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	mkCA := func(name string) (*x509.Certificate, *ecdsa.PrivateKey) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, k
	}
	other, _ := mkCA("another CA")
	issuer, issuerKey := mkCA("issuing CA")
	var caPEM []byte
	for _, c := range []*x509.Certificate{other, issuer} {
		caPEM = append(caPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	write(t, filepath.Join(keys, "ca.crt"), caPEM)

	var pub crypto.PublicKey
	var keyBlock *pem.Block
	switch format {
	case sec1:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, _ := x509.MarshalECPrivateKey(k)
		pub, keyBlock = &k.PublicKey, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	default:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		pub = &k.PublicKey
		if format == pkcs1 {
			keyBlock = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
		} else {
			der, _ := x509.MarshalPKCS8PrivateKey(k)
			keyBlock = &pem.Block{Type: "PRIVATE KEY", Bytes: der}
		}
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "123456"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, pub, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(keys, "client.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	write(t, filepath.Join(keys, "client.key"), pem.EncodeToMemory(keyBlock))
}

func write(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// fixture copies a testdata configuration beside fresh PKI.
func fixture(t *testing.T, name string, format keyFormat) string {
	t.Helper()
	dir := t.TempDir()
	writePKI(t, dir, format)
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	write(t, p, b)
	return p
}

// lineOf finds the line where a directive appears in a file, as an oracle
// independent of the loader.
func lineOf(t *testing.T, path, name string) int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		if w := strings.Fields(sc.Text()); len(w) > 0 && w[0] == name {
			return n
		}
	}
	t.Fatalf("%s not in %s", name, path)
	return 0
}

func TestLoadTargetConfig(t *testing.T) {
	path := fixture(t, "target.ovpn", pkcs1)
	cfg, ignored, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.48:1181", "198.51.100.147:1193", "198.51.100.147:1181"}
	if !slices.Equal(cfg.Remotes, want) {
		t.Fatalf("remotes %q, want %q", cfg.Remotes, want)
	}
	leaf, err := x509.ParseCertificate(cfg.Certificate.Certificate[0])
	if err != nil || leaf.Subject.CommonName != "123456" {
		t.Fatalf("client certificate %v, %v", leaf, err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: cfg.RootCAs, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("the CA pool does not hold the second certificate of ca.crt: %v", err)
	}
	names := []string{"dev", "daemon", "writepid", "mute-replay-warnings", "passtos", "txqueuelen", "fast-io",
		"socket-flags", "tcp-queue-limit", "verb", "log-append", "mute"}
	if len(ignored) != len(names) {
		t.Fatalf("%d ignored directives %+v, want %d", len(ignored), ignored, len(names))
	}
	for _, ig := range ignored {
		if !slices.Contains(names, ig.Directive) || ig.Line != lineOf(t, path, ig.Directive) {
			t.Errorf("ignored %+v: wrong name or line (want line %d)", ig, lineOf(t, path, ig.Directive))
		}
	}
	if cfg.ResolveRetry != 0 || cfg.TunMTU != 0 || cfg.MSSFix != 0 || cfg.ConnectTimeout != 0 || cfg.ConnectRetry != 0 {
		t.Fatalf("defaults changed: %+v", cfg)
	}
}

func TestLoadTargetOptions(t *testing.T) {
	cfg, _, err := LoadConfig(fixture(t, "target-options.ovpn", pkcs1))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TunMTU != 1450 || cfg.MSSFix != 1410 || !cfg.MSSFixPayload || cfg.ConnectTimeout != 20*time.Second ||
		cfg.ConnectRetry != 5*time.Second || cfg.ConnectRetryCap != 60*time.Second {
		t.Fatalf("tun-mtu %d, mssfix %d payload %v, connect-timeout %v, connect-retry %v max %v",
			cfg.TunMTU, cfg.MSSFix, cfg.MSSFixPayload, cfg.ConnectTimeout, cfg.ConnectRetry, cfg.ConnectRetryCap)
	}
	if got := stackMTU(cfg, 0, false); got != 1385 {
		t.Fatalf("stack MTU %d, want 1385 (mssfix 1410 without mtu, spec notes 18.3)", got)
	}
	if got := stackMTU(cfg, 1500, false); got != 1385 {
		t.Fatalf("stack MTU with a pushed tun-mtu %d, want 1385", got)
	}
	if got := stackMTU(Config{TunMTU: 1300}, 0, false); got != 1300 {
		t.Fatalf("configured tun-mtu not used: %d", got)
	}
	if got := stackMTU(Config{TunMTU: 1300}, 1400, false); got != 1400 {
		t.Fatalf("pushed tun-mtu did not win: %d", got)
	}
}

// base is a minimal accepted configuration for the tables below.
const base = "client\nca keys/ca.crt\ncert keys/client.crt\nkey keys/client.key\nremote 192.0.2.1 1194\n"

func TestParseMappings(t *testing.T) {
	for _, c := range []struct {
		extra string
		check func(*profile) bool
	}{
		{"resolv-retry infinite", func(p *profile) bool { return p.resolveRetry == 0 }},
		{"resolv-retry 0", func(p *profile) bool { return p.resolveRetry < 0 }},
		{"resolv-retry 30", func(p *profile) bool { return p.resolveRetry == 30*time.Second }},
		{"mssfix 0", func(p *profile) bool { return p.mssfix < 0 }},
		{"mssfix 1400", func(p *profile) bool { return p.mssfix == 1400 && p.mssfixPayload }},
		{"mssfix 1400 mtu", func(p *profile) bool { return p.mssfix == 1400 && !p.mssfixPayload }},
		{"mssfix", func(p *profile) bool { return p.mssfix == 0 }},
		{"connect-timeout 7", func(p *profile) bool { return p.connectTimeout == 7*time.Second }},
		{"connect-retry 2", func(p *profile) bool { return p.connectRetry == 2*time.Second && p.connectRetryM == 0 }},
		{"connect-retry 2 90", func(p *profile) bool { return p.connectRetryM == 90*time.Second }},
		{"tun-mtu 1400", func(p *profile) bool { return p.tunMTU == 1400 }},
		{"remote 2001:db8::1 1194", func(p *profile) bool { return slices.Contains(p.remotes, "[2001:db8::1]:1194") }},
		{"remote host.example", func(p *profile) bool { return slices.Contains(p.remotes, "host.example:1194") }},
	} {
		p, err := parseOVPN([]byte(base + c.extra + "\n"))
		if err != nil {
			t.Errorf("%s: %v", c.extra, err)
			continue
		}
		if !c.check(p) {
			t.Errorf("%s: wrong mapping: %+v", c.extra, p)
		}
	}
}

const blocks = "client\nca a\ncert b\nkey c\n"

// refusals are inputs the parser must refuse, each with a word its error
// names.
var refusals = []struct{ input, want string }{
	{base + "tls-auth ta.key 1\n", "tls-auth"},
	{base + "cipher AES-256-CBC\n", "cipher"},
	{base + "--client\n", "--client"},
	{base + "comp-lzo yes\n", "comp-lzo"},
	{base + "comp-lzo adaptive\n", "comp-lzo"},
	{base + "comp-lzo\n", "comp-lzo"},
	{base + "remote h 1194 tcp\n", "tcp"},
	{base + "remote h 0\n", "port"},
	{base + "remote h 70000\n", "port"},
	{base + "remote-cert-tls client\n", "client"},
	{base + "mssfix 1400 fixed\n", "fixed"},
	{base + "tun-mtu 500\n", "tun-mtu"},
	{base + "resolv-retry soon\n", "resolv-retry"},
	{base + "connect-retry 10 5\n", "connect-retry"},
	{base + "connect-retry 0\n", "connect-retry"},
	{base + "<ca>\n-----BEGIN CERTIFICATE-----\n</ca>\n", "<ca>"},
	{blocks + "<connection>\nremote a 1\n", "not closed"},
	{blocks + "<connection>\n<connection>\n", "inside another"},
	{blocks + "<connection>\nremote a 1\nremote b 1\n</connection>\n", "2 remotes"},
	{blocks + "<connection>\nremote a 1\ntun-mtu 1400\n</connection>\n", "tun-mtu"},
	{blocks + "remote x 1\n<connection>\nremote a 1\n</connection>\n", "both inside and outside"},
	{strings.Replace(base, "client\n", "", 1), "client"},
	{strings.Replace(base, "ca keys/ca.crt\n", "", 1), "ca"},
	{strings.Replace(base, "cert keys/client.crt\n", "", 1), "cert"},
	{strings.Replace(base, "key keys/client.key\n", "", 1), "key"},
	{strings.Replace(base, "remote 192.0.2.1 1194\n", "", 1), "remote"},
	{strings.Replace(base, "ca keys/ca.crt", "ca keys/ca.crt # trailing comment", 1), "ca"},
	{base + "tun-mtu 1400\ntun-mtu 1300\n", "twice"},
	{base + "remote \"unterminated\n", "quote"},
	{base + "dev tap\n", "dev"},
	{base + "dev tap0\n", "dev"},
	{base + "dev null\n", "dev"},
	{base + "dev-type tap\n", "dev-type"},
	{base + "mssfix 20\n", "mssfix"},
	{base + "mssfix 60 mtu\n", "mssfix"},
}

func TestParseRefusals(t *testing.T) {
	for _, c := range refusals {
		_, err := parseOVPN([]byte(c.input))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: err %v, want one naming %q", c.input, err, c.want)
		}
	}
}

func TestParseSyntax(t *testing.T) {
	in := strings.Join([]string{
		"client",
		"   # an indented comment",
		"\t; another",
		`ca "dir with space/ca.crt"`,
		`cert dir\ with\ space/client.crt`,
		`key 'C:\keys\client.key'`,
		"remote 192.0.2.1 1194",
	}, "\r\n")
	p, err := parseOVPN([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if p.ca != "dir with space/ca.crt" || p.cert != "dir with space/client.crt" || p.key != `C:\keys\client.key` {
		t.Fatalf("paths %q %q %q", p.ca, p.cert, p.key)
	}
	if !slices.Equal(p.remotes, []string{"192.0.2.1:1194"}) {
		t.Fatalf("remotes %q (a CRLF file keeps no \\r)", p.remotes)
	}
}

func TestKeyFormats(t *testing.T) {
	for _, f := range []keyFormat{pkcs1, pkcs8, sec1} {
		if _, _, err := LoadConfig(fixture(t, "target.ovpn", f)); err != nil {
			t.Errorf("format %d: %v", f, err)
		}
	}
}

func TestKeyRefusals(t *testing.T) {
	t.Run("legacy encrypted PEM", func(t *testing.T) {
		path := fixture(t, "target.ovpn", pkcs1)
		keyPath := filepath.Join(filepath.Dir(path), "keys", "client.key")
		b, _ := os.ReadFile(keyPath)
		blk, _ := pem.Decode(b)
		blk.Headers = map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,00000000000000000000000000000000"}
		write(t, keyPath, pem.EncodeToMemory(blk))
		if _, _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "encrypted") || !strings.Contains(err.Error(), keyPath) {
			t.Fatalf("err %v, want encrypted naming %s", err, keyPath)
		}
	})
	t.Run("PKCS#8 encrypted", func(t *testing.T) {
		path := fixture(t, "target.ovpn", pkcs8)
		keyPath := filepath.Join(filepath.Dir(path), "keys", "client.key")
		write(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{0x30, 0}}))
		if _, _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "encrypted") {
			t.Fatalf("err %v, want encrypted", err)
		}
	})
	t.Run("no CA certificate", func(t *testing.T) {
		path := fixture(t, "target.ovpn", pkcs1)
		caPath := filepath.Join(filepath.Dir(path), "keys", "ca.crt")
		write(t, caPath, []byte("not a certificate\n"))
		if _, _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), caPath) {
			t.Fatalf("err %v, want one naming %s", err, caPath)
		}
	})
	t.Run("key for another certificate", func(t *testing.T) {
		path := fixture(t, "target.ovpn", pkcs1)
		other := t.TempDir()
		writePKI(t, other, pkcs1)
		b, _ := os.ReadFile(filepath.Join(other, "keys", "client.key"))
		write(t, filepath.Join(filepath.Dir(path), "keys", "client.key"), b)
		if _, _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "client.key") {
			t.Fatalf("err %v, want a mismatch naming the key", err)
		}
	})
	t.Run("relative paths resolve beside the file", func(t *testing.T) {
		path := fixture(t, "target.ovpn", pkcs1)
		t.Chdir(t.TempDir())
		if _, _, err := LoadConfig(path); err != nil {
			t.Fatalf("from another working directory: %v", err)
		}
	})
}

func FuzzParseOVPN(f *testing.F) {
	for _, name := range []string{"target.ovpn", "target-options.ovpn"} {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte(base))
	f.Add([]byte("client\n<connection>\nremote a 1\n</connection>\n"))
	f.Add([]byte(`ca "a\"b" 'c d' e\ f`))
	for _, c := range refusals {
		f.Add([]byte(c.input))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := parseOVPN(data)
		if err == nil && len(p.remotes) == 0 {
			t.Fatal("accepted a profile with no remote")
		}
	})
}
