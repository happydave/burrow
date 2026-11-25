package session

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T, name string) ca {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return ca{c, key}
}

func (c ca) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// leaf issues a server certificate from c, adjusted by mod.
func (c ca) leaf(t *testing.T, mod func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "server"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if mod != nil {
		mod(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	l, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestVerifyServer(t *testing.T) {
	good, other := newCA(t, "burrow test CA"), newCA(t, "another CA")
	cases := []struct {
		name   string
		leaf   *x509.Certificate
		accept bool
		reason string // part of the refusal's message, where it matters
	}{
		{"good server leaf", good.leaf(t, nil), true, ""},
		{"leaf from another CA", other.leaf(t, nil), false, ""},
		{"clientAuth-only leaf", good.leaf(t, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }), false, ""},
		{"leaf with no EKU", good.leaf(t, func(c *x509.Certificate) { c.ExtKeyUsage = nil }), false, ""},
		{"leaf with only anyExtendedKeyUsage", good.leaf(t, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} }), false, ""},
		{"expired leaf", good.leaf(t, func(c *x509.Certificate) { c.NotBefore, c.NotAfter = now.Add(-3*time.Hour), now.Add(-2*time.Hour) }), false, ""},
		{"no keyUsage extension", good.leaf(t, func(c *x509.Certificate) { c.KeyUsage = 0 }), false, "no keyUsage extension"},
		{"keyUsage without digitalSignature", good.leaf(t, func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment }), false, "lacks digitalSignature"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := verifyServer([]*x509.Certificate{c.leaf}, good.pool(), now)
			if c.accept && err != nil {
				t.Fatalf("refused a good leaf: %v", err)
			}
			if !c.accept {
				if err == nil {
					t.Fatal("accepted")
				}
				if !errors.Is(err, errCertRejected) {
					t.Fatalf("refusal %v is not errCertRejected", err)
				}
				if !strings.Contains(err.Error(), c.reason) {
					t.Fatalf("refusal %q does not say %q", err, c.reason)
				}
			}
		})
	}
	if err := verifyServer(nil, good.pool(), now); !errors.Is(err, errCertRejected) {
		t.Errorf("an empty chain: %v", err)
	}
}

func TestTLSConfigAlwaysVerifies(t *testing.T) {
	ca := newCA(t, "burrow test CA")
	cfg := tlsConfig(ca.pool(), tlsCertForTest(), func() time.Time { return now })
	if !cfg.InsecureSkipVerify || cfg.VerifyConnection == nil {
		t.Fatal("the host name check may be off only together with burrow's own verification")
	}
	if cfg.VerifyPeerCertificate != nil || cfg.ServerName != "" {
		t.Error("unexpected extra verification or a server name")
	}
}

// intermediate issues a CA certificate from c, with the given EKUs (none
// means unrestricted).
func (c ca) intermediate(t *testing.T, ekus []x509.ExtKeyUsage) ca {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "intermediate"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: ekus}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	ic, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return ca{ic, key}
}

// TestVerifyIntermediates (review finding 17): a leaf under an intermediate
// the server supplies verifies; without the intermediate, or under one
// whose EKUs leave out serverAuth, it does not. A nil pool is refused
// (finding 25).
func TestVerifyIntermediates(t *testing.T) {
	root := newCA(t, "root")
	inter := root.intermediate(t, nil)
	leaf := inter.leaf(t, nil)
	if err := verifyServer([]*x509.Certificate{leaf, inter.cert}, root.pool(), now); err != nil {
		t.Fatalf("a leaf with its intermediate: %v", err)
	}
	if err := verifyServer([]*x509.Certificate{leaf}, root.pool(), now); !errors.Is(err, errCertRejected) {
		t.Fatalf("a leaf without its intermediate: %v", err)
	}
	clientOnly := root.intermediate(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	l2 := clientOnly.leaf(t, nil)
	if err := verifyServer([]*x509.Certificate{l2, clientOnly.cert}, root.pool(), now); !errors.Is(err, errCertRejected) {
		t.Fatalf("an intermediate restricted to clientAuth: %v", err)
	}
	// A nil pool would fall back to the system roots; the refusal must be
	// the explicit one, not a chain that happens not to verify.
	if err := verifyServer([]*x509.Certificate{leaf, inter.cert}, nil, now); !errors.Is(err, errCertRejected) || !strings.Contains(err.Error(), "no CA pool") {
		t.Fatalf("a nil pool: %v, want the no-CA-pool refusal", err)
	}
	if cfg := tlsConfig(root.pool(), tls.Certificate{}, func() time.Time { return now }); cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("minimum TLS version %x, want 1.3 (finding 6)", cfg.MinVersion)
	}
}
