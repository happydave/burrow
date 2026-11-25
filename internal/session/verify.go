package session

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// errCertRejected marks a server certificate burrow refuses.
var errCertRejected = errors.New("server certificate rejected")

// verifyServer is the remote-cert-tls server check (spec notes section 19):
// the leaf chains to pool at now, carries serverAuth in its own extended key
// usage list, and has a keyUsage extension with digitalSignature. Go accepts
// a leaf with no EKU for any usage, and does not check keyUsage, so both are
// checked here.
func verifyServer(chain []*x509.Certificate, pool *x509.CertPool, now time.Time) error {
	if len(chain) == 0 {
		return fmt.Errorf("%w: no certificate presented", errCertRejected)
	}
	leaf := chain[0]
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: pool, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("%w: %w", errCertRejected, err)
	}
	serverAuth := false
	for _, u := range leaf.ExtKeyUsage {
		if u == x509.ExtKeyUsageServerAuth {
			serverAuth = true
		}
	}
	if !serverAuth {
		return fmt.Errorf("%w: the leaf does not list serverAuth in its extended key usage", errCertRejected)
	}
	if leaf.KeyUsage == 0 {
		return fmt.Errorf("%w: the leaf has no keyUsage extension", errCertRejected)
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("%w: the leaf's keyUsage lacks digitalSignature", errCertRejected)
	}
	return nil
}

// tlsConfig is the only place burrow builds a TLS client configuration.
// OpenVPN verifies certificates, not host names, so Go's host name check is
// turned off; verifyServer replaces the whole verification, and the two are
// set together here so one is never set without the other.
func tlsConfig(pool *x509.CertPool, cert tls.Certificate, now func() time.Time) *tls.Config {
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyServer(cs.PeerCertificates, pool, now())
		},
	}
}
