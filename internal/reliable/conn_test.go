package reliable

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/happydave/burrow/internal/clock"
	"github.com/happydave/burrow/internal/wire"
)

func TestConnReadEndsOnClose(t *testing.T) {
	c := NewConn(New(Config{Own: sidC}), clock.Real(), nil, nil, nil)
	errc := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 10))
		errc <- err
	}()
	t.Cleanup(func() { c.Close() })
	waitBlocked(t, c)
	c.Close()
	select {
	case err := <-errc:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Read after Close returned %v, want net.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a blocked Read did not return after Close")
	}
	if _, err := c.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Write after Close returned %v", err)
	}
}

// waitBlocked returns once a Read or Write is blocked in c, so a test of
// what wakes it does not race the goroutine's start.
func waitBlocked(t *testing.T, c *Conn) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c.mu.Lock()
		n := c.waiters
		c.mu.Unlock()
		if n > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no Read or Write blocked within 5 s")
		}
		time.Sleep(time.Millisecond) // polling the waiter count, bounded above
	}
}

func TestConnReadDeadlineOnFakeClock(t *testing.T) {
	fake := clock.NewFake(t0)
	c := NewConn(New(Config{Own: sidC}), fake, nil, nil, nil)
	t.Cleanup(func() { c.Close() })
	if err := c.SetReadDeadline(t0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		_, err := c.Read(make([]byte, 10))
		errc <- err
	}()
	<-started
	select {
	case err := <-errc:
		t.Fatalf("Read returned %v before the deadline", err)
	case <-time.After(50 * time.Millisecond):
	}
	// The reader may not have armed its timer yet; advance until it returns.
	deadline := time.After(5 * time.Second)
	for {
		fake.Advance(time.Second)
		select {
		case err := <-errc:
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("Read returned %v, want the deadline error", err)
			}
			return
		case <-deadline:
			t.Fatal("Read did not return after its deadline passed on the fake clock")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// lossyPair joins two Conns through drivers and a lossy in-memory link, on
// the real clock with short retransmission intervals.
type lossyPair struct {
	mu   sync.Mutex
	rng  *mrand.Rand
	loss float64
	dup  float64
}

func (p *lossyPair) keep() (send, twice bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rng.Float64() >= p.loss, p.rng.Float64() < p.dup
}

func (p *lossyPair) drive(ctx context.Context, t *testing.T, c *Conn, kick <-chan struct{}, in <-chan []byte, out chan<- []byte, done *sync.WaitGroup) {
	defer done.Done()
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case b := <-in:
			cc, err := wire.DecodeControl(b)
			if err != nil {
				t.Errorf("undecodable packet on the link: %v", err)
				return
			}
			c.Do(func(s *State) { s.Receive(cc) })
		case <-kick:
		case <-timer.C:
		}
		var pkts [][]byte
		var next time.Time
		var ok bool
		c.Do(func(s *State) {
			pkts = s.Poll(time.Now())
			next, ok = s.NextPoll()
		})
		for _, b := range pkts {
			send, twice := p.keep()
			for i := 0; send && i < 1+btoi(twice); i++ {
				select {
				case out <- b:
				default:
				}
			}
		}
		wait := time.Hour
		if ok {
			wait = max(time.Until(next), 0)
		}
		timer.Reset(wait)
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func testCerts(t *testing.T) (*x509.CertPool, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test server"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"server"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestTLSOverLossyReliability(t *testing.T) {
	cfg := Config{InitialRetransmit: 20 * time.Millisecond, MaxRetransmit: 160 * time.Millisecond}
	cliCfg, srvCfg := cfg, cfg
	cliCfg.Own, cliCfg.ResetOp = sidC, wire.HardResetClientV2
	srvCfg.Own, srvCfg.Peer, srvCfg.PeerKnown, srvCfg.ResetOp = sidS, sidC, true, wire.HardResetServerV2
	cliKick, srvKick := make(chan struct{}, 1), make(chan struct{}, 1)
	kicker := func(ch chan struct{}) func() {
		return func() {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}
	cli := NewConn(New(cliCfg), clock.Real(), kicker(cliKick), nil, nil)
	srv := NewConn(New(srvCfg), clock.Real(), kicker(srvKick), nil, nil)
	toSrv, toCli := make(chan []byte, 4096), make(chan []byte, 4096)
	p := &lossyPair{rng: mrand.New(mrand.NewPCG(7, 11)), loss: 0.10, dup: 0.05}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go p.drive(ctx, t, cli, cliKick, toCli, toSrv, &wg)
	go p.drive(ctx, t, srv, srvKick, toSrv, toCli, &wg)
	t.Cleanup(func() { cli.Close(); srv.Close(); cancel(); wg.Wait() })
	cliKick <- struct{}{}

	pool, cert := testCerts(t)
	tc := tls.Client(cli, &tls.Config{RootCAs: pool, ServerName: "server", MinVersion: tls.VersionTLS13})
	ts := tls.Server(srv, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	for _, c := range []net.Conn{cli, srv} {
		if err := c.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	hs := make(chan error, 1)
	hctx, hcancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer hcancel()
	go func() { hs <- ts.HandshakeContext(hctx) }()
	if err := tc.HandshakeContext(hctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-hs; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	if v := tc.ConnectionState().Version; v != tls.VersionTLS13 {
		t.Fatalf("negotiated %x, want TLS 1.3", v)
	}
	csC, csS := tc.ConnectionState(), ts.ConnectionState()
	ekmC, err := csC.ExportKeyingMaterial("EXPORTER-OpenVPN-datakeys", nil, 256)
	if err != nil {
		t.Fatal(err)
	}
	ekmS, err := csS.ExportKeyingMaterial("EXPORTER-OpenVPN-datakeys", nil, 256)
	if err != nil {
		t.Fatal(err)
	}
	if string(ekmC) != string(ekmS) || len(ekmC) != 256 {
		t.Fatal("the two sides exported different key material")
	}

	up, down := make([]byte, 64<<10), make([]byte, 64<<10)
	_, _ = rand.Read(up)
	_, _ = rand.Read(down)
	errs := make(chan error, 2)
	go func() { _, err := tc.Write(up); errs <- err }()
	go func() { _, err := ts.Write(down); errs <- err }()
	gotUp, gotDown := make([]byte, len(up)), make([]byte, len(down))
	if _, err := io.ReadFull(ts, gotUp); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if _, err := io.ReadFull(tc, gotDown); err != nil {
		t.Fatalf("client read: %v", err)
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if string(gotUp) != string(up) || string(gotDown) != string(down) {
		t.Fatal("application data differs after crossing the lossy link")
	}
	var resent int
	cli.Do(func(s *State) { resent = s.Stats().Resent })
	t.Logf("TLS 1.3 and 64 KiB each way over 10%% loss and 5%% duplication; client resent %d packets", resent)
}
