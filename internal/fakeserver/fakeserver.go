// Package fakeserver is an in-process OpenVPN-protocol server for tests. It
// answers the hard reset and completes TLS 1.3 and key method 2. By default
// it then never pushes, the shape of a server whose admission hook says
// nothing; with Options.Push it pushes, carries data, and renegotiates.
// Only tests import it.
package fakeserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/happydave/burrow/internal/clock"
	"github.com/happydave/burrow/internal/datachan"
	"github.com/happydave/burrow/internal/reliable"
	"github.com/happydave/burrow/internal/wire"
)

// Options select the server's behaviour.
type Options struct {
	// Push, when set, is the PUSH_REPLY sent for a PUSH_REQUEST. Its cipher
	// and peer-id give the data channel, which echoes each IP packet back
	// under the key it arrived on.
	Push string
	// SendOnNewKey sends one data packet under each renegotiated key 100 ms
	// after the server has installed it, by when the client has its key too
	// (real servers waited about 9.5 s).
	SendOnNewKey bool
	// StallRenegotiation answers a soft reset but never completes TLS.
	StallRenegotiation bool
	// BadCertOnRenegotiation presents a leaf without the serverAuth EKU on
	// every renegotiated key.
	BadCertOnRenegotiation bool
	// TLS12Only offers TLS 1.2 and nothing newer.
	TLS12Only bool
}

// Push is a PUSH_REPLY in the target profile's shape (spec notes O9).
const Push = "PUSH_REPLY,ping 10,ping-restart 60,ifconfig 10.88.0.4 10.88.0.1,peer-id 0,cipher AES-256-GCM,protocol-flags cc-exit tls-ekm"

// Server is a fake server on a loopback port.
type Server struct {
	pc      net.PacketConn
	Pool    *x509.CertPool // verifies the server's certificate
	cert    tls.Certificate
	badCert tls.Certificate
	opts    Options
	resets  atomic.Int64
	wg      sync.WaitGroup

	mu      sync.Mutex
	clients []*client
}

// Silent is the never-pushing server.
type Silent = Server

// StartSilent starts a server that never pushes; it stops at the test's
// end.
func StartSilent(t testing.TB) *Server { return Start(t, Options{}) }

// Start starts a server with the given options; it stops at the test's end.
func Start(t testing.TB, opts Options) *Server {
	t.Helper()
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pool, cert, bad := identity(t)
	s := &Server{pc: pc, Pool: pool, cert: cert, badCert: bad, opts: opts}
	s.wg.Add(1)
	go s.serve()
	t.Cleanup(func() {
		pc.Close()
		s.mu.Lock()
		for _, c := range s.clients {
			c.close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
	return s
}

// Addr is the server's host:port.
func (s *Server) Addr() string { return s.pc.LocalAddr().String() }

// Resets counts the hard resets the server has received from new sessions.
func (s *Server) Resets() int64 { return s.resets.Load() }

func (s *Server) last() *client {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.clients) == 0 {
		return nil
	}
	return s.clients[len(s.clients)-1]
}

// Renegotiate starts a soft reset under the next key ID with the latest
// client. It reports false when there is no client yet.
func (s *Server) Renegotiate() bool {
	c := s.last()
	if c == nil {
		return false
	}
	c.mu.Lock()
	id := c.newest + 1
	if c.newest >= 7 {
		id = 1
	}
	k := c.startKeyLocked(id)
	c.mu.Unlock()
	k.kickNow()
	return true
}

// Message writes a control message on key id's TLS session with the latest
// client. It reports false when that key's session is not up.
func (s *Server) Message(id uint8, msg string) bool {
	c := s.last()
	if c == nil {
		return false
	}
	c.mu.Lock()
	k := c.keys[id]
	c.mu.Unlock()
	if k == nil {
		return false
	}
	k.mu.Lock()
	tc := k.tc
	k.mu.Unlock()
	if tc == nil {
		return false
	}
	_, err := tc.Write(append([]byte(msg), 0))
	return err == nil
}

// Received returns the control messages the latest client sent on key id
// after key method 2.
func (s *Server) Received(id uint8) []string {
	c := s.last()
	if c == nil {
		return nil
	}
	c.mu.Lock()
	k := c.keys[id]
	c.mu.Unlock()
	if k == nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]string(nil), k.received...)
}

// Arrival is one data packet the server opened.
type Arrival struct {
	Key  uint8
	Time time.Time
}

// Arrivals returns the data packets the latest client sent, in order.
func (s *Server) Arrivals() []Arrival {
	c := s.last()
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Arrival(nil), c.arrivals...)
}

// NewKeySent returns when the server sent its first packet under key id.
func (s *Server) NewKeySent(id uint8) (time.Time, bool) {
	c := s.last()
	if c == nil {
		return time.Time{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.newKeySent[id]
	return t, ok
}

// identity makes a CA, a server certificate with the serverAuth EKU, and
// one with only the clientAuth EKU, which remote-cert-tls server rejects.
func identity(t testing.TB) (*x509.CertPool, tls.Certificate, tls.Certificate) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake server CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := func(serial int64, eku x509.ExtKeyUsage) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "server"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return pool, leaf(3, x509.ExtKeyUsageServerAuth), leaf(4, x509.ExtKeyUsageClientAuth)
}

func (s *Server) serve() {
	defer s.wg.Done()
	byID := map[wire.SessionID]*client{}
	buf := make([]byte, wire.MaxDatagram+1)
	var lastData *client
	for {
		n, from, err := s.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		b := append([]byte(nil), buf[:n]...)
		op, _, err := wire.Header(b)
		if err != nil {
			continue
		}
		if wire.IsData(op) {
			// One client carries data at a time in these tests.
			if lastData == nil || lastData.from.String() != from.String() {
				lastData = s.clientFrom(from)
			}
			if lastData != nil {
				lastData.data(b)
			}
			continue
		}
		// DecodeControl's payload aliases its input, so b is a copy.
		c, err := wire.DecodeControl(b)
		if err != nil {
			continue
		}
		cl, ok := byID[c.Session]
		if !ok {
			if c.Op != wire.HardResetClientV2 {
				continue
			}
			s.resets.Add(1)
			cl = s.newClient(c.Session, from)
			byID[c.Session] = cl
		}
		cl.control(c)
	}
}

func (s *Server) clientFrom(from net.Addr) *client {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.clients) - 1; i >= 0; i-- {
		if s.clients[i].from.String() == from.String() {
			return s.clients[i]
		}
	}
	return nil
}

// client is one client session's state on the server.
type client struct {
	s    *Server
	id   wire.SessionID // the client's
	own  wire.SessionID
	from net.Addr

	mu         sync.Mutex
	keys       map[uint8]*skey
	newest     uint8
	cipher     string
	arrivals   []Arrival
	newKeySent map[uint8]time.Time
}

func (s *Server) newClient(id wire.SessionID, from net.Addr) *client {
	c := &client{s: s, id: id, from: from, keys: map[uint8]*skey{}, newKeySent: map[uint8]time.Time{},
		own: wire.SessionID{0x5e, 1, 2, 3, 4, 5, 6, 7}, cipher: "AES-256-GCM"}
	for _, f := range strings.Split(s.opts.Push, ",") {
		if v, ok := strings.CutPrefix(f, "cipher "); ok {
			c.cipher = v
		}
	}
	s.mu.Lock()
	s.clients = append(s.clients, c)
	s.mu.Unlock()
	c.mu.Lock()
	c.startKeyLocked(0)
	c.mu.Unlock()
	return c
}

func (c *client) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range c.keys {
		k.close()
	}
}

func (c *client) control(ctl wire.Control) {
	c.mu.Lock()
	k, ok := c.keys[ctl.KeyID]
	if !ok && ctl.Op == wire.SoftResetV1 {
		k = c.startKeyLocked(ctl.KeyID) // the client renegotiates
	}
	c.mu.Unlock()
	if k == nil {
		return
	}
	select {
	case k.in <- ctl:
	default:
	}
}

// skey is one key ID's state on the server.
type skey struct {
	c         *client
	id        uint8
	in        chan wire.Control
	kick      chan struct{}
	conn      *reliable.Conn
	done      chan struct{}
	closeOnce sync.Once
	sealer    *datachan.Sealer
	opener    *datachan.Opener

	mu       sync.Mutex
	tc       *tls.Conn // set once key method 2 is done
	received []string
}

func (k *skey) kickNow() {
	select {
	case k.kick <- struct{}{}:
	default:
	}
}

func (k *skey) close() { k.closeOnce.Do(func() { close(k.done) }) }

// startKeyLocked starts the server side of key id. The caller holds c.mu.
func (c *client) startKeyLocked(id uint8) *skey {
	if k, ok := c.keys[id]; ok {
		return k
	}
	op := wire.HardResetServerV2
	if id != 0 {
		op = wire.SoftResetV1
	}
	cfg := reliable.Config{KeyID: id, Own: c.own, Peer: c.id, PeerKnown: true, ResetOp: op,
		InitialRetransmit: 50 * time.Millisecond, MaxRetransmit: 200 * time.Millisecond}
	k := &skey{c: c, id: id, in: make(chan wire.Control, 256), kick: make(chan struct{}, 1), done: make(chan struct{})}
	k.conn = reliable.NewConn(reliable.New(cfg), clock.Real(), k.kickNow, nil, nil)
	c.keys[id] = k
	if id != 0 {
		c.newest = id
	}
	c.s.wg.Add(2)
	go k.pump()
	go k.session()
	return k
}

// pump runs the key's reliability state.
func (k *skey) pump() {
	defer k.c.s.wg.Done()
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		select {
		case <-k.done:
			k.conn.Close()
			return
		case ctl := <-k.in:
			k.conn.Do(func(st *reliable.State) { st.Receive(ctl) })
		case <-k.kick:
		case <-timer.C:
		}
		var out [][]byte
		var next time.Time
		var due bool
		k.conn.Do(func(st *reliable.State) { out = st.Poll(time.Now()); next, due = st.NextPoll() })
		for _, b := range out {
			_, _ = k.c.s.pc.WriteTo(b, k.c.from)
		}
		if due {
			timer.Reset(max(time.Until(next), 0))
		} else {
			timer.Reset(time.Hour)
		}
	}
}

// session runs TLS, key method 2, and for key 0 the push.
func (k *skey) session() {
	defer k.c.s.wg.Done()
	opts := k.c.s.opts
	if k.id != 0 && opts.StallRenegotiation {
		<-k.done
		return
	}
	cert := k.c.s.cert
	if k.id != 0 && opts.BadCertOnRenegotiation {
		cert = k.c.s.badCert
	}
	tcfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	if opts.TLS12Only {
		tcfg.MinVersion, tcfg.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	}
	tc := tls.Server(k.conn, tcfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-k.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	if err := tc.HandshakeContext(ctx); err != nil {
		return
	}
	buf := make([]byte, 4096)
	if _, err := tc.Read(buf); err != nil { // the client's key method 2
		return
	}
	reply := append([]byte{0, 0, 0, 0, 2}, make([]byte, 64)...)
	reply = appendString(reply, "V4,dev-type tun")
	if _, err := tc.Write(reply); err != nil {
		return
	}
	k.mu.Lock()
	k.tc = tc
	k.mu.Unlock()
	if opts.Push != "" {
		cs := tc.ConnectionState()
		ekm, err := cs.ExportKeyingMaterial("EXPORTER-OpenVPN-datakeys", nil, 256)
		if err != nil {
			return
		}
		k.install(ekm)
	}
	for {
		n, err := tc.Read(buf)
		if err != nil {
			return
		}
		k.mu.Lock()
		k.received = append(k.received, strings.TrimRight(string(buf[:n]), "\x00"))
		k.mu.Unlock()
		if k.id == 0 && opts.Push != "" && strings.HasPrefix(string(buf[:n]), "PUSH_REQUEST") {
			if _, err := tc.Write(append([]byte(opts.Push), 0)); err != nil {
				return
			}
		}
	}
}

// install derives the server's data keys: its sealing half is the client's
// opening half.
func (k *skey) install(ekm []byte) {
	clientSend, clientRecv, err := datachan.KeysFromEKM(ekm, k.c.cipher)
	if err != nil {
		return
	}
	k.c.mu.Lock()
	k.sealer = datachan.NewSealer(clientRecv, k.id, 0)
	k.opener = datachan.NewOpener(clientSend, k.id, time.Now)
	k.c.mu.Unlock()
	if k.id == 0 || !k.c.s.opts.SendOnNewKey {
		return
	}
	select {
	case <-k.done:
		return
	case <-time.After(100 * time.Millisecond):
	}
	k.c.mu.Lock()
	pkt, _, _ := k.sealer.Seal(datachan.Frame(datachan.PingPayload))
	k.c.newKeySent[k.id] = time.Now()
	k.c.mu.Unlock()
	_, _ = k.c.s.pc.WriteTo(pkt, k.c.from)
}

// data opens one data packet under its key and echoes an IP packet back
// under the same key; pings are not echoed.
func (c *client) data(b []byte) {
	_, id, _ := wire.Header(b)
	c.mu.Lock()
	k := c.keys[id]
	if k == nil || k.opener == nil {
		c.mu.Unlock()
		return
	}
	pt, err := k.opener.Open(b)
	if err != nil {
		c.mu.Unlock()
		return
	}
	c.arrivals = append(c.arrivals, Arrival{Key: id, Time: time.Now()})
	ip, ok := datachan.Unframe(pt)
	var out []byte
	if ok && !datachan.IsPing(ip) {
		out, _, _ = k.sealer.Seal(pt)
	}
	c.mu.Unlock()
	if out != nil {
		_, _ = c.s.pc.WriteTo(out, c.from)
	}
}

// appendString appends a key-method-2 string: a 2-byte length counting a
// trailing NUL, the text, the NUL (spec notes 6.2).
func appendString(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(s)+1))
	b = append(b, s...)
	return append(b, 0)
}
