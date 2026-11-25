// Package link is burrow's UDP link to one remote: a connected socket on an
// ephemeral local port, read by one goroutine into a bounded queue.
package link

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/happydave/burrow/internal/wire"
)

// QueueSize bounds received datagrams waiting for the session.
const QueueSize = 256

// Dialer opens the socket. *net.Dialer satisfies it; a caller may supply
// another (a proxy, a later transport).
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Stats counts datagrams the link dropped.
type Stats struct {
	Oversize, QueueFull int64
}

// Link is one connected UDP socket and its reader.
type Link struct {
	conn      net.Conn
	in        chan []byte
	done      chan struct{}
	err       error
	oversize  atomic.Int64
	queueFull atomic.Int64
	closeOnce sync.Once
}

// Dial connects to address over UDP with d, or a net.Dialer when d is nil,
// and starts the reader.
func Dial(ctx context.Context, d Dialer, address string) (*Link, error) {
	if d == nil {
		d = &net.Dialer{}
	}
	conn, err := d.DialContext(ctx, "udp", address)
	if err != nil {
		return nil, err
	}
	l := &Link{conn: conn, in: make(chan []byte, QueueSize), done: make(chan struct{})}
	go l.read()
	return l, nil
}

func (l *Link) read() {
	defer close(l.done)
	buf := make([]byte, wire.MaxDatagram+1)
	for {
		n, err := l.conn.Read(buf)
		if err != nil {
			if transient(err) {
				continue
			}
			if tooBig(err) {
				l.oversize.Add(1)
				continue
			}
			if !errors.Is(err, net.ErrClosed) {
				l.err = err
			}
			return
		}
		if n > wire.MaxDatagram {
			l.oversize.Add(1)
			continue
		}
		select {
		case l.in <- append([]byte(nil), buf[:n]...):
		default:
			l.queueFull.Add(1)
		}
	}
}

// transient reports whether a read error is a network condition the
// remote may recover from: a connected UDP socket reports an ICMP error as
// a failed read (port unreachable as ECONNREFUSED; host and network
// unreachable on macOS and the BSDs, and on Linux for some firewall
// rejects). The reader goes on; the keepalive notices a remote that stays
// gone.
func transient(err error) bool {
	for _, e := range []error{syscall.ECONNREFUSED, syscall.EHOSTUNREACH, syscall.ENETUNREACH,
		syscall.EHOSTDOWN, syscall.EMSGSIZE, syscall.ECONNRESET} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// Packets delivers received datagrams. It is never closed; Done reports the
// reader's end.
func (l *Link) Packets() <-chan []byte { return l.in }

// Done is closed when the reader has exited.
func (l *Link) Done() <-chan struct{} { return l.done }

// Err is the error that ended the reader, other than Close; valid after Done.
func (l *Link) Err() error {
	<-l.done
	return l.err
}

// Write sends one datagram.
func (l *Link) Write(b []byte) error {
	_, err := l.conn.Write(b)
	return err
}

// LocalAddr and RemoteAddr report the socket's addresses.
func (l *Link) LocalAddr() net.Addr  { return l.conn.LocalAddr() }
func (l *Link) RemoteAddr() net.Addr { return l.conn.RemoteAddr() }

// Stats returns the drop counters.
func (l *Link) Stats() Stats {
	return Stats{Oversize: l.oversize.Load(), QueueFull: l.queueFull.Load()}
}

// Close closes the socket and waits for the reader to exit.
func (l *Link) Close() error {
	var err error
	l.closeOnce.Do(func() { err = l.conn.Close() })
	<-l.done
	return err
}
