package burrow

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// packetPath carries IP packets to and from the server: the session, or a
// pipe in tests.
type packetPath interface {
	WritePacket(ip []byte) error
	ReadPacket(ctx context.Context) ([]byte, error)
}

// stack is the userspace network stack and the two pumps that join it to
// a packet path.
type stack struct {
	dev  tun.Device
	net  *netstack.Net
	path packetPath

	cancel    context.CancelFunc
	pumps     sync.WaitGroup
	closeOnce sync.Once

	sent, received, sendErrors, injectErrors atomic.Int64
}

func newStack(path packetPath, local netip.Addr, dns []netip.Addr, mtu int) (*stack, error) {
	dev, tnet, err := netstack.CreateNetTUN([]netip.Addr{local}, dns, mtu)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &stack{dev: dev, net: tnet, path: path, cancel: cancel}
	s.pumps.Add(2)
	go s.outbound(mtu)
	go s.inbound(ctx)
	return s, nil
}

// outbound moves packets from the stack to the path. It reads until the
// device closes: gVisor blocks its own writers while the device goes
// unread, so a failed send is counted and the loop goes on.
func (s *stack) outbound(mtu int) {
	defer s.pumps.Done()
	bufs := [][]byte{make([]byte, mtu)}
	sizes := []int{0}
	for {
		n, err := s.dev.Read(bufs, sizes, 0)
		if err != nil {
			return
		}
		for i := range n {
			if s.path.WritePacket(bufs[i][:sizes[i]]) != nil {
				s.sendErrors.Add(1)
			} else {
				s.sent.Add(1)
			}
		}
	}
}

// inbound moves packets from the path into the stack. Injection does not
// block.
func (s *stack) inbound(ctx context.Context) {
	defer s.pumps.Done()
	for {
		ip, err := s.path.ReadPacket(ctx)
		if err != nil {
			return
		}
		if _, err := s.dev.Write([][]byte{ip}, 0); err != nil {
			s.injectErrors.Add(1)
		} else {
			s.received.Add(1)
		}
	}
}

// close stops both pumps and the stack, and returns once the pumps have
// exited.
func (s *stack) close() {
	s.closeOnce.Do(func() {
		s.cancel()
		_ = s.dev.Close()
	})
	s.pumps.Wait()
}
