package netstackcheck

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// forward copies IP packets from one device to the other until src closes,
// counting them, as burrow's data channel will carry them.
func forward(src, dst tun.Device, count *atomic.Int64) {
	bufs := [][]byte{make([]byte, 65535)}
	sizes := []int{0}
	for {
		n, err := src.Read(bufs, sizes, 0)
		if err != nil {
			return
		}
		for i := range n {
			if _, err := dst.Write([][]byte{bufs[i][:sizes[i]]}, 0); err != nil {
				return
			}
			count.Add(1)
		}
	}
}

func pattern(seed byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed + byte(i%251)
	}
	return b
}

func TestTCPBetweenTwoNetstacks(t *testing.T) {
	addrA := netip.MustParseAddr("10.200.0.1")
	addrB := netip.MustParseAddr("10.200.0.2")
	devA, netA, err := netstack.CreateNetTUN([]netip.Addr{addrA}, nil, 1500)
	if err != nil {
		t.Fatal(err)
	}
	devB, netB, err := netstack.CreateNetTUN([]netip.Addr{addrB}, nil, 1500)
	if err != nil {
		t.Fatal(err)
	}
	var aToB, bToA atomic.Int64
	go forward(devA, devB, &aToB)
	go forward(devB, devA, &bToA)
	t.Cleanup(func() { devA.Close(); devB.Close() })

	ln, err := netB.ListenTCPAddrPort(netip.AddrPortFrom(addrB, 7000))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	const size = 64 << 10
	request, reply := pattern(1, size), pattern(7, size)
	serverErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer c.Close()
		got := make([]byte, size)
		if _, err := io.ReadFull(c, got); err != nil {
			serverErr <- fmt.Errorf("server read: %w", err)
			return
		}
		if !bytes.Equal(got, request) {
			serverErr <- errors.New("server received different bytes")
			return
		}
		_, err = c.Write(reply)
		serverErr <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := netA.DialContext(ctx, "tcp", netip.AddrPortFrom(addrB, 7000).String())
	if err != nil {
		t.Fatalf("dial: %v (packets A to B %d, B to A %d)", err, aToB.Load(), bToA.Load())
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(request); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got := make([]byte, size)
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("client read: %v (packets A to B %d, B to A %d)", err, aToB.Load(), bToA.Load())
	}
	if !bytes.Equal(got, reply) {
		t.Fatal("client received different bytes")
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	t.Logf("64 KiB each way; packets A to B %d, B to A %d", aToB.Load(), bToA.Load())
}
