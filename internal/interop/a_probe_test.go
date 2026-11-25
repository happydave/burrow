//go:build interop

package interop

import (
	"os"
	"testing"
)

// TestNoTunDevice is the harness's proof that the client side has no TUN
// device. interop/run.sh runs it alone before any other test; with
// BURROW_INTEROP_EXPECT_TUN=1 it is the probe's own control, expecting the
// device to open.
func TestNoTunDevice(t *testing.T) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err == nil {
		f.Close()
	}
	if os.Getenv("BURROW_INTEROP_EXPECT_TUN") == "1" {
		if err != nil {
			t.Fatalf("control: /dev/net/tun should open when the device is given: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatal("/dev/net/tun opened: the client container must not have a TUN device")
	}
	t.Logf("as expected, /dev/net/tun does not open: %v", err)
}
