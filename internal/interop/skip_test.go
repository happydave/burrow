//go:build !interop

package interop

import "testing"

func TestInteropNeedsHarness(t *testing.T) {
	t.Skip("interop tests run through interop/run.sh with -tags interop")
}
