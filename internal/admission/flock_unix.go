//go:build unix

package admission

import (
	"os"
	"syscall"
)

// flock takes an exclusive advisory lock on f and returns its release.
func flock(f *os.File) (func(), error) {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return nil, err
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }, nil
}
