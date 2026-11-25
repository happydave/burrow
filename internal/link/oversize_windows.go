//go:build windows

package link

import (
	"errors"
	"syscall"
)

// wsaemsgsize is Windows' "message too long": a datagram larger than the
// read buffer arrives as this error instead of being truncated.
const wsaemsgsize = syscall.Errno(10040)

// tooBig reports whether a read failed only because the datagram was over
// the buffer, which the reader drops and counts.
func tooBig(err error) bool { return errors.Is(err, wsaemsgsize) }
