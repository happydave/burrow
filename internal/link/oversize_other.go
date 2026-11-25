//go:build !windows

package link

// tooBig is false here: Linux and the BSDs truncate a datagram larger than
// the read buffer, and the reader sees its full length.
func tooBig(error) bool { return false }
