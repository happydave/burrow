//go:build !unix

package admission

import "os"

// flock is unavailable here, so the file store refuses rather than share a
// history it cannot lock.
func flock(*os.File) (func(), error) { return nil, ErrFileStoreUnsupported }
