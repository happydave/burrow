package api

import (
	"errors"
	"fmt"
	"io"
	"testing"
)

func TestErrorKindAndUnwrap(t *testing.T) {
	cause := io.ErrUnexpectedEOF
	err := fmt.Errorf("connecting: %w", &Error{Stage: StageLink, Kind: KindUnreachable, Err: cause})
	var e *Error
	if !errors.As(err, &e) || e.Stage != StageLink {
		t.Fatalf("errors.As did not find the Error through a wrap: %v", err)
	}
	if !errors.Is(err, KindUnreachable) {
		t.Error("errors.Is should match the kind")
	}
	if errors.Is(err, KindPacketIDLimit) {
		t.Error("errors.Is matched a different kind")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Error("errors.Is should reach the cause")
	}
	if got := e.Error(); got != "burrow: link: unreachable: unexpected EOF" {
		t.Errorf("message %q", got)
	}
}
