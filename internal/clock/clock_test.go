package clock

import (
	"testing"
	"time"
)

func fired(tm Timer) bool {
	select {
	case <-tm.C():
		return true
	default:
		return false
	}
}

func TestFakeTimerFiresAtItsDeadline(t *testing.T) {
	f := NewFake(time.Unix(1000, 0))
	tm := f.NewTimer(2 * time.Second)
	f.Advance(2*time.Second - time.Nanosecond)
	if fired(tm) {
		t.Fatal("fired one nanosecond early")
	}
	f.Advance(time.Nanosecond)
	if !fired(tm) {
		t.Fatal("did not fire at its deadline")
	}
	f.Advance(time.Hour)
	if fired(tm) {
		t.Fatal("fired twice")
	}
}

func TestFakeTimerStopAndReset(t *testing.T) {
	f := NewFake(time.Unix(1000, 0))
	tm := f.NewTimer(time.Second)
	if !tm.Stop() {
		t.Fatal("Stop of an armed timer should report true")
	}
	f.Advance(2 * time.Second)
	if fired(tm) {
		t.Fatal("a stopped timer fired")
	}
	tm.Reset(time.Second)
	f.Advance(time.Second)
	if !fired(tm) {
		t.Fatal("a reset timer did not fire")
	}
	if got := f.Now(); !got.Equal(time.Unix(1003, 0)) {
		t.Errorf("Now = %v, want 1003 s", got)
	}
}
