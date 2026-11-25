package admission

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/happydave/burrow/internal/api"
)

func TestClassify(t *testing.T) {
	e := func(st api.Stage, k api.Kind) error { return fmt.Errorf("wrapped: %w", &api.Error{Stage: st, Kind: k}) }
	cases := []struct {
		name string
		err  error
		want Outcome
	}{
		{"established", nil, Established},
		{"no stage", errors.New("bad config"), NotCounted},
		{"guard refusal", e(api.StageLink, api.KindAdmissionRefused), NotCounted},
		{"link unreachable", e(api.StageLink, api.KindUnreachable), NotCounted},
		{"hard reset unanswered", e(api.StageHardReset, api.KindUnreachable), NotCounted},
		{"canceled before the reset", e(api.StageHardReset, api.KindCanceled), NotCounted},
		{"TLS failure", e(api.StageTLS, api.KindTLS), Refused},
		{"certificate rejected", e(api.StageTLS, api.KindCertRejected), Refused},
		{"canceled after the reset", e(api.StageTLS, api.KindCanceled), Refused},
		{"key exchange", e(api.StageKeyExchange, api.KindKeyExchange), Refused},
		{"AUTH_FAILED", e(api.StagePush, api.KindAuthFailed), Refused},
		{"not admitted", e(api.StagePush, api.KindNotAdmitted), Refused},
		{"fatal push", e(api.StagePush, api.KindUnsupportedPush), Refused},
		{"closed during push", e(api.StagePush, api.KindClosedByServer), Refused},
	}
	for _, c := range cases {
		if got := Classify(c.err); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

var now = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

func rec(age time.Duration, o Outcome) Record { return Record{Time: now.Add(-age), Outcome: o} }

func TestAllowedRefusesWhatItExistsToRefuse(t *testing.T) {
	cases := []struct {
		name    string
		records []Record
		p       Policy
		want    bool
	}{
		{"none", nil, DefaultPolicy, true},
		{"two refused", []Record{rec(time.Minute, Refused), rec(2*time.Minute, Refused)}, DefaultPolicy, true},
		{"three refused: the fourth is refused", []Record{rec(time.Minute, Refused), rec(2*time.Minute, Refused), rec(3*time.Minute, Refused)}, DefaultPolicy, false},
		{"two refused and a pending one", []Record{rec(time.Minute, Refused), rec(2*time.Minute, Refused), rec(0, Pending)}, DefaultPolicy, false},
		{"oldest aged out by a second", []Record{rec(time.Minute, Refused), rec(2*time.Minute, Refused), rec(time.Hour+time.Second, Refused)}, DefaultPolicy, true},
		{"oldest exactly a window old still counts", []Record{rec(time.Minute, Refused), rec(2*time.Minute, Refused), rec(time.Hour, Refused)}, DefaultPolicy, false},
		{"a future record counts as now", []Record{rec(time.Minute, Refused), rec(2*time.Minute, Refused), rec(-time.Hour, Refused)}, DefaultPolicy, false},
		{"established ones do not count by default", []Record{rec(time.Minute, Established), rec(2*time.Minute, Established), rec(3*time.Minute, Established), rec(4*time.Minute, NotCounted)}, DefaultPolicy, true},
		{"live: one established and one refused stop a third", []Record{rec(time.Minute, Established), rec(2*time.Minute, Refused)}, LivePolicy, false},
		{"live: one attempt leaves one", []Record{rec(time.Minute, Refused)}, LivePolicy, true},
	}
	for _, c := range cases {
		if got := Allowed(c.records, c.p, now); got != c.want {
			t.Errorf("%s: allowed=%v, want %v", c.name, got, c.want)
		}
	}
}

func TestDomain(t *testing.T) {
	if a, b := Domain("", "127.0.0.1:1193"), Domain("", "127.0.0.1:1181"); a != b || a != "127.0.0.1" {
		t.Errorf("two ports on one host: %q and %q", a, b)
	}
	if got := Domain("example", "127.0.0.1:1193"); got != "example" {
		t.Errorf("configured domain: %q", got)
	}
}
