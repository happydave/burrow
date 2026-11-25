//go:build interop

package interop

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/happydave/burrow"
)

// Measurements, opt-in with BURROW_INTEROP_MEASURE=1. Each logs
// one line per run, prefixed "measure", for docs/measurements.md.

const bigSize = 64 << 20

func measuring(t *testing.T) int {
	t.Helper()
	variant(t, "plain")
	if os.Getenv("BURROW_INTEROP_MEASURE") == "" {
		t.Skip("measurement; BURROW_INTEROP_MEASURE=1 runs it")
	}
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		t.Fatal(err)
	}
	load, err := strconv.ParseFloat(strings.Fields(string(b))[0], 64)
	if err != nil || load > 2 {
		t.Fatalf("refusing to measure: 1-minute load average %q, want at most 2", strings.Fields(string(b))[0])
	}
	runs, err := strconv.Atoi(os.Getenv("BURROW_INTEROP_RUNS"))
	if err != nil || runs < 1 {
		runs = 3
	}
	return runs
}

func cpuTime() time.Duration {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

func mibps(n int64, d time.Duration) float64 { return float64(n) / (1 << 20) / d.Seconds() }

type sample struct {
	bytes int64
	wall  time.Duration
	cpu   time.Duration
}

// transfer times f, which moves n bytes, with the process CPU time it used.
func transfer(t *testing.T, f func() int64) sample {
	t.Helper()
	c0, w0 := cpuTime(), time.Now()
	n := f()
	return sample{bytes: n, wall: time.Since(w0), cpu: cpuTime() - c0}
}

func logSample(t *testing.T, arm string, run int, s sample, tn *burrow.Tunnel) {
	t.Helper()
	line := fmt.Sprintf("measure arm=%s run=%d bytes=%d secs=%.3f MiBps=%.1f cpu=%.3fs", arm, run, s.bytes, s.wall.Seconds(), mibps(s.bytes, s.wall), s.cpu.Seconds())
	if tn != nil {
		st := tn.Stats()
		line += fmt.Sprintf(" recvfull=%d injecterr=%d senderr=%d authfail=%d", st.ReceiveFull, st.StackInjectErrors, st.StackSendErrors, st.DataAuthFailed)
	}
	t.Log(line)
}

func download(t *testing.T, c *http.Client, url, wantSHA string) int64 {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	h := sha256.New()
	n, err := io.Copy(h, resp.Body)
	if err != nil || n != bigSize {
		t.Fatalf("GET %s: %d bytes, %v", url, n, err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != wantSHA {
		t.Fatalf("GET %s: SHA-256 %s, want %s", url, got, wantSHA)
	}
	return n
}

func TestMeasureThroughput(t *testing.T) {
	runs := measuring(t)
	wantSHA := os.Getenv("BURROW_INTEROP_BIG_SHA256")
	if wantSHA == "" {
		t.Fatal("BURROW_INTEROP_BIG_SHA256 is not set: run.sh did not write big.bin")
	}
	body := make([]byte, bigSize)
	if _, err := rand.Read(body); err != nil {
		t.Fatal(err)
	}
	for run := 1; run <= runs; run++ {
		base := &http.Client{Timeout: 5 * time.Minute}
		logSample(t, "baseline-download", run, transfer(t, func() int64 { return download(t, base, "http://127.0.0.1:8081/big.bin", wantSHA) }), nil)

		tn := tunnel(t)
		c := &http.Client{Transport: &http.Transport{DialContext: tn.DialContext}, Timeout: 5 * time.Minute}
		logSample(t, "download", run, transfer(t, func() int64 { return download(t, c, "http://10.88.0.1:8080/big.bin", wantSHA) }), tn)
		logSample(t, "upload", run, transfer(t, func() int64 {
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://10.88.0.1:8080/cgi-bin/sink", bytes.NewReader(body))
			resp, err := c.Do(req)
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			defer resp.Body.Close()
			got, _ := io.ReadAll(resp.Body)
			if n, err := strconv.Atoi(strings.TrimSpace(string(got))); err != nil || n != bigSize {
				t.Fatalf("POST: the sink read %q, want %d", got, bigSize)
			}
			return bigSize
		}), tn)
		tn.Close()
	}
}

func TestMeasureHandshake(t *testing.T) {
	measuring(t)
	const n = 20
	var totals []time.Duration
	stages := map[burrow.Stage][]time.Duration{}
	order := []burrow.Stage{burrow.StageLink, burrow.StageHardReset, burrow.StageTLS, burrow.StageKeyExchange, burrow.StagePush}
	for i := range n {
		start := time.Now()
		tn := tunnel(t)
		total := time.Since(start)
		totals = append(totals, total)
		entered := map[burrow.Stage]time.Time{}
		var parts []string
		for len(tn.Events()) > 0 {
			e := <-tn.Events()
			switch e.Kind {
			case burrow.EventStageEntered:
				entered[e.Stage] = e.Time
			case burrow.EventStageCompleted:
				if t0, ok := entered[e.Stage]; ok {
					stages[e.Stage] = append(stages[e.Stage], e.Time.Sub(t0))
					parts = append(parts, fmt.Sprintf("%s=%.1fms", strings.ReplaceAll(string(e.Stage), " ", "-"), float64(e.Time.Sub(t0).Microseconds())/1000))
				}
			}
		}
		tn.Close()
		t.Logf("measure arm=handshake run=%d total=%.1fms %s", i+1, float64(total.Microseconds())/1000, strings.Join(parts, " "))
	}
	summary := func(ds []time.Duration) string {
		if len(ds) == 0 {
			return "none"
		}
		s := slices.Clone(ds)
		slices.Sort(s)
		ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
		return fmt.Sprintf("median=%.1fms p90=%.1fms max=%.1fms n=%d", ms(s[len(s)/2]), ms(s[len(s)*9/10]), ms(s[len(s)-1]), len(s))
	}
	t.Logf("measure summary handshake total %s", summary(totals))
	for _, st := range order {
		t.Logf("measure summary stage %q %s", st, summary(stages[st]))
	}
}
