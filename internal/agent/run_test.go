package agent_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/makhammatovb/fleetguard/internal/agent"
	"github.com/makhammatovb/fleetguard/internal/server/httpapi"
)

// runEnv fronts the real server router with a recording proxy so a test can
// count requests and force a status on a path before the real handler runs.
type runEnv struct {
	*env
	mu       sync.Mutex
	paths    []string
	override map[string]func(n int) int // path -> status to force (0 = pass through); n counts requests to that path from 1
	counts   map[string]int
	cancel   context.CancelFunc
	pollSec  *int // when set, heartbeats get this poll_interval_sec instead of the real server's
}

func newRunEnv(t *testing.T) *runEnv {
	t.Helper()
	e := newEnv(t)
	re := &runEnv{env: e, override: map[string]func(int) int{}, counts: map[string]int{}}
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	router := httpapi.NewAgentRouter(e.st, e.pki.CA, proxySecret, lg)
	re.cfg.ServerURL = NewTestProxy(t, e.pki, proxySecret, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		re.mu.Lock()
		re.paths = append(re.paths, r.URL.Path)
		re.counts[r.URL.Path]++
		n := re.counts[r.URL.Path]
		f := re.override[r.URL.Path]
		poll := re.pollSec
		re.mu.Unlock()
		if poll != nil && r.URL.Path == hbPath {
			_, _ = fmt.Fprintf(w, `{"config_version":1,"poll_interval_sec":%d}`, *poll)
			return
		}
		if f != nil {
			if code := f(n); code != 0 {
				http.Error(w, http.StatusText(code), code)
				return
			}
		}
		router.ServeHTTP(w, r)
	}))
	return re
}

func (re *runEnv) count(path string) int {
	re.mu.Lock()
	defer re.mu.Unlock()
	return re.counts[path]
}

func (re *runEnv) sequence() []string {
	re.mu.Lock()
	defer re.mu.Unlock()
	var seq []string
	for _, p := range re.paths {
		if p != "/v1/enrol" { // the test's own setup
			seq = append(seq, p)
		}
	}
	return seq
}

func (re *runEnv) setPoll(n int) {
	re.mu.Lock()
	defer re.mu.Unlock()
	re.pollSec = &n
}

func (re *runEnv) force(path string, f func(n int) int) {
	re.mu.Lock()
	defer re.mu.Unlock()
	re.override[path] = f
}

const (
	hbPath = "/v1/heartbeat"
	rePath = "/v1/re-enrol"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// drive runs the loop until it has waited stopAfter times, recording every
// requested wait. The loop's wait is replaced, so no real time passes.
func (re *runEnv) drive(t *testing.T, now func() time.Time, stopAfter int, jitter func(time.Duration) time.Duration) (waits []time.Duration, err error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hooks := agent.RunHooks{
		Log:    quiet,
		Jitter: jitter,
		Wait: func(ctx context.Context, d time.Duration) error {
			waits = append(waits, d)
			if len(waits) >= stopAfter {
				cancel()
			}
			return ctx.Err()
		},
	}
	err = agent.RunWithHooks(ctx, re.cfg, now, hooks)
	if len(waits) < stopAfter {
		t.Fatalf("loop waited %d times, want %d; Run returned %v", len(waits), stopAfter, err)
	}
	return waits, err
}

func ceilingJitter(c time.Duration) time.Duration { return c }

func TestRunSendsHeartbeatEveryInterval(t *testing.T) {
	re := newRunEnv(t)
	re.enrol(t)
	re.cfg.PollInterval = 45 * time.Second // the real server answers 30, which wins

	waits, err := re.drive(t, time.Now, 3, ceilingJitter)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run err = %v, want context.Canceled", err)
	}
	if got := re.count(hbPath); got != 3 {
		t.Errorf("heartbeats = %d, want 3", got)
	}
	for i, d := range waits {
		if d != 30*time.Second {
			t.Errorf("wait %d = %v, want the server's 30s poll interval", i, d)
		}
	}
	if got := re.count(rePath); got != 0 {
		t.Errorf("re-enrol requests = %d, want 0 on a healthy agent", got)
	}
}

func TestRunBacksOffOnServerError(t *testing.T) {
	re := newRunEnv(t)
	re.enrol(t)
	re.force(hbPath, func(int) int { return http.StatusInternalServerError })

	waits, err := re.drive(t, time.Now, 12, ceilingJitter)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run err = %v, want context.Canceled", err)
	}
	want := []time.Duration{5, 10, 20, 40, 80, 160, 300, 300, 300, 300, 300, 300}
	for i, w := range want {
		if waits[i] != w*time.Second {
			t.Errorf("wait %d = %v, want %v", i, waits[i], w*time.Second)
		}
	}
	if got := re.count(rePath); got != 0 {
		t.Errorf("re-enrol requests = %d on a 500, want 0", got)
	}
}

func TestRunBackoffUsesFullJitter(t *testing.T) {
	re := newRunEnv(t)
	re.enrol(t)
	re.force(hbPath, func(int) int { return http.StatusInternalServerError })

	waits, _ := re.drive(t, time.Now, 10, nil) // nil = the real jitter
	ceiling := 5 * time.Second
	distinct := map[time.Duration]bool{}
	for i, d := range waits {
		if d < time.Second || d > ceiling {
			t.Errorf("wait %d = %v, want within [1s, %v]", i, d, ceiling)
		}
		distinct[d] = true
		ceiling = min(ceiling*2, 5*time.Minute)
	}
	if len(distinct) < 3 {
		t.Errorf("only %d distinct waits in %v: no jitter is being applied", len(distinct), waits)
	}
}

func TestRunBacksOffOnRateLimitWithoutReEnrolling(t *testing.T) {
	re := newRunEnv(t)
	re.enrol(t)
	re.force(hbPath, func(int) int { return http.StatusTooManyRequests })

	waits, _ := re.drive(t, time.Now, 4, ceilingJitter)
	if got := re.count(rePath); got != 0 {
		t.Errorf("re-enrol requests = %d on a 429, want 0", got)
	}
	for i, w := range []time.Duration{5, 10, 20, 40} {
		if waits[i] != w*time.Second {
			t.Errorf("wait %d = %v, want %v", i, waits[i], w*time.Second)
		}
	}
}

func TestRunReEnrolsOnUnauthorised(t *testing.T) {
	re := newRunEnv(t)
	re.enrol(t)
	re.force(hbPath, func(n int) int {
		if n == 1 {
			return http.StatusUnauthorized
		}
		return 0
	})

	_, err := re.drive(t, time.Now, 2, ceilingJitter)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run err = %v", err)
	}
	if got := re.count(rePath); got != 1 {
		t.Errorf("re-enrol requests = %d, want exactly 1", got)
	}
	seq := re.sequence()
	if len(seq) < 3 || seq[0] != hbPath || seq[1] != rePath || seq[2] != hbPath {
		t.Errorf("request order = %v, want heartbeat, re-enrol, heartbeat", seq)
	}
}

func TestRunReEnrolsOnlyOncePerFailureEpisode(t *testing.T) {
	re := newRunEnv(t)
	re.enrol(t)
	re.force(hbPath, func(int) int { return http.StatusUnauthorized })

	waits, _ := re.drive(t, time.Now, 4, ceilingJitter)
	if got := re.count(rePath); got != 1 {
		t.Errorf("re-enrol requests = %d over 4 failed ticks, want 1", got)
	}
	if waits[0] != 5*time.Second || waits[1] != 10*time.Second {
		t.Errorf("waits = %v, want backoff 5s, 10s after the single re-enrol", waits)
	}
}

func TestRunOnForbiddenReEnrolsOnceThenBacksOffToMaximumAndKeepsRunning(t *testing.T) {
	re := newRunEnv(t)
	re.enrol(t)
	re.force(hbPath, func(int) int { return http.StatusForbidden })

	waits, err := re.drive(t, time.Now, 4, ceilingJitter)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v: it must keep retrying, ending only on cancellation", err)
	}
	if got := re.count(rePath); got != 1 {
		t.Errorf("re-enrol requests = %d, want 1", got)
	}
	for i, d := range waits {
		if d != 5*time.Minute {
			t.Errorf("wait %d = %v, want the 5m maximum", i, d)
		}
	}
}

func TestRunOnForbiddenKeepsRetryingReEnrolWhenItIsRefused(t *testing.T) {
	re := newRunEnv(t)
	re.enrol(t)
	re.force(hbPath, func(int) int { return http.StatusForbidden })
	re.force(rePath, func(int) int { return http.StatusInternalServerError }) // transient failure

	waits, err := re.drive(t, time.Now, 3, ceilingJitter)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v: the agent must keep retrying, not exit", err)
	}
	// Re-enrol is the only recovery from a superseded certificate, so it must
	// be retried on every attempt, not abandoned after the first failure.
	if got := re.count(rePath); got != 3 {
		t.Errorf("re-enrol requests = %d over 3 ticks, want 3 (one per tick)", got)
	}
	for i, d := range waits {
		if d != 5*time.Minute {
			t.Errorf("wait %d = %v, want the 5m maximum", i, d)
		}
	}
}

func TestRunHealsAfterForbiddenWhenReEnrolRecovers(t *testing.T) {
	re := newRunEnv(t)
	re.enrol(t)
	// Superseded: the heartbeat 403s until a re-enrol has succeeded.
	re.force(hbPath, func(int) int {
		if re.count(rePath) < 2 { // the 2nd re-enrol request is the first to succeed
			return http.StatusForbidden
		}
		return 0
	})
	re.force(rePath, func(n int) int {
		if n == 1 {
			return http.StatusServiceUnavailable
		}
		return 0
	})
	waits, _ := re.drive(t, time.Now, 3, ceilingJitter)
	if waits[len(waits)-1] != 30*time.Second {
		t.Errorf("last wait = %v, want the normal 30s poll once healed", waits[len(waits)-1])
	}
}

func TestRunForbiddenWaitIsJittered(t *testing.T) {
	re := newRunEnv(t)
	re.enrol(t)
	re.force(hbPath, func(int) int { return http.StatusForbidden })
	half := func(c time.Duration) time.Duration { return c / 2 }
	waits, _ := re.drive(t, time.Now, 2, half)
	for i, d := range waits {
		if d != 150*time.Second {
			t.Errorf("wait %d = %v, want 150s: the 403 wait must pass through jitter, or a fleet stays in lockstep", i, d)
		}
	}
}

func TestRunRecoversWhenServerReturns(t *testing.T) {
	re := newRunEnv(t)
	re.enrol(t)
	re.cfg.PollInterval = 30 * time.Second
	re.force(hbPath, func(n int) int {
		if n <= 2 {
			return http.StatusInternalServerError
		}
		return 0
	})

	waits, _ := re.drive(t, time.Now, 4, ceilingJitter)
	want := []time.Duration{5 * time.Second, 10 * time.Second, 30 * time.Second, 30 * time.Second}
	for i, w := range want {
		if waits[i] != w {
			t.Errorf("wait %d = %v, want %v (backoff must reset after a success)", i, waits[i], w)
		}
	}
}

func TestRunRotatesCertificateBeforeExpiry(t *testing.T) {
	re := newRunEnv(t)
	old := re.enrol(t)
	oldKey := readFile(t, filepath.Join(re.cfg.StateDir, "agent.key"))

	// The clock reads 29 days before expiry until the agent re-enrols, then
	// real time, since the replacement certificate is issued on the real clock.
	now := func() time.Time {
		if re.count(rePath) == 0 {
			return old.NotAfter.Add(-29 * 24 * time.Hour)
		}
		return time.Now()
	}
	_, err := re.drive(t, now, 3, ceilingJitter)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run err = %v", err)
	}
	if got := re.count(rePath); got != 1 {
		t.Errorf("re-enrol requests = %d, want exactly 1", got)
	}
	if seq := re.sequence(); len(seq) < 2 || seq[0] != rePath || seq[1] != hbPath {
		t.Errorf("request order = %v, want re-enrol before the first heartbeat", seq)
	}
	if got := re.count(hbPath); got != 3 {
		t.Errorf("heartbeats = %d, want 3 (the rotated identity keeps working)", got)
	}
	if _, err := agent.LoadIdentity(re.cfg); err != nil {
		t.Fatalf("LoadIdentity after rotation: %v", err)
	}
	if bytes.Equal(oldKey, readFile(t, filepath.Join(re.cfg.StateDir, "agent.key"))) {
		t.Error("the rotated key was not persisted")
	}
}

func TestRunRecoversFromExpiredCertificateWithoutAdmin(t *testing.T) {
	re := newRunEnv(t)
	enrolled := re.enrol(t)
	expiredPEM, err := re.pki.CA.Sign(csrFor(t, filepath.Join(re.cfg.StateDir, "agent.key")), enrolled.ServerID,
		30*time.Second, time.Now())
	if err != nil {
		t.Fatalf("sign expired: %v", err)
	}
	if err := os.WriteFile(filepath.Join(re.cfg.StateDir, "agent.crt"), expiredPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	// Real time is past the 30s certificate; the fake clock says so too.
	now := func() time.Time { return time.Now().Add(time.Hour) }

	if _, err := re.drive(t, now, 1, ceilingJitter); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run err = %v", err)
	}
	if re.count(rePath) != 1 || re.count(hbPath) != 1 {
		t.Errorf("re-enrol=%d heartbeat=%d, want 1 and 1", re.count(rePath), re.count(hbPath))
	}
}

func TestRunResumesPartialEnrolmentWithReEnrol(t *testing.T) {
	re := newRunEnv(t)
	re.enrol(t)
	// The process died after writing the secrets but before agent.crt.
	if err := os.Remove(filepath.Join(re.cfg.StateDir, "agent.crt")); err != nil {
		t.Fatal(err)
	}
	if _, err := re.drive(t, time.Now, 1, ceilingJitter); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run err = %v", err)
	}
	if re.count(rePath) != 1 || re.count(hbPath) != 1 {
		t.Errorf("re-enrol=%d heartbeat=%d, want 1 and 1", re.count(rePath), re.count(hbPath))
	}
}

func TestRunWithoutIdentityFailsClearly(t *testing.T) {
	e := newEnv(t)
	err := agent.Run(context.Background(), e.cfg, time.Now)
	if !errors.Is(err, agent.ErrNoIdentity) {
		t.Fatalf("Run err = %v, want ErrNoIdentity", err)
	}
}

func TestRunWithoutCACrtFailsClosed(t *testing.T) {
	e := newEnv(t)
	e.enrol(t)
	if err := os.Remove(filepath.Join(e.cfg.StateDir, "ca.crt")); err != nil {
		t.Fatal(err)
	}
	if err := agent.Run(context.Background(), e.cfg, time.Now); !errors.Is(err, agent.ErrNoCA) {
		t.Fatalf("Run err = %v, want ErrNoCA", err)
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	re := newRunEnv(t)
	re.enrol(t)
	re.cfg.PollInterval = time.Hour // real timers: a loop that slept the interval would hang

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var seen atomic.Bool
	re.force(hbPath, func(int) int { seen.Store(true); return 0 })

	done := make(chan error, 1)
	go func() { done <- agent.Run(ctx, re.cfg, time.Now) }()
	deadline := time.Now().Add(10 * time.Second)
	for !seen.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !seen.Load() {
		t.Fatal("no heartbeat reached the server")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run err = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

func TestRunHonoursServerPollInterval(t *testing.T) {
	cases := []struct {
		name   string
		server int
		want   time.Duration
	}{
		{"server value is used", 60, 60 * time.Second},
		{"zero falls back to the configured interval", 0, 45 * time.Second},
		{"below the floor is clamped up", 1, 10 * time.Second},
		{"negative is clamped up", -5, 10 * time.Second},
		{"above the ceiling is clamped down", 7 * 24 * 3600, time.Hour},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			re := newRunEnv(t)
			re.enrol(t)
			re.cfg.PollInterval = 45 * time.Second
			re.setPoll(c.server)

			waits, err := re.drive(t, time.Now, 2, ceilingJitter)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Run err = %v, want context.Canceled (a clamped value is not an error)", err)
			}
			for i, d := range waits {
				if d != c.want {
					t.Errorf("wait %d = %v, want %v", i, d, c.want)
				}
			}
		})
	}
}

func TestRunClampsConfiguredPollInterval(t *testing.T) {
	for name, cfgInterval := range map[string]time.Duration{"1ms": time.Millisecond, "a week": 7 * 24 * time.Hour} {
		t.Run(name, func(t *testing.T) {
			re := newRunEnv(t)
			re.enrol(t)
			re.cfg.PollInterval = cfgInterval
			re.setPoll(0) // the server states no preference, so the config applies
			waits, _ := re.drive(t, time.Now, 2, ceilingJitter)
			want := 10 * time.Second
			if cfgInterval > time.Hour {
				want = time.Hour
			}
			for i, d := range waits {
				if d != want {
					t.Errorf("wait %d = %v, want %v", i, d, want)
				}
			}
		})
	}
}

func TestRunWaitsBetweenHeartbeats(t *testing.T) {
	re := newRunEnv(t)
	re.enrol(t)
	re.cfg.PollInterval = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Run(ctx, re.cfg, time.Now) }()
	deadline := time.Now().Add(10 * time.Second)
	for re.count(hbPath) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond) // a loop that does not wait would send hundreds here
	if got := re.count(hbPath); got != 1 {
		t.Errorf("heartbeats after 300ms = %d, want exactly 1: the loop is not waiting", got)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("Run err = %v, want context.Canceled", err)
	}
}

func TestRunRejectsInvalidVersionAtStartup(t *testing.T) {
	re := newRunEnv(t)
	re.enrol(t)
	old := agent.Version
	agent.Version = "has a space/slash"
	t.Cleanup(func() { agent.Version = old })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := agent.Run(ctx, re.cfg, time.Now)
	if err == nil || ctx.Err() != nil {
		t.Fatalf("Run err = %v, want a startup validation error before the 2s limit", err)
	}
	if got := re.count(hbPath); got != 0 {
		t.Errorf("%d heartbeats sent with an invalid version, want 0", got)
	}
}
