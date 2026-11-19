package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/makhammatovb/fleetguard/pkg/api"
)

// Version is the agent version reported in heartbeats and at enrolment. The
// release build overrides it with -ldflags "-X .../internal/agent.Version=...".
var Version = "dev"

const (
	bootIDPath  = "/proc/sys/kernel/random/boot_id"
	uptimePath  = "/proc/uptime"
	minBackoff  = 5 * time.Second
	maxBackoff  = 5 * time.Minute
	minWait     = time.Second // floor under jitter so a retry never becomes a hot loop
	maxBackoffN = 16          // doublings beyond this cannot change the capped result
)

// runHooks lets tests replace the loop's sleeping, randomness and logging.
// Zero fields select the real behaviour.
type runHooks struct {
	wait   func(ctx context.Context, d time.Duration) error
	jitter func(ceiling time.Duration) time.Duration
	log    *slog.Logger
}

// Run is the agent's long-running supervisor. It sends a heartbeat every
// cfg.PollInterval, rotates the certificate when it nears expiry, and recovers
// from rejected identities by re-enrolling. It only ever dials out. It returns
// when ctx is cancelled (with ctx.Err()) or when the state directory cannot
// yield an identity; it never exits because of anything the server says, so an
// agent whose server was disabled recovers by itself once it is re-enabled.
func Run(ctx context.Context, cfg Config, now func() time.Time) error {
	return run(ctx, cfg, now, runHooks{})
}

func run(ctx context.Context, cfg Config, now func() time.Time, h runHooks) error {
	if h.wait == nil {
		h.wait = sleep
	}
	if h.jitter == nil {
		h.jitter = fullJitter
	}
	if h.log == nil {
		h.log = slog.Default()
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = DefaultPollInterval
	}
	l := &loop{cfg: cfg, now: now, h: h, bootID: readBootID(bootIDPath), started: now()}
	id, err := l.startIdentity(ctx)
	if err != nil {
		return err
	}
	l.setIdentity(id)
	defer l.client.Close()

	for {
		delay := l.tick(ctx)
		if err := ctx.Err(); err != nil {
			return err
		}
		if delay > 0 {
			if err := h.wait(ctx, delay); err != nil {
				return err
			}
		}
	}
}

// loop is the supervisor's state. It is used by a single goroutine.
type loop struct {
	cfg     Config
	now     func() time.Time
	h       runHooks
	bootID  string
	started time.Time

	id     Identity
	client *Client // built once per identity and reused for every heartbeat

	fails       int       // consecutive failed ticks; drives the backoff
	reenrolled  bool      // a re-enrol was already tried in this failure episode
	rotFails    int       // consecutive failed rotations
	rotateAfter time.Time // do not retry rotation before this
}

func (l *loop) setIdentity(id Identity) {
	if l.client != nil {
		l.client.Close()
	}
	l.id = id
	l.client = NewClient(id, l.cfg)
}

// startIdentity loads the persisted identity. If only part of an enrolment
// survived (the secrets are on disk but the certificate is missing or does not
// match its key) it re-enrols, because the one-time token is already spent and
// Enrol would fail for good.
func (l *loop) startIdentity(ctx context.Context) (Identity, error) {
	id, err := LoadIdentity(l.cfg)
	if err == nil {
		return id, nil
	}
	if errors.Is(err, ErrNoCA) {
		return Identity{}, err
	}
	if !HasEnrolSecrets(l.cfg) {
		if errors.Is(err, ErrNoIdentity) {
			return Identity{}, fmt.Errorf("agent is not enrolled; run `fleetguard-agent enrol --token=<token>`: %w", err)
		}
		return Identity{}, err
	}
	l.h.log.Warn("identity incomplete, re-enrolling", "reason", err)
	for fails := 1; ; fails++ {
		id, rerr := ReEnrol(ctx, l.cfg)
		if rerr == nil {
			return id, nil
		}
		if errors.Is(rerr, ErrNoCA) || errors.Is(rerr, ErrNoIdentity) {
			return Identity{}, rerr
		}
		if err := ctx.Err(); err != nil {
			return Identity{}, err
		}
		l.h.log.Warn("re-enrol failed, will retry", "error", rerr)
		if err := l.h.wait(ctx, l.h.jitter(backoffCeiling(fails))); err != nil {
			return Identity{}, err
		}
	}
}

// refresh re-enrols and switches to the new identity.
func (l *loop) refresh(ctx context.Context) error {
	id, err := ReEnrol(ctx, l.cfg)
	if err != nil {
		return err
	}
	l.setIdentity(id)
	return nil
}

// tick does one unit of work and returns how long to wait before the next; a
// zero delay means run again straight away.
func (l *loop) tick(ctx context.Context) time.Duration {
	if l.id.NeedsRotation(l.now()) && !l.now().Before(l.rotateAfter) {
		if err := l.refresh(ctx); err != nil {
			if ctx.Err() != nil {
				return 0
			}
			l.rotFails++
			l.rotateAfter = l.now().Add(l.h.jitter(backoffCeiling(l.rotFails)))
			l.h.log.Warn("certificate rotation failed", "error", err)
		} else {
			l.rotFails = 0
			l.h.log.Info("certificate rotated", "not_after", l.id.NotAfter)
		}
	}

	_, err := l.client.SendHeartbeat(ctx, l.heartbeat())
	if err == nil {
		l.fails, l.reenrolled = 0, false
		return l.cfg.PollInterval
	}
	if ctx.Err() != nil {
		return 0
	}
	l.fails++

	var se *StatusError
	code := 0
	if errors.As(err, &se) {
		code = se.Code
	}
	l.h.log.Warn("heartbeat failed", "error", err)

	switch code {
	case 401, 403:
		// The identity was not accepted, or is superseded or revoked. Try to
		// get a new one, once per episode.
		if !l.reenrolled {
			l.reenrolled = true
			rerr := l.refresh(ctx)
			if ctx.Err() != nil {
				return 0
			}
			if rerr == nil {
				l.fails = 0 // a fresh identity starts a fresh backoff
				l.h.log.Info("re-enrolled after rejection", "status", code)
				return 0
			}
			l.h.log.Warn("re-enrol failed", "error", rerr)
		}
		if code == 403 {
			// Revoked, decommissioned or still superseded: wait the longest
			// interval and keep trying, so the agent heals on its own.
			return maxBackoff
		}
	}
	// Transport errors, 429, 5xx and a 401 that survived re-enrolment. A 429 is
	// deliberately not re-enrolled: the identity is fine.
	return l.h.jitter(backoffCeiling(l.fails))
}

func (l *loop) heartbeat() api.Heartbeat {
	return api.Heartbeat{
		ServerID:     l.id.ServerID,
		AgentVersion: Version,
		BootID:       l.bootID,
		UptimeSec:    l.uptime(),
		SentAt:       l.now().UTC(),
	}
}

// uptime is the host's uptime from /proc/uptime. Where that is unavailable it
// is the time since the agent started.
func (l *loop) uptime() int64 {
	if b, err := os.ReadFile(uptimePath); err == nil {
		if f, _, _ := strings.Cut(strings.TrimSpace(string(b)), " "); f != "" {
			if secs, perr := strconv.ParseFloat(f, 64); perr == nil && secs >= 0 {
				return int64(secs)
			}
		}
	}
	return int64(l.now().Sub(l.started).Seconds())
}

// readBootID returns the kernel boot id, or "" where the file is absent (such
// as macOS); an empty boot id is valid in a heartbeat.
func readBootID(path string) string {
	b, err := os.ReadFile(path) //nolint:gosec // fixed kernel path, or a test path
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// backoffCeiling is the largest wait after n consecutive failures: 5 s doubling
// to a 5 minute cap.
func backoffCeiling(n int) time.Duration {
	if n < 1 {
		n = 1
	}
	if n > maxBackoffN {
		return maxBackoff
	}
	return min(minBackoff<<(n-1), maxBackoff)
}

// fullJitter picks uniformly in [0, ceiling], but never below minWait.
func fullJitter(ceiling time.Duration) time.Duration {
	if ceiling <= minWait {
		return ceiling
	}
	return max(minWait, rand.N(ceiling+1)) //nolint:gosec // retry spreading, not security
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// HasEnrolSecrets reports whether the state directory holds the server id and
// enrolment secret, which is what ReEnrol needs. It is true after a completed
// enrolment and also after one interrupted before the certificate was written.
func HasEnrolSecrets(cfg Config) bool {
	if _, err := readState(cfg.StateDir, fileServerID); err != nil {
		return false
	}
	_, err := readState(cfg.StateDir, fileEnrolKey)
	return err == nil
}

// ErrAlreadyEnrolled is returned by EnrolOrResume when a usable identity exists.
var ErrAlreadyEnrolled = errors.New("agent: already enrolled; nothing to do")

// EnrolOrResume enrols with a one-time token. If an earlier enrolment was
// interrupted after the server spent the token but before the certificate was
// written, the token cannot be used again, so it resumes with ReEnrol instead
// and ignores the token.
func EnrolOrResume(ctx context.Context, cfg Config, token, hostname, version string) (Identity, error) {
	if _, err := LoadIdentity(cfg); err == nil {
		return Identity{}, ErrAlreadyEnrolled
	}
	if HasEnrolSecrets(cfg) {
		return ReEnrol(ctx, cfg)
	}
	return Enrol(ctx, cfg, token, hostname, version)
}
