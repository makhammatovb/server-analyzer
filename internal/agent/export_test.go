package agent

import (
	"context"
	"log/slog"
	"time"
)

// RunHooks replaces the loop's real sleeping and randomness so tests neither
// wait in real time nor depend on chance. Nil fields use the real behaviour.
type RunHooks struct {
	Wait   func(ctx context.Context, d time.Duration) error
	Jitter func(ceiling time.Duration) time.Duration
	Log    *slog.Logger
}

// RunWithHooks is Run with its waiting, jitter and logging injected.
func RunWithHooks(ctx context.Context, cfg Config, now func() time.Time, h RunHooks) error {
	return run(ctx, cfg, now, runHooks{wait: h.Wait, jitter: h.Jitter, log: h.Log})
}
