package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// AppendAudit appends an entry to the audit log. detail is marshalled to JSON;
// nil is stored as an empty object.
func (s *Store) AppendAudit(ctx context.Context, actor, action, target string, detail any) error {
	return appendAudit(ctx, s.pool, actor, action, target, detail)
}

// appendAudit is AppendAudit against any executor, so a caller can write the
// audit row in the same transaction as the change it records.
func appendAudit(ctx context.Context, db execer, actor, action, target string, detail any) error {
	if detail == nil {
		detail = struct{}{}
	}
	raw, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("store: marshal audit detail: %w", err)
	}
	_, err = db.Exec(ctx,
		`INSERT INTO audit_log (at, actor, action, target, detail) VALUES ($1, $2, $3, $4, $5)`,
		time.Now().UTC(), actor, action, target, raw)
	if err != nil {
		return fmt.Errorf("store: append audit: %w", err)
	}
	return nil
}
