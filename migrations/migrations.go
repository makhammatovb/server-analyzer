// Package migrations embeds the goose SQL migrations so the server binary
// carries its own schema.
package migrations

import "embed"

// FS holds every *.sql migration in this directory.
//
//go:embed *.sql
var FS embed.FS
