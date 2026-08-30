// Package migrations exposes the immutable, checked-in database migrations.
package migrations

import "embed"

// FS contains every SQL migration compiled into the release binaries.
//
//go:embed *.sql
var FS embed.FS
