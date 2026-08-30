package logcenter

import (
	"context"

	"github.com/jackc/pgx/v5"
)

type exportAuthorizationTxContextKey struct{}

// WithExportAuthorizationTx binds the caller-owned transaction to the
// authorization callback used while creating an export. The value is
// intentionally scoped to this package so application code can only retrieve
// it through the read-only helper below.
func WithExportAuthorizationTx(ctx context.Context, tx pgx.Tx) context.Context {
	if ctx == nil || tx == nil {
		return ctx
	}
	return context.WithValue(ctx, exportAuthorizationTxContextKey{}, tx)
}

// ExportAuthorizationTxFromContext returns the transaction supplied by the
// export store, when the authorization callback is running inside the create
// transaction.
func ExportAuthorizationTxFromContext(ctx context.Context) (pgx.Tx, bool) {
	if ctx == nil {
		return nil, false
	}
	tx, ok := ctx.Value(exportAuthorizationTxContextKey{}).(pgx.Tx)
	return tx, ok && tx != nil
}
