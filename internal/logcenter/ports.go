package logcenter

import (
	"context"

	"github.com/jackc/pgx/v5"
)

type OperationWriter interface {
	AppendOperation(context.Context, pgx.Tx, OperationCommand) error
}

type AuthenticationWriter interface {
	AppendAuthentication(context.Context, pgx.Tx, AuthenticationEvent) error
}

type ApplicationRequestWriter interface {
	AppendApplicationRequest(context.Context, ApplicationRequestEvent) error
}

type GitSyncWriter interface {
	AppendGitSync(context.Context, pgx.Tx, GitSyncEvent) error
}
