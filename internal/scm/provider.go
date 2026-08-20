package scm

import (
	"context"
	"net/http"

	"xminds-release-platform/internal/identity"
)

type Provider interface {
	VerifyConnection(ctx context.Context, connection Connection) (Capabilities, error)
	VerifyWebhook(ctx context.Context, connection Connection, headers http.Header, body []byte) (WebhookEvent, error)
	GetCommit(ctx context.Context, connection Connection, repository, sha string) (Commit, error)
	WriteStatus(ctx context.Context, connection Connection, status CommitStatus) error
	VerifyWorkload(ctx context.Context, connection Connection, token string) (identity.Principal, error)
}
