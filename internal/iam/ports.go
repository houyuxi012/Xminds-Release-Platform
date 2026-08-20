package iam

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/identity"
)

type Repository interface {
	WithinTransaction(ctx context.Context, function func(pgx.Tx) error) error
	GetLoginState(ctx context.Context, tx pgx.Tx) (LoginState, error)
	SetLoginState(ctx context.Context, tx pgx.Tx, state LoginState, expectedVersion int64) error
	GetIdentitySource(ctx context.Context, tx pgx.Tx, id uuid.UUID) (IdentitySource, error)
	SaveIdentitySource(ctx context.Context, tx pgx.Tx, source IdentitySource, expectedVersion int64) error
	CountUsableEmergencyAdministrators(ctx context.Context, tx pgx.Tx, excluding uuid.UUID, at time.Time) (int, error)
	GetUser(ctx context.Context, tx pgx.Tx, id uuid.UUID) (UserPrincipal, error)
	SaveUser(ctx context.Context, tx pgx.Tx, user UserPrincipal, expectedVersion int64) error
	UserCanBeEnabled(ctx context.Context, tx pgx.Tx, user UserPrincipal) (bool, error)
	InsertLocalUser(ctx context.Context, tx pgx.Tx, user UserPrincipal, credential LocalCredential) error
	ListUsers(ctx context.Context, page Page) (UserPage, error)
	FindLocalAuthentication(ctx context.Context, canonicalUsername string) (LoginState, UserPrincipal, LocalCredential, error)
	InsertOrganization(ctx context.Context, tx pgx.Tx, organization OrganizationUnit) error
	GetOrganization(ctx context.Context, tx pgx.Tx, id uuid.UUID) (OrganizationUnit, error)
	ListOrganizations(ctx context.Context, page Page) (OrganizationPage, error)
	InsertRoleBinding(ctx context.Context, tx pgx.Tx, binding RoleBinding) error
	GetRoleBinding(ctx context.Context, tx pgx.Tx, id uuid.UUID) (RoleBinding, error)
	ListRoleBindings(ctx context.Context, page Page) (RoleBindingPage, error)
	DeleteRoleBinding(ctx context.Context, tx pgx.Tx, id uuid.UUID, expectedVersion int64) error
	InsertIdentitySource(ctx context.Context, tx pgx.Tx, source IdentitySource) error
	ListIdentitySources(ctx context.Context, page Page) (IdentitySourcePage, error)
	UpdateIdentitySourceDraft(ctx context.Context, tx pgx.Tx, source IdentitySource, expectedVersion int64) error
}

type AuditAppender interface {
	Append(ctx context.Context, tx pgx.Tx, command audit.AppendCommand) (audit.Event, error)
}

type SessionRevoker interface {
	RevokeSubject(ctx context.Context, tx pgx.Tx, subjectID uuid.UUID, reason string) error
	RevokeOrganizationMembers(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, reason string) error
	RevokeRegularLocalSessions(ctx context.Context, tx pgx.Tx, reason string) error
}

type PasswordVerifier interface {
	Verify(password string, digest PasswordDigest) error
}

type PasswordService interface {
	PasswordVerifier
	Hash(ctx context.Context, password string) (PasswordDigest, error)
}

type HighRiskAuthorizer interface {
	Authorize(ctx context.Context, actor identity.Principal, operation string, proof HighRiskProof, request RequestContext) error
}

type DirectoryAdapter interface {
	Verify(ctx context.Context, source IdentitySource) (CapabilityReport, error)
	Preview(ctx context.Context, source IdentitySource) (SyncDiff, error)
	Sync(ctx context.Context, source IdentitySource, cursor string) (SyncPage, error)
}

type CapabilityReport struct {
	Reachable           bool
	RequiredAttributes  []string
	SupportsIncremental bool
}

type SyncDiff struct {
	CreateCount   int
	UpdateCount   int
	DisableCount  int
	ConflictCount int
}

type SyncPage struct {
	Users      []DirectoryUser
	NextCursor string
}

type DirectoryUser struct {
	ExternalSubject string
	DisplayName     string
	Email           string
	Enabled         bool
}
