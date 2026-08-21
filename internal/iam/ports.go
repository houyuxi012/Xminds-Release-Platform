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
	GetUser(ctx context.Context, tx pgx.Tx, id uuid.UUID) (UserPrincipal, error)
	SaveUser(ctx context.Context, tx pgx.Tx, user UserPrincipal, expectedVersion int64) error
	UserCanBeEnabled(ctx context.Context, tx pgx.Tx, user UserPrincipal) (bool, error)
	InsertLocalUser(ctx context.Context, tx pgx.Tx, user UserPrincipal, credential LocalCredential) error
	ListUsers(ctx context.Context, page Page) (UserPage, error)
	FindLocalAuthentication(ctx context.Context, canonicalUsername string) (LoginState, UserPrincipal, LocalCredential, error)
	InsertOrganization(ctx context.Context, tx pgx.Tx, organization OrganizationUnit) error
	GetOrganization(ctx context.Context, tx pgx.Tx, id uuid.UUID) (OrganizationUnit, error)
	ListOrganizations(ctx context.Context, page Page) (OrganizationPage, error)
	ListOrganizationChildren(ctx context.Context, organizationID uuid.UUID, page Page) (OrganizationPage, error)
	ListOrganizationMemberships(ctx context.Context, organizationID uuid.UUID, page Page) (OrganizationMembershipPage, error)
	GetOrganizationMembership(ctx context.Context, tx pgx.Tx, organizationID, userID uuid.UUID, sourceOwned bool) (OrganizationMembership, error)
	InsertPlatformOrganizationMembership(ctx context.Context, tx pgx.Tx, membership OrganizationMembership) error
	SavePlatformOrganizationMembership(ctx context.Context, tx pgx.Tx, membership OrganizationMembership, expectedVersion int64) error
	SaveOrganization(ctx context.Context, tx pgx.Tx, organization OrganizationUnit, expectedVersion int64) error
	InsertRoleBinding(ctx context.Context, tx pgx.Tx, binding RoleBinding) error
	GetRoleBinding(ctx context.Context, tx pgx.Tx, id uuid.UUID) (RoleBinding, error)
	ListRoleBindings(ctx context.Context, page Page) (RoleBindingPage, error)
	DeleteRoleBinding(ctx context.Context, tx pgx.Tx, id uuid.UUID, expectedVersion int64) error
	InsertIdentitySource(ctx context.Context, tx pgx.Tx, source IdentitySource) error
	ListIdentitySources(ctx context.Context, page Page) (IdentitySourcePage, error)
	UpdateIdentitySourceDraft(ctx context.Context, tx pgx.Tx, source IdentitySource, expectedVersion int64) error
}

// ScopeCatalogValidator is the authoritative catalog boundary for IAM role
// scopes. Transactional callers pass their transaction so the validated
// product/channel remains protected until the role binding is persisted.
type ScopeCatalogValidator interface {
	ValidateRoleBindingScope(ctx context.Context, tx pgx.Tx, scope CatalogScope) error
}

type BreakGlassInvariantRepository interface {
	LockBreakGlassInvariant(ctx context.Context, tx pgx.Tx) error
	EvaluateBreakGlassInvariant(ctx context.Context, tx pgx.Tx, at time.Time) (BreakGlassInvariantEvaluation, error)
}

type BreakGlassInvariant interface {
	LockAuthority(ctx context.Context, tx pgx.Tx) error
	RequireUsableAdministrator(ctx context.Context, tx pgx.Tx, at time.Time) error
	LockAndRequireUsableAdministrator(ctx context.Context, tx pgx.Tx, at time.Time) error
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
	Reachable                bool     `json:"reachable"`
	RequiredAttributes       []string `json:"required_mappings"`
	RequiredMappingsComplete bool     `json:"required_mappings_complete"`
	SupportsIncremental      bool     `json:"supports_incremental"`
	SupportsPagination       bool     `json:"supports_pagination"`
}

type SyncDiff struct {
	CreateCount   int
	UpdateCount   int
	DisableCount  int
	ConflictCount int
}

type SyncPage struct {
	Users               []DirectoryUser
	Organizations       []DirectoryOrganization
	Memberships         []DirectoryMembership
	OrganizationParents []DirectoryOrganizationParent
	NextCursor          string
	Complete            bool
}

type DirectoryUser struct {
	ExternalSubject string
	Username        string
	DisplayName     string
	Email           string
	Enabled         bool
}

type DirectoryOrganization struct {
	ExternalID       string
	Name             string
	ParentExternalID string
}

type DirectoryMembership struct {
	OrganizationExternalID string
	UserExternalSubject    string
}

type DirectoryOrganizationParent struct {
	OrganizationExternalID string
	ParentExternalID       string
}
