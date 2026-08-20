package iam

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"xminds-release-platform/internal/identity"
)

var ErrGovernedPrincipalUnavailable = errors.New("governed principal is unavailable")

// GovernedPrincipalResolver replaces untrusted human/local token claims with
// current IAM state. Workloads retain their explicitly configured verifier
// identity and are never silently mapped through human directory records.
type GovernedPrincipalResolver struct {
	repository *PostgresRepository
	now        func() time.Time
}

func NewGovernedPrincipalResolver(repository *PostgresRepository, now func() time.Time) (*GovernedPrincipalResolver, error) {
	if repository == nil || repository.pool == nil || now == nil {
		return nil, ErrIAMConfiguration
	}
	return &GovernedPrincipalResolver{repository: repository, now: now}, nil
}

func (resolver *GovernedPrincipalResolver) ResolvePrincipal(ctx context.Context, principal identity.Principal) (identity.Principal, error) {
	if principal.Kind == identity.PrincipalKindWorkload {
		return principal, nil
	}
	if principal.Kind != identity.PrincipalKindHuman && principal.Kind != identity.PrincipalKindLocal {
		return identity.Principal{}, ErrGovernedPrincipalUnavailable
	}
	var sourceStatus *IdentitySourceStatus
	user, err := scanUser(resolver.repository.pool.QueryRow(ctx, userSelect+`
WHERE lower(user_record.username) = lower($1) OR user_record.external_subject = $1
ORDER BY user_record.created_at DESC LIMIT 1`, strings.TrimSpace(principal.Subject)))
	if err != nil {
		return identity.Principal{}, ErrGovernedPrincipalUnavailable
	}
	if user.IdentitySourceID != uuid.Nil {
		var status IdentitySourceStatus
		if err := resolver.repository.pool.QueryRow(ctx, `SELECT status FROM identity_sources WHERE id = $1`, user.IdentitySourceID).Scan(&status); err != nil {
			return identity.Principal{}, ErrGovernedPrincipalUnavailable
		}
		sourceStatus = &status
	}
	if user.Status != UserStatusActive || (sourceStatus != nil && *sourceStatus != IdentitySourceStatusEnabled) {
		return identity.Principal{}, ErrGovernedPrincipalUnavailable
	}
	rows, err := resolver.repository.pool.Query(ctx, `SELECT organization_id FROM organization_memberships WHERE user_id=$1`, user.ID)
	if err != nil {
		return identity.Principal{}, ErrGovernedPrincipalUnavailable
	}
	defer rows.Close()
	organizations := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		if rows.Scan(&id) != nil {
			return identity.Principal{}, ErrGovernedPrincipalUnavailable
		}
		organizations = append(organizations, id)
	}
	bindings, err := resolver.repository.ListRoleBindingsForPrincipal(ctx, user.ID, organizations)
	if err != nil {
		return identity.Principal{}, err
	}
	principal.Roles, principal.ProductIDs, principal.Governed, principal.RoleScopes = nil, nil, true, make([]identity.RoleScope, 0, len(bindings))
	for _, binding := range bindings {
		if bindingActive(binding, resolver.now().UTC()) {
			principal.RoleScopes = append(principal.RoleScopes, identity.RoleScope{Role: binding.Role, Effect: string(binding.Effect), ScopeType: string(binding.ScopeType), ProductID: binding.ProductID, ChannelName: binding.ChannelName})
		}
	}
	return principal, nil
}

func (repository *PostgresRepository) ListRoleBindingsForPrincipal(ctx context.Context, userID uuid.UUID, organizations []uuid.UUID) ([]RoleBinding, error) {
	rows, err := repository.pool.Query(ctx, roleBindingSelect+` WHERE (subject_type='user' AND subject_id=$1) OR (subject_type='organization' AND subject_id = ANY($2))`, userID, organizations)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []RoleBinding{}
	for rows.Next() {
		binding, scanErr := scanRoleBinding(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, binding)
	}
	return result, rows.Err()
}
