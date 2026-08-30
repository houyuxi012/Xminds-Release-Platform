package iam

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"xminds-release-platform/internal/identity"
)

func TestResolveAccessCombinesDirectAndOrganizationBindings(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC)
	userID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e21")
	organizationID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e22")
	bindings := []RoleBinding{
		allowBinding(SubjectTypeUser, userID, identity.RoleViewer, ScopeTypePlatform, "", "", now),
		allowBinding(SubjectTypeOrganization, organizationID, identity.RolePublisher, ScopeTypeProduct, "ngep", "", now),
	}

	access := ResolveAccess(UserPrincipal{ID: userID, Status: UserStatusActive}, []uuid.UUID{organizationID}, bindings, now)

	if !access.Allowed(identity.RoleViewer, "", "") {
		t.Fatal("platform viewer access was not inherited from direct binding")
	}
	if !access.Allowed(identity.RolePublisher, "ngep", "") {
		t.Fatal("product publisher access was not inherited from organization binding")
	}
}

func TestResolveAccessDenyPrecedesAllowAtMatchingScope(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC)
	userID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e31")
	organizationID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e32")
	bindings := []RoleBinding{
		allowBinding(SubjectTypeOrganization, organizationID, identity.RolePublisher, ScopeTypeProduct, "ngep", "", now),
		{
			ID: uuid.New(), SubjectType: SubjectTypeUser, SubjectID: userID, Role: identity.RolePublisher,
			ScopeType: ScopeTypeProduct, ProductID: "ngep", Effect: BindingEffectDeny,
			ValidFrom: now.Add(-time.Hour),
		},
	}

	access := ResolveAccess(UserPrincipal{ID: userID, Status: UserStatusActive}, []uuid.UUID{organizationID}, bindings, now)

	if access.Allowed(identity.RolePublisher, "ngep", "") {
		t.Fatal("explicit user deny did not override organization allow")
	}
}

func TestResolveAccessIgnoresExpiredBindingsAndDisabledUsers(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC)
	userID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e41")
	expired := allowBinding(SubjectTypeUser, userID, identity.RoleAdmin, ScopeTypePlatform, "", "", now)
	expired.ValidUntil = now.Add(-time.Second)

	if ResolveAccess(UserPrincipal{ID: userID, Status: UserStatusActive}, nil, []RoleBinding{expired}, now).Allowed(identity.RoleAdmin, "", "") {
		t.Fatal("expired binding remained active")
	}
	active := allowBinding(SubjectTypeUser, userID, identity.RoleAdmin, ScopeTypePlatform, "", "", now)
	if ResolveAccess(UserPrincipal{ID: userID, Status: UserStatusDisabled}, nil, []RoleBinding{active}, now).Allowed(identity.RoleAdmin, "", "") {
		t.Fatal("disabled user retained access")
	}
}

func allowBinding(subjectType SubjectType, subjectID uuid.UUID, role identity.Role, scope ScopeType, productID, channel string, now time.Time) RoleBinding {
	return RoleBinding{
		ID: uuid.New(), SubjectType: subjectType, SubjectID: subjectID, Role: role,
		ScopeType: scope, ProductID: productID, ChannelName: channel, Effect: BindingEffectAllow,
		ValidFrom: now.Add(-time.Hour),
	}
}
