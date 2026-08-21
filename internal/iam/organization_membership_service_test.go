package iam

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"xminds-release-platform/internal/identity"
)

// Mutation caught: removing the identity.manage check would expose organization
// hierarchy and membership facts to an unprivileged principal.
func TestOrganizationReadsRequireIdentityManageAndReturnActiveMembershipEdges(t *testing.T) {
	harness := newIAMHarness(t)
	organizationID := uuid.New()
	childID := uuid.New()
	userID := uuid.New()
	harness.repository.organizations[organizationID] = OrganizationUnit{ID: organizationID, Name: "Engineering", Status: OrganizationStatusActive, Version: 4}
	harness.repository.organizations[childID] = OrganizationUnit{ID: childID, ParentID: organizationID, Name: "Release", Status: OrganizationStatusActive, Version: 2}
	harness.repository.users[userID] = UserPrincipal{ID: userID, Username: "member", Status: UserStatusActive, Version: 3}
	harness.repository.organizationMemberships[organizationMembershipKey{organizationID: organizationID, userID: userID, sourceOwned: true}] = OrganizationMembership{
		OrganizationID: organizationID, UserID: userID, SourceOwned: true, Status: OrganizationMembershipStatusActive, Version: 1,
	}
	harness.repository.organizationMemberships[organizationMembershipKey{organizationID: organizationID, userID: uuid.New(), sourceOwned: false}] = OrganizationMembership{
		OrganizationID: organizationID, UserID: uuid.New(), SourceOwned: false, Status: OrganizationMembershipStatusRemoved, Version: 2,
	}

	unauthorized := identity.Principal{Subject: "viewer", Kind: identity.PrincipalKindHuman, Roles: []identity.Role{identity.RoleViewer}}
	if _, err := harness.service.GetOrganization(context.Background(), unauthorized, organizationID); !errors.Is(err, identity.ErrActionDenied) {
		t.Fatalf("GetOrganization unauthorized error = %v", err)
	}
	if organization, err := harness.service.GetOrganization(context.Background(), harness.admin, organizationID); err != nil || organization.ID != organizationID {
		t.Fatalf("GetOrganization() = %+v, %v", organization, err)
	}
	if page, err := harness.service.ListOrganizationChildren(context.Background(), harness.admin, organizationID, Page{}); err != nil || len(page.Items) != 1 || page.Items[0].ID != childID {
		t.Fatalf("ListOrganizationChildren() = %+v, %v", page, err)
	}
	if page, err := harness.service.ListOrganizationMemberships(context.Background(), harness.admin, organizationID, Page{}); err != nil || len(page.Items) != 1 || page.Items[0].UserID != userID || !page.Items[0].SourceOwned {
		t.Fatalf("ListOrganizationMemberships() = %+v, %v", page, err)
	}
}

// Mutation caught: treating a source edge as the platform edge would prevent
// independent authority facts from coexisting.
func TestCreateOrganizationMembershipKeepsSourceAndPlatformEdgesIndependent(t *testing.T) {
	harness, organizationID, userID := organizationMembershipHarness(t)
	harness.repository.organizationMemberships[organizationMembershipKey{organizationID: organizationID, userID: userID, sourceOwned: true}] = OrganizationMembership{
		OrganizationID: organizationID, UserID: userID, SourceOwned: true, Status: OrganizationMembershipStatusActive, Version: 7,
	}

	created, err := harness.service.CreateOrganizationMembership(context.Background(), harness.admin, organizationID, CreateOrganizationMembershipCommand{
		OrganizationVersion: 4, UserID: userID, UserVersion: 3, Reason: "approved supplemental access",
	}, harness.proof(), harness.request)
	if err != nil {
		t.Fatalf("CreateOrganizationMembership() error = %v", err)
	}
	if created.SourceOwned || created.Status != OrganizationMembershipStatusActive || created.Version != 1 {
		t.Fatalf("created membership = %+v", created)
	}
	if harness.repository.organizations[organizationID].Version != 5 {
		t.Fatalf("organization version = %d", harness.repository.organizations[organizationID].Version)
	}
	if len(harness.sessions.subjects) != 1 || harness.sessions.subjects[0] != userID {
		t.Fatalf("revoked subjects = %v", harness.sessions.subjects)
	}
	if len(harness.auditor.commands) != 1 || harness.auditor.commands[0].Action != "identity.organization_membership.create" {
		t.Fatalf("audit commands = %+v", harness.auditor.commands)
	}
	metadata := harness.auditor.commands[0].Metadata
	if metadata["reason_digest"] == "" || metadata["reason_characters"] != 28 || metadata["reason"] != nil {
		t.Fatalf("audit reason metadata = %#v", metadata)
	}
}

// Mutation caught: proof consumption before optimistic/resource validation
// would burn a challenge for a request that could never commit.
func TestOrganizationMembershipPreflightFailuresDoNotConsumeProof(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*iamHarness, uuid.UUID, uuid.UUID)
		command CreateOrganizationMembershipCommand
		want    error
	}{
		{name: "organization version", command: CreateOrganizationMembershipCommand{OrganizationVersion: 3, UserVersion: 3, Reason: "approved supplemental access"}, want: ErrIAMConflict},
		{name: "user version", command: CreateOrganizationMembershipCommand{OrganizationVersion: 4, UserVersion: 2, Reason: "approved supplemental access"}, want: ErrIAMConflict},
		{name: "organization disabled", mutate: func(h *iamHarness, organizationID, _ uuid.UUID) {
			value := h.repository.organizations[organizationID]
			value.Status = OrganizationStatusDisabled
			h.repository.organizations[organizationID] = value
		}, command: CreateOrganizationMembershipCommand{OrganizationVersion: 4, UserVersion: 3, Reason: "approved supplemental access"}, want: ErrOrganizationMembershipInvalid},
		{name: "user disabled", mutate: func(h *iamHarness, _, userID uuid.UUID) {
			value := h.repository.users[userID]
			value.Status = UserStatusDisabled
			h.repository.users[userID] = value
		}, command: CreateOrganizationMembershipCommand{OrganizationVersion: 4, UserVersion: 3, Reason: "approved supplemental access"}, want: ErrOrganizationMembershipInvalid},
		{name: "short reason", command: CreateOrganizationMembershipCommand{OrganizationVersion: 4, UserVersion: 3, Reason: "short"}, want: ErrOrganizationMembershipInvalid},
		{name: "surrounding whitespace", command: CreateOrganizationMembershipCommand{OrganizationVersion: 4, UserVersion: 3, Reason: " approved supplemental access "}, want: ErrOrganizationMembershipInvalid},
		{name: "unicode over maximum", command: CreateOrganizationMembershipCommand{OrganizationVersion: 4, UserVersion: 3, Reason: strings.Repeat("界", 513)}, want: ErrOrganizationMembershipInvalid},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			harness, organizationID, userID := organizationMembershipHarness(t)
			testCase.command.UserID = userID
			if testCase.mutate != nil {
				testCase.mutate(harness, organizationID, userID)
			}
			_, err := harness.service.CreateOrganizationMembership(context.Background(), harness.admin, organizationID, testCase.command, harness.proof(), harness.request)
			if !errors.Is(err, testCase.want) {
				t.Fatalf("CreateOrganizationMembership() error = %v, want %v", err, testCase.want)
			}
			if len(harness.highRisk.operations) != 0 {
				t.Fatalf("preflight failure consumed proof: %v", harness.highRisk.operations)
			}
		})
	}
}

func TestOrganizationMembershipReasonAcceptsExactly512UnicodeCharacters(t *testing.T) {
	harness, organizationID, userID := organizationMembershipHarness(t)
	if _, err := harness.service.CreateOrganizationMembership(context.Background(), harness.admin, organizationID, CreateOrganizationMembershipCommand{
		OrganizationVersion: 4, UserID: userID, UserVersion: 3, Reason: strings.Repeat("界", 512),
	}, harness.proof(), harness.request); err != nil {
		t.Fatalf("CreateOrganizationMembership(512 Unicode characters) error=%v", err)
	}
}

// Mutation caught: hard deletion or matching the source-owned edge would erase
// upstream authority and reintroduce ABA hazards.
func TestDeleteOrganizationMembershipSoftRemovesOnlyExpectedPlatformGeneration(t *testing.T) {
	harness, organizationID, userID := organizationMembershipHarness(t)
	platformKey := organizationMembershipKey{organizationID: organizationID, userID: userID, sourceOwned: false}
	sourceKey := organizationMembershipKey{organizationID: organizationID, userID: userID, sourceOwned: true}
	harness.repository.organizationMemberships[platformKey] = OrganizationMembership{OrganizationID: organizationID, UserID: userID, Status: OrganizationMembershipStatusActive, Version: 5}
	harness.repository.organizationMemberships[sourceKey] = OrganizationMembership{OrganizationID: organizationID, UserID: userID, SourceOwned: true, Status: OrganizationMembershipStatusActive, Version: 9}

	err := harness.service.DeleteOrganizationMembership(context.Background(), harness.admin, organizationID, userID, DeleteOrganizationMembershipCommand{
		OrganizationVersion: 4, UserVersion: 3, MembershipVersion: 5, Reason: "remove obsolete supplemental access",
	}, harness.proof(), harness.request)
	if err != nil {
		t.Fatalf("DeleteOrganizationMembership() error = %v", err)
	}
	platform := harness.repository.organizationMemberships[platformKey]
	if platform.Status != OrganizationMembershipStatusRemoved || platform.Version != 6 {
		t.Fatalf("platform membership = %+v", platform)
	}
	if source := harness.repository.organizationMemberships[sourceKey]; source.Status != OrganizationMembershipStatusActive || source.Version != 9 {
		t.Fatalf("source membership changed = %+v", source)
	}
	if err := harness.service.DeleteOrganizationMembership(context.Background(), harness.admin, organizationID, userID, DeleteOrganizationMembershipCommand{
		OrganizationVersion: 5, UserVersion: 3, MembershipVersion: 5, Reason: "remove obsolete supplemental access",
	}, harness.proof(), harness.request); !errors.Is(err, ErrOrganizationMembershipNotFound) {
		t.Fatalf("stale delete error = %v, want membership not found", err)
	}
}

func organizationMembershipHarness(t *testing.T) (*iamHarness, uuid.UUID, uuid.UUID) {
	t.Helper()
	harness := newIAMHarness(t)
	harness.admin.Kind = identity.PrincipalKindLocal
	harness.admin.Governed = true
	harness.admin.GovernedUserID = harness.emergencyAdminID.String()
	harness.admin.AuthenticationAssurance = 2
	harness.admin.RoleScopes = []identity.RoleScope{{Role: identity.RoleAdmin, Effect: "allow", ScopeType: "platform"}}
	organizationID, userID := uuid.New(), uuid.New()
	harness.repository.organizations[organizationID] = OrganizationUnit{ID: organizationID, Name: "Engineering", Status: OrganizationStatusActive, Version: 4, CreatedAt: harness.now, UpdatedAt: harness.now}
	harness.repository.users[userID] = UserPrincipal{ID: userID, Username: "release.member", Kind: UserKindLocal, Status: UserStatusActive, Version: 3, CreatedAt: harness.now, UpdatedAt: harness.now}
	return harness, organizationID, userID
}
