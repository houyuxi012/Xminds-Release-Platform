package iam

import (
	"context"
	"errors"
	"reflect"
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
func TestCreateOrganizationMembershipPreflightFailuresDoNotConsumeProof(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*iamHarness, *identity.Principal, *uuid.UUID, *CreateOrganizationMembershipCommand)
		want    error
	}{
		{name: "permission", prepare: func(_ *iamHarness, actor *identity.Principal, _ *uuid.UUID, _ *CreateOrganizationMembershipCommand) {
			actor.Roles, actor.RoleScopes = []identity.Role{identity.RoleViewer}, nil
		}, want: identity.ErrActionDenied},
		{name: "governed actor", prepare: func(_ *iamHarness, actor *identity.Principal, _ *uuid.UUID, _ *CreateOrganizationMembershipCommand) {
			actor.Governed = false
		}, want: ErrHighRiskConfirmationRequired},
		{name: "invalid input", prepare: func(_ *iamHarness, _ *identity.Principal, _ *uuid.UUID, command *CreateOrganizationMembershipCommand) {
			command.Reason = "short"
		}, want: ErrOrganizationMembershipInvalid},
		{name: "organization missing", prepare: func(_ *iamHarness, _ *identity.Principal, organizationID *uuid.UUID, _ *CreateOrganizationMembershipCommand) {
			*organizationID = uuid.New()
		}, want: ErrOrganizationNotFound},
		{name: "user missing", prepare: func(_ *iamHarness, _ *identity.Principal, _ *uuid.UUID, command *CreateOrganizationMembershipCommand) {
			command.UserID = uuid.New()
		}, want: ErrUserNotFound},
		{name: "organization version", prepare: func(_ *iamHarness, _ *identity.Principal, _ *uuid.UUID, command *CreateOrganizationMembershipCommand) {
			command.OrganizationVersion--
		}, want: ErrIAMConflict},
		{name: "user version", prepare: func(_ *iamHarness, _ *identity.Principal, _ *uuid.UUID, command *CreateOrganizationMembershipCommand) {
			command.UserVersion--
		}, want: ErrIAMConflict},
		{name: "organization disabled", prepare: func(h *iamHarness, _ *identity.Principal, organizationID *uuid.UUID, _ *CreateOrganizationMembershipCommand) {
			value := h.repository.organizations[*organizationID]
			value.Status = OrganizationStatusDisabled
			h.repository.organizations[*organizationID] = value
		}, want: ErrOrganizationMembershipInvalid},
		{name: "user disabled", prepare: func(h *iamHarness, _ *identity.Principal, _ *uuid.UUID, command *CreateOrganizationMembershipCommand) {
			value := h.repository.users[command.UserID]
			value.Status = UserStatusDisabled
			h.repository.users[command.UserID] = value
		}, want: ErrOrganizationMembershipInvalid},
		{name: "platform membership active", prepare: func(h *iamHarness, _ *identity.Principal, organizationID *uuid.UUID, command *CreateOrganizationMembershipCommand) {
			h.repository.organizationMemberships[organizationMembershipKey{organizationID: *organizationID, userID: command.UserID, sourceOwned: false}] = OrganizationMembership{OrganizationID: *organizationID, UserID: command.UserID, Status: OrganizationMembershipStatusActive, Version: 2}
		}, want: ErrIAMConflict},
		{name: "surrounding whitespace", prepare: func(_ *iamHarness, _ *identity.Principal, _ *uuid.UUID, command *CreateOrganizationMembershipCommand) {
			command.Reason = " approved supplemental access "
		}, want: ErrOrganizationMembershipInvalid},
		{name: "unicode over maximum", prepare: func(_ *iamHarness, _ *identity.Principal, _ *uuid.UUID, command *CreateOrganizationMembershipCommand) {
			command.Reason = strings.Repeat("界", 513)
		}, want: ErrOrganizationMembershipInvalid},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			harness, organizationID, userID := organizationMembershipHarness(t)
			actor := harness.admin
			command := CreateOrganizationMembershipCommand{OrganizationVersion: 4, UserID: userID, UserVersion: 3, Reason: "approved supplemental access"}
			testCase.prepare(harness, &actor, &organizationID, &command)
			before := captureOrganizationMembershipBusinessState(harness)

			_, err := harness.service.CreateOrganizationMembership(context.Background(), actor, organizationID, command, harness.proof(), harness.request)
			if !errors.Is(err, testCase.want) {
				t.Fatalf("CreateOrganizationMembership() error = %v, want %v", err, testCase.want)
			}
			assertOrganizationMembershipPreflightUnchanged(t, harness, before)
		})
	}
}

func TestDeleteOrganizationMembershipPreflightFailuresDoNotConsumeProof(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*iamHarness, *identity.Principal, *uuid.UUID, *uuid.UUID, *DeleteOrganizationMembershipCommand)
		want    error
	}{
		{name: "permission", prepare: func(_ *iamHarness, actor *identity.Principal, _, _ *uuid.UUID, _ *DeleteOrganizationMembershipCommand) {
			actor.Roles, actor.RoleScopes = []identity.Role{identity.RoleViewer}, nil
		}, want: identity.ErrActionDenied},
		{name: "governed actor", prepare: func(_ *iamHarness, actor *identity.Principal, _, _ *uuid.UUID, _ *DeleteOrganizationMembershipCommand) {
			actor.Governed = false
		}, want: ErrHighRiskConfirmationRequired},
		{name: "invalid input", prepare: func(_ *iamHarness, _ *identity.Principal, _, _ *uuid.UUID, command *DeleteOrganizationMembershipCommand) {
			command.MembershipVersion = 0
		}, want: ErrOrganizationMembershipInvalid},
		{name: "organization missing", prepare: func(_ *iamHarness, _ *identity.Principal, organizationID, _ *uuid.UUID, _ *DeleteOrganizationMembershipCommand) {
			*organizationID = uuid.New()
		}, want: ErrOrganizationNotFound},
		{name: "user missing", prepare: func(_ *iamHarness, _ *identity.Principal, _, userID *uuid.UUID, _ *DeleteOrganizationMembershipCommand) {
			*userID = uuid.New()
		}, want: ErrUserNotFound},
		{name: "platform membership missing", prepare: func(h *iamHarness, _ *identity.Principal, organizationID, userID *uuid.UUID, _ *DeleteOrganizationMembershipCommand) {
			delete(h.repository.organizationMemberships, organizationMembershipKey{organizationID: *organizationID, userID: *userID, sourceOwned: false})
		}, want: ErrOrganizationMembershipNotFound},
		{name: "source membership only", prepare: func(h *iamHarness, _ *identity.Principal, organizationID, userID *uuid.UUID, _ *DeleteOrganizationMembershipCommand) {
			delete(h.repository.organizationMemberships, organizationMembershipKey{organizationID: *organizationID, userID: *userID, sourceOwned: false})
			h.repository.organizationMemberships[organizationMembershipKey{organizationID: *organizationID, userID: *userID, sourceOwned: true}] = OrganizationMembership{OrganizationID: *organizationID, UserID: *userID, SourceOwned: true, Status: OrganizationMembershipStatusActive, Version: 9}
		}, want: ErrOrganizationMembershipNotFound},
		{name: "organization version", prepare: func(_ *iamHarness, _ *identity.Principal, _, _ *uuid.UUID, command *DeleteOrganizationMembershipCommand) {
			command.OrganizationVersion--
		}, want: ErrIAMConflict},
		{name: "user version", prepare: func(_ *iamHarness, _ *identity.Principal, _, _ *uuid.UUID, command *DeleteOrganizationMembershipCommand) {
			command.UserVersion--
		}, want: ErrIAMConflict},
		{name: "membership version", prepare: func(_ *iamHarness, _ *identity.Principal, _, _ *uuid.UUID, command *DeleteOrganizationMembershipCommand) {
			command.MembershipVersion--
		}, want: ErrIAMConflict},
		{name: "organization disabled", prepare: func(h *iamHarness, _ *identity.Principal, organizationID, _ *uuid.UUID, _ *DeleteOrganizationMembershipCommand) {
			value := h.repository.organizations[*organizationID]
			value.Status = OrganizationStatusDisabled
			h.repository.organizations[*organizationID] = value
		}, want: ErrOrganizationMembershipInvalid},
		{name: "user disabled", prepare: func(h *iamHarness, _ *identity.Principal, _, userID *uuid.UUID, _ *DeleteOrganizationMembershipCommand) {
			value := h.repository.users[*userID]
			value.Status = UserStatusDisabled
			h.repository.users[*userID] = value
		}, want: ErrOrganizationMembershipInvalid},
		{name: "platform membership removed", prepare: func(h *iamHarness, _ *identity.Principal, organizationID, userID *uuid.UUID, _ *DeleteOrganizationMembershipCommand) {
			key := organizationMembershipKey{organizationID: *organizationID, userID: *userID, sourceOwned: false}
			value := h.repository.organizationMemberships[key]
			value.Status = OrganizationMembershipStatusRemoved
			h.repository.organizationMemberships[key] = value
		}, want: ErrOrganizationMembershipNotFound},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			harness, organizationID, userID := organizationMembershipHarness(t)
			harness.repository.organizationMemberships[organizationMembershipKey{organizationID: organizationID, userID: userID, sourceOwned: false}] = OrganizationMembership{OrganizationID: organizationID, UserID: userID, Status: OrganizationMembershipStatusActive, Version: 5}
			actor := harness.admin
			command := DeleteOrganizationMembershipCommand{OrganizationVersion: 4, UserVersion: 3, MembershipVersion: 5, Reason: "remove obsolete supplemental access"}
			testCase.prepare(harness, &actor, &organizationID, &userID, &command)
			before := captureOrganizationMembershipBusinessState(harness)

			err := harness.service.DeleteOrganizationMembership(context.Background(), actor, organizationID, userID, command, harness.proof(), harness.request)
			if !errors.Is(err, testCase.want) {
				t.Fatalf("DeleteOrganizationMembership() error = %v, want %v", err, testCase.want)
			}
			assertOrganizationMembershipPreflightUnchanged(t, harness, before)
		})
	}
}

type organizationMembershipBusinessState struct {
	organizations map[uuid.UUID]OrganizationUnit
	users         map[uuid.UUID]UserPrincipal
	memberships   map[organizationMembershipKey]OrganizationMembership
	transactions  int
	audits        int
	revocations   int
}

func captureOrganizationMembershipBusinessState(harness *iamHarness) organizationMembershipBusinessState {
	return organizationMembershipBusinessState{
		organizations: cloneIAMOrganizations(harness.repository.organizations),
		users:         cloneIAMUsers(harness.repository.users),
		memberships:   cloneIAMOrganizationMemberships(harness.repository.organizationMemberships),
		transactions:  harness.repository.withinTransactionCalls,
		audits:        len(harness.auditor.commands),
		revocations:   len(harness.sessions.subjects),
	}
}

func assertOrganizationMembershipPreflightUnchanged(t *testing.T, harness *iamHarness, before organizationMembershipBusinessState) {
	t.Helper()
	if len(harness.highRisk.operations) != 0 {
		t.Fatalf("preflight failure consumed proof: %v", harness.highRisk.operations)
	}
	after := captureOrganizationMembershipBusinessState(harness)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("preflight failure changed business state\nbefore=%#v\nafter=%#v", before, after)
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
