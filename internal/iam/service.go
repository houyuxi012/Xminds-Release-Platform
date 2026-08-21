package iam

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/identity"
)

const maximumReauthenticationAge = 5 * time.Minute

const localActivationLifetime = 24 * time.Hour

var identityFaultCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)
var localUsernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,127}$`)

type ServiceConfig struct {
	Repository    Repository
	ScopeCatalog  ScopeCatalogValidator
	BreakGlass    BreakGlassInvariant
	Auditor       AuditAppender
	Sessions      SessionRevoker
	Passwords     PasswordService
	Directory     DirectoryAdapter
	DirectorySync *DirectorySyncService
	HighRisk      HighRiskAuthorizer
	Clock         func() time.Time
}

type Service struct {
	repository    Repository
	scopeCatalog  ScopeCatalogValidator
	breakGlass    BreakGlassInvariant
	auditor       AuditAppender
	sessions      SessionRevoker
	passwords     PasswordService
	directory     DirectoryAdapter
	directorySync *DirectorySyncService
	highRisk      HighRiskAuthorizer
	authorizer    *identity.Authorizer
	clock         func() time.Time
}

func (service *Service) CreateOrganization(ctx context.Context, actor identity.Principal, command CreateOrganizationCommand, request RequestContext) (OrganizationUnit, error) {
	if err := service.authorizer.Require(actor, identity.ActionIdentityManage, ""); err != nil {
		return OrganizationUnit{}, err
	}
	name := strings.TrimSpace(command.Name)
	if name == "" || len([]rune(name)) > 256 {
		return OrganizationUnit{}, ErrUserInputInvalid
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	id, err := uuid.NewV7()
	if err != nil {
		return OrganizationUnit{}, fmt.Errorf("generate organization ID: %w", err)
	}
	organization := OrganizationUnit{ID: id, ParentID: command.ParentID, Name: name, SourceOwned: false, Status: OrganizationStatusActive, Version: 1, CreatedAt: now, UpdatedAt: now}
	err = service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if command.ParentID != uuid.Nil {
			parent, parentErr := service.repository.GetOrganization(ctx, tx, command.ParentID)
			if parentErr != nil {
				return parentErr
			}
			if parent.Status != OrganizationStatusActive {
				return ErrUserInputInvalid
			}
		}
		if insertErr := service.repository.InsertOrganization(ctx, tx, organization); insertErr != nil {
			return insertErr
		}
		_, appendErr := service.auditor.Append(ctx, tx, audit.AppendCommand{Actor: actor, Action: "identity.organization.create", ResourceType: "organization_unit", ResourceID: organization.ID.String(), Outcome: audit.OutcomeSuccess, RequestID: request.RequestID, SourceIP: request.SourceIP, Metadata: map[string]any{"name": organization.Name, "parent_id": organization.ParentID.String()}})
		return appendErr
	})
	if err != nil {
		return OrganizationUnit{}, err
	}
	return organization, nil
}

func (service *Service) ListOrganizations(ctx context.Context, actor identity.Principal, page Page) (OrganizationPage, error) {
	if err := service.authorizer.Require(actor, identity.ActionIdentityManage, ""); err != nil {
		return OrganizationPage{}, err
	}
	if !validIAMPage(page) {
		return OrganizationPage{}, ErrPageInvalid
	}
	return service.repository.ListOrganizations(ctx, page)
}

func (service *Service) GetOrganization(ctx context.Context, actor identity.Principal, organizationID uuid.UUID) (OrganizationUnit, error) {
	if err := service.authorizer.Require(actor, identity.ActionIdentityManage, ""); err != nil {
		return OrganizationUnit{}, err
	}
	if organizationID == uuid.Nil {
		return OrganizationUnit{}, ErrOrganizationNotFound
	}
	return service.repository.GetOrganization(ctx, nil, organizationID)
}

func (service *Service) ListOrganizationChildren(ctx context.Context, actor identity.Principal, organizationID uuid.UUID, page Page) (OrganizationPage, error) {
	if err := service.authorizer.Require(actor, identity.ActionIdentityManage, ""); err != nil {
		return OrganizationPage{}, err
	}
	if organizationID == uuid.Nil {
		return OrganizationPage{}, ErrOrganizationNotFound
	}
	if !validIAMPage(page) {
		return OrganizationPage{}, ErrPageInvalid
	}
	if _, err := service.repository.GetOrganization(ctx, nil, organizationID); err != nil {
		return OrganizationPage{}, err
	}
	return service.repository.ListOrganizationChildren(ctx, organizationID, page)
}

func (service *Service) ListOrganizationMemberships(ctx context.Context, actor identity.Principal, organizationID uuid.UUID, page Page) (OrganizationMembershipPage, error) {
	if err := service.authorizer.Require(actor, identity.ActionIdentityManage, ""); err != nil {
		return OrganizationMembershipPage{}, err
	}
	if organizationID == uuid.Nil {
		return OrganizationMembershipPage{}, ErrOrganizationNotFound
	}
	if !validIAMPage(page) {
		return OrganizationMembershipPage{}, ErrPageInvalid
	}
	if _, err := service.repository.GetOrganization(ctx, nil, organizationID); err != nil {
		return OrganizationMembershipPage{}, err
	}
	return service.repository.ListOrganizationMemberships(ctx, organizationID, page)
}

func (service *Service) CreateOrganizationMembership(ctx context.Context, actor identity.Principal, organizationID uuid.UUID, command CreateOrganizationMembershipCommand, proof HighRiskProof, request RequestContext) (OrganizationMembership, error) {
	if err := service.requireGovernedIdentityManager(actor); err != nil {
		return OrganizationMembership{}, err
	}
	reasonDigest, reasonCharacters, err := validateOrganizationMembershipCommand(organizationID, command.UserID, command.OrganizationVersion, command.UserVersion, command.Reason)
	if err != nil {
		return OrganizationMembership{}, err
	}
	if service.sessions == nil || service.breakGlass == nil {
		return OrganizationMembership{}, ErrIAMConfiguration
	}
	organization, user, current, currentExists, err := service.preflightOrganizationMembership(ctx, nil, organizationID, command.UserID)
	if err != nil {
		return OrganizationMembership{}, err
	}
	if organization.Version != command.OrganizationVersion || user.Version != command.UserVersion {
		return OrganizationMembership{}, ErrIAMConflict
	}
	if organization.Status != OrganizationStatusActive || user.Status != UserStatusActive {
		return OrganizationMembership{}, ErrOrganizationMembershipInvalid
	}
	if currentExists && current.Status == OrganizationMembershipStatusActive {
		return OrganizationMembership{}, ErrIAMConflict
	}
	if err := service.consumeHighRisk(ctx, actor, string(ReauthenticationOperationOrganizationMembershipCreate), proof, request); err != nil {
		return OrganizationMembership{}, err
	}

	now := service.clock().UTC().Truncate(time.Microsecond)
	var result OrganizationMembership
	err = service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if lockErr := service.breakGlass.LockAuthority(ctx, tx); lockErr != nil {
			return lockErr
		}
		lockedOrganization, lockedUser, lockedMembership, membershipExists, lockErr := service.preflightOrganizationMembership(ctx, tx, organizationID, command.UserID)
		if lockErr != nil {
			return lockErr
		}
		if lockedOrganization.Version != command.OrganizationVersion || lockedUser.Version != command.UserVersion {
			return ErrIAMConflict
		}
		if lockedOrganization.Status != OrganizationStatusActive || lockedUser.Status != UserStatusActive {
			return ErrOrganizationMembershipInvalid
		}
		previousStatus, previousVersion := "absent", int64(0)
		if membershipExists {
			previousStatus, previousVersion = string(lockedMembership.Status), lockedMembership.Version
			if lockedMembership.Status == OrganizationMembershipStatusActive {
				return ErrIAMConflict
			}
			lockedMembership.Status = OrganizationMembershipStatusActive
			lockedMembership.Version++
			lockedMembership.UpdatedAt = now
			if saveErr := service.repository.SavePlatformOrganizationMembership(ctx, tx, lockedMembership, previousVersion); saveErr != nil {
				return saveErr
			}
			result = lockedMembership
		} else {
			result = OrganizationMembership{OrganizationID: organizationID, UserID: command.UserID, SourceOwned: false, Status: OrganizationMembershipStatusActive, Version: 1, CreatedAt: now, UpdatedAt: now}
			if insertErr := service.repository.InsertPlatformOrganizationMembership(ctx, tx, result); insertErr != nil {
				return insertErr
			}
		}
		previousOrganizationVersion := lockedOrganization.Version
		lockedOrganization.Version++
		lockedOrganization.UpdatedAt = now
		if saveErr := service.repository.SaveOrganization(ctx, tx, lockedOrganization, previousOrganizationVersion); saveErr != nil {
			return saveErr
		}
		if invariantErr := service.breakGlass.RequireUsableAdministrator(ctx, tx, now); invariantErr != nil {
			return invariantErr
		}
		if revokeErr := service.sessions.RevokeSubject(ctx, tx, command.UserID, "organization membership changed"); revokeErr != nil {
			return fmt.Errorf("revoke membership subject sessions: %w", revokeErr)
		}
		_, appendErr := service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: scrubIAMHighRiskAuditActor(actor), Action: string(ReauthenticationOperationOrganizationMembershipCreate), ResourceType: "organization_membership", ResourceID: organizationMembershipResourceID(organizationID, command.UserID),
			Outcome: audit.OutcomeSuccess, RequestID: request.RequestID, SourceIP: request.SourceIP,
			Metadata: organizationMembershipAuditMetadata(organizationID, command.UserID, previousStatus, string(result.Status), previousVersion, result.Version, previousOrganizationVersion, lockedOrganization.Version, reasonDigest, reasonCharacters),
		})
		return appendErr
	})
	if err != nil {
		return OrganizationMembership{}, err
	}
	return result, nil
}

func (service *Service) DeleteOrganizationMembership(ctx context.Context, actor identity.Principal, organizationID, userID uuid.UUID, command DeleteOrganizationMembershipCommand, proof HighRiskProof, request RequestContext) error {
	if err := service.requireGovernedIdentityManager(actor); err != nil {
		return err
	}
	reasonDigest, reasonCharacters, err := validateOrganizationMembershipCommand(organizationID, userID, command.OrganizationVersion, command.UserVersion, command.Reason)
	if err != nil || command.MembershipVersion < 1 {
		return ErrOrganizationMembershipInvalid
	}
	if service.sessions == nil || service.breakGlass == nil {
		return ErrIAMConfiguration
	}
	organization, user, membership, exists, err := service.preflightOrganizationMembership(ctx, nil, organizationID, userID)
	if err != nil {
		return err
	}
	if organization.Version != command.OrganizationVersion || user.Version != command.UserVersion {
		return ErrIAMConflict
	}
	if !exists || membership.Status != OrganizationMembershipStatusActive {
		return ErrOrganizationMembershipNotFound
	}
	if membership.Version != command.MembershipVersion {
		return ErrIAMConflict
	}
	if err := service.consumeHighRisk(ctx, actor, string(ReauthenticationOperationOrganizationMembershipDelete), proof, request); err != nil {
		return err
	}

	now := service.clock().UTC().Truncate(time.Microsecond)
	return service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if lockErr := service.breakGlass.LockAuthority(ctx, tx); lockErr != nil {
			return lockErr
		}
		lockedOrganization, lockedUser, lockedMembership, lockedExists, lockErr := service.preflightOrganizationMembership(ctx, tx, organizationID, userID)
		if lockErr != nil {
			return lockErr
		}
		if lockedOrganization.Version != command.OrganizationVersion || lockedUser.Version != command.UserVersion {
			return ErrIAMConflict
		}
		if !lockedExists || lockedMembership.Status != OrganizationMembershipStatusActive {
			return ErrOrganizationMembershipNotFound
		}
		if lockedMembership.Version != command.MembershipVersion {
			return ErrIAMConflict
		}
		previousMembershipVersion := lockedMembership.Version
		lockedMembership.Status = OrganizationMembershipStatusRemoved
		lockedMembership.Version++
		lockedMembership.UpdatedAt = now
		if saveErr := service.repository.SavePlatformOrganizationMembership(ctx, tx, lockedMembership, previousMembershipVersion); saveErr != nil {
			return saveErr
		}
		previousOrganizationVersion := lockedOrganization.Version
		lockedOrganization.Version++
		lockedOrganization.UpdatedAt = now
		if saveErr := service.repository.SaveOrganization(ctx, tx, lockedOrganization, previousOrganizationVersion); saveErr != nil {
			return saveErr
		}
		if invariantErr := service.breakGlass.RequireUsableAdministrator(ctx, tx, now); invariantErr != nil {
			return invariantErr
		}
		if revokeErr := service.sessions.RevokeSubject(ctx, tx, userID, "organization membership changed"); revokeErr != nil {
			return fmt.Errorf("revoke membership subject sessions: %w", revokeErr)
		}
		_, appendErr := service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: scrubIAMHighRiskAuditActor(actor), Action: string(ReauthenticationOperationOrganizationMembershipDelete), ResourceType: "organization_membership", ResourceID: organizationMembershipResourceID(organizationID, userID),
			Outcome: audit.OutcomeSuccess, RequestID: request.RequestID, SourceIP: request.SourceIP,
			Metadata: organizationMembershipAuditMetadata(organizationID, userID, string(OrganizationMembershipStatusActive), string(OrganizationMembershipStatusRemoved), previousMembershipVersion, lockedMembership.Version, previousOrganizationVersion, lockedOrganization.Version, reasonDigest, reasonCharacters),
		})
		return appendErr
	})
}

func (service *Service) preflightOrganizationMembership(ctx context.Context, tx pgx.Tx, organizationID, userID uuid.UUID) (OrganizationUnit, UserPrincipal, OrganizationMembership, bool, error) {
	organization, err := service.repository.GetOrganization(ctx, tx, organizationID)
	if err != nil {
		return OrganizationUnit{}, UserPrincipal{}, OrganizationMembership{}, false, err
	}
	user, err := service.repository.GetUser(ctx, tx, userID)
	if err != nil {
		return OrganizationUnit{}, UserPrincipal{}, OrganizationMembership{}, false, err
	}
	membership, err := service.repository.GetOrganizationMembership(ctx, tx, organizationID, userID, false)
	if errors.Is(err, ErrOrganizationMembershipNotFound) {
		return organization, user, OrganizationMembership{}, false, nil
	}
	if err != nil {
		return OrganizationUnit{}, UserPrincipal{}, OrganizationMembership{}, false, err
	}
	return organization, user, membership, true, nil
}

func validateOrganizationMembershipCommand(organizationID, userID uuid.UUID, organizationVersion, userVersion int64, reason string) (string, int, error) {
	reasonCharacters, validReason := canonicalOrganizationMembershipReason(reason)
	if organizationID == uuid.Nil || userID == uuid.Nil || organizationVersion < 1 || userVersion < 1 || !validReason {
		return "", 0, ErrOrganizationMembershipInvalid
	}
	digest := sha256.Sum256([]byte(reason))
	return hex.EncodeToString(digest[:]), reasonCharacters, nil
}

func canonicalOrganizationMembershipReason(rawReason string) (int, bool) {
	characters := len([]rune(rawReason))
	return characters, rawReason == strings.TrimSpace(rawReason) && characters >= 8 && characters <= 512
}

func organizationMembershipResourceID(organizationID, userID uuid.UUID) string {
	return organizationID.String() + ":" + userID.String() + ":platform"
}

func organizationMembershipAuditMetadata(organizationID, userID uuid.UUID, previousStatus, newStatus string, previousMembershipVersion, newMembershipVersion, previousOrganizationVersion, newOrganizationVersion int64, reasonDigest string, reasonCharacters int) map[string]any {
	return map[string]any{
		"organization_id": organizationID.String(), "user_id": userID.String(), "source_owned": false,
		"previous_status": previousStatus, "new_status": newStatus,
		"previous_membership_version": previousMembershipVersion, "new_membership_version": newMembershipVersion,
		"previous_organization_version": previousOrganizationVersion, "new_organization_version": newOrganizationVersion,
		"reason_digest": reasonDigest, "reason_characters": reasonCharacters,
	}
}

func scrubIAMHighRiskAuditActor(actor identity.Principal) identity.Principal {
	actor.TokenID = ""
	actor.AuthenticatedAt = time.Time{}
	actor.AuthenticationAssurance = 0
	return actor
}

func (service *Service) CreateRoleBinding(ctx context.Context, actor identity.Principal, command CreateRoleBindingCommand, proof HighRiskProof, request RequestContext) (RoleBinding, error) {
	if err := service.requireIdentityManage(actor); err != nil {
		return RoleBinding{}, err
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	if command.ValidFrom.IsZero() {
		command.ValidFrom = now
	} else {
		command.ValidFrom = command.ValidFrom.UTC().Truncate(time.Microsecond)
	}
	if !command.ValidUntil.IsZero() {
		command.ValidUntil = command.ValidUntil.UTC().Truncate(time.Microsecond)
		if !command.ValidUntil.After(command.ValidFrom) {
			return RoleBinding{}, ErrRoleBindingInvalid
		}
	}
	if err := validateRoleBindingCommand(command); err != nil {
		return RoleBinding{}, err
	}
	if command.SubjectVersion < 1 {
		return RoleBinding{}, ErrRoleBindingInvalid
	}
	if err := service.scopeCatalog.ValidateRoleBindingScope(ctx, nil, catalogScopeFromCommand(command)); err != nil {
		return RoleBinding{}, err
	}
	if err := service.validateRoleBindingSubject(ctx, nil, command, false); err != nil {
		return RoleBinding{}, err
	}
	administratorElevation := command.Role == identity.RoleAdmin && command.ScopeType == ScopeTypePlatform && command.Effect == BindingEffectAllow
	if administratorElevation && service.sessions == nil {
		return RoleBinding{}, ErrIAMConfiguration
	}
	if err := service.consumeHighRisk(ctx, actor, string(ReauthenticationOperationRoleBindingCreate), proof, request); err != nil {
		return RoleBinding{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return RoleBinding{}, fmt.Errorf("generate role binding ID: %w", err)
	}
	binding := RoleBinding{ID: id, SubjectType: command.SubjectType, SubjectID: command.SubjectID, Role: command.Role, ScopeType: command.ScopeType, ProductID: strings.TrimSpace(command.ProductID), ChannelName: strings.TrimSpace(command.ChannelName), Effect: command.Effect, ValidFrom: command.ValidFrom, ValidUntil: command.ValidUntil, CreatedBy: actor.Subject, Version: 1, CreatedAt: now, UpdatedAt: now}
	administratorReduction := binding.Role == identity.RoleAdmin && binding.ScopeType == ScopeTypePlatform && binding.Effect == BindingEffectDeny
	err = service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if administratorReduction {
			if lockErr := service.breakGlass.LockAuthority(ctx, tx); lockErr != nil {
				return lockErr
			}
		}
		if validationErr := service.scopeCatalog.ValidateRoleBindingScope(ctx, tx, catalogScopeFromCommand(command)); validationErr != nil {
			return validationErr
		}
		if validationErr := service.validateRoleBindingSubject(ctx, tx, command, true); validationErr != nil {
			return validationErr
		}
		if insertErr := service.repository.InsertRoleBinding(ctx, tx, binding); insertErr != nil {
			return insertErr
		}
		if administratorReduction {
			if invariantErr := service.breakGlass.RequireUsableAdministrator(ctx, tx, now); invariantErr != nil {
				return invariantErr
			}
		}
		if administratorElevation {
			if binding.SubjectType == SubjectTypeUser {
				if err := service.sessions.RevokeSubject(ctx, tx, binding.SubjectID, "administrator role granted"); err != nil {
					return fmt.Errorf("revoke elevated subject sessions: %w", err)
				}
			} else if err := service.sessions.RevokeOrganizationMembers(ctx, tx, binding.SubjectID, "administrator role granted to organization"); err != nil {
				return fmt.Errorf("revoke elevated organization member sessions: %w", err)
			}
		}
		_, appendErr := service.auditor.Append(ctx, tx, audit.AppendCommand{Actor: actor, Action: "identity.role_binding.create", ResourceType: "role_binding", ResourceID: binding.ID.String(), Outcome: audit.OutcomeSuccess, RequestID: request.RequestID, SourceIP: request.SourceIP, Metadata: map[string]any{"subject_type": binding.SubjectType, "subject_id": binding.SubjectID.String(), "role": binding.Role, "scope_type": binding.ScopeType, "effect": binding.Effect}})
		return appendErr
	})
	if err != nil {
		return RoleBinding{}, err
	}
	return binding, nil
}

func (service *Service) validateRoleBindingSubject(ctx context.Context, tx pgx.Tx, command CreateRoleBindingCommand, enforceSecurity bool) error {
	if command.SubjectType == SubjectTypeUser {
		subject, err := service.repository.GetUser(ctx, tx, command.SubjectID)
		if err != nil {
			return err
		}
		if subject.Version != command.SubjectVersion {
			return ErrIAMConflict
		}
		if enforceSecurity && command.Role == identity.RoleAdmin && command.ScopeType == ScopeTypePlatform && command.Effect == BindingEffectAllow &&
			(subject.Kind == UserKindLocal || subject.Kind == UserKindEmergency) && !subject.MFAEnrolled {
			return ErrRoleBindingInvalid
		}
		return nil
	}
	organization, err := service.repository.GetOrganization(ctx, tx, command.SubjectID)
	if err != nil {
		return err
	}
	if organization.Version != command.SubjectVersion {
		return ErrIAMConflict
	}
	return nil
}

func (service *Service) ListRoleBindings(ctx context.Context, actor identity.Principal, page Page) (RoleBindingPage, error) {
	if err := service.authorizer.Require(actor, identity.ActionIdentityManage, ""); err != nil {
		return RoleBindingPage{}, err
	}
	if !validIAMPage(page) {
		return RoleBindingPage{}, ErrPageInvalid
	}
	return service.repository.ListRoleBindings(ctx, page)
}

func (service *Service) DeleteRoleBinding(ctx context.Context, actor identity.Principal, bindingID uuid.UUID, expectedVersion int64, proof HighRiskProof, request RequestContext) error {
	if err := service.requireIdentityManage(actor); err != nil {
		return err
	}
	if bindingID == uuid.Nil || expectedVersion < 1 {
		return ErrRoleBindingInvalid
	}
	if service.sessions == nil {
		return ErrIAMConfiguration
	}
	preflight, err := service.repository.GetRoleBinding(ctx, nil, bindingID)
	if err != nil {
		return err
	}
	if preflight.Version != expectedVersion {
		return ErrIAMConflict
	}
	administratorReduction := preflight.Role == identity.RoleAdmin && preflight.ScopeType == ScopeTypePlatform && preflight.Effect == BindingEffectAllow
	if err := service.consumeHighRisk(ctx, actor, string(ReauthenticationOperationRoleBindingDelete), proof, request); err != nil {
		return err
	}
	err = service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if administratorReduction {
			if lockErr := service.breakGlass.LockAuthority(ctx, tx); lockErr != nil {
				return lockErr
			}
		}
		binding, err := service.repository.GetRoleBinding(ctx, tx, bindingID)
		if err != nil {
			return err
		}
		if binding.Version != expectedVersion {
			return ErrIAMConflict
		}
		if err := service.repository.DeleteRoleBinding(ctx, tx, bindingID, expectedVersion); err != nil {
			return err
		}
		if administratorReduction {
			if invariantErr := service.breakGlass.RequireUsableAdministrator(ctx, tx, service.clock().UTC().Truncate(time.Microsecond)); invariantErr != nil {
				return invariantErr
			}
		}
		if binding.SubjectType == SubjectTypeUser {
			if err := service.sessions.RevokeSubject(ctx, tx, binding.SubjectID, "role binding removed"); err != nil {
				return fmt.Errorf("revoke sessions after role binding removal: %w", err)
			}
		} else if err := service.sessions.RevokeOrganizationMembers(ctx, tx, binding.SubjectID, "organization role binding removed"); err != nil {
			return fmt.Errorf("revoke organization member sessions after role binding removal: %w", err)
		}
		_, err = service.auditor.Append(ctx, tx, audit.AppendCommand{Actor: actor, Action: "identity.role_binding.delete", ResourceType: "role_binding", ResourceID: binding.ID.String(), Outcome: audit.OutcomeSuccess, RequestID: request.RequestID, SourceIP: request.SourceIP, Metadata: map[string]any{"subject_type": binding.SubjectType, "subject_id": binding.SubjectID.String(), "role": binding.Role, "scope_type": binding.ScopeType, "effect": binding.Effect, "version": binding.Version}})
		return err
	})
	if err != nil {
		return err
	}
	return nil
}

func (service *Service) CreateIdentitySource(ctx context.Context, actor identity.Principal, command CreateIdentitySourceCommand, request RequestContext) (IdentitySource, error) {
	if err := service.authorizer.Require(actor, identity.ActionIdentityManage, ""); err != nil {
		return IdentitySource{}, err
	}
	name, secretReference := strings.TrimSpace(command.Name), strings.TrimSpace(command.SecretReference)
	if name == "" || len([]rune(name)) > 128 || len(secretReference) > 256 || secretReference == "" || (command.Kind != IdentitySourceOIDC && command.Kind != IdentitySourceSCIM) {
		return IdentitySource{}, ErrIdentitySourceInputInvalid
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	id, err := uuid.NewV7()
	if err != nil {
		return IdentitySource{}, fmt.Errorf("generate identity source ID: %w", err)
	}
	source := IdentitySource{ID: id, Name: name, Kind: command.Kind, Status: IdentitySourceStatusDraft, SecretReference: secretReference, RequiredMappingsComplete: command.RequiredMappingsComplete, Version: 1, CreatedAt: now, UpdatedAt: now}
	err = service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if insertErr := service.repository.InsertIdentitySource(ctx, tx, source); insertErr != nil {
			return insertErr
		}
		_, appendErr := service.auditor.Append(ctx, tx, audit.AppendCommand{Actor: actor, Action: "identity.source.create", ResourceType: "identity_source", ResourceID: source.ID.String(), Outcome: audit.OutcomeSuccess, RequestID: request.RequestID, SourceIP: request.SourceIP, Metadata: map[string]any{"name": source.Name, "source_kind": source.Kind, "required_mappings_complete": source.RequiredMappingsComplete}})
		return appendErr
	})
	if err != nil {
		return IdentitySource{}, err
	}
	return redactIdentitySource(source), nil
}

func (service *Service) ListIdentitySources(ctx context.Context, actor identity.Principal, page Page) (IdentitySourcePage, error) {
	if err := service.authorizer.Require(actor, identity.ActionIdentityManage, ""); err != nil {
		return IdentitySourcePage{}, err
	}
	if !validIAMPage(page) {
		return IdentitySourcePage{}, ErrPageInvalid
	}
	result, err := service.repository.ListIdentitySources(ctx, page)
	if err != nil {
		return IdentitySourcePage{}, err
	}
	for index := range result.Items {
		result.Items[index] = redactIdentitySource(result.Items[index])
	}
	return result, nil
}

func (service *Service) PatchIdentitySourceDraft(ctx context.Context, actor identity.Principal, sourceID uuid.UUID, command PatchIdentitySourceCommand, request RequestContext) (IdentitySource, error) {
	if err := service.authorizer.Require(actor, identity.ActionIdentityManage, ""); err != nil {
		return IdentitySource{}, err
	}
	if sourceID == uuid.Nil || command.Version < 1 || (command.Name == nil && command.SecretReference == nil && command.RequiredMappingsComplete == nil) {
		return IdentitySource{}, ErrIdentitySourceInputInvalid
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	var patched IdentitySource
	err := service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		source, err := service.repository.GetIdentitySource(ctx, tx, sourceID)
		if err != nil {
			return err
		}
		if source.Status != IdentitySourceStatusDraft || source.Version != command.Version {
			if source.Version != command.Version {
				return ErrIAMConflict
			}
			return ErrIdentitySourceInputInvalid
		}
		if command.Name != nil {
			source.Name = strings.TrimSpace(*command.Name)
			if source.Name == "" || len([]rune(source.Name)) > 128 {
				return ErrIdentitySourceInputInvalid
			}
		}
		if command.SecretReference != nil {
			source.SecretReference = strings.TrimSpace(*command.SecretReference)
			if source.SecretReference == "" || len(source.SecretReference) > 256 {
				return ErrIdentitySourceInputInvalid
			}
		}
		if command.RequiredMappingsComplete != nil {
			source.RequiredMappingsComplete = *command.RequiredMappingsComplete
		}
		source.Version++
		source.UpdatedAt = now
		if err := service.repository.UpdateIdentitySourceDraft(ctx, tx, source, command.Version); err != nil {
			return err
		}
		_, err = service.auditor.Append(ctx, tx, audit.AppendCommand{Actor: actor, Action: "identity.source.patch", ResourceType: "identity_source", ResourceID: source.ID.String(), Outcome: audit.OutcomeSuccess, RequestID: request.RequestID, SourceIP: request.SourceIP, Metadata: map[string]any{"name": source.Name, "required_mappings_complete": source.RequiredMappingsComplete, "version": source.Version}})
		patched = source
		return err
	})
	if err != nil {
		return IdentitySource{}, err
	}
	return redactIdentitySource(patched), nil
}

func (service *Service) VerifyIdentitySource(ctx context.Context, actor identity.Principal, sourceID uuid.UUID, request RequestContext) (CapabilityReport, error) {
	return service.VerifyIdentitySourceVersioned(ctx, actor, sourceID, 0, request)
}

func (service *Service) VerifyIdentitySourceVersioned(ctx context.Context, actor identity.Principal, sourceID uuid.UUID, expectedVersion int64, request RequestContext) (CapabilityReport, error) {
	if err := service.authorizer.Require(actor, identity.ActionIdentityManage, ""); err != nil {
		return CapabilityReport{}, err
	}
	if service.directory == nil {
		return CapabilityReport{}, ErrDirectoryAdapterUnavailable
	}
	source, err := service.repository.GetIdentitySource(ctx, nil, sourceID)
	if err != nil {
		return CapabilityReport{}, err
	}
	if source.Status != IdentitySourceStatusDraft && source.Status != IdentitySourceStatusVerified {
		return CapabilityReport{}, ErrIdentitySourceInputInvalid
	}
	if expectedVersion > 0 && source.Version != expectedVersion {
		return CapabilityReport{}, ErrIAMConflict
	}
	report, err := service.directory.Verify(ctx, source)
	if err != nil {
		return CapabilityReport{}, err
	}
	if !report.Reachable {
		return CapabilityReport{}, ErrIdentitySourceInputInvalid
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	err = service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		current, err := service.repository.GetIdentitySource(ctx, tx, sourceID)
		if err != nil {
			return err
		}
		if current.Version != source.Version || (current.Status != IdentitySourceStatusDraft && current.Status != IdentitySourceStatusVerified) {
			return ErrIAMConflict
		}
		current.Status, current.VerifiedAt, current.Version, current.UpdatedAt = IdentitySourceStatusVerified, now, current.Version+1, now
		if err := service.repository.SaveIdentitySource(ctx, tx, current, current.Version-1); err != nil {
			return err
		}
		_, err = service.auditor.Append(ctx, tx, audit.AppendCommand{Actor: actor, Action: "identity.source.verify", ResourceType: "identity_source", ResourceID: current.ID.String(), Outcome: audit.OutcomeSuccess, RequestID: request.RequestID, SourceIP: request.SourceIP, Metadata: map[string]any{"source_kind": current.Kind, "supports_incremental": report.SupportsIncremental}})
		return err
	})
	return report, err
}

func (service *Service) StartDirectorySync(ctx context.Context, actor identity.Principal, sourceID uuid.UUID, mode DirectorySyncMode, expectedVersion int64, request RequestContext) (DirectorySyncJob, error) {
	if service == nil || service.directorySync == nil {
		return DirectorySyncJob{}, ErrDirectorySyncConfiguration
	}
	return service.directorySync.Start(ctx, actor, sourceID, mode, expectedVersion, request)
}

func (service *Service) GetDirectorySyncJob(ctx context.Context, actor identity.Principal, sourceID, jobID uuid.UUID) (DirectorySyncJob, error) {
	if service == nil || service.directorySync == nil {
		return DirectorySyncJob{}, ErrDirectorySyncConfiguration
	}
	return service.directorySync.GetJob(ctx, actor, sourceID, jobID)
}

func (service *Service) ListDirectorySyncConflicts(ctx context.Context, actor identity.Principal, sourceID uuid.UUID, status DirectorySyncConflictStatusFilter, page Page) (DirectorySyncConflictPage, error) {
	if service == nil || service.directorySync == nil {
		return DirectorySyncConflictPage{}, ErrDirectorySyncConfiguration
	}
	return service.directorySync.ListConflicts(ctx, actor, sourceID, status, page)
}

func (service *Service) ResolveDirectorySyncConflict(ctx context.Context, actor identity.Principal, sourceID, conflictID uuid.UUID, command ResolveDirectorySyncConflictCommand, proof HighRiskProof, request RequestContext) (DirectorySyncConflict, error) {
	if service == nil || service.directorySync == nil {
		return DirectorySyncConflict{}, ErrDirectorySyncConfiguration
	}
	return service.directorySync.ResolveConflict(ctx, actor, sourceID, conflictID, command, proof, request)
}

func (service *Service) PreviewIdentitySource(ctx context.Context, actor identity.Principal, sourceID uuid.UUID, request RequestContext) (SyncDiff, error) {
	if err := service.authorizer.Require(actor, identity.ActionIdentityManage, ""); err != nil {
		return SyncDiff{}, err
	}
	if service.directory == nil {
		return SyncDiff{}, ErrDirectoryAdapterUnavailable
	}
	source, err := service.repository.GetIdentitySource(ctx, nil, sourceID)
	if err != nil {
		return SyncDiff{}, err
	}
	if source.Status != IdentitySourceStatusVerified || source.VerifiedAt.IsZero() {
		return SyncDiff{}, ErrIdentitySourceInputInvalid
	}
	diff, err := service.directory.Preview(ctx, source)
	if err != nil {
		return SyncDiff{}, err
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	err = service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		current, err := service.repository.GetIdentitySource(ctx, tx, sourceID)
		if err != nil {
			return err
		}
		if current.Version != source.Version || current.Status != IdentitySourceStatusVerified || current.VerifiedAt.IsZero() {
			return ErrIAMConflict
		}
		current.PreviewedAt, current.Version, current.UpdatedAt = now, current.Version+1, now
		if err := service.repository.SaveIdentitySource(ctx, tx, current, current.Version-1); err != nil {
			return err
		}
		_, err = service.auditor.Append(ctx, tx, audit.AppendCommand{Actor: actor, Action: "identity.source.sync_preview", ResourceType: "identity_source", ResourceID: current.ID.String(), Outcome: audit.OutcomeSuccess, RequestID: request.RequestID, SourceIP: request.SourceIP, Metadata: map[string]any{"create_count": diff.CreateCount, "update_count": diff.UpdateCount, "disable_count": diff.DisableCount, "conflict_count": diff.ConflictCount}})
		return err
	})
	return diff, err
}

func (service *Service) CreateLocalUser(ctx context.Context, actor identity.Principal, command CreateLocalUserCommand, request RequestContext) (LocalUserProvisioning, error) {
	if err := service.authorizer.Require(actor, identity.ActionIdentityManage, ""); err != nil {
		return LocalUserProvisioning{}, err
	}
	command, err := validateCreateLocalUserCommand(command)
	if err != nil {
		return LocalUserProvisioning{}, ErrUserInputInvalid
	}
	activationToken, err := generateActivationToken()
	if err != nil {
		return LocalUserProvisioning{}, err
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	activationExpires := now.Add(localActivationLifetime)
	activationDigest := sha256.Sum256([]byte(activationToken))
	userID, err := uuid.NewV7()
	if err != nil {
		return LocalUserProvisioning{}, fmt.Errorf("generate local user ID: %w", err)
	}
	user := UserPrincipal{
		ID: userID, Username: command.Username, DisplayName: command.DisplayName, Email: command.Email,
		Kind: UserKindLocal, Status: UserStatusPending, Version: 1, CreatedAt: now, UpdatedAt: now,
	}
	credential := LocalCredential{
		UserID:           user.ID,
		ActivationDigest: hex.EncodeToString(activationDigest[:]), ActivationExpiresAt: activationExpires,
	}
	err = service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if insertErr := service.repository.InsertLocalUser(ctx, tx, user, credential); insertErr != nil {
			return insertErr
		}
		_, appendErr := service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: actor, Action: "identity.local_user.create", ResourceType: "user_principal", ResourceID: user.ID.String(),
			Outcome: audit.OutcomeSuccess, RequestID: request.RequestID, SourceIP: request.SourceIP,
			Metadata: map[string]any{"username": user.Username, "user_kind": user.Kind, "status": user.Status},
		})
		return appendErr
	})
	if err != nil {
		return LocalUserProvisioning{}, err
	}
	return LocalUserProvisioning{User: user, ActivationToken: activationToken, ActivationExpires: activationExpires}, nil
}

func (service *Service) GetUser(ctx context.Context, actor identity.Principal, userID uuid.UUID) (UserPrincipal, error) {
	if err := service.authorizer.Require(actor, identity.ActionIdentityManage, ""); err != nil {
		return UserPrincipal{}, err
	}
	return service.repository.GetUser(ctx, nil, userID)
}

func (service *Service) ListUsers(ctx context.Context, actor identity.Principal, page Page) (UserPage, error) {
	if err := service.authorizer.Require(actor, identity.ActionIdentityManage, ""); err != nil {
		return UserPage{}, err
	}
	if page.Limit < 0 || page.Limit > 200 || (page.BeforeTime.IsZero() != (page.BeforeID == uuid.Nil)) {
		return UserPage{}, ErrPageInvalid
	}
	return service.repository.ListUsers(ctx, page)
}

func generateActivationToken() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate activation token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func NewService(config ServiceConfig) (*Service, error) {
	if config.Repository == nil || config.ScopeCatalog == nil || config.BreakGlass == nil || config.Auditor == nil || config.Passwords == nil || config.Clock == nil {
		return nil, ErrIAMConfiguration
	}
	return &Service{
		repository: config.Repository, scopeCatalog: config.ScopeCatalog, breakGlass: config.BreakGlass, auditor: config.Auditor, sessions: config.Sessions, directory: config.Directory, directorySync: config.DirectorySync, highRisk: config.HighRisk,
		passwords: config.Passwords, authorizer: identity.NewAuthorizer(), clock: config.Clock,
	}, nil
}

func validIAMPage(page Page) bool {
	return page.Limit >= 0 && page.Limit <= 200 && (page.BeforeTime.IsZero() == (page.BeforeID == uuid.Nil))
}

func validateRoleBindingCommand(command CreateRoleBindingCommand) error {
	if command.SubjectID == uuid.Nil || (command.SubjectType != SubjectTypeUser && command.SubjectType != SubjectTypeOrganization) ||
		(command.Effect != BindingEffectAllow && command.Effect != BindingEffectDeny) {
		return ErrRoleBindingInvalid
	}
	switch command.Role {
	case identity.RoleAdmin, identity.RolePublisher, identity.RoleApprover, identity.RoleAuditor, identity.RoleViewer:
	default:
		return ErrRoleBindingInvalid
	}
	productID, channelName := strings.TrimSpace(command.ProductID), strings.TrimSpace(command.ChannelName)
	if len([]rune(productID)) > 128 || len([]rune(channelName)) > 64 {
		return ErrRoleBindingInvalid
	}
	switch command.ScopeType {
	case ScopeTypePlatform:
		if productID != "" || channelName != "" {
			return ErrRoleBindingInvalid
		}
	case ScopeTypeProduct:
		if productID == "" || channelName != "" {
			return ErrRoleBindingInvalid
		}
	case ScopeTypeChannel:
		if productID == "" || channelName == "" {
			return ErrRoleBindingInvalid
		}
	default:
		return ErrRoleBindingInvalid
	}
	return nil
}

func catalogScopeFromCommand(command CreateRoleBindingCommand) CatalogScope {
	return CatalogScope{
		Type: command.ScopeType, ProductID: strings.TrimSpace(command.ProductID), ChannelName: strings.TrimSpace(command.ChannelName),
	}
}

func (service *Service) EnableSSO(ctx context.Context, actor identity.Principal, sourceID uuid.UUID, expectedVersion int64, proof HighRiskProof, request RequestContext) error {
	if err := service.requireIdentityManage(actor); err != nil {
		return err
	}
	if sourceID == uuid.Nil || expectedVersion < 1 {
		return ErrSSOPreconditionFailed
	}
	if service.sessions == nil {
		return ErrIAMConfiguration
	}
	preflightSource, err := service.repository.GetIdentitySource(ctx, nil, sourceID)
	if err != nil {
		return err
	}
	if preflightSource.Version != expectedVersion {
		return ErrIAMConflict
	}
	if preflightSource.Kind != IdentitySourceOIDC {
		return ErrSSOPreconditionFailed
	}
	if err := service.consumeHighRisk(ctx, actor, string(ReauthenticationOperationSSOEnable), proof, request); err != nil {
		return err
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	return service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if lockErr := service.breakGlass.LockAuthority(ctx, tx); lockErr != nil {
			return lockErr
		}
		state, err := service.repository.GetLoginState(ctx, tx)
		if err != nil {
			return err
		}
		if state.Mode != LoginModeLocal && state.Mode != LoginModeConfiguring {
			return ErrLoginModeTransitionInvalid
		}
		source, err := service.repository.GetIdentitySource(ctx, tx, sourceID)
		if err != nil {
			return err
		}
		if source.Version != expectedVersion {
			return ErrIAMConflict
		}
		if source.Kind != IdentitySourceOIDC || source.Status != IdentitySourceStatusVerified || source.VerifiedAt.IsZero() || source.PreviewedAt.IsZero() ||
			!source.RequiredMappingsComplete {
			return ErrSSOPreconditionFailed
		}
		previousMode := state.Mode
		state.Mode = LoginModeSSO
		state.ActiveSourceID = source.ID
		state.FaultCode = ""
		state.Version++
		state.UpdatedBy = actor.Subject
		state.UpdatedAt = now
		if err := service.repository.SetLoginState(ctx, tx, state, state.Version-1); err != nil {
			return err
		}
		sourceVersion := source.Version
		source.Status = IdentitySourceStatusEnabled
		source.FaultCode = ""
		source.Version++
		source.UpdatedAt = now
		if err := service.repository.SaveIdentitySource(ctx, tx, source, sourceVersion); err != nil {
			return err
		}
		if err := service.sessions.RevokeRegularLocalSessions(ctx, tx, "login mode changed to sso"); err != nil {
			return fmt.Errorf("revoke regular local sessions for SSO: %w", err)
		}
		if invariantErr := service.breakGlass.RequireUsableAdministrator(ctx, tx, now); invariantErr != nil {
			if invariantErr == ErrLastEmergencyAdministrator {
				return ErrSSOPreconditionFailed
			}
			return invariantErr
		}
		_, err = service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: actor, Action: "identity.sso.enable", ResourceType: "identity_source", ResourceID: source.ID.String(),
			Outcome: audit.OutcomeSuccess, RequestID: request.RequestID, SourceIP: request.SourceIP,
			Metadata: map[string]any{"before_mode": previousMode, "after_mode": state.Mode, "source_kind": source.Kind},
		})
		return err
	})
}

func (service *Service) MarkIdentitySourceFault(ctx context.Context, actor identity.Principal, sourceID uuid.UUID, code string, request RequestContext) error {
	if service.sessions == nil {
		return ErrIAMConfiguration
	}
	if err := service.authorizer.Require(actor, identity.ActionIdentityManage, ""); err != nil {
		return err
	}
	code = strings.TrimSpace(code)
	if sourceID == uuid.Nil || !identityFaultCodePattern.MatchString(code) {
		return ErrIdentityFaultCodeInvalid
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	return service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		state, err := service.repository.GetLoginState(ctx, tx)
		if err != nil {
			return err
		}
		if state.Mode != LoginModeSSO || state.ActiveSourceID != sourceID {
			return ErrLoginModeTransitionInvalid
		}
		source, err := service.repository.GetIdentitySource(ctx, tx, sourceID)
		if err != nil {
			return err
		}
		state.Mode = LoginModeFault
		state.FaultCode = code
		state.Version++
		state.UpdatedBy = actor.Subject
		state.UpdatedAt = now
		if err := service.repository.SetLoginState(ctx, tx, state, state.Version-1); err != nil {
			return err
		}
		sourceVersion := source.Version
		source.Status = IdentitySourceStatusFault
		source.FaultCode = code
		source.Version++
		source.UpdatedAt = now
		if err := service.repository.SaveIdentitySource(ctx, tx, source, sourceVersion); err != nil {
			return err
		}
		if err := service.sessions.RevokeRegularLocalSessions(ctx, tx, "login mode changed to fault"); err != nil {
			return fmt.Errorf("revoke regular local sessions for identity fault: %w", err)
		}
		_, err = service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: actor, Action: "identity.sso.fault", ResourceType: "identity_source", ResourceID: source.ID.String(),
			Outcome: audit.OutcomeFailed, RequestID: request.RequestID, SourceIP: request.SourceIP,
			Metadata: map[string]any{"error_code": code, "login_mode": state.Mode},
		})
		return err
	})
}

func (service *Service) DisableSSO(ctx context.Context, actor identity.Principal, sourceID uuid.UUID, expectedVersion int64, proof HighRiskProof, request RequestContext) error {
	if err := service.requireIdentityManage(actor); err != nil {
		return err
	}
	if sourceID == uuid.Nil || expectedVersion < 1 {
		return ErrSSOPreconditionFailed
	}
	preflightSource, err := service.repository.GetIdentitySource(ctx, nil, sourceID)
	if err != nil {
		return err
	}
	if preflightSource.Version != expectedVersion {
		return ErrIAMConflict
	}
	if err := service.consumeHighRisk(ctx, actor, string(ReauthenticationOperationSSODisable), proof, request); err != nil {
		return err
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	return service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		state, err := service.repository.GetLoginState(ctx, tx)
		if err != nil {
			return err
		}
		if (state.Mode != LoginModeSSO && state.Mode != LoginModeFault) || state.ActiveSourceID == uuid.Nil {
			return ErrLoginModeTransitionInvalid
		}
		source, err := service.repository.GetIdentitySource(ctx, tx, state.ActiveSourceID)
		if err != nil {
			return err
		}
		if state.ActiveSourceID != sourceID || source.Version != expectedVersion {
			return ErrIAMConflict
		}
		previousMode := state.Mode
		previousFaultCode := state.FaultCode
		state.Mode = LoginModeLocal
		state.ActiveSourceID = uuid.Nil
		state.FaultCode = ""
		state.Version++
		state.UpdatedBy = actor.Subject
		state.UpdatedAt = now
		if err := service.repository.SetLoginState(ctx, tx, state, state.Version-1); err != nil {
			return err
		}
		sourceVersion := source.Version
		source.Status = IdentitySourceStatusDisabled
		source.FaultCode = ""
		source.Version++
		source.UpdatedAt = now
		if err := service.repository.SaveIdentitySource(ctx, tx, source, sourceVersion); err != nil {
			return err
		}
		_, err = service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: actor, Action: "identity.sso.disable", ResourceType: "identity_source", ResourceID: source.ID.String(),
			Outcome: audit.OutcomeSuccess, RequestID: request.RequestID, SourceIP: request.SourceIP,
			Metadata: map[string]any{"before_mode": previousMode, "after_mode": state.Mode, "previous_fault_code": previousFaultCode},
		})
		return err
	})
}

func (service *Service) DisableUser(ctx context.Context, actor identity.Principal, userID uuid.UUID, expectedVersion int64, reason string, proof HighRiskProof, request RequestContext) error {
	if err := service.requireIdentityManage(actor); err != nil {
		return err
	}
	reason = strings.TrimSpace(reason)
	if userID == uuid.Nil || expectedVersion < 1 || reason == "" || len(reason) > 256 {
		return ErrDisableReasonRequired
	}
	if service.sessions == nil {
		return ErrIAMConfiguration
	}
	preflight, err := service.repository.GetUser(ctx, nil, userID)
	if err != nil {
		return err
	}
	if preflight.Version != expectedVersion {
		return ErrIAMConflict
	}
	if err := service.consumeHighRisk(ctx, actor, string(ReauthenticationOperationUserDisable), proof, request); err != nil {
		return err
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	err = service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if preflight.Kind == UserKindEmergency {
			if lockErr := service.breakGlass.LockAuthority(ctx, tx); lockErr != nil {
				return lockErr
			}
		}
		user, err := service.repository.GetUser(ctx, tx, userID)
		if err != nil {
			return err
		}
		if user.Status == UserStatusDisabled {
			return ErrUserAlreadyDisabled
		}
		if user.Version != expectedVersion {
			return ErrIAMConflict
		}
		previousStatus := user.Status
		previousVersion := user.Version
		user.Status = UserStatusDisabled
		user.DisabledAt = now
		user.DisabledReason = reason
		user.Version++
		user.UpdatedAt = now
		if err := service.repository.SaveUser(ctx, tx, user, previousVersion); err != nil {
			return err
		}
		if user.Kind == UserKindEmergency {
			if invariantErr := service.breakGlass.RequireUsableAdministrator(ctx, tx, now); invariantErr != nil {
				return invariantErr
			}
		}
		if err := service.sessions.RevokeSubject(ctx, tx, userID, reason); err != nil {
			return fmt.Errorf("revoke disabled user sessions: %w", err)
		}
		_, err = service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: actor, Action: "identity.user.disable", ResourceType: "user_principal", ResourceID: user.ID.String(),
			Outcome: audit.OutcomeSuccess, RequestID: request.RequestID, SourceIP: request.SourceIP,
			Metadata: map[string]any{"before_status": previousStatus, "after_status": user.Status, "reason": reason},
		})
		return err
	})
	if err != nil {
		return err
	}
	return nil
}

func (service *Service) EnableUser(ctx context.Context, actor identity.Principal, userID uuid.UUID, expectedVersion int64, reason string, proof HighRiskProof, request RequestContext) error {
	if err := service.requireIdentityManage(actor); err != nil {
		return err
	}
	reason = strings.TrimSpace(reason)
	if userID == uuid.Nil || expectedVersion < 1 || reason == "" || len(reason) > 256 {
		return ErrEnableReasonRequired
	}
	preflight, err := service.repository.GetUser(ctx, nil, userID)
	if err != nil {
		return err
	}
	if preflight.Version != expectedVersion {
		return ErrIAMConflict
	}
	if err := service.consumeHighRisk(ctx, actor, string(ReauthenticationOperationUserEnable), proof, request); err != nil {
		return err
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	return service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		user, getErr := service.repository.GetUser(ctx, tx, userID)
		if getErr != nil {
			return getErr
		}
		if user.Version != expectedVersion {
			return ErrIAMConflict
		}
		if user.Status == UserStatusActive {
			return ErrUserAlreadyEnabled
		}
		if user.Status != UserStatusDisabled {
			return ErrUserCannotBeEnabled
		}
		usable, usabilityErr := service.repository.UserCanBeEnabled(ctx, tx, user)
		if usabilityErr != nil {
			return usabilityErr
		}
		if !usable {
			return ErrUserCannotBeEnabled
		}
		previousStatus := user.Status
		user.Status, user.DisabledAt, user.DisabledReason = UserStatusActive, time.Time{}, ""
		user.Version++
		user.UpdatedAt = now
		if saveErr := service.repository.SaveUser(ctx, tx, user, expectedVersion); saveErr != nil {
			return saveErr
		}
		_, appendErr := service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: actor, Action: "identity.user.enable", ResourceType: "user_principal", ResourceID: user.ID.String(),
			Outcome: audit.OutcomeSuccess, RequestID: request.RequestID, SourceIP: request.SourceIP,
			Metadata: map[string]any{"before_status": previousStatus, "after_status": user.Status, "reason": reason},
		})
		return appendErr
	})
}

func (service *Service) RevokeUserSessions(ctx context.Context, actor identity.Principal, userID uuid.UUID, expectedVersion int64, reason string, proof HighRiskProof, request RequestContext) error {
	if err := service.requireIdentityManage(actor); err != nil {
		return err
	}
	reason = strings.TrimSpace(reason)
	if userID == uuid.Nil || expectedVersion < 1 || reason == "" || len(reason) > 256 {
		return ErrRevokeReasonRequired
	}
	if service.sessions == nil {
		return ErrIAMConfiguration
	}
	preflight, err := service.repository.GetUser(ctx, nil, userID)
	if err != nil {
		return err
	}
	if preflight.Version != expectedVersion {
		return ErrIAMConflict
	}
	if err := service.consumeHighRisk(ctx, actor, string(ReauthenticationOperationUserRevokeSessions), proof, request); err != nil {
		return err
	}
	return service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		user, getErr := service.repository.GetUser(ctx, tx, userID)
		if getErr != nil {
			return getErr
		}
		if user.Version != expectedVersion {
			return ErrIAMConflict
		}
		if revokeErr := service.sessions.RevokeSubject(ctx, tx, userID, reason); revokeErr != nil {
			return fmt.Errorf("revoke user sessions: %w", revokeErr)
		}
		_, appendErr := service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: actor, Action: "identity.user.revoke_sessions", ResourceType: "user_principal", ResourceID: user.ID.String(),
			Outcome: audit.OutcomeSuccess, RequestID: request.RequestID, SourceIP: request.SourceIP,
			Metadata: map[string]any{"reason": reason, "version": user.Version},
		})
		return appendErr
	})
}

func (service *Service) AuthenticateLocal(ctx context.Context, username, password string) (UserPrincipal, error) {
	username = canonicalUsername(username)
	state, user, credential, err := service.repository.FindLocalAuthentication(ctx, username)
	if state.Mode == LoginModeSSO || state.Mode == LoginModeFault {
		if user.Kind != UserKindEmergency {
			return UserPrincipal{}, ErrLocalLoginDisabled
		}
	}
	if err != nil {
		return UserPrincipal{}, ErrLocalCredentialInvalid
	}
	if user.Status != UserStatusActive || (credential.LockedUntil.After(service.clock())) {
		return UserPrincipal{}, ErrLocalCredentialLocked
	}
	if err := service.passwords.Verify(password, credential.Password); err != nil {
		return UserPrincipal{}, ErrLocalCredentialInvalid
	}
	return user, nil
}

func (service *Service) requireIdentityManage(actor identity.Principal) error {
	if service == nil || service.authorizer == nil || service.highRisk == nil {
		return ErrIAMConfiguration
	}
	return service.authorizer.Require(actor, identity.ActionIdentityManage, "")
}

func (service *Service) requireGovernedIdentityManager(actor identity.Principal) error {
	if err := service.requireIdentityManage(actor); err != nil {
		return err
	}
	if !actor.Governed || (actor.Kind != identity.PrincipalKindHuman && actor.Kind != identity.PrincipalKindLocal) {
		return ErrHighRiskConfirmationRequired
	}
	governedUserID, err := uuid.Parse(strings.TrimSpace(actor.GovernedUserID))
	if err != nil || governedUserID == uuid.Nil {
		return ErrHighRiskConfirmationRequired
	}
	return nil
}

func (service *Service) consumeHighRisk(ctx context.Context, actor identity.Principal, operation string, proof HighRiskProof, request RequestContext) error {
	if !proof.Confirmed {
		return ErrHighRiskConfirmationRequired
	}
	if err := service.highRisk.Authorize(ctx, actor, operation, proof, request); err != nil {
		return ErrHighRiskConfirmationRequired
	}
	return nil
}

func canonicalUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func redactIdentitySource(source IdentitySource) IdentitySource {
	source.SecretReference = ""
	return source
}
