package iam

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/identity"
)

type emergencyProvisioningRepository interface {
	CanonicalPrincipalAvailable(ctx context.Context, username, email string) (bool, error)
	ProvisionPendingEmergency(ctx context.Context, tx pgx.Tx, user UserPrincipal, credential LocalCredential, binding RoleBinding) error
	GetLocalCredential(ctx context.Context, userID uuid.UUID) (LocalCredential, error)
	GetLocalCredentialForUpdate(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (LocalCredential, error)
	SaveEmergencyActivation(ctx context.Context, tx pgx.Tx, userID uuid.UUID, activationDigest string, activationExpiresAt time.Time) error
}

func (service *Service) ProvisionEmergencyUser(ctx context.Context, actor identity.Principal, command CreateEmergencyUserCommand, proof HighRiskProof, request RequestContext) (LocalUserProvisioning, error) {
	if err := service.requireGovernedIdentityManager(actor); err != nil {
		return LocalUserProvisioning{}, err
	}
	validated, err := validateCreateLocalUserCommand(CreateLocalUserCommand{Username: command.Username, DisplayName: command.DisplayName, Email: command.Email})
	if err != nil {
		return LocalUserProvisioning{}, ErrUserInputInvalid
	}
	reasonDigest, reasonCharacters, err := validateMFAReason(command.Reason)
	if err != nil {
		return LocalUserProvisioning{}, err
	}
	repository, ok := service.repository.(emergencyProvisioningRepository)
	if !ok {
		return LocalUserProvisioning{}, ErrIAMConfiguration
	}
	actorID, err := uuid.Parse(actor.GovernedUserID)
	if err != nil || actorID == uuid.Nil {
		return LocalUserProvisioning{}, ErrHighRiskConfirmationRequired
	}
	actorUser, err := service.repository.GetUser(ctx, nil, actorID)
	if err != nil || !service.governedMFAActorCurrent(ctx, nil, actor, actorUser) {
		return LocalUserProvisioning{}, ErrHighRiskConfirmationRequired
	}
	available, err := repository.CanonicalPrincipalAvailable(ctx, validated.Username, validated.Email)
	if err != nil {
		return LocalUserProvisioning{}, err
	}
	if !available {
		return LocalUserProvisioning{}, ErrIAMConflict
	}
	if err := service.consumeHighRisk(ctx, actor, string(ReauthenticationOperationEmergencyUserCreate), proof, request); err != nil {
		return LocalUserProvisioning{}, err
	}
	activationToken, err := generateActivationToken()
	if err != nil {
		return LocalUserProvisioning{}, err
	}
	userID, err := uuid.NewV7()
	if err != nil {
		return LocalUserProvisioning{}, err
	}
	bindingID, err := uuid.NewV7()
	if err != nil {
		return LocalUserProvisioning{}, err
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	expiresAt := now.Add(localActivationLifetime)
	digest := sha256.Sum256([]byte(activationToken))
	user := UserPrincipal{
		ID: userID, Username: validated.Username, DisplayName: validated.DisplayName, Email: validated.Email,
		Kind: UserKindEmergency, Status: UserStatusPending, Version: 1, CreatedAt: now, UpdatedAt: now,
	}
	credential := LocalCredential{UserID: userID, ActivationDigest: hex.EncodeToString(digest[:]), ActivationExpiresAt: expiresAt}
	binding := RoleBinding{
		ID: bindingID, SubjectType: SubjectTypeUser, SubjectID: userID, Role: identity.RoleAdmin,
		ScopeType: ScopeTypePlatform, Effect: BindingEffectAllow, ValidFrom: now, CreatedBy: actor.Subject,
		Version: 1, CreatedAt: now, UpdatedAt: now,
	}
	err = service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		currentActor, err := service.repository.GetUser(ctx, tx, actorID)
		if err != nil || !service.governedMFAActorCurrent(ctx, tx, actor, currentActor) {
			return ErrHighRiskConfirmationRequired
		}
		if err := repository.ProvisionPendingEmergency(ctx, tx, user, credential, binding); err != nil {
			return err
		}
		_, err = service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: actor, Action: "identity.emergency_user.create", ResourceType: "user_principal", ResourceID: userID.String(),
			Outcome: audit.OutcomeSuccess, RequestID: request.RequestID, SourceIP: request.SourceIP,
			Metadata: map[string]any{"reason_digest": reasonDigest, "reason_characters": reasonCharacters, "status": user.Status},
		})
		return err
	})
	if err != nil {
		return LocalUserProvisioning{}, err
	}
	return LocalUserProvisioning{User: user, ActivationToken: activationToken, ActivationExpires: expiresAt}, nil
}

func (service *Service) ReissueEmergencyActivation(ctx context.Context, actor identity.Principal, userID uuid.UUID, command ReissueEmergencyActivationCommand, proof HighRiskProof, request RequestContext) (LocalUserProvisioning, error) {
	if err := service.requireGovernedIdentityManager(actor); err != nil {
		return LocalUserProvisioning{}, err
	}
	reasonDigest, reasonCharacters, err := validateMFAReason(command.Reason)
	if err != nil || userID == uuid.Nil || command.UserVersion < 1 {
		return LocalUserProvisioning{}, ErrUserInputInvalid
	}
	repository, ok := service.repository.(emergencyProvisioningRepository)
	if !ok {
		return LocalUserProvisioning{}, ErrIAMConfiguration
	}
	actorID, err := uuid.Parse(actor.GovernedUserID)
	if err != nil || actorID == uuid.Nil {
		return LocalUserProvisioning{}, ErrHighRiskConfirmationRequired
	}
	actorUser, err := service.repository.GetUser(ctx, nil, actorID)
	if err != nil || !service.governedMFAActorCurrent(ctx, nil, actor, actorUser) {
		return LocalUserProvisioning{}, ErrHighRiskConfirmationRequired
	}
	user, err := service.repository.GetUser(ctx, nil, userID)
	if err != nil {
		return LocalUserProvisioning{}, err
	}
	credential, err := repository.GetLocalCredential(ctx, userID)
	if err != nil {
		return LocalUserProvisioning{}, err
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	if user.Kind != UserKindEmergency || user.Status != UserStatusPending || user.Version != command.UserVersion ||
		credential.ActivationDigest == "" || credential.ActivationExpiresAt.After(now) {
		return LocalUserProvisioning{}, ErrUserInputInvalid
	}
	if err := service.consumeHighRisk(ctx, actor, string(ReauthenticationOperationEmergencyActivationReissue), proof, request); err != nil {
		return LocalUserProvisioning{}, err
	}
	token, err := generateActivationToken()
	if err != nil {
		return LocalUserProvisioning{}, err
	}
	digest := sha256.Sum256([]byte(token))
	expiresAt := now.Add(localActivationLifetime)
	err = service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		lockedUsers, err := service.lockMFAUsers(ctx, tx, actorID, userID)
		if err != nil {
			return err
		}
		actorUser, target := lockedUsers[actorID], lockedUsers[userID]
		if !service.governedMFAActorCurrent(ctx, tx, actor, actorUser) || target.Kind != UserKindEmergency ||
			target.Status != UserStatusPending || target.Version != command.UserVersion {
			return ErrIAMConflict
		}
		lockedCredential, err := repository.GetLocalCredentialForUpdate(ctx, tx, userID)
		if err != nil || lockedCredential.ActivationDigest == "" || lockedCredential.ActivationExpiresAt.After(now) {
			if err != nil {
				return err
			}
			return ErrIAMConflict
		}
		target.Version, target.UpdatedAt = target.Version+1, now
		if err := service.repository.SaveUser(ctx, tx, target, command.UserVersion); err != nil {
			return err
		}
		if err := repository.SaveEmergencyActivation(ctx, tx, userID, hex.EncodeToString(digest[:]), expiresAt); err != nil {
			return err
		}
		_, err = service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: actor, Action: "identity.emergency_user.activation.reissue", ResourceType: "user_principal", ResourceID: userID.String(),
			Outcome: audit.OutcomeSuccess, RequestID: request.RequestID, SourceIP: request.SourceIP,
			Metadata: map[string]any{"reason_digest": reasonDigest, "reason_characters": reasonCharacters, "user_version": target.Version},
		})
		user = target
		return err
	})
	if err != nil {
		return LocalUserProvisioning{}, err
	}
	return LocalUserProvisioning{User: user, ActivationToken: token, ActivationExpires: expiresAt}, nil
}
