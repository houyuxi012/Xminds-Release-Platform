package iam

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/identity"
)

type mfaManagementRepository interface {
	GetMFAEnrollment(ctx context.Context, enrollmentID uuid.UUID) (MFAEnrollment, error)
	GetPendingMFAEnrollmentForUpdate(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (MFAEnrollment, error)
	GetMFAEnrollmentForUpdate(ctx context.Context, tx pgx.Tx, enrollmentID uuid.UUID) (MFAEnrollment, error)
	ExpireMFAEnrollment(ctx context.Context, tx pgx.Tx, enrollmentID uuid.UUID, expectedVersion int64, expiredAt time.Time) error
	InsertMFAEnrollment(ctx context.Context, tx pgx.Tx, enrollment MFAEnrollment) error
	ConfirmMFAEnrollment(ctx context.Context, tx pgx.Tx, enrollmentID uuid.UUID, expectedVersion int64, confirmedAt time.Time) error
	GetLocalCredentialForUpdate(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (LocalCredential, error)
	GetLocalCredential(ctx context.Context, userID uuid.UUID) (LocalCredential, error)
	SaveMFACredential(ctx context.Context, tx pgx.Tx, credential LocalCredential) error
	LockMFASecretReference(ctx context.Context, tx pgx.Tx, reference string) error
	MFASecretReferenceHasTombstone(ctx context.Context, tx pgx.Tx, reference string) (bool, error)
	EnqueueMFASecretGC(ctx context.Context, tx pgx.Tx, reference string, notBefore, createdAt time.Time) error
	ReplaceMFARecoveryCodes(ctx context.Context, tx pgx.Tx, userID, generationID uuid.UUID, digests []string, createdAt time.Time) error
}

func (service *Service) BeginMFARotation(ctx context.Context, actor identity.Principal, userID uuid.UUID, command BeginMFARotationCommand, proof HighRiskProof, request RequestContext) (MFAEnrollmentStart, error) {
	if err := service.requireGovernedIdentityManager(actor); err != nil {
		return MFAEnrollmentStart{}, err
	}
	reasonDigest, reasonCharacters, err := validateMFAReason(command.Reason)
	if err != nil || userID == uuid.Nil || command.UserVersion < 1 {
		return MFAEnrollmentStart{}, ErrUserInputInvalid
	}
	actorID, parseErr := uuid.Parse(actor.GovernedUserID)
	if parseErr != nil || actorID == uuid.Nil || service.mfaRepository == nil || service.mfaSecrets == nil || service.mfaVerifier == nil {
		return MFAEnrollmentStart{}, ErrIAMConfiguration
	}
	preflightTarget, err := service.repository.GetUser(ctx, nil, userID)
	if err != nil {
		return MFAEnrollmentStart{}, err
	}
	if preflightTarget.Version != command.UserVersion {
		return MFAEnrollmentStart{}, ErrIAMConflict
	}
	if preflightTarget.Status != UserStatusActive || (preflightTarget.Kind != UserKindLocal && preflightTarget.Kind != UserKindEmergency) {
		return MFAEnrollmentStart{}, ErrUserInputInvalid
	}
	preflightActor, err := service.repository.GetUser(ctx, nil, actorID)
	if err != nil || !service.governedMFAActorCurrent(ctx, nil, actor, preflightActor) {
		return MFAEnrollmentStart{}, ErrHighRiskConfirmationRequired
	}
	bindingVersion, bindingDigest, bindingOK := canonicalReauthenticationActorBinding(actor)
	if !bindingOK {
		return MFAEnrollmentStart{}, ErrHighRiskConfirmationRequired
	}
	if err := service.consumeHighRisk(ctx, actor, string(ReauthenticationOperationMFAEnrollmentBegin), proof, request); err != nil {
		return MFAEnrollmentStart{}, err
	}

	now := service.clock().UTC().Truncate(time.Microsecond)
	enrollmentID, seed, err := generateMFAEnrollmentSecret()
	if err != nil {
		return MFAEnrollmentStart{}, err
	}
	reference, err := service.mfaSecrets.Create(ctx, enrollmentID, seed)
	if err != nil {
		return MFAEnrollmentStart{}, err
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		cleanupContext, cancel := context.WithTimeout(context.Background(), mfaSecretCleanupTimeout)
		defer cancel()
		_ = service.mfaSecrets.Delete(cleanupContext, reference)
	}()

	expiresAt := now.Add(service.mfaEnrollmentTTL)
	enrollment := MFAEnrollment{
		ID: enrollmentID, UserID: userID, Purpose: MFAEnrollmentPurposeRotation, Status: MFAEnrollmentStatusPending,
		SecretReference: reference, CreatedByUserID: actorID, CreatorBindingVersion: int(bindingVersion),
		CreatorBindingDigest: bindingDigest, ExpectedUserVersion: command.UserVersion, ExpiresAt: expiresAt,
		Version: 1, CreatedAt: now, UpdatedAt: now,
	}
	err = service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		lockedUsers, lockErr := service.lockMFAUsers(ctx, tx, actorID, userID)
		if lockErr != nil {
			return lockErr
		}
		actorUser, target := lockedUsers[actorID], lockedUsers[userID]
		if !service.governedMFAActorCurrent(ctx, tx, actor, actorUser) || target.Status != UserStatusActive || target.Version != command.UserVersion ||
			(target.Kind != UserKindLocal && target.Kind != UserKindEmergency) {
			return ErrIAMConflict
		}
		pending, pendingErr := service.mfaRepository.GetPendingMFAEnrollmentForUpdate(ctx, tx, userID)
		if pendingErr == nil {
			if err := service.mfaRepository.ExpireMFAEnrollment(ctx, tx, pending.ID, pending.Version, now); err != nil {
				return err
			}
		} else if !errors.Is(pendingErr, ErrMFAEnrollmentNotFound) {
			return pendingErr
		}
		if err := service.mfaRepository.InsertMFAEnrollment(ctx, tx, enrollment); err != nil {
			return err
		}
		_, err := service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: actor, Action: "identity.mfa_enrollment.begin", ResourceType: "user_principal", ResourceID: userID.String(),
			Outcome: audit.OutcomeSuccess, RequestID: request.RequestID, SourceIP: request.SourceIP,
			Metadata: map[string]any{"purpose": string(MFAEnrollmentPurposeRotation), "reason_digest": reasonDigest, "reason_characters": reasonCharacters},
		})
		return err
	})
	if err != nil {
		return MFAEnrollmentStart{}, err
	}
	committed = true
	return MFAEnrollmentStart{ID: enrollmentID, Secret: seed, OTPAuthURI: mfaOTPAuthURI(service.mfaIssuer, preflightTarget.Username, seed), ExpiresAt: expiresAt}, nil
}

func (service *Service) ConfirmMFARotation(ctx context.Context, actor identity.Principal, userID, enrollmentID uuid.UUID, command ConfirmMFARotationCommand, request RequestContext) (LocalActivationResult, error) {
	if err := service.requireGovernedIdentityManager(actor); err != nil {
		return LocalActivationResult{}, err
	}
	reasonDigest, reasonCharacters, err := validateMFAReason(command.Reason)
	if err != nil || userID == uuid.Nil || enrollmentID == uuid.Nil || command.UserVersion < 1 || strings.TrimSpace(command.MFAProof) == "" {
		return LocalActivationResult{}, ErrUserInputInvalid
	}
	actorID, err := uuid.Parse(actor.GovernedUserID)
	if err != nil || actorID == uuid.Nil || service.mfaRepository == nil || service.mfaVerifier == nil || service.sessions == nil {
		return LocalActivationResult{}, ErrIAMConfiguration
	}
	preflightActor, err := service.repository.GetUser(ctx, nil, actorID)
	if err != nil || !service.governedMFAActorCurrent(ctx, nil, actor, preflightActor) {
		return LocalActivationResult{}, ErrHighRiskConfirmationRequired
	}
	preflightTarget, err := service.repository.GetUser(ctx, nil, userID)
	if err != nil {
		return LocalActivationResult{}, err
	}
	if preflightTarget.Status != UserStatusActive || preflightTarget.Version != command.UserVersion || (preflightTarget.Kind != UserKindLocal && preflightTarget.Kind != UserKindEmergency) {
		return LocalActivationResult{}, ErrIAMConflict
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	preflightEnrollment, err := service.mfaRepository.GetMFAEnrollment(ctx, enrollmentID)
	if err != nil || !validRotationEnrollmentForActor(preflightEnrollment, userID, command.UserVersion, actor) || !preflightEnrollment.ExpiresAt.After(now) {
		return LocalActivationResult{}, ErrMFAEnrollmentNotFound
	}
	preflightCredential, err := service.mfaRepository.GetLocalCredential(ctx, userID)
	if err != nil {
		return LocalActivationResult{}, err
	}
	assertion, err := service.mfaVerifier.Verify(ctx, preflightEnrollment.SecretReference, command.MFAProof)
	if err != nil || assertion.Counter <= preflightCredential.MFALastCounter {
		return LocalActivationResult{}, ErrMFAProofInvalid
	}
	recoveryCodes, recoveryDigests, recoveryGeneration, err := generateMFARecoveryCodeSet(10)
	if err != nil {
		return LocalActivationResult{}, err
	}
	legacyReferenceRetained := false
	err = service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		lockedUsers, err := service.lockMFAUsers(ctx, tx, actorID, userID)
		if err != nil {
			return err
		}
		actorUser, target := lockedUsers[actorID], lockedUsers[userID]
		if !service.governedMFAActorCurrent(ctx, tx, actor, actorUser) || target.Status != UserStatusActive ||
			target.Version != command.UserVersion || (target.Kind != UserKindLocal && target.Kind != UserKindEmergency) {
			return ErrIAMConflict
		}
		credential, err := service.mfaRepository.GetLocalCredentialForUpdate(ctx, tx, userID)
		if err != nil {
			return err
		}
		enrollment, err := service.mfaRepository.GetMFAEnrollmentForUpdate(ctx, tx, enrollmentID)
		if err != nil || !validRotationEnrollmentForActor(enrollment, userID, command.UserVersion, actor) ||
			enrollment.Version != preflightEnrollment.Version || enrollment.SecretReference != preflightEnrollment.SecretReference ||
			credential.MFASecretReference != preflightCredential.MFASecretReference || credential.MFALastCounter != preflightCredential.MFALastCounter ||
			assertion.Counter <= credential.MFALastCounter || !enrollment.ExpiresAt.After(now) {
			return ErrIAMConflict
		}
		if err := service.mfaRepository.LockMFASecretReference(ctx, tx, enrollment.SecretReference); err != nil {
			return err
		}
		tombstone, err := service.mfaRepository.MFASecretReferenceHasTombstone(ctx, tx, enrollment.SecretReference)
		if err != nil || tombstone {
			if err != nil {
				return err
			}
			return ErrIAMConflict
		}
		oldReference := credential.MFASecretReference
		credential.MFASecretReference, credential.MFALastCounter = enrollment.SecretReference, assertion.Counter
		if err := service.mfaRepository.SaveMFACredential(ctx, tx, credential); err != nil {
			return err
		}
		target.MFAEnrolled, target.Version, target.UpdatedAt = true, target.Version+1, now
		if err := service.repository.SaveUser(ctx, tx, target, command.UserVersion); err != nil {
			return err
		}
		if err := service.mfaRepository.ConfirmMFAEnrollment(ctx, tx, enrollment.ID, enrollment.Version, now); err != nil {
			return err
		}
		if err := service.mfaRepository.ReplaceMFARecoveryCodes(ctx, tx, userID, recoveryGeneration, recoveryDigests, now); err != nil {
			return err
		}
		if oldReference != "" && oldReference != enrollment.SecretReference && strings.HasPrefix(oldReference, mfaSecretReferencePrefix) {
			if err := service.mfaRepository.EnqueueMFASecretGC(ctx, tx, oldReference, now, now); err != nil {
				return err
			}
		} else if strings.HasPrefix(oldReference, "secret://iam/") {
			legacyReferenceRetained = true
		}
		if err := service.sessions.RevokeSubject(ctx, tx, userID, "mfa_rotation"); err != nil {
			return err
		}
		_, err = service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: actor, Action: "identity.mfa_enrollment.confirm", ResourceType: "user_principal", ResourceID: userID.String(),
			Outcome: audit.OutcomeSuccess, RequestID: request.RequestID, SourceIP: request.SourceIP,
			Metadata: map[string]any{"reason_digest": reasonDigest, "reason_characters": reasonCharacters, "user_version": target.Version, "legacy_reference_retained": legacyReferenceRetained},
		})
		return err
	})
	if err != nil {
		return LocalActivationResult{}, err
	}
	return LocalActivationResult{RecoveryCodes: recoveryCodes}, nil
}

func (service *Service) RegenerateMFARecoveryCodes(ctx context.Context, actor identity.Principal, userID uuid.UUID, command RegenerateMFARecoveryCodesCommand, proof HighRiskProof, request RequestContext) (LocalActivationResult, error) {
	if err := service.requireGovernedIdentityManager(actor); err != nil {
		return LocalActivationResult{}, err
	}
	reasonDigest, reasonCharacters, err := validateMFAReason(command.Reason)
	if err != nil || userID == uuid.Nil || command.UserVersion < 1 || service.mfaRepository == nil || service.sessions == nil {
		return LocalActivationResult{}, ErrUserInputInvalid
	}
	actorID, err := uuid.Parse(actor.GovernedUserID)
	if err != nil || actorID == uuid.Nil {
		return LocalActivationResult{}, ErrHighRiskConfirmationRequired
	}
	preflightActor, err := service.repository.GetUser(ctx, nil, actorID)
	if err != nil || !service.governedMFAActorCurrent(ctx, nil, actor, preflightActor) {
		return LocalActivationResult{}, ErrHighRiskConfirmationRequired
	}
	preflightTarget, err := service.repository.GetUser(ctx, nil, userID)
	if err != nil {
		return LocalActivationResult{}, err
	}
	if preflightTarget.Version != command.UserVersion {
		return LocalActivationResult{}, ErrIAMConflict
	}
	if preflightTarget.Status != UserStatusActive || !preflightTarget.MFAEnrolled || (preflightTarget.Kind != UserKindLocal && preflightTarget.Kind != UserKindEmergency) {
		return LocalActivationResult{}, ErrUserInputInvalid
	}
	if err := service.consumeHighRisk(ctx, actor, string(ReauthenticationOperationMFARecoveryCodesRegenerate), proof, request); err != nil {
		return LocalActivationResult{}, err
	}
	recoveryCodes, recoveryDigests, generationID, err := generateMFARecoveryCodeSet(10)
	if err != nil {
		return LocalActivationResult{}, err
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	err = service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		lockedUsers, err := service.lockMFAUsers(ctx, tx, actorID, userID)
		if err != nil {
			return err
		}
		actorUser, target := lockedUsers[actorID], lockedUsers[userID]
		if !service.governedMFAActorCurrent(ctx, tx, actor, actorUser) || target.Status != UserStatusActive ||
			!target.MFAEnrolled || target.Version != command.UserVersion {
			return ErrIAMConflict
		}
		target.Version, target.UpdatedAt = target.Version+1, now
		if err := service.repository.SaveUser(ctx, tx, target, command.UserVersion); err != nil {
			return err
		}
		if err := service.mfaRepository.ReplaceMFARecoveryCodes(ctx, tx, userID, generationID, recoveryDigests, now); err != nil {
			return err
		}
		if err := service.sessions.RevokeSubject(ctx, tx, userID, "mfa_recovery_codes_regenerated"); err != nil {
			return err
		}
		_, err = service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: actor, Action: "identity.mfa_recovery_codes.regenerate", ResourceType: "user_principal", ResourceID: userID.String(),
			Outcome: audit.OutcomeSuccess, RequestID: request.RequestID, SourceIP: request.SourceIP,
			Metadata: map[string]any{"reason_digest": reasonDigest, "reason_characters": reasonCharacters, "user_version": target.Version},
		})
		return err
	})
	if err != nil {
		return LocalActivationResult{}, err
	}
	return LocalActivationResult{RecoveryCodes: recoveryCodes}, nil
}

func validRotationEnrollmentForActor(enrollment MFAEnrollment, userID uuid.UUID, userVersion int64, actor identity.Principal) bool {
	bindingVersion, bindingDigest, ok := canonicalReauthenticationActorBinding(actor)
	return ok && enrollment.ID != uuid.Nil && enrollment.UserID == userID && enrollment.Purpose == MFAEnrollmentPurposeRotation &&
		enrollment.Status == MFAEnrollmentStatusPending && enrollment.ExpectedUserVersion == userVersion &&
		enrollment.CreatedByUserID.String() == actor.GovernedUserID && enrollment.CreatorBindingVersion == int(bindingVersion) &&
		subtle.ConstantTimeCompare(enrollment.CreatorBindingDigest[:], bindingDigest[:]) == 1
}

func (service *Service) governedMFAActorCurrent(ctx context.Context, tx pgx.Tx, actor identity.Principal, user UserPrincipal) bool {
	if user.ID.String() != actor.GovernedUserID || user.Status != UserStatusActive {
		return false
	}
	switch actor.Kind {
	case identity.PrincipalKindHuman:
		sourceID, err := uuid.Parse(actor.IdentitySourceID)
		if err != nil || user.Kind != UserKindExternal || user.IdentitySourceID != sourceID {
			return false
		}
		source, err := service.repository.GetIdentitySource(ctx, tx, sourceID)
		return err == nil && source.Status == IdentitySourceStatusEnabled
	case identity.PrincipalKindLocal:
		return (user.Kind == UserKindLocal || user.Kind == UserKindEmergency) && user.IdentitySourceID == uuid.Nil && actor.IdentitySourceID == ""
	default:
		return false
	}
}

func (service *Service) lockMFAUsers(ctx context.Context, tx pgx.Tx, userIDs ...uuid.UUID) (map[uuid.UUID]UserPrincipal, error) {
	unique := make(map[uuid.UUID]struct{}, len(userIDs))
	for _, userID := range userIDs {
		unique[userID] = struct{}{}
	}
	ordered := make([]uuid.UUID, 0, len(unique))
	for userID := range unique {
		ordered = append(ordered, userID)
	}
	sort.Slice(ordered, func(left, right int) bool { return ordered[left].String() < ordered[right].String() })
	users := make(map[uuid.UUID]UserPrincipal, len(ordered))
	for _, userID := range ordered {
		user, err := service.repository.GetUser(ctx, tx, userID)
		if err != nil {
			return nil, err
		}
		users[userID] = user
	}
	return users, nil
}

func generateMFAEnrollmentSecret() (uuid.UUID, string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, "", ErrIAMConfiguration
	}
	seedBytes := make([]byte, 20)
	if _, err := rand.Read(seedBytes); err != nil {
		return uuid.Nil, "", ErrIAMConfiguration
	}
	return id, base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seedBytes), nil
}

func validateMFAReason(reason string) (string, int, error) {
	characters := len([]rune(reason))
	if reason != strings.TrimSpace(reason) || characters < 8 || characters > 512 {
		return "", 0, ErrUserInputInvalid
	}
	digest := sha256.Sum256([]byte(reason))
	return hex.EncodeToString(digest[:]), characters, nil
}
