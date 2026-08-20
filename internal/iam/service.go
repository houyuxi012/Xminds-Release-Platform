package iam

import (
	"context"
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

var identityFaultCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)

type ServiceConfig struct {
	Repository Repository
	Auditor    AuditAppender
	Sessions   SessionRevoker
	Passwords  PasswordVerifier
	Clock      func() time.Time
}

type Service struct {
	repository Repository
	auditor    AuditAppender
	sessions   SessionRevoker
	passwords  PasswordVerifier
	authorizer *identity.Authorizer
	clock      func() time.Time
}

func NewService(config ServiceConfig) (*Service, error) {
	if config.Repository == nil || config.Auditor == nil || config.Sessions == nil || config.Passwords == nil || config.Clock == nil {
		return nil, ErrIAMConfiguration
	}
	return &Service{
		repository: config.Repository, auditor: config.Auditor, sessions: config.Sessions,
		passwords: config.Passwords, authorizer: identity.NewAuthorizer(), clock: config.Clock,
	}, nil
}

func (service *Service) EnableSSO(ctx context.Context, actor identity.Principal, sourceID uuid.UUID, confirmation HighRiskConfirmation, request RequestContext) error {
	if err := service.requireHighRisk(actor, confirmation); err != nil {
		return err
	}
	if sourceID == uuid.Nil {
		return ErrSSOPreconditionFailed
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	return service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
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
		emergencyCount, err := service.repository.CountUsableEmergencyAdministrators(ctx, tx, uuid.Nil, now)
		if err != nil {
			return err
		}
		if source.Status != IdentitySourceStatusVerified || source.VerifiedAt.IsZero() || source.PreviewedAt.IsZero() ||
			!source.RequiredMappingsComplete || emergencyCount < 1 {
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
		_, err = service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: actor, Action: "identity.sso.enable", ResourceType: "identity_source", ResourceID: source.ID.String(),
			Outcome: audit.OutcomeSuccess, RequestID: request.RequestID, SourceIP: request.SourceIP,
			Metadata: map[string]any{"before_mode": previousMode, "after_mode": state.Mode, "source_kind": source.Kind},
		})
		return err
	})
}

func (service *Service) MarkIdentitySourceFault(ctx context.Context, actor identity.Principal, sourceID uuid.UUID, code string, request RequestContext) error {
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
		_, err = service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: actor, Action: "identity.sso.fault", ResourceType: "identity_source", ResourceID: source.ID.String(),
			Outcome: audit.OutcomeFailed, RequestID: request.RequestID, SourceIP: request.SourceIP,
			Metadata: map[string]any{"error_code": code, "login_mode": state.Mode},
		})
		return err
	})
}

func (service *Service) DisableSSO(ctx context.Context, actor identity.Principal, confirmation HighRiskConfirmation, request RequestContext) error {
	if err := service.requireHighRisk(actor, confirmation); err != nil {
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

func (service *Service) DisableUser(ctx context.Context, actor identity.Principal, userID uuid.UUID, reason string, confirmation HighRiskConfirmation, request RequestContext) error {
	if err := service.requireHighRisk(actor, confirmation); err != nil {
		return err
	}
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > 512 {
		return ErrDisableReasonRequired
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	err := service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		user, err := service.repository.GetUser(ctx, tx, userID)
		if err != nil {
			return err
		}
		if user.Status == UserStatusDisabled {
			return ErrUserAlreadyDisabled
		}
		if user.Kind == UserKindEmergency {
			remaining, err := service.repository.CountUsableEmergencyAdministrators(ctx, tx, user.ID, now)
			if err != nil {
				return err
			}
			if remaining == 0 {
				return ErrLastEmergencyAdministrator
			}
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
	if err := service.sessions.RevokeSubject(ctx, userID, reason); err != nil {
		return fmt.Errorf("revoke disabled user sessions: %w", err)
	}
	return nil
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

func (service *Service) requireHighRisk(actor identity.Principal, confirmation HighRiskConfirmation) error {
	if service == nil || service.authorizer == nil || service.clock == nil {
		return ErrIAMConfiguration
	}
	if err := service.authorizer.Require(actor, identity.ActionIdentityManage, ""); err != nil {
		return err
	}
	now := service.clock().UTC()
	reauthenticatedAt := confirmation.ReauthenticatedAt.UTC()
	if !confirmation.Confirmed || reauthenticatedAt.IsZero() || reauthenticatedAt.After(now) || now.Sub(reauthenticatedAt) > maximumReauthenticationAge {
		return ErrHighRiskConfirmationRequired
	}
	return nil
}

func canonicalUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}
