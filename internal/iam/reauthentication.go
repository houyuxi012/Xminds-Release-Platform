package iam

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/identity"
)

const reauthenticationEvidencePrefix = "xmr_"

type ReauthenticationOperation string

const (
	ReauthenticationOperationRoleBindingCreate  ReauthenticationOperation = "identity.role_binding.create"
	ReauthenticationOperationRoleBindingDelete  ReauthenticationOperation = "identity.role_binding.delete"
	ReauthenticationOperationUserDisable        ReauthenticationOperation = "identity.user.disable"
	ReauthenticationOperationUserEnable         ReauthenticationOperation = "identity.user.enable"
	ReauthenticationOperationUserRevokeSessions ReauthenticationOperation = "identity.user.revoke_sessions"
	ReauthenticationOperationSSOEnable          ReauthenticationOperation = "identity.sso.enable"
	ReauthenticationOperationSSODisable         ReauthenticationOperation = "identity.sso.disable"
)

type ReauthenticationStatus string

const (
	ReauthenticationStatusPending  ReauthenticationStatus = "pending"
	ReauthenticationStatusVerified ReauthenticationStatus = "verified"
	ReauthenticationStatusConsumed ReauthenticationStatus = "consumed"
	ReauthenticationStatusExpired  ReauthenticationStatus = "expired"
)

type ReauthenticationChallenge struct {
	ID                  uuid.UUID
	ActorSubject        string
	ActorKind           identity.PrincipalKind
	CreatedTokenDigest  string
	Operation           ReauthenticationOperation
	Status              ReauthenticationStatus
	VerifiedTokenDigest string
	EvidenceDigest      string
	CreatedAt           time.Time
	VerifiedAt          time.Time
	ChallengeExpiresAt  time.Time
	EvidenceExpiresAt   time.Time
	ConsumedAt          time.Time
	CreatedRequestID    string
	CompletedRequestID  string
	Version             int64
}

// ExpiresAt returns the active deadline without exposing stored verifier bindings.
func (challenge ReauthenticationChallenge) ExpiresAt() time.Time {
	if challenge.Status == ReauthenticationStatusVerified && !challenge.EvidenceExpiresAt.IsZero() {
		return challenge.EvidenceExpiresAt
	}
	return challenge.ChallengeExpiresAt
}

type ReauthenticationChallengeResult struct {
	ID        uuid.UUID
	Operation ReauthenticationOperation
	Status    ReauthenticationStatus
	ExpiresAt time.Time
}

type ReauthenticationEvidence struct {
	ChallengeID uuid.UUID
	Evidence    string
	ExpiresAt   time.Time
}

type CompleteReauthenticationCommand struct {
	Password string
	MFAProof string
}

type ReauthenticationPolicy struct {
	ChallengeTTL      time.Duration
	EvidenceTTL       time.Duration
	OIDCMaximumAge    time.Duration
	AllowedClockSkew  time.Duration
	TerminalRetention time.Duration
	CleanupBatchSize  int
}

func DefaultReauthenticationPolicy() ReauthenticationPolicy {
	return ReauthenticationPolicy{
		ChallengeTTL: 5 * time.Minute, EvidenceTTL: 2 * time.Minute, OIDCMaximumAge: 5 * time.Minute,
		AllowedClockSkew: 30 * time.Second, TerminalRetention: 24 * time.Hour, CleanupBatchSize: 128,
	}
}

func validReauthenticationPolicy(policy ReauthenticationPolicy) bool {
	return policy.ChallengeTTL >= time.Minute && policy.ChallengeTTL <= 10*time.Minute &&
		policy.EvidenceTTL >= 30*time.Second && policy.EvidenceTTL <= 5*time.Minute && policy.EvidenceTTL <= policy.ChallengeTTL &&
		policy.OIDCMaximumAge >= time.Minute && policy.OIDCMaximumAge <= 10*time.Minute &&
		policy.AllowedClockSkew >= 0 && policy.AllowedClockSkew <= 2*time.Minute &&
		policy.TerminalRetention >= time.Hour && policy.TerminalRetention <= 7*24*time.Hour &&
		policy.CleanupBatchSize >= 1 && policy.CleanupBatchSize <= 1000
}

type ReauthenticationRepository interface {
	WithinTransaction(ctx context.Context, function func(pgx.Tx) error) error
	CleanupReauthenticationChallenges(ctx context.Context, tx pgx.Tx, now time.Time, retention time.Duration, limit int) error
	InsertReauthenticationChallenge(ctx context.Context, tx pgx.Tx, challenge ReauthenticationChallenge) error
	GetReauthenticationChallenge(ctx context.Context, tx pgx.Tx, id uuid.UUID) (ReauthenticationChallenge, error)
	SaveReauthenticationChallenge(ctx context.Context, tx pgx.Tx, challenge ReauthenticationChallenge, expectedVersion int64) error
}

type LocalReauthenticator interface {
	Reauthenticate(ctx context.Context, actor identity.Principal, command CompleteReauthenticationCommand, request RequestContext) error
}

type ReauthenticationConfig struct {
	Repository ReauthenticationRepository
	Auditor    AuditAppender
	Local      LocalReauthenticator
	Clock      func() time.Time
	Policy     ReauthenticationPolicy
}

type ReauthenticationService struct {
	repository ReauthenticationRepository
	auditor    AuditAppender
	local      LocalReauthenticator
	authorizer *identity.Authorizer
	clock      func() time.Time
	policy     ReauthenticationPolicy
}

func NewReauthenticationService(config ReauthenticationConfig) (*ReauthenticationService, error) {
	if config.Repository == nil || config.Auditor == nil || config.Local == nil || config.Clock == nil || !validReauthenticationPolicy(config.Policy) {
		return nil, ErrIAMConfiguration
	}
	return &ReauthenticationService{
		repository: config.Repository, auditor: config.Auditor, local: config.Local,
		authorizer: identity.NewAuthorizer(), clock: config.Clock, policy: config.Policy,
	}, nil
}

func (service *ReauthenticationService) CreateChallenge(ctx context.Context, actor identity.Principal, operation ReauthenticationOperation, request RequestContext) (ReauthenticationChallengeResult, error) {
	if !service.allowedActor(actor) || !validReauthenticationOperation(operation) {
		return ReauthenticationChallengeResult{}, ErrHighRiskConfirmationRequired
	}
	if err := service.authorizer.Require(actor, identity.ActionIdentityManage, ""); err != nil {
		return ReauthenticationChallengeResult{}, err
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	id, err := uuid.NewV7()
	if err != nil {
		return ReauthenticationChallengeResult{}, fmt.Errorf("generate reauthentication challenge ID: %w", err)
	}
	challenge := ReauthenticationChallenge{
		ID: id, ActorSubject: strings.TrimSpace(actor.Subject), ActorKind: actor.Kind,
		CreatedTokenDigest: reauthenticationDigest(actor.TokenID), Operation: operation, Status: ReauthenticationStatusPending,
		CreatedAt: now, ChallengeExpiresAt: now.Add(service.policy.ChallengeTTL), CreatedRequestID: request.RequestID, Version: 1,
	}
	err = service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if cleanupErr := service.repository.CleanupReauthenticationChallenges(ctx, tx, now, service.policy.TerminalRetention, service.policy.CleanupBatchSize); cleanupErr != nil {
			return cleanupErr
		}
		if insertErr := service.repository.InsertReauthenticationChallenge(ctx, tx, challenge); insertErr != nil {
			return insertErr
		}
		return service.appendAudit(ctx, tx, actor, "identity.reauthentication.challenge.create", challenge, audit.OutcomeSuccess, request)
	})
	if err != nil {
		return ReauthenticationChallengeResult{}, err
	}
	return ReauthenticationChallengeResult{ID: id, Operation: operation, Status: challenge.Status, ExpiresAt: challenge.ChallengeExpiresAt}, nil
}

func (service *ReauthenticationService) CompleteChallenge(ctx context.Context, actor identity.Principal, challengeID uuid.UUID, command CompleteReauthenticationCommand, request RequestContext) (ReauthenticationEvidence, error) {
	if !service.allowedActor(actor) || challengeID == uuid.Nil || challengeID.Version() != 7 {
		return ReauthenticationEvidence{}, ErrHighRiskConfirmationRequired
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	preflight, err := service.repository.GetReauthenticationChallenge(ctx, nil, challengeID)
	if err != nil || !service.canComplete(preflight, actor, now) {
		return ReauthenticationEvidence{}, ErrHighRiskConfirmationRequired
	}
	switch actor.Kind {
	case identity.PrincipalKindHuman:
		if actor.AuthenticatedAt.IsZero() || actor.AuthenticationAssurance < 1 || actor.AuthenticatedAt.After(now.Add(service.policy.AllowedClockSkew)) || now.Sub(actor.AuthenticatedAt) > service.policy.OIDCMaximumAge {
			return ReauthenticationEvidence{}, ErrHighRiskConfirmationRequired
		}
	case identity.PrincipalKindLocal:
		if preflight.CreatedTokenDigest != reauthenticationDigest(actor.TokenID) {
			return ReauthenticationEvidence{}, ErrHighRiskConfirmationRequired
		}
		if err := service.local.Reauthenticate(ctx, actor, command, request); err != nil {
			return ReauthenticationEvidence{}, err
		}
	default:
		return ReauthenticationEvidence{}, ErrHighRiskConfirmationRequired
	}
	evidence, err := generateReauthenticationEvidence()
	if err != nil {
		return ReauthenticationEvidence{}, err
	}
	var expiresAt time.Time
	err = service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		challenge, getErr := service.repository.GetReauthenticationChallenge(ctx, tx, challengeID)
		if getErr != nil || !service.canComplete(challenge, actor, now) {
			return ErrHighRiskConfirmationRequired
		}
		previousVersion := challenge.Version
		challenge.Status = ReauthenticationStatusVerified
		challenge.VerifiedTokenDigest = reauthenticationDigest(actor.TokenID)
		challenge.EvidenceDigest = reauthenticationDigest(evidence)
		challenge.VerifiedAt = now
		challenge.EvidenceExpiresAt = now.Add(service.policy.EvidenceTTL)
		if challenge.EvidenceExpiresAt.After(challenge.ChallengeExpiresAt) {
			challenge.EvidenceExpiresAt = challenge.ChallengeExpiresAt
		}
		challenge.CompletedRequestID = request.RequestID
		challenge.Version++
		if saveErr := service.repository.SaveReauthenticationChallenge(ctx, tx, challenge, previousVersion); saveErr != nil {
			return saveErr
		}
		if appendErr := service.appendAudit(ctx, tx, actor, "identity.reauthentication.challenge.complete", challenge, audit.OutcomeSuccess, request); appendErr != nil {
			return appendErr
		}
		expiresAt = challenge.EvidenceExpiresAt
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrHighRiskConfirmationRequired) || errors.Is(err, ErrIAMConflict) {
			return ReauthenticationEvidence{}, ErrHighRiskConfirmationRequired
		}
		return ReauthenticationEvidence{}, err
	}
	return ReauthenticationEvidence{ChallengeID: challengeID, Evidence: evidence, ExpiresAt: expiresAt}, nil
}

func (service *ReauthenticationService) Authorize(ctx context.Context, actor identity.Principal, operation string, proof HighRiskProof, request RequestContext) error {
	parsedOperation := ReauthenticationOperation(strings.TrimSpace(operation))
	challengeID, evidenceOK := parseReauthenticationProof(proof)
	if !proof.Confirmed || !service.allowedActor(actor) || !validReauthenticationOperation(parsedOperation) || !evidenceOK {
		return ErrHighRiskConfirmationRequired
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	err := service.repository.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if cleanupErr := service.repository.CleanupReauthenticationChallenges(ctx, tx, now, service.policy.TerminalRetention, service.policy.CleanupBatchSize); cleanupErr != nil {
			return cleanupErr
		}
		challenge, getErr := service.repository.GetReauthenticationChallenge(ctx, tx, challengeID)
		if getErr != nil || challenge.Status != ReauthenticationStatusVerified || challenge.Operation != parsedOperation ||
			challenge.ActorSubject != strings.TrimSpace(actor.Subject) || challenge.ActorKind != actor.Kind ||
			!challenge.EvidenceExpiresAt.After(now) || challenge.VerifiedTokenDigest != reauthenticationDigest(actor.TokenID) ||
			subtle.ConstantTimeCompare([]byte(challenge.EvidenceDigest), []byte(reauthenticationDigest(proof.Evidence))) != 1 {
			return ErrHighRiskConfirmationRequired
		}
		previousVersion := challenge.Version
		challenge.Status, challenge.ConsumedAt, challenge.Version = ReauthenticationStatusConsumed, now, challenge.Version+1
		if saveErr := service.repository.SaveReauthenticationChallenge(ctx, tx, challenge, previousVersion); saveErr != nil {
			return saveErr
		}
		return service.appendAudit(ctx, tx, actor, "identity.reauthentication.challenge.consume", challenge, audit.OutcomeSuccess, request)
	})
	if err != nil {
		return ErrHighRiskConfirmationRequired
	}
	return nil
}

func (service *ReauthenticationService) allowedActor(actor identity.Principal) bool {
	if service == nil || service.repository == nil || service.authorizer == nil || strings.TrimSpace(actor.Subject) == "" || strings.TrimSpace(actor.TokenID) == "" {
		return false
	}
	return actor.Kind == identity.PrincipalKindHuman || actor.Kind == identity.PrincipalKindLocal
}

func (service *ReauthenticationService) canComplete(challenge ReauthenticationChallenge, actor identity.Principal, now time.Time) bool {
	return challenge.ID != uuid.Nil && challenge.Status == ReauthenticationStatusPending && challenge.ChallengeExpiresAt.After(now) &&
		challenge.ActorSubject == strings.TrimSpace(actor.Subject) && challenge.ActorKind == actor.Kind
}

func (service *ReauthenticationService) appendAudit(ctx context.Context, tx pgx.Tx, actor identity.Principal, action string, challenge ReauthenticationChallenge, outcome audit.Outcome, request RequestContext) error {
	auditActor := actor
	auditActor.TokenID = ""
	auditActor.AuthenticatedAt = time.Time{}
	auditActor.AuthenticationAssurance = 0
	_, err := service.auditor.Append(ctx, tx, audit.AppendCommand{
		Actor: auditActor, Action: action, ResourceType: "reauthentication_challenge", ResourceID: reauthenticationDigest(challenge.ID.String()),
		Outcome: outcome, RequestID: request.RequestID, SourceIP: request.SourceIP,
		Metadata: map[string]any{"operation": challenge.Operation, "status": challenge.Status},
	})
	return err
}

func validReauthenticationOperation(operation ReauthenticationOperation) bool {
	switch operation {
	case ReauthenticationOperationRoleBindingCreate, ReauthenticationOperationRoleBindingDelete,
		ReauthenticationOperationUserDisable, ReauthenticationOperationUserEnable, ReauthenticationOperationUserRevokeSessions,
		ReauthenticationOperationSSOEnable, ReauthenticationOperationSSODisable:
		return true
	default:
		return false
	}
}

func generateReauthenticationEvidence() (string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generate reauthentication evidence: %w", err)
	}
	return reauthenticationEvidencePrefix + base64.RawURLEncoding.EncodeToString(secret), nil
}

func parseReauthenticationProof(proof HighRiskProof) (uuid.UUID, bool) {
	id, err := uuid.Parse(strings.TrimSpace(proof.ChallengeID))
	if err != nil || id.Version() != 7 {
		return uuid.Nil, false
	}
	secret, found := strings.CutPrefix(strings.TrimSpace(proof.Evidence), reauthenticationEvidencePrefix)
	if !found {
		return uuid.Nil, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(secret)
	return id, err == nil && len(decoded) == 32 && len(proof.Evidence) <= 128
}

func reauthenticationDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
