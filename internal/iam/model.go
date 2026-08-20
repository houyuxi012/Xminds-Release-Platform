package iam

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

type LoginMode string

const (
	LoginModeLocal       LoginMode = "local"
	LoginModeConfiguring LoginMode = "configuring"
	LoginModeSSO         LoginMode = "sso"
	LoginModeFault       LoginMode = "fault"
)

type IdentitySourceKind string

const (
	IdentitySourceLocal IdentitySourceKind = "local"
	IdentitySourceOIDC  IdentitySourceKind = "oidc"
	IdentitySourceSCIM  IdentitySourceKind = "scim"
)

type IdentitySourceStatus string

const (
	IdentitySourceStatusDraft    IdentitySourceStatus = "draft"
	IdentitySourceStatusVerified IdentitySourceStatus = "verified"
	IdentitySourceStatusEnabled  IdentitySourceStatus = "enabled"
	IdentitySourceStatusFault    IdentitySourceStatus = "fault"
	IdentitySourceStatusDisabled IdentitySourceStatus = "disabled"
)

type UserKind string

const (
	UserKindExternal  UserKind = "external"
	UserKindLocal     UserKind = "local"
	UserKindEmergency UserKind = "emergency"
)

type UserStatus string

const (
	UserStatusPending  UserStatus = "pending"
	UserStatusActive   UserStatus = "active"
	UserStatusDisabled UserStatus = "disabled"
	UserStatusLocked   UserStatus = "locked"
)

var (
	ErrIAMConfiguration             = errors.New("IAM service configuration is invalid")
	ErrIAMConflict                  = errors.New("IAM record changed concurrently")
	ErrSSOPreconditionFailed        = errors.New("SSO enablement preconditions are not satisfied")
	ErrLoginModeTransitionInvalid   = errors.New("login mode transition is invalid")
	ErrLocalLoginDisabled           = errors.New("regular local login is disabled")
	ErrLastEmergencyAdministrator   = errors.New("last usable emergency administrator cannot be disabled")
	ErrHighRiskConfirmationRequired = errors.New("fresh reauthentication and explicit confirmation are required")
	ErrIdentitySourceNotFound       = errors.New("identity source was not found")
	ErrUserNotFound                 = errors.New("user was not found")
	ErrUserAlreadyDisabled          = errors.New("user is already disabled")
	ErrLocalCredentialInvalid       = errors.New("local credential is invalid")
	ErrLocalCredentialLocked        = errors.New("local credential is locked")
	ErrDisableReasonRequired        = errors.New("user disable reason is required")
	ErrIdentityFaultCodeInvalid     = errors.New("identity source fault code is invalid")
)

type LoginState struct {
	Mode           LoginMode
	ActiveSourceID uuid.UUID
	FaultCode      string
	Version        int64
	UpdatedBy      string
	UpdatedAt      time.Time
}

type IdentitySource struct {
	ID                       uuid.UUID
	Name                     string
	Kind                     IdentitySourceKind
	Status                   IdentitySourceStatus
	SecretReference          string
	RequiredMappingsComplete bool
	VerifiedAt               time.Time
	PreviewedAt              time.Time
	FaultCode                string
	Version                  int64
	CreatedAt                time.Time
	UpdatedAt                time.Time
}

type UserPrincipal struct {
	ID                  uuid.UUID
	IdentitySourceID    uuid.UUID
	ExternalSubject     string
	Username            string
	DisplayName         string
	Email               string
	Kind                UserKind
	Status              UserStatus
	MFAEnrolled         bool
	CredentialRotatedAt time.Time
	Version             int64
	CreatedAt           time.Time
	UpdatedAt           time.Time
	DisabledAt          time.Time
	DisabledReason      string
}

type PasswordDigest struct {
	Algorithm  string
	Parameters string
	Salt       []byte
	DerivedKey []byte
}

type LocalCredential struct {
	UserID              uuid.UUID
	Password            PasswordDigest
	FailedAttempts      int
	LockedUntil         time.Time
	PasswordChangedAt   time.Time
	ActivationDigest    string
	ActivationExpiresAt time.Time
}

type HighRiskConfirmation struct {
	Confirmed         bool
	ReauthenticatedAt time.Time
}

type RequestContext struct {
	RequestID string
	SourceIP  string
}
