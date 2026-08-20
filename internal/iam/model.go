package iam

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"xminds-release-platform/internal/identity"
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

type SubjectType string

const (
	SubjectTypeUser         SubjectType = "user"
	SubjectTypeOrganization SubjectType = "organization"
)

type ScopeType string

const (
	ScopeTypePlatform ScopeType = "platform"
	ScopeTypeProduct  ScopeType = "product"
	ScopeTypeChannel  ScopeType = "channel"
)

type BindingEffect string

const (
	BindingEffectAllow BindingEffect = "allow"
	BindingEffectDeny  BindingEffect = "deny"
)

type OrganizationStatus string

const (
	OrganizationStatusActive   OrganizationStatus = "active"
	OrganizationStatusDisabled OrganizationStatus = "disabled"
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
	ErrUserAlreadyEnabled           = errors.New("user is already enabled")
	ErrUserCannotBeEnabled          = errors.New("user authentication source is not usable")
	ErrLocalCredentialInvalid       = errors.New("local credential is invalid")
	ErrLocalCredentialLocked        = errors.New("local credential is locked")
	ErrDisableReasonRequired        = errors.New("user disable reason is required")
	ErrEnableReasonRequired         = errors.New("user enable reason is required")
	ErrRevokeReasonRequired         = errors.New("session revocation reason is required")
	ErrIdentityFaultCodeInvalid     = errors.New("identity source fault code is invalid")
	ErrUserInputInvalid             = errors.New("user input is invalid")
	ErrPageInvalid                  = errors.New("IAM page parameters are invalid")
	ErrOrganizationNotFound         = errors.New("organization was not found")
	ErrRoleBindingNotFound          = errors.New("role binding was not found")
	ErrRoleBindingInvalid           = errors.New("role binding input is invalid")
	ErrIdentitySourceInputInvalid   = errors.New("identity source input is invalid")
	ErrDirectoryAdapterUnavailable  = errors.New("directory adapter is unavailable")
	ErrLocalAuthenticationFailed    = errors.New("local authentication failed")
	ErrLocalAuthenticationLimited   = errors.New("local authentication rate limit exceeded")
	ErrPasswordRecentlyUsed         = errors.New("password was recently used")
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
	ID                       uuid.UUID            `json:"id"`
	Name                     string               `json:"name"`
	Kind                     IdentitySourceKind   `json:"kind"`
	Status                   IdentitySourceStatus `json:"status"`
	SecretReference          string               `json:"-"`
	RequiredMappingsComplete bool                 `json:"required_mappings_complete"`
	VerifiedAt               time.Time            `json:"verified_at,omitempty"`
	PreviewedAt              time.Time            `json:"previewed_at,omitempty"`
	FaultCode                string               `json:"fault_code,omitempty"`
	Version                  int64                `json:"version"`
	CreatedAt                time.Time            `json:"created_at"`
	UpdatedAt                time.Time            `json:"updated_at"`
}

type UserPrincipal struct {
	ID                  uuid.UUID  `json:"id"`
	IdentitySourceID    uuid.UUID  `json:"identity_source_id,omitempty"`
	ExternalSubject     string     `json:"external_subject,omitempty"`
	Username            string     `json:"username"`
	DisplayName         string     `json:"display_name"`
	Email               string     `json:"email,omitempty"`
	Kind                UserKind   `json:"kind"`
	Status              UserStatus `json:"status"`
	MFAEnrolled         bool       `json:"mfa_enrolled"`
	CredentialRotatedAt time.Time  `json:"credential_rotated_at,omitempty"`
	Version             int64      `json:"version"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	DisabledAt          time.Time  `json:"disabled_at,omitempty"`
	DisabledReason      string     `json:"disabled_reason,omitempty"`
}

type OrganizationUnit struct {
	ID               uuid.UUID          `json:"id"`
	IdentitySourceID uuid.UUID          `json:"identity_source_id,omitempty"`
	ExternalID       string             `json:"external_id,omitempty"`
	ParentID         uuid.UUID          `json:"parent_id,omitempty"`
	Name             string             `json:"name"`
	SourceOwned      bool               `json:"source_owned"`
	Status           OrganizationStatus `json:"status"`
	Version          int64              `json:"version"`
	CreatedAt        time.Time          `json:"created_at"`
	UpdatedAt        time.Time          `json:"updated_at"`
}

type RoleBinding struct {
	ID          uuid.UUID     `json:"id"`
	SubjectType SubjectType   `json:"subject_type"`
	SubjectID   uuid.UUID     `json:"subject_id"`
	Role        identity.Role `json:"role"`
	ScopeType   ScopeType     `json:"scope_type"`
	ProductID   string        `json:"product_id,omitempty"`
	ChannelName string        `json:"channel_name,omitempty"`
	Effect      BindingEffect `json:"effect"`
	ValidFrom   time.Time     `json:"valid_from"`
	ValidUntil  time.Time     `json:"valid_until,omitempty"`
	CreatedBy   string        `json:"created_by"`
	Version     int64         `json:"version"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
}

type CatalogScope struct {
	Type        ScopeType
	ProductID   string
	ChannelName string
}

// BreakGlassInvariantEvaluation separates immediate authentication health
// from scheduled permission continuity. Credential freshness and lock state
// apply only to CurrentUsableAdministrators; future permission boundaries use
// structurally recoverable emergency identities.
type BreakGlassInvariantEvaluation struct {
	CurrentUsableAdministrators int
	FirstScheduledPermissionGap time.Time
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
	MFASecretReference  string
	MFALastCounter      int64
}

type ActivateLocalAccountCommand struct {
	ActivationToken    string
	NewPassword        string
	MFASecretReference string
	MFAProof           string
}

type LocalLoginCommand struct {
	Username string
	Password string
	MFAProof string
}

type AuthenticationMethod string

const (
	AuthenticationMethodLocal            AuthenticationMethod = "local_password"
	AuthenticationMethodEmergency        AuthenticationMethod = "emergency_password"
	AuthenticationMethodReauthentication AuthenticationMethod = "reauthentication"
)

type Session struct {
	ID                   uuid.UUID
	TokenDigest          string
	SubjectID            uuid.UUID
	AuthenticationMethod AuthenticationMethod
	MFALevel             int
	AuthenticatedAt      time.Time
	LastUsedAt           time.Time
	AbsoluteExpiresAt    time.Time
	IdleExpiresAt        time.Time
	RevokedAt            time.Time
	RevocationReason     string
	Version              int64
}

type AuthenticatedSubject struct {
	ID          uuid.UUID `json:"id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	Kind        UserKind  `json:"kind"`
}

type LoginResult struct {
	AccessToken string
	TokenType   string
	ExpiresAt   time.Time
	Subject     AuthenticatedSubject
}

type RateLimitScope string

const (
	RateLimitScopeAccount RateLimitScope = "account"
	RateLimitScopeIP      RateLimitScope = "ip"
)

// HighRiskProof contains opaque verifier-bound material. It intentionally has
// no client-supplied time: freshness is established only by the authority.
type HighRiskProof struct {
	ChallengeID string
	Evidence    string
	Confirmed   bool
}

type RequestContext struct {
	RequestID string
	SourceIP  string
}

type Page struct {
	Limit      int
	BeforeTime time.Time
	BeforeID   uuid.UUID
}

type UserPage struct {
	Items      []UserPrincipal `json:"items"`
	NextCursor string          `json:"next_cursor,omitempty"`
}

type CreateLocalUserCommand struct {
	Username    string
	DisplayName string
	Email       string
}

type LocalUserProvisioning struct {
	User              UserPrincipal `json:"user"`
	ActivationToken   string        `json:"activation_token"`
	ActivationExpires time.Time     `json:"activation_expires_at"`
}

type OrganizationPage struct {
	Items      []OrganizationUnit `json:"items"`
	NextCursor string             `json:"next_cursor,omitempty"`
}

type RoleBindingPage struct {
	Items      []RoleBinding `json:"items"`
	NextCursor string        `json:"next_cursor,omitempty"`
}

type IdentitySourcePage struct {
	Items      []IdentitySource `json:"items"`
	NextCursor string           `json:"next_cursor,omitempty"`
}

type CreateOrganizationCommand struct {
	Name     string
	ParentID uuid.UUID
}

type CreateRoleBindingCommand struct {
	SubjectType    SubjectType
	SubjectID      uuid.UUID
	SubjectVersion int64
	Role           identity.Role
	ScopeType      ScopeType
	ProductID      string
	ChannelName    string
	Effect         BindingEffect
	ValidFrom      time.Time
	ValidUntil     time.Time
}

type CreateIdentitySourceCommand struct {
	Name                     string
	Kind                     IdentitySourceKind
	SecretReference          string
	RequiredMappingsComplete bool
}

type PatchIdentitySourceCommand struct {
	Name                     *string
	SecretReference          *string
	RequiredMappingsComplete *bool
	Version                  int64
}
