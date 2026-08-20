package authorizationcontext

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"
)

type LicenseStatus string

const (
	LicenseStatusValid     LicenseStatus = "valid"
	LicenseStatusExpired   LicenseStatus = "expired"
	LicenseStatusRevoked   LicenseStatus = "revoked"
	LicenseStatusSuspended LicenseStatus = "suspended"
)

type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
)

var (
	ErrResolverConfiguration = errors.New("authorization context resolver configuration is invalid")
	ErrUntrustedContext      = errors.New("authorization context is not trusted")
	ErrContextClaimsInvalid  = errors.New("authorization context claims are invalid")
	ErrRequestBindingInvalid = errors.New("authorization context request binding is invalid")
	ErrContextReplay         = errors.New("authorization context was replayed")
)

type SignedEnvelope struct {
	Compact string
}

type RequestBinding struct {
	RequestID string
	Method    string
	Path      string
}

type Snapshot struct {
	CustomerID        string
	CustomerName      string
	TenantID          string
	AuthorizationName string
	ClientAppVersion  string
	LicenseID         string
	LicenseExpiresAt  time.Time
	LicenseStatus     LicenseStatus
	Decision          Decision
	ReasonCode        string
	ValidatedAt       time.Time
	ValidatorIssuer   string
	ContextDigest     [sha256.Size]byte
}

type Resolver interface {
	Resolve(ctx context.Context, envelope SignedEnvelope, binding RequestBinding) (Snapshot, error)
}

type ReplayStore interface {
	Claim(contextID string, expiresAt, now time.Time) bool
}
