package authorizationcontext

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"time"
)

type LicenseStatus string

const (
	LicenseStatusValid    LicenseStatus = "valid"
	LicenseStatusExpiring LicenseStatus = "expiring"
	LicenseStatusExpired  LicenseStatus = "expired"
	LicenseStatusRevoked  LicenseStatus = "revoked"
	LicenseStatusUnknown  LicenseStatus = "unknown"
)

type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
)

var (
	ErrResolverConfiguration  = errors.New("authorization context resolver configuration is invalid")
	ErrUntrustedContext       = errors.New("authorization context is not trusted")
	ErrContextClaimsInvalid   = errors.New("authorization context claims are invalid")
	ErrRequestBindingInvalid  = errors.New("authorization context request binding is invalid")
	ErrContextReplay          = errors.New("authorization context was replayed")
	ErrReplayStoreUnavailable = errors.New("authorization context replay store is unavailable")
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
	ClientAppID       string
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

type VerifiedContext struct {
	SnapshotCandidate Snapshot
	ValidatorIssuer   string
	ContextID         string
	ExpiresAt         time.Time
}

type ReplayStore interface {
	Claim(ctx context.Context, issuer, contextID string, expiresAt, now time.Time) (bool, error)
}

func canonicalReplayIdentity(issuer, contextID string) (string, string, bool) {
	issuer = strings.TrimSpace(issuer)
	contextID = strings.TrimSpace(contextID)
	return issuer, contextID, issuer != "" && contextID != ""
}

type Verifier interface {
	VerifyAndCanonicalize(context.Context, SignedEnvelope, RequestBinding) (VerifiedContext, error)
}

type Resolver interface {
	Verifier
	Claim(context.Context, VerifiedContext) (Snapshot, error)
}
