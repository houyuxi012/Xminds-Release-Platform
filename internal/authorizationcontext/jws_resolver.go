package authorizationcontext

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const maximumSignedContextBytes = 16 * 1024

var reasonCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)

type JWSResolverConfig struct {
	Issuer            string
	Audience          string
	VerificationKey   any
	Algorithms        []jose.SignatureAlgorithm
	ReplayStore       ReplayStore
	Clock             func() time.Time
	ClockSkew         time.Duration
	MaximumContextAge time.Duration
}

type JWSResolver struct {
	config JWSResolverConfig
}

type signedClaims struct {
	Issuer            string        `json:"iss"`
	Audience          []string      `json:"aud"`
	ExpiresAt         int64         `json:"exp"`
	NotBefore         int64         `json:"nbf"`
	IssuedAt          int64         `json:"iat"`
	ContextID         string        `json:"jti"`
	RequestID         string        `json:"request_id"`
	Method            string        `json:"method"`
	Path              string        `json:"path"`
	CustomerID        string        `json:"customer_id"`
	CustomerName      string        `json:"customer_name"`
	TenantID          string        `json:"tenant_id"`
	AuthorizationName string        `json:"authorization_name"`
	ClientAppID       string        `json:"client_app_id"`
	ClientAppVersion  string        `json:"client_app_version"`
	LicenseID         string        `json:"license_id"`
	LicenseExpiresAt  time.Time     `json:"license_expires_at"`
	LicenseStatus     LicenseStatus `json:"license_status"`
	Decision          Decision      `json:"decision"`
	ReasonCode        string        `json:"reason_code"`
	ValidatedAt       time.Time     `json:"validated_at"`
}

func NewJWSResolver(config JWSResolverConfig) (*JWSResolver, error) {
	config.Issuer = strings.TrimSpace(config.Issuer)
	config.Audience = strings.TrimSpace(config.Audience)
	if config.Issuer == "" || config.Audience == "" || config.VerificationKey == nil || len(config.Algorithms) == 0 ||
		config.ReplayStore == nil || config.Clock == nil || config.ClockSkew < 0 || config.ClockSkew > time.Minute ||
		config.MaximumContextAge <= 0 || config.MaximumContextAge > 10*time.Minute {
		return nil, ErrResolverConfiguration
	}
	for _, algorithm := range config.Algorithms {
		switch algorithm {
		case jose.EdDSA, jose.RS256, jose.PS256, jose.ES256:
		default:
			return nil, ErrResolverConfiguration
		}
	}
	return &JWSResolver{config: config}, nil
}

func (resolver *JWSResolver) VerifyAndCanonicalize(_ context.Context, envelope SignedEnvelope, binding RequestBinding) (VerifiedContext, error) {
	if resolver == nil || resolver.config.Clock == nil || resolver.config.ReplayStore == nil {
		return VerifiedContext{}, ErrResolverConfiguration
	}
	compact := strings.TrimSpace(envelope.Compact)
	if compact == "" || len(compact) > maximumSignedContextBytes || strings.HasPrefix(compact, "{") {
		return VerifiedContext{}, ErrUntrustedContext
	}
	object, err := jose.ParseSignedCompact(compact, resolver.config.Algorithms)
	if err != nil || len(object.Signatures) != 1 {
		return VerifiedContext{}, ErrUntrustedContext
	}
	payload, err := object.Verify(resolver.config.VerificationKey)
	if err != nil {
		return VerifiedContext{}, ErrUntrustedContext
	}
	var claims signedClaims
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&claims); err != nil {
		return VerifiedContext{}, ErrContextClaimsInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return VerifiedContext{}, ErrContextClaimsInvalid
	}
	now := resolver.config.Clock().UTC().Truncate(time.Microsecond)
	if err := resolver.validateClaims(claims, binding, now); err != nil {
		return VerifiedContext{}, err
	}
	expiresAt := time.Unix(claims.ExpiresAt, 0).UTC()
	issuer, contextID, ok := canonicalReplayIdentity(claims.Issuer, claims.ContextID)
	if !ok {
		return VerifiedContext{}, ErrContextClaimsInvalid
	}
	snapshot := Snapshot{
		CustomerID: strings.TrimSpace(claims.CustomerID), CustomerName: strings.TrimSpace(claims.CustomerName),
		TenantID: strings.TrimSpace(claims.TenantID), AuthorizationName: strings.TrimSpace(claims.AuthorizationName),
		ClientAppID:      strings.TrimSpace(claims.ClientAppID),
		ClientAppVersion: strings.TrimSpace(claims.ClientAppVersion), LicenseID: strings.TrimSpace(claims.LicenseID),
		LicenseExpiresAt: claims.LicenseExpiresAt.UTC(), LicenseStatus: claims.LicenseStatus,
		Decision: claims.Decision, ReasonCode: claims.ReasonCode, ValidatedAt: claims.ValidatedAt.UTC(), ValidatorIssuer: resolver.config.Issuer,
	}
	applyLicenseDecision(&snapshot, now)
	snapshot.ContextDigest = digestSnapshot(snapshot)
	return VerifiedContext{SnapshotCandidate: snapshot, ValidatorIssuer: issuer, ContextID: contextID, ExpiresAt: expiresAt.Add(resolver.config.ClockSkew)}, nil
}

func (resolver *JWSResolver) Claim(ctx context.Context, verified VerifiedContext) (Snapshot, error) {
	if resolver == nil || resolver.config.ReplayStore == nil || resolver.config.Clock == nil {
		return Snapshot{}, ErrResolverConfiguration
	}
	now := resolver.config.Clock().UTC().Truncate(time.Microsecond)
	claimed, err := resolver.config.ReplayStore.Claim(ctx, verified.ValidatorIssuer, verified.ContextID, verified.ExpiresAt, now)
	if err != nil {
		return Snapshot{}, ErrReplayStoreUnavailable
	}
	if !claimed {
		return Snapshot{}, ErrContextReplay
	}
	return verified.SnapshotCandidate, nil
}

func (resolver *JWSResolver) Resolve(ctx context.Context, envelope SignedEnvelope, binding RequestBinding) (Snapshot, error) {
	verified, err := resolver.VerifyAndCanonicalize(ctx, envelope, binding)
	if err != nil {
		return Snapshot{}, err
	}
	return resolver.Claim(ctx, verified)
}

func (resolver *JWSResolver) validateClaims(claims signedClaims, binding RequestBinding, now time.Time) error {
	if strings.TrimSpace(claims.Issuer) != resolver.config.Issuer || !containsAudience(claims.Audience, resolver.config.Audience) {
		return ErrUntrustedContext
	}
	expiresAt := time.Unix(claims.ExpiresAt, 0).UTC()
	notBefore := time.Unix(claims.NotBefore, 0).UTC()
	issuedAt := time.Unix(claims.IssuedAt, 0).UTC()
	if claims.ExpiresAt <= 0 || claims.NotBefore <= 0 || claims.IssuedAt <= 0 || !expiresAt.After(now.Add(-resolver.config.ClockSkew)) ||
		notBefore.After(now.Add(resolver.config.ClockSkew)) || issuedAt.After(now.Add(resolver.config.ClockSkew)) ||
		now.Sub(issuedAt) > resolver.config.MaximumContextAge+resolver.config.ClockSkew || !expiresAt.After(issuedAt) {
		return ErrUntrustedContext
	}
	if strings.TrimSpace(claims.RequestID) != strings.TrimSpace(binding.RequestID) || strings.ToUpper(strings.TrimSpace(claims.Method)) != strings.ToUpper(strings.TrimSpace(binding.Method)) ||
		strings.TrimSpace(claims.Path) != strings.TrimSpace(binding.Path) {
		return ErrRequestBindingInvalid
	}
	if !validBoundedClaims(claims, now, resolver.config.ClockSkew) {
		return ErrContextClaimsInvalid
	}
	return nil
}

func validBoundedClaims(claims signedClaims, now time.Time, skew time.Duration) bool {
	values := []struct {
		value string
		max   int
	}{
		{claims.ContextID, 128}, {claims.RequestID, 128}, {claims.Method, 16}, {claims.Path, 2048},
		{claims.CustomerID, 128}, {claims.CustomerName, 256}, {claims.TenantID, 128}, {claims.ClientAppID, 128},
		{claims.AuthorizationName, 256}, {claims.ClientAppVersion, 128}, {claims.LicenseID, 128},
	}
	for _, item := range values {
		if strings.TrimSpace(item.value) == "" || len([]rune(item.value)) > item.max {
			return false
		}
	}
	if !strings.HasPrefix(strings.TrimSpace(claims.Path), "/") || strings.ContainsAny(claims.Path, "?#") || !reasonCodePattern.MatchString(claims.ReasonCode) || claims.LicenseExpiresAt.IsZero() || claims.ValidatedAt.IsZero() || claims.ValidatedAt.After(now.Add(skew)) || claims.ValidatedAt.Before(time.Unix(claims.IssuedAt, 0).UTC().Add(-skew)) {
		return false
	}
	switch claims.LicenseStatus {
	case LicenseStatusValid, LicenseStatusExpiring, LicenseStatusExpired, LicenseStatusRevoked, LicenseStatusUnknown:
	default:
		return false
	}
	return claims.Decision == DecisionAllow || claims.Decision == DecisionDeny
}

func containsAudience(values []string, wanted string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == wanted {
			return true
		}
	}
	return false
}

func applyLicenseDecision(snapshot *Snapshot, now time.Time) {
	if snapshot.LicenseStatus == LicenseStatusValid && !snapshot.LicenseExpiresAt.After(now) {
		snapshot.LicenseStatus = LicenseStatusExpired
	}
	if snapshot.LicenseStatus == LicenseStatusValid || snapshot.LicenseStatus == LicenseStatusExpiring {
		return
	}
	snapshot.Decision = DecisionDeny
	switch snapshot.LicenseStatus {
	case LicenseStatusExpired:
		snapshot.ReasonCode = "LICENSE_EXPIRED"
	case LicenseStatusRevoked:
		snapshot.ReasonCode = "LICENSE_REVOKED"
	case LicenseStatusUnknown:
		snapshot.ReasonCode = "LICENSE_UNKNOWN"
	}
}

func digestSnapshot(snapshot Snapshot) [sha256.Size]byte {
	canonical := struct {
		CustomerID, CustomerName, TenantID, AuthorizationName, ClientAppID, ClientAppVersion, LicenseID string
		LicenseExpiresAt                                                                                string
		LicenseStatus                                                                                   LicenseStatus
		Decision                                                                                        Decision
		ReasonCode, ValidatedAt, ValidatorIssuer                                                        string
	}{
		snapshot.CustomerID, snapshot.CustomerName, snapshot.TenantID, snapshot.AuthorizationName, snapshot.ClientAppID,
		snapshot.ClientAppVersion, snapshot.LicenseID, snapshot.LicenseExpiresAt.UTC().Format(time.RFC3339Nano),
		snapshot.LicenseStatus, snapshot.Decision, snapshot.ReasonCode,
		snapshot.ValidatedAt.UTC().Format(time.RFC3339Nano), snapshot.ValidatorIssuer,
	}
	payload, _ := json.Marshal(canonical)
	return sha256.Sum256(payload)
}

type MemoryReplayStore struct {
	mutex   sync.Mutex
	entries map[string]time.Time
}

func NewMemoryReplayStore() *MemoryReplayStore {
	return &MemoryReplayStore{entries: make(map[string]time.Time)}
}

func (store *MemoryReplayStore) Claim(_ context.Context, issuer, contextID string, expiresAt, now time.Time) (bool, error) {
	issuer, contextID, ok := canonicalReplayIdentity(issuer, contextID)
	if store == nil || !ok || !expiresAt.After(now) {
		return false, nil
	}
	store.mutex.Lock()
	defer store.mutex.Unlock()
	for id, expiry := range store.entries {
		if !expiry.After(now) {
			delete(store.entries, id)
		}
	}
	key := issuer + "\x00" + contextID
	if _, exists := store.entries[key]; exists {
		return false, nil
	}
	store.entries[key] = expiresAt
	return true, nil
}
