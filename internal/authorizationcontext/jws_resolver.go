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
	ClientAppVersion  string        `json:"client_app_version"`
	LicenseID         string        `json:"license_id"`
	LicenseExpiresAt  time.Time     `json:"license_expires_at"`
	LicenseStatus     LicenseStatus `json:"license_status"`
	Decision          Decision      `json:"decision"`
	ReasonCode        string        `json:"reason_code"`
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

func (resolver *JWSResolver) Resolve(_ context.Context, envelope SignedEnvelope, binding RequestBinding) (Snapshot, error) {
	if resolver == nil || resolver.config.Clock == nil || resolver.config.ReplayStore == nil {
		return Snapshot{}, ErrResolverConfiguration
	}
	compact := strings.TrimSpace(envelope.Compact)
	if compact == "" || len(compact) > maximumSignedContextBytes || strings.HasPrefix(compact, "{") {
		return Snapshot{}, ErrUntrustedContext
	}
	object, err := jose.ParseSignedCompact(compact, resolver.config.Algorithms)
	if err != nil || len(object.Signatures) != 1 {
		return Snapshot{}, ErrUntrustedContext
	}
	payload, err := object.Verify(resolver.config.VerificationKey)
	if err != nil {
		return Snapshot{}, ErrUntrustedContext
	}
	var claims signedClaims
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&claims); err != nil {
		return Snapshot{}, ErrContextClaimsInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Snapshot{}, ErrContextClaimsInvalid
	}
	now := resolver.config.Clock().UTC().Truncate(time.Microsecond)
	if err := resolver.validateClaims(claims, binding, now); err != nil {
		return Snapshot{}, err
	}
	expiresAt := time.Unix(claims.ExpiresAt, 0).UTC()
	if !resolver.config.ReplayStore.Claim(claims.ContextID, expiresAt.Add(resolver.config.ClockSkew), now) {
		return Snapshot{}, ErrContextReplay
	}
	snapshot := Snapshot{
		CustomerID: strings.TrimSpace(claims.CustomerID), CustomerName: strings.TrimSpace(claims.CustomerName),
		TenantID: strings.TrimSpace(claims.TenantID), AuthorizationName: strings.TrimSpace(claims.AuthorizationName),
		ClientAppVersion: strings.TrimSpace(claims.ClientAppVersion), LicenseID: strings.TrimSpace(claims.LicenseID),
		LicenseExpiresAt: claims.LicenseExpiresAt.UTC(), LicenseStatus: claims.LicenseStatus,
		Decision: claims.Decision, ReasonCode: claims.ReasonCode, ValidatedAt: now, ValidatorIssuer: resolver.config.Issuer,
	}
	applyLicenseDecision(&snapshot, now)
	snapshot.ContextDigest = digestSnapshot(snapshot)
	return snapshot, nil
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
	if !validBoundedClaims(claims) {
		return ErrContextClaimsInvalid
	}
	return nil
}

func validBoundedClaims(claims signedClaims) bool {
	values := []struct {
		value string
		max   int
	}{
		{claims.ContextID, 128}, {claims.RequestID, 128}, {claims.Method, 16}, {claims.Path, 2048},
		{claims.CustomerID, 128}, {claims.CustomerName, 256}, {claims.TenantID, 128},
		{claims.AuthorizationName, 256}, {claims.ClientAppVersion, 128}, {claims.LicenseID, 128},
	}
	for _, item := range values {
		if strings.TrimSpace(item.value) == "" || len([]rune(item.value)) > item.max {
			return false
		}
	}
	if !strings.HasPrefix(strings.TrimSpace(claims.Path), "/") || strings.ContainsAny(claims.Path, "?#") || !reasonCodePattern.MatchString(claims.ReasonCode) || claims.LicenseExpiresAt.IsZero() {
		return false
	}
	switch claims.LicenseStatus {
	case LicenseStatusValid, LicenseStatusExpired, LicenseStatusRevoked, LicenseStatusSuspended:
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
	if snapshot.LicenseStatus == LicenseStatusValid {
		return
	}
	snapshot.Decision = DecisionDeny
	switch snapshot.LicenseStatus {
	case LicenseStatusExpired:
		snapshot.ReasonCode = "LICENSE_EXPIRED"
	case LicenseStatusRevoked:
		snapshot.ReasonCode = "LICENSE_REVOKED"
	case LicenseStatusSuspended:
		snapshot.ReasonCode = "LICENSE_SUSPENDED"
	}
}

func digestSnapshot(snapshot Snapshot) [sha256.Size]byte {
	canonical := struct {
		CustomerID, CustomerName, TenantID, AuthorizationName, ClientAppVersion, LicenseID string
		LicenseExpiresAt                                                                   string
		LicenseStatus                                                                      LicenseStatus
		Decision                                                                           Decision
		ReasonCode, ValidatedAt, ValidatorIssuer                                           string
	}{
		snapshot.CustomerID, snapshot.CustomerName, snapshot.TenantID, snapshot.AuthorizationName,
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

func (store *MemoryReplayStore) Claim(contextID string, expiresAt, now time.Time) bool {
	if store == nil || strings.TrimSpace(contextID) == "" || !expiresAt.After(now) {
		return false
	}
	store.mutex.Lock()
	defer store.mutex.Unlock()
	for id, expiry := range store.entries {
		if !expiry.After(now) {
			delete(store.entries, id)
		}
	}
	if _, exists := store.entries[contextID]; exists {
		return false
	}
	store.entries[contextID] = expiresAt
	return true
}
