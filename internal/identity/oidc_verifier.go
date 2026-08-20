package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

const (
	defaultRolesClaim            = "roles"
	defaultProductIDsClaim       = "product_ids"
	defaultTokenUseClaim         = "token_use"
	defaultWorkloadProviderClaim = "workload_provider"
	defaultHumanTokenUse         = "human"
)

var (
	ErrOIDCConfigurationInvalid = errors.New("OIDC configuration is invalid")
	ErrTokenClaimsInvalid       = errors.New("token claims are invalid")
	ErrTokenUseInvalid          = errors.New("token use is invalid")
	ErrUnknownRole              = errors.New("token contains an unknown role")
	ErrTokenIDRequired          = errors.New("token ID is required")
	ErrWorkloadProviderInvalid  = errors.New("workload provider is invalid")
)

type OIDCVerifierConfig struct {
	Issuer                string
	Audience              string
	RolesClaim            string
	ProductIDsClaim       string
	TokenUseClaim         string
	WorkloadProviderClaim string
	SigningAlgorithms     []string
	HTTPClient            *http.Client
	JWKSURL               string
}

type idTokenVerifier interface {
	Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error)
}

type OIDCVerifier struct {
	tokens                  idTokenVerifier
	rolesClaim              string
	productIDsClaim         string
	tokenUseClaim           string
	requiredTokenUse        string
	principalKind           PrincipalKind
	workloadProviderClaim   string
	requireWorkloadProvider bool
}

func NewOIDCVerifier(ctx context.Context, config OIDCVerifierConfig) (*OIDCVerifier, error) {
	return newTokenVerifier(ctx, config, PrincipalKindHuman, defaultHumanTokenUse)
}

func newTokenVerifier(ctx context.Context, config OIDCVerifierConfig, kind PrincipalKind, requiredTokenUse string) (*OIDCVerifier, error) {
	normalized, err := normalizeOIDCConfig(config)
	if err != nil {
		return nil, err
	}
	clientContext := oidc.ClientContext(ctx, normalized.HTTPClient)
	verifierConfig := &oidc.Config{
		ClientID:             normalized.Audience,
		SupportedSigningAlgs: normalized.SigningAlgorithms,
	}
	var tokenVerifier idTokenVerifier
	if normalized.JWKSURL == "" {
		provider, err := oidc.NewProvider(clientContext, normalized.Issuer)
		if err != nil {
			return nil, fmt.Errorf("discover OIDC provider: %w", err)
		}
		tokenVerifier = provider.VerifierContext(clientContext, verifierConfig)
	} else {
		keys := oidc.NewRemoteKeySet(clientContext, normalized.JWKSURL)
		tokenVerifier = oidc.NewVerifier(normalized.Issuer, keys, verifierConfig)
	}
	return &OIDCVerifier{
		tokens:                  tokenVerifier,
		rolesClaim:              normalized.RolesClaim,
		productIDsClaim:         normalized.ProductIDsClaim,
		tokenUseClaim:           normalized.TokenUseClaim,
		requiredTokenUse:        requiredTokenUse,
		principalKind:           kind,
		workloadProviderClaim:   normalized.WorkloadProviderClaim,
		requireWorkloadProvider: kind == PrincipalKindWorkload,
	}, nil
}

func (verifier *OIDCVerifier) Verify(ctx context.Context, rawToken string) (Principal, error) {
	if verifier == nil || verifier.tokens == nil {
		return Principal{}, ErrOIDCConfigurationInvalid
	}
	token, err := verifier.tokens.Verify(ctx, rawToken)
	if err != nil {
		return Principal{}, fmt.Errorf("verify OIDC token: %w", err)
	}
	var claims map[string]json.RawMessage
	if err := token.Claims(&claims); err != nil {
		return Principal{}, fmt.Errorf("decode OIDC claims: %w", ErrTokenClaimsInvalid)
	}

	var subject string
	if err := decodeClaim(claims, "sub", &subject); err != nil || strings.TrimSpace(subject) == "" {
		return Principal{}, fmt.Errorf("subject claim: %w", ErrTokenClaimsInvalid)
	}
	var tokenUse string
	if err := decodeClaim(claims, verifier.tokenUseClaim, &tokenUse); err != nil || tokenUse != verifier.requiredTokenUse {
		return Principal{}, ErrTokenUseInvalid
	}
	roles, err := decodeRoles(claims, verifier.rolesClaim)
	if err != nil {
		return Principal{}, err
	}
	productIDs, err := decodeStringList(claims, verifier.productIDsClaim)
	if err != nil {
		return Principal{}, fmt.Errorf("product IDs claim: %w", ErrTokenClaimsInvalid)
	}
	var tokenID string
	if raw, exists := claims["jti"]; exists {
		if err := json.Unmarshal(raw, &tokenID); err != nil {
			return Principal{}, fmt.Errorf("token ID claim: %w", ErrTokenClaimsInvalid)
		}
	}
	if strings.TrimSpace(tokenID) == "" {
		return Principal{}, ErrTokenIDRequired
	}
	var provider WorkloadProvider
	if verifier.requireWorkloadProvider {
		var providerValue string
		if err := decodeClaim(claims, verifier.workloadProviderClaim, &providerValue); err != nil {
			return Principal{}, ErrWorkloadProviderInvalid
		}
		provider = WorkloadProvider(strings.TrimSpace(providerValue))
		switch provider {
		case WorkloadProviderGitHubActions, WorkloadProviderGitHubEnterpriseActions, WorkloadProviderGitLabCI:
		default:
			return Principal{}, ErrWorkloadProviderInvalid
		}
	}
	var authenticatedAt time.Time
	authenticationAssurance := 0
	if verifier.principalKind == PrincipalKindHuman {
		if raw, exists := claims["auth_time"]; exists {
			var unixSeconds int64
			if err := json.Unmarshal(raw, &unixSeconds); err != nil || unixSeconds <= 0 {
				return Principal{}, fmt.Errorf("authentication time claim: %w", ErrTokenClaimsInvalid)
			}
			authenticatedAt = time.Unix(unixSeconds, 0).UTC()
		}
		if raw, exists := claims["amr"]; exists {
			var methods []string
			if err := json.Unmarshal(raw, &methods); err != nil {
				return Principal{}, fmt.Errorf("authentication methods claim: %w", ErrTokenClaimsInvalid)
			}
			authenticationAssurance = authenticationAssuranceFromMethods(methods)
		}
	}

	principal := Principal{
		Subject: strings.TrimSpace(subject), Kind: verifier.principalKind, Roles: roles,
		ProductIDs: productIDs, TokenID: strings.TrimSpace(tokenID), Provider: provider,
		AuthenticatedAt: authenticatedAt, AuthenticationAssurance: authenticationAssurance,
	}
	if err := principal.Validate(); err != nil {
		return Principal{}, err
	}
	return principal, nil
}

func authenticationAssuranceFromMethods(methods []string) int {
	categories := map[string]struct{}{}
	for _, method := range methods {
		switch strings.ToLower(strings.TrimSpace(method)) {
		case "mfa":
			return 1
		case "pwd", "pin", "kba":
			categories["knowledge"] = struct{}{}
		case "otp", "sms", "hwk", "swk", "sc", "tel", "fido", "fido2", "webauthn", "pop":
			categories["possession"] = struct{}{}
		case "face", "fpt", "iris", "retina", "vbm", "voice":
			categories["inherence"] = struct{}{}
		}
	}
	if len(categories) >= 2 {
		return 1
	}
	return 0
}

func normalizeOIDCConfig(config OIDCVerifierConfig) (OIDCVerifierConfig, error) {
	config.Issuer = strings.TrimRight(strings.TrimSpace(config.Issuer), "/")
	config.Audience = strings.TrimSpace(config.Audience)
	if config.Issuer == "" || config.Audience == "" {
		return OIDCVerifierConfig{}, ErrOIDCConfigurationInvalid
	}
	issuerURL, err := url.Parse(config.Issuer)
	if err != nil || issuerURL.Host == "" || issuerURL.User != nil || issuerURL.RawQuery != "" || issuerURL.Fragment != "" {
		return OIDCVerifierConfig{}, ErrOIDCConfigurationInvalid
	}
	if issuerURL.Scheme != "https" && !(issuerURL.Scheme == "http" && isLoopbackHost(issuerURL.Hostname())) {
		return OIDCVerifierConfig{}, ErrOIDCConfigurationInvalid
	}
	if config.JWKSURL = strings.TrimSpace(config.JWKSURL); config.JWKSURL != "" {
		jwksURL, jwksErr := url.Parse(config.JWKSURL)
		if jwksErr != nil || jwksURL.Host == "" || jwksURL.User != nil || jwksURL.Fragment != "" || jwksURL.RawQuery != "" || jwksURL.RawPath != "" ||
			jwksURL.Scheme != issuerURL.Scheme || !strings.EqualFold(jwksURL.Host, issuerURL.Host) {
			return OIDCVerifierConfig{}, ErrOIDCConfigurationInvalid
		}
	}
	if config.RolesClaim = strings.TrimSpace(config.RolesClaim); config.RolesClaim == "" {
		config.RolesClaim = defaultRolesClaim
	}
	if config.ProductIDsClaim = strings.TrimSpace(config.ProductIDsClaim); config.ProductIDsClaim == "" {
		config.ProductIDsClaim = defaultProductIDsClaim
	}
	if config.TokenUseClaim = strings.TrimSpace(config.TokenUseClaim); config.TokenUseClaim == "" {
		config.TokenUseClaim = defaultTokenUseClaim
	}
	if config.WorkloadProviderClaim = strings.TrimSpace(config.WorkloadProviderClaim); config.WorkloadProviderClaim == "" {
		config.WorkloadProviderClaim = defaultWorkloadProviderClaim
	}
	if len(config.SigningAlgorithms) == 0 {
		config.SigningAlgorithms = []string{"RS256", "PS256", "ES256"}
	}
	allowedAlgorithms := map[string]struct{}{
		"RS256": {}, "RS384": {}, "RS512": {},
		"PS256": {}, "PS384": {}, "PS512": {},
		"ES256": {}, "ES384": {}, "ES512": {},
		"EdDSA": {},
	}
	for _, algorithm := range config.SigningAlgorithms {
		if _, allowed := allowedAlgorithms[algorithm]; !allowed {
			return OIDCVerifierConfig{}, ErrOIDCConfigurationInvalid
		}
	}
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return config, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func decodeClaim(claims map[string]json.RawMessage, name string, target any) error {
	raw, exists := claims[name]
	if !exists {
		return ErrTokenClaimsInvalid
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return ErrTokenClaimsInvalid
	}
	return nil
}

func decodeRoles(claims map[string]json.RawMessage, name string) ([]Role, error) {
	values, err := decodeStringList(claims, name)
	if err != nil {
		return nil, fmt.Errorf("roles claim: %w", ErrTokenClaimsInvalid)
	}
	roles := make([]Role, 0, len(values))
	for _, value := range values {
		role := Role(value)
		switch role {
		case RoleAdmin, RolePublisher, RoleApprover, RoleAuditor, RoleViewer:
			roles = append(roles, role)
		default:
			return nil, fmt.Errorf("%w: %s", ErrUnknownRole, value)
		}
	}
	return roles, nil
}

func decodeStringList(claims map[string]json.RawMessage, name string) ([]string, error) {
	var values []string
	if err := decodeClaim(claims, name, &values); err != nil {
		return nil, err
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, ErrTokenClaimsInvalid
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, nil
}
