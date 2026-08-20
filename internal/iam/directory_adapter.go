package iam

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"xminds-release-platform/internal/platform/egress"
	"xminds-release-platform/internal/platform/strictjson"
)

const (
	defaultDirectoryRequestTimeout = 10 * time.Second
	minimumDirectoryRequestTimeout = time.Second
	maximumDirectoryRequestTimeout = 30 * time.Second
	defaultDirectoryMaximumPages   = 10_000
	defaultDirectoryMaximumObjects = 100_000
	maximumDirectoryResponseBytes  = 2 * 1024 * 1024
	maximumDirectorySecretBytes    = 4 * 1024
	maximumDirectoryStringBytes    = 512

	scimListResponseSchema = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimResourceTypeSchema = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	scimUserSchema         = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimGroupSchema        = "urn:ietf:params:scim:schemas:core:2.0:Group"
)

var (
	ErrDirectoryConfigurationInvalid = errors.New("directory configuration is invalid")
	ErrDirectoryUpstreamRejected     = errors.New("directory upstream request was rejected")
	ErrDirectoryResponseInvalid      = errors.New("directory upstream response is invalid")
	ErrDirectoryLimitExceeded        = errors.New("directory synchronization limit was exceeded")
	ErrDirectoryCursorInvalid        = errors.New("directory synchronization cursor is invalid")
)

type SecretBackedDirectoryAdapterConfig struct {
	Secrets                SecretResolver
	OIDCTrusts             *OIDCTrustFactory
	Resolver               egress.IPResolver
	Dialer                 egress.Dialer
	RequestTimeout         time.Duration
	MaximumPages           int
	MaximumObjects         int
	AllowLoopbackHTTP      bool
	AllowedPrivatePrefixes []netip.Prefix
}

type SecretBackedDirectoryAdapter struct {
	secrets                SecretResolver
	oidcTrusts             *OIDCTrustFactory
	resolver               egress.IPResolver
	dialer                 egress.Dialer
	requestTimeout         time.Duration
	maximumPages           int
	maximumObjects         int
	allowLoopbackHTTP      bool
	allowedPrivatePrefixes []netip.Prefix
}

type oidcDirectorySecret struct {
	Issuer            string   `json:"issuer"`
	Audience          string   `json:"audience"`
	RolesClaim        string   `json:"roles_claim"`
	ProductIDsClaim   string   `json:"product_ids_claim"`
	TokenUseClaim     string   `json:"token_use_claim"`
	SigningAlgorithms []string `json:"signing_algorithms"`
	CAReference       string   `json:"ca_reference,omitempty"`
}

type scimDirectorySecret struct {
	BaseURL              string `json:"base_url"`
	BearerTokenReference string `json:"bearer_token_reference"`
	CAReference          string `json:"ca_reference,omitempty"`
	PageSize             int    `json:"page_size"`
}

type oidcDiscoveryDocument struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

type oidcJWKSet struct {
	Keys []struct {
		KeyType  string `json:"kty"`
		KeyID    string `json:"kid"`
		Use      string `json:"use"`
		Alg      string `json:"alg"`
		Modulus  string `json:"n"`
		Exponent string `json:"e"`
		Curve    string `json:"crv"`
		X        string `json:"x"`
		Y        string `json:"y"`
	} `json:"keys"`
}

type scimServiceProviderConfig struct {
	Schemas    []string `json:"schemas"`
	Pagination struct {
		Supported bool `json:"supported"`
	} `json:"pagination"`
}

type scimResourceType struct {
	Schemas  []string `json:"schemas"`
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Endpoint string   `json:"endpoint"`
	Schema   string   `json:"schema"`
}

type scimListResponse struct {
	Schemas      []string          `json:"schemas"`
	TotalResults int               `json:"totalResults"`
	StartIndex   int               `json:"startIndex"`
	ItemsPerPage int               `json:"itemsPerPage"`
	Resources    []json.RawMessage `json:"Resources"`
}

type scimUser struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id"`
	UserName    string   `json:"userName"`
	DisplayName string   `json:"displayName"`
	Active      *bool    `json:"active"`
	Emails      []struct {
		Value   string `json:"value"`
		Primary bool   `json:"primary"`
	} `json:"emails"`
}

type scimGroup struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id"`
	DisplayName string   `json:"displayName"`
	Members     []struct {
		Value string `json:"value"`
		Type  string `json:"type"`
	} `json:"members"`
}

type scimCursor struct {
	Resource    string `json:"resource"`
	StartIndex  int    `json:"start_index"`
	Pages       int    `json:"pages"`
	Objects     int    `json:"objects"`
	UsersTotal  *int   `json:"users_total,omitempty"`
	GroupsTotal *int   `json:"groups_total,omitempty"`
}

func NewSecretBackedDirectoryAdapter(config SecretBackedDirectoryAdapterConfig) (*SecretBackedDirectoryAdapter, error) {
	if config.RequestTimeout == 0 {
		config.RequestTimeout = defaultDirectoryRequestTimeout
	}
	if config.MaximumPages == 0 {
		config.MaximumPages = defaultDirectoryMaximumPages
	}
	if config.MaximumObjects == 0 {
		config.MaximumObjects = defaultDirectoryMaximumObjects
	}
	if config.Resolver == nil {
		config.Resolver = net.DefaultResolver
	}
	if config.Dialer == nil {
		config.Dialer = &net.Dialer{Timeout: config.RequestTimeout / 2, KeepAlive: 30 * time.Second}
	}
	if config.Secrets == nil || config.RequestTimeout < minimumDirectoryRequestTimeout || config.RequestTimeout > maximumDirectoryRequestTimeout ||
		config.MaximumPages < 1 || config.MaximumPages > defaultDirectoryMaximumPages || config.MaximumObjects < 1 || config.MaximumObjects > defaultDirectoryMaximumObjects ||
		config.Resolver == nil || config.Dialer == nil {
		return nil, ErrDirectoryConfigurationInvalid
	}
	if config.OIDCTrusts == nil {
		var err error
		config.OIDCTrusts, err = NewOIDCTrustFactory(OIDCTrustFactoryConfig{
			Secrets: config.Secrets, Resolver: config.Resolver, Dialer: config.Dialer, RequestTimeout: config.RequestTimeout,
			AllowLoopbackHTTP: config.AllowLoopbackHTTP, AllowedPrivatePrefixes: config.AllowedPrivatePrefixes,
		})
		if err != nil {
			return nil, err
		}
	}
	return &SecretBackedDirectoryAdapter{
		secrets: config.Secrets, oidcTrusts: config.OIDCTrusts, resolver: config.Resolver, dialer: config.Dialer,
		requestTimeout: config.RequestTimeout, maximumPages: config.MaximumPages,
		maximumObjects: config.MaximumObjects, allowLoopbackHTTP: config.AllowLoopbackHTTP,
		allowedPrivatePrefixes: append([]netip.Prefix(nil), config.AllowedPrivatePrefixes...),
	}, nil
}

func (adapter *SecretBackedDirectoryAdapter) Verify(ctx context.Context, source IdentitySource) (CapabilityReport, error) {
	if adapter == nil || adapter.secrets == nil || source.ID == [16]byte{} {
		return CapabilityReport{}, ErrDirectoryConfigurationInvalid
	}
	ctx, cancel := adapter.operationContext(ctx)
	defer cancel()
	switch source.Kind {
	case IdentitySourceOIDC:
		return adapter.verifyOIDC(ctx, source)
	case IdentitySourceSCIM:
		return adapter.verifySCIM(ctx, source)
	default:
		return CapabilityReport{}, ErrDirectoryConfigurationInvalid
	}
}

func (adapter *SecretBackedDirectoryAdapter) Preview(_ context.Context, source IdentitySource) (SyncDiff, error) {
	if source.Kind != IdentitySourceOIDC && source.Kind != IdentitySourceSCIM {
		return SyncDiff{}, ErrDirectoryConfigurationInvalid
	}
	return SyncDiff{}, nil
}

func (adapter *SecretBackedDirectoryAdapter) Sync(ctx context.Context, source IdentitySource, cursor string) (SyncPage, error) {
	if adapter == nil || adapter.secrets == nil || source.Kind != IdentitySourceSCIM {
		return SyncPage{}, ErrDirectoryConfigurationInvalid
	}
	ctx, cancel := adapter.operationContext(ctx)
	defer cancel()
	configuration, bearer, client, err := adapter.loadSCIM(ctx, source)
	if err != nil {
		return SyncPage{}, err
	}
	position, err := decodeSCIMCursor(cursor)
	if err != nil {
		return SyncPage{}, err
	}
	if position.Pages >= adapter.maximumPages || position.Objects >= adapter.maximumObjects {
		return SyncPage{}, ErrDirectoryLimitExceeded
	}
	resourceEndpoint := "Users"
	if position.Resource == "groups" {
		resourceEndpoint = "Groups"
	}
	endpoint := configuration.BaseURL + "/" + resourceEndpoint
	requestURL, err := url.Parse(endpoint)
	if err != nil {
		return SyncPage{}, ErrDirectoryConfigurationInvalid
	}
	query := requestURL.Query()
	query.Set("startIndex", strconv.Itoa(position.StartIndex))
	query.Set("count", strconv.Itoa(configuration.PageSize))
	requestURL.RawQuery = query.Encode()
	var response scimListResponse
	if err := adapter.getJSON(ctx, client, requestURL.String(), bearer, &response); err != nil {
		return SyncPage{}, err
	}
	if err := validateSCIMListResponse(response, position.StartIndex, configuration.PageSize); err != nil {
		return SyncPage{}, err
	}
	if err := pinSCIMTotalResults(&position, response.TotalResults); err != nil {
		return SyncPage{}, err
	}
	position.Pages++
	if position.Pages > adapter.maximumPages {
		return SyncPage{}, ErrDirectoryLimitExceeded
	}
	page := SyncPage{}
	if position.Resource == "users" {
		page.Users, err = normalizeSCIMUsers(response.Resources)
	} else {
		page.Organizations, page.Memberships, page.OrganizationParents, err = normalizeSCIMGroups(response.Resources)
	}
	if err != nil {
		return SyncPage{}, err
	}
	position.Objects += len(page.Users) + len(page.Organizations) + len(page.Memberships) + len(page.OrganizationParents)
	if position.Objects > adapter.maximumObjects {
		return SyncPage{}, ErrDirectoryLimitExceeded
	}
	nextIndex := response.StartIndex + len(response.Resources)
	if nextIndex <= response.TotalResults {
		position.StartIndex = nextIndex
		page.NextCursor, err = encodeSCIMCursor(position)
		return page, err
	}
	if position.Resource == "users" {
		position.Resource = "groups"
		position.StartIndex = 1
		page.NextCursor, err = encodeSCIMCursor(position)
		return page, err
	}
	page.Complete = true
	return page, nil
}

func (adapter *SecretBackedDirectoryAdapter) operationContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil || adapter == nil || adapter.requestTimeout <= 0 {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx, func() {}
	}
	return context.WithTimeout(parent, adapter.requestTimeout)
}

func (adapter *SecretBackedDirectoryAdapter) verifyOIDC(ctx context.Context, source IdentitySource) (CapabilityReport, error) {
	if adapter == nil || adapter.oidcTrusts == nil {
		return CapabilityReport{}, ErrDirectoryConfigurationInvalid
	}
	material, err := adapter.oidcTrusts.resolve(ctx, source)
	if err != nil {
		return CapabilityReport{}, err
	}
	if _, _, _, err := adapter.oidcTrusts.prepare(ctx, material); err != nil {
		return CapabilityReport{}, err
	}
	return CapabilityReport{
		Reachable: true, RequiredAttributes: []string{"subject", "display_name", "email", "roles", "product_ids"},
		RequiredMappingsComplete: source.RequiredMappingsComplete,
	}, nil
}

func (adapter *SecretBackedDirectoryAdapter) verifySCIM(ctx context.Context, source IdentitySource) (CapabilityReport, error) {
	configuration, bearer, client, err := adapter.loadSCIM(ctx, source)
	if err != nil {
		return CapabilityReport{}, err
	}
	var providerConfiguration scimServiceProviderConfig
	if err := adapter.getJSON(ctx, client, configuration.BaseURL+"/ServiceProviderConfig", bearer, &providerConfiguration); err != nil {
		return CapabilityReport{}, err
	}
	if !containsString(providerConfiguration.Schemas, "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig") || !providerConfiguration.Pagination.Supported {
		return CapabilityReport{}, ErrDirectoryResponseInvalid
	}
	resourceTypes, err := adapter.collectSCIMResourceTypes(ctx, client, configuration.BaseURL+"/ResourceTypes", bearer)
	if err != nil || !validSCIMResourceTypes(resourceTypes) {
		if err != nil {
			return CapabilityReport{}, err
		}
		return CapabilityReport{}, ErrDirectoryResponseInvalid
	}
	return CapabilityReport{
		Reachable: true, RequiredAttributes: []string{"subject", "display_name", "email", "organizations"},
		RequiredMappingsComplete: source.RequiredMappingsComplete, SupportsPagination: true,
	}, nil
}

func (adapter *SecretBackedDirectoryAdapter) collectSCIMResourceTypes(ctx context.Context, client *http.Client, endpoint, bearer string) ([]json.RawMessage, error) {
	const resourceTypePageSize = 200
	resources := make([]json.RawMessage, 0, 2)
	startIndex := 1
	totalResults := -1
	for page := 0; page < adapter.maximumPages; page++ {
		requestURL, err := url.Parse(endpoint)
		if err != nil {
			return nil, ErrDirectoryConfigurationInvalid
		}
		query := requestURL.Query()
		query.Set("startIndex", strconv.Itoa(startIndex))
		query.Set("count", strconv.Itoa(resourceTypePageSize))
		requestURL.RawQuery = query.Encode()
		var response scimListResponse
		if err := adapter.getJSON(ctx, client, requestURL.String(), bearer, &response); err != nil {
			return nil, err
		}
		if err := validateSCIMListResponse(response, startIndex, resourceTypePageSize); err != nil {
			return nil, err
		}
		if totalResults < 0 {
			totalResults = response.TotalResults
		} else if response.TotalResults != totalResults {
			return nil, ErrDirectoryResponseInvalid
		}
		resources = append(resources, response.Resources...)
		if len(resources) > adapter.maximumObjects || len(resources) > totalResults {
			return nil, ErrDirectoryLimitExceeded
		}
		startIndex = response.StartIndex + len(response.Resources)
		if startIndex > totalResults {
			if len(resources) != totalResults {
				return nil, ErrDirectoryResponseInvalid
			}
			return resources, nil
		}
	}
	return nil, ErrDirectoryLimitExceeded
}

func (adapter *SecretBackedDirectoryAdapter) loadSCIM(ctx context.Context, source IdentitySource) (scimDirectorySecret, string, *http.Client, error) {
	contents, err := adapter.secrets.Resolve(ctx, source.SecretReference)
	if err != nil {
		return scimDirectorySecret{}, "", nil, ErrDirectoryConfigurationInvalid
	}
	var configuration scimDirectorySecret
	if err := decodeStrictJSON(contents, &configuration); err != nil || configuration.PageSize < 1 || configuration.PageSize > 200 ||
		!validSecretReference(configuration.BearerTokenReference) || !safeBaseURL(configuration.BaseURL, adapter.allowLoopbackHTTP) {
		return scimDirectorySecret{}, "", nil, ErrDirectoryConfigurationInvalid
	}
	configuration.BaseURL = strings.TrimSuffix(strings.TrimSpace(configuration.BaseURL), "/")
	bearer, err := adapter.secrets.Resolve(ctx, configuration.BearerTokenReference)
	if err != nil || len(bytes.TrimSpace(bearer)) < 8 || len(bytes.TrimSpace(bearer)) > 4096 || bytes.ContainsAny(bearer, "\r\n") {
		return scimDirectorySecret{}, "", nil, ErrDirectoryConfigurationInvalid
	}
	client, err := adapter.newHTTPClient(ctx, configuration.CAReference, configuration.BaseURL)
	if err != nil {
		return scimDirectorySecret{}, "", nil, err
	}
	return configuration, string(bytes.TrimSpace(bearer)), client, nil
}

func (adapter *SecretBackedDirectoryAdapter) newHTTPClient(ctx context.Context, caReference, baseURL string) (*http.Client, error) {
	parsedBase, err := url.Parse(baseURL)
	if err != nil || parsedBase.Hostname() == "" {
		return nil, ErrDirectoryConfigurationInvalid
	}
	wantedHost := strings.ToLower(strings.TrimSuffix(parsedBase.Hostname(), "."))
	addresses, err := egress.ResolvePinnedAddresses(ctx, adapter.resolver, wantedHost, egress.Policy{
		AllowLoopback:          adapter.allowLoopbackHTTP,
		AllowedPrivatePrefixes: adapter.allowedPrivatePrefixes,
	})
	if err != nil {
		return nil, ErrDirectoryConfigurationInvalid
	}
	pinnedDialContext, err := egress.NewPinnedDialContext(wantedHost, addresses, adapter.dialer)
	if err != nil {
		return nil, ErrDirectoryConfigurationInvalid
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if strings.TrimSpace(caReference) != "" {
		if !validSecretReference(caReference) {
			return nil, ErrDirectoryConfigurationInvalid
		}
		bundle, resolveErr := adapter.secrets.Resolve(ctx, caReference)
		if resolveErr != nil || !roots.AppendCertsFromPEM(bundle) {
			return nil, ErrDirectoryConfigurationInvalid
		}
	}
	transport := &http.Transport{
		Proxy: nil, DialContext: pinnedDialContext, ForceAttemptHTTP2: true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: wantedHost},
		TLSHandshakeTimeout: adapter.requestTimeout / 2, ResponseHeaderTimeout: adapter.requestTimeout / 2,
		IdleConnTimeout: 30 * time.Second, MaxIdleConns: 10, MaxIdleConnsPerHost: 2,
	}
	return &http.Client{
		Transport: transport, Timeout: adapter.requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func (adapter *SecretBackedDirectoryAdapter) getJSON(ctx context.Context, client *http.Client, endpoint, bearer string, target any) error {
	return getDirectoryJSON(ctx, client, endpoint, bearer, target)
}

func getDirectoryJSON(ctx context.Context, client *http.Client, endpoint, bearer string, target any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ErrDirectoryConfigurationInvalid
	}
	request.Header.Set("Accept", "application/scim+json, application/json")
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := client.Do(request)
	if err != nil {
		return ErrDirectoryUpstreamRejected
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return ErrDirectoryUpstreamRejected
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/json" && mediaType != "application/scim+json") {
		return ErrDirectoryResponseInvalid
	}
	limited := io.LimitReader(response.Body, maximumDirectoryResponseBytes+1)
	contents, err := io.ReadAll(limited)
	if err != nil || strictjson.DecodeKnownBytes(contents, maximumDirectoryResponseBytes, target) != nil {
		return ErrDirectoryResponseInvalid
	}
	return nil
}

func decodeStrictJSON(contents []byte, target any) error {
	return strictjson.DecodeBytes(contents, maximumDirectorySecretBytes, target)
}

func validSigningAlgorithms(algorithms []string) bool {
	if len(algorithms) == 0 || len(algorithms) > 8 {
		return false
	}
	seen := make(map[string]struct{}, len(algorithms))
	for _, algorithm := range algorithms {
		switch algorithm {
		case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512":
		default:
			return false
		}
		if _, duplicate := seen[algorithm]; duplicate {
			return false
		}
		seen[algorithm] = struct{}{}
	}
	return true
}

func parseRSAJWK(encodedModulus, encodedExponent string) (*rsa.PublicKey, bool) {
	modulusBytes, modulusErr := base64.RawURLEncoding.DecodeString(encodedModulus)
	exponentBytes, exponentErr := base64.RawURLEncoding.DecodeString(encodedExponent)
	if modulusErr != nil || exponentErr != nil || len(modulusBytes) < 256 || len(modulusBytes) > 1024 || len(exponentBytes) == 0 || len(exponentBytes) > 4 {
		return nil, false
	}
	modulus := new(big.Int).SetBytes(modulusBytes)
	exponent := new(big.Int).SetBytes(exponentBytes)
	if modulus.BitLen() < 2048 || modulus.Bit(0) != 1 || !exponent.IsInt64() || exponent.Int64() < 3 || exponent.Int64() > 1<<31-1 || exponent.Bit(0) != 1 {
		return nil, false
	}
	return &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}, true
}

func parseECJWK(algorithm, curveName, encodedX, encodedY string) (*ecdsa.PublicKey, bool) {
	var curve elliptic.Curve
	switch {
	case algorithm == "ES256" && curveName == "P-256":
		curve = elliptic.P256()
	case algorithm == "ES384" && curveName == "P-384":
		curve = elliptic.P384()
	case algorithm == "ES512" && curveName == "P-521":
		curve = elliptic.P521()
	default:
		return nil, false
	}
	xBytes, xErr := base64.RawURLEncoding.DecodeString(encodedX)
	yBytes, yErr := base64.RawURLEncoding.DecodeString(encodedY)
	coordinateBytes := (curve.Params().BitSize + 7) / 8
	if xErr != nil || yErr != nil || len(xBytes) != coordinateBytes || len(yBytes) != coordinateBytes {
		return nil, false
	}
	x, y := new(big.Int).SetBytes(xBytes), new(big.Int).SetBytes(yBytes)
	if !curve.IsOnCurve(x, y) {
		return nil, false
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, true
}

func safeBaseURL(raw string, allowLoopbackHTTP bool) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	if parsed.Scheme != "http" || !allowLoopbackHTTP {
		return false
	}
	host := parsed.Hostname()
	return host == "localhost" || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
}

func safeRelatedURL(raw, base string, allowLoopbackHTTP bool) bool {
	if !safeBaseURL(raw, allowLoopbackHTTP) {
		return false
	}
	related, relatedErr := url.Parse(raw)
	origin, originErr := url.Parse(base)
	return relatedErr == nil && originErr == nil && related.Scheme == origin.Scheme && strings.EqualFold(related.Host, origin.Host)
}

func validSecretReference(reference string) bool {
	reference = strings.TrimSpace(reference)
	name, found := strings.CutPrefix(reference, "secret://iam/")
	return found && name != "" && len(reference) <= 256 && !strings.ContainsAny(name, `/\\`)
}

func validClaimName(claim string) bool {
	claim = strings.TrimSpace(claim)
	return claim != "" && len(claim) <= 128 && !strings.ContainsAny(claim, "\x00\r\n")
}

func validSCIMResourceTypes(resources []json.RawMessage) bool {
	foundUser, foundGroup := false, false
	seenIDs := make(map[string]struct{}, len(resources))
	for _, raw := range resources {
		var resource scimResourceType
		if strictjson.DecodeKnownBytes(raw, maximumDirectoryResponseBytes, &resource) != nil || !containsString(resource.Schemas, scimResourceTypeSchema) {
			return false
		}
		resource.ID = strings.TrimSpace(resource.ID)
		if _, duplicate := seenIDs[resource.ID]; resource.ID == "" || duplicate {
			return false
		}
		seenIDs[resource.ID] = struct{}{}
		switch {
		case resource.ID == "User" && resource.Name == "User" && resource.Endpoint == "/Users" && resource.Schema == scimUserSchema:
			foundUser = true
		case resource.ID == "Group" && resource.Name == "Group" && resource.Endpoint == "/Groups" && resource.Schema == scimGroupSchema:
			foundGroup = true
		}
	}
	return foundUser && foundGroup
}

func validateSCIMListResponse(response scimListResponse, expectedStart, pageSize int) error {
	if !containsString(response.Schemas, scimListResponseSchema) || response.TotalResults < 0 || response.StartIndex != expectedStart ||
		response.ItemsPerPage != len(response.Resources) || len(response.Resources) > pageSize || expectedStart < 1 ||
		expectedStart-1+len(response.Resources) > response.TotalResults || (expectedStart <= response.TotalResults && len(response.Resources) == 0) {
		return ErrDirectoryResponseInvalid
	}
	return nil
}

func pinSCIMTotalResults(cursor *scimCursor, totalResults int) error {
	if cursor == nil || totalResults < 0 {
		return ErrDirectoryResponseInvalid
	}
	total := &cursor.UsersTotal
	if cursor.Resource == "groups" {
		total = &cursor.GroupsTotal
	}
	if *total == nil {
		pinned := totalResults
		*total = &pinned
		return nil
	}
	if **total != totalResults {
		return ErrDirectoryResponseInvalid
	}
	return nil
}

func normalizeSCIMUsers(resources []json.RawMessage) ([]DirectoryUser, error) {
	users := make([]DirectoryUser, 0, len(resources))
	for _, raw := range resources {
		var external scimUser
		if strictjson.DecodeKnownBytes(raw, maximumDirectoryResponseBytes, &external) != nil || !containsString(external.Schemas, scimUserSchema) {
			return nil, ErrDirectoryResponseInvalid
		}
		external.ID = strings.TrimSpace(external.ID)
		username := canonicalUsername(external.UserName)
		displayName := strings.TrimSpace(external.DisplayName)
		if displayName == "" {
			displayName = username
		}
		if external.ID == "" || len(external.ID) > maximumDirectoryStringBytes || !localUsernamePattern.MatchString(username) || len([]rune(displayName)) > 256 {
			return nil, ErrDirectoryResponseInvalid
		}
		emailAddress, err := normalizedSCIMEmail(external.Emails)
		if err != nil {
			return nil, err
		}
		enabled := true
		if external.Active != nil {
			enabled = *external.Active
		}
		users = append(users, DirectoryUser{ExternalSubject: external.ID, Username: username, DisplayName: displayName, Email: emailAddress, Enabled: enabled})
	}
	return users, nil
}

func normalizeSCIMGroups(resources []json.RawMessage) ([]DirectoryOrganization, []DirectoryMembership, []DirectoryOrganizationParent, error) {
	organizations := make([]DirectoryOrganization, 0, len(resources))
	memberships := make([]DirectoryMembership, 0)
	parents := make([]DirectoryOrganizationParent, 0)
	for _, raw := range resources {
		var group scimGroup
		if strictjson.DecodeKnownBytes(raw, maximumDirectoryResponseBytes, &group) != nil || !containsString(group.Schemas, scimGroupSchema) {
			return nil, nil, nil, ErrDirectoryResponseInvalid
		}
		group.ID = strings.TrimSpace(group.ID)
		group.DisplayName = strings.TrimSpace(group.DisplayName)
		if group.ID == "" || len(group.ID) > maximumDirectoryStringBytes || group.DisplayName == "" || len([]rune(group.DisplayName)) > 256 {
			return nil, nil, nil, ErrDirectoryResponseInvalid
		}
		organizations = append(organizations, DirectoryOrganization{ExternalID: group.ID, Name: group.DisplayName})
		for _, member := range group.Members {
			member.Value = strings.TrimSpace(member.Value)
			if member.Value == "" || len(member.Value) > maximumDirectoryStringBytes {
				return nil, nil, nil, ErrDirectoryResponseInvalid
			}
			switch strings.ToLower(strings.TrimSpace(member.Type)) {
			case "user":
				memberships = append(memberships, DirectoryMembership{OrganizationExternalID: group.ID, UserExternalSubject: member.Value})
			case "group":
				parents = append(parents, DirectoryOrganizationParent{OrganizationExternalID: member.Value, ParentExternalID: group.ID})
			default:
				return nil, nil, nil, ErrDirectoryResponseInvalid
			}
		}
	}
	return organizations, memberships, parents, nil
}

func normalizedSCIMEmail(emails []struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary"`
}) (string, error) {
	first, primary := "", ""
	primaryCount := 0
	for _, candidate := range emails {
		value := strings.ToLower(strings.TrimSpace(candidate.Value))
		if value == "" {
			if candidate.Primary {
				return "", ErrDirectoryResponseInvalid
			}
			continue
		}
		address, err := mail.ParseAddress(value)
		if err != nil || address.Address != value || len(value) > 320 {
			return "", ErrDirectoryResponseInvalid
		}
		if first == "" {
			first = value
		}
		if candidate.Primary {
			primaryCount++
			primary = value
			if primaryCount > 1 {
				return "", ErrDirectoryResponseInvalid
			}
		}
	}
	if primary != "" {
		return primary, nil
	}
	return first, nil
}

func decodeSCIMCursor(encoded string) (scimCursor, error) {
	if strings.TrimSpace(encoded) == "" {
		return scimCursor{Resource: "users", StartIndex: 1}, nil
	}
	contents, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(contents) == 0 || len(contents) > 512 {
		return scimCursor{}, ErrDirectoryCursorInvalid
	}
	var cursor scimCursor
	if decodeStrictJSON(contents, &cursor) != nil || (cursor.Resource != "users" && cursor.Resource != "groups") || cursor.StartIndex < 1 || cursor.Pages < 0 || cursor.Objects < 0 ||
		(cursor.UsersTotal != nil && *cursor.UsersTotal < 0) || (cursor.GroupsTotal != nil && *cursor.GroupsTotal < 0) ||
		(cursor.Resource == "groups" && cursor.UsersTotal == nil) {
		return scimCursor{}, ErrDirectoryCursorInvalid
	}
	return cursor, nil
}

func encodeSCIMCursor(cursor scimCursor) (string, error) {
	contents, err := json.Marshal(cursor)
	if err != nil {
		return "", fmt.Errorf("encode SCIM cursor: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(contents), nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
