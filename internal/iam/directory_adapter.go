package iam

import (
	"bytes"
	"context"
	"crypto/elliptic"
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
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultDirectoryRequestTimeout = 10 * time.Second
	minimumDirectoryRequestTimeout = time.Second
	maximumDirectoryRequestTimeout = 30 * time.Second
	defaultDirectoryMaximumPages   = 10_000
	defaultDirectoryMaximumObjects = 100_000
	maximumDirectoryResponseBytes  = 2 * 1024 * 1024
	maximumDirectoryStringBytes    = 512

	scimListResponseSchema = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
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
	Secrets           SecretResolver
	RequestTimeout    time.Duration
	MaximumPages      int
	MaximumObjects    int
	AllowLoopbackHTTP bool
}

type SecretBackedDirectoryAdapter struct {
	secrets           SecretResolver
	requestTimeout    time.Duration
	maximumPages      int
	maximumObjects    int
	allowLoopbackHTTP bool
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
	Schemas []string `json:"schemas"`
}

type scimResourceType struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
	Schema   string `json:"schema"`
}

type scimListResponse struct {
	Schemas      []string          `json:"schemas"`
	TotalResults int               `json:"totalResults"`
	StartIndex   int               `json:"startIndex"`
	ItemsPerPage int               `json:"itemsPerPage"`
	Resources    []json.RawMessage `json:"Resources"`
}

type scimUser struct {
	ID          string `json:"id"`
	UserName    string `json:"userName"`
	DisplayName string `json:"displayName"`
	Active      *bool  `json:"active"`
	Emails      []struct {
		Value   string `json:"value"`
		Primary bool   `json:"primary"`
	} `json:"emails"`
}

type scimGroup struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Members     []struct {
		Value string `json:"value"`
		Type  string `json:"type"`
	} `json:"members"`
}

type scimCursor struct {
	Resource   string `json:"resource"`
	StartIndex int    `json:"start_index"`
	Pages      int    `json:"pages"`
	Objects    int    `json:"objects"`
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
	if config.Secrets == nil || config.RequestTimeout < minimumDirectoryRequestTimeout || config.RequestTimeout > maximumDirectoryRequestTimeout ||
		config.MaximumPages < 1 || config.MaximumPages > defaultDirectoryMaximumPages || config.MaximumObjects < 1 || config.MaximumObjects > defaultDirectoryMaximumObjects {
		return nil, ErrDirectoryConfigurationInvalid
	}
	return &SecretBackedDirectoryAdapter{
		secrets: config.Secrets, requestTimeout: config.RequestTimeout, maximumPages: config.MaximumPages,
		maximumObjects: config.MaximumObjects, allowLoopbackHTTP: config.AllowLoopbackHTTP,
	}, nil
}

func (adapter *SecretBackedDirectoryAdapter) Verify(ctx context.Context, source IdentitySource) (CapabilityReport, error) {
	if adapter == nil || adapter.secrets == nil || source.ID == [16]byte{} {
		return CapabilityReport{}, ErrDirectoryConfigurationInvalid
	}
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

func (adapter *SecretBackedDirectoryAdapter) verifyOIDC(ctx context.Context, source IdentitySource) (CapabilityReport, error) {
	configuration, client, err := adapter.loadOIDC(ctx, source)
	if err != nil {
		return CapabilityReport{}, err
	}
	var discovery oidcDiscoveryDocument
	if err := adapter.getJSON(ctx, client, configuration.Issuer+"/.well-known/openid-configuration", "", &discovery); err != nil {
		return CapabilityReport{}, err
	}
	if discovery.Issuer != configuration.Issuer || !safeRelatedURL(discovery.JWKSURI, configuration.Issuer, adapter.allowLoopbackHTTP) {
		return CapabilityReport{}, ErrDirectoryResponseInvalid
	}
	var keySet oidcJWKSet
	if err := adapter.getJSON(ctx, client, discovery.JWKSURI, "", &keySet); err != nil {
		return CapabilityReport{}, err
	}
	if !validOIDCKeySet(keySet, configuration.SigningAlgorithms) {
		return CapabilityReport{}, ErrDirectoryResponseInvalid
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
	if !containsString(providerConfiguration.Schemas, "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig") {
		return CapabilityReport{}, ErrDirectoryResponseInvalid
	}
	var resourceTypes scimListResponse
	if err := adapter.getJSON(ctx, client, configuration.BaseURL+"/ResourceTypes", bearer, &resourceTypes); err != nil {
		return CapabilityReport{}, err
	}
	if !containsString(resourceTypes.Schemas, scimListResponseSchema) || !validSCIMResourceTypes(resourceTypes.Resources) {
		return CapabilityReport{}, ErrDirectoryResponseInvalid
	}
	return CapabilityReport{
		Reachable: true, RequiredAttributes: []string{"subject", "display_name", "email", "organizations"},
		RequiredMappingsComplete: source.RequiredMappingsComplete, SupportsPagination: true,
	}, nil
}

func (adapter *SecretBackedDirectoryAdapter) loadOIDC(ctx context.Context, source IdentitySource) (oidcDirectorySecret, *http.Client, error) {
	contents, err := adapter.secrets.Resolve(ctx, source.SecretReference)
	if err != nil {
		return oidcDirectorySecret{}, nil, ErrDirectoryConfigurationInvalid
	}
	var configuration oidcDirectorySecret
	if err := decodeStrictJSON(contents, &configuration); err != nil || strings.TrimSpace(configuration.Audience) == "" ||
		!validClaimName(configuration.RolesClaim) || !validClaimName(configuration.ProductIDsClaim) || !validClaimName(configuration.TokenUseClaim) ||
		!validSigningAlgorithms(configuration.SigningAlgorithms) || !safeBaseURL(configuration.Issuer, adapter.allowLoopbackHTTP) {
		return oidcDirectorySecret{}, nil, ErrDirectoryConfigurationInvalid
	}
	configuration.Issuer = strings.TrimSuffix(strings.TrimSpace(configuration.Issuer), "/")
	client, err := adapter.newHTTPClient(ctx, configuration.CAReference)
	return configuration, client, err
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
	client, err := adapter.newHTTPClient(ctx, configuration.CAReference)
	if err != nil {
		return scimDirectorySecret{}, "", nil, err
	}
	return configuration, string(bytes.TrimSpace(bearer)), client, nil
}

func (adapter *SecretBackedDirectoryAdapter) newHTTPClient(ctx context.Context, caReference string) (*http.Client, error) {
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
	dialer := &net.Dialer{Timeout: adapter.requestTimeout / 2, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout: adapter.requestTimeout / 2, ResponseHeaderTimeout: adapter.requestTimeout / 2,
		IdleConnTimeout: 30 * time.Second, MaxIdleConns: 10, MaxIdleConnsPerHost: 2,
	}
	return &http.Client{
		Transport: transport, Timeout: adapter.requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func (adapter *SecretBackedDirectoryAdapter) getJSON(ctx context.Context, client *http.Client, endpoint, bearer string, target any) error {
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
	if err != nil || len(contents) == 0 || len(contents) > maximumDirectoryResponseBytes || !json.Valid(contents) {
		return ErrDirectoryResponseInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := decoder.Decode(target); err != nil {
		return ErrDirectoryResponseInvalid
	}
	return nil
}

func decodeStrictJSON(contents []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrDirectoryConfigurationInvalid
	}
	return nil
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

func validOIDCKeySet(keySet oidcJWKSet, algorithms []string) bool {
	allowed := make(map[string]struct{}, len(algorithms))
	for _, algorithm := range algorithms {
		allowed[algorithm] = struct{}{}
	}
	for _, key := range keySet.Keys {
		_, algorithmAllowed := allowed[key.Alg]
		if !algorithmAllowed || strings.TrimSpace(key.KeyID) == "" || (key.Use != "" && key.Use != "sig") {
			continue
		}
		if (strings.HasPrefix(key.Alg, "RS") || strings.HasPrefix(key.Alg, "PS")) && key.KeyType == "RSA" && validRSAJWK(key.Modulus, key.Exponent) {
			return true
		}
		if strings.HasPrefix(key.Alg, "ES") && key.KeyType == "EC" && validECJWK(key.Alg, key.Curve, key.X, key.Y) {
			return true
		}
	}
	return false
}

func validRSAJWK(encodedModulus, encodedExponent string) bool {
	modulusBytes, modulusErr := base64.RawURLEncoding.DecodeString(encodedModulus)
	exponentBytes, exponentErr := base64.RawURLEncoding.DecodeString(encodedExponent)
	if modulusErr != nil || exponentErr != nil || len(modulusBytes) < 256 || len(modulusBytes) > 1024 || len(exponentBytes) == 0 || len(exponentBytes) > 4 {
		return false
	}
	modulus := new(big.Int).SetBytes(modulusBytes)
	exponent := new(big.Int).SetBytes(exponentBytes)
	return modulus.BitLen() >= 2048 && modulus.Bit(0) == 1 && exponent.IsInt64() && exponent.Int64() >= 3 && exponent.Int64() <= 1<<31-1 && exponent.Bit(0) == 1
}

func validECJWK(algorithm, curveName, encodedX, encodedY string) bool {
	var curve elliptic.Curve
	switch {
	case algorithm == "ES256" && curveName == "P-256":
		curve = elliptic.P256()
	case algorithm == "ES384" && curveName == "P-384":
		curve = elliptic.P384()
	case algorithm == "ES512" && curveName == "P-521":
		curve = elliptic.P521()
	default:
		return false
	}
	xBytes, xErr := base64.RawURLEncoding.DecodeString(encodedX)
	yBytes, yErr := base64.RawURLEncoding.DecodeString(encodedY)
	coordinateBytes := (curve.Params().BitSize + 7) / 8
	if xErr != nil || yErr != nil || len(xBytes) != coordinateBytes || len(yBytes) != coordinateBytes {
		return false
	}
	return curve.IsOnCurve(new(big.Int).SetBytes(xBytes), new(big.Int).SetBytes(yBytes))
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
	for _, raw := range resources {
		var resource scimResourceType
		if json.Unmarshal(raw, &resource) != nil {
			return false
		}
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

func normalizeSCIMUsers(resources []json.RawMessage) ([]DirectoryUser, error) {
	users := make([]DirectoryUser, 0, len(resources))
	for _, raw := range resources {
		var external scimUser
		if json.Unmarshal(raw, &external) != nil {
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
		if json.Unmarshal(raw, &group) != nil {
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
			if member.Value == "" || len(member.Value) > maximumDirectoryStringBytes || member.Value == group.ID {
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
	selected := ""
	for _, candidate := range emails {
		value := strings.ToLower(strings.TrimSpace(candidate.Value))
		if value == "" {
			continue
		}
		address, err := mail.ParseAddress(value)
		if err != nil || address.Address != value || len(value) > 320 {
			return "", ErrDirectoryResponseInvalid
		}
		if selected == "" || candidate.Primary {
			selected = value
		}
		if candidate.Primary {
			break
		}
	}
	return selected, nil
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
	if decodeStrictJSON(contents, &cursor) != nil || (cursor.Resource != "users" && cursor.Resource != "groups") || cursor.StartIndex < 1 || cursor.Pages < 0 || cursor.Objects < 0 {
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
