package iam

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/egress"
)

// OIDCTrustFactoryConfig defines the single trust boundary used by directory
// verification and active human OIDC authentication.
type OIDCTrustFactoryConfig struct {
	Secrets                SecretResolver
	Resolver               egress.IPResolver
	Dialer                 egress.Dialer
	RequestTimeout         time.Duration
	AllowLoopbackHTTP      bool
	AllowedPrivatePrefixes []netip.Prefix
}

type OIDCTrustFactory struct {
	secrets                SecretResolver
	resolver               egress.IPResolver
	dialer                 egress.Dialer
	requestTimeout         time.Duration
	allowLoopbackHTTP      bool
	allowedPrivatePrefixes []netip.Prefix
}

type oidcTrustMaterial struct {
	configuration oidcDirectorySecret
	caBundle      []byte
	digest        [sha256.Size]byte
}

func NewOIDCTrustFactory(config OIDCTrustFactoryConfig) (*OIDCTrustFactory, error) {
	if config.RequestTimeout == 0 {
		config.RequestTimeout = defaultDirectoryRequestTimeout
	}
	if config.Resolver == nil {
		config.Resolver = net.DefaultResolver
	}
	if config.Dialer == nil {
		config.Dialer = &net.Dialer{Timeout: config.RequestTimeout / 2, KeepAlive: 30 * time.Second}
	}
	if config.Secrets == nil || config.RequestTimeout < minimumDirectoryRequestTimeout || config.RequestTimeout > maximumDirectoryRequestTimeout {
		return nil, ErrDirectoryConfigurationInvalid
	}
	return &OIDCTrustFactory{
		secrets: config.Secrets, resolver: config.Resolver, dialer: config.Dialer, requestTimeout: config.RequestTimeout,
		allowLoopbackHTTP: config.AllowLoopbackHTTP, allowedPrivatePrefixes: append([]netip.Prefix(nil), config.AllowedPrivatePrefixes...),
	}, nil
}

func (factory *OIDCTrustFactory) operationContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil || factory == nil || factory.requestTimeout <= 0 {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx, func() {}
	}
	return context.WithTimeout(parent, factory.requestTimeout)
}

func (factory *OIDCTrustFactory) resolve(ctx context.Context, source IdentitySource) (oidcTrustMaterial, error) {
	if factory == nil || factory.secrets == nil || source.ID == [16]byte{} || source.Kind != IdentitySourceOIDC {
		return oidcTrustMaterial{}, ErrDirectoryConfigurationInvalid
	}
	contents, err := factory.secrets.Resolve(ctx, source.SecretReference)
	if err != nil {
		return oidcTrustMaterial{}, ErrDirectoryConfigurationInvalid
	}
	var configuration oidcDirectorySecret
	if err := decodeStrictJSON(contents, &configuration); err != nil || strings.TrimSpace(configuration.Audience) == "" ||
		!validClaimName(configuration.RolesClaim) || !validClaimName(configuration.ProductIDsClaim) || configuration.TokenUseClaim != "token_use" ||
		!validSigningAlgorithms(configuration.SigningAlgorithms) || !safeBaseURL(configuration.Issuer, factory.allowLoopbackHTTP) {
		return oidcTrustMaterial{}, ErrDirectoryConfigurationInvalid
	}
	configuration.Issuer = strings.TrimSuffix(strings.TrimSpace(configuration.Issuer), "/")
	var caBundle []byte
	if strings.TrimSpace(configuration.CAReference) != "" {
		if !validSecretReference(configuration.CAReference) {
			return oidcTrustMaterial{}, ErrDirectoryConfigurationInvalid
		}
		caBundle, err = factory.secrets.Resolve(ctx, configuration.CAReference)
		if err != nil {
			return oidcTrustMaterial{}, ErrDirectoryConfigurationInvalid
		}
	}
	digestInput := make([]byte, 0, len(contents)+len(caBundle)+1)
	digestInput = append(digestInput, contents...)
	digestInput = append(digestInput, 0)
	digestInput = append(digestInput, caBundle...)
	return oidcTrustMaterial{configuration: configuration, caBundle: caBundle, digest: sha256.Sum256(digestInput)}, nil
}

func (factory *OIDCTrustFactory) client(ctx context.Context, material oidcTrustMaterial) (*http.Client, error) {
	configuration := material.configuration
	parsedBase, err := url.Parse(configuration.Issuer)
	if err != nil || parsedBase.Hostname() == "" {
		return nil, ErrDirectoryConfigurationInvalid
	}
	wantedHost := strings.ToLower(strings.TrimSuffix(parsedBase.Hostname(), "."))
	addresses, err := egress.ResolvePinnedAddresses(ctx, factory.resolver, wantedHost, egress.Policy{
		AllowLoopback: factory.allowLoopbackHTTP, AllowedPrivatePrefixes: factory.allowedPrivatePrefixes,
	})
	if err != nil {
		return nil, ErrDirectoryConfigurationInvalid
	}
	pinnedDialContext, err := egress.NewPinnedDialContext(wantedHost, addresses, factory.dialer)
	if err != nil {
		return nil, ErrDirectoryConfigurationInvalid
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if len(material.caBundle) > 0 && !roots.AppendCertsFromPEM(material.caBundle) {
		return nil, ErrDirectoryConfigurationInvalid
	}
	transport := &http.Transport{
		Proxy: nil, DialContext: pinnedDialContext, ForceAttemptHTTP2: true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: wantedHost},
		TLSHandshakeTimeout: factory.requestTimeout / 2, ResponseHeaderTimeout: factory.requestTimeout / 2,
		IdleConnTimeout: 30 * time.Second, MaxIdleConns: 10, MaxIdleConnsPerHost: 2,
	}
	return &http.Client{
		Transport: transport, Timeout: factory.requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func (factory *OIDCTrustFactory) humanVerifier(ctx context.Context, material oidcTrustMaterial) (identity.Verifier, error) {
	client, jwksURL, prefetchedKeys, err := factory.prepare(ctx, material)
	if err != nil {
		return nil, err
	}
	configuration := material.configuration
	keySet, err := newBoundedOIDCKeySet(client, jwksURL, configuration.SigningAlgorithms, prefetchedKeys, factory.requestTimeout)
	if err != nil {
		return nil, ErrDirectoryResponseInvalid
	}
	verifier, err := identity.NewOIDCVerifier(ctx, identity.OIDCVerifierConfig{
		Issuer: configuration.Issuer, Audience: configuration.Audience, RolesClaim: configuration.RolesClaim,
		ProductIDsClaim: configuration.ProductIDsClaim, TokenUseClaim: configuration.TokenUseClaim,
		SigningAlgorithms: append([]string(nil), configuration.SigningAlgorithms...), HTTPClient: client, KeySet: keySet,
	})
	if err != nil {
		return nil, ErrDirectoryUpstreamRejected
	}
	return verifier, nil
}

func (factory *OIDCTrustFactory) prepare(ctx context.Context, material oidcTrustMaterial) (*http.Client, string, oidcJWKSet, error) {
	client, err := factory.client(ctx, material)
	if err != nil {
		return nil, "", oidcJWKSet{}, err
	}
	configuration := material.configuration
	var discovery oidcDiscoveryDocument
	if err := getDirectoryJSON(ctx, client, configuration.Issuer+"/.well-known/openid-configuration", "", &discovery); err != nil {
		return nil, "", oidcJWKSet{}, err
	}
	if discovery.Issuer != configuration.Issuer || !safeRelatedURL(discovery.JWKSURI, configuration.Issuer, factory.allowLoopbackHTTP) {
		return nil, "", oidcJWKSet{}, ErrDirectoryResponseInvalid
	}
	var keySet oidcJWKSet
	if err := getDirectoryJSON(ctx, client, discovery.JWKSURI, "", &keySet); err != nil {
		return nil, "", oidcJWKSet{}, err
	}
	allowedAlgorithms, err := oidcAllowedAlgorithms(configuration.SigningAlgorithms)
	if err != nil {
		return nil, "", oidcJWKSet{}, ErrDirectoryResponseInvalid
	}
	if _, err := parseOIDCVerificationKeys(keySet, allowedAlgorithms); err != nil {
		return nil, "", oidcJWKSet{}, ErrDirectoryResponseInvalid
	}
	return client, discovery.JWKSURI, keySet, nil
}

func oidcTrustDigestText(digest [sha256.Size]byte) string {
	return hex.EncodeToString(digest[:])
}
