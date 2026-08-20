package iam

import (
	"context"
	"errors"
	"strconv"
	"sync"

	"github.com/google/uuid"

	"xminds-release-platform/internal/identity"
)

var (
	ErrActiveOIDCVerifierConfiguration = errors.New("active OIDC verifier configuration is invalid")
	ErrActiveOIDCAuthenticationFailed  = errors.New("active OIDC authentication failed")
)

type ActiveOIDCStateReader interface {
	GetActiveOIDCSnapshot(ctx context.Context) (LoginState, IdentitySource, error)
}

type ActiveOIDCVerifierConfig struct {
	Repository             ActiveOIDCStateReader
	Trusts                 *OIDCTrustFactory
	MaximumCachedVerifiers int
}

type ActiveOIDCVerifier struct {
	repository ActiveOIDCStateReader
	trusts     *OIDCTrustFactory
	maximum    int
	mu         sync.Mutex
	sequence   uint64
	cache      map[string]activeOIDCCacheEntry
	building   map[string]*activeOIDCBuild
}

type activeOIDCCacheEntry struct {
	verifier identity.Verifier
	used     uint64
}

type activeOIDCBuild struct {
	done     chan struct{}
	verifier identity.Verifier
	err      error
}

type activeOIDCTrustSnapshot struct {
	sourceID uuid.UUID
	version  int64
	digest   string
}

func NewActiveOIDCVerifier(config ActiveOIDCVerifierConfig) (*ActiveOIDCVerifier, error) {
	if config.MaximumCachedVerifiers == 0 {
		config.MaximumCachedVerifiers = 16
	}
	if config.Repository == nil || config.Trusts == nil || config.MaximumCachedVerifiers < 1 || config.MaximumCachedVerifiers > 128 {
		return nil, ErrActiveOIDCVerifierConfiguration
	}
	return &ActiveOIDCVerifier{
		repository: config.Repository, trusts: config.Trusts, maximum: config.MaximumCachedVerifiers,
		cache: make(map[string]activeOIDCCacheEntry), building: make(map[string]*activeOIDCBuild),
	}, nil
}

func (verifier *ActiveOIDCVerifier) Verify(ctx context.Context, rawToken string) (identity.Principal, error) {
	if verifier == nil || verifier.repository == nil || verifier.trusts == nil {
		return identity.Principal{}, ErrActiveOIDCVerifierConfiguration
	}
	ctx, cancel := verifier.trusts.operationContext(ctx)
	defer cancel()
	trustedVerifier, snapshot, err := verifier.activeTrust(ctx)
	if err != nil {
		return identity.Principal{}, err
	}
	principal, err := trustedVerifier.Verify(ctx, rawToken)
	if err != nil || principal.Kind != identity.PrincipalKindHuman {
		return identity.Principal{}, ErrActiveOIDCAuthenticationFailed
	}
	if !verifier.trustStillActive(ctx, snapshot) {
		return identity.Principal{}, ErrActiveOIDCAuthenticationFailed
	}
	principal.IdentitySourceID = snapshot.sourceID.String()
	return principal, nil
}

// Validate checks the currently active trust during startup without requiring
// an end-user token. Local/configuring/fault modes remain bootable for recovery.
func (verifier *ActiveOIDCVerifier) Validate(ctx context.Context) error {
	if verifier == nil || verifier.repository == nil || verifier.trusts == nil {
		return ErrActiveOIDCVerifierConfiguration
	}
	ctx, cancel := verifier.trusts.operationContext(ctx)
	defer cancel()
	state, source, err := verifier.repository.GetActiveOIDCSnapshot(ctx)
	if err != nil {
		return ErrActiveOIDCAuthenticationFailed
	}
	if state.Mode != LoginModeSSO {
		return nil
	}
	_, _, err = verifier.activeTrustForSnapshot(ctx, state, source)
	return err
}

func (verifier *ActiveOIDCVerifier) activeTrust(ctx context.Context) (identity.Verifier, activeOIDCTrustSnapshot, error) {
	state, source, err := verifier.repository.GetActiveOIDCSnapshot(ctx)
	if err != nil || state.Mode != LoginModeSSO || state.ActiveSourceID == uuid.Nil {
		return nil, activeOIDCTrustSnapshot{}, ErrActiveOIDCAuthenticationFailed
	}
	return verifier.activeTrustForSnapshot(ctx, state, source)
}

func (verifier *ActiveOIDCVerifier) activeTrustForSnapshot(ctx context.Context, state LoginState, source IdentitySource) (identity.Verifier, activeOIDCTrustSnapshot, error) {
	if state.Mode != LoginModeSSO || state.ActiveSourceID == uuid.Nil {
		return nil, activeOIDCTrustSnapshot{}, ErrActiveOIDCAuthenticationFailed
	}
	if source.ID != state.ActiveSourceID || source.Kind != IdentitySourceOIDC || source.Status != IdentitySourceStatusEnabled {
		return nil, activeOIDCTrustSnapshot{}, ErrActiveOIDCAuthenticationFailed
	}
	material, err := verifier.trusts.resolve(ctx, source)
	if err != nil {
		return nil, activeOIDCTrustSnapshot{}, ErrActiveOIDCAuthenticationFailed
	}
	trustedVerifier, err := verifier.verifierFor(ctx, source, material)
	if err != nil {
		return nil, activeOIDCTrustSnapshot{}, ErrActiveOIDCAuthenticationFailed
	}
	return trustedVerifier, activeOIDCTrustSnapshot{sourceID: source.ID, version: source.Version, digest: oidcTrustDigestText(material.digest)}, nil
}

func (verifier *ActiveOIDCVerifier) trustStillActive(ctx context.Context, snapshot activeOIDCTrustSnapshot) bool {
	state, source, err := verifier.repository.GetActiveOIDCSnapshot(ctx)
	if err != nil || state.Mode != LoginModeSSO || state.ActiveSourceID != snapshot.sourceID {
		return false
	}
	if source.ID != snapshot.sourceID || source.Kind != IdentitySourceOIDC || source.Status != IdentitySourceStatusEnabled || source.Version != snapshot.version {
		return false
	}
	material, err := verifier.trusts.resolve(ctx, source)
	return err == nil && oidcTrustDigestText(material.digest) == snapshot.digest
}

func (verifier *ActiveOIDCVerifier) verifierFor(ctx context.Context, source IdentitySource, material oidcTrustMaterial) (identity.Verifier, error) {
	key := source.ID.String() + ":" + strconv.FormatInt(source.Version, 10) + ":" + oidcTrustDigestText(material.digest)
	verifier.mu.Lock()
	if cached, found := verifier.cache[key]; found {
		verifier.sequence++
		cached.used = verifier.sequence
		verifier.cache[key] = cached
		verifier.mu.Unlock()
		return cached.verifier, nil
	}
	if build, found := verifier.building[key]; found {
		verifier.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-build.done:
			return build.verifier, build.err
		}
	}
	build := &activeOIDCBuild{done: make(chan struct{})}
	verifier.building[key] = build
	verifier.mu.Unlock()

	built, err := verifier.trusts.humanVerifier(ctx, material)
	verifier.mu.Lock()
	build.verifier, build.err = built, err
	delete(verifier.building, key)
	if err == nil {
		verifier.sequence++
		verifier.cache[key] = activeOIDCCacheEntry{verifier: built, used: verifier.sequence}
		verifier.evictOldestLocked()
	}
	close(build.done)
	verifier.mu.Unlock()
	return built, err
}

func (verifier *ActiveOIDCVerifier) evictOldestLocked() {
	for len(verifier.cache) > verifier.maximum {
		oldestKey := ""
		var oldestUse uint64
		for key, entry := range verifier.cache {
			if oldestKey == "" || entry.used < oldestUse {
				oldestKey, oldestUse = key, entry.used
			}
		}
		delete(verifier.cache, oldestKey)
	}
}
