package iam

import (
	"context"
	"crypto"
	"errors"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	maximumOIDCVerificationKeys = 128
	maximumOIDCKeyIDBytes       = 128
	maximumOIDCNegativeKeyIDs   = 128
	oidcNegativeKeyIDTTL        = 5 * time.Second
	oidcRefreshSuccessCooldown  = 5 * time.Second
	oidcRefreshFailureBase      = time.Second
	oidcRefreshFailureMaximum   = 30 * time.Second
	oidcRefreshJitterDivisor    = 4
)

var errOIDCKeySetRejected = errors.New("OIDC key set rejected")

type boundedOIDCKeySet struct {
	client     *http.Client
	jwksURL    string
	algorithms []jose.SignatureAlgorithm
	allowed    map[string]struct{}
	now        func() time.Time
	// refreshTimeout bounds the shared refresh independently of any waiter.
	refreshTimeout time.Duration

	mu                 sync.RWMutex
	keys               map[string]oidcVerificationKey
	negative           map[string]time.Time
	negativeOrder      []string
	refreshing         *oidcKeyRefresh
	nextAllowedRefresh time.Time
	refreshFailures    int
	refreshJitter      func(time.Duration) time.Duration
}

type oidcVerificationKey struct {
	algorithm string
	publicKey crypto.PublicKey
}

type oidcKeyRefresh struct {
	done chan struct{}
	err  error
}

func newBoundedOIDCKeySet(client *http.Client, jwksURL string, algorithms []string, initial oidcJWKSet, refreshTimeout time.Duration) (*boundedOIDCKeySet, error) {
	if client == nil || strings.TrimSpace(jwksURL) == "" || len(algorithms) == 0 || refreshTimeout <= 0 {
		return nil, errOIDCKeySetRejected
	}
	allowed, err := oidcAllowedAlgorithms(algorithms)
	if err != nil {
		return nil, err
	}
	joseAlgorithms := make([]jose.SignatureAlgorithm, 0, len(algorithms))
	for _, algorithm := range algorithms {
		joseAlgorithms = append(joseAlgorithms, jose.SignatureAlgorithm(algorithm))
	}
	keys, err := parseOIDCVerificationKeys(initial, allowed)
	if err != nil {
		return nil, err
	}
	return &boundedOIDCKeySet{
		client: client, jwksURL: jwksURL, algorithms: joseAlgorithms, allowed: allowed, now: time.Now,
		refreshTimeout: refreshTimeout, keys: keys, negative: make(map[string]time.Time), refreshJitter: randomOIDCRefreshJitter,
	}, nil
}

func oidcAllowedAlgorithms(algorithms []string) (map[string]struct{}, error) {
	if len(algorithms) == 0 {
		return nil, errOIDCKeySetRejected
	}
	allowed := make(map[string]struct{}, len(algorithms))
	for _, algorithm := range algorithms {
		if strings.TrimSpace(algorithm) != algorithm || algorithm == "" {
			return nil, errOIDCKeySetRejected
		}
		if _, duplicate := allowed[algorithm]; duplicate {
			return nil, errOIDCKeySetRejected
		}
		allowed[algorithm] = struct{}{}
	}
	return allowed, nil
}

func (keySet *boundedOIDCKeySet) VerifySignature(ctx context.Context, rawJWT string) ([]byte, error) {
	if keySet == nil || keySet.client == nil || ctx == nil || len(rawJWT) == 0 {
		return nil, errOIDCKeySetRejected
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	signature, err := jose.ParseSigned(rawJWT, keySet.algorithms)
	if err != nil || len(signature.Signatures) != 1 {
		return nil, errOIDCKeySetRejected
	}
	header := signature.Signatures[0].Header
	keyID := header.KeyID
	if len(keyID) == 0 || len(keyID) > maximumOIDCKeyIDBytes {
		return nil, errOIDCKeySetRejected
	}
	payload, found, verified := keySet.verifyCached(signature, keyID, header.Algorithm)
	if found && verified {
		return payload, nil
	}
	if !found && keySet.negativeCached(keyID) {
		return nil, errOIDCKeySetRejected
	}
	if err := keySet.refresh(ctx, keyID, found); err != nil {
		return nil, err
	}
	if payload, found, verified = keySet.verifyCached(signature, keyID, header.Algorithm); found && verified {
		return payload, nil
	}
	if !found {
		keySet.rememberNegative(keyID)
	}
	return nil, errOIDCKeySetRejected
}

func (keySet *boundedOIDCKeySet) verifyCached(signature *jose.JSONWebSignature, keyID, algorithm string) ([]byte, bool, bool) {
	keySet.mu.RLock()
	key, found := keySet.keys[keyID]
	keySet.mu.RUnlock()
	if !found {
		return nil, false, false
	}
	if key.algorithm != algorithm {
		return nil, true, false
	}
	payload, err := signature.Verify(key.publicKey)
	return payload, true, err == nil
}

func (keySet *boundedOIDCKeySet) negativeCached(keyID string) bool {
	now := keySet.now()
	keySet.mu.Lock()
	defer keySet.mu.Unlock()
	expiresAt, found := keySet.negative[keyID]
	if !found {
		return false
	}
	if !expiresAt.After(now) {
		delete(keySet.negative, keyID)
		keySet.removeNegativeOrder(keyID)
		return false
	}
	return true
}

func (keySet *boundedOIDCKeySet) refresh(ctx context.Context, wantedKeyID string, force bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	keySet.mu.Lock()
	if _, available := keySet.keys[wantedKeyID]; available && !force {
		keySet.mu.Unlock()
		return nil
	}
	if current := keySet.refreshing; current != nil {
		keySet.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-current.done:
			return current.err
		}
	}
	if keySet.nextAllowedRefresh.After(keySet.now()) {
		keySet.mu.Unlock()
		return errOIDCKeySetRejected
	}
	refresh := &oidcKeyRefresh{done: make(chan struct{})}
	keySet.refreshing = refresh
	keySet.mu.Unlock()
	go keySet.executeRefresh(refresh)
	return waitForOIDCKeyRefresh(ctx, refresh)
}

func (keySet *boundedOIDCKeySet) executeRefresh(refresh *oidcKeyRefresh) {
	ctx, cancel := context.WithTimeout(context.Background(), keySet.refreshTimeout)
	defer cancel()
	keys, err := keySet.fetch(ctx)

	keySet.mu.Lock()
	if err == nil {
		keySet.keys = keys
		keySet.negative = make(map[string]time.Time)
		keySet.negativeOrder = nil
		keySet.refreshFailures = 0
		keySet.nextAllowedRefresh = keySet.now().Add(keySet.refreshDelay(oidcRefreshSuccessCooldown))
	} else {
		if keySet.refreshFailures < 32 {
			keySet.refreshFailures++
		}
		keySet.nextAllowedRefresh = keySet.now().Add(keySet.refreshDelay(oidcRefreshFailureBackoff(keySet.refreshFailures)))
	}
	refresh.err = err
	keySet.refreshing = nil
	close(refresh.done)
	keySet.mu.Unlock()
}

func waitForOIDCKeyRefresh(ctx context.Context, refresh *oidcKeyRefresh) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-refresh.done:
		return refresh.err
	}
}

func (keySet *boundedOIDCKeySet) refreshDelay(base time.Duration) time.Duration {
	maximumJitter := base / oidcRefreshJitterDivisor
	if maximumJitter <= 0 || keySet.refreshJitter == nil {
		return base
	}
	jitter := keySet.refreshJitter(maximumJitter)
	if jitter < 0 {
		jitter = 0
	}
	if jitter > maximumJitter {
		jitter = maximumJitter
	}
	return base + jitter
}

func oidcRefreshFailureBackoff(failures int) time.Duration {
	delay := oidcRefreshFailureBase
	for step := 1; step < failures && delay < oidcRefreshFailureMaximum; step++ {
		if delay > oidcRefreshFailureMaximum/2 {
			return oidcRefreshFailureMaximum
		}
		delay *= 2
	}
	if delay > oidcRefreshFailureMaximum {
		return oidcRefreshFailureMaximum
	}
	return delay
}

func randomOIDCRefreshJitter(maximum time.Duration) time.Duration {
	if maximum <= 0 {
		return 0
	}
	return time.Duration(rand.Uint64N(uint64(maximum) + 1))
}

func (keySet *boundedOIDCKeySet) fetch(ctx context.Context) (map[string]oidcVerificationKey, error) {
	var response oidcJWKSet
	if err := getDirectoryJSON(ctx, keySet.client, keySet.jwksURL, "", &response); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	return parseOIDCVerificationKeys(response, keySet.allowed)
}

func (keySet *boundedOIDCKeySet) rememberNegative(keyID string) {
	keySet.mu.Lock()
	defer keySet.mu.Unlock()
	if _, found := keySet.negative[keyID]; !found {
		for len(keySet.negative) >= maximumOIDCNegativeKeyIDs && len(keySet.negativeOrder) > 0 {
			oldest := keySet.negativeOrder[0]
			keySet.negativeOrder = keySet.negativeOrder[1:]
			delete(keySet.negative, oldest)
		}
		if len(keySet.negative) >= maximumOIDCNegativeKeyIDs {
			keySet.negative = make(map[string]time.Time)
			keySet.negativeOrder = nil
		}
		keySet.negativeOrder = append(keySet.negativeOrder, keyID)
	}
	keySet.negative[keyID] = keySet.now().Add(oidcNegativeKeyIDTTL)
}

func (keySet *boundedOIDCKeySet) removeNegativeOrder(keyID string) {
	for index, cachedKeyID := range keySet.negativeOrder {
		if cachedKeyID == keyID {
			keySet.negativeOrder = append(keySet.negativeOrder[:index], keySet.negativeOrder[index+1:]...)
			return
		}
	}
}

func parseOIDCVerificationKeys(keySet oidcJWKSet, allowed map[string]struct{}) (map[string]oidcVerificationKey, error) {
	if len(keySet.Keys) == 0 || len(keySet.Keys) > maximumOIDCVerificationKeys {
		return nil, errOIDCKeySetRejected
	}
	keys := make(map[string]oidcVerificationKey, len(keySet.Keys))
	for _, key := range keySet.Keys {
		if _, permitted := allowed[key.Alg]; !permitted || key.Use != "" && key.Use != "sig" {
			continue
		}
		keyID := strings.TrimSpace(key.KeyID)
		if keyID == "" || keyID != key.KeyID || len(keyID) > maximumOIDCKeyIDBytes {
			return nil, errOIDCKeySetRejected
		}
		if _, duplicate := keys[keyID]; duplicate {
			return nil, errOIDCKeySetRejected
		}
		var publicKey crypto.PublicKey
		var valid bool
		switch {
		case (strings.HasPrefix(key.Alg, "RS") || strings.HasPrefix(key.Alg, "PS")) && key.KeyType == "RSA":
			publicKey, valid = parseRSAJWK(key.Modulus, key.Exponent)
		case strings.HasPrefix(key.Alg, "ES") && key.KeyType == "EC":
			publicKey, valid = parseECJWK(key.Alg, key.Curve, key.X, key.Y)
		}
		if !valid {
			return nil, errOIDCKeySetRejected
		}
		keys[keyID] = oidcVerificationKey{algorithm: key.Alg, publicKey: publicKey}
	}
	if len(keys) == 0 {
		return nil, errOIDCKeySetRejected
	}
	return keys, nil
}
