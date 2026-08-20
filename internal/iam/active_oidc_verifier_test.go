package iam

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"xminds-release-platform/internal/identity"
)

func TestActiveOIDCVerifierFailsClosedUnlessLoginStateNamesEnabledOIDCSource(t *testing.T) {
	t.Parallel()

	sourceID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48ea1")
	for name, testCase := range map[string]struct {
		state  LoginState
		source IdentitySource
	}{
		"local mode":       {state: LoginState{Mode: LoginModeLocal}, source: IdentitySource{ID: sourceID, Kind: IdentitySourceOIDC, Status: IdentitySourceStatusEnabled}},
		"configuring mode": {state: LoginState{Mode: LoginModeConfiguring, ActiveSourceID: sourceID}, source: IdentitySource{ID: sourceID, Kind: IdentitySourceOIDC, Status: IdentitySourceStatusEnabled}},
		"fault mode":       {state: LoginState{Mode: LoginModeFault, ActiveSourceID: sourceID}, source: IdentitySource{ID: sourceID, Kind: IdentitySourceOIDC, Status: IdentitySourceStatusFault}},
		"missing active":   {state: LoginState{Mode: LoginModeSSO}, source: IdentitySource{ID: sourceID, Kind: IdentitySourceOIDC, Status: IdentitySourceStatusEnabled}},
		"SCIM active":      {state: LoginState{Mode: LoginModeSSO, ActiveSourceID: sourceID}, source: IdentitySource{ID: sourceID, Kind: IdentitySourceSCIM, Status: IdentitySourceStatusEnabled}},
		"unknown source":   {state: LoginState{Mode: LoginModeSSO, ActiveSourceID: sourceID}, source: IdentitySource{}},
		"draft source":     {state: LoginState{Mode: LoginModeSSO, ActiveSourceID: sourceID}, source: IdentitySource{ID: sourceID, Kind: IdentitySourceOIDC, Status: IdentitySourceStatusDraft}},
		"verified source":  {state: LoginState{Mode: LoginModeSSO, ActiveSourceID: sourceID}, source: IdentitySource{ID: sourceID, Kind: IdentitySourceOIDC, Status: IdentitySourceStatusVerified}},
		"disabled source":  {state: LoginState{Mode: LoginModeSSO, ActiveSourceID: sourceID}, source: IdentitySource{ID: sourceID, Kind: IdentitySourceOIDC, Status: IdentitySourceStatusDisabled}},
		"fault source":     {state: LoginState{Mode: LoginModeSSO, ActiveSourceID: sourceID}, source: IdentitySource{ID: sourceID, Kind: IdentitySourceOIDC, Status: IdentitySourceStatusFault}},
	} {
		t.Run(name, func(t *testing.T) {
			repository := &activeOIDCStateStub{state: testCase.state, source: testCase.source}
			trusts, err := NewOIDCTrustFactory(OIDCTrustFactoryConfig{Secrets: directorySecretMap{}})
			if err != nil {
				t.Fatal(err)
			}
			verifier, err := NewActiveOIDCVerifier(ActiveOIDCVerifierConfig{Repository: repository, Trusts: trusts})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := verifier.Verify(context.Background(), "untrusted-token"); !errors.Is(err, ErrActiveOIDCAuthenticationFailed) {
				t.Fatalf("Verify() error = %v, want %v", err, ErrActiveOIDCAuthenticationFailed)
			}
			if repository.sourceReads.Load() != int32(boolToInt(testCase.state.Mode == LoginModeSSO && testCase.state.ActiveSourceID != uuid.Nil)) {
				t.Fatalf("source reads = %d", repository.sourceReads.Load())
			}
		})
	}
}

func TestActiveOIDCVerifierConcurrentFirstUseBuildsTrustOnce(t *testing.T) {
	issuer := newActiveOIDCTestIssuer(t)
	secrets := newRotatingOIDCSecrets(map[string][]byte{
		"secret://iam/active":    activeOIDCTestSecret(t, issuer.server.URL, "active-audience", "secret://iam/active-ca"),
		"secret://iam/active-ca": directoryTestServerCA(t, issuer.server),
	})
	source := IdentitySource{ID: uuid.New(), Kind: IdentitySourceOIDC, Status: IdentitySourceStatusEnabled, SecretReference: "secret://iam/active", Version: 5}
	repository := &activeOIDCStateStub{state: LoginState{Mode: LoginModeSSO, ActiveSourceID: source.ID}, source: source}
	verifier := newActiveOIDCTestVerifier(t, repository, secrets)
	token := issuer.sign(t, activeOIDCTestClaims("alice", "active-audience", "concurrent-token"))
	const callers = 16
	started := make(chan struct{})
	errorsFound := make(chan error, callers)
	var wait sync.WaitGroup
	wait.Add(callers)
	for range callers {
		go func() {
			defer wait.Done()
			<-started
			principal, err := verifier.Verify(context.Background(), token)
			if err == nil && principal.TokenID != "concurrent-token" {
				err = errors.New("wrong principal returned")
			}
			errorsFound <- err
		}()
	}
	close(started)
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatalf("concurrent Verify() error=%v", err)
		}
	}
	if calls := issuer.discoveryCalls.Load(); calls != 1 {
		t.Fatalf("discovery requests=%d, want one shared trust build", calls)
	}
}

func TestActiveOIDCVerifierEvictsOldTrustBeyondConfiguredCacheBound(t *testing.T) {
	issuers := []*activeOIDCTestIssuer{newActiveOIDCTestIssuer(t), newActiveOIDCTestIssuer(t), newActiveOIDCTestIssuer(t)}
	const sourceSecret = "secret://iam/bounded-oidc"
	const caSecret = "secret://iam/bounded-ca"
	secrets := newRotatingOIDCSecrets(nil)
	source := IdentitySource{ID: uuid.New(), Kind: IdentitySourceOIDC, Status: IdentitySourceStatusEnabled, SecretReference: sourceSecret, Version: 9}
	repository := &activeOIDCStateStub{state: LoginState{Mode: LoginModeSSO, ActiveSourceID: source.ID}, source: source}
	trusts, err := NewOIDCTrustFactory(OIDCTrustFactoryConfig{Secrets: secrets, RequestTimeout: 3 * time.Second, AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewActiveOIDCVerifier(ActiveOIDCVerifierConfig{Repository: repository, Trusts: trusts, MaximumCachedVerifiers: 2})
	if err != nil {
		t.Fatal(err)
	}
	for index, issuer := range issuers {
		audience := fmt.Sprintf("bounded-audience-%d", index)
		secrets.Replace(map[string][]byte{sourceSecret: activeOIDCTestSecret(t, issuer.server.URL, audience, caSecret), caSecret: directoryTestServerCA(t, issuer.server)})
		if _, err := verifier.Verify(context.Background(), issuer.sign(t, activeOIDCTestClaims("alice", audience, fmt.Sprintf("bounded-%d", index)))); err != nil {
			t.Fatalf("Verify(configuration %d) error=%v", index, err)
		}
	}
	secrets.Replace(map[string][]byte{sourceSecret: activeOIDCTestSecret(t, issuers[0].server.URL, "bounded-audience-0", caSecret), caSecret: directoryTestServerCA(t, issuers[0].server)})
	if _, err := verifier.Verify(context.Background(), issuers[0].sign(t, activeOIDCTestClaims("alice", "bounded-audience-0", "bounded-revisit"))); err != nil {
		t.Fatalf("Verify(evicted trust) error=%v", err)
	}
	if calls := issuers[0].discoveryCalls.Load(); calls != 2 {
		t.Fatalf("first trust discovery requests=%d, want rebuild after bounded eviction", calls)
	}
}

func TestActiveOIDCVerifierStartupValidationFailsClosedOnlyForBrokenActiveTrust(t *testing.T) {
	source := IdentitySource{ID: uuid.New(), Kind: IdentitySourceOIDC, Status: IdentitySourceStatusEnabled, SecretReference: "secret://iam/missing", Version: 1}
	localRepository := &activeOIDCStateStub{state: LoginState{Mode: LoginModeLocal}}
	localVerifier := newActiveOIDCTestVerifier(t, localRepository, directorySecretMap{})
	if err := localVerifier.Validate(context.Background()); err != nil {
		t.Fatalf("Validate(local mode) error=%v", err)
	}
	ssoRepository := &activeOIDCStateStub{state: LoginState{Mode: LoginModeSSO, ActiveSourceID: source.ID}, source: source}
	ssoVerifier := newActiveOIDCTestVerifier(t, ssoRepository, directorySecretMap{})
	if err := ssoVerifier.Validate(context.Background()); !errors.Is(err, ErrActiveOIDCAuthenticationFailed) {
		t.Fatalf("Validate(broken active trust) error=%v", err)
	}
}

func TestActiveOIDCVerifierOperationDeadlineIncludesLoginStateRead(t *testing.T) {
	trusts, err := NewOIDCTrustFactory(OIDCTrustFactoryConfig{Secrets: directorySecretMap{}, RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewActiveOIDCVerifier(ActiveOIDCVerifierConfig{Repository: blockingActiveOIDCStateReader{}, Trusts: trusts})
	if err != nil {
		t.Fatal(err)
	}
	parent, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	started := time.Now()
	if _, err := verifier.Verify(parent, "untrusted-token"); !errors.Is(err, ErrActiveOIDCAuthenticationFailed) {
		t.Fatalf("Verify(blocking state) error=%v", err)
	}
	if elapsed := time.Since(started); elapsed < 800*time.Millisecond || elapsed > 1500*time.Millisecond {
		t.Fatalf("Verify(blocking state) elapsed=%v, want unified one-second operation budget", elapsed)
	}
}

func TestOIDCTrustFactoryRequiresCanonicalTokenUseClaimForDispatcherAgreement(t *testing.T) {
	secrets := directorySecretMap{"secret://iam/oidc": []byte(`{"issuer":"https://identity.example.com","audience":"console","roles_claim":"roles","product_ids_claim":"product_ids","token_use_claim":"custom_use","signing_algorithms":["RS256"]}`)}
	trusts, err := NewOIDCTrustFactory(OIDCTrustFactoryConfig{Secrets: secrets})
	if err != nil {
		t.Fatal(err)
	}
	_, err = trusts.resolve(context.Background(), IdentitySource{ID: uuid.New(), Kind: IdentitySourceOIDC, SecretReference: "secret://iam/oidc"})
	if !errors.Is(err, ErrDirectoryConfigurationInvalid) {
		t.Fatalf("resolve(custom token use claim) error=%v", err)
	}
}

func TestActiveOIDCVerifierUsesSharedExactFieldDiscoveryValidation(t *testing.T) {
	issuer := newActiveOIDCTestIssuer(t)
	issuer.discoveryBody = []byte(fmt.Sprintf(`{"Issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q,"response_types_supported":["id_token"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]}`,
		issuer.server.URL, issuer.server.URL+"/authorize", issuer.server.URL+"/token", issuer.server.URL+"/jwks"))
	secrets := newRotatingOIDCSecrets(map[string][]byte{
		"secret://iam/active":    activeOIDCTestSecret(t, issuer.server.URL, "active-audience", "secret://iam/active-ca"),
		"secret://iam/active-ca": directoryTestServerCA(t, issuer.server),
	})
	source := IdentitySource{ID: uuid.New(), Kind: IdentitySourceOIDC, Status: IdentitySourceStatusEnabled, SecretReference: "secret://iam/active", Version: 1}
	verifier := newActiveOIDCTestVerifier(t, &activeOIDCStateStub{state: LoginState{Mode: LoginModeSSO, ActiveSourceID: source.ID}, source: source}, secrets)
	token := issuer.sign(t, activeOIDCTestClaims("alice", "active-audience", "case-alias-discovery"))
	if _, err := verifier.Verify(context.Background(), token); !errors.Is(err, ErrActiveOIDCAuthenticationFailed) {
		t.Fatalf("case-fold discovery field error=%v", err)
	}
}

func TestManagementDispatcherKeepsStaticWorkloadOIDCIndependentFromHumanLoginMode(t *testing.T) {
	issuer := newActiveOIDCTestIssuer(t)
	workloadVerifier, err := identity.NewWorkloadVerifier(context.Background(), identity.OIDCVerifierConfig{
		Issuer: issuer.server.URL, Audience: "workload-audience", HTTPClient: issuer.server.Client(), SigningAlgorithms: []string{"RS256"},
	})
	if err != nil {
		t.Fatal(err)
	}
	repository := &activeOIDCStateStub{state: LoginState{Mode: LoginModeLocal}}
	humanVerifier := newActiveOIDCTestVerifier(t, repository, directorySecretMap{})
	management, err := identity.NewManagementVerifier(
		humanVerifier,
		workloadVerifier,
		iamIdentityVerifierFunc(func(context.Context, string) (identity.Principal, error) {
			return identity.Principal{}, errors.New("unexpected API token route")
		}),
		iamIdentityVerifierFunc(func(context.Context, string) (identity.Principal, error) {
			return identity.Principal{}, errors.New("unexpected local route")
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	token := issuer.sign(t, map[string]any{
		"sub": "release-runner", "aud": "workload-audience", "jti": "workload-token", "token_use": "workload",
		"workload_provider": string(identity.WorkloadProviderGitHubActions), "roles": []string{"publisher"}, "product_ids": []string{"product-a"},
	})
	principal, err := management.Verify(context.Background(), token)
	if err != nil || principal.Kind != identity.PrincipalKindWorkload || principal.TokenID != "workload-token" {
		t.Fatalf("Verify(workload in local human mode) principal=%#v error=%v", principal, err)
	}
	if stateReads, sourceReads := repository.stateReads.Load(), repository.sourceReads.Load(); stateReads != 0 || sourceReads != 0 {
		t.Fatalf("workload token queried human state/source %d/%d times", stateReads, sourceReads)
	}
}

func TestActiveOIDCVerifierSwitchesActiveSourceWithoutCrossIssuerSubjectReuse(t *testing.T) {
	issuerA := newActiveOIDCTestIssuer(t)
	issuerB := newActiveOIDCTestIssuer(t)
	secrets := newRotatingOIDCSecrets(map[string][]byte{
		"secret://iam/oidc-a": activeOIDCTestSecret(t, issuerA.server.URL, "audience-a", "secret://iam/ca-a"),
		"secret://iam/ca-a":   directoryTestServerCA(t, issuerA.server),
		"secret://iam/oidc-b": activeOIDCTestSecret(t, issuerB.server.URL, "audience-b", "secret://iam/ca-b"),
		"secret://iam/ca-b":   directoryTestServerCA(t, issuerB.server),
	})
	sourceA := IdentitySource{ID: uuid.New(), Kind: IdentitySourceOIDC, Status: IdentitySourceStatusEnabled, SecretReference: "secret://iam/oidc-a", Version: 7}
	sourceB := IdentitySource{ID: uuid.New(), Kind: IdentitySourceOIDC, Status: IdentitySourceStatusEnabled, SecretReference: "secret://iam/oidc-b", Version: 11}
	repository := &activeOIDCStateStub{state: LoginState{Mode: LoginModeSSO, ActiveSourceID: sourceA.ID}, source: sourceA, sources: map[uuid.UUID]IdentitySource{sourceA.ID: sourceA, sourceB.ID: sourceB}}
	verifier := newActiveOIDCTestVerifier(t, repository, secrets)
	tokenA := issuerA.sign(t, activeOIDCTestClaims("same-subject", "audience-a", "token-a"))
	tokenB := issuerB.sign(t, activeOIDCTestClaims("same-subject", "audience-b", "token-b"))

	principal, err := verifier.Verify(context.Background(), tokenA)
	if err != nil || principal.Subject != "same-subject" || principal.TokenID != "token-a" || principal.IdentitySourceID != sourceA.ID.String() {
		t.Fatalf("Verify(source A) principal=%#v error=%v", principal, err)
	}
	repository.setActiveSource(sourceB.ID)
	if _, err := verifier.Verify(context.Background(), tokenA); !errors.Is(err, ErrActiveOIDCAuthenticationFailed) {
		t.Fatalf("old issuer after switch error=%v", err)
	}
	principal, err = verifier.Verify(context.Background(), tokenB)
	if err != nil || principal.Subject != "same-subject" || principal.TokenID != "token-b" || principal.IdentitySourceID != sourceB.ID.String() {
		t.Fatalf("Verify(source B) principal=%#v error=%v", principal, err)
	}
}

func TestActiveOIDCVerifierReloadsAtomicSecretRotationWithoutSourceVersionChange(t *testing.T) {
	issuerA := newActiveOIDCTestIssuer(t)
	issuerB := newActiveOIDCTestIssuer(t)
	const sourceSecret = "secret://iam/active-oidc"
	const caSecret = "secret://iam/active-ca"
	secrets := newRotatingOIDCSecrets(map[string][]byte{
		sourceSecret: activeOIDCTestSecret(t, issuerA.server.URL, "audience-a", caSecret),
		caSecret:     directoryTestServerCA(t, issuerA.server),
	})
	source := IdentitySource{ID: uuid.New(), Kind: IdentitySourceOIDC, Status: IdentitySourceStatusEnabled, SecretReference: sourceSecret, Version: 23}
	repository := &activeOIDCStateStub{state: LoginState{Mode: LoginModeSSO, ActiveSourceID: source.ID}, source: source}
	verifier := newActiveOIDCTestVerifier(t, repository, secrets)
	tokenA := issuerA.sign(t, activeOIDCTestClaims("alice", "audience-a", "before-rotation"))
	tokenB := issuerB.sign(t, activeOIDCTestClaims("alice", "audience-b", "after-rotation"))

	if _, err := verifier.Verify(context.Background(), tokenA); err != nil {
		t.Fatalf("Verify(before rotation) error=%v", err)
	}
	secrets.Replace(map[string][]byte{
		sourceSecret: activeOIDCTestSecret(t, issuerB.server.URL, "audience-b", caSecret),
		caSecret:     directoryTestServerCA(t, issuerB.server),
	})
	if _, err := verifier.Verify(context.Background(), tokenA); !errors.Is(err, ErrActiveOIDCAuthenticationFailed) {
		t.Fatalf("old token after Secret rotation error=%v", err)
	}
	principal, err := verifier.Verify(context.Background(), tokenB)
	if err != nil || principal.TokenID != "after-rotation" {
		t.Fatalf("Verify(after rotation) principal=%#v error=%v", principal, err)
	}
	if source.Version != 23 || repository.source.Version != 23 {
		t.Fatalf("Secret rotation unexpectedly changed source version: source=%d repository=%d", source.Version, repository.source.Version)
	}
}

func TestActiveOIDCVerifierRevalidatesActiveSourceAfterTokenVerification(t *testing.T) {
	issuerA := newActiveOIDCTestIssuer(t)
	issuerB := newActiveOIDCTestIssuer(t)
	issuerA.blockJWKS()
	secrets := newRotatingOIDCSecrets(map[string][]byte{
		"secret://iam/oidc-a": activeOIDCTestSecret(t, issuerA.server.URL, "audience-a", "secret://iam/ca-a"),
		"secret://iam/ca-a":   directoryTestServerCA(t, issuerA.server),
		"secret://iam/oidc-b": activeOIDCTestSecret(t, issuerB.server.URL, "audience-b", "secret://iam/ca-b"),
		"secret://iam/ca-b":   directoryTestServerCA(t, issuerB.server),
	})
	sourceA := IdentitySource{ID: uuid.New(), Kind: IdentitySourceOIDC, Status: IdentitySourceStatusEnabled, SecretReference: "secret://iam/oidc-a", Version: 3}
	sourceB := IdentitySource{ID: uuid.New(), Kind: IdentitySourceOIDC, Status: IdentitySourceStatusEnabled, SecretReference: "secret://iam/oidc-b", Version: 4}
	repository := &activeOIDCStateStub{state: LoginState{Mode: LoginModeSSO, ActiveSourceID: sourceA.ID}, sources: map[uuid.UUID]IdentitySource{sourceA.ID: sourceA, sourceB.ID: sourceB}}
	verifier := newActiveOIDCTestVerifier(t, repository, secrets)
	tokenA := issuerA.sign(t, activeOIDCTestClaims("same-subject", "audience-a", "in-flight-a"))
	result := make(chan error, 1)
	go func() {
		_, err := verifier.Verify(context.Background(), tokenA)
		result <- err
	}()
	<-issuerA.jwksStarted
	repository.setActiveSource(sourceB.ID)
	close(issuerA.releaseJWKS)
	if err := <-result; !errors.Is(err, ErrActiveOIDCAuthenticationFailed) {
		t.Fatalf("in-flight old source error=%v", err)
	}
}

func TestActiveOIDCVerifierRejectsSourceSwitchBetweenRevalidationReads(t *testing.T) {
	t.Parallel()

	sourceA := IdentitySource{
		ID: uuid.New(), Kind: IdentitySourceOIDC, Status: IdentitySourceStatusEnabled,
		SecretReference: "secret://iam/source-a", Version: 3,
	}
	sourceB := IdentitySource{ID: uuid.New(), Kind: IdentitySourceOIDC, Status: IdentitySourceStatusEnabled, Version: 4}
	secrets := directorySecretMap{
		sourceA.SecretReference: activeOIDCTestSecret(t, "https://identity.example.com", "audience-a", ""),
	}
	trusts, err := NewOIDCTrustFactory(OIDCTrustFactoryConfig{Secrets: secrets})
	if err != nil {
		t.Fatal(err)
	}
	material, err := trusts.resolve(context.Background(), sourceA)
	if err != nil {
		t.Fatal(err)
	}
	repository := &switchingBetweenActiveOIDCReads{sourceA: sourceA, sourceB: sourceB}
	verifier, err := NewActiveOIDCVerifier(ActiveOIDCVerifierConfig{Repository: repository, Trusts: trusts})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := activeOIDCTrustSnapshot{sourceID: sourceA.ID, version: sourceA.Version, digest: oidcTrustDigestText(material.digest)}

	if verifier.trustStillActive(context.Background(), snapshot) {
		t.Fatal("trust remained active after source changed between state and source reads")
	}
}

type activeOIDCStateStub struct {
	mu          sync.RWMutex
	state       LoginState
	source      IdentitySource
	stateErr    error
	sourceErr   error
	sourceReads atomic.Int32
	stateReads  atomic.Int32
	sources     map[uuid.UUID]IdentitySource
}

type blockingActiveOIDCStateReader struct{}

type switchingBetweenActiveOIDCReads struct {
	sourceA  IdentitySource
	sourceB  IdentitySource
	switched bool
}

type iamIdentityVerifierFunc func(context.Context, string) (identity.Principal, error)

func (function iamIdentityVerifierFunc) Verify(ctx context.Context, rawToken string) (identity.Principal, error) {
	return function(ctx, rawToken)
}

func (blockingActiveOIDCStateReader) GetActiveOIDCSnapshot(ctx context.Context) (LoginState, IdentitySource, error) {
	<-ctx.Done()
	return LoginState{}, IdentitySource{}, ctx.Err()
}

func (repository *switchingBetweenActiveOIDCReads) GetActiveOIDCSnapshot(context.Context) (LoginState, IdentitySource, error) {
	repository.switched = true
	return LoginState{Mode: LoginModeSSO, ActiveSourceID: repository.sourceB.ID}, repository.sourceB, nil
}

func (repository *activeOIDCStateStub) GetActiveOIDCSnapshot(context.Context) (LoginState, IdentitySource, error) {
	repository.stateReads.Add(1)
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	if repository.stateErr != nil {
		return LoginState{}, IdentitySource{}, repository.stateErr
	}
	state := repository.state
	if state.Mode != LoginModeSSO || state.ActiveSourceID == uuid.Nil {
		return state, IdentitySource{}, nil
	}
	repository.sourceReads.Add(1)
	if repository.sourceErr != nil {
		return LoginState{}, IdentitySource{}, repository.sourceErr
	}
	if repository.sources != nil {
		source, found := repository.sources[state.ActiveSourceID]
		if !found {
			return LoginState{}, IdentitySource{}, ErrIdentitySourceNotFound
		}
		return state, source, nil
	}
	if repository.source.ID != state.ActiveSourceID {
		return LoginState{}, IdentitySource{}, ErrIdentitySourceNotFound
	}
	return state, repository.source, nil
}

func (repository *activeOIDCStateStub) setActiveSource(sourceID uuid.UUID) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.state.ActiveSourceID = sourceID
}

func newActiveOIDCTestVerifier(t *testing.T, repository ActiveOIDCStateReader, secrets SecretResolver) *ActiveOIDCVerifier {
	t.Helper()
	trusts, err := NewOIDCTrustFactory(OIDCTrustFactoryConfig{Secrets: secrets, RequestTimeout: 3 * time.Second, AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewActiveOIDCVerifier(ActiveOIDCVerifierConfig{Repository: repository, Trusts: trusts, MaximumCachedVerifiers: 4})
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

type rotatingOIDCSecrets struct {
	mu     sync.RWMutex
	values map[string][]byte
}

func newRotatingOIDCSecrets(values map[string][]byte) *rotatingOIDCSecrets {
	secrets := &rotatingOIDCSecrets{}
	secrets.Replace(values)
	return secrets
}

func (secrets *rotatingOIDCSecrets) Resolve(_ context.Context, reference string) ([]byte, error) {
	secrets.mu.RLock()
	defer secrets.mu.RUnlock()
	value, found := secrets.values[reference]
	if !found {
		return nil, ErrSecretReferenceInvalid
	}
	return append([]byte(nil), value...), nil
}

func (secrets *rotatingOIDCSecrets) Replace(values map[string][]byte) {
	secrets.mu.Lock()
	defer secrets.mu.Unlock()
	secrets.values = make(map[string][]byte, len(values))
	for reference, value := range values {
		secrets.values[reference] = append([]byte(nil), value...)
	}
}

type activeOIDCTestIssuer struct {
	server         *httptest.Server
	key            *rsa.PrivateKey
	discoveryCalls atomic.Int32
	discoveryBody  []byte
	jwksStarted    chan struct{}
	releaseJWKS    chan struct{}
	jwksOnce       sync.Once
}

func newActiveOIDCTestIssuer(t *testing.T) *activeOIDCTestIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	fixture := &activeOIDCTestIssuer{key: key}
	fixture.server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/.well-known/openid-configuration":
			fixture.discoveryCalls.Add(1)
			if fixture.discoveryBody != nil {
				_, _ = writer.Write(fixture.discoveryBody)
				return
			}
			writeDirectoryTestJSON(t, writer, map[string]any{
				"issuer": fixture.server.URL, "authorization_endpoint": fixture.server.URL + "/authorize",
				"token_endpoint": fixture.server.URL + "/token", "jwks_uri": fixture.server.URL + "/jwks",
				"response_types_supported": []string{"id_token"}, "subject_types_supported": []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/jwks":
			if fixture.jwksStarted != nil {
				fixture.jwksOnce.Do(func() { close(fixture.jwksStarted) })
				<-fixture.releaseJWKS
			}
			writeDirectoryTestJSON(t, writer, map[string]any{"keys": []map[string]any{{
				"kty": "RSA", "use": "sig", "kid": "active-key", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}}})
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (issuer *activeOIDCTestIssuer) blockJWKS() {
	issuer.jwksStarted = make(chan struct{})
	issuer.releaseJWKS = make(chan struct{})
}

func (issuer *activeOIDCTestIssuer) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	now := time.Now().UTC()
	claims["iss"] = issuer.server.URL
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(5 * time.Minute).Unix()
	header := activeOIDCEncodeJWTPart(t, map[string]any{"alg": "RS256", "kid": "active-key", "typ": "JWT"})
	payload := activeOIDCEncodeJWTPart(t, claims)
	signingInput := header + "." + payload
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, issuer.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func activeOIDCEncodeJWTPart(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JWT part: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func activeOIDCTestSecret(t *testing.T, issuer, audience, caReference string) []byte {
	t.Helper()
	contents, err := json.Marshal(map[string]any{
		"issuer": issuer, "audience": audience, "roles_claim": "roles", "product_ids_claim": "product_ids",
		"token_use_claim": "token_use", "signing_algorithms": []string{"RS256"}, "ca_reference": caReference,
	})
	if err != nil {
		t.Fatal(err)
	}
	return contents
}

func activeOIDCTestClaims(subject, audience, tokenID string) map[string]any {
	return map[string]any{
		"sub": subject, "aud": audience, "jti": tokenID, "token_use": "human",
		"roles": []string{string(identity.RoleViewer)}, "product_ids": []string{"product-a"},
	}
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
