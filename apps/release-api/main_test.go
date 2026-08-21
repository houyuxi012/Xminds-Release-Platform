package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/iam"
	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/buildinfo"
	"xminds-release-platform/internal/platform/config"
	"xminds-release-platform/internal/platform/httpserver"
	"xminds-release-platform/internal/product"
)

func TestRunRequiresExplicitCommand(t *testing.T) {
	t.Parallel()

	err := run(context.Background(), nil, map[string]string{})
	if !errors.Is(err, errUsage) {
		t.Fatalf("run() error = %v, want %v", err, errUsage)
	}
}

func TestRunMigrationValidatesConfigurationBeforeConnecting(t *testing.T) {
	t.Parallel()

	err := run(context.Background(), []string{"migrate"}, map[string]string{
		"XMINDS_RELEASE_ENVIRONMENT": "test",
	})
	if !errors.Is(err, config.ErrDatabaseURLRequired) {
		t.Fatalf("run() error = %v, want %v", err, config.ErrDatabaseURLRequired)
	}
}

func TestLoadAPIRuntimeConfigRejectsMissingPublicDistributionSettings(t *testing.T) {
	t.Parallel()

	base := map[string]string{
		"XMINDS_RELEASE_OBJECT_STORE_ACCESS_KEY":             "access-key",
		"XMINDS_RELEASE_OBJECT_STORE_SECRET_KEY":             "secret-key",
		"XMINDS_RELEASE_DEFAULT_PRODUCT_ID":                  "ngep",
		"XMINDS_RELEASE_DEFAULT_CHANNEL":                     "stable",
		"XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY":            t.TempDir(),
		"XMINDS_RELEASE_IAM_MFA_ENROLLMENT_SECRET_DIRECTORY": t.TempDir(),
		"XMINDS_RELEASE_IAM_USE_DEVELOPMENT_BREACH_CORPUS":   "true",
	}
	for _, key := range []string{
		"XMINDS_RELEASE_OBJECT_STORE_ACCESS_KEY",
		"XMINDS_RELEASE_OBJECT_STORE_SECRET_KEY",
		"XMINDS_RELEASE_DEFAULT_PRODUCT_ID",
		"XMINDS_RELEASE_DEFAULT_CHANNEL",
	} {
		t.Run(key, func(t *testing.T) {
			environ := make(map[string]string, len(base))
			for name, value := range base {
				environ[name] = value
			}
			delete(environ, key)
			if _, err := loadAPIRuntimeConfig(environ, "development"); !errors.Is(err, errAPIRuntimeConfiguration) {
				t.Fatalf("loadAPIRuntimeConfig() error = %v", err)
			}
		})
	}
}

func TestLoadAPIRuntimeConfigRejectsMissingProductionLocalAuthenticationSecurity(t *testing.T) {
	t.Parallel()
	_, err := loadAPIRuntimeConfig(map[string]string{
		"XMINDS_RELEASE_OBJECT_STORE_ACCESS_KEY":             "access-key",
		"XMINDS_RELEASE_OBJECT_STORE_SECRET_KEY":             "secret-key",
		"XMINDS_RELEASE_DEFAULT_PRODUCT_ID":                  "ngep",
		"XMINDS_RELEASE_DEFAULT_CHANNEL":                     "stable",
		"XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY":            t.TempDir(),
		"XMINDS_RELEASE_IAM_MFA_ENROLLMENT_SECRET_DIRECTORY": t.TempDir(),
	}, "production")
	if !errors.Is(err, errAPIRuntimeConfiguration) {
		t.Fatalf("loadAPIRuntimeConfig() error = %v", err)
	}
}

func TestLoadAPIRuntimeConfigParsesValidatedSettings(t *testing.T) {
	t.Parallel()

	configuration, err := loadAPIRuntimeConfig(map[string]string{
		"XMINDS_RELEASE_OBJECT_STORE_ACCESS_KEY":             " access-key ",
		"XMINDS_RELEASE_OBJECT_STORE_SECRET_KEY":             " secret-key ",
		"XMINDS_RELEASE_OBJECT_STORE_REGION":                 " cn-east-1 ",
		"XMINDS_RELEASE_OBJECT_STORE_SESSION_TOKEN":          " session-token ",
		"XMINDS_RELEASE_ENDPOINT_CA_DIRECTORY":               " /run/secrets/xminds-release/endpoint-cas ",
		"XMINDS_RELEASE_ENDPOINT_ALLOWED_PRIVATE_CIDRS":      "10.42.7.0/24,fd12:3456:789a::/48",
		"XMINDS_RELEASE_DEFAULT_PRODUCT_ID":                  " ngep ",
		"XMINDS_RELEASE_DEFAULT_CHANNEL":                     " stable ",
		"XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY":            " " + t.TempDir() + " ",
		"XMINDS_RELEASE_IAM_MFA_ENROLLMENT_SECRET_DIRECTORY": " " + t.TempDir() + " ",
		"XMINDS_RELEASE_IAM_USE_DEVELOPMENT_BREACH_CORPUS":   "true",
	}, "development")
	if err != nil {
		t.Fatalf("loadAPIRuntimeConfig() error = %v", err)
	}
	if configuration.DefaultProductID != "ngep" || configuration.DefaultChannel != "stable" || configuration.Region != "cn-east-1" ||
		configuration.EndpointCADirectory != "/run/secrets/xminds-release/endpoint-cas" || len(configuration.EndpointAllowedPrivatePrefixes) != 2 || !configuration.LocalAuth.UseDevelopmentBreachCorpus {
		t.Fatalf("configuration = %+v", configuration)
	}
}

func TestLoadAPIRuntimeConfigRejectsUnsafeEndpointPrivateCIDR(t *testing.T) {
	t.Parallel()
	_, err := loadAPIRuntimeConfig(map[string]string{
		"XMINDS_RELEASE_OBJECT_STORE_ACCESS_KEY":             "access-key",
		"XMINDS_RELEASE_OBJECT_STORE_SECRET_KEY":             "secret-key",
		"XMINDS_RELEASE_DEFAULT_PRODUCT_ID":                  "ngep",
		"XMINDS_RELEASE_DEFAULT_CHANNEL":                     "stable",
		"XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY":            t.TempDir(),
		"XMINDS_RELEASE_IAM_MFA_ENROLLMENT_SECRET_DIRECTORY": t.TempDir(),
		"XMINDS_RELEASE_IAM_USE_DEVELOPMENT_BREACH_CORPUS":   "true",
		"XMINDS_RELEASE_ENDPOINT_ALLOWED_PRIVATE_CIDRS":      "100.64.0.0/10",
	}, "development")
	if !errors.Is(err, errAPIRuntimeConfiguration) {
		t.Fatalf("loadAPIRuntimeConfig() error=%v", err)
	}
}

func TestRunMFASecretGCStopsBeforeSecretStoreShutdown(t *testing.T) {
	t.Parallel()
	repository := &blockingRuntimeMFASecretGCRepository{entered: make(chan struct{})}
	worker, err := iam.NewMFASecretGCWorker(iam.MFASecretGCWorkerConfig{Repository: repository, Secrets: runtimeMFASecretStore{}, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runMFASecretGC(ctx, worker, time.Hour)
	}()
	select {
	case <-repository.entered:
	case <-time.After(time.Second):
		t.Fatal("GC worker did not enter repository")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("GC worker did not stop after cancellation")
	}
}

type blockingRuntimeMFASecretGCRepository struct{ entered chan struct{} }

func (repository *blockingRuntimeMFASecretGCRepository) WithinTransaction(_ context.Context, function func(pgx.Tx) error) error {
	return function(nil)
}

func (repository *blockingRuntimeMFASecretGCRepository) ListDueMFASecretGC(ctx context.Context, _ time.Time, _ int) ([]iam.MFASecretGCItem, error) {
	close(repository.entered)
	<-ctx.Done()
	return nil, ctx.Err()
}

func (*blockingRuntimeMFASecretGCRepository) LeaseDueMFASecretGC(context.Context, pgx.Tx, string, time.Time, uuid.UUID, time.Time) (bool, error) {
	return false, nil
}
func (*blockingRuntimeMFASecretGCRepository) CompleteMFASecretGC(context.Context, pgx.Tx, string, uuid.UUID) error {
	return nil
}
func (*blockingRuntimeMFASecretGCRepository) FailMFASecretGC(context.Context, pgx.Tx, string, uuid.UUID, time.Time, string, time.Time) error {
	return nil
}
func (*blockingRuntimeMFASecretGCRepository) LockMFASecretReference(context.Context, pgx.Tx, string) error {
	return nil
}
func (*blockingRuntimeMFASecretGCRepository) MFASecretReferenceIsLive(context.Context, pgx.Tx, string, time.Time) (bool, error) {
	return false, nil
}
func (*blockingRuntimeMFASecretGCRepository) MFASecretReferenceHasTombstone(context.Context, pgx.Tx, string) (bool, error) {
	return false, nil
}
func (*blockingRuntimeMFASecretGCRepository) EnqueueMFASecretGC(context.Context, pgx.Tx, string, time.Time, time.Time) error {
	return nil
}

type runtimeMFASecretStore struct{}

func (runtimeMFASecretStore) Resolve(context.Context, string) ([]byte, error) { return nil, nil }
func (runtimeMFASecretStore) Create(context.Context, uuid.UUID, string) (string, error) {
	return "", nil
}
func (runtimeMFASecretStore) Delete(context.Context, string) error { return nil }
func (runtimeMFASecretStore) ListOrphanCandidates(context.Context, time.Time, int) ([]string, error) {
	return nil, nil
}

func TestManagementRoutesExposeProductAPIWithVerifiedPrincipal(t *testing.T) {
	t.Parallel()

	application := &recordingProductApplication{}
	verifier := mainVerifierFunc(func(context.Context, string) (identity.Principal, error) {
		return identity.Principal{
			Subject:    "alice",
			Kind:       identity.PrincipalKindHuman,
			Roles:      []identity.Role{identity.RoleAdmin},
			ProductIDs: []string{"ngep"},
			TokenID:    "token-1",
		}, nil
	})
	handler := httpserver.NewManagementHandler(
		nil,
		buildinfo.Current(),
		identity.AuthenticationMiddleware(verifier),
		managementRoutes(managementApplications{Products: application}),
	)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
	request.Header.Set("Authorization", "Bearer signed-token")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"id":"ngep"`) {
		t.Fatalf("body = %s", response.Body.String())
	}
	if application.listedBy != "alice" {
		t.Fatalf("product list principal = %q", application.listedBy)
	}
}

func TestManagementRoutesExposeProtectedReauthenticationAPI(t *testing.T) {
	t.Parallel()
	application := &recordingReauthenticationApplication{}
	verifier := mainVerifierFunc(func(context.Context, string) (identity.Principal, error) {
		return identity.Principal{Subject: "admin", Kind: identity.PrincipalKindHuman, Roles: []identity.Role{identity.RoleAdmin}, TokenID: "token-1"}, nil
	})
	handler := httpserver.NewManagementHandler(
		nil,
		buildinfo.Current(),
		identity.AuthenticationMiddleware(verifier),
		managementRoutes(managementApplications{Reauthentication: application}),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/reauth-challenges", strings.NewReader(`{"operation":"identity.user.disable"}`))
	request.Header.Set("Authorization", "Bearer signed-token")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated || application.operation != iam.ReauthenticationOperationUserDisable {
		t.Fatalf("status = %d, operation = %q, body = %s", response.Code, application.operation, response.Body.String())
	}
}

type mainVerifierFunc func(context.Context, string) (identity.Principal, error)

func (function mainVerifierFunc) Verify(ctx context.Context, token string) (identity.Principal, error) {
	return function(ctx, token)
}

type recordingProductApplication struct {
	listedBy string
}

type recordingReauthenticationApplication struct {
	operation iam.ReauthenticationOperation
}

func (application *recordingReauthenticationApplication) CreateChallenge(_ context.Context, _ identity.Principal, operation iam.ReauthenticationOperation, _ iam.RequestContext) (iam.ReauthenticationChallengeResult, error) {
	application.operation = operation
	return iam.ReauthenticationChallengeResult{ID: uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e13"), Operation: operation, Status: iam.ReauthenticationStatusPending, ExpiresAt: time.Now().Add(time.Minute)}, nil
}

func (*recordingReauthenticationApplication) CompleteChallenge(context.Context, identity.Principal, uuid.UUID, iam.CompleteReauthenticationCommand, iam.RequestContext) (iam.ReauthenticationEvidence, error) {
	return iam.ReauthenticationEvidence{}, errors.New("unexpected challenge completion")
}

func (*recordingProductApplication) Register(context.Context, identity.Principal, []byte, product.RequestContext) (product.Product, error) {
	return product.Product{}, errors.New("unexpected product registration")
}

func (*recordingProductApplication) Get(context.Context, identity.Principal, string) (product.Product, error) {
	return product.Product{}, errors.New("unexpected product read")
}

func (application *recordingProductApplication) List(_ context.Context, principal identity.Principal, _ product.Page) (product.ProductPage, error) {
	application.listedBy = principal.Subject
	return product.ProductPage{Items: []product.Product{{ID: "ngep", DisplayName: "NGEP"}}}, nil
}

func (*recordingProductApplication) Deactivate(context.Context, identity.Principal, string, product.RequestContext) (product.Product, error) {
	return product.Product{}, errors.New("unexpected product deactivation")
}
