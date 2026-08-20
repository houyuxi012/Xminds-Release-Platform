package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
		"XMINDS_RELEASE_OBJECT_STORE_ACCESS_KEY":  "access-key",
		"XMINDS_RELEASE_OBJECT_STORE_SECRET_KEY":  "secret-key",
		"XMINDS_RELEASE_DEFAULT_PRODUCT_ID":       "ngep",
		"XMINDS_RELEASE_DEFAULT_CHANNEL":          "stable",
		"XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY": t.TempDir(),
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
		"XMINDS_RELEASE_OBJECT_STORE_ACCESS_KEY":  "access-key",
		"XMINDS_RELEASE_OBJECT_STORE_SECRET_KEY":  "secret-key",
		"XMINDS_RELEASE_DEFAULT_PRODUCT_ID":       "ngep",
		"XMINDS_RELEASE_DEFAULT_CHANNEL":          "stable",
		"XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY": t.TempDir(),
	}, "production")
	if !errors.Is(err, errAPIRuntimeConfiguration) {
		t.Fatalf("loadAPIRuntimeConfig() error = %v", err)
	}
}

func TestLoadAPIRuntimeConfigParsesValidatedSettings(t *testing.T) {
	t.Parallel()

	configuration, err := loadAPIRuntimeConfig(map[string]string{
		"XMINDS_RELEASE_OBJECT_STORE_ACCESS_KEY":    " access-key ",
		"XMINDS_RELEASE_OBJECT_STORE_SECRET_KEY":    " secret-key ",
		"XMINDS_RELEASE_OBJECT_STORE_REGION":        " cn-east-1 ",
		"XMINDS_RELEASE_OBJECT_STORE_SESSION_TOKEN": " session-token ",
		"XMINDS_RELEASE_ENDPOINT_CA_DIRECTORY":      " /run/secrets/xminds-release/endpoint-cas ",
		"XMINDS_RELEASE_DEFAULT_PRODUCT_ID":         " ngep ",
		"XMINDS_RELEASE_DEFAULT_CHANNEL":            " stable ",
		"XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY":   " " + t.TempDir() + " ",
	}, "development")
	if err != nil {
		t.Fatalf("loadAPIRuntimeConfig() error = %v", err)
	}
	if configuration.DefaultProductID != "ngep" || configuration.DefaultChannel != "stable" || configuration.Region != "cn-east-1" ||
		configuration.EndpointCADirectory != "/run/secrets/xminds-release/endpoint-cas" || !configuration.LocalAuth.UseDevelopmentBreachCorpus {
		t.Fatalf("configuration = %+v", configuration)
	}
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

type mainVerifierFunc func(context.Context, string) (identity.Principal, error)

func (function mainVerifierFunc) Verify(ctx context.Context, token string) (identity.Principal, error) {
	return function(ctx, token)
}

type recordingProductApplication struct {
	listedBy string
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
