package product

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/identity"
)

const (
	defaultPageLimit          = 50
	maximumPageLimit          = 200
	productAuthorizationProbe = "__authorization_scope_probe__"
)

var ErrPageInvalid = errors.New("product page is invalid")

type AuditAppender interface {
	Append(ctx context.Context, tx pgx.Tx, command audit.AppendCommand) (audit.Event, error)
}

type Service struct {
	repository Repository
	transactor Transactor
	auditor    AuditAppender
	authorizer *identity.Authorizer
	now        func() time.Time
}

func NewService(repository Repository, transactor Transactor, auditor AuditAppender) *Service {
	return &Service{
		repository: repository,
		transactor: transactor,
		auditor:    auditor,
		authorizer: identity.NewAuthorizer(),
		now:        time.Now,
	}
}

func (service *Service) Register(ctx context.Context, principal identity.Principal, rawManifest []byte, request RequestContext) (Product, error) {
	if err := service.validateWriteDependencies(); err != nil {
		return Product{}, err
	}
	if err := service.authorizer.Require(principal, identity.ActionProductRegister, ""); err != nil {
		return Product{}, err
	}
	manifest, canonical, digest, err := ParseManifest(rawManifest)
	if err != nil {
		return Product{}, err
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	product := Product{
		ID:                manifest.ProductID,
		DisplayName:       manifest.DisplayName,
		SchemaVersion:     manifest.SchemaVersion,
		ArtifactTypes:     append([]string{}, manifest.ArtifactTypes...),
		VersionScheme:     manifest.VersionScheme,
		CompatibilityKeys: append([]string{}, manifest.CompatibilityKeys...),
		CatalogFormat:     manifest.CatalogFormat,
		Manifest:          canonical,
		ManifestDigest:    digest,
		Status:            ProductStatusActive,
		CreatedBy:         strings.TrimSpace(principal.Subject),
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	channels := make([]Channel, 0, len(manifest.DefaultChannels))
	for position, item := range manifest.DefaultChannels {
		channels = append(channels, Channel{
			ProductID:   manifest.ProductID,
			Name:        item.Name,
			DisplayName: item.DisplayName,
			Position:    position,
			CreatedAt:   now,
		})
	}
	product.Channels = append([]Channel(nil), channels...)

	err = service.transactor.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if err := service.repository.Create(ctx, tx, product, channels); err != nil {
			return err
		}
		if _, err := service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor:        principal,
			Action:       "product.register",
			ProductID:    product.ID,
			ResourceType: "product",
			ResourceID:   product.ID,
			Outcome:      audit.OutcomeSuccess,
			RequestID:    request.RequestID,
			SourceIP:     request.SourceIP,
			Metadata: map[string]any{
				"manifest_digest": product.ManifestDigest,
				"schema_version":  product.SchemaVersion,
			},
		}); err != nil {
			return fmt.Errorf("append product registration audit event: %w", err)
		}
		return nil
	})
	if err != nil {
		return Product{}, err
	}
	return product, nil
}

func (service *Service) Get(ctx context.Context, principal identity.Principal, productID string) (Product, error) {
	if service == nil || service.repository == nil || service.authorizer == nil {
		return Product{}, ErrRepositoryRequired
	}
	productID = strings.TrimSpace(productID)
	if err := service.authorizer.Require(principal, identity.ActionProductRead, productID); err != nil {
		return Product{}, err
	}
	return service.repository.Get(ctx, productID)
}

func (service *Service) List(ctx context.Context, principal identity.Principal, page Page) (ProductPage, error) {
	if service == nil || service.repository == nil || service.authorizer == nil {
		return ProductPage{}, ErrRepositoryRequired
	}
	if err := principal.Validate(); err != nil {
		return ProductPage{}, err
	}
	if page.Limit < 0 || page.Limit > maximumPageLimit || (page.BeforeID == "") != page.BeforeTime.IsZero() {
		return ProductPage{}, ErrPageInvalid
	}
	if page.Limit == 0 {
		page.Limit = defaultPageLimit
	}
	scope, err := service.resolveProductListScope(principal)
	if err != nil {
		return ProductPage{}, err
	}
	return service.repository.List(ctx, scope, page)
}

func (service *Service) resolveProductListScope(principal identity.Principal) (ProductListScope, error) {
	if !principal.Governed {
		productIDs := uniqueNonEmpty(principal.ProductIDs)
		for _, productID := range productIDs {
			if err := service.authorizer.Require(principal, identity.ActionProductRead, productID); err != nil {
				return ProductListScope{}, err
			}
		}
		return ProductListScope{IncludedProductIDs: productIDs}, nil
	}

	allProducts := service.authorizer.Require(principal, identity.ActionProductRead, productAuthorizationProbe) == nil
	candidates := make([]string, 0, len(principal.RoleScopes))
	for _, roleScope := range principal.RoleScopes {
		if roleScope.ProductID != "" {
			candidates = append(candidates, roleScope.ProductID)
		}
	}
	candidates = uniqueNonEmpty(candidates)
	result := ProductListScope{AllProducts: allProducts}
	for _, productID := range candidates {
		err := service.authorizer.Require(principal, identity.ActionProductRead, productID)
		switch {
		case err == nil && !allProducts:
			result.IncludedProductIDs = append(result.IncludedProductIDs, productID)
		case errors.Is(err, identity.ErrActionDenied) && allProducts:
			result.ExcludedProductIDs = append(result.ExcludedProductIDs, productID)
		case err == nil || errors.Is(err, identity.ErrActionDenied):
			continue
		default:
			return ProductListScope{}, err
		}
	}
	return result, nil
}

func (service *Service) Deactivate(ctx context.Context, principal identity.Principal, productID string, request RequestContext) (Product, error) {
	if err := service.validateWriteDependencies(); err != nil {
		return Product{}, err
	}
	productID = strings.TrimSpace(productID)
	if err := service.authorizer.Require(principal, identity.ActionProductManage, productID); err != nil {
		return Product{}, err
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	var product Product
	err := service.transactor.WithinTransaction(ctx, func(tx pgx.Tx) error {
		var err error
		product, err = service.repository.Deactivate(ctx, tx, productID, now)
		if err != nil {
			return err
		}
		_, err = service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: principal, Action: "product.deactivate", ProductID: productID,
			ResourceType: "product", ResourceID: productID, Outcome: audit.OutcomeSuccess,
			RequestID: request.RequestID, SourceIP: request.SourceIP,
		})
		if err != nil {
			return fmt.Errorf("append product deactivation audit event: %w", err)
		}
		return nil
	})
	return product, err
}

func (service *Service) validateWriteDependencies() error {
	if service == nil || service.repository == nil || service.authorizer == nil {
		return ErrRepositoryRequired
	}
	if service.transactor == nil {
		return ErrTransactorRequired
	}
	if service.auditor == nil {
		return ErrAuditAppenderRequired
	}
	return nil
}

func uniqueNonEmpty(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
