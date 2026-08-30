package product

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrTransactionRequired = errors.New("product transaction is required")

type PostgresRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func (repository *PostgresRepository) Create(ctx context.Context, tx pgx.Tx, product Product, channels []Channel) error {
	if tx == nil {
		return ErrTransactionRequired
	}
	_, err := tx.Exec(ctx, `
INSERT INTO products (
    id, display_name, schema_version, artifact_types, version_scheme,
    compatibility_keys, catalog_format, manifest_json, manifest_digest,
    status, created_by, created_at, updated_at, deactivated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
`,
		product.ID,
		product.DisplayName,
		product.SchemaVersion,
		product.ArtifactTypes,
		product.VersionScheme,
		product.CompatibilityKeys,
		product.CatalogFormat,
		product.Manifest,
		product.ManifestDigest,
		product.Status,
		product.CreatedBy,
		product.CreatedAt,
		product.UpdatedAt,
		product.DeactivatedAt,
	)
	if err != nil {
		return mapCreateError(err)
	}
	for _, channel := range channels {
		if _, err := tx.Exec(ctx, `
INSERT INTO product_channels (product_id, name, display_name, position, created_at)
VALUES ($1, $2, $3, $4, $5)
`, channel.ProductID, channel.Name, channel.DisplayName, channel.Position, channel.CreatedAt); err != nil {
			return fmt.Errorf("insert product channel %q: %w", channel.Name, err)
		}
	}
	return nil
}

func (repository *PostgresRepository) Get(ctx context.Context, productID string) (Product, error) {
	if repository == nil || repository.pool == nil {
		return Product{}, ErrRepositoryRequired
	}
	product, err := scanProduct(repository.pool.QueryRow(ctx, productSelect+` WHERE id = $1`, productID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Product{}, ErrProductNotFound
	}
	if err != nil {
		return Product{}, fmt.Errorf("get product: %w", err)
	}
	channels, err := repository.loadChannels(ctx, repository.pool, []string{product.ID})
	if err != nil {
		return Product{}, err
	}
	product.Channels = channels[product.ID]
	return product, nil
}

func (repository *PostgresRepository) List(ctx context.Context, scope ProductListScope, page Page) (ProductPage, error) {
	if repository == nil || repository.pool == nil {
		return ProductPage{}, ErrRepositoryRequired
	}
	if !scope.AllProducts && len(scope.IncludedProductIDs) == 0 {
		return ProductPage{Items: []Product{}}, nil
	}
	query := productSelect
	arguments := make([]any, 0, 4)
	if scope.AllProducts {
		query += ` WHERE NOT (id = ANY($1))`
		arguments = append(arguments, append([]string{}, scope.ExcludedProductIDs...))
	} else {
		query += ` WHERE id = ANY($1)`
		arguments = append(arguments, append([]string{}, scope.IncludedProductIDs...))
	}
	if !page.BeforeTime.IsZero() {
		query += ` AND (created_at, id) < ($2, $3)`
		arguments = append(arguments, page.BeforeTime.UTC(), page.BeforeID)
	}
	query += fmt.Sprintf(` ORDER BY created_at DESC, id DESC LIMIT $%d`, len(arguments)+1)
	arguments = append(arguments, page.Limit+1)
	rows, err := repository.pool.Query(ctx, query, arguments...)
	if err != nil {
		return ProductPage{}, fmt.Errorf("list products: %w", err)
	}
	defer rows.Close()
	items := make([]Product, 0, page.Limit+1)
	for rows.Next() {
		item, scanErr := scanProduct(rows)
		if scanErr != nil {
			return ProductPage{}, fmt.Errorf("scan product: %w", scanErr)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return ProductPage{}, fmt.Errorf("iterate products: %w", err)
	}
	pageResult := ProductPage{Items: items}
	if len(items) > page.Limit {
		last := items[page.Limit-1]
		pageResult.Items = items[:page.Limit]
		pageResult.NextCursor = encodePageCursor(last.CreatedAt, last.ID)
	}
	ids := make([]string, 0, len(pageResult.Items))
	for _, item := range pageResult.Items {
		ids = append(ids, item.ID)
	}
	channels, err := repository.loadChannels(ctx, repository.pool, ids)
	if err != nil {
		return ProductPage{}, err
	}
	for index := range pageResult.Items {
		pageResult.Items[index].Channels = channels[pageResult.Items[index].ID]
	}
	return pageResult, nil
}

func (repository *PostgresRepository) Deactivate(ctx context.Context, tx pgx.Tx, productID string, deactivatedAt time.Time) (Product, error) {
	if tx == nil {
		return Product{}, ErrTransactionRequired
	}
	product, err := scanProduct(tx.QueryRow(ctx, productSelect+`
 WHERE id = $1
 FOR UPDATE
`, productID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Product{}, ErrProductNotFound
	}
	if err != nil {
		return Product{}, fmt.Errorf("lock product for deactivation: %w", err)
	}
	var updatedAt time.Time
	if err := tx.QueryRow(ctx, `
UPDATE products
SET status = 'inactive', deactivated_at = $2, updated_at = $2
WHERE id = $1
RETURNING updated_at
`, productID, deactivatedAt).Scan(&updatedAt); err != nil {
		return Product{}, fmt.Errorf("deactivate product: %w", err)
	}
	product.Status = ProductStatusInactive
	product.DeactivatedAt = &deactivatedAt
	product.UpdatedAt = updatedAt
	channels, err := repository.loadChannels(ctx, tx, []string{product.ID})
	if err != nil {
		return Product{}, err
	}
	product.Channels = channels[product.ID]
	return product, nil
}

const productSelect = `
SELECT
    id, display_name, schema_version, artifact_types, version_scheme,
    compatibility_keys, catalog_format, manifest_json, manifest_digest,
    status, created_by, created_at, updated_at, deactivated_at
FROM products`

type productRowScanner interface {
	Scan(dest ...any) error
}

func scanProduct(row productRowScanner) (Product, error) {
	var product Product
	err := row.Scan(
		&product.ID,
		&product.DisplayName,
		&product.SchemaVersion,
		&product.ArtifactTypes,
		&product.VersionScheme,
		&product.CompatibilityKeys,
		&product.CatalogFormat,
		&product.Manifest,
		&product.ManifestDigest,
		&product.Status,
		&product.CreatedBy,
		&product.CreatedAt,
		&product.UpdatedAt,
		&product.DeactivatedAt,
	)
	return product, err
}

type productQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func (repository *PostgresRepository) loadChannels(ctx context.Context, querier productQuerier, productIDs []string) (map[string][]Channel, error) {
	result := make(map[string][]Channel, len(productIDs))
	for _, productID := range productIDs {
		result[productID] = []Channel{}
	}
	if len(productIDs) == 0 {
		return result, nil
	}
	rows, err := querier.Query(ctx, `
SELECT product_id, name, display_name, position, created_at
FROM product_channels
WHERE product_id = ANY($1)
ORDER BY product_id, position
`, productIDs)
	if err != nil {
		return nil, fmt.Errorf("list product channels: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var channel Channel
		if err := rows.Scan(&channel.ProductID, &channel.Name, &channel.DisplayName, &channel.Position, &channel.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan product channel: %w", err)
		}
		result[channel.ProductID] = append(result[channel.ProductID], channel)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate product channels: %w", err)
	}
	return result, nil
}

func mapCreateError(err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "23505" {
		switch postgresError.ConstraintName {
		case "products_pkey":
			return ErrProductIDExists
		case "products_manifest_digest_unique":
			return ErrManifestDigestExists
		}
	}
	return fmt.Errorf("insert product: %w", err)
}
