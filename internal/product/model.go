package product

import (
	"encoding/json"
	"time"
)

type Status string

const (
	ProductStatusActive   Status = "active"
	ProductStatusInactive Status = "inactive"
)

type Product struct {
	ID                string          `json:"id"`
	DisplayName       string          `json:"display_name"`
	SchemaVersion     string          `json:"schema_version"`
	ArtifactTypes     []string        `json:"artifact_types"`
	VersionScheme     string          `json:"version_scheme"`
	CompatibilityKeys []string        `json:"compatibility_keys"`
	CatalogFormat     string          `json:"catalog_format"`
	Manifest          json.RawMessage `json:"manifest"`
	ManifestDigest    string          `json:"manifest_digest"`
	Status            Status          `json:"status"`
	Channels          []Channel       `json:"channels"`
	CreatedBy         string          `json:"created_by"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
	DeactivatedAt     *time.Time      `json:"deactivated_at,omitempty"`
}

type Channel struct {
	ProductID   string    `json:"product_id"`
	Name        string    `json:"name"`
	DisplayName string    `json:"display_name"`
	Position    int       `json:"position"`
	CreatedAt   time.Time `json:"created_at"`
}

type Page struct {
	Limit      int
	BeforeTime time.Time
	BeforeID   string
}

type ProductPage struct {
	Items      []Product `json:"items"`
	NextCursor string    `json:"next_cursor,omitempty"`
}

type RequestContext struct {
	RequestID string
	SourceIP  string
}
