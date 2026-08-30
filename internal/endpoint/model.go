package endpoint

import (
	"errors"
	"regexp"
	"time"

	"github.com/google/uuid"
)

type Type string

const (
	TypeOrigin  Type = "origin"
	TypeCDN     Type = "cdn"
	TypePrivate Type = "private"
)

type Status string

const (
	StatusPending   Status = "pending"
	StatusActive    Status = "active"
	StatusUnhealthy Status = "unhealthy"
	StatusDisabled  Status = "disabled"
)

var (
	ErrEndpointInvalid       = errors.New("distribution endpoint is invalid")
	ErrEndpointNotFound      = errors.New("distribution endpoint was not found")
	ErrEndpointRepository    = errors.New("distribution endpoint repository is required")
	ErrEndpointTransactor    = errors.New("distribution endpoint transactor is required")
	ErrEndpointProbe         = errors.New("distribution endpoint probe is required")
	ErrEndpointAudit         = errors.New("distribution endpoint audit appender is required")
	ErrCatalogDigestMismatch = errors.New("distribution endpoint catalog digest does not match current catalog")
	ErrEndpointProbeFailed   = errors.New("distribution endpoint probe failed")
)

var endpointRegionPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)

type Endpoint struct {
	ID                  uuid.UUID  `json:"id"`
	ProductID           string     `json:"product_id"`
	Name                string     `json:"name"`
	Type                Type       `json:"type"`
	Region              string     `json:"region"`
	Priority            int        `json:"priority"`
	BaseURL             string     `json:"base_url"`
	PathPrefix          string     `json:"path_prefix"`
	HealthPath          string     `json:"health_path"`
	TLSCARef            string     `json:"tls_ca_ref,omitempty"`
	Status              Status     `json:"status"`
	LastRootDigest      string     `json:"last_root_digest,omitempty"`
	LastTimestampDigest string     `json:"last_timestamp_digest,omitempty"`
	LastCheckedAt       *time.Time `json:"last_checked_at,omitempty"`
	FailureCount        int        `json:"failure_count"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

type RegisterCommand struct {
	ProductID  string `json:"product_id"`
	Name       string `json:"name"`
	Type       Type   `json:"type"`
	Region     string `json:"region"`
	Priority   int    `json:"priority"`
	BaseURL    string `json:"base_url"`
	PathPrefix string `json:"path_prefix"`
	HealthPath string `json:"health_path"`
	TLSCARef   string `json:"tls_ca_ref,omitempty"`
}

type RequestContext struct {
	RequestID string
	SourceIP  string
}

type ProbeResult struct {
	RootDigest      string
	TimestampDigest string
}
