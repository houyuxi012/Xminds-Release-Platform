package audit

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"xminds-release-platform/internal/identity"
)

const zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeDenied  Outcome = "denied"
	OutcomeFailed  Outcome = "failed"
)

type Event struct {
	ID              uuid.UUID                 `json:"id"`
	OccurredAt      time.Time                 `json:"occurred_at"`
	ProductID       string                    `json:"product_id"`
	ActorSubject    string                    `json:"actor_subject"`
	ActorKind       identity.PrincipalKind    `json:"actor_kind"`
	ActorProvider   identity.WorkloadProvider `json:"actor_provider"`
	ActorRoles      []identity.Role           `json:"actor_roles"`
	ActorProductIDs []string                  `json:"actor_product_ids"`
	TokenID         string                    `json:"token_id"`
	Action          string                    `json:"action"`
	ResourceType    string                    `json:"resource_type"`
	ResourceID      string                    `json:"resource_id"`
	Outcome         Outcome                   `json:"outcome"`
	RequestID       uuid.UUID                 `json:"request_id"`
	SourceIP        string                    `json:"source_ip,omitempty"`
	Metadata        json.RawMessage           `json:"metadata"`
	PreviousHash    string                    `json:"previous_hash"`
	EventHash       string                    `json:"event_hash"`
}

type AppendCommand struct {
	Actor        identity.Principal
	Action       string
	ProductID    string
	ResourceType string
	ResourceID   string
	Outcome      Outcome
	RequestID    string
	SourceIP     string
	Metadata     map[string]any
}

type QueryFilter struct {
	ProductID    string
	ActorSubject string
	Action       string
	Outcome      Outcome
	Since        time.Time
	Until        time.Time
	Limit        int
	BeforeTime   time.Time
	BeforeID     uuid.UUID
}

type ExportStatus string

const (
	ExportStatusPending   ExportStatus = "pending"
	ExportStatusCompleted ExportStatus = "completed"
	ExportStatusFailed    ExportStatus = "failed"
)

type Export struct {
	ID          uuid.UUID       `json:"id"`
	ProductID   string          `json:"product_id"`
	RequestedBy string          `json:"requested_by"`
	RequestID   uuid.UUID       `json:"request_id"`
	Filter      json.RawMessage `json:"-"`
	Status      ExportStatus    `json:"status"`
	ObjectKey   string          `json:"object_key,omitempty"`
	SHA256      string          `json:"sha256,omitempty"`
	SizeBytes   int64           `json:"size_bytes,omitempty"`
	ExpiresAt   time.Time       `json:"expires_at,omitempty"`
	ErrorCode   string          `json:"error_code,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

type ExportDownload struct {
	ExportID  uuid.UUID
	ObjectKey string
	SHA256    string
	SizeBytes int64
	ExpiresAt time.Time
}

type StartExportCommand struct {
	Actor     identity.Principal
	ProductID string
	Filter    QueryFilter
	RequestID string
	SourceIP  string
}
