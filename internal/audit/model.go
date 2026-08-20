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
	ID              uuid.UUID
	OccurredAt      time.Time
	ProductID       string
	ActorSubject    string
	ActorKind       identity.PrincipalKind
	ActorProvider   identity.WorkloadProvider
	ActorRoles      []identity.Role
	ActorProductIDs []string
	TokenID         string
	Action          string
	ResourceType    string
	ResourceID      string
	Outcome         Outcome
	RequestID       uuid.UUID
	SourceIP        string
	Metadata        json.RawMessage
	PreviousHash    string
	EventHash       string
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
	ID          uuid.UUID
	ProductID   string
	RequestedBy string
	RequestID   uuid.UUID
	Filter      json.RawMessage
	Status      ExportStatus
	ObjectKey   string
	SHA256      string
	SizeBytes   int64
	ExpiresAt   time.Time
	ErrorCode   string
	CreatedAt   time.Time
	UpdatedAt   time.Time
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
