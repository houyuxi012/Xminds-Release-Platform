package logcenter

import "time"

type EventMetadata struct {
	RequestID     string
	CorrelationID string
	TraceID       string
	SourceIP      string
	SchemaVersion int16
}

type Result string

const (
	ResultSuccess Result = "success"
	ResultDenied  Result = "denied"
	ResultFailed  Result = "failed"
)

type OperationCommand struct {
	Metadata        EventMetadata
	EventID         string
	OccurredAt      time.Time
	ProductID       string
	Action          string
	ResourceType    string
	ResourceID      string
	Result          Result
	ActorSubject    string
	ActorKind       string
	MetadataSummary map[string]any
}

type AuthenticationEvent struct {
	Metadata             EventMetadata
	EventID              string
	OccurredAt           time.Time
	ProductID            string
	Subject              string
	ClientName           string
	IdentitySourceID     string
	AuthenticationMethod string
	MFALevel             string
	Result               Result
	ReasonCode           string
}

type ApplicationRequestEvent struct {
	Metadata          EventMetadata
	EventID           string
	OccurredAt        time.Time
	ProductID         string
	ClientAppID       string
	ClientAppVersion  string
	HTTPMethod        string
	RouteTemplate     string
	HTTPStatus        *int
	DurationMS        int64
	SnapshotTrusted   bool
	CustomerID        string
	CustomerName      string
	TenantID          string
	AuthorizationName string
	LicenseID         string
	LicenseExpiresAt  *time.Time
	LicenseStatus     string
	Decision          string
	Result            Result
	ReasonCode        string
	ValidatedAt       *time.Time
	ValidatorIssuer   string
	ContextDigest     []byte
}

type GitSyncEvent struct {
	Metadata       EventMetadata
	EventID        string
	OccurredAt     time.Time
	ProductID      string
	Provider       string
	RepositoryID   string
	RepositoryName string
	CommitSHA      string
	TagName        string
	Stage          string
	Attempt        int
	Result         Result
	ErrorCode      string
}
