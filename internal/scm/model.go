package scm

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

type ProviderKind string

const (
	ProviderGitHub ProviderKind = "github"
	ProviderGitLab ProviderKind = "gitlab"
)

type ConnectionStatus string

const (
	ConnectionStatusActive  ConnectionStatus = "active"
	ConnectionStatusRevoked ConnectionStatus = "revoked"
)

var (
	ErrConnectionNotFound       = errors.New("SCM connection was not found")
	ErrConnectionInvalid        = errors.New("SCM connection is invalid")
	ErrConnectionInactive       = errors.New("SCM connection is inactive")
	ErrDeliveryNotFound         = errors.New("SCM webhook delivery was not found")
	ErrDeliveryReplayConflict   = errors.New("SCM webhook delivery replay payload differs")
	ErrWebhookEventInvalid      = errors.New("SCM webhook event is invalid")
	ErrWebhookPayloadTooLarge   = errors.New("SCM webhook payload exceeds size limit")
	ErrWebhookServiceConfig     = errors.New("SCM webhook service configuration is invalid")
	ErrProviderUnsupported      = errors.New("SCM provider is unsupported")
	ErrWebhookSignatureInvalid  = errors.New("SCM webhook signature is invalid")
	ErrProviderResponseInvalid  = errors.New("SCM provider response is invalid")
	ErrProviderRequestFailed    = errors.New("SCM provider request failed")
	ErrCredentialUnavailable    = errors.New("SCM credential is unavailable")
	ErrWorkloadVerifierRequired = errors.New("SCM workload verifier is required")
	ErrWorkloadIdentityInvalid  = errors.New("SCM workload identity is invalid")
)

type Instance struct {
	ID         string
	Provider   ProviderKind
	APIBaseURL string
}

type Connection struct {
	ID                     uuid.UUID
	ProductID              string
	Name                   string
	Provider               ProviderKind
	Status                 ConnectionStatus
	APIBaseURL             string
	APIVersion             string
	CredentialID           uuid.UUID
	WebhookCredentialID    uuid.UUID
	OIDCIssuer             string
	OIDCAudience           string
	AllowedRepositories    []string
	ResolvedAddresses      []string
	EnterpriseCABundlePEM  []byte
	ProxyURL               string
	ProxyResolvedAddresses []string
	NoProxy                []string
	Capabilities           Capabilities
	CertificateSHA256      string
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

type Capabilities struct {
	CommitStatuses    bool   `json:"commit_statuses"`
	CheckRuns         bool   `json:"check_runs"`
	WorkloadOIDC      bool   `json:"workload_oidc"`
	CertificateSHA256 string `json:"certificate_sha256"`
}

type WebhookEvent struct {
	Provider      ProviderKind
	EventID       string
	EventType     string
	Repository    string
	Ref           string
	Tag           string
	CommitSHA     string
	PipelineID    string
	Actor         string
	OccurredAt    time.Time
	PayloadDigest string
	Payload       json.RawMessage
}

type Commit struct {
	Repository  string
	SHA         string
	WebURL      string
	Author      string
	Message     string
	CommittedAt time.Time
}

type CommitState string

const (
	CommitStatePending CommitState = "pending"
	CommitStateSuccess CommitState = "success"
	CommitStateFailure CommitState = "failure"
	CommitStateError   CommitState = "error"
)

type CommitStatus struct {
	Repository  string
	SHA         string
	State       CommitState
	Context     string
	Description string
	TargetURL   string
}

type Delivery struct {
	ID            uuid.UUID
	ConnectionID  uuid.UUID
	EventID       string
	EventType     string
	PayloadDigest string
	Repository    string
	CommitSHA     string
	OccurredAt    time.Time
	ReceivedAt    time.Time
}
