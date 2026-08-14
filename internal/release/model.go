package release

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

type Status string

const (
	StatusDraft      Status = "DRAFT"
	StatusSubmitted  Status = "SUBMITTED"
	StatusApproved   Status = "APPROVED"
	StatusRejected   Status = "REJECTED"
	StatusPublishing Status = "PUBLISHING"
	StatusPublished  Status = "PUBLISHED"
	StatusFailed     Status = "FAILED"
)

var (
	ErrReleaseNotFound          = errors.New("release was not found")
	ErrReleaseVersionExists     = errors.New("release version already exists in product channel")
	ErrInvalidTransition        = errors.New("release state transition is invalid")
	ErrSelfApprovalForbidden    = errors.New("release submitter cannot approve own release")
	ErrStaleRelease             = errors.New("release optimistic lock is stale")
	ErrProductInvalid           = errors.New("release product is invalid")
	ErrChannelInvalid           = errors.New("release channel is invalid")
	ErrVersionInvalid           = errors.New("release version is invalid")
	ErrReleaseNotesInvalid      = errors.New("release notes are invalid")
	ErrReleaseNotesMismatch     = errors.New("release notes digest does not match")
	ErrCompatibilityInvalid     = errors.New("release compatibility is invalid")
	ErrCompatibilityMismatch    = errors.New("release compatibility digest does not match")
	ErrArtifactsInvalid         = errors.New("release artifact bindings are invalid")
	ErrArtifactProductMismatch  = errors.New("release artifact does not belong to product")
	ErrSourceInvalid            = errors.New("release source provenance is invalid")
	ErrIdempotencyKeyInvalid    = errors.New("release idempotency key is invalid")
	ErrAttemptNotFound          = errors.New("release attempt was not found")
	ErrAttemptAlreadyExists     = errors.New("release idempotency key already exists")
	ErrRevocationReasonRequired = errors.New("release revocation reason is required")
	ErrRejectionReasonRequired  = errors.New("release rejection reason is required")
	ErrReleaseAlreadyRevoked    = errors.New("release is already revoked")
	ErrRepositoryRequired       = errors.New("release repository is required")
	ErrTransactorRequired       = errors.New("release transactor is required")
	ErrProductReaderRequired    = errors.New("release product reader is required")
	ErrArtifactReaderRequired   = errors.New("release artifact reader is required")
	ErrAuditAppenderRequired    = errors.New("release audit appender is required")
	ErrJobEnqueuerRequired      = errors.New("release job enqueuer is required")
)

type Source struct {
	Repository  string `json:"repository"`
	CommitSHA   string `json:"commit_sha"`
	Tag         string `json:"tag"`
	PipelineRef string `json:"pipeline_ref"`
}

type ArtifactBinding struct {
	ArtifactID   uuid.UUID `json:"artifact_id"`
	ArtifactType string    `json:"artifact_type"`
	Filename     string    `json:"filename"`
	Size         int64     `json:"size"`
	SHA256       string    `json:"sha256"`
}

type Release struct {
	ID                     uuid.UUID         `json:"id"`
	ProductID              string            `json:"product_id"`
	Channel                string            `json:"channel"`
	Version                string            `json:"version"`
	Status                 Status            `json:"status"`
	LockVersion            int64             `json:"lock_version"`
	ReleaseNotes           string            `json:"release_notes"`
	ReleaseNotesSHA256     string            `json:"release_notes_sha256"`
	Compatibility          json.RawMessage   `json:"compatibility"`
	CompatibilitySHA256    string            `json:"compatibility_sha256"`
	Artifacts              []ArtifactBinding `json:"artifacts"`
	Source                 Source            `json:"source"`
	CreatedBy              string            `json:"created_by"`
	CreatedAt              time.Time         `json:"created_at"`
	UpdatedAt              time.Time         `json:"updated_at"`
	SubmittedBy            string            `json:"submitted_by,omitempty"`
	SubmittedAt            *time.Time        `json:"submitted_at,omitempty"`
	ApprovedBy             string            `json:"approved_by,omitempty"`
	ApprovedAt             *time.Time        `json:"approved_at,omitempty"`
	RejectedBy             string            `json:"rejected_by,omitempty"`
	RejectedAt             *time.Time        `json:"rejected_at,omitempty"`
	RejectionReason        string            `json:"rejection_reason,omitempty"`
	RevokedAt              *time.Time        `json:"revoked_at,omitempty"`
	RevokedBy              string            `json:"revoked_by,omitempty"`
	RevocationReason       string            `json:"revocation_reason,omitempty"`
	PublicationFailureCode string            `json:"publication_failure_code,omitempty"`
}

type CreateCommand struct {
	ProductID           string
	Channel             string
	Version             string
	ReleaseNotes        []byte
	ReleaseNotesSHA256  string
	Compatibility       []byte
	CompatibilitySHA256 string
	ArtifactIDs         []uuid.UUID
	Source              Source
}

type TransitionCommand struct {
	ReleaseID           uuid.UUID
	ProductID           string
	From                Status
	To                  Status
	ExpectedLockVersion int64
	Actor               string
	Reason              string
	At                  time.Time
}

type RequestContext struct {
	RequestID string
	SourceIP  string
}

type AttemptKind string

const (
	AttemptKindPublish AttemptKind = "publish"
	AttemptKindRetry   AttemptKind = "retry"
	AttemptKindRevoke  AttemptKind = "revoke"
)

type AttemptStatus string

const (
	AttemptStatusPending AttemptStatus = "pending"
)

type Attempt struct {
	ID             uuid.UUID     `json:"id"`
	ReleaseID      uuid.UUID     `json:"release_id"`
	Kind           AttemptKind   `json:"kind"`
	Number         int           `json:"number"`
	IdempotencyKey string        `json:"idempotency_key"`
	Status         AttemptStatus `json:"status"`
	CreatedBy      string        `json:"created_by"`
	CreatedAt      time.Time     `json:"created_at"`
}

type OperationResult struct {
	Release Release `json:"release"`
	Attempt Attempt `json:"attempt"`
}

type RevokeCommand struct {
	ReleaseID           uuid.UUID
	ProductID           string
	ExpectedLockVersion int64
	Actor               string
	Reason              string
	At                  time.Time
}
