package jobs

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Status string

const (
	StatusPending    Status = "pending"
	StatusLeased     Status = "leased"
	StatusCompleted  Status = "completed"
	StatusDeadLetter Status = "dead_letter"
)

var (
	ErrKindRequired       = errors.New("job kind is required")
	ErrAggregateIDInvalid = errors.New("job aggregate ID is invalid")
	ErrPayloadInvalid     = errors.New("job payload must be a JSON object")
	ErrAvailableAtInvalid = errors.New("job available time is invalid")
)

type Job struct {
	ID             uuid.UUID
	Kind           string
	AggregateID    uuid.UUID
	Payload        json.RawMessage
	Status         Status
	Attempts       int
	AvailableAt    time.Time
	LeaseOwner     string
	LeaseExpiresAt *time.Time
	LastErrorCode  string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func New(kind string, aggregateID uuid.UUID, payload json.RawMessage, availableAt time.Time) (Job, error) {
	kind = strings.TrimSpace(kind)
	if kind == "" || len(kind) > 128 {
		return Job{}, ErrKindRequired
	}
	if aggregateID == uuid.Nil {
		return Job{}, ErrAggregateIDInvalid
	}
	var object map[string]json.RawMessage
	if !json.Valid(payload) || json.Unmarshal(payload, &object) != nil || object == nil {
		return Job{}, ErrPayloadInvalid
	}
	if availableAt.IsZero() {
		return Job{}, ErrAvailableAtInvalid
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Job{}, err
	}
	return Job{
		ID:          id,
		Kind:        kind,
		AggregateID: aggregateID,
		Payload:     append(json.RawMessage(nil), payload...),
		Status:      StatusPending,
		AvailableAt: availableAt.UTC(),
	}, nil
}
