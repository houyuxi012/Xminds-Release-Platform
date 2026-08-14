package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/jobs"
)

const maximumMetadataBytes = 64 * 1024

var (
	ErrRepositoryRequired  = errors.New("audit repository is required")
	ErrActionInvalid       = errors.New("audit action is invalid")
	ErrResourceTypeInvalid = errors.New("audit resource type is invalid")
	ErrResourceIDInvalid   = errors.New("audit resource ID is invalid")
	ErrOutcomeInvalid      = errors.New("audit outcome is invalid")
	ErrRequestIDInvalid    = errors.New("audit request ID is invalid")
	ErrSourceIPInvalid     = errors.New("audit source IP is invalid")
	ErrMetadataInvalid     = errors.New("audit metadata is invalid")
	ErrMetadataTooLarge    = errors.New("audit metadata exceeds size limit")
	ErrExportJobsRequired  = errors.New("audit export job enqueuer is required")
	ErrExportNotFound      = errors.New("audit export was not found")
	ErrExportFilterInvalid = errors.New("audit export filter is invalid")
)

var auditActionPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)+$`)
var resourceTypePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)

type Service struct {
	repository  Repository
	authorizer  *identity.Authorizer
	jobEnqueuer JobEnqueuer
	now         func() time.Time
}

type JobEnqueuer interface {
	Enqueue(ctx context.Context, tx pgx.Tx, job jobs.Job) error
}

func NewService(repository Repository, jobEnqueuers ...JobEnqueuer) *Service {
	var jobEnqueuer JobEnqueuer
	if len(jobEnqueuers) > 0 {
		jobEnqueuer = jobEnqueuers[0]
	}
	return &Service{
		repository:  repository,
		authorizer:  identity.NewAuthorizer(),
		jobEnqueuer: jobEnqueuer,
		now:         time.Now,
	}
}

func (service *Service) Append(ctx context.Context, tx pgx.Tx, command AppendCommand) (Event, error) {
	if service == nil || service.repository == nil {
		return Event{}, ErrRepositoryRequired
	}
	if err := command.Actor.Validate(); err != nil {
		return Event{}, err
	}
	command.Action = strings.TrimSpace(command.Action)
	if !auditActionPattern.MatchString(command.Action) || len(command.Action) > 128 {
		return Event{}, ErrActionInvalid
	}
	command.ResourceType = strings.TrimSpace(command.ResourceType)
	if !resourceTypePattern.MatchString(command.ResourceType) || len(command.ResourceType) > 128 {
		return Event{}, ErrResourceTypeInvalid
	}
	command.ResourceID = strings.TrimSpace(command.ResourceID)
	if command.ResourceID == "" || len(command.ResourceID) > 512 {
		return Event{}, ErrResourceIDInvalid
	}
	switch command.Outcome {
	case OutcomeSuccess, OutcomeDenied, OutcomeFailed:
	default:
		return Event{}, ErrOutcomeInvalid
	}
	requestID, err := uuid.Parse(strings.TrimSpace(command.RequestID))
	if err != nil {
		return Event{}, ErrRequestIDInvalid
	}
	command.SourceIP = strings.TrimSpace(command.SourceIP)
	if command.SourceIP != "" {
		if _, err := netip.ParseAddr(command.SourceIP); err != nil {
			return Event{}, ErrSourceIPInvalid
		}
	}
	metadata, err := encodeRedactedMetadata(command.Metadata)
	if err != nil {
		return Event{}, err
	}
	eventID, err := uuid.NewV7()
	if err != nil {
		return Event{}, fmt.Errorf("generate audit event ID: %w", err)
	}
	event := Event{
		ID:              eventID,
		OccurredAt:      service.now().UTC(),
		ProductID:       strings.TrimSpace(command.ProductID),
		ActorSubject:    strings.TrimSpace(command.Actor.Subject),
		ActorKind:       command.Actor.Kind,
		ActorProvider:   command.Actor.Provider,
		ActorRoles:      append([]identity.Role(nil), command.Actor.Roles...),
		ActorProductIDs: append([]string(nil), command.Actor.ProductIDs...),
		TokenID:         strings.TrimSpace(command.Actor.TokenID),
		Action:          command.Action,
		ResourceType:    command.ResourceType,
		ResourceID:      command.ResourceID,
		Outcome:         command.Outcome,
		RequestID:       requestID,
		SourceIP:        command.SourceIP,
		Metadata:        metadata,
	}
	return service.repository.Append(ctx, tx, event)
}

func (service *Service) Query(ctx context.Context, principal identity.Principal, filter QueryFilter) ([]Event, error) {
	if service == nil || service.repository == nil || service.authorizer == nil {
		return nil, ErrRepositoryRequired
	}
	if err := service.authorizer.Require(principal, identity.ActionAuditRead, filter.ProductID); err != nil {
		return nil, err
	}
	if filter.Limit <= 0 {
		filter.Limit = 100
	}
	if filter.Limit > 500 {
		filter.Limit = 500
	}
	return service.repository.Query(ctx, filter)
}

func (service *Service) StartExport(ctx context.Context, tx pgx.Tx, command StartExportCommand) (Export, error) {
	if service == nil || service.repository == nil {
		return Export{}, ErrRepositoryRequired
	}
	if service.jobEnqueuer == nil {
		return Export{}, ErrExportJobsRequired
	}
	command.ProductID = strings.TrimSpace(command.ProductID)
	if err := service.authorizer.Require(command.Actor, identity.ActionAuditRead, command.ProductID); err != nil {
		return Export{}, err
	}
	if (!command.Filter.Since.IsZero() && !command.Filter.Until.IsZero() && command.Filter.Since.After(command.Filter.Until)) ||
		(command.Filter.ProductID != "" && command.Filter.ProductID != command.ProductID) {
		return Export{}, ErrExportFilterInvalid
	}
	command.Filter.ProductID = command.ProductID
	command.Filter.Limit = 0
	command.Filter.BeforeTime = time.Time{}
	command.Filter.BeforeID = uuid.Nil
	filterJSON, err := json.Marshal(command.Filter)
	if err != nil {
		return Export{}, fmt.Errorf("encode audit export filter: %w", ErrExportFilterInvalid)
	}
	requestID, err := uuid.Parse(strings.TrimSpace(command.RequestID))
	if err != nil {
		return Export{}, ErrRequestIDInvalid
	}
	exportID, err := uuid.NewV7()
	if err != nil {
		return Export{}, fmt.Errorf("generate audit export ID: %w", err)
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	export := Export{
		ID:          exportID,
		ProductID:   command.ProductID,
		RequestedBy: strings.TrimSpace(command.Actor.Subject),
		RequestID:   requestID,
		Filter:      filterJSON,
		Status:      ExportStatusPending,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := service.repository.StartExport(ctx, tx, export); err != nil {
		return Export{}, err
	}
	payload, err := json.Marshal(map[string]string{
		"export_id":  export.ID.String(),
		"product_id": export.ProductID,
	})
	if err != nil {
		return Export{}, fmt.Errorf("encode audit export job: %w", err)
	}
	job, err := jobs.New("audit.export.v1", export.ID, payload, now)
	if err != nil {
		return Export{}, err
	}
	if err := service.jobEnqueuer.Enqueue(ctx, tx, job); err != nil {
		return Export{}, fmt.Errorf("enqueue audit export: %w", err)
	}
	if _, err := service.Append(ctx, tx, AppendCommand{
		Actor:        command.Actor,
		Action:       "audit.export.start",
		ProductID:    command.ProductID,
		ResourceType: "audit_export",
		ResourceID:   export.ID.String(),
		Outcome:      OutcomeSuccess,
		RequestID:    command.RequestID,
		SourceIP:     command.SourceIP,
		Metadata: map[string]any{
			"export_id": export.ID.String(),
		},
	}); err != nil {
		return Export{}, fmt.Errorf("audit export request: %w", err)
	}
	return export, nil
}

func (service *Service) GetExport(ctx context.Context, principal identity.Principal, id uuid.UUID) (Export, error) {
	if service == nil || service.repository == nil {
		return Export{}, ErrRepositoryRequired
	}
	if id == uuid.Nil {
		return Export{}, ErrExportNotFound
	}
	export, err := service.repository.GetExport(ctx, id)
	if err != nil {
		return Export{}, err
	}
	if err := service.authorizer.Require(principal, identity.ActionAuditRead, export.ProductID); err != nil {
		return Export{}, err
	}
	return export, nil
}

func encodeRedactedMetadata(metadata map[string]any) (json.RawMessage, error) {
	if metadata == nil {
		metadata = map[string]any{}
	}
	redacted := redactMap(metadata)
	payload, err := json.Marshal(redacted)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMetadataInvalid, err)
	}
	if len(payload) > maximumMetadataBytes {
		return nil, ErrMetadataTooLarge
	}
	return payload, nil
}

func redactMap(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		if sensitiveKey(key) {
			result[key] = "[REDACTED]"
			continue
		}
		result[key] = redactValue(value)
	}
	return result
}

func redactValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return redactMap(typed)
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = redactValue(item)
		}
		return result
	default:
		return value
	}
}

func sensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	normalized = strings.NewReplacer("-", "_", " ", "_").Replace(normalized)
	for _, marker := range []string{
		"authorization",
		"cookie",
		"password",
		"secret",
		"token",
		"private_key",
		"license_key",
	} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}
