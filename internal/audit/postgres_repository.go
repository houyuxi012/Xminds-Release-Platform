package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"xminds-release-platform/internal/identity"
)

var (
	ErrTransactionRequired = errors.New("audit append transaction is required")
	ErrQueryFilterInvalid  = errors.New("audit query filter is invalid")
)

type PostgresRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func (repository *PostgresRepository) Append(ctx context.Context, tx pgx.Tx, event Event) (Event, error) {
	if tx == nil {
		return Event{}, ErrTransactionRequired
	}
	partitionKey := "global"
	if event.ProductID != "" {
		partitionKey = "product:" + event.ProductID
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO audit_chain_heads (partition_key, head_hash)
VALUES ($1, $2)
ON CONFLICT (partition_key) DO NOTHING
`, partitionKey, zeroHash); err != nil {
		return Event{}, fmt.Errorf("initialize audit hash chain: %w", err)
	}
	if err := tx.QueryRow(ctx, `
SELECT head_hash
FROM audit_chain_heads
WHERE partition_key = $1
FOR UPDATE
`, partitionKey).Scan(&event.PreviousHash); err != nil {
		return Event{}, fmt.Errorf("lock audit hash chain: %w", err)
	}

	event.OccurredAt = event.OccurredAt.UTC().Truncate(time.Microsecond)
	eventHash, err := calculateEventHash(event)
	if err != nil {
		return Event{}, err
	}
	event.EventHash = eventHash
	roleValues := make([]string, len(event.ActorRoles))
	for index, role := range event.ActorRoles {
		roleValues[index] = string(role)
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO audit_events (
    id, occurred_at, product_id, actor_subject, actor_kind, actor_provider,
    actor_roles, actor_product_ids, token_id, action, resource_type, resource_id,
    outcome, request_id, source_ip, metadata, previous_hash, event_hash
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
    $13, $14, NULLIF($15, '')::inet, $16, $17, $18
)
`,
		event.ID,
		event.OccurredAt,
		event.ProductID,
		event.ActorSubject,
		event.ActorKind,
		event.ActorProvider,
		roleValues,
		event.ActorProductIDs,
		event.TokenID,
		event.Action,
		event.ResourceType,
		event.ResourceID,
		event.Outcome,
		event.RequestID,
		event.SourceIP,
		event.Metadata,
		event.PreviousHash,
		event.EventHash,
	); err != nil {
		return Event{}, fmt.Errorf("insert audit event: %w", err)
	}
	result, err := tx.Exec(ctx, `
UPDATE audit_chain_heads
SET head_hash = $2, updated_at = clock_timestamp()
WHERE partition_key = $1 AND head_hash = $3
`, partitionKey, event.EventHash, event.PreviousHash)
	if err != nil {
		return Event{}, fmt.Errorf("advance audit hash chain: %w", err)
	}
	if result.RowsAffected() != 1 {
		return Event{}, errors.New("audit hash chain changed unexpectedly")
	}
	return event, nil
}

func (repository *PostgresRepository) Query(ctx context.Context, filter QueryFilter) ([]Event, error) {
	if repository == nil || repository.pool == nil {
		return nil, ErrRepositoryRequired
	}
	if filter.Limit <= 0 || filter.Limit > 500 || (!filter.Since.IsZero() && !filter.Until.IsZero() && filter.Since.After(filter.Until)) {
		return nil, ErrQueryFilterInvalid
	}
	query := `
SELECT
    id, occurred_at, product_id, actor_subject, actor_kind, actor_provider,
    actor_roles, actor_product_ids, token_id, action, resource_type, resource_id,
    outcome, request_id, COALESCE(host(source_ip), ''), metadata, previous_hash, event_hash
FROM audit_events
WHERE TRUE`
	arguments := make([]any, 0, 8)
	addCondition := func(condition string, value any) {
		arguments = append(arguments, value)
		query += fmt.Sprintf("\n  AND "+condition, len(arguments))
	}
	if filter.ProductID != "" {
		addCondition("product_id = $%d", filter.ProductID)
	}
	if filter.ActorSubject != "" {
		addCondition("actor_subject = $%d", filter.ActorSubject)
	}
	if filter.Action != "" {
		addCondition("action = $%d", filter.Action)
	}
	if filter.Outcome != "" {
		addCondition("outcome = $%d", filter.Outcome)
	}
	if !filter.Since.IsZero() {
		addCondition("occurred_at >= $%d", filter.Since.UTC())
	}
	if !filter.Until.IsZero() {
		addCondition("occurred_at <= $%d", filter.Until.UTC())
	}
	if !filter.BeforeTime.IsZero() || filter.BeforeID != [16]byte{} {
		if filter.BeforeTime.IsZero() || filter.BeforeID == [16]byte{} {
			return nil, ErrQueryFilterInvalid
		}
		arguments = append(arguments, filter.BeforeTime.UTC(), filter.BeforeID)
		query += fmt.Sprintf("\n  AND (occurred_at, id) < ($%d, $%d)", len(arguments)-1, len(arguments))
	}
	arguments = append(arguments, filter.Limit)
	query += fmt.Sprintf("\nORDER BY occurred_at DESC, id DESC\nLIMIT $%d", len(arguments))

	rows, err := repository.pool.Query(ctx, query, arguments...)
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	defer rows.Close()
	events := make([]Event, 0, filter.Limit)
	for rows.Next() {
		event, scanErr := scanEvent(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan audit event: %w", scanErr)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit events: %w", err)
	}
	return events, nil
}

func (repository *PostgresRepository) StartExport(ctx context.Context, tx pgx.Tx, export Export) error {
	if tx == nil {
		return ErrTransactionRequired
	}
	_, err := tx.Exec(ctx, `
INSERT INTO audit_exports (
    id, product_id, requested_by, request_id, filter, status,
    object_key, error_code, created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, '', '', $7, $7)
`,
		export.ID,
		export.ProductID,
		export.RequestedBy,
		export.RequestID,
		export.Filter,
		export.Status,
		export.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert audit export request: %w", err)
	}
	return nil
}

func (repository *PostgresRepository) GetExport(ctx context.Context, id uuid.UUID) (Export, error) {
	if repository == nil || repository.pool == nil {
		return Export{}, ErrRepositoryRequired
	}
	var export Export
	var expiresAt *time.Time
	err := repository.pool.QueryRow(ctx, `
SELECT
    id, product_id, requested_by, request_id, filter, status,
    object_key, COALESCE(sha256, ''), COALESCE(size_bytes, 0), expires_at,
    error_code, created_at, updated_at
FROM audit_exports
WHERE id = $1
`, id).Scan(
		&export.ID,
		&export.ProductID,
		&export.RequestedBy,
		&export.RequestID,
		&export.Filter,
		&export.Status,
		&export.ObjectKey,
		&export.SHA256,
		&export.SizeBytes,
		&expiresAt,
		&export.ErrorCode,
		&export.CreatedAt,
		&export.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Export{}, ErrExportNotFound
	}
	if err != nil {
		return Export{}, fmt.Errorf("get audit export: %w", err)
	}
	if expiresAt != nil {
		export.ExpiresAt = expiresAt.UTC()
	}
	return export, nil
}

func (repository *PostgresRepository) CompleteExport(ctx context.Context, tx pgx.Tx, completed Export) error {
	if tx == nil {
		return ErrTransactionRequired
	}
	if completed.ID == uuid.Nil || completed.ObjectKey == "" || len(completed.SHA256) != 64 || completed.SizeBytes <= 0 || completed.ExpiresAt.IsZero() || completed.UpdatedAt.IsZero() {
		return ErrExportFilterInvalid
	}
	result, err := tx.Exec(ctx, `
UPDATE audit_exports
SET status = 'completed', object_key = $2, sha256 = $3, size_bytes = $4,
    expires_at = $5, error_code = '', updated_at = $6
WHERE id = $1 AND status = 'pending'
`, completed.ID, completed.ObjectKey, completed.SHA256, completed.SizeBytes,
		completed.ExpiresAt.UTC(), completed.UpdatedAt.UTC())
	if err != nil {
		return fmt.Errorf("complete audit export: %w", err)
	}
	if result.RowsAffected() != 1 {
		current, getErr := repository.GetExport(ctx, completed.ID)
		if getErr == nil && current.Status == ExportStatusCompleted && current.ObjectKey == completed.ObjectKey && current.SHA256 == completed.SHA256 {
			return nil
		}
		return ErrExportNotReady
	}
	return nil
}

func (repository *PostgresRepository) FailExport(ctx context.Context, tx pgx.Tx, id uuid.UUID, code string, failedAt time.Time) error {
	if tx == nil {
		return ErrTransactionRequired
	}
	code = strings.TrimSpace(code)
	if id == uuid.Nil || code == "" || len(code) > 128 || failedAt.IsZero() {
		return ErrExportFilterInvalid
	}
	result, err := tx.Exec(ctx, `
UPDATE audit_exports
SET status = 'failed', error_code = $2, updated_at = $3
WHERE id = $1 AND status = 'pending'
`, id, code, failedAt.UTC())
	if err != nil {
		return fmt.Errorf("fail audit export: %w", err)
	}
	if result.RowsAffected() != 1 {
		current, getErr := repository.GetExport(ctx, id)
		if getErr == nil && current.Status == ExportStatusFailed && current.ErrorCode == code {
			return nil
		}
		return ErrExportNotReady
	}
	return nil
}

func calculateEventHash(event Event) (string, error) {
	canonical := struct {
		ID              string                    `json:"id"`
		OccurredAt      string                    `json:"occurred_at"`
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
		RequestID       string                    `json:"request_id"`
		SourceIP        string                    `json:"source_ip"`
		Metadata        json.RawMessage           `json:"metadata"`
		PreviousHash    string                    `json:"previous_hash"`
	}{
		ID:              event.ID.String(),
		OccurredAt:      event.OccurredAt.UTC().Format(time.RFC3339Nano),
		ProductID:       event.ProductID,
		ActorSubject:    event.ActorSubject,
		ActorKind:       event.ActorKind,
		ActorProvider:   event.ActorProvider,
		ActorRoles:      event.ActorRoles,
		ActorProductIDs: event.ActorProductIDs,
		TokenID:         event.TokenID,
		Action:          event.Action,
		ResourceType:    event.ResourceType,
		ResourceID:      event.ResourceID,
		Outcome:         event.Outcome,
		RequestID:       event.RequestID.String(),
		SourceIP:        event.SourceIP,
		Metadata:        event.Metadata,
		PreviousHash:    strings.TrimSpace(event.PreviousHash),
	}
	payload, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("canonicalize audit event: %w", err)
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

type eventRowScanner interface {
	Scan(dest ...any) error
}

func scanEvent(row eventRowScanner) (Event, error) {
	var event Event
	var roleValues []string
	err := row.Scan(
		&event.ID,
		&event.OccurredAt,
		&event.ProductID,
		&event.ActorSubject,
		&event.ActorKind,
		&event.ActorProvider,
		&roleValues,
		&event.ActorProductIDs,
		&event.TokenID,
		&event.Action,
		&event.ResourceType,
		&event.ResourceID,
		&event.Outcome,
		&event.RequestID,
		&event.SourceIP,
		&event.Metadata,
		&event.PreviousHash,
		&event.EventHash,
	)
	if err != nil {
		return Event{}, err
	}
	event.ActorRoles = make([]identity.Role, len(roleValues))
	for index, role := range roleValues {
		event.ActorRoles[index] = identity.Role(role)
	}
	event.PreviousHash = strings.TrimSpace(event.PreviousHash)
	event.EventHash = strings.TrimSpace(event.EventHash)
	return event, nil
}
