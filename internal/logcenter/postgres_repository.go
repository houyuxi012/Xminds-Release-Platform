package logcenter

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrRepositoryUnavailable = errors.New("log repository unavailable")
	ErrEventIdentityConflict = errors.New("log event identity conflict")
	ErrEventAlreadyExists    = errors.New("log event already exists")
)

func nilIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}

type PostgresRepository struct{ pool *pgxpool.Pool }

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func appendIdentityAndExec(ctx context.Context, tx pgx.Tx, repo *PostgresRepository, eventID, kind string, occurred time.Time, value any, query string, args ...any) error {
	payload, err := canonicalPayload(value)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	if err := repo.ClaimEventIdentity(ctx, tx, eventID, kind, occurred.UTC().Format("2006-01"), eventID, digest[:], occurred); err != nil {
		if errors.Is(err, ErrEventAlreadyExists) {
			return nil
		}
		return err
	}
	_, err = tx.Exec(ctx, query, args...)
	return err
}

func canonicalPayload(value any) ([]byte, error) {
	switch event := value.(type) {
	case OperationCommand:
		return json.Marshal(struct {
			ID, At, Request, Product, Action, ResourceType, ResourceID string
			Result                                                     Result
			Metadata                                                   EventMetadata
			Summary                                                    map[string]any
		}{event.EventID, event.OccurredAt.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano), event.Metadata.RequestID, event.ProductID, event.Action, event.ResourceType, event.ResourceID, event.Result, event.Metadata, event.MetadataSummary})
	case AuthenticationEvent:
		return json.Marshal(struct {
			ID, At, Request, Product, Subject, Source, Method, MFA, Client, Reason string
			Result                                                                 Result
			Metadata                                                               EventMetadata
		}{event.EventID, event.OccurredAt.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano), event.Metadata.RequestID, event.ProductID, event.Subject, event.IdentitySourceID, event.AuthenticationMethod, event.MFALevel, event.ClientName, event.ReasonCode, event.Result, event.Metadata})
	case GitSyncEvent:
		return json.Marshal(struct {
			ID, At, Request, Product, Provider, RepoID, Repo, SHA, Tag, Stage, Error string
			Attempt                                                                  int
			Result                                                                   Result
			Metadata                                                                 EventMetadata
		}{event.EventID, event.OccurredAt.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano), event.Metadata.RequestID, event.ProductID, event.Provider, event.RepositoryID, event.RepositoryName, event.CommitSHA, event.TagName, event.Stage, event.ErrorCode, event.Attempt, event.Result, event.Metadata})
	case ApplicationRequestEvent:
		return json.Marshal(struct {
			ID, At, Request, Product, ClientID, ClientVersion, Method, Route, Customer, CustomerName, Tenant, Authorization, License, Status, Decision, Reason, Issuer string
			HTTPStatus                                                                                                                                                 *int
			Duration                                                                                                                                                   int64
			Trusted                                                                                                                                                    bool
			ExpiresAt, ValidatedAt                                                                                                                                     string
			Digest                                                                                                                                                     []byte
			Result                                                                                                                                                     Result
			Metadata                                                                                                                                                   EventMetadata
		}{event.EventID, event.OccurredAt.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano), event.Metadata.RequestID, event.ProductID, event.ClientAppID, event.ClientAppVersion, event.HTTPMethod, event.RouteTemplate, event.CustomerID, event.CustomerName, event.TenantID, event.AuthorizationName, event.LicenseID, event.LicenseStatus, event.Decision, event.ReasonCode, event.ValidatorIssuer, event.HTTPStatus, event.DurationMS, event.SnapshotTrusted, formatTime(event.LicenseExpiresAt), formatTime(event.ValidatedAt), append([]byte(nil), event.ContextDigest...), event.Result, event.Metadata})
	default:
		return nil, ErrEventIdentityConflict
	}
}

func formatTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
}

func (repository *PostgresRepository) AppendOperation(ctx context.Context, tx pgx.Tx, input OperationCommand) error {
	e, err := NewOperation(input)
	if err != nil {
		return err
	}
	return appendIdentityAndExec(ctx, tx, repository, e.EventID, "operation", e.OccurredAt, e, `INSERT INTO log_operation_events(event_id,occurred_at,request_id,correlation_id,trace_id,product_id,actor_subject,actor_kind,action,resource_type,resource_id,result,source_ip,metadata_summary,schema_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, e.EventID, e.OccurredAt, e.Metadata.RequestID, nilIfEmpty(e.Metadata.CorrelationID), nilIfEmpty(e.Metadata.TraceID), nilIfEmpty(e.ProductID), nilIfEmpty(e.ActorSubject), nilIfEmpty(e.ActorKind), e.Action, e.ResourceType, nilIfEmpty(e.ResourceID), e.Result, nilIfEmpty(e.Metadata.SourceIP), e.MetadataSummary, e.Metadata.SchemaVersion)
}

func (repository *PostgresRepository) AppendAuthentication(ctx context.Context, tx pgx.Tx, input AuthenticationEvent) error {
	e, err := NewAuthentication(input)
	if err != nil {
		return err
	}
	return appendIdentityAndExec(ctx, tx, repository, e.EventID, "authentication", e.OccurredAt, e, `INSERT INTO log_authentication_events(event_id,occurred_at,request_id,correlation_id,trace_id,product_id,subject,identity_source_id,authentication_method,mfa_level,client_name,result,reason_code,source_ip,schema_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, e.EventID, e.OccurredAt, e.Metadata.RequestID, nilIfEmpty(e.Metadata.CorrelationID), nilIfEmpty(e.Metadata.TraceID), nilIfEmpty(e.ProductID), e.Subject, e.IdentitySourceID, e.AuthenticationMethod, nilIfEmpty(e.MFALevel), nilIfEmpty(e.ClientName), e.Result, nilIfEmpty(e.ReasonCode), nilIfEmpty(e.Metadata.SourceIP), e.Metadata.SchemaVersion)
}

func (repository *PostgresRepository) AppendGitSync(ctx context.Context, tx pgx.Tx, input GitSyncEvent) error {
	e, err := NewGitSync(input)
	if err != nil {
		return err
	}
	return appendIdentityAndExec(ctx, tx, repository, e.EventID, "git_sync", e.OccurredAt, e, `INSERT INTO log_git_sync_events(event_id,occurred_at,request_id,correlation_id,trace_id,product_id,provider,repository_id,repository_name,commit_sha,tag_name,stage,attempt,result,error_code,source_ip,schema_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, e.EventID, e.OccurredAt, e.Metadata.RequestID, nilIfEmpty(e.Metadata.CorrelationID), nilIfEmpty(e.Metadata.TraceID), nilIfEmpty(e.ProductID), e.Provider, e.RepositoryID, e.RepositoryName, nilIfEmpty(e.CommitSHA), nilIfEmpty(e.TagName), e.Stage, e.Attempt, e.Result, nilIfEmpty(e.ErrorCode), nilIfEmpty(e.Metadata.SourceIP), e.Metadata.SchemaVersion)
}

func (repository *PostgresRepository) AppendApplicationRequest(ctx context.Context, input ApplicationRequestEvent) error {
	if repository == nil || repository.pool == nil {
		return ErrRepositoryUnavailable
	}
	e, err := NewApplicationRequest(input)
	if err != nil {
		return err
	}
	tx, err := repository.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = appendIdentityAndExec(ctx, tx, repository, e.EventID, "application_request", e.OccurredAt, e, `INSERT INTO log_application_request_events(event_id,occurred_at,request_id,correlation_id,trace_id,product_id,client_app_id,client_app_version,http_method,route_template,http_status,duration_ms,snapshot_trusted,customer_id,customer_name,tenant_id,authorization_name,license_id,license_expires_at,license_status,decision,reason_code,validated_at,validator_issuer,context_digest,result,source_ip,schema_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28)`, e.EventID, e.OccurredAt, e.Metadata.RequestID, nilIfEmpty(e.Metadata.CorrelationID), nilIfEmpty(e.Metadata.TraceID), nilIfEmpty(e.ProductID), e.ClientAppID, e.ClientAppVersion, e.HTTPMethod, e.RouteTemplate, e.HTTPStatus, e.DurationMS, e.SnapshotTrusted, nilIfEmpty(e.CustomerID), nilIfEmpty(e.CustomerName), nilIfEmpty(e.TenantID), nilIfEmpty(e.AuthorizationName), nilIfEmpty(e.LicenseID), e.LicenseExpiresAt, e.LicenseStatus, e.Decision, e.ReasonCode, e.ValidatedAt, e.ValidatorIssuer, e.ContextDigest, e.Result, nilIfEmpty(e.Metadata.SourceIP), e.Metadata.SchemaVersion); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (repository *PostgresRepository) ClaimEventIdentity(ctx context.Context, tx pgx.Tx, eventID, logType, periodKey, dedupeKey string, digest []byte, createdAt time.Time) error {
	if repository == nil || repository.pool == nil || tx == nil {
		return ErrRepositoryUnavailable
	}
	id, err := uuid.Parse(eventID)
	if err != nil || len(digest) != 32 {
		return ErrEventIdentityConflict
	}
	var claimed uuid.UUID
	err = tx.QueryRow(ctx, `INSERT INTO log_event_identities(event_id,log_type,period_key,dedupe_key,payload_digest,created_at) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING RETURNING event_id`, id, logType, periodKey, dedupeKey, digest, createdAt.UTC()).Scan(&claimed)
	if err == nil {
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("claim log event identity: %w", err)
	}
	var existingType, existingPeriod string
	var existingDigest []byte
	if err := tx.QueryRow(ctx, `SELECT log_type,period_key,payload_digest FROM log_event_identities WHERE event_id=$1 OR (log_type=$2 AND dedupe_key=$3) LIMIT 1`, id, logType, dedupeKey).Scan(&existingType, &existingPeriod, &existingDigest); err != nil {
		return fmt.Errorf("read log event identity: %w", err)
	}
	if existingType != logType || existingPeriod != periodKey || string(existingDigest) != string(digest) {
		return ErrEventIdentityConflict
	}
	return ErrEventAlreadyExists
}
