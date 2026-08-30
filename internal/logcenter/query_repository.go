package logcenter

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrInvalidLogQuery = errors.New("invalid log query")

type LogQueryFilters struct {
	From              time.Time `json:"from,omitempty"`
	To                time.Time `json:"to,omitempty"`
	ProductID         string    `json:"product_id,omitempty"`
	CustomerID        string    `json:"customer_id,omitempty"`
	AuthorizationName string    `json:"authorization_name,omitempty"`
	ClientAppID       string    `json:"client_app_id,omitempty"`
	ClientAppVersion  string    `json:"client_app_version,omitempty"`
	LicenseID         string    `json:"license_id,omitempty"`
	LicenseStatus     string    `json:"license_status,omitempty"`
	Decision          string    `json:"decision,omitempty"`
	Result            string    `json:"result,omitempty"`
	RequestID         string    `json:"request_id,omitempty"`
	CorrelationID     string    `json:"correlation_id,omitempty"`
	HTTPStatus        *int      `json:"http_status,omitempty"`
	Limit             int       `json:"limit,omitempty"`
	Cursor            string    `json:"cursor,omitempty"`
}
type LogQueryRow struct{ Values map[string]any }
type LogQueryPage struct {
	Items      []LogQueryRow
	NextCursor string
}
type QueryRepository struct {
	pool    *pgxpool.Pool
	cursors *CursorCodec
}

func (q *QueryRepository) QueryRelated(ctx context.Context, scope LogReadScope, f LogQueryFilters) (LogQueryPage, error) {
	if q == nil || q.pool == nil {
		return LogQueryPage{}, ErrRepositoryUnavailable
	}
	if f.RequestID == "" && f.CorrelationID == "" {
		return LogQueryPage{}, ErrInvalidLogQuery
	}
	if err := validateLogFilters(f); err != nil {
		return LogQueryPage{}, err
	}
	if f.Limit == 0 {
		f.Limit = 50
	}
	var boundary LogCursor
	if f.Cursor != "" {
		if q.cursors == nil {
			return LogQueryPage{}, ErrRepositoryUnavailable
		}
		decoded, err := q.cursors.Decode(f.Cursor, "related", queryFilterDigest(f), scope.Digest, f.Limit)
		if err != nil {
			return LogQueryPage{}, err
		}
		boundary = decoded
	}
	base := f
	base.Cursor = ""
	out := LogQueryPage{}
	for _, t := range []ScopeTable{ScopeTableOperations, ScopeTableAuthentications, ScopeTableApplicationRequests, ScopeTableGitSyncs} {
		branch := base
		if boundary.LastOccurredAt != nil && string(t) >= boundary.LastLogType {
			if q.cursors == nil {
				return LogQueryPage{}, ErrRepositoryUnavailable
			}
			token, err := q.cursors.Encode(LogCursor{Route: string(t), FilterDigest: queryFilterDigest(base), ScopeDigest: scope.Digest, Limit: base.Limit, LastEventID: boundary.LastEventID, LastOccurredAt: boundary.LastOccurredAt})
			if err != nil {
				return LogQueryPage{}, err
			}
			branch.Cursor = token
		}
		p, e := q.Query(ctx, scope, t, branch)
		if e != nil {
			return LogQueryPage{}, e
		}
		for _, row := range p.Items {
			if row.Values == nil {
				row.Values = map[string]any{}
			}
			row.Values["log_type"] = string(t)
			out.Items = append(out.Items, row)
		}
	}
	sort.SliceStable(out.Items, func(i, j int) bool {
		ai, aok := out.Items[i].Values["occurred_at"].(time.Time)
		aj, bok := out.Items[j].Values["occurred_at"].(time.Time)
		if aok && bok && !ai.Equal(aj) {
			return ai.After(aj)
		}
		aiID, _ := queryUUIDString(out.Items[i].Values["event_id"])
		ajID, _ := queryUUIDString(out.Items[j].Values["event_id"])
		if aiID != ajID {
			return aiID > ajID
		}
		return fmt.Sprint(out.Items[i].Values["log_type"]) > fmt.Sprint(out.Items[j].Values["log_type"])
	})
	if boundary.LastOccurredAt != nil {
		filtered := out.Items[:0]
		for _, item := range out.Items {
			occurred, ok := item.Values["occurred_at"].(time.Time)
			if !ok {
				continue
			}
			id, ok := queryUUIDString(item.Values["event_id"])
			if !ok {
				continue
			}
			logType, _ := item.Values["log_type"].(string)
			if occurred.Before(*boundary.LastOccurredAt) || (occurred.Equal(*boundary.LastOccurredAt) && (id < boundary.LastEventID || (id == boundary.LastEventID && logType < boundary.LastLogType))) {
				filtered = append(filtered, item)
			}
		}
		out.Items = filtered
	}
	if len(out.Items) > f.Limit {
		last := out.Items[f.Limit-1]
		out.Items = out.Items[:f.Limit]
		if q.cursors == nil {
			return LogQueryPage{}, ErrRepositoryUnavailable
		}
		occurred, ok := last.Values["occurred_at"].(time.Time)
		if !ok {
			return LogQueryPage{}, ErrInvalidLogQuery
		}
		occurred = occurred.UTC()
		id, ok := queryUUIDString(last.Values["event_id"])
		if !ok {
			return LogQueryPage{}, ErrInvalidLogQuery
		}
		typeName, _ := last.Values["log_type"].(string)
		token, err := q.cursors.Encode(LogCursor{Route: "related", FilterDigest: queryFilterDigest(base), ScopeDigest: scope.Digest, Limit: f.Limit, LastEventID: id, LastLogType: typeName, LastOccurredAt: &occurred})
		if err != nil {
			return LogQueryPage{}, err
		}
		out.NextCursor = token
	}
	return out, nil
}

func queryFilterDigest(f LogQueryFilters) [32]byte {
	f.Cursor = ""
	return FilterDigest(fmt.Sprintf("%+v", f))
}

func physicalLogTable(table ScopeTable) string {
	switch table {
	case ScopeTableOperations:
		return "log_operation_events"
	case ScopeTableAuthentications:
		return "log_authentication_events"
	case ScopeTableApplicationRequests:
		return "log_application_request_events"
	case ScopeTableGitSyncs:
		return "log_git_sync_events"
	}
	return ""
}

func NewQueryRepository(pool *pgxpool.Pool, cursors *CursorCodec) *QueryRepository {
	return &QueryRepository{pool: pool, cursors: cursors}
}

func validateLogFilters(f LogQueryFilters) error {
	if f.Limit == 0 {
		f.Limit = 50
	}
	if f.Limit < 1 || f.Limit > 200 {
		return ErrInvalidLogQuery
	}
	if f.From.IsZero() != f.To.IsZero() {
		return ErrInvalidLogQuery
	}
	if !f.From.IsZero() && (f.To.Before(f.From) || f.To.Sub(f.From) > 31*24*time.Hour) {
		return ErrInvalidLogQuery
	}
	for _, v := range []string{f.ProductID, f.CustomerID, f.AuthorizationName, f.ClientAppID, f.ClientAppVersion, f.LicenseID, f.LicenseStatus, f.Decision, f.Result, f.RequestID, f.CorrelationID} {
		if len(v) > 256 || strings.TrimSpace(v) != v {
			return ErrInvalidLogQuery
		}
	}
	if f.HTTPStatus != nil && (*f.HTTPStatus < 100 || *f.HTTPStatus > 599) {
		return ErrInvalidLogQuery
	}
	if len(f.Cursor) > 512 {
		return ErrInvalidLogQuery
	}
	return nil
}
func (q *QueryRepository) Query(ctx context.Context, scope LogReadScope, table ScopeTable, f LogQueryFilters) (LogQueryPage, error) {
	if q == nil || q.pool == nil {
		return LogQueryPage{}, ErrRepositoryUnavailable
	}
	if err := validateLogFilters(f); err != nil {
		return LogQueryPage{}, err
	}
	if f.Limit == 0 {
		f.Limit = 50
	}
	if f.Cursor != "" && q.cursors == nil {
		return LogQueryPage{}, ErrRepositoryUnavailable
	}
	lastKey := ""
	var lastOccurred time.Time
	if f.Cursor != "" && q.cursors != nil {
		decoded, err := q.cursors.Decode(f.Cursor, string(table), queryFilterDigest(f), scope.Digest, f.Limit)
		if err != nil {
			return LogQueryPage{}, err
		}
		lastKey = decoded.LastEventID
		if decoded.LastOccurredAt != nil {
			lastOccurred = *decoded.LastOccurredAt
		}
	}
	physical := physicalLogTable(table)
	if physical == "" {
		return LogQueryPage{}, ErrInvalidLogQuery
	}
	predicate, args, err := ScopePredicate(scope, table)
	if err != nil {
		return LogQueryPage{}, err
	}
	where := []string{predicate}
	if !f.From.IsZero() {
		where = append(where, fmt.Sprintf("occurred_at >= $%d AND occurred_at < $%d", len(args)+1, len(args)+2))
		args = append(args, f.From.UTC(), f.To.UTC())
	}
	if f.ProductID != "" {
		where = append(where, fmt.Sprintf("product_id = $%d", len(args)+1))
		args = append(args, f.ProductID)
	}
	if lastKey != "" {
		where = append(where, fmt.Sprintf("(occurred_at,event_id) < ($%d,$%d)", len(args)+1, len(args)+2))
		args = append(args, lastOccurred, lastKey)
	}
	for _, item := range []struct{ name, val string }{{"request_id", f.RequestID}, {"correlation_id", f.CorrelationID}, {"result", f.Result}} {
		if item.val != "" {
			where = append(where, fmt.Sprintf("%s = $%d", item.name, len(args)+1))
			args = append(args, item.val)
		}
	}
	if table == ScopeTableApplicationRequests {
		for _, item := range []struct{ name, val string }{{"customer_id", f.CustomerID}, {"authorization_name", f.AuthorizationName}, {"client_app_id", f.ClientAppID}, {"client_app_version", f.ClientAppVersion}, {"license_id", f.LicenseID}, {"license_status", f.LicenseStatus}, {"decision", f.Decision}, {"result", f.Result}, {"request_id", f.RequestID}, {"correlation_id", f.CorrelationID}} {
			if item.val != "" {
				where = append(where, fmt.Sprintf("%s = $%d", item.name, len(args)+1))
				args = append(args, item.val)
			}
		}
		if f.HTTPStatus != nil {
			where = append(where, fmt.Sprintf("http_status = $%d", len(args)+1))
			args = append(args, *f.HTTPStatus)
		}
	}
	sql := fmt.Sprintf("SELECT * FROM %s WHERE %s ORDER BY occurred_at DESC,event_id DESC LIMIT %d", physical, strings.Join(where, " AND "), f.Limit+1)
	rows, err := q.pool.Query(ctx, sql, args...)
	if err != nil {
		return LogQueryPage{}, err
	}
	defer rows.Close()
	out := LogQueryPage{Items: make([]LogQueryRow, 0)}
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			return LogQueryPage{}, err
		}
		fields := rows.FieldDescriptions()
		m := make(map[string]any, len(vals))
		for i, v := range vals {
			m[string(fields[i].Name)] = v
		}
		out.Items = append(out.Items, LogQueryRow{Values: m})
	}
	if err := rows.Err(); err != nil {
		return LogQueryPage{}, err
	}
	if len(out.Items) > f.Limit {
		last := out.Items[f.Limit-1]
		out.Items = out.Items[:f.Limit]
		if q.cursors != nil {
			id, ok := queryUUIDString(last.Values["event_id"])
			if !ok {
				return LogQueryPage{}, ErrInvalidLogQuery
			}
			occurred, ok := last.Values["occurred_at"].(time.Time)
			if !ok {
				return LogQueryPage{}, ErrInvalidLogQuery
			}
			occurred = occurred.UTC()
			token, err := q.cursors.Encode(LogCursor{Route: string(table), FilterDigest: queryFilterDigest(f), ScopeDigest: scope.Digest, Limit: f.Limit, LastEventID: id, LastOccurredAt: &occurred})
			if err != nil {
				return LogQueryPage{}, err
			}
			out.NextCursor = token
		}
	}
	return out, nil
}
func queryUUIDString(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		_, e := uuid.Parse(v)
		return v, e == nil
	case uuid.UUID:
		return v.String(), true
	case [16]byte:
		return uuid.UUID(v).String(), true
	case pgtype.UUID:
		if !v.Valid {
			return "", false
		}
		id, err := uuid.FromBytes(v.Bytes[:])
		if err != nil {
			return "", false
		}
		return id.String(), true
	default:
		return "", false
	}
}
func (q *QueryRepository) QueryOperations(ctx context.Context, s LogReadScope, f LogQueryFilters) (LogQueryPage, error) {
	return q.Query(ctx, s, ScopeTableOperations, f)
}
func (q *QueryRepository) QueryAuthentications(ctx context.Context, s LogReadScope, f LogQueryFilters) (LogQueryPage, error) {
	return q.Query(ctx, s, ScopeTableAuthentications, f)
}
func (q *QueryRepository) QueryApplicationRequests(ctx context.Context, s LogReadScope, f LogQueryFilters) (LogQueryPage, error) {
	return q.Query(ctx, s, ScopeTableApplicationRequests, f)
}
func (q *QueryRepository) QueryGitSyncs(ctx context.Context, s LogReadScope, f LogQueryFilters) (LogQueryPage, error) {
	return q.Query(ctx, s, ScopeTableGitSyncs, f)
}

var _ = pgx.ErrNoRows
