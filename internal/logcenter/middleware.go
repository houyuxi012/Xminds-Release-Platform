package logcenter

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"xminds-release-platform/internal/authorizationcontext"
)

// IntentSpool is deliberately smaller than EncryptedSpool so ordering can be
// tested without replacing the encryption boundary.
type IntentSpool interface{ ReserveAndWrite([]byte) error }
type IntentLifecycle interface{ DeleteEventIntents(string) error }
type IntentReplacer interface {
	ReplaceEventIntent(string, middlewareIntent) error
}

// CriticalErrorSink is the observability boundary for failures after a
// request has entered the logging protocol. Implementations should increment
// a durable metric/alert and retain the error details without request data.
type CriticalErrorSink interface {
	RecordCritical(context.Context, error)
}

type MiddlewareConfig struct {
	Resolver       authorizationcontext.Resolver
	Spool          IntentSpool
	ApplicationLog ApplicationRequestWriter
	ProductID      string
	RouteTemplate  func(*http.Request) string
	Critical       CriticalErrorSink
}

var ErrMiddlewareUnavailable = errors.New("authorization middleware unavailable")

type middlewareIntent struct {
	Version           int        `json:"version"`
	EventID           string     `json:"event_id"`
	RequestID         string     `json:"request_id"`
	ProductID         string     `json:"product_id"`
	Method            string     `json:"method"`
	Route             string     `json:"route"`
	StartedAt         time.Time  `json:"started_at"`
	Decision          string     `json:"decision"`
	Reason            string     `json:"reason_code"`
	SnapshotTrusted   bool       `json:"snapshot_trusted"`
	CustomerID        string     `json:"customer_id,omitempty"`
	CustomerName      string     `json:"customer_name,omitempty"`
	TenantID          string     `json:"tenant_id,omitempty"`
	AuthorizationName string     `json:"authorization_name,omitempty"`
	LicenseID         string     `json:"license_id,omitempty"`
	LicenseStatus     string     `json:"license_status,omitempty"`
	LicenseExpiresAt  *time.Time `json:"license_expires_at,omitempty"`
	ValidatedAt       *time.Time `json:"validated_at,omitempty"`
	ValidatorIssuer   string     `json:"validator_issuer,omitempty"`
	ContextDigest     []byte     `json:"context_digest,omitempty"`
	ClientAppID       string     `json:"client_app_id"`
	ClientAppVersion  string     `json:"client_app_version"`
	State             string     `json:"state"`
	Attempts          int        `json:"attempts"`
}

// AuthorizationMiddleware protects a public application handler. The order
// of operations is intentionally explicit: verify, reserve+fsync, claim,
// authorize, then invoke the handler and append the immutable event.
func AuthorizationMiddleware(config MiddlewareConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		started := time.Now()
		requestID := r.Header.Get("X-Request-ID")
		if _, err := uuid.Parse(requestID); err != nil {
			generated, genErr := uuid.NewV7()
			if genErr != nil {
				writeMiddlewareProblem(w, http.StatusServiceUnavailable, "LOG_CENTER_UNAVAILABLE", "request logging is unavailable", requestID)
				return
			}
			requestID = generated.String()
		}
		eventID, eventErr := uuid.NewV7()
		if eventErr != nil {
			writeMiddlewareProblem(w, http.StatusServiceUnavailable, "LOG_CENTER_UNAVAILABLE", "request logging is unavailable", requestID)
			return
		}
		if config.Resolver == nil || config.Spool == nil || next == nil {
			writeMiddlewareProblem(w, http.StatusServiceUnavailable, "AUTHORIZATION_CONTEXT_UNAVAILABLE", "authorization context is unavailable")
			return
		}
		path := r.URL.EscapedPath()
		if path == "" {
			path = r.URL.Path
		}
		verified, err := config.Resolver.VerifyAndCanonicalize(r.Context(), authorizationcontext.SignedEnvelope{Compact: r.Header.Get("X-Xminds-Authorization-Context")}, authorizationcontext.RequestBinding{RequestID: requestID, Method: r.Method, Path: path})
		if err != nil {
			reason := "AUTHORIZATION_CONTEXT_INVALID"
			intent := untrustedMiddlewareIntent(eventID.String(), requestID, config.ProductID, r.Method, path, started, reason)
			if persistErr := persistMiddlewareIntent(config.Spool, intent); persistErr != nil {
				reportCritical(config.Critical, r.Context(), persistErr)
				writeMiddlewareProblem(w, http.StatusServiceUnavailable, "LOG_SPOOL_UNAVAILABLE", "request logging is unavailable", requestID)
				return
			}
			if appendErr := appendUntrustedEvent(r.Context(), config.ApplicationLog, requestID, eventID.String(), config.ProductID, r.Method, path, reason, started); appendErr != nil {
				reportCritical(config.Critical, r.Context(), appendErr)
			} else if lifecycle, ok := config.Spool.(IntentLifecycle); ok {
				if deleteErr := lifecycle.DeleteEventIntents(eventID.String()); deleteErr != nil {
					reportCritical(config.Critical, r.Context(), deleteErr)
				}
			} else {
				reportCritical(config.Critical, r.Context(), ErrMiddlewareUnavailable)
			}
			writeMiddlewareProblem(w, http.StatusForbidden, reason, "authorization context is invalid", requestID)
			return
		}
		candidate := verified.SnapshotCandidate
		reason := candidate.ReasonCode
		if reason == "" {
			reason = "AUTHORIZATION_CONTEXT_INVALID"
		}
		if err := persistMiddlewareIntent(config.Spool, pendingMiddlewareIntent(eventID.String(), requestID, config.ProductID, r.Method, path, started, string(candidate.Decision), reason)); err != nil {
			reportCritical(config.Critical, r.Context(), err)
			writeMiddlewareProblem(w, http.StatusServiceUnavailable, "LOG_SPOOL_SATURATED", "request logging capacity is unavailable", requestID)
			return
		}
		snapshot, err := config.Resolver.Claim(r.Context(), verified)
		if err != nil {
			reason = reasonForClaimError(err)
			intent := untrustedMiddlewareIntent(eventID.String(), requestID, config.ProductID, r.Method, path, started, reason)
			if settleErr := replaceMiddlewareIntent(config.Spool, eventID.String(), intent); settleErr != nil {
				reportCritical(config.Critical, r.Context(), settleErr)
				writeMiddlewareProblem(w, http.StatusServiceUnavailable, "LOG_SPOOL_UNAVAILABLE", "request logging is unavailable", requestID)
				return
			}
			if appendErr := appendUntrustedEvent(r.Context(), config.ApplicationLog, requestID, eventID.String(), config.ProductID, r.Method, path, reason, started); appendErr != nil {
				reportCritical(config.Critical, r.Context(), appendErr)
			} else if lifecycle, ok := config.Spool.(IntentLifecycle); ok {
				if deleteErr := lifecycle.DeleteEventIntents(eventID.String()); deleteErr != nil {
					reportCritical(config.Critical, r.Context(), deleteErr)
				}
			} else {
				reportCritical(config.Critical, r.Context(), ErrMiddlewareUnavailable)
			}
			writeMiddlewareProblem(w, http.StatusForbidden, reason, "authorization context cannot be used", requestID)
			return
		}
		claimedIntent := trustedMiddlewareIntent(eventID.String(), requestID, config.ProductID, r.Method, path, started, string(snapshot.Decision), reason, snapshot, "claimed")
		if err := replaceMiddlewareIntent(config.Spool, eventID.String(), claimedIntent); err != nil {
			reportCritical(config.Critical, r.Context(), err)
			writeMiddlewareProblem(w, http.StatusServiceUnavailable, "LOG_SPOOL_UNAVAILABLE", "request logging is unavailable", requestID)
			return
		}
		status := http.StatusForbidden
		if snapshot.Decision == authorizationcontext.DecisionAllow {
			recorder := &middlewareResponseRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(recorder, r)
			status = recorder.status
		} else {
			writeMiddlewareProblem(w, http.StatusForbidden, reason, "request is not authorized", requestID)
		}
		if config.ApplicationLog != nil {
			route := r.URL.Path
			if config.RouteTemplate != nil {
				route = config.RouteTemplate(r)
			}
			result := ResultDenied
			decision := string(authorizationcontext.DecisionDeny)
			if snapshot.Decision == authorizationcontext.DecisionAllow {
				result = ResultSuccess
				decision = string(snapshot.Decision)
			}
			statusCopy := status
			validated, validatedErr := NewApplicationRequestWithIdentity(ApplicationRequestEvent{Metadata: EventMetadata{RequestID: requestID, SchemaVersion: 1}, EventID: eventID.String(), OccurredAt: time.Now().UTC(), ProductID: config.ProductID, ClientAppID: snapshot.ClientAppID, ClientAppVersion: snapshot.ClientAppVersion, HTTPMethod: r.Method, RouteTemplate: route, HTTPStatus: &statusCopy, DurationMS: time.Since(started).Milliseconds(), SnapshotTrusted: true, CustomerID: snapshot.CustomerID, CustomerName: snapshot.CustomerName, TenantID: snapshot.TenantID, AuthorizationName: snapshot.AuthorizationName, LicenseID: snapshot.LicenseID, LicenseExpiresAt: middlewareTimePtr(snapshot.LicenseExpiresAt), LicenseStatus: string(snapshot.LicenseStatus), Decision: decision, Result: result, ReasonCode: reason, ValidatedAt: middlewareTimePtr(snapshot.ValidatedAt), ValidatorIssuer: snapshot.ValidatorIssuer, ContextDigest: snapshot.ContextDigest[:]}, eventID.String())
			if validatedErr == nil {
				if appendErr := config.ApplicationLog.AppendApplicationRequest(r.Context(), validated); appendErr != nil {
					replacement := untrustedMiddlewareIntent(eventID.String(), requestID, config.ProductID, r.Method, route, started, "REQUEST_COMPLETION_UNKNOWN")
					if err := replaceMiddlewareIntent(config.Spool, eventID.String(), replacement); err != nil {
						reportCritical(config.Critical, r.Context(), err)
					}
				} else if lifecycle, ok := config.Spool.(IntentLifecycle); ok {
					if err := lifecycle.DeleteEventIntents(eventID.String()); err != nil {
						reportCritical(config.Critical, r.Context(), err)
					}
				} else {
					reportCritical(config.Critical, r.Context(), validatedErr)
					fallback := untrustedMiddlewareIntent(eventID.String(), requestID, config.ProductID, r.Method, route, started, "REQUEST_COMPLETION_UNKNOWN")
					if replaceErr := replaceMiddlewareIntent(config.Spool, eventID.String(), fallback); replaceErr != nil {
						reportCritical(config.Critical, r.Context(), replaceErr)
					}
				}
			}
		} else {
			reportCritical(config.Critical, r.Context(), ErrMiddlewareUnavailable)
		}
	})
}

func middlewareTimePtr(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	value = value.UTC()
	return &value
}
func reasonForClaimError(err error) string {
	if errors.Is(err, authorizationcontext.ErrContextReplay) {
		return "CONTEXT_REPLAYED"
	}
	return "CONTEXT_STORE_UNAVAILABLE"
}
func persistMiddlewareIntent(spool IntentSpool, record middlewareIntent) error {
	if spool == nil {
		return ErrMiddlewareUnavailable
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return spool.ReserveAndWrite(payload)
}

func appendUntrustedEvent(ctx context.Context, writer ApplicationRequestWriter, requestID, eventID, product, method, route, reason string, started time.Time) error {
	if writer == nil {
		return ErrMiddlewareUnavailable
	}
	status := http.StatusForbidden
	event, err := NewApplicationRequestWithIdentity(ApplicationRequestEvent{Metadata: EventMetadata{RequestID: requestID, SchemaVersion: 1}, EventID: eventID, OccurredAt: time.Now().UTC(), ProductID: product, ClientAppID: "unknown", ClientAppVersion: "unknown", HTTPMethod: method, RouteTemplate: route, HTTPStatus: &status, DurationMS: time.Since(started).Milliseconds(), SnapshotTrusted: false, Decision: "deny", Result: ResultDenied, ReasonCode: reason}, eventID)
	if err == nil {
		return writer.AppendApplicationRequest(ctx, event)
	}
	return err
}

func pendingMiddlewareIntent(eventID, requestID, product, method, route string, started time.Time, decision, reason string) middlewareIntent {
	return middlewareIntent{Version: 1, EventID: eventID, RequestID: requestID, ProductID: product, Method: method, Route: route, StartedAt: started.UTC(), Decision: decision, Reason: reason, SnapshotTrusted: false, ClientAppID: "unknown", ClientAppVersion: "unknown", State: "pending", Attempts: 1}
}

func untrustedMiddlewareIntent(eventID, requestID, product, method, route string, started time.Time, reason string) middlewareIntent {
	return middlewareIntent{Version: 1, EventID: eventID, RequestID: requestID, ProductID: product, Method: method, Route: route, StartedAt: started.UTC(), Decision: "deny", Reason: reason, SnapshotTrusted: false, ClientAppID: "unknown", ClientAppVersion: "unknown", State: "completed", Attempts: 1}
}

func trustedMiddlewareIntent(eventID, requestID, product, method, route string, started time.Time, decision, reason string, snapshot authorizationcontext.Snapshot, state string) middlewareIntent {
	return middlewareIntent{Version: 1, EventID: eventID, RequestID: requestID, ProductID: product, Method: method, Route: route, StartedAt: started.UTC(), Decision: decision, Reason: reason, SnapshotTrusted: true, ClientAppID: snapshot.ClientAppID, ClientAppVersion: snapshot.ClientAppVersion, CustomerID: snapshot.CustomerID, CustomerName: snapshot.CustomerName, TenantID: snapshot.TenantID, AuthorizationName: snapshot.AuthorizationName, LicenseID: snapshot.LicenseID, LicenseStatus: string(snapshot.LicenseStatus), LicenseExpiresAt: middlewareTimePtr(snapshot.LicenseExpiresAt), ValidatedAt: middlewareTimePtr(snapshot.ValidatedAt), ValidatorIssuer: snapshot.ValidatorIssuer, ContextDigest: snapshot.ContextDigest[:], State: state, Attempts: 1}
}

func replaceMiddlewareIntent(spool IntentSpool, eventID string, record middlewareIntent) error {
	replacer, ok := spool.(IntentReplacer)
	if !ok {
		return ErrMiddlewareUnavailable
	}
	return replacer.ReplaceEventIntent(eventID, record)
}

func reportCritical(sink CriticalErrorSink, ctx context.Context, err error) {
	if err == nil {
		return
	}
	if sink != nil {
		sink.RecordCritical(ctx, err)
		return
	}
	slog.Error("log center critical error", "error", err)
}

func writeMiddlewareProblem(w http.ResponseWriter, status int, code, detail string, requestID ...string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	instance := ""
	if len(requestID) > 0 {
		instance = "/requests/" + requestID[0]
	}
	payload, err := json.Marshal(map[string]any{"type": "https://xminds.dev/problems/" + code, "title": code, "status": status, "detail": detail, "instance": instance})
	if err != nil {
		slog.Error("marshal middleware problem response", "error", err)
		return
	}
	if _, err := w.Write(payload); err != nil {
		slog.Error("write middleware problem response", "error", err)
	}
}

type middlewareResponseRecorder struct {
	http.ResponseWriter
	status int
}

func (r *middlewareResponseRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}
func (r *middlewareResponseRecorder) Write(body []byte) (int, error) {
	if r.status == http.StatusOK {
		r.WriteHeader(http.StatusOK)
	}
	return r.ResponseWriter.Write(body)
}
