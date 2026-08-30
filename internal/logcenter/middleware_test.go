package logcenter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"xminds-release-platform/internal/authorizationcontext"
)

type middlewareResolver struct {
	verified authorizationcontext.VerifiedContext
	claimed  bool
}

func (r *middlewareResolver) VerifyAndCanonicalize(context.Context, authorizationcontext.SignedEnvelope, authorizationcontext.RequestBinding) (authorizationcontext.VerifiedContext, error) {
	return r.verified, nil
}
func (r *middlewareResolver) Claim(context.Context, authorizationcontext.VerifiedContext) (authorizationcontext.Snapshot, error) {
	r.claimed = true
	return r.verified.SnapshotCandidate, nil
}

type middlewareSpool struct{ writes int }

func (s *middlewareSpool) ReserveAndWrite([]byte) error                      { s.writes++; return nil }
func (s *middlewareSpool) ReplaceEventIntent(string, middlewareIntent) error { s.writes++; return nil }

func TestAuthorizationMiddlewarePersistsIntentBeforeClaimAndCallsHandler(t *testing.T) {
	resolver := &middlewareResolver{verified: authorizationcontext.VerifiedContext{SnapshotCandidate: authorizationcontext.Snapshot{Decision: authorizationcontext.DecisionAllow}, ValidatorIssuer: "issuer", ContextID: "ctx"}}
	spool := &middlewareSpool{}
	called := false
	h := AuthorizationMiddleware(MiddlewareConfig{Resolver: resolver, Spool: spool, ProductID: "release"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(http.StatusNoContent) }))
	req := httptest.NewRequest(http.MethodGet, "/v1/products", nil)
	req.Header.Set("X-Xminds-Authorization-Context", "signed")
	req.Header.Set("X-Request-ID", uuid.New().String())
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusNoContent || !called || !resolver.claimed || spool.writes != 2 {
		t.Fatalf("status=%d called=%v claimed=%v writes=%d", res.Code, called, resolver.claimed, spool.writes)
	}
}

func TestAuthorizationMiddlewareSpoolSaturationDoesNotClaimOrCallHandler(t *testing.T) {
	resolver := &middlewareResolver{verified: authorizationcontext.VerifiedContext{SnapshotCandidate: authorizationcontext.Snapshot{Decision: authorizationcontext.DecisionAllow}, ValidatorIssuer: "issuer", ContextID: "ctx"}}
	spool := &failingMiddlewareSpool{}
	called := false
	h := AuthorizationMiddleware(MiddlewareConfig{Resolver: resolver, Spool: spool}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Xminds-Authorization-Context", "signed")
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusServiceUnavailable || called || resolver.claimed {
		t.Fatalf("status=%d called=%v claimed=%v", res.Code, called, resolver.claimed)
	}
}

type failingMiddlewareSpool struct{}

func (*failingMiddlewareSpool) ReserveAndWrite([]byte) error { return ErrSpoolFull }
