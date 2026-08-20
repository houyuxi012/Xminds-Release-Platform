package scm

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestGitHubAdapterVerifiesSHA256WebhookAndNormalizesTagPush(t *testing.T) {
	t.Parallel()

	secret := []byte("github-webhook-secret-with-adequate-entropy")
	credentialID := uuid.New()
	body := []byte(`{"ref":"refs/tags/v1.2.3","after":"0123456789012345678901234567890123456789","repository":{"full_name":"acme/ngep"},"sender":{"login":"release-bot"},"head_commit":{"timestamp":"2026-08-20T08:00:00Z"}}`)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(body)
	headers := http.Header{
		"X-Github-Delivery":   []string{"delivery-42"},
		"X-Github-Event":      []string{"push"},
		"X-Hub-Signature-256": []string{"sha256=" + hex.EncodeToString(mac.Sum(nil))},
	}
	adapter, err := NewGitHubAdapter(AdapterConfig{
		Credentials: fixedCredentialStore{credentials: map[uuid.UUID]SecretCredential{
			credentialID: {ID: credentialID, Kind: CredentialKindWebhookSecret, Secret: secret},
		}},
		Clock: func() time.Time { return time.Date(2026, 8, 20, 8, 0, 1, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	event, err := adapter.VerifyWebhook(context.Background(), Connection{
		ID: uuid.New(), Provider: ProviderGitHub, Status: ConnectionStatusActive, WebhookCredentialID: credentialID,
	}, headers, body)
	if err != nil {
		t.Fatal(err)
	}
	if event.EventID != "delivery-42" || event.EventType != "push" || event.Repository != "acme/ngep" ||
		event.Ref != "refs/tags/v1.2.3" || event.Tag != "v1.2.3" || event.CommitSHA != "0123456789012345678901234567890123456789" ||
		event.Actor != "release-bot" || !event.OccurredAt.Equal(time.Date(2026, 8, 20, 8, 0, 0, 0, time.UTC)) {
		t.Fatalf("normalized event = %+v", event)
	}
	if event.PayloadDigest != "4b8e9b8412502f8719a63181afbf2fbd3372d6fe24b6f780bb58ebb60fee8400" {
		t.Fatalf("payload digest = %q", event.PayloadDigest)
	}

	headers.Set("X-Hub-Signature-256", "sha256="+string(make([]byte, 64)))
	if _, err := adapter.VerifyWebhook(context.Background(), Connection{
		ID: uuid.New(), Provider: ProviderGitHub, Status: ConnectionStatusActive, WebhookCredentialID: credentialID,
	}, headers, body); err != ErrWebhookSignatureInvalid {
		t.Fatalf("invalid signature error = %v, want %v", err, ErrWebhookSignatureInvalid)
	}
}

func TestGitHubAdapterGetsCommitWithExplicitEnterpriseAPIBaseURL(t *testing.T) {
	t.Parallel()

	credentialID := uuid.New()
	sha := "0123456789012345678901234567890123456789"
	doer := &recordingDoer{response: jsonResponse(http.StatusOK, `{"sha":"`+sha+`","html_url":"https://github.corp/acme/ngep/commit/`+sha+`","commit":{"message":"release","author":{"name":"Alice","date":"2026-08-20T08:00:00Z"}}}`)}
	adapter := mustGitHubAdapter(t, AdapterConfig{
		Clients: fixedClientFactory{client: doer},
		Credentials: fixedCredentialStore{credentials: map[uuid.UUID]SecretCredential{
			credentialID: {ID: credentialID, Kind: CredentialKindGitHubToken, Secret: []byte("github-access-token")},
		}}, Clock: time.Now,
	})
	commit, err := adapter.GetCommit(context.Background(), Connection{
		ID: uuid.New(), Provider: ProviderGitHub, Status: ConnectionStatusActive,
		APIBaseURL: "https://github.corp.example/api/v3", CredentialID: credentialID,
	}, "acme/ngep", sha)
	if err != nil {
		t.Fatal(err)
	}
	if commit.SHA != sha || commit.Author != "Alice" || commit.Message != "release" {
		t.Fatalf("commit = %+v", commit)
	}
	if doer.request.Method != http.MethodGet || doer.request.URL.String() != "https://github.corp.example/api/v3/repos/acme/ngep/commits/"+sha ||
		doer.request.Header.Get("Authorization") != "Bearer github-access-token" {
		t.Fatalf("request = %s %s headers=%v", doer.request.Method, doer.request.URL, doer.request.Header)
	}
}

func TestGitHubAdapterWritesCommitStatusWhenChecksAreUnavailable(t *testing.T) {
	t.Parallel()

	credentialID := uuid.New()
	sha := "0123456789012345678901234567890123456789"
	doer := &recordingDoer{response: jsonResponse(http.StatusCreated, `{}`)}
	adapter := mustGitHubAdapter(t, AdapterConfig{
		Clients: fixedClientFactory{client: doer},
		Credentials: fixedCredentialStore{credentials: map[uuid.UUID]SecretCredential{
			credentialID: {ID: credentialID, Kind: CredentialKindGitHubToken, Secret: []byte("github-access-token")},
		}}, Clock: time.Now,
	})
	err := adapter.WriteStatus(context.Background(), Connection{
		ID: uuid.New(), Provider: ProviderGitHub, Status: ConnectionStatusActive,
		APIBaseURL: "https://api.github.com", CredentialID: credentialID,
		Capabilities: Capabilities{CommitStatuses: true},
	}, CommitStatus{
		Repository: "acme/ngep", SHA: sha, State: CommitStateSuccess,
		Context: "xminds/release", Description: "Published", TargetURL: "https://release.example/releases/42",
	})
	if err != nil {
		t.Fatal(err)
	}
	if doer.request.Method != http.MethodPost || doer.request.URL.String() != "https://api.github.com/repos/acme/ngep/statuses/"+sha {
		t.Fatalf("request = %s %s", doer.request.Method, doer.request.URL)
	}
	if string(doer.body) != `{"context":"xminds/release","description":"Published","state":"success","target_url":"https://release.example/releases/42"}`+"\n" {
		t.Fatalf("request body = %q", doer.body)
	}
}

func TestGitHubAdapterWritesCheckRunWhenCapabilityIsAvailable(t *testing.T) {
	t.Parallel()

	credentialID := uuid.New()
	sha := "0123456789012345678901234567890123456789"
	doer := &recordingDoer{response: jsonResponse(http.StatusCreated, `{}`)}
	adapter := mustGitHubAdapter(t, AdapterConfig{
		Clients: fixedClientFactory{client: doer},
		Credentials: fixedCredentialStore{credentials: map[uuid.UUID]SecretCredential{
			credentialID: {ID: credentialID, Kind: CredentialKindGitHubAppToken, Secret: []byte("github-app-token")},
		}}, Clock: time.Now,
	})
	err := adapter.WriteStatus(context.Background(), Connection{
		ID: uuid.New(), Provider: ProviderGitHub, Status: ConnectionStatusActive,
		APIBaseURL: "https://api.github.com", CredentialID: credentialID,
		Capabilities: Capabilities{CheckRuns: true, CommitStatuses: true},
	}, CommitStatus{
		Repository: "acme/ngep", SHA: sha, State: CommitStateFailure,
		Context: "xminds/release", Description: "Publication failed", TargetURL: "https://release.example/releases/42",
	})
	if err != nil {
		t.Fatal(err)
	}
	if doer.request.URL.String() != "https://api.github.com/repos/acme/ngep/check-runs" {
		t.Fatalf("request URL = %s", doer.request.URL)
	}
	if string(doer.body) != `{"conclusion":"failure","details_url":"https://release.example/releases/42","head_sha":"`+sha+`","name":"xminds/release","output":{"summary":"Publication failed","title":"Xminds Release Platform"},"status":"completed"}`+"\n" {
		t.Fatalf("request body = %q", doer.body)
	}
}

func mustGitHubAdapter(t *testing.T, config AdapterConfig) *GitHubAdapter {
	t.Helper()
	adapter, err := NewGitHubAdapter(config)
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

type fixedClientFactory struct{ client HTTPDoer }

func (factory fixedClientFactory) ClientFor(Connection) (HTTPDoer, error) { return factory.client, nil }

type recordingDoer struct {
	request  *http.Request
	body     []byte
	response *http.Response
	err      error
}

func (doer *recordingDoer) Do(request *http.Request) (*http.Response, error) {
	doer.request = request.Clone(request.Context())
	if request.Body != nil {
		doer.body, _ = io.ReadAll(request.Body)
	}
	return doer.response, doer.err
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(strings.TrimSpace(body))),
	}
}
