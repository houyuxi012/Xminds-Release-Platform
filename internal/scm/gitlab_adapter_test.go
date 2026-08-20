package scm

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestGitLabAdapterVerifiesStandardWebhookAndNormalizesPush(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 20, 8, 0, 0, 0, time.UTC)
	key := []byte("01234567890123456789012345678901")
	token := []byte("whsec_" + base64.StdEncoding.EncodeToString(key))
	credentialID := uuid.New()
	body := []byte(`{"object_kind":"push","event_created_at":"2026-08-20T08:00:00Z","ref":"refs/heads/main","checkout_sha":"abcdefabcdefabcdefabcdefabcdefabcdefabcd","user_username":"gitlab-bot","project":{"path_with_namespace":"acme/ngep"}}`)
	eventID := "019cff00-1111-7000-8000-000000000042"
	timestamp := strconv.FormatInt(now.Unix(), 10)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(eventID + "." + timestamp + "." + string(body)))
	headers := http.Header{
		"Webhook-Id":        []string{eventID},
		"Webhook-Timestamp": []string{timestamp},
		"Webhook-Signature": []string{"v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))},
		"X-Gitlab-Event":    []string{"Push Hook"},
	}
	adapter, err := NewGitLabAdapter(AdapterConfig{
		Credentials: fixedCredentialStore{credentials: map[uuid.UUID]SecretCredential{
			credentialID: {ID: credentialID, Kind: CredentialKindWebhookSigningToken, Secret: token},
		}},
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	event, err := adapter.VerifyWebhook(context.Background(), Connection{
		ID: uuid.New(), Provider: ProviderGitLab, Status: ConnectionStatusActive, WebhookCredentialID: credentialID,
	}, headers, body)
	if err != nil {
		t.Fatal(err)
	}
	if event.EventID != eventID || event.EventType != "push" || event.Repository != "acme/ngep" || event.Ref != "refs/heads/main" ||
		event.CommitSHA != "abcdefabcdefabcdefabcdefabcdefabcdefabcd" || event.Actor != "gitlab-bot" || !event.OccurredAt.Equal(now) {
		t.Fatalf("normalized event = %+v", event)
	}
	if event.PayloadDigest != "45e13731bfc51947367a003edb529afa3c39784bf57a09fc5d98021aa19a3853" {
		t.Fatalf("payload digest = %q", event.PayloadDigest)
	}
}

func TestGitLabAdapterGetsCommitFromSelfManagedAPI(t *testing.T) {
	t.Parallel()

	credentialID := uuid.New()
	sha := "abcdefabcdefabcdefabcdefabcdefabcdefabcd"
	doer := &recordingDoer{response: jsonResponse(http.StatusOK, `{"id":"`+sha+`","web_url":"https://gitlab.corp/acme/ngep/-/commit/`+sha+`","message":"release","author_name":"Alice","committed_date":"2026-08-20T08:00:00Z"}`)}
	adapter := mustGitLabAdapter(t, AdapterConfig{
		Clients: fixedClientFactory{client: doer},
		Credentials: fixedCredentialStore{credentials: map[uuid.UUID]SecretCredential{
			credentialID: {ID: credentialID, Kind: CredentialKindGitLabAccessToken, Secret: []byte("gitlab-access-token")},
		}}, Clock: time.Now,
	})
	commit, err := adapter.GetCommit(context.Background(), Connection{
		ID: uuid.New(), Provider: ProviderGitLab, Status: ConnectionStatusActive,
		APIBaseURL: "https://gitlab.corp.example/api/v4", CredentialID: credentialID,
	}, "acme/ngep", sha)
	if err != nil {
		t.Fatal(err)
	}
	if commit.SHA != sha || commit.Author != "Alice" || commit.Message != "release" {
		t.Fatalf("commit = %+v", commit)
	}
	if doer.request.URL.String() != "https://gitlab.corp.example/api/v4/projects/acme%2Fngep/repository/commits/"+sha ||
		doer.request.Header.Get("PRIVATE-TOKEN") != "gitlab-access-token" {
		t.Fatalf("request = %s headers=%v", doer.request.URL, doer.request.Header)
	}
}

func TestGitLabAdapterWritesCommitStatus(t *testing.T) {
	t.Parallel()

	credentialID := uuid.New()
	sha := "abcdefabcdefabcdefabcdefabcdefabcdefabcd"
	doer := &recordingDoer{response: jsonResponse(http.StatusCreated, `{}`)}
	adapter := mustGitLabAdapter(t, AdapterConfig{
		Clients: fixedClientFactory{client: doer},
		Credentials: fixedCredentialStore{credentials: map[uuid.UUID]SecretCredential{
			credentialID: {ID: credentialID, Kind: CredentialKindGitLabAccessToken, Secret: []byte("gitlab-access-token")},
		}}, Clock: time.Now,
	})
	err := adapter.WriteStatus(context.Background(), Connection{
		ID: uuid.New(), Provider: ProviderGitLab, Status: ConnectionStatusActive,
		APIBaseURL: "https://gitlab.corp.example/api/v4", CredentialID: credentialID,
		Capabilities: Capabilities{CommitStatuses: true},
	}, CommitStatus{
		Repository: "acme/ngep", SHA: sha, State: CommitStateSuccess,
		Context: "xminds/release", Description: "Published", TargetURL: "https://release.example/releases/42",
	})
	if err != nil {
		t.Fatal(err)
	}
	if doer.request.URL.String() != "https://gitlab.corp.example/api/v4/projects/acme%2Fngep/statuses/"+sha ||
		doer.request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Fatalf("request = %s headers=%v", doer.request.URL, doer.request.Header)
	}
	for _, field := range []string{"description=Published", "name=xminds%2Frelease", "state=success", "target_url=https%3A%2F%2Frelease.example%2Freleases%2F42"} {
		if !strings.Contains(string(doer.body), field) {
			t.Fatalf("request body %q does not contain %q", doer.body, field)
		}
	}
}

func mustGitLabAdapter(t *testing.T, config AdapterConfig) *GitLabAdapter {
	t.Helper()
	adapter, err := NewGitLabAdapter(config)
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func TestGitLabAdapterSupportsLegacySecretTokenDuringSigningMigration(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 20, 8, 0, 0, 0, time.UTC)
	secret := []byte("legacy-gitlab-webhook-secret")
	credentialID := uuid.New()
	body := []byte(`{"object_kind":"push","event_created_at":"2026-08-20T08:00:00Z","ref":"refs/heads/main","checkout_sha":"abcdefabcdefabcdefabcdefabcdefabcdefabcd","user_username":"gitlab-bot","project":{"path_with_namespace":"acme/ngep"}}`)
	headers := http.Header{
		"X-Gitlab-Event":      []string{"Push Hook"},
		"X-Gitlab-Event-Uuid": []string{"legacy-event-42"},
		"X-Gitlab-Token":      []string{string(secret)},
	}
	adapter, err := NewGitLabAdapter(AdapterConfig{
		Credentials: fixedCredentialStore{credentials: map[uuid.UUID]SecretCredential{
			credentialID: {ID: credentialID, Kind: CredentialKindWebhookSecret, Secret: secret},
		}},
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	event, err := adapter.VerifyWebhook(context.Background(), Connection{
		ID: uuid.New(), Provider: ProviderGitLab, Status: ConnectionStatusActive, WebhookCredentialID: credentialID,
	}, headers, body)
	if err != nil {
		t.Fatal(err)
	}
	if event.EventID != "legacy-event-42" || event.Repository != "acme/ngep" {
		t.Fatalf("normalized legacy event = %+v", event)
	}
	headers.Set("X-Gitlab-Token", "wrong-secret")
	if _, err := adapter.VerifyWebhook(context.Background(), Connection{
		ID: uuid.New(), Provider: ProviderGitLab, Status: ConnectionStatusActive, WebhookCredentialID: credentialID,
	}, headers, body); err != ErrWebhookSignatureInvalid {
		t.Fatalf("invalid legacy secret error = %v, want %v", err, ErrWebhookSignatureInvalid)
	}
}

type fixedCredentialStore struct {
	credentials map[uuid.UUID]SecretCredential
}

func (store fixedCredentialStore) UseCredential(_ context.Context, id uuid.UUID, use func(SecretCredential) error) error {
	credential, exists := store.credentials[id]
	if !exists {
		return ErrCredentialUnavailable
	}
	credential.Secret = append([]byte(nil), credential.Secret...)
	defer func() {
		for index := range credential.Secret {
			credential.Secret[index] = 0
		}
	}()
	return use(credential)
}
