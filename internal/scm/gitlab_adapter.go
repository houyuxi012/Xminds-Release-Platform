package scm

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"xminds-release-platform/internal/identity"
)

const maximumWebhookClockSkew = 5 * time.Minute

type GitLabAdapter struct {
	credentials CredentialUser
	clients     SCMClientFactory
	workloads   WorkloadVerifierResolver
	clock       func() time.Time
}

func (adapter *GitLabAdapter) GetCommit(ctx context.Context, connection Connection, repository, sha string) (Commit, error) {
	sha = strings.ToLower(strings.TrimSpace(sha))
	if err := validateProviderOperation(connection, ProviderGitLab, repository, sha); err != nil {
		return Commit{}, err
	}
	endpoint, err := gitlabEndpoint(connection.APIBaseURL, repository, "repository", "commits", sha)
	if err != nil {
		return Commit{}, err
	}
	response, err := adapter.gitlabRequest(ctx, connection, http.MethodGet, endpoint, nil, "")
	if err != nil {
		return Commit{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Commit{}, providerHTTPError(response.StatusCode)
	}
	var payload struct {
		ID            string    `json:"id"`
		WebURL        string    `json:"web_url"`
		Message       string    `json:"message"`
		AuthorName    string    `json:"author_name"`
		CommittedDate time.Time `json:"committed_date"`
	}
	if err := decodeProviderJSON(response, &payload); err != nil {
		return Commit{}, err
	}
	payload.ID = strings.ToLower(strings.TrimSpace(payload.ID))
	if payload.ID != sha || strings.TrimSpace(payload.AuthorName) == "" || strings.TrimSpace(payload.Message) == "" {
		return Commit{}, ErrProviderResponseInvalid
	}
	return Commit{
		Repository: repository, SHA: payload.ID, WebURL: strings.TrimSpace(payload.WebURL),
		Author: strings.TrimSpace(payload.AuthorName), Message: strings.TrimSpace(payload.Message),
		CommittedAt: payload.CommittedDate.UTC(),
	}, nil
}

func (adapter *GitLabAdapter) WriteStatus(ctx context.Context, connection Connection, status CommitStatus) error {
	status.SHA = strings.ToLower(strings.TrimSpace(status.SHA))
	if err := validateCommitStatus(connection, ProviderGitLab, status); err != nil {
		return err
	}
	if !connection.Capabilities.CommitStatuses {
		return ErrProviderUnsupported
	}
	endpoint, err := gitlabEndpoint(connection.APIBaseURL, status.Repository, "statuses", status.SHA)
	if err != nil {
		return err
	}
	state := string(status.State)
	if status.State == CommitStateError {
		state = string(CommitStateFailure)
	}
	values := url.Values{
		"description": []string{status.Description},
		"name":        []string{status.Context},
		"state":       []string{state},
	}
	if status.TargetURL != "" {
		values.Set("target_url", status.TargetURL)
	}
	response, err := adapter.gitlabRequest(ctx, connection, http.MethodPost, endpoint, bytes.NewBufferString(values.Encode()), "application/x-www-form-urlencoded")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return providerHTTPError(response.StatusCode)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumProviderResponseBytes+1))
	return nil
}

func (adapter *GitLabAdapter) gitlabRequest(ctx context.Context, connection Connection, method, endpoint string, body io.Reader, contentType string) (*http.Response, error) {
	if adapter == nil || adapter.clients == nil || adapter.credentials == nil || connection.CredentialID == [16]byte{} {
		return nil, ErrConnectionInvalid
	}
	client, err := adapter.clients.ClientFor(connection)
	if err != nil || client == nil {
		return nil, errors.Join(ErrProviderRequestFailed, err)
	}
	var response *http.Response
	err = adapter.credentials.UseCredential(ctx, connection.CredentialID, func(credential SecretCredential) error {
		if credential.Kind != CredentialKindGitLabAccessToken {
			return ErrCredentialUnavailable
		}
		request, requestErr := http.NewRequestWithContext(ctx, method, endpoint, body)
		if requestErr != nil {
			return ErrProviderRequestFailed
		}
		request.Header.Set("Accept", "application/json")
		request.Header.Set("PRIVATE-TOKEN", string(credential.Secret))
		if contentType != "" {
			request.Header.Set("Content-Type", contentType)
		}
		response, requestErr = client.Do(request)
		if requestErr != nil {
			return errors.Join(ErrProviderRequestFailed, requestErr)
		}
		return nil
	})
	return response, err
}

func gitlabEndpoint(baseURL, repository string, parts ...string) (string, error) {
	parsed, err := parseConnectionAPIBaseURL(baseURL)
	if err != nil || !repositoryPattern.MatchString(repository) {
		return "", ErrConnectionInvalid
	}
	base := strings.TrimSuffix(parsed.String(), "/")
	endpoint := base + "/projects/" + url.PathEscape(repository)
	for _, part := range parts {
		endpoint += "/" + url.PathEscape(part)
	}
	return endpoint, nil
}

func NewGitLabAdapter(config AdapterConfig) (*GitLabAdapter, error) {
	if config.Credentials == nil || config.Clock == nil {
		return nil, ErrConnectionInvalid
	}
	return &GitLabAdapter{credentials: config.Credentials, clients: config.Clients, workloads: config.Workloads, clock: config.Clock}, nil
}

func (adapter *GitLabAdapter) VerifyConnection(ctx context.Context, connection Connection) (Capabilities, error) {
	if connection.Provider != ProviderGitLab || connection.Status != ConnectionStatusActive {
		return Capabilities{}, ErrConnectionInvalid
	}
	endpoint, err := providerProbeEndpoint(connection.APIBaseURL, "version")
	if err != nil {
		return Capabilities{}, err
	}
	response, err := adapter.gitlabRequest(ctx, connection, http.MethodGet, endpoint, nil, "")
	if err != nil {
		return Capabilities{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Capabilities{}, providerHTTPError(response.StatusCode)
	}
	fingerprint, err := peerCertificateFingerprint(response)
	if err != nil {
		return Capabilities{}, err
	}
	return Capabilities{
		CommitStatuses: true, WorkloadOIDC: strings.TrimSpace(connection.OIDCIssuer) != "", CertificateSHA256: fingerprint,
	}, nil
}

func (adapter *GitLabAdapter) VerifyWorkload(ctx context.Context, connection Connection, token string) (identity.Principal, error) {
	principal, err := verifyProviderWorkload(ctx, adapter.workloads, connection, ProviderGitLab, strings.TrimSpace(token))
	if err != nil {
		return identity.Principal{}, err
	}
	if principal.Provider != identity.WorkloadProviderGitLabCI {
		return identity.Principal{}, ErrWorkloadIdentityInvalid
	}
	return principal, nil
}

func (adapter *GitLabAdapter) VerifyWebhook(ctx context.Context, connection Connection, headers http.Header, body []byte) (WebhookEvent, error) {
	if adapter == nil || connection.Provider != ProviderGitLab || connection.Status != ConnectionStatusActive || connection.WebhookCredentialID == [16]byte{} || len(body) == 0 || len(body) > maximumWebhookPayloadBytes {
		return WebhookEvent{}, ErrWebhookEventInvalid
	}
	now := adapter.clock().UTC()
	var eventID string
	signedAt := now
	err := adapter.credentials.UseCredential(ctx, connection.WebhookCredentialID, func(credential SecretCredential) error {
		switch credential.Kind {
		case CredentialKindWebhookSigningToken:
			eventID = strings.TrimSpace(headers.Get("Webhook-Id"))
			timestampText := strings.TrimSpace(headers.Get("Webhook-Timestamp"))
			timestamp, parseErr := strconv.ParseInt(timestampText, 10, 64)
			if parseErr != nil || !eventIDPattern.MatchString(eventID) {
				return ErrWebhookSignatureInvalid
			}
			signedAt = time.Unix(timestamp, 0).UTC()
			if signedAt.Before(now.Add(-maximumWebhookClockSkew)) || signedAt.After(now.Add(maximumWebhookClockSkew)) {
				return ErrWebhookSignatureInvalid
			}
			signatures := strings.Fields(headers.Get("Webhook-Signature"))
			if len(signatures) == 0 {
				return ErrWebhookSignatureInvalid
			}
			token := strings.TrimPrefix(string(credential.Secret), "whsec_")
			key, decodeErr := base64.StdEncoding.DecodeString(token)
			if decodeErr != nil || len(key) != 32 {
				wipeBytes(key)
				return ErrCredentialUnavailable
			}
			defer wipeBytes(key)
			mac := hmac.New(sha256.New, key)
			_, _ = mac.Write([]byte(eventID))
			_, _ = mac.Write([]byte("."))
			_, _ = mac.Write([]byte(timestampText))
			_, _ = mac.Write([]byte("."))
			_, _ = mac.Write(body)
			expected := mac.Sum(nil)
			for _, signature := range signatures {
				if !strings.HasPrefix(signature, "v1,") {
					continue
				}
				provided, decodeErr := base64.StdEncoding.DecodeString(strings.TrimPrefix(signature, "v1,"))
				if decodeErr == nil && hmac.Equal(provided, expected) {
					return nil
				}
			}
			return ErrWebhookSignatureInvalid
		case CredentialKindWebhookSecret:
			eventID = strings.TrimSpace(headers.Get("X-Gitlab-Event-UUID"))
			if eventID == "" {
				eventID = strings.TrimSpace(headers.Get("X-Gitlab-Webhook-UUID"))
			}
			provided := []byte(headers.Get("X-Gitlab-Token"))
			if !eventIDPattern.MatchString(eventID) || len(credential.Secret) < 16 || !hmac.Equal(provided, credential.Secret) {
				return ErrWebhookSignatureInvalid
			}
			return nil
		default:
			return ErrCredentialUnavailable
		}
	})
	if err != nil {
		return WebhookEvent{}, err
	}

	var payload struct {
		ObjectKind     string    `json:"object_kind"`
		EventCreatedAt time.Time `json:"event_created_at"`
		Ref            string    `json:"ref"`
		CheckoutSHA    string    `json:"checkout_sha"`
		After          string    `json:"after"`
		UserUsername   string    `json:"user_username"`
		Project        struct {
			PathWithNamespace string `json:"path_with_namespace"`
		} `json:"project"`
		ObjectAttributes struct {
			ID        int64     `json:"id"`
			SHA       string    `json:"sha"`
			Ref       string    `json:"ref"`
			CreatedAt time.Time `json:"created_at"`
		} `json:"object_attributes"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return WebhookEvent{}, ErrWebhookEventInvalid
	}
	eventType := strings.ToLower(strings.TrimSpace(payload.ObjectKind))
	commitSHA := strings.ToLower(strings.TrimSpace(payload.CheckoutSHA))
	if commitSHA == "" {
		commitSHA = strings.ToLower(strings.TrimSpace(payload.After))
	}
	event := WebhookEvent{
		Provider: ProviderGitLab, EventID: eventID, EventType: eventType,
		Repository: strings.TrimSpace(payload.Project.PathWithNamespace), Ref: strings.TrimSpace(payload.Ref),
		CommitSHA: commitSHA, Actor: strings.TrimSpace(payload.UserUsername), OccurredAt: payload.EventCreatedAt.UTC(),
		Payload: append([]byte(nil), body...),
	}
	if eventType == "pipeline" {
		event.CommitSHA = strings.ToLower(strings.TrimSpace(payload.ObjectAttributes.SHA))
		event.Ref = "refs/heads/" + strings.TrimSpace(payload.ObjectAttributes.Ref)
		event.PipelineID = formatPositiveID(payload.ObjectAttributes.ID)
		event.OccurredAt = payload.ObjectAttributes.CreatedAt.UTC()
	}
	if strings.HasPrefix(event.Ref, "refs/tags/") {
		event.Tag = strings.TrimPrefix(event.Ref, "refs/tags/")
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = signedAt
	}
	digest := sha256.Sum256(body)
	event.PayloadDigest = hex.EncodeToString(digest[:])
	if !repositoryPattern.MatchString(event.Repository) || !commitSHAPattern.MatchString(event.CommitSHA) || event.Actor == "" || (eventType != "push" && eventType != "pipeline") {
		return WebhookEvent{}, ErrWebhookEventInvalid
	}
	return event, nil
}

func formatPositiveID(value int64) string {
	if value <= 0 {
		return ""
	}
	return strconv.FormatInt(value, 10)
}
