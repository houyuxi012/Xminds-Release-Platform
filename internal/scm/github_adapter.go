package scm

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"xminds-release-platform/internal/identity"
)

const maximumProviderResponseBytes = 4 * 1024 * 1024

type GitHubAdapter struct {
	credentials CredentialUser
	clients     SCMClientFactory
	workloads   WorkloadVerifierResolver
	clock       func() time.Time
}

func NewGitHubAdapter(config AdapterConfig) (*GitHubAdapter, error) {
	if config.Credentials == nil || config.Clock == nil {
		return nil, ErrConnectionInvalid
	}
	return &GitHubAdapter{credentials: config.Credentials, clients: config.Clients, workloads: config.Workloads, clock: config.Clock}, nil
}

func (adapter *GitHubAdapter) VerifyConnection(ctx context.Context, connection Connection) (Capabilities, error) {
	if connection.Provider != ProviderGitHub || connection.Status != ConnectionStatusActive {
		return Capabilities{}, ErrConnectionInvalid
	}
	endpoint, err := providerProbeEndpoint(connection.APIBaseURL, "meta")
	if err != nil {
		return Capabilities{}, err
	}
	response, err := adapter.githubRequest(ctx, connection, http.MethodGet, endpoint, nil)
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
	capabilities := Capabilities{CommitStatuses: true, WorkloadOIDC: strings.TrimSpace(connection.OIDCIssuer) != "", CertificateSHA256: fingerprint}
	err = adapter.credentials.UseCredential(ctx, connection.CredentialID, func(credential SecretCredential) error {
		capabilities.CheckRuns = credential.Kind == CredentialKindGitHubAppToken
		return nil
	})
	return capabilities, err
}

func (adapter *GitHubAdapter) VerifyWorkload(ctx context.Context, connection Connection, token string) (identity.Principal, error) {
	principal, err := verifyProviderWorkload(ctx, adapter.workloads, connection, ProviderGitHub, strings.TrimSpace(token))
	if err != nil {
		return identity.Principal{}, err
	}
	if principal.Provider != identity.WorkloadProviderGitHubActions && principal.Provider != identity.WorkloadProviderGitHubEnterpriseActions {
		return identity.Principal{}, ErrWorkloadIdentityInvalid
	}
	return principal, nil
}

func (adapter *GitHubAdapter) VerifyWebhook(ctx context.Context, connection Connection, headers http.Header, body []byte) (WebhookEvent, error) {
	if adapter == nil || connection.Provider != ProviderGitHub || connection.Status != ConnectionStatusActive || connection.WebhookCredentialID == [16]byte{} || len(body) == 0 || len(body) > maximumWebhookPayloadBytes {
		return WebhookEvent{}, ErrWebhookEventInvalid
	}
	signature := strings.TrimSpace(headers.Get("X-Hub-Signature-256"))
	if len(signature) != len("sha256=")+sha256.Size*2 || !strings.HasPrefix(signature, "sha256=") {
		return WebhookEvent{}, ErrWebhookSignatureInvalid
	}
	provided, err := hex.DecodeString(strings.TrimPrefix(signature, "sha256="))
	if err != nil || len(provided) != sha256.Size {
		return WebhookEvent{}, ErrWebhookSignatureInvalid
	}
	err = adapter.credentials.UseCredential(ctx, connection.WebhookCredentialID, func(credential SecretCredential) error {
		if credential.Kind != CredentialKindWebhookSecret || len(credential.Secret) < 16 {
			return ErrCredentialUnavailable
		}
		mac := hmac.New(sha256.New, credential.Secret)
		_, _ = mac.Write(body)
		if !hmac.Equal(provided, mac.Sum(nil)) {
			return ErrWebhookSignatureInvalid
		}
		return nil
	})
	if err != nil {
		return WebhookEvent{}, err
	}

	var payload struct {
		Ref        string `json:"ref"`
		After      string `json:"after"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
		Sender struct {
			Login string `json:"login"`
		} `json:"sender"`
		HeadCommit struct {
			Timestamp time.Time `json:"timestamp"`
		} `json:"head_commit"`
		WorkflowRun struct {
			ID         int64     `json:"id"`
			HeadSHA    string    `json:"head_sha"`
			HeadBranch string    `json:"head_branch"`
			UpdatedAt  time.Time `json:"updated_at"`
		} `json:"workflow_run"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return WebhookEvent{}, ErrWebhookEventInvalid
	}
	eventType := strings.ToLower(strings.TrimSpace(headers.Get("X-GitHub-Event")))
	event := WebhookEvent{
		Provider: ProviderGitHub, EventID: strings.TrimSpace(headers.Get("X-GitHub-Delivery")), EventType: eventType,
		Repository: strings.TrimSpace(payload.Repository.FullName), Ref: strings.TrimSpace(payload.Ref),
		CommitSHA: strings.ToLower(strings.TrimSpace(payload.After)), Actor: strings.TrimSpace(payload.Sender.Login),
		OccurredAt: payload.HeadCommit.Timestamp.UTC(), Payload: append([]byte(nil), body...),
	}
	if eventType == "workflow_run" {
		event.CommitSHA = strings.ToLower(strings.TrimSpace(payload.WorkflowRun.HeadSHA))
		event.Ref = "refs/heads/" + strings.TrimSpace(payload.WorkflowRun.HeadBranch)
		event.PipelineID = formatPositiveID(payload.WorkflowRun.ID)
		event.OccurredAt = payload.WorkflowRun.UpdatedAt.UTC()
	}
	if strings.HasPrefix(event.Ref, "refs/tags/") {
		event.Tag = strings.TrimPrefix(event.Ref, "refs/tags/")
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = adapter.clock().UTC()
	}
	digest := sha256.Sum256(body)
	event.PayloadDigest = hex.EncodeToString(digest[:])
	if !eventIDPattern.MatchString(event.EventID) || !repositoryPattern.MatchString(event.Repository) || !commitSHAPattern.MatchString(event.CommitSHA) || event.Actor == "" || (eventType != "push" && eventType != "workflow_run") {
		return WebhookEvent{}, ErrWebhookEventInvalid
	}
	return event, nil
}

func (adapter *GitHubAdapter) GetCommit(ctx context.Context, connection Connection, repository, sha string) (Commit, error) {
	sha = strings.ToLower(strings.TrimSpace(sha))
	if err := validateProviderOperation(connection, ProviderGitHub, repository, sha); err != nil {
		return Commit{}, err
	}
	endpoint, err := githubEndpoint(connection.APIBaseURL, repository, "commits", sha)
	if err != nil {
		return Commit{}, err
	}
	response, err := adapter.githubRequest(ctx, connection, http.MethodGet, endpoint, nil)
	if err != nil {
		return Commit{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Commit{}, providerHTTPError(response.StatusCode)
	}
	var payload struct {
		SHA     string `json:"sha"`
		HTMLURL string `json:"html_url"`
		Commit  struct {
			Message string `json:"message"`
			Author  struct {
				Name string    `json:"name"`
				Date time.Time `json:"date"`
			} `json:"author"`
		} `json:"commit"`
	}
	if err := decodeProviderJSON(response, &payload); err != nil {
		return Commit{}, err
	}
	payload.SHA = strings.ToLower(strings.TrimSpace(payload.SHA))
	if payload.SHA != sha || strings.TrimSpace(payload.Commit.Author.Name) == "" || strings.TrimSpace(payload.Commit.Message) == "" {
		return Commit{}, ErrProviderResponseInvalid
	}
	return Commit{
		Repository: repository, SHA: payload.SHA, WebURL: strings.TrimSpace(payload.HTMLURL),
		Author: strings.TrimSpace(payload.Commit.Author.Name), Message: strings.TrimSpace(payload.Commit.Message),
		CommittedAt: payload.Commit.Author.Date.UTC(),
	}, nil
}

func (adapter *GitHubAdapter) WriteStatus(ctx context.Context, connection Connection, status CommitStatus) error {
	status.SHA = strings.ToLower(strings.TrimSpace(status.SHA))
	if err := validateCommitStatus(connection, ProviderGitHub, status); err != nil {
		return err
	}
	if connection.Capabilities.CheckRuns {
		return adapter.writeCheckRun(ctx, connection, status)
	}
	if !connection.Capabilities.CommitStatuses {
		return ErrProviderUnsupported
	}
	endpoint, err := githubEndpoint(connection.APIBaseURL, status.Repository, "statuses", status.SHA)
	if err != nil {
		return err
	}
	payload := struct {
		Context     string `json:"context"`
		Description string `json:"description"`
		State       string `json:"state"`
		TargetURL   string `json:"target_url"`
	}{Context: status.Context, Description: status.Description, State: string(status.State), TargetURL: status.TargetURL}
	body := &bytes.Buffer{}
	encoder := json.NewEncoder(body)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(payload); err != nil {
		return ErrProviderRequestFailed
	}
	response, err := adapter.githubRequest(ctx, connection, http.MethodPost, endpoint, body)
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

func (adapter *GitHubAdapter) writeCheckRun(ctx context.Context, connection Connection, status CommitStatus) error {
	endpoint, err := githubEndpoint(connection.APIBaseURL, status.Repository, "check-runs")
	if err != nil {
		return err
	}
	checkStatus := "completed"
	conclusion := string(status.State)
	if status.State == CommitStatePending {
		checkStatus = "in_progress"
		conclusion = ""
	} else if status.State == CommitStateError {
		conclusion = "failure"
	}
	payload := struct {
		Conclusion string `json:"conclusion,omitempty"`
		DetailsURL string `json:"details_url,omitempty"`
		HeadSHA    string `json:"head_sha"`
		Name       string `json:"name"`
		Output     struct {
			Summary string `json:"summary"`
			Title   string `json:"title"`
		} `json:"output"`
		Status string `json:"status"`
	}{Conclusion: conclusion, DetailsURL: status.TargetURL, HeadSHA: status.SHA, Name: status.Context, Status: checkStatus}
	payload.Output.Summary = status.Description
	payload.Output.Title = "Xminds Release Platform"
	body := &bytes.Buffer{}
	encoder := json.NewEncoder(body)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(payload); err != nil {
		return ErrProviderRequestFailed
	}
	response, err := adapter.githubRequest(ctx, connection, http.MethodPost, endpoint, body)
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

func (adapter *GitHubAdapter) githubRequest(ctx context.Context, connection Connection, method, endpoint string, body io.Reader) (*http.Response, error) {
	if adapter == nil || adapter.clients == nil || adapter.credentials == nil || connection.CredentialID == [16]byte{} {
		return nil, ErrConnectionInvalid
	}
	client, err := adapter.clients.ClientFor(connection)
	if err != nil || client == nil {
		return nil, errors.Join(ErrProviderRequestFailed, err)
	}
	var response *http.Response
	err = adapter.credentials.UseCredential(ctx, connection.CredentialID, func(credential SecretCredential) error {
		if credential.Kind != CredentialKindGitHubToken && credential.Kind != CredentialKindGitHubAppToken {
			return ErrCredentialUnavailable
		}
		request, requestErr := http.NewRequestWithContext(ctx, method, endpoint, body)
		if requestErr != nil {
			return ErrProviderRequestFailed
		}
		request.Header.Set("Accept", "application/vnd.github+json")
		request.Header.Set("Authorization", "Bearer "+string(credential.Secret))
		request.Header.Set("Content-Type", "application/json")
		if version := strings.TrimSpace(connection.APIVersion); version != "" {
			request.Header.Set("X-GitHub-Api-Version", version)
		}
		response, requestErr = client.Do(request)
		if requestErr != nil {
			return errors.Join(ErrProviderRequestFailed, requestErr)
		}
		return nil
	})
	return response, err
}

func githubEndpoint(baseURL, repository string, parts ...string) (string, error) {
	parsed, err := parseConnectionAPIBaseURL(baseURL)
	if err != nil || !repositoryPattern.MatchString(repository) {
		return "", ErrConnectionInvalid
	}
	repositoryParts := strings.Split(repository, "/")
	allParts := []string{parsed.Path, "repos", url.PathEscape(repositoryParts[0]), url.PathEscape(repositoryParts[1])}
	for _, part := range parts {
		allParts = append(allParts, url.PathEscape(part))
	}
	parsed.Path = path.Join(allParts...)
	parsed.RawPath = ""
	return parsed.String(), nil
}

func validateProviderOperation(connection Connection, kind ProviderKind, repository, sha string) error {
	if connection.ID == [16]byte{} || connection.Provider != kind || connection.Status != ConnectionStatusActive ||
		!repositoryPattern.MatchString(strings.TrimSpace(repository)) || !commitSHAPattern.MatchString(sha) {
		return ErrConnectionInvalid
	}
	return nil
}

func validateCommitStatus(connection Connection, kind ProviderKind, status CommitStatus) error {
	if err := validateProviderOperation(connection, kind, status.Repository, status.SHA); err != nil {
		return err
	}
	if status.State != CommitStatePending && status.State != CommitStateSuccess && status.State != CommitStateFailure && status.State != CommitStateError {
		return ErrProviderRequestFailed
	}
	if strings.TrimSpace(status.Context) == "" || len(status.Context) > 100 || len(status.Description) > 140 {
		return ErrProviderRequestFailed
	}
	if status.TargetURL != "" {
		parsed, err := url.Parse(status.TargetURL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return ErrProviderRequestFailed
		}
	}
	return nil
}

func decodeProviderJSON(response *http.Response, target any) error {
	if response == nil || response.Body == nil || !strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "json") {
		return ErrProviderResponseInvalid
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maximumProviderResponseBytes+1))
	if err := decoder.Decode(target); err != nil {
		return ErrProviderResponseInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrProviderResponseInvalid
	}
	return nil
}

func providerHTTPError(statusCode int) error {
	return fmt.Errorf("%w: HTTP status %d", ErrProviderRequestFailed, statusCode)
}
