package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/database"
)

const fixturePasswordEnvironment = "XMINDS_RELEASE_RUNTIME_FIXTURE_PASSWORD"

type runtimeCredentials struct {
	Username        string    `json:"username"`
	Password        string    `json:"password"`
	TOTPSecret      string    `json:"totp_secret"`
	DisplayName     string    `json:"display_name"`
	TOTPAvailableAt time.Time `json:"totp_available_at"`
}

type runtimeFixtureConfig struct {
	DatabaseURL    string
	APIURL         string
	OutputPath     string
	RepositoryRoot string
	Username       string
	DisplayName    string
	Password       string
}

type enrollmentResponse struct {
	ID     uuid.UUID `json:"id"`
	Secret string    `json:"secret"`
}

func main() {
	config := runtimeFixtureConfig{}
	flag.StringVar(&config.DatabaseURL, "database-url", "", "dedicated loopback PostgreSQL test database URL")
	flag.StringVar(&config.APIURL, "api-url", "", "loopback release API base URL")
	flag.StringVar(&config.OutputPath, "output", "", "absolute path for the private credentials file")
	flag.StringVar(&config.RepositoryRoot, "repository-root", "", "absolute repository root excluded from credentials output")
	flag.StringVar(&config.Username, "username", "runtime.admin", "fixture administrator username")
	flag.StringVar(&config.DisplayName, "display-name", "Runtime Administrator", "fixture administrator display name")
	flag.Parse()
	config.Password = os.Getenv(fixturePasswordEnvironment)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := run(ctx, config); err != nil {
		fmt.Fprintf(os.Stderr, "runtime administrator fixture failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("runtime administrator fixture created")
}

func run(ctx context.Context, config runtimeFixtureConfig) error {
	if err := validateRuntimeConfig(config.DatabaseURL, config.APIURL, config.OutputPath, config.RepositoryRoot); err != nil {
		return err
	}
	config.Username = strings.TrimSpace(config.Username)
	config.DisplayName = strings.TrimSpace(config.DisplayName)
	if config.Username == "" || len(config.Username) > 128 || config.DisplayName == "" || len(config.DisplayName) > 256 {
		return errors.New("fixture identity is invalid")
	}
	if config.Password == "" {
		return fmt.Errorf("%s is required", fixturePasswordEnvironment)
	}
	credentialsFile, err := reserveCredentialsOutput(config.OutputPath)
	if err != nil {
		return err
	}
	credentialsWritten := false
	defer func() {
		if !credentialsWritten {
			_ = credentialsFile.Close()
			_ = os.Remove(config.OutputPath)
		}
	}()

	activationToken, err := randomToken(32)
	if err != nil {
		return errors.New("generate activation token")
	}
	pool, err := database.Open(ctx, config.DatabaseURL)
	if err != nil {
		return errors.New("open dedicated test database")
	}
	defer pool.Close()

	userID, err := seedPendingAdministrator(ctx, pool, config, activationToken)
	if err != nil {
		return err
	}
	enrollment, err := beginEnrollment(ctx, config.APIURL, activationToken)
	if err != nil {
		return compensateFixtureFailure(ctx, pool, userID, err)
	}
	activationTime := time.Now().UTC()
	proof, err := generateTOTP(enrollment.Secret, activationTime, 6)
	if err != nil {
		return compensateFixtureFailure(ctx, pool, userID, errors.New("generate activation MFA proof"))
	}
	if err := activateAdministrator(ctx, config.APIURL, activationToken, config.Password, enrollment.ID, proof); err != nil {
		return compensateFixtureFailure(ctx, pool, userID, err)
	}
	if err := writeReservedCredentials(credentialsFile, runtimeCredentials{
		Username: config.Username, Password: config.Password, TOTPSecret: enrollment.Secret, DisplayName: config.DisplayName,
		TOTPAvailableAt: time.Unix(((activationTime.Unix()/30)+1)*30, 0).UTC(),
	}); err != nil {
		return compensateFixtureFailure(ctx, pool, userID, err)
	}
	credentialsWritten = true
	return nil
}

func validateRuntimeConfig(databaseURL string, apiURL string, outputPath string, repositoryRoot string) error {
	databaseConfig, err := pgxpool.ParseConfig(strings.TrimSpace(databaseURL))
	if err != nil {
		return errors.New("database URL is invalid")
	}
	if !isLoopbackHost(databaseConfig.ConnConfig.Host) {
		return errors.New("database host must be loopback")
	}
	if !strings.Contains(strings.ToLower(databaseConfig.ConnConfig.Database), "test") {
		return errors.New("database name must contain test")
	}
	parsedAPI, err := url.Parse(strings.TrimSpace(apiURL))
	if err != nil || (parsedAPI.Scheme != "http" && parsedAPI.Scheme != "https") || parsedAPI.Host == "" || parsedAPI.User != nil || parsedAPI.RawQuery != "" || parsedAPI.Fragment != "" {
		return errors.New("API URL is invalid")
	}
	if !isLoopbackHost(parsedAPI.Hostname()) {
		return errors.New("API host must be loopback")
	}
	if err := validateCredentialsOutputLocation(outputPath, repositoryRoot); err != nil {
		return err
	}
	return nil
}

func validateCredentialsOutputLocation(outputPath string, repositoryRoot string) error {
	if outputPath == "" || !filepath.IsAbs(outputPath) {
		return errors.New("credentials output path must be absolute")
	}
	if repositoryRoot == "" || !filepath.IsAbs(repositoryRoot) {
		return errors.New("repository root must be absolute")
	}
	canonicalRepositoryRoot, err := filepath.EvalSymlinks(filepath.Clean(repositoryRoot))
	if err != nil {
		return errors.New("resolve repository root")
	}
	repositoryInfo, err := os.Stat(canonicalRepositoryRoot)
	if err != nil || !repositoryInfo.IsDir() {
		return errors.New("repository root must be a directory")
	}

	outputParent := filepath.Dir(filepath.Clean(outputPath))
	canonicalOutputParent, err := filepath.EvalSymlinks(outputParent)
	if err != nil {
		return errors.New("resolve credentials output directory")
	}
	parentInfo, err := os.Stat(canonicalOutputParent)
	if err != nil || !parentInfo.IsDir() {
		return errors.New("credentials output directory must exist")
	}
	if parentInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("credentials output directory must be private")
	}

	canonicalOutput := filepath.Join(canonicalOutputParent, filepath.Base(filepath.Clean(outputPath)))
	if pathWithin(canonicalRepositoryRoot, canonicalOutput) {
		return errors.New("credentials output must be outside repository")
	}
	if outputInfo, lstatErr := os.Lstat(outputPath); lstatErr == nil {
		if outputInfo.Mode()&os.ModeSymlink != 0 {
			return errors.New("credentials output must not be a symbolic link")
		}
	} else if !os.IsNotExist(lstatErr) {
		return errors.New("inspect credentials output")
	}
	return nil
}

func pathWithin(root string, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	if err != nil || filepath.IsAbs(relative) {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func seedPendingAdministrator(ctx context.Context, pool *pgxpool.Pool, config runtimeFixtureConfig, activationToken string) (uuid.UUID, error) {
	userID, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, errors.New("generate fixture user ID")
	}
	bindingID, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, errors.New("generate fixture role binding ID")
	}
	activationDigest := sha256.Sum256([]byte(activationToken))
	now := time.Now().UTC()
	auditor := audit.NewService(audit.NewPostgresRepository(pool))

	err = database.WithTx(ctx, pool, func(tx pgx.Tx) error {
		if _, executeErr := tx.Exec(ctx, `
INSERT INTO user_principals (
    id, username, display_name, user_kind, status, mfa_enrolled,
    version, created_at, updated_at
) VALUES ($1,$2,$3,'local','pending',FALSE,1,$4,$4)`, userID, config.Username, config.DisplayName, now); executeErr != nil {
			return errors.New("insert fixture user")
		}
		if _, executeErr := tx.Exec(ctx, `
INSERT INTO local_credentials (
    user_id, failed_attempts, activation_digest, activation_expires_at
) VALUES ($1,0,$2,$3)`, userID, hex.EncodeToString(activationDigest[:]), now.Add(15*time.Minute)); executeErr != nil {
			return errors.New("insert fixture activation credential")
		}
		if _, executeErr := tx.Exec(ctx, `
INSERT INTO role_bindings (
    id, subject_type, subject_id, role_name, scope_type, effect, valid_from,
    created_by, version, created_at, updated_at
) VALUES ($1,'user',$2,'admin','platform','allow',$3,'system:test-bootstrap',1,$3,$3)`, bindingID, userID, now); executeErr != nil {
			return errors.New("insert fixture administrator binding")
		}
		_, appendErr := auditor.Append(ctx, tx, audit.AppendCommand{
			Actor:        identity.Principal{Subject: "system:test-bootstrap", Kind: identity.PrincipalKindWorkload},
			Action:       "identity.local_user.test_bootstrap",
			ResourceType: "user",
			ResourceID:   userID.String(),
			Outcome:      audit.OutcomeSuccess,
			RequestID:    uuid.NewString(),
			SourceIP:     "127.0.0.1",
			Metadata:     map[string]any{"fixture": "runtime-console-acceptance"},
		})
		if appendErr != nil {
			return errors.New("append fixture audit event")
		}
		return nil
	})
	if err != nil {
		return uuid.Nil, err
	}
	return userID, nil
}

func compensateFixtureFailure(ctx context.Context, pool *pgxpool.Pool, userID uuid.UUID, cause error) error {
	cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := cleanupFixtureAdministrator(cleanupContext, pool, userID); err != nil {
		return errors.Join(cause, fmt.Errorf("cleanup runtime fixture administrator: %w", err))
	}
	return cause
}

func cleanupFixtureAdministrator(ctx context.Context, pool *pgxpool.Pool, userID uuid.UUID) error {
	if pool == nil || userID == uuid.Nil {
		return errors.New("fixture cleanup target is invalid")
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	auditor := audit.NewService(audit.NewPostgresRepository(pool))
	return database.WithTx(ctx, pool, func(tx pgx.Tx) error {
		if _, err := auditor.Append(ctx, tx, audit.AppendCommand{
			Actor:        identity.Principal{Subject: "system:test-bootstrap", Kind: identity.PrincipalKindWorkload},
			Action:       "identity.local_user.test_bootstrap.cleanup",
			ResourceType: "user",
			ResourceID:   userID.String(),
			Outcome:      audit.OutcomeSuccess,
			RequestID:    uuid.NewString(),
			SourceIP:     "127.0.0.1",
			Metadata:     map[string]any{"fixture": "runtime-console-acceptance", "reason": "fixture_failed"},
		}); err != nil {
			return errors.New("append fixture cleanup audit event")
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO iam_mfa_secret_gc (secret_reference,state,not_before,attempts,last_error_code,created_at,updated_at)
SELECT DISTINCT reference,'pending',$2::timestamptz,0,'',$2::timestamptz,$2::timestamptz
FROM (
    SELECT secret_reference AS reference FROM iam_mfa_enrollments WHERE user_id=$1
    UNION
    SELECT mfa_secret_reference AS reference FROM local_credentials WHERE user_id=$1
) AS references_to_delete
WHERE reference <> ''
ON CONFLICT (secret_reference) DO NOTHING`, userID, now); err != nil {
			return fmt.Errorf("schedule fixture MFA secret cleanup: %w", err)
		}
		statements := []string{
			`DELETE FROM local_sessions WHERE subject_id=$1`,
			`DELETE FROM iam_mfa_recovery_codes WHERE user_id=$1`,
			`DELETE FROM iam_mfa_enrollments WHERE user_id=$1`,
			`DELETE FROM local_password_history WHERE user_id=$1`,
			`DELETE FROM organization_memberships WHERE user_id=$1`,
			`DELETE FROM role_bindings WHERE subject_type='user' AND subject_id=$1 AND created_by='system:test-bootstrap'`,
			`DELETE FROM local_credentials WHERE user_id=$1`,
			`DELETE FROM user_principals WHERE id=$1`,
		}
		for _, statement := range statements {
			if _, err := tx.Exec(ctx, statement, userID); err != nil {
				return fmt.Errorf("delete runtime fixture administrator state: %w", err)
			}
		}
		return nil
	})
}

func beginEnrollment(ctx context.Context, apiURL string, activationToken string) (enrollmentResponse, error) {
	var response enrollmentResponse
	status, err := postJSON(ctx, strings.TrimRight(apiURL, "/")+"/api/v1/auth/local/mfa-enrollments", map[string]string{
		"activation_token": activationToken,
	}, &response)
	if err != nil {
		return response, errors.New("request activation MFA enrollment")
	}
	if status != http.StatusCreated || response.ID == uuid.Nil || strings.TrimSpace(response.Secret) == "" {
		return response, fmt.Errorf("activation MFA enrollment returned HTTP %d", status)
	}
	return response, nil
}

func activateAdministrator(ctx context.Context, apiURL string, activationToken string, password string, enrollmentID uuid.UUID, proof string) error {
	status, err := postJSON(ctx, strings.TrimRight(apiURL, "/")+"/api/v1/auth/local/activate", map[string]string{
		"activation_token":  activationToken,
		"new_password":      password,
		"mfa_enrollment_id": enrollmentID.String(),
		"mfa_proof":         proof,
	}, nil)
	if err != nil {
		return errors.New("request local administrator activation")
	}
	if status != http.StatusOK {
		return fmt.Errorf("local administrator activation returned HTTP %d", status)
	}
	return nil
}

func postJSON(ctx context.Context, endpoint string, body any, output any) (int, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if output == nil {
		_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
		return response.StatusCode, err
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 64*1024)).Decode(output); err != nil {
		return response.StatusCode, err
	}
	return response.StatusCode, nil
}

func randomToken(bytesCount int) (string, error) {
	raw := make([]byte, bytesCount)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func generateTOTP(secret string, at time.Time, digits int) (string, error) {
	if digits < 6 || digits > 8 {
		return "", errors.New("TOTP digits must be between 6 and 8")
	}
	normalized := strings.ToUpper(strings.TrimSpace(secret))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(normalized)
	if err != nil || len(key) == 0 {
		return "", errors.New("TOTP secret is invalid")
	}
	counter := uint64(at.UTC().Unix() / 30)
	message := make([]byte, 8)
	binary.BigEndian.PutUint64(message, counter)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(message)
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	value := (uint32(digest[offset])&0x7f)<<24 |
		uint32(digest[offset+1])<<16 |
		uint32(digest[offset+2])<<8 |
		uint32(digest[offset+3])
	modulus := uint32(1)
	for range digits {
		modulus *= 10
	}
	return fmt.Sprintf("%0*d", digits, value%modulus), nil
}

func reserveCredentialsOutput(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, errors.New("create private credentials output reservation")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, errors.New("credentials output must be a regular 0600 file")
	}
	return file, nil
}

func writeCredentials(path string, credentials runtimeCredentials) error {
	file, err := reserveCredentialsOutput(path)
	if err != nil {
		return err
	}
	if err := writeReservedCredentials(file, credentials); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func writeReservedCredentials(file *os.File, credentials runtimeCredentials) error {
	payload, err := json.Marshal(credentials)
	if err != nil {
		return errors.New("encode runtime credentials")
	}
	payload = append(payload, '\n')
	if file == nil {
		return errors.New("runtime credentials output is unavailable")
	}
	writeErr := error(nil)
	if _, err := file.Write(payload); err != nil {
		writeErr = errors.New("write private runtime credentials file")
	} else if err := file.Sync(); err != nil {
		writeErr = errors.New("sync private runtime credentials file")
	}
	if closeErr := file.Close(); writeErr == nil && closeErr != nil {
		writeErr = errors.New("close private runtime credentials file")
	}
	return writeErr
}
