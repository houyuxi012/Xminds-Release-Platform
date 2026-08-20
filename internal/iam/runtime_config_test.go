package iam

import (
	"errors"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLoadLocalAuthRuntimeConfigFailsClosedWithoutProductionSecurityInputs(t *testing.T) {
	t.Parallel()
	for name, environment := range map[string]string{"production": "production", "staging": "staging", "test": "test"} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadLocalAuthRuntimeConfig(map[string]string{}, environment)
			if !errors.Is(err, ErrLocalAuthRuntimeConfiguration) {
				t.Fatalf("LoadLocalAuthRuntimeConfig() error = %v", err)
			}
		})
	}
}

func TestLoadDirectoryRuntimeConfigUsesBoundedSharedSecretRoot(t *testing.T) {
	t.Parallel()
	secretDirectory := t.TempDir()
	configuration, err := LoadDirectoryRuntimeConfig(map[string]string{
		"XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY":                    secretDirectory,
		"XMINDS_RELEASE_IAM_DIRECTORY_REQUEST_TIMEOUT":               "12s",
		"XMINDS_RELEASE_IAM_DIRECTORY_MAXIMUM_PAGES":                 "250",
		"XMINDS_RELEASE_IAM_DIRECTORY_MAXIMUM_OBJECTS":               "25000",
		"XMINDS_RELEASE_IAM_DIRECTORY_ALLOW_LOOPBACK_HTTP":           "true",
		"XMINDS_RELEASE_IAM_DIRECTORY_ALLOWED_PRIVATE_CIDRS":         "10.20.30.0/24,fd00:1234::/48",
		"XMINDS_RELEASE_IAM_DIRECTORY_CONFLICT_CURSOR_KEY_REFERENCE": "secret://iam/test-directory-cursor-key",
		"XMINDS_RELEASE_IAM_DIRECTORY_CONFLICT_CURSOR_TTL":           "30m",
	}, "test")
	if err != nil {
		t.Fatalf("LoadDirectoryRuntimeConfig() error = %v", err)
	}
	if configuration.SecretDirectory != filepath.Clean(secretDirectory) || configuration.RequestTimeout != 12*time.Second ||
		configuration.MaximumPages != 250 || configuration.MaximumObjects != 25000 || !configuration.AllowLoopbackHTTP ||
		!reflect.DeepEqual(configuration.AllowedPrivatePrefixes, []netip.Prefix{netip.MustParsePrefix("10.20.30.0/24"), netip.MustParsePrefix("fd00:1234::/48")}) ||
		configuration.ConflictCursorKeyReference != "secret://iam/test-directory-cursor-key" || configuration.ConflictCursorTTL != 30*time.Minute {
		t.Fatalf("configuration = %+v", configuration)
	}
}

func TestLoadDirectoryRuntimeConfigFailsClosedForUnsafeOverrides(t *testing.T) {
	t.Parallel()
	secretDirectory := t.TempDir()
	for name, testCase := range map[string]struct {
		environment string
		overrides   map[string]string
	}{
		"missing root":                 {environment: "production", overrides: map[string]string{"XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY": ""}},
		"relative root":                {environment: "production", overrides: map[string]string{"XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY": "relative"}},
		"short timeout":                {environment: "production", overrides: map[string]string{"XMINDS_RELEASE_IAM_DIRECTORY_REQUEST_TIMEOUT": "500ms"}},
		"too many pages":               {environment: "production", overrides: map[string]string{"XMINDS_RELEASE_IAM_DIRECTORY_MAXIMUM_PAGES": "10001"}},
		"too many objects":             {environment: "production", overrides: map[string]string{"XMINDS_RELEASE_IAM_DIRECTORY_MAXIMUM_OBJECTS": "100001"}},
		"production loopback":          {environment: "production", overrides: map[string]string{"XMINDS_RELEASE_IAM_DIRECTORY_ALLOW_LOOPBACK_HTTP": "true"}},
		"implicit test loopback":       {environment: "test", overrides: map[string]string{"XMINDS_RELEASE_IAM_DIRECTORY_ALLOW_LOOPBACK_HTTP": "yes"}},
		"invalid private CIDR":         {environment: "production", overrides: map[string]string{"XMINDS_RELEASE_IAM_DIRECTORY_ALLOWED_PRIVATE_CIDRS": "100.64.0.0/10"}},
		"unmasked private CIDR":        {environment: "production", overrides: map[string]string{"XMINDS_RELEASE_IAM_DIRECTORY_ALLOWED_PRIVATE_CIDRS": "10.20.30.7/24"}},
		"invalid cursor key reference": {environment: "production", overrides: map[string]string{"XMINDS_RELEASE_IAM_DIRECTORY_CONFLICT_CURSOR_KEY_REFERENCE": "file:///tmp/key"}},
		"short cursor ttl":             {environment: "production", overrides: map[string]string{"XMINDS_RELEASE_IAM_DIRECTORY_CONFLICT_CURSOR_TTL": "30s"}},
		"long cursor ttl":              {environment: "production", overrides: map[string]string{"XMINDS_RELEASE_IAM_DIRECTORY_CONFLICT_CURSOR_TTL": "25h"}},
	} {
		t.Run(name, func(t *testing.T) {
			environ := map[string]string{"XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY": secretDirectory}
			for key, value := range testCase.overrides {
				environ[key] = value
			}
			if _, err := LoadDirectoryRuntimeConfig(environ, testCase.environment); !errors.Is(err, ErrDirectoryRuntimeConfiguration) {
				t.Fatalf("LoadDirectoryRuntimeConfig() error = %v", err)
			}
		})
	}
}

func TestLoadLocalAuthRuntimeConfigRequiresExplicitDevelopmentCorpusOptIn(t *testing.T) {
	t.Parallel()
	if _, err := LoadLocalAuthRuntimeConfig(map[string]string{}, "development"); !errors.Is(err, ErrLocalAuthRuntimeConfiguration) {
		t.Fatalf("development without MFA directory error = %v", err)
	}
	secretDirectory := t.TempDir()
	base := map[string]string{"XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY": secretDirectory}
	if _, err := LoadLocalAuthRuntimeConfig(base, "development"); !errors.Is(err, ErrLocalAuthRuntimeConfiguration) {
		t.Fatalf("implicit development corpus error = %v", err)
	}
	if _, err := LoadLocalAuthRuntimeConfig(map[string]string{
		"XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY":          secretDirectory,
		"XMINDS_RELEASE_IAM_USE_DEVELOPMENT_BREACH_CORPUS": "true",
	}, ""); !errors.Is(err, ErrLocalAuthRuntimeConfiguration) {
		t.Fatalf("missing environment with development opt-in error = %v", err)
	}
	for name, testCase := range map[string]struct {
		environ     map[string]string
		environment string
	}{
		"production opt-in": {map[string]string{
			"XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY":          secretDirectory,
			"XMINDS_RELEASE_IAM_USE_DEVELOPMENT_BREACH_CORPUS": "true",
		}, "production"},
		"invalid boolean": {map[string]string{
			"XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY":          secretDirectory,
			"XMINDS_RELEASE_IAM_USE_DEVELOPMENT_BREACH_CORPUS": "yes",
		}, "development"},
		"ambiguous sources": {map[string]string{
			"XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY":          secretDirectory,
			"XMINDS_RELEASE_IAM_USE_DEVELOPMENT_BREACH_CORPUS": "true",
			"XMINDS_RELEASE_IAM_BREACH_CORPUS":                 filepath.Join(t.TempDir(), "breaches.txt"),
		}, "development"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadLocalAuthRuntimeConfig(testCase.environ, testCase.environment); !errors.Is(err, ErrLocalAuthRuntimeConfiguration) {
				t.Fatalf("unsafe development corpus configuration error = %v", err)
			}
		})
	}
	configuration, err := LoadLocalAuthRuntimeConfig(map[string]string{
		"XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY":          secretDirectory,
		"XMINDS_RELEASE_IAM_USE_DEVELOPMENT_BREACH_CORPUS": "true",
	}, "development")
	if err != nil {
		t.Fatalf("LoadLocalAuthRuntimeConfig() error = %v", err)
	}
	if !configuration.UseDevelopmentBreachCorpus || configuration.MFASecretDirectory != filepath.Clean(secretDirectory) {
		t.Fatalf("configuration = %+v", configuration)
	}
}

func TestLoadLocalAuthRuntimeConfigRejectsUnsafePolicyOverrides(t *testing.T) {
	t.Parallel()
	base := map[string]string{
		"XMINDS_RELEASE_IAM_BREACH_CORPUS":        filepath.Join(t.TempDir(), "breaches.txt"),
		"XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY": t.TempDir(),
	}
	for key, value := range map[string]string{
		"XMINDS_RELEASE_IAM_ACCOUNT_LIMIT":              "4",
		"XMINDS_RELEASE_IAM_SESSION_ABSOLUTE":           "72h",
		"XMINDS_RELEASE_IAM_EMERGENCY_SESSION_ABSOLUTE": "2h",
		"XMINDS_RELEASE_IAM_TOTP_SKEW":                  "5",
		"XMINDS_RELEASE_IAM_ARGON_MEMORY_KIB":           "1024",
		"XMINDS_RELEASE_IAM_ARGON_MEMORY_KIB_OVERFLOW":  "4295032832",
		"XMINDS_RELEASE_IAM_LOCKOUT_TOO_FEW":            "2:5m",
		"XMINDS_RELEASE_IAM_LOCKOUT_DUPLICATE":          "5:5m,5:10m",
		"XMINDS_RELEASE_IAM_LOCKOUT_DURATION_ORDER":     "5:10m,8:5m",
		"XMINDS_RELEASE_IAM_LOCKOUT_ATTEMPT_OVERFLOW":   "999999999999999999999999:5m",
		"XMINDS_RELEASE_IAM_LOCKOUT_DURATION_OVERFLOW":  "5:999999999999999999999h",
		"XMINDS_RELEASE_IAM_LOCKOUT_TOO_MANY":           "3:1m,4:2m,5:3m,6:4m,7:5m,8:6m",
	} {
		t.Run(key, func(t *testing.T) {
			environment := make(map[string]string, len(base)+1)
			for name, configured := range base {
				environment[name] = configured
			}
			actualKey := key
			if key == "XMINDS_RELEASE_IAM_ARGON_MEMORY_KIB_OVERFLOW" {
				actualKey = "XMINDS_RELEASE_IAM_ARGON_MEMORY_KIB"
			}
			if strings.HasPrefix(key, "XMINDS_RELEASE_IAM_LOCKOUT_") {
				actualKey = "XMINDS_RELEASE_IAM_LOCKOUT_STAGES"
			}
			environment[actualKey] = value
			if _, err := LoadLocalAuthRuntimeConfig(environment, "production"); !errors.Is(err, ErrLocalAuthRuntimeConfiguration) {
				t.Fatalf("override %s=%s error = %v", key, value, err)
			}
		})
	}
}

func TestLoadLocalAuthRuntimeConfigParsesBoundedPolicy(t *testing.T) {
	t.Parallel()
	configuration, err := LoadLocalAuthRuntimeConfig(map[string]string{
		"XMINDS_RELEASE_IAM_BREACH_CORPUS":        filepath.Join(t.TempDir(), "breaches.txt"),
		"XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY": t.TempDir(),
		"XMINDS_RELEASE_IAM_ACCOUNT_LIMIT":        "20",
		"XMINDS_RELEASE_IAM_SESSION_IDLE":         "45m",
		"XMINDS_RELEASE_IAM_TOTP_ALGORITHM":       "sha256",
		"XMINDS_RELEASE_IAM_TOTP_PERIOD":          "60s",
		"XMINDS_RELEASE_IAM_ARGON_ITERATIONS":     "4",
		"XMINDS_RELEASE_IAM_LOCKOUT_STAGES":       "4:3m,7:20m,9:12h",
	}, "production")
	if err != nil {
		t.Fatalf("LoadLocalAuthRuntimeConfig() error = %v", err)
	}
	wantStages := []LockoutStage{{FailedAttempts: 4, Duration: 3 * time.Minute}, {FailedAttempts: 7, Duration: 20 * time.Minute}, {FailedAttempts: 9, Duration: 12 * time.Hour}}
	if configuration.Policy.AccountLimit != 20 || configuration.Policy.SessionIdle != 45*time.Minute || configuration.TOTP.Algorithm != "SHA256" || configuration.TOTP.Period != time.Minute || configuration.Password.Iterations != 4 || !reflect.DeepEqual(configuration.Policy.LockoutStages, wantStages) {
		t.Fatalf("configuration = %+v", configuration)
	}
}

func TestLoadLocalAuthRuntimeConfigParsesBoundedReauthenticationPolicy(t *testing.T) {
	t.Parallel()
	configuration, err := LoadLocalAuthRuntimeConfig(map[string]string{
		"XMINDS_RELEASE_IAM_BREACH_CORPUS":             filepath.Join(t.TempDir(), "breaches.txt"),
		"XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY":      t.TempDir(),
		"XMINDS_RELEASE_IAM_REAUTH_CHALLENGE_TTL":      "6m",
		"XMINDS_RELEASE_IAM_REAUTH_EVIDENCE_TTL":       "90s",
		"XMINDS_RELEASE_IAM_REAUTH_OIDC_MAXIMUM_AGE":   "4m",
		"XMINDS_RELEASE_IAM_REAUTH_ALLOWED_CLOCK_SKEW": "45s",
		"XMINDS_RELEASE_IAM_REAUTH_TERMINAL_RETENTION": "48h",
		"XMINDS_RELEASE_IAM_REAUTH_CLEANUP_BATCH_SIZE": "256",
	}, "production")
	if err != nil {
		t.Fatalf("LoadLocalAuthRuntimeConfig() error = %v", err)
	}
	want := ReauthenticationPolicy{
		ChallengeTTL: 6 * time.Minute, EvidenceTTL: 90 * time.Second, OIDCMaximumAge: 4 * time.Minute,
		AllowedClockSkew: 45 * time.Second, TerminalRetention: 48 * time.Hour, CleanupBatchSize: 256,
	}
	if !reflect.DeepEqual(configuration.Reauthentication, want) {
		t.Fatalf("reauthentication policy = %+v, want %+v", configuration.Reauthentication, want)
	}
}

func TestLoadLocalAuthRuntimeConfigRejectsUnsafeReauthenticationPolicy(t *testing.T) {
	t.Parallel()
	base := map[string]string{
		"XMINDS_RELEASE_IAM_BREACH_CORPUS":        filepath.Join(t.TempDir(), "breaches.txt"),
		"XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY": t.TempDir(),
	}
	for key, value := range map[string]string{
		"XMINDS_RELEASE_IAM_REAUTH_CHALLENGE_TTL":      "30s",
		"XMINDS_RELEASE_IAM_REAUTH_EVIDENCE_TTL":       "6m",
		"XMINDS_RELEASE_IAM_REAUTH_OIDC_MAXIMUM_AGE":   "11m",
		"XMINDS_RELEASE_IAM_REAUTH_ALLOWED_CLOCK_SKEW": "3m",
		"XMINDS_RELEASE_IAM_REAUTH_TERMINAL_RETENTION": "30m",
		"XMINDS_RELEASE_IAM_REAUTH_CLEANUP_BATCH_SIZE": "0",
	} {
		t.Run(key, func(t *testing.T) {
			environ := make(map[string]string, len(base)+1)
			for name, configured := range base {
				environ[name] = configured
			}
			environ[key] = value
			if _, err := LoadLocalAuthRuntimeConfig(environ, "production"); !errors.Is(err, ErrLocalAuthRuntimeConfiguration) {
				t.Fatalf("override %s=%s error = %v", key, value, err)
			}
		})
	}
}
