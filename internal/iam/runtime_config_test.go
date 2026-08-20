package iam

import (
	"errors"
	"path/filepath"
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

func TestLoadLocalAuthRuntimeConfigAllowsOnlyExplicitDevelopmentMFAResolver(t *testing.T) {
	t.Parallel()
	if _, err := LoadLocalAuthRuntimeConfig(map[string]string{}, "development"); !errors.Is(err, ErrLocalAuthRuntimeConfiguration) {
		t.Fatalf("development without MFA directory error = %v", err)
	}
	secretDirectory := t.TempDir()
	configuration, err := LoadLocalAuthRuntimeConfig(map[string]string{
		"XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY": secretDirectory,
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
	}, "production")
	if err != nil {
		t.Fatalf("LoadLocalAuthRuntimeConfig() error = %v", err)
	}
	if configuration.Policy.AccountLimit != 20 || configuration.Policy.SessionIdle != 45*time.Minute || configuration.TOTP.Algorithm != "SHA256" || configuration.TOTP.Period != time.Minute || configuration.Password.Iterations != 4 {
		t.Fatalf("configuration = %+v", configuration)
	}
}
