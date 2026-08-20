package iam

import (
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var (
	ErrLocalAuthRuntimeConfiguration = errors.New("local authentication runtime configuration is invalid")
	ErrDirectoryRuntimeConfiguration = errors.New("directory runtime configuration is invalid")
)

type DirectoryRuntimeConfig struct {
	SecretDirectory   string
	RequestTimeout    time.Duration
	MaximumPages      int
	MaximumObjects    int
	AllowLoopbackHTTP bool
}

type LocalAuthRuntimeConfig struct {
	BreachCorpusPath           string
	UseDevelopmentBreachCorpus bool
	MFASecretDirectory         string
	Password                   PasswordPolicyConfig
	TOTP                       TOTPConfig
	Policy                     LocalAuthPolicy
	Reauthentication           ReauthenticationPolicy
}

func LoadDirectoryRuntimeConfig(environ map[string]string, environment string) (DirectoryRuntimeConfig, error) {
	configuration := DirectoryRuntimeConfig{
		SecretDirectory: strings.TrimSpace(environ["XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY"]),
		RequestTimeout:  defaultDirectoryRequestTimeout,
		MaximumPages:    defaultDirectoryMaximumPages,
		MaximumObjects:  defaultDirectoryMaximumObjects,
	}
	if configuration.SecretDirectory == "" || !filepath.IsAbs(configuration.SecretDirectory) {
		return DirectoryRuntimeConfig{}, ErrDirectoryRuntimeConfiguration
	}
	configuration.SecretDirectory = filepath.Clean(configuration.SecretDirectory)

	var err error
	if raw := strings.TrimSpace(environ["XMINDS_RELEASE_IAM_DIRECTORY_REQUEST_TIMEOUT"]); raw != "" {
		configuration.RequestTimeout, err = time.ParseDuration(raw)
		if err != nil {
			return DirectoryRuntimeConfig{}, ErrDirectoryRuntimeConfiguration
		}
	}
	if raw := strings.TrimSpace(environ["XMINDS_RELEASE_IAM_DIRECTORY_MAXIMUM_PAGES"]); raw != "" {
		configuration.MaximumPages, err = strconv.Atoi(raw)
		if err != nil {
			return DirectoryRuntimeConfig{}, ErrDirectoryRuntimeConfiguration
		}
	}
	if raw := strings.TrimSpace(environ["XMINDS_RELEASE_IAM_DIRECTORY_MAXIMUM_OBJECTS"]); raw != "" {
		configuration.MaximumObjects, err = strconv.Atoi(raw)
		if err != nil {
			return DirectoryRuntimeConfig{}, ErrDirectoryRuntimeConfiguration
		}
	}
	loopback := strings.ToLower(strings.TrimSpace(environ["XMINDS_RELEASE_IAM_DIRECTORY_ALLOW_LOOPBACK_HTTP"]))
	if loopback != "" && loopback != "true" && loopback != "false" {
		return DirectoryRuntimeConfig{}, ErrDirectoryRuntimeConfiguration
	}
	configuration.AllowLoopbackHTTP = loopback == "true"
	environment = strings.ToLower(strings.TrimSpace(environment))
	if configuration.RequestTimeout < minimumDirectoryRequestTimeout || configuration.RequestTimeout > maximumDirectoryRequestTimeout ||
		configuration.MaximumPages < 1 || configuration.MaximumPages > defaultDirectoryMaximumPages ||
		configuration.MaximumObjects < 1 || configuration.MaximumObjects > defaultDirectoryMaximumObjects ||
		(configuration.AllowLoopbackHTTP && environment != "development" && environment != "test") {
		return DirectoryRuntimeConfig{}, ErrDirectoryRuntimeConfiguration
	}
	return configuration, nil
}

func LoadLocalAuthRuntimeConfig(environ map[string]string, environment string) (LocalAuthRuntimeConfig, error) {
	configuration := LocalAuthRuntimeConfig{
		BreachCorpusPath:   strings.TrimSpace(environ["XMINDS_RELEASE_IAM_BREACH_CORPUS"]),
		MFASecretDirectory: strings.TrimSpace(environ["XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY"]),
		Password: PasswordPolicyConfig{
			MinimumLength: 16, MemoryKiB: 64 * 1024, Iterations: 3, Parallelism: 2, SaltBytes: 16, DerivedKeyBytes: 32,
		},
		TOTP:             TOTPConfig{Digits: 6, Period: 30 * time.Second, Skew: 1, Algorithm: "SHA1"},
		Policy:           DefaultLocalAuthPolicy(),
		Reauthentication: DefaultReauthenticationPolicy(),
	}
	environment = strings.ToLower(strings.TrimSpace(environment))
	developmentCorpus := strings.ToLower(strings.TrimSpace(environ["XMINDS_RELEASE_IAM_USE_DEVELOPMENT_BREACH_CORPUS"]))
	if developmentCorpus != "" && developmentCorpus != "true" && developmentCorpus != "false" {
		return LocalAuthRuntimeConfig{}, ErrLocalAuthRuntimeConfiguration
	}
	if configuration.BreachCorpusPath == "" {
		if environment != "development" || developmentCorpus != "true" {
			return LocalAuthRuntimeConfig{}, ErrLocalAuthRuntimeConfiguration
		}
		configuration.UseDevelopmentBreachCorpus = true
	} else if developmentCorpus == "true" {
		return LocalAuthRuntimeConfig{}, ErrLocalAuthRuntimeConfiguration
	} else if !filepath.IsAbs(configuration.BreachCorpusPath) {
		return LocalAuthRuntimeConfig{}, ErrLocalAuthRuntimeConfiguration
	} else {
		configuration.BreachCorpusPath = filepath.Clean(configuration.BreachCorpusPath)
	}
	if configuration.MFASecretDirectory == "" || !filepath.IsAbs(configuration.MFASecretDirectory) {
		return LocalAuthRuntimeConfig{}, ErrLocalAuthRuntimeConfiguration
	}
	configuration.MFASecretDirectory = filepath.Clean(configuration.MFASecretDirectory)

	var err error
	configuration.Password.MinimumLength, err = optionalInt(environ, "XMINDS_RELEASE_IAM_PASSWORD_MIN_LENGTH", configuration.Password.MinimumLength)
	if err != nil {
		return LocalAuthRuntimeConfig{}, err
	}
	memory, err := optionalInt(environ, "XMINDS_RELEASE_IAM_ARGON_MEMORY_KIB", int(configuration.Password.MemoryKiB))
	if err != nil {
		return LocalAuthRuntimeConfig{}, err
	}
	if memory > 256*1024 {
		return LocalAuthRuntimeConfig{}, ErrLocalAuthRuntimeConfiguration
	}
	configuration.Password.MemoryKiB = uint32(memory)
	iterations, err := optionalInt(environ, "XMINDS_RELEASE_IAM_ARGON_ITERATIONS", int(configuration.Password.Iterations))
	if err != nil {
		return LocalAuthRuntimeConfig{}, err
	}
	if iterations > 10 {
		return LocalAuthRuntimeConfig{}, ErrLocalAuthRuntimeConfiguration
	}
	configuration.Password.Iterations = uint32(iterations)
	parallelism, err := optionalInt(environ, "XMINDS_RELEASE_IAM_ARGON_PARALLELISM", int(configuration.Password.Parallelism))
	if err != nil {
		return LocalAuthRuntimeConfig{}, err
	}
	if parallelism > 8 {
		return LocalAuthRuntimeConfig{}, ErrLocalAuthRuntimeConfiguration
	}
	configuration.Password.Parallelism = uint8(parallelism)

	configuration.Policy.AccountLimit, err = optionalInt(environ, "XMINDS_RELEASE_IAM_ACCOUNT_LIMIT", configuration.Policy.AccountLimit)
	if err != nil {
		return LocalAuthRuntimeConfig{}, err
	}
	configuration.Policy.IPLimit, err = optionalInt(environ, "XMINDS_RELEASE_IAM_IP_LIMIT", configuration.Policy.IPLimit)
	if err != nil {
		return LocalAuthRuntimeConfig{}, err
	}
	configuration.Policy.AccountWindow, err = optionalDuration(environ, "XMINDS_RELEASE_IAM_ACCOUNT_WINDOW", configuration.Policy.AccountWindow)
	if err != nil {
		return LocalAuthRuntimeConfig{}, err
	}
	configuration.Policy.IPWindow, err = optionalDuration(environ, "XMINDS_RELEASE_IAM_IP_WINDOW", configuration.Policy.IPWindow)
	if err != nil {
		return LocalAuthRuntimeConfig{}, err
	}
	configuration.Policy.SessionAbsolute, err = optionalDuration(environ, "XMINDS_RELEASE_IAM_SESSION_ABSOLUTE", configuration.Policy.SessionAbsolute)
	if err != nil {
		return LocalAuthRuntimeConfig{}, err
	}
	configuration.Policy.SessionIdle, err = optionalDuration(environ, "XMINDS_RELEASE_IAM_SESSION_IDLE", configuration.Policy.SessionIdle)
	if err != nil {
		return LocalAuthRuntimeConfig{}, err
	}
	configuration.Policy.EmergencyAbsolute, err = optionalDuration(environ, "XMINDS_RELEASE_IAM_EMERGENCY_SESSION_ABSOLUTE", configuration.Policy.EmergencyAbsolute)
	if err != nil {
		return LocalAuthRuntimeConfig{}, err
	}
	configuration.Policy.EmergencyIdle, err = optionalDuration(environ, "XMINDS_RELEASE_IAM_EMERGENCY_SESSION_IDLE", configuration.Policy.EmergencyIdle)
	if err != nil {
		return LocalAuthRuntimeConfig{}, err
	}
	configuration.Policy.LockoutStages, err = parseLockoutStages(environ["XMINDS_RELEASE_IAM_LOCKOUT_STAGES"], configuration.Policy.LockoutStages)
	if err != nil {
		return LocalAuthRuntimeConfig{}, err
	}

	configuration.TOTP.Digits, err = optionalInt(environ, "XMINDS_RELEASE_IAM_TOTP_DIGITS", configuration.TOTP.Digits)
	if err != nil {
		return LocalAuthRuntimeConfig{}, err
	}
	configuration.TOTP.Skew, err = optionalInt(environ, "XMINDS_RELEASE_IAM_TOTP_SKEW", configuration.TOTP.Skew)
	if err != nil {
		return LocalAuthRuntimeConfig{}, err
	}
	configuration.TOTP.Period, err = optionalDuration(environ, "XMINDS_RELEASE_IAM_TOTP_PERIOD", configuration.TOTP.Period)
	if err != nil {
		return LocalAuthRuntimeConfig{}, err
	}
	if algorithm := strings.TrimSpace(environ["XMINDS_RELEASE_IAM_TOTP_ALGORITHM"]); algorithm != "" {
		configuration.TOTP.Algorithm = strings.ToUpper(algorithm)
	}
	configuration.Reauthentication.ChallengeTTL, err = optionalDuration(environ, "XMINDS_RELEASE_IAM_REAUTH_CHALLENGE_TTL", configuration.Reauthentication.ChallengeTTL)
	if err != nil {
		return LocalAuthRuntimeConfig{}, err
	}
	configuration.Reauthentication.EvidenceTTL, err = optionalDuration(environ, "XMINDS_RELEASE_IAM_REAUTH_EVIDENCE_TTL", configuration.Reauthentication.EvidenceTTL)
	if err != nil {
		return LocalAuthRuntimeConfig{}, err
	}
	configuration.Reauthentication.OIDCMaximumAge, err = optionalDuration(environ, "XMINDS_RELEASE_IAM_REAUTH_OIDC_MAXIMUM_AGE", configuration.Reauthentication.OIDCMaximumAge)
	if err != nil {
		return LocalAuthRuntimeConfig{}, err
	}
	configuration.Reauthentication.AllowedClockSkew, err = optionalDuration(environ, "XMINDS_RELEASE_IAM_REAUTH_ALLOWED_CLOCK_SKEW", configuration.Reauthentication.AllowedClockSkew)
	if err != nil {
		return LocalAuthRuntimeConfig{}, err
	}
	configuration.Reauthentication.TerminalRetention, err = optionalDuration(environ, "XMINDS_RELEASE_IAM_REAUTH_TERMINAL_RETENTION", configuration.Reauthentication.TerminalRetention)
	if err != nil {
		return LocalAuthRuntimeConfig{}, err
	}
	configuration.Reauthentication.CleanupBatchSize, err = optionalInt(environ, "XMINDS_RELEASE_IAM_REAUTH_CLEANUP_BATCH_SIZE", configuration.Reauthentication.CleanupBatchSize)
	if err != nil {
		return LocalAuthRuntimeConfig{}, err
	}
	if !validPasswordPolicy(configuration.Password) || !validLocalAuthPolicy(configuration.Policy) ||
		!validReauthenticationPolicy(configuration.Reauthentication) ||
		(configuration.TOTP.Digits != 6 && configuration.TOTP.Digits != 8) || configuration.TOTP.Skew < 0 || configuration.TOTP.Skew > 2 ||
		configuration.TOTP.Period < 30*time.Second || configuration.TOTP.Period > 2*time.Minute ||
		(configuration.TOTP.Algorithm != "SHA1" && configuration.TOTP.Algorithm != "SHA256") {
		return LocalAuthRuntimeConfig{}, ErrLocalAuthRuntimeConfiguration
	}
	return configuration, nil
}

func parseLockoutStages(raw string, fallback []LockoutStage) ([]LockoutStage, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return append([]LockoutStage(nil), fallback...), nil
	}
	parts := strings.Split(raw, ",")
	stages := make([]LockoutStage, 0, len(parts))
	for _, part := range parts {
		fields := strings.Split(strings.TrimSpace(part), ":")
		if len(fields) != 2 {
			return nil, ErrLocalAuthRuntimeConfiguration
		}
		attempts, err := strconv.Atoi(strings.TrimSpace(fields[0]))
		if err != nil {
			return nil, ErrLocalAuthRuntimeConfiguration
		}
		duration, err := time.ParseDuration(strings.TrimSpace(fields[1]))
		if err != nil {
			return nil, ErrLocalAuthRuntimeConfiguration
		}
		stages = append(stages, LockoutStage{FailedAttempts: attempts, Duration: duration})
	}
	if !validLockoutStages(stages) {
		return nil, ErrLocalAuthRuntimeConfiguration
	}
	return stages, nil
}

func optionalInt(environ map[string]string, key string, fallback int) (int, error) {
	raw := strings.TrimSpace(environ[key])
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		return 0, ErrLocalAuthRuntimeConfiguration
	}
	return value, nil
}

func optionalDuration(environ map[string]string, key string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(environ[key])
	if raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, ErrLocalAuthRuntimeConfiguration
	}
	return value, nil
}
