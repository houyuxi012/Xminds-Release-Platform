package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"xminds-release-platform/internal/breachcorpus"
)

func TestRunBuildsVerifiesAndDeploymentChecksRelease(t *testing.T) {
	t.Parallel()

	source := writeCLISource(t, testCLISHA1Digest+"\n"+testCLISHA256Digest+"\n")
	requestPath := writeCLIRequest(t, fileDigest(t, source))
	outputRoot := privateCLIOutputRoot(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"build",
		"--request", requestPath,
		"--input", "source-a=" + source,
		"--output-root", outputRoot,
	}, &stdout, &stderr, func() time.Time { return fixedCLITime })
	if code != 0 {
		t.Fatalf("run(build) code = %d, stderr = %s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), source) || strings.Contains(stdout.String(), testCLISHA1Digest) ||
		strings.Contains(stderr.String(), source) || strings.Contains(stderr.String(), testCLISHA1Digest) {
		t.Fatal("CLI disclosed a source path or corpus entry")
	}
	var result breachcorpus.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.ReleaseDirectory == "" || result.Counts.UniqueEntries != 2 {
		t.Fatalf("result = %+v", result)
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{
		"verify",
		"--release-dir", result.ReleaseDirectory,
	}, &stdout, &stderr, time.Now)
	if code != 0 {
		t.Fatalf("run(verify) code = %d, stderr = %s", code, stderr.String())
	}
	var verified breachcorpus.Result
	if err := json.Unmarshal(stdout.Bytes(), &verified); err != nil {
		t.Fatalf("decode verification: %v", err)
	}
	if verified.CorpusSHA256 != result.CorpusSHA256 || verified.ManifestSHA256 != result.ManifestSHA256 {
		t.Fatalf("verified = %+v, built = %+v", verified, result)
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{
		"verify",
		"--mode", "deployment",
		"--release-dir", result.ReleaseDirectory,
		"--expected-owner-uid", strconv.Itoa(os.Geteuid()),
		"--expected-group-gid", strconv.Itoa(os.Getegid()),
	}, &stdout, &stderr, time.Now)
	if code != 0 {
		t.Fatalf("run(deployment verify) code = %d, stderr = %s", code, stderr.String())
	}
}

func TestRunReturnsUsageExitWithoutEchoingUntrustedArguments(t *testing.T) {
	t.Parallel()

	tests := map[string][]string{
		"missing command":        {},
		"unknown command":        {"publish"},
		"plaintext shaped input": {"build", "--input", "password=Secret123!"},
		"missing deployment uid": {"verify", "--mode", "deployment", "--release-dir", "/opt/xminds/breach-corpora/" + breachcorpus.ReleaseDirectoryPrefix + strings.Repeat("0", 64)},
		"runtime mode is internal": {
			"verify", "--mode", "runtime", "--release-dir", "/opt/xminds/breach-corpora/" + breachcorpus.ReleaseDirectoryPrefix + strings.Repeat("0", 64),
		},
	}
	for name, arguments := range tests {
		arguments := arguments
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if code := run(arguments, &stdout, &stderr, time.Now); code != 2 {
				t.Fatalf("run() code = %d, stdout = %s, stderr = %s", code, stdout.String(), stderr.String())
			}
			if strings.Contains(stdout.String()+stderr.String(), "Secret123!") {
				t.Fatal("CLI echoed an untrusted argument")
			}
		})
	}
}

func TestRunFailsClosedWithoutEchoingSourceForDigestMismatchOrLinkedRequest(t *testing.T) {
	t.Parallel()

	source := writeCLISource(t, testCLISHA1Digest+"\n")
	validRequest := writeCLIRequest(t, strings.Repeat("0", 64))
	linkedRequest := filepath.Join(t.TempDir(), "linked-request.json")
	if err := os.Symlink(validRequest, linkedRequest); err != nil {
		t.Fatal(err)
	}
	for name, requestPath := range map[string]string{
		"digest mismatch": validRequest,
		"linked request":  linkedRequest,
	} {
		requestPath := requestPath
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			outputRoot := privateCLIOutputRoot(t)
			var stdout, stderr bytes.Buffer
			code := run([]string{
				"build",
				"--request", requestPath,
				"--input", "source-a=" + source,
				"--output-root", outputRoot,
			}, &stdout, &stderr, func() time.Time { return fixedCLITime })
			if code != 1 {
				t.Fatalf("run() code = %d, stdout = %s, stderr = %s", code, stdout.String(), stderr.String())
			}
			combined := stdout.String() + stderr.String()
			if strings.Contains(combined, source) || strings.Contains(combined, testCLISHA1Digest) {
				t.Fatal("CLI echoed a source path or corpus entry")
			}
		})
	}
}

const (
	testCLISHA1Digest   = "844EBA1A7A7BEBADAAD266BF2DB5B9429D441818"
	testCLISHA256Digest = "6CE0335CCB0E6AD50693A435D4BF0659DB2D69D53D84631661774AC86E8F5722"
)

var fixedCLITime = time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)

func writeCLISource(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "source.txt")
	if err := os.WriteFile(path, []byte(contents), 0o400); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeCLIRequest(t *testing.T, expectedDigest string) string {
	t.Helper()
	request := breachcorpus.BuildRequest{
		SchemaVersion: breachcorpus.ManifestSchemaVersion,
		CorpusVersion: "2026.08.30.1",
		Sources: []breachcorpus.SourceRequest{{
			ID: "source-a", Version: "2026-08", ExpectedSHA256: expectedDigest, LicenseReviewRef: "LEGAL-1",
		}},
	}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "build-request.json")
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func privateCLIOutputRoot(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = filepath.Walk(path, func(current string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				_ = os.Chmod(current, 0o700)
			} else {
				_ = os.Chmod(current, 0o600)
			}
			return nil
		})
	})
	return path
}

func fileDigest(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
