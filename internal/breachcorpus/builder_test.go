package breachcorpus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

var fixedBuildTime = time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)

func TestBuildIsStableAcrossInputOrderAndDeduplicates(t *testing.T) {
	t.Parallel()

	firstRoot := privateDirectory(t)
	secondRoot := privateDirectory(t)
	sourceA := writeSource(t, "source-a.txt", testSHA1Digest+"\n")
	sourceB := writeSource(t, "source-b.txt", strings.ToLower(testSHA1Digest)+"\n# approved\n"+testSHA256Digest+"\n")
	request := buildRequestForSources(t,
		sourceDefinition{id: "source-b", path: sourceB, version: "2026-08-b", license: "LEGAL-B"},
		sourceDefinition{id: "source-a", path: sourceA, version: "2026-08-a", license: "LEGAL-A"},
	)
	generator := Generator{Name: "xminds-breach-corpus", Version: "0.1.0-p0", Commit: "0123456789ab"}

	first, err := Build(context.Background(), request, []Input{
		{SourceID: "source-b", Path: sourceB},
		{SourceID: "source-a", Path: sourceA},
	}, firstRoot, generator, func() time.Time { return fixedBuildTime })
	if err != nil {
		t.Fatalf("Build(first) error = %v", err)
	}
	second, err := Build(context.Background(), request, []Input{
		{SourceID: "source-a", Path: sourceA},
		{SourceID: "source-b", Path: sourceB},
	}, secondRoot, generator, func() time.Time { return fixedBuildTime })
	if err != nil {
		t.Fatalf("Build(second) error = %v", err)
	}
	if first.CorpusSHA256 != second.CorpusSHA256 || first.Counts.UniqueEntries != 2 ||
		first.Counts.DuplicateEntries != 1 || first.Counts.SHA1Entries != 1 || first.Counts.SHA256Entries != 1 {
		t.Fatalf("unstable build: first=%+v second=%+v", first, second)
	}

	wantLines := []string{testSHA1Digest, testSHA256Digest}
	sort.Strings(wantLines)
	wantCorpus := strings.Join(wantLines, "\n") + "\n"
	corpusPath := filepath.Join(first.ReleaseDirectory, CorpusFileName)
	raw, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != wantCorpus {
		t.Fatalf("corpus = %q, want %q", raw, wantCorpus)
	}
	digest := sha256.Sum256(raw)
	wantDigest := hex.EncodeToString(digest[:])
	if first.CorpusSHA256 != wantDigest || filepath.Base(first.ReleaseDirectory) != ReleaseDirectoryPrefix+wantDigest {
		t.Fatalf("result = %+v, digest = %s", first, wantDigest)
	}
	assertReadOnlyMode(t, corpusPath)
	assertReadOnlyMode(t, filepath.Join(first.ReleaseDirectory, ManifestFileName))
}

func TestBuildWritesStrictTechnicalEvidenceWithoutLocalPaths(t *testing.T) {
	t.Parallel()

	outputRoot := privateDirectory(t)
	source := writeSource(t, "technical-evidence.txt", testSHA1Digest+"\n")
	request := buildRequestForSources(t, sourceDefinition{id: "approved-source", path: source, version: "2026-08", license: "LEGAL-2026-001"})
	result, err := Build(
		context.Background(),
		request,
		[]Input{{SourceID: "approved-source", Path: source}},
		outputRoot,
		Generator{Name: "xminds-breach-corpus", Version: "0.1.0-p0", Commit: "0123456789ab"},
		func() time.Time { return fixedBuildTime },
	)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(result.ReleaseDirectory, ManifestFileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), source) || strings.Contains(string(raw), testSHA1Digest) {
		t.Fatal("manifest disclosed a local path or corpus entry")
	}
	var manifest Manifest
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if manifest.SchemaVersion != ManifestSchemaVersion || manifest.Format != Format ||
		manifest.CorpusVersion != "2026.08.30.1" || manifest.GeneratedAt != "2026-08-30T12:00:00Z" ||
		manifest.Corpus.SHA256 != result.CorpusSHA256 || manifest.Corpus.UniqueEntries != 1 ||
		len(manifest.Sources) != 1 || manifest.Sources[0].ID != "approved-source" ||
		manifest.Sources[0].LicenseReviewRef != "LEGAL-2026-001" {
		t.Fatalf("manifest = %+v", manifest)
	}
	manifestDigest := sha256.Sum256(raw)
	if result.ManifestSHA256 != hex.EncodeToString(manifestDigest[:]) {
		t.Fatalf("manifest digest = %s, result = %s", hex.EncodeToString(manifestDigest[:]), result.ManifestSHA256)
	}
}

func TestBuildFailsClosedForInvalidInputsAndLeavesNoRelease(t *testing.T) {
	t.Parallel()

	validSource := writeSource(t, "valid.txt", testSHA1Digest+"\n")
	symlinkPath := filepath.Join(t.TempDir(), "linked.txt")
	if err := os.Symlink(validSource, symlinkPath); err != nil {
		t.Fatal(err)
	}
	oversizedPath := filepath.Join(t.TempDir(), "oversized.txt")
	oversized, err := os.OpenFile(oversizedPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o400)
	if err != nil {
		t.Fatal(err)
	}
	if err := oversized.Truncate(MaximumTotalInputBytes + 1); err != nil {
		_ = oversized.Close()
		t.Fatal(err)
	}
	if err := oversized.Close(); err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		path           string
		expectedDigest string
	}{
		"digest mismatch": {path: validSource, expectedDigest: strings.Repeat("0", 64)},
		"symbolic link":   {path: symlinkPath, expectedDigest: fileSHA256(t, validSource)},
		"oversized input": {path: oversizedPath, expectedDigest: strings.Repeat("0", 64)},
	}
	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			outputRoot := privateDirectory(t)
			request := BuildRequest{
				SchemaVersion: ManifestSchemaVersion,
				CorpusVersion: "2026.08.30.1",
				Sources: []SourceRequest{{
					ID: "source-a", Version: "1", ExpectedSHA256: test.expectedDigest, LicenseReviewRef: "LEGAL-1",
				}},
			}
			_, err := Build(
				context.Background(),
				request,
				[]Input{{SourceID: "source-a", Path: test.path}},
				outputRoot,
				Generator{Name: "xminds-breach-corpus", Version: "0.1.0-p0", Commit: "0123456789ab"},
				func() time.Time { return fixedBuildTime },
			)
			if !errors.Is(err, ErrBuildFailed) {
				t.Fatalf("Build() error = %v", err)
			}
			entries, readErr := os.ReadDir(outputRoot)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("failed build left output entries: %v", entries)
			}
		})
	}
}

func TestBuildRejectsExistingContentAddressedReleaseWithoutChangingIt(t *testing.T) {
	t.Parallel()

	outputRoot := privateDirectory(t)
	source := writeSource(t, "existing-release.txt", testSHA1Digest+"\n")
	request := buildRequestForSources(t, sourceDefinition{id: "source-a", path: source, version: "1", license: "LEGAL-1"})
	generator := Generator{Name: "xminds-breach-corpus", Version: "0.1.0-p0", Commit: "0123456789ab"}
	first, err := Build(
		context.Background(), request, []Input{{SourceID: "source-a", Path: source}},
		outputRoot, generator, func() time.Time { return fixedBuildTime },
	)
	if err != nil {
		t.Fatalf("Build(first) error = %v", err)
	}
	before, err := os.ReadFile(filepath.Join(first.ReleaseDirectory, ManifestFileName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Build(
		context.Background(), request, []Input{{SourceID: "source-a", Path: source}},
		outputRoot, generator, func() time.Time { return fixedBuildTime.Add(time.Hour) },
	); !errors.Is(err, ErrBuildFailed) {
		t.Fatalf("Build(second) error = %v", err)
	}
	after, err := os.ReadFile(filepath.Join(first.ReleaseDirectory, ManifestFileName))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("existing manifest changed")
	}
}

func TestMergeRunsFailsBeforeWritingPastOutputLimit(t *testing.T) {
	t.Parallel()

	runPath := filepath.Join(t.TempDir(), "run.txt")
	if err := os.WriteFile(runPath, []byte(testSHA1Digest+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(t.TempDir(), CorpusFileName)
	if _, _, _, err := mergeRuns([]string{runPath}, outputPath, 1, 40); !errors.Is(err, ErrBuildFailed) {
		t.Fatalf("mergeRuns() error = %v", err)
	}
}

func TestPreflightInputBytesRejectsCumulativeLimitBeforeParsing(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	first := filepath.Join(directory, "first.txt")
	second := filepath.Join(directory, "second.txt")
	for _, path := range []string{first, second} {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o400)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(MaximumTotalInputBytes/2 + 1); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	bindings := []sourceBinding{{path: first}, {path: second}}
	if _, err := preflightInputBytes(bindings); !errors.Is(err, ErrBuildFailed) {
		t.Fatalf("preflightInputBytes() error = %v", err)
	}
}

type sourceDefinition struct {
	id      string
	path    string
	version string
	license string
}

func buildRequestForSources(t *testing.T, sources ...sourceDefinition) BuildRequest {
	t.Helper()
	request := BuildRequest{SchemaVersion: ManifestSchemaVersion, CorpusVersion: "2026.08.30.1"}
	for _, source := range sources {
		raw, err := os.ReadFile(source.path)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(raw)
		request.Sources = append(request.Sources, SourceRequest{
			ID: source.id, Version: source.version, ExpectedSHA256: hex.EncodeToString(digest[:]), LicenseReviewRef: source.license,
		})
	}
	return request
}

func writeSource(t *testing.T, name, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(contents), 0o400); err != nil {
		t.Fatal(err)
	}
	return path
}

func privateDirectory(t *testing.T) string {
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

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func assertReadOnlyMode(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o222 != 0 {
		t.Fatalf("%s mode = %o", filepath.Base(path), info.Mode().Perm())
	}
}
