package breachcorpus

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVerifyReleaseAcceptsBuiltArtifactAndReturnsMembershipSet(t *testing.T) {
	t.Parallel()

	release := validReleaseFixture(t)
	verified, err := VerifyRelease(release, VerifyOptions{Mode: ArtifactMode})
	if err != nil {
		t.Fatalf("VerifyRelease() error = %v", err)
	}
	if verified.Manifest.Format != Format || verified.Result.ReleaseDirectory != release ||
		verified.Result.Counts.UniqueEntries != 2 || !verified.Set.ContainsPassword(testSHA1Password) ||
		!verified.Set.ContainsPassword(testSHA256Password) {
		t.Fatalf("verified release = %+v", verified.Result)
	}
}

func TestVerifyReleaseAcceptsSourceWhoseFinalDigestHasNoNewline(t *testing.T) {
	t.Parallel()

	outputRoot := privateDirectory(t)
	source := writeSource(t, "no-final-newline.txt", testSHA1Digest)
	request := buildRequestForSources(t, sourceDefinition{id: "source-a", path: source, version: "2026-08", license: "LEGAL-1"})
	result, err := Build(
		context.Background(),
		request,
		[]Input{{SourceID: "source-a", Path: source}},
		outputRoot,
		Generator{Name: "xminds-breach-corpus", Version: "0.1.0-p0", Commit: "0123456789ab"},
		func() time.Time { return fixedBuildTime },
	)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if _, err := VerifyRelease(result.ReleaseDirectory, VerifyOptions{Mode: ArtifactMode}); err != nil {
		t.Fatalf("VerifyRelease() error = %v", err)
	}
}

func TestVerifyReleaseRejectsTamperedManifestCorpusAndDirectoryName(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*testing.T, string) string{
		"impossible duplicate count": func(t *testing.T, release string) string {
			makeReleaseMutable(t, release)
			path := filepath.Join(release, ManifestFileName)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var manifest Manifest
			if err := json.Unmarshal(raw, &manifest); err != nil {
				t.Fatal(err)
			}
			manifest.Corpus.DuplicateEntries = math.MaxUint64
			changed, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			writeReadOnlyFile(t, path, append(changed, '\n'))
			restoreReleaseReadOnly(t, release)
			return release
		},
		"unknown manifest field": func(t *testing.T, release string) string {
			makeReleaseMutable(t, release)
			path := filepath.Join(release, ManifestFileName)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var value map[string]any
			if err := json.Unmarshal(raw, &value); err != nil {
				t.Fatal(err)
			}
			value["unapproved"] = true
			changed, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			writeReadOnlyFile(t, path, append(changed, '\n'))
			restoreReleaseReadOnly(t, release)
			return release
		},
		"corpus content": func(t *testing.T, release string) string {
			makeReleaseMutable(t, release)
			writeReadOnlyFile(t, filepath.Join(release, CorpusFileName), []byte(testSHA1Digest+"\n"))
			restoreReleaseReadOnly(t, release)
			return release
		},
		"directory name": func(t *testing.T, release string) string {
			parent := filepath.Dir(release)
			renamed := filepath.Join(parent, ReleaseDirectoryPrefix+strings.Repeat("0", 64))
			if err := os.Rename(release, renamed); err != nil {
				t.Fatal(err)
			}
			return renamed
		},
	}
	for name, mutate := range tests {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			release := mutate(t, validReleaseFixture(t))
			if _, err := VerifyRelease(release, VerifyOptions{Mode: ArtifactMode}); !errors.Is(err, ErrInvalidRelease) {
				t.Fatalf("VerifyRelease() error = %v", err)
			}
		})
	}
}

func TestVerifyReleaseRejectsWritableLinkedOrNonCanonicalCorpus(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*testing.T, string){
		"writable corpus": func(t *testing.T, release string) {
			if err := os.Chmod(filepath.Join(release, CorpusFileName), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"linked corpus": func(t *testing.T, release string) {
			makeReleaseMutable(t, release)
			corpus := filepath.Join(release, CorpusFileName)
			target := filepath.Join(filepath.Dir(release), "linked-target.txt")
			if err := os.WriteFile(target, []byte(testSHA1Digest+"\n"), 0o400); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(corpus); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, corpus); err != nil {
				t.Fatal(err)
			}
			restoreReleaseReadOnly(t, release)
		},
		"unsorted corpus": func(t *testing.T, release string) {
			makeReleaseMutable(t, release)
			writeReadOnlyFile(t, filepath.Join(release, CorpusFileName), []byte(testSHA1Digest+"\n"+testSHA256Digest+"\n"))
			restoreReleaseReadOnly(t, release)
		},
		"missing final newline": func(t *testing.T, release string) {
			makeReleaseMutable(t, release)
			writeReadOnlyFile(t, filepath.Join(release, CorpusFileName), []byte(testSHA1Digest))
			restoreReleaseReadOnly(t, release)
		},
	}
	for name, mutate := range tests {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			release := validReleaseFixture(t)
			mutate(t, release)
			if _, err := VerifyRelease(release, VerifyOptions{Mode: ArtifactMode}); !errors.Is(err, ErrInvalidRelease) {
				t.Fatalf("VerifyRelease() error = %v", err)
			}
		})
	}
}

func TestVerifyReleaseEnforcesParentAndDeploymentOwnership(t *testing.T) {
	t.Parallel()

	release := validReleaseFixture(t)
	directory, err := openDirectoryNoFollow(release)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	metadata, err := metadataFor(directory)
	if err != nil {
		t.Fatal(err)
	}
	expected := &OwnershipExpectation{OwnerUID: metadata.uid, GroupGID: metadata.gid}
	if _, err := VerifyRelease(release, VerifyOptions{Mode: DeploymentMode, ExpectedOwnership: expected}); err != nil {
		t.Fatalf("VerifyRelease(deployment) error = %v", err)
	}
	wrong := &OwnershipExpectation{OwnerUID: metadata.uid + 1, GroupGID: metadata.gid}
	if _, err := VerifyRelease(release, VerifyOptions{Mode: DeploymentMode, ExpectedOwnership: wrong}); !errors.Is(err, ErrInvalidRelease) {
		t.Fatalf("VerifyRelease(wrong owner) error = %v", err)
	}

	if err := os.Chmod(filepath.Dir(release), 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRelease(release, VerifyOptions{Mode: ArtifactMode}); !errors.Is(err, ErrInvalidRelease) {
		t.Fatalf("VerifyRelease(writable parent) error = %v", err)
	}
}

func TestVerifyReleaseRuntimeRejectsServiceOwnedArtifacts(t *testing.T) {
	t.Parallel()

	release := validReleaseFixture(t)
	serviceUID := uint32(os.Geteuid())
	if _, err := VerifyRelease(release, VerifyOptions{Mode: RuntimeMode, EffectiveServiceUID: &serviceUID}); !errors.Is(err, ErrInvalidRelease) {
		t.Fatalf("VerifyRelease(runtime) error = %v", err)
	}
}

func validReleaseFixture(t *testing.T) string {
	t.Helper()
	outputRoot := privateDirectory(t)
	source := writeSource(t, "verified-source.txt", testSHA1Digest+"\n"+testSHA256Digest+"\n")
	request := buildRequestForSources(t, sourceDefinition{id: "source-a", path: source, version: "2026-08", license: "LEGAL-1"})
	result, err := Build(
		context.Background(),
		request,
		[]Input{{SourceID: "source-a", Path: source}},
		outputRoot,
		Generator{Name: "xminds-breach-corpus", Version: "0.1.0-p0", Commit: "0123456789ab"},
		func() time.Time { return fixedBuildTime },
	)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	return result.ReleaseDirectory
}

func makeReleaseMutable(t *testing.T, release string) {
	t.Helper()
	if err := os.Chmod(release, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{CorpusFileName, ManifestFileName} {
		if err := os.Chmod(filepath.Join(release, name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func restoreReleaseReadOnly(t *testing.T, release string) {
	t.Helper()
	for _, name := range []string{CorpusFileName, ManifestFileName} {
		if info, err := os.Lstat(filepath.Join(release, name)); err == nil && info.Mode().IsRegular() {
			if err := os.Chmod(filepath.Join(release, name), 0o400); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.Chmod(release, 0o500); err != nil {
		t.Fatal(err)
	}
}

func writeReadOnlyFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
}
