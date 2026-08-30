package breachcorpus

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type sourceBinding struct {
	request SourceRequest
	path    string
}

func Build(
	ctx context.Context,
	request BuildRequest,
	inputs []Input,
	outputRoot string,
	generator Generator,
	clock func() time.Time,
) (Result, error) {
	if ctx == nil || clock == nil || ValidateInputs(request, inputs) != nil ||
		!validGenerator(generator) || !validPrivateOutputRoot(outputRoot) {
		return Result{}, ErrBuildFailed
	}
	bindings := orderedBindings(request, inputs)
	totalInputBytes, err := preflightInputBytes(bindings)
	if err != nil {
		return Result{}, ErrBuildFailed
	}

	staging, err := os.MkdirTemp(outputRoot, ".breach-corpus-build-")
	if err != nil {
		return Result{}, ErrBuildFailed
	}
	defer func() {
		if staging != "" {
			_ = os.Chmod(staging, 0o700)
			_ = os.RemoveAll(staging)
		}
	}()
	if err := os.Chmod(staging, 0o700); err != nil {
		return Result{}, ErrBuildFailed
	}
	runDirectory := filepath.Join(staging, "runs")
	if err := os.Mkdir(runDirectory, 0o700); err != nil {
		return Result{}, ErrBuildFailed
	}

	chunk := make([]string, 0, 4096)
	chunkBytes := 0
	runPaths := make([]string, 0, 8)
	var rawEntries uint64
	var processedInputBytes int64
	evidence := make([]SourceEvidence, 0, len(bindings))

	flush := func() error {
		if len(chunk) == 0 {
			return nil
		}
		path, err := writeSortedRun(runDirectory, len(runPaths), chunk)
		if err != nil {
			return err
		}
		runPaths = append(runPaths, path)
		chunk = make([]string, 0, 4096)
		chunkBytes = 0
		return nil
	}

	for _, binding := range bindings {
		if err := ctx.Err(); err != nil {
			return Result{}, ErrBuildFailed
		}
		sourceEvidence, inputBytes, err := readSource(binding, func(digest string) error {
			if rawEntries == math.MaxUint64 {
				return ErrBuildFailed
			}
			rawEntries++
			chunk = append(chunk, digest)
			chunkBytes += len(digest) + 1
			if chunkBytes >= buildChunkBytes {
				return flush()
			}
			return nil
		})
		if err != nil || inputBytes < 0 || processedInputBytes > totalInputBytes-inputBytes {
			return Result{}, ErrBuildFailed
		}
		processedInputBytes += inputBytes
		evidence = append(evidence, sourceEvidence)
	}
	if processedInputBytes != totalInputBytes || rawEntries == 0 {
		return Result{}, ErrBuildFailed
	}
	if err := flush(); err != nil {
		return Result{}, ErrBuildFailed
	}

	corpusPath := filepath.Join(staging, CorpusFileName)
	counts, corpusBytes, corpusDigest, err := mergeRuns(runPaths, corpusPath, rawEntries, MaximumCorpusBytes)
	if err != nil {
		return Result{}, ErrBuildFailed
	}
	if err := os.RemoveAll(runDirectory); err != nil {
		return Result{}, ErrBuildFailed
	}

	manifest := Manifest{
		SchemaVersion: ManifestSchemaVersion,
		Format:        Format,
		CorpusVersion: request.CorpusVersion,
		GeneratedAt:   clock().UTC().Format(time.RFC3339),
		Generator:     generator,
		Sources:       evidence,
		Corpus: CorpusEvidence{
			File:             CorpusFileName,
			Bytes:            corpusBytes,
			SHA256:           corpusDigest,
			SHA1Entries:      counts.SHA1Entries,
			SHA256Entries:    counts.SHA256Entries,
			UniqueEntries:    counts.UniqueEntries,
			DuplicateEntries: counts.DuplicateEntries,
			RejectedEntries:  counts.RejectedEntries,
		},
	}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		return Result{}, ErrBuildFailed
	}
	manifestRaw = append(manifestRaw, '\n')
	manifestPath := filepath.Join(staging, ManifestFileName)
	if err := writeSynchronizedFile(manifestPath, manifestRaw); err != nil {
		return Result{}, ErrBuildFailed
	}
	manifestDigest := sha256.Sum256(manifestRaw)

	if err := os.Chmod(corpusPath, 0o400); err != nil {
		return Result{}, ErrBuildFailed
	}
	if err := os.Chmod(manifestPath, 0o400); err != nil {
		return Result{}, ErrBuildFailed
	}
	if err := syncDirectory(staging); err != nil {
		return Result{}, ErrBuildFailed
	}

	releaseDirectory := filepath.Join(outputRoot, ReleaseDirectoryPrefix+corpusDigest)
	if _, err := os.Lstat(releaseDirectory); err == nil || !errors.Is(err, os.ErrNotExist) {
		return Result{}, ErrBuildFailed
	}
	if err := os.Chmod(staging, 0o500); err != nil {
		return Result{}, ErrBuildFailed
	}
	if err := os.Rename(staging, releaseDirectory); err != nil {
		return Result{}, ErrBuildFailed
	}
	staging = ""
	if err := syncDirectory(outputRoot); err != nil {
		return Result{}, ErrBuildFailed
	}

	return Result{
		ReleaseDirectory: releaseDirectory,
		CorpusSHA256:     corpusDigest,
		ManifestSHA256:   hex.EncodeToString(manifestDigest[:]),
		Counts:           counts,
		CorpusBytes:      corpusBytes,
	}, nil
}

func orderedBindings(request BuildRequest, inputs []Input) []sourceBinding {
	inputPaths := make(map[string]string, len(inputs))
	for _, input := range inputs {
		inputPaths[input.SourceID] = input.Path
	}
	bindings := make([]sourceBinding, 0, len(request.Sources))
	for _, source := range request.Sources {
		bindings = append(bindings, sourceBinding{request: source, path: inputPaths[source.ID]})
	}
	sort.Slice(bindings, func(left, right int) bool {
		return bindings[left].request.ID < bindings[right].request.ID
	})
	return bindings
}

func preflightInputBytes(bindings []sourceBinding) (int64, error) {
	var total int64
	for _, binding := range bindings {
		info, err := os.Lstat(binding.path)
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 ||
			info.Size() > MaximumTotalInputBytes || total > MaximumTotalInputBytes-info.Size() {
			return 0, ErrBuildFailed
		}
		total += info.Size()
	}
	if total <= 0 {
		return 0, ErrBuildFailed
	}
	return total, nil
}

func readSource(binding sourceBinding, consume func(string) error) (SourceEvidence, int64, error) {
	info, err := os.Lstat(binding.path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaximumTotalInputBytes {
		return SourceEvidence{}, 0, ErrBuildFailed
	}
	file, err := os.Open(binding.path)
	if err != nil {
		return SourceEvidence{}, 0, ErrBuildFailed
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		return SourceEvidence{}, 0, ErrBuildFailed
	}

	hasher := sha256.New()
	scanner := bufio.NewScanner(io.TeeReader(file, hasher))
	scanner.Buffer(make([]byte, 1024), MaximumLineBytes+1)
	for scanner.Scan() {
		digest, _, ignored, err := NormalizeLine(scanner.Text())
		if err != nil {
			return SourceEvidence{}, 0, ErrBuildFailed
		}
		if ignored {
			continue
		}
		if err := consume(digest); err != nil {
			return SourceEvidence{}, 0, ErrBuildFailed
		}
	}
	if scanner.Err() != nil {
		return SourceEvidence{}, 0, ErrBuildFailed
	}
	afterInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, afterInfo) || afterInfo.Size() != info.Size() {
		return SourceEvidence{}, 0, ErrBuildFailed
	}
	actualDigest := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(actualDigest, binding.request.ExpectedSHA256) {
		return SourceEvidence{}, 0, ErrBuildFailed
	}
	return SourceEvidence{
		ID:               binding.request.ID,
		Version:          binding.request.Version,
		Bytes:            info.Size(),
		SHA256:           actualDigest,
		LicenseReviewRef: binding.request.LicenseReviewRef,
	}, info.Size(), nil
}

func validGenerator(generator Generator) bool {
	return generator.Name == "xminds-breach-corpus" &&
		validBoundedText(generator.Version, maximumVersionBytes) &&
		validBoundedText(generator.Commit, maximumVersionBytes)
}

func validPrivateOutputRoot(path string) bool {
	if path == "" || strings.TrimSpace(path) != path || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.IsDir() && info.Mode().Perm()&0o077 == 0
}

func writeSynchronizedFile(path string, contents []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrBuildFailed
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return ErrBuildFailed
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return ErrBuildFailed
	}
	if err := file.Close(); err != nil {
		return ErrBuildFailed
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return ErrBuildFailed
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return ErrBuildFailed
	}
	return nil
}
