package breachcorpus

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"xminds-release-platform/internal/platform/strictjson"
)

const maximumManifestBytes = 1 << 20

func VerifyRelease(releaseDirectory string, options VerifyOptions) (*Release, error) {
	if !validVerificationRequest(releaseDirectory, options) {
		return nil, ErrInvalidRelease
	}
	expectedDigest := strings.TrimPrefix(filepath.Base(releaseDirectory), ReleaseDirectoryPrefix)

	parent, err := openDirectoryNoFollow(filepath.Dir(releaseDirectory))
	if err != nil {
		return nil, ErrInvalidRelease
	}
	defer parent.Close()
	parentMetadata, err := metadataFor(parent)
	if err != nil || !parentMetadata.mode.IsDir() || parentMetadata.mode.Perm()&0o022 != 0 {
		return nil, ErrInvalidRelease
	}

	directory, err := openDirectoryNoFollow(releaseDirectory)
	if err != nil {
		return nil, ErrInvalidRelease
	}
	defer directory.Close()
	directoryMetadata, err := metadataFor(directory)
	if err != nil || !directoryMetadata.mode.IsDir() || directoryMetadata.mode.Perm()&0o222 != 0 {
		return nil, ErrInvalidRelease
	}

	names, err := directory.Readdirnames(-1)
	if err != nil {
		return nil, ErrInvalidRelease
	}
	sort.Strings(names)
	if len(names) != 2 || names[0] != CorpusFileName || names[1] != ManifestFileName {
		return nil, ErrInvalidRelease
	}

	corpus, corpusMetadata, err := openRegularFileAt(directory, CorpusFileName)
	if err != nil {
		return nil, ErrInvalidRelease
	}
	defer corpus.Close()
	manifestFile, manifestMetadata, err := openRegularFileAt(directory, ManifestFileName)
	if err != nil {
		return nil, ErrInvalidRelease
	}
	defer manifestFile.Close()
	if corpusMetadata.mode.Perm()&0o222 != 0 || manifestMetadata.mode.Perm()&0o222 != 0 ||
		corpusMetadata.size <= 0 || corpusMetadata.size > MaximumCorpusBytes ||
		manifestMetadata.size <= 0 || manifestMetadata.size > maximumManifestBytes ||
		!validOwnership(options, parentMetadata, directoryMetadata, corpusMetadata, manifestMetadata) {
		return nil, ErrInvalidRelease
	}

	manifestRaw, err := readFileSnapshot(manifestFile, manifestMetadata, maximumManifestBytes)
	if err != nil {
		return nil, ErrInvalidRelease
	}
	var manifest Manifest
	if err := strictjson.DecodeBytes(manifestRaw, maximumManifestBytes, &manifest); err != nil ||
		!validManifest(manifest, expectedDigest) {
		return nil, ErrInvalidRelease
	}
	canonicalManifest, err := json.Marshal(manifest)
	if err != nil {
		return nil, ErrInvalidRelease
	}
	canonicalManifest = append(canonicalManifest, '\n')
	if !bytes.Equal(manifestRaw, canonicalManifest) {
		return nil, ErrInvalidRelease
	}

	set, counts, corpusBytes, corpusDigest, err := verifyCanonicalCorpus(corpus, corpusMetadata)
	if err != nil || corpusDigest != expectedDigest || manifest.Corpus.Bytes != corpusBytes ||
		manifest.Corpus.SHA256 != corpusDigest ||
		manifest.Corpus.SHA1Entries != counts.SHA1Entries ||
		manifest.Corpus.SHA256Entries != counts.SHA256Entries ||
		manifest.Corpus.UniqueEntries != counts.UniqueEntries ||
		manifest.Corpus.RejectedEntries != 0 {
		return nil, ErrInvalidRelease
	}

	reopenedCorpus, _, err := openRegularFileAt(directory, CorpusFileName)
	if err != nil {
		return nil, ErrInvalidRelease
	}
	defer reopenedCorpus.Close()
	reopenedManifest, _, err := openRegularFileAt(directory, ManifestFileName)
	if err != nil {
		return nil, ErrInvalidRelease
	}
	defer reopenedManifest.Close()
	reopenedDirectory, err := openDirectoryNoFollow(releaseDirectory)
	if err != nil {
		return nil, ErrInvalidRelease
	}
	defer reopenedDirectory.Close()
	if !sameOpenFile(corpus, reopenedCorpus) || !sameOpenFile(manifestFile, reopenedManifest) ||
		!sameOpenFile(directory, reopenedDirectory) {
		return nil, ErrInvalidRelease
	}

	manifestDigest := sha256.Sum256(manifestRaw)
	counts.DuplicateEntries = manifest.Corpus.DuplicateEntries
	return &Release{
		Manifest: manifest,
		Set:      set,
		Result: Result{
			ReleaseDirectory: releaseDirectory,
			CorpusSHA256:     corpusDigest,
			ManifestSHA256:   hex.EncodeToString(manifestDigest[:]),
			Counts:           counts,
			CorpusBytes:      corpusBytes,
		},
	}, nil
}

func validVerificationRequest(path string, options VerifyOptions) bool {
	if path == "" || strings.TrimSpace(path) != path || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	base := filepath.Base(path)
	if !strings.HasPrefix(base, ReleaseDirectoryPrefix) {
		return false
	}
	digest := strings.TrimPrefix(base, ReleaseDirectoryPrefix)
	if digest != strings.ToLower(digest) || !validSHA256(digest) {
		return false
	}
	switch options.Mode {
	case ArtifactMode:
		return options.ExpectedOwnership == nil && options.EffectiveServiceUID == nil
	case DeploymentMode:
		return options.ExpectedOwnership != nil && options.EffectiveServiceUID == nil
	case RuntimeMode:
		return options.ExpectedOwnership == nil && options.EffectiveServiceUID != nil
	default:
		return false
	}
}

func validOwnership(options VerifyOptions, values ...fileMetadata) bool {
	if options.Mode == DeploymentMode {
		expected := options.ExpectedOwnership
		if expected == nil || len(values) < 2 || values[0].uid != expected.OwnerUID {
			return false
		}
		for _, value := range values[1:] {
			if value.uid != expected.OwnerUID || value.gid != expected.GroupGID {
				return false
			}
		}
	}
	if options.Mode == RuntimeMode {
		if options.EffectiveServiceUID == nil || *options.EffectiveServiceUID == 0 {
			return false
		}
		for _, value := range values {
			if value.uid == *options.EffectiveServiceUID {
				return false
			}
		}
	}
	return true
}

func readFileSnapshot(file *os.File, initial fileMetadata, maximumBytes int64) ([]byte, error) {
	if initial.size <= 0 || initial.size > maximumBytes {
		return nil, ErrInvalidRelease
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumBytes+1))
	if err != nil || int64(len(raw)) != initial.size {
		return nil, ErrInvalidRelease
	}
	after, err := metadataFor(file)
	if err != nil || after.dev != initial.dev || after.ino != initial.ino || after.size != initial.size {
		return nil, ErrInvalidRelease
	}
	return raw, nil
}

func validManifest(manifest Manifest, expectedDigest string) bool {
	if manifest.SchemaVersion != ManifestSchemaVersion || manifest.Format != Format ||
		!validBoundedText(manifest.CorpusVersion, maximumVersionBytes) ||
		!validGenerator(manifest.Generator) || len(manifest.Sources) == 0 ||
		len(manifest.Sources) > MaximumInputCount ||
		manifest.Corpus.File != CorpusFileName || manifest.Corpus.Bytes <= 0 ||
		manifest.Corpus.Bytes > MaximumCorpusBytes ||
		manifest.Corpus.SHA256 != expectedDigest ||
		manifest.Corpus.SHA256 != strings.ToLower(manifest.Corpus.SHA256) ||
		manifest.Corpus.UniqueEntries == 0 ||
		manifest.Corpus.SHA1Entries > manifest.Corpus.UniqueEntries ||
		manifest.Corpus.SHA256Entries > manifest.Corpus.UniqueEntries ||
		manifest.Corpus.SHA1Entries+manifest.Corpus.SHA256Entries != manifest.Corpus.UniqueEntries ||
		manifest.Corpus.RejectedEntries != 0 {
		return false
	}
	generatedAt, err := time.Parse(time.RFC3339, manifest.GeneratedAt)
	if err != nil || !strings.HasSuffix(manifest.GeneratedAt, "Z") ||
		generatedAt.UTC().Format(time.RFC3339) != manifest.GeneratedAt {
		return false
	}

	var totalInputBytes int64
	var previousID string
	for _, source := range manifest.Sources {
		if !sourceIDPattern.MatchString(source.ID) || source.ID <= previousID ||
			!validBoundedText(source.Version, maximumVersionBytes) ||
			!licenseRefPattern.MatchString(source.LicenseReviewRef) ||
			source.SHA256 != strings.ToLower(source.SHA256) || !validSHA256(source.SHA256) ||
			source.Bytes <= 0 || source.Bytes > MaximumTotalInputBytes ||
			totalInputBytes > MaximumTotalInputBytes-source.Bytes {
			return false
		}
		totalInputBytes += source.Bytes
		previousID = source.ID
	}
	if totalInputBytes <= 0 {
		return false
	}
	maximumPossibleEntries := uint64(totalInputBytes / 41)
	return manifest.Corpus.UniqueEntries <= maximumPossibleEntries &&
		manifest.Corpus.DuplicateEntries <= maximumPossibleEntries-manifest.Corpus.UniqueEntries
}

func verifyCanonicalCorpus(file *os.File, initial fileMetadata) (*Set, Counts, int64, string, error) {
	var counts Counts
	if initial.size <= 0 || initial.size > MaximumCorpusBytes {
		return nil, counts, 0, "", ErrInvalidRelease
	}
	hasher := sha256.New()
	scanner := bufio.NewScanner(io.TeeReader(file, hasher))
	scanner.Buffer(make([]byte, 1024), MaximumLineBytes+1)
	set := &Set{sha1: make(map[string]struct{}), sha256: make(map[string]struct{})}
	var previous string
	var bytesRead int64
	for scanner.Scan() {
		line := scanner.Text()
		digest, algorithm, ignored, err := NormalizeLine(line)
		if err != nil || ignored || digest != line || (previous != "" && digest <= previous) {
			return nil, counts, 0, "", ErrInvalidRelease
		}
		lineBytes := int64(len(line) + 1)
		if lineBytes > MaximumCorpusBytes || bytesRead > MaximumCorpusBytes-lineBytes {
			return nil, counts, 0, "", ErrInvalidRelease
		}
		bytesRead += lineBytes
		switch algorithm {
		case SHA1:
			set.sha1[digest] = struct{}{}
			counts.SHA1Entries++
		case SHA256:
			set.sha256[digest] = struct{}{}
			counts.SHA256Entries++
		default:
			return nil, counts, 0, "", ErrInvalidRelease
		}
		counts.UniqueEntries++
		previous = digest
	}
	if scanner.Err() != nil || counts.UniqueEntries == 0 || bytesRead != initial.size {
		return nil, counts, 0, "", ErrInvalidRelease
	}
	after, err := metadataFor(file)
	if err != nil || after.dev != initial.dev || after.ino != initial.ino || after.size != initial.size {
		return nil, counts, 0, "", ErrInvalidRelease
	}
	return set, counts, bytesRead, hex.EncodeToString(hasher.Sum(nil)), nil
}
