package iam

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"embed"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const maximumBreachCorpusBytes = 128 << 20

//go:embed breach_corpus_development.txt
var developmentBreachCorpus embed.FS

var (
	ErrBreachCorpusInvalid    = errors.New("breached-password corpus is invalid")
	ErrMFAConfiguration       = errors.New("MFA configuration is invalid")
	ErrMFAProofInvalid        = errors.New("MFA proof is invalid")
	ErrSecretReferenceInvalid = errors.New("secret reference is invalid")
)

type FileBreachChecker struct {
	sha1Digests   map[string]struct{}
	sha256Digests map[string]struct{}
}

func NewFileBreachChecker(path string) (*FileBreachChecker, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, ErrBreachCorpusInvalid
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o222 != 0 || info.Size() <= 0 || info.Size() > maximumBreachCorpusBytes {
		return nil, ErrBreachCorpusInvalid
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open breached-password corpus: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		return nil, ErrBreachCorpusInvalid
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 4096)
	return parseBreachCorpus(scanner)
}

func NewDevelopmentBreachChecker() (*FileBreachChecker, error) {
	file, err := developmentBreachCorpus.Open("breach_corpus_development.txt")
	if err != nil {
		return nil, ErrBreachCorpusInvalid
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 4096)
	return parseBreachCorpus(scanner)
}

func parseBreachCorpus(scanner *bufio.Scanner) (*FileBreachChecker, error) {
	checker := &FileBreachChecker{sha1Digests: make(map[string]struct{}), sha256Digests: make(map[string]struct{})}
	for scanner.Scan() {
		line := strings.ToUpper(strings.TrimSpace(scanner.Text()))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		decoded, decodeErr := hex.DecodeString(line)
		if decodeErr != nil {
			return nil, ErrBreachCorpusInvalid
		}
		switch len(decoded) {
		case sha1.Size:
			checker.sha1Digests[line] = struct{}{}
		case sha256.Size:
			checker.sha256Digests[line] = struct{}{}
		default:
			return nil, ErrBreachCorpusInvalid
		}
	}
	if err := scanner.Err(); err != nil || len(checker.sha1Digests)+len(checker.sha256Digests) == 0 {
		return nil, ErrBreachCorpusInvalid
	}
	return checker, nil
}

func (checker *FileBreachChecker) IsBreached(_ context.Context, password string) (bool, error) {
	if checker == nil || len(checker.sha1Digests)+len(checker.sha256Digests) == 0 {
		return false, ErrBreachCorpusInvalid
	}
	sha1Digest := sha1.Sum([]byte(password))
	if _, found := checker.sha1Digests[strings.ToUpper(hex.EncodeToString(sha1Digest[:]))]; found {
		return true, nil
	}
	sha256Digest := sha256.Sum256([]byte(password))
	_, found := checker.sha256Digests[strings.ToUpper(hex.EncodeToString(sha256Digest[:]))]
	return found, nil
}

type SecretResolver interface {
	Resolve(ctx context.Context, reference string) ([]byte, error)
}

type DirectorySecretResolver struct {
	mutex    sync.RWMutex
	root     *os.File
	executor *secretIOExecutor
}

func NewDirectorySecretResolver(root string) (*DirectorySecretResolver, error) {
	root = strings.TrimSpace(root)
	if root == "" || !filepath.IsAbs(root) {
		return nil, ErrSecretReferenceInvalid
	}
	clean := filepath.Clean(root)
	directory, err := openDirectoryPathNoFollow(clean)
	if err != nil {
		return nil, ErrSecretReferenceInvalid
	}
	if !trustedDirectoryDescriptor(directory) {
		_ = directory.Close()
		return nil, ErrSecretReferenceInvalid
	}
	resolver := &DirectorySecretResolver{root: directory}
	resolver.executor = newSecretIOExecutor(directorySecretIOWorkers, directorySecretIOQueueSize, resolver.readSnapshot)
	if resolver.executor == nil {
		_ = directory.Close()
		return nil, ErrSecretReferenceInvalid
	}
	return resolver, nil
}

func (resolver *DirectorySecretResolver) Resolve(ctx context.Context, reference string) ([]byte, error) {
	if resolver == nil || resolver.executor == nil || ctx == nil {
		return nil, ErrSecretReferenceInvalid
	}
	const prefix = "secret://iam/"
	name, found := strings.CutPrefix(strings.TrimSpace(reference), prefix)
	if !found || name == "" || name != filepath.Base(name) || strings.ContainsAny(name, `/\\`) {
		return nil, ErrSecretReferenceInvalid
	}
	return resolver.executor.Resolve(ctx, name)
}

func (resolver *DirectorySecretResolver) readSnapshot(name string) ([]byte, error) {
	resolver.mutex.RLock()
	defer resolver.mutex.RUnlock()
	if resolver.root == nil || !trustedDirectoryDescriptor(resolver.root) {
		return nil, ErrSecretReferenceInvalid
	}
	fd, err := unix.Openat(int(resolver.root.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrSecretReferenceInvalid
	}
	secret := os.NewFile(uintptr(fd), name)
	if secret == nil {
		_ = unix.Close(fd)
		return nil, ErrSecretReferenceInvalid
	}
	defer secret.Close()
	info, err := secret.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > 4096 || !trustedDescriptorOwner(secret) {
		return nil, ErrSecretReferenceInvalid
	}
	contents, err := io.ReadAll(io.LimitReader(secret, 4097))
	if err != nil || len(contents) == 0 || len(contents) > 4096 {
		return nil, ErrSecretReferenceInvalid
	}
	return []byte(strings.TrimSpace(string(contents))), nil
}

func (resolver *DirectorySecretResolver) Close() error {
	if resolver == nil {
		return nil
	}
	if resolver.executor != nil {
		resolver.executor.Close()
	}
	resolver.mutex.Lock()
	defer resolver.mutex.Unlock()
	if resolver.root == nil {
		return nil
	}
	err := resolver.root.Close()
	resolver.root = nil
	return err
}

func openDirectoryPathNoFollow(path string) (*os.File, error) {
	current, err := openDirectoryAt(unix.AT_FDCWD, string(filepath.Separator))
	if err != nil {
		return nil, err
	}
	relative := strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator))
	if relative == "" {
		return current, nil
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		next, openErr := openDirectoryAt(int(current.Fd()), component)
		_ = current.Close()
		if openErr != nil {
			return nil, openErr
		}
		current = next
	}
	return current, nil
}

func openDirectoryAt(parentFD int, name string) (*os.File, error) {
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrSecretReferenceInvalid
	}
	info, err := file.Stat()
	if err != nil || !info.IsDir() {
		_ = file.Close()
		return nil, ErrSecretReferenceInvalid
	}
	return file, nil
}

func trustedDescriptorOwner(file *os.File) bool {
	if file == nil {
		return false
	}
	var metadata unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &metadata); err != nil {
		return false
	}
	return metadata.Uid == 0 || int(metadata.Uid) == os.Geteuid()
}

func trustedDirectoryDescriptor(directory *os.File) bool {
	if directory == nil || !trustedDescriptorOwner(directory) {
		return false
	}
	info, err := directory.Stat()
	return err == nil && info.IsDir() && info.Mode().Perm()&0o022 == 0
}

type TOTPConfig struct {
	Digits    int
	Period    time.Duration
	Skew      int
	Algorithm string
}

type MFAAssertion struct {
	Counter int64
}

type MFAVerifier interface {
	Verify(ctx context.Context, secretReference, proof string) (MFAAssertion, error)
}

type TOTPVerifier struct {
	config   TOTPConfig
	resolver SecretResolver
	clock    func() time.Time
}

func NewTOTPVerifier(config TOTPConfig, resolver SecretResolver, clock func() time.Time) (*TOTPVerifier, error) {
	if config.Algorithm == "" {
		config.Algorithm = "SHA1"
	}
	config.Algorithm = strings.ToUpper(config.Algorithm)
	if resolver == nil || clock == nil || (config.Digits != 6 && config.Digits != 8) ||
		config.Period < 30*time.Second || config.Period > 2*time.Minute || config.Skew < 0 || config.Skew > 2 ||
		(config.Algorithm != "SHA1" && config.Algorithm != "SHA256") {
		return nil, ErrMFAConfiguration
	}
	return &TOTPVerifier{config: config, resolver: resolver, clock: clock}, nil
}

func (verifier *TOTPVerifier) Verify(ctx context.Context, secretReference, proof string) (MFAAssertion, error) {
	if verifier == nil || verifier.resolver == nil || verifier.clock == nil {
		return MFAAssertion{}, ErrMFAConfiguration
	}
	if len(proof) != verifier.config.Digits {
		return MFAAssertion{}, ErrMFAProofInvalid
	}
	if _, err := strconv.ParseUint(proof, 10, 32); err != nil {
		return MFAAssertion{}, ErrMFAProofInvalid
	}
	encoded, err := verifier.resolver.Resolve(ctx, secretReference)
	if err != nil {
		return MFAAssertion{}, ErrMFAProofInvalid
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(string(encoded))))
	if err != nil || len(secret) < 16 || len(secret) > 128 {
		return MFAAssertion{}, ErrMFAProofInvalid
	}
	counter := verifier.clock().UTC().Unix() / int64(verifier.config.Period/time.Second)
	for offset := -verifier.config.Skew; offset <= verifier.config.Skew; offset++ {
		candidate := counter + int64(offset)
		if candidate < 0 {
			continue
		}
		if hmac.Equal([]byte(totpCode(secret, candidate, verifier.config)), []byte(proof)) {
			return MFAAssertion{Counter: candidate}, nil
		}
	}
	return MFAAssertion{}, ErrMFAProofInvalid
}

func totpCode(secret []byte, counter int64, config TOTPConfig) string {
	var constructor func() hash.Hash = sha1.New
	if config.Algorithm == "SHA256" {
		constructor = sha256.New
	}
	buffer := make([]byte, 8)
	binary.BigEndian.PutUint64(buffer, uint64(counter))
	mac := hmac.New(constructor, secret)
	_, _ = mac.Write(buffer)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 | uint32(sum[offset+1])<<16 | uint32(sum[offset+2])<<8 | uint32(sum[offset+3])
	modulus := uint32(1)
	for range config.Digits {
		modulus *= 10
	}
	return fmt.Sprintf("%0*d", config.Digits, value%modulus)
}
