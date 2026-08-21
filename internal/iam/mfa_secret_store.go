package iam

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const (
	mfaSecretReferencePrefix = "secret://iam-mfa/"
	mfaSecretIOWorkers       = 4
	mfaSecretIOQueueSize     = 32
	mfaSecretMaximumBatch    = 128
	mfaSecretMaximumScan     = 256
	mfaSecretOrphanGrace     = time.Hour
)

type MFASecretStore interface {
	SecretResolver
	Create(ctx context.Context, enrollmentID uuid.UUID, base32Secret string) (string, error)
	Delete(ctx context.Context, reference string) error
	ListOrphanCandidates(ctx context.Context, olderThan time.Time, limit int) ([]string, error)
}

type RoutingSecretResolver struct {
	IAM SecretResolver
	MFA SecretResolver
}

// ProbeMFASecretStore verifies the complete create, resolve and delete path
// without exposing the generated seed or reference to logs or callers.
func ProbeMFASecretStore(ctx context.Context, store MFASecretStore) error {
	if ctx == nil || store == nil {
		return ErrIAMConfiguration
	}
	enrollmentID, err := uuid.NewV7()
	if err != nil {
		return ErrIAMConfiguration
	}
	seedBytes := make([]byte, 20)
	if _, err := rand.Read(seedBytes); err != nil {
		return ErrIAMConfiguration
	}
	seed := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seedBytes)
	reference, err := store.Create(ctx, enrollmentID, seed)
	if err != nil {
		return err
	}
	deleted := false
	defer func() {
		if !deleted {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), mfaSecretCleanupTimeout)
			defer cancel()
			_ = store.Delete(cleanupCtx, reference)
		}
	}()
	resolved, err := store.Resolve(ctx, reference)
	if err != nil || subtle.ConstantTimeCompare(resolved, []byte(seed)) != 1 {
		if err != nil {
			return err
		}
		return ErrSecretReferenceInvalid
	}
	if err := store.Delete(ctx, reference); err != nil {
		return err
	}
	deleted = true
	return nil
}

func (resolver RoutingSecretResolver) Resolve(ctx context.Context, reference string) ([]byte, error) {
	if ctx == nil || reference != strings.TrimSpace(reference) {
		return nil, ErrSecretReferenceInvalid
	}
	if strings.HasPrefix(reference, mfaSecretReferencePrefix) {
		if resolver.MFA == nil {
			return nil, ErrSecretReferenceInvalid
		}
		if _, ok := parseMFASecretReference(reference); !ok {
			return nil, ErrSecretReferenceInvalid
		}
		return resolver.MFA.Resolve(ctx, reference)
	}
	const iamPrefix = "secret://iam/"
	if strings.HasPrefix(reference, iamPrefix) {
		name := strings.TrimPrefix(reference, iamPrefix)
		if resolver.IAM == nil || name == "" || name != filepath.Base(name) || strings.ContainsAny(name, `/\`) || strings.Contains(name, "://") {
			return nil, ErrSecretReferenceInvalid
		}
		return resolver.IAM.Resolve(ctx, reference)
	}
	return nil, ErrSecretReferenceInvalid
}

type FileMFASecretStore struct {
	mutex    sync.RWMutex
	root     *os.File
	executor *mfaSecretIOExecutor
	shutdown sync.Once
	scanMu   sync.Mutex
	scanRoot *os.File
}

func NewFileMFASecretStore(root string) (*FileMFASecretStore, error) {
	root = strings.TrimSpace(root)
	if root == "" || !filepath.IsAbs(root) || root != filepath.Clean(root) {
		return nil, ErrSecretReferenceInvalid
	}
	directory, err := openDirectoryPathNoFollow(root)
	if err != nil || !trustedDirectoryDescriptor(directory) {
		if directory != nil {
			_ = directory.Close()
		}
		return nil, ErrSecretReferenceInvalid
	}
	if !writableMFASecretDirectory(directory) {
		_ = directory.Close()
		return nil, ErrSecretReferenceInvalid
	}
	store := &FileMFASecretStore{root: directory, executor: newMFASecretIOExecutor(mfaSecretIOWorkers, mfaSecretIOQueueSize)}
	if store.executor == nil {
		_ = directory.Close()
		return nil, ErrSecretReferenceInvalid
	}
	return store, nil
}

func writableMFASecretDirectory(directory *os.File) bool {
	if directory == nil {
		return false
	}
	var metadata unix.Stat_t
	if err := unix.Fstat(int(directory.Fd()), &metadata); err != nil || int(metadata.Uid) != os.Geteuid() {
		return false
	}
	info, err := directory.Stat()
	return err == nil && info.Mode().Perm()&0o200 != 0
}

func (store *FileMFASecretStore) Create(ctx context.Context, enrollmentID uuid.UUID, base32Secret string) (string, error) {
	name, reference, valid := mfaSecretIdentity(enrollmentID)
	if !valid || !validMFASeed(base32Secret) {
		return "", ErrSecretReferenceInvalid
	}
	value, err := store.do(ctx, func() (any, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		store.mutex.RLock()
		defer store.mutex.RUnlock()
		if store.root == nil || !trustedDirectoryDescriptor(store.root) {
			return nil, ErrSecretReferenceInvalid
		}
		fd, openErr := unix.Openat(int(store.root.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o400)
		if openErr != nil {
			return nil, ErrSecretReferenceInvalid
		}
		remove := true
		defer func() {
			_ = unix.Close(fd)
			if remove {
				_ = unix.Unlinkat(int(store.root.Fd()), name, 0)
				_ = unix.Fsync(int(store.root.Fd()))
			}
		}()
		if err := unix.Fchmod(fd, 0o400); err != nil {
			return nil, ErrSecretReferenceInvalid
		}
		if err := writeMFASecretFully(fd, []byte(base32Secret), unix.Write); err != nil {
			return nil, err
		}
		if err := unix.Fsync(fd); err != nil {
			return nil, ErrSecretReferenceInvalid
		}
		if err := unix.Close(fd); err != nil {
			fd = -1
			return nil, ErrSecretReferenceInvalid
		}
		fd = -1
		if err := unix.Fsync(int(store.root.Fd())); err != nil {
			return nil, ErrSecretReferenceInvalid
		}
		remove = false
		return reference, nil
	})
	if err != nil {
		return "", err
	}
	result, ok := value.(string)
	if !ok {
		return "", ErrSecretReferenceInvalid
	}
	return result, nil
}

func (store *FileMFASecretStore) Resolve(ctx context.Context, reference string) ([]byte, error) {
	name, ok := parseMFASecretReference(reference)
	if !ok {
		return nil, ErrSecretReferenceInvalid
	}
	value, err := store.do(ctx, func() (any, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		store.mutex.RLock()
		defer store.mutex.RUnlock()
		if store.root == nil || !trustedDirectoryDescriptor(store.root) {
			return nil, ErrSecretReferenceInvalid
		}
		fd, openErr := unix.Openat(int(store.root.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			return nil, ErrSecretReferenceInvalid
		}
		secret := os.NewFile(uintptr(fd), name)
		if secret == nil {
			_ = unix.Close(fd)
			return nil, ErrSecretReferenceInvalid
		}
		defer secret.Close()
		info, statErr := secret.Stat()
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 || !trustedDescriptorOwner(secret) || info.Size() != 32 {
			return nil, ErrSecretReferenceInvalid
		}
		contents, readErr := io.ReadAll(io.LimitReader(secret, 33))
		if readErr != nil || !validMFASeed(string(contents)) {
			return nil, ErrSecretReferenceInvalid
		}
		return contents, nil
	})
	if err != nil {
		return nil, err
	}
	contents, ok := value.([]byte)
	if !ok {
		return nil, ErrSecretReferenceInvalid
	}
	return contents, nil
}

func (store *FileMFASecretStore) Delete(ctx context.Context, reference string) error {
	name, ok := parseMFASecretReference(reference)
	if !ok {
		return ErrSecretReferenceInvalid
	}
	_, err := store.do(ctx, func() (any, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		store.mutex.RLock()
		defer store.mutex.RUnlock()
		if store.root == nil || !trustedDirectoryDescriptor(store.root) {
			return nil, ErrSecretReferenceInvalid
		}
		unlinkErr := unix.Unlinkat(int(store.root.Fd()), name, 0)
		if unlinkErr != nil && !errors.Is(unlinkErr, unix.ENOENT) {
			return nil, ErrSecretReferenceInvalid
		}
		if unlinkErr == nil {
			if err := unix.Fsync(int(store.root.Fd())); err != nil {
				return nil, ErrSecretReferenceInvalid
			}
		}
		return nil, nil
	})
	return err
}

func (store *FileMFASecretStore) ListOrphanCandidates(ctx context.Context, olderThan time.Time, limit int) ([]string, error) {
	if olderThan.IsZero() || olderThan.After(time.Now().UTC().Add(-mfaSecretOrphanGrace)) || limit < 1 || limit > mfaSecretMaximumBatch {
		return nil, ErrSecretReferenceInvalid
	}
	value, err := store.do(ctx, func() (any, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		store.mutex.RLock()
		defer store.mutex.RUnlock()
		if store.root == nil || !trustedDirectoryDescriptor(store.root) {
			return nil, ErrSecretReferenceInvalid
		}
		store.scanMu.Lock()
		defer store.scanMu.Unlock()
		candidates := make([]string, 0, limit)
		scanned := 0
		for scanned < mfaSecretMaximumScan && len(candidates) < limit {
			if store.scanRoot == nil {
				fd, openErr := unix.Openat(int(store.root.Fd()), ".", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
				if openErr != nil {
					return nil, ErrSecretReferenceInvalid
				}
				store.scanRoot = os.NewFile(uintptr(fd), "mfa-enrollment-secret-scan")
				if store.scanRoot == nil {
					_ = unix.Close(fd)
					return nil, ErrSecretReferenceInvalid
				}
			}
			entries, readErr := store.scanRoot.ReadDir(min(32, mfaSecretMaximumScan-scanned))
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				return nil, ErrSecretReferenceInvalid
			}
			scanned += len(entries)
			for _, entry := range entries {
				name := entry.Name()
				if _, ok := parseMFASecretReference(mfaSecretReferencePrefix + name); !ok {
					continue
				}
				fileFD, openErr := unix.Openat(int(store.root.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
				if openErr != nil {
					return nil, ErrSecretReferenceInvalid
				}
				file := os.NewFile(uintptr(fileFD), name)
				if file == nil {
					_ = unix.Close(fileFD)
					return nil, ErrSecretReferenceInvalid
				}
				info, statErr := file.Stat()
				trusted := statErr == nil && info.Mode().IsRegular() && info.Mode().Perm() == 0o400 && trustedDescriptorOwner(file)
				_ = file.Close()
				if !trusted {
					return nil, ErrSecretReferenceInvalid
				}
				if info.ModTime().UTC().Before(olderThan.UTC()) {
					if len(candidates) < limit {
						candidates = append(candidates, mfaSecretReferencePrefix+name)
					}
				}
			}
			if errors.Is(readErr, io.EOF) || len(entries) == 0 {
				_ = store.scanRoot.Close()
				store.scanRoot = nil
				break
			}
		}
		sort.Strings(candidates)
		return candidates, nil
	})
	if err != nil {
		return nil, err
	}
	candidates, ok := value.([]string)
	if !ok {
		return nil, ErrSecretReferenceInvalid
	}
	return candidates, nil
}

func (store *FileMFASecretStore) Close() error {
	if store == nil {
		return nil
	}
	store.shutdown.Do(func() {
		done := store.executor.Close()
		go func() {
			<-done
			store.mutex.Lock()
			defer store.mutex.Unlock()
			store.scanMu.Lock()
			if store.scanRoot != nil {
				_ = store.scanRoot.Close()
				store.scanRoot = nil
			}
			store.scanMu.Unlock()
			if store.root != nil {
				_ = store.root.Close()
				store.root = nil
			}
		}()
	})
	return nil
}

func (store *FileMFASecretStore) do(ctx context.Context, operation mfaSecretIOOperation) (any, error) {
	if store == nil || store.executor == nil || ctx == nil {
		return nil, ErrSecretReferenceInvalid
	}
	return store.executor.Do(ctx, operation)
}

func mfaSecretIdentity(id uuid.UUID) (string, string, bool) {
	if id == uuid.Nil || id.Version() != 7 {
		return "", "", false
	}
	name := "mfa-" + id.String() + ".totp"
	return name, mfaSecretReferencePrefix + name, true
}

func parseMFASecretReference(reference string) (string, bool) {
	if reference == "" || reference != strings.TrimSpace(reference) {
		return "", false
	}
	name, found := strings.CutPrefix(reference, mfaSecretReferencePrefix)
	if !found || name == "" || name != filepath.Base(name) || strings.ContainsAny(name, `/\`) {
		return "", false
	}
	const prefix, suffix = "mfa-", ".totp"
	encodedID, found := strings.CutPrefix(name, prefix)
	if !found {
		return "", false
	}
	encodedID, found = strings.CutSuffix(encodedID, suffix)
	if !found {
		return "", false
	}
	id, err := uuid.Parse(encodedID)
	if err != nil || id.Version() != 7 || encodedID != id.String() {
		return "", false
	}
	wantName, _, valid := mfaSecretIdentity(id)
	return name, valid && name == wantName
}

func validMFASeed(secret string) bool {
	if len(secret) != 32 || secret != strings.ToUpper(secret) || strings.Contains(secret, "=") {
		return false
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	return err == nil && len(decoded) == 20 && base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(decoded) == secret
}

type mfaSecretWrite func(fd int, value []byte) (int, error)

func writeMFASecretFully(fd int, value []byte, write mfaSecretWrite) error {
	if fd < 0 || len(value) == 0 || write == nil {
		return ErrSecretReferenceInvalid
	}
	for len(value) > 0 {
		written, err := write(fd, value)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || written <= 0 || written > len(value) {
			return ErrSecretReferenceInvalid
		}
		value = value[written:]
	}
	return nil
}

type mfaSecretIOOperation func() (any, error)

type mfaSecretIORequest struct {
	ctx       context.Context
	operation mfaSecretIOOperation
	result    chan mfaSecretIOResult
}

type mfaSecretIOResult struct {
	value any
	err   error
}

type mfaSecretIOExecutor struct {
	requests chan mfaSecretIORequest
	stop     chan struct{}
	done     chan struct{}
	closed   atomic.Bool
	once     sync.Once
	workers  sync.WaitGroup
}

func newMFASecretIOExecutor(workerCount, queueSize int) *mfaSecretIOExecutor {
	if workerCount < 1 || queueSize < 1 {
		return nil
	}
	executor := &mfaSecretIOExecutor{
		requests: make(chan mfaSecretIORequest, queueSize),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	executor.workers.Add(workerCount)
	for range workerCount {
		go executor.run()
	}
	return executor
}

func (executor *mfaSecretIOExecutor) Do(ctx context.Context, operation mfaSecretIOOperation) (any, error) {
	if executor == nil || ctx == nil || operation == nil || executor.closed.Load() {
		return nil, ErrSecretReferenceInvalid
	}
	request := mfaSecretIORequest{ctx: ctx, operation: operation, result: make(chan mfaSecretIOResult, 1)}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-executor.stop:
		return nil, ErrSecretReferenceInvalid
	case executor.requests <- request:
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-executor.stop:
		return nil, ErrSecretReferenceInvalid
	case result := <-request.result:
		return result.value, result.err
	}
}

func (executor *mfaSecretIOExecutor) Close() <-chan struct{} {
	if executor == nil {
		done := make(chan struct{})
		close(done)
		return done
	}
	executor.closed.Store(true)
	executor.once.Do(func() {
		close(executor.stop)
		go func() {
			executor.workers.Wait()
			close(executor.done)
		}()
	})
	return executor.done
}

func (executor *mfaSecretIOExecutor) run() {
	defer executor.workers.Done()
	for {
		select {
		case <-executor.stop:
			executor.rejectPending()
			return
		case request := <-executor.requests:
			if executor.closed.Load() {
				request.result <- mfaSecretIOResult{err: ErrSecretReferenceInvalid}
				executor.rejectPending()
				return
			}
			if err := request.ctx.Err(); err != nil {
				request.result <- mfaSecretIOResult{err: err}
				continue
			}
			value, err := request.operation()
			request.result <- mfaSecretIOResult{value: value, err: err}
		}
	}
}

func (executor *mfaSecretIOExecutor) rejectPending() {
	for {
		select {
		case request := <-executor.requests:
			request.result <- mfaSecretIOResult{err: ErrSecretReferenceInvalid}
		default:
			return
		}
	}
}
