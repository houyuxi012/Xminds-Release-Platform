package iam

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"xminds-release-platform/internal/breachcorpus"
)

func TestReleaseBreachCheckerLoadsVerifiedManifestAndRejectsServiceOwnedRelease(t *testing.T) {
	t.Parallel()

	const (
		sha1Password   = "Known-SHA1-Breached-Password!"
		sha1Digest     = "844EBA1A7A7BEBADAAD266BF2DB5B9429D441818"
		sha256Password = "Known-SHA256-Breached-Password!"
		sha256Digest   = "6CE0335CCB0E6AD50693A435D4BF0659DB2D69D53D84631661774AC86E8F5722"
	)
	releaseDirectory := buildIAMCorpusRelease(t, sha1Digest+"\n"+sha256Digest+"\n")
	serviceUID := uint32(os.Geteuid() + 1)
	if serviceUID == 0 {
		serviceUID = 1
	}
	checker, err := newReleaseBreachChecker(releaseDirectory, serviceUID)
	if err != nil {
		t.Fatalf("newReleaseBreachChecker() error = %v", err)
	}
	for _, password := range []string{sha1Password, sha256Password} {
		breached, checkErr := checker.IsBreached(context.Background(), password)
		if checkErr != nil || !breached {
			t.Fatalf("IsBreached(%q) = %v, %v", password, breached, checkErr)
		}
	}
	breached, err := checker.IsBreached(context.Background(), "A-Different-Safe-Password!")
	if err != nil || breached {
		t.Fatalf("IsBreached(safe) = %v, %v", breached, err)
	}
	if _, err := NewReleaseBreachChecker(releaseDirectory); !errors.Is(err, ErrBreachCorpusInvalid) {
		t.Fatalf("NewReleaseBreachChecker(service-owned release) error = %v", err)
	}
}

func TestReleaseBreachCheckerRejectsTamperedManifest(t *testing.T) {
	t.Parallel()
	releaseDirectory := buildIAMCorpusRelease(t, "844EBA1A7A7BEBADAAD266BF2DB5B9429D441818\n")
	manifestPath := filepath.Join(releaseDirectory, breachcorpus.ManifestFileName)
	if err := os.Chmod(releaseDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(manifestPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(manifestPath, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(releaseDirectory, 0o500); err != nil {
		t.Fatal(err)
	}
	serviceUID := uint32(os.Geteuid() + 1)
	if serviceUID == 0 {
		serviceUID = 1
	}
	if _, err := newReleaseBreachChecker(releaseDirectory, serviceUID); !errors.Is(err, ErrBreachCorpusInvalid) {
		t.Fatalf("newReleaseBreachChecker(tampered manifest) error = %v", err)
	}
}

func buildIAMCorpusRelease(t *testing.T, corpus string) string {
	t.Helper()
	outputRoot := t.TempDir()
	if err := os.Chmod(outputRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(t.TempDir(), "approved-source.txt")
	if err := os.WriteFile(sourcePath, []byte(corpus), 0o400); err != nil {
		t.Fatal(err)
	}
	sourceDigest := sha256.Sum256([]byte(corpus))
	result, err := breachcorpus.Build(context.Background(), breachcorpus.BuildRequest{
		SchemaVersion: breachcorpus.ManifestSchemaVersion,
		CorpusVersion: "2026.08.30.1",
		Sources: []breachcorpus.SourceRequest{{
			ID: "approved-source", Version: "2026-08", ExpectedSHA256: hex.EncodeToString(sourceDigest[:]), LicenseReviewRef: "LEGAL-2026-001",
		}},
	}, []breachcorpus.Input{{SourceID: "approved-source", Path: sourcePath}}, outputRoot,
		breachcorpus.Generator{Name: "xminds-breach-corpus", Version: "test", Commit: "0123456789ab"}, time.Now)
	if err != nil {
		t.Fatalf("build IAM breach corpus release: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(result.ReleaseDirectory, 0o700)
		_ = os.Chmod(filepath.Join(result.ReleaseDirectory, breachcorpus.ManifestFileName), 0o600)
		_ = os.Chmod(filepath.Join(result.ReleaseDirectory, breachcorpus.CorpusFileName), 0o600)
	})
	return result.ReleaseDirectory
}

func TestDevelopmentBreachCheckerRejectsEmbeddedCommonPassword(t *testing.T) {
	t.Parallel()
	checker, err := NewDevelopmentBreachChecker()
	if err != nil {
		t.Fatal(err)
	}
	breached, err := checker.IsBreached(context.Background(), "password")
	if err != nil || !breached {
		t.Fatalf("IsBreached(password) = %v, %v", breached, err)
	}
}

func TestTOTPVerifierResolvesReferencedSecretAndRejectsWrongWindow(t *testing.T) {
	t.Parallel()

	now := time.Unix(59, 0).UTC()
	resolver := staticSecretResolver{value: []byte("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")}
	verifier, err := NewTOTPVerifier(TOTPConfig{Digits: 8, Period: 30 * time.Second, Skew: 0}, &resolver, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewTOTPVerifier() error = %v", err)
	}
	assertion, err := verifier.Verify(context.Background(), "secret://iam/admin-totp", "94287082")
	if err != nil || assertion.Counter != 1 {
		t.Fatalf("Verify(valid) = %+v, %v", assertion, err)
	}
	if resolver.reference != "secret://iam/admin-totp" {
		t.Fatalf("resolved reference = %q", resolver.reference)
	}
	if _, err := verifier.Verify(context.Background(), "secret://iam/admin-totp", "07081804"); !errors.Is(err, ErrMFAProofInvalid) {
		t.Fatalf("Verify(future proof) error = %v", err)
	}
}

func TestDirectorySecretResolverConfinesReferencesToConfiguredRoot(t *testing.T) {
	t.Parallel()

	directory := resolvedTempDir(t)
	if err := os.WriteFile(filepath.Join(directory, "admin-totp"), []byte("JBSWY3DPEHPK3PXP\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewDirectorySecretResolver(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	secret, err := resolver.Resolve(context.Background(), "secret://iam/admin-totp")
	if err != nil || string(secret) != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("Resolve(valid) = %q, %v", secret, err)
	}
	for _, reference := range []string{"secret://iam/../escape", "file:///etc/passwd", "secret://other/admin-totp"} {
		if _, err := resolver.Resolve(context.Background(), reference); !errors.Is(err, ErrSecretReferenceInvalid) {
			t.Fatalf("Resolve(%q) error = %v", reference, err)
		}
	}
}

func TestDirectorySecretResolverReturnsWhenContextExpiresDuringBlockedFileOpen(t *testing.T) {
	root := resolvedTempDir(t)
	fifo := filepath.Join(root, "blocked-secret")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewDirectorySecretResolver(root)
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, resolveErr := resolver.Resolve(ctx, "secret://iam/blocked-secret")
		result <- resolveErr
	}()

	var resolveErr error
	returnedBeforeRelease := false
	select {
	case resolveErr = <-result:
		returnedBeforeRelease = true
	case <-time.After(400 * time.Millisecond):
	}
	writer, openErr := unix.Open(fifo, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if openErr != nil {
		t.Fatalf("release blocked FIFO open: %v", openErr)
	}
	_ = unix.Close(writer)
	if !returnedBeforeRelease {
		resolveErr = <-result
		t.Fatalf("Resolve() ignored context deadline until blocking file open was externally released: %v", resolveErr)
	}
	if !errors.Is(resolveErr, context.DeadlineExceeded) {
		t.Fatalf("Resolve() error=%v, want context deadline exceeded", resolveErr)
	}
}

func TestDirectorySecretResolverCloseReturnsWhileFIFOOpenIsPermanentlyBlocked(t *testing.T) {
	root := resolvedTempDir(t)
	fifo := filepath.Join(root, "permanently-blocked-secret")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewDirectorySecretResolver(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	resolveResult := make(chan error, 1)
	go func() {
		_, resolveErr := resolver.Resolve(ctx, "secret://iam/permanently-blocked-secret")
		resolveResult <- resolveErr
	}()
	if resolveErr := <-resolveResult; !errors.Is(resolveErr, context.DeadlineExceeded) {
		t.Fatalf("Resolve() error=%v, want context deadline exceeded", resolveErr)
	}
	closeResult := make(chan error, 1)
	go func() { closeResult <- resolver.Close() }()
	select {
	case closeErr := <-closeResult:
		if closeErr != nil {
			t.Fatalf("Close() error=%v", closeErr)
		}
	case <-time.After(150 * time.Millisecond):
		writer, openErr := unix.Open(fifo, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if openErr == nil {
			_ = unix.Close(writer)
		}
		<-closeResult
		t.Fatal("Close() waited for a worker blocked in an uncancelable FIFO open")
	}
	resolver.mutex.RLock()
	rootStillPinned := resolver.root != nil
	resolver.mutex.RUnlock()
	if !rootStillPinned {
		t.Fatal("Close() closed the pinned root while a Secret worker was still using it")
	}
	writer, err := unix.Open(fifo, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("release blocked FIFO open: %v", err)
	}
	_ = unix.Close(writer)
	deadline := time.Now().Add(time.Second)
	for {
		resolver.mutex.RLock()
		rootClosed := resolver.root == nil
		resolver.mutex.RUnlock()
		if rootClosed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pinned root was not closed after the blocked Secret worker exited")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestSecretIOExecutorCloseFailsQueuedAndNewRequestsWithoutWaitingForWorkers(t *testing.T) {
	const (
		workers = 2
		queued  = 8
	)
	started := make(chan struct{}, workers)
	release := make(chan struct{})
	var reads atomic.Int32
	executor := newSecretIOExecutor(workers, queued, func(string) ([]byte, error) {
		reads.Add(1)
		started <- struct{}{}
		<-release
		return []byte("snapshot"), nil
	})

	results := make(chan error, workers+queued)
	for range workers + queued {
		go func() {
			_, err := executor.Resolve(context.Background(), "blocked-secret")
			results <- err
		}()
	}
	for range workers {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("Secret worker did not begin its blocking read")
		}
	}

	workersDone := executor.Close()
	if _, err := executor.Resolve(context.Background(), "after-close"); !errors.Is(err, ErrSecretReferenceInvalid) {
		t.Fatalf("Resolve(after Close) error=%v, want secret reference invalid", err)
	}
	for range workers + queued {
		select {
		case err := <-results:
			if !errors.Is(err, ErrSecretReferenceInvalid) {
				t.Fatalf("Resolve(during Close) error=%v, want secret reference invalid", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Close did not release a Secret caller")
		}
	}
	select {
	case <-workersDone:
		t.Fatal("executor reported shutdown while fixed workers remained blocked")
	default:
	}
	if got := reads.Load(); got != workers {
		t.Fatalf("Secret reads after Close=%d, want only %d reads already in progress", got, workers)
	}
	close(release)
	select {
	case <-workersDone:
	case <-time.After(time.Second):
		t.Fatal("executor did not report shutdown after its fixed workers exited")
	}
}

func TestSecretIOExecutorResolveCloseRaceIsFailClosed(t *testing.T) {
	for range 100 {
		executor := newSecretIOExecutor(1, 1, func(string) ([]byte, error) {
			return []byte("snapshot"), nil
		})
		start := make(chan struct{})
		result := make(chan error, 1)
		go func() {
			<-start
			_, err := executor.Resolve(context.Background(), "racing-secret")
			result <- err
		}()
		close(start)
		workersDone := executor.Close()
		select {
		case err := <-result:
			if err != nil && !errors.Is(err, ErrSecretReferenceInvalid) {
				t.Fatalf("Resolve racing with Close error=%v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Resolve racing with Close did not return")
		}
		select {
		case <-workersDone:
		case <-time.After(time.Second):
			t.Fatal("executor did not finish after Resolve/Close race")
		}
	}
}

func TestSecretIOExecutorCapsBlockedWorkersAndReturnsCanceledCallers(t *testing.T) {
	const (
		workers   = 2
		callers   = 12
		queueSize = 2
	)
	release := make(chan struct{})
	var active, maximum atomic.Int32
	executor := newSecretIOExecutor(workers, queueSize, func(string) ([]byte, error) {
		current := active.Add(1)
		for {
			observed := maximum.Load()
			if current <= observed || maximum.CompareAndSwap(observed, current) {
				break
			}
		}
		<-release
		active.Add(-1)
		return []byte("snapshot"), nil
	})

	results := make(chan error, callers)
	for range callers {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			_, err := executor.Resolve(ctx, "secret://iam/blocked")
			results <- err
		}()
	}
	for range callers {
		select {
		case err := <-results:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Resolve() error=%v, want context deadline exceeded", err)
			}
		case <-time.After(time.Second):
			t.Fatal("canceled Secret caller did not return")
		}
	}
	if got := maximum.Load(); got != workers {
		t.Fatalf("maximum blocked Secret readers=%d, want fixed worker cap %d", got, workers)
	}
	close(release)
	executor.Close()
}

func TestDirectorySecretResolverRejectsSymlinkRoot(t *testing.T) {
	t.Parallel()
	realRoot := resolvedTempDir(t)
	linkedRoot := filepath.Join(resolvedTempDir(t), "iam-secrets")
	if err := os.Symlink(realRoot, linkedRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDirectorySecretResolver(linkedRoot); !errors.Is(err, ErrSecretReferenceInvalid) {
		t.Fatalf("NewDirectorySecretResolver(symlink root) error = %v", err)
	}
}

func TestDirectorySecretResolverRejectsSymlinkAncestor(t *testing.T) {
	realParent := resolvedTempDir(t)
	realRoot := filepath.Join(realParent, "iam-secrets")
	if err := os.Mkdir(realRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(resolvedTempDir(t), "linked-parent")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDirectorySecretResolver(filepath.Join(linkedParent, "iam-secrets")); !errors.Is(err, ErrSecretReferenceInvalid) {
		t.Fatalf("NewDirectorySecretResolver(symlink ancestor) error = %v", err)
	}
}

func TestDirectorySecretResolverRejectsGroupOrWorldWritableRoot(t *testing.T) {
	for name, mode := range map[string]os.FileMode{"group writable": 0o770, "world writable": 0o702} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(resolvedTempDir(t), "iam-secrets")
			if err := os.Mkdir(root, mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(root, mode); err != nil {
				t.Fatal(err)
			}
			if _, err := NewDirectorySecretResolver(root); !errors.Is(err, ErrSecretReferenceInvalid) {
				t.Fatalf("NewDirectorySecretResolver(%s root) error = %v", name, err)
			}
		})
	}
}

func TestDirectorySecretResolverRejectsRootPermissionChangeAfterConstruction(t *testing.T) {
	root := filepath.Join(resolvedTempDir(t), "iam-secrets")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "admin-totp"), []byte("PINNED-SECRET"), 0o400); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewDirectorySecretResolver(root)
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	if err := os.Chmod(root, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(context.Background(), "secret://iam/admin-totp"); !errors.Is(err, ErrSecretReferenceInvalid) {
		t.Fatalf("Resolve(group-writable pinned root) error = %v", err)
	}
}

func TestDirectorySecretResolverRejectsUntrustedOwnerWhenSupported(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing fixtures to an untrusted owner requires root")
	}
	t.Run("root", func(t *testing.T) {
		root := filepath.Join(resolvedTempDir(t), "iam-secrets")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(root, 65534, -1); err != nil {
			t.Fatal(err)
		}
		if _, err := NewDirectorySecretResolver(root); !errors.Is(err, ErrSecretReferenceInvalid) {
			t.Fatalf("NewDirectorySecretResolver(untrusted root owner) error = %v", err)
		}
	})
	t.Run("secret", func(t *testing.T) {
		root := filepath.Join(resolvedTempDir(t), "iam-secrets")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		secretPath := filepath.Join(root, "admin-totp")
		if err := os.WriteFile(secretPath, []byte("UNTRUSTED-SECRET"), 0o400); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(secretPath, 65534, -1); err != nil {
			t.Fatal(err)
		}
		resolver, err := NewDirectorySecretResolver(root)
		if err != nil {
			t.Fatal(err)
		}
		defer resolver.Close()
		if _, err := resolver.Resolve(context.Background(), "secret://iam/admin-totp"); !errors.Is(err, ErrSecretReferenceInvalid) {
			t.Fatalf("Resolve(untrusted secret owner) error = %v", err)
		}
	})
}

func TestDirectorySecretResolverPinsOpenedRootAcrossPathReplacement(t *testing.T) {
	parent := resolvedTempDir(t)
	root := filepath.Join(parent, "iam-secrets")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "admin-totp"), []byte("ORIGINAL-SECRET"), 0o400); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewDirectorySecretResolver(root)
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	pinned := filepath.Join(parent, "pinned-root")
	if err := os.Rename(root, pinned); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "admin-totp"), []byte("REPLACEMENT-SECRET"), 0o400); err != nil {
		t.Fatal(err)
	}
	secret, err := resolver.Resolve(context.Background(), "secret://iam/admin-totp")
	if err != nil || string(secret) != "ORIGINAL-SECRET" {
		t.Fatalf("Resolve(after root replacement) = %q, %v", secret, err)
	}
}

func TestDirectorySecretResolverReadsCompleteAtomicFileRotationSnapshots(t *testing.T) {
	root := resolvedTempDir(t)
	secretPath := filepath.Join(root, "rotating-secret")
	if err := os.WriteFile(secretPath, []byte("OLD-COMPLETE-SNAPSHOT"), 0o400); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewDirectorySecretResolver(root)
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	oldSnapshot, err := resolver.Resolve(context.Background(), "secret://iam/rotating-secret")
	if err != nil || string(oldSnapshot) != "OLD-COMPLETE-SNAPSHOT" {
		t.Fatalf("Resolve(old snapshot)=%q, %v", oldSnapshot, err)
	}
	replacement := filepath.Join(root, "replacement")
	if err := os.WriteFile(replacement, []byte("NEW-COMPLETE-SNAPSHOT"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, secretPath); err != nil {
		t.Fatal(err)
	}
	newSnapshot, err := resolver.Resolve(context.Background(), "secret://iam/rotating-secret")
	if err != nil || string(newSnapshot) != "NEW-COMPLETE-SNAPSHOT" {
		t.Fatalf("Resolve(new snapshot)=%q, %v", newSnapshot, err)
	}
}

func resolvedTempDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

type staticSecretResolver struct {
	reference string
	value     []byte
}

func (resolver *staticSecretResolver) Resolve(_ context.Context, reference string) ([]byte, error) {
	resolver.reference = reference
	return append([]byte(nil), resolver.value...), nil
}
