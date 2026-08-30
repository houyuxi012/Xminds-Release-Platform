package iam

import (
	"context"
	"encoding/base32"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestFileMFASecretStoreCreatesCanonicalOwnerOnlySecret(t *testing.T) {
	root := mfaSecretTestRoot(t)
	store, err := NewFileMFASecretStore(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	id := mustMFAEnrollmentID(t)
	secret := testMFASeed()

	reference, err := store.Create(context.Background(), id, secret)
	if err != nil {
		t.Fatal(err)
	}
	wantReference := "secret://iam-mfa/mfa-" + id.String() + ".totp"
	if reference != wantReference {
		t.Fatalf("reference=%q, want %q", reference, wantReference)
	}
	path := filepath.Join(root, "mfa-"+id.String()+".totp")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != secret {
		t.Fatal("persisted MFA secret differs from generated seed")
	}
	resolved, err := store.Resolve(context.Background(), reference)
	if err != nil || string(resolved) != secret {
		t.Fatalf("resolved MFA secret differs from stored seed error=%v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o400 {
		t.Fatalf("MFA secret permissions=%#o, want 0400", info.Mode().Perm())
	}
	if _, err := store.Create(context.Background(), id, secret); !errors.Is(err, ErrSecretReferenceInvalid) {
		t.Fatalf("duplicate Create error=%v", err)
	}
	if err := store.Delete(context.Background(), "secret://iam-mfa/../mfa-"+id.String()+".totp"); !errors.Is(err, ErrSecretReferenceInvalid) {
		t.Fatalf("traversal Delete error=%v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("invalid delete changed canonical secret: %v", err)
	}
	if err := store.Delete(context.Background(), reference); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted secret stat error=%v", err)
	}
	if err := store.Delete(context.Background(), reference); err != nil {
		t.Fatalf("idempotent Delete error=%v", err)
	}
}

func TestFileMFASecretStoreRejectsUnsafeRootsTargetsAndInputs(t *testing.T) {
	root := mfaSecretTestRoot(t)
	linkedRoot := filepath.Join(t.TempDir(), "linked-root")
	if err := os.Symlink(root, linkedRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileMFASecretStore(linkedRoot); !errors.Is(err, ErrSecretReferenceInvalid) {
		t.Fatalf("symlink root error=%v", err)
	}
	linkedParent := filepath.Join(t.TempDir(), "linked-parent")
	if err := os.Symlink(filepath.Dir(root), linkedParent); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileMFASecretStore(filepath.Join(linkedParent, filepath.Base(root))); !errors.Is(err, ErrSecretReferenceInvalid) {
		t.Fatalf("symlink ancestor error=%v", err)
	}
	unsafeRoot := mfaSecretTestRoot(t)
	if err := os.Chmod(unsafeRoot, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileMFASecretStore(unsafeRoot); !errors.Is(err, ErrSecretReferenceInvalid) {
		t.Fatalf("group/other writable root error=%v", err)
	}

	store, err := NewFileMFASecretStore(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	id := mustMFAEnrollmentID(t)
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("do-not-overwrite"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "mfa-"+id.String()+".totp")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(context.Background(), id, testMFASeed()); !errors.Is(err, ErrSecretReferenceInvalid) {
		t.Fatalf("symlink final target Create error=%v", err)
	}
	contents, err := os.ReadFile(target)
	if err != nil || string(contents) != "do-not-overwrite" {
		t.Fatalf("symlink target changed contents=%q error=%v", contents, err)
	}
	if _, err := store.Create(context.Background(), uuid.New(), testMFASeed()); !errors.Is(err, ErrSecretReferenceInvalid) {
		t.Fatalf("UUIDv4 Create error=%v", err)
	}
	if _, err := store.Create(context.Background(), mustMFAEnrollmentID(t), "not-base32"); !errors.Is(err, ErrSecretReferenceInvalid) {
		t.Fatalf("invalid seed Create error=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Create(cancelled, mustMFAEnrollmentID(t), testMFASeed()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Create error=%v", err)
	}
}

func TestFileMFASecretStoreListsOnlyOldCanonicalOrphanCandidates(t *testing.T) {
	root := mfaSecretTestRoot(t)
	store, err := NewFileMFASecretStore(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	oldReferencedID := mustMFAEnrollmentID(t)
	oldOrphanID := mustMFAEnrollmentID(t)
	recentOrphanID := mustMFAEnrollmentID(t)
	oldReferenced, err := store.Create(context.Background(), oldReferencedID, testMFASeed())
	if err != nil {
		t.Fatal(err)
	}
	oldOrphan, err := store.Create(context.Background(), oldOrphanID, testMFASeed())
	if err != nil {
		t.Fatal(err)
	}
	recentOrphan, err := store.Create(context.Background(), recentOrphanID, testMFASeed())
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	for _, id := range []uuid.UUID{oldReferencedID, oldOrphanID} {
		if err := os.Chtimes(filepath.Join(root, "mfa-"+id.String()+".totp"), old, old); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "unrelated.txt"), []byte("keep"), 0o400); err != nil {
		t.Fatal(err)
	}

	candidates, err := store.ListOrphanCandidates(context.Background(), time.Now().Add(-time.Hour), 128)
	if err != nil {
		t.Fatal(err)
	}
	wantCandidates := []string{oldReferenced, oldOrphan}
	sort.Strings(wantCandidates)
	if len(candidates) != 2 || candidates[0] != wantCandidates[0] || candidates[1] != wantCandidates[1] {
		t.Fatalf("candidates=%v, want two old canonical references in filename order", candidates)
	}
	for _, reference := range []string{oldReferenced, oldOrphan, recentOrphan, "secret://iam-mfa/unrelated.txt"} {
		name := strings.TrimPrefix(reference, "secret://iam-mfa/")
		_, statErr := os.Stat(filepath.Join(root, name))
		if statErr != nil {
			t.Errorf("candidate listing mutated %s: %v", name, statErr)
		}
	}
	if _, err := store.ListOrphanCandidates(context.Background(), time.Now(), 129); !errors.Is(err, ErrSecretReferenceInvalid) {
		t.Fatalf("oversized candidate listing error=%v", err)
	}
	if _, err := store.ListOrphanCandidates(context.Background(), time.Now(), 0); !errors.Is(err, ErrSecretReferenceInvalid) {
		t.Fatalf("zero-sized candidate listing error=%v", err)
	}
}

func TestFileMFASecretStoreCandidateScanAdvancesPastFullBatchAndWraps(t *testing.T) {
	root := mfaSecretTestRoot(t)
	store, err := NewFileMFASecretStore(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	old := time.Now().Add(-2 * time.Hour)
	want := map[string]struct{}{}
	for range 130 {
		id := mustMFAEnrollmentID(t)
		reference, createErr := store.Create(context.Background(), id, testMFASeed())
		if createErr != nil {
			t.Fatal(createErr)
		}
		want[reference] = struct{}{}
		if err := os.Chtimes(filepath.Join(root, strings.TrimPrefix(reference, mfaSecretReferencePrefix)), old, old); err != nil {
			t.Fatal(err)
		}
	}
	found := map[string]struct{}{}
	for range 4 {
		candidates, listErr := store.ListOrphanCandidates(context.Background(), time.Now().Add(-time.Hour), 128)
		if listErr != nil {
			t.Fatal(listErr)
		}
		if len(candidates) > 128 {
			t.Fatalf("single scan returned %d candidates", len(candidates))
		}
		for _, reference := range candidates {
			found[reference] = struct{}{}
		}
		if len(found) == len(want) {
			break
		}
	}
	if len(found) != len(want) {
		t.Fatalf("forward scan found %d/%d candidates", len(found), len(want))
	}
}

func TestRoutingSecretResolverSeparatesLegacyAndEnrollmentNamespaces(t *testing.T) {
	legacy := &staticSecretResolver{value: []byte("legacy")}
	mfa := &staticSecretResolver{value: []byte("mfa")}
	router := RoutingSecretResolver{IAM: legacy, MFA: mfa}

	value, err := router.Resolve(context.Background(), "secret://iam/legacy-admin.totp")
	if err != nil || string(value) != "legacy" || legacy.reference != "secret://iam/legacy-admin.totp" || mfa.reference != "" {
		t.Fatalf("legacy routing value=%q error=%v legacy=%q mfa=%q", value, err, legacy.reference, mfa.reference)
	}
	legacy.reference = ""
	value, err = router.Resolve(context.Background(), "secret://iam-mfa/mfa-0198f8dd-5f0c-7c32-9076-96ee511ad08a.totp")
	if err != nil || string(value) != "mfa" || mfa.reference == "" || legacy.reference != "" {
		t.Fatalf("MFA routing value=%q error=%v legacy=%q mfa=%q", value, err, legacy.reference, mfa.reference)
	}
	for _, reference := range []string{
		"SECRET://iam/legacy-admin.totp",
		"secret://iam-mfa/../legacy-admin.totp",
		"secret://iam-mfa/secret://iam/legacy-admin.totp",
		"secret://unknown/value",
	} {
		legacy.reference, mfa.reference = "", ""
		if _, err := router.Resolve(context.Background(), reference); !errors.Is(err, ErrSecretReferenceInvalid) || legacy.reference != "" || mfa.reference != "" {
			t.Errorf("unsafe reference %q error=%v legacy=%q mfa=%q", reference, err, legacy.reference, mfa.reference)
		}
	}
}

func TestWriteMFASecretFullyHandlesShortWritesAndZeroProgress(t *testing.T) {
	remaining := []byte("0123456789")
	written := 0
	err := writeMFASecretFully(7, remaining, func(fd int, value []byte) (int, error) {
		if fd != 7 {
			t.Fatalf("fd=%d", fd)
		}
		n := min(3, len(value))
		written += n
		return n, nil
	})
	if err != nil || written != len(remaining) {
		t.Fatalf("short write result bytes=%d error=%v", written, err)
	}
	if err := writeMFASecretFully(7, remaining, func(int, []byte) (int, error) { return 0, nil }); !errors.Is(err, ErrSecretReferenceInvalid) {
		t.Fatalf("zero-progress write error=%v", err)
	}
}

func TestMFASecretIOExecutorIsBoundedAndCloseDoesNotWaitForBlockedIO(t *testing.T) {
	block := make(chan struct{})
	started := make(chan struct{}, 1)
	executor := newMFASecretIOExecutor(1, 1)
	firstDone := make(chan error, 1)
	go func() {
		_, err := executor.Do(context.Background(), func() (any, error) {
			started <- struct{}{}
			<-block
			return nil, nil
		})
		firstDone <- err
	}()
	<-started
	secondDone := make(chan error, 1)
	var secondExecuted atomic.Bool
	go func() {
		_, err := executor.Do(context.Background(), func() (any, error) {
			secondExecuted.Store(true)
			return nil, nil
		})
		secondDone <- err
	}()
	deadline := time.Now().Add(time.Second)
	for len(executor.requests) != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := executor.Do(ctx, func() (any, error) { return nil, nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("full queue Do error=%v", err)
	}
	startedClose := time.Now()
	done := executor.Close()
	if time.Since(startedClose) > 100*time.Millisecond {
		t.Fatal("Close waited for blocked file I/O")
	}
	select {
	case <-done:
		t.Fatal("executor stopped before blocked operation was released")
	default:
	}
	close(block)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("executor did not stop after blocked operation completed")
	}
	<-firstDone
	<-secondDone
	if secondExecuted.Load() {
		t.Fatal("queued file operation executed after Close")
	}
}

func TestFileMFASecretStoreCloseRejectsNewWork(t *testing.T) {
	store, err := NewFileMFASecretStore(mfaSecretTestRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(context.Background(), mustMFAEnrollmentID(t), testMFASeed()); !errors.Is(err, ErrSecretReferenceInvalid) {
		t.Fatalf("Create after Close error=%v", err)
	}
}

func TestProbeMFASecretStoreLeavesNoSensitiveArtifact(t *testing.T) {
	t.Parallel()
	root := mfaSecretTestRoot(t)
	store, err := NewFileMFASecretStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := ProbeMFASecretStore(context.Background(), store); err != nil {
		t.Fatalf("ProbeMFASecretStore() error=%v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("startup probe left secret artifacts: %+v", entries)
	}
}

func mustMFAEnrollmentID(t *testing.T) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func testMFASeed() string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("0123456789abcdefghij"))
}

func mfaSecretTestRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}
