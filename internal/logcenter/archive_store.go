package logcenter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"path"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"xminds-release-platform/internal/platform/objectstore"
)

// ArchiveStore is the narrow port exposed to the export worker. It does not
// expose final-object deletion or arbitrary multipart lifecycle operations.
type ArchiveStore interface {
	PutImmutable(context.Context, string, []byte, string) error
}

type immutableArchiveStore struct {
	final   objectstore.Store
	staging objectstore.Store
	lock    func(context.Context, string, func(context.Context) error) error
}

func NewArchiveStore(backend objectstore.Store) (ArchiveStore, error) {
	if backend == nil {
		return nil, ErrExportWorkerConfiguration
	}
	return &immutableArchiveStore{final: backend, staging: backend}, nil
}

func NewArchiveStoreWithStaging(final, staging objectstore.Store) (ArchiveStore, error) {
	if final == nil || staging == nil {
		return nil, ErrExportWorkerConfiguration
	}
	return &immutableArchiveStore{final: final, staging: staging}, nil
}

func NewArchiveStoreWithPostgresLock(final, staging objectstore.Store, pool *pgxpool.Pool) (ArchiveStore, error) {
	if final == nil || staging == nil || pool == nil {
		return nil, ErrExportWorkerConfiguration
	}
	return &immutableArchiveStore{
		final: final, staging: staging,
		lock: func(ctx context.Context, key string, operation func(context.Context) error) error {
			conn, err := pool.Acquire(ctx)
			if err != nil {
				return err
			}
			defer conn.Release()
			lockKey := "log-export-archive\x00" + key
			if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended($1, 0))`, lockKey); err != nil {
				return err
			}
			defer func() {
				_, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, lockKey)
			}()
			return operation(ctx)
		},
	}, nil
}

func (store *immutableArchiveStore) PutImmutable(ctx context.Context, key string, data []byte, contentType string) error {
	if store == nil || store.final == nil || store.staging == nil {
		return ErrExportWorkerConfiguration
	}
	_, digest, cleanup, err := stageExportObject(ctx, store.staging, key, data, contentType)
	if err != nil {
		return err
	}
	defer cleanup()
	if store.lock != nil {
		return store.lock(ctx, key, func(checkCtx context.Context) error {
			info, statErr := store.final.Stat(checkCtx, key)
			if statErr == nil {
				if info.Size != int64(len(data)) {
					return objectstore.ErrSizeMismatch
				}
				if verifyErr := verifyExportObject(checkCtx, store.final, key, int64(len(data)), digest); verifyErr != nil {
					return verifyErr
				}
				return nil
			}
			if !errors.Is(statErr, objectstore.ErrObjectNotFound) {
				return statErr
			}
			return publishExportObject(checkCtx, store.final, key, data, digest, contentType)
		})
	}
	return publishExportObject(ctx, store.final, key, data, digest, contentType)
}

func putExportObject(ctx context.Context, store objectstore.Store, key string, data []byte, contentType string) error {
	return putExportObjectAcross(ctx, store, store, key, data, contentType)
}

func putExportObjectAcross(ctx context.Context, staging, final objectstore.Store, key string, data []byte, contentType string) error {
	if staging == nil || final == nil {
		return ErrExportWorkerConfiguration
	}
	_, digest, cleanup, err := stageExportObject(ctx, staging, key, data, contentType)
	if err != nil {
		return err
	}
	defer cleanup()
	return publishExportObject(ctx, final, key, data, digest, contentType)
}

func stageExportObject(ctx context.Context, staging objectstore.Store, key string, data []byte, contentType string) (string, string, func(), error) {
	stagingKey := path.Join("uploads", "log-exports", ".staging", uuid.NewString(), path.Base(key))
	uploadID, err := staging.BeginMultipart(ctx, stagingKey, contentType)
	if err != nil {
		return "", "", func() {}, err
	}
	completed := false
	cleanup := func() {
		if !completed {
			_ = staging.AbortMultipart(ctx, stagingKey, uploadID)
			return
		}
		_ = staging.Delete(ctx, stagingKey)
	}
	digest := ManifestDigest(data)
	part, err := staging.PutPart(ctx, stagingKey, uploadID, 1, bytes.NewReader(data), int64(len(data)), digest)
	if err != nil {
		cleanup()
		return "", "", func() {}, err
	}
	if err := staging.CompleteMultipart(ctx, stagingKey, uploadID, []objectstore.Part{part}); err != nil {
		cleanup()
		return "", "", func() {}, err
	}
	completed = true
	if err := verifyExportObject(ctx, staging, stagingKey, int64(len(data)), digest); err != nil {
		cleanup()
		return "", "", func() {}, err
	}
	return stagingKey, digest, cleanup, nil
}

func publishExportObject(ctx context.Context, final objectstore.Store, key string, data []byte, digest, contentType string) error {
	if existing, err := final.Stat(ctx, key); err == nil {
		if existing.Size != int64(len(data)) {
			return objectstore.ErrSizeMismatch
		}
		return verifyExportObject(ctx, final, key, int64(len(data)), digest)
	} else if !errors.Is(err, objectstore.ErrObjectNotFound) {
		return err
	}
	finalUploadID, err := final.BeginMultipart(ctx, key, contentType)
	if err != nil {
		if errors.Is(err, objectstore.ErrObjectAlreadyExists) {
			return verifyExportObject(ctx, final, key, int64(len(data)), digest)
		}
		return err
	}
	finalPart, err := final.PutPart(ctx, key, finalUploadID, 1, bytes.NewReader(data), int64(len(data)), digest)
	if err != nil {
		_ = final.AbortMultipart(ctx, key, finalUploadID)
		return err
	}
	if err := final.CompleteMultipart(ctx, key, finalUploadID, []objectstore.Part{finalPart}); err != nil {
		_ = final.AbortMultipart(ctx, key, finalUploadID)
		if errors.Is(err, objectstore.ErrObjectAlreadyExists) {
			return verifyExportObject(ctx, final, key, int64(len(data)), digest)
		}
		return err
	}
	if err := verifyExportObject(ctx, final, key, int64(len(data)), digest); err != nil {
		return err
	}
	return nil
}

func verifyExportObject(ctx context.Context, store objectstore.Store, key string, expectedSize int64, expectedDigest string) error {
	info, err := store.Stat(ctx, key)
	if err != nil {
		return err
	}
	if info.Size != expectedSize {
		return objectstore.ErrSizeMismatch
	}
	reader, _, err := store.Open(ctx, key, 0, -1)
	if err != nil {
		return err
	}
	hash := sha256.New()
	readSize, copyErr := io.Copy(hash, io.LimitReader(reader, expectedSize+1))
	closeErr := reader.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if readSize != expectedSize || hex.EncodeToString(hash.Sum(nil)) != expectedDigest {
		return objectstore.ErrDigestMismatch
	}
	return nil
}
