package logcenter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/google/uuid"
)

type SpoolReplayer struct {
	Spool          *EncryptedSpool
	Consume        func(context.Context, []byte) error
	ApplicationLog ApplicationRequestWriter
}

func (replayer *SpoolReplayer) RunOnce(ctx context.Context) error {
	if replayer == nil || replayer.Spool == nil || (replayer.Consume == nil && replayer.ApplicationLog == nil) {
		return ErrRepositoryUnavailable
	}
	lock, err := os.OpenFile(filepath.Join(replayer.Spool.dir, ".quota.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	entries, err := os.ReadDir(replayer.Spool.dir)
	if err != nil {
		if unlockErr := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); unlockErr != nil {
			return fmt.Errorf("read spool dir: %w (unlock: %v)", err, unlockErr)
		}
		return err
	}
	processing := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() || len(entry.Name()) < len("intent-") || entry.Name()[:len("intent-")] != "intent-" {
			continue
		}
		target := filepath.Join(replayer.Spool.dir, ".processing-"+uuid.New().String())
		if err := os.Rename(filepath.Join(replayer.Spool.dir, entry.Name()), target); err != nil {
			if unlockErr := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); unlockErr != nil {
				return fmt.Errorf("claim spool intent %s: %w (unlock: %v)", entry.Name(), err, unlockErr)
			}
			return fmt.Errorf("claim spool intent %s: %w", entry.Name(), err)
		}
		processing = append(processing, target)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
		return fmt.Errorf("unlock spool: %w", err)
	}
	for _, path := range processing {
		item, readErr := replayer.Spool.readEnvelope(path)
		if readErr != nil {
			if quarantineErr := quarantine(path); quarantineErr != nil {
				return fmt.Errorf("quarantine unreadable intent: %w (original: %v)", quarantineErr, readErr)
			}
			continue
		}
		if replayer.ApplicationLog != nil {
			var record middlewareIntent
			if jsonErr := json.Unmarshal(item, &record); jsonErr != nil || record.Version != 1 || record.EventID == "" {
				if quarantineErr := quarantine(path); quarantineErr != nil {
					return fmt.Errorf("quarantine malformed intent: %w", quarantineErr)
				}
				continue
			}
			if err := replayer.appendIntent(ctx, record); err != nil {
				if errors.Is(err, ErrEventIdentityConflict) {
					if quarantineErr := quarantine(path); quarantineErr != nil {
						return fmt.Errorf("quarantine conflicting intent: %w", quarantineErr)
					}
					continue
				}
				if restoreErr := restoreIntent(path, replayer.Spool.dir, record.EventID); restoreErr != nil {
					return fmt.Errorf("replay intent: %w (restore: %v)", err, restoreErr)
				}
				return err
			}
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("remove replayed intent: %w", err)
			}
			continue
		}
		if err := replayer.Consume(ctx, item); err != nil {
			if restoreErr := os.Rename(path, filepath.Join(replayer.Spool.dir, "intent-"+uuid.New().String())); restoreErr != nil {
				return fmt.Errorf("consume intent: %w (restore: %v)", err, restoreErr)
			}
			return err
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove replayed intent: %w", err)
		}
	}
	return nil
}

func (replayer *SpoolReplayer) appendIntent(ctx context.Context, record middlewareIntent) error {
	status := (*int)(nil)
	reason := record.Reason
	result := ResultDenied
	decision := "deny"
	completionUnknown := record.State == "pending" || record.State == "claimed" || record.State == "unknown"
	trusted := record.SnapshotTrusted && !completionUnknown
	if completionUnknown {
		reason = "REQUEST_COMPLETION_UNKNOWN"
		result = ResultFailed
		status = nil
	}
	if trusted {
		decision = record.Decision
		result = ResultSuccess
		if decision != "allow" {
			result = ResultDenied
		}
		status = nil
	}
	clientID, clientVersion := record.ClientAppID, record.ClientAppVersion
	if !trusted {
		clientID, clientVersion = "unknown", "unknown"
		record.CustomerID, record.CustomerName, record.TenantID = "", "", ""
		record.AuthorizationName, record.LicenseID, record.LicenseStatus = "", "", ""
		record.LicenseExpiresAt, record.ValidatedAt, record.ValidatorIssuer, record.ContextDigest = nil, nil, "", nil
		decision = "deny"
		if !completionUnknown {
			result = ResultDenied
		}
	}
	event, err := NewApplicationRequestWithIdentity(ApplicationRequestEvent{Metadata: EventMetadata{RequestID: record.RequestID, SchemaVersion: 1}, EventID: record.EventID, OccurredAt: record.StartedAt, ProductID: record.ProductID, ClientAppID: clientID, ClientAppVersion: clientVersion, HTTPMethod: record.Method, RouteTemplate: record.Route, HTTPStatus: status, DurationMS: 0, SnapshotTrusted: trusted, CustomerID: record.CustomerID, CustomerName: record.CustomerName, TenantID: record.TenantID, AuthorizationName: record.AuthorizationName, LicenseID: record.LicenseID, LicenseExpiresAt: record.LicenseExpiresAt, LicenseStatus: record.LicenseStatus, Decision: decision, Result: result, ReasonCode: reason, ValidatedAt: record.ValidatedAt, ValidatorIssuer: record.ValidatorIssuer, ContextDigest: record.ContextDigest}, record.EventID)
	if err != nil {
		return err
	}
	return replayer.ApplicationLog.AppendApplicationRequest(ctx, event)
}

func restoreIntent(path, dir, eventID string) error {
	return os.Rename(path, filepath.Join(dir, "intent-"+eventID))
}
