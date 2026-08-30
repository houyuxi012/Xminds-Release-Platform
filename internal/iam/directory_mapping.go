package iam

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const directoryMappingLockNamespace = "xminds-release-platform:iam:directory-mapping:"

type directoryMappingConflicts struct {
	ambiguousEmail   bool
	usernameConflict bool
}

type principalMappingCandidate struct {
	username string
	email    string
}

// directoryUserMappingConflictsUnderLock re-checks current principals after
// the caller has locked the complete batch mapping key set. Email remains a
// conflict signal, not an identity merge key.
func directoryUserMappingConflictsUnderLock(ctx context.Context, tx pgx.Tx, sourceID uuid.UUID, externalSubject, username, email string) (directoryMappingConflicts, error) {
	var conflicts directoryMappingConflicts
	if err := tx.QueryRow(ctx, `
SELECT EXISTS (
		   SELECT 1 FROM principal_mapping_registry mapping
		   WHERE $4<>'' AND mapping.mapping_kind='email' AND mapping.canonical_value=lower($4)
		     AND NOT (mapping.identity_source_id=$1 AND mapping.external_subject=$2)
       ),
       EXISTS (
		   SELECT 1 FROM principal_mapping_registry mapping
		   WHERE mapping.mapping_kind='username' AND mapping.canonical_value=lower($3)
		     AND NOT (mapping.identity_source_id=$1 AND mapping.external_subject=$2)
       )`, sourceID, externalSubject, username, email).Scan(&conflicts.ambiguousEmail, &conflicts.usernameConflict); err != nil {
		return directoryMappingConflicts{}, fmt.Errorf("revalidate directory mapping: %w", err)
	}
	return conflicts, nil
}

// lockPrincipalMappingKeys is the single pre-write lock authority for every
// production path that can create or change a canonical username/email. The
// trigger remains the final registry authority, but never becomes the first
// lock acquisition after PostgreSQL has already reserved a unique-index key.
func lockPrincipalMappingKeys(ctx context.Context, tx pgx.Tx, username, email string) error {
	return lockPrincipalMappingCandidates(ctx, tx, []principalMappingCandidate{{username: username, email: email}})
}

// lockPrincipalMappingCandidates acquires every canonical mapping lock for a
// write batch in one global order. Both local single-user writes and directory
// batch writes use this authority, preventing lock-order inversions across
// sources while retaining the registry trigger as the final database guard.
func lockPrincipalMappingCandidates(ctx context.Context, tx pgx.Tx, candidates []principalMappingCandidate) error {
	if tx == nil {
		return ErrIAMConfiguration
	}
	uniqueKeys := make(map[string]struct{}, len(candidates)*2)
	for _, candidate := range candidates {
		canonicalUsername := strings.ToLower(strings.TrimSpace(candidate.username))
		canonicalEmail := strings.ToLower(strings.TrimSpace(candidate.email))
		if canonicalUsername == "" {
			return ErrIAMConfiguration
		}
		uniqueKeys["username:"+canonicalUsername] = struct{}{}
		if canonicalEmail != "" {
			uniqueKeys["email:"+canonicalEmail] = struct{}{}
		}
	}
	keys := make([]string, 0, len(uniqueKeys))
	for key := range uniqueKeys {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, directoryMappingLockNamespace+key); err != nil {
			return fmt.Errorf("lock principal mapping key: %w", err)
		}
	}
	return nil
}
