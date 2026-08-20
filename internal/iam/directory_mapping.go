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

// revalidateDirectoryUserMapping serializes only colliding canonical mapping
// keys and re-checks current principals while those transaction locks are held.
// It deliberately does not treat email as an identity merge key.
func revalidateDirectoryUserMapping(ctx context.Context, tx pgx.Tx, sourceID uuid.UUID, externalSubject, username, email string) (directoryMappingConflicts, error) {
	if err := lockPrincipalMappingKeys(ctx, tx, username, email); err != nil {
		return directoryMappingConflicts{}, err
	}
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
	if tx == nil {
		return ErrIAMConfiguration
	}
	canonicalUsername := strings.ToLower(strings.TrimSpace(username))
	canonicalEmail := strings.ToLower(strings.TrimSpace(email))
	if canonicalUsername == "" {
		return ErrIAMConfiguration
	}
	keys := []string{"username:" + canonicalUsername}
	if canonicalEmail != "" {
		keys = append(keys, "email:"+canonicalEmail)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, directoryMappingLockNamespace+key); err != nil {
			return fmt.Errorf("lock principal mapping key: %w", err)
		}
	}
	return nil
}
