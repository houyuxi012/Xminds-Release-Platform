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
	keys := []string{"username:" + strings.ToLower(username)}
	if email != "" {
		keys = append(keys, "email:"+strings.ToLower(email))
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, directoryMappingLockNamespace+key); err != nil {
			return directoryMappingConflicts{}, fmt.Errorf("lock directory mapping key: %w", err)
		}
	}
	var conflicts directoryMappingConflicts
	if err := tx.QueryRow(ctx, `
SELECT EXISTS (
           SELECT 1 FROM user_principals principal
           WHERE $4<>'' AND lower(principal.email)=lower($4)
             AND NOT (principal.identity_source_id=$1 AND principal.external_subject=$2)
       ),
       EXISTS (
           SELECT 1 FROM user_principals principal
           WHERE lower(principal.username)=lower($3)
             AND NOT (principal.identity_source_id=$1 AND principal.external_subject=$2)
       )`, sourceID, externalSubject, username, email).Scan(&conflicts.ambiguousEmail, &conflicts.usernameConflict); err != nil {
		return directoryMappingConflicts{}, fmt.Errorf("revalidate directory mapping: %w", err)
	}
	return conflicts, nil
}
