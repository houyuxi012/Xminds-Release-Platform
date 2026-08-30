package integration_test

import (
	"context"
	"encoding/base64"
	"errors"
	"io/fs"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/iam"
	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/migrations"
)

// Mutation caught: retaining the legacy two-column primary key would collapse
// independently owned directory and platform authority edges.
func TestOrganizationMembershipMigrationV17UpgradeRollbackAndReapply(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	adminPool, pool, databaseName := isolatedIntegrationDatabase(t, ctx, databaseURL, "organization_membership_migration_")
	t.Cleanup(func() {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), `DROP DATABASE `+databaseName)
		adminPool.Close()
	})
	if err := database.ApplyMigrations(ctx, pool, directoryMigrationSubset(t, 17)); err != nil {
		t.Fatalf("apply migrations 1..17: %v", err)
	}
	now := time.Date(2026, 8, 21, 16, 0, 0, 0, time.UTC)
	organizationID, userID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO user_principals (id,username,display_name,user_kind,status,version,created_at,updated_at) VALUES ($1,'migration.member','Migration Member','local','active',1,$2,$2)`, userID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO organization_units (id,name,source_owned,status,version,created_at,updated_at) VALUES ($1,'Migration Organization',FALSE,'active',1,$2,$2)`, organizationID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO organization_memberships (organization_id,user_id,source_owned,created_at) VALUES ($1,$2,TRUE,$3)`, organizationID, userID, now); err != nil {
		t.Fatal(err)
	}
	checksums := migrationChecksums(t, ctx, pool, 17)
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatalf("upgrade v17 to v18: %v", err)
	}
	for version, checksum := range checksums {
		var current string
		if err := pool.QueryRow(ctx, `SELECT checksum FROM schema_migrations WHERE version=$1`, version).Scan(&current); err != nil || current != checksum {
			t.Fatalf("migration %d checksum changed: before=%s after=%s error=%v", version, checksum, current, err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO organization_memberships (organization_id,user_id,source_owned,status,version,created_at,updated_at) VALUES ($1,$2,FALSE,'active',1,$3,$3)`, organizationID, userID, now); err != nil {
		t.Fatalf("dual ownership insert: %v", err)
	}
	tombstoneOrganizationID, tombstoneUserID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO user_principals (id,username,display_name,user_kind,status,version,created_at,updated_at) VALUES ($1,'migration.tombstone','Migration Tombstone','local','active',1,$2,$2)`, tombstoneUserID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO organization_units (id,name,source_owned,status,version,created_at,updated_at) VALUES ($1,'Migration Tombstone Organization',FALSE,'active',1,$2,$2)`, tombstoneOrganizationID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO organization_memberships (organization_id,user_id,source_owned,status,version,created_at,updated_at) VALUES ($1,$2,FALSE,'removed',2,$3,$4)`, tombstoneOrganizationID, tombstoneUserID, now, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var primaryKeyColumns string
	if err := pool.QueryRow(ctx, `SELECT string_agg(attribute.attname,',' ORDER BY key.ordinality) FROM pg_constraint constraint_record CROSS JOIN LATERAL unnest(constraint_record.conkey) WITH ORDINALITY AS key(attnum,ordinality) JOIN pg_attribute attribute ON attribute.attrelid=constraint_record.conrelid AND attribute.attnum=key.attnum WHERE constraint_record.conrelid='organization_memberships'::regclass AND constraint_record.contype='p'`).Scan(&primaryKeyColumns); err != nil || primaryKeyColumns != "organization_id,user_id,source_owned" {
		t.Fatalf("membership primary key=%q error=%v", primaryKeyColumns, err)
	}
	var governanceColumns, governanceIndexes int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='organization_memberships' AND column_name IN ('status','version','updated_at') AND is_nullable='NO'`).Scan(&governanceColumns); err != nil || governanceColumns != 3 {
		t.Fatalf("membership governance columns=%d error=%v", governanceColumns, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_indexes WHERE schemaname='public' AND indexname IN ('organization_memberships_active_organization_idx','organization_memberships_active_user_idx','organization_units_parent_created_idx')`).Scan(&governanceIndexes); err != nil || governanceIndexes != 3 {
		t.Fatalf("membership governance indexes=%d error=%v", governanceIndexes, err)
	}
	for _, operation := range []string{"identity.organization_membership.create", "identity.organization_membership.delete"} {
		challengeID, err := uuid.NewV7()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO iam_reauthentication_challenges (id,actor_subject,actor_kind,actor_binding_version,actor_binding_digest,created_token_digest,operation,status,created_at,challenge_expires_at,created_request_id,version) VALUES ($1,'migration-admin','human',1,repeat('a',64),repeat('b',64),$2,'pending',$3,$4,$5,1)`, challengeID, operation, now, now.Add(time.Minute), uuid.New()); err != nil {
			t.Fatalf("operation %s rejected after up: %v", operation, err)
		}
	}
	downSQL, err := fs.ReadFile(migrations.FS, "000018_organization_membership_governance.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, string(downSQL)); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("apply v18 down: %v", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version=18`); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var sourceOwned bool
	if err := pool.QueryRow(ctx, `SELECT source_owned FROM organization_memberships WHERE organization_id=$1 AND user_id=$2`, organizationID, userID).Scan(&sourceOwned); err != nil || !sourceOwned {
		t.Fatalf("down did not preserve authoritative source edge: source_owned=%v error=%v", sourceOwned, err)
	}
	var tombstoneRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM organization_memberships WHERE organization_id=$1 AND user_id=$2`, tombstoneOrganizationID, tombstoneUserID).Scan(&tombstoneRows); err != nil || tombstoneRows != 0 {
		t.Fatalf("down retained tombstone rows=%d error=%v", tombstoneRows, err)
	}
	var operationRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM iam_reauthentication_challenges WHERE operation LIKE 'identity.organization_membership.%'`).Scan(&operationRows); err != nil || operationRows != 0 {
		t.Fatalf("new challenge rows after down=%d error=%v", operationRows, err)
	}
	rejectedChallengeID, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO iam_reauthentication_challenges (id,actor_subject,actor_kind,actor_binding_version,actor_binding_digest,created_token_digest,operation,status,created_at,challenge_expires_at,created_request_id,version) VALUES ($1,'migration-admin','human',1,repeat('a',64),repeat('b',64),'identity.organization_membership.create','pending',$2,$3,$4,1)`, rejectedChallengeID, now, now.Add(time.Minute), uuid.New()); err == nil {
		t.Fatal("membership reauthentication operation accepted after v18 down")
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='organization_memberships' AND column_name IN ('status','version','updated_at')`).Scan(&governanceColumns); err != nil || governanceColumns != 0 {
		t.Fatalf("membership governance columns after down=%d error=%v", governanceColumns, err)
	}
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatalf("reapply v18: %v", err)
	}
	requirePostgreSQLMajorVersion(t, ctx, pool)
}

// Mutation caught: ordering a dual-owned edge only by (created_at,user_id)
// drops the second ownership fact at a page boundary.
func TestOrganizationMembershipPostgresPaginationUsesOwnershipAsFinalTieBreaker(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}
	resetOrganizationMembershipIntegrationTables(t, ctx, pool)

	now := time.Date(2026, 8, 21, 19, 0, 0, 0, time.UTC)
	organizationID, userID := uuid.New(), uuid.New()
	seedOrganizationMembershipPrincipalAndOrganization(t, ctx, pool, organizationID, userID, now)
	if _, err := pool.Exec(ctx, `
INSERT INTO organization_memberships (organization_id,user_id,source_owned,status,version,created_at,updated_at)
VALUES ($1,$2,TRUE,'active',1,$3,$3),($1,$2,FALSE,'active',1,$3,$3)`, organizationID, userID, now); err != nil {
		t.Fatal(err)
	}

	repository := iam.NewPostgresRepository(pool)
	first, err := repository.ListOrganizationMemberships(ctx, organizationID, iam.Page{Limit: 1})
	if err != nil || len(first.Items) != 1 || !first.Items[0].SourceOwned || first.NextCursor == "" {
		t.Fatalf("first membership page=%+v error=%v", first, err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(first.NextCursor)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(payload), "\n")
	if len(parts) != 3 || parts[2] != "source" {
		t.Fatalf("membership cursor payload=%q", payload)
	}
	beforeTime, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		t.Fatal(err)
	}
	beforeUserID, err := uuid.Parse(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	beforeSourceOwned := true
	second, err := repository.ListOrganizationMemberships(ctx, organizationID, iam.Page{
		Limit: 1, BeforeTime: beforeTime, BeforeID: beforeUserID, BeforeSourceOwned: &beforeSourceOwned,
	})
	if err != nil || len(second.Items) != 1 || second.Items[0].SourceOwned || second.NextCursor != "" {
		t.Fatalf("second membership page=%+v error=%v", second, err)
	}
}

// Mutation caught: omitting either the composite edge lock or organization
// generation check permits two identical platform grants and two audits.
func TestOrganizationMembershipPostgresConcurrentCreateCommitsOnce(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}
	resetOrganizationMembershipIntegrationTables(t, ctx, pool)

	now := time.Date(2026, 8, 21, 19, 15, 0, 0, time.UTC)
	organizationID, userID, emergencyID := uuid.New(), uuid.New(), uuid.New()
	seedOrganizationMembershipPrincipalAndOrganization(t, ctx, pool, organizationID, userID, now)
	seedOrganizationMembershipEmergencyAdministrator(t, ctx, pool, emergencyID, now)
	requestIDs := make([]string, 2)
	if _, err := pool.Exec(ctx, `
INSERT INTO local_sessions (
    id,token_digest,subject_id,authentication_method,mfa_level,authenticated_at,last_used_at,
    absolute_expires_at,idle_expires_at,version
) VALUES ($1,$2,$3,'local_password',0,$4,$4,$5,$5,1)`, uuid.New(), integrationSHA256Hex("membership-concurrent-session"), userID, now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	repository := iam.NewPostgresRepository(pool)
	realAuditor := audit.NewService(audit.NewPostgresRepository(pool))
	actor := organizationMembershipIntegrationActor(emergencyID, now)
	reauthentication := newOrganizationMembershipReauthenticationService(t, repository, realAuditor, now)
	proofs := make([]iam.HighRiskProof, 2)
	requests := make([]iam.RequestContext, 2)
	for index := range proofs {
		proofs[index], requests[index] = completeIntegrationReauthenticationProof(t, ctx, reauthentication, actor, actor, iam.ReauthenticationOperationOrganizationMembershipCreate)
		requestIDs[index] = requests[index].RequestID
	}
	rendezvous := newProductionProofRendezvous(reauthentication, 2)
	service := newOrganizationMembershipIntegrationService(t, repository, realAuditor, rendezvous, now)

	start := make(chan struct{})
	results := make(chan error, 2)
	var group sync.WaitGroup
	for index := 0; index < 2; index++ {
		index := index
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			_, createErr := service.CreateOrganizationMembership(ctx, actor, organizationID, iam.CreateOrganizationMembershipCommand{
				OrganizationVersion: 1, UserID: userID, UserVersion: 1, Reason: "approved concurrent supplemental access",
			}, proofs[index], requests[index])
			results <- createErr
		}()
	}
	close(start)
	rendezvous.releaseWhenAllConsumed(t, ctx)
	group.Wait()
	close(results)
	successes, conflicts := 0, 0
	for result := range results {
		switch {
		case result == nil:
			successes++
		case errors.Is(result, iam.ErrIAMConflict):
			conflicts++
		default:
			t.Fatalf("concurrent membership create error=%v", result)
		}
	}
	var activeEdges, organizationVersion, auditEvents, activeSessions int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM organization_memberships WHERE organization_id=$1 AND user_id=$2 AND source_owned=FALSE AND status='active'`, organizationID, userID).Scan(&activeEdges); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT version FROM organization_units WHERE id=$1`, organizationID).Scan(&organizationVersion); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE request_id=ANY($1::uuid[]) AND action='identity.organization_membership.create'`, requestIDs).Scan(&auditEvents); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM local_sessions WHERE subject_id=$1 AND revoked_at IS NULL`, userID).Scan(&activeSessions); err != nil {
		t.Fatal(err)
	}
	if successes != 1 || conflicts != 1 || activeEdges != 1 || organizationVersion != 2 || auditEvents != 1 || activeSessions != 0 {
		t.Fatalf("concurrent create success=%d conflict=%d edges=%d org_version=%d audits=%d sessions=%d", successes, conflicts, activeEdges, organizationVersion, auditEvents, activeSessions)
	}
	for _, proof := range proofs {
		requireIntegrationProofConsumedAndUnreplayable(t, ctx, pool, reauthentication, actor, iam.ReauthenticationOperationOrganizationMembershipCreate, proof)
	}
}

// Mutation caught: hard-delete/reinsert semantics or a missing optimistic edge
// generation allows two stale deletes to both claim success.
func TestOrganizationMembershipPostgresConcurrentDeleteAndCreateDeleteRaceCommitOnce(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}

	runFixture := func(t *testing.T) (*iam.PostgresRepository, iam.AuditAppender, identity.Principal, uuid.UUID, uuid.UUID, time.Time) {
		t.Helper()
		resetOrganizationMembershipIntegrationTables(t, ctx, pool)
		now := time.Date(2026, 8, 21, 19, 20, 0, 0, time.UTC)
		organizationID, userID, emergencyID := uuid.New(), uuid.New(), uuid.New()
		seedOrganizationMembershipPrincipalAndOrganization(t, ctx, pool, organizationID, userID, now)
		seedOrganizationMembershipEmergencyAdministrator(t, ctx, pool, emergencyID, now)
		if _, err := pool.Exec(ctx, `
INSERT INTO organization_memberships (organization_id,user_id,source_owned,status,version,created_at,updated_at)
VALUES ($1,$2,FALSE,'active',1,$3,$3)`, organizationID, userID, now); err != nil {
			t.Fatal(err)
		}
		repository := iam.NewPostgresRepository(pool)
		realAuditor := audit.NewService(audit.NewPostgresRepository(pool))
		return repository, realAuditor, organizationMembershipIntegrationActor(emergencyID, now), organizationID, userID, now
	}

	t.Run("double delete", func(t *testing.T) {
		repository, realAuditor, actor, organizationID, userID, now := runFixture(t)
		reauthentication := newOrganizationMembershipReauthenticationService(t, repository, realAuditor, now)
		proofs := make([]iam.HighRiskProof, 2)
		requests := make([]iam.RequestContext, 2)
		requestIDs := make([]string, 2)
		for index := range proofs {
			proofs[index], requests[index] = completeIntegrationReauthenticationProof(t, ctx, reauthentication, actor, actor, iam.ReauthenticationOperationOrganizationMembershipDelete)
			requestIDs[index] = requests[index].RequestID
		}
		rendezvous := newProductionProofRendezvous(reauthentication, 2)
		service := newOrganizationMembershipIntegrationService(t, repository, realAuditor, rendezvous, now)
		start := make(chan struct{})
		results := make(chan error, 2)
		for index := 0; index < 2; index++ {
			index := index
			go func() {
				<-start
				results <- service.DeleteOrganizationMembership(ctx, actor, organizationID, userID, iam.DeleteOrganizationMembershipCommand{
					OrganizationVersion: 1, UserVersion: 1, MembershipVersion: 1, Reason: "remove stale concurrent supplemental access",
				}, proofs[index], requests[index])
			}()
		}
		close(start)
		rendezvous.releaseWhenAllConsumed(t, ctx)
		successes, rejected := 0, 0
		for index := 0; index < 2; index++ {
			switch result := <-results; {
			case result == nil:
				successes++
			case errors.Is(result, iam.ErrIAMConflict), errors.Is(result, iam.ErrOrganizationMembershipNotFound):
				rejected++
			default:
				t.Fatalf("concurrent membership delete error=%v", result)
			}
		}
		var status string
		var membershipVersion, organizationVersion, auditEvents int
		if err := pool.QueryRow(ctx, `SELECT status,version FROM organization_memberships WHERE organization_id=$1 AND user_id=$2 AND source_owned=FALSE`, organizationID, userID).Scan(&status, &membershipVersion); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT version FROM organization_units WHERE id=$1`, organizationID).Scan(&organizationVersion); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE request_id=ANY($1::uuid[]) AND action='identity.organization_membership.delete'`, requestIDs).Scan(&auditEvents); err != nil {
			t.Fatal(err)
		}
		if successes != 1 || rejected != 1 || status != "removed" || membershipVersion != 2 || organizationVersion != 2 || auditEvents != 1 {
			t.Fatalf("double delete success=%d rejected=%d status=%s membership_version=%d org_version=%d audits=%d", successes, rejected, status, membershipVersion, organizationVersion, auditEvents)
		}
		for _, proof := range proofs {
			requireIntegrationProofConsumedAndUnreplayable(t, ctx, pool, reauthentication, actor, iam.ReauthenticationOperationOrganizationMembershipDelete, proof)
		}
	})

	t.Run("create delete against one organization generation", func(t *testing.T) {
		repository, realAuditor, actor, organizationID, deleteUserID, now := runFixture(t)
		createUserID := uuid.New()
		seedOrganizationMembershipPrincipal(t, ctx, pool, createUserID, now)
		reauthentication := newOrganizationMembershipReauthenticationService(t, repository, realAuditor, now)
		createProof, createRequest := completeIntegrationReauthenticationProof(t, ctx, reauthentication, actor, actor, iam.ReauthenticationOperationOrganizationMembershipCreate)
		deleteProof, deleteRequest := completeIntegrationReauthenticationProof(t, ctx, reauthentication, actor, actor, iam.ReauthenticationOperationOrganizationMembershipDelete)
		requestIDs := []string{createRequest.RequestID, deleteRequest.RequestID}
		rendezvous := newProductionProofRendezvous(reauthentication, 2)
		service := newOrganizationMembershipIntegrationService(t, repository, realAuditor, rendezvous, now)
		start := make(chan struct{})
		results := make(chan error, 2)
		go func() {
			<-start
			_, createErr := service.CreateOrganizationMembership(ctx, actor, organizationID, iam.CreateOrganizationMembershipCommand{
				OrganizationVersion: 1, UserID: createUserID, UserVersion: 1, Reason: "create concurrent supplemental access",
			}, createProof, createRequest)
			results <- createErr
		}()
		go func() {
			<-start
			results <- service.DeleteOrganizationMembership(ctx, actor, organizationID, deleteUserID, iam.DeleteOrganizationMembershipCommand{
				OrganizationVersion: 1, UserVersion: 1, MembershipVersion: 1, Reason: "remove concurrent supplemental access",
			}, deleteProof, deleteRequest)
		}()
		close(start)
		rendezvous.releaseWhenAllConsumed(t, ctx)
		successes, rejected := 0, 0
		for index := 0; index < 2; index++ {
			switch result := <-results; {
			case result == nil:
				successes++
			case errors.Is(result, iam.ErrIAMConflict), errors.Is(result, iam.ErrOrganizationMembershipNotFound):
				rejected++
			default:
				t.Fatalf("create/delete membership race error=%v", result)
			}
		}
		var createEdges, deleteMembershipVersion, organizationVersion, auditEvents int
		var deleteStatus string
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM organization_memberships WHERE organization_id=$1 AND user_id=$2 AND source_owned=FALSE AND status='active'`, organizationID, createUserID).Scan(&createEdges); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT status,version FROM organization_memberships WHERE organization_id=$1 AND user_id=$2 AND source_owned=FALSE`, organizationID, deleteUserID).Scan(&deleteStatus, &deleteMembershipVersion); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT version FROM organization_units WHERE id=$1`, organizationID).Scan(&organizationVersion); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE request_id=ANY($1::uuid[]) AND action LIKE 'identity.organization_membership.%'`, requestIDs).Scan(&auditEvents); err != nil {
			t.Fatal(err)
		}
		createWon := createEdges == 1 && deleteStatus == "active" && deleteMembershipVersion == 1
		deleteWon := createEdges == 0 && deleteStatus == "removed" && deleteMembershipVersion == 2
		if successes != 1 || rejected != 1 || organizationVersion != 2 || auditEvents != 1 || (!createWon && !deleteWon) {
			t.Fatalf("create/delete success=%d rejected=%d create_edges=%d delete=%s/%d org_version=%d audits=%d", successes, rejected, createEdges, deleteStatus, deleteMembershipVersion, organizationVersion, auditEvents)
		}
		requireIntegrationProofConsumedAndUnreplayable(t, ctx, pool, reauthentication, actor, iam.ReauthenticationOperationOrganizationMembershipCreate, createProof)
		requireIntegrationProofConsumedAndUnreplayable(t, ctx, pool, reauthentication, actor, iam.ReauthenticationOperationOrganizationMembershipDelete, deleteProof)
	})
}

// Mutation caught: coupling proof consumption to the business transaction
// permits replay after an immutable-audit outage, while committing business
// state before audit leaks a grant without evidence.
func TestOrganizationMembershipPostgresAuditFailureRollsBackBusinessButConsumesProof(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}
	resetOrganizationMembershipIntegrationTables(t, ctx, pool)

	now := time.Date(2026, 8, 21, 19, 30, 0, 0, time.UTC)
	organizationID, userID, emergencyID := uuid.New(), uuid.New(), uuid.New()
	seedOrganizationMembershipPrincipalAndOrganization(t, ctx, pool, organizationID, userID, now)
	seedOrganizationMembershipEmergencyAdministrator(t, ctx, pool, emergencyID, now)
	if _, err := pool.Exec(ctx, `
INSERT INTO local_sessions (
    id,token_digest,subject_id,authentication_method,mfa_level,authenticated_at,last_used_at,
    absolute_expires_at,idle_expires_at,version
) VALUES ($1,$2,$3,'local_password',0,$4,$4,$5,$5,1)`, uuid.New(), integrationSHA256Hex("membership-audit-session"), userID, now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	repository := iam.NewPostgresRepository(pool)
	realAuditor := audit.NewService(audit.NewPostgresRepository(pool))
	actor := organizationMembershipIntegrationActor(emergencyID, now)
	creator := actor
	reauthentication, err := iam.NewReauthenticationService(iam.ReauthenticationConfig{
		Repository: repository, Auditor: realAuditor, Local: integrationLocalReauthenticator{},
		Clock: func() time.Time { return now }, Policy: iam.DefaultReauthenticationPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	proof, request := completeIntegrationReauthenticationProof(t, ctx, reauthentication, creator, actor, iam.ReauthenticationOperationOrganizationMembershipCreate)
	failingService := newOrganizationMembershipIntegrationService(t, repository, failingIAMAuditAppender{}, reauthentication, now)
	reason := "approved audit rollback supplemental access"
	_, createErr := failingService.CreateOrganizationMembership(ctx, actor, organizationID, iam.CreateOrganizationMembershipCommand{
		OrganizationVersion: 1, UserID: userID, UserVersion: 1, Reason: reason,
	}, proof, request)
	if !errors.Is(createErr, errIntegrationAuditFailure) {
		t.Fatalf("CreateOrganizationMembership(audit failure) error=%v", createErr)
	}
	challengeID, err := uuid.Parse(proof.ChallengeID)
	if err != nil {
		t.Fatal(err)
	}
	var platformRows, organizationVersion, activeSessions, businessAudits int
	var challengeStatus string
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM organization_memberships WHERE organization_id=$1 AND user_id=$2 AND source_owned=FALSE`, organizationID, userID).Scan(&platformRows); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT version FROM organization_units WHERE id=$1`, organizationID).Scan(&organizationVersion); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM local_sessions WHERE subject_id=$1 AND revoked_at IS NULL`, userID).Scan(&activeSessions); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT status FROM iam_reauthentication_challenges WHERE id=$1`, challengeID).Scan(&challengeStatus); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE request_id=$1 AND action='identity.organization_membership.create'`, request.RequestID).Scan(&businessAudits); err != nil {
		t.Fatal(err)
	}
	if platformRows != 0 || organizationVersion != 1 || activeSessions != 1 || challengeStatus != "consumed" || businessAudits != 0 {
		t.Fatalf("audit rollback rows=%d org_version=%d sessions=%d challenge=%s audits=%d", platformRows, organizationVersion, activeSessions, challengeStatus, businessAudits)
	}
	realService := newOrganizationMembershipIntegrationService(t, repository, realAuditor, reauthentication, now)
	if _, err := realService.CreateOrganizationMembership(ctx, actor, organizationID, iam.CreateOrganizationMembershipCommand{
		OrganizationVersion: 1, UserID: userID, UserVersion: 1, Reason: reason,
	}, proof, iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.111"}); !errors.Is(err, iam.ErrHighRiskConfirmationRequired) {
		t.Fatalf("consumed membership proof replay error=%v", err)
	}
	freshProof, freshRequest := completeIntegrationReauthenticationProof(t, ctx, reauthentication, creator, actor, iam.ReauthenticationOperationOrganizationMembershipCreate)
	if _, err := realService.CreateOrganizationMembership(ctx, actor, organizationID, iam.CreateOrganizationMembershipCommand{
		OrganizationVersion: 1, UserID: userID, UserVersion: 1, Reason: reason,
	}, freshProof, freshRequest); err != nil {
		t.Fatalf("fresh proof membership recovery error=%v", err)
	}
	var auditMetadata, auditTokenID string
	if err := pool.QueryRow(ctx, `SELECT metadata::text,token_id FROM audit_events WHERE request_id=$1 AND action='identity.organization_membership.create'`, freshRequest.RequestID).Scan(&auditMetadata, &auditTokenID); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(auditMetadata, reason) || !strings.Contains(auditMetadata, `"reason_digest"`) || auditTokenID != "" {
		t.Fatalf("membership audit leaked secret context metadata=%s token_id=%q", auditMetadata, auditTokenID)
	}

	if _, err := pool.Exec(ctx, `
INSERT INTO local_sessions (
    id,token_digest,subject_id,authentication_method,mfa_level,authenticated_at,last_used_at,
    absolute_expires_at,idle_expires_at,version
) VALUES ($1,$2,$3,'local_password',0,$4,$4,$5,$5,1)`, uuid.New(), integrationSHA256Hex("membership-delete-audit-session"), userID, now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	deleteReason := "remove audit rollback supplemental access"
	deleteProof, deleteRequest := completeIntegrationReauthenticationProof(t, ctx, reauthentication, creator, actor, iam.ReauthenticationOperationOrganizationMembershipDelete)
	if deleteErr := failingService.DeleteOrganizationMembership(ctx, actor, organizationID, userID, iam.DeleteOrganizationMembershipCommand{
		OrganizationVersion: 2, UserVersion: 1, MembershipVersion: 1, Reason: deleteReason,
	}, deleteProof, deleteRequest); !errors.Is(deleteErr, errIntegrationAuditFailure) {
		t.Fatalf("DeleteOrganizationMembership(audit failure) error=%v", deleteErr)
	}
	deleteChallengeID, err := uuid.Parse(deleteProof.ChallengeID)
	if err != nil {
		t.Fatal(err)
	}
	var membershipStatus string
	var membershipVersion int
	if err := pool.QueryRow(ctx, `SELECT status,version FROM organization_memberships WHERE organization_id=$1 AND user_id=$2 AND source_owned=FALSE`, organizationID, userID).Scan(&membershipStatus, &membershipVersion); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT version FROM organization_units WHERE id=$1`, organizationID).Scan(&organizationVersion); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM local_sessions WHERE subject_id=$1 AND revoked_at IS NULL`, userID).Scan(&activeSessions); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT status FROM iam_reauthentication_challenges WHERE id=$1`, deleteChallengeID).Scan(&challengeStatus); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE request_id=$1 AND action='identity.organization_membership.delete'`, deleteRequest.RequestID).Scan(&businessAudits); err != nil {
		t.Fatal(err)
	}
	if membershipStatus != "active" || membershipVersion != 1 || organizationVersion != 2 || activeSessions != 1 || challengeStatus != "consumed" || businessAudits != 0 {
		t.Fatalf("delete audit rollback membership=%s/%d org_version=%d sessions=%d challenge=%s audits=%d", membershipStatus, membershipVersion, organizationVersion, activeSessions, challengeStatus, businessAudits)
	}
	if err := realService.DeleteOrganizationMembership(ctx, actor, organizationID, userID, iam.DeleteOrganizationMembershipCommand{
		OrganizationVersion: 2, UserVersion: 1, MembershipVersion: 1, Reason: deleteReason,
	}, deleteProof, iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.112"}); !errors.Is(err, iam.ErrHighRiskConfirmationRequired) {
		t.Fatalf("consumed delete proof replay error=%v", err)
	}
	freshDeleteProof, freshDeleteRequest := completeIntegrationReauthenticationProof(t, ctx, reauthentication, creator, actor, iam.ReauthenticationOperationOrganizationMembershipDelete)
	if err := realService.DeleteOrganizationMembership(ctx, actor, organizationID, userID, iam.DeleteOrganizationMembershipCommand{
		OrganizationVersion: 2, UserVersion: 1, MembershipVersion: 1, Reason: deleteReason,
	}, freshDeleteProof, freshDeleteRequest); err != nil {
		t.Fatalf("fresh delete proof membership recovery error=%v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT status,version FROM organization_memberships WHERE organization_id=$1 AND user_id=$2 AND source_owned=FALSE`, organizationID, userID).Scan(&membershipStatus, &membershipVersion); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT version FROM organization_units WHERE id=$1`, organizationID).Scan(&organizationVersion); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM local_sessions WHERE subject_id=$1 AND revoked_at IS NULL`, userID).Scan(&activeSessions); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE request_id=$1 AND action='identity.organization_membership.delete'`, freshDeleteRequest.RequestID).Scan(&businessAudits); err != nil {
		t.Fatal(err)
	}
	if membershipStatus != "removed" || membershipVersion != 2 || organizationVersion != 3 || activeSessions != 0 || businessAudits != 1 {
		t.Fatalf("fresh delete membership=%s/%d org_version=%d sessions=%d audits=%d", membershipStatus, membershipVersion, organizationVersion, activeSessions, businessAudits)
	}
}

// Mutation caught: checking break-glass before the tentative edge change lets
// an organization deny grant or organization allow removal eliminate the last
// usable emergency administrator.
func TestOrganizationMembershipPostgresBreakGlassEvaluatesTentativeGraph(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 21, 19, 45, 0, 0, time.UTC)

	t.Run("create organization deny", func(t *testing.T) {
		resetOrganizationMembershipIntegrationTables(t, ctx, pool)
		organizationID, emergencyID := uuid.New(), uuid.New()
		seedOrganizationMembershipEmergencyAdministrator(t, ctx, pool, emergencyID, now)
		if _, err := pool.Exec(ctx, `
INSERT INTO organization_units (id,name,source_owned,status,version,created_at,updated_at)
VALUES ($1,'Deny Organization',FALSE,'active',1,$2,$2)`, organizationID, now); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `
INSERT INTO role_bindings (id,subject_type,subject_id,role_name,scope_type,effect,valid_from,created_by,version,created_at,updated_at)
VALUES ($1,'organization',$2,'admin','platform','deny',$3,'test:bootstrap',1,$3,$3)`, uuid.New(), organizationID, now); err != nil {
			t.Fatal(err)
		}
		repository := iam.NewPostgresRepository(pool)
		realAuditor := audit.NewService(audit.NewPostgresRepository(pool))
		actor := organizationMembershipIntegrationActor(emergencyID, now)
		reauthentication := newOrganizationMembershipReauthenticationService(t, repository, realAuditor, now)
		proof, request := completeIntegrationReauthenticationProof(t, ctx, reauthentication, actor, actor, iam.ReauthenticationOperationOrganizationMembershipCreate)
		service := newOrganizationMembershipIntegrationService(t, repository, realAuditor, reauthentication, now)
		_, createErr := service.CreateOrganizationMembership(ctx, actor, organizationID, iam.CreateOrganizationMembershipCommand{
			OrganizationVersion: 1, UserID: emergencyID, UserVersion: 1, Reason: "deny would remove emergency authority",
		}, proof, request)
		if !errors.Is(createErr, iam.ErrLastEmergencyAdministrator) {
			t.Fatalf("create deny membership error=%v", createErr)
		}
		assertOrganizationMembershipInvariantRollback(t, ctx, pool, organizationID, emergencyID, false, "", 0, request.RequestID)
		requireIntegrationProofConsumedAndUnreplayable(t, ctx, pool, reauthentication, actor, iam.ReauthenticationOperationOrganizationMembershipCreate, proof)

		freshProof, freshRequest := completeIntegrationReauthenticationProof(t, ctx, reauthentication, actor, actor, iam.ReauthenticationOperationOrganizationMembershipCreate)
		if _, err := service.CreateOrganizationMembership(ctx, actor, organizationID, iam.CreateOrganizationMembershipCommand{
			OrganizationVersion: 1, UserID: emergencyID, UserVersion: 1, Reason: "deny would remove emergency authority",
		}, freshProof, freshRequest); !errors.Is(err, iam.ErrLastEmergencyAdministrator) {
			t.Fatalf("fresh proof create deny membership error=%v", err)
		}
		assertOrganizationMembershipInvariantRollback(t, ctx, pool, organizationID, emergencyID, false, "", 0, freshRequest.RequestID)
		requireIntegrationProofConsumedAndUnreplayable(t, ctx, pool, reauthentication, actor, iam.ReauthenticationOperationOrganizationMembershipCreate, freshProof)
	})

	t.Run("delete organization allow", func(t *testing.T) {
		resetOrganizationMembershipIntegrationTables(t, ctx, pool)
		organizationID, emergencyID := uuid.New(), uuid.New()
		seedOrganizationMembershipEmergencyPrincipal(t, ctx, pool, emergencyID, now)
		if _, err := pool.Exec(ctx, `
INSERT INTO organization_units (id,name,source_owned,status,version,created_at,updated_at)
VALUES ($1,'Allow Organization',FALSE,'active',1,$2,$2)`, organizationID, now); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `
INSERT INTO organization_memberships (organization_id,user_id,source_owned,status,version,created_at,updated_at)
VALUES ($1,$2,FALSE,'active',1,$3,$3)`, organizationID, emergencyID, now); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `
INSERT INTO role_bindings (id,subject_type,subject_id,role_name,scope_type,effect,valid_from,created_by,version,created_at,updated_at)
VALUES ($1,'organization',$2,'admin','platform','allow',$3,'test:bootstrap',1,$3,$3)`, uuid.New(), organizationID, now); err != nil {
			t.Fatal(err)
		}
		repository := iam.NewPostgresRepository(pool)
		realAuditor := audit.NewService(audit.NewPostgresRepository(pool))
		actor := organizationMembershipIntegrationActor(emergencyID, now)
		reauthentication := newOrganizationMembershipReauthenticationService(t, repository, realAuditor, now)
		proof, request := completeIntegrationReauthenticationProof(t, ctx, reauthentication, actor, actor, iam.ReauthenticationOperationOrganizationMembershipDelete)
		service := newOrganizationMembershipIntegrationService(t, repository, realAuditor, reauthentication, now)
		deleteErr := service.DeleteOrganizationMembership(ctx, actor, organizationID, emergencyID, iam.DeleteOrganizationMembershipCommand{
			OrganizationVersion: 1, UserVersion: 1, MembershipVersion: 1, Reason: "allow removal would remove emergency authority",
		}, proof, request)
		if !errors.Is(deleteErr, iam.ErrLastEmergencyAdministrator) {
			t.Fatalf("delete allow membership error=%v", deleteErr)
		}
		assertOrganizationMembershipInvariantRollback(t, ctx, pool, organizationID, emergencyID, true, "active", 1, request.RequestID)
		requireIntegrationProofConsumedAndUnreplayable(t, ctx, pool, reauthentication, actor, iam.ReauthenticationOperationOrganizationMembershipDelete, proof)

		freshProof, freshRequest := completeIntegrationReauthenticationProof(t, ctx, reauthentication, actor, actor, iam.ReauthenticationOperationOrganizationMembershipDelete)
		if err := service.DeleteOrganizationMembership(ctx, actor, organizationID, emergencyID, iam.DeleteOrganizationMembershipCommand{
			OrganizationVersion: 1, UserVersion: 1, MembershipVersion: 1, Reason: "allow removal would remove emergency authority",
		}, freshProof, freshRequest); !errors.Is(err, iam.ErrLastEmergencyAdministrator) {
			t.Fatalf("fresh proof delete allow membership error=%v", err)
		}
		assertOrganizationMembershipInvariantRollback(t, ctx, pool, organizationID, emergencyID, true, "active", 1, freshRequest.RequestID)
		requireIntegrationProofConsumedAndUnreplayable(t, ctx, pool, reauthentication, actor, iam.ReauthenticationOperationOrganizationMembershipDelete, freshProof)
	})
}

// Mutation caught: reading tombstones or failing to DISTINCT dual ownership
// repeats organization-derived role scopes and can preserve revoked access.
func TestOrganizationMembershipPostgresAuthorizationUsesDistinctActiveEdges(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}
	resetOrganizationMembershipIntegrationTables(t, ctx, pool)
	now := time.Date(2026, 8, 21, 19, 55, 0, 0, time.UTC)
	organizationID, userID := uuid.New(), uuid.New()
	seedOrganizationMembershipPrincipalAndOrganization(t, ctx, pool, organizationID, userID, now)
	if _, err := pool.Exec(ctx, `
INSERT INTO organization_memberships (organization_id,user_id,source_owned,status,version,created_at,updated_at)
VALUES ($1,$2,TRUE,'active',1,$3,$3),($1,$2,FALSE,'active',1,$3,$3)`, organizationID, userID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO role_bindings (id,subject_type,subject_id,role_name,scope_type,effect,valid_from,created_by,version,created_at,updated_at)
VALUES ($1,'organization',$2,'viewer','platform','allow',$3,'test:bootstrap',1,$3,$3)`, uuid.New(), organizationID, now); err != nil {
		t.Fatal(err)
	}
	resolver, err := iam.NewGovernedPrincipalResolver(iam.NewPostgresRepository(pool), func() time.Time { return now.Add(time.Minute) })
	if err != nil {
		t.Fatal(err)
	}
	resolve := func() identity.Principal {
		t.Helper()
		principal, resolveErr := resolver.ResolvePrincipal(ctx, identity.Principal{Subject: "membership." + userID.String(), Kind: identity.PrincipalKindLocal, AuthenticationAssurance: 1})
		if resolveErr != nil {
			t.Fatalf("ResolvePrincipal() error=%v", resolveErr)
		}
		return principal
	}
	if principal := resolve(); len(principal.RoleScopes) != 1 || principal.RoleScopes[0].Role != identity.RoleViewer {
		t.Fatalf("dual active role scopes=%+v", principal.RoleScopes)
	}
	if _, err := pool.Exec(ctx, `UPDATE organization_memberships SET status='removed',version=version+1,updated_at=$3 WHERE organization_id=$1 AND user_id=$2`, organizationID, userID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if principal := resolve(); len(principal.RoleScopes) != 0 {
		t.Fatalf("removed membership propagated scopes=%+v", principal.RoleScopes)
	}
}

// Mutation caught: taking organization/user locks before the shared break-glass
// authority creates an advisory/entity deadlock and lets independent reductions
// jointly remove every emergency administrator.
func TestOrganizationMembershipPostgresSerializesWithEmergencyUserReduction(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}
	resetOrganizationMembershipIntegrationTables(t, ctx, pool)
	now := time.Date(2026, 8, 21, 20, 0, 0, 0, time.UTC)
	organizationID, organizationAdminID, directAdminID := uuid.New(), uuid.New(), uuid.New()
	seedOrganizationMembershipEmergencyPrincipal(t, ctx, pool, organizationAdminID, now)
	seedOrganizationMembershipEmergencyAdministrator(t, ctx, pool, directAdminID, now)
	if _, err := pool.Exec(ctx, `
INSERT INTO organization_units (id,name,source_owned,status,version,created_at,updated_at)
VALUES ($1,'Emergency Allow Organization',FALSE,'active',1,$2,$2)`, organizationID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO organization_memberships (organization_id,user_id,source_owned,status,version,created_at,updated_at)
VALUES ($1,$2,FALSE,'active',1,$3,$3)`, organizationID, organizationAdminID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO role_bindings (id,subject_type,subject_id,role_name,scope_type,effect,valid_from,created_by,version,created_at,updated_at)
VALUES ($1,'organization',$2,'admin','platform','allow',$3,'test:bootstrap',1,$3,$3)`, uuid.New(), organizationID, now); err != nil {
		t.Fatal(err)
	}
	repository := iam.NewPostgresRepository(pool)
	service := newOrganizationMembershipIntegrationService(t, repository, audit.NewService(audit.NewPostgresRepository(pool)), integrationHighRiskAuthorizer{}, now)
	actor := organizationMembershipIntegrationActor(directAdminID, now)
	start := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		<-start
		results <- service.DeleteOrganizationMembership(ctx, actor, organizationID, organizationAdminID, iam.DeleteOrganizationMembershipCommand{
			OrganizationVersion: 1, UserVersion: 1, MembershipVersion: 1, Reason: "remove one emergency administrator path",
		}, iam.HighRiskProof{Confirmed: true}, iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.117"})
	}()
	go func() {
		<-start
		results <- service.DisableUser(ctx, actor, directAdminID, 1, "disable one emergency administrator", iam.HighRiskProof{Confirmed: true}, iam.RequestContext{RequestID: uuid.NewString(), SourceIP: "192.0.2.118"})
	}()
	close(start)
	successes, invariantFailures := 0, 0
	for index := 0; index < 2; index++ {
		switch result := <-results; {
		case result == nil:
			successes++
		case errors.Is(result, iam.ErrLastEmergencyAdministrator):
			invariantFailures++
		default:
			t.Fatalf("membership/user reduction error=%v", result)
		}
	}
	var usableAdministrators int
	if err := pool.QueryRow(ctx, `
WITH active_emergency AS (
    SELECT principal.id
    FROM user_principals principal
    WHERE principal.user_kind='emergency' AND principal.status='active'
), effective_admin AS (
    SELECT principal.id
    FROM active_emergency principal
    WHERE EXISTS (
        SELECT 1 FROM role_bindings binding
        WHERE binding.role_name='admin' AND binding.scope_type='platform' AND binding.effect='allow'
          AND (binding.valid_until IS NULL OR binding.valid_until>$1)
          AND ((binding.subject_type='user' AND binding.subject_id=principal.id) OR
               (binding.subject_type='organization' AND EXISTS (
                   SELECT 1 FROM organization_memberships membership
                   WHERE membership.user_id=principal.id AND membership.organization_id=binding.subject_id AND membership.status='active'
               )))
    )
)
SELECT count(*) FROM effective_admin`, now).Scan(&usableAdministrators); err != nil {
		t.Fatal(err)
	}
	if successes != 1 || invariantFailures != 1 || usableAdministrators != 1 {
		t.Fatalf("membership/user serialization successes=%d invariant_failures=%d usable_admins=%d", successes, invariantFailures, usableAdministrators)
	}
}

func resetOrganizationMembershipIntegrationTables(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
TRUNCATE TABLE iam_reauthentication_challenges, local_sessions, local_auth_rate_limits, emergency_access_events,
directory_sync_conflicts, directory_sync_jobs, role_bindings, organization_memberships, organization_units,
local_password_history, local_credentials, user_principals, iam_login_state, identity_sources CASCADE;
INSERT INTO iam_login_state (singleton,login_mode,version,updated_by,updated_at)
VALUES (TRUE,'local',1,'test:bootstrap',clock_timestamp())`); err != nil {
		t.Fatalf("reset organization membership tables: %v", err)
	}
}

func seedOrganizationMembershipPrincipalAndOrganization(t *testing.T, ctx context.Context, pool *pgxpool.Pool, organizationID, userID uuid.UUID, now time.Time) {
	t.Helper()
	seedOrganizationMembershipPrincipal(t, ctx, pool, userID, now)
	if _, err := pool.Exec(ctx, `
INSERT INTO organization_units (id,name,source_owned,status,version,created_at,updated_at)
VALUES ($1,'Membership Organization',FALSE,'active',1,$2,$2)`, organizationID, now); err != nil {
		t.Fatalf("seed membership organization: %v", err)
	}
}

func seedOrganizationMembershipPrincipal(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID uuid.UUID, now time.Time) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
INSERT INTO user_principals (id,username,display_name,user_kind,status,version,created_at,updated_at)
VALUES ($1,$2,'Membership Target','local','active',1,$3,$3)`, userID, "membership."+userID.String(), now); err != nil {
		t.Fatalf("seed membership principal: %v", err)
	}
}

func seedOrganizationMembershipEmergencyAdministrator(t *testing.T, ctx context.Context, pool *pgxpool.Pool, emergencyID uuid.UUID, now time.Time) {
	t.Helper()
	seedOrganizationMembershipEmergencyPrincipal(t, ctx, pool, emergencyID, now)
	if _, err := pool.Exec(ctx, `
INSERT INTO role_bindings (
    id,subject_type,subject_id,role_name,scope_type,effect,valid_from,created_by,version,created_at,updated_at
) VALUES ($1,'user',$2,'admin','platform','allow',$3,'test:bootstrap',1,$3,$3)`, uuid.New(), emergencyID, now.Add(-time.Hour)); err != nil {
		t.Fatalf("seed membership emergency binding: %v", err)
	}
}

func seedOrganizationMembershipEmergencyPrincipal(t *testing.T, ctx context.Context, pool *pgxpool.Pool, emergencyID uuid.UUID, now time.Time) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
INSERT INTO user_principals (
    id,username,display_name,user_kind,status,mfa_enrolled,credential_rotated_at,version,created_at,updated_at
) VALUES ($1,$2,'Membership Emergency','emergency','active',TRUE,$3,1,$3,$3)`, emergencyID, "emergency."+emergencyID.String(), now.Add(-time.Hour)); err != nil {
		t.Fatalf("seed membership emergency: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO local_credentials (
    user_id,algorithm,parameters,salt,derived_key,failed_attempts,password_changed_at,mfa_secret_reference
) VALUES ($1,'argon2id','m=19456,t=1,p=1,l=32',decode(repeat('11',16),'hex'),decode(repeat('22',32),'hex'),0,$2,$3)`, emergencyID, now.Add(-time.Hour), "secret://mfa/"+emergencyID.String()); err != nil {
		t.Fatalf("seed membership emergency credential: %v", err)
	}
}

func assertOrganizationMembershipInvariantRollback(t *testing.T, ctx context.Context, pool *pgxpool.Pool, organizationID, userID uuid.UUID, membershipExists bool, expectedStatus string, expectedMembershipVersion int, requestID string) {
	t.Helper()
	var organizationVersion, membershipRows, auditEvents int
	if err := pool.QueryRow(ctx, `SELECT version FROM organization_units WHERE id=$1`, organizationID).Scan(&organizationVersion); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM organization_memberships WHERE organization_id=$1 AND user_id=$2 AND source_owned=FALSE`, organizationID, userID).Scan(&membershipRows); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE request_id=$1 AND action LIKE 'identity.organization_membership.%'`, requestID).Scan(&auditEvents); err != nil {
		t.Fatal(err)
	}
	if organizationVersion != 1 || membershipRows != map[bool]int{true: 1, false: 0}[membershipExists] || auditEvents != 0 {
		t.Fatalf("invariant rollback org_version=%d membership_rows=%d audit_events=%d", organizationVersion, membershipRows, auditEvents)
	}
	if membershipExists {
		var status string
		var version int
		if err := pool.QueryRow(ctx, `SELECT status,version FROM organization_memberships WHERE organization_id=$1 AND user_id=$2 AND source_owned=FALSE`, organizationID, userID).Scan(&status, &version); err != nil {
			t.Fatal(err)
		}
		if status != expectedStatus || version != expectedMembershipVersion {
			t.Fatalf("invariant rollback membership=%s/%d", status, version)
		}
	}
}

func newOrganizationMembershipIntegrationService(t *testing.T, repository *iam.PostgresRepository, auditor iam.AuditAppender, highRisk iam.HighRiskAuthorizer, now time.Time) *iam.Service {
	t.Helper()
	passwords, err := iam.NewPasswordManager(iam.PasswordPolicyConfig{
		MinimumLength: 16, MemoryKiB: 19 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, DerivedKeyBytes: 32,
	}, integrationBreachChecker{})
	if err != nil {
		t.Fatal(err)
	}
	service, err := iam.NewService(iam.ServiceConfig{
		Repository: repository, ScopeCatalog: repository, BreakGlass: iam.NewBreakGlassInvariantAuthority(repository),
		Auditor: auditor, Sessions: repository, Passwords: passwords, HighRisk: highRisk, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func newOrganizationMembershipReauthenticationService(t *testing.T, repository *iam.PostgresRepository, auditor iam.AuditAppender, now time.Time) *iam.ReauthenticationService {
	t.Helper()
	service, err := iam.NewReauthenticationService(iam.ReauthenticationConfig{
		Repository: repository,
		Auditor:    auditor,
		Local:      integrationLocalReauthenticator{},
		Clock:      func() time.Time { return now },
		Policy:     iam.DefaultReauthenticationPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

type productionProofRendezvous struct {
	delegate iam.HighRiskAuthorizer
	expected int
	mu       sync.Mutex
	reached  int
	ready    chan struct{}
	release  chan struct{}
}

func newProductionProofRendezvous(delegate iam.HighRiskAuthorizer, expected int) *productionProofRendezvous {
	return &productionProofRendezvous{delegate: delegate, expected: expected, ready: make(chan struct{}), release: make(chan struct{})}
}

func (rendezvous *productionProofRendezvous) Authorize(ctx context.Context, actor identity.Principal, operation string, proof iam.HighRiskProof, request iam.RequestContext) error {
	if err := rendezvous.delegate.Authorize(ctx, actor, operation, proof, request); err != nil {
		return err
	}
	rendezvous.mu.Lock()
	rendezvous.reached++
	if rendezvous.reached == rendezvous.expected {
		close(rendezvous.ready)
	}
	rendezvous.mu.Unlock()
	select {
	case <-rendezvous.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (rendezvous *productionProofRendezvous) releaseWhenAllConsumed(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case <-rendezvous.ready:
		close(rendezvous.release)
	case <-ctx.Done():
		t.Fatalf("wait for production proof consumption: %v", ctx.Err())
	}
}

func organizationMembershipIntegrationActor(emergencyID uuid.UUID, now time.Time) identity.Principal {
	return identity.Principal{
		Subject: "membership.admin", Kind: identity.PrincipalKindLocal, TokenID: "membership-fresh-token",
		Governed: true, GovernedUserID: emergencyID.String(), AuthenticatedAt: now.Add(-time.Minute), AuthenticationAssurance: 2,
		RoleScopes: []identity.RoleScope{{Role: identity.RoleAdmin, Effect: "allow", ScopeType: "platform"}},
	}
}

func migrationChecksums(t *testing.T, ctx context.Context, pool *pgxpool.Pool, maximumVersion int) map[int]string {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT version,checksum FROM schema_migrations WHERE version BETWEEN 1 AND $1 ORDER BY version`, maximumVersion)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	result := make(map[int]string, maximumVersion)
	for rows.Next() {
		var version int
		var checksum string
		if err := rows.Scan(&version, &checksum); err != nil {
			t.Fatal(err)
		}
		result[version] = checksum
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}
