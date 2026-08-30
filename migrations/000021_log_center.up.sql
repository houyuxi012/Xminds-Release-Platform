-- Task 15 foundation: replay claims and durable maintenance scheduling.
-- Evidence partitions and typed log tables are added in subsequent Task 15 slices.
CREATE TABLE log_center_role_provenance (id BOOLEAN PRIMARY KEY DEFAULT TRUE, created_by_migration BOOLEAN NOT NULL, role_granted_to_executor BOOLEAN NOT NULL, migration_executor TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL);
DO $$ DECLARE created_here BOOLEAN := FALSE; granted_here BOOLEAN := FALSE; BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'xminds_log_owner') THEN CREATE ROLE xminds_log_owner NOLOGIN; created_here := TRUE; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid JOIN pg_roles u ON u.oid=m.member WHERE r.rolname='xminds_log_owner' AND u.rolname=CURRENT_USER) THEN GRANT xminds_log_owner TO CURRENT_USER; granted_here := TRUE; END IF;
    INSERT INTO log_center_role_provenance(created_by_migration, role_granted_to_executor, migration_executor, created_at) VALUES (created_here, granted_here, CURRENT_USER, clock_timestamp());
END $$;

-- PostgreSQL 15+ no longer grants CREATE on the public schema to every role.
-- The dedicated SECURITY DEFINER owner needs only schema-level DDL rights for
-- creating the monthly partitions below; it remains NOLOGIN and is not granted
-- to runtime principals.
GRANT USAGE, CREATE ON SCHEMA public TO xminds_log_owner;

CREATE TABLE authorization_context_replay_claims (
    validator_issuer VARCHAR(256) NOT NULL,
    context_id VARCHAR(128) NOT NULL,
    claimed_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (validator_issuer, context_id),
    CHECK (validator_issuer <> ''),
    CHECK (context_id <> ''),
    CHECK (expires_at > claimed_at)
);

CREATE INDEX authorization_context_replay_claims_expiry_idx
    ON authorization_context_replay_claims (expires_at, validator_issuer, context_id);

CREATE TABLE log_maintenance_schedule (
    id UUID PRIMARY KEY,
    job_kind VARCHAR(128) NOT NULL,
    period_key VARCHAR(10) NOT NULL,
    run_no INTEGER NOT NULL DEFAULT 0,
    dedupe_key VARCHAR(256) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'pending',
    lease_token UUID,
    leased_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (job_kind IN (
        'authorization.context_replay_gc.v1',
        'log.partition.ensure.v1',
        'log.partition.archive.v1',
        'log.partition.purge.v1'
    )),
    CHECK (status IN ('pending', 'leased', 'completed', 'failed')),
    CHECK (run_no >= 0),
    CHECK (
        (job_kind = 'authorization.context_replay_gc.v1' AND run_no BETWEEN 0 AND 287 AND period_key ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$')
        OR
        (job_kind <> 'authorization.context_replay_gc.v1' AND run_no = 0 AND period_key ~ '^[0-9]{4}-[0-9]{2}$')
    ),
    CHECK (dedupe_key <> ''),
    CHECK (updated_at >= created_at),
    CHECK (
        (status <> 'leased' AND lease_token IS NULL AND leased_until IS NULL)
        OR (status = 'leased' AND lease_token IS NOT NULL AND leased_until IS NOT NULL AND leased_until > updated_at)
    )
);

CREATE UNIQUE INDEX log_maintenance_schedule_period_run_uidx
    ON log_maintenance_schedule (job_kind, period_key, run_no);
CREATE UNIQUE INDEX log_maintenance_schedule_dedupe_uidx
    ON log_maintenance_schedule (dedupe_key);

CREATE TABLE log_event_identities (
    event_id UUID PRIMARY KEY,
    log_type VARCHAR(32) NOT NULL,
    period_key VARCHAR(10) NOT NULL,
    dedupe_key VARCHAR(256) NOT NULL,
    payload_digest BYTEA NOT NULL CHECK (octet_length(payload_digest) = 32),
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (log_type, dedupe_key)
    ,CHECK (log_type IN ('operation','authentication','application_request','git_sync'))
    ,CHECK (period_key ~ '^[0-9]{4}-[0-9]{2}$')
    ,CHECK (dedupe_key <> '')
);

CREATE TABLE log_operation_events (
    event_id UUID NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    request_id UUID NOT NULL,
    correlation_id UUID,
    trace_id VARCHAR(64),
    product_id VARCHAR(128),
    actor_subject VARCHAR(256),
    actor_kind VARCHAR(32),
    action VARCHAR(128) NOT NULL,
    resource_type VARCHAR(128) NOT NULL,
    resource_id VARCHAR(256),
    result VARCHAR(16) NOT NULL CHECK (result IN ('success','denied','failed')),
    source_ip INET,
    metadata_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    schema_version SMALLINT NOT NULL DEFAULT 1,
    PRIMARY KEY (occurred_at, event_id)
) PARTITION BY RANGE (occurred_at);

CREATE TABLE log_authentication_events (
    event_id UUID NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    request_id UUID NOT NULL,
    correlation_id UUID,
    trace_id VARCHAR(64),
    product_id VARCHAR(128),
    subject VARCHAR(256) NOT NULL,
    identity_source_id VARCHAR(128),
    authentication_method VARCHAR(64) NOT NULL,
    mfa_level VARCHAR(32),
    client_name VARCHAR(128),
    result VARCHAR(16) NOT NULL CHECK (result IN ('success','denied','failed')),
    reason_code VARCHAR(64),
    source_ip INET,
    schema_version SMALLINT NOT NULL DEFAULT 1,
    PRIMARY KEY (occurred_at, event_id)
) PARTITION BY RANGE (occurred_at);

CREATE TABLE log_application_request_events (
    event_id UUID NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    request_id UUID NOT NULL,
    correlation_id UUID,
    trace_id VARCHAR(64),
    product_id VARCHAR(128),
    client_app_id VARCHAR(128) NOT NULL,
    client_app_version VARCHAR(128) NOT NULL,
    http_method VARCHAR(16) NOT NULL,
    route_template VARCHAR(512) NOT NULL,
    http_status INTEGER,
    duration_ms BIGINT NOT NULL CHECK (duration_ms >= 0),
    snapshot_trusted BOOLEAN NOT NULL,
    customer_id VARCHAR(128), customer_name VARCHAR(256), tenant_id VARCHAR(128),
    authorization_name VARCHAR(256), license_id VARCHAR(128), license_expires_at TIMESTAMPTZ, license_status VARCHAR(16),
    decision VARCHAR(16) NOT NULL CHECK (decision IN ('allow','deny')),
    reason_code VARCHAR(64) NOT NULL,
    validated_at TIMESTAMPTZ, validator_issuer VARCHAR(256), context_digest BYTEA,
    result VARCHAR(16) NOT NULL CHECK (result IN ('success','denied','failed')),
    source_ip INET, schema_version SMALLINT NOT NULL DEFAULT 1,
    PRIMARY KEY (occurred_at, event_id),
    CHECK ((snapshot_trusted AND customer_id IS NOT NULL AND customer_name IS NOT NULL AND authorization_name IS NOT NULL AND license_id IS NOT NULL AND license_expires_at IS NOT NULL AND license_status IN ('valid','expiring','expired','revoked','unknown') AND validated_at IS NOT NULL AND validator_issuer IS NOT NULL AND context_digest IS NOT NULL AND octet_length(context_digest)=32 AND reason_code <> '' AND result IN ('success','denied','failed'))
       OR (NOT snapshot_trusted AND customer_id IS NULL AND customer_name IS NULL AND tenant_id IS NULL AND authorization_name IS NULL AND license_id IS NULL AND license_expires_at IS NULL AND license_status IS NULL AND validated_at IS NULL AND validator_issuer IS NULL AND context_digest IS NULL AND decision='deny' AND result IN ('denied','failed') AND reason_code <> ''))
) PARTITION BY RANGE (occurred_at);

CREATE TABLE log_git_sync_events (
    event_id UUID NOT NULL, occurred_at TIMESTAMPTZ NOT NULL, request_id UUID NOT NULL, correlation_id UUID, trace_id VARCHAR(64), product_id VARCHAR(128),
    provider VARCHAR(64) NOT NULL, repository_id VARCHAR(256) NOT NULL, repository_name VARCHAR(256) NOT NULL, commit_sha VARCHAR(64), tag_name VARCHAR(256),
    stage VARCHAR(32) NOT NULL CHECK (stage IN ('webhook_accept','fetch','validate','apply','status_writeback')), attempt INTEGER NOT NULL CHECK (attempt > 0),
    result VARCHAR(16) NOT NULL CHECK (result IN ('success','denied','failed')), error_code VARCHAR(128), source_ip INET, schema_version SMALLINT NOT NULL DEFAULT 1,
    PRIMARY KEY (occurred_at, event_id)
) PARTITION BY RANGE (occurred_at);

CREATE OR REPLACE FUNCTION logcenter_reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'log evidence is immutable' USING ERRCODE = '55000'; END $$;

CREATE OR REPLACE FUNCTION public.project_audit_event_row(p public.audit_events) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE event_period_key TEXT; existing_type TEXT; existing_period TEXT; existing_digest BYTEA; correlation UUID; trace TEXT; summary JSONB; BEGIN
    IF p.event_hash !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'event hash is invalid' USING ERRCODE = '22000'; END IF;
    IF p.metadata::text ~* '(authorization|cookie|token|password|secret|private_key|license_key|recovery_code|signed_context|webhook_secret)' THEN RAISE EXCEPTION 'sensitive metadata is invalid' USING ERRCODE = '22000'; END IF;
    IF p.metadata ? 'changed_fields' AND (jsonb_typeof(p.metadata -> 'changed_fields') <> 'array' OR EXISTS (SELECT 1 FROM jsonb_array_elements(p.metadata -> 'changed_fields') item WHERE jsonb_typeof(item) <> 'string' OR length(item #>> '{}') > 128)) THEN RAISE EXCEPTION 'changed fields metadata is invalid' USING ERRCODE = '22000'; END IF;
    IF p.metadata ? 'reason_summary' AND (jsonb_typeof(p.metadata -> 'reason_summary') <> 'string' OR length(p.metadata ->> 'reason_summary') NOT BETWEEN 1 AND 256) THEN RAISE EXCEPTION 'reason metadata is invalid' USING ERRCODE = '22000'; END IF;
    IF p.metadata ? 'version_before' AND jsonb_typeof(p.metadata -> 'version_before') NOT IN ('string','number','boolean') THEN RAISE EXCEPTION 'version metadata is invalid' USING ERRCODE = '22000'; END IF;
    IF p.metadata ? 'version_after' AND jsonb_typeof(p.metadata -> 'version_after') NOT IN ('string','number','boolean') THEN RAISE EXCEPTION 'version metadata is invalid' USING ERRCODE = '22000'; END IF;
    event_period_key := to_char(p.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM');
    IF p.metadata ? 'correlation_id' AND jsonb_typeof(p.metadata -> 'correlation_id') <> 'string' THEN RAISE EXCEPTION 'correlation metadata is invalid' USING ERRCODE = '22000'; END IF;
    IF p.metadata ? 'trace_id' AND (jsonb_typeof(p.metadata -> 'trace_id') <> 'string' OR (p.metadata ->> 'trace_id') !~ '^[0-9a-fA-F]{32}$') THEN RAISE EXCEPTION 'trace metadata is invalid' USING ERRCODE = '22000'; END IF;
    IF p.metadata ? 'correlation_id' THEN correlation := (p.metadata ->> 'correlation_id')::uuid; END IF;
    IF p.metadata ? 'trace_id' THEN trace := p.metadata ->> 'trace_id'; END IF;
    summary := jsonb_strip_nulls(jsonb_build_object('changed_fields', p.metadata -> 'changed_fields', 'version_before', p.metadata -> 'version_before', 'version_after', p.metadata -> 'version_after', 'reason_summary', p.metadata -> 'reason_summary'));
    SELECT identity_row.log_type, identity_row.period_key, identity_row.payload_digest
      INTO existing_type, existing_period, existing_digest
      FROM public.log_event_identities AS identity_row
     WHERE identity_row.event_id = p.id;
    IF FOUND AND (existing_type <> 'operation' OR existing_period <> event_period_key OR existing_digest <> decode(p.event_hash, 'hex')) THEN RAISE EXCEPTION 'event identity conflict' USING ERRCODE = '23505'; END IF;
    IF NOT FOUND THEN INSERT INTO log_event_identities(event_id, log_type, period_key, dedupe_key, payload_digest, created_at)
        VALUES (p.id, 'operation', event_period_key, p.event_hash, decode(p.event_hash, 'hex'), clock_timestamp()); END IF;
    INSERT INTO log_operation_events(event_id, occurred_at, request_id, correlation_id, trace_id, product_id, actor_subject, actor_kind, action, resource_type, resource_id, result, source_ip, metadata_summary, schema_version)
    VALUES (p.id, p.occurred_at, p.request_id, correlation, trace, NULLIF(p.product_id, ''), p.actor_subject, p.actor_kind, p.action, p.resource_type, p.resource_id, p.outcome, p.source_ip, summary, 1);

    RETURN;
END $$;
CREATE OR REPLACE FUNCTION public.project_audit_event() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$ BEGIN PERFORM public.project_audit_event_row(NEW); RETURN NEW; END $$;
CREATE TRIGGER audit_events_log_center_projection AFTER INSERT ON public.audit_events FOR EACH ROW EXECUTE FUNCTION public.project_audit_event();
REVOKE ALL ON FUNCTION public.project_audit_event_row(public.audit_events) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.project_audit_event() FROM PUBLIC;

CREATE TRIGGER log_operation_events_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON log_operation_events FOR EACH STATEMENT EXECUTE FUNCTION logcenter_reject_mutation();
CREATE TRIGGER log_authentication_events_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON log_authentication_events FOR EACH STATEMENT EXECUTE FUNCTION logcenter_reject_mutation();
CREATE TRIGGER log_application_request_events_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON log_application_request_events FOR EACH STATEMENT EXECUTE FUNCTION logcenter_reject_mutation();
CREATE TRIGGER log_git_sync_events_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON log_git_sync_events FOR EACH STATEMENT EXECUTE FUNCTION logcenter_reject_mutation();
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON log_operation_events, log_authentication_events, log_application_request_events, log_git_sync_events FROM PUBLIC;
GRANT SELECT, INSERT ON log_event_identities TO xminds_log_owner;
GRANT SELECT, INSERT ON log_operation_events TO xminds_log_owner;
ALTER FUNCTION public.project_audit_event_row(public.audit_events) OWNER TO xminds_log_owner;
ALTER FUNCTION public.project_audit_event() OWNER TO xminds_log_owner;
ALTER FUNCTION public.logcenter_reject_mutation() OWNER TO xminds_log_owner;

CREATE OR REPLACE FUNCTION public.ensure_log_monthly_partitions(p_month DATE) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE month_start DATE; month_end DATE; suffix TEXT; parent_name TEXT;
BEGIN
    month_start := date_trunc('month', p_month)::date;
    IF p_month <> month_start THEN RAISE EXCEPTION 'partition month must be month start' USING ERRCODE = '22023'; END IF;
    month_end := (month_start + interval '1 month')::date;
    PERFORM pg_advisory_xact_lock(hashtextextended('xminds-log-partition:' || to_char(month_start, 'YYYY-MM'), 0));
    suffix := to_char(month_start, 'YYYYMM');
    FOREACH parent_name IN ARRAY ARRAY['log_operation_events','log_authentication_events','log_application_request_events','log_git_sync_events'] LOOP
        EXECUTE format('CREATE TABLE IF NOT EXISTS public.%I_%s PARTITION OF public.%I FOR VALUES FROM (%L) TO (%L)', parent_name, suffix, parent_name, month_start, month_end);
        EXECUTE format('REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.%I_%s FROM PUBLIC', parent_name, suffix);
    END LOOP;
END $$;
ALTER FUNCTION public.ensure_log_monthly_partitions(DATE) OWNER TO xminds_log_owner;
REVOKE ALL ON FUNCTION public.ensure_log_monthly_partitions(DATE) FROM PUBLIC;
ALTER TABLE public.log_operation_events OWNER TO xminds_log_owner;
ALTER TABLE public.log_authentication_events OWNER TO xminds_log_owner;
ALTER TABLE public.log_application_request_events OWNER TO xminds_log_owner;
ALTER TABLE public.log_git_sync_events OWNER TO xminds_log_owner;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='xminds_release_api') THEN GRANT EXECUTE ON FUNCTION public.ensure_log_monthly_partitions(DATE) TO xminds_release_api; END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='xminds_release_worker') THEN GRANT EXECUTE ON FUNCTION public.ensure_log_monthly_partitions(DATE) TO xminds_release_worker; END IF;
END $$;

DO $$ DECLARE month_start DATE; BEGIN
    FOR month_start IN
        SELECT (date_trunc('month', clock_timestamp() AT TIME ZONE 'UTC') + (n * interval '1 month'))::date
        FROM generate_series(-1, 2) n
    LOOP
        PERFORM public.ensure_log_monthly_partitions(month_start);
    END LOOP;
END $$;

DO $$ DECLARE month_start TIMESTAMPTZ; month_end TIMESTAMPTZ; audit_row audit_events; BEGIN
    FOR month_start IN SELECT DISTINCT date_trunc('month', occurred_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' FROM audit_events
        UNION SELECT date_trunc('month', clock_timestamp() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' LOOP
        month_end := month_start + interval '1 month';
        PERFORM public.ensure_log_monthly_partitions(month_start::date);
        FOR audit_row IN SELECT * FROM public.audit_events WHERE occurred_at >= month_start AND occurred_at < month_end ORDER BY occurred_at, id LOOP
            PERFORM public.project_audit_event_row(audit_row);
        END LOOP;
    END LOOP;
END $$;
