CREATE SCHEMA IF NOT EXISTS hartevo_cell;

CREATE TABLE IF NOT EXISTS hartevo_cell.schema_migrations (
    version BIGINT PRIMARY KEY CHECK (version > 0),
    checksum TEXT NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
    applied_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS hartevo_cell.cell_configuration (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    configured_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS hartevo_cell.tenant_cells (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL CHECK (length(btrim(tenant_id)) > 0),
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cell, tenant_id)
);

CREATE TABLE IF NOT EXISTS hartevo_cell.projects (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL CHECK (length(btrim(project_id)) > 0),
    encryption_mode TEXT NOT NULL
        CHECK (encryption_mode IN ('personal_e2ee', 'team_envelope')),
    remote_execution_opt_in BOOLEAN NOT NULL DEFAULT FALSE,
    metadata_digest TEXT NOT NULL CHECK (metadata_digest ~ '^[0-9a-f]{64}$'),
    revision BIGINT NOT NULL CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cell, tenant_id, project_id),
    FOREIGN KEY (cell, tenant_id)
        REFERENCES hartevo_cell.tenant_cells (cell, tenant_id),
    CHECK (encryption_mode <> 'personal_e2ee' OR NOT remote_execution_opt_in),
    CHECK (created_at <= updated_at)
);

CREATE TABLE IF NOT EXISTS hartevo_cell.remote_worker_transport_registrations (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    mission_id TEXT NOT NULL CHECK (length(btrim(mission_id)) > 0),
    registration_id TEXT NOT NULL CHECK (length(btrim(registration_id)) > 0),
    dispatch_registration_id TEXT NOT NULL
        CHECK (dispatch_registration_id ~ '^[0-9a-f]{64}$'),
    worker_id TEXT NOT NULL CHECK (length(btrim(worker_id)) > 0),
    plugin_id TEXT NOT NULL CHECK (length(btrim(plugin_id)) > 0),
    service_id TEXT NOT NULL CHECK (length(btrim(service_id)) > 0),
    service_version BIGINT NOT NULL CHECK (service_version > 0),
    service_contract_digest TEXT NOT NULL
        CHECK (service_contract_digest ~ '^[0-9a-f]{64}$'),
    provider_id TEXT NOT NULL CHECK (length(btrim(provider_id)) > 0),
    provider_version BIGINT NOT NULL CHECK (provider_version > 0),
    provider_implementation_digest TEXT NOT NULL
        CHECK (provider_implementation_digest ~ '^[0-9a-f]{64}$'),
    consumer_id TEXT NOT NULL CHECK (length(btrim(consumer_id)) > 0),
    consumer_min_service_version BIGINT NOT NULL
        CHECK (consumer_min_service_version > 0),
    consumer_descriptor_digest TEXT NOT NULL
        CHECK (consumer_descriptor_digest ~ '^[0-9a-f]{64}$'),
    idempotency_key TEXT NOT NULL CHECK (idempotency_key ~ '^[0-9a-f]{64}$'),
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    state TEXT NOT NULL CHECK (state IN ('mounted', 'unmounted', 'revoked')),
    mounted_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    unmounted_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revocation_reason_digest TEXT
        CHECK (revocation_reason_digest IS NULL
            OR revocation_reason_digest ~ '^[0-9a-f]{64}$'),
    revision BIGINT NOT NULL CHECK (revision > 0),
    PRIMARY KEY (cell, tenant_id, project_id, mission_id, registration_id),
    UNIQUE (cell, tenant_id, project_id, mission_id, idempotency_key),
    FOREIGN KEY (cell, tenant_id, project_id)
        REFERENCES hartevo_cell.projects (cell, tenant_id, project_id),
    CHECK (mounted_at <= updated_at),
    CHECK (state <> 'mounted' OR (unmounted_at IS NULL AND revoked_at IS NULL)),
    CHECK (state <> 'unmounted' OR (unmounted_at IS NOT NULL AND revoked_at IS NULL)),
    CHECK (state <> 'revoked' OR revoked_at IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS hartevo_cell.remote_worker_dispatch_registrations (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    mission_id TEXT NOT NULL CHECK (length(btrim(mission_id)) > 0),
    registration_id TEXT NOT NULL CHECK (length(btrim(registration_id)) > 0),
    dispatch_registration_id TEXT NOT NULL
        CHECK (dispatch_registration_id ~ '^[0-9a-f]{64}$'),
    worker_id TEXT NOT NULL CHECK (length(btrim(worker_id)) > 0),
    registered_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    PRIMARY KEY (cell, tenant_id, project_id, mission_id, dispatch_registration_id),
    UNIQUE (cell, tenant_id, project_id, mission_id, registration_id,
        dispatch_registration_id),
    FOREIGN KEY (cell, tenant_id, project_id, mission_id, registration_id)
        REFERENCES hartevo_cell.remote_worker_transport_registrations
            (cell, tenant_id, project_id, mission_id, registration_id),
    CHECK (registered_at <= updated_at)
);

CREATE TABLE IF NOT EXISTS hartevo_cell.sync_object_versions (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    object_id TEXT NOT NULL CHECK (length(btrim(object_id)) > 0),
    object_kind TEXT NOT NULL CHECK (length(btrim(object_kind)) > 0),
    revision BIGINT NOT NULL CHECK (revision > 0),
    key_version BIGINT NOT NULL CHECK (key_version > 0),
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 12),
    ciphertext BYTEA NOT NULL
        CHECK (octet_length(ciphertext) BETWEEN 16 AND 16777216),
    aad_digest TEXT NOT NULL CHECK (aad_digest ~ '^[0-9a-f]{64}$'),
    content_digest TEXT NOT NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
    tombstone BOOLEAN NOT NULL DEFAULT FALSE,
    recorded_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cell, tenant_id, project_id, object_id, revision),
    FOREIGN KEY (cell, tenant_id, project_id)
        REFERENCES hartevo_cell.projects (cell, tenant_id, project_id)
);

CREATE TABLE IF NOT EXISTS hartevo_cell.sync_object_heads (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    object_id TEXT NOT NULL,
    object_kind TEXT NOT NULL,
    current_revision BIGINT NOT NULL CHECK (current_revision > 0),
    key_version BIGINT NOT NULL CHECK (key_version > 0),
    content_digest TEXT NOT NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
    tombstone BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cell, tenant_id, project_id, object_id),
    FOREIGN KEY (cell, tenant_id, project_id, object_id, current_revision)
        REFERENCES hartevo_cell.sync_object_versions
            (cell, tenant_id, project_id, object_id, revision)
);

CREATE TABLE IF NOT EXISTS hartevo_cell.device_sync_registrations (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    region TEXT NOT NULL CHECK (region IN ('us', 'eu')),
    mission_scope_digest TEXT NOT NULL CHECK (mission_scope_digest ~ '^[0-9a-f]{64}$'),
    device_id TEXT NOT NULL CHECK (length(btrim(device_id)) > 0),
    project_key_generation BIGINT NOT NULL CHECK (project_key_generation > 0),
    keyring_manifest_digest TEXT NOT NULL
        CHECK (keyring_manifest_digest ~ '^[0-9a-f]{64}$'),
    registration_version BIGINT NOT NULL CHECK (registration_version > 0),
    registration_digest TEXT NOT NULL CHECK (registration_digest ~ '^[0-9a-f]{64}$'),
    device_public_key_digest TEXT NOT NULL
        CHECK (device_public_key_digest ~ '^[0-9a-f]{64}$'),
    service_id TEXT NOT NULL CHECK (length(btrim(service_id)) > 0),
    service_version BIGINT NOT NULL CHECK (service_version > 0),
    service_contract_digest TEXT NOT NULL
        CHECK (service_contract_digest ~ '^[0-9a-f]{64}$'),
    provider_id TEXT NOT NULL CHECK (length(btrim(provider_id)) > 0),
    provider_region TEXT NOT NULL CHECK (provider_region IN ('us', 'eu')),
    provider_version BIGINT NOT NULL CHECK (provider_version > 0),
    provider_implementation_digest TEXT NOT NULL
        CHECK (provider_implementation_digest ~ '^[0-9a-f]{64}$'),
    consumer_id TEXT NOT NULL CHECK (length(btrim(consumer_id)) > 0),
    consumer_min_service_version BIGINT NOT NULL CHECK (consumer_min_service_version > 0),
    consumer_descriptor_digest TEXT NOT NULL
        CHECK (consumer_descriptor_digest ~ '^[0-9a-f]{64}$'),
    idempotency_key TEXT NOT NULL CHECK (idempotency_key ~ '^[0-9a-f]{64}$'),
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    state TEXT NOT NULL CHECK (state IN ('attached', 'unmounted', 'revoked')),
    attached_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    released_at TIMESTAMPTZ,
    release_reason_digest TEXT
        CHECK (release_reason_digest IS NULL OR release_reason_digest ~ '^[0-9a-f]{64}$'),
    revision BIGINT NOT NULL CHECK (revision > 0),
    PRIMARY KEY (cell, tenant_id, project_id, device_id, registration_version),
    UNIQUE (cell, tenant_id, project_id, registration_digest),
    UNIQUE (cell, tenant_id, project_id, idempotency_key),
    FOREIGN KEY (cell, tenant_id, project_id)
        REFERENCES hartevo_cell.projects (cell, tenant_id, project_id),
    CHECK (region = cell AND provider_region = region),
    CHECK (attached_at <= updated_at),
    CHECK (
        (state = 'attached' AND revision = 1 AND released_at IS NULL
            AND release_reason_digest IS NULL)
        OR (state IN ('unmounted', 'revoked') AND revision = 2
            AND released_at = updated_at AND release_reason_digest IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS hartevo_cell.device_sync_document_versions (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    document_id TEXT NOT NULL CHECK (length(btrim(document_id)) > 0),
    object_kind TEXT NOT NULL CHECK (length(btrim(object_kind)) > 0),
    revision BIGINT NOT NULL CHECK (revision > 0),
    project_key_generation BIGINT NOT NULL CHECK (project_key_generation > 0),
    keyring_manifest_digest TEXT NOT NULL
        CHECK (keyring_manifest_digest ~ '^[0-9a-f]{64}$'),
    registration_version BIGINT NOT NULL CHECK (registration_version > 0),
    registration_digest TEXT NOT NULL CHECK (registration_digest ~ '^[0-9a-f]{64}$'),
    key_version BIGINT NOT NULL CHECK (key_version > 0),
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 12),
    ciphertext BYTEA NOT NULL
        CHECK (octet_length(ciphertext) BETWEEN 16 AND 16777216),
    aad_digest TEXT NOT NULL CHECK (aad_digest ~ '^[0-9a-f]{64}$'),
    content_digest TEXT NOT NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
    tombstone BOOLEAN NOT NULL DEFAULT FALSE,
    recorded_at TIMESTAMPTZ NOT NULL,
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    head_digest TEXT NOT NULL CHECK (head_digest ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (cell, tenant_id, project_id, document_id, revision),
    FOREIGN KEY (cell, tenant_id, project_id)
        REFERENCES hartevo_cell.projects (cell, tenant_id, project_id),
    CHECK (tombstone = FALSE OR revision > 1)
);

CREATE TABLE IF NOT EXISTS hartevo_cell.device_sync_document_heads (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    document_id TEXT NOT NULL CHECK (length(btrim(document_id)) > 0),
    object_kind TEXT NOT NULL CHECK (length(btrim(object_kind)) > 0),
    current_revision BIGINT NOT NULL CHECK (current_revision > 0),
    project_key_generation BIGINT NOT NULL CHECK (project_key_generation > 0),
    keyring_manifest_digest TEXT NOT NULL
        CHECK (keyring_manifest_digest ~ '^[0-9a-f]{64}$'),
    registration_version BIGINT NOT NULL CHECK (registration_version > 0),
    registration_digest TEXT NOT NULL CHECK (registration_digest ~ '^[0-9a-f]{64}$'),
    key_version BIGINT NOT NULL CHECK (key_version > 0),
    content_digest TEXT NOT NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
    tombstone BOOLEAN NOT NULL DEFAULT FALSE,
    head_digest TEXT NOT NULL CHECK (head_digest ~ '^[0-9a-f]{64}$'),
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cell, tenant_id, project_id, document_id),
    FOREIGN KEY (cell, tenant_id, project_id, document_id, current_revision)
        REFERENCES hartevo_cell.device_sync_document_versions
            (cell, tenant_id, project_id, document_id, revision)
);

CREATE TABLE IF NOT EXISTS hartevo_cell.device_sync_event_log (
    sequence BIGSERIAL PRIMARY KEY,
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN (
        'attached', 'head_advanced', 'unmounted', 'revoked', 'crash_reclaimed',
        'stale_generation_reclaimed')),
    resource_id TEXT NOT NULL CHECK (length(btrim(resource_id)) > 0),
    device_id TEXT NOT NULL CHECK (length(btrim(device_id)) > 0),
    mission_scope_digest TEXT NOT NULL CHECK (mission_scope_digest ~ '^[0-9a-f]{64}$'),
    project_key_generation BIGINT NOT NULL CHECK (project_key_generation > 0),
    keyring_manifest_digest TEXT NOT NULL
        CHECK (keyring_manifest_digest ~ '^[0-9a-f]{64}$'),
    registration_version BIGINT NOT NULL CHECK (registration_version > 0),
    registration_digest TEXT NOT NULL CHECK (registration_digest ~ '^[0-9a-f]{64}$'),
    document_id TEXT,
    result_revision BIGINT CHECK (result_revision IS NULL OR result_revision > 0),
    result_head_digest TEXT
        CHECK (result_head_digest IS NULL OR result_head_digest ~ '^[0-9a-f]{64}$'),
    operation_id_digest TEXT NOT NULL CHECK (operation_id_digest ~ '^[0-9a-f]{64}$'),
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    recorded_at TIMESTAMPTZ NOT NULL,
    event_digest TEXT NOT NULL CHECK (event_digest ~ '^[0-9a-f]{64}$'),
    UNIQUE (cell, tenant_id, project_id, operation_id_digest),
    FOREIGN KEY (cell, tenant_id, project_id)
        REFERENCES hartevo_cell.projects (cell, tenant_id, project_id),
    CHECK (
        (event_type = 'head_advanced' AND document_id IS NOT NULL
            AND result_revision IS NOT NULL AND result_head_digest IS NOT NULL)
        OR (event_type <> 'head_advanced' AND document_id IS NULL
            AND result_revision IS NULL AND result_head_digest IS NULL)
    )
);

CREATE TABLE IF NOT EXISTS hartevo_cell.domain_events (
    sequence BIGSERIAL PRIMARY KEY,
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    aggregate_type TEXT NOT NULL CHECK (length(btrim(aggregate_type)) > 0),
    aggregate_id TEXT NOT NULL CHECK (length(btrim(aggregate_id)) > 0),
    event_type TEXT NOT NULL CHECK (length(btrim(event_type)) > 0),
    object_revision BIGINT NOT NULL CHECK (object_revision > 0),
    key_version BIGINT NOT NULL CHECK (key_version > 0),
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 12),
    payload_ciphertext BYTEA NOT NULL
        CHECK (octet_length(payload_ciphertext) BETWEEN 16 AND 16777216),
    aad_digest TEXT NOT NULL CHECK (aad_digest ~ '^[0-9a-f]{64}$'),
    content_digest TEXT NOT NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
    tombstone BOOLEAN NOT NULL DEFAULT FALSE,
    recorded_at TIMESTAMPTZ NOT NULL,
    UNIQUE (cell, tenant_id, project_id, sequence),
    FOREIGN KEY (cell, tenant_id, project_id)
        REFERENCES hartevo_cell.projects (cell, tenant_id, project_id)
);

CREATE TABLE IF NOT EXISTS hartevo_cell.outbox_messages (
    sequence BIGSERIAL PRIMARY KEY,
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    event_sequence BIGINT NOT NULL,
    event_type TEXT NOT NULL CHECK (length(btrim(event_type)) > 0),
    object_id TEXT NOT NULL CHECK (length(btrim(object_id)) > 0),
    object_revision BIGINT NOT NULL CHECK (object_revision > 0),
    key_version BIGINT NOT NULL CHECK (key_version > 0),
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 12),
    payload_ciphertext BYTEA NOT NULL
        CHECK (octet_length(payload_ciphertext) BETWEEN 16 AND 16777216),
    aad_digest TEXT NOT NULL CHECK (aad_digest ~ '^[0-9a-f]{64}$'),
    content_digest TEXT NOT NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
    tombstone BOOLEAN NOT NULL DEFAULT FALSE,
    idempotency_key TEXT NOT NULL CHECK (length(btrim(idempotency_key)) > 0),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'leased', 'published', 'dead_letter')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at TIMESTAMPTZ NOT NULL,
    lease_owner TEXT,
    lease_generation BIGINT NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
    lease_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    published_at TIMESTAMPTZ,
    UNIQUE (cell, tenant_id, project_id, idempotency_key),
    UNIQUE (cell, tenant_id, project_id, sequence),
    FOREIGN KEY (cell, tenant_id, project_id)
        REFERENCES hartevo_cell.projects (cell, tenant_id, project_id),
    FOREIGN KEY (cell, tenant_id, project_id, event_sequence)
        REFERENCES hartevo_cell.domain_events
            (cell, tenant_id, project_id, sequence),
    CHECK (
        (status = 'leased' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR (status <> 'leased' AND lease_owner IS NULL AND lease_expires_at IS NULL)
    )
);

-- Scheduler coordination records contain only routing metadata, digests and
-- bounded counters. Raw owner/token values and project/runtime content never
-- cross this Cell boundary.
CREATE TABLE IF NOT EXISTS hartevo_cell.scheduler_schedules (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    schedule_id TEXT NOT NULL CHECK (length(btrim(schedule_id)) > 0),
    mission_id_digest TEXT NOT NULL CHECK (mission_id_digest ~ '^[0-9a-fA-F]{64}$'),
    cycle BIGINT NOT NULL CHECK (cycle > 0),
    trigger TEXT NOT NULL CHECK (trigger IN ('interval', 'event', 'interval_or_event')),
    status TEXT NOT NULL CHECK (
        status IN ('pending', 'leased', 'triggered', 'paused', 'expired', 'dead_letter', 'uncertain')
    ),
    next_due_at TIMESTAMPTZ,
    contract_valid_until TIMESTAMPTZ NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    record_json JSONB NOT NULL CHECK (jsonb_typeof(record_json) = 'object'),
    PRIMARY KEY (cell, tenant_id, project_id, schedule_id),
    FOREIGN KEY (cell, tenant_id, project_id)
        REFERENCES hartevo_cell.projects (cell, tenant_id, project_id),
    CHECK (contract_valid_until > COALESCE(next_due_at, contract_valid_until - INTERVAL '1 microsecond'))
);

CREATE TABLE IF NOT EXISTS hartevo_cell.scheduler_leader_leases (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    lease_key_digest TEXT NOT NULL CHECK (lease_key_digest ~ '^[0-9a-fA-F]{64}$'),
    owner_digest TEXT NOT NULL CHECK (owner_digest ~ '^[0-9a-fA-F]{64}$'),
    token_digest TEXT NOT NULL CHECK (token_digest ~ '^[0-9a-fA-F]{64}$'),
    generation BIGINT NOT NULL CHECK (generation > 0),
    claimed_at TIMESTAMPTZ NOT NULL,
    heartbeat_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cell, tenant_id, lease_key_digest),
    FOREIGN KEY (cell, tenant_id)
        REFERENCES hartevo_cell.tenant_cells (cell, tenant_id),
    CHECK (claimed_at <= heartbeat_at AND heartbeat_at < expires_at)
);

CREATE TABLE IF NOT EXISTS hartevo_cell.scheduler_worker_leases (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    schedule_id TEXT NOT NULL,
    worker_id_digest TEXT NOT NULL CHECK (worker_id_digest ~ '^[0-9a-fA-F]{64}$'),
    owner_digest TEXT NOT NULL CHECK (owner_digest ~ '^[0-9a-fA-F]{64}$'),
    token_digest TEXT NOT NULL CHECK (token_digest ~ '^[0-9a-fA-F]{64}$'),
    generation BIGINT NOT NULL CHECK (generation > 0),
    claimed_at TIMESTAMPTZ NOT NULL,
    heartbeat_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cell, tenant_id, project_id, schedule_id, worker_id_digest),
    FOREIGN KEY (cell, tenant_id, project_id, schedule_id)
        REFERENCES hartevo_cell.scheduler_schedules
            (cell, tenant_id, project_id, schedule_id),
    CHECK (claimed_at <= heartbeat_at AND heartbeat_at < expires_at)
);

CREATE TABLE IF NOT EXISTS hartevo_cell.scheduler_tenant_state (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    fairness_weight INTEGER NOT NULL CHECK (fairness_weight > 0 AND fairness_weight <= 1000),
    virtual_finish BIGINT NOT NULL CHECK (virtual_finish >= 0),
    backpressure_state TEXT NOT NULL CHECK (backpressure_state IN ('open', 'soft', 'hard')),
    pending BIGINT NOT NULL CHECK (pending >= 0),
    in_flight BIGINT NOT NULL CHECK (in_flight >= 0),
    max_pending BIGINT NOT NULL CHECK (max_pending > 0),
    max_in_flight BIGINT NOT NULL CHECK (max_in_flight > 0),
    revision BIGINT NOT NULL CHECK (revision > 0),
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cell, tenant_id),
    FOREIGN KEY (cell, tenant_id)
        REFERENCES hartevo_cell.tenant_cells (cell, tenant_id),
    CHECK (pending <= max_pending AND in_flight <= max_in_flight)
);

CREATE TABLE IF NOT EXISTS hartevo_cell.scheduler_lease_takeovers (
    sequence BIGSERIAL PRIMARY KEY,
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT,
    lease_kind TEXT NOT NULL CHECK (lease_kind IN ('leader', 'worker')),
    lease_id_digest TEXT NOT NULL CHECK (lease_id_digest ~ '^[0-9a-fA-F]{64}$'),
    previous_generation BIGINT NOT NULL CHECK (previous_generation > 0),
    generation BIGINT NOT NULL CHECK (generation = previous_generation + 1),
    previous_owner_digest TEXT NOT NULL CHECK (previous_owner_digest ~ '^[0-9a-fA-F]{64}$'),
    owner_digest TEXT NOT NULL CHECK (owner_digest ~ '^[0-9a-fA-F]{64}$'),
    reason TEXT NOT NULL CHECK (reason IN ('expired', 'coordinator_restart', 'explicit')),
    evidence_digest TEXT NOT NULL CHECK (evidence_digest ~ '^[0-9a-fA-F]{64}$'),
    observed_at TIMESTAMPTZ NOT NULL,
    UNIQUE (cell, tenant_id, lease_kind, lease_id_digest, generation),
    FOREIGN KEY (cell, tenant_id)
        REFERENCES hartevo_cell.tenant_cells (cell, tenant_id),
    CHECK (project_id IS NULL OR length(btrim(project_id)) > 0)
);

CREATE TABLE IF NOT EXISTS hartevo_cell.scheduler_attempts (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    schedule_id TEXT NOT NULL,
    attempt_id_digest TEXT NOT NULL CHECK (attempt_id_digest ~ '^[0-9a-fA-F]{64}$'),
    worker_generation BIGINT NOT NULL CHECK (worker_generation > 0),
    surface TEXT NOT NULL CHECK (surface IN ('runtime', 'browser', 'effect')),
    outcome TEXT NOT NULL CHECK (outcome IN ('running', 'succeeded', 'failed', 'uncertain', 'completed')),
    replay TEXT NOT NULL CHECK (replay IN ('allowed', 'suppressed_uncertain', 'suppressed_completed')),
    idempotency_key_digest TEXT NOT NULL CHECK (idempotency_key_digest ~ '^[0-9a-fA-F]{64}$'),
    started_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    record_json JSONB NOT NULL CHECK (jsonb_typeof(record_json) = 'object'),
    PRIMARY KEY (cell, tenant_id, project_id, attempt_id_digest),
    FOREIGN KEY (cell, tenant_id, project_id, schedule_id)
        REFERENCES hartevo_cell.scheduler_schedules
            (cell, tenant_id, project_id, schedule_id),
    CHECK (started_at <= updated_at),
    CHECK (outcome <> 'uncertain' OR replay = 'suppressed_uncertain'),
    CHECK (outcome <> 'completed' OR replay = 'suppressed_completed')
);

CREATE TABLE IF NOT EXISTS hartevo_cell.sync_mutations (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL CHECK (length(btrim(idempotency_key)) > 0),
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    object_id TEXT NOT NULL,
    object_revision BIGINT NOT NULL CHECK (object_revision > 0),
    content_digest TEXT NOT NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
    event_sequence BIGINT NOT NULL,
    outbox_sequence BIGINT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cell, tenant_id, project_id, idempotency_key),
    FOREIGN KEY (cell, tenant_id, project_id)
        REFERENCES hartevo_cell.projects (cell, tenant_id, project_id),
    FOREIGN KEY (cell, tenant_id, project_id, event_sequence)
        REFERENCES hartevo_cell.domain_events
            (cell, tenant_id, project_id, sequence),
    FOREIGN KEY (cell, tenant_id, project_id, outbox_sequence)
        REFERENCES hartevo_cell.outbox_messages
            (cell, tenant_id, project_id, sequence)
);

CREATE TABLE IF NOT EXISTS hartevo_cell.remote_worker_mailbox_messages (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    mission_id TEXT NOT NULL CHECK (length(btrim(mission_id)) > 0),
    task_id TEXT NOT NULL CHECK (length(btrim(task_id)) > 0),
    worker_id TEXT NOT NULL CHECK (length(btrim(worker_id)) > 0),
    payload_key_version BIGINT NOT NULL CHECK (payload_key_version > 0),
    payload_nonce BYTEA NOT NULL CHECK (octet_length(payload_nonce) = 12),
    payload_ciphertext BYTEA NOT NULL
        CHECK (octet_length(payload_ciphertext) BETWEEN 16 AND 16777216),
    payload_aad_digest TEXT NOT NULL CHECK (payload_aad_digest ~ '^[0-9a-f]{64}$'),
    payload_content_digest TEXT NOT NULL CHECK (payload_content_digest ~ '^[0-9a-f]{64}$'),
    idempotency_key TEXT NOT NULL CHECK (idempotency_key ~ '^[0-9a-f]{64}$'),
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'leased', 'completed', 'dead_letter')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    lease_id TEXT,
    lease_generation BIGINT NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
    lease_owner TEXT,
    lease_token_digest TEXT,
    claim_idempotency_key TEXT,
    claim_request_digest TEXT,
    lease_expires_at TIMESTAMPTZ,
    heartbeat_at TIMESTAMPTZ,
    result_digest TEXT,
    completion_idempotency_key TEXT,
    completion_request_digest TEXT,
    completed_at TIMESTAMPTZ,
    enqueued_at TIMESTAMPTZ NOT NULL,
    deadline_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    dispatch_registration_id TEXT
        CHECK (dispatch_registration_id IS NULL
            OR dispatch_registration_id ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (cell, tenant_id, project_id, task_id),
    UNIQUE (cell, tenant_id, project_id, idempotency_key),
    UNIQUE (cell, tenant_id, project_id, claim_idempotency_key),
    UNIQUE (cell, tenant_id, project_id, completion_idempotency_key),
    FOREIGN KEY (cell, tenant_id, project_id)
        REFERENCES hartevo_cell.projects (cell, tenant_id, project_id),
    CHECK (enqueued_at < deadline_at AND enqueued_at <= updated_at),
    CHECK (lease_token_digest IS NULL OR lease_token_digest ~ '^[0-9a-f]{64}$'),
    CHECK (claim_idempotency_key IS NULL OR claim_idempotency_key ~ '^[0-9a-f]{64}$'),
    CHECK (claim_request_digest IS NULL OR claim_request_digest ~ '^[0-9a-f]{64}$'),
    CHECK (result_digest IS NULL OR result_digest ~ '^[0-9a-f]{64}$'),
    CHECK (completion_idempotency_key IS NULL
        OR completion_idempotency_key ~ '^[0-9a-f]{64}$'),
    CHECK (completion_request_digest IS NULL
        OR completion_request_digest ~ '^[0-9a-f]{64}$'),
    CHECK (
        (status = 'pending'
            AND lease_id IS NULL AND lease_generation = 0
            AND lease_owner IS NULL AND lease_token_digest IS NULL
            AND claim_idempotency_key IS NULL AND claim_request_digest IS NULL
            AND lease_expires_at IS NULL AND heartbeat_at IS NULL
            AND result_digest IS NULL AND completion_idempotency_key IS NULL
            AND completion_request_digest IS NULL AND completed_at IS NULL)
        OR (status = 'leased'
            AND attempts > 0 AND lease_id IS NOT NULL
            AND lease_generation > 0 AND lease_owner IS NOT NULL
            AND length(btrim(lease_owner)) > 0
            AND lease_token_digest IS NOT NULL
            AND claim_idempotency_key IS NOT NULL
            AND claim_request_digest IS NOT NULL
            AND lease_expires_at IS NOT NULL AND heartbeat_at IS NOT NULL
            AND lease_expires_at > heartbeat_at
            AND result_digest IS NULL AND completion_idempotency_key IS NULL
            AND completion_request_digest IS NULL AND completed_at IS NULL)
        OR (status = 'completed'
            AND attempts > 0 AND lease_id IS NULL
            AND lease_owner IS NULL AND lease_token_digest IS NULL
            AND claim_idempotency_key IS NOT NULL
            AND claim_request_digest IS NOT NULL
            AND lease_expires_at IS NULL AND heartbeat_at IS NULL
            AND result_digest IS NOT NULL
            AND completion_idempotency_key IS NOT NULL
            AND completion_request_digest IS NOT NULL
            AND completed_at IS NOT NULL AND completed_at >= enqueued_at)
        OR (status = 'dead_letter'
            AND lease_id IS NULL AND lease_owner IS NULL
            AND lease_token_digest IS NULL AND lease_expires_at IS NULL
            AND heartbeat_at IS NULL AND result_digest IS NULL
            AND completion_idempotency_key IS NULL
            AND completion_request_digest IS NULL AND completed_at IS NULL)
    )
);

CREATE TABLE IF NOT EXISTS hartevo_cell.remote_worker_claims (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    claim_idempotency_key TEXT NOT NULL CHECK (claim_idempotency_key ~ '^[0-9a-f]{64}$'),
    claim_request_digest TEXT NOT NULL CHECK (claim_request_digest ~ '^[0-9a-f]{64}$'),
    lease_id TEXT NOT NULL CHECK (length(btrim(lease_id)) > 0),
    lease_generation BIGINT NOT NULL CHECK (lease_generation > 0),
    lease_owner TEXT NOT NULL CHECK (length(btrim(lease_owner)) > 0),
    lease_token_digest TEXT NOT NULL CHECK (lease_token_digest ~ '^[0-9a-f]{64}$'),
    attempts INTEGER NOT NULL CHECK (attempts > 0),
    heartbeat_at TIMESTAMPTZ NOT NULL,
    lease_expires_at TIMESTAMPTZ NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    claimed_at TIMESTAMPTZ NOT NULL,
    dispatch_registration_id TEXT
        CHECK (dispatch_registration_id IS NULL
            OR dispatch_registration_id ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (cell, tenant_id, project_id, claim_idempotency_key),
    UNIQUE (cell, tenant_id, project_id, task_id, lease_generation),
    FOREIGN KEY (cell, tenant_id, project_id, task_id)
        REFERENCES hartevo_cell.remote_worker_mailbox_messages
            (cell, tenant_id, project_id, task_id),
    CHECK (lease_expires_at > heartbeat_at)
);

CREATE TABLE IF NOT EXISTS hartevo_cell.remote_worker_work_requests (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    mission_id TEXT NOT NULL CHECK (length(btrim(mission_id)) > 0),
    task_id TEXT NOT NULL CHECK (length(btrim(task_id)) > 0),
    worker_id TEXT NOT NULL CHECK (length(btrim(worker_id)) > 0),
    dispatch_registration_id TEXT NOT NULL
        CHECK (dispatch_registration_id ~ '^[0-9a-f]{64}$'),
    project_key_generation BIGINT NOT NULL CHECK (project_key_generation > 0),
    mission_generation BIGINT NOT NULL CHECK (mission_generation > 0),
    mission_version BIGINT NOT NULL CHECK (mission_version > 0),
    mission_digest TEXT NOT NULL CHECK (mission_digest ~ '^[0-9a-f]{64}$'),
    input_key_version BIGINT NOT NULL CHECK (input_key_version > 0),
    input_nonce BYTEA NOT NULL CHECK (octet_length(input_nonce) = 12),
    input_ciphertext BYTEA NOT NULL
        CHECK (octet_length(input_ciphertext) BETWEEN 16 AND 524288),
    input_aad_digest TEXT NOT NULL CHECK (input_aad_digest ~ '^[0-9a-f]{64}$'),
    input_content_digest TEXT NOT NULL CHECK (input_content_digest ~ '^[0-9a-f]{64}$'),
    idempotency_key TEXT NOT NULL CHECK (idempotency_key ~ '^[0-9a-f]{64}$'),
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'leased', 'completed', 'cancelled',
                          'uncertain', 'dead_letter')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    lease_id TEXT,
    lease_generation BIGINT NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
    lease_owner TEXT,
    lease_token_digest TEXT,
    claim_idempotency_key TEXT,
    claim_request_digest TEXT,
    lease_expires_at TIMESTAMPTZ,
    heartbeat_at TIMESTAMPTZ,
    completion_idempotency_key TEXT,
    completion_request_digest TEXT,
    completed_at TIMESTAMPTZ,
    terminal_idempotency_key TEXT,
    terminal_request_digest TEXT,
    terminal_reason_digest TEXT,
    terminal_at TIMESTAMPTZ,
    enqueued_at TIMESTAMPTZ NOT NULL,
    deadline_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    PRIMARY KEY (cell, tenant_id, project_id, task_id),
    UNIQUE (cell, tenant_id, project_id, idempotency_key),
    FOREIGN KEY (cell, tenant_id, project_id)
        REFERENCES hartevo_cell.projects (cell, tenant_id, project_id),
    CHECK (enqueued_at < deadline_at AND enqueued_at <= updated_at),
    CHECK (lease_token_digest IS NULL OR lease_token_digest ~ '^[0-9a-f]{64}$'),
    CHECK (claim_idempotency_key IS NULL OR claim_idempotency_key ~ '^[0-9a-f]{64}$'),
    CHECK (claim_request_digest IS NULL OR claim_request_digest ~ '^[0-9a-f]{64}$'),
    CHECK (completion_idempotency_key IS NULL
        OR completion_idempotency_key ~ '^[0-9a-f]{64}$'),
    CHECK (completion_request_digest IS NULL
        OR completion_request_digest ~ '^[0-9a-f]{64}$'),
    CHECK (terminal_idempotency_key IS NULL
        OR terminal_idempotency_key ~ '^[0-9a-f]{64}$'),
    CHECK (terminal_request_digest IS NULL
        OR terminal_request_digest ~ '^[0-9a-f]{64}$'),
    CHECK (terminal_reason_digest IS NULL
        OR terminal_reason_digest ~ '^[0-9a-f]{64}$'),
    CHECK (
        (status = 'pending'
            AND attempts = 0 AND lease_id IS NULL AND lease_generation = 0
            AND lease_owner IS NULL AND lease_token_digest IS NULL
            AND claim_idempotency_key IS NULL AND claim_request_digest IS NULL
            AND lease_expires_at IS NULL AND heartbeat_at IS NULL
            AND completion_idempotency_key IS NULL AND completion_request_digest IS NULL
            AND completed_at IS NULL AND terminal_idempotency_key IS NULL
            AND terminal_request_digest IS NULL AND terminal_reason_digest IS NULL
            AND terminal_at IS NULL)
        OR (status = 'leased'
            AND attempts > 0 AND lease_id IS NOT NULL AND lease_generation > 0
            AND lease_owner IS NOT NULL AND length(btrim(lease_owner)) > 0
            AND lease_token_digest IS NOT NULL AND claim_idempotency_key IS NOT NULL
            AND claim_request_digest IS NOT NULL AND lease_expires_at IS NOT NULL
            AND heartbeat_at IS NOT NULL AND lease_expires_at > heartbeat_at
            AND completion_idempotency_key IS NULL AND completion_request_digest IS NULL
            AND completed_at IS NULL AND terminal_idempotency_key IS NULL
            AND terminal_request_digest IS NULL AND terminal_reason_digest IS NULL
            AND terminal_at IS NULL)
        OR (status = 'completed'
            AND attempts > 0 AND lease_id IS NULL AND lease_generation = 0
            AND lease_owner IS NULL AND lease_token_digest IS NULL
            AND claim_idempotency_key IS NOT NULL AND claim_request_digest IS NOT NULL
            AND lease_expires_at IS NULL AND heartbeat_at IS NULL
            AND completion_idempotency_key IS NOT NULL
            AND completion_request_digest IS NOT NULL AND completed_at IS NOT NULL
            AND terminal_idempotency_key IS NULL AND terminal_request_digest IS NULL
            AND terminal_reason_digest IS NULL AND terminal_at IS NULL)
        OR (status IN ('cancelled', 'uncertain', 'dead_letter')
            AND lease_id IS NULL AND lease_generation = 0
            AND lease_owner IS NULL AND lease_token_digest IS NULL
            AND lease_expires_at IS NULL AND heartbeat_at IS NULL
            AND completion_idempotency_key IS NULL AND completion_request_digest IS NULL
            AND completed_at IS NULL AND terminal_idempotency_key IS NOT NULL
            AND terminal_request_digest IS NOT NULL AND terminal_reason_digest IS NOT NULL
            AND terminal_at IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS hartevo_cell.remote_worker_result_receipts (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    mission_id TEXT NOT NULL CHECK (length(btrim(mission_id)) > 0),
    task_id TEXT NOT NULL,
    project_key_generation BIGINT NOT NULL CHECK (project_key_generation > 0),
    mission_generation BIGINT NOT NULL CHECK (mission_generation > 0),
    mission_version BIGINT NOT NULL CHECK (mission_version > 0),
    mission_digest TEXT NOT NULL CHECK (mission_digest ~ '^[0-9a-f]{64}$'),
    dispatch_registration_id TEXT NOT NULL
        CHECK (dispatch_registration_id ~ '^[0-9a-f]{64}$'),
    lease_id TEXT NOT NULL CHECK (length(btrim(lease_id)) > 0),
    lease_generation BIGINT NOT NULL CHECK (lease_generation > 0),
    lease_owner TEXT NOT NULL CHECK (length(btrim(lease_owner)) > 0),
    provider_id TEXT NOT NULL CHECK (length(btrim(provider_id)) > 0),
    provider_implementation_digest TEXT NOT NULL
        CHECK (provider_implementation_digest ~ '^[0-9a-f]{64}$'),
    service_contract_digest TEXT NOT NULL CHECK (service_contract_digest ~ '^[0-9a-f]{64}$'),
    current_commit_digest TEXT NOT NULL CHECK (current_commit_digest ~ '^[0-9a-f]{64}$'),
    output_key_version BIGINT NOT NULL CHECK (output_key_version > 0),
    output_nonce BYTEA NOT NULL CHECK (octet_length(output_nonce) = 12),
    output_ciphertext BYTEA NOT NULL
        CHECK (octet_length(output_ciphertext) BETWEEN 16 AND 2097152),
    output_aad_digest TEXT NOT NULL CHECK (output_aad_digest ~ '^[0-9a-f]{64}$'),
    output_content_digest TEXT NOT NULL CHECK (output_content_digest ~ '^[0-9a-f]{64}$'),
    evidence_digest TEXT NOT NULL CHECK (evidence_digest ~ '^[0-9a-f]{64}$'),
    effect_receipt_digest TEXT
        CHECK (effect_receipt_digest IS NULL OR effect_receipt_digest ~ '^[0-9a-f]{64}$'),
    outcome_link_digest TEXT
        CHECK (outcome_link_digest IS NULL OR outcome_link_digest ~ '^[0-9a-f]{64}$'),
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    result_digest TEXT NOT NULL CHECK (result_digest ~ '^[0-9a-f]{64}$'),
    receipt_digest TEXT NOT NULL CHECK (receipt_digest ~ '^[0-9a-f]{64}$'),
    completion_idempotency_key TEXT NOT NULL CHECK (completion_idempotency_key ~ '^[0-9a-f]{64}$'),
    completed_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    PRIMARY KEY (cell, tenant_id, project_id, task_id),
    UNIQUE (cell, tenant_id, project_id, receipt_digest),
    FOREIGN KEY (cell, tenant_id, project_id, task_id)
        REFERENCES hartevo_cell.remote_worker_work_requests
            (cell, tenant_id, project_id, task_id),
    CHECK (completed_at <= recorded_at)
);

CREATE TABLE IF NOT EXISTS hartevo_cell.remote_worker_work_log (
    sequence BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    mission_id TEXT NOT NULL CHECK (length(btrim(mission_id)) > 0),
    task_id TEXT NOT NULL,
    operation_id_digest TEXT NOT NULL CHECK (operation_id_digest ~ '^[0-9a-f]{64}$'),
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    event_type TEXT NOT NULL CHECK (event_type IN (
        'enqueued', 'claimed', 'takeover', 'heartbeat', 'completed',
        'cancelled', 'uncertain', 'dead_letter')),
    project_key_generation BIGINT NOT NULL CHECK (project_key_generation > 0),
    mission_generation BIGINT NOT NULL CHECK (mission_generation > 0),
    mission_version BIGINT NOT NULL CHECK (mission_version > 0),
    mission_digest TEXT NOT NULL CHECK (mission_digest ~ '^[0-9a-f]{64}$'),
    lease_id TEXT,
    lease_generation BIGINT NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
    lease_owner TEXT,
    lease_token_digest TEXT
        CHECK (lease_token_digest IS NULL OR lease_token_digest ~ '^[0-9a-f]{64}$'),
    lease_expires_at TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    revision BIGINT NOT NULL CHECK (revision >= 0),
    reason_digest TEXT CHECK (reason_digest IS NULL OR reason_digest ~ '^[0-9a-f]{64}$'),
    result_receipt_digest TEXT
        CHECK (result_receipt_digest IS NULL OR result_receipt_digest ~ '^[0-9a-f]{64}$'),
    recorded_at TIMESTAMPTZ NOT NULL,
    event_digest TEXT NOT NULL CHECK (event_digest ~ '^[0-9a-f]{64}$'),
    UNIQUE (cell, tenant_id, project_id, operation_id_digest),
    FOREIGN KEY (cell, tenant_id, project_id, task_id)
        REFERENCES hartevo_cell.remote_worker_work_requests
            (cell, tenant_id, project_id, task_id)
);

CREATE TABLE IF NOT EXISTS hartevo_cell.device_public_key_versions (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    device_id TEXT NOT NULL CHECK (length(btrim(device_id)) > 0),
    revision BIGINT NOT NULL CHECK (revision > 0),
    algorithm TEXT NOT NULL
        CHECK (algorithm = 'x25519_hkdf_sha256_aes256_gcm_v1'),
    public_key BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
    public_key_digest TEXT NOT NULL CHECK (public_key_digest ~ '^[0-9a-f]{64}$'),
    authorized_by TEXT NOT NULL CHECK (length(btrim(authorized_by)) > 0),
    authorization_evidence_digest TEXT NOT NULL
        CHECK (authorization_evidence_digest ~ '^[0-9a-f]{64}$'),
    idempotency_key TEXT NOT NULL CHECK (idempotency_key ~ '^[0-9a-f]{64}$'),
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    registered_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    PRIMARY KEY (cell, tenant_id, project_id, device_id, revision),
    UNIQUE (cell, tenant_id, project_id, idempotency_key),
    FOREIGN KEY (cell, tenant_id, project_id)
        REFERENCES hartevo_cell.projects (cell, tenant_id, project_id),
    CHECK (registered_at <= updated_at),
    CHECK (revoked_at IS NULL OR revoked_at = updated_at)
);

CREATE TABLE IF NOT EXISTS hartevo_cell.device_public_key_heads (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    current_revision BIGINT NOT NULL CHECK (current_revision > 0),
    public_key_digest TEXT NOT NULL CHECK (public_key_digest ~ '^[0-9a-f]{64}$'),
    revoked_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cell, tenant_id, project_id, device_id),
    FOREIGN KEY (cell, tenant_id, project_id, device_id, current_revision)
        REFERENCES hartevo_cell.device_public_key_versions
            (cell, tenant_id, project_id, device_id, revision)
);

CREATE TABLE IF NOT EXISTS hartevo_cell.keyring_bootstrap_versions (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    keyring_revision BIGINT NOT NULL CHECK (keyring_revision > 0),
    previous_keyring_revision BIGINT,
    manifest_digest TEXT NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    bootstrap_json JSONB NOT NULL CHECK (jsonb_typeof(bootstrap_json) = 'object'),
    published_by TEXT NOT NULL CHECK (length(btrim(published_by)) > 0),
    authorizing_envelope_digest TEXT NOT NULL
        CHECK (authorizing_envelope_digest ~ '^[0-9a-f]{64}$'),
    authorization_evidence_digest TEXT NOT NULL
        CHECK (authorization_evidence_digest ~ '^[0-9a-f]{64}$'),
    idempotency_key TEXT NOT NULL CHECK (idempotency_key ~ '^[0-9a-f]{64}$'),
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    published_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cell, tenant_id, project_id, keyring_revision),
    UNIQUE (cell, tenant_id, project_id, idempotency_key),
    FOREIGN KEY (cell, tenant_id, project_id)
        REFERENCES hartevo_cell.projects (cell, tenant_id, project_id),
    CHECK (
        previous_keyring_revision IS NULL
        OR (previous_keyring_revision > 0 AND previous_keyring_revision < keyring_revision)
    )
);

CREATE TABLE IF NOT EXISTS hartevo_cell.keyring_bootstrap_heads (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    current_keyring_revision BIGINT NOT NULL CHECK (current_keyring_revision > 0),
    manifest_digest TEXT NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cell, tenant_id, project_id),
    FOREIGN KEY (cell, tenant_id, project_id, current_keyring_revision)
        REFERENCES hartevo_cell.keyring_bootstrap_versions
            (cell, tenant_id, project_id, keyring_revision)
);

CREATE TABLE IF NOT EXISTS hartevo_cell.device_handoff_grants (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    grant_id TEXT NOT NULL CHECK (length(btrim(grant_id)) > 0),
    project_mode TEXT NOT NULL
        CHECK (project_mode IN ('personal_e2ee', 'team_envelope')),
    source_recipient TEXT NOT NULL CHECK (length(btrim(source_recipient)) > 0),
    source_envelope_digest TEXT NOT NULL
        CHECK (source_envelope_digest ~ '^[0-9a-f]{64}$'),
    source_keyring_manifest_digest TEXT NOT NULL
        CHECK (source_keyring_manifest_digest ~ '^[0-9a-f]{64}$'),
    target_device_id TEXT NOT NULL CHECK (length(btrim(target_device_id)) > 0),
    target_public_key_digest TEXT NOT NULL
        CHECK (target_public_key_digest ~ '^[0-9a-f]{64}$'),
    key_version BIGINT NOT NULL CHECK (key_version > 0),
    expected_keyring_revision BIGINT NOT NULL CHECK (expected_keyring_revision > 0),
    algorithm TEXT NOT NULL
        CHECK (algorithm = 'x25519_hkdf_sha256_aes256_gcm_v1'),
    sender_ephemeral_public_key BYTEA NOT NULL
        CHECK (octet_length(sender_ephemeral_public_key) = 32),
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 12),
    ciphertext BYTEA NOT NULL CHECK (octet_length(ciphertext) = 48),
    aad_digest TEXT NOT NULL CHECK (aad_digest ~ '^[0-9a-f]{64}$'),
    content_digest TEXT NOT NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
    authorized_by TEXT NOT NULL CHECK (length(btrim(authorized_by)) > 0),
    authorization_evidence_digest TEXT NOT NULL
        CHECK (authorization_evidence_digest ~ '^[0-9a-f]{64}$'),
    intent_digest TEXT NOT NULL CHECK (intent_digest ~ '^[0-9a-f]{64}$'),
    idempotency_key TEXT NOT NULL CHECK (idempotency_key ~ '^[0-9a-f]{64}$'),
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    grant_json JSONB NOT NULL CHECK (jsonb_typeof(grant_json) = 'object'),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cell, tenant_id, project_id, grant_id),
    UNIQUE (cell, tenant_id, project_id, idempotency_key),
    FOREIGN KEY (cell, tenant_id, project_id)
        REFERENCES hartevo_cell.projects (cell, tenant_id, project_id),
    CHECK (created_at < expires_at)
);

CREATE TABLE IF NOT EXISTS hartevo_cell.device_handoff_revocations (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    revoked_by TEXT NOT NULL CHECK (length(btrim(revoked_by)) > 0),
    authorization_evidence_digest TEXT NOT NULL
        CHECK (authorization_evidence_digest ~ '^[0-9a-f]{64}$'),
    idempotency_key TEXT NOT NULL CHECK (idempotency_key ~ '^[0-9a-f]{64}$'),
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    revoked_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cell, tenant_id, project_id, grant_id),
    UNIQUE (cell, tenant_id, project_id, idempotency_key),
    FOREIGN KEY (cell, tenant_id, project_id, grant_id)
        REFERENCES hartevo_cell.device_handoff_grants
            (cell, tenant_id, project_id, grant_id)
);

CREATE TABLE IF NOT EXISTS hartevo_cell.device_handoff_claims (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    claim_id TEXT NOT NULL CHECK (length(btrim(claim_id)) > 0),
    target_device_id TEXT NOT NULL CHECK (length(btrim(target_device_id)) > 0),
    target_public_key_digest TEXT NOT NULL
        CHECK (target_public_key_digest ~ '^[0-9a-f]{64}$'),
    idempotency_key TEXT NOT NULL CHECK (idempotency_key ~ '^[0-9a-f]{64}$'),
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    claim_json JSONB NOT NULL CHECK (jsonb_typeof(claim_json) = 'object'),
    claimed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cell, tenant_id, project_id, grant_id),
    UNIQUE (cell, tenant_id, project_id, claim_id),
    UNIQUE (cell, tenant_id, project_id, idempotency_key),
    FOREIGN KEY (cell, tenant_id, project_id, grant_id)
        REFERENCES hartevo_cell.device_handoff_grants
            (cell, tenant_id, project_id, grant_id)
);

CREATE TABLE IF NOT EXISTS hartevo_cell.device_handoff_consumptions (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    claim_id TEXT NOT NULL CHECK (length(btrim(claim_id)) > 0),
    receipt_id TEXT NOT NULL CHECK (length(btrim(receipt_id)) > 0),
    target_device_id TEXT NOT NULL CHECK (length(btrim(target_device_id)) > 0),
    target_public_key_digest TEXT NOT NULL
        CHECK (target_public_key_digest ~ '^[0-9a-f]{64}$'),
    key_version BIGINT NOT NULL CHECK (key_version > 0),
    attachment_id TEXT NOT NULL CHECK (length(btrim(attachment_id)) > 0),
    result_keyring_revision BIGINT NOT NULL CHECK (result_keyring_revision > 0),
    receipt_digest TEXT NOT NULL CHECK (receipt_digest ~ '^[0-9a-f]{64}$'),
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    consumed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cell, tenant_id, project_id, grant_id),
    UNIQUE (cell, tenant_id, project_id, receipt_id),
    FOREIGN KEY (cell, tenant_id, project_id, grant_id)
        REFERENCES hartevo_cell.device_handoff_grants
            (cell, tenant_id, project_id, grant_id),
    FOREIGN KEY (cell, tenant_id, project_id, claim_id)
        REFERENCES hartevo_cell.device_handoff_claims
            (cell, tenant_id, project_id, claim_id)
);

CREATE TABLE IF NOT EXISTS hartevo_cell.effect_permission_fence_versions (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    fence_kind TEXT NOT NULL
        CHECK (fence_kind IN ('connection', 'consent', 'conversation', 'creator_contact')),
    primary_id TEXT NOT NULL CHECK (length(btrim(primary_id)) > 0),
    secondary_id TEXT NOT NULL DEFAULT '',
    registry_revision BIGINT NOT NULL CHECK (registry_revision > 0),
    primary_revision BIGINT NOT NULL CHECK (primary_revision > 0),
    secondary_revision BIGINT NOT NULL DEFAULT 0 CHECK (secondary_revision >= 0),
    control_generation BIGINT NOT NULL DEFAULT 0 CHECK (control_generation >= 0),
    evidence_digest TEXT NOT NULL CHECK (evidence_digest ~ '^[0-9a-f]{64}$'),
    active BOOLEAN NOT NULL,
    idempotency_key TEXT NOT NULL CHECK (idempotency_key ~ '^[0-9a-f]{64}$'),
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    recorded_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (
        cell, tenant_id, project_id, fence_kind, primary_id, secondary_id,
        registry_revision
    ),
    UNIQUE (cell, tenant_id, project_id, idempotency_key),
    FOREIGN KEY (cell, tenant_id, project_id)
        REFERENCES hartevo_cell.projects (cell, tenant_id, project_id),
    CHECK (
        (fence_kind IN ('connection', 'consent')
            AND secondary_id = '' AND secondary_revision = 0 AND control_generation = 0)
        OR (fence_kind = 'conversation'
            AND secondary_id = '' AND secondary_revision = 0 AND control_generation > 0)
        OR (fence_kind = 'creator_contact'
            AND length(btrim(secondary_id)) > 0
            AND secondary_revision > 0 AND control_generation = 0)
    )
);

CREATE TABLE IF NOT EXISTS hartevo_cell.effect_permission_fence_heads (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    fence_kind TEXT NOT NULL,
    primary_id TEXT NOT NULL,
    secondary_id TEXT NOT NULL DEFAULT '',
    current_registry_revision BIGINT NOT NULL CHECK (current_registry_revision > 0),
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cell, tenant_id, project_id, fence_kind, primary_id, secondary_id),
    FOREIGN KEY (
        cell, tenant_id, project_id, fence_kind, primary_id, secondary_id,
        current_registry_revision
    ) REFERENCES hartevo_cell.effect_permission_fence_versions (
        cell, tenant_id, project_id, fence_kind, primary_id, secondary_id,
        registry_revision
    )
);

CREATE TABLE IF NOT EXISTS hartevo_cell.effect_idempotency (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    mission_id TEXT NOT NULL CHECK (length(btrim(mission_id)) > 0),
    idempotency_key TEXT NOT NULL CHECK (length(btrim(idempotency_key)) > 0),
    effect_id TEXT NOT NULL CHECK (length(btrim(effect_id)) > 0),
    approval_digest TEXT NOT NULL CHECK (approval_digest ~ '^[0-9a-f]{64}$'),
    status TEXT NOT NULL CHECK (
        status IN (
            'executing', 'receipt_recorded', 'verified', 'uncertain',
            'verification_required', 'failed'
        )
    ),
    receipt_json JSONB,
    verification_json JSONB,
    terminal_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cell, tenant_id, project_id, idempotency_key),
    UNIQUE (cell, tenant_id, project_id, effect_id),
    FOREIGN KEY (cell, tenant_id, project_id)
        REFERENCES hartevo_cell.projects (cell, tenant_id, project_id),
    CHECK (created_at <= updated_at),
    CHECK (
        (status = 'executing'
            AND receipt_json IS NULL AND verification_json IS NULL
            AND terminal_reason IS NULL)
        OR (status = 'receipt_recorded'
            AND receipt_json IS NOT NULL AND verification_json IS NULL
            AND terminal_reason IS NULL)
        OR (status = 'verified'
            AND receipt_json IS NOT NULL AND verification_json IS NOT NULL
            AND terminal_reason IS NULL)
        OR (status = 'uncertain'
            AND receipt_json IS NULL AND verification_json IS NULL
            AND terminal_reason IS NOT NULL AND length(btrim(terminal_reason)) > 0)
        OR (status = 'verification_required'
            AND receipt_json IS NOT NULL AND verification_json IS NOT NULL
            AND terminal_reason IS NOT NULL AND length(btrim(terminal_reason)) > 0)
        OR (status = 'failed' AND terminal_reason IS NOT NULL
            AND length(btrim(terminal_reason)) > 0
            AND (
                (receipt_json IS NULL AND verification_json IS NULL)
                OR (receipt_json IS NOT NULL AND verification_json IS NOT NULL)
            ))
    ),
    CHECK (receipt_json IS NULL OR jsonb_typeof(receipt_json) = 'object'),
    CHECK (verification_json IS NULL OR jsonb_typeof(verification_json) = 'object')
);

CREATE TABLE IF NOT EXISTS hartevo_cell.effect_execution_attempts (
    attempt_id TEXT NOT NULL CHECK (length(btrim(attempt_id)) > 0),
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    mission_id TEXT NOT NULL CHECK (length(btrim(mission_id)) > 0),
    effect_id TEXT NOT NULL CHECK (length(btrim(effect_id)) > 0),
    attempt_no BIGINT NOT NULL CHECK (attempt_no > 0),
    generation BIGINT NOT NULL CHECK (generation > 0),
    status TEXT NOT NULL CHECK (
        status IN (
            'executing', 'receipt_recorded', 'verifying', 'verified',
            'uncertain', 'verification_required', 'failed'
        )
    ),
    lease_owner TEXT NOT NULL CHECK (length(btrim(lease_owner)) > 0),
    lease_expires_at TIMESTAMPTZ NOT NULL,
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    receipt_json JSONB,
    verification_json JSONB,
    failure_class TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cell, tenant_id, project_id, attempt_id),
    UNIQUE (cell, tenant_id, project_id, effect_id, attempt_no),
    FOREIGN KEY (cell, tenant_id, project_id)
        REFERENCES hartevo_cell.projects (cell, tenant_id, project_id),
    FOREIGN KEY (cell, tenant_id, project_id, effect_id)
        REFERENCES hartevo_cell.effect_idempotency
            (cell, tenant_id, project_id, effect_id),
    CHECK (created_at <= updated_at AND lease_expires_at > created_at),
    CHECK (
        (status = 'executing'
            AND receipt_json IS NULL AND verification_json IS NULL
            AND failure_class IS NULL)
        OR (status IN ('receipt_recorded', 'verifying')
            AND receipt_json IS NOT NULL AND verification_json IS NULL
            AND failure_class IS NULL)
        OR (status = 'verified'
            AND receipt_json IS NOT NULL AND verification_json IS NOT NULL
            AND failure_class IS NULL)
        OR (status = 'uncertain'
            AND receipt_json IS NULL AND verification_json IS NULL
            AND failure_class IS NOT NULL AND length(btrim(failure_class)) > 0)
        OR (status = 'verification_required'
            AND receipt_json IS NOT NULL AND verification_json IS NOT NULL
            AND failure_class IS NOT NULL AND length(btrim(failure_class)) > 0)
        OR (status = 'failed' AND failure_class IS NOT NULL
            AND length(btrim(failure_class)) > 0
            AND (
                (receipt_json IS NULL AND verification_json IS NULL)
                OR (receipt_json IS NOT NULL AND verification_json IS NOT NULL)
            ))
    ),
    CHECK (receipt_json IS NULL OR jsonb_typeof(receipt_json) = 'object'),
    CHECK (verification_json IS NULL OR jsonb_typeof(verification_json) = 'object')
);

CREATE TABLE IF NOT EXISTS hartevo_cell.effect_reconciliation_heads (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    mission_id TEXT NOT NULL CHECK (length(btrim(mission_id)) > 0),
    effect_id TEXT NOT NULL CHECK (length(btrim(effect_id)) > 0),
    idempotency_key TEXT NOT NULL CHECK (length(btrim(idempotency_key)) > 0),
    approval_digest TEXT NOT NULL CHECK (approval_digest ~ '^[0-9a-f]{64}$'),
    policy_version TEXT NOT NULL CHECK (length(btrim(policy_version)) > 0),
    policy_digest TEXT NOT NULL CHECK (policy_digest ~ '^[0-9a-f]{64}$'),
    max_attempts BIGINT NOT NULL CHECK (max_attempts BETWEEN 1 AND 100),
    retry_delay_seconds BIGINT NOT NULL
        CHECK (retry_delay_seconds BETWEEN 1 AND 2592000),
    attempts BIGINT NOT NULL CHECK (attempts BETWEEN 1 AND max_attempts),
    generation BIGINT NOT NULL CHECK (generation > 0),
    status TEXT NOT NULL CHECK (
        status IN (
            'leased', 'retry_wait', 'receipt_found', 'not_executed',
            'provider_rejected', 'dead_letter'
        )
    ),
    lease_owner TEXT,
    lease_expires_at TIMESTAMPTZ,
    retry_at TIMESTAMPTZ,
    evidence_digest TEXT CHECK (
        evidence_digest IS NULL OR evidence_digest ~ '^[0-9a-f]{64}$'
    ),
    observation_json JSONB,
    terminal_reason TEXT,
    initial_execution_started_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cell, tenant_id, project_id, effect_id),
    UNIQUE (cell, tenant_id, project_id, idempotency_key),
    FOREIGN KEY (cell, tenant_id, project_id, effect_id)
        REFERENCES hartevo_cell.effect_idempotency
            (cell, tenant_id, project_id, effect_id),
    CHECK (created_at <= updated_at AND initial_execution_started_at <= updated_at),
    CHECK (observation_json IS NULL OR jsonb_typeof(observation_json) = 'object'),
    CHECK (
        (status = 'leased'
            AND lease_owner IS NOT NULL AND length(btrim(lease_owner)) > 0
            AND lease_expires_at IS NOT NULL AND lease_expires_at > updated_at
            AND retry_at IS NULL AND evidence_digest IS NULL
            AND observation_json IS NULL AND terminal_reason IS NULL)
        OR (status = 'retry_wait'
            AND lease_owner IS NULL AND lease_expires_at IS NULL
            AND retry_at IS NOT NULL AND retry_at > updated_at
            AND evidence_digest IS NOT NULL AND observation_json IS NOT NULL
            AND terminal_reason IS NOT NULL AND length(btrim(terminal_reason)) > 0)
        OR (status = 'receipt_found'
            AND lease_owner IS NULL AND lease_expires_at IS NULL AND retry_at IS NULL
            AND evidence_digest IS NOT NULL AND observation_json IS NOT NULL
            AND terminal_reason IS NULL)
        OR (status IN ('not_executed', 'provider_rejected', 'dead_letter')
            AND lease_owner IS NULL AND lease_expires_at IS NULL AND retry_at IS NULL
            AND evidence_digest IS NOT NULL AND observation_json IS NOT NULL
            AND terminal_reason IS NOT NULL AND length(btrim(terminal_reason)) > 0)
    )
);

CREATE TABLE IF NOT EXISTS hartevo_cell.effect_reconciliation_attempts (
    attempt_id TEXT NOT NULL CHECK (length(btrim(attempt_id)) > 0),
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    mission_id TEXT NOT NULL CHECK (length(btrim(mission_id)) > 0),
    effect_id TEXT NOT NULL CHECK (length(btrim(effect_id)) > 0),
    attempt_no BIGINT NOT NULL CHECK (attempt_no BETWEEN 1 AND 100),
    generation BIGINT NOT NULL CHECK (generation > 0),
    status TEXT NOT NULL CHECK (
        status IN (
            'leased', 'retry_wait', 'receipt_found', 'not_executed',
            'provider_rejected', 'dead_letter'
        )
    ),
    lease_owner TEXT NOT NULL CHECK (length(btrim(lease_owner)) > 0),
    lease_expires_at TIMESTAMPTZ NOT NULL,
    evidence_digest TEXT CHECK (
        evidence_digest IS NULL OR evidence_digest ~ '^[0-9a-f]{64}$'
    ),
    observation_json JSONB,
    failure_class TEXT,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (cell, tenant_id, project_id, attempt_id),
    UNIQUE (cell, tenant_id, project_id, effect_id, attempt_no),
    FOREIGN KEY (cell, tenant_id, project_id, effect_id)
        REFERENCES hartevo_cell.effect_reconciliation_heads
            (cell, tenant_id, project_id, effect_id),
    CHECK (lease_expires_at > started_at),
    CHECK (observation_json IS NULL OR jsonb_typeof(observation_json) = 'object'),
    CHECK (
        (status = 'leased' AND evidence_digest IS NULL
            AND observation_json IS NULL AND failure_class IS NULL
            AND completed_at IS NULL)
        OR (status <> 'leased' AND evidence_digest IS NOT NULL
            AND observation_json IS NOT NULL AND failure_class IS NOT NULL
            AND length(btrim(failure_class)) > 0 AND completed_at IS NOT NULL
            AND completed_at >= started_at)
    )
);

CREATE TABLE IF NOT EXISTS hartevo_cell.effect_rate_limit_buckets (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    scope_digest TEXT NOT NULL CHECK (scope_digest ~ '^[0-9a-f]{64}$'),
    rule_id TEXT NOT NULL CHECK (length(btrim(rule_id)) > 0),
    policy_version TEXT NOT NULL CHECK (length(btrim(policy_version)) > 0),
    policy_digest TEXT NOT NULL CHECK (policy_digest ~ '^[0-9a-f]{64}$'),
    provider TEXT NOT NULL CHECK (length(btrim(provider)) > 0),
    account_id TEXT,
    capability TEXT NOT NULL CHECK (length(btrim(capability)) > 0),
    window_started_at TIMESTAMPTZ NOT NULL,
    window_ends_at TIMESTAMPTZ NOT NULL,
    max_executions BIGINT NOT NULL CHECK (max_executions > 0),
    window_seconds BIGINT NOT NULL CHECK (window_seconds > 0),
    consumed BIGINT NOT NULL CHECK (consumed >= 0 AND consumed <= max_executions),
    revision BIGINT NOT NULL CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cell, tenant_id, project_id, scope_digest, window_started_at),
    FOREIGN KEY (cell, tenant_id, project_id)
        REFERENCES hartevo_cell.projects (cell, tenant_id, project_id),
    CHECK (window_started_at < window_ends_at AND created_at <= updated_at)
);

CREATE TABLE IF NOT EXISTS hartevo_cell.effect_rate_limit_reservations (
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    mission_id TEXT NOT NULL CHECK (length(btrim(mission_id)) > 0),
    effect_id TEXT NOT NULL CHECK (length(btrim(effect_id)) > 0),
    idempotency_key TEXT NOT NULL CHECK (length(btrim(idempotency_key)) > 0),
    approval_digest TEXT NOT NULL CHECK (approval_digest ~ '^[0-9a-f]{64}$'),
    scope_digest TEXT NOT NULL CHECK (scope_digest ~ '^[0-9a-f]{64}$'),
    rule_id TEXT NOT NULL CHECK (length(btrim(rule_id)) > 0),
    window_started_at TIMESTAMPTZ NOT NULL,
    window_ends_at TIMESTAMPTZ NOT NULL,
    reserved_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cell, tenant_id, project_id, effect_id),
    UNIQUE (cell, tenant_id, project_id, idempotency_key),
    FOREIGN KEY (cell, tenant_id, project_id)
        REFERENCES hartevo_cell.projects (cell, tenant_id, project_id),
    FOREIGN KEY (cell, tenant_id, project_id, scope_digest, window_started_at)
        REFERENCES hartevo_cell.effect_rate_limit_buckets (
            cell, tenant_id, project_id, scope_digest, window_started_at
        ),
    CHECK (window_started_at < window_ends_at),
    CHECK (reserved_at >= window_started_at AND reserved_at < window_ends_at)
);

CREATE TABLE IF NOT EXISTS hartevo_cell.effect_rate_limit_decisions (
    sequence BIGSERIAL PRIMARY KEY,
    cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    mission_id TEXT NOT NULL CHECK (length(btrim(mission_id)) > 0),
    effect_id TEXT NOT NULL CHECK (length(btrim(effect_id)) > 0),
    approval_digest TEXT NOT NULL CHECK (approval_digest ~ '^[0-9a-f]{64}$'),
    scope_digest TEXT NOT NULL CHECK (scope_digest ~ '^[0-9a-f]{64}$'),
    rule_id TEXT NOT NULL CHECK (length(btrim(rule_id)) > 0),
    decision TEXT NOT NULL CHECK (decision IN ('reserved', 'denied')),
    consumed_before BIGINT NOT NULL CHECK (consumed_before >= 0),
    consumed_after BIGINT NOT NULL CHECK (consumed_after >= 0),
    window_started_at TIMESTAMPTZ NOT NULL,
    window_ends_at TIMESTAMPTZ NOT NULL,
    decided_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (cell, tenant_id, project_id)
        REFERENCES hartevo_cell.projects (cell, tenant_id, project_id),
    CHECK (window_started_at < window_ends_at),
    CHECK (decided_at >= window_started_at AND decided_at < window_ends_at),
    CHECK (
        (decision = 'reserved' AND consumed_after = consumed_before + 1)
        OR (decision = 'denied' AND consumed_after = consumed_before)
    )
);

ALTER TABLE hartevo_cell.remote_worker_mailbox_messages
    ADD COLUMN IF NOT EXISTS dispatch_registration_id TEXT;
ALTER TABLE hartevo_cell.remote_worker_claims
    ADD COLUMN IF NOT EXISTS dispatch_registration_id TEXT;

CREATE INDEX IF NOT EXISTS outbox_claim_idx
    ON hartevo_cell.outbox_messages
        (cell, tenant_id, status, available_at, sequence);
CREATE INDEX IF NOT EXISTS scheduler_schedule_due_idx
    ON hartevo_cell.scheduler_schedules
        (cell, tenant_id, status, next_due_at, contract_valid_until, revision);
CREATE INDEX IF NOT EXISTS scheduler_worker_takeover_idx
    ON hartevo_cell.scheduler_worker_leases
        (cell, tenant_id, project_id, expires_at, generation);
CREATE INDEX IF NOT EXISTS scheduler_takeover_lookup_idx
    ON hartevo_cell.scheduler_lease_takeovers
        (cell, tenant_id, lease_kind, lease_id_digest, generation);
CREATE INDEX IF NOT EXISTS scheduler_attempt_reconcile_idx
    ON hartevo_cell.scheduler_attempts
        (cell, tenant_id, project_id, schedule_id, outcome, updated_at);
CREATE INDEX IF NOT EXISTS sync_versions_replay_idx
    ON hartevo_cell.sync_object_versions
        (cell, tenant_id, project_id, recorded_at, object_id, revision);
CREATE INDEX IF NOT EXISTS remote_worker_claim_idx
    ON hartevo_cell.remote_worker_mailbox_messages
        (cell, tenant_id, project_id, mission_id, dispatch_registration_id,
            worker_id, status, enqueued_at, task_id);
CREATE INDEX IF NOT EXISTS remote_worker_transport_registration_scope_idx
    ON hartevo_cell.remote_worker_transport_registrations
        (cell, tenant_id, project_id, mission_id, state, service_id);
CREATE INDEX IF NOT EXISTS remote_worker_dispatch_registration_scope_idx
    ON hartevo_cell.remote_worker_dispatch_registrations
        (cell, tenant_id, project_id, mission_id, dispatch_registration_id);
CREATE INDEX IF NOT EXISTS remote_worker_work_claim_idx
    ON hartevo_cell.remote_worker_work_requests
        (cell, tenant_id, project_id, mission_id, dispatch_registration_id,
            worker_id, status, enqueued_at, deadline_at, task_id);
CREATE INDEX IF NOT EXISTS remote_worker_work_log_task_idx
    ON hartevo_cell.remote_worker_work_log
        (cell, tenant_id, project_id, task_id, sequence);
CREATE UNIQUE INDEX IF NOT EXISTS device_sync_active_registration_idx
    ON hartevo_cell.device_sync_registrations
        (cell, tenant_id, project_id, device_id)
        WHERE state = 'attached';
CREATE INDEX IF NOT EXISTS device_sync_registration_scope_idx
    ON hartevo_cell.device_sync_registrations
        (cell, tenant_id, project_id, device_id, state, project_key_generation);
CREATE INDEX IF NOT EXISTS device_sync_document_head_scope_idx
    ON hartevo_cell.device_sync_document_heads
        (cell, tenant_id, project_id, updated_at, document_id);
CREATE INDEX IF NOT EXISTS device_sync_event_resource_idx
    ON hartevo_cell.device_sync_event_log
        (cell, tenant_id, project_id, resource_id, sequence);
CREATE INDEX IF NOT EXISTS device_handoff_target_idx
    ON hartevo_cell.device_handoff_grants
        (cell, tenant_id, project_id, target_device_id, expires_at);
CREATE INDEX IF NOT EXISTS effect_attempt_claim_idx
    ON hartevo_cell.effect_execution_attempts
        (cell, tenant_id, project_id, effect_id, generation DESC);
CREATE INDEX IF NOT EXISTS effect_reconciliation_claim_idx
    ON hartevo_cell.effect_reconciliation_heads
        (cell, tenant_id, project_id, status, retry_at, lease_expires_at);
CREATE INDEX IF NOT EXISTS effect_rate_limit_decision_idx
    ON hartevo_cell.effect_rate_limit_decisions
        (cell, tenant_id, project_id, scope_digest, window_started_at, sequence);

ALTER TABLE hartevo_cell.tenant_cells ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.tenant_cells FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.projects FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.remote_worker_transport_registrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.remote_worker_transport_registrations FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.remote_worker_dispatch_registrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.remote_worker_dispatch_registrations FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.sync_object_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.sync_object_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.sync_object_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.sync_object_heads FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.domain_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.domain_events FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.outbox_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.outbox_messages FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.scheduler_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.scheduler_schedules FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.scheduler_leader_leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.scheduler_leader_leases FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.scheduler_worker_leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.scheduler_worker_leases FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.scheduler_tenant_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.scheduler_tenant_state FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.scheduler_lease_takeovers ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.scheduler_lease_takeovers FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.scheduler_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.scheduler_attempts FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.sync_mutations ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.sync_mutations FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.remote_worker_mailbox_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.remote_worker_mailbox_messages FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.remote_worker_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.remote_worker_claims FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.remote_worker_work_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.remote_worker_work_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.remote_worker_result_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.remote_worker_result_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.remote_worker_work_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.remote_worker_work_log FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.device_sync_registrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.device_sync_registrations FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.device_sync_document_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.device_sync_document_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.device_sync_document_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.device_sync_document_heads FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.device_sync_event_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.device_sync_event_log FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.device_public_key_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.device_public_key_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.device_public_key_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.device_public_key_heads FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.keyring_bootstrap_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.keyring_bootstrap_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.keyring_bootstrap_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.keyring_bootstrap_heads FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.device_handoff_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.device_handoff_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.device_handoff_revocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.device_handoff_revocations FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.device_handoff_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.device_handoff_claims FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.device_handoff_consumptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.device_handoff_consumptions FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.effect_permission_fence_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.effect_permission_fence_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.effect_permission_fence_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.effect_permission_fence_heads FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.effect_idempotency ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.effect_idempotency FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.effect_execution_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.effect_execution_attempts FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.effect_reconciliation_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.effect_reconciliation_heads FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.effect_reconciliation_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.effect_reconciliation_attempts FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.effect_rate_limit_buckets ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.effect_rate_limit_buckets FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.effect_rate_limit_reservations ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.effect_rate_limit_reservations FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.effect_rate_limit_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.effect_rate_limit_decisions FORCE ROW LEVEL SECURITY;

DO $hartevo_rls$
DECLARE
    scoped_table TEXT;
BEGIN
    FOREACH scoped_table IN ARRAY ARRAY[
        'tenant_cells',
        'projects',
        'remote_worker_transport_registrations',
        'remote_worker_dispatch_registrations',
        'sync_object_versions',
        'sync_object_heads',
        'domain_events',
        'outbox_messages',
        'scheduler_schedules',
        'scheduler_leader_leases',
        'scheduler_worker_leases',
        'scheduler_tenant_state',
        'scheduler_lease_takeovers',
        'scheduler_attempts',
        'sync_mutations',
        'remote_worker_mailbox_messages',
        'remote_worker_claims',
        'remote_worker_work_requests',
        'remote_worker_result_receipts',
        'remote_worker_work_log',
        'device_sync_registrations',
        'device_sync_document_versions',
        'device_sync_document_heads',
        'device_sync_event_log',
        'device_public_key_versions',
        'device_public_key_heads',
        'keyring_bootstrap_versions',
        'keyring_bootstrap_heads',
        'device_handoff_grants',
        'device_handoff_revocations',
        'device_handoff_claims',
        'device_handoff_consumptions',
        'effect_permission_fence_versions',
        'effect_permission_fence_heads',
        'effect_idempotency',
        'effect_execution_attempts',
        'effect_reconciliation_heads',
        'effect_reconciliation_attempts',
        'effect_rate_limit_buckets',
        'effect_rate_limit_reservations',
        'effect_rate_limit_decisions'
    ]
    LOOP
        EXECUTE format(
            'DROP POLICY IF EXISTS tenant_cell_scope ON hartevo_cell.%I',
            scoped_table
        );
        EXECUTE format(
            'CREATE POLICY tenant_cell_scope ON hartevo_cell.%I '
            'USING (tenant_id = current_setting(''hartevo.tenant_id'', true) '
            'AND cell = current_setting(''hartevo.cell'', true)) '
            'WITH CHECK (tenant_id = current_setting(''hartevo.tenant_id'', true) '
            'AND cell = current_setting(''hartevo.cell'', true))',
            scoped_table
        );
    END LOOP;
END
$hartevo_rls$;
