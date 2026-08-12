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

CREATE INDEX IF NOT EXISTS outbox_claim_idx
    ON hartevo_cell.outbox_messages
        (cell, tenant_id, status, available_at, sequence);
CREATE INDEX IF NOT EXISTS sync_versions_replay_idx
    ON hartevo_cell.sync_object_versions
        (cell, tenant_id, project_id, recorded_at, object_id, revision);
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
ALTER TABLE hartevo_cell.sync_object_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.sync_object_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.sync_object_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.sync_object_heads FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.domain_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.domain_events FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.outbox_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.outbox_messages FORCE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.sync_mutations ENABLE ROW LEVEL SECURITY;
ALTER TABLE hartevo_cell.sync_mutations FORCE ROW LEVEL SECURITY;
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
        'sync_object_versions',
        'sync_object_heads',
        'domain_events',
        'outbox_messages',
        'sync_mutations',
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
