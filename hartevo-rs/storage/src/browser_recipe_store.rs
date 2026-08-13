//! SQLCipher-backed Signed Browser Recipe trust and registry persistence.
//!
//! Complete public keys, signed manifests, signatures, and evaluation records
//! remain inside the encrypted database. Normalized projections and
//! Event/Outbox payloads contain only scope, lifecycle metadata, and digests.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use hartevo_browser_adapter::{
    BrowserRecipeActivation, BrowserRecipeActiveVersion, BrowserRecipeCandidate,
    BrowserRecipeKeyPurpose, BrowserRecipeRegistry, BrowserRecipeRegistrySnapshot,
    BrowserRecipeRelease, BrowserRecipeTrustSnapshot, BrowserRecipeTrustStore,
    TrustedBrowserRecipeKey,
};
use hartevo_domain_kernel::{BrowserRecipeId, EffectClass, ProjectId, TenantId};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::aggregate::{AtomicMutation, PendingEvent, append_events};
use crate::{ProjectStore, StorageError};

const RECIPE_PERSISTENCE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug)]
pub struct BrowserRecipeRuntimeState {
    pub trust: BrowserRecipeTrustStore,
    pub registry: BrowserRecipeRegistry,
    head_revisions: BTreeMap<BrowserRecipeId, u64>,
}

impl BrowserRecipeRuntimeState {
    pub fn head_revision(&self, recipe_id: &BrowserRecipeId) -> Option<u64> {
        self.head_revisions.get(recipe_id).copied()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct DurableBrowserRecipeTrustKey {
    schema_version: u32,
    key: TrustedBrowserRecipeKey,
    installation_evidence_digest: String,
    installed_at: DateTime<Utc>,
    revocation_evidence_digest: Option<String>,
}

impl DurableBrowserRecipeTrustKey {
    fn validate(&self) -> Result<(), StorageError> {
        BrowserRecipeTrustStore::restore(BrowserRecipeTrustSnapshot {
            schema_version: 1,
            keys: vec![self.key.clone()],
        })?;
        if self.schema_version != RECIPE_PERSISTENCE_SCHEMA_VERSION
            || !is_sha256(&self.installation_evidence_digest)
            || self.installed_at < self.key.valid_from
            || self.installed_at >= self.key.valid_until
            || self.key.revision == 0
            || self.key.revoked_at.is_some() != self.revocation_evidence_digest.is_some()
            || self
                .revocation_evidence_digest
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
        {
            return Err(StorageError::DomainDecode(
                "invalid durable browser recipe trust key".into(),
            ));
        }
        Ok(())
    }

    fn digest(&self) -> Result<String, StorageError> {
        self.validate()?;
        digest_json(self)
    }
}

impl ProjectStore {
    pub fn install_browser_recipe_trust_key_atomic(
        &mut self,
        project_id: &ProjectId,
        key: TrustedBrowserRecipeKey,
        installation_evidence_digest: String,
        installed_at: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        let record = DurableBrowserRecipeTrustKey {
            schema_version: RECIPE_PERSISTENCE_SCHEMA_VERSION,
            key,
            installation_evidence_digest,
            installed_at,
            revocation_evidence_digest: None,
        };
        record.validate()?;
        if record.key.revision != 1 || record.key.revoked_at.is_some() {
            return Err(StorageError::InvalidInitialRevision(record.key.revision));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let tenant_id = tenant_for_project(&transaction, project_id)?;
        if let Some(existing) = load_trust_key_record(&transaction, project_id, &record.key.id)? {
            if existing == record {
                return Ok(idempotent(record.key.revision));
            }
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "browser recipe trust key",
                id: record.key.id.clone(),
            });
        }
        insert_trust_key(&transaction, &tenant_id, project_id, &record)?;
        let event = trust_key_event("browser.recipe_trust_key_installed", &record, installed_at)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            tenant_id.as_str(),
            project_id.as_str(),
            None,
            "browser_recipe_trust_key",
            &digest_identity(&record.key.id),
            &[event],
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: record.key.revision,
        })
    }

    pub fn revoke_browser_recipe_trust_key_atomic(
        &mut self,
        project_id: &ProjectId,
        key_id: &str,
        expected_revision: u64,
        revocation_evidence_digest: String,
        revoked_at: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        if !is_sha256(&revocation_evidence_digest) {
            return Err(StorageError::DomainDecode(
                "browser recipe revocation evidence must be a SHA-256 digest".into(),
            ));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let tenant_id = tenant_for_project(&transaction, project_id)?;
        let mut record =
            load_trust_key_record(&transaction, project_id, key_id)?.ok_or_else(|| {
                StorageError::ScopedRecordNotFound {
                    kind: "browser recipe trust key",
                    project_id: project_id.clone(),
                    id: key_id.to_owned(),
                }
            })?;
        if expected_revision.checked_add(1) == Some(record.key.revision)
            && record.key.revoked_at == Some(revoked_at)
            && record.revocation_evidence_digest.as_deref()
                == Some(revocation_evidence_digest.as_str())
        {
            return Ok(idempotent(record.key.revision));
        }
        if record.key.revision != expected_revision {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("browser_recipe_trust_key:{}", digest_identity(key_id)),
                expected_revision,
            });
        }
        record.key.revoke(expected_revision, revoked_at)?;
        record.revocation_evidence_digest = Some(revocation_evidence_digest);
        record.validate()?;
        update_trust_key(
            &transaction,
            &tenant_id,
            project_id,
            &record,
            expected_revision,
        )?;
        let event = trust_key_event("browser.recipe_trust_key_revoked", &record, revoked_at)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            tenant_id.as_str(),
            project_id.as_str(),
            None,
            "browser_recipe_trust_key",
            &digest_identity(key_id),
            &[event],
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: record.key.revision,
        })
    }

    pub fn register_browser_recipe_candidate_atomic(
        &mut self,
        project_id: &ProjectId,
        candidate: BrowserRecipeCandidate,
        now: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        let recipe_id = candidate.manifest.id.clone();
        let version = candidate.manifest.version;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let tenant_id = tenant_for_project(&transaction, project_id)?;
        let mut state = load_runtime_state(&transaction, project_id, &tenant_id)?;
        state
            .registry
            .register_candidate(candidate, &state.trust, now)?;
        let candidate = state.registry.candidate(&recipe_id, version)?;
        if let Some(existing) = load_candidate(
            &transaction,
            project_id,
            &candidate.manifest.id,
            candidate.manifest.version,
        )? {
            if &existing == candidate {
                return Ok(idempotent(u64::from(candidate.manifest.version)));
            }
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "browser recipe candidate",
                id: format!("{}:{}", candidate.manifest.id, candidate.manifest.version),
            });
        }
        insert_candidate(&transaction, &tenant_id, project_id, candidate)?;
        let event = candidate_event(candidate, now)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            tenant_id.as_str(),
            project_id.as_str(),
            None,
            "browser_recipe_candidate",
            &recipe_aggregate_digest(&candidate.manifest.id, candidate.manifest.version),
            &[event],
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: u64::from(candidate.manifest.version),
        })
    }

    pub fn register_browser_recipe_release_atomic(
        &mut self,
        project_id: &ProjectId,
        release: BrowserRecipeRelease,
        now: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        let recipe_id = release.candidate.manifest.id.clone();
        let version = release.candidate.manifest.version;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let tenant_id = tenant_for_project(&transaction, project_id)?;
        let mut state = load_runtime_state(&transaction, project_id, &tenant_id)?;
        state
            .registry
            .register_release(release, &state.trust, now)?;
        let release = state.registry.release(&recipe_id, version)?;
        let manifest = &release.candidate.manifest;
        if let Some(existing) =
            load_release(&transaction, project_id, &manifest.id, manifest.version)?
        {
            if &existing == release {
                return Ok(idempotent(u64::from(manifest.version)));
            }
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "browser recipe release",
                id: format!("{}:{}", manifest.id, manifest.version),
            });
        }
        insert_release(&transaction, &tenant_id, project_id, release)?;
        let event = release_event(release, now)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            tenant_id.as_str(),
            project_id.as_str(),
            None,
            "browser_recipe_release",
            &recipe_aggregate_digest(&manifest.id, manifest.version),
            &[event],
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: u64::from(manifest.version),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn activate_browser_recipe_release_atomic(
        &mut self,
        project_id: &ProjectId,
        recipe_id: &BrowserRecipeId,
        version: u32,
        expected_active_version: Option<u32>,
        activation_evidence_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let tenant_id = tenant_for_project(&transaction, project_id)?;
        let mut state = load_runtime_state(&transaction, project_id, &tenant_id)?;
        state.registry.activate_release(
            recipe_id,
            version,
            expected_active_version,
            activation_evidence_digest,
            &state.trust,
            now,
        )?;
        let activation = state.registry.active_activation(recipe_id)?.clone();
        if load_activation(&transaction, project_id, recipe_id, version)?.as_ref()
            == Some(&activation)
        {
            return Ok(idempotent(state.head_revision(recipe_id).ok_or_else(
                || StorageError::DomainDecode("recipe activation has no durable head".into()),
            )?));
        }
        let previous_head_revision = state.head_revision(recipe_id);
        let next_head_revision = previous_head_revision
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(StorageError::RevisionOverflow(u64::MAX))?;
        insert_activation(&transaction, &tenant_id, project_id, &activation)?;
        write_recipe_head(
            &transaction,
            &tenant_id,
            project_id,
            recipe_id,
            &activation,
            previous_head_revision,
            next_head_revision,
        )?;
        let event = activation_event(&activation, next_head_revision)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            tenant_id.as_str(),
            project_id.as_str(),
            None,
            "browser_recipe_activation",
            &digest_identity(recipe_id.as_str()),
            &[event],
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: next_head_revision,
        })
    }

    pub fn load_browser_recipe_runtime_state(
        &self,
        project_id: &ProjectId,
    ) -> Result<BrowserRecipeRuntimeState, StorageError> {
        let tenant_id = tenant_for_project(&self.connection, project_id)?;
        load_runtime_state(&self.connection, project_id, &tenant_id)
    }
}

fn load_runtime_state(
    connection: &Connection,
    project_id: &ProjectId,
    tenant_id: &TenantId,
) -> Result<BrowserRecipeRuntimeState, StorageError> {
    let trust_records = load_trust_key_records(connection, project_id)?;
    if trust_records.iter().any(|record| record.key.id.is_empty()) {
        return Err(StorageError::DomainDecode(
            "empty browser recipe trust key identifier".into(),
        ));
    }
    let trust = BrowserRecipeTrustStore::restore(BrowserRecipeTrustSnapshot {
        schema_version: 1,
        keys: trust_records.into_iter().map(|record| record.key).collect(),
    })?;
    let candidates = load_candidates(connection, project_id)?;
    let releases = load_releases(connection, project_id)?;
    let activations = load_activations(connection, project_id)?;
    let (active_versions, head_revisions) = load_heads(connection, project_id, tenant_id)?;
    let registry = BrowserRecipeRegistry::restore(
        BrowserRecipeRegistrySnapshot {
            schema_version: 1,
            candidates,
            releases,
            activations,
            active_versions,
        },
        &trust,
    )?;
    Ok(BrowserRecipeRuntimeState {
        trust,
        registry,
        head_revisions,
    })
}

fn tenant_for_project(
    connection: &Connection,
    project_id: &ProjectId,
) -> Result<TenantId, StorageError> {
    connection
        .query_row(
            "SELECT tenant_id FROM projects WHERE id = ?1",
            [project_id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(TenantId::from_stable)
        .ok_or_else(|| StorageError::ProjectNotFound(project_id.clone()))
}

fn insert_trust_key(
    transaction: &Transaction<'_>,
    tenant_id: &TenantId,
    project_id: &ProjectId,
    record: &DurableBrowserRecipeTrustKey,
) -> Result<(), StorageError> {
    let public_key_digest = public_key_digest(&record.key)?;
    transaction.execute(
        "INSERT INTO browser_recipe_trust_keys
           (tenant_id, project_id, key_id, key_id_digest, purpose, public_key_digest,
            installation_evidence_digest, revocation_evidence_digest, valid_from, valid_until,
            revoked_at, revision, installed_at, record_digest, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            tenant_id.as_str(),
            project_id.as_str(),
            record.key.id,
            digest_identity(&record.key.id),
            key_purpose_name(record.key.purpose),
            public_key_digest,
            record.installation_evidence_digest,
            record.revocation_evidence_digest,
            record.key.valid_from.to_rfc3339(),
            record.key.valid_until.to_rfc3339(),
            record.key.revoked_at.map(|value| value.to_rfc3339()),
            to_sql_u64(record.key.revision)?,
            record.installed_at.to_rfc3339(),
            record.digest()?,
            serde_json::to_string(record)?,
        ],
    )?;
    Ok(())
}

fn update_trust_key(
    transaction: &Transaction<'_>,
    tenant_id: &TenantId,
    project_id: &ProjectId,
    record: &DurableBrowserRecipeTrustKey,
    expected_revision: u64,
) -> Result<(), StorageError> {
    let updated = transaction.execute(
        "UPDATE browser_recipe_trust_keys SET
           revocation_evidence_digest = ?4, revoked_at = ?5, revision = ?6,
           record_digest = ?7, record_json = ?8
         WHERE tenant_id = ?1 AND project_id = ?2 AND key_id = ?3 AND revision = ?9",
        params![
            tenant_id.as_str(),
            project_id.as_str(),
            record.key.id,
            record.revocation_evidence_digest,
            record.key.revoked_at.map(|value| value.to_rfc3339()),
            to_sql_u64(record.key.revision)?,
            record.digest()?,
            serde_json::to_string(record)?,
            to_sql_u64(expected_revision)?,
        ],
    )?;
    if updated != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!(
                "browser_recipe_trust_key:{}",
                digest_identity(&record.key.id)
            ),
            expected_revision,
        });
    }
    Ok(())
}

fn load_trust_key_record(
    connection: &Connection,
    project_id: &ProjectId,
    key_id: &str,
) -> Result<Option<DurableBrowserRecipeTrustKey>, StorageError> {
    let tenant_id = tenant_for_project(connection, project_id)?;
    let projection = connection
        .query_row(
            "SELECT tenant_id, key_id_digest, purpose, public_key_digest,
                    installation_evidence_digest, revocation_evidence_digest, valid_from,
                    valid_until, revoked_at, revision, installed_at, record_digest, record_json
             FROM browser_recipe_trust_keys WHERE project_id = ?1 AND key_id = ?2",
            params![project_id.as_str(), key_id],
            decode_trust_projection_row,
        )
        .optional()?;
    projection
        .as_ref()
        .map(|projection| decode_trust_key(&tenant_id, key_id, projection))
        .transpose()
}

fn load_trust_key_records(
    connection: &Connection,
    project_id: &ProjectId,
) -> Result<Vec<DurableBrowserRecipeTrustKey>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT key_id FROM browser_recipe_trust_keys
         WHERE project_id = ?1 ORDER BY key_id",
    )?;
    let key_ids = statement
        .query_map([project_id.as_str()], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    key_ids
        .into_iter()
        .map(|key_id| {
            load_trust_key_record(connection, project_id, &key_id)?.ok_or_else(|| {
                StorageError::ScopedRecordNotFound {
                    kind: "browser recipe trust key",
                    project_id: project_id.clone(),
                    id: key_id,
                }
            })
        })
        .collect()
}

#[derive(Eq, PartialEq)]
struct TrustProjection {
    tenant_id: String,
    key_id_digest: String,
    purpose: String,
    public_key_digest: String,
    installation_evidence_digest: String,
    revocation_evidence_digest: Option<String>,
    valid_from: String,
    valid_until: String,
    revoked_at: Option<String>,
    revision: i64,
    installed_at: String,
    record_digest: String,
    record_json: String,
}

fn decode_trust_projection_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TrustProjection> {
    Ok(TrustProjection {
        tenant_id: row.get(0)?,
        key_id_digest: row.get(1)?,
        purpose: row.get(2)?,
        public_key_digest: row.get(3)?,
        installation_evidence_digest: row.get(4)?,
        revocation_evidence_digest: row.get(5)?,
        valid_from: row.get(6)?,
        valid_until: row.get(7)?,
        revoked_at: row.get(8)?,
        revision: row.get(9)?,
        installed_at: row.get(10)?,
        record_digest: row.get(11)?,
        record_json: row.get(12)?,
    })
}

fn decode_trust_key(
    tenant_id: &TenantId,
    key_id: &str,
    projection: &TrustProjection,
) -> Result<DurableBrowserRecipeTrustKey, StorageError> {
    let record: DurableBrowserRecipeTrustKey = serde_json::from_str(&projection.record_json)?;
    record.validate()?;
    let expected = TrustProjection {
        tenant_id: tenant_id.to_string(),
        key_id_digest: digest_identity(&record.key.id),
        purpose: key_purpose_name(record.key.purpose).into(),
        public_key_digest: public_key_digest(&record.key)?,
        installation_evidence_digest: record.installation_evidence_digest.clone(),
        revocation_evidence_digest: record.revocation_evidence_digest.clone(),
        valid_from: record.key.valid_from.to_rfc3339(),
        valid_until: record.key.valid_until.to_rfc3339(),
        revoked_at: record.key.revoked_at.map(|value| value.to_rfc3339()),
        revision: to_sql_u64(record.key.revision)?,
        installed_at: record.installed_at.to_rfc3339(),
        record_digest: record.digest()?,
        record_json: projection.record_json.clone(),
    };
    if record.key.id != key_id || *projection != expected {
        return Err(StorageError::ImmutableRecordMismatch {
            kind: "browser recipe trust projection",
            id: digest_identity(key_id),
        });
    }
    Ok(record)
}

fn insert_candidate(
    transaction: &Transaction<'_>,
    tenant_id: &TenantId,
    project_id: &ProjectId,
    candidate: &BrowserRecipeCandidate,
) -> Result<(), StorageError> {
    let manifest = &candidate.manifest;
    let candidate_digest = candidate.digest()?;
    transaction.execute(
        "INSERT INTO browser_recipe_candidates
           (tenant_id, project_id, recipe_id, recipe_id_digest, version, candidate_digest,
            provider_digest, origin_digest, capability_digest, effect_class,
            publisher_key_id_digest, created_at, expires_at, record_digest, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            tenant_id.as_str(),
            project_id.as_str(),
            manifest.id.as_str(),
            digest_identity(manifest.id.as_str()),
            i64::from(manifest.version),
            candidate_digest,
            digest_identity(&manifest.provider),
            manifest.origin_digest,
            digest_identity(&manifest.capability),
            effect_class_name(&manifest.effect_class),
            digest_identity(&manifest.publisher_key_id),
            manifest.created_at.to_rfc3339(),
            manifest.expires_at.to_rfc3339(),
            candidate.digest()?,
            serde_json::to_string(candidate)?,
        ],
    )?;
    Ok(())
}

fn load_candidate(
    connection: &Connection,
    project_id: &ProjectId,
    recipe_id: &BrowserRecipeId,
    version: u32,
) -> Result<Option<BrowserRecipeCandidate>, StorageError> {
    let tenant_id = tenant_for_project(connection, project_id)?;
    let row = connection
        .query_row(
            "SELECT tenant_id, recipe_id_digest, candidate_digest, provider_digest,
                    origin_digest, capability_digest, effect_class, publisher_key_id_digest,
                    created_at, expires_at, record_digest, record_json
             FROM browser_recipe_candidates
             WHERE project_id = ?1 AND recipe_id = ?2 AND version = ?3",
            params![project_id.as_str(), recipe_id.as_str(), i64::from(version)],
            |row| {
                Ok(CandidateProjection {
                    tenant_id: row.get(0)?,
                    recipe_id_digest: row.get(1)?,
                    candidate_digest: row.get(2)?,
                    provider_digest: row.get(3)?,
                    origin_digest: row.get(4)?,
                    capability_digest: row.get(5)?,
                    effect_class: row.get(6)?,
                    publisher_key_id_digest: row.get(7)?,
                    created_at: row.get(8)?,
                    expires_at: row.get(9)?,
                    record_digest: row.get(10)?,
                    record_json: row.get(11)?,
                })
            },
        )
        .optional()?;
    row.as_ref()
        .map(|row| decode_candidate(&tenant_id, recipe_id, version, row))
        .transpose()
}

struct CandidateProjection {
    tenant_id: String,
    recipe_id_digest: String,
    candidate_digest: String,
    provider_digest: String,
    origin_digest: String,
    capability_digest: String,
    effect_class: String,
    publisher_key_id_digest: String,
    created_at: String,
    expires_at: String,
    record_digest: String,
    record_json: String,
}

fn decode_candidate(
    tenant_id: &TenantId,
    recipe_id: &BrowserRecipeId,
    version: u32,
    row: &CandidateProjection,
) -> Result<BrowserRecipeCandidate, StorageError> {
    let candidate: BrowserRecipeCandidate = serde_json::from_str(&row.record_json)?;
    let manifest = &candidate.manifest;
    let digest = candidate.digest()?;
    if row.tenant_id != tenant_id.as_str()
        || manifest.id != *recipe_id
        || manifest.version != version
        || row.recipe_id_digest != digest_identity(manifest.id.as_str())
        || row.candidate_digest != digest
        || row.provider_digest != digest_identity(&manifest.provider)
        || row.origin_digest != manifest.origin_digest
        || row.capability_digest != digest_identity(&manifest.capability)
        || row.effect_class != effect_class_name(&manifest.effect_class)
        || row.publisher_key_id_digest != digest_identity(&manifest.publisher_key_id)
        || row.created_at != manifest.created_at.to_rfc3339()
        || row.expires_at != manifest.expires_at.to_rfc3339()
        || row.record_digest != candidate.digest()?
    {
        return Err(StorageError::ImmutableRecordMismatch {
            kind: "browser recipe candidate projection",
            id: recipe_aggregate_digest(recipe_id, version),
        });
    }
    Ok(candidate)
}

fn load_candidates(
    connection: &Connection,
    project_id: &ProjectId,
) -> Result<Vec<BrowserRecipeCandidate>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT recipe_id, version FROM browser_recipe_candidates
         WHERE project_id = ?1 ORDER BY recipe_id, version",
    )?;
    let rows = statement
        .query_map([project_id.as_str()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(id, version)| {
            let version = to_u32(version)?;
            let recipe_id = BrowserRecipeId::from_stable(id);
            load_candidate(connection, project_id, &recipe_id, version)?.ok_or_else(|| {
                StorageError::ScopedRecordNotFound {
                    kind: "browser recipe candidate",
                    project_id: project_id.clone(),
                    id: recipe_aggregate_digest(&recipe_id, version),
                }
            })
        })
        .collect()
}

fn insert_release(
    transaction: &Transaction<'_>,
    tenant_id: &TenantId,
    project_id: &ProjectId,
    release: &BrowserRecipeRelease,
) -> Result<(), StorageError> {
    let manifest = &release.candidate.manifest;
    let evidence = &release.promotion.evidence;
    transaction.execute(
        "INSERT INTO browser_recipe_releases
           (tenant_id, project_id, recipe_id, recipe_id_digest, version, candidate_digest,
            release_digest, release_key_id_digest, v1_result_digest, v2_result_digest,
            safety_suite_digest, contamination_audit_digest, rollback_strategy_digest,
            promotion_approval_digest, promoted_at, expires_at, record_digest, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                 ?15, ?16, ?17, ?18)",
        params![
            tenant_id.as_str(),
            project_id.as_str(),
            manifest.id.as_str(),
            digest_identity(manifest.id.as_str()),
            i64::from(manifest.version),
            release.candidate.digest()?,
            release.digest()?,
            digest_identity(&release.promotion.release_key_id),
            evidence.v1_result_digest,
            evidence.v2_result_digest,
            evidence.safety_suite_digest,
            evidence.contamination_audit_digest,
            evidence.rollback_strategy_digest,
            evidence.promotion_approval_digest,
            release.promotion.promoted_at.to_rfc3339(),
            release.promotion.expires_at.to_rfc3339(),
            release.digest()?,
            serde_json::to_string(release)?,
        ],
    )?;
    Ok(())
}

fn load_release(
    connection: &Connection,
    project_id: &ProjectId,
    recipe_id: &BrowserRecipeId,
    version: u32,
) -> Result<Option<BrowserRecipeRelease>, StorageError> {
    let tenant_id = tenant_for_project(connection, project_id)?;
    let row = connection
        .query_row(
            "SELECT tenant_id, recipe_id_digest, candidate_digest, release_digest,
                    release_key_id_digest, v1_result_digest, v2_result_digest,
                    safety_suite_digest, contamination_audit_digest, rollback_strategy_digest,
                    promotion_approval_digest, promoted_at, expires_at, record_digest, record_json
             FROM browser_recipe_releases
             WHERE project_id = ?1 AND recipe_id = ?2 AND version = ?3",
            params![project_id.as_str(), recipe_id.as_str(), i64::from(version)],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, String>(14)?,
                ))
            },
        )
        .optional()?;
    row.as_ref()
        .map(|row| decode_release(&tenant_id, recipe_id, version, row))
        .transpose()
}

#[allow(clippy::type_complexity)]
fn decode_release(
    tenant_id: &TenantId,
    recipe_id: &BrowserRecipeId,
    version: u32,
    row: &(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    ),
) -> Result<BrowserRecipeRelease, StorageError> {
    let release: BrowserRecipeRelease = serde_json::from_str(&row.14)?;
    let manifest = &release.candidate.manifest;
    let evidence = &release.promotion.evidence;
    if row.0 != tenant_id.as_str()
        || manifest.id != *recipe_id
        || manifest.version != version
        || row.1 != digest_identity(manifest.id.as_str())
        || row.2 != release.candidate.digest()?
        || row.3 != release.digest()?
        || row.4 != digest_identity(&release.promotion.release_key_id)
        || row.5 != evidence.v1_result_digest
        || row.6 != evidence.v2_result_digest
        || row.7 != evidence.safety_suite_digest
        || row.8 != evidence.contamination_audit_digest
        || row.9 != evidence.rollback_strategy_digest
        || row.10 != evidence.promotion_approval_digest
        || row.11 != release.promotion.promoted_at.to_rfc3339()
        || row.12 != release.promotion.expires_at.to_rfc3339()
        || row.13 != release.digest()?
    {
        return Err(StorageError::ImmutableRecordMismatch {
            kind: "browser recipe release projection",
            id: recipe_aggregate_digest(recipe_id, version),
        });
    }
    Ok(release)
}

fn load_releases(
    connection: &Connection,
    project_id: &ProjectId,
) -> Result<Vec<BrowserRecipeRelease>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT recipe_id, version FROM browser_recipe_releases
         WHERE project_id = ?1 ORDER BY recipe_id, version",
    )?;
    let rows = statement
        .query_map([project_id.as_str()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(id, version)| {
            let version = to_u32(version)?;
            let recipe_id = BrowserRecipeId::from_stable(id);
            load_release(connection, project_id, &recipe_id, version)?.ok_or_else(|| {
                StorageError::ScopedRecordNotFound {
                    kind: "browser recipe release",
                    project_id: project_id.clone(),
                    id: recipe_aggregate_digest(&recipe_id, version),
                }
            })
        })
        .collect()
}

fn insert_activation(
    transaction: &Transaction<'_>,
    tenant_id: &TenantId,
    project_id: &ProjectId,
    activation: &BrowserRecipeActivation,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO browser_recipe_activations
           (tenant_id, project_id, recipe_id, recipe_id_digest, version, release_digest,
            previous_version, activation_evidence_digest, activated_at, activation_digest,
            record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            tenant_id.as_str(),
            project_id.as_str(),
            activation.recipe_id.as_str(),
            digest_identity(activation.recipe_id.as_str()),
            i64::from(activation.recipe_version),
            activation.release_digest,
            activation.previous_version.map(i64::from),
            activation.activation_evidence_digest,
            activation.activated_at.to_rfc3339(),
            activation.digest()?,
            serde_json::to_string(activation)?,
        ],
    )?;
    Ok(())
}

fn load_activation(
    connection: &Connection,
    project_id: &ProjectId,
    recipe_id: &BrowserRecipeId,
    version: u32,
) -> Result<Option<BrowserRecipeActivation>, StorageError> {
    let tenant_id = tenant_for_project(connection, project_id)?;
    let row = connection
        .query_row(
            "SELECT tenant_id, recipe_id_digest, release_digest, previous_version,
                    activation_evidence_digest, activated_at, activation_digest, record_json
             FROM browser_recipe_activations
             WHERE project_id = ?1 AND recipe_id = ?2 AND version = ?3",
            params![project_id.as_str(), recipe_id.as_str(), i64::from(version)],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                ))
            },
        )
        .optional()?;
    row.map(|row| {
        let activation: BrowserRecipeActivation = serde_json::from_str(&row.7)?;
        if row.0 != tenant_id.as_str()
            || activation.recipe_id != *recipe_id
            || activation.recipe_version != version
            || row.1 != digest_identity(recipe_id.as_str())
            || row.2 != activation.release_digest
            || row.3.map(to_u32).transpose()? != activation.previous_version
            || row.4 != activation.activation_evidence_digest
            || row.5 != activation.activated_at.to_rfc3339()
            || row.6 != activation.digest()?
        {
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "browser recipe activation projection",
                id: recipe_aggregate_digest(recipe_id, version),
            });
        }
        Ok(activation)
    })
    .transpose()
}

fn load_activations(
    connection: &Connection,
    project_id: &ProjectId,
) -> Result<Vec<BrowserRecipeActivation>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT recipe_id, version FROM browser_recipe_activations
         WHERE project_id = ?1 ORDER BY activated_at, recipe_id, version",
    )?;
    let rows = statement
        .query_map([project_id.as_str()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(id, version)| {
            let version = to_u32(version)?;
            let recipe_id = BrowserRecipeId::from_stable(id);
            load_activation(connection, project_id, &recipe_id, version)?.ok_or_else(|| {
                StorageError::ScopedRecordNotFound {
                    kind: "browser recipe activation",
                    project_id: project_id.clone(),
                    id: recipe_aggregate_digest(&recipe_id, version),
                }
            })
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn write_recipe_head(
    transaction: &Transaction<'_>,
    tenant_id: &TenantId,
    project_id: &ProjectId,
    recipe_id: &BrowserRecipeId,
    activation: &BrowserRecipeActivation,
    previous_head_revision: Option<u64>,
    next_head_revision: u64,
) -> Result<(), StorageError> {
    let changed = if let Some(previous_head_revision) = previous_head_revision {
        transaction.execute(
            "UPDATE browser_recipe_heads SET active_version = ?4, activation_digest = ?5,
                    revision = ?6, updated_at = ?7
             WHERE tenant_id = ?1 AND project_id = ?2 AND recipe_id = ?3
                   AND revision = ?8 AND active_version = ?9",
            params![
                tenant_id.as_str(),
                project_id.as_str(),
                recipe_id.as_str(),
                i64::from(activation.recipe_version),
                activation.digest()?,
                to_sql_u64(next_head_revision)?,
                activation.activated_at.to_rfc3339(),
                to_sql_u64(previous_head_revision)?,
                activation.previous_version.map(i64::from),
            ],
        )?
    } else {
        transaction.execute(
            "INSERT INTO browser_recipe_heads
               (tenant_id, project_id, recipe_id, recipe_id_digest, active_version,
                activation_digest, revision, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                tenant_id.as_str(),
                project_id.as_str(),
                recipe_id.as_str(),
                digest_identity(recipe_id.as_str()),
                i64::from(activation.recipe_version),
                activation.digest()?,
                to_sql_u64(next_head_revision)?,
                activation.activated_at.to_rfc3339(),
            ],
        )?
    };
    if changed != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!(
                "browser_recipe_head:{}",
                digest_identity(recipe_id.as_str())
            ),
            expected_revision: previous_head_revision.unwrap_or(0),
        });
    }
    Ok(())
}

fn load_heads(
    connection: &Connection,
    project_id: &ProjectId,
    tenant_id: &TenantId,
) -> Result<
    (
        Vec<BrowserRecipeActiveVersion>,
        BTreeMap<BrowserRecipeId, u64>,
    ),
    StorageError,
> {
    let mut statement = connection.prepare(
        "SELECT tenant_id, recipe_id, recipe_id_digest, active_version, activation_digest,
                revision, updated_at
         FROM browser_recipe_heads WHERE project_id = ?1 ORDER BY recipe_id",
    )?;
    let rows = statement
        .query_map([project_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, String>(6)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut active_versions = Vec::with_capacity(rows.len());
    let mut revisions = BTreeMap::new();
    for row in rows {
        let recipe_id = BrowserRecipeId::from_stable(row.1);
        let version = to_u32(row.3)?;
        let revision = to_u64(row.5)?;
        let activation =
            load_activation(connection, project_id, &recipe_id, version)?.ok_or_else(|| {
                StorageError::ImmutableRecordMismatch {
                    kind: "browser recipe head projection",
                    id: digest_identity(recipe_id.as_str()),
                }
            })?;
        let activation_count = connection.query_row(
            "SELECT COUNT(*) FROM browser_recipe_activations
             WHERE project_id = ?1 AND recipe_id = ?2",
            params![project_id.as_str(), recipe_id.as_str()],
            |row| row.get::<_, i64>(0),
        )?;
        if row.0 != tenant_id.as_str()
            || row.2 != digest_identity(recipe_id.as_str())
            || row.4 != activation.digest()?
            || revision == 0
            || revision != to_u64(activation_count)?
            || row.6 != activation.activated_at.to_rfc3339()
            || revisions.insert(recipe_id.clone(), revision).is_some()
        {
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "browser recipe head projection",
                id: digest_identity(recipe_id.as_str()),
            });
        }
        active_versions.push(BrowserRecipeActiveVersion {
            recipe_id,
            version,
            activation_digest: row.4,
        });
    }
    Ok((active_versions, revisions))
}

fn trust_key_event(
    event_type: &str,
    record: &DurableBrowserRecipeTrustKey,
    recorded_at: DateTime<Utc>,
) -> Result<PendingEvent, StorageError> {
    Ok(PendingEvent::new(
        event_type,
        serde_json::json!({
            "keyIdDigest": digest_identity(&record.key.id),
            "keyRecordDigest": record.digest()?,
            "purpose": key_purpose_name(record.key.purpose),
            "publicKeyDigest": public_key_digest(&record.key)?,
            "installationEvidenceDigest": record.installation_evidence_digest,
            "revocationEvidenceDigest": record.revocation_evidence_digest,
            "validFrom": record.key.valid_from,
            "validUntil": record.key.valid_until,
            "revokedAt": record.key.revoked_at,
            "revision": record.key.revision,
        }),
        recorded_at,
    ))
}

fn candidate_event(
    candidate: &BrowserRecipeCandidate,
    recorded_at: DateTime<Utc>,
) -> Result<PendingEvent, StorageError> {
    let manifest = &candidate.manifest;
    Ok(PendingEvent::new(
        "browser.recipe_candidate_registered",
        serde_json::json!({
            "recipeIdDigest": digest_identity(manifest.id.as_str()),
            "version": manifest.version,
            "candidateDigest": candidate.digest()?,
            "providerDigest": digest_identity(&manifest.provider),
            "originDigest": manifest.origin_digest,
            "capabilityDigest": digest_identity(&manifest.capability),
            "publisherKeyIdDigest": digest_identity(&manifest.publisher_key_id),
            "createdAt": manifest.created_at,
            "expiresAt": manifest.expires_at,
        }),
        recorded_at,
    ))
}

fn release_event(
    release: &BrowserRecipeRelease,
    recorded_at: DateTime<Utc>,
) -> Result<PendingEvent, StorageError> {
    let manifest = &release.candidate.manifest;
    Ok(PendingEvent::new(
        "browser.recipe_release_registered",
        serde_json::json!({
            "recipeIdDigest": digest_identity(manifest.id.as_str()),
            "version": manifest.version,
            "candidateDigest": release.candidate.digest()?,
            "releaseDigest": release.digest()?,
            "releaseKeyIdDigest": digest_identity(&release.promotion.release_key_id),
            "v1ResultDigest": release.promotion.evidence.v1_result_digest,
            "v2ResultDigest": release.promotion.evidence.v2_result_digest,
            "safetySuiteDigest": release.promotion.evidence.safety_suite_digest,
            "contaminationAuditDigest": release.promotion.evidence.contamination_audit_digest,
            "rollbackStrategyDigest": release.promotion.evidence.rollback_strategy_digest,
            "promotionApprovalDigest": release.promotion.evidence.promotion_approval_digest,
            "promotedAt": release.promotion.promoted_at,
            "expiresAt": release.promotion.expires_at,
        }),
        recorded_at,
    ))
}

fn activation_event(
    activation: &BrowserRecipeActivation,
    head_revision: u64,
) -> Result<PendingEvent, StorageError> {
    Ok(PendingEvent::new(
        "browser.recipe_release_activated",
        serde_json::json!({
            "recipeIdDigest": digest_identity(activation.recipe_id.as_str()),
            "version": activation.recipe_version,
            "releaseDigest": activation.release_digest,
            "previousVersion": activation.previous_version,
            "activationEvidenceDigest": activation.activation_evidence_digest,
            "activationDigest": activation.digest()?,
            "headRevision": head_revision,
            "activatedAt": activation.activated_at,
        }),
        activation.activated_at,
    ))
}

fn key_purpose_name(purpose: BrowserRecipeKeyPurpose) -> &'static str {
    match purpose {
        BrowserRecipeKeyPurpose::CandidatePublisher => "candidate_publisher",
        BrowserRecipeKeyPurpose::ProductionRelease => "production_release",
    }
}

fn effect_class_name(effect_class: &EffectClass) -> &'static str {
    match effect_class {
        EffectClass::Read => "read",
        EffectClass::LocalWrite => "local_write",
        EffectClass::ExternalWrite => "external_write",
        EffectClass::Outreach => "outreach",
        EffectClass::Spend => "spend",
        EffectClass::Payment => "payment",
    }
}

fn public_key_digest(key: &TrustedBrowserRecipeKey) -> Result<String, StorageError> {
    let bytes = hex::decode(&key.public_key_hex)
        .map_err(|_| StorageError::DomainDecode("invalid browser recipe public key".into()))?;
    Ok(digest_bytes(&bytes))
}

fn recipe_aggregate_digest(recipe_id: &BrowserRecipeId, version: u32) -> String {
    digest_bytes(format!("{}:{version}", recipe_id.as_str()).as_bytes())
}

fn digest_identity(value: &str) -> String {
    digest_bytes(value.as_bytes())
}

fn digest_json(value: &impl Serialize) -> Result<String, StorageError> {
    Ok(digest_bytes(&serde_json::to_vec(value)?))
}

fn digest_bytes(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn idempotent(state_revision: u64) -> AtomicMutation {
    AtomicMutation {
        event_sequences: Vec::new(),
        outbox_sequences: Vec::new(),
        state_revision,
    }
}

fn to_sql_u64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::RevisionOverflow(value))
}

fn to_u64(value: i64) -> Result<u64, StorageError> {
    u64::try_from(value).map_err(|_| StorageError::DomainDecode("negative revision".into()))
}

fn to_u32(value: i64) -> Result<u32, StorageError> {
    u32::try_from(value).map_err(|_| StorageError::DomainDecode("invalid recipe version".into()))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use chrono::{Duration, TimeZone};
    use hartevo_browser_adapter::{
        BrowserActionKind, BrowserActionRisk, BrowserActionSurface,
        BrowserRecipeEvaluationEvidence, BrowserRecipeManifest, BrowserRecipePromotion,
        BrowserRecipeStep,
    };
    use hartevo_domain_kernel::{Project, StorageMode};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use tempfile::tempdir;

    use super::*;
    use crate::{DatabaseKey, STORAGE_SCHEMA_VERSION};

    struct RecipeFixture {
        now: DateTime<Utc>,
        candidate_signer: Ed25519KeyPair,
        release_signer: Ed25519KeyPair,
        project: Project,
    }

    fn fixture(root: &std::path::Path) -> RecipeFixture {
        RecipeFixture {
            now: Utc
                .with_ymd_and_hms(2026, 8, 11, 18, 0, 0)
                .single()
                .expect("time"),
            candidate_signer: Ed25519KeyPair::from_seed_unchecked(&[17; 32])
                .expect("candidate signer"),
            release_signer: Ed25519KeyPair::from_seed_unchecked(&[19; 32]).expect("release signer"),
            project: Project::create_local(
                TenantId::from("tenant-recipe-storage"),
                ProjectId::from("project-recipe-storage"),
                "Recipe storage",
                "",
                root,
                StorageMode::LocalExisting,
            )
            .expect("project"),
        }
    }

    fn trust_keys(fixture: &RecipeFixture) -> [TrustedBrowserRecipeKey; 2] {
        [
            TrustedBrowserRecipeKey::new(
                "candidate-key-storage",
                BrowserRecipeKeyPurpose::CandidatePublisher,
                fixture.candidate_signer.public_key().as_ref(),
                fixture.now - Duration::days(1),
                fixture.now + Duration::days(400),
            )
            .expect("candidate key"),
            TrustedBrowserRecipeKey::new(
                "release-key-storage",
                BrowserRecipeKeyPurpose::ProductionRelease,
                fixture.release_signer.public_key().as_ref(),
                fixture.now - Duration::days(1),
                fixture.now + Duration::days(400),
            )
            .expect("release key"),
        ]
    }

    fn candidate(fixture: &RecipeFixture, version: u32) -> BrowserRecipeCandidate {
        let manifest = BrowserRecipeManifest {
            schema_version: 1,
            id: BrowserRecipeId::from("durable-publish-recipe"),
            version,
            provider: "fixture-private-provider".into(),
            origin_digest: "1".repeat(64),
            capability: "channel.publish".into(),
            effect_class: EffectClass::ExternalWrite,
            steps: vec![BrowserRecipeStep {
                sequence: 1,
                kind: BrowserActionKind::Click,
                surface: BrowserActionSurface::Semantic,
                risk: BrowserActionRisk::PotentialExternalWrite,
                selector_digest: "2".repeat(64),
            }],
            publisher_key_id: "candidate-key-storage".into(),
            created_at: fixture.now - Duration::hours(1),
            expires_at: fixture.now + Duration::days(30),
        };
        let payload = BrowserRecipeCandidate::signing_payload(&manifest).expect("payload");
        BrowserRecipeCandidate::new(
            manifest,
            hex::encode(fixture.candidate_signer.sign(&payload).as_ref()),
        )
        .expect("candidate")
    }

    fn release(fixture: &RecipeFixture, version: u32) -> BrowserRecipeRelease {
        let candidate = candidate(fixture, version);
        let evidence = BrowserRecipeEvaluationEvidence {
            v1_dataset_revision: format!("recipe-v1-holdout-{version}"),
            v1_result_digest: "3".repeat(64),
            v1_passed: 9,
            v1_total: 10,
            v2_dataset_revision: format!("recipe-v2-shadow-{version}"),
            v2_result_digest: "4".repeat(64),
            v2_passed: 4,
            v2_total: 5,
            safety_suite_digest: "5".repeat(64),
            contamination_audit_digest: "6".repeat(64),
            rollback_strategy_digest: "7".repeat(64),
            promotion_approval_digest: "8".repeat(64),
        };
        let candidate_digest = candidate.digest().expect("candidate digest");
        let promoted_at = fixture.now - Duration::minutes(30);
        let expires_at = fixture.now + Duration::days(20);
        let payload = BrowserRecipePromotion::signing_payload(
            &candidate_digest,
            &evidence,
            "release-key-storage",
            promoted_at,
            expires_at,
        )
        .expect("promotion payload");
        BrowserRecipeRelease {
            candidate,
            promotion: BrowserRecipePromotion {
                schema_version: 1,
                candidate_digest,
                evidence,
                release_key_id: "release-key-storage".into(),
                promoted_at,
                expires_at,
                signature_hex: hex::encode(fixture.release_signer.sign(&payload).as_ref()),
            },
        }
    }

    fn install_fixture_state(store: &mut ProjectStore, fixture: &RecipeFixture, versions: &[u32]) {
        store.save_project(&fixture.project).expect("save project");
        for (index, key) in trust_keys(fixture).into_iter().enumerate() {
            store
                .install_browser_recipe_trust_key_atomic(
                    &fixture.project.id,
                    key,
                    if index == 0 {
                        "9".repeat(64)
                    } else {
                        "a".repeat(64)
                    },
                    fixture.now,
                )
                .expect("install trust key");
        }
        for version in versions {
            let release = release(fixture, *version);
            store
                .register_browser_recipe_candidate_atomic(
                    &fixture.project.id,
                    release.candidate.clone(),
                    fixture.now,
                )
                .expect("register candidate");
            store
                .register_browser_recipe_release_atomic(&fixture.project.id, release, fixture.now)
                .expect("register release");
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one durable journey proves encrypted registration, activation, restart, revocation, redaction, and projection tamper fencing"
    )]
    fn recipe_trust_activation_and_revocation_survive_restart_and_fail_closed() {
        let directory = tempdir().expect("directory");
        let database_path = directory.path().join("recipe-state.sqlite3");
        let key = DatabaseKey::new([59; 32]).expect("database key");
        let fixture = fixture(directory.path());
        let recipe_id = BrowserRecipeId::from("durable-publish-recipe");
        let release_signature = release(&fixture, 1).promotion.signature_hex;
        {
            let mut store = ProjectStore::open(&database_path, &key).expect("store");
            install_fixture_state(&mut store, &fixture, &[1]);
            let activated = store
                .activate_browser_recipe_release_atomic(
                    &fixture.project.id,
                    &recipe_id,
                    1,
                    None,
                    &"b".repeat(64),
                    fixture.now,
                )
                .expect("activate");
            assert_eq!(activated.state_revision, 1);
            assert_eq!(activated.event_sequences.len(), 1);
            let replay = store
                .activate_browser_recipe_release_atomic(
                    &fixture.project.id,
                    &recipe_id,
                    1,
                    None,
                    &"b".repeat(64),
                    fixture.now,
                )
                .expect("idempotent activation replay");
            assert!(replay.event_sequences.is_empty());
            assert!(matches!(
                store.activate_browser_recipe_release_atomic(
                    &fixture.project.id,
                    &recipe_id,
                    1,
                    None,
                    &"c".repeat(64),
                    fixture.now,
                ),
                Err(StorageError::Browser(
                    hartevo_browser_adapter::BrowserError::RecipeActivationConflict
                ))
            ));
            let payloads = store
                .connection
                .prepare(
                    "SELECT payload_json FROM domain_events
                     WHERE project_id = ?1 ORDER BY sequence",
                )
                .expect("payload statement")
                .query_map([fixture.project.id.as_str()], |row| row.get::<_, String>(0))
                .expect("payload rows")
                .collect::<Result<Vec<_>, _>>()
                .expect("payloads")
                .join("\n");
            for private_value in [
                "durable-publish-recipe",
                "candidate-key-storage",
                "release-key-storage",
                "fixture-private-provider",
                "channel.publish",
                release_signature.as_str(),
            ] {
                assert!(!payloads.contains(private_value));
            }
        }
        {
            let mut restarted = ProjectStore::open(&database_path, &key).expect("restart");
            let restored = restarted
                .load_browser_recipe_runtime_state(&fixture.project.id)
                .expect("restore runtime state");
            assert_eq!(restored.registry.active_version(&recipe_id), Some(1));
            assert_eq!(restored.head_revision(&recipe_id), Some(1));
            restored
                .registry
                .active_release(&recipe_id)
                .expect("active release")
                .verify(&restored.trust, fixture.now + Duration::seconds(1))
                .expect("current signature after restart");
            restarted
                .revoke_browser_recipe_trust_key_atomic(
                    &fixture.project.id,
                    "release-key-storage",
                    1,
                    "d".repeat(64),
                    fixture.now + Duration::seconds(2),
                )
                .expect("persist revocation");
        }
        {
            let restarted = ProjectStore::open(&database_path, &key).expect("revoked restart");
            let restored = restarted
                .load_browser_recipe_runtime_state(&fixture.project.id)
                .expect("restore revoked state");
            assert_eq!(
                restored
                    .registry
                    .active_release(&recipe_id)
                    .expect("active release")
                    .verify(&restored.trust, fixture.now + Duration::seconds(3))
                    .expect_err("revoked release key must stop execution")
                    .code(),
                "BROWSER_RECIPE_KEY_REVOKED"
            );
            restarted
                .connection
                .execute(
                    "UPDATE browser_recipe_candidates SET provider_digest = ?4
                     WHERE project_id = ?1 AND recipe_id = ?2 AND version = ?3",
                    params![
                        fixture.project.id.as_str(),
                        recipe_id.as_str(),
                        1_i64,
                        "f".repeat(64)
                    ],
                )
                .expect("tamper projection");
            assert!(matches!(
                restarted.load_browser_recipe_runtime_state(&fixture.project.id),
                Err(StorageError::ImmutableRecordMismatch {
                    kind: "browser recipe candidate projection",
                    ..
                })
            ));
        }
    }

    #[test]
    fn activation_head_is_monotonic_cas_and_rollback_projection_fails_closed() {
        let directory = tempdir().expect("directory");
        let database_path = directory.path().join("recipe-head.sqlite3");
        let key = DatabaseKey::new([61; 32]).expect("database key");
        let fixture = fixture(directory.path());
        let recipe_id = BrowserRecipeId::from("durable-publish-recipe");
        let mut store = ProjectStore::open(&database_path, &key).expect("store");
        install_fixture_state(&mut store, &fixture, &[1, 2]);
        store
            .activate_browser_recipe_release_atomic(
                &fixture.project.id,
                &recipe_id,
                1,
                None,
                &"b".repeat(64),
                fixture.now,
            )
            .expect("activate v1");
        assert!(matches!(
            store.activate_browser_recipe_release_atomic(
                &fixture.project.id,
                &recipe_id,
                2,
                None,
                &"c".repeat(64),
                fixture.now + Duration::seconds(1),
            ),
            Err(StorageError::Browser(
                hartevo_browser_adapter::BrowserError::RecipeActivationConflict
            ))
        ));
        let v2 = store
            .activate_browser_recipe_release_atomic(
                &fixture.project.id,
                &recipe_id,
                2,
                Some(1),
                &"c".repeat(64),
                fixture.now + Duration::seconds(1),
            )
            .expect("activate v2");
        assert_eq!(v2.state_revision, 2);
        drop(store);

        let restarted = ProjectStore::open(&database_path, &key).expect("restart");
        let state = restarted
            .load_browser_recipe_runtime_state(&fixture.project.id)
            .expect("restore v2");
        assert_eq!(state.registry.active_version(&recipe_id), Some(2));
        assert_eq!(state.head_revision(&recipe_id), Some(2));
        restarted
            .connection
            .execute(
                "UPDATE browser_recipe_heads SET active_version = 1,
                        activation_digest = (
                          SELECT activation_digest FROM browser_recipe_activations
                          WHERE project_id = ?1 AND recipe_id = ?2 AND version = 1
                        ), revision = 1
                 WHERE project_id = ?1 AND recipe_id = ?2",
                params![fixture.project.id.as_str(), recipe_id.as_str()],
            )
            .expect("tamper rollback head");
        assert!(matches!(
            restarted.load_browser_recipe_runtime_state(&fixture.project.id),
            Err(StorageError::ImmutableRecordMismatch {
                kind: "browser recipe head projection",
                ..
            } | StorageError::Browser(
                hartevo_browser_adapter::BrowserError::RecipeActivationConflict
            ))
        ));
    }

    #[test]
    fn migration_v34_backs_up_v33_and_reinstalls_recipe_tables_idempotently() {
        let directory = tempdir().expect("directory");
        let database_path = directory.path().join("recipe-migration.sqlite3");
        let key = DatabaseKey::new([67; 32]).expect("key");
        {
            let store = ProjectStore::open(&database_path, &key).expect("current store");
            crate::downgrade_identity_bootstrap_schema_for_test(&store.connection);
            store
                .connection
                .execute_batch(
                    "DROP TABLE browser_recipe_heads;
                     DROP TABLE browser_recipe_activations;
                     DROP TABLE browser_recipe_releases;
                     DROP TABLE browser_recipe_candidates;
                     DROP TABLE browser_recipe_trust_keys;
                     DROP TABLE IF EXISTS runtime_turn_private_messages;
                     DROP TABLE IF EXISTS mission_conversation_messages;
                     DROP TABLE IF EXISTS mission_conversations;
                     DROP TABLE IF EXISTS mission_checkpoints;
                     DROP TABLE IF EXISTS mission_definition_oracles;
                     DROP TABLE IF EXISTS mission_definition_artifacts;
                     DROP TABLE IF EXISTS mission_definition_capabilities;
                     DROP TABLE IF EXISTS mission_definitions;
                     DELETE FROM schema_migrations WHERE version >= 34;",
                )
                .expect("construct v33");
        }
        {
            let store = ProjectStore::open(&database_path, &key).expect("migrate v33");
            assert_eq!(
                super::super::current_schema_version(&store.connection).expect("version"),
                STORAGE_SCHEMA_VERSION
            );
            let table_count = store
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'
                     AND name IN (
                       'browser_recipe_trust_keys', 'browser_recipe_candidates',
                       'browser_recipe_releases', 'browser_recipe_activations',
                       'browser_recipe_heads'
                     )",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("table count");
            assert_eq!(table_count, 5);
        }
        let backup_count = fs::read_dir(directory.path())
            .expect("list directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v33")
            })
            .count();
        assert_eq!(backup_count, 1);
        drop(ProjectStore::open(&database_path, &key).expect("idempotent reopen"));
        let reopened_backup_count = fs::read_dir(directory.path())
            .expect("list directory after reopen")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v33")
            })
            .count();
        assert_eq!(reopened_backup_count, 1);
    }
}
