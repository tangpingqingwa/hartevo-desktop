//! SQLCipher-backed Signed Browser Recipe trust and registry persistence.
//!
//! Complete public keys, signed manifests, signatures, and evaluation records
//! remain inside the encrypted database. Normalized projections and
//! Event/Outbox payloads contain only scope, lifecycle metadata, and digests.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use hartevo_browser_adapter::{
    BrowserRecipeActivation, BrowserRecipeActiveVersion, BrowserRecipeAuthorityBlockKind,
    BrowserRecipeAuthorityKeyPurpose, BrowserRecipeAuthorityObservation,
    BrowserRecipeAuthorityRootHead, BrowserRecipeAuthorityTombstone, BrowserRecipeCandidate,
    BrowserRecipeKeyPurpose, BrowserRecipeRegistry, BrowserRecipeRegistrySnapshot,
    BrowserRecipeRelease, BrowserRecipeTrustSnapshot, BrowserRecipeTrustStore,
    TrustedBrowserRecipeKey,
};
use hartevo_domain_kernel::{BrowserRecipeId, EffectClass, ProjectId, TenantId};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::aggregate::{AtomicMutation, PendingEvent, append_events};
use crate::{ProjectStore, SecretReference, StorageError};

const RECIPE_PERSISTENCE_SCHEMA_VERSION: u32 = 1;
const RECIPE_AUTHORITY_PERSISTENCE_SCHEMA_VERSION: u32 = 1;

/// Result of an atomic, monotonic Recipe root-authority persistence attempt.
/// Exact current-head retries have no event/outbox side effects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserRecipeAuthorityPersistOutcome {
    pub snapshot_revision: u64,
    pub rotation_epoch: u64,
    pub duplicate: bool,
    pub event_sequences: Vec<i64>,
    pub outbox_sequences: Vec<i64>,
}

/// Crash-recovered, secret-free lifecycle state plus its opaque OS-store
/// reference. The referenced private root bytes never enter SQLCipher.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DurableBrowserRecipeAuthorityState {
    pub observation: BrowserRecipeAuthorityObservation,
    pub previous_snapshot_digest: Option<String>,
    pub active_root_secret_reference: Option<SecretReference>,
}

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

    /// Validates the checked lifecycle admission contract before any database
    /// transaction begins. With the baseline empty registration set this
    /// always fails closed and cannot create durable rows.
    #[allow(clippy::too_many_arguments)]
    pub fn persist_browser_recipe_root_authority_snapshot_atomic(
        &mut self,
        snapshot_json: &str,
        expected_tenant_id: &TenantId,
        expected_project_id: &ProjectId,
        expected_snapshot_revision: u64,
        expected_snapshot_as_of: DateTime<Utc>,
        expected_snapshot_digest: &str,
        validation_at: DateTime<Utc>,
        active_root_secret_reference: Option<&SecretReference>,
    ) -> Result<BrowserRecipeAuthorityPersistOutcome, StorageError> {
        let observation =
            BrowserRecipeTrustStore::validate_supplied_root_authority_snapshot_for_persistence(
                snapshot_json,
                expected_tenant_id,
                expected_project_id,
                expected_snapshot_revision,
                expected_snapshot_as_of,
                expected_snapshot_digest,
                validation_at,
            )?;
        self.persist_browser_recipe_authority_observation_atomic(
            &observation,
            active_root_secret_reference,
        )
    }

    /// Restores and revalidates the complete append-only observation chain,
    /// tombstone set, head projection, and opaque root-secret references.
    /// Returned data is not current authority and cannot authorize dispatch.
    pub fn load_browser_recipe_root_authority_state(
        &self,
        project_id: &ProjectId,
    ) -> Result<Option<DurableBrowserRecipeAuthorityState>, StorageError> {
        let tenant_id = tenant_for_project(&self.connection, project_id)?;
        load_durable_authority_state(&self.connection, project_id, &tenant_id)
    }

    fn persist_browser_recipe_authority_observation_atomic(
        &mut self,
        observation: &BrowserRecipeAuthorityObservation,
        active_root_secret_reference: Option<&SecretReference>,
    ) -> Result<BrowserRecipeAuthorityPersistOutcome, StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let tenant_id = tenant_for_project(&transaction, &observation.project_id)?;
        validate_authority_observation(observation, &tenant_id, &observation.project_id)?;
        let credential_id =
            validate_active_root_secret_reference(observation, active_root_secret_reference)?;
        let current =
            load_durable_authority_state(&transaction, &observation.project_id, &tenant_id)?;
        if let Some(current) = current.as_ref() {
            if observation.snapshot_revision == current.observation.snapshot_revision {
                if observation == &current.observation
                    && active_root_secret_reference == current.active_root_secret_reference.as_ref()
                {
                    return Ok(BrowserRecipeAuthorityPersistOutcome {
                        snapshot_revision: observation.snapshot_revision,
                        rotation_epoch: observation.rotation_epoch,
                        duplicate: true,
                        event_sequences: Vec::new(),
                        outbox_sequences: Vec::new(),
                    });
                }
                return Err(authority_mismatch(
                    "browser recipe authority replay conflict",
                    &observation.project_id,
                ));
            }
            validate_authority_transition(&current.observation, observation)?;
        }
        let previous_snapshot_digest = current
            .as_ref()
            .map(|state| state.observation.snapshot_digest.as_str());
        insert_authority_snapshot(
            &transaction,
            observation,
            previous_snapshot_digest,
            credential_id.as_deref(),
        )?;
        persist_authority_tombstones(&transaction, observation)?;
        if let (Some(root), Some(reference)) = (
            observation.active_root.as_ref(),
            active_root_secret_reference,
        ) {
            persist_root_secret_reference(&transaction, observation, root, reference)?;
        }
        write_authority_head(
            &transaction,
            observation,
            credential_id.as_deref(),
            current
                .as_ref()
                .map(|state| state.observation.snapshot_revision),
        )?;
        let event = PendingEvent::new(
            "browser.recipe_root_authority_snapshot_observed",
            serde_json::json!({
                "snapshotDigest": observation.snapshot_digest,
                "stateDigest": observation.state_digest,
                "snapshotRevision": observation.snapshot_revision,
                "rotationEpoch": observation.rotation_epoch,
                "activeRootKeyIdDigest": observation.active_root.as_ref()
                    .map(|root| digest_identity(&root.key_id)),
                "tombstoneDigests": observation.tombstones.iter()
                    .map(|tombstone| authority_tombstone_digest(
                        &observation.tenant_id,
                        &observation.project_id,
                        tombstone,
                    ))
                    .collect::<Result<Vec<_>, _>>()?,
                "snapshotFreshnessAuthority": false,
                "productionDispatch": false,
            }),
            observation.validation_at,
        );
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            observation.tenant_id.as_str(),
            observation.project_id.as_str(),
            None,
            "browser_recipe_root_authority",
            &digest_identity(observation.project_id.as_str()),
            &[event],
        )?;
        transaction.commit()?;
        Ok(BrowserRecipeAuthorityPersistOutcome {
            snapshot_revision: observation.snapshot_revision,
            rotation_epoch: observation.rotation_epoch,
            duplicate: false,
            event_sequences,
            outbox_sequences,
        })
    }
}

fn authority_mismatch(kind: &'static str, project_id: &ProjectId) -> StorageError {
    StorageError::ImmutableRecordMismatch {
        kind,
        id: digest_identity(project_id.as_str()),
    }
}

fn valid_authority_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1_024
        && value == value.trim()
        && !value.chars().any(char::is_control)
}

fn validate_authority_observation(
    observation: &BrowserRecipeAuthorityObservation,
    expected_tenant_id: &TenantId,
    expected_project_id: &ProjectId,
) -> Result<(), StorageError> {
    if observation.schema_version != RECIPE_AUTHORITY_PERSISTENCE_SCHEMA_VERSION
        || &observation.tenant_id != expected_tenant_id
        || &observation.project_id != expected_project_id
        || observation.snapshot_revision == 0
        || observation.rotation_epoch == 0
        || observation.snapshot_as_of > observation.validation_at
        || !is_sha256(&observation.snapshot_digest)
        || !is_sha256(&observation.state_digest)
        || observation.snapshot_freshness_authority
        || observation.production_dispatch
    {
        return Err(authority_mismatch(
            "browser recipe authority observation",
            expected_project_id,
        ));
    }
    if let Some(root) = observation.active_root.as_ref()
        && (!valid_authority_identifier(&root.key_id)
            || !is_sha256(&root.public_key_digest)
            || root.generation != observation.rotation_epoch
            || root.revision == 0
            || !is_sha256(&root.lineage_digest))
    {
        return Err(authority_mismatch(
            "browser recipe authority active root",
            expected_project_id,
        ));
    }
    let mut identities = std::collections::BTreeSet::new();
    let mut previous_identity = None;
    for tombstone in &observation.tombstones {
        let identity = (tombstone.key_id.clone(), tombstone.kind);
        if !valid_authority_identifier(&tombstone.key_id)
            || !is_sha256(&tombstone.public_key_digest)
            || tombstone.blocked_revision == 0
            || !is_sha256(&tombstone.lineage_digest)
            || tombstone.effective_at > observation.snapshot_as_of
            || !identities.insert(identity.clone())
            || previous_identity
                .as_ref()
                .is_some_and(|previous| previous >= &identity)
            || observation
                .active_root
                .as_ref()
                .is_some_and(|root| root.key_id == tombstone.key_id)
        {
            return Err(authority_mismatch(
                "browser recipe authority tombstone",
                expected_project_id,
            ));
        }
        previous_identity = Some(identity);
    }
    Ok(())
}

fn validate_active_root_secret_reference(
    observation: &BrowserRecipeAuthorityObservation,
    reference: Option<&SecretReference>,
) -> Result<Option<String>, StorageError> {
    match (&observation.active_root, reference) {
        (None, None) => Ok(None),
        (Some(root), Some(reference)) => {
            let expected = SecretReference::browser_recipe_root_signing_key(
                observation.tenant_id.clone(),
                observation.project_id.clone(),
                &root.key_id,
                root.generation,
            )
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
            if reference != &expected {
                return Err(authority_mismatch(
                    "browser recipe root secret reference",
                    &observation.project_id,
                ));
            }
            reference
                .credential_id()
                .map(Some)
                .map_err(|error| StorageError::DomainDecode(error.to_string()))
        }
        _ => Err(authority_mismatch(
            "browser recipe root secret reference",
            &observation.project_id,
        )),
    }
}

fn validate_authority_transition(
    current: &BrowserRecipeAuthorityObservation,
    next: &BrowserRecipeAuthorityObservation,
) -> Result<(), StorageError> {
    if current.tenant_id != next.tenant_id
        || current.project_id != next.project_id
        || next.snapshot_revision <= current.snapshot_revision
        || next.snapshot_as_of < current.snapshot_as_of
        || next.snapshot_digest == current.snapshot_digest
    {
        return Err(authority_mismatch(
            "browser recipe authority rollback",
            &next.project_id,
        ));
    }
    let next_tombstones = next
        .tombstones
        .iter()
        .map(|tombstone| ((&tombstone.key_id, tombstone.kind), tombstone))
        .collect::<BTreeMap<_, _>>();
    if current.tombstones.iter().any(|tombstone| {
        next_tombstones
            .get(&(&tombstone.key_id, tombstone.kind))
            .is_none_or(|next| *next != tombstone)
    }) {
        return Err(authority_mismatch(
            "browser recipe authority tombstone rollback",
            &next.project_id,
        ));
    }
    if next.rotation_epoch == current.rotation_epoch {
        match (&current.active_root, &next.active_root) {
            (Some(current_root), Some(next_root)) if current_root == next_root => {}
            (Some(current_root), None)
                if next.tombstones.iter().any(|tombstone| {
                    tombstone.key_id == current_root.key_id
                        && tombstone.public_key_digest == current_root.public_key_digest
                        && tombstone.kind == BrowserRecipeAuthorityBlockKind::Compromised
                }) => {}
            (None, None) => {}
            _ => {
                return Err(authority_mismatch(
                    "browser recipe authority epoch binding",
                    &next.project_id,
                ));
            }
        }
    } else {
        let expected_epoch = current
            .rotation_epoch
            .checked_add(1)
            .ok_or(StorageError::RevisionOverflow(current.rotation_epoch))?;
        let (Some(current_root), Some(next_root)) = (&current.active_root, &next.active_root)
        else {
            return Err(authority_mismatch(
                "browser recipe authority rotation head",
                &next.project_id,
            ));
        };
        if next.rotation_epoch != expected_epoch
            || next_root.generation != expected_epoch
            || next_root.key_id == current_root.key_id
            || next_root.public_key_digest == current_root.public_key_digest
            || next_root.lineage_digest == current_root.lineage_digest
        {
            return Err(authority_mismatch(
                "browser recipe authority rotation epoch",
                &next.project_id,
            ));
        }
    }
    Ok(())
}

fn authority_observation_digest(
    observation: &BrowserRecipeAuthorityObservation,
) -> Result<String, StorageError> {
    digest_json(&(
        "hartevo-browser-recipe-authority-observation/v1",
        observation,
    ))
}

fn authority_tombstone_digest(
    tenant_id: &TenantId,
    project_id: &ProjectId,
    tombstone: &BrowserRecipeAuthorityTombstone,
) -> Result<String, StorageError> {
    digest_json(&(
        "hartevo-browser-recipe-authority-tombstone/v1",
        tenant_id,
        project_id,
        tombstone,
    ))
}

fn root_reference_digest(reference: &SecretReference) -> Result<String, StorageError> {
    digest_json(&("hartevo-browser-recipe-root-secret-reference/v1", reference))
}

fn authority_purpose_name(purpose: BrowserRecipeAuthorityKeyPurpose) -> &'static str {
    match purpose {
        BrowserRecipeAuthorityKeyPurpose::RootAuthority => "root_authority",
        BrowserRecipeAuthorityKeyPurpose::CandidatePublisher => "candidate_publisher",
        BrowserRecipeAuthorityKeyPurpose::ProductionRelease => "production_release",
    }
}

fn authority_block_kind_name(kind: BrowserRecipeAuthorityBlockKind) -> &'static str {
    match kind {
        BrowserRecipeAuthorityBlockKind::Revoked => "revoked",
        BrowserRecipeAuthorityBlockKind::Compromised => "compromised",
    }
}

fn insert_authority_snapshot(
    transaction: &Transaction<'_>,
    observation: &BrowserRecipeAuthorityObservation,
    previous_snapshot_digest: Option<&str>,
    active_secret_credential_id: Option<&str>,
) -> Result<(), StorageError> {
    let root = observation.active_root.as_ref();
    transaction.execute(
        "INSERT INTO browser_recipe_authority_snapshots
           (tenant_id, project_id, snapshot_revision, snapshot_as_of, validation_at,
            snapshot_digest, state_digest, rotation_epoch, previous_snapshot_digest,
            active_root_key_id, active_root_public_key_digest, active_root_generation,
            active_root_revision, active_root_lineage_digest, active_secret_credential_id,
            observation_digest, observation_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                 ?14, ?15, ?16, ?17)",
        params![
            observation.tenant_id.as_str(),
            observation.project_id.as_str(),
            to_sql_u64(observation.snapshot_revision)?,
            observation.snapshot_as_of.to_rfc3339(),
            observation.validation_at.to_rfc3339(),
            observation.snapshot_digest,
            observation.state_digest,
            to_sql_u64(observation.rotation_epoch)?,
            previous_snapshot_digest,
            root.map(|root| root.key_id.as_str()),
            root.map(|root| root.public_key_digest.as_str()),
            root.map(|root| to_sql_u64(root.generation)).transpose()?,
            root.map(|root| to_sql_u64(root.revision)).transpose()?,
            root.map(|root| root.lineage_digest.as_str()),
            active_secret_credential_id,
            authority_observation_digest(observation)?,
            serde_json::to_string(observation)?,
        ],
    )?;
    Ok(())
}

fn persist_authority_tombstones(
    transaction: &Transaction<'_>,
    observation: &BrowserRecipeAuthorityObservation,
) -> Result<(), StorageError> {
    for tombstone in &observation.tombstones {
        let digest =
            authority_tombstone_digest(&observation.tenant_id, &observation.project_id, tombstone)?;
        let record_json = serde_json::to_string(tombstone)?;
        let inserted = transaction.execute(
            "INSERT INTO browser_recipe_authority_tombstones
               (tenant_id, project_id, key_id, key_id_digest, purpose,
                public_key_digest, blocked_revision, lineage_digest, block_kind,
                effective_at, first_snapshot_revision, tombstone_digest, tombstone_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(project_id, key_id, block_kind) DO NOTHING",
            params![
                observation.tenant_id.as_str(),
                observation.project_id.as_str(),
                tombstone.key_id,
                digest_identity(&tombstone.key_id),
                authority_purpose_name(tombstone.purpose),
                tombstone.public_key_digest,
                to_sql_u64(tombstone.blocked_revision)?,
                tombstone.lineage_digest,
                authority_block_kind_name(tombstone.kind),
                tombstone.effective_at.to_rfc3339(),
                to_sql_u64(observation.snapshot_revision)?,
                digest,
                record_json,
            ],
        )?;
        if inserted == 0 {
            let stored = transaction
                .query_row(
                    "SELECT tombstone_digest, tombstone_json
                     FROM browser_recipe_authority_tombstones
                     WHERE project_id = ?1 AND key_id = ?2 AND block_kind = ?3",
                    params![
                        observation.project_id.as_str(),
                        tombstone.key_id,
                        authority_block_kind_name(tombstone.kind),
                    ],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?
                .ok_or_else(|| {
                    authority_mismatch(
                        "browser recipe authority tombstone",
                        &observation.project_id,
                    )
                })?;
            if stored.0 != digest || stored.1 != record_json {
                return Err(authority_mismatch(
                    "browser recipe authority tombstone",
                    &observation.project_id,
                ));
            }
        }
    }
    Ok(())
}

fn persist_root_secret_reference(
    transaction: &Transaction<'_>,
    observation: &BrowserRecipeAuthorityObservation,
    root: &BrowserRecipeAuthorityRootHead,
    reference: &SecretReference,
) -> Result<(), StorageError> {
    let credential_id = reference
        .credential_id()
        .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
    let reference_digest = root_reference_digest(reference)?;
    let reference_json = serde_json::to_string(reference)?;
    let inserted = transaction.execute(
        "INSERT INTO browser_recipe_root_secret_references
           (tenant_id, project_id, root_key_id, root_key_id_digest, public_key_digest,
            generation, credential_id, reference_digest, reference_json,
            first_snapshot_revision)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(project_id, root_key_id, generation) DO NOTHING",
        params![
            observation.tenant_id.as_str(),
            observation.project_id.as_str(),
            root.key_id,
            digest_identity(&root.key_id),
            root.public_key_digest,
            to_sql_u64(root.generation)?,
            credential_id,
            reference_digest,
            reference_json,
            to_sql_u64(observation.snapshot_revision)?,
        ],
    )?;
    if inserted == 0 {
        let stored = transaction
            .query_row(
                "SELECT public_key_digest, credential_id, reference_digest, reference_json
                 FROM browser_recipe_root_secret_references
                 WHERE project_id = ?1 AND root_key_id = ?2 AND generation = ?3",
                params![
                    observation.project_id.as_str(),
                    root.key_id,
                    to_sql_u64(root.generation)?,
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| {
                authority_mismatch(
                    "browser recipe root secret reference",
                    &observation.project_id,
                )
            })?;
        if stored
            != (
                root.public_key_digest.clone(),
                credential_id,
                reference_digest,
                reference_json,
            )
        {
            return Err(authority_mismatch(
                "browser recipe root secret reference",
                &observation.project_id,
            ));
        }
    }
    Ok(())
}

fn write_authority_head(
    transaction: &Transaction<'_>,
    observation: &BrowserRecipeAuthorityObservation,
    active_secret_credential_id: Option<&str>,
    expected_snapshot_revision: Option<u64>,
) -> Result<(), StorageError> {
    let root = observation.active_root.as_ref();
    let snapshot_revision = to_sql_u64(observation.snapshot_revision)?;
    let snapshot_as_of = observation.snapshot_as_of.to_rfc3339();
    let rotation_epoch = to_sql_u64(observation.rotation_epoch)?;
    let root_generation = root.map(|root| to_sql_u64(root.generation)).transpose()?;
    let root_revision = root.map(|root| to_sql_u64(root.revision)).transpose()?;
    let observation_digest = authority_observation_digest(observation)?;
    let updated_at = observation.validation_at.to_rfc3339();
    let changed = if let Some(expected) = expected_snapshot_revision {
        transaction.execute(
            "UPDATE browser_recipe_authority_heads
             SET tenant_id = ?1, snapshot_revision = ?3, snapshot_as_of = ?4,
                 snapshot_digest = ?5, state_digest = ?6, rotation_epoch = ?7,
                 active_root_key_id = ?8, active_root_public_key_digest = ?9,
                 active_root_generation = ?10, active_root_revision = ?11,
                 active_root_lineage_digest = ?12, active_secret_credential_id = ?13,
                 observation_digest = ?14, updated_at = ?15
             WHERE project_id = ?2 AND snapshot_revision = ?16",
            params![
                observation.tenant_id.as_str(),
                observation.project_id.as_str(),
                snapshot_revision,
                snapshot_as_of,
                observation.snapshot_digest,
                observation.state_digest,
                rotation_epoch,
                root.map(|root| root.key_id.as_str()),
                root.map(|root| root.public_key_digest.as_str()),
                root_generation,
                root_revision,
                root.map(|root| root.lineage_digest.as_str()),
                active_secret_credential_id,
                observation_digest,
                updated_at,
                to_sql_u64(expected)?,
            ],
        )?
    } else {
        transaction.execute(
            "INSERT INTO browser_recipe_authority_heads
               (tenant_id, project_id, snapshot_revision, snapshot_as_of,
                snapshot_digest, state_digest, rotation_epoch, active_root_key_id,
                active_root_public_key_digest, active_root_generation,
                active_root_revision, active_root_lineage_digest,
                active_secret_credential_id, observation_digest, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                observation.tenant_id.as_str(),
                observation.project_id.as_str(),
                snapshot_revision,
                snapshot_as_of,
                observation.snapshot_digest,
                observation.state_digest,
                rotation_epoch,
                root.map(|root| root.key_id.as_str()),
                root.map(|root| root.public_key_digest.as_str()),
                root_generation,
                root_revision,
                root.map(|root| root.lineage_digest.as_str()),
                active_secret_credential_id,
                observation_digest,
                updated_at,
            ],
        )?
    };
    if changed != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!(
                "browser_recipe_root_authority:{}",
                digest_identity(observation.project_id.as_str())
            ),
            expected_revision: expected_snapshot_revision.unwrap_or(0),
        });
    }
    Ok(())
}

struct AuthoritySnapshotProjection {
    tenant_id: String,
    snapshot_revision: i64,
    snapshot_as_of: String,
    validation_at: String,
    snapshot_digest: String,
    state_digest: String,
    rotation_epoch: i64,
    previous_snapshot_digest: Option<String>,
    active_root_key_id: Option<String>,
    active_root_public_key_digest: Option<String>,
    active_root_generation: Option<i64>,
    active_root_revision: Option<i64>,
    active_root_lineage_digest: Option<String>,
    active_secret_credential_id: Option<String>,
    observation_digest: String,
    observation_json: String,
}

impl AuthoritySnapshotProjection {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            tenant_id: row.get(0)?,
            snapshot_revision: row.get(1)?,
            snapshot_as_of: row.get(2)?,
            validation_at: row.get(3)?,
            snapshot_digest: row.get(4)?,
            state_digest: row.get(5)?,
            rotation_epoch: row.get(6)?,
            previous_snapshot_digest: row.get(7)?,
            active_root_key_id: row.get(8)?,
            active_root_public_key_digest: row.get(9)?,
            active_root_generation: row.get(10)?,
            active_root_revision: row.get(11)?,
            active_root_lineage_digest: row.get(12)?,
            active_secret_credential_id: row.get(13)?,
            observation_digest: row.get(14)?,
            observation_json: row.get(15)?,
        })
    }

    fn decode(
        &self,
        tenant_id: &TenantId,
        project_id: &ProjectId,
    ) -> Result<BrowserRecipeAuthorityObservation, StorageError> {
        let observation: BrowserRecipeAuthorityObservation =
            serde_json::from_str(&self.observation_json)?;
        validate_authority_observation(&observation, tenant_id, project_id)?;
        let root = observation.active_root.as_ref();
        if self.tenant_id != tenant_id.as_str()
            || to_u64(self.snapshot_revision)? != observation.snapshot_revision
            || self.snapshot_as_of != observation.snapshot_as_of.to_rfc3339()
            || self.validation_at != observation.validation_at.to_rfc3339()
            || self.snapshot_digest != observation.snapshot_digest
            || self.state_digest != observation.state_digest
            || to_u64(self.rotation_epoch)? != observation.rotation_epoch
            || self.active_root_key_id.as_deref() != root.map(|root| root.key_id.as_str())
            || self.active_root_public_key_digest.as_deref()
                != root.map(|root| root.public_key_digest.as_str())
            || self.active_root_generation.map(to_u64).transpose()?
                != root.map(|root| root.generation)
            || self.active_root_revision.map(to_u64).transpose()? != root.map(|root| root.revision)
            || self.active_root_lineage_digest.as_deref()
                != root.map(|root| root.lineage_digest.as_str())
            || self.observation_digest != authority_observation_digest(&observation)?
        {
            return Err(authority_mismatch(
                "browser recipe authority snapshot projection",
                project_id,
            ));
        }
        Ok(observation)
    }
}

struct RootSecretReferenceProjection {
    tenant_id: String,
    root_key_id: String,
    root_key_id_digest: String,
    public_key_digest: String,
    generation: i64,
    credential_id: String,
    reference_digest: String,
    reference_json: String,
    first_snapshot_revision: i64,
}

impl RootSecretReferenceProjection {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            tenant_id: row.get(0)?,
            root_key_id: row.get(1)?,
            root_key_id_digest: row.get(2)?,
            public_key_digest: row.get(3)?,
            generation: row.get(4)?,
            credential_id: row.get(5)?,
            reference_digest: row.get(6)?,
            reference_json: row.get(7)?,
            first_snapshot_revision: row.get(8)?,
        })
    }
}

struct LoadedRootSecretReference {
    reference: SecretReference,
    public_key_digest: String,
    first_snapshot_revision: u64,
}

fn load_root_secret_references(
    connection: &Connection,
    project_id: &ProjectId,
    tenant_id: &TenantId,
) -> Result<BTreeMap<String, LoadedRootSecretReference>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT tenant_id, root_key_id, root_key_id_digest, public_key_digest,
                generation, credential_id, reference_digest, reference_json,
                first_snapshot_revision
         FROM browser_recipe_root_secret_references
         WHERE project_id = ?1 ORDER BY generation, root_key_id",
    )?;
    let rows = statement
        .query_map([project_id.as_str()], RootSecretReferenceProjection::read)?
        .collect::<Result<Vec<_>, _>>()?;
    let mut references = BTreeMap::new();
    for row in rows {
        let generation = to_u64(row.generation)?;
        let reference: SecretReference = serde_json::from_str(&row.reference_json)?;
        let expected = SecretReference::browser_recipe_root_signing_key(
            tenant_id.clone(),
            project_id.clone(),
            &row.root_key_id,
            generation,
        )
        .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        if row.tenant_id != tenant_id.as_str()
            || row.root_key_id_digest != digest_identity(&row.root_key_id)
            || !is_sha256(&row.public_key_digest)
            || reference != expected
            || row.credential_id
                != reference
                    .credential_id()
                    .map_err(|error| StorageError::DomainDecode(error.to_string()))?
            || row.reference_digest != root_reference_digest(&reference)?
            || row.reference_json != serde_json::to_string(&reference)?
            || references
                .insert(
                    row.credential_id.clone(),
                    LoadedRootSecretReference {
                        reference,
                        public_key_digest: row.public_key_digest,
                        first_snapshot_revision: to_u64(row.first_snapshot_revision)?,
                    },
                )
                .is_some()
        {
            return Err(authority_mismatch(
                "browser recipe root secret reference projection",
                project_id,
            ));
        }
    }
    Ok(references)
}

struct AuthorityTombstoneProjection {
    tenant_id: String,
    key_id: String,
    key_id_digest: String,
    purpose: String,
    public_key_digest: String,
    blocked_revision: i64,
    lineage_digest: String,
    block_kind: String,
    effective_at: String,
    first_snapshot_revision: i64,
    tombstone_digest: String,
    tombstone_json: String,
}

impl AuthorityTombstoneProjection {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            tenant_id: row.get(0)?,
            key_id: row.get(1)?,
            key_id_digest: row.get(2)?,
            purpose: row.get(3)?,
            public_key_digest: row.get(4)?,
            blocked_revision: row.get(5)?,
            lineage_digest: row.get(6)?,
            block_kind: row.get(7)?,
            effective_at: row.get(8)?,
            first_snapshot_revision: row.get(9)?,
            tombstone_digest: row.get(10)?,
            tombstone_json: row.get(11)?,
        })
    }

    fn decode(
        &self,
        tenant_id: &TenantId,
        project_id: &ProjectId,
    ) -> Result<BrowserRecipeAuthorityTombstone, StorageError> {
        let tombstone: BrowserRecipeAuthorityTombstone =
            serde_json::from_str(&self.tombstone_json)?;
        if self.tenant_id != tenant_id.as_str()
            || self.key_id != tombstone.key_id
            || self.key_id_digest != digest_identity(&tombstone.key_id)
            || self.purpose != authority_purpose_name(tombstone.purpose)
            || self.public_key_digest != tombstone.public_key_digest
            || to_u64(self.blocked_revision)? != tombstone.blocked_revision
            || self.lineage_digest != tombstone.lineage_digest
            || self.block_kind != authority_block_kind_name(tombstone.kind)
            || self.effective_at != tombstone.effective_at.to_rfc3339()
            || self.tombstone_digest
                != authority_tombstone_digest(tenant_id, project_id, &tombstone)?
            || self.tombstone_json != serde_json::to_string(&tombstone)?
        {
            return Err(authority_mismatch(
                "browser recipe authority tombstone projection",
                project_id,
            ));
        }
        Ok(tombstone)
    }
}

fn load_authority_tombstones(
    connection: &Connection,
    project_id: &ProjectId,
    tenant_id: &TenantId,
) -> Result<Vec<(BrowserRecipeAuthorityTombstone, u64)>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT tenant_id, key_id, key_id_digest, purpose, public_key_digest,
                blocked_revision, lineage_digest, block_kind, effective_at,
                first_snapshot_revision,
                tombstone_digest, tombstone_json
         FROM browser_recipe_authority_tombstones
         WHERE project_id = ?1
         ORDER BY key_id, CASE block_kind WHEN 'revoked' THEN 0 ELSE 1 END",
    )?;
    statement
        .query_map([project_id.as_str()], AuthorityTombstoneProjection::read)?
        .map(|row| {
            let row = row.map_err(StorageError::from)?;
            Ok((
                row.decode(tenant_id, project_id)?,
                to_u64(row.first_snapshot_revision)?,
            ))
        })
        .collect()
}

fn authority_head_matches(
    connection: &Connection,
    project_id: &ProjectId,
    tenant_id: &TenantId,
    observation: &BrowserRecipeAuthorityObservation,
    active_secret_credential_id: Option<&str>,
) -> Result<bool, StorageError> {
    let head = connection
        .query_row(
            "SELECT tenant_id, snapshot_revision, snapshot_as_of, snapshot_digest,
                    state_digest, rotation_epoch, active_root_key_id,
                    active_root_public_key_digest, active_root_generation,
                    active_root_revision, active_root_lineage_digest,
                    active_secret_credential_id, observation_digest, updated_at
             FROM browser_recipe_authority_heads WHERE project_id = ?1",
            [project_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                    row.get::<_, Option<i64>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, String>(13)?,
                ))
            },
        )
        .optional()?;
    let Some(head) = head else {
        return Ok(false);
    };
    let root = observation.active_root.as_ref();
    Ok(head.0 == tenant_id.as_str()
        && to_u64(head.1)? == observation.snapshot_revision
        && head.2 == observation.snapshot_as_of.to_rfc3339()
        && head.3 == observation.snapshot_digest
        && head.4 == observation.state_digest
        && to_u64(head.5)? == observation.rotation_epoch
        && head.6.as_deref() == root.map(|root| root.key_id.as_str())
        && head.7.as_deref() == root.map(|root| root.public_key_digest.as_str())
        && head.8.map(to_u64).transpose()? == root.map(|root| root.generation)
        && head.9.map(to_u64).transpose()? == root.map(|root| root.revision)
        && head.10.as_deref() == root.map(|root| root.lineage_digest.as_str())
        && head.11.as_deref() == active_secret_credential_id
        && head.12 == authority_observation_digest(observation)?
        && head.13 == observation.validation_at.to_rfc3339())
}

#[allow(
    clippy::too_many_lines,
    reason = "crash recovery validates the snapshot chain, tombstones, secret references, and head as one fail-closed proof"
)]
fn load_durable_authority_state(
    connection: &Connection,
    project_id: &ProjectId,
    tenant_id: &TenantId,
) -> Result<Option<DurableBrowserRecipeAuthorityState>, StorageError> {
    let references = load_root_secret_references(connection, project_id, tenant_id)?;
    let persisted_tombstones = load_authority_tombstones(connection, project_id, tenant_id)?;
    let mut statement = connection.prepare(
        "SELECT tenant_id, snapshot_revision, snapshot_as_of, validation_at,
                snapshot_digest, state_digest, rotation_epoch, previous_snapshot_digest,
                active_root_key_id, active_root_public_key_digest, active_root_generation,
                active_root_revision, active_root_lineage_digest,
                active_secret_credential_id, observation_digest, observation_json
         FROM browser_recipe_authority_snapshots
         WHERE project_id = ?1 ORDER BY snapshot_revision",
    )?;
    let rows = statement
        .query_map([project_id.as_str()], AuthoritySnapshotProjection::read)?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.is_empty() {
        let head_count = connection.query_row(
            "SELECT COUNT(*) FROM browser_recipe_authority_heads WHERE project_id = ?1",
            [project_id.as_str()],
            |row| row.get::<_, i64>(0),
        )?;
        if head_count != 0 || !references.is_empty() || !persisted_tombstones.is_empty() {
            return Err(authority_mismatch(
                "browser recipe authority orphan projection",
                project_id,
            ));
        }
        return Ok(None);
    }
    let mut previous_observation: Option<BrowserRecipeAuthorityObservation> = None;
    let mut latest_previous_digest = None;
    let mut latest_credential_id = None;
    let mut used_credentials = std::collections::BTreeSet::new();
    let persisted_tombstone_first_revisions = persisted_tombstones
        .iter()
        .map(|(tombstone, revision)| ((tombstone.key_id.clone(), tombstone.kind), *revision))
        .collect::<BTreeMap<_, _>>();
    let mut observed_tombstone_first_revisions = BTreeMap::new();
    for row in &rows {
        let observation = row.decode(tenant_id, project_id)?;
        match previous_observation.as_ref() {
            None if row.previous_snapshot_digest.is_some() => {
                return Err(authority_mismatch(
                    "browser recipe authority snapshot chain",
                    project_id,
                ));
            }
            Some(previous)
                if row.previous_snapshot_digest.as_deref()
                    != Some(previous.snapshot_digest.as_str()) =>
            {
                return Err(authority_mismatch(
                    "browser recipe authority snapshot chain",
                    project_id,
                ));
            }
            Some(previous) => validate_authority_transition(previous, &observation)?,
            None => {}
        }
        for tombstone in &observation.tombstones {
            observed_tombstone_first_revisions
                .entry((tombstone.key_id.clone(), tombstone.kind))
                .or_insert(observation.snapshot_revision);
        }
        match (
            &observation.active_root,
            row.active_secret_credential_id.as_deref(),
        ) {
            (Some(root), Some(credential_id)) => {
                let Some(stored_reference) = references.get(credential_id) else {
                    return Err(authority_mismatch(
                        "browser recipe root secret reference recovery",
                        project_id,
                    ));
                };
                let expected_credential = validate_active_root_secret_reference(
                    &observation,
                    Some(&stored_reference.reference),
                )?;
                if expected_credential.as_deref() != Some(credential_id)
                    || stored_reference.public_key_digest != root.public_key_digest
                    || (used_credentials.insert(credential_id.to_owned())
                        && stored_reference.first_snapshot_revision
                            != observation.snapshot_revision)
                {
                    return Err(authority_mismatch(
                        "browser recipe root secret reference recovery",
                        project_id,
                    ));
                }
            }
            (None, None) => {}
            _ => {
                return Err(authority_mismatch(
                    "browser recipe root secret reference recovery",
                    project_id,
                ));
            }
        }
        latest_previous_digest.clone_from(&row.previous_snapshot_digest);
        latest_credential_id.clone_from(&row.active_secret_credential_id);
        previous_observation = Some(observation);
    }
    let observation = previous_observation.expect("non-empty authority snapshots");
    let persisted_tombstone_values = persisted_tombstones
        .iter()
        .map(|(tombstone, _)| tombstone.clone())
        .collect::<Vec<_>>();
    if persisted_tombstone_values != observation.tombstones
        || persisted_tombstone_first_revisions != observed_tombstone_first_revisions
        || used_credentials.len() != references.len()
        || !authority_head_matches(
            connection,
            project_id,
            tenant_id,
            &observation,
            latest_credential_id.as_deref(),
        )?
    {
        return Err(authority_mismatch(
            "browser recipe authority recovery projection",
            project_id,
        ));
    }
    let active_root_secret_reference = latest_credential_id
        .as_ref()
        .and_then(|credential_id| references.get(credential_id))
        .map(|stored| stored.reference.clone());
    Ok(Some(DurableBrowserRecipeAuthorityState {
        observation,
        previous_snapshot_digest: latest_previous_digest,
        active_root_secret_reference,
    }))
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

    fn authority_observation(
        fixture: &RecipeFixture,
        snapshot_revision: u64,
        rotation_epoch: u64,
        root_key_id: Option<&str>,
        tombstones: Vec<BrowserRecipeAuthorityTombstone>,
    ) -> BrowserRecipeAuthorityObservation {
        let snapshot_as_of = fixture.now
            + Duration::seconds(i64::try_from(snapshot_revision).expect("fixture revision"));
        BrowserRecipeAuthorityObservation {
            schema_version: 1,
            tenant_id: fixture.project.tenant_id.clone(),
            project_id: fixture.project.id.clone(),
            snapshot_revision,
            snapshot_as_of,
            validation_at: snapshot_as_of + Duration::seconds(1),
            snapshot_digest: digest_bytes(
                format!("snapshot:{snapshot_revision}:{rotation_epoch}").as_bytes(),
            ),
            state_digest: digest_bytes(
                format!("state:{snapshot_revision}:{rotation_epoch}").as_bytes(),
            ),
            rotation_epoch,
            active_root: root_key_id.map(|key_id| BrowserRecipeAuthorityRootHead {
                key_id: key_id.to_owned(),
                public_key_digest: digest_bytes(format!("public:{key_id}").as_bytes()),
                generation: rotation_epoch,
                revision: 1,
                lineage_digest: digest_bytes(
                    format!("lineage:{key_id}:{rotation_epoch}").as_bytes(),
                ),
            }),
            tombstones,
            snapshot_freshness_authority: false,
            production_dispatch: false,
        }
    }

    fn authority_tombstone(
        fixture: &RecipeFixture,
        key_id: &str,
    ) -> BrowserRecipeAuthorityTombstone {
        BrowserRecipeAuthorityTombstone {
            key_id: key_id.to_owned(),
            purpose: BrowserRecipeAuthorityKeyPurpose::CandidatePublisher,
            public_key_digest: digest_bytes(format!("public:{key_id}").as_bytes()),
            blocked_revision: 2,
            lineage_digest: digest_bytes(format!("lineage:{key_id}").as_bytes()),
            kind: BrowserRecipeAuthorityBlockKind::Revoked,
            effective_at: fixture.now + Duration::seconds(2),
        }
    }

    fn authority_reference(observation: &BrowserRecipeAuthorityObservation) -> SecretReference {
        let root = observation.active_root.as_ref().expect("active root");
        SecretReference::browser_recipe_root_signing_key(
            observation.tenant_id.clone(),
            observation.project_id.clone(),
            &root.key_id,
            root.generation,
        )
        .expect("root secret reference")
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one durable journey proves epoch rotation, tombstone monotonicity, replay rejection, redaction, and crash recovery"
    )]
    fn root_authority_epoch_tombstone_and_secret_reference_survive_restart() {
        let directory = tempdir().expect("directory");
        let database_path = directory.path().join("recipe-authority.sqlite3");
        let key = DatabaseKey::new([71; 32]).expect("database key");
        let fixture = fixture(directory.path());
        let first = authority_observation(&fixture, 1, 1, Some("root-1"), Vec::new());
        let first_reference = authority_reference(&first);
        let tombstone = authority_tombstone(&fixture, "candidate-1");
        let revoked =
            authority_observation(&fixture, 2, 1, Some("root-1"), vec![tombstone.clone()]);
        let rotated =
            authority_observation(&fixture, 3, 2, Some("root-2"), vec![tombstone.clone()]);
        let rotated_reference = authority_reference(&rotated);
        {
            let mut store = ProjectStore::open(&database_path, &key).expect("store");
            store.save_project(&fixture.project).expect("project");
            let first_outcome = store
                .persist_browser_recipe_authority_observation_atomic(&first, Some(&first_reference))
                .expect("persist initial epoch");
            assert!(!first_outcome.duplicate);
            assert_eq!(first_outcome.rotation_epoch, 1);
            assert_eq!(first_outcome.event_sequences.len(), 1);
            let duplicate = store
                .persist_browser_recipe_authority_observation_atomic(&first, Some(&first_reference))
                .expect("idempotent crash retry");
            assert!(duplicate.duplicate);
            assert!(duplicate.event_sequences.is_empty());
            store
                .persist_browser_recipe_authority_observation_atomic(
                    &revoked,
                    Some(&first_reference),
                )
                .expect("persist leaf revocation tombstone");

            assert!(matches!(
                store.persist_browser_recipe_authority_observation_atomic(
                    &first,
                    Some(&first_reference),
                ),
                Err(StorageError::ImmutableRecordMismatch {
                    kind: "browser recipe authority rollback",
                    ..
                })
            ));
            let mut same_revision_fork = revoked.clone();
            same_revision_fork.state_digest = "f".repeat(64);
            assert!(matches!(
                store.persist_browser_recipe_authority_observation_atomic(
                    &same_revision_fork,
                    Some(&first_reference),
                ),
                Err(StorageError::ImmutableRecordMismatch {
                    kind: "browser recipe authority replay conflict",
                    ..
                })
            ));
            let removed_tombstone =
                authority_observation(&fixture, 3, 1, Some("root-1"), Vec::new());
            assert!(matches!(
                store.persist_browser_recipe_authority_observation_atomic(
                    &removed_tombstone,
                    Some(&first_reference),
                ),
                Err(StorageError::ImmutableRecordMismatch {
                    kind: "browser recipe authority tombstone rollback",
                    ..
                })
            ));
            let epoch_jump =
                authority_observation(&fixture, 3, 3, Some("root-3"), vec![tombstone.clone()]);
            assert!(matches!(
                store.persist_browser_recipe_authority_observation_atomic(
                    &epoch_jump,
                    Some(&authority_reference(&epoch_jump)),
                ),
                Err(StorageError::ImmutableRecordMismatch {
                    kind: "browser recipe authority rotation epoch",
                    ..
                })
            ));
            let wrong_reference = SecretReference::browser_recipe_root_signing_key(
                rotated.tenant_id.clone(),
                rotated.project_id.clone(),
                "root-substitution",
                2,
            )
            .expect("wrong reference shape");
            assert!(matches!(
                store.persist_browser_recipe_authority_observation_atomic(
                    &rotated,
                    Some(&wrong_reference),
                ),
                Err(StorageError::ImmutableRecordMismatch {
                    kind: "browser recipe root secret reference",
                    ..
                })
            ));
            store
                .persist_browser_recipe_authority_observation_atomic(
                    &rotated,
                    Some(&rotated_reference),
                )
                .expect("persist next root epoch");

            let payloads = store
                .connection
                .prepare(
                    "SELECT payload_json FROM domain_events
                     WHERE project_id = ?1 AND event_type =
                       'browser.recipe_root_authority_snapshot_observed'",
                )
                .expect("event query")
                .query_map([fixture.project.id.as_str()], |row| row.get::<_, String>(0))
                .expect("event rows")
                .collect::<Result<Vec<_>, _>>()
                .expect("event payloads")
                .join("\n");
            for secret_or_identity in ["root-1", "root-2", "candidate-1", "privateKey"] {
                assert!(!payloads.contains(secret_or_identity));
            }
        }
        let restarted = ProjectStore::open(&database_path, &key).expect("crash restart");
        let recovered = restarted
            .load_browser_recipe_root_authority_state(&fixture.project.id)
            .expect("recover authority chain")
            .expect("durable authority state");
        assert_eq!(recovered.observation, rotated);
        assert_eq!(
            recovered.previous_snapshot_digest.as_deref(),
            Some(revoked.snapshot_digest.as_str())
        );
        assert_eq!(
            recovered.active_root_secret_reference,
            Some(rotated_reference)
        );
        assert_eq!(recovered.observation.tombstones, vec![tombstone]);

        restarted
            .connection
            .execute(
                "DELETE FROM browser_recipe_authority_tombstones
                 WHERE project_id = ?1 AND key_id = 'candidate-1'",
                [fixture.project.id.as_str()],
            )
            .expect("tamper tombstone projection");
        assert!(matches!(
            restarted.load_browser_recipe_root_authority_state(&fixture.project.id),
            Err(StorageError::ImmutableRecordMismatch {
                kind: "browser recipe authority recovery projection",
                ..
            })
        ));
    }

    #[test]
    fn schema_v48_migration_is_transactional_and_retryable() {
        let mut store = ProjectStore::in_memory().expect("current store");
        store
            .connection
            .execute_batch(
                "DROP TABLE browser_recipe_authority_heads;
                 DROP TABLE browser_recipe_authority_tombstones;
                 DROP TABLE browser_recipe_root_secret_references;
                 DROP TABLE browser_recipe_authority_snapshots;
                 DELETE FROM schema_migrations WHERE version = 48;",
            )
            .expect("construct schema v47");
        assert_eq!(store.schema_version().expect("v47 schema"), 47);
        store
            .connection
            .execute_batch(
                "CREATE TABLE browser_recipe_authority_heads (
                   sentinel INTEGER NOT NULL
                 );",
            )
            .expect("inject migration collision");
        assert!(matches!(
            store.migrate(),
            Err(StorageError::DomainDecode(_))
        ));
        assert_eq!(store.schema_version().expect("rolled back schema"), 47);
        assert_eq!(
            store
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master
                     WHERE type = 'table' AND name = 'browser_recipe_authority_snapshots'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("rolled back table count"),
            0
        );
        assert_eq!(
            store
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM schema_migrations WHERE version = 48",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("rolled back ledger"),
            0
        );
        store
            .connection
            .execute_batch("DROP TABLE browser_recipe_authority_heads;")
            .expect("remove collision");
        store.migrate().expect("retry schema v48 migration");
        assert_eq!(
            store.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        assert_eq!(
            store
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'
                     AND name IN (
                       'browser_recipe_authority_snapshots',
                       'browser_recipe_authority_heads',
                       'browser_recipe_authority_tombstones',
                       'browser_recipe_root_secret_references'
                     )",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("authority lifecycle tables"),
            4
        );
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
