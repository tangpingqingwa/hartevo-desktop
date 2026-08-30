use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{Effect, EffectId, MissionId, ProjectId, TenantId};
use hartevo_effect_broker::PermissionEvidence;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::{ProjectStore, StorageError, authorization, normalized};

const PROVIDER_RECOVERY_TABLE_SQL: &str = "CREATE TABLE IF NOT EXISTS provider_recovery_heads (
  tenant_id TEXT NOT NULL CHECK (length(trim(tenant_id)) > 0),
  project_id TEXT NOT NULL CHECK (length(trim(project_id)) > 0),
  mission_id TEXT NOT NULL CHECK (length(trim(mission_id)) > 0),
  effect_id TEXT NOT NULL CHECK (length(trim(effect_id)) > 0),
  binding_digest TEXT NOT NULL CHECK (length(binding_digest) = 64),
  state TEXT NOT NULL CHECK (state IN (
    'prepared', 'in_flight', 'uncertain', 'not_executed',
    'receipt_observed', 'verified', 'failed_closed'
  )),
  revision INTEGER NOT NULL CHECK (revision > 0),
  updated_at TEXT NOT NULL,
  record_json TEXT NOT NULL,
  PRIMARY KEY (project_id, effect_id)
)";

const PROVIDER_RECOVERY_INDEX_SQL: &str =
    "CREATE INDEX IF NOT EXISTS provider_recovery_scope_state_idx
     ON provider_recovery_heads(tenant_id, project_id, mission_id, state, updated_at)";

pub(crate) fn install_provider_recovery_schema(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<(), StorageError> {
    transaction.execute_batch(PROVIDER_RECOVERY_TABLE_SQL)?;
    transaction.execute_batch(PROVIDER_RECOVERY_INDEX_SQL)?;
    Ok(())
}

pub(crate) fn verify_provider_recovery_schema(
    connection: &rusqlite::Connection,
) -> Result<(), StorageError> {
    let table_sql = schema_sql(connection, "table", "provider_recovery_heads")?;
    let index_sql = schema_sql(connection, "index", "provider_recovery_scope_state_idx")?;
    if normalize_schema_sql(&table_sql) != normalize_schema_sql(PROVIDER_RECOVERY_TABLE_SQL) {
        return Err(StorageError::DomainDecode(
            "provider recovery table definition does not match v48".into(),
        ));
    }
    if normalize_schema_sql(&index_sql) != normalize_schema_sql(PROVIDER_RECOVERY_INDEX_SQL) {
        return Err(StorageError::DomainDecode(
            "provider recovery v48 index definition does not match".into(),
        ));
    }
    Ok(())
}

fn schema_sql(
    connection: &rusqlite::Connection,
    object_type: &str,
    name: &str,
) -> Result<String, StorageError> {
    connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = ?1 AND name = ?2",
            params![object_type, name],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| {
            StorageError::DomainDecode(format!(
                "provider recovery v48 {object_type} {name} is missing"
            ))
        })
}

fn normalize_schema_sql(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace("CREATE TABLE IF NOT EXISTS", "CREATE TABLE")
        .replace("CREATE INDEX IF NOT EXISTS", "CREATE INDEX")
}

/// Durable state for one provider write. Only `Prepared` may be claimed for
/// execution; every later state is permanently reconciliation-only.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderRecoveryState {
    Prepared,
    InFlight,
    Uncertain,
    NotExecuted,
    ReceiptObserved,
    Verified,
    FailedClosed,
}

impl ProviderRecoveryState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::InFlight => "in_flight",
            Self::Uncertain => "uncertain",
            Self::NotExecuted => "not_executed",
            Self::ReceiptObserved => "receipt_observed",
            Self::Verified => "verified",
            Self::FailedClosed => "failed_closed",
        }
    }
}

/// Exact, content-free binding for one encrypted provider payload capsule.
/// Provider payloads, response bodies, credentials, and live capabilities are
/// deliberately absent.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderRecoveryBinding {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub mission_revision: u64,
    pub effect_id: EffectId,
    pub effect_digest: String,
    pub approval_scope_digest: String,
    pub broker_authorization_digest: String,
    pub provider_id: String,
    pub capability_id: String,
    pub account_scope_digest: String,
    pub adapter_id: String,
    pub adapter_version: u64,
    pub plugin_revision: u64,
    pub provider_generation: u64,
    pub payload_digest: String,
    pub provider_idempotency_key_digest: String,
    pub sdk_idempotency_key_digest: String,
    pub credential_revision: u64,
    pub keyring_revision: u64,
    pub binding_digest: String,
}

impl fmt::Debug for ProviderRecoveryBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderRecoveryBinding")
            .field("project_id", &self.project_id)
            .field("mission_id", &self.mission_id)
            .field("mission_revision", &self.mission_revision)
            .field("effect_id", &self.effect_id)
            .field("provider_id", &self.provider_id)
            .field("capability_id", &self.capability_id)
            .field("adapter_id", &self.adapter_id)
            .field("adapter_version", &self.adapter_version)
            .field("plugin_revision", &self.plugin_revision)
            .field("provider_generation", &self.provider_generation)
            .field("credential_revision", &self.credential_revision)
            .field("keyring_revision", &self.keyring_revision)
            .field("binding_digest", &self.binding_digest)
            .finish_non_exhaustive()
    }
}

impl ProviderRecoveryBinding {
    pub fn validate(&self) -> Result<(), StorageError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.effect_id.as_str().trim().is_empty()
            || self.provider_id.trim().is_empty()
            || self.capability_id.trim().is_empty()
            || self.adapter_id.trim().is_empty()
            || self.mission_revision == 0
            || self.adapter_version == 0
            || self.plugin_revision == 0
            || self.provider_generation == 0
            || self.credential_revision == 0
            || self.keyring_revision == 0
            || [
                self.effect_digest.as_str(),
                self.approval_scope_digest.as_str(),
                self.broker_authorization_digest.as_str(),
                self.account_scope_digest.as_str(),
                self.payload_digest.as_str(),
                self.provider_idempotency_key_digest.as_str(),
                self.sdk_idempotency_key_digest.as_str(),
                self.binding_digest.as_str(),
            ]
            .iter()
            .any(|value| !is_sha256(value))
        {
            return Err(invalid_record());
        }
        Ok(())
    }
}

/// Reference to one already atomically written encrypted CAS object.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderRecoveryCapsule {
    pub storage_ref: String,
    pub content_digest: String,
    pub byte_len: u64,
    pub key_version: u64,
    pub object_revision: u64,
}

impl fmt::Debug for ProviderRecoveryCapsule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderRecoveryCapsule")
            .field("storage_ref", &self.storage_ref)
            .field("content_digest", &self.content_digest)
            .field("byte_len", &self.byte_len)
            .field("key_version", &self.key_version)
            .field("object_revision", &self.object_revision)
            .finish()
    }
}

impl ProviderRecoveryCapsule {
    pub fn validate(&self) -> Result<(), StorageError> {
        if !is_sha256(&self.content_digest)
            || self.storage_ref != format!("cas://{}", self.content_digest)
            || self.byte_len == 0
            || self.key_version == 0
            || self.object_revision == 0
        {
            return Err(invalid_record());
        }
        Ok(())
    }
}

/// Content-free durable head. The serialized record may contain identifiers
/// and digests only; the private approved payload remains in encrypted CAS.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderRecoveryHead {
    pub binding: ProviderRecoveryBinding,
    pub capsule: ProviderRecoveryCapsule,
    pub state: ProviderRecoveryState,
    pub revision: u64,
    pub readback_storage_ref: Option<String>,
    pub readback_content_digest: Option<String>,
    pub receipt_evidence_digest: Option<String>,
    pub verification_evidence_digest: Option<String>,
    pub prepared_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl fmt::Debug for ProviderRecoveryHead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderRecoveryHead")
            .field("binding", &self.binding)
            .field("capsule", &self.capsule)
            .field("state", &self.state)
            .field("revision", &self.revision)
            .field("has_readback", &self.readback_storage_ref.is_some())
            .field("has_receipt", &self.receipt_evidence_digest.is_some())
            .field(
                "has_verification",
                &self.verification_evidence_digest.is_some(),
            )
            .field("prepared_at", &self.prepared_at)
            .field("expires_at", &self.expires_at)
            .field("updated_at", &self.updated_at)
            .finish_non_exhaustive()
    }
}

impl ProviderRecoveryHead {
    pub fn prepared(
        binding: ProviderRecoveryBinding,
        capsule: ProviderRecoveryCapsule,
        prepared_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, StorageError> {
        let head = Self {
            binding,
            capsule,
            state: ProviderRecoveryState::Prepared,
            revision: 1,
            readback_storage_ref: None,
            readback_content_digest: None,
            receipt_evidence_digest: None,
            verification_evidence_digest: None,
            prepared_at,
            expires_at,
            updated_at: prepared_at,
        };
        head.validate()?;
        Ok(head)
    }

    pub fn validate(&self) -> Result<(), StorageError> {
        self.binding.validate()?;
        self.capsule.validate()?;
        let readback_valid = match (
            self.readback_storage_ref.as_deref(),
            self.readback_content_digest.as_deref(),
        ) {
            (None, None) => true,
            (Some(storage_ref), Some(digest)) => {
                is_sha256(digest) && storage_ref == format!("cas://{digest}")
            }
            _ => false,
        };
        let evidence_valid = self
            .receipt_evidence_digest
            .as_deref()
            .is_none_or(is_sha256)
            && self
                .verification_evidence_digest
                .as_deref()
                .is_none_or(is_sha256);
        let state_valid = match self.state {
            ProviderRecoveryState::Prepared
            | ProviderRecoveryState::InFlight
            | ProviderRecoveryState::Uncertain => {
                self.readback_storage_ref.is_none()
                    && self.receipt_evidence_digest.is_none()
                    && self.verification_evidence_digest.is_none()
            }
            ProviderRecoveryState::NotExecuted => {
                self.readback_storage_ref.is_some()
                    && self.receipt_evidence_digest.is_none()
                    && self.verification_evidence_digest.is_none()
            }
            ProviderRecoveryState::ReceiptObserved => {
                self.readback_storage_ref.is_some()
                    && self.receipt_evidence_digest.is_some()
                    && self.verification_evidence_digest.is_none()
            }
            ProviderRecoveryState::Verified => {
                self.readback_storage_ref.is_some()
                    && self.receipt_evidence_digest.is_some()
                    && self.verification_evidence_digest.is_some()
            }
            ProviderRecoveryState::FailedClosed => self.verification_evidence_digest.is_none(),
        };
        if self.revision == 0
            || self.expires_at <= self.prepared_at
            || self.updated_at < self.prepared_at
            || !readback_valid
            || !evidence_valid
            || !state_valid
        {
            return Err(invalid_record());
        }
        Ok(())
    }

    pub const fn execution_claimable(&self) -> bool {
        matches!(self.state, ProviderRecoveryState::Prepared)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRecoveryPrepareOutcome {
    pub head: ProviderRecoveryHead,
    pub duplicate: bool,
}

impl ProjectStore {
    pub fn prepare_provider_recovery(
        &mut self,
        head: &ProviderRecoveryHead,
    ) -> Result<ProviderRecoveryPrepareOutcome, StorageError> {
        head.validate()?;
        if head.state != ProviderRecoveryState::Prepared || head.revision != 1 {
            return Err(StorageError::InvalidInitialRevision(head.revision));
        }
        let transaction = self.connection.transaction()?;
        if let Some(existing) = load_head(
            &transaction,
            &head.binding.project_id,
            &head.binding.effect_id,
        )? {
            if existing.binding != head.binding || existing.capsule != head.capsule {
                return Err(StorageError::ImmutableRecordMismatch {
                    kind: "provider recovery binding",
                    id: head.binding.effect_id.to_string(),
                });
            }
            transaction.commit()?;
            return Ok(ProviderRecoveryPrepareOutcome {
                head: existing,
                duplicate: true,
            });
        }
        insert_head(&transaction, head)?;
        transaction.commit()?;
        Ok(ProviderRecoveryPrepareOutcome {
            head: head.clone(),
            duplicate: false,
        })
    }

    pub fn load_provider_recovery(
        &self,
        project_id: &ProjectId,
        effect_id: &EffectId,
    ) -> Result<ProviderRecoveryHead, StorageError> {
        load_head(&self.connection, project_id, effect_id)?.ok_or_else(|| {
            StorageError::ScopedRecordNotFound {
                kind: "provider recovery",
                project_id: project_id.clone(),
                id: effect_id.to_string(),
            }
        })
    }

    #[cfg(test)]
    pub(crate) fn claim_provider_recovery_execution(
        &mut self,
        project_id: &ProjectId,
        effect_id: &EffectId,
        expected_revision: u64,
        expected_binding_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<ProviderRecoveryHead, StorageError> {
        self.transition_provider_recovery(
            project_id,
            effect_id,
            expected_revision,
            expected_binding_digest,
            ProviderRecoveryTransition::Claim,
            None,
            now,
        )
    }

    /// Claims one prepared recovery only after the current durable Mission,
    /// Effect/Approval, and permission fences have been re-read and locked in
    /// the same SQLCipher transaction as the state transition.
    #[allow(clippy::too_many_arguments)]
    pub fn claim_provider_recovery_execution_authorized(
        &mut self,
        project_id: &ProjectId,
        effect_id: &EffectId,
        expected_revision: u64,
        expected_binding_digest: &str,
        effect: &Effect,
        permission_evidence: &PermissionEvidence,
        now: DateTime<Utc>,
    ) -> Result<ProviderRecoveryHead, StorageError> {
        self.transition_provider_recovery(
            project_id,
            effect_id,
            expected_revision,
            expected_binding_digest,
            ProviderRecoveryTransition::Claim,
            Some(ProviderRecoveryClaimAuthority {
                effect,
                permission_evidence,
            }),
            now,
        )
    }

    pub fn mark_provider_recovery_uncertain(
        &mut self,
        project_id: &ProjectId,
        effect_id: &EffectId,
        expected_revision: u64,
        expected_binding_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<ProviderRecoveryHead, StorageError> {
        self.transition_provider_recovery(
            project_id,
            effect_id,
            expected_revision,
            expected_binding_digest,
            ProviderRecoveryTransition::Uncertain,
            None,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_provider_recovery_not_executed(
        &mut self,
        project_id: &ProjectId,
        effect_id: &EffectId,
        expected_revision: u64,
        expected_binding_digest: &str,
        readback_storage_ref: String,
        readback_content_digest: String,
        now: DateTime<Utc>,
    ) -> Result<ProviderRecoveryHead, StorageError> {
        self.transition_provider_recovery(
            project_id,
            effect_id,
            expected_revision,
            expected_binding_digest,
            ProviderRecoveryTransition::NotExecuted {
                readback_storage_ref,
                readback_content_digest,
            },
            None,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_provider_recovery_receipt(
        &mut self,
        project_id: &ProjectId,
        effect_id: &EffectId,
        expected_revision: u64,
        expected_binding_digest: &str,
        readback_storage_ref: String,
        readback_content_digest: String,
        receipt_evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<ProviderRecoveryHead, StorageError> {
        self.transition_provider_recovery(
            project_id,
            effect_id,
            expected_revision,
            expected_binding_digest,
            ProviderRecoveryTransition::Receipt {
                readback_storage_ref,
                readback_content_digest,
                receipt_evidence_digest,
            },
            None,
            now,
        )
    }

    pub fn record_provider_recovery_verified(
        &mut self,
        project_id: &ProjectId,
        effect_id: &EffectId,
        expected_revision: u64,
        expected_binding_digest: &str,
        verification_evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<ProviderRecoveryHead, StorageError> {
        self.transition_provider_recovery(
            project_id,
            effect_id,
            expected_revision,
            expected_binding_digest,
            ProviderRecoveryTransition::Verified {
                verification_evidence_digest,
            },
            None,
            now,
        )
    }

    pub fn fail_provider_recovery_closed(
        &mut self,
        project_id: &ProjectId,
        effect_id: &EffectId,
        expected_revision: u64,
        expected_binding_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<ProviderRecoveryHead, StorageError> {
        self.transition_provider_recovery(
            project_id,
            effect_id,
            expected_revision,
            expected_binding_digest,
            ProviderRecoveryTransition::FailedClosed,
            None,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn transition_provider_recovery(
        &mut self,
        project_id: &ProjectId,
        effect_id: &EffectId,
        expected_revision: u64,
        expected_binding_digest: &str,
        transition: ProviderRecoveryTransition,
        claim_authority: Option<ProviderRecoveryClaimAuthority<'_>>,
        now: DateTime<Utc>,
    ) -> Result<ProviderRecoveryHead, StorageError> {
        if !is_sha256(expected_binding_digest) {
            return Err(invalid_record());
        }
        let transaction = self.connection.transaction()?;
        let mut head = load_head(&transaction, project_id, effect_id)?.ok_or_else(|| {
            StorageError::ScopedRecordNotFound {
                kind: "provider recovery",
                project_id: project_id.clone(),
                id: effect_id.to_string(),
            }
        })?;
        if head.revision != expected_revision
            || head.binding.binding_digest != expected_binding_digest
        {
            return Err(conflict(effect_id, expected_revision));
        }
        if let Some(authority) = claim_authority {
            if !matches!(transition, ProviderRecoveryTransition::Claim) {
                return Err(invalid_record());
            }
            validate_claim_authority(&transaction, &head, &authority)?;
        }
        let previous_state = head.state;
        apply_transition(&mut head, transition, now)?;
        let changed = transaction.execute(
            "UPDATE provider_recovery_heads
             SET state = ?1, revision = ?2, updated_at = ?3, record_json = ?4
             WHERE project_id = ?5 AND effect_id = ?6 AND revision = ?7
               AND binding_digest = ?8 AND state = ?9",
            params![
                head.state.as_str(),
                to_sql_u64(head.revision)?,
                head.updated_at.to_rfc3339(),
                serde_json::to_string(&head)?,
                project_id.as_str(),
                effect_id.as_str(),
                to_sql_u64(expected_revision)?,
                expected_binding_digest,
                previous_state.as_str(),
            ],
        )?;
        if changed != 1 {
            return Err(conflict(effect_id, expected_revision));
        }
        transaction.commit()?;
        Ok(head)
    }
}

struct ProviderRecoveryClaimAuthority<'a> {
    effect: &'a Effect,
    permission_evidence: &'a PermissionEvidence,
}

fn validate_claim_authority(
    transaction: &rusqlite::Transaction<'_>,
    head: &ProviderRecoveryHead,
    authority: &ProviderRecoveryClaimAuthority<'_>,
) -> Result<(), StorageError> {
    let binding = &head.binding;
    let effect = authority.effect;
    if effect.tenant_id != binding.tenant_id
        || effect.project_id != binding.project_id
        || effect.mission_id != binding.mission_id
        || effect.id != binding.effect_id
        || effect.approval_digest() != binding.approval_scope_digest
        || effect.approval.as_ref().is_none_or(|approval| {
            approval.permission_digest != binding.broker_authorization_digest
        })
    {
        return Err(invalid_record());
    }
    let mission =
        normalized::load_mission_normalized(transaction, &binding.project_id, &binding.mission_id)?
            .ok_or_else(invalid_record)?;
    let current_effect = mission
        .effects
        .iter()
        .find(|candidate| candidate.id == binding.effect_id)
        .ok_or_else(invalid_record)?;
    if mission.tenant_id != binding.tenant_id
        || mission.revision != binding.mission_revision
        || current_effect != effect
    {
        return Err(invalid_record());
    }
    authority
        .permission_evidence
        .validate_for_effect(current_effect)
        .map_err(|_| invalid_record())?;
    authorization::validate_permission_fences(
        transaction,
        current_effect,
        authority.permission_evidence,
    )
    .map_err(|_| invalid_record())
}

enum ProviderRecoveryTransition {
    Claim,
    Uncertain,
    NotExecuted {
        readback_storage_ref: String,
        readback_content_digest: String,
    },
    Receipt {
        readback_storage_ref: String,
        readback_content_digest: String,
        receipt_evidence_digest: String,
    },
    Verified {
        verification_evidence_digest: String,
    },
    FailedClosed,
}

fn apply_transition(
    head: &mut ProviderRecoveryHead,
    transition: ProviderRecoveryTransition,
    now: DateTime<Utc>,
) -> Result<(), StorageError> {
    let next_state = match transition {
        ProviderRecoveryTransition::Claim
            if head.state == ProviderRecoveryState::Prepared && now < head.expires_at =>
        {
            ProviderRecoveryState::InFlight
        }
        ProviderRecoveryTransition::Uncertain if head.state == ProviderRecoveryState::InFlight => {
            ProviderRecoveryState::Uncertain
        }
        ProviderRecoveryTransition::NotExecuted {
            readback_storage_ref,
            readback_content_digest,
        } if matches!(
            head.state,
            ProviderRecoveryState::InFlight | ProviderRecoveryState::Uncertain
        ) =>
        {
            set_readback(head, readback_storage_ref, readback_content_digest)?;
            ProviderRecoveryState::NotExecuted
        }
        ProviderRecoveryTransition::Receipt {
            readback_storage_ref,
            readback_content_digest,
            receipt_evidence_digest,
        } if matches!(
            head.state,
            ProviderRecoveryState::InFlight | ProviderRecoveryState::Uncertain
        ) =>
        {
            set_readback(head, readback_storage_ref, readback_content_digest)?;
            if !is_sha256(&receipt_evidence_digest) {
                return Err(invalid_record());
            }
            head.receipt_evidence_digest = Some(receipt_evidence_digest);
            ProviderRecoveryState::ReceiptObserved
        }
        ProviderRecoveryTransition::Verified {
            verification_evidence_digest,
        } if head.state == ProviderRecoveryState::ReceiptObserved => {
            if !is_sha256(&verification_evidence_digest) {
                return Err(invalid_record());
            }
            head.verification_evidence_digest = Some(verification_evidence_digest);
            ProviderRecoveryState::Verified
        }
        ProviderRecoveryTransition::FailedClosed
            if !matches!(
                head.state,
                ProviderRecoveryState::NotExecuted
                    | ProviderRecoveryState::Verified
                    | ProviderRecoveryState::FailedClosed
            ) =>
        {
            ProviderRecoveryState::FailedClosed
        }
        _ => {
            return Err(StorageError::InvalidProviderRecoveryTransition {
                state: head.state.as_str().into(),
            });
        }
    };
    head.state = next_state;
    head.revision = head
        .revision
        .checked_add(1)
        .ok_or(StorageError::RevisionOverflow(head.revision))?;
    head.updated_at = now;
    head.validate()
}

fn set_readback(
    head: &mut ProviderRecoveryHead,
    storage_ref: String,
    content_digest: String,
) -> Result<(), StorageError> {
    if !is_sha256(&content_digest) || storage_ref != format!("cas://{content_digest}") {
        return Err(invalid_record());
    }
    head.readback_storage_ref = Some(storage_ref);
    head.readback_content_digest = Some(content_digest);
    Ok(())
}

fn insert_head(
    transaction: &rusqlite::Transaction<'_>,
    head: &ProviderRecoveryHead,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO provider_recovery_heads
           (tenant_id, project_id, mission_id, effect_id, binding_digest, state,
            revision, updated_at, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            head.binding.tenant_id.as_str(),
            head.binding.project_id.as_str(),
            head.binding.mission_id.as_str(),
            head.binding.effect_id.as_str(),
            head.binding.binding_digest,
            head.state.as_str(),
            to_sql_u64(head.revision)?,
            head.updated_at.to_rfc3339(),
            serde_json::to_string(head)?,
        ],
    )?;
    Ok(())
}

fn load_head(
    connection: &rusqlite::Connection,
    project_id: &ProjectId,
    effect_id: &EffectId,
) -> Result<Option<ProviderRecoveryHead>, StorageError> {
    let row = connection
        .query_row(
            "SELECT tenant_id, mission_id, binding_digest, state, revision,
                    updated_at, record_json
             FROM provider_recovery_heads
             WHERE project_id = ?1 AND effect_id = ?2",
            params![project_id.as_str(), effect_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()?;
    let Some((tenant_id, mission_id, binding_digest, state, revision, updated_at, record_json)) =
        row
    else {
        return Ok(None);
    };
    let head: ProviderRecoveryHead = serde_json::from_str(&record_json)?;
    head.validate()?;
    if head.binding.project_id != *project_id
        || head.binding.effect_id != *effect_id
        || head.binding.tenant_id.as_str() != tenant_id
        || head.binding.mission_id.as_str() != mission_id
        || head.binding.binding_digest != binding_digest
        || head.state.as_str() != state
        || to_sql_u64(head.revision)? != revision
        || head.updated_at.to_rfc3339() != updated_at
    {
        return Err(StorageError::DomainDecode(
            "provider recovery normalized projection mismatch".into(),
        ));
    }
    Ok(Some(head))
}

fn to_sql_u64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::RevisionOverflow(value))
}

fn conflict(effect_id: &EffectId, expected_revision: u64) -> StorageError {
    StorageError::OptimisticConflict {
        aggregate: format!("provider_recovery:{effect_id}"),
        expected_revision,
    }
}

fn invalid_record() -> StorageError {
    StorageError::DomainDecode("invalid provider recovery record".into())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use chrono::{Duration, TimeZone};

    use super::*;

    fn digest(marker: char) -> String {
        marker.to_string().repeat(64)
    }

    fn prepared_head() -> ProviderRecoveryHead {
        let now = Utc.with_ymd_and_hms(2026, 8, 30, 8, 0, 0).unwrap();
        ProviderRecoveryHead::prepared(
            ProviderRecoveryBinding {
                tenant_id: TenantId::from_stable("tenant-n12b"),
                project_id: ProjectId::from_stable("project-n12b"),
                mission_id: MissionId::from_stable("mission-n12b"),
                mission_revision: 7,
                effect_id: EffectId::from_stable("effect-n12b"),
                effect_digest: digest('1'),
                approval_scope_digest: digest('2'),
                broker_authorization_digest: digest('3'),
                provider_id: "shopify".into(),
                capability_id: "commerce.fulfillment.draft".into(),
                account_scope_digest: digest('4'),
                adapter_id: "application.shopify.fulfillment.effect".into(),
                adapter_version: 1,
                plugin_revision: 3,
                provider_generation: 5,
                payload_digest: digest('5'),
                provider_idempotency_key_digest: digest('6'),
                sdk_idempotency_key_digest: digest('7'),
                credential_revision: 2,
                keyring_revision: 4,
                binding_digest: digest('8'),
            },
            ProviderRecoveryCapsule {
                storage_ref: format!("cas://{}", digest('9')),
                content_digest: digest('9'),
                byte_len: 512,
                key_version: 2,
                object_revision: 1,
            },
            now,
            now + Duration::minutes(10),
        )
        .unwrap()
    }

    fn database_key() -> crate::DatabaseKey {
        crate::DatabaseKey::new([11_u8; 32]).unwrap()
    }

    #[test]
    fn migration_v48_is_additive_backed_up_and_retryable() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("provider-recovery-v47.sqlite3");
        {
            let store = ProjectStore::open(&path, &database_key()).unwrap();
            store
                .connection
                .execute_batch(
                    "DROP TABLE provider_recovery_heads;
                     DELETE FROM schema_migrations WHERE version >= 48;",
                )
                .unwrap();
            assert_eq!(store.schema_version().unwrap(), 47);
        }
        let migrated = ProjectStore::open(&path, &database_key()).unwrap();
        assert_eq!(migrated.schema_version().unwrap(), 48);
        assert_eq!(
            migrated
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master
                     WHERE type = 'table' AND name = 'provider_recovery_heads'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        drop(migrated);
        assert_eq!(
            fs::read_dir(directory.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v47"))
                .count(),
            1
        );

        let mut retry = ProjectStore::in_memory().unwrap();
        retry
            .connection
            .execute_batch(
                "DROP TABLE provider_recovery_heads;
                 DELETE FROM schema_migrations WHERE version >= 48;
                 CREATE TABLE provider_recovery_heads (sentinel INTEGER NOT NULL);",
            )
            .unwrap();
        assert!(retry.migrate().is_err());
        assert_eq!(retry.schema_version().unwrap(), 47);
        assert_eq!(
            retry
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('provider_recovery_heads')
                     WHERE name = 'sentinel'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        retry
            .connection
            .execute_batch("DROP TABLE provider_recovery_heads;")
            .unwrap();
        retry.migrate().unwrap();
        assert_eq!(retry.schema_version().unwrap(), 48);
    }

    #[test]
    fn migration_v48_rejects_constraint_and_index_collisions() {
        let mut store = ProjectStore::in_memory().unwrap();
        store
            .connection
            .execute_batch(
                "DROP TABLE provider_recovery_heads;
                 DELETE FROM schema_migrations WHERE version >= 48;
                 CREATE TABLE provider_recovery_heads (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   effect_id TEXT NOT NULL,
                   binding_digest TEXT NOT NULL,
                   state TEXT NOT NULL,
                   revision INTEGER NOT NULL,
                   updated_at TEXT NOT NULL,
                   record_json TEXT NOT NULL
                 );
                 CREATE INDEX provider_recovery_scope_state_idx
                   ON provider_recovery_heads(effect_id);",
            )
            .unwrap();

        assert!(matches!(
            store.migrate(),
            Err(StorageError::DomainDecode(_))
        ));
        assert_eq!(store.schema_version().unwrap(), 47);
        assert!(verify_provider_recovery_schema(&store.connection).is_err());
        store
            .connection
            .execute_batch(
                "INSERT INTO provider_recovery_heads VALUES
                   ('tenant', 'project', 'mission', 'effect', 'digest', 'prepared', 1, 'now', '{}');
                 INSERT INTO provider_recovery_heads VALUES
                   ('tenant', 'project', 'mission', 'effect', 'digest', 'in_flight', 2, 'later', '{}');",
            )
            .unwrap();
        assert_eq!(
            store
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM provider_recovery_heads
                     WHERE project_id = 'project' AND effect_id = 'effect'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            2
        );
    }

    #[test]
    fn schema_verifier_preserves_check_literal_case() {
        let store = ProjectStore::in_memory().unwrap();
        store
            .connection
            .execute_batch("DROP TABLE provider_recovery_heads;")
            .unwrap();
        let drifted = PROVIDER_RECOVERY_TABLE_SQL.replace("'prepared'", "'PREPARED'");
        store.connection.execute_batch(&drifted).unwrap();
        store
            .connection
            .execute_batch(PROVIDER_RECOVERY_INDEX_SQL)
            .unwrap();

        assert!(verify_provider_recovery_schema(&store.connection).is_err());
    }

    #[test]
    fn prepared_head_is_idempotent_and_claim_is_single_use() {
        let mut store = ProjectStore::in_memory().unwrap();
        let prepared = prepared_head();
        let first = store.prepare_provider_recovery(&prepared).unwrap();
        assert!(!first.duplicate);
        let duplicate = store.prepare_provider_recovery(&prepared).unwrap();
        assert!(duplicate.duplicate);

        let claimed = store
            .claim_provider_recovery_execution(
                &prepared.binding.project_id,
                &prepared.binding.effect_id,
                1,
                &prepared.binding.binding_digest,
                prepared.prepared_at + Duration::seconds(1),
            )
            .unwrap();
        assert_eq!(claimed.state, ProviderRecoveryState::InFlight);
        assert_eq!(claimed.revision, 2);
        assert!(
            store
                .claim_provider_recovery_execution(
                    &prepared.binding.project_id,
                    &prepared.binding.effect_id,
                    2,
                    &prepared.binding.binding_digest,
                    prepared.prepared_at + Duration::seconds(2),
                )
                .is_err()
        );
    }

    #[test]
    fn uncertain_and_not_executed_are_reconciliation_only() {
        let mut store = ProjectStore::in_memory().unwrap();
        let prepared = prepared_head();
        store.prepare_provider_recovery(&prepared).unwrap();
        let claimed = store
            .claim_provider_recovery_execution(
                &prepared.binding.project_id,
                &prepared.binding.effect_id,
                1,
                &prepared.binding.binding_digest,
                prepared.prepared_at + Duration::seconds(1),
            )
            .unwrap();
        let uncertain = store
            .mark_provider_recovery_uncertain(
                &prepared.binding.project_id,
                &prepared.binding.effect_id,
                claimed.revision,
                &prepared.binding.binding_digest,
                prepared.prepared_at + Duration::seconds(2),
            )
            .unwrap();
        let readback_digest = digest('a');
        let terminal = store
            .record_provider_recovery_not_executed(
                &prepared.binding.project_id,
                &prepared.binding.effect_id,
                uncertain.revision,
                &prepared.binding.binding_digest,
                format!("cas://{readback_digest}"),
                readback_digest,
                prepared.prepared_at + Duration::seconds(3),
            )
            .unwrap();
        assert_eq!(terminal.state, ProviderRecoveryState::NotExecuted);
        assert!(!terminal.execution_claimable());
        assert!(
            store
                .claim_provider_recovery_execution(
                    &prepared.binding.project_id,
                    &prepared.binding.effect_id,
                    terminal.revision,
                    &prepared.binding.binding_digest,
                    prepared.prepared_at + Duration::seconds(4),
                )
                .is_err()
        );
    }

    #[test]
    fn normalized_projection_tamper_fails_closed() {
        let mut store = ProjectStore::in_memory().unwrap();
        let prepared = prepared_head();
        store.prepare_provider_recovery(&prepared).unwrap();
        store
            .connection
            .execute(
                "UPDATE provider_recovery_heads SET binding_digest = ?1",
                [digest('f')],
            )
            .unwrap();
        assert!(matches!(
            store.load_provider_recovery(&prepared.binding.project_id, &prepared.binding.effect_id),
            Err(StorageError::DomainDecode(_))
        ));
    }

    #[test]
    fn debug_and_serialized_head_are_content_free() {
        let head = prepared_head();
        let debug = format!("{head:?}");
        let json = serde_json::to_string(&head).unwrap();
        for marker in ["private-line-item-marker", "shopify-token-marker"] {
            assert!(!debug.contains(marker));
            assert!(!json.contains(marker));
        }
        assert!(!debug.contains(&head.binding.broker_authorization_digest));
    }
}
