use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    DeviceAttachment, DeviceAttachmentId, DeviceAttachmentStatus, KeyEnvelope, KeyEnvelopeId,
    KeyRecipient, ProjectId, ProjectKeyring, TenantId,
};
use rusqlite::{OptionalExtension, Row, Transaction, params};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::aggregate::{PendingEvent, append_events};
use crate::{PersistedMutation, ProjectStore, SecretReference, StorageError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceAttachmentPrepareOutcome {
    pub attachment: DeviceAttachment,
    pub duplicate: bool,
}

/// SQLCipher-local metadata that lets the Desktop recover the exact OS/Vault
/// wrapping-key reference for an immutable envelope after restart. It never
/// contains the wrapping key or project content key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectKeySecretReference {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub envelope_id: KeyEnvelopeId,
    pub key_version: u64,
    pub recipient: KeyRecipient,
    pub reference: SecretReference,
}

impl ProjectKeySecretReference {
    pub fn bind(envelope: &KeyEnvelope, reference: SecretReference) -> Result<Self, StorageError> {
        let binding = Self {
            tenant_id: envelope.tenant_id.clone(),
            project_id: envelope.project_id.clone(),
            envelope_id: envelope.id.clone(),
            key_version: envelope.key_version,
            recipient: envelope.recipient.clone(),
            reference,
        };
        binding.validate_against(envelope)?;
        Ok(binding)
    }

    fn validate_against(&self, envelope: &KeyEnvelope) -> Result<(), StorageError> {
        let reference = &self.reference;
        let credential_id = reference
            .credential_id()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        if self.tenant_id != envelope.tenant_id
            || self.project_id != envelope.project_id
            || self.envelope_id != envelope.id
            || self.key_version != envelope.key_version
            || self.recipient != envelope.recipient
            || matches!(self.recipient, KeyRecipient::Recovery(_))
            || reference.tenant_id != self.tenant_id
            || reference.project_id != self.project_id
            || reference.account_scope != self.recipient.stable_scope()
            || reference.version != self.key_version
            || !reference.purpose.starts_with("project_")
            || credential_id != envelope.wrapping_key_reference_digest
        {
            return Err(StorageError::DomainDecode(
                "local key reference does not match its immutable envelope scope".into(),
            ));
        }
        Ok(())
    }
}

impl ProjectStore {
    pub fn create_project_keyring(
        &mut self,
        keyring: &ProjectKeyring,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        self.create_project_keyring_with_secret_references(
            keyring,
            &[],
            event_type,
            payload,
            recorded_at,
        )
    }

    pub fn create_project_keyring_with_secret_references(
        &mut self,
        keyring: &ProjectKeyring,
        secret_references: &[ProjectKeySecretReference],
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        validate_keyring(keyring)?;
        if keyring.revision != 1 {
            return Err(StorageError::InvalidInitialRevision(keyring.revision));
        }
        let transaction = self.connection.transaction()?;
        ensure_project(&transaction, &keyring.tenant_id, &keyring.project_id)?;
        let existing_envelope_ids = BTreeSet::new();
        transaction.execute(
            "INSERT INTO project_keyrings
               (tenant_id, project_id, mode, active_key_version, remote_execution_opt_in,
                rotation_required, revision, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                keyring.tenant_id.as_str(),
                keyring.project_id.as_str(),
                enum_name(&keyring.mode)?,
                to_sql_u64(keyring.active_key_version)?,
                bool_sql(keyring.remote_execution_opt_in),
                bool_sql(keyring.rotation_required),
                to_sql_u64(keyring.revision)?,
                keyring.created_at.to_rfc3339(),
                keyring.updated_at.to_rfc3339(),
            ],
        )?;
        persist_envelopes(&transaction, keyring)?;
        persist_secret_references(&transaction, keyring, secret_references)?;
        require_new_envelopes_have_secret_references(
            &transaction,
            keyring,
            &existing_envelope_ids,
        )?;
        finish(transaction, keyring, event_type, payload, recorded_at)
    }

    /// Imports a remotely bootstrapped ciphertext-only keyring after the
    /// application has proved an exact claimed handoff can decrypt its project
    /// key. This path accepts a later revision but never overwrites a local
    /// keyring or performs last-write-wins reconciliation.
    pub fn import_claimed_project_keyring(
        &mut self,
        keyring: &ProjectKeyring,
        manifest_digest: &str,
        recorded_at: DateTime<Utc>,
    ) -> Result<bool, StorageError> {
        validate_keyring(keyring)?;
        if keyring.canonical_digest()? != manifest_digest {
            return Err(StorageError::DomainDecode(
                "claimed keyring manifest digest mismatch".into(),
            ));
        }
        match self.load_project_keyring(&keyring.project_id) {
            Ok(existing) if existing == *keyring => return Ok(true),
            Ok(_) => {
                return Err(StorageError::ImmutableRecordMismatch {
                    kind: "claimed project keyring",
                    id: keyring.project_id.to_string(),
                });
            }
            Err(StorageError::ScopedRecordNotFound { .. }) => {}
            Err(error) => return Err(error),
        }
        let transaction = self.connection.transaction()?;
        ensure_project(&transaction, &keyring.tenant_id, &keyring.project_id)?;
        transaction.execute(
            "INSERT INTO project_keyrings
               (tenant_id, project_id, mode, active_key_version, remote_execution_opt_in,
                rotation_required, revision, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                keyring.tenant_id.as_str(),
                keyring.project_id.as_str(),
                enum_name(&keyring.mode)?,
                to_sql_u64(keyring.active_key_version)?,
                bool_sql(keyring.remote_execution_opt_in),
                bool_sql(keyring.rotation_required),
                to_sql_u64(keyring.revision)?,
                keyring.created_at.to_rfc3339(),
                keyring.updated_at.to_rfc3339(),
            ],
        )?;
        persist_envelopes(&transaction, keyring)?;
        append_events(
            &transaction,
            keyring.tenant_id.as_str(),
            keyring.project_id.as_str(),
            None,
            "project_keyring",
            keyring.project_id.as_str(),
            &[PendingEvent::new(
                "project_keyring.claimed_bootstrap_imported",
                serde_json::json!({
                    "keyringRevision": keyring.revision,
                    "activeKeyVersion": keyring.active_key_version,
                    "manifestDigest": manifest_digest,
                    "envelopeCount": keyring.envelopes.len(),
                }),
                recorded_at,
            )],
        )?;
        transaction.commit()?;
        Ok(false)
    }

    pub fn update_project_keyring(
        &mut self,
        keyring: &ProjectKeyring,
        expected_revision: u64,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        self.update_project_keyring_with_secret_references(
            keyring,
            expected_revision,
            &[],
            event_type,
            payload,
            recorded_at,
        )
    }

    pub fn update_project_keyring_with_secret_references(
        &mut self,
        keyring: &ProjectKeyring,
        expected_revision: u64,
        secret_references: &[ProjectKeySecretReference],
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        validate_keyring(keyring)?;
        require_next(expected_revision, keyring.revision)?;
        let transaction = self.connection.transaction()?;
        ensure_project(&transaction, &keyring.tenant_id, &keyring.project_id)?;
        let existing_envelope_ids = load_envelope_ids(&transaction, &keyring.project_id)?;
        let updated = transaction.execute(
            "UPDATE project_keyrings SET mode = ?3, active_key_version = ?4,
               remote_execution_opt_in = ?5, rotation_required = ?6, revision = ?7,
               updated_at = ?8
             WHERE tenant_id = ?1 AND project_id = ?2 AND revision = ?9",
            params![
                keyring.tenant_id.as_str(),
                keyring.project_id.as_str(),
                enum_name(&keyring.mode)?,
                to_sql_u64(keyring.active_key_version)?,
                bool_sql(keyring.remote_execution_opt_in),
                bool_sql(keyring.rotation_required),
                to_sql_u64(keyring.revision)?,
                keyring.updated_at.to_rfc3339(),
                to_sql_u64(expected_revision)?,
            ],
        )?;
        if updated != 1 {
            return Err(StorageError::OptimisticConflict {
                aggregate: "project_keyring".into(),
                expected_revision,
            });
        }
        persist_envelopes(&transaction, keyring)?;
        persist_secret_references(&transaction, keyring, secret_references)?;
        require_new_envelopes_have_secret_references(
            &transaction,
            keyring,
            &existing_envelope_ids,
        )?;
        finish(transaction, keyring, event_type, payload, recorded_at)
    }

    pub fn load_project_keyring(
        &self,
        project_id: &ProjectId,
    ) -> Result<ProjectKeyring, StorageError> {
        let row = self
            .connection
            .query_row(
                "SELECT tenant_id, mode, active_key_version, remote_execution_opt_in,
                        rotation_required, revision, created_at, updated_at
                 FROM project_keyrings WHERE project_id = ?1",
                [project_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| StorageError::ScopedRecordNotFound {
                kind: "project keyring",
                project_id: project_id.clone(),
                id: project_id.to_string(),
            })?;
        let mut statement = self.connection.prepare(
            "SELECT id, tenant_id, project_id, key_version, recipient_kind, recipient_id,
                    wrapping_key_reference_digest, algorithm, nonce, ciphertext, aad_digest,
                    created_at, expires_at, revoked_at, immutable_digest, record_json
             FROM project_key_envelopes
             WHERE project_id = ?1 ORDER BY sequence ASC",
        )?;
        let envelopes = statement
            .query_map([project_id.as_str()], load_envelope_projection)?
            .map(|row| validate_envelope_projection(&row?))
            .collect::<Result<Vec<_>, _>>()?;
        let keyring = ProjectKeyring {
            tenant_id: TenantId::from_stable(row.0),
            project_id: project_id.clone(),
            mode: decode_enum(&row.1)?,
            active_key_version: from_sql_u64(row.2, "active key version")?,
            remote_execution_opt_in: parse_bool(row.3, "remote execution opt in")?,
            rotation_required: parse_bool(row.4, "rotation required")?,
            envelopes,
            revision: from_sql_u64(row.5, "project keyring revision")?,
            created_at: parse_time(&row.6)?,
            updated_at: parse_time(&row.7)?,
        };
        validate_keyring(&keyring)?;
        Ok(keyring)
    }

    pub fn load_project_key_secret_references(
        &self,
        project_id: &ProjectId,
        recipient: &KeyRecipient,
    ) -> Result<Vec<ProjectKeySecretReference>, StorageError> {
        let keyring = self.load_project_keyring(project_id)?;
        let mut statement = self.connection.prepare(
            "SELECT tenant_id, project_id, envelope_id, key_version,
                    recipient_scope_digest, credential_id, record_digest, record_json
             FROM project_key_secret_references
             WHERE project_id = ?1 ORDER BY key_version ASC, envelope_id ASC",
        )?;
        let mut references = Vec::new();
        let rows = statement.query_map([project_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
            ))
        })?;
        for row in rows {
            let row = row?;
            let binding: ProjectKeySecretReference = decode_json(&row.7)?;
            let envelope = keyring
                .envelopes
                .iter()
                .find(|envelope| envelope.id == binding.envelope_id)
                .ok_or_else(|| StorageError::ScopedRecordNotFound {
                    kind: "key envelope for local secret reference",
                    project_id: project_id.clone(),
                    id: binding.envelope_id.to_string(),
                })?;
            binding.validate_against(envelope)?;
            let expected_record_digest = secret_reference_record_digest(&binding)?;
            let expected_recipient_digest = sha256_text(&binding.recipient.stable_scope());
            let expected_credential_id = binding
                .reference
                .credential_id()
                .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
            if row.0 != binding.tenant_id.as_str()
                || row.1 != binding.project_id.as_str()
                || row.2 != binding.envelope_id.as_str()
                || from_sql_u64(row.3, "local key reference version")? != binding.key_version
                || row.4 != expected_recipient_digest
                || row.5 != expected_credential_id
                || row.6 != expected_record_digest
            {
                return Err(StorageError::ImmutableRecordMismatch {
                    kind: "local key secret reference projection",
                    id: binding.envelope_id.to_string(),
                });
            }
            if &binding.recipient == recipient {
                references.push(binding);
            }
        }
        Ok(references)
    }

    pub fn prepare_device_attachment(
        &mut self,
        attachment: &DeviceAttachment,
    ) -> Result<DeviceAttachmentPrepareOutcome, StorageError> {
        attachment.validate()?;
        if attachment.status != DeviceAttachmentStatus::Prepared || attachment.revision != 1 {
            return Err(StorageError::InvalidInitialRevision(attachment.revision));
        }
        let transaction = self.connection.transaction()?;
        ensure_project(&transaction, &attachment.tenant_id, &attachment.project_id)?;
        if let Some(existing) = load_device_attachment_by_idempotency(
            &transaction,
            &attachment.project_id,
            &attachment.idempotency_key_digest,
        )? {
            if existing != *attachment {
                return Err(StorageError::ImmutableRecordMismatch {
                    kind: "device attachment intent",
                    id: attachment.idempotency_key_digest.clone(),
                });
            }
            transaction.commit()?;
            return Ok(DeviceAttachmentPrepareOutcome {
                attachment: existing,
                duplicate: true,
            });
        }
        require_attachment_keyring_head(&transaction, attachment)?;
        insert_device_attachment(&transaction, attachment)?;
        append_events(
            &transaction,
            attachment.tenant_id.as_str(),
            attachment.project_id.as_str(),
            None,
            "device_attachment",
            attachment.id.as_str(),
            &[PendingEvent::new(
                "project_keyring.device_attachment_prepared",
                serde_json::json!({
                    "attachmentId": attachment.id,
                    "method": attachment.method,
                    "sourceRecipient": attachment.source_recipient.stable_scope(),
                    "deviceId": attachment.device_id,
                    "keyVersion": attachment.key_version,
                    "expectedKeyringRevision": attachment.expected_keyring_revision,
                    "intentDigest": attachment.intent_digest,
                    "authorizedBy": attachment.authorized_by,
                    "authorizationEvidenceDigest": attachment.authorization_evidence_digest,
                }),
                attachment.created_at,
            )],
        )?;
        transaction.commit()?;
        Ok(DeviceAttachmentPrepareOutcome {
            attachment: attachment.clone(),
            duplicate: false,
        })
    }

    pub fn apply_device_attachment(
        &mut self,
        attachment: &DeviceAttachment,
        keyring: &ProjectKeyring,
        expected_attachment_revision: u64,
        expected_keyring_revision: u64,
        now: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        self.apply_device_attachment_with_secret_reference(
            attachment,
            keyring,
            expected_attachment_revision,
            expected_keyring_revision,
            None,
            now,
        )
    }

    pub fn apply_device_attachment_with_secret_reference(
        &mut self,
        attachment: &DeviceAttachment,
        keyring: &ProjectKeyring,
        expected_attachment_revision: u64,
        expected_keyring_revision: u64,
        secret_reference: Option<&ProjectKeySecretReference>,
        now: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        attachment.validate()?;
        validate_keyring(keyring)?;
        let transaction = self.connection.transaction()?;
        let existing_envelope_ids = load_envelope_ids(&transaction, &attachment.project_id)?;
        let previous =
            load_device_attachment(&transaction, &attachment.project_id, &attachment.id)?
                .ok_or_else(|| StorageError::ScopedRecordNotFound {
                    kind: "device attachment",
                    project_id: attachment.project_id.clone(),
                    id: attachment.id.to_string(),
                })?;
        if previous.revision != expected_attachment_revision
            || !attachment.follows(&previous)?
            || attachment.status != DeviceAttachmentStatus::Applied
            || expected_keyring_revision != previous.expected_keyring_revision
            || keyring.revision != attachment.result_keyring_revision.unwrap_or(0)
            || keyring.tenant_id != attachment.tenant_id
            || keyring.project_id != attachment.project_id
            || keyring.mode != attachment.project_mode
            || keyring.active_key_version != attachment.key_version
            || !keyring.envelopes.contains(&attachment.envelope)
        {
            return Err(StorageError::DomainDecode(
                "device attachment apply does not match prepared keyring transition".into(),
            ));
        }
        update_keyring_header(&transaction, keyring, expected_keyring_revision)?;
        persist_envelopes(&transaction, keyring)?;
        if let Some(reference) = secret_reference {
            persist_secret_references(&transaction, keyring, std::slice::from_ref(reference))?;
        }
        require_new_envelopes_have_secret_references(
            &transaction,
            keyring,
            &existing_envelope_ids,
        )?;
        update_device_attachment(&transaction, attachment, expected_attachment_revision)?;
        let (events, outbox) = append_events(
            &transaction,
            attachment.tenant_id.as_str(),
            attachment.project_id.as_str(),
            None,
            "device_attachment",
            attachment.id.as_str(),
            &[PendingEvent::new(
                "project_keyring.device_attached",
                serde_json::json!({
                    "attachmentId": attachment.id,
                    "method": attachment.method,
                    "deviceId": attachment.device_id,
                    "keyVersion": attachment.key_version,
                    "keyringRevision": keyring.revision,
                    "envelopeId": attachment.envelope.id,
                    "intentDigest": attachment.intent_digest,
                    "authorizedBy": attachment.authorized_by,
                    "authorizationEvidenceDigest": attachment.authorization_evidence_digest,
                }),
                now,
            )],
        )?;
        transaction.commit()?;
        Ok(PersistedMutation {
            event_sequence: events[0],
            outbox_sequence: outbox[0],
            state_revision: keyring.revision,
        })
    }

    pub fn mark_device_attachment_conflict(
        &mut self,
        attachment: &DeviceAttachment,
        expected_revision: u64,
        now: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        attachment.validate()?;
        if attachment.status != DeviceAttachmentStatus::Conflict {
            return Err(StorageError::DomainDecode(
                "device attachment conflict requires a terminal conflict record".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        let previous =
            load_device_attachment(&transaction, &attachment.project_id, &attachment.id)?
                .ok_or_else(|| StorageError::ScopedRecordNotFound {
                    kind: "device attachment",
                    project_id: attachment.project_id.clone(),
                    id: attachment.id.to_string(),
                })?;
        if previous.revision != expected_revision || !attachment.follows(&previous)? {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("device_attachment:{}", attachment.id),
                expected_revision,
            });
        }
        update_device_attachment(&transaction, attachment, expected_revision)?;
        let (events, outbox) = append_events(
            &transaction,
            attachment.tenant_id.as_str(),
            attachment.project_id.as_str(),
            None,
            "device_attachment",
            attachment.id.as_str(),
            &[PendingEvent::new(
                "project_keyring.device_attachment_conflict",
                serde_json::json!({
                    "attachmentId": attachment.id,
                    "deviceId": attachment.device_id,
                    "keyVersion": attachment.key_version,
                    "intentDigest": attachment.intent_digest,
                    "errorCode": attachment.error_code,
                }),
                now,
            )],
        )?;
        transaction.commit()?;
        Ok(PersistedMutation {
            event_sequence: events[0],
            outbox_sequence: outbox[0],
            state_revision: attachment.revision,
        })
    }

    pub fn load_device_attachment_by_idempotency(
        &self,
        project_id: &ProjectId,
        idempotency_key_digest: &str,
    ) -> Result<DeviceAttachment, StorageError> {
        load_device_attachment_by_idempotency(&self.connection, project_id, idempotency_key_digest)?
            .ok_or_else(|| StorageError::ScopedRecordNotFound {
                kind: "device attachment",
                project_id: project_id.clone(),
                id: idempotency_key_digest.to_owned(),
            })
    }
}

fn require_attachment_keyring_head(
    transaction: &Transaction<'_>,
    attachment: &DeviceAttachment,
) -> Result<(), StorageError> {
    let head = transaction
        .query_row(
            "SELECT mode, active_key_version, revision
             FROM project_keyrings WHERE tenant_id = ?1 AND project_id = ?2",
            params![
                attachment.tenant_id.as_str(),
                attachment.project_id.as_str()
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| StorageError::ScopedRecordNotFound {
            kind: "project keyring",
            project_id: attachment.project_id.clone(),
            id: attachment.project_id.to_string(),
        })?;
    if head.0 != enum_name(&attachment.project_mode)?
        || from_sql_u64(head.1, "active key version")? != attachment.key_version
        || from_sql_u64(head.2, "project keyring revision")? != attachment.expected_keyring_revision
    {
        return Err(StorageError::OptimisticConflict {
            aggregate: "project_keyring".into(),
            expected_revision: attachment.expected_keyring_revision,
        });
    }
    let existing_device = transaction
        .query_row(
            "SELECT 1 FROM project_key_envelopes
             WHERE project_id = ?1 AND key_version = ?2
               AND recipient_kind = 'device' AND recipient_id = ?3",
            params![
                attachment.project_id.as_str(),
                to_sql_u64(attachment.key_version)?,
                attachment.device_id.as_str(),
            ],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if existing_device {
        return Err(StorageError::ImmutableRecordMismatch {
            kind: "device key recipient",
            id: attachment.device_id.to_string(),
        });
    }
    Ok(())
}

fn update_keyring_header(
    transaction: &Transaction<'_>,
    keyring: &ProjectKeyring,
    expected_revision: u64,
) -> Result<(), StorageError> {
    require_next(expected_revision, keyring.revision)?;
    let updated = transaction.execute(
        "UPDATE project_keyrings SET mode = ?3, active_key_version = ?4,
           remote_execution_opt_in = ?5, rotation_required = ?6, revision = ?7,
           updated_at = ?8
         WHERE tenant_id = ?1 AND project_id = ?2 AND revision = ?9",
        params![
            keyring.tenant_id.as_str(),
            keyring.project_id.as_str(),
            enum_name(&keyring.mode)?,
            to_sql_u64(keyring.active_key_version)?,
            bool_sql(keyring.remote_execution_opt_in),
            bool_sql(keyring.rotation_required),
            to_sql_u64(keyring.revision)?,
            keyring.updated_at.to_rfc3339(),
            to_sql_u64(expected_revision)?,
        ],
    )?;
    if updated != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: "project_keyring".into(),
            expected_revision,
        });
    }
    Ok(())
}

fn insert_device_attachment(
    transaction: &Transaction<'_>,
    attachment: &DeviceAttachment,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO device_key_attachments
           (tenant_id, project_id, attachment_id, idempotency_key_digest,
            intent_digest, project_mode, method, source_recipient_kind,
            source_recipient_id, device_id, key_version, expected_keyring_revision,
            envelope_id, wrapping_key_reference_digest, authorized_by,
            authorization_evidence_digest, status, result_keyring_revision,
            error_code, attachment_revision, created_at, updated_at, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                 ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)",
        rusqlite::params_from_iter(device_attachment_params(attachment)?),
    )?;
    Ok(())
}

fn update_device_attachment(
    transaction: &Transaction<'_>,
    attachment: &DeviceAttachment,
    expected_revision: u64,
) -> Result<(), StorageError> {
    let changed = transaction.execute(
        "UPDATE device_key_attachments
         SET status = ?3, result_keyring_revision = ?4, error_code = ?5,
             attachment_revision = ?6, updated_at = ?7, record_json = ?8
         WHERE project_id = ?1 AND attachment_id = ?2 AND attachment_revision = ?9",
        params![
            attachment.project_id.as_str(),
            attachment.id.as_str(),
            attachment_status_name(attachment.status),
            attachment
                .result_keyring_revision
                .map(to_sql_u64)
                .transpose()?,
            attachment.error_code,
            to_sql_u64(attachment.revision)?,
            attachment.updated_at.to_rfc3339(),
            serde_json::to_string(attachment)?,
            to_sql_u64(expected_revision)?,
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("device_attachment:{}", attachment.id),
            expected_revision,
        });
    }
    Ok(())
}

fn load_device_attachment_by_idempotency(
    connection: &rusqlite::Connection,
    project_id: &ProjectId,
    idempotency_key_digest: &str,
) -> Result<Option<DeviceAttachment>, StorageError> {
    load_device_attachment_where(
        connection,
        "project_id = ?1 AND idempotency_key_digest = ?2",
        params![project_id.as_str(), idempotency_key_digest],
    )
}

fn load_device_attachment(
    connection: &rusqlite::Connection,
    project_id: &ProjectId,
    attachment_id: &DeviceAttachmentId,
) -> Result<Option<DeviceAttachment>, StorageError> {
    load_device_attachment_where(
        connection,
        "project_id = ?1 AND attachment_id = ?2",
        params![project_id.as_str(), attachment_id.as_str()],
    )
}

fn load_device_attachment_where(
    connection: &rusqlite::Connection,
    predicate: &str,
    query_params: impl rusqlite::Params,
) -> Result<Option<DeviceAttachment>, StorageError> {
    let sql = format!("SELECT record_json FROM device_key_attachments WHERE {predicate}");
    let json = connection
        .query_row(&sql, query_params, |row| row.get::<_, String>(0))
        .optional()?;
    let Some(json) = json else {
        return Ok(None);
    };
    let attachment: DeviceAttachment = serde_json::from_str(&json)?;
    attachment.validate()?;
    let normalized = connection
        .query_row(
            "SELECT 1 FROM device_key_attachments
             WHERE tenant_id = ?1 AND project_id = ?2 AND attachment_id = ?3
               AND idempotency_key_digest = ?4 AND intent_digest = ?5
               AND project_mode = ?6 AND method = ?7
               AND source_recipient_kind = ?8 AND source_recipient_id = ?9
               AND device_id = ?10 AND key_version = ?11
               AND expected_keyring_revision = ?12 AND envelope_id = ?13
               AND wrapping_key_reference_digest = ?14 AND authorized_by = ?15
               AND authorization_evidence_digest = ?16 AND status = ?17
               AND result_keyring_revision IS ?18 AND error_code IS ?19
               AND attachment_revision = ?20 AND created_at = ?21
               AND updated_at = ?22 AND record_json = ?23",
            rusqlite::params_from_iter(device_attachment_params(&attachment)?),
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !normalized {
        return Err(StorageError::DomainDecode(
            "normalized device attachment differs from record body".into(),
        ));
    }
    Ok(Some(attachment))
}

fn device_attachment_params(
    attachment: &DeviceAttachment,
) -> Result<Vec<rusqlite::types::Value>, StorageError> {
    let (source_kind, source_id) = attachment_source_scope(&attachment.source_recipient)?;
    Ok(vec![
        attachment.tenant_id.as_str().to_owned().into(),
        attachment.project_id.as_str().to_owned().into(),
        attachment.id.as_str().to_owned().into(),
        attachment.idempotency_key_digest.clone().into(),
        attachment.intent_digest.clone().into(),
        enum_name(&attachment.project_mode)?.into(),
        enum_name(&attachment.method)?.into(),
        source_kind.to_owned().into(),
        source_id.to_owned().into(),
        attachment.device_id.as_str().to_owned().into(),
        to_sql_u64(attachment.key_version)?.into(),
        to_sql_u64(attachment.expected_keyring_revision)?.into(),
        attachment.envelope.id.as_str().to_owned().into(),
        attachment
            .envelope
            .wrapping_key_reference_digest
            .clone()
            .into(),
        attachment.authorized_by.as_str().to_owned().into(),
        attachment.authorization_evidence_digest.clone().into(),
        attachment_status_name(attachment.status).to_owned().into(),
        attachment
            .result_keyring_revision
            .map(to_sql_u64)
            .transpose()?
            .map_or(rusqlite::types::Value::Null, Into::into),
        attachment
            .error_code
            .clone()
            .map_or(rusqlite::types::Value::Null, Into::into),
        to_sql_u64(attachment.revision)?.into(),
        attachment.created_at.to_rfc3339().into(),
        attachment.updated_at.to_rfc3339().into(),
        serde_json::to_string(attachment)?.into(),
    ])
}

fn attachment_source_scope(recipient: &KeyRecipient) -> Result<(&'static str, &str), StorageError> {
    match recipient {
        KeyRecipient::Device(id) => Ok(("device", id.as_str())),
        KeyRecipient::Member(id) => Ok(("member", id.as_str())),
        KeyRecipient::Recovery(id) => Ok(("recovery", id)),
        KeyRecipient::Worker(_) => Err(StorageError::DomainDecode(
            "worker cannot source a device attachment".into(),
        )),
    }
}

const fn attachment_status_name(status: DeviceAttachmentStatus) -> &'static str {
    match status {
        DeviceAttachmentStatus::Prepared => "prepared",
        DeviceAttachmentStatus::Applied => "applied",
        DeviceAttachmentStatus::Conflict => "conflict",
    }
}

fn persist_secret_references(
    transaction: &Transaction<'_>,
    keyring: &ProjectKeyring,
    bindings: &[ProjectKeySecretReference],
) -> Result<(), StorageError> {
    for binding in bindings {
        let envelope = keyring
            .envelopes
            .iter()
            .find(|envelope| envelope.id == binding.envelope_id)
            .ok_or_else(|| StorageError::ScopedRecordNotFound {
                kind: "key envelope for local secret reference",
                project_id: keyring.project_id.clone(),
                id: binding.envelope_id.to_string(),
            })?;
        binding.validate_against(envelope)?;
        let recipient_scope_digest = sha256_text(&binding.recipient.stable_scope());
        let credential_id = binding
            .reference
            .credential_id()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        let record_digest = secret_reference_record_digest(binding)?;
        let record_json = serde_json::to_string(binding)?;
        let inserted = transaction.execute(
            "INSERT INTO project_key_secret_references
               (tenant_id, project_id, envelope_id, key_version,
                recipient_scope_digest, credential_id, record_digest, record_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(project_id, envelope_id) DO NOTHING",
            params![
                binding.tenant_id.as_str(),
                binding.project_id.as_str(),
                binding.envelope_id.as_str(),
                to_sql_u64(binding.key_version)?,
                recipient_scope_digest,
                credential_id,
                record_digest,
                record_json,
            ],
        )?;
        if inserted == 0 {
            let stored = transaction
                .query_row(
                    "SELECT record_digest, record_json
                     FROM project_key_secret_references
                     WHERE project_id = ?1 AND envelope_id = ?2",
                    params![binding.project_id.as_str(), binding.envelope_id.as_str()],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?
                .ok_or_else(|| StorageError::ImmutableRecordMismatch {
                    kind: "local key secret reference",
                    id: binding.envelope_id.to_string(),
                })?;
            if stored.0 != record_digest || stored.1 != record_json {
                return Err(StorageError::ImmutableRecordMismatch {
                    kind: "local key secret reference",
                    id: binding.envelope_id.to_string(),
                });
            }
        }
    }
    Ok(())
}

struct EnvelopeProjection {
    id: String,
    tenant_id: String,
    project_id: String,
    key_version: i64,
    recipient_kind: String,
    recipient_id: String,
    wrapping_key_reference_digest: String,
    algorithm: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    aad_digest: String,
    created_at: String,
    expires_at: Option<String>,
    revoked_at: Option<String>,
    immutable_digest: String,
    record_json: String,
}

fn load_envelope_projection(row: &Row<'_>) -> rusqlite::Result<EnvelopeProjection> {
    Ok(EnvelopeProjection {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        project_id: row.get(2)?,
        key_version: row.get(3)?,
        recipient_kind: row.get(4)?,
        recipient_id: row.get(5)?,
        wrapping_key_reference_digest: row.get(6)?,
        algorithm: row.get(7)?,
        nonce: row.get(8)?,
        ciphertext: row.get(9)?,
        aad_digest: row.get(10)?,
        created_at: row.get(11)?,
        expires_at: row.get(12)?,
        revoked_at: row.get(13)?,
        immutable_digest: row.get(14)?,
        record_json: row.get(15)?,
    })
}

fn validate_envelope_projection(
    projection: &EnvelopeProjection,
) -> Result<KeyEnvelope, StorageError> {
    let envelope: KeyEnvelope = decode_json(&projection.record_json)?;
    let (recipient_kind, recipient_id) = recipient_scope(&envelope.recipient);
    let expected_immutable_digest = immutable_envelope_digest(&envelope)?;
    if projection.id != envelope.id.as_str()
        || projection.tenant_id != envelope.tenant_id.as_str()
        || projection.project_id != envelope.project_id.as_str()
        || from_sql_u64(projection.key_version, "key envelope version")? != envelope.key_version
        || projection.recipient_kind != recipient_kind
        || projection.recipient_id != recipient_id
        || projection.wrapping_key_reference_digest != envelope.wrapping_key_reference_digest
        || projection.algorithm != enum_name(&envelope.sealed_key.algorithm)?
        || projection.nonce != envelope.sealed_key.nonce
        || projection.ciphertext != envelope.sealed_key.ciphertext
        || projection.aad_digest != envelope.sealed_key.aad_digest
        || projection.created_at != envelope.created_at.to_rfc3339()
        || projection.expires_at != envelope.expires_at.map(|value| value.to_rfc3339())
        || projection.revoked_at != envelope.revoked_at.map(|value| value.to_rfc3339())
        || projection.immutable_digest != expected_immutable_digest
    {
        return Err(StorageError::ImmutableRecordMismatch {
            kind: "key envelope projection",
            id: envelope.id.to_string(),
        });
    }
    Ok(envelope)
}

fn load_envelope_ids(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
) -> Result<BTreeSet<String>, StorageError> {
    let mut statement = transaction.prepare(
        "SELECT id FROM project_key_envelopes WHERE project_id = ?1 ORDER BY sequence ASC",
    )?;
    statement
        .query_map([project_id.as_str()], |row| row.get::<_, String>(0))?
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(StorageError::from)
}

fn require_new_envelopes_have_secret_references(
    transaction: &Transaction<'_>,
    keyring: &ProjectKeyring,
    existing_envelope_ids: &BTreeSet<String>,
) -> Result<(), StorageError> {
    for envelope in keyring.envelopes.iter().filter(|envelope| {
        !matches!(envelope.recipient, KeyRecipient::Recovery(_))
            && !existing_envelope_ids.contains(envelope.id.as_str())
    }) {
        let binding_exists = transaction
            .query_row(
                "SELECT 1 FROM project_key_secret_references
                 WHERE project_id = ?1 AND envelope_id = ?2",
                params![envelope.project_id.as_str(), envelope.id.as_str()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !binding_exists {
            return Err(StorageError::DomainDecode(
                "new non-recovery envelope requires an atomic local SecretReference binding".into(),
            ));
        }
    }
    Ok(())
}

fn secret_reference_record_digest(
    binding: &ProjectKeySecretReference,
) -> Result<String, StorageError> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(binding)?)
    ))
}

fn sha256_text(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn persist_envelopes(
    transaction: &Transaction<'_>,
    keyring: &ProjectKeyring,
) -> Result<(), StorageError> {
    for envelope in &keyring.envelopes {
        let (recipient_kind, recipient_id) = recipient_scope(&envelope.recipient);
        let immutable_digest = immutable_envelope_digest(envelope)?;
        let record_json = serde_json::to_string(envelope)?;
        let inserted = transaction.execute(
            "INSERT INTO project_key_envelopes
               (id, tenant_id, project_id, key_version, recipient_kind, recipient_id,
                wrapping_key_reference_digest, algorithm, nonce, ciphertext, aad_digest,
                created_at, expires_at, revoked_at, immutable_digest, record_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                     ?13, ?14, ?15, ?16)
             ON CONFLICT(project_id, id) DO NOTHING",
            params![
                envelope.id.as_str(),
                envelope.tenant_id.as_str(),
                envelope.project_id.as_str(),
                to_sql_u64(envelope.key_version)?,
                recipient_kind,
                recipient_id,
                envelope.wrapping_key_reference_digest,
                enum_name(&envelope.sealed_key.algorithm)?,
                envelope.sealed_key.nonce,
                envelope.sealed_key.ciphertext,
                envelope.sealed_key.aad_digest,
                envelope.created_at.to_rfc3339(),
                envelope.expires_at.map(|value| value.to_rfc3339()),
                envelope.revoked_at.map(|value| value.to_rfc3339()),
                immutable_digest,
                record_json,
            ],
        )?;
        if inserted == 0 {
            verify_and_update_existing(transaction, envelope, &immutable_digest, &record_json)?;
        }
    }
    Ok(())
}

fn verify_and_update_existing(
    transaction: &Transaction<'_>,
    envelope: &KeyEnvelope,
    immutable_digest: &str,
    record_json: &str,
) -> Result<(), StorageError> {
    let stored = transaction
        .query_row(
            "SELECT immutable_digest FROM project_key_envelopes
             WHERE project_id = ?1 AND id = ?2",
            params![envelope.project_id.as_str(), envelope.id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| StorageError::ScopedRecordNotFound {
            kind: "key envelope",
            project_id: envelope.project_id.clone(),
            id: envelope.id.to_string(),
        })?;
    if stored != immutable_digest {
        return Err(StorageError::ImmutableRecordMismatch {
            kind: "key envelope",
            id: envelope.id.to_string(),
        });
    }
    transaction.execute(
        "UPDATE project_key_envelopes SET revoked_at = ?3, record_json = ?4
         WHERE project_id = ?1 AND id = ?2",
        params![
            envelope.project_id.as_str(),
            envelope.id.as_str(),
            envelope.revoked_at.map(|value| value.to_rfc3339()),
            record_json,
        ],
    )?;
    Ok(())
}

fn immutable_envelope_digest(envelope: &KeyEnvelope) -> Result<String, StorageError> {
    let immutable = serde_json::json!({
        "id": envelope.id,
        "tenantId": envelope.tenant_id,
        "projectId": envelope.project_id,
        "keyVersion": envelope.key_version,
        "recipient": envelope.recipient,
        "wrappingKeyReferenceDigest": envelope.wrapping_key_reference_digest,
        "sealedKey": envelope.sealed_key,
        "createdAt": envelope.created_at,
        "expiresAt": envelope.expires_at,
    });
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&immutable)?)
    ))
}

fn recipient_scope(recipient: &KeyRecipient) -> (&'static str, &str) {
    match recipient {
        KeyRecipient::Device(id) => ("device", id.as_str()),
        KeyRecipient::Member(id) => ("member", id.as_str()),
        KeyRecipient::Worker(id) => ("worker", id.as_str()),
        KeyRecipient::Recovery(id) => ("recovery", id.as_str()),
    }
}

fn ensure_project(
    transaction: &Transaction<'_>,
    tenant_id: &TenantId,
    project_id: &ProjectId,
) -> Result<(), StorageError> {
    let stored_tenant = transaction
        .query_row(
            "SELECT tenant_id FROM projects WHERE id = ?1",
            [project_id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| StorageError::ProjectNotFound(project_id.clone()))?;
    if stored_tenant != tenant_id.as_str() {
        return Err(StorageError::TenantScopeMismatch);
    }
    Ok(())
}

fn finish(
    transaction: Transaction<'_>,
    keyring: &ProjectKeyring,
    event_type: &str,
    payload: &Value,
    recorded_at: DateTime<Utc>,
) -> Result<PersistedMutation, StorageError> {
    if event_type.trim().is_empty() {
        return Err(StorageError::EmptyEventType);
    }
    let payload_json = serde_json::to_string(payload)?;
    transaction.execute(
        "INSERT INTO domain_events
           (tenant_id, project_id, mission_id, event_type, payload_json, recorded_at)
         VALUES (?1, ?2, NULL, ?3, ?4, ?5)",
        params![
            keyring.tenant_id.as_str(),
            keyring.project_id.as_str(),
            event_type,
            payload_json,
            recorded_at.to_rfc3339(),
        ],
    )?;
    let event_sequence = transaction.last_insert_rowid();
    transaction.execute(
        "INSERT INTO outbox_messages
           (tenant_id, project_id, mission_id, aggregate_type, aggregate_id, event_type,
            payload_json, available_at, created_at)
         VALUES (?1, ?2, NULL, 'project_keyring', ?2, ?3, ?4, ?5, ?5)",
        params![
            keyring.tenant_id.as_str(),
            keyring.project_id.as_str(),
            event_type,
            payload_json,
            recorded_at.to_rfc3339(),
        ],
    )?;
    let outbox_sequence = transaction.last_insert_rowid();
    transaction.commit()?;
    Ok(PersistedMutation {
        event_sequence,
        outbox_sequence,
        state_revision: keyring.revision,
    })
}

fn validate_keyring(keyring: &ProjectKeyring) -> Result<(), StorageError> {
    keyring
        .validate()
        .map_err(|error| StorageError::DomainDecode(error.to_string()))
}

fn require_next(expected: u64, actual: u64) -> Result<(), StorageError> {
    let next = expected
        .checked_add(1)
        .ok_or(StorageError::RevisionOverflow(expected))?;
    if actual == next {
        Ok(())
    } else {
        Err(StorageError::UnexpectedNextRevision {
            expected: next,
            actual,
        })
    }
}

fn enum_name(value: &impl Serialize) -> Result<String, StorageError> {
    serde_json::to_value(value)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| StorageError::DomainDecode("enum did not serialize as a string".into()))
}

fn decode_enum<T: DeserializeOwned>(value: &str) -> Result<T, StorageError> {
    Ok(serde_json::from_value(Value::String(value.to_owned()))?)
}

fn decode_json<T: DeserializeOwned>(value: &str) -> Result<T, StorageError> {
    Ok(serde_json::from_str(value)?)
}

fn parse_time(value: &str) -> Result<DateTime<Utc>, StorageError> {
    Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
}

fn bool_sql(value: bool) -> i64 {
    i64::from(value)
}

fn parse_bool(value: i64, field: &str) -> Result<bool, StorageError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(StorageError::DomainDecode(format!(
            "invalid {field}: {value}"
        ))),
    }
}

fn to_sql_u64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::RevisionOverflow(value))
}

fn from_sql_u64(value: i64, field: &str) -> Result<u64, StorageError> {
    u64::try_from(value)
        .map_err(|_| StorageError::DomainDecode(format!("invalid {field}: {value}")))
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        ActorId, DeviceAttachmentMethod, DeviceId, KeyEnvelopeId, MemberId, Project,
        ProjectEncryptionMode, StorageMode,
    };

    use super::*;
    use crate::{DatabaseKey, EnvelopeContext, EnvelopeCrypto, KeyMaterial, SecretReference};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 10, 8, 0, 0)
            .single()
            .expect("valid time")
    }

    fn project() -> Project {
        Project::create_local(
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            "Encrypted project",
            "",
            "/tmp/hartevo-encrypted-project",
            StorageMode::LocalEncryptedSync,
        )
        .expect("project")
    }

    fn envelope(
        id: &str,
        version: u64,
        recipient: KeyRecipient,
        project_key: &KeyMaterial,
        wrapping_key: &KeyMaterial,
        created_at: DateTime<Utc>,
    ) -> KeyEnvelope {
        let reference = SecretReference {
            tenant_id: TenantId::from("tenant-1"),
            project_id: ProjectId::from("project-1"),
            provider: "os-keychain".into(),
            account_scope: recipient.stable_scope(),
            purpose: "project_wrapping_key".into(),
            version,
        };
        let context = EnvelopeContext {
            tenant_id: TenantId::from("tenant-1"),
            project_id: ProjectId::from("project-1"),
            key_version: version,
            recipient: recipient.clone(),
            purpose: "project_content_key".into(),
            expires_at: None,
        };
        KeyEnvelope {
            id: KeyEnvelopeId::from(id),
            tenant_id: TenantId::from("tenant-1"),
            project_id: ProjectId::from("project-1"),
            key_version: version,
            recipient,
            wrapping_key_reference_digest: reference.credential_id().expect("reference"),
            sealed_key: EnvelopeCrypto::seal_key(project_key, wrapping_key, &context)
                .expect("sealed key"),
            created_at,
            expires_at: None,
            revoked_at: None,
        }
    }

    fn wrapping_reference(recipient: &KeyRecipient, version: u64) -> SecretReference {
        SecretReference {
            tenant_id: TenantId::from("tenant-1"),
            project_id: ProjectId::from("project-1"),
            provider: "os-keychain".into(),
            account_scope: recipient.stable_scope(),
            purpose: "project_wrapping_key".into(),
            version,
        }
    }

    #[test]
    fn keyring_creation_without_atomic_secret_reference_rolls_back() {
        let project = project();
        let project_key = KeyMaterial::from_bytes([7; 32]).expect("project key");
        let wrapping_key = KeyMaterial::from_bytes([8; 32]).expect("wrapping key");
        let recipient = KeyRecipient::Device(DeviceId::from("device-missing-binding"));
        let keyring = ProjectKeyring::initialize(
            project.tenant_id.clone(),
            project.id.clone(),
            ProjectEncryptionMode::TeamEnvelope,
            vec![envelope(
                "envelope-missing-binding-v1",
                1,
                recipient,
                &project_key,
                &wrapping_key,
                now(),
            )],
            now(),
        )
        .expect("keyring");
        let mut store = ProjectStore::in_memory().expect("store");
        store.save_project(&project).expect("project");

        assert!(matches!(
            store.create_project_keyring(
                &keyring,
                "project_keyring.created",
                &serde_json::json!({}),
                now(),
            ),
            Err(StorageError::DomainDecode(message))
                if message.contains("requires an atomic local SecretReference binding")
        ));
        for table in ["project_keyrings", "project_key_envelopes"] {
            let sql = format!("SELECT COUNT(*) FROM {table}");
            assert_eq!(
                store
                    .connection
                    .query_row(&sql, [], |row| row.get::<_, i64>(0))
                    .expect("rolled-back row count"),
                0,
                "{table} must roll back with the missing binding"
            );
        }
    }

    #[test]
    fn local_secret_reference_failure_rolls_back_keyring_atomically() {
        let project = project();
        let project_key = KeyMaterial::from_bytes([7; 32]).expect("project key");
        let wrapping_key = KeyMaterial::from_bytes([8; 32]).expect("wrapping key");
        let recipient = KeyRecipient::Device(DeviceId::from("device-reference-registry"));
        let envelope = envelope(
            "envelope-reference-registry-v1",
            1,
            recipient.clone(),
            &project_key,
            &wrapping_key,
            now(),
        );
        let binding = ProjectKeySecretReference::bind(&envelope, wrapping_reference(&recipient, 1))
            .expect("exact binding");
        let keyring = ProjectKeyring::initialize(
            project.tenant_id.clone(),
            project.id.clone(),
            ProjectEncryptionMode::TeamEnvelope,
            vec![envelope],
            now(),
        )
        .expect("keyring");

        let mut failing = ProjectStore::in_memory().expect("failing store");
        failing.save_project(&project).expect("project");
        failing
            .connection
            .execute_batch(
                "CREATE TRIGGER fail_local_key_reference
                 BEFORE INSERT ON project_key_secret_references
                 BEGIN SELECT RAISE(ABORT, 'injected local reference failure'); END;",
            )
            .expect("failure trigger");
        assert!(
            failing
                .create_project_keyring_with_secret_references(
                    &keyring,
                    std::slice::from_ref(&binding),
                    "project_keyring.created",
                    &serde_json::json!({}),
                    now(),
                )
                .is_err()
        );
        assert_eq!(
            failing
                .connection
                .query_row("SELECT COUNT(*) FROM project_keyrings", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("keyring count"),
            0
        );
        assert_eq!(
            failing
                .connection
                .query_row("SELECT COUNT(*) FROM project_key_envelopes", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("envelope count"),
            0
        );
    }

    #[test]
    fn local_secret_reference_binding_is_restart_metadata_and_tamper_evident() {
        let project = project();
        let project_key = KeyMaterial::from_bytes([7; 32]).expect("project key");
        let wrapping_key = KeyMaterial::from_bytes([8; 32]).expect("wrapping key");
        let recipient = KeyRecipient::Device(DeviceId::from("device-reference-registry"));
        let envelope = envelope(
            "envelope-reference-registry-v1",
            1,
            recipient.clone(),
            &project_key,
            &wrapping_key,
            now(),
        );
        let binding = ProjectKeySecretReference::bind(&envelope, wrapping_reference(&recipient, 1))
            .expect("exact binding");
        let keyring = ProjectKeyring::initialize(
            project.tenant_id.clone(),
            project.id.clone(),
            ProjectEncryptionMode::TeamEnvelope,
            vec![envelope],
            now(),
        )
        .expect("keyring");

        let mut store = ProjectStore::in_memory().expect("store");
        store.save_project(&project).expect("project");
        store
            .create_project_keyring_with_secret_references(
                &keyring,
                std::slice::from_ref(&binding),
                "project_keyring.created",
                &serde_json::json!({}),
                now(),
            )
            .expect("atomic keyring and reference");
        assert_eq!(
            store
                .load_project_key_secret_references(&project.id, &recipient)
                .expect("restored reference"),
            vec![binding.clone()]
        );
        let stored_json = store
            .connection
            .query_row(
                "SELECT record_json FROM project_key_secret_references
                 WHERE project_id = ?1 AND envelope_id = ?2",
                params![project.id.as_str(), binding.envelope_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .expect("binding JSON");
        assert!(!stored_json.contains(&"08".repeat(32)));
        store
            .connection
            .execute(
                "UPDATE project_key_secret_references SET credential_id = ?3
                 WHERE project_id = ?1 AND envelope_id = ?2",
                params![
                    project.id.as_str(),
                    binding.envelope_id.as_str(),
                    "f".repeat(64)
                ],
            )
            .expect("tamper normalized credential projection");
        assert!(matches!(
            store.load_project_key_secret_references(&project.id, &recipient),
            Err(StorageError::ImmutableRecordMismatch {
                kind: "local key secret reference projection",
                ..
            })
        ));
    }

    #[test]
    fn keyring_round_trip_keeps_only_wrapped_project_key_material() {
        let mut store = ProjectStore::in_memory().expect("store");
        let project = project();
        store.save_project(&project).expect("project");
        let project_key = KeyMaterial::from_bytes([7; 32]).expect("project key");
        let wrapping_key = KeyMaterial::from_bytes([8; 32]).expect("wrapping key");
        let recovery_key = KeyMaterial::from_bytes([9; 32]).expect("recovery key");
        let recipient = KeyRecipient::Device(DeviceId::from("device-1"));
        let device_envelope = envelope(
            "envelope-v1",
            1,
            recipient.clone(),
            &project_key,
            &wrapping_key,
            now(),
        );
        let device_binding =
            ProjectKeySecretReference::bind(&device_envelope, wrapping_reference(&recipient, 1))
                .expect("device binding");
        let recovery_envelope = envelope(
            "recovery-envelope-v1",
            1,
            KeyRecipient::Recovery("recovery-kit-1".into()),
            &project_key,
            &recovery_key,
            now(),
        );
        let keyring = ProjectKeyring::initialize(
            project.tenant_id.clone(),
            project.id.clone(),
            ProjectEncryptionMode::PersonalE2ee,
            vec![device_envelope, recovery_envelope],
            now(),
        )
        .expect("keyring");
        store
            .create_project_keyring_with_secret_references(
                &keyring,
                std::slice::from_ref(&device_binding),
                "project_keyring.created",
                &serde_json::json!({"activeKeyVersion": 1}),
                now(),
            )
            .expect("persist keyring");
        let restored = store
            .load_project_keyring(&project.id)
            .expect("restored keyring");
        assert_eq!(restored, keyring);
        let stored_envelope = restored
            .active_envelope_for(&recipient, now())
            .expect("device envelope");
        let context = EnvelopeContext {
            tenant_id: project.tenant_id,
            project_id: project.id,
            key_version: 1,
            recipient,
            purpose: "project_content_key".into(),
            expires_at: None,
        };
        let opened = EnvelopeCrypto::open_key(&stored_envelope.sealed_key, &wrapping_key, &context)
            .expect("open project key");
        assert_eq!(
            opened.to_secret().as_slice(),
            project_key.to_secret().as_slice()
        );
        store
            .connection
            .execute(
                "UPDATE project_key_envelopes SET recipient_id = 'device-forged'
                 WHERE project_id = ?1 AND id = ?2",
                params![keyring.project_id.as_str(), stored_envelope.id.as_str()],
            )
            .expect("tamper normalized envelope projection");
        assert!(matches!(
            store.load_project_keyring(&keyring.project_id),
            Err(StorageError::ImmutableRecordMismatch {
                kind: "key envelope projection",
                ..
            })
        ));
    }

    #[test]
    fn revoked_member_rotation_is_cas_persisted_and_stale_writes_fail() {
        let mut store = ProjectStore::in_memory().expect("store");
        let project = project();
        store.save_project(&project).expect("project");
        let first_key = KeyMaterial::from_bytes([7; 32]).expect("first key");
        let second_key = KeyMaterial::from_bytes([6; 32]).expect("second key");
        let wrapping_key = KeyMaterial::from_bytes([8; 32]).expect("wrapping key");
        let member_one = KeyRecipient::Member(MemberId::from("member-1"));
        let member_two = KeyRecipient::Member(MemberId::from("member-2"));
        let member_one_envelope = envelope(
            "member-1-v1",
            1,
            member_one.clone(),
            &first_key,
            &wrapping_key,
            now(),
        );
        let member_one_binding = ProjectKeySecretReference::bind(
            &member_one_envelope,
            wrapping_reference(&member_one, 1),
        )
        .expect("member one binding");
        let mut keyring = ProjectKeyring::initialize(
            project.tenant_id,
            project.id.clone(),
            ProjectEncryptionMode::TeamEnvelope,
            vec![member_one_envelope],
            now(),
        )
        .expect("team keyring");
        store
            .create_project_keyring_with_secret_references(
                &keyring,
                std::slice::from_ref(&member_one_binding),
                "project_keyring.created",
                &serde_json::json!({}),
                now(),
            )
            .expect("persist keyring");
        let mut stale = keyring.clone();
        keyring
            .revoke_recipient(&member_one, now() + Duration::minutes(1))
            .expect("revoke");
        store
            .update_project_keyring(
                &keyring,
                1,
                "project_keyring.recipient_revoked",
                &serde_json::json!({"recipient": member_one.stable_scope()}),
                now() + Duration::minutes(1),
            )
            .expect("persist revoke");
        stale
            .set_remote_execution_opt_in(true, now() + Duration::minutes(1))
            .expect("stale mutation");
        assert!(matches!(
            store.update_project_keyring(
                &stale,
                1,
                "project_keyring.remote_enabled",
                &serde_json::json!({}),
                now() + Duration::minutes(1),
            ),
            Err(StorageError::OptimisticConflict { .. })
        ));

        let member_two_envelope = envelope(
            "member-2-v2",
            2,
            member_two.clone(),
            &second_key,
            &wrapping_key,
            now() + Duration::minutes(2),
        );
        let member_two_binding = ProjectKeySecretReference::bind(
            &member_two_envelope,
            wrapping_reference(&member_two, 2),
        )
        .expect("member two binding");
        keyring
            .rotate(vec![member_two_envelope], now() + Duration::minutes(2))
            .expect("rotate");
        store
            .update_project_keyring_with_secret_references(
                &keyring,
                2,
                std::slice::from_ref(&member_two_binding),
                "project_keyring.rotated",
                &serde_json::json!({"activeKeyVersion": 2}),
                now() + Duration::minutes(2),
            )
            .expect("persist rotation");
        let restored = store.load_project_keyring(&project.id).expect("restored");
        assert_eq!(restored.active_key_version, 2);
        assert!(!restored.rotation_required);
        assert!(
            restored
                .active_envelope_for(&member_two, now() + Duration::minutes(2))
                .is_ok()
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the test proves an actual encrypted database restart between Prepared and Applied plus exact replay and atomic keyring persistence"
    )]
    fn prepared_device_attachment_resumes_after_reopen_and_applies_atomically() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("device-attachment.sqlite3");
        let database_key = DatabaseKey::new([3; 32]).expect("database key");
        let project = project();
        let project_key = KeyMaterial::from_bytes([7; 32]).expect("project key");
        let device_one_key = KeyMaterial::from_bytes([8; 32]).expect("device one key");
        let recovery_key = KeyMaterial::from_bytes([9; 32]).expect("recovery key");
        let device_two_key = KeyMaterial::from_bytes([6; 32]).expect("device two key");
        let device_one = KeyRecipient::Device(DeviceId::from("device-1"));
        let device_two = KeyRecipient::Device(DeviceId::from("device-2"));
        let device_one_envelope = envelope(
            "device-1-v1",
            1,
            device_one.clone(),
            &project_key,
            &device_one_key,
            now(),
        );
        let device_one_binding = ProjectKeySecretReference::bind(
            &device_one_envelope,
            wrapping_reference(&device_one, 1),
        )
        .expect("device one binding");
        let initial_keyring = ProjectKeyring::initialize(
            project.tenant_id.clone(),
            project.id.clone(),
            ProjectEncryptionMode::PersonalE2ee,
            vec![
                device_one_envelope,
                envelope(
                    "recovery-v1",
                    1,
                    KeyRecipient::Recovery("recovery-1".into()),
                    &project_key,
                    &recovery_key,
                    now(),
                ),
            ],
            now(),
        )
        .expect("personal keyring");
        let device_two_envelope = envelope(
            "device-2-v1",
            1,
            device_two.clone(),
            &project_key,
            &device_two_key,
            now() + Duration::minutes(1),
        );
        let device_two_binding = ProjectKeySecretReference::bind(
            &device_two_envelope,
            wrapping_reference(&device_two, 1),
        )
        .expect("device two binding");
        let prepared = DeviceAttachment::prepare(
            DeviceAttachmentId::from("attachment-device-2"),
            project.tenant_id.clone(),
            project.id.clone(),
            ProjectEncryptionMode::PersonalE2ee,
            DeviceAttachmentMethod::AuthorizedRecipient,
            device_one,
            DeviceId::from("device-2"),
            1,
            1,
            device_two_envelope.clone(),
            ActorId::from("owner-1"),
            "1".repeat(64),
            "2".repeat(64),
            "3".repeat(64),
            now() + Duration::minutes(1),
        )
        .expect("prepared attachment");

        {
            let mut store = ProjectStore::open(&database, &database_key).expect("store");
            store.save_project(&project).expect("project");
            store
                .create_project_keyring_with_secret_references(
                    &initial_keyring,
                    std::slice::from_ref(&device_one_binding),
                    "project_keyring.created",
                    &serde_json::json!({}),
                    now(),
                )
                .expect("keyring");
            let outcome = store
                .prepare_device_attachment(&prepared)
                .expect("durable prepare");
            assert!(!outcome.duplicate);
        }

        {
            let mut reopened = ProjectStore::open(&database, &database_key).expect("reopen");
            let restored = reopened
                .load_device_attachment_by_idempotency(
                    &project.id,
                    &prepared.idempotency_key_digest,
                )
                .expect("prepared attachment survives");
            assert_eq!(restored.status, DeviceAttachmentStatus::Prepared);
            let duplicate = reopened
                .prepare_device_attachment(&prepared)
                .expect("exact prepare replay");
            assert!(duplicate.duplicate);
            let mut next_keyring = reopened
                .load_project_keyring(&project.id)
                .expect("current keyring");
            next_keyring
                .add_envelope(device_two_envelope, now() + Duration::minutes(2))
                .expect("attach device envelope");
            let applied = restored
                .mark_applied(
                    restored.revision,
                    next_keyring.revision,
                    now() + Duration::minutes(2),
                )
                .expect("apply attachment state");
            reopened
                .apply_device_attachment_with_secret_reference(
                    &applied,
                    &next_keyring,
                    restored.revision,
                    restored.expected_keyring_revision,
                    Some(&device_two_binding),
                    now() + Duration::minutes(2),
                )
                .expect("atomic attachment and keyring update");
        }

        let reopened = ProjectStore::open(&database, &database_key).expect("second reopen");
        let attachment = reopened
            .load_device_attachment_by_idempotency(&project.id, &prepared.idempotency_key_digest)
            .expect("applied attachment");
        assert_eq!(attachment.status, DeviceAttachmentStatus::Applied);
        let keyring = reopened
            .load_project_keyring(&project.id)
            .expect("applied keyring");
        assert_eq!(keyring.revision, 2);
        assert!(
            keyring
                .active_envelope_for(&device_two, now() + Duration::minutes(2))
                .is_ok()
        );
    }

    #[test]
    fn migration_v35_backs_up_v34_and_installs_local_key_reference_registry_idempotently() {
        let directory = tempfile::tempdir().expect("directory");
        let database_path = directory.path().join("key-reference-migration.sqlite3");
        let key = DatabaseKey::new([68; 32]).expect("database key");
        {
            let store = ProjectStore::open(&database_path, &key).expect("current store");
            crate::downgrade_identity_bootstrap_schema_for_test(&store.connection);
            store
                .connection
                .execute_batch(
                    "DROP TABLE project_key_secret_references;
                     DROP TABLE IF EXISTS runtime_turn_private_messages;
                     DROP TABLE IF EXISTS mission_conversation_messages;
                     DROP TABLE IF EXISTS mission_conversations;
                     DROP TABLE IF EXISTS mission_checkpoints;
                     DROP TABLE IF EXISTS mission_definition_oracles;
                     DROP TABLE IF EXISTS mission_definition_artifacts;
                     DROP TABLE IF EXISTS mission_definition_capabilities;
                     DROP TABLE IF EXISTS mission_definitions;
                     DELETE FROM schema_migrations WHERE version >= 35;",
                )
                .expect("construct v34");
        }
        {
            let store = ProjectStore::open(&database_path, &key).expect("migrate v34");
            assert_eq!(
                super::super::current_schema_version(&store.connection).expect("version"),
                crate::STORAGE_SCHEMA_VERSION
            );
            assert_eq!(
                store
                    .connection
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_master
                         WHERE type = 'table' AND name = 'project_key_secret_references'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .expect("table count"),
                1
            );
        }
        let backup_count = std::fs::read_dir(directory.path())
            .expect("list migration directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v34")
            })
            .count();
        assert_eq!(backup_count, 1);
        drop(ProjectStore::open(&database_path, &key).expect("idempotent reopen"));
        let reopened_backup_count = std::fs::read_dir(directory.path())
            .expect("list directory after reopen")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v34")
            })
            .count();
        assert_eq!(reopened_backup_count, 1);
    }
}
