use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    ActorId, DeviceAttachmentId, DeviceHandoffId, DeviceId, KeyEnvelopeId, MemberId, ProjectId,
    ReceiptId, TenantId, WorkerId,
};

const MAX_WORKER_KEY_TTL_SECONDS: i64 = 15 * 60;
const MAX_DEVICE_HANDOFF_TTL_SECONDS: i64 = 24 * 60 * 60;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectEncryptionMode {
    PersonalE2ee,
    TeamEnvelope,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "id")]
pub enum KeyRecipient {
    Device(DeviceId),
    Member(MemberId),
    Worker(WorkerId),
    Recovery(String),
}

impl KeyRecipient {
    pub fn stable_scope(&self) -> String {
        match self {
            Self::Device(id) => format!("device:{id}"),
            Self::Member(id) => format!("member:{id}"),
            Self::Worker(id) => format!("worker:{id}"),
            Self::Recovery(id) => format!("recovery:{id}"),
        }
    }

    fn is_worker(&self) -> bool {
        matches!(self, Self::Worker(_))
    }

    fn is_long_lived(&self) -> bool {
        !self.is_worker()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyWrapAlgorithm {
    Aes256GcmV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WrappedKeyCiphertext {
    pub algorithm: KeyWrapAlgorithm,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub aad_digest: String,
}

impl WrappedKeyCiphertext {
    pub fn validate(&self) -> bool {
        self.nonce.len() == 12 && self.ciphertext.len() >= 16 && is_sha256(&self.aad_digest)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyEnvelope {
    pub id: KeyEnvelopeId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub key_version: u64,
    pub recipient: KeyRecipient,
    /// Opaque reference digest for an OS/Vault wrapping key. Never the key itself.
    pub wrapping_key_reference_digest: String,
    pub sealed_key: WrappedKeyCiphertext,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl KeyEnvelope {
    pub fn validate(&self) -> Result<(), KeyManagementError> {
        if self.id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.key_version == 0
            || !is_sha256(&self.wrapping_key_reference_digest)
            || !self.sealed_key.validate()
            || self
                .expires_at
                .is_some_and(|expires| expires <= self.created_at)
            || self
                .revoked_at
                .is_some_and(|revoked| revoked < self.created_at)
            || (self.recipient.is_worker() && self.expires_at.is_none())
        {
            return Err(KeyManagementError::InvalidEnvelope);
        }
        Ok(())
    }

    pub fn is_available(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none()
            && self.created_at <= now
            && self.expires_at.is_none_or(|expires| expires > now)
    }

    pub fn canonical_digest(&self) -> Result<String, KeyManagementError> {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectKeyring {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mode: ProjectEncryptionMode,
    pub active_key_version: u64,
    pub remote_execution_opt_in: bool,
    pub rotation_required: bool,
    pub envelopes: Vec<KeyEnvelope>,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKeyAgreementAlgorithm {
    X25519HkdfSha256Aes256GcmV1,
}

/// Public, project-scoped device bootstrap material. The matching private key
/// is generated on the device and belongs in the operating-system credential
/// store; the Cell only receives this registration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePublicKeyRegistration {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub device_id: DeviceId,
    pub algorithm: DeviceKeyAgreementAlgorithm,
    pub public_key: Vec<u8>,
    pub public_key_digest: String,
    pub authorized_by: ActorId,
    pub authorization_evidence_digest: String,
    pub idempotency_key_digest: String,
    pub revision: u64,
    pub registered_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl DevicePublicKeyRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn register(
        tenant_id: TenantId,
        project_id: ProjectId,
        device_id: DeviceId,
        public_key: Vec<u8>,
        authorized_by: ActorId,
        authorization_evidence_digest: String,
        idempotency_key_digest: String,
        now: DateTime<Utc>,
    ) -> Result<Self, KeyManagementError> {
        let registration = Self {
            tenant_id,
            project_id,
            device_id,
            algorithm: DeviceKeyAgreementAlgorithm::X25519HkdfSha256Aes256GcmV1,
            public_key_digest: sha256_bytes(&public_key),
            public_key,
            authorized_by,
            authorization_evidence_digest,
            idempotency_key_digest,
            revision: 1,
            registered_at: now,
            updated_at: now,
            revoked_at: None,
        };
        registration.validate()?;
        Ok(registration)
    }

    pub fn rotate(
        &self,
        expected_revision: u64,
        public_key: Vec<u8>,
        authorized_by: ActorId,
        authorization_evidence_digest: String,
        idempotency_key_digest: String,
        now: DateTime<Utc>,
    ) -> Result<Self, KeyManagementError> {
        if self.revision != expected_revision
            || self.revoked_at.is_some()
            || now < self.updated_at
            || public_key == self.public_key
        {
            return Err(KeyManagementError::InvalidDevicePublicKeyTransition);
        }
        let mut next = self.clone();
        next.public_key_digest = sha256_bytes(&public_key);
        next.public_key = public_key;
        next.authorized_by = authorized_by;
        next.authorization_evidence_digest = authorization_evidence_digest;
        next.idempotency_key_digest = idempotency_key_digest;
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(KeyManagementError::RevisionOverflow)?;
        next.updated_at = now;
        next.validate()?;
        Ok(next)
    }

    pub fn revoke(
        &self,
        expected_revision: u64,
        authorized_by: ActorId,
        authorization_evidence_digest: String,
        idempotency_key_digest: String,
        now: DateTime<Utc>,
    ) -> Result<Self, KeyManagementError> {
        if self.revision != expected_revision || self.revoked_at.is_some() || now < self.updated_at
        {
            return Err(KeyManagementError::InvalidDevicePublicKeyTransition);
        }
        let mut next = self.clone();
        next.authorized_by = authorized_by;
        next.authorization_evidence_digest = authorization_evidence_digest;
        next.idempotency_key_digest = idempotency_key_digest;
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(KeyManagementError::RevisionOverflow)?;
        next.updated_at = now;
        next.revoked_at = Some(now);
        next.validate()?;
        Ok(next)
    }

    pub fn validate(&self) -> Result<(), KeyManagementError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.device_id.as_str().trim().is_empty()
            || self.public_key.len() != 32
            || self.public_key.iter().all(|byte| *byte == 0)
            || self.public_key_digest != sha256_bytes(&self.public_key)
            || self.authorized_by.as_str().trim().is_empty()
            || !is_sha256(&self.authorization_evidence_digest)
            || !is_sha256(&self.idempotency_key_digest)
            || self.revision == 0
            || self.registered_at > self.updated_at
            || self
                .revoked_at
                .is_some_and(|revoked| revoked != self.updated_at)
        {
            return Err(KeyManagementError::InvalidDevicePublicKeyRegistration);
        }
        Ok(())
    }

    pub fn follows(&self, previous: &Self) -> Result<bool, KeyManagementError> {
        self.validate()?;
        previous.validate()?;
        let same_scope = self.tenant_id == previous.tenant_id
            && self.project_id == previous.project_id
            && self.device_id == previous.device_id
            && self.algorithm == previous.algorithm
            && self.registered_at == previous.registered_at;
        let valid_change = if self.revoked_at.is_some() {
            self.public_key == previous.public_key && previous.revoked_at.is_none()
        } else {
            self.public_key != previous.public_key && previous.revoked_at.is_none()
        };
        Ok(same_scope
            && valid_change
            && self.revision == previous.revision.saturating_add(1)
            && self.updated_at >= previous.updated_at)
    }

    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        self.registered_at <= now && self.updated_at <= now && self.revoked_at.is_none()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceHandoffContext {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub grant_id: DeviceHandoffId,
    pub project_mode: ProjectEncryptionMode,
    pub source_recipient: KeyRecipient,
    pub source_envelope_digest: String,
    pub source_keyring_manifest_digest: String,
    pub target_device_id: DeviceId,
    pub target_public_key_digest: String,
    pub key_version: u64,
    pub expected_keyring_revision: u64,
    pub expires_at: DateTime<Utc>,
}

impl DeviceHandoffContext {
    pub fn validate(&self) -> Result<(), KeyManagementError> {
        let source_valid = matches!(
            (&self.project_mode, &self.source_recipient),
            (ProjectEncryptionMode::PersonalE2ee, KeyRecipient::Device(_))
                | (
                    ProjectEncryptionMode::TeamEnvelope,
                    KeyRecipient::Device(_) | KeyRecipient::Member(_),
                )
        );
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.grant_id.as_str().trim().is_empty()
            || self.target_device_id.as_str().trim().is_empty()
            || !source_valid
            || matches!(
                &self.source_recipient,
                KeyRecipient::Device(source) if source == &self.target_device_id
            )
            || !is_sha256(&self.source_envelope_digest)
            || !is_sha256(&self.source_keyring_manifest_digest)
            || !is_sha256(&self.target_public_key_digest)
            || self.key_version == 0
            || self.expected_keyring_revision == 0
        {
            return Err(KeyManagementError::InvalidDeviceHandoff);
        }
        Ok(())
    }

    pub fn canonical_digest(&self) -> Result<String, KeyManagementError> {
        self.validate()?;
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceHandoffCiphertext {
    pub algorithm: DeviceKeyAgreementAlgorithm,
    pub sender_ephemeral_public_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub aad_digest: String,
    pub content_digest: String,
}

impl DeviceHandoffCiphertext {
    pub fn validate(&self) -> bool {
        self.sender_ephemeral_public_key.len() == 32
            && !self
                .sender_ephemeral_public_key
                .iter()
                .all(|byte| *byte == 0)
            && self.nonce.len() == 12
            && self.ciphertext.len() == 48
            && is_sha256(&self.aad_digest)
            && self.content_digest == sha256_bytes(&self.ciphertext)
    }
}

/// A short-lived, exact-scope transport grant. It contains only a project key
/// encrypted to the target device public key; it is not a reusable project
/// envelope and cannot authorize key administration on its own.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceHandoffGrant {
    pub context: DeviceHandoffContext,
    pub ciphertext: DeviceHandoffCiphertext,
    pub authorized_by: ActorId,
    pub authorization_evidence_digest: String,
    pub idempotency_key_digest: String,
    pub intent_digest: String,
    pub created_at: DateTime<Utc>,
}

impl DeviceHandoffGrant {
    pub fn prepare(
        context: DeviceHandoffContext,
        ciphertext: DeviceHandoffCiphertext,
        authorized_by: ActorId,
        authorization_evidence_digest: String,
        idempotency_key_digest: String,
        created_at: DateTime<Utc>,
    ) -> Result<Self, KeyManagementError> {
        let intent_digest = context.canonical_digest()?;
        let grant = Self {
            context,
            ciphertext,
            authorized_by,
            authorization_evidence_digest,
            idempotency_key_digest,
            intent_digest,
            created_at,
        };
        grant.validate()?;
        Ok(grant)
    }

    pub fn validate(&self) -> Result<(), KeyManagementError> {
        self.context.validate()?;
        let max_expiry = self
            .created_at
            .checked_add_signed(Duration::seconds(MAX_DEVICE_HANDOFF_TTL_SECONDS))
            .ok_or(KeyManagementError::RevisionOverflow)?;
        if !self.ciphertext.validate()
            || self.ciphertext.algorithm != DeviceKeyAgreementAlgorithm::X25519HkdfSha256Aes256GcmV1
            || self.ciphertext.aad_digest != self.context.canonical_digest()?
            || self.intent_digest != self.ciphertext.aad_digest
            || self.authorized_by.as_str().trim().is_empty()
            || !is_sha256(&self.authorization_evidence_digest)
            || !is_sha256(&self.idempotency_key_digest)
            || self.context.expires_at <= self.created_at
            || self.context.expires_at > max_expiry
        {
            return Err(KeyManagementError::InvalidDeviceHandoff);
        }
        Ok(())
    }

    pub fn is_unexpired(&self, now: DateTime<Utc>) -> bool {
        self.created_at <= now && now < self.context.expires_at
    }

    pub fn request_digest(&self) -> Result<String, KeyManagementError> {
        self.validate()?;
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceHandoffRevocation {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub grant_id: DeviceHandoffId,
    pub revoked_by: ActorId,
    pub authorization_evidence_digest: String,
    pub idempotency_key_digest: String,
    pub revoked_at: DateTime<Utc>,
}

impl DeviceHandoffRevocation {
    pub fn validate_against(&self, grant: &DeviceHandoffGrant) -> Result<(), KeyManagementError> {
        grant.validate()?;
        if self.tenant_id != grant.context.tenant_id
            || self.project_id != grant.context.project_id
            || self.grant_id != grant.context.grant_id
            || self.revoked_by.as_str().trim().is_empty()
            || !is_sha256(&self.authorization_evidence_digest)
            || !is_sha256(&self.idempotency_key_digest)
            || self.revoked_at < grant.created_at
        {
            return Err(KeyManagementError::InvalidDeviceHandoffRevocation);
        }
        Ok(())
    }

    pub fn request_digest(&self) -> Result<String, KeyManagementError> {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceHandoffClaim {
    pub claim_id: ReceiptId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub grant_id: DeviceHandoffId,
    pub target_device_id: DeviceId,
    pub target_public_key_digest: String,
    pub idempotency_key_digest: String,
    pub claimed_at: DateTime<Utc>,
}

impl DeviceHandoffClaim {
    pub fn issue(
        grant: &DeviceHandoffGrant,
        claim_id: ReceiptId,
        idempotency_key_digest: String,
        claimed_at: DateTime<Utc>,
    ) -> Result<Self, KeyManagementError> {
        let claim = Self {
            claim_id,
            tenant_id: grant.context.tenant_id.clone(),
            project_id: grant.context.project_id.clone(),
            grant_id: grant.context.grant_id.clone(),
            target_device_id: grant.context.target_device_id.clone(),
            target_public_key_digest: grant.context.target_public_key_digest.clone(),
            idempotency_key_digest,
            claimed_at,
        };
        claim.validate_against(grant)?;
        Ok(claim)
    }

    pub fn validate_against(&self, grant: &DeviceHandoffGrant) -> Result<(), KeyManagementError> {
        grant.validate()?;
        if self.claim_id.as_str().trim().is_empty()
            || self.tenant_id != grant.context.tenant_id
            || self.project_id != grant.context.project_id
            || self.grant_id != grant.context.grant_id
            || self.target_device_id != grant.context.target_device_id
            || self.target_public_key_digest != grant.context.target_public_key_digest
            || !is_sha256(&self.idempotency_key_digest)
            || !grant.is_unexpired(self.claimed_at)
        {
            return Err(KeyManagementError::InvalidDeviceHandoffClaim);
        }
        Ok(())
    }

    pub fn request_digest(&self) -> Result<String, KeyManagementError> {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceHandoffConsumption {
    pub claim_id: ReceiptId,
    pub receipt_id: ReceiptId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub grant_id: DeviceHandoffId,
    pub target_device_id: DeviceId,
    pub target_public_key_digest: String,
    pub key_version: u64,
    pub attachment_id: DeviceAttachmentId,
    pub result_keyring_revision: u64,
    pub receipt_digest: String,
    pub consumed_at: DateTime<Utc>,
}

impl DeviceHandoffConsumption {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        grant: &DeviceHandoffGrant,
        claim: &DeviceHandoffClaim,
        receipt_id: ReceiptId,
        attachment_id: DeviceAttachmentId,
        result_keyring_revision: u64,
        receipt_digest: String,
        consumed_at: DateTime<Utc>,
    ) -> Result<Self, KeyManagementError> {
        let consumption = Self {
            claim_id: claim.claim_id.clone(),
            receipt_id,
            tenant_id: grant.context.tenant_id.clone(),
            project_id: grant.context.project_id.clone(),
            grant_id: grant.context.grant_id.clone(),
            target_device_id: grant.context.target_device_id.clone(),
            target_public_key_digest: grant.context.target_public_key_digest.clone(),
            key_version: grant.context.key_version,
            attachment_id,
            result_keyring_revision,
            receipt_digest,
            consumed_at,
        };
        consumption.validate_against(grant, claim)?;
        Ok(consumption)
    }

    pub fn validate_against(
        &self,
        grant: &DeviceHandoffGrant,
        claim: &DeviceHandoffClaim,
    ) -> Result<(), KeyManagementError> {
        grant.validate()?;
        claim.validate_against(grant)?;
        let finalize_deadline = claim
            .claimed_at
            .checked_add_signed(Duration::seconds(MAX_DEVICE_HANDOFF_TTL_SECONDS))
            .ok_or(KeyManagementError::RevisionOverflow)?;
        if self.claim_id != claim.claim_id
            || self.receipt_id.as_str().trim().is_empty()
            || self.tenant_id != grant.context.tenant_id
            || self.project_id != grant.context.project_id
            || self.grant_id != grant.context.grant_id
            || self.target_device_id != grant.context.target_device_id
            || self.target_public_key_digest != grant.context.target_public_key_digest
            || self.key_version != grant.context.key_version
            || self.attachment_id.as_str().trim().is_empty()
            || self.result_keyring_revision
                != grant
                    .context
                    .expected_keyring_revision
                    .checked_add(1)
                    .ok_or(KeyManagementError::RevisionOverflow)?
            || !is_sha256(&self.receipt_digest)
            || self.consumed_at < claim.claimed_at
            || self.consumed_at > finalize_deadline
        {
            return Err(KeyManagementError::InvalidDeviceHandoffConsumption);
        }
        Ok(())
    }

    pub fn request_digest(&self) -> Result<String, KeyManagementError> {
        canonical_digest(self)
    }
}

/// Server-readable bootstrap metadata for locating opaque key envelopes. It
/// deliberately excludes every project body, private device key, recovery
/// secret, token, cookie, and browser profile.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectKeyringBootstrap {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub keyring: ProjectKeyring,
    pub previous_keyring_revision: Option<u64>,
    pub manifest_digest: String,
    pub published_by: KeyRecipient,
    pub authorizing_envelope_digest: String,
    pub authorization_evidence_digest: String,
    pub idempotency_key_digest: String,
    pub published_at: DateTime<Utc>,
}

impl ProjectKeyringBootstrap {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        keyring: ProjectKeyring,
        previous_keyring_revision: Option<u64>,
        published_by: KeyRecipient,
        authorizing_envelope_digest: String,
        authorization_evidence_digest: String,
        idempotency_key_digest: String,
        published_at: DateTime<Utc>,
    ) -> Result<Self, KeyManagementError> {
        let bootstrap = Self {
            tenant_id: keyring.tenant_id.clone(),
            project_id: keyring.project_id.clone(),
            manifest_digest: keyring.canonical_digest()?,
            keyring,
            previous_keyring_revision,
            published_by,
            authorizing_envelope_digest,
            authorization_evidence_digest,
            idempotency_key_digest,
            published_at,
        };
        bootstrap.validate()?;
        Ok(bootstrap)
    }

    pub fn validate(&self) -> Result<(), KeyManagementError> {
        self.keyring.validate()?;
        let publisher_valid = matches!(
            (&self.keyring.mode, &self.published_by),
            (ProjectEncryptionMode::PersonalE2ee, KeyRecipient::Device(_))
                | (
                    ProjectEncryptionMode::TeamEnvelope,
                    KeyRecipient::Device(_) | KeyRecipient::Member(_),
                )
        );
        if self.tenant_id != self.keyring.tenant_id
            || self.project_id != self.keyring.project_id
            || !publisher_valid
            || self.manifest_digest != self.keyring.canonical_digest()?
            || !is_sha256(&self.authorizing_envelope_digest)
            || !is_sha256(&self.authorization_evidence_digest)
            || !is_sha256(&self.idempotency_key_digest)
            || self.published_at < self.keyring.updated_at
            || match self.previous_keyring_revision {
                None => self.keyring.revision != 1,
                Some(previous) => previous.checked_add(1) != Some(self.keyring.revision),
            }
        {
            return Err(KeyManagementError::InvalidProjectKeyringBootstrap);
        }
        if self.previous_keyring_revision.is_none() {
            let envelope = self
                .keyring
                .available_envelope_for_version(
                    &self.published_by,
                    self.keyring.active_key_version,
                    self.published_at,
                )
                .map_err(|_| KeyManagementError::InvalidProjectKeyringBootstrap)?;
            if envelope.canonical_digest()? != self.authorizing_envelope_digest {
                return Err(KeyManagementError::InvalidProjectKeyringBootstrap);
            }
        }
        Ok(())
    }

    pub fn request_digest(&self) -> Result<String, KeyManagementError> {
        self.validate()?;
        canonical_digest(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceAttachmentMethod {
    AuthorizedRecipient,
    PublicKeyHandoff,
    RecoveryKit,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceAttachmentStatus {
    Prepared,
    Applied,
    Conflict,
}

/// Ciphertext-only saga for binding a device wrapping key to an existing
/// project keyring. Recovery is a dedicated method and never grants a Recovery
/// recipient generic key-administration authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceAttachment {
    pub id: DeviceAttachmentId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub project_mode: ProjectEncryptionMode,
    pub method: DeviceAttachmentMethod,
    pub source_recipient: KeyRecipient,
    pub device_id: DeviceId,
    pub key_version: u64,
    pub expected_keyring_revision: u64,
    pub envelope: KeyEnvelope,
    pub authorized_by: ActorId,
    pub authorization_evidence_digest: String,
    pub idempotency_key_digest: String,
    pub intent_digest: String,
    pub status: DeviceAttachmentStatus,
    pub result_keyring_revision: Option<u64>,
    pub error_code: Option<String>,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl DeviceAttachment {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        id: DeviceAttachmentId,
        tenant_id: TenantId,
        project_id: ProjectId,
        project_mode: ProjectEncryptionMode,
        method: DeviceAttachmentMethod,
        source_recipient: KeyRecipient,
        device_id: DeviceId,
        key_version: u64,
        expected_keyring_revision: u64,
        envelope: KeyEnvelope,
        authorized_by: ActorId,
        authorization_evidence_digest: String,
        idempotency_key_digest: String,
        intent_digest: String,
        now: DateTime<Utc>,
    ) -> Result<Self, KeyManagementError> {
        let attachment = Self {
            id,
            tenant_id,
            project_id,
            project_mode,
            method,
            source_recipient,
            device_id,
            key_version,
            expected_keyring_revision,
            envelope,
            authorized_by,
            authorization_evidence_digest,
            idempotency_key_digest,
            intent_digest,
            status: DeviceAttachmentStatus::Prepared,
            result_keyring_revision: None,
            error_code: None,
            revision: 1,
            created_at: now,
            updated_at: now,
        };
        attachment.validate()?;
        Ok(attachment)
    }

    pub fn mark_applied(
        &self,
        expected_revision: u64,
        result_keyring_revision: u64,
        now: DateTime<Utc>,
    ) -> Result<Self, KeyManagementError> {
        if self.status != DeviceAttachmentStatus::Prepared
            || self.revision != expected_revision
            || result_keyring_revision
                != self
                    .expected_keyring_revision
                    .checked_add(1)
                    .ok_or(KeyManagementError::RevisionOverflow)?
            || now < self.updated_at
        {
            return Err(KeyManagementError::InvalidDeviceAttachmentTransition);
        }
        let mut next = self.clone();
        next.status = DeviceAttachmentStatus::Applied;
        next.result_keyring_revision = Some(result_keyring_revision);
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(KeyManagementError::RevisionOverflow)?;
        next.updated_at = now;
        next.validate()?;
        Ok(next)
    }

    pub fn mark_conflict(
        &self,
        expected_revision: u64,
        error_code: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<Self, KeyManagementError> {
        let error_code = error_code.into();
        if self.status != DeviceAttachmentStatus::Prepared
            || self.revision != expected_revision
            || error_code.trim().is_empty()
            || now < self.updated_at
        {
            return Err(KeyManagementError::InvalidDeviceAttachmentTransition);
        }
        let mut next = self.clone();
        next.status = DeviceAttachmentStatus::Conflict;
        next.error_code = Some(error_code);
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(KeyManagementError::RevisionOverflow)?;
        next.updated_at = now;
        next.validate()?;
        Ok(next)
    }

    pub fn follows(&self, previous: &Self) -> Result<bool, KeyManagementError> {
        self.validate()?;
        previous.validate()?;
        let mut expected = previous.clone();
        expected.status = self.status;
        expected.result_keyring_revision = self.result_keyring_revision;
        expected.error_code.clone_from(&self.error_code);
        expected.revision = self.revision;
        expected.updated_at = self.updated_at;
        Ok(expected == *self
            && previous.status == DeviceAttachmentStatus::Prepared
            && self.revision == previous.revision.saturating_add(1)
            && self.updated_at >= previous.updated_at)
    }

    pub fn validate(&self) -> Result<(), KeyManagementError> {
        self.envelope.validate()?;
        let method_valid = matches!(
            (&self.method, &self.source_recipient, &self.project_mode),
            (
                DeviceAttachmentMethod::AuthorizedRecipient
                    | DeviceAttachmentMethod::PublicKeyHandoff,
                KeyRecipient::Device(_) | KeyRecipient::Member(_),
                _,
            ) | (
                DeviceAttachmentMethod::RecoveryKit,
                KeyRecipient::Recovery(_),
                ProjectEncryptionMode::PersonalE2ee,
            )
        );
        let status_valid = match self.status {
            DeviceAttachmentStatus::Prepared => {
                self.revision == 1
                    && self.result_keyring_revision.is_none()
                    && self.error_code.is_none()
            }
            DeviceAttachmentStatus::Applied => {
                self.revision == 2
                    && self.result_keyring_revision == self.expected_keyring_revision.checked_add(1)
                    && self.error_code.is_none()
            }
            DeviceAttachmentStatus::Conflict => {
                self.revision == 2
                    && self.result_keyring_revision.is_none()
                    && self
                        .error_code
                        .as_ref()
                        .is_some_and(|code| !code.trim().is_empty())
            }
        };
        if self.id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.device_id.as_str().trim().is_empty()
            || self.key_version == 0
            || self.expected_keyring_revision == 0
            || !method_valid
            || matches!(
                &self.source_recipient,
                KeyRecipient::Device(source) if source == &self.device_id
            )
            || self.envelope.tenant_id != self.tenant_id
            || self.envelope.project_id != self.project_id
            || self.envelope.key_version != self.key_version
            || self.envelope.recipient != KeyRecipient::Device(self.device_id.clone())
            || self.envelope.expires_at.is_some()
            || self.envelope.revoked_at.is_some()
            || self.envelope.created_at != self.created_at
            || self.authorized_by.as_str().trim().is_empty()
            || !is_sha256(&self.authorization_evidence_digest)
            || !is_sha256(&self.idempotency_key_digest)
            || !is_sha256(&self.intent_digest)
            || !status_valid
            || self.created_at > self.updated_at
        {
            return Err(KeyManagementError::InvalidDeviceAttachment);
        }
        Ok(())
    }
}

impl ProjectKeyring {
    pub fn initialize(
        tenant_id: TenantId,
        project_id: ProjectId,
        mode: ProjectEncryptionMode,
        envelopes: Vec<KeyEnvelope>,
        now: DateTime<Utc>,
    ) -> Result<Self, KeyManagementError> {
        let keyring = Self {
            tenant_id,
            project_id,
            mode,
            active_key_version: 1,
            remote_execution_opt_in: false,
            rotation_required: false,
            envelopes,
            revision: 1,
            created_at: now,
            updated_at: now,
        };
        keyring.validate()?;
        Ok(keyring)
    }

    pub fn validate(&self) -> Result<(), KeyManagementError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.active_key_version == 0
            || self.revision == 0
            || self.created_at > self.updated_at
            || (self.mode == ProjectEncryptionMode::PersonalE2ee && self.remote_execution_opt_in)
        {
            return Err(KeyManagementError::InvalidKeyring);
        }
        let mut ids = BTreeSet::new();
        let mut recipient_versions = BTreeSet::new();
        for envelope in &self.envelopes {
            envelope.validate()?;
            if envelope.tenant_id != self.tenant_id
                || envelope.project_id != self.project_id
                || !ids.insert(envelope.id.clone())
                || !recipient_versions.insert((envelope.key_version, envelope.recipient.clone()))
                || (self.mode == ProjectEncryptionMode::PersonalE2ee
                    && matches!(
                        envelope.recipient,
                        KeyRecipient::Member(_) | KeyRecipient::Worker(_)
                    ))
            {
                return Err(KeyManagementError::EnvelopeScopeMismatch);
            }
        }
        if !self.rotation_required
            && !required_recipient_set_is_available(
                &self.mode,
                &self.envelopes,
                self.active_key_version,
                self.updated_at,
            )
        {
            return Err(KeyManagementError::NoActiveRecoveryPath);
        }
        Ok(())
    }

    pub fn canonical_digest(&self) -> Result<String, KeyManagementError> {
        self.validate()?;
        canonical_digest(self)
    }

    pub fn follows(&self, previous: &Self) -> Result<bool, KeyManagementError> {
        self.validate()?;
        previous.validate()?;
        if self.tenant_id != previous.tenant_id
            || self.project_id != previous.project_id
            || self.mode != previous.mode
            || self.created_at != previous.created_at
            || self.revision != previous.revision.saturating_add(1)
            || self.updated_at < previous.updated_at
            || self.active_key_version < previous.active_key_version
            || self.active_key_version > previous.active_key_version.saturating_add(1)
        {
            return Ok(false);
        }
        for old in &previous.envelopes {
            let Some(new) = self
                .envelopes
                .iter()
                .find(|candidate| candidate.id == old.id)
            else {
                return Ok(false);
            };
            let mut expected = old.clone();
            expected.revoked_at = new.revoked_at;
            if expected != *new
                || (old.revoked_at.is_some() && new.revoked_at != old.revoked_at)
                || (old.revoked_at.is_none()
                    && new
                        .revoked_at
                        .is_some_and(|revoked| revoked != self.updated_at))
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn add_envelope(
        &mut self,
        envelope: KeyEnvelope,
        now: DateTime<Utc>,
    ) -> Result<(), KeyManagementError> {
        envelope.validate()?;
        self.require_scope_and_active_version(&envelope)?;
        if self.rotation_required
            || self.envelopes.iter().any(|stored| {
                stored.id == envelope.id
                    || (stored.key_version == envelope.key_version
                        && stored.recipient == envelope.recipient)
            })
        {
            return Err(KeyManagementError::DuplicateOrRotationRequired);
        }
        self.validate_recipient_for_mode(&envelope.recipient)?;
        self.validate_worker_envelope(&envelope, now)?;
        let next_revision = self.next_revision()?;
        self.envelopes.push(envelope);
        self.revision = next_revision;
        self.updated_at = now;
        Ok(())
    }

    pub fn set_remote_execution_opt_in(
        &mut self,
        enabled: bool,
        now: DateTime<Utc>,
    ) -> Result<(), KeyManagementError> {
        if self.mode != ProjectEncryptionMode::TeamEnvelope {
            return Err(KeyManagementError::RemoteExecutionNotAllowed);
        }
        if self.remote_execution_opt_in == enabled {
            return Ok(());
        }
        let next_revision = self.next_revision()?;
        self.remote_execution_opt_in = enabled;
        if !enabled {
            for envelope in self
                .envelopes
                .iter_mut()
                .filter(|envelope| envelope.recipient.is_worker() && envelope.revoked_at.is_none())
            {
                envelope.revoked_at = Some(now);
            }
        }
        self.revision = next_revision;
        self.updated_at = now;
        Ok(())
    }

    pub fn revoke_recipient(
        &mut self,
        recipient: &KeyRecipient,
        now: DateTime<Utc>,
    ) -> Result<(), KeyManagementError> {
        let matching = self
            .envelopes
            .iter()
            .enumerate()
            .filter(|(_, envelope)| {
                &envelope.recipient == recipient && envelope.revoked_at.is_none()
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matching.is_empty() {
            return Err(KeyManagementError::RecipientNotFound);
        }
        let next_revision = self.next_revision()?;
        for index in matching {
            self.envelopes[index].revoked_at = Some(now);
        }
        if recipient.is_long_lived() {
            self.rotation_required = true;
        }
        self.revision = next_revision;
        self.updated_at = now;
        Ok(())
    }

    pub fn rotate(
        &mut self,
        new_envelopes: Vec<KeyEnvelope>,
        now: DateTime<Utc>,
    ) -> Result<u64, KeyManagementError> {
        let new_version = self
            .active_key_version
            .checked_add(1)
            .ok_or(KeyManagementError::RevisionOverflow)?;
        if new_envelopes.is_empty() {
            return Err(KeyManagementError::NoActiveRecoveryPath);
        }
        let mut recipients = BTreeSet::new();
        for envelope in &new_envelopes {
            envelope.validate()?;
            if envelope.tenant_id != self.tenant_id
                || envelope.project_id != self.project_id
                || envelope.key_version != new_version
                || !recipients.insert(envelope.recipient.clone())
                || envelope.recipient.is_worker()
            {
                return Err(KeyManagementError::EnvelopeScopeMismatch);
            }
            self.validate_recipient_for_mode(&envelope.recipient)?;
        }
        if !required_recipient_set_is_available(&self.mode, &new_envelopes, new_version, now) {
            return Err(KeyManagementError::NoActiveRecoveryPath);
        }
        let next_revision = self.next_revision()?;
        for envelope in self
            .envelopes
            .iter_mut()
            .filter(|envelope| envelope.recipient.is_worker() && envelope.revoked_at.is_none())
        {
            envelope.revoked_at = Some(now);
        }
        self.envelopes.extend(new_envelopes);
        self.active_key_version = new_version;
        self.rotation_required = false;
        self.revision = next_revision;
        self.updated_at = now;
        Ok(new_version)
    }

    pub fn revoke_and_rotate(
        &mut self,
        revoked_recipient: &KeyRecipient,
        new_envelopes: Vec<KeyEnvelope>,
        now: DateTime<Utc>,
    ) -> Result<u64, KeyManagementError> {
        if !revoked_recipient.is_long_lived() {
            return Err(KeyManagementError::RecipientNotAllowed);
        }
        let matching = self
            .envelopes
            .iter()
            .enumerate()
            .filter(|(_, envelope)| {
                &envelope.recipient == revoked_recipient && envelope.revoked_at.is_none()
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matching.is_empty() {
            return Err(KeyManagementError::RecipientNotFound);
        }
        let new_version = self
            .active_key_version
            .checked_add(1)
            .ok_or(KeyManagementError::RevisionOverflow)?;
        let mut recipients = BTreeSet::new();
        for envelope in &new_envelopes {
            envelope.validate()?;
            if envelope.tenant_id != self.tenant_id
                || envelope.project_id != self.project_id
                || envelope.key_version != new_version
                || envelope.recipient == *revoked_recipient
                || envelope.recipient.is_worker()
                || !recipients.insert(envelope.recipient.clone())
            {
                return Err(KeyManagementError::EnvelopeScopeMismatch);
            }
            self.validate_recipient_for_mode(&envelope.recipient)?;
        }
        if !required_recipient_set_is_available(&self.mode, &new_envelopes, new_version, now) {
            return Err(KeyManagementError::NoActiveRecoveryPath);
        }
        let next_revision = self.next_revision()?;
        for index in matching {
            self.envelopes[index].revoked_at = Some(now);
        }
        for envelope in self
            .envelopes
            .iter_mut()
            .filter(|envelope| envelope.recipient.is_worker() && envelope.revoked_at.is_none())
        {
            envelope.revoked_at = Some(now);
        }
        self.envelopes.extend(new_envelopes);
        self.active_key_version = new_version;
        self.rotation_required = false;
        self.revision = next_revision;
        self.updated_at = now;
        Ok(new_version)
    }

    pub fn active_envelope_for(
        &self,
        recipient: &KeyRecipient,
        now: DateTime<Utc>,
    ) -> Result<&KeyEnvelope, KeyManagementError> {
        if self.rotation_required {
            return Err(KeyManagementError::RotationRequired);
        }
        if recipient.is_worker() && !self.remote_execution_opt_in {
            return Err(KeyManagementError::RemoteExecutionNotAllowed);
        }
        self.envelopes
            .iter()
            .find(|envelope| {
                envelope.key_version == self.active_key_version
                    && &envelope.recipient == recipient
                    && envelope.is_available(now)
            })
            .ok_or(KeyManagementError::RecipientNotFound)
    }

    pub fn available_envelope_for_version(
        &self,
        recipient: &KeyRecipient,
        key_version: u64,
        now: DateTime<Utc>,
    ) -> Result<&KeyEnvelope, KeyManagementError> {
        if key_version == 0 {
            return Err(KeyManagementError::EnvelopeScopeMismatch);
        }
        if recipient.is_worker()
            && (key_version != self.active_key_version || !self.remote_execution_opt_in)
        {
            return Err(KeyManagementError::RemoteExecutionNotAllowed);
        }
        self.envelopes
            .iter()
            .find(|envelope| {
                envelope.key_version == key_version
                    && &envelope.recipient == recipient
                    && envelope.is_available(now)
            })
            .ok_or(KeyManagementError::RecipientNotFound)
    }

    fn require_scope_and_active_version(
        &self,
        envelope: &KeyEnvelope,
    ) -> Result<(), KeyManagementError> {
        if envelope.tenant_id != self.tenant_id
            || envelope.project_id != self.project_id
            || envelope.key_version != self.active_key_version
        {
            return Err(KeyManagementError::EnvelopeScopeMismatch);
        }
        Ok(())
    }

    fn validate_recipient_for_mode(
        &self,
        recipient: &KeyRecipient,
    ) -> Result<(), KeyManagementError> {
        if self.mode == ProjectEncryptionMode::PersonalE2ee
            && matches!(recipient, KeyRecipient::Member(_) | KeyRecipient::Worker(_))
        {
            return Err(KeyManagementError::RecipientNotAllowed);
        }
        Ok(())
    }

    fn validate_worker_envelope(
        &self,
        envelope: &KeyEnvelope,
        now: DateTime<Utc>,
    ) -> Result<(), KeyManagementError> {
        if !envelope.recipient.is_worker() {
            return Ok(());
        }
        let max_expiry = envelope
            .created_at
            .checked_add_signed(Duration::seconds(MAX_WORKER_KEY_TTL_SECONDS))
            .ok_or(KeyManagementError::RevisionOverflow)?;
        if self.mode != ProjectEncryptionMode::TeamEnvelope
            || !self.remote_execution_opt_in
            || envelope.created_at > now
            || envelope
                .expires_at
                .is_none_or(|expires| expires <= now || expires > max_expiry)
        {
            return Err(KeyManagementError::InvalidWorkerEnvelope);
        }
        Ok(())
    }

    fn next_revision(&self) -> Result<u64, KeyManagementError> {
        self.revision
            .checked_add(1)
            .ok_or(KeyManagementError::RevisionOverflow)
    }
}

fn required_recipient_set_is_available(
    mode: &ProjectEncryptionMode,
    envelopes: &[KeyEnvelope],
    key_version: u64,
    now: DateTime<Utc>,
) -> bool {
    let available = |predicate: fn(&KeyRecipient) -> bool| {
        envelopes.iter().any(|envelope| {
            envelope.key_version == key_version
                && envelope.is_available(now)
                && predicate(&envelope.recipient)
        })
    };
    match mode {
        ProjectEncryptionMode::PersonalE2ee => {
            available(|recipient| matches!(recipient, KeyRecipient::Device(_)))
                && available(|recipient| matches!(recipient, KeyRecipient::Recovery(_)))
        }
        ProjectEncryptionMode::TeamEnvelope => available(|recipient| {
            matches!(recipient, KeyRecipient::Device(_) | KeyRecipient::Member(_))
        }),
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum KeyManagementError {
    #[error("project keyring metadata is invalid")]
    InvalidKeyring,
    #[error("wrapped project key envelope is invalid")]
    InvalidEnvelope,
    #[error("wrapped project key envelope crosses tenant, project, version, or recipient scope")]
    EnvelopeScopeMismatch,
    #[error(
        "project keyring does not have the required active device/member/recovery envelope set"
    )]
    NoActiveRecoveryPath,
    #[error("recipient type is not allowed by the project encryption mode")]
    RecipientNotAllowed,
    #[error("remote execution was not explicitly enabled for this team project")]
    RemoteExecutionNotAllowed,
    #[error("worker envelope is not short-lived, current, or within remote execution scope")]
    InvalidWorkerEnvelope,
    #[error("key envelope is duplicated or key rotation must complete first")]
    DuplicateOrRotationRequired,
    #[error("key recipient has no available envelope")]
    RecipientNotFound,
    #[error("key rotation is required before unwrapping the active project key")]
    RotationRequired,
    #[error("key version or aggregate revision overflow")]
    RevisionOverflow,
    #[error("device attachment scope, method, ciphertext, authorization, or digest is invalid")]
    InvalidDeviceAttachment,
    #[error("device attachment cannot make the requested state or revision transition")]
    InvalidDeviceAttachmentTransition,
    #[error("device public-key registration is malformed or crosses project scope")]
    InvalidDevicePublicKeyRegistration,
    #[error("device public-key registration cannot make the requested revision transition")]
    InvalidDevicePublicKeyTransition,
    #[error("device handoff grant, scope, expiry, intent, or ciphertext is invalid")]
    InvalidDeviceHandoff,
    #[error("device handoff revocation does not match the exact grant scope")]
    InvalidDeviceHandoffRevocation,
    #[error("device handoff claim does not match an unexpired exact target grant")]
    InvalidDeviceHandoffClaim,
    #[error("device handoff consumption does not prove an exact in-window attachment")]
    InvalidDeviceHandoffConsumption,
    #[error("project keyring bootstrap metadata, authorization, or revision is invalid")]
    InvalidProjectKeyringBootstrap,
    #[error("key-management canonical serialization failed")]
    CanonicalSerialization,
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, KeyManagementError> {
    serde_json::to_vec(value)
        .map(|bytes| sha256_bytes(&bytes))
        .map_err(|_| KeyManagementError::CanonicalSerialization)
}

fn sha256_bytes(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use proptest::prelude::*;

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 10, 8, 0, 0)
            .single()
            .expect("valid time")
    }

    fn envelope(
        id: &str,
        version: u64,
        recipient: KeyRecipient,
        expires_at: Option<DateTime<Utc>>,
    ) -> KeyEnvelope {
        KeyEnvelope {
            id: KeyEnvelopeId::from(id),
            tenant_id: TenantId::from("tenant-1"),
            project_id: ProjectId::from("project-1"),
            key_version: version,
            recipient,
            wrapping_key_reference_digest: "a".repeat(64),
            sealed_key: WrappedKeyCiphertext {
                algorithm: KeyWrapAlgorithm::Aes256GcmV1,
                nonce: vec![7; 12],
                ciphertext: vec![8; 48],
                aad_digest: "b".repeat(64),
            },
            created_at: now(),
            expires_at,
            revoked_at: None,
        }
    }

    fn envelope_at(
        id: impl Into<String>,
        version: u64,
        recipient: KeyRecipient,
        created_at: DateTime<Utc>,
        expires_at: Option<DateTime<Utc>>,
    ) -> KeyEnvelope {
        KeyEnvelope {
            id: KeyEnvelopeId::from_stable(id),
            tenant_id: TenantId::from("tenant-1"),
            project_id: ProjectId::from("project-1"),
            key_version: version,
            recipient,
            wrapping_key_reference_digest: "a".repeat(64),
            sealed_key: WrappedKeyCiphertext {
                algorithm: KeyWrapAlgorithm::Aes256GcmV1,
                nonce: vec![7; 12],
                ciphertext: vec![8; 48],
                aad_digest: "b".repeat(64),
            },
            created_at,
            expires_at,
            revoked_at: None,
        }
    }

    #[derive(Clone, Debug)]
    enum KeyringAction {
        SetRemote(bool),
        AddWorker { slot: u8, ttl_minutes: u8 },
        AddMember(u8),
        RevokeMember(u8),
        Rotate,
        RevokeAndRotate(u8),
        AdvanceMinutes(u8),
    }

    fn keyring_action() -> impl Strategy<Value = KeyringAction> {
        prop_oneof![
            any::<bool>().prop_map(KeyringAction::SetRemote),
            (0_u8..5, 0_u8..21)
                .prop_map(|(slot, ttl_minutes)| KeyringAction::AddWorker { slot, ttl_minutes }),
            (0_u8..5).prop_map(KeyringAction::AddMember),
            (0_u8..5).prop_map(KeyringAction::RevokeMember),
            Just(KeyringAction::Rotate),
            (0_u8..5).prop_map(KeyringAction::RevokeAndRotate),
            (0_u8..31).prop_map(KeyringAction::AdvanceMinutes),
        ]
    }

    fn rotation_envelopes(
        keyring: &ProjectKeyring,
        excluded: Option<&KeyRecipient>,
        at: DateTime<Utc>,
        next_id: &mut u64,
    ) -> Vec<KeyEnvelope> {
        let new_version = keyring.active_key_version + 1;
        let mut recipients = keyring
            .envelopes
            .iter()
            .filter(|envelope| {
                envelope.key_version == keyring.active_key_version
                    && envelope.recipient.is_long_lived()
                    && envelope.is_available(at)
                    && excluded != Some(&envelope.recipient)
            })
            .map(|envelope| envelope.recipient.clone())
            .collect::<BTreeSet<_>>();
        if recipients.is_empty() {
            recipients.insert(KeyRecipient::Device(DeviceId::from("rescue-device")));
        }
        recipients
            .into_iter()
            .map(|recipient| {
                *next_id += 1;
                envelope_at(
                    format!("generated-envelope-{next_id}"),
                    new_version,
                    recipient,
                    at,
                    None,
                )
            })
            .collect()
    }

    #[test]
    fn personal_e2ee_never_allows_member_or_worker_envelopes() {
        let mut keyring = ProjectKeyring::initialize(
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            ProjectEncryptionMode::PersonalE2ee,
            vec![
                envelope(
                    "device-envelope",
                    1,
                    KeyRecipient::Device(DeviceId::from("device-1")),
                    None,
                ),
                envelope(
                    "recovery-envelope",
                    1,
                    KeyRecipient::Recovery("recovery-kit-1".into()),
                    None,
                ),
            ],
            now(),
        )
        .expect("personal keyring");
        assert_eq!(
            keyring.set_remote_execution_opt_in(true, now()),
            Err(KeyManagementError::RemoteExecutionNotAllowed)
        );
        assert_eq!(
            keyring.add_envelope(
                envelope(
                    "member-envelope",
                    1,
                    KeyRecipient::Member(MemberId::from("member-1")),
                    None,
                ),
                now(),
            ),
            Err(KeyManagementError::RecipientNotAllowed)
        );
    }

    #[test]
    fn personal_e2ee_requires_device_and_user_held_recovery_on_create_and_rotate() {
        let device = KeyRecipient::Device(DeviceId::from("device-1"));
        assert_eq!(
            ProjectKeyring::initialize(
                TenantId::from("tenant-1"),
                ProjectId::from("project-1"),
                ProjectEncryptionMode::PersonalE2ee,
                vec![envelope("device-v1", 1, device.clone(), None)],
                now(),
            ),
            Err(KeyManagementError::NoActiveRecoveryPath)
        );

        let recovery = KeyRecipient::Recovery("recovery-kit-1".into());
        let mut keyring = ProjectKeyring::initialize(
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            ProjectEncryptionMode::PersonalE2ee,
            vec![
                envelope("device-v1", 1, device.clone(), None),
                envelope("recovery-v1", 1, recovery.clone(), None),
            ],
            now(),
        )
        .expect("complete personal recipient set");
        keyring
            .revoke_recipient(&device, now() + Duration::minutes(1))
            .expect("revoke device");
        assert_eq!(
            keyring.rotate(
                vec![envelope("device-v2", 2, device.clone(), None)],
                now() + Duration::minutes(2),
            ),
            Err(KeyManagementError::NoActiveRecoveryPath)
        );
        keyring
            .rotate(
                vec![
                    envelope("device-v2", 2, device.clone(), None),
                    envelope("recovery-v2", 2, recovery, None),
                ],
                now() + Duration::minutes(2),
            )
            .expect("rotate complete personal recipient set");
        assert!(
            keyring
                .active_envelope_for(&device, now() + Duration::minutes(2))
                .is_ok()
        );
    }

    #[test]
    fn recovery_attachment_is_personal_only_and_applies_one_exact_keyring_revision() {
        let device = DeviceId::from("device-2");
        let recovery = KeyRecipient::Recovery("recovery-kit-1".into());
        let attachment = DeviceAttachment::prepare(
            DeviceAttachmentId::from("attachment-1"),
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            ProjectEncryptionMode::PersonalE2ee,
            DeviceAttachmentMethod::RecoveryKit,
            recovery.clone(),
            device.clone(),
            1,
            3,
            envelope("device-2-v1", 1, KeyRecipient::Device(device), None),
            ActorId::from("user-1"),
            "c".repeat(64),
            "d".repeat(64),
            "e".repeat(64),
            now(),
        )
        .expect("prepared recovery attachment");
        let applied = attachment
            .mark_applied(1, 4, now() + Duration::minutes(1))
            .expect("one exact applied revision");
        assert_eq!(applied.status, DeviceAttachmentStatus::Applied);
        assert_eq!(applied.result_keyring_revision, Some(4));
        assert_eq!(
            attachment.mark_applied(1, 5, now() + Duration::minutes(1)),
            Err(KeyManagementError::InvalidDeviceAttachmentTransition)
        );

        assert_eq!(
            DeviceAttachment::prepare(
                DeviceAttachmentId::from("attachment-team-recovery"),
                TenantId::from("tenant-1"),
                ProjectId::from("project-1"),
                ProjectEncryptionMode::TeamEnvelope,
                DeviceAttachmentMethod::RecoveryKit,
                recovery,
                DeviceId::from("device-3"),
                1,
                3,
                envelope(
                    "device-3-v1",
                    1,
                    KeyRecipient::Device(DeviceId::from("device-3")),
                    None,
                ),
                ActorId::from("user-1"),
                "c".repeat(64),
                "d".repeat(64),
                "e".repeat(64),
                now(),
            ),
            Err(KeyManagementError::InvalidDeviceAttachment)
        );
    }

    #[test]
    fn device_public_key_registration_is_scoped_rotatable_and_permanently_revocable() {
        let registration = DevicePublicKeyRegistration::register(
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            DeviceId::from("device-new"),
            vec![7; 32],
            ActorId::from("user-1"),
            "a".repeat(64),
            "b".repeat(64),
            now(),
        )
        .expect("registered public key");
        let rotated = registration
            .rotate(
                1,
                vec![8; 32],
                ActorId::from("user-1"),
                "c".repeat(64),
                "d".repeat(64),
                now() + Duration::minutes(1),
            )
            .expect("rotated public key");
        assert!(rotated.follows(&registration).expect("valid lineage"));
        let revoked = rotated
            .revoke(
                2,
                ActorId::from("user-1"),
                "e".repeat(64),
                "f".repeat(64),
                now() + Duration::minutes(2),
            )
            .expect("revoked public key");
        assert!(revoked.follows(&rotated).expect("revocation lineage"));
        assert!(!revoked.is_active(now() + Duration::minutes(3)));
        assert_eq!(
            revoked.rotate(
                3,
                vec![9; 32],
                ActorId::from("user-1"),
                "1".repeat(64),
                "2".repeat(64),
                now() + Duration::minutes(3),
            ),
            Err(KeyManagementError::InvalidDevicePublicKeyTransition)
        );
    }

    #[test]
    fn handoff_grant_and_consumption_bind_exact_keyring_revision_and_expiry() {
        let source = KeyRecipient::Device(DeviceId::from("device-source"));
        let source_envelope = envelope("source-envelope", 1, source.clone(), None);
        let context = DeviceHandoffContext {
            tenant_id: TenantId::from("tenant-1"),
            project_id: ProjectId::from("project-1"),
            grant_id: DeviceHandoffId::from("grant-1"),
            project_mode: ProjectEncryptionMode::PersonalE2ee,
            source_recipient: source,
            source_envelope_digest: source_envelope
                .canonical_digest()
                .expect("source envelope digest"),
            source_keyring_manifest_digest: "6".repeat(64),
            target_device_id: DeviceId::from("device-target"),
            target_public_key_digest: "7".repeat(64),
            key_version: 1,
            expected_keyring_revision: 3,
            expires_at: now() + Duration::hours(1),
        };
        let aad_digest = context.canonical_digest().expect("handoff intent");
        let ciphertext_bytes = vec![8; 48];
        let grant = DeviceHandoffGrant::prepare(
            context,
            DeviceHandoffCiphertext {
                algorithm: DeviceKeyAgreementAlgorithm::X25519HkdfSha256Aes256GcmV1,
                sender_ephemeral_public_key: vec![9; 32],
                nonce: vec![4; 12],
                content_digest: sha256_bytes(&ciphertext_bytes),
                ciphertext: ciphertext_bytes,
                aad_digest,
            },
            ActorId::from("user-1"),
            "a".repeat(64),
            "b".repeat(64),
            now(),
        )
        .expect("exact handoff grant");
        let claim = DeviceHandoffClaim::issue(
            &grant,
            ReceiptId::from("handoff-claim-1"),
            "0".repeat(64),
            now() + Duration::minutes(4),
        )
        .expect("in-window claim");
        let consumption = DeviceHandoffConsumption::issue(
            &grant,
            &claim,
            ReceiptId::from("handoff-receipt-1"),
            DeviceAttachmentId::from("attachment-1"),
            4,
            "c".repeat(64),
            now() + Duration::minutes(5),
        )
        .expect("in-window exact consumption");
        assert_eq!(consumption.result_keyring_revision, 4);
        assert_eq!(
            DeviceHandoffConsumption::issue(
                &grant,
                &claim,
                ReceiptId::from("handoff-receipt-late"),
                DeviceAttachmentId::from("attachment-late"),
                4,
                "d".repeat(64),
                now() + Duration::hours(25),
            ),
            Err(KeyManagementError::InvalidDeviceHandoffConsumption)
        );
    }

    #[test]
    fn initial_keyring_bootstrap_is_ciphertext_only_and_authorized_by_exact_envelope() {
        let source = KeyRecipient::Device(DeviceId::from("device-1"));
        let source_envelope = envelope("device-envelope", 1, source.clone(), None);
        let keyring = ProjectKeyring::initialize(
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            ProjectEncryptionMode::PersonalE2ee,
            vec![
                source_envelope.clone(),
                envelope(
                    "recovery-envelope",
                    1,
                    KeyRecipient::Recovery("recovery-kit-1".into()),
                    None,
                ),
            ],
            now(),
        )
        .expect("personal keyring");
        let bootstrap = ProjectKeyringBootstrap::prepare(
            keyring,
            None,
            source,
            source_envelope
                .canonical_digest()
                .expect("authorizing envelope digest"),
            "a".repeat(64),
            "b".repeat(64),
            now(),
        )
        .expect("initial bootstrap");
        let serialized = serde_json::to_string(&bootstrap).expect("serialize bootstrap");
        assert!(!serialized.contains("project body"));
        assert!(!serialized.contains("privateKey"));
        assert_eq!(bootstrap.keyring.revision, 1);
    }

    #[test]
    fn worker_key_requires_team_opt_in_and_expires_within_fifteen_minutes() {
        let mut keyring = ProjectKeyring::initialize(
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            ProjectEncryptionMode::TeamEnvelope,
            vec![envelope(
                "member-envelope",
                1,
                KeyRecipient::Member(MemberId::from("member-1")),
                None,
            )],
            now(),
        )
        .expect("team keyring");
        let worker = KeyRecipient::Worker(WorkerId::from("worker-1"));
        assert_eq!(
            keyring.add_envelope(
                envelope(
                    "worker-envelope",
                    1,
                    worker.clone(),
                    Some(now() + Duration::minutes(10)),
                ),
                now(),
            ),
            Err(KeyManagementError::InvalidWorkerEnvelope)
        );
        keyring
            .set_remote_execution_opt_in(true, now())
            .expect("explicit opt in");
        keyring
            .add_envelope(
                envelope(
                    "worker-envelope",
                    1,
                    worker.clone(),
                    Some(now() + Duration::minutes(10)),
                ),
                now(),
            )
            .expect("short worker envelope");
        assert!(keyring.active_envelope_for(&worker, now()).is_ok());
        keyring
            .set_remote_execution_opt_in(false, now() + Duration::minutes(1))
            .expect("opt out");
        assert_eq!(
            keyring.active_envelope_for(&worker, now() + Duration::minutes(1)),
            Err(KeyManagementError::RemoteExecutionNotAllowed)
        );
    }

    #[test]
    fn member_revocation_blocks_unwrap_until_a_new_key_version_is_wrapped() {
        let member_one = KeyRecipient::Member(MemberId::from("member-1"));
        let member_two = KeyRecipient::Member(MemberId::from("member-2"));
        let mut keyring = ProjectKeyring::initialize(
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            ProjectEncryptionMode::TeamEnvelope,
            vec![envelope("member-1-v1", 1, member_one.clone(), None)],
            now(),
        )
        .expect("team keyring");
        keyring
            .revoke_recipient(&member_one, now() + Duration::minutes(1))
            .expect("revoke");
        assert_eq!(
            keyring.active_envelope_for(&member_one, now() + Duration::minutes(1)),
            Err(KeyManagementError::RotationRequired)
        );
        let version = keyring
            .rotate(
                vec![envelope("member-2-v2", 2, member_two.clone(), None)],
                now() + Duration::minutes(2),
            )
            .expect("rotate");
        assert_eq!(version, 2);
        assert!(
            keyring
                .active_envelope_for(&member_two, now() + Duration::minutes(2))
                .is_ok()
        );
        assert_eq!(
            keyring.active_envelope_for(&member_one, now() + Duration::minutes(2)),
            Err(KeyManagementError::RecipientNotFound)
        );
    }

    #[test]
    fn member_revocation_and_rotation_are_one_domain_revision() {
        let removed = KeyRecipient::Member(MemberId::from("member-1"));
        let retained = KeyRecipient::Member(MemberId::from("member-2"));
        let mut keyring = ProjectKeyring::initialize(
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            ProjectEncryptionMode::TeamEnvelope,
            vec![envelope("member-1-v1", 1, removed.clone(), None)],
            now(),
        )
        .expect("team keyring");

        let version = keyring
            .revoke_and_rotate(
                &removed,
                vec![envelope("member-2-v2", 2, retained.clone(), None)],
                now() + Duration::minutes(1),
            )
            .expect("atomic revoke and rotate");

        assert_eq!(version, 2);
        assert_eq!(keyring.revision, 2);
        assert!(!keyring.rotation_required);
        assert!(
            keyring
                .active_envelope_for(&retained, now() + Duration::minutes(1))
                .is_ok()
        );
        assert_eq!(
            keyring.active_envelope_for(&removed, now() + Duration::minutes(1)),
            Err(KeyManagementError::RecipientNotFound)
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        #[test]
        fn arbitrary_team_key_sequences_preserve_rotation_and_worker_boundaries(
            actions in prop::collection::vec(keyring_action(), 1..64),
        ) {
            let mut at = now();
            let mut next_id = 10_u64;
            let mut keyring = ProjectKeyring::initialize(
                TenantId::from("tenant-1"),
                ProjectId::from("project-1"),
                ProjectEncryptionMode::TeamEnvelope,
                vec![
                    envelope_at(
                        "device-v1",
                        1,
                        KeyRecipient::Device(DeviceId::from("device-0")),
                        at,
                        None,
                    ),
                    envelope_at(
                        "member-v1",
                        1,
                        KeyRecipient::Member(MemberId::from("member-0")),
                        at,
                        None,
                    ),
                ],
                at,
            )?;

            for action in actions {
                let before = keyring.clone();
                let result = match action {
                    KeyringAction::SetRemote(enabled) => {
                        keyring.set_remote_execution_opt_in(enabled, at)
                    }
                    KeyringAction::AddWorker { slot, ttl_minutes } => {
                        next_id += 1;
                        let worker = KeyRecipient::Worker(WorkerId::from_stable(format!(
                            "worker-{slot}"
                        )));
                        let worker_envelope = envelope_at(
                            format!("generated-envelope-{next_id}"),
                            keyring.active_key_version,
                            worker,
                            at,
                            Some(at + Duration::minutes(i64::from(ttl_minutes))),
                        );
                        keyring.add_envelope(worker_envelope, at)
                    }
                    KeyringAction::AddMember(slot) => {
                        next_id += 1;
                        let member_envelope = envelope_at(
                            format!("generated-envelope-{next_id}"),
                            keyring.active_key_version,
                            KeyRecipient::Member(MemberId::from_stable(format!("member-{slot}"))),
                            at,
                            None,
                        );
                        keyring.add_envelope(member_envelope, at)
                    }
                    KeyringAction::RevokeMember(slot) => keyring.revoke_recipient(
                        &KeyRecipient::Member(MemberId::from_stable(format!("member-{slot}"))),
                        at,
                    ),
                    KeyringAction::Rotate => {
                        let envelopes = rotation_envelopes(&keyring, None, at, &mut next_id);
                        keyring.rotate(envelopes, at).map(|_| ())
                    }
                    KeyringAction::RevokeAndRotate(slot) => {
                        let removed = KeyRecipient::Member(MemberId::from_stable(format!(
                            "member-{slot}"
                        )));
                        let envelopes =
                            rotation_envelopes(&keyring, Some(&removed), at, &mut next_id);
                        keyring
                            .revoke_and_rotate(&removed, envelopes, at)
                            .map(|_| ())
                    }
                    KeyringAction::AdvanceMinutes(minutes) => {
                        at += Duration::minutes(i64::from(minutes));
                        Ok(())
                    }
                };

                if result.is_err() {
                    prop_assert_eq!(&keyring, &before);
                }
                prop_assert!(keyring.validate().is_ok());
                prop_assert!(keyring.revision >= before.revision);
                prop_assert!(keyring.revision <= before.revision + 1);
                prop_assert!(keyring.active_key_version >= before.active_key_version);
                prop_assert!(keyring.active_key_version <= before.active_key_version + 1);

                for stored in &keyring.envelopes {
                    if stored.recipient.is_worker() {
                        let expires_at = stored.expires_at.expect("worker expiry");
                        prop_assert!(
                            expires_at - stored.created_at
                                <= Duration::seconds(MAX_WORKER_KEY_TTL_SECONDS)
                        );
                        if stored.is_available(at)
                            && stored.key_version == keyring.active_key_version
                        {
                            prop_assert!(keyring.remote_execution_opt_in);
                        }
                    }
                }
                if keyring.active_key_version > before.active_key_version {
                    let prior_workers_revoked = keyring
                        .envelopes
                        .iter()
                        .filter(|envelope| {
                            envelope.recipient.is_worker()
                                && envelope.key_version < keyring.active_key_version
                        })
                        .all(|envelope| envelope.revoked_at.is_some());
                    prop_assert!(prior_workers_revoked);
                }
                if !keyring.remote_execution_opt_in {
                    let all_workers_revoked = keyring
                        .envelopes
                        .iter()
                        .filter(|envelope| envelope.recipient.is_worker())
                        .all(|envelope| envelope.revoked_at.is_some());
                    prop_assert!(all_workers_revoked);
                }
            }
        }
    }
}
