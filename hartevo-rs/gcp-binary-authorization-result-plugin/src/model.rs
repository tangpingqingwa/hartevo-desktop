use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    GCP_BINARY_AUTHORIZATION_RESULT_CONTRACT_VERSION,
    GCP_BINARY_AUTHORIZATION_RESULT_SCHEMA_VERSION,
};

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 128;
pub(crate) const MAX_ATTESTORS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("image digest must be sha256:<64 lowercase hex characters>")]
    InvalidImageDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("scope is invalid")]
    InvalidScope,
    #[error("scope must contain at least one attestor")]
    EmptyAttestorSet,
    #[error("scope contains a duplicate or too many attestors")]
    InvalidAttestorSet,
    #[error("opaque secret reference is invalid")]
    InvalidSecretReference,
    #[error("policy summary is not bound to the requested scope")]
    InvalidPolicy,
    #[error("attestor summary is not bound to the requested scope")]
    InvalidAttestor,
    #[error("attestation occurrence is invalid")]
    InvalidOccurrence,
    #[error("evidence is invalid")]
    InvalidEvidence,
    #[error("digest does not match immutable contents")]
    DigestMismatch,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration or secret reference is revoked")]
    Revoked,
    #[error("platform is unsupported or malformed")]
    InvalidPlatform,
}

/// A lowercase SHA-256 digest. Raw provider payloads are intentionally never
/// represented by this Layer-1 model; evidence crosses the boundary as
/// digests and bounded typed summaries only.
#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if is_sha256(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field);
        }
        Self::from_bytes(&bytes)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn append_field(bytes: &mut Vec<u8>, field: &str) {
    bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
    bytes.extend_from_slice(field.as_bytes());
}

pub(crate) fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && !value.starts_with('.')
        && !value.ends_with('.')
}

macro_rules! string_identifier {
    ($name:ident) => {
        #[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if valid_identifier(&value) {
                    Ok(Self(value))
                } else {
                    Err(ModelError::InvalidIdentifier)
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&Digest::from_text(&self.0))
                    .finish()
            }
        }
    };
}

string_identifier!(ProjectId);
string_identifier!(PolicyId);
string_identifier!(AttestorId);
string_identifier!(MissionId);
string_identifier!(WorkProductId);
string_identifier!(ServiceId);
string_identifier!(ProviderId);
string_identifier!(ConsumerId);

/// Convenient domain names for the Project/Mission/Work Product boundary.
pub type Project = ProjectId;
pub type Mission = MissionId;
pub type WorkProduct = WorkProductId;
pub type ProjectScope = ProjectId;
pub type MissionScope = MissionId;
pub type WorkProductScope = WorkProductId;
pub type AuthKind = GcpAuthKind;
pub type GcpBinaryAuthorizationAuthKind = GcpAuthKind;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::InvalidRevision)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GcpAuthKind {
    OAuth,
    ServiceAccount,
}

/// A normalized image identity. It contains no image bytes and is bound to
/// every validation request and response.
#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ImageDigest(String);

impl ImageDigest {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        let Some(hex_digest) = value.strip_prefix("sha256:") else {
            return Err(ModelError::InvalidImageDigest);
        };
        if is_sha256(hex_digest) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidImageDigest)
        }
    }

    pub fn from_hex(value: impl Into<String>) -> Result<Self, ModelError> {
        Self::new(format!("sha256:{}", value.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-binary-authorization-image/v1",
            std::slice::from_ref(&self.0),
        )
    }
}

impl fmt::Debug for ImageDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ImageDigest")
            .field(&self.digest())
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Gke,
    CloudRun,
    Anthos,
    Other(String),
}

impl Platform {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_lowercase();
        match value.as_str() {
            "gke" => Ok(Self::Gke),
            "cloud_run" | "cloud-run" => Ok(Self::CloudRun),
            "anthos" => Ok(Self::Anthos),
            _ if valid_identifier(&value) => Ok(Self::Other(value)),
            _ => Err(ModelError::InvalidPlatform),
        }
    }

    pub const fn gke() -> Self {
        Self::Gke
    }

    pub const fn cloud_run() -> Self {
        Self::CloudRun
    }

    pub const fn anthos() -> Self {
        Self::Anthos
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Gke => "gke",
            Self::CloudRun => "cloud_run",
            Self::Anthos => "anthos",
            Self::Other(value) => value,
        }
    }
}

/// Opaque reference to a host-owned OAuth or service-account secret.
///
/// The reference identifier itself is never retained, serialized, or printed.
/// Layer 1 stores only a digest, scope binding, credential revision, and auth
/// kind. Credential resolution remains a Layer-2 host concern.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    auth_kind: GcpAuthKind,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            auth_kind: self.auth_kind,
            revoked: self.revoked,
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("auth_kind", &self.auth_kind)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.auth_kind == other.auth_kind
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl SecretReference {
    pub fn new(
        reference: impl Into<String>,
        scope: &GcpBinaryAuthorizationScope,
        credential_revision: Revision,
        auth_kind: GcpAuthKind,
    ) -> Result<Self, ModelError> {
        let reference = reference.into();
        if reference.trim().is_empty()
            || reference.chars().any(char::is_control)
            || reference.len() > MAX_IDENTIFIER_BYTES * 4
        {
            return Err(ModelError::InvalidSecretReference);
        }
        Ok(Self {
            reference_digest: Digest::from_fields(
                "gcp-binary-authorization-secret-reference/v1",
                &[
                    reference,
                    scope.scope_digest().as_str().to_owned(),
                    credential_revision.get().to_string(),
                    format!("{auth_kind:?}"),
                ],
            ),
            scope_digest: scope.scope_digest().clone(),
            credential_revision,
            auth_kind,
            revoked: false,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn auth_kind(&self) -> GcpAuthKind {
        self.auth_kind
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpBinaryAuthorizationScope {
    project_id: ProjectId,
    policy_id: PolicyId,
    attestor_ids: Vec<AttestorId>,
    image_digest: ImageDigest,
    platform: Platform,
    mission_id: MissionId,
    work_product_id: WorkProductId,
    work_product_revision: Revision,
    permission_digest: Digest,
    consent_digest: Digest,
    policy_digest: Digest,
    attestor_digest: Digest,
    scope_digest: Digest,
}

impl GcpBinaryAuthorizationScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: ProjectId,
        policy_id: PolicyId,
        attestor_ids: impl IntoIterator<Item = AttestorId>,
        image_digest: ImageDigest,
        platform: Platform,
        mission_id: MissionId,
        work_product_id: WorkProductId,
        work_product_revision: Revision,
        permission_digest: Digest,
        consent_digest: Digest,
    ) -> Result<Self, ModelError> {
        let mut attestor_ids = attestor_ids.into_iter().collect::<Vec<_>>();
        attestor_ids.sort();
        attestor_ids.dedup();
        if attestor_ids.is_empty() {
            return Err(ModelError::EmptyAttestorSet);
        }
        if attestor_ids.len() > MAX_ATTESTORS {
            return Err(ModelError::InvalidAttestorSet);
        }
        let policy_digest = Digest::from_fields(
            "gcp-binary-authorization-policy-scope/v1",
            &[
                project_id.as_str().to_owned(),
                policy_id.as_str().to_owned(),
            ],
        );
        let attestor_digest = Digest::from_fields(
            "gcp-binary-authorization-attestor-set/v1",
            &attestor_ids
                .iter()
                .map(|attestor| attestor.as_str().to_owned())
                .collect::<Vec<_>>(),
        );
        let scope_digest = Digest::from_fields(
            "gcp-binary-authorization-scope/v1",
            &[
                project_id.as_str().to_owned(),
                policy_id.as_str().to_owned(),
                attestor_digest.as_str().to_owned(),
                image_digest.as_str().to_owned(),
                platform.as_str().to_owned(),
                mission_id.as_str().to_owned(),
                work_product_id.as_str().to_owned(),
                work_product_revision.get().to_string(),
                permission_digest.as_str().to_owned(),
                consent_digest.as_str().to_owned(),
            ],
        );
        Ok(Self {
            project_id,
            policy_id,
            attestor_ids,
            image_digest,
            platform,
            mission_id,
            work_product_id,
            work_product_revision,
            permission_digest,
            consent_digest,
            policy_digest,
            attestor_digest,
            scope_digest,
        })
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn policy_id(&self) -> &PolicyId {
        &self.policy_id
    }

    pub fn attestor_ids(&self) -> &[AttestorId] {
        &self.attestor_ids
    }

    pub fn contains_attestor(&self, attestor_id: &AttestorId) -> bool {
        self.attestor_ids.binary_search(attestor_id).is_ok()
    }

    pub fn image_digest(&self) -> &ImageDigest {
        &self.image_digest
    }

    pub fn image_binding_digest(&self) -> Digest {
        self.image_digest.digest()
    }

    pub fn platform(&self) -> &Platform {
        &self.platform
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product_id
    }

    pub const fn work_product_revision(&self) -> Revision {
        self.work_product_revision
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub fn policy_digest(&self) -> &Digest {
        &self.policy_digest
    }

    pub fn attestor_digest(&self) -> &Digest {
        &self.attestor_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn provider_fence(&self, secret: &SecretReference) -> Result<ProviderFence, ModelError> {
        ProviderFence::new(self, secret)
    }
}

pub type BinaryAuthorizationScope = GcpBinaryAuthorizationScope;

/// The only authority fence a Layer-1 provider may carry. It proves that the
/// host supplied permission and consent digests, while explicitly asserting
/// that no external Effect is requested or authorized by this crate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentEffectFence {
    permission_digest: Digest,
    consent_digest: Digest,
    effect_policy_digest: Digest,
    effect_requested: bool,
    effect_receipt_digest: Option<Digest>,
}

impl ConsentEffectFence {
    pub fn read_only(scope: &GcpBinaryAuthorizationScope) -> Self {
        Self {
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            effect_policy_digest: Digest::from_fields(
                "gcp-binary-authorization-layer1-no-effect/v1",
                &[scope.scope_digest().as_str().to_owned()],
            ),
            effect_requested: false,
            effect_receipt_digest: None,
        }
    }

    pub fn validate_for(&self, scope: &GcpBinaryAuthorizationScope) -> Result<(), ModelError> {
        if self.permission_digest != *scope.permission_digest()
            || self.consent_digest != *scope.consent_digest()
            || self.effect_requested
            || self.effect_receipt_digest.is_some()
        {
            Err(ModelError::InvalidScope)
        } else {
            Ok(())
        }
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub fn effect_policy_digest(&self) -> &Digest {
        &self.effect_policy_digest
    }

    pub const fn effect_requested(&self) -> bool {
        self.effect_requested
    }

    pub fn effect_receipt_digest(&self) -> Option<&Digest> {
        self.effect_receipt_digest.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderFence {
    scope_digest: Digest,
    permission_digest: Digest,
    consent_digest: Digest,
    secret_reference_digest: Digest,
    credential_revision: Revision,
    auth_kind: GcpAuthKind,
    authority: ConsentEffectFence,
}

impl ProviderFence {
    pub fn new(
        scope: &GcpBinaryAuthorizationScope,
        secret: &SecretReference,
    ) -> Result<Self, ModelError> {
        if secret.scope_digest() != scope.scope_digest() || secret.is_revoked() {
            return Err(ModelError::Revoked);
        }
        Ok(Self {
            scope_digest: scope.scope_digest().clone(),
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            secret_reference_digest: secret.reference_digest().clone(),
            credential_revision: secret.credential_revision(),
            auth_kind: secret.auth_kind(),
            authority: ConsentEffectFence::read_only(scope),
        })
    }

    pub fn validate_for(
        &self,
        scope: &GcpBinaryAuthorizationScope,
        secret: &SecretReference,
    ) -> Result<(), ModelError> {
        if self.scope_digest != *scope.scope_digest()
            || self.permission_digest != *scope.permission_digest()
            || self.consent_digest != *scope.consent_digest()
            || self.secret_reference_digest != *secret.reference_digest()
            || self.credential_revision != secret.credential_revision()
            || self.auth_kind != secret.auth_kind()
            || secret.is_revoked()
        {
            return Err(ModelError::InvalidScope);
        }
        self.authority.validate_for(scope)
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        &self.secret_reference_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn auth_kind(&self) -> GcpAuthKind {
        self.auth_kind
    }

    pub fn authority(&self) -> &ConsentEffectFence {
        &self.authority
    }

    pub(crate) fn from_parts(
        scope_digest: Digest,
        permission_digest: Digest,
        consent_digest: Digest,
        secret_reference_digest: Digest,
        credential_revision: Revision,
        auth_kind: GcpAuthKind,
        authority: ConsentEffectFence,
    ) -> Self {
        Self {
            scope_digest,
            permission_digest,
            consent_digest,
            secret_reference_digest,
            credential_revision,
            auth_kind,
            authority,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDefaultAction {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicySummary {
    project_id: ProjectId,
    policy_id: PolicyId,
    platform: Platform,
    policy_version: Revision,
    allowed_attestors: Vec<AttestorId>,
    default_action: PolicyDefaultAction,
    policy_digest: Digest,
    policy_content_digest: Digest,
}

impl PolicySummary {
    pub fn new(
        scope: &GcpBinaryAuthorizationScope,
        policy_version: Revision,
        allowed_attestors: impl IntoIterator<Item = AttestorId>,
        default_action: PolicyDefaultAction,
    ) -> Result<Self, ModelError> {
        let mut allowed_attestors = allowed_attestors.into_iter().collect::<Vec<_>>();
        allowed_attestors.sort();
        allowed_attestors.dedup();
        if allowed_attestors.is_empty()
            || allowed_attestors.len() > MAX_ATTESTORS
            || allowed_attestors
                .iter()
                .any(|attestor| !scope.contains_attestor(attestor))
        {
            return Err(ModelError::InvalidPolicy);
        }
        let policy_digest = scope.policy_digest().clone();
        let policy_content_digest = Digest::from_fields(
            "gcp-binary-authorization-policy-content/v1",
            &[
                policy_digest.as_str().to_owned(),
                policy_version.get().to_string(),
                scope.platform().as_str().to_owned(),
                default_action.to_string(),
                Digest::from_fields(
                    "gcp-binary-authorization-policy-attestors/v1",
                    &allowed_attestors
                        .iter()
                        .map(|attestor| attestor.as_str().to_owned())
                        .collect::<Vec<_>>(),
                )
                .as_str()
                .to_owned(),
            ],
        );
        Ok(Self {
            project_id: scope.project_id().clone(),
            policy_id: scope.policy_id().clone(),
            platform: scope.platform().clone(),
            policy_version,
            allowed_attestors,
            default_action,
            policy_digest,
            policy_content_digest,
        })
    }

    pub fn validate_for(&self, scope: &GcpBinaryAuthorizationScope) -> Result<(), ModelError> {
        if self.project_id != *scope.project_id()
            || self.policy_id != *scope.policy_id()
            || self.platform != *scope.platform()
            || self.policy_digest != *scope.policy_digest()
            || self.allowed_attestors.is_empty()
            || self.allowed_attestors.len() > MAX_ATTESTORS
            || self
                .allowed_attestors
                .iter()
                .any(|attestor| !scope.contains_attestor(attestor))
        {
            return Err(ModelError::InvalidPolicy);
        }
        Ok(())
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn policy_id(&self) -> &PolicyId {
        &self.policy_id
    }

    pub fn platform(&self) -> &Platform {
        &self.platform
    }

    pub const fn policy_version(&self) -> Revision {
        self.policy_version
    }

    pub fn allowed_attestors(&self) -> &[AttestorId] {
        &self.allowed_attestors
    }

    pub const fn default_action(&self) -> PolicyDefaultAction {
        self.default_action
    }

    pub fn policy_digest(&self) -> &Digest {
        &self.policy_digest
    }

    pub fn policy_content_digest(&self) -> &Digest {
        &self.policy_content_digest
    }
}

impl fmt::Display for PolicyDefaultAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestorSummary {
    project_id: ProjectId,
    policy_id: PolicyId,
    attestor_id: AttestorId,
    platform: Platform,
    attestor_version: Revision,
    revoked: bool,
    public_key_digest: Option<Digest>,
    attestor_digest: Digest,
}

impl AttestorSummary {
    pub fn new(
        scope: &GcpBinaryAuthorizationScope,
        attestor_id: AttestorId,
        attestor_version: Revision,
        revoked: bool,
        public_key_digest: Option<Digest>,
    ) -> Result<Self, ModelError> {
        if !scope.contains_attestor(&attestor_id) {
            return Err(ModelError::InvalidAttestor);
        }
        let attestor_digest = Digest::from_fields(
            "gcp-binary-authorization-attestor-content/v1",
            &[
                scope.project_id().as_str().to_owned(),
                scope.policy_id().as_str().to_owned(),
                attestor_id.as_str().to_owned(),
                scope.platform().as_str().to_owned(),
                attestor_version.get().to_string(),
                revoked.to_string(),
                public_key_digest
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            project_id: scope.project_id().clone(),
            policy_id: scope.policy_id().clone(),
            attestor_id,
            platform: scope.platform().clone(),
            attestor_version,
            revoked,
            public_key_digest,
            attestor_digest,
        })
    }

    pub fn validate_for(&self, scope: &GcpBinaryAuthorizationScope) -> Result<(), ModelError> {
        if self.project_id != *scope.project_id()
            || self.policy_id != *scope.policy_id()
            || self.platform != *scope.platform()
            || !scope.contains_attestor(&self.attestor_id)
        {
            Err(ModelError::InvalidAttestor)
        } else {
            Ok(())
        }
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn policy_id(&self) -> &PolicyId {
        &self.policy_id
    }

    pub fn attestor_id(&self) -> &AttestorId {
        &self.attestor_id
    }

    pub fn platform(&self) -> &Platform {
        &self.platform
    }

    pub const fn attestor_version(&self) -> Revision {
        self.attestor_version
    }

    pub const fn revoked(&self) -> bool {
        self.revoked
    }

    pub fn public_key_digest(&self) -> Option<&Digest> {
        self.public_key_digest.as_ref()
    }

    pub fn attestor_digest(&self) -> &Digest {
        &self.attestor_digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationDecision {
    Allow,
    Deny,
    Error,
    Unknown,
}

pub type AttestationValidationDecision = ValidationDecision;
pub type ValidationStatus = ValidationDecision;

impl ValidationDecision {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Allow | Self::Deny)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationReason {
    PolicyAllow,
    PolicyDeny,
    AttestorRevoked,
    ImageDigestMismatch,
    OccurrenceRejected,
    ProviderError,
    ProviderUnknown,
    PartialEvidence,
    AccessLost,
    Replay,
    Tamper,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdversarialFinding {
    Replay,
    Tamper,
    Revocation,
    Partial,
    AccessLoss,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCompleteness {
    Complete,
    Partial,
    AccessLost,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    BlockedEnv,
    PermissionDenied,
    NotFound,
    InvalidResponse,
    ConsentEffectBypass,
    Timeout,
    Replay,
    Tampered,
    Revoked,
    Partial,
    AccessLost,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderErrorEvidence {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub diagnostic_digest: Digest,
}

impl ProviderErrorEvidence {
    pub fn new(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        retryable: bool,
        diagnostic: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            kind,
            status_code,
            retryable,
            diagnostic_digest: Digest::from_text(diagnostic),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub policy_digest: Digest,
    pub attestor_digest: Digest,
    pub image_digest: Digest,
    pub occurrence_digest: Digest,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    pub fn recompute(&self) -> Digest {
        Digest::from_fields(
            "gcp-binary-authorization-evidence-digests/v1",
            &[
                self.version_digest.as_str().to_owned(),
                self.contract_digest.as_str().to_owned(),
                self.provider_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.policy_digest.as_str().to_owned(),
                self.attestor_digest.as_str().to_owned(),
                self.image_digest.as_str().to_owned(),
                self.occurrence_digest.as_str().to_owned(),
                self.request_digest.as_str().to_owned(),
                self.response_digest.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpBinaryAuthorizationRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub policy_digest: Digest,
    pub attestor_digest: Digest,
    pub image_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub revision: Revision,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl GcpBinaryAuthorizationRegistration {
    pub fn new(
        scope: &GcpBinaryAuthorizationScope,
        secret: &SecretReference,
        provider_digest: Digest,
    ) -> Result<Self, ModelError> {
        if secret.scope_digest() != scope.scope_digest() || secret.is_revoked() {
            return Err(ModelError::Revoked);
        }
        let version_digest = Digest::from_text("gcp-binary-authorization-result-plugin/1.0.0");
        let contract_digest =
            Digest::from_text(crate::GCP_BINARY_AUTHORIZATION_RESULT_CONTRACT_JSON);
        let evidence_digest = Digest::from_fields(
            "gcp-binary-authorization-empty-evidence/v1",
            &[scope.scope_digest().as_str().to_owned()],
        );
        let mut registration = Self {
            plugin_version: "1.0.0".to_owned(),
            contract_version: GCP_BINARY_AUTHORIZATION_RESULT_CONTRACT_VERSION.to_owned(),
            version_digest,
            contract_digest,
            provider_digest,
            permission_digest: scope.permission_digest().clone(),
            scope_digest: scope.scope_digest().clone(),
            policy_digest: scope.policy_digest().clone(),
            attestor_digest: scope.attestor_digest().clone(),
            image_digest: scope.image_binding_digest(),
            evidence_digest,
            secret_reference_digest: secret.reference_digest().clone(),
            credential_revision: secret.credential_revision(),
            revision: Revision::new(1)?,
            state: RegistrationState::Active,
            registration_digest: Digest::from_text("0"),
        };
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-binary-authorization-registration/v1",
            &[
                self.plugin_version.clone(),
                self.contract_version.clone(),
                self.version_digest.as_str().to_owned(),
                self.contract_digest.as_str().to_owned(),
                self.provider_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.policy_digest.as_str().to_owned(),
                self.attestor_digest.as_str().to_owned(),
                self.image_digest.as_str().to_owned(),
                self.evidence_digest.as_str().to_owned(),
                self.secret_reference_digest.as_str().to_owned(),
                self.credential_revision.get().to_string(),
                self.revision.get().to_string(),
                format!("{:?}", self.state),
            ],
        )
    }

    pub fn validate_for(
        &self,
        scope: &GcpBinaryAuthorizationScope,
        secret: &SecretReference,
        provider_digest: &Digest,
    ) -> Result<(), ModelError> {
        if self.plugin_version != "1.0.0"
            || self.contract_version != GCP_BINARY_AUTHORIZATION_RESULT_CONTRACT_VERSION
            || self.version_digest
                != Digest::from_text("gcp-binary-authorization-result-plugin/1.0.0")
            || self.contract_digest
                != Digest::from_text(crate::GCP_BINARY_AUTHORIZATION_RESULT_CONTRACT_JSON)
            || self.provider_digest != *provider_digest
            || self.permission_digest != *scope.permission_digest()
            || self.scope_digest != *scope.scope_digest()
            || self.policy_digest != *scope.policy_digest()
            || self.attestor_digest != *scope.attestor_digest()
            || self.image_digest != scope.image_binding_digest()
            || self.secret_reference_digest != *secret.reference_digest()
            || self.credential_revision != secret.credential_revision()
            || self.registration_digest != self.compute_digest()
        {
            return Err(ModelError::InvalidRegistration);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.state == RegistrationState::Revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        self.state = RegistrationState::Revoked;
        self.revision = Revision::new(self.revision.get().saturating_add(1))?;
        self.registration_digest = self.compute_digest();
        Ok(())
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }
}

/// A digest-only representation of one proposed `validateAttestationOccurrence`
/// call. It contains no attestation payload or signature material.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationOccurrenceReference {
    occurrence_digest: Digest,
    image_digest: ImageDigest,
    attestor_id: AttestorId,
}

impl AttestationOccurrenceReference {
    pub fn new(
        occurrence_digest: Digest,
        image_digest: ImageDigest,
        attestor_id: AttestorId,
    ) -> Result<Self, ModelError> {
        if occurrence_digest.as_str().is_empty() {
            return Err(ModelError::InvalidOccurrence);
        }
        Ok(Self {
            occurrence_digest,
            image_digest,
            attestor_id,
        })
    }

    pub fn occurrence_digest(&self) -> &Digest {
        &self.occurrence_digest
    }

    pub fn image_digest(&self) -> &ImageDigest {
        &self.image_digest
    }

    pub fn attestor_id(&self) -> &AttestorId {
        &self.attestor_id
    }
}

/// Shared marker proving that the Layer-1 boundary has no native authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct Layer1EvidenceAuthority;

impl Layer1EvidenceAuthority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
        false
    }

    pub const fn consent() -> bool {
        false
    }

    pub const fn effect() -> bool {
        false
    }

    pub const fn durable_receipt() -> bool {
        false
    }

    pub const fn adopted_outcome() -> bool {
        false
    }
}

/// Compile-time aliases used by callers that prefer shorter domain names.
pub type PermissionDigest = Digest;
pub type ScopeDigest = Digest;
pub type PolicyDigest = Digest;
pub type AttestorDigest = Digest;
pub type EvidenceDigest = Digest;

#[allow(dead_code)]
fn _contract_constants_are_used() -> (&'static str, &'static str) {
    (
        GCP_BINARY_AUTHORIZATION_RESULT_SCHEMA_VERSION,
        GCP_BINARY_AUTHORIZATION_RESULT_CONTRACT_VERSION,
    )
}
