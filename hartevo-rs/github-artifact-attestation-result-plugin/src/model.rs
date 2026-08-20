//! Typed scope, redacted attestation metadata, and lifecycle primitives.
//!
//! This module intentionally has no credential, bundle, signature, certificate,
//! timestamp, predicate-body, or artifact-byte representation. Inputs that
//! would contain those values are hashed at the provider boundary.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_TEXT_BYTES: usize = 512;
pub const MAX_PREDICATE_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u32 = 100;
pub const MAX_PAGES: u32 = 8;
pub const MAX_ATTESTATIONS: usize = 256;
pub const MAX_RESPONSE_BYTES: u32 = 1_048_576;
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;
pub const MAX_TIMESTAMP_BYTES: usize = 64;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("subject digest must be sha256:<64 lowercase hexadecimal characters>")]
    InvalidSubjectDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("attestation scope is invalid")]
    InvalidScope,
    #[error("required read permissions are missing")]
    MissingPermission,
    #[error("a write permission is not allowed in the Layer-1 snapshot")]
    WritePermission,
    #[error("repository owner must match the organization scope")]
    RepositoryOrganizationMismatch,
    #[error("repository id must be non-zero")]
    InvalidRepositoryId,
    #[error("predicate type is invalid")]
    InvalidPredicate,
    #[error("timestamp metadata is invalid or too long")]
    InvalidTimestamp,
    #[error("attestation identity is invalid")]
    InvalidAttestation,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is not revoked")]
    NotRevoked,
    #[error("registration revision overflowed")]
    RevisionOverflow,
    #[error("metadata digest fence is invalid")]
    InvalidMetadataFence,
}

pub type Digest = String;

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    hex::encode(Sha256::digest(bytes))
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    sha256_digest(&serde_json::to_vec(value).expect("typed Layer-1 value serializes"))
}

#[must_use]
pub fn metadata_digest(value: impl AsRef<[u8]>) -> Digest {
    sha256_digest(value.as_ref())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':' | b'@')
        })
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), ModelError> {
    if valid_digest(value) {
        Ok(())
    } else {
        Err(ModelError::InvalidDigest { field })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Version {
    major: u16,
    minor: u16,
    patch: u16,
}

impl Version {
    #[must_use]
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

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

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn next(self) -> Result<Self, ModelError> {
        self.0
            .checked_add(1)
            .ok_or(ModelError::RevisionOverflow)
            .and_then(Self::new)
    }
}

macro_rules! string_type {
    ($name:ident, $field:literal, $maximum:expr) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if valid_identifier(&value, $maximum) {
                    Ok(Self(value))
                } else {
                    Err(ModelError::InvalidIdentifier { field: $field })
                }
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

string_type!(InstallationId, "installation id", MAX_IDENTIFIER_BYTES);
string_type!(GithubOrganization, "organization", MAX_IDENTIFIER_BYTES);
string_type!(GithubRepositoryName, "repository", MAX_IDENTIFIER_BYTES);
string_type!(MissionId, "mission id", MAX_IDENTIFIER_BYTES);
string_type!(ProjectId, "project id", MAX_IDENTIFIER_BYTES);
string_type!(WorkProductId, "work product id", MAX_IDENTIFIER_BYTES);
string_type!(RegistrationId, "registration id", MAX_IDENTIFIER_BYTES);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubAuthKind {
    App,
    OAuth,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubRepositoryVisibility {
    Public,
    Private,
    Internal,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryAccess {
    Accessible,
    Filtered,
    NotFound,
}

impl RepositoryAccess {
    #[must_use]
    pub const fn is_accessible(self) -> bool {
        matches!(self, Self::Accessible)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubRepository {
    pub owner: GithubOrganization,
    pub name: GithubRepositoryName,
    pub repository_id: Option<u64>,
    pub visibility: GithubRepositoryVisibility,
}

impl GithubRepository {
    pub fn new(
        owner: GithubOrganization,
        name: GithubRepositoryName,
        visibility: GithubRepositoryVisibility,
    ) -> Result<Self, ModelError> {
        Ok(Self {
            owner,
            name,
            repository_id: None,
            visibility,
        })
    }

    pub fn with_repository_id(mut self, repository_id: u64) -> Result<Self, ModelError> {
        if repository_id == 0 {
            return Err(ModelError::InvalidRepositoryId);
        }
        self.repository_id = Some(repository_id);
        Ok(self)
    }

    #[must_use]
    pub fn full_name(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SubjectDigest(String);

impl SubjectDigest {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        let Some(hex_digest) = value.strip_prefix("sha256:") else {
            return Err(ModelError::InvalidSubjectDigest);
        };
        if hex_digest.len() != 64
            || !hex_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ModelError::InvalidSubjectDigest);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        metadata_digest(self.0.as_bytes())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PredicateType(String);

impl PredicateType {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if !valid_identifier(&value, MAX_PREDICATE_BYTES) || value.chars().any(char::is_whitespace)
        {
            Err(ModelError::InvalidPredicate)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        metadata_digest(self.0.as_bytes())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScopeBinding {
    pub project_id: ProjectId,
    pub project_revision: Revision,
    pub mission_id: MissionId,
    pub mission_revision: Revision,
    pub work_product_id: WorkProductId,
    pub work_product_revision: Revision,
}

impl MissionScopeBinding {
    pub fn new(
        project_id: ProjectId,
        project_revision: Revision,
        mission_id: MissionId,
        mission_revision: Revision,
        work_product_id: WorkProductId,
        work_product_revision: Revision,
    ) -> Result<Self, ModelError> {
        let value = Self {
            project_id,
            project_revision,
            mission_id,
            mission_revision,
            work_product_id,
            work_product_revision,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.project_revision.get() == 0
            || self.mission_revision.get() == 0
            || self.work_product_revision.get() == 0
        {
            Err(ModelError::InvalidScope)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubAttestationPermission {
    AttestationsRead,
    MetadataRead,
}

impl GithubAttestationPermission {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AttestationsRead => "attestations:read",
            Self::MetadataRead => "metadata:read",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    pub permissions: BTreeSet<GithubAttestationPermission>,
    pub permission_digest: Digest,
}

impl PermissionSnapshot {
    pub fn new(
        permissions: impl IntoIterator<Item = GithubAttestationPermission>,
    ) -> Result<Self, ModelError> {
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        if !permissions.contains(&GithubAttestationPermission::AttestationsRead)
            || !permissions.contains(&GithubAttestationPermission::MetadataRead)
        {
            return Err(ModelError::MissingPermission);
        }
        let permission_digest = canonical_digest(
            &permissions
                .iter()
                .map(|permission| permission.as_str())
                .collect::<Vec<_>>(),
        );
        Ok(Self {
            permissions,
            permission_digest,
        })
    }

    #[must_use]
    pub fn least_privilege() -> Self {
        Self::new([
            GithubAttestationPermission::AttestationsRead,
            GithubAttestationPermission::MetadataRead,
        ])
        .expect("the required read permissions are valid")
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let rebuilt = Self::new(self.permissions.iter().copied())?;
        if rebuilt == *self {
            Ok(())
        } else {
            Err(ModelError::WritePermission)
        }
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.permission_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttestationMetadataDigestFence {
    pub signer_identity_digest: Digest,
    pub certificate_digest: Digest,
    pub signature_digest: Digest,
    pub timestamp_digest: Digest,
    pub predicate_metadata_digest: Digest,
    pub verification_metadata_digest: Digest,
}

impl AttestationMetadataDigestFence {
    pub fn new(
        signer_identity: impl AsRef<[u8]>,
        certificate: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
        timestamp: impl AsRef<[u8]>,
        predicate_metadata: impl AsRef<[u8]>,
        verification_metadata: impl AsRef<[u8]>,
    ) -> Result<Self, ModelError> {
        let timestamp = timestamp.as_ref();
        if timestamp.is_empty()
            || timestamp.len() > MAX_TIMESTAMP_BYTES
            || !timestamp.contains(&b'T')
            || !timestamp.ends_with(b"Z")
        {
            return Err(ModelError::InvalidTimestamp);
        }
        let value = Self {
            signer_identity_digest: metadata_digest(signer_identity),
            certificate_digest: metadata_digest(certificate),
            signature_digest: metadata_digest(signature),
            timestamp_digest: metadata_digest(timestamp),
            predicate_metadata_digest: metadata_digest(predicate_metadata),
            verification_metadata_digest: metadata_digest(verification_metadata),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn from_digests(
        signer_identity_digest: Digest,
        certificate_digest: Digest,
        signature_digest: Digest,
        timestamp_digest: Digest,
        predicate_metadata_digest: Digest,
        verification_metadata_digest: Digest,
    ) -> Result<Self, ModelError> {
        let value = Self {
            signer_identity_digest,
            certificate_digest,
            signature_digest,
            timestamp_digest,
            predicate_metadata_digest,
            verification_metadata_digest,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        for (field, digest) in [
            ("signer identity", &self.signer_identity_digest),
            ("certificate", &self.certificate_digest),
            ("signature", &self.signature_digest),
            ("timestamp", &self.timestamp_digest),
            ("predicate metadata", &self.predicate_metadata_digest),
            ("verification metadata", &self.verification_metadata_digest),
        ] {
            validate_digest(digest, field)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubArtifactAttestationScope {
    pub installation_id: InstallationId,
    pub organization: GithubOrganization,
    pub repository: GithubRepository,
    pub subject_digest: SubjectDigest,
    pub predicate_type: PredicateType,
    pub permissions: PermissionSnapshot,
    pub mission: MissionScopeBinding,
    pub evidence_policy_digest: Digest,
    pub metadata_fence: Option<AttestationMetadataDigestFence>,
    scope_digest: Digest,
}

impl GithubArtifactAttestationScope {
    pub fn new(
        installation_id: InstallationId,
        organization: GithubOrganization,
        repository: GithubRepository,
        subject_digest: SubjectDigest,
        predicate_type: PredicateType,
        permissions: PermissionSnapshot,
        mission: MissionScopeBinding,
    ) -> Result<Self, ModelError> {
        let mut value = Self {
            installation_id,
            organization,
            repository,
            subject_digest,
            predicate_type,
            permissions,
            mission,
            evidence_policy_digest: Self::evidence_policy_digest(),
            metadata_fence: None,
            scope_digest: metadata_digest(b"unsealed-github-artifact-attestation-scope"),
        };
        value.scope_digest = value.computed_digest();
        value.validate()?;
        Ok(value)
    }

    pub fn with_metadata_fence(
        mut self,
        metadata_fence: AttestationMetadataDigestFence,
    ) -> Result<Self, ModelError> {
        metadata_fence.validate()?;
        self.metadata_fence = Some(metadata_fence);
        self.scope_digest = self.computed_digest();
        self.validate()?;
        Ok(self)
    }

    #[must_use]
    pub fn evidence_policy_digest() -> Digest {
        metadata_digest(
            b"github-artifact-attestation-result/evidence-policy/v1|subject-digest|predicate-type|signer-digest|certificate-digest|signature-digest|timestamp-digest|predicate-metadata-digest|no-bundle|no-bytes|no-trust-root",
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.repository.owner != self.organization
            || self.evidence_policy_digest != Self::evidence_policy_digest()
            || self.scope_digest != self.computed_digest()
        {
            return Err(ModelError::InvalidScope);
        }
        self.permissions.validate()?;
        self.mission.validate()?;
        if let Some(fence) = &self.metadata_fence {
            fence.validate()?;
        }
        Ok(())
    }

    #[must_use]
    pub fn computed_digest(&self) -> Digest {
        canonical_digest(&(
            &self.installation_id,
            &self.organization,
            &self.repository,
            &self.subject_digest,
            &self.predicate_type,
            &self.permissions,
            &self.mission,
            &self.evidence_policy_digest,
            &self.metadata_fence,
        ))
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn installation_digest(&self) -> Digest {
        canonical_digest(&self.installation_id)
    }

    #[must_use]
    pub fn organization_digest(&self) -> Digest {
        canonical_digest(&self.organization)
    }

    #[must_use]
    pub fn repository_digest(&self) -> Digest {
        self.repository.digest()
    }

    #[must_use]
    pub fn subject_digest_fence(&self) -> Digest {
        self.subject_digest.digest()
    }

    #[must_use]
    pub fn predicate_digest(&self) -> Digest {
        self.predicate_type.digest()
    }

    #[must_use]
    pub fn mission_digest(&self) -> Digest {
        self.mission.digest()
    }
}

/// Opaque host-managed App/OAuth reference. The supplied reference identifier
/// is hashed and discarded; this type deliberately implements no serde traits.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    auth_kind: GithubAuthKind,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &GithubArtifactAttestationScope,
        credential_revision: u64,
        auth_kind: GithubAuthKind,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_identifier(&reference_id, MAX_IDENTIFIER_BYTES) {
            return Err(ModelError::InvalidIdentifier {
                field: "secret reference",
            });
        }
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.digest().clone();
        let reference_digest = canonical_digest(&(
            "github-artifact-attestation-secret-reference/v1",
            reference_id,
            &scope_digest,
            credential_revision,
            auth_kind,
        ));
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
            auth_kind,
            revoked: false,
        })
    }

    #[must_use]
    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    #[must_use]
    pub const fn auth_kind(&self) -> GithubAuthKind {
        self.auth_kind
    }

    #[must_use]
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

    pub fn validate_for_scope(
        &self,
        scope: &GithubArtifactAttestationScope,
    ) -> Result<(), ModelError> {
        if self.scope_digest == *scope.digest() && valid_digest(&self.reference_digest) {
            Ok(())
        } else {
            Err(ModelError::InvalidScope)
        }
    }
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
}

impl TransportProvenance {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }

    #[must_use]
    pub const fn connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn first_party(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Unmounted,
    Revoked,
}

impl RegistrationState {
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubAttestationRecord {
    pub attestation_digest: Digest,
    pub repository_id: u64,
    pub repository_visibility: GithubRepositoryVisibility,
    pub repository_access: RepositoryAccess,
    pub subject_digest: SubjectDigest,
    pub predicate_type: PredicateType,
    pub signer_identity_digest: Digest,
    pub certificate_digest: Digest,
    pub signature_digest: Digest,
    pub timestamp_digest: Digest,
    pub predicate_metadata_digest: Digest,
    pub verification_metadata_digest: Digest,
    pub metadata_digest: Digest,
}

impl GithubAttestationRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        opaque_attestation_reference: impl AsRef<[u8]>,
        repository_id: u64,
        repository_visibility: GithubRepositoryVisibility,
        repository_access: RepositoryAccess,
        subject_digest: SubjectDigest,
        predicate_type: PredicateType,
        metadata: AttestationMetadataDigestFence,
    ) -> Result<Self, ModelError> {
        if repository_id == 0 {
            return Err(ModelError::InvalidAttestation);
        }
        metadata.validate()?;
        let mut value = Self {
            attestation_digest: metadata_digest(opaque_attestation_reference),
            repository_id,
            repository_visibility,
            repository_access,
            subject_digest,
            predicate_type,
            signer_identity_digest: metadata.signer_identity_digest,
            certificate_digest: metadata.certificate_digest,
            signature_digest: metadata.signature_digest,
            timestamp_digest: metadata.timestamp_digest,
            predicate_metadata_digest: metadata.predicate_metadata_digest,
            verification_metadata_digest: metadata.verification_metadata_digest,
            metadata_digest: metadata_digest(b"unsealed-github-artifact-attestation-metadata"),
        };
        value.metadata_digest = value.computed_digest();
        value.validate_digest()?;
        Ok(value)
    }

    #[must_use]
    pub fn metadata(&self) -> AttestationMetadataDigestFence {
        AttestationMetadataDigestFence {
            signer_identity_digest: self.signer_identity_digest.clone(),
            certificate_digest: self.certificate_digest.clone(),
            signature_digest: self.signature_digest.clone(),
            timestamp_digest: self.timestamp_digest.clone(),
            predicate_metadata_digest: self.predicate_metadata_digest.clone(),
            verification_metadata_digest: self.verification_metadata_digest.clone(),
        }
    }

    #[must_use]
    pub fn computed_digest(&self) -> Digest {
        canonical_digest(&(
            &self.attestation_digest,
            self.repository_id,
            self.repository_visibility,
            self.repository_access,
            &self.subject_digest,
            &self.predicate_type,
            &self.signer_identity_digest,
            &self.certificate_digest,
            &self.signature_digest,
            &self.timestamp_digest,
            &self.predicate_metadata_digest,
            &self.verification_metadata_digest,
        ))
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        if self.repository_id == 0
            || validate_digest(&self.attestation_digest, "attestation").is_err()
            || self.metadata().validate().is_err()
            || self.metadata_digest != self.computed_digest()
        {
            Err(ModelError::InvalidAttestation)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpaquePageToken {
    token_digest: Digest,
}

impl OpaquePageToken {
    pub fn new(raw_token: impl AsRef<[u8]>) -> Result<Self, ModelError> {
        let raw_token = raw_token.as_ref();
        if raw_token.is_empty() || raw_token.len() > MAX_TEXT_BYTES {
            return Err(ModelError::InvalidText {
                field: "page token",
            });
        }
        Ok(Self {
            token_digest: metadata_digest(raw_token),
        })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.token_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubAttestationPage {
    pub page: u32,
    pub items: Vec<GithubAttestationRecord>,
    pub next_page_token: Option<OpaquePageToken>,
    pub repository_visibility: GithubRepositoryVisibility,
    pub repository_access: RepositoryAccess,
    pub response_bytes: u32,
    pub truncated: bool,
    pub response_digest: Digest,
}

impl GithubAttestationPage {
    pub fn new(
        page: u32,
        items: Vec<GithubAttestationRecord>,
        next_page_token: Option<OpaquePageToken>,
        repository_visibility: GithubRepositoryVisibility,
        repository_access: RepositoryAccess,
    ) -> Result<Self, ModelError> {
        if page == 0 || items.len() > MAX_ATTESTATIONS {
            return Err(ModelError::InvalidScope);
        }
        let mut value = Self {
            page,
            items,
            next_page_token,
            repository_visibility,
            repository_access,
            response_bytes: 0,
            truncated: false,
            response_digest: metadata_digest(b"unsealed-github-artifact-attestation-page"),
        };
        value.seal();
        Ok(value)
    }

    pub fn seal(&mut self) {
        let response_len = serde_json::to_vec(&(
            self.page,
            &self.items,
            &self.next_page_token,
            self.repository_visibility,
            self.repository_access,
            self.truncated,
        ))
        .map_or(usize::MAX, |bytes| bytes.len());
        self.response_bytes = u32::try_from(response_len).unwrap_or(u32::MAX);
        self.response_digest = self.computed_digest();
    }

    pub fn mark_truncated(&mut self) {
        self.truncated = true;
        self.seal();
    }

    #[must_use]
    pub fn computed_digest(&self) -> Digest {
        canonical_digest(&(
            self.page,
            &self.items,
            &self.next_page_token,
            self.repository_visibility,
            self.repository_access,
            self.response_bytes,
            self.truncated,
        ))
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        if self.page == 0
            || self.items.len() > MAX_ATTESTATIONS
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self
                .items
                .iter()
                .any(|item| item.validate_digest().is_err())
            || self.response_digest != self.computed_digest()
        {
            Err(ModelError::InvalidAttestation)
        } else {
            Ok(())
        }
    }
}
