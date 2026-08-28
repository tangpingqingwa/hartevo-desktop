//! Bounded Vault governance values.
//!
//! The model intentionally contains normalized evidence only.  It has no
//! token string, secret value, raw policy name, raw lease id, HTTP body, or
//! native credential handle.  Opaque references are reduced to digests at the
//! boundary and are never serializable.

use std::{
    collections::BTreeSet,
    fmt,
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize, de::Error as DeError};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    MISSION_VAULT_GOVERNANCE_CONSUMER_ID, VAULT_GOVERNANCE_RESULT_CONTRACT_VERSION,
    VAULT_GOVERNANCE_RESULT_PROVIDER_ID, VAULT_GOVERNANCE_RESULT_PROVIDER_REVISION,
    VAULT_GOVERNANCE_RESULT_SCHEMA_VERSION, VAULT_GOVERNANCE_RESULT_SERVICE_ID,
};

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_PATH_BYTES: usize = 256;
pub const MAX_OPAQUE_REFERENCE_BYTES: usize = 512;
pub const MAX_ALLOWLISTED_PATHS: usize = 16;
pub const MAX_CAPABILITY_CLASSES_PER_PATH: usize = 8;
pub const MAX_POLICY_CLASSES: usize = 16;
pub const MAX_RECEIPTS: usize = 4;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} contains a path traversal or a forbidden root/system segment")]
    ForbiddenPath { field: &'static str },
    #[error("{field} exceeds the Layer-1 bound")]
    BoundExceeded { field: &'static str },
    #[error("{field} contains a duplicate value")]
    Duplicate { field: &'static str },
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("scope is invalid")]
    InvalidScope,
    #[error("secret reference is invalid")]
    InvalidSecretReference,
    #[error("lease reference is invalid")]
    InvalidLeaseReference,
    #[error("capability class is invalid for the bounded observation")]
    InvalidCapability,
    #[error("evidence digest does not match its immutable contents")]
    DigestMismatch,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("scope or revision drifted")]
    ScopeMismatch,
    #[error("response payload is invalid for the requested operation")]
    InvalidResponse,
    #[error("request must select at least one bounded observation")]
    EmptyRequest,
    #[error("evidence has no provider-issued origin seal")]
    OriginUnavailable,
    #[error("evidence provider origin or lifecycle binding drifted")]
    OriginMismatch,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(DeError::custom)
    }
}

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field);
        }
        Self::from_bytes(&bytes)
    }

    pub(crate) fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub(crate) fn is_zero(&self) -> bool {
        self.0.as_bytes().iter().all(|byte| *byte == b'0')
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

fn append_field(bytes: &mut Vec<u8>, field: &str) {
    bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
    bytes.extend_from_slice(field.as_bytes());
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), ModelError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || value.starts_with('.')
        || value.ends_with('.')
    {
        return Err(ModelError::InvalidText { field });
    }
    Ok(())
}

fn validate_hierarchical(value: &str, field: &'static str) -> Result<(), ModelError> {
    if value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || value.trim() != value
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains("//")
        || value.chars().any(char::is_control)
    {
        return Err(ModelError::InvalidText { field });
    }
    for segment in value.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(ModelError::ForbiddenPath { field });
        }
        if !segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'$'))
        {
            return Err(ModelError::InvalidText { field });
        }
    }
    Ok(())
}

fn validate_opaque(value: &str, field: &'static str) -> Result<(), ModelError> {
    if value.is_empty()
        || value.len() > MAX_OPAQUE_REFERENCE_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(ModelError::InvalidText { field })
    } else {
        Ok(())
    }
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(DeError::custom)
            }
        }

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }
    };
}

bounded_identifier!(ProjectId, "project id");
bounded_identifier!(MissionId, "mission id");

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl<'de> Deserialize<'de> for Revision {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(u64::deserialize(deserializer)?).map_err(DeError::custom)
    }
}

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

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct VaultNamespace(String);

impl<'de> Deserialize<'de> for VaultNamespace {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(DeError::custom)
    }
}

impl VaultNamespace {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_hierarchical(&value, "namespace")?;
        if value == "root" {
            return Err(ModelError::ForbiddenPath { field: "namespace" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for VaultNamespace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("VaultNamespace")
            .field(&self.0)
            .finish()
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct VaultMount(String);

impl<'de> Deserialize<'de> for VaultMount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(DeError::custom)
    }
}

impl VaultMount {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_hierarchical(&value, "mount")?;
        if value == "sys" || value == "auth" || value == "root" {
            return Err(ModelError::ForbiddenPath { field: "mount" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn mount_digest(&self) -> Digest {
        Digest::from_fields("vault-mount/v1", std::slice::from_ref(&self.0))
    }
}

impl fmt::Debug for VaultMount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("VaultMount").field(&self.0).finish()
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct VaultPath(String);

impl<'de> Deserialize<'de> for VaultPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(DeError::custom)
    }
}

impl VaultPath {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_hierarchical(&value, "path")?;
        let first_segment = value.split('/').next().unwrap_or_default();
        if matches!(first_segment, "sys" | "auth" | "root" | "cubbyhole")
            || value.contains("/root/")
        {
            return Err(ModelError::ForbiddenPath { field: "path" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn digest(&self) -> Digest {
        Digest::from_fields("vault-path/v1", std::slice::from_ref(&self.0))
    }

    pub fn path_digest(&self) -> Digest {
        self.digest()
    }
}

impl fmt::Debug for VaultPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("VaultPath").field(&self.0).finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultSecretRole {
    ObservationOnly,
}

impl VaultSecretRole {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ObservationOnly => "observation_only",
        }
    }
}

/// A scope fence for one exact Mission/Project revision pair.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultScope {
    namespace: VaultNamespace,
    mount: VaultMount,
    allowlisted_paths: Vec<VaultPath>,
    policy_digest: Digest,
    lease_scope_digest: Digest,
    mission_id: MissionId,
    mission_revision: Revision,
    project_id: ProjectId,
    project_revision: Revision,
    secret_reference_digest: Option<Digest>,
    credential_revision: Option<Revision>,
    secret_role: Option<VaultSecretRole>,
    valid_from_unix_seconds: Option<u64>,
    valid_until_unix_seconds: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VaultScopeWire {
    namespace: VaultNamespace,
    mount: VaultMount,
    allowlisted_paths: Vec<VaultPath>,
    policy_digest: Digest,
    lease_scope_digest: Digest,
    mission_id: MissionId,
    mission_revision: Revision,
    project_id: ProjectId,
    project_revision: Revision,
    secret_reference_digest: Option<Digest>,
    credential_revision: Option<Revision>,
    secret_role: Option<VaultSecretRole>,
    valid_from_unix_seconds: Option<u64>,
    valid_until_unix_seconds: Option<u64>,
}

impl<'de> Deserialize<'de> for VaultScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = VaultScopeWire::deserialize(deserializer)?;
        let scope = Self {
            namespace: wire.namespace,
            mount: wire.mount,
            allowlisted_paths: wire.allowlisted_paths,
            policy_digest: wire.policy_digest,
            lease_scope_digest: wire.lease_scope_digest,
            mission_id: wire.mission_id,
            mission_revision: wire.mission_revision,
            project_id: wire.project_id,
            project_revision: wire.project_revision,
            secret_reference_digest: wire.secret_reference_digest,
            credential_revision: wire.credential_revision,
            secret_role: wire.secret_role,
            valid_from_unix_seconds: wire.valid_from_unix_seconds,
            valid_until_unix_seconds: wire.valid_until_unix_seconds,
        };
        scope.validate_shape().map_err(DeError::custom)?;
        Ok(scope)
    }
}

impl VaultScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        namespace: impl Into<String>,
        mount: impl Into<String>,
        allowlisted_paths: impl IntoIterator<Item = VaultPath>,
        mission_id: impl Into<String>,
        mission_revision: u64,
        project_id: impl Into<String>,
        project_revision: u64,
    ) -> Result<Self, ModelError> {
        let paths = allowlisted_paths.into_iter().collect::<Vec<_>>();
        if paths.is_empty() || paths.len() > MAX_ALLOWLISTED_PATHS {
            return Err(ModelError::BoundExceeded {
                field: "allowlisted paths",
            });
        }
        let unique = paths.iter().collect::<BTreeSet<_>>();
        if unique.len() != paths.len() {
            return Err(ModelError::Duplicate {
                field: "allowlisted paths",
            });
        }
        let mission_id = MissionId::new(mission_id)?;
        let project_id = ProjectId::new(project_id)?;
        let mission_revision = Revision::new(mission_revision)?;
        let project_revision = Revision::new(project_revision)?;
        let policy_digest = Digest::from_fields(
            "vault-policy-scope/unbound/v1",
            &[
                mission_id.as_str().to_owned(),
                project_id.as_str().to_owned(),
            ],
        );
        let lease_scope_digest = Digest::from_text("vault-lease-scope/unbound/v1");
        Ok(Self {
            namespace: VaultNamespace::new(namespace)?,
            mount: VaultMount::new(mount)?,
            allowlisted_paths: paths,
            policy_digest,
            lease_scope_digest,
            mission_id,
            mission_revision,
            project_id,
            project_revision,
            secret_reference_digest: None,
            credential_revision: None,
            secret_role: None,
            valid_from_unix_seconds: None,
            valid_until_unix_seconds: None,
        })
    }

    fn validate_shape(&self) -> Result<(), ModelError> {
        if self.allowlisted_paths.is_empty() || self.allowlisted_paths.len() > MAX_ALLOWLISTED_PATHS
        {
            return Err(ModelError::BoundExceeded {
                field: "allowlisted paths",
            });
        }
        if self.allowlisted_paths.iter().collect::<BTreeSet<_>>().len()
            != self.allowlisted_paths.len()
        {
            return Err(ModelError::Duplicate {
                field: "allowlisted paths",
            });
        }
        let binding_fields = [
            self.secret_reference_digest.is_some(),
            self.credential_revision.is_some(),
            self.secret_role.is_some(),
            self.valid_from_unix_seconds.is_some(),
            self.valid_until_unix_seconds.is_some(),
        ];
        if binding_fields.iter().any(|present| *present)
            && binding_fields.iter().any(|present| !*present)
        {
            return Err(ModelError::InvalidScope);
        }
        if let (Some(valid_from), Some(valid_until)) =
            (self.valid_from_unix_seconds, self.valid_until_unix_seconds)
            && valid_until <= valid_from
        {
            return Err(ModelError::InvalidScope);
        }
        Ok(())
    }

    #[must_use]
    pub fn with_policy_digest(mut self, policy_digest: Digest) -> Self {
        self.policy_digest = policy_digest;
        self
    }

    #[must_use]
    pub fn with_lease_scope_digest(mut self, lease_scope_digest: Digest) -> Self {
        self.lease_scope_digest = lease_scope_digest;
        self
    }

    #[must_use]
    pub fn bind_lease(mut self, lease: &LeaseReference) -> Self {
        self.lease_scope_digest = lease.reference_digest().clone();
        self
    }

    pub fn bind_secret_reference(
        mut self,
        secret_reference: &SecretReference,
    ) -> Result<Self, ModelError> {
        if secret_reference.scope_identity_digest() != &self.identity_digest() {
            return Err(ModelError::ScopeMismatch);
        }
        if self.is_secret_bound() {
            return Err(ModelError::InvalidScope);
        }
        self.secret_reference_digest = Some(secret_reference.reference_digest().clone());
        self.credential_revision = Some(secret_reference.credential_revision());
        self.secret_role = Some(secret_reference.secret_role());
        self.valid_from_unix_seconds = Some(secret_reference.valid_from_unix_seconds());
        self.valid_until_unix_seconds = Some(secret_reference.valid_until_unix_seconds());
        self.validate_shape()?;
        Ok(self)
    }

    pub fn namespace(&self) -> &VaultNamespace {
        &self.namespace
    }

    pub fn mount(&self) -> &VaultMount {
        &self.mount
    }

    pub fn allowlisted_paths(&self) -> &[VaultPath] {
        &self.allowlisted_paths
    }

    pub fn policy_digest(&self) -> &Digest {
        &self.policy_digest
    }

    pub fn lease_scope_digest(&self) -> &Digest {
        &self.lease_scope_digest
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub const fn mission_revision(&self) -> Revision {
        self.mission_revision
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub const fn project_revision(&self) -> Revision {
        self.project_revision
    }

    pub fn secret_reference_digest(&self) -> Option<&Digest> {
        self.secret_reference_digest.as_ref()
    }

    pub const fn credential_revision(&self) -> Option<Revision> {
        self.credential_revision
    }

    pub const fn secret_role(&self) -> Option<VaultSecretRole> {
        self.secret_role
    }

    pub const fn valid_from_unix_seconds(&self) -> Option<u64> {
        self.valid_from_unix_seconds
    }

    pub const fn valid_until_unix_seconds(&self) -> Option<u64> {
        self.valid_until_unix_seconds
    }

    pub const fn is_secret_bound(&self) -> bool {
        self.secret_reference_digest.is_some()
    }

    pub fn contains_path(&self, path: &VaultPath) -> bool {
        self.allowlisted_paths.contains(path)
    }

    pub fn identity_digest(&self) -> Digest {
        let mut fields = vec![
            self.namespace.as_str().to_owned(),
            self.mount.as_str().to_owned(),
            self.policy_digest.as_str().to_owned(),
            self.lease_scope_digest.as_str().to_owned(),
            self.mission_id.as_str().to_owned(),
            self.mission_revision.get().to_string(),
            self.project_id.as_str().to_owned(),
            self.project_revision.get().to_string(),
        ];
        fields.extend(
            self.allowlisted_paths
                .iter()
                .map(|path| path.as_str().to_owned()),
        );
        Digest::from_fields("vault-governance-scope-identity/v1", &fields)
    }

    pub fn scope_digest(&self) -> Digest {
        let mut fields = vec![self.identity_digest().as_str().to_owned()];
        fields.push(
            self.secret_reference_digest
                .as_ref()
                .map_or_else(|| "unbound".to_owned(), |digest| digest.as_str().to_owned()),
        );
        fields.push(self.credential_revision.map_or_else(
            || "unbound".to_owned(),
            |revision| revision.get().to_string(),
        ));
        fields.push(
            self.secret_role
                .map_or_else(|| "unbound".to_owned(), |role| role.as_str().to_owned()),
        );
        fields.push(
            self.valid_from_unix_seconds
                .map_or_else(|| "unbound".to_owned(), |value| value.to_string()),
        );
        fields.push(
            self.valid_until_unix_seconds
                .map_or_else(|| "unbound".to_owned(), |value| value.to_string()),
        );
        Digest::from_fields("vault-governance-scope/v2", &fields)
    }
}

/// Opaque host authority reference.  The supplied reference id is hashed and
/// immediately dropped; this type intentionally does not implement Serialize.
pub struct SecretReference {
    reference_digest: Digest,
    scope_identity_digest: Digest,
    credential_revision: Revision,
    secret_role: VaultSecretRole,
    valid_from_unix_seconds: u64,
    valid_until_unix_seconds: u64,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_identity_digest: self.scope_identity_digest.clone(),
            credential_revision: self.credential_revision,
            secret_role: self.secret_role,
            valid_from_unix_seconds: self.valid_from_unix_seconds,
            valid_until_unix_seconds: self.valid_until_unix_seconds,
            revoked: self.revoked,
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_identity_digest", &self.scope_identity_digest)
            .field("credential_revision", &self.credential_revision)
            .field("secret_role", &self.secret_role)
            .field("valid_from_unix_seconds", &self.valid_from_unix_seconds)
            .field("valid_until_unix_seconds", &self.valid_until_unix_seconds)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_identity_digest == other.scope_identity_digest
            && self.credential_revision == other.credential_revision
            && self.secret_role == other.secret_role
            && self.valid_from_unix_seconds == other.valid_from_unix_seconds
            && self.valid_until_unix_seconds == other.valid_until_unix_seconds
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &VaultScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new_with_window(
            reference_id,
            scope,
            credential_revision,
            VaultSecretRole::ObservationOnly,
            0,
            u64::MAX,
        )
    }

    pub fn new_with_window(
        reference_id: impl Into<String>,
        scope: &VaultScope,
        credential_revision: u64,
        secret_role: VaultSecretRole,
        valid_from_unix_seconds: u64,
        valid_until_unix_seconds: u64,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        validate_opaque(&reference_id, "secret reference")?;
        let credential_revision = Revision::new(credential_revision)?;
        if valid_until_unix_seconds <= valid_from_unix_seconds {
            return Err(ModelError::InvalidSecretReference);
        }
        let scope_identity_digest = scope.identity_digest();
        let reference_digest = Digest::from_fields(
            "vault-secret-reference/v1",
            &[
                reference_id,
                scope_identity_digest.as_str().to_owned(),
                credential_revision.get().to_string(),
                secret_role.as_str().to_owned(),
                valid_from_unix_seconds.to_string(),
                valid_until_unix_seconds.to_string(),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_identity_digest,
            credential_revision,
            secret_role,
            valid_from_unix_seconds,
            valid_until_unix_seconds,
            revoked: false,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_identity_digest
    }

    pub fn scope_identity_digest(&self) -> &Digest {
        &self.scope_identity_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn secret_role(&self) -> VaultSecretRole {
        self.secret_role
    }

    pub const fn valid_from_unix_seconds(&self) -> u64 {
        self.valid_from_unix_seconds
    }

    pub const fn valid_until_unix_seconds(&self) -> u64 {
        self.valid_until_unix_seconds
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

/// A lease selector has the same opaque boundary as a SecretReference.  The
/// provider only receives its digest and can never retain a lease identifier.
pub struct LeaseReference {
    reference_digest: Digest,
}

impl Clone for LeaseReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
        }
    }
}

impl fmt::Debug for LeaseReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LeaseReference")
            .field("reference_digest", &self.reference_digest)
            .finish()
    }
}

impl PartialEq for LeaseReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
    }
}

impl Eq for LeaseReference {}

impl LeaseReference {
    pub fn new(lease_id: impl Into<String>) -> Result<Self, ModelError> {
        let lease_id = lease_id.into();
        validate_opaque(&lease_id, "lease reference")?;
        Ok(Self {
            reference_digest: Digest::from_fields("vault-lease-reference/v1", &[lease_id]),
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultOperation {
    SysHealth,
    AuthTokenLookupSelf,
    SysCapabilitiesSelfAllowlisted,
    SysLeasesLookupMetadata,
}

impl VaultOperation {
    pub const ALL: [Self; 4] = [
        Self::SysHealth,
        Self::AuthTokenLookupSelf,
        Self::SysCapabilitiesSelfAllowlisted,
        Self::SysLeasesLookupMetadata,
    ];

    pub const fn is_read_only(self) -> bool {
        true
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Active,
    Standby,
    PerformanceStandby,
    Sealed,
    Uninitialized,
    Removed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenStatus {
    Active,
    Expired,
    Revoked,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseStatus {
    Active,
    Expired,
    Revoked,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyClass {
    Default,
    ReadOnly,
    Metadata,
    TokenSelfLookup,
    LeaseMetadata,
    Unknown,
}

impl PolicyClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::ReadOnly => "read_only",
            Self::Metadata => "metadata",
            Self::TokenSelfLookup => "token_self_lookup",
            Self::LeaseMetadata => "lease_metadata",
            Self::Unknown => "unknown",
        }
    }

    const fn is_bounded(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityClass {
    Create,
    Read,
    Update,
    Delete,
    List,
    Patch,
    Sudo,
    Deny,
    Unknown,
}

impl CapabilityClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Read => "read",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::List => "list",
            Self::Patch => "patch",
            Self::Sudo => "sudo",
            Self::Deny => "deny",
            Self::Unknown => "unknown",
        }
    }

    pub const fn is_bounded(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

fn normalize_capabilities(
    mut capabilities: Vec<CapabilityClass>,
) -> Result<Vec<CapabilityClass>, ModelError> {
    if capabilities.is_empty() || capabilities.len() > MAX_CAPABILITY_CLASSES_PER_PATH {
        return Err(ModelError::BoundExceeded {
            field: "capability classes",
        });
    }
    if capabilities.iter().any(|class| !class.is_bounded()) {
        return Err(ModelError::InvalidCapability);
    }
    capabilities.sort_unstable();
    capabilities.dedup();
    Ok(capabilities)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultHealthMetadata {
    pub initialized: bool,
    pub sealed: bool,
    pub standby: bool,
    pub performance_standby: bool,
    pub removed_from_cluster: bool,
    pub cluster_id_digest: Digest,
    pub cluster_name_digest: Digest,
    pub version_digest: Digest,
}

impl Default for VaultHealthMetadata {
    fn default() -> Self {
        Self {
            initialized: true,
            sealed: false,
            standby: false,
            performance_standby: false,
            removed_from_cluster: false,
            cluster_id_digest: Digest::from_text("fixture-cluster-id"),
            cluster_name_digest: Digest::from_text("fixture-cluster-name"),
            version_digest: Digest::from_text("vault-fixture-version"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultTokenSelfMetadata {
    pub token_digest: Digest,
    pub accessor_digest: Digest,
    pub entity_id_digest: Option<Digest>,
    pub ttl_seconds: u64,
    pub renewable: bool,
    pub policy_classes: Vec<PolicyClass>,
    pub policy_digest: Digest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VaultTokenSelfMetadataWire {
    token_digest: Digest,
    accessor_digest: Digest,
    entity_id_digest: Option<Digest>,
    ttl_seconds: u64,
    renewable: bool,
    policy_classes: Vec<PolicyClass>,
    policy_digest: Digest,
}

impl<'de> Deserialize<'de> for VaultTokenSelfMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = VaultTokenSelfMetadataWire::deserialize(deserializer)?;
        let metadata = Self::new(
            wire.token_digest,
            wire.accessor_digest,
            wire.entity_id_digest,
            wire.ttl_seconds,
            wire.renewable,
            wire.policy_classes,
        )
        .map_err(DeError::custom)?;
        if metadata.policy_digest != wire.policy_digest {
            return Err(DeError::custom(ModelError::DigestMismatch));
        }
        Ok(metadata)
    }
}

impl VaultTokenSelfMetadata {
    pub fn new(
        token_digest: Digest,
        accessor_digest: Digest,
        entity_id_digest: Option<Digest>,
        ttl_seconds: u64,
        renewable: bool,
        mut policy_classes: Vec<PolicyClass>,
    ) -> Result<Self, ModelError> {
        if policy_classes.is_empty() || policy_classes.len() > MAX_POLICY_CLASSES {
            return Err(ModelError::BoundExceeded {
                field: "policy classes",
            });
        }
        if policy_classes.iter().any(|class| !class.is_bounded()) {
            return Err(ModelError::InvalidCapability);
        }
        policy_classes.sort_unstable();
        policy_classes.dedup();
        let policy_digest = Digest::from_fields(
            "vault-policy-classes/v1",
            &policy_classes
                .iter()
                .map(|class| class.as_str().to_owned())
                .collect::<Vec<_>>(),
        );
        Ok(Self {
            token_digest,
            accessor_digest,
            entity_id_digest,
            ttl_seconds,
            renewable,
            policy_classes,
            policy_digest,
        })
    }

    pub fn status(&self) -> TokenStatus {
        if self.ttl_seconds == 0 {
            TokenStatus::Expired
        } else {
            TokenStatus::Active
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultCapabilityMetadata {
    pub path_digest: Digest,
    pub capability_classes: Vec<CapabilityClass>,
    pub capability_digest: Digest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VaultCapabilityMetadataWire {
    path_digest: Digest,
    capability_classes: Vec<CapabilityClass>,
    capability_digest: Digest,
}

impl<'de> Deserialize<'de> for VaultCapabilityMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = VaultCapabilityMetadataWire::deserialize(deserializer)?;
        let metadata =
            Self::new(wire.path_digest, wire.capability_classes).map_err(DeError::custom)?;
        if metadata.capability_digest != wire.capability_digest {
            return Err(DeError::custom(ModelError::DigestMismatch));
        }
        Ok(metadata)
    }
}

impl VaultCapabilityMetadata {
    pub fn new(
        path_digest: Digest,
        capabilities: Vec<CapabilityClass>,
    ) -> Result<Self, ModelError> {
        let capability_classes = normalize_capabilities(capabilities)?;
        let capability_digest = Digest::from_fields(
            "vault-capabilities/v1",
            &[
                path_digest.as_str().to_owned(),
                capability_classes
                    .iter()
                    .map(|class| class.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            ],
        );
        Ok(Self {
            path_digest,
            capability_classes,
            capability_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultLeaseMetadata {
    pub lease_digest: Digest,
    pub mount_digest: Digest,
    pub path_digest: Digest,
    pub ttl_seconds: u64,
    pub renewable: bool,
}

impl VaultLeaseMetadata {
    pub fn new(
        lease_digest: Digest,
        mount_digest: Digest,
        path_digest: Digest,
        ttl_seconds: u64,
        renewable: bool,
    ) -> Self {
        Self {
            lease_digest,
            mount_digest,
            path_digest,
            ttl_seconds,
            renewable,
        }
    }

    pub fn status(&self) -> LeaseStatus {
        if self.ttl_seconds == 0 {
            LeaseStatus::Expired
        } else {
            LeaseStatus::Active
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum VaultResponsePayload {
    Health(VaultHealthMetadata),
    TokenSelf(VaultTokenSelfMetadata),
    CapabilitiesSelf(Vec<VaultCapabilityMetadata>),
    LeaseLookup(VaultLeaseMetadata),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultResponseReceipt {
    pub operation: VaultOperation,
    pub request_digest: Digest,
    pub response_status: u16,
    pub response_size: usize,
    pub response_digest: Digest,
    pub provider_revision: String,
    pub raw_provider_payload_retained: bool,
    pub secret_values_retained: bool,
    pub token_material_retained: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultHealthEvidence {
    pub status: HealthStatus,
    pub http_status: u16,
    pub metadata: VaultHealthMetadata,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultTokenEvidence {
    pub token_digest: Digest,
    pub accessor_digest: Digest,
    pub entity_id_digest: Option<Digest>,
    pub status: TokenStatus,
    pub ttl_seconds: u64,
    pub renewable: bool,
    pub policy_classes: Vec<PolicyClass>,
    pub policy_digest: Digest,
}

impl From<VaultTokenSelfMetadata> for VaultTokenEvidence {
    fn from(metadata: VaultTokenSelfMetadata) -> Self {
        let status = metadata.status();
        Self {
            token_digest: metadata.token_digest,
            accessor_digest: metadata.accessor_digest,
            entity_id_digest: metadata.entity_id_digest,
            status,
            ttl_seconds: metadata.ttl_seconds,
            renewable: metadata.renewable,
            policy_classes: metadata.policy_classes,
            policy_digest: metadata.policy_digest,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultCapabilityEvidence {
    pub path_digest: Digest,
    pub capability_classes: Vec<CapabilityClass>,
    pub capability_digest: Digest,
}

impl From<VaultCapabilityMetadata> for VaultCapabilityEvidence {
    fn from(metadata: VaultCapabilityMetadata) -> Self {
        Self {
            path_digest: metadata.path_digest,
            capability_classes: metadata.capability_classes,
            capability_digest: metadata.capability_digest,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultLeaseEvidence {
    pub lease_digest: Digest,
    pub mount_digest: Digest,
    pub path_digest: Digest,
    pub status: LeaseStatus,
    pub ttl_seconds: u64,
    pub renewable: bool,
}

impl From<VaultLeaseMetadata> for VaultLeaseEvidence {
    fn from(metadata: VaultLeaseMetadata) -> Self {
        let status = metadata.status();
        Self {
            lease_digest: metadata.lease_digest,
            mount_digest: metadata.mount_digest,
            path_digest: metadata.path_digest,
            status,
            ttl_seconds: metadata.ttl_seconds,
            renewable: metadata.renewable,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EvidenceOriginSeal {
    mac: Digest,
    lifecycle_generation: u64,
    registration_digest: Digest,
    scope_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultGovernanceEvidence {
    pub schema_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub service_id: String,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub consumer_id: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub lifecycle_generation: u64,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub secret_role: VaultSecretRole,
    pub valid_from_unix_seconds: u64,
    pub valid_until_unix_seconds: u64,
    pub provenance: ProviderProvenance,
    pub observed_at_unix_seconds: u64,
    pub operations: Vec<VaultOperation>,
    pub receipts: Vec<VaultResponseReceipt>,
    pub health: Option<VaultHealthEvidence>,
    pub token: Option<VaultTokenEvidence>,
    pub capabilities: Vec<VaultCapabilityEvidence>,
    pub lease: Option<VaultLeaseEvidence>,
    pub partial: bool,
    pub provider_unknown: bool,
    pub read_only: bool,
    pub native_evidence: bool,
    pub external_write_performed: bool,
    pub secret_values_retained: bool,
    pub token_material_retained: bool,
    pub raw_provider_payload_retained: bool,
    pub evidence_digest: Digest,
    #[serde(skip)]
    pub(crate) origin_seal: Option<EvidenceOriginSeal>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VaultGovernanceEvidenceWire {
    schema_version: String,
    contract_version: String,
    contract_digest: Digest,
    service_id: String,
    provider_id: String,
    provider_version: String,
    provider_revision: String,
    provider_digest: Digest,
    consumer_id: String,
    scope_digest: Digest,
    registration_digest: Digest,
    lifecycle_generation: u64,
    secret_reference_digest: Digest,
    credential_revision: Revision,
    secret_role: VaultSecretRole,
    valid_from_unix_seconds: u64,
    valid_until_unix_seconds: u64,
    provenance: ProviderProvenance,
    observed_at_unix_seconds: u64,
    operations: Vec<VaultOperation>,
    receipts: Vec<VaultResponseReceipt>,
    health: Option<VaultHealthEvidence>,
    token: Option<VaultTokenEvidence>,
    capabilities: Vec<VaultCapabilityEvidence>,
    lease: Option<VaultLeaseEvidence>,
    partial: bool,
    provider_unknown: bool,
    read_only: bool,
    native_evidence: bool,
    external_write_performed: bool,
    secret_values_retained: bool,
    token_material_retained: bool,
    raw_provider_payload_retained: bool,
    evidence_digest: Digest,
}

impl<'de> Deserialize<'de> for VaultGovernanceEvidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = VaultGovernanceEvidenceWire::deserialize(deserializer)?;
        let evidence = Self {
            schema_version: wire.schema_version,
            contract_version: wire.contract_version,
            contract_digest: wire.contract_digest,
            service_id: wire.service_id,
            provider_id: wire.provider_id,
            provider_version: wire.provider_version,
            provider_revision: wire.provider_revision,
            provider_digest: wire.provider_digest,
            consumer_id: wire.consumer_id,
            scope_digest: wire.scope_digest,
            registration_digest: wire.registration_digest,
            lifecycle_generation: wire.lifecycle_generation,
            secret_reference_digest: wire.secret_reference_digest,
            credential_revision: wire.credential_revision,
            secret_role: wire.secret_role,
            valid_from_unix_seconds: wire.valid_from_unix_seconds,
            valid_until_unix_seconds: wire.valid_until_unix_seconds,
            provenance: wire.provenance,
            observed_at_unix_seconds: wire.observed_at_unix_seconds,
            operations: wire.operations,
            receipts: wire.receipts,
            health: wire.health,
            token: wire.token,
            capabilities: wire.capabilities,
            lease: wire.lease,
            partial: wire.partial,
            provider_unknown: wire.provider_unknown,
            read_only: wire.read_only,
            native_evidence: wire.native_evidence,
            external_write_performed: wire.external_write_performed,
            secret_values_retained: wire.secret_values_retained,
            token_material_retained: wire.token_material_retained,
            raw_provider_payload_retained: wire.raw_provider_payload_retained,
            evidence_digest: wire.evidence_digest,
            origin_seal: None,
        };
        evidence.validate().map_err(DeError::custom)?;
        Ok(evidence)
    }
}

impl VaultGovernanceEvidence {
    fn origin_key() -> &'static [u8; 32] {
        static ORIGIN_KEY: OnceLock<[u8; 32]> = OnceLock::new();
        ORIGIN_KEY.get_or_init(|| {
            let mut material = Vec::new();
            material.extend_from_slice(&std::process::id().to_be_bytes());
            material.extend_from_slice(
                &SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
                    .to_be_bytes(),
            );
            Sha256::digest(material).into()
        })
    }

    fn origin_mac(
        &self,
        lifecycle_generation: u64,
        registration_digest: &Digest,
        scope_digest: &Digest,
    ) -> Digest {
        let mut material = Vec::new();
        material.extend_from_slice(Self::origin_key());
        material.extend_from_slice(&lifecycle_generation.to_be_bytes());
        material.extend_from_slice(registration_digest.as_str().as_bytes());
        material.extend_from_slice(scope_digest.as_str().as_bytes());
        let mut canonical = self.clone();
        canonical.evidence_digest = Digest::zero();
        canonical.origin_seal = None;
        material.extend(serde_json::to_vec(&canonical).expect("bounded Vault evidence serializes"));
        Digest::from_bytes(&material)
    }

    pub(crate) fn seal_from_provider(
        &mut self,
        lifecycle_generation: u64,
    ) -> Result<(), ModelError> {
        if lifecycle_generation == 0 || self.origin_seal.is_some() {
            return Err(ModelError::OriginMismatch);
        }
        let registration_digest = self.registration_digest.clone();
        let scope_digest = self.scope_digest.clone();
        let mac = self.origin_mac(lifecycle_generation, &registration_digest, &scope_digest);
        self.origin_seal = Some(EvidenceOriginSeal {
            mac,
            lifecycle_generation,
            registration_digest,
            scope_digest,
        });
        Ok(())
    }

    fn validate_origin(&self) -> Result<(), ModelError> {
        let Some(origin) = &self.origin_seal else {
            return Err(ModelError::OriginUnavailable);
        };
        if origin.lifecycle_generation != self.lifecycle_generation
            || origin.registration_digest != self.registration_digest
            || origin.scope_digest != self.scope_digest
            || origin.mac
                != self.origin_mac(
                    self.lifecycle_generation,
                    &self.registration_digest,
                    &self.scope_digest,
                )
        {
            return Err(ModelError::OriginMismatch);
        }
        Ok(())
    }

    pub(crate) fn compute_evidence_digest(&self) -> Digest {
        let mut material = self.clone();
        material.evidence_digest = Digest::zero();
        Digest::from_bytes(
            &serde_json::to_vec(&material).expect("bounded Vault evidence serializes"),
        )
    }

    pub fn verify_digest(&self) -> Result<(), ModelError> {
        if self.compute_evidence_digest() == self.evidence_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.validate_origin()?;
        if self.schema_version != VAULT_GOVERNANCE_RESULT_SCHEMA_VERSION
            || self.contract_version != VAULT_GOVERNANCE_RESULT_CONTRACT_VERSION
            || self.service_id != VAULT_GOVERNANCE_RESULT_SERVICE_ID
            || self.provider_id != VAULT_GOVERNANCE_RESULT_PROVIDER_ID
            || self.consumer_id != MISSION_VAULT_GOVERNANCE_CONSUMER_ID
            || self.provider_version.is_empty()
            || self.provider_revision != VAULT_GOVERNANCE_RESULT_PROVIDER_REVISION
            || self.provider_digest.is_zero()
            || self.contract_digest != crate::contract_digest()
            || self.secret_reference_digest.is_zero()
            || self.scope_digest.is_zero()
            || self.registration_digest.is_zero()
            || self.lifecycle_generation == 0
            || self.valid_until_unix_seconds <= self.valid_from_unix_seconds
            || self.observed_at_unix_seconds < self.valid_from_unix_seconds
            || self.observed_at_unix_seconds >= self.valid_until_unix_seconds
            || !self.read_only
            || self.native_evidence
            || self.external_write_performed
            || self.secret_values_retained
            || self.token_material_retained
            || self.raw_provider_payload_retained
            || self.partial
            || self.provider_unknown
            || self.operations.is_empty()
            || self.operations.len() > VaultOperation::ALL.len()
            || self.receipts.is_empty()
            || self.receipts.len() > MAX_RECEIPTS
            || self.receipts.len() != self.operations.len()
            || self.capabilities.len() > MAX_ALLOWLISTED_PATHS
        {
            return Err(ModelError::InvalidResponse);
        }
        if self
            .operations
            .iter()
            .any(|operation| !operation.is_read_only())
        {
            return Err(ModelError::InvalidResponse);
        }
        if self.receipts.iter().any(|receipt| {
            receipt.raw_provider_payload_retained
                || receipt.secret_values_retained
                || receipt.token_material_retained
                || receipt.response_size > MAX_RESPONSE_BYTES
                || receipt.provider_revision != VAULT_GOVERNANCE_RESULT_PROVIDER_REVISION
                || receipt.request_digest.is_zero()
                || receipt.response_digest.is_zero()
        }) {
            return Err(ModelError::InvalidResponse);
        }
        if self
            .receipts
            .iter()
            .zip(self.operations.iter())
            .any(|(receipt, operation)| receipt.operation != *operation)
        {
            return Err(ModelError::InvalidResponse);
        }
        for capability in &self.capabilities {
            if capability.capability_classes.is_empty()
                || capability.capability_classes.len() > MAX_CAPABILITY_CLASSES_PER_PATH
                || capability
                    .capability_classes
                    .iter()
                    .any(|class| !class.is_bounded())
            {
                return Err(ModelError::InvalidCapability);
            }
        }
        if let Some(token) = &self.token
            && (token.policy_classes.is_empty() || token.policy_classes.len() > MAX_POLICY_CLASSES)
        {
            return Err(ModelError::BoundExceeded {
                field: "policy classes",
            });
        }
        if let Some(token) = &self.token {
            let expected = Digest::from_fields(
                "vault-policy-classes/v1",
                &token
                    .policy_classes
                    .iter()
                    .map(|class| class.as_str().to_owned())
                    .collect::<Vec<_>>(),
            );
            if token.policy_digest != expected
                || token.policy_classes.iter().any(|class| !class.is_bounded())
            {
                return Err(ModelError::InvalidResponse);
            }
        }
        if self.capabilities.iter().any(|capability| {
            capability.capability_digest
                != Digest::from_fields(
                    "vault-capabilities/v1",
                    &[
                        capability.path_digest.as_str().to_owned(),
                        capability
                            .capability_classes
                            .iter()
                            .map(|class| class.as_str())
                            .collect::<Vec<_>>()
                            .join(","),
                    ],
                )
        }) {
            return Err(ModelError::InvalidResponse);
        }
        self.verify_digest()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityCheck {
    path: VaultPath,
    required: Vec<CapabilityClass>,
}

impl CapabilityCheck {
    pub fn new(
        path: VaultPath,
        required: impl IntoIterator<Item = CapabilityClass>,
    ) -> Result<Self, ModelError> {
        let required = normalize_capabilities(required.into_iter().collect())?;
        Ok(Self { path, required })
    }

    pub fn path(&self) -> &VaultPath {
        &self.path
    }

    pub fn required(&self) -> &[CapabilityClass] {
        &self.required
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultReadRequest {
    observed_at_unix_seconds: u64,
    include_health: bool,
    include_token_self: bool,
    capability_checks: Vec<CapabilityCheck>,
    lease_reference: Option<LeaseReference>,
}

impl Default for VaultReadRequest {
    fn default() -> Self {
        Self {
            observed_at_unix_seconds: 1,
            include_health: true,
            include_token_self: true,
            capability_checks: Vec::new(),
            lease_reference: None,
        }
    }
}

impl VaultReadRequest {
    pub fn new(observed_at_unix_seconds: u64) -> Self {
        Self {
            observed_at_unix_seconds,
            ..Self::default()
        }
    }

    pub fn health_only(observed_at_unix_seconds: u64) -> Self {
        Self {
            observed_at_unix_seconds,
            include_health: true,
            include_token_self: false,
            capability_checks: Vec::new(),
            lease_reference: None,
        }
    }

    #[must_use]
    pub fn include_health(mut self, include: bool) -> Self {
        self.include_health = include;
        self
    }

    #[must_use]
    pub fn include_token_self(mut self, include: bool) -> Self {
        self.include_token_self = include;
        self
    }

    #[must_use]
    pub fn check_capability(mut self, check: CapabilityCheck) -> Self {
        self.capability_checks.push(check);
        self
    }

    pub fn check_path(
        self,
        path: VaultPath,
        required: impl IntoIterator<Item = CapabilityClass>,
    ) -> Result<Self, ModelError> {
        Ok(self.check_capability(CapabilityCheck::new(path, required)?))
    }

    #[must_use]
    pub fn lookup_lease(mut self, lease_reference: LeaseReference) -> Self {
        self.lease_reference = Some(lease_reference);
        self
    }

    pub const fn observed_at_unix_seconds(&self) -> u64 {
        self.observed_at_unix_seconds
    }

    pub const fn includes_health(&self) -> bool {
        self.include_health
    }

    pub const fn includes_token_self(&self) -> bool {
        self.include_token_self
    }

    pub fn capability_checks(&self) -> &[CapabilityCheck] {
        &self.capability_checks
    }

    pub fn lease_reference(&self) -> Option<&LeaseReference> {
        self.lease_reference.as_ref()
    }

    pub(crate) fn validate(&self, scope: &VaultScope) -> Result<(), ModelError> {
        let Some(valid_from) = scope.valid_from_unix_seconds() else {
            return Err(ModelError::InvalidScope);
        };
        let Some(valid_until) = scope.valid_until_unix_seconds() else {
            return Err(ModelError::InvalidScope);
        };
        if self.observed_at_unix_seconds < valid_from
            || self.observed_at_unix_seconds >= valid_until
        {
            return Err(ModelError::ScopeMismatch);
        }
        if !self.include_health
            && !self.include_token_self
            && self.capability_checks.is_empty()
            && self.lease_reference.is_none()
        {
            return Err(ModelError::EmptyRequest);
        }
        if self.capability_checks.len() > MAX_ALLOWLISTED_PATHS {
            return Err(ModelError::BoundExceeded {
                field: "capability checks",
            });
        }
        let mut seen = BTreeSet::new();
        for check in &self.capability_checks {
            if !scope.contains_path(check.path()) {
                return Err(ModelError::ScopeMismatch);
            }
            if !seen.insert(check.path()) {
                return Err(ModelError::Duplicate {
                    field: "capability checks",
                });
            }
        }
        if let Some(lease) = &self.lease_reference
            && scope.lease_scope_digest() != lease.reference_digest()
        {
            return Err(ModelError::ScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionAvailability {
    NotAdoptedLayer2,
}

impl AdoptionAvailability {
    pub const fn is_adopted(self) -> bool {
        false
    }
}

pub(crate) fn digest_serializable<T: Serialize + ?Sized>(value: &T) -> Digest {
    Digest::from_bytes(&serde_json::to_vec(value).expect("bounded Vault value serializes"))
}

pub(crate) fn mount_digest(mount: &VaultMount) -> Digest {
    Digest::from_fields("vault-mount/v1", &[mount.as_str().to_owned()])
}
