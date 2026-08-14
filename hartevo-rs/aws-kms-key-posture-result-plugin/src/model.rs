//! Redacted, bounded model types for the AWS KMS key-posture boundary.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_ARN_BYTES: usize = 2_048;
pub const MAX_MARKER_BYTES: usize = 100_000;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_KEYS: usize = 256;
pub const MAX_ALIASES: usize = 256;
pub const MAX_GRANTS: usize = 256;
pub const MAX_RESPONSE_BYTES: u64 = 1_048_576;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} is too long")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    ControlCharacter { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} is not a valid digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} contains a duplicate")]
    Duplicate { field: &'static str },
    #[error("{field} exceeds its bound")]
    BoundExceeded { field: &'static str },
    #[error("the scope digest does not match")]
    ScopeMismatch,
    #[error("the permission digest does not match")]
    PermissionMismatch,
    #[error("the key is outside the exact scope")]
    KeyOutOfScope,
    #[error("the key state is unsafe for posture evidence")]
    UnsafeKeyState,
    #[error("eventual-consistency evidence is not accepted")]
    EventualConsistency,
    #[error("partial evidence is not accepted")]
    PartialEvidence,
    #[error("the opaque marker is invalid")]
    InvalidMarker,
    #[error("a marker loop was observed")]
    MarkerLoop,
    #[error("the registration is already revoked")]
    AlreadyRevoked,
    #[error("the registration is already reversed")]
    AlreadyReversed,
    #[error("the registration or secret reference is revoked")]
    Revoked,
}

fn validate_text(value: &str, field: &'static str, max: usize) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > max {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::ControlCharacter { field });
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), ModelError> {
    validate_text(value, field, MAX_IDENTIFIER_BYTES)?;
    if value.chars().any(char::is_whitespace) {
        return Err(ModelError::Invalid { field });
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("aws-kms-", $field, "/v1"),
                    &[("value", self.0.clone())],
                )
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.digest())
                    .finish()
            }
        }
    };
}

bounded_identifier!(MissionId, "mission-id");
bounded_identifier!(ProjectId, "project-id");
bounded_identifier!(WorkProductId, "work-product-id");
bounded_identifier!(DeploymentId, "deployment-id");

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_parts(domain: &str, fields: &[(&str, String)]) -> Self {
        let mut input = Vec::new();
        append_field(&mut input, domain);
        for (name, value) in fields {
            append_field(&mut input, name);
            append_field(&mut input, value);
        }
        Self::from_bytes(&input)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_lowercase();
        if valid_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest {
                field: "SHA-256 digest",
            })
        }
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        if valid_digest(self.as_str()) {
            Ok(())
        } else {
            Err(ModelError::InvalidDigest {
                field: "SHA-256 digest",
            })
        }
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

fn append_field(input: &mut Vec<u8>, value: &str) {
    input.extend_from_slice(&(value.len() as u64).to_be_bytes());
    input.extend_from_slice(value.as_bytes());
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::Invalid { field: "revision" })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionBinding {
    pub fn new(id: MissionId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-kms-mission/v1",
            &[
                ("id", self.id.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectBinding {
    pub fn new(id: ProjectId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-kms-project/v1",
            &[
                ("id", self.id.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub fn new(id: WorkProductId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-kms-work-product/v1",
            &[
                ("id", self.id.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentBinding {
    pub id: DeploymentId,
    pub revision: Revision,
}

impl DeploymentBinding {
    pub fn new(id: DeploymentId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-kms-deployment/v1",
            &[
                ("id", self.id.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AwsAccountId(String);

impl AwsAccountId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit()) {
            Ok(Self(value))
        } else {
            Err(ModelError::Invalid {
                field: "AWS account id",
            })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        Self::new(value)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("aws-kms-account/v1", &[("value", self.0.clone())])
    }
}

impl fmt::Debug for AwsAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AwsAccountId")
            .field(&self.digest())
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "AWS region")?;
        if value.len() > 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ModelError::Invalid {
                field: "AWS region",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        Self::new(value)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("aws-kms-region/v1", &[("value", self.0.clone())])
    }
}

impl fmt::Debug for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("AwsRegion").field(&self.0).finish()
    }
}

impl AsRef<str> for AwsRegion {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct KmsKeyId(String);

impl KmsKeyId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "KMS key id")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        Self::new(value)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("aws-kms-key-id/v1", &[("value", self.0.clone())])
    }
}

impl fmt::Debug for KmsKeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("KmsKeyId")
            .field(&self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct KmsKeyArn(String);

impl KmsKeyArn {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "KMS key ARN", MAX_ARN_BYTES)?;
        if !value.starts_with("arn:") || !value.contains(":kms:") {
            return Err(ModelError::Invalid {
                field: "KMS key ARN",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        Self::new(value)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("aws-kms-key-arn/v1", &[("value", self.0.clone())])
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

impl fmt::Debug for KmsKeyArn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("KmsKeyArn")
            .field(&self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct KmsKeyReference {
    key_id: KmsKeyId,
    key_arn: Option<KmsKeyArn>,
}

impl KmsKeyReference {
    pub fn new(key_id: KmsKeyId, key_arn: Option<KmsKeyArn>) -> Result<Self, ModelError> {
        let value = Self { key_id, key_arn };
        value.validate()?;
        Ok(value)
    }

    pub fn from_id(value: impl Into<String>) -> Result<Self, ModelError> {
        Self::new(KmsKeyId::new(value)?, None)
    }

    pub fn key_id(&self) -> &KmsKeyId {
        &self.key_id
    }

    pub fn key_arn(&self) -> Option<&KmsKeyArn> {
        self.key_arn.as_ref()
    }

    pub fn key_id_digest(&self) -> Digest {
        self.key_id.digest()
    }

    pub fn key_arn_digest(&self) -> Option<Digest> {
        self.key_arn.as_ref().map(KmsKeyArn::digest)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-kms-key-reference/v1",
            &[
                ("key_id", self.key_id_digest().as_str().to_owned()),
                (
                    "key_arn",
                    self.key_arn_digest()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        if let Some(arn) = &self.key_arn {
            arn.validate()?;
        }
        Ok(())
    }
}

impl fmt::Debug for KmsKeyReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KmsKeyReference")
            .field("key_id_digest", &self.key_id_digest())
            .field("key_arn_digest", &self.key_arn_digest())
            .finish()
    }
}

impl Serialize for KmsKeyReference {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("KmsKeyReference", 2)?;
        state.serialize_field("keyIdDigest", &self.key_id_digest())?;
        state.serialize_field("keyArnDigest", &self.key_arn_digest())?;
        state.end()
    }
}

/// A SigV4 reference is intentionally not `Serialize`. Its handle is only
/// useful to a future Layer-2 resolver and is never exposed in evidence.
#[derive(Eq, PartialEq)]
pub struct SigV4SecretReference {
    reference_id: String,
    region: AwsRegion,
    scope_digest: Digest,
    revision: Revision,
    revoked: bool,
}

pub type SecretReference = SigV4SecretReference;

impl Clone for SigV4SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_id: self.reference_id.clone(),
            region: self.region.clone(),
            scope_digest: self.scope_digest.clone(),
            revision: self.revision,
            revoked: self.revoked,
        }
    }
}

impl fmt::Debug for SigV4SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigV4SecretReference")
            .field("reference_id", &"<opaque>")
            .field("region", &self.region)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl SigV4SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        region: impl AsRef<str>,
        scope_digest: Digest,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        let region = AwsRegion::new(region.as_ref().to_owned())?;
        validate_identifier(&reference_id, "SigV4 secret reference")?;
        scope_digest.validate()?;
        Ok(Self {
            reference_id,
            region,
            scope_digest,
            revision,
            revoked: false,
        })
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-kms-sigv4-secret-reference/v1",
            &[
                ("reference", self.reference_id.clone()),
                ("region", self.region.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn ensure_active(&self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::Revoked)
        } else {
            Ok(())
        }
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

impl Drop for SigV4SecretReference {
    fn drop(&mut self) {
        self.reference_id.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum AwsKmsReadOperation {
    ListKeys,
    DescribeKey,
    GetKeyRotationStatus,
    ListAliases,
    ListGrants,
    KeyPosture,
}

impl AwsKmsReadOperation {
    pub const API: [Self; 5] = [
        Self::ListKeys,
        Self::DescribeKey,
        Self::GetKeyRotationStatus,
        Self::ListAliases,
        Self::ListGrants,
    ];

    pub const fn is_api(self) -> bool {
        !matches!(self, Self::KeyPosture)
    }

    pub const fn permission_name(self) -> &'static str {
        match self {
            Self::ListKeys => "kms:ListKeys",
            Self::DescribeKey => "kms:DescribeKey",
            Self::GetKeyRotationStatus => "kms:GetKeyRotationStatus",
            Self::ListAliases => "kms:ListAliases",
            Self::ListGrants => "kms:ListGrants",
            Self::KeyPosture => "mission:aws-kms-key-posture",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionFence {
    pub permission_id: String,
    pub revision: Revision,
    pub operations: BTreeSet<AwsKmsReadOperation>,
    pub permission_digest: Digest,
}

impl PermissionFence {
    pub fn new(
        permission_id: impl Into<String>,
        revision: Revision,
        operations: impl IntoIterator<Item = AwsKmsReadOperation>,
    ) -> Result<Self, ModelError> {
        let permission_id = permission_id.into();
        validate_identifier(&permission_id, "permission id")?;
        let operations = operations
            .into_iter()
            .filter(|operation| operation.is_api())
            .collect::<BTreeSet<_>>();
        if operations.is_empty() {
            return Err(ModelError::Invalid {
                field: "permission operations",
            });
        }
        let permission_digest = Self::compute_digest(&permission_id, revision, &operations);
        Ok(Self {
            permission_id,
            revision,
            operations,
            permission_digest,
        })
    }

    pub fn readonly(
        permission_id: impl Into<String>,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        Self::new(permission_id, revision, AwsKmsReadOperation::API)
    }

    pub fn permits(&self, operation: AwsKmsReadOperation) -> bool {
        self.operations.contains(&operation)
    }

    pub fn digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn verify(&self) -> Result<(), ModelError> {
        if self.permission_digest
            != Self::compute_digest(&self.permission_id, self.revision, &self.operations)
        {
            Err(ModelError::PermissionMismatch)
        } else {
            Ok(())
        }
    }

    fn compute_digest(
        permission_id: &str,
        revision: Revision,
        operations: &BTreeSet<AwsKmsReadOperation>,
    ) -> Digest {
        let operation_names = operations
            .iter()
            .map(|operation| operation.permission_name())
            .collect::<Vec<_>>()
            .join(",");
        Digest::from_parts(
            "aws-kms-permission-fence/v1",
            &[
                ("id", permission_id.to_owned()),
                ("revision", revision.get().to_string()),
                ("operations", operation_names),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsKmsScope {
    pub account_id: AwsAccountId,
    pub region: AwsRegion,
    pub key_allowlist: Option<Vec<KmsKeyReference>>,
    pub deployment: DeploymentBinding,
    pub mission: MissionBinding,
    pub project: ProjectBinding,
    pub work_product: WorkProductBinding,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
}

impl AwsKmsScope {
    pub fn new(
        account_id: AwsAccountId,
        region: AwsRegion,
        key_allowlist: Option<Vec<KmsKeyReference>>,
        deployment: DeploymentBinding,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        permission_digest: Digest,
    ) -> Result<Self, ModelError> {
        if let Some(keys) = &key_allowlist {
            if keys.is_empty() || keys.len() > MAX_KEYS {
                return Err(ModelError::BoundExceeded {
                    field: "key allowlist",
                });
            }
            let mut seen = BTreeSet::new();
            for key in keys {
                key.validate()?;
                if !seen.insert(key.digest()) {
                    return Err(ModelError::Duplicate {
                        field: "key allowlist",
                    });
                }
            }
        }
        permission_digest.validate()?;
        let mut scope = Self {
            account_id,
            region,
            key_allowlist,
            deployment,
            mission,
            project,
            work_product,
            permission_digest,
            scope_digest: Digest::zero(),
        };
        scope.scope_digest = scope.compute_digest();
        Ok(scope)
    }

    pub fn for_account_region(
        account_id: AwsAccountId,
        region: AwsRegion,
        key_allowlist: Option<Vec<KmsKeyReference>>,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        permission_digest: Digest,
    ) -> Result<Self, ModelError> {
        Self::new(
            account_id,
            region,
            key_allowlist,
            DeploymentBinding::new(DeploymentId::new("deployment-unbound")?, Revision::new(1)?),
            mission,
            project,
            work_product,
            permission_digest,
        )
    }

    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn contains_key(&self, key: &KmsKeyReference) -> bool {
        self.key_allowlist.as_ref().is_none_or(|allowlist| {
            allowlist
                .iter()
                .any(|candidate| candidate.digest() == key.digest())
        })
    }

    pub fn allowed_key(&self) -> Option<&KmsKeyReference> {
        self.key_allowlist.as_ref().and_then(|keys| keys.first())
    }

    pub fn verify(&self) -> Result<(), ModelError> {
        if self.scope_digest != self.compute_digest() {
            Err(ModelError::ScopeMismatch)
        } else {
            Ok(())
        }
    }

    fn compute_digest(&self) -> Digest {
        let key_digests = self
            .key_allowlist
            .as_ref()
            .map_or_else(String::new, |keys| {
                keys.iter()
                    .map(|key| key.digest().as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join(",")
            });
        Digest::from_parts(
            "aws-kms-scope/v1",
            &[
                ("account", self.account_id.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                ("keys", key_digests),
                ("deployment", self.deployment.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
                ("permission", self.permission_digest.as_str().to_owned()),
            ],
        )
    }
}

impl Serialize for AwsKmsScope {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("AwsKmsScope", 9)?;
        state.serialize_field("accountDigest", &self.account_id.digest())?;
        state.serialize_field("region", self.region.as_str())?;
        state.serialize_field(
            "keyAllowlist",
            &self
                .key_allowlist
                .as_ref()
                .map(|keys| keys.iter().map(KmsKeyReference::digest).collect::<Vec<_>>()),
        )?;
        state.serialize_field("deployment", &self.deployment)?;
        state.serialize_field("mission", &self.mission)?;
        state.serialize_field("project", &self.project)?;
        state.serialize_field("workProduct", &self.work_product)?;
        state.serialize_field("permissionDigest", &self.permission_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.end()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KmsKeyState {
    Enabled,
    Disabled,
    PendingDeletion,
    PendingImport,
    PendingReplicaDeletion,
    Unavailable,
    Updating,
    Unknown,
}

impl KmsKeyState {
    pub const fn is_safe(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KmsKeySpec {
    SymmetricDefault,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    Hsm1,
    Hsm2,
    EccNistP256,
    EccNistP384,
    EccNistP521,
    EccSecgP256k1,
    Sm2,
    MlDsa44,
    MlDsa65,
    MlDsa87,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KmsKeyUsage {
    EncryptDecrypt,
    SignVerify,
    GenerateVerifyMac,
    KeyAgreement,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KmsKeyOrigin {
    AwsKms,
    External,
    CustomKeyStore,
    CloudHsm,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConsistencyState {
    Stable,
    EventualConsistency,
    Unknown,
}

impl ConsistencyState {
    pub const fn is_stable(self) -> bool {
        matches!(self, Self::Stable)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KmsKeyMetadataInput {
    pub key: KmsKeyReference,
    pub state: KmsKeyState,
    pub spec: KmsKeySpec,
    pub usage: KmsKeyUsage,
    pub origin: KmsKeyOrigin,
    pub multi_region: bool,
    pub creation_date: Option<DateTime<Utc>>,
    pub deletion_date: Option<DateTime<Utc>>,
    pub consistency: ConsistencyState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KmsKeyMetadata {
    pub key_id_digest: Digest,
    pub key_arn_digest: Option<Digest>,
    pub state: KmsKeyState,
    pub spec: KmsKeySpec,
    pub usage: KmsKeyUsage,
    pub origin: KmsKeyOrigin,
    pub multi_region: bool,
    pub creation_date: Option<DateTime<Utc>>,
    pub deletion_date: Option<DateTime<Utc>>,
    pub consistency: ConsistencyState,
}

impl KmsKeyMetadata {
    pub fn from_input(input: KmsKeyMetadataInput) -> Self {
        Self {
            key_id_digest: input.key.key_id_digest(),
            key_arn_digest: input.key.key_arn_digest(),
            state: input.state,
            spec: input.spec,
            usage: input.usage,
            origin: input.origin,
            multi_region: input.multi_region,
            creation_date: input.creation_date,
            deletion_date: input.deletion_date,
            consistency: input.consistency,
        }
    }

    pub fn key_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-kms-key-metadata/v1",
            &[
                ("id", self.key_id_digest.as_str().to_owned()),
                (
                    "arn",
                    self.key_arn_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("state", format!("{:?}", self.state)),
                ("spec", format!("{:?}", self.spec)),
                ("usage", format!("{:?}", self.usage)),
                ("origin", format!("{:?}", self.origin)),
                ("multi_region", self.multi_region.to_string()),
                (
                    "creation",
                    self.creation_date
                        .map_or_else(String::new, |date| date.to_rfc3339()),
                ),
                (
                    "deletion",
                    self.deletion_date
                        .map_or_else(String::new, |date| date.to_rfc3339()),
                ),
                ("consistency", format!("{:?}", self.consistency)),
            ],
        )
    }

    pub fn validate_posture(&self) -> Result<(), ModelError> {
        self.key_id_digest.validate()?;
        if let Some(arn) = &self.key_arn_digest {
            arn.validate()?;
        }
        if !self.consistency.is_stable() || !self.state.is_safe() || self.deletion_date.is_some() {
            return Err(ModelError::UnsafeKeyState);
        }
        if matches!(self.spec, KmsKeySpec::Unknown)
            || matches!(self.usage, KmsKeyUsage::Unknown)
            || matches!(self.origin, KmsKeyOrigin::Unknown)
        {
            return Err(ModelError::UnsafeKeyState);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KmsKeySummary {
    pub key_id_digest: Digest,
    pub key_arn_digest: Option<Digest>,
}

impl KmsKeySummary {
    pub fn from_key(key: &KmsKeyReference) -> Self {
        Self {
            key_id_digest: key.key_id_digest(),
            key_arn_digest: key.key_arn_digest(),
        }
    }

    pub fn key_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-kms-key-summary/v1",
            &[
                ("id", self.key_id_digest.as_str().to_owned()),
                (
                    "arn",
                    self.key_arn_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        self.key_id_digest.validate()?;
        if let Some(arn) = &self.key_arn_digest {
            arn.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RotationStatus {
    pub enabled: bool,
    pub period_days: Option<u32>,
    pub next_rotation_date: Option<DateTime<Utc>>,
    pub consistency: ConsistencyState,
}

impl RotationStatus {
    pub fn validate(&self) -> Result<(), ModelError> {
        if !self.consistency.is_stable()
            || self
                .period_days
                .is_some_and(|days| !(1..=3_650).contains(&days))
        {
            Err(ModelError::EventualConsistency)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-kms-rotation-status/v1",
            &[
                ("enabled", self.enabled.to_string()),
                (
                    "period",
                    self.period_days
                        .map_or_else(String::new, |days| days.to_string()),
                ),
                (
                    "next",
                    self.next_rotation_date
                        .map_or_else(String::new, |date| date.to_rfc3339()),
                ),
                ("consistency", format!("{:?}", self.consistency)),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KmsAliasSummary {
    pub alias_name_digest: Digest,
    pub target_key_id_digest: Digest,
}

impl KmsAliasSummary {
    pub fn from_provider_fields(
        alias_name: impl Into<String>,
        target_key_id: &KmsKeyId,
    ) -> Result<Self, ModelError> {
        let alias_name = alias_name.into();
        validate_identifier(&alias_name, "KMS alias")?;
        Ok(Self {
            alias_name_digest: Digest::from_parts("aws-kms-alias-name/v1", &[("name", alias_name)]),
            target_key_id_digest: target_key_id.digest(),
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-kms-alias-summary/v1",
            &[
                ("alias", self.alias_name_digest.as_str().to_owned()),
                ("target", self.target_key_id_digest.as_str().to_owned()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        self.alias_name_digest.validate()?;
        self.target_key_id_digest.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KmsGrantSummary {
    pub grant_digest: Digest,
    pub operations_digest: Digest,
    pub constraints_digest: Option<Digest>,
}

impl KmsGrantSummary {
    pub fn from_provider_fields(
        grant_id: impl Into<String>,
        grantee_principal: impl Into<String>,
        retiring_principal: Option<impl Into<String>>,
        operations: impl IntoIterator<Item = impl AsRef<str>>,
        constraints: Option<impl AsRef<str>>,
    ) -> Result<Self, ModelError> {
        let grant_id = grant_id.into();
        let grantee_principal = grantee_principal.into();
        validate_identifier(&grant_id, "KMS grant id")?;
        validate_text(
            &grantee_principal,
            "KMS grantee principal",
            MAX_IDENTIFIER_BYTES * 4,
        )?;
        let retiring_principal = retiring_principal.map(Into::into);
        if let Some(principal) = &retiring_principal {
            validate_text(
                principal,
                "KMS retiring principal",
                MAX_IDENTIFIER_BYTES * 4,
            )?;
        }
        let operation_names = operations
            .into_iter()
            .map(|operation| operation.as_ref().to_owned())
            .collect::<Vec<_>>();
        if operation_names.is_empty() {
            return Err(ModelError::Invalid {
                field: "KMS grant operations",
            });
        }
        for operation in &operation_names {
            validate_identifier(operation, "KMS grant operation")?;
        }
        let constraints = constraints.map(|value| value.as_ref().to_owned());
        if let Some(value) = &constraints {
            validate_text(value, "KMS grant constraints", MAX_IDENTIFIER_BYTES * 4)?;
        }
        let operations_digest = Digest::from_parts(
            "aws-kms-grant-operations/v1",
            &[("operations", operation_names.join(","))],
        );
        let principal_digest = Digest::from_parts(
            "aws-kms-grant-principals/v1",
            &[
                ("grantee", grantee_principal),
                ("retiring", retiring_principal.unwrap_or_default()),
            ],
        );
        let constraints_digest = constraints
            .map(|value| Digest::from_parts("aws-kms-grant-constraints/v1", &[("value", value)]));
        Ok(Self {
            grant_digest: Digest::from_parts(
                "aws-kms-grant-summary/v1",
                &[
                    ("id", grant_id),
                    ("principals", principal_digest.as_str().to_owned()),
                    ("operations", operations_digest.as_str().to_owned()),
                    (
                        "constraints",
                        constraints_digest
                            .as_ref()
                            .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                    ),
                ],
            ),
            operations_digest,
            constraints_digest,
        })
    }

    pub fn from_digests(
        grant_digest: Digest,
        operations_digest: Digest,
        constraints_digest: Option<Digest>,
    ) -> Result<Self, ModelError> {
        grant_digest.validate()?;
        operations_digest.validate()?;
        if let Some(digest) = &constraints_digest {
            digest.validate()?;
        }
        Ok(Self {
            grant_digest,
            operations_digest,
            constraints_digest,
        })
    }

    pub fn digest(&self) -> Digest {
        self.grant_digest.clone()
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        self.grant_digest.validate()?;
        self.operations_digest.validate()?;
        if let Some(digest) = &self.constraints_digest {
            digest.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueMarker {
    token: String,
}

impl OpaqueMarker {
    pub fn new(token: impl Into<String>) -> Result<Self, ModelError> {
        let token = token.into();
        if token.is_empty() || token.len() > MAX_MARKER_BYTES || token.chars().any(char::is_control)
        {
            Err(ModelError::InvalidMarker)
        } else {
            Ok(Self { token })
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-kms-pagination-marker/v1",
            &[("marker", self.token.clone())],
        )
    }
}

impl fmt::Debug for OpaqueMarker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("OpaqueMarker")
            .field(&self.digest())
            .finish()
    }
}

impl Drop for OpaqueMarker {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub const fn first_party(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactedRequestReceipt {
    pub operation: AwsKmsReadOperation,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub response_bytes: u64,
    pub attempts: u8,
    pub status: ReceiptStatus,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    BoundedSuccess,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CostReceipt {
    pub bounded_api_calls: u32,
    pub response_bytes: u64,
    pub estimate_digest: Digest,
    pub authoritative: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Complete,
}

impl CostReceipt {
    pub fn new(bounded_api_calls: u32, response_bytes: u64) -> Self {
        Self {
            bounded_api_calls,
            response_bytes,
            estimate_digest: Digest::from_parts(
                "aws-kms-cost-estimate/v1",
                &[
                    ("calls", bounded_api_calls.to_string()),
                    ("bytes", response_bytes.to_string()),
                ],
            ),
            authoritative: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginationSummary {
    pub pages_observed: u16,
    pub items_observed: usize,
    pub complete: bool,
    pub marker_digests: Vec<Digest>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityBoundary {
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub cryptographic_verification_authority: bool,
    pub key_mutation_authority: bool,
    pub policy_authority: bool,
    pub outcome_authority: bool,
    pub durable_receipt: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyPostureProjection {
    pub key_id_digest: Digest,
    pub key_arn_digest: Option<Digest>,
    pub state: KmsKeyState,
    pub spec: KmsKeySpec,
    pub usage: KmsKeyUsage,
    pub origin: KmsKeyOrigin,
    pub multi_region: bool,
    pub alias_count: usize,
    pub alias_digest: Digest,
    pub grant_count: usize,
    pub grant_digest: Digest,
    pub rotation_enabled: bool,
    pub rotation_period_days: Option<u32>,
    pub rotation_next_date: Option<DateTime<Utc>>,
}

impl KeyPostureProjection {
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-kms-key-posture-projection/v1",
            &[
                ("id", self.key_id_digest.as_str().to_owned()),
                (
                    "arn",
                    self.key_arn_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("state", format!("{:?}", self.state)),
                ("spec", format!("{:?}", self.spec)),
                ("usage", format!("{:?}", self.usage)),
                ("origin", format!("{:?}", self.origin)),
                ("multi_region", self.multi_region.to_string()),
                ("alias_count", self.alias_count.to_string()),
                ("alias_digest", self.alias_digest.as_str().to_owned()),
                ("grant_count", self.grant_count.to_string()),
                ("grant_digest", self.grant_digest.as_str().to_owned()),
                ("rotation_enabled", self.rotation_enabled.to_string()),
                (
                    "rotation_period",
                    self.rotation_period_days
                        .map_or_else(String::new, |days| days.to_string()),
                ),
                (
                    "rotation_next",
                    self.rotation_next_date
                        .map_or_else(String::new, |date| date.to_rfc3339()),
                ),
            ],
        )
    }
}
