use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{AwsCloudFormationDriftError, Result};
use crate::{
    CONTRACT_DIGEST, CONTRACT_VERSION, LAYER1_PERMISSIONS, MAX_EVENTS, MAX_IDENTIFIER_BYTES,
    MAX_LOGICAL_RESOURCE_IDS, MAX_PAGE_SIZE, MAX_PAGES, MAX_POLLS, MAX_RESOURCES,
    MAX_RESPONSE_BYTES, MAX_RESPONSE_BYTES_USIZE,
};

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
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for (name, value) in fields {
            append_field(&mut bytes, name);
            append_field(&mut bytes, value);
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(AwsCloudFormationDriftError::InvalidDigest)
        }
    }

    pub const fn zero() -> Self {
        Self(String::new())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(&self.0) {
            Ok(())
        } else {
            Err(AwsCloudFormationDriftError::InvalidDigest)
        }
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

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn digest_serialized<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    Digest::from_bytes(&bytes)
}

fn valid_text(value: &str, max_bytes: usize, allow_internal_whitespace: bool) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && (allow_internal_whitespace || !value.chars().any(char::is_whitespace))
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    valid_text(value, max_bytes, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_arn(value: &str) -> bool {
    valid_text(value, 2_048, false) && value.starts_with("arn:")
}

fn valid_stack_name_or_arn(value: &str) -> bool {
    if valid_arn(value) {
        return true;
    }
    value.len() <= 128
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

macro_rules! opaque_text {
    ($name:ident, $field:literal, $validator:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(AwsCloudFormationDriftError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("aws-cloudformation-", $field, "/v1"),
                    &[("value", self.0.clone())],
                )
            }

            pub fn redacted(&self) -> String {
                format!("{}:{}", $field, &self.digest().as_str()[..16])
            }

            #[allow(dead_code)]
            pub(crate) fn validate(&self) -> Result<()> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(AwsCloudFormationDriftError::InvalidIdentifier { field: $field })
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.redacted())
                    .finish()
            }
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                serializer.serialize_str(self.digest().as_str())
            }
        }
    };
}

opaque_text!(AwsAccountId, "account", |value: &str| value.len() == 12
    && value.bytes().all(|byte| byte.is_ascii_digit()));
opaque_text!(AwsRegion, "region", |value: &str| valid_identifier(
    value, 64
));
opaque_text!(StackName, "stack", valid_stack_name_or_arn);
opaque_text!(StackDriftDetectionId, "drift-detection", |value: &str| {
    (1..=36).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
});
opaque_text!(LogicalResourceId, "logical-resource", |value: &str| {
    valid_text(value, 255, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
});
opaque_text!(ResourceType, "resource-type", |value: &str| {
    valid_text(value, 256, false)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'/' | b'.' | b'-' | b'_')
        })
});

#[derive(Clone, Eq, PartialEq)]
pub struct MissionIdentity {
    id: String,
    revision: u64,
}

impl MissionIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        if !valid_identifier(&id, MAX_IDENTIFIER_BYTES) || revision == 0 {
            return Err(AwsCloudFormationDriftError::InvalidScope);
        }
        Ok(Self { id, revision })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cloudformation-mission/v1",
            &[
                ("id", self.id.clone()),
                ("revision", self.revision.to_string()),
            ],
        )
    }

    fn validate(&self) -> Result<()> {
        if valid_identifier(&self.id, MAX_IDENTIFIER_BYTES) && self.revision != 0 {
            Ok(())
        } else {
            Err(AwsCloudFormationDriftError::InvalidScope)
        }
    }
}

impl fmt::Debug for MissionIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionIdentity")
            .field("id_digest", &self.digest())
            .field("revision", &self.revision)
            .finish()
    }
}

impl Serialize for MissionIdentity {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("MissionIdentity", 2)?;
        state.serialize_field("idDigest", &self.digest())?;
        state.serialize_field("revision", &self.revision)?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProjectIdentity {
    id: String,
    revision: u64,
}

impl ProjectIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        if !valid_identifier(&id, MAX_IDENTIFIER_BYTES) || revision == 0 {
            return Err(AwsCloudFormationDriftError::InvalidScope);
        }
        Ok(Self { id, revision })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cloudformation-project/v1",
            &[
                ("id", self.id.clone()),
                ("revision", self.revision.to_string()),
            ],
        )
    }

    fn validate(&self) -> Result<()> {
        if valid_identifier(&self.id, MAX_IDENTIFIER_BYTES) && self.revision != 0 {
            Ok(())
        } else {
            Err(AwsCloudFormationDriftError::InvalidScope)
        }
    }
}

impl fmt::Debug for ProjectIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectIdentity")
            .field("id_digest", &self.digest())
            .field("revision", &self.revision)
            .finish()
    }
}

impl Serialize for ProjectIdentity {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ProjectIdentity", 2)?;
        state.serialize_field("idDigest", &self.digest())?;
        state.serialize_field("revision", &self.revision)?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct WorkProductIdentity {
    id: String,
    revision: u64,
}

impl WorkProductIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        if !valid_identifier(&id, MAX_IDENTIFIER_BYTES) || revision == 0 {
            return Err(AwsCloudFormationDriftError::InvalidScope);
        }
        Ok(Self { id, revision })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cloudformation-work-product/v1",
            &[
                ("id", self.id.clone()),
                ("revision", self.revision.to_string()),
            ],
        )
    }

    fn validate(&self) -> Result<()> {
        if valid_identifier(&self.id, MAX_IDENTIFIER_BYTES) && self.revision != 0 {
            Ok(())
        } else {
            Err(AwsCloudFormationDriftError::InvalidScope)
        }
    }
}

impl fmt::Debug for WorkProductIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkProductIdentity")
            .field("id_digest", &self.digest())
            .field("revision", &self.revision)
            .finish()
    }
}

impl Serialize for WorkProductIdentity {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("WorkProductIdentity", 2)?;
        state.serialize_field("idDigest", &self.digest())?;
        state.serialize_field("revision", &self.revision)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

pub fn mission_projection(value: &MissionIdentity) -> MissionProjection {
    MissionProjection {
        id_digest: value.digest(),
        revision: value.revision,
    }
}

pub fn project_projection(value: &ProjectIdentity) -> ProjectProjection {
    ProjectProjection {
        id_digest: value.digest(),
        revision: value.revision,
    }
}

pub fn work_product_projection(value: &WorkProductIdentity) -> WorkProductProjection {
    WorkProductProjection {
        id_digest: value.digest(),
        revision: value.revision,
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsCloudFormationDriftScope {
    account: AwsAccountId,
    region: AwsRegion,
    stack: StackName,
    stack_revision: u64,
    mission: MissionIdentity,
    project: ProjectIdentity,
    work_product: WorkProductIdentity,
}

impl AwsCloudFormationDriftScope {
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        stack: StackName,
        stack_revision: u64,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let scope = Self {
            account,
            region,
            stack,
            stack_revision,
            mission,
            project,
            work_product,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn account(&self) -> &AwsAccountId {
        &self.account
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn stack(&self) -> &StackName {
        &self.stack
    }

    pub const fn stack_revision(&self) -> u64 {
        self.stack_revision
    }

    pub fn mission(&self) -> &MissionIdentity {
        &self.mission
    }

    pub fn project(&self) -> &ProjectIdentity {
        &self.project
    }

    pub fn work_product(&self) -> &WorkProductIdentity {
        &self.work_product
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cloudformation-drift-scope/v1",
            &[
                ("account", self.account.digest().to_string()),
                ("region", self.region.digest().to_string()),
                ("stack", self.stack.digest().to_string()),
                ("stack_revision", self.stack_revision.to_string()),
                ("mission", self.mission.digest().to_string()),
                ("project", self.project.digest().to_string()),
                ("work_product", self.work_product.digest().to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.account.validate()?;
        self.region.validate()?;
        self.stack.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()?;
        if self.stack_revision == 0 {
            return Err(AwsCloudFormationDriftError::InvalidScope);
        }
        Ok(())
    }
}

impl fmt::Debug for AwsCloudFormationDriftScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCloudFormationDriftScope")
            .field("digest", &self.digest())
            .field("account", &self.account)
            .field("region", &self.region)
            .field("stack", &self.stack)
            .field("stack_revision", &self.stack_revision)
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Sigv4Credential,
}

/// An opaque credential handle. The caller's handle is hashed and dropped;
/// the type deliberately implements neither `Serialize` nor `Deserialize`.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    scope_digest: Digest,
    revision: u64,
    revoked: bool,
}

impl SecretReference {
    pub fn new(opaque_handle: impl Into<String>, revision: u64) -> Result<Self> {
        let mut handle = opaque_handle.into();
        if !valid_text(&handle, MAX_IDENTIFIER_BYTES, true) || revision == 0 {
            handle.zeroize();
            return Err(AwsCloudFormationDriftError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_parts(
            "aws-cloudformation-opaque-sigv4-reference/v1",
            &[
                ("kind", "sigv4_credential".to_owned()),
                ("handle", handle.clone()),
                ("revision", revision.to_string()),
            ],
        );
        handle.zeroize();
        Ok(Self {
            kind: SecretKind::Sigv4Credential,
            reference_digest,
            scope_digest: Digest::from_text("unbound-aws-cloudformation-secret-scope"),
            revision,
            revoked: false,
        })
    }

    pub fn sigv4(
        opaque_handle: impl Into<String>,
        scope: &AwsCloudFormationDriftScope,
        revision: u64,
    ) -> Result<Self> {
        let mut reference = Self::new(opaque_handle, revision)?;
        reference.scope_digest = scope.digest();
        reference.reference_digest = Digest::from_parts(
            "aws-cloudformation-opaque-sigv4-reference/v1",
            &[
                ("kind", "sigv4_credential".to_owned()),
                ("reference", reference.reference_digest.to_string()),
                ("scope", reference.scope_digest.to_string()),
                ("revision", revision.to_string()),
            ],
        );
        Ok(reference)
    }

    pub fn for_scope(
        opaque_handle: impl Into<String>,
        scope: &AwsCloudFormationDriftScope,
        revision: u64,
    ) -> Result<Self> {
        Self::sigv4(opaque_handle, scope, revision)
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub(crate) fn validate(&self, scope: &AwsCloudFormationDriftScope) -> Result<()> {
        if self.kind != SecretKind::Sigv4Credential
            || self.revision == 0
            || self.revoked
            || self.scope_digest != scope.digest()
        {
            return Err(AwsCloudFormationDriftError::InvalidSecretReference);
        }
        self.reference_digest.validate()
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }

    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    pub revision: u64,
    pub permissions: BTreeSet<String>,
}

impl PermissionSnapshot {
    pub fn new<I, S>(revision: u64, permissions: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let value = Self {
            revision,
            permissions: permissions.into_iter().map(Into::into).collect(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn for_layer_one(revision: u64) -> Self {
        Self {
            revision,
            permissions: LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cloudformation-permissions/v1",
            &[
                ("revision", self.revision.to_string()),
                (
                    "permissions",
                    self.permissions
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.revision == 0
            || self.permissions.is_empty()
            || self
                .permissions
                .iter()
                .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
        {
            Err(AwsCloudFormationDriftError::InvalidPermissionSnapshot)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ConsentScope {
    id: String,
    revision: u64,
    permissions: BTreeSet<String>,
    expires_at: DateTime<Utc>,
    revoked: bool,
}

impl ConsentScope {
    pub fn new<I, S>(
        id: impl Into<String>,
        revision: u64,
        permissions: I,
        expires_at: DateTime<Utc>,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let value = Self {
            id: id.into(),
            revision,
            permissions: permissions.into_iter().map(Into::into).collect(),
            expires_at,
            revoked: false,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn for_layer_one(
        id: impl Into<String>,
        revision: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new(id, revision, LAYER1_PERMISSIONS, expires_at)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cloudformation-consent/v1",
            &[
                ("id", self.id.clone()),
                ("revision", self.revision.to_string()),
                (
                    "permissions",
                    self.permissions
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("expires_at", self.expires_at.to_rfc3339()),
                ("revoked", self.revoked.to_string()),
            ],
        )
    }

    pub fn is_active_at(&self, at: DateTime<Utc>) -> bool {
        !self.revoked && at < self.expires_at
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if !valid_identifier(&self.id, MAX_IDENTIFIER_BYTES)
            || self.revision == 0
            || self.permissions.is_empty()
            || self
                .permissions
                .iter()
                .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
        {
            return Err(AwsCloudFormationDriftError::InvalidConsent);
        }
        Ok(())
    }
}

impl fmt::Debug for ConsentScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsentScope")
            .field("digest", &self.digest())
            .field("revision", &self.revision)
            .field("expires_at", &self.expires_at)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueCursor {
    token_digest: Digest,
    binding_digest: Option<Digest>,
    page_number: u16,
}

impl OpaqueCursor {
    pub fn new(value: impl AsRef<str>) -> Result<Self> {
        let value = value.as_ref();
        if !valid_text(value, 1_024, false) {
            return Err(AwsCloudFormationDriftError::InvalidText {
                field: "next token",
            });
        }
        Ok(Self {
            token_digest: Digest::from_parts(
                "aws-cloudformation-next-token/v1",
                &[("token", value.to_owned())],
            ),
            binding_digest: None,
            page_number: 0,
        })
    }

    pub fn bind(&self, binding_digest: &Digest, page_number: u16) -> Self {
        Self {
            token_digest: self.token_digest.clone(),
            binding_digest: Some(binding_digest.clone()),
            page_number,
        }
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn binding_digest(&self) -> Option<&Digest> {
        self.binding_digest.as_ref()
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

impl Serialize for OpaqueCursor {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("OpaqueCursor", 3)?;
        state.serialize_field("opaque", &true)?;
        state.serialize_field("tokenDigest", &self.token_digest)?;
        state.serialize_field("bindingDigest", &self.binding_digest)?;
        state.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CloudFormationStackStatus {
    CreateInProgress,
    CreateFailed,
    CreateComplete,
    DeleteInProgress,
    DeleteFailed,
    DeleteComplete,
    RollbackInProgress,
    RollbackFailed,
    RollbackComplete,
    UpdateInProgress,
    UpdateFailed,
    UpdateComplete,
    UpdateRollbackInProgress,
    UpdateRollbackFailed,
    UpdateRollbackComplete,
    ImportInProgress,
    ImportFailed,
    ImportComplete,
    ImportRollbackInProgress,
    ImportRollbackFailed,
    ImportRollbackComplete,
    ReviewInProgress,
    Unknown,
}

impl CloudFormationStackStatus {
    pub fn parse_api(value: &str) -> Self {
        match value {
            "CREATE_IN_PROGRESS" => Self::CreateInProgress,
            "CREATE_FAILED" => Self::CreateFailed,
            "CREATE_COMPLETE" => Self::CreateComplete,
            "DELETE_IN_PROGRESS" => Self::DeleteInProgress,
            "DELETE_FAILED" => Self::DeleteFailed,
            "DELETE_COMPLETE" => Self::DeleteComplete,
            "ROLLBACK_IN_PROGRESS" => Self::RollbackInProgress,
            "ROLLBACK_FAILED" => Self::RollbackFailed,
            "ROLLBACK_COMPLETE" => Self::RollbackComplete,
            "UPDATE_IN_PROGRESS" => Self::UpdateInProgress,
            "UPDATE_FAILED" => Self::UpdateFailed,
            "UPDATE_COMPLETE" => Self::UpdateComplete,
            "UPDATE_ROLLBACK_IN_PROGRESS" => Self::UpdateRollbackInProgress,
            "UPDATE_ROLLBACK_FAILED" => Self::UpdateRollbackFailed,
            "UPDATE_ROLLBACK_COMPLETE" => Self::UpdateRollbackComplete,
            "IMPORT_IN_PROGRESS" => Self::ImportInProgress,
            "IMPORT_FAILED" => Self::ImportFailed,
            "IMPORT_COMPLETE" => Self::ImportComplete,
            "IMPORT_ROLLBACK_IN_PROGRESS" => Self::ImportRollbackInProgress,
            "IMPORT_ROLLBACK_FAILED" => Self::ImportRollbackFailed,
            "IMPORT_ROLLBACK_COMPLETE" => Self::ImportRollbackComplete,
            "REVIEW_IN_PROGRESS" => Self::ReviewInProgress,
            _ => Self::Unknown,
        }
    }
}

pub type CloudFormationResourceStatus = CloudFormationStackStatus;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StackDriftStatus {
    Drifted,
    InSync,
    Unknown,
    NotChecked,
}

impl StackDriftStatus {
    pub fn parse_api(value: &str) -> Self {
        match value {
            "DRIFTED" => Self::Drifted,
            "IN_SYNC" => Self::InSync,
            "UNKNOWN" => Self::Unknown,
            _ => Self::NotChecked,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DriftDetectionStatus {
    DetectionInProgress,
    DetectionFailed,
    DetectionComplete,
}

impl DriftDetectionStatus {
    pub fn parse_api(value: &str) -> Self {
        match value {
            "DETECTION_COMPLETE" => Self::DetectionComplete,
            "DETECTION_FAILED" => Self::DetectionFailed,
            _ => Self::DetectionInProgress,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResourceDriftStatus {
    InSync,
    Modified,
    Deleted,
    Unknown,
    NotChecked,
    Unsupported,
}

impl ResourceDriftStatus {
    pub fn parse_api(value: &str) -> Self {
        match value {
            "IN_SYNC" => Self::InSync,
            "MODIFIED" => Self::Modified,
            "DELETED" => Self::Deleted,
            "UNKNOWN" => Self::Unknown,
            "UNSUPPORTED" => Self::Unsupported,
            _ => Self::NotChecked,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CloudFormationOperation {
    DescribeStacks,
    DescribeStackEvents,
    DetectStackDrift,
    DescribeStackDriftDetectionStatus,
    DescribeStackResourceDrifts,
}

impl CloudFormationOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DescribeStacks => "DescribeStacks",
            Self::DescribeStackEvents => "DescribeStackEvents",
            Self::DetectStackDrift => "DetectStackDrift",
            Self::DescribeStackDriftDetectionStatus => "DescribeStackDriftDetectionStatus",
            Self::DescribeStackResourceDrifts => "DescribeStackResourceDrifts",
        }
    }

    pub const fn permission(self) -> &'static str {
        match self {
            Self::DescribeStacks => "cloudformation:DescribeStacks",
            Self::DescribeStackEvents => "cloudformation:DescribeStackEvents",
            Self::DetectStackDrift => "cloudformation:DetectStackDrift",
            Self::DescribeStackDriftDetectionStatus => {
                "cloudformation:DescribeStackDriftDetectionStatus"
            }
            Self::DescribeStackResourceDrifts => "cloudformation:DescribeStackResourceDrifts",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceDriftFilter {
    pub statuses: BTreeSet<ResourceDriftStatus>,
}

impl ResourceDriftFilter {
    pub fn new<I>(statuses: I) -> Result<Self>
    where
        I: IntoIterator<Item = ResourceDriftStatus>,
    {
        let statuses = statuses.into_iter().collect::<BTreeSet<_>>();
        if statuses.is_empty() || statuses.len() > 6 {
            return Err(AwsCloudFormationDriftError::InvalidRequest);
        }
        Ok(Self { statuses })
    }

    pub fn all() -> Self {
        Self {
            statuses: [
                ResourceDriftStatus::InSync,
                ResourceDriftStatus::Modified,
                ResourceDriftStatus::Deleted,
                ResourceDriftStatus::Unknown,
                ResourceDriftStatus::NotChecked,
                ResourceDriftStatus::Unsupported,
            ]
            .into_iter()
            .collect(),
        }
    }

    pub fn allows(&self, status: ResourceDriftStatus) -> bool {
        self.statuses.contains(&status)
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StackSummary {
    pub stack_digest: Digest,
    pub stack_revision: u64,
    pub status: CloudFormationStackStatus,
    pub creation_time: DateTime<Utc>,
    pub last_updated_time: Option<DateTime<Utc>>,
    pub deletion_time: Option<DateTime<Utc>>,
    pub drift_status: Option<StackDriftStatus>,
    pub last_drift_check: Option<DateTime<Utc>>,
    pub status_reason_digest: Option<Digest>,
    pub summary_digest: Digest,
}

impl StackSummary {
    pub fn new(
        scope: &AwsCloudFormationDriftScope,
        status: CloudFormationStackStatus,
        creation_time: DateTime<Utc>,
        last_updated_time: Option<DateTime<Utc>>,
        deletion_time: Option<DateTime<Utc>>,
        drift_status: Option<StackDriftStatus>,
        last_drift_check: Option<DateTime<Utc>>,
        status_reason: Option<&str>,
    ) -> Result<Self> {
        let status_reason_digest = status_reason
            .map(|value| {
                if valid_text(value, 1_024, true) {
                    Ok(Digest::from_parts(
                        "aws-cloudformation-stack-status-reason/v1",
                        &[("reason", value.to_owned())],
                    ))
                } else {
                    Err(AwsCloudFormationDriftError::InvalidText {
                        field: "stack status reason",
                    })
                }
            })
            .transpose()?;
        let mut summary = Self {
            stack_digest: scope.stack.digest(),
            stack_revision: scope.stack_revision,
            status,
            creation_time,
            last_updated_time,
            deletion_time,
            drift_status,
            last_drift_check,
            status_reason_digest,
            summary_digest: Digest::from_text("unsealed-cloudformation-stack-summary"),
        };
        summary.summary_digest = summary.recomputed_digest();
        Ok(summary)
    }

    pub fn digest(&self) -> Digest {
        self.summary_digest.clone()
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            &self.stack_digest,
            self.stack_revision,
            self.status,
            self.creation_time,
            self.last_updated_time,
            self.deletion_time,
            self.drift_status,
            self.last_drift_check,
            &self.status_reason_digest,
        ))
    }

    pub fn validate_against(&self, scope: &AwsCloudFormationDriftScope) -> Result<()> {
        if self.stack_digest != scope.stack.digest()
            || self.stack_revision != scope.stack_revision
            || self.summary_digest != self.recomputed_digest()
        {
            return Err(AwsCloudFormationDriftError::StackRevisionDrift);
        }
        self.status_reason_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StackEvent {
    pub stack_digest: Digest,
    pub stack_revision: u64,
    pub event_digest: Digest,
    pub event_id_digest: Digest,
    pub logical_resource_id_digest: Digest,
    pub resource_type_digest: Digest,
    pub resource_status: CloudFormationResourceStatus,
    pub timestamp: DateTime<Utc>,
    pub status_reason_digest: Option<Digest>,
}

impl StackEvent {
    pub fn new(
        scope: &AwsCloudFormationDriftScope,
        event_id: &str,
        logical_resource_id: &str,
        resource_type: &str,
        resource_status: CloudFormationResourceStatus,
        timestamp: DateTime<Utc>,
        status_reason: Option<&str>,
    ) -> Result<Self> {
        let event_id_digest = Digest::from_parts(
            "aws-cloudformation-event-id/v1",
            &[("event_id", event_id.to_owned())],
        );
        let logical_resource_id_digest = Digest::from_parts(
            "aws-cloudformation-logical-resource-id/v1",
            &[("logical_id", logical_resource_id.to_owned())],
        );
        let resource_type_digest = Digest::from_parts(
            "aws-cloudformation-resource-type/v1",
            &[("resource_type", resource_type.to_owned())],
        );
        let status_reason_digest = status_reason
            .map(|value| {
                if valid_text(value, 1_024, true) {
                    Ok(Digest::from_parts(
                        "aws-cloudformation-event-status-reason/v1",
                        &[("reason", value.to_owned())],
                    ))
                } else {
                    Err(AwsCloudFormationDriftError::InvalidText {
                        field: "event status reason",
                    })
                }
            })
            .transpose()?;
        let mut event = Self {
            stack_digest: scope.stack.digest(),
            stack_revision: scope.stack_revision,
            event_digest: Digest::from_text("unsealed-cloudformation-event"),
            event_id_digest,
            logical_resource_id_digest,
            resource_type_digest,
            resource_status,
            timestamp,
            status_reason_digest,
        };
        event.event_digest = event.recomputed_digest();
        Ok(event)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            &self.stack_digest,
            self.stack_revision,
            &self.event_id_digest,
            &self.logical_resource_id_digest,
            &self.resource_type_digest,
            self.resource_status,
            self.timestamp,
            &self.status_reason_digest,
        ))
    }

    pub fn validate_against(&self, scope: &AwsCloudFormationDriftScope) -> Result<()> {
        if self.stack_digest != scope.stack.digest()
            || self.stack_revision != scope.stack_revision
            || self.event_digest != self.recomputed_digest()
        {
            return Err(AwsCloudFormationDriftError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceDrift {
    pub stack_digest: Digest,
    pub stack_revision: u64,
    pub resource_digest: Digest,
    pub logical_resource_id_digest: Digest,
    pub physical_resource_id_digest: Option<Digest>,
    pub resource_type_digest: Digest,
    pub status: ResourceDriftStatus,
    pub timestamp: DateTime<Utc>,
    pub property_difference_count: u16,
    pub property_difference_digest: Option<Digest>,
    pub drift_digest: Digest,
}

impl ResourceDrift {
    pub fn new(
        scope: &AwsCloudFormationDriftScope,
        logical_resource_id: &str,
        physical_resource_id: Option<&str>,
        resource_type: &str,
        status: ResourceDriftStatus,
        timestamp: DateTime<Utc>,
        property_difference_count: u16,
        property_difference_digest: Option<Digest>,
    ) -> Result<Self> {
        if !valid_text(logical_resource_id, 255, false)
            || !valid_text(resource_type, 256, false)
            || physical_resource_id.is_some_and(|value| !valid_text(value, 2_048, false))
        {
            return Err(AwsCloudFormationDriftError::InvalidIdentifier {
                field: "resource drift identifier",
            });
        }
        if let Some(digest) = &property_difference_digest {
            digest.validate()?;
        }
        let logical_resource_id_digest = Digest::from_parts(
            "aws-cloudformation-logical-resource-id/v1",
            &[("logical_id", logical_resource_id.to_owned())],
        );
        let physical_resource_id_digest = physical_resource_id.map(|value| {
            Digest::from_parts(
                "aws-cloudformation-physical-resource-id/v1",
                &[("physical_id", value.to_owned())],
            )
        });
        let resource_type_digest = Digest::from_parts(
            "aws-cloudformation-resource-type/v1",
            &[("resource_type", resource_type.to_owned())],
        );
        let resource_digest = Digest::from_parts(
            "aws-cloudformation-resource-drift-resource/v1",
            &[
                ("logical", logical_resource_id_digest.to_string()),
                (
                    "physical",
                    physical_resource_id_digest
                        .as_ref()
                        .map_or_else(String::new, ToString::to_string),
                ),
                ("type", resource_type_digest.to_string()),
            ],
        );
        let mut drift = Self {
            stack_digest: scope.stack.digest(),
            stack_revision: scope.stack_revision,
            resource_digest,
            logical_resource_id_digest,
            physical_resource_id_digest,
            resource_type_digest,
            status,
            timestamp,
            property_difference_count,
            property_difference_digest,
            drift_digest: Digest::from_text("unsealed-cloudformation-resource-drift"),
        };
        drift.drift_digest = drift.recomputed_digest();
        Ok(drift)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            &self.stack_digest,
            self.stack_revision,
            &self.resource_digest,
            &self.logical_resource_id_digest,
            &self.physical_resource_id_digest,
            &self.resource_type_digest,
            self.status,
            self.timestamp,
            self.property_difference_count,
            &self.property_difference_digest,
        ))
    }

    pub fn validate_against(&self, scope: &AwsCloudFormationDriftScope) -> Result<()> {
        if self.stack_digest != scope.stack.digest()
            || self.stack_revision != scope.stack_revision
            || self.drift_digest != self.recomputed_digest()
        {
            return Err(AwsCloudFormationDriftError::StackRevisionDrift);
        }
        self.property_difference_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DriftDetectionProgress {
    pub detection_id_digest: Digest,
    pub status: DriftDetectionStatus,
    pub stack_drift_status: Option<StackDriftStatus>,
    pub drifted_resource_count: Option<u32>,
    pub status_reason_digest: Option<Digest>,
    pub started_at: DateTime<Utc>,
    pub last_observed_at: DateTime<Utc>,
    pub polls_observed: u16,
    pub progress_digest: Digest,
}

impl DriftDetectionProgress {
    pub fn new(
        detection_id: &StackDriftDetectionId,
        status: DriftDetectionStatus,
        stack_drift_status: Option<StackDriftStatus>,
        drifted_resource_count: Option<u32>,
        status_reason_digest: Option<Digest>,
        started_at: DateTime<Utc>,
        last_observed_at: DateTime<Utc>,
        polls_observed: u16,
    ) -> Result<Self> {
        if let Some(digest) = &status_reason_digest {
            digest.validate()?;
        }
        let mut progress = Self {
            detection_id_digest: detection_id.digest(),
            status,
            stack_drift_status,
            drifted_resource_count,
            status_reason_digest,
            started_at,
            last_observed_at,
            polls_observed,
            progress_digest: Digest::from_text("unsealed-cloudformation-drift-progress"),
        };
        progress.progress_digest = progress.recomputed_digest();
        Ok(progress)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            &self.detection_id_digest,
            self.status,
            self.stack_drift_status,
            self.drifted_resource_count,
            &self.status_reason_digest,
            self.started_at,
            self.last_observed_at,
            self.polls_observed,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeStacksRequest {
    pub scope_digest: Digest,
    pub stack: StackName,
    pub stack_revision: u64,
    pub page_size: u16,
    pub max_pages: u16,
    pub max_response_bytes: usize,
    pub cursor: Option<OpaqueCursor>,
}

impl DescribeStacksRequest {
    pub fn new(
        scope: &AwsCloudFormationDriftScope,
        page_size: u16,
        max_pages: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self> {
        let mut request = Self {
            scope_digest: scope.digest(),
            stack: scope.stack.clone(),
            stack_revision: scope.stack_revision,
            page_size,
            max_pages,
            max_response_bytes: MAX_RESPONSE_BYTES_USIZE,
            cursor: None,
        };
        request.validate_bounds()?;
        request.cursor = request.bind_cursor(cursor)?;
        Ok(request)
    }

    fn validate_bounds(&self) -> Result<()> {
        if self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES_USIZE
            || self.stack_revision == 0
        {
            return Err(AwsCloudFormationDriftError::InvalidRequest);
        }
        Ok(())
    }

    pub fn query_digest(&self) -> Digest {
        digest_serialized(&(
            CloudFormationOperation::DescribeStacks,
            &self.scope_digest,
            &self.stack,
            self.stack_revision,
            self.page_size,
            self.max_pages,
            self.max_response_bytes,
        ))
    }

    pub fn request_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cloudformation-describe-stacks-request/v1",
            &[
                ("query", self.query_digest().to_string()),
                (
                    "cursor",
                    self.cursor
                        .as_ref()
                        .map_or_else(String::new, |value| value.token_digest().to_string()),
                ),
            ],
        )
    }

    pub fn page_number(&self) -> u16 {
        self.cursor.as_ref().map_or(1, OpaqueCursor::page_number)
    }

    pub fn with_cursor(&self, cursor: Option<OpaqueCursor>) -> Result<Self> {
        let mut next = self.clone();
        next.cursor = next.bind_cursor(cursor)?;
        Ok(next)
    }

    fn bind_cursor(&self, cursor: Option<OpaqueCursor>) -> Result<Option<OpaqueCursor>> {
        let Some(cursor) = cursor else {
            return Ok(None);
        };
        let next_page = if cursor.page_number() == 0 {
            self.page_number().saturating_add(1)
        } else {
            cursor.page_number()
        };
        if let Some(binding) = cursor.binding_digest()
            && binding != &self.query_digest()
        {
            return Err(AwsCloudFormationDriftError::CursorMismatch);
        }
        Ok(Some(cursor.bind(&self.query_digest(), next_page)))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeStackEventsRequest {
    pub scope_digest: Digest,
    pub stack: StackName,
    pub stack_revision: u64,
    pub page_size: u16,
    pub max_pages: u16,
    pub max_response_bytes: usize,
    pub cursor: Option<OpaqueCursor>,
}

impl DescribeStackEventsRequest {
    pub fn new(
        scope: &AwsCloudFormationDriftScope,
        page_size: u16,
        max_pages: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self> {
        let mut request = Self {
            scope_digest: scope.digest(),
            stack: scope.stack.clone(),
            stack_revision: scope.stack_revision,
            page_size,
            max_pages,
            max_response_bytes: MAX_RESPONSE_BYTES_USIZE,
            cursor: None,
        };
        request.validate_bounds()?;
        request.cursor = request.bind_cursor(cursor)?;
        Ok(request)
    }

    fn validate_bounds(&self) -> Result<()> {
        if self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES_USIZE
            || self.stack_revision == 0
        {
            return Err(AwsCloudFormationDriftError::InvalidRequest);
        }
        Ok(())
    }

    pub fn query_digest(&self) -> Digest {
        digest_serialized(&(
            CloudFormationOperation::DescribeStackEvents,
            &self.scope_digest,
            &self.stack,
            self.stack_revision,
            self.page_size,
            self.max_pages,
            self.max_response_bytes,
        ))
    }

    pub fn request_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cloudformation-describe-stack-events-request/v1",
            &[
                ("query", self.query_digest().to_string()),
                (
                    "cursor",
                    self.cursor
                        .as_ref()
                        .map_or_else(String::new, |value| value.token_digest().to_string()),
                ),
            ],
        )
    }

    pub fn page_number(&self) -> u16 {
        self.cursor.as_ref().map_or(1, OpaqueCursor::page_number)
    }

    pub fn with_cursor(&self, cursor: Option<OpaqueCursor>) -> Result<Self> {
        let mut next = self.clone();
        next.cursor = next.bind_cursor(cursor)?;
        Ok(next)
    }

    fn bind_cursor(&self, cursor: Option<OpaqueCursor>) -> Result<Option<OpaqueCursor>> {
        let Some(cursor) = cursor else {
            return Ok(None);
        };
        let next_page = if cursor.page_number() == 0 {
            self.page_number().saturating_add(1)
        } else {
            cursor.page_number()
        };
        if let Some(binding) = cursor.binding_digest()
            && binding != &self.query_digest()
        {
            return Err(AwsCloudFormationDriftError::CursorMismatch);
        }
        Ok(Some(cursor.bind(&self.query_digest(), next_page)))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectStackDriftRequest {
    pub scope_digest: Digest,
    pub stack: StackName,
    pub stack_revision: u64,
    pub logical_resource_ids: Vec<LogicalResourceId>,
}

impl DetectStackDriftRequest {
    pub fn new(
        scope: &AwsCloudFormationDriftScope,
        logical_resource_ids: impl IntoIterator<Item = LogicalResourceId>,
    ) -> Result<Self> {
        let logical_resource_ids = logical_resource_ids.into_iter().collect::<Vec<_>>();
        if logical_resource_ids.len() > MAX_LOGICAL_RESOURCE_IDS {
            return Err(AwsCloudFormationDriftError::InvalidRequest);
        }
        let mut seen = BTreeSet::new();
        for logical_id in &logical_resource_ids {
            if !seen.insert(logical_id.digest()) {
                return Err(AwsCloudFormationDriftError::InvalidRequest);
            }
        }
        Ok(Self {
            scope_digest: scope.digest(),
            stack: scope.stack.clone(),
            stack_revision: scope.stack_revision,
            logical_resource_ids,
        })
    }

    pub fn request_digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeStackDriftDetectionStatusRequest {
    pub scope_digest: Digest,
    pub stack: StackName,
    pub stack_revision: u64,
    pub detection_id: StackDriftDetectionId,
}

impl DescribeStackDriftDetectionStatusRequest {
    pub fn new(
        scope: &AwsCloudFormationDriftScope,
        detection_id: StackDriftDetectionId,
    ) -> Result<Self> {
        Ok(Self {
            scope_digest: scope.digest(),
            stack: scope.stack.clone(),
            stack_revision: scope.stack_revision,
            detection_id,
        })
    }

    pub fn request_digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeStackResourceDriftsRequest {
    pub scope_digest: Digest,
    pub stack: StackName,
    pub stack_revision: u64,
    pub filter: ResourceDriftFilter,
    pub page_size: u16,
    pub max_pages: u16,
    pub max_response_bytes: usize,
    pub cursor: Option<OpaqueCursor>,
}

impl DescribeStackResourceDriftsRequest {
    pub fn new(
        scope: &AwsCloudFormationDriftScope,
        filter: ResourceDriftFilter,
        page_size: u16,
        max_pages: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self> {
        let mut request = Self {
            scope_digest: scope.digest(),
            stack: scope.stack.clone(),
            stack_revision: scope.stack_revision,
            filter,
            page_size,
            max_pages,
            max_response_bytes: MAX_RESPONSE_BYTES_USIZE,
            cursor: None,
        };
        request.validate_bounds()?;
        request.cursor = request.bind_cursor(cursor)?;
        Ok(request)
    }

    fn validate_bounds(&self) -> Result<()> {
        if self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES_USIZE
            || self.stack_revision == 0
        {
            return Err(AwsCloudFormationDriftError::InvalidRequest);
        }
        Ok(())
    }

    pub fn query_digest(&self) -> Digest {
        digest_serialized(&(
            CloudFormationOperation::DescribeStackResourceDrifts,
            &self.scope_digest,
            &self.stack,
            self.stack_revision,
            &self.filter,
            self.page_size,
            self.max_pages,
            self.max_response_bytes,
        ))
    }

    pub fn request_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cloudformation-describe-stack-resource-drifts-request/v1",
            &[
                ("query", self.query_digest().to_string()),
                (
                    "cursor",
                    self.cursor
                        .as_ref()
                        .map_or_else(String::new, |value| value.token_digest().to_string()),
                ),
            ],
        )
    }

    pub fn page_number(&self) -> u16 {
        self.cursor.as_ref().map_or(1, OpaqueCursor::page_number)
    }

    pub fn with_cursor(&self, cursor: Option<OpaqueCursor>) -> Result<Self> {
        let mut next = self.clone();
        next.cursor = next.bind_cursor(cursor)?;
        Ok(next)
    }

    fn bind_cursor(&self, cursor: Option<OpaqueCursor>) -> Result<Option<OpaqueCursor>> {
        let Some(cursor) = cursor else {
            return Ok(None);
        };
        let next_page = if cursor.page_number() == 0 {
            self.page_number().saturating_add(1)
        } else {
            cursor.page_number()
        };
        if let Some(binding) = cursor.binding_digest()
            && binding != &self.query_digest()
        {
            return Err(AwsCloudFormationDriftError::CursorMismatch);
        }
        Ok(Some(cursor.bind(&self.query_digest(), next_page)))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeStacksResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub stacks: Vec<StackSummary>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl DescribeStacksResponse {
    pub fn new(
        request: &DescribeStacksRequest,
        stacks: Vec<StackSummary>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if stacks.len() > MAX_PAGE_SIZE as usize {
            return Err(AwsCloudFormationDriftError::InvalidRequest);
        }
        for stack in &stacks {
            stack.validate_against_scope_digest(
                &request.scope_digest,
                &request.stack.digest(),
                request.stack_revision,
            )?;
        }
        validate_next_cursor(
            request.page_number(),
            request.query_digest(),
            next_cursor.as_ref(),
        )?;
        let mut response = Self {
            scope_digest: request.scope_digest.clone(),
            request_digest: request.request_digest(),
            page_number: request.page_number(),
            stacks,
            next_cursor,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-cloudformation-describe-stacks"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.recomputed_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.evidence_digest = digest;
        self
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            &self.scope_digest,
            &self.request_digest,
            self.page_number,
            &self.stacks,
            &self.next_cursor,
            self.response_bytes,
            self.provenance,
        ))
    }

    pub fn validate_integrity(&self, request: &DescribeStacksRequest) -> Result<()> {
        if self.scope_digest != request.scope_digest
            || self.request_digest != request.request_digest()
            || self.page_number != request.page_number()
            || self.evidence_digest != self.recomputed_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
        {
            return Err(AwsCloudFormationDriftError::TamperedEvidence);
        }
        for stack in &self.stacks {
            stack.validate_against_scope_digest(
                &request.scope_digest,
                &request.stack.digest(),
                request.stack_revision,
            )?;
        }
        validate_next_cursor(
            request.page_number(),
            request.query_digest(),
            self.next_cursor.as_ref(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeStackEventsResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub events: Vec<StackEvent>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl DescribeStackEventsResponse {
    pub fn new(
        request: &DescribeStackEventsRequest,
        events: Vec<StackEvent>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if events.len() > MAX_EVENTS {
            return Err(AwsCloudFormationDriftError::InvalidRequest);
        }
        for event in &events {
            event.validate_against_scope_digest(
                &request.scope_digest,
                &request.stack.digest(),
                request.stack_revision,
            )?;
        }
        validate_next_cursor(
            request.page_number(),
            request.query_digest(),
            next_cursor.as_ref(),
        )?;
        let mut response = Self {
            scope_digest: request.scope_digest.clone(),
            request_digest: request.request_digest(),
            page_number: request.page_number(),
            events,
            next_cursor,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-cloudformation-describe-stack-events"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.recomputed_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.evidence_digest = digest;
        self
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            &self.scope_digest,
            &self.request_digest,
            self.page_number,
            &self.events,
            &self.next_cursor,
            self.response_bytes,
            self.provenance,
        ))
    }

    pub fn validate_integrity(&self, request: &DescribeStackEventsRequest) -> Result<()> {
        if self.scope_digest != request.scope_digest
            || self.request_digest != request.request_digest()
            || self.page_number != request.page_number()
            || self.evidence_digest != self.recomputed_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
        {
            return Err(AwsCloudFormationDriftError::TamperedEvidence);
        }
        for event in &self.events {
            event.validate_against_scope_digest(
                &request.scope_digest,
                &request.stack.digest(),
                request.stack_revision,
            )?;
        }
        validate_next_cursor(
            request.page_number(),
            request.query_digest(),
            self.next_cursor.as_ref(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectStackDriftResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub detection_id: StackDriftDetectionId,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl DetectStackDriftResponse {
    pub fn new(
        request: &DetectStackDriftRequest,
        detection_id: StackDriftDetectionId,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        let mut response = Self {
            scope_digest: request.scope_digest.clone(),
            request_digest: request.request_digest(),
            detection_id,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-cloudformation-detect-stack-drift"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.recomputed_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.evidence_digest = digest;
        self
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            &self.scope_digest,
            &self.request_digest,
            &self.detection_id,
            self.response_bytes,
            self.provenance,
        ))
    }

    pub fn validate_integrity(&self, request: &DetectStackDriftRequest) -> Result<()> {
        if self.scope_digest != request.scope_digest
            || self.request_digest != request.request_digest()
            || self.evidence_digest != self.recomputed_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
        {
            return Err(AwsCloudFormationDriftError::TamperedEvidence);
        }
        self.detection_id.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeStackDriftDetectionStatusResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub stack_digest: Digest,
    pub stack_revision: u64,
    pub detection_id: StackDriftDetectionId,
    pub status: DriftDetectionStatus,
    pub status_reason_digest: Option<Digest>,
    pub drifted_resource_count: Option<u32>,
    pub stack_drift_status: Option<StackDriftStatus>,
    pub timestamp: DateTime<Utc>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl DescribeStackDriftDetectionStatusResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &DescribeStackDriftDetectionStatusRequest,
        status: DriftDetectionStatus,
        status_reason: Option<&str>,
        drifted_resource_count: Option<u32>,
        stack_drift_status: Option<StackDriftStatus>,
        timestamp: DateTime<Utc>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        let status_reason_digest = status_reason
            .map(|value| {
                if valid_text(value, 1_024, true) {
                    Ok(Digest::from_parts(
                        "aws-cloudformation-detection-status-reason/v1",
                        &[("reason", value.to_owned())],
                    ))
                } else {
                    Err(AwsCloudFormationDriftError::InvalidText {
                        field: "detection status reason",
                    })
                }
            })
            .transpose()?;
        let mut response = Self {
            scope_digest: request.scope_digest.clone(),
            request_digest: request.request_digest(),
            stack_digest: request.stack.digest(),
            stack_revision: request.stack_revision,
            detection_id: request.detection_id.clone(),
            status,
            status_reason_digest,
            drifted_resource_count,
            stack_drift_status,
            timestamp,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-cloudformation-detection-status"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.recomputed_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.evidence_digest = digest;
        self
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            &self.scope_digest,
            &self.request_digest,
            &self.stack_digest,
            self.stack_revision,
            &self.detection_id,
            self.status,
            &self.status_reason_digest,
            self.drifted_resource_count,
            self.stack_drift_status,
            self.timestamp,
            self.response_bytes,
            self.provenance,
        ))
    }

    pub fn validate_integrity(
        &self,
        request: &DescribeStackDriftDetectionStatusRequest,
    ) -> Result<()> {
        if self.scope_digest != request.scope_digest
            || self.request_digest != request.request_digest()
            || self.stack_digest != request.stack.digest()
            || self.stack_revision != request.stack_revision
            || self.detection_id != request.detection_id
            || self.evidence_digest != self.recomputed_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
        {
            return Err(AwsCloudFormationDriftError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeStackResourceDriftsResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub resources: Vec<ResourceDrift>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl DescribeStackResourceDriftsResponse {
    pub fn new(
        request: &DescribeStackResourceDriftsRequest,
        resources: Vec<ResourceDrift>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if resources.len() > MAX_RESOURCES {
            return Err(AwsCloudFormationDriftError::InvalidRequest);
        }
        for resource in &resources {
            resource.validate_against_request(request)?;
        }
        validate_next_cursor(
            request.page_number(),
            request.query_digest(),
            next_cursor.as_ref(),
        )?;
        let mut response = Self {
            scope_digest: request.scope_digest.clone(),
            request_digest: request.request_digest(),
            page_number: request.page_number(),
            resources,
            next_cursor,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-cloudformation-resource-drifts"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.recomputed_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.evidence_digest = digest;
        self
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            &self.scope_digest,
            &self.request_digest,
            self.page_number,
            &self.resources,
            &self.next_cursor,
            self.response_bytes,
            self.provenance,
        ))
    }

    pub fn validate_integrity(&self, request: &DescribeStackResourceDriftsRequest) -> Result<()> {
        if self.scope_digest != request.scope_digest
            || self.request_digest != request.request_digest()
            || self.page_number != request.page_number()
            || self.evidence_digest != self.recomputed_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
        {
            return Err(AwsCloudFormationDriftError::TamperedEvidence);
        }
        for resource in &self.resources {
            resource.validate_against_request(request)?;
        }
        validate_next_cursor(
            request.page_number(),
            request.query_digest(),
            self.next_cursor.as_ref(),
        )
    }
}

fn validate_response_bytes(response_bytes: u64) -> Result<()> {
    if response_bytes == 0 || response_bytes > MAX_RESPONSE_BYTES {
        Err(AwsCloudFormationDriftError::InvalidRequest)
    } else {
        Ok(())
    }
}

fn validate_next_cursor(
    page_number: u16,
    query_digest: Digest,
    cursor: Option<&OpaqueCursor>,
) -> Result<()> {
    if let Some(cursor) = cursor
        && (cursor.binding_digest() != Some(&query_digest)
            || cursor.page_number() != page_number.saturating_add(1))
    {
        return Err(AwsCloudFormationDriftError::CursorMismatch);
    }
    Ok(())
}

impl StackSummary {
    fn validate_against_scope_digest(
        &self,
        scope_digest: &Digest,
        stack_digest: &Digest,
        stack_revision: u64,
    ) -> Result<()> {
        if self.stack_digest != *stack_digest
            || self.stack_revision != stack_revision
            || self.summary_digest != self.recomputed_digest()
        {
            return Err(AwsCloudFormationDriftError::StackRevisionDrift);
        }
        if *scope_digest == Digest::zero() {
            return Err(AwsCloudFormationDriftError::ScopeMismatch);
        }
        Ok(())
    }
}

impl StackEvent {
    fn validate_against_scope_digest(
        &self,
        scope_digest: &Digest,
        stack_digest: &Digest,
        stack_revision: u64,
    ) -> Result<()> {
        if self.stack_digest != *stack_digest
            || self.stack_revision != stack_revision
            || self.event_digest != self.recomputed_digest()
        {
            return Err(AwsCloudFormationDriftError::TamperedEvidence);
        }
        if *scope_digest == Digest::zero() {
            return Err(AwsCloudFormationDriftError::ScopeMismatch);
        }
        Ok(())
    }
}

impl ResourceDrift {
    fn validate_against_request(&self, request: &DescribeStackResourceDriftsRequest) -> Result<()> {
        if self.stack_digest != request.stack.digest()
            || self.stack_revision != request.stack_revision
            || self.drift_digest != self.recomputed_digest()
            || !request.filter.allows(self.status)
        {
            return Err(AwsCloudFormationDriftError::StackRevisionDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudFormationEvidenceState {
    Completed,
    InProgress,
    Partial,
    AccessLoss,
    Throttled,
    ProviderUnknown,
    NotFound,
    RegistrationRevoked,
}

impl CloudFormationEvidenceState {
    pub const fn is_non_adoptable(self) -> bool {
        !matches!(self, Self::Completed)
    }

    pub const fn is_review_complete(self) -> bool {
        matches!(self, Self::Completed)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub stack_digest: Option<Digest>,
    pub event_digest: Option<Digest>,
    pub detection_digest: Option<Digest>,
    pub resource_drift_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudFormationDriftEvidence {
    pub state: CloudFormationEvidenceState,
    pub stack_revision: u64,
    pub stack: Option<StackSummary>,
    pub events: Vec<StackEvent>,
    pub detection: Option<DriftDetectionProgress>,
    pub resource_drifts: Vec<ResourceDrift>,
    pub stacks_pages: u16,
    pub events_pages: u16,
    pub resource_pages: u16,
    pub polls_observed: u16,
    pub complete: bool,
    pub truncated: bool,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub raw_templates_retained: bool,
    pub raw_properties_retained: bool,
    pub remediation_available: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderErrorEvidence {
    pub operation: CloudFormationOperation,
    pub status_code: Option<u16>,
    pub category: String,
    pub failure_digest: Digest,
}

impl ProviderErrorEvidence {
    pub fn new(
        operation: CloudFormationOperation,
        status_code: Option<u16>,
        category: impl Into<String>,
    ) -> Self {
        let category = category.into();
        let failure_digest = Digest::from_parts(
            "aws-cloudformation-provider-failure/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                (
                    "status",
                    status_code.map_or_else(String::new, |value| value.to_string()),
                ),
                ("category", category.clone()),
            ],
        );
        Self {
            operation,
            status_code,
            category,
            failure_digest,
        }
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cloudformation-provider-failure/v1",
            &[
                ("operation", self.operation.as_str().to_owned()),
                (
                    "status",
                    self.status_code
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                ("category", self.category.clone()),
            ],
        )
    }
}

fn aggregate_event_digest(events: &[StackEvent]) -> Option<Digest> {
    if events.is_empty() {
        None
    } else {
        Some(Digest::from_parts(
            "aws-cloudformation-events/v1",
            &[(
                "events",
                events
                    .iter()
                    .map(|event| event.event_digest.to_string())
                    .collect::<Vec<_>>()
                    .join("\n"),
            )],
        ))
    }
}

fn aggregate_resource_drift_digest(resources: &[ResourceDrift]) -> Option<Digest> {
    if resources.is_empty() {
        None
    } else {
        Some(Digest::from_parts(
            "aws-cloudformation-resource-drifts/v1",
            &[(
                "resources",
                resources
                    .iter()
                    .map(|resource| resource.drift_digest.to_string())
                    .collect::<Vec<_>>()
                    .join("\n"),
            )],
        ))
    }
}

impl CloudFormationDriftEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state: CloudFormationEvidenceState,
        stack_revision: u64,
        stack: Option<StackSummary>,
        events: Vec<StackEvent>,
        detection: Option<DriftDetectionProgress>,
        resource_drifts: Vec<ResourceDrift>,
        stacks_pages: u16,
        events_pages: u16,
        resource_pages: u16,
        polls_observed: u16,
        complete: bool,
        truncated: bool,
        provider_errors: Vec<ProviderErrorEvidence>,
        provider_digest: Digest,
        api_digest: Digest,
        permission_digest: Digest,
        consent_digest: Digest,
        scope_digest: Digest,
        request_digest: Digest,
        cursor_digest: Option<Digest>,
        provenance: TransportProvenance,
    ) -> Self {
        let stack_digest = stack.as_ref().map(StackSummary::digest);
        let event_digest = aggregate_event_digest(&events);
        let detection_digest = detection
            .as_ref()
            .map(|value| value.progress_digest.clone());
        let resource_drift_digest = aggregate_resource_drift_digest(&resource_drifts);
        let evidence = EvidenceDigests {
            plugin_version_digest: Digest::from_text(crate::PLUGIN_VERSION),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())
                .unwrap_or_else(|_| Digest::zero()),
            provider_digest,
            api_digest,
            permission_digest,
            consent_digest,
            scope_digest,
            request_digest,
            cursor_digest,
            stack_digest,
            event_digest,
            detection_digest,
            resource_drift_digest,
            evidence_digest: Digest::from_text("unsealed-cloudformation-evidence"),
        };
        let mut result = Self {
            state,
            stack_revision,
            stack,
            events,
            detection,
            resource_drifts,
            stacks_pages,
            events_pages,
            resource_pages,
            polls_observed,
            complete,
            truncated,
            provider_errors,
            evidence,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            raw_templates_retained: false,
            raw_properties_retained: false,
            remediation_available: false,
        };
        result.evidence.evidence_digest = result.recomputed_evidence_digest();
        result
    }

    pub fn recomputed_evidence_digest(&self) -> Digest {
        let evidence = &self.evidence;
        Digest::from_parts(
            "aws-cloudformation-evidence/v1",
            &[
                ("state", format!("{:?}", self.state)),
                ("stack_revision", self.stack_revision.to_string()),
                ("plugin_version", evidence.plugin_version_digest.to_string()),
                ("contract", evidence.contract_digest.to_string()),
                ("provider", evidence.provider_digest.to_string()),
                ("api", evidence.api_digest.to_string()),
                ("permission", evidence.permission_digest.to_string()),
                ("consent", evidence.consent_digest.to_string()),
                ("scope", evidence.scope_digest.to_string()),
                ("request", evidence.request_digest.to_string()),
                (
                    "cursor",
                    evidence
                        .cursor_digest
                        .as_ref()
                        .map_or_else(String::new, ToString::to_string),
                ),
                (
                    "stack",
                    evidence
                        .stack_digest
                        .as_ref()
                        .map_or_else(String::new, ToString::to_string),
                ),
                (
                    "events",
                    evidence
                        .event_digest
                        .as_ref()
                        .map_or_else(String::new, ToString::to_string),
                ),
                (
                    "detection",
                    evidence
                        .detection_digest
                        .as_ref()
                        .map_or_else(String::new, ToString::to_string),
                ),
                (
                    "resource_drifts",
                    evidence
                        .resource_drift_digest
                        .as_ref()
                        .map_or_else(String::new, ToString::to_string),
                ),
                ("stacks_pages", self.stacks_pages.to_string()),
                ("events_pages", self.events_pages.to_string()),
                ("resource_pages", self.resource_pages.to_string()),
                ("polls", self.polls_observed.to_string()),
                ("complete", self.complete.to_string()),
                ("truncated", self.truncated.to_string()),
                (
                    "provider_errors",
                    self.provider_errors
                        .iter()
                        .map(|error| error.failure_digest.to_string())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.raw_templates_retained
            || self.raw_properties_retained
            || self.remediation_available
            || self.evidence.plugin_version_digest != Digest::from_text(crate::PLUGIN_VERSION)
            || self.evidence.contract_digest.as_str() != CONTRACT_DIGEST
            || self.evidence.api_digest != crate::api_digest()
        {
            return Err(AwsCloudFormationDriftError::TamperedEvidence);
        }
        self.evidence.contract_digest.validate()?;
        self.evidence.plugin_version_digest.validate()?;
        self.evidence.provider_digest.validate()?;
        self.evidence.api_digest.validate()?;
        self.evidence.permission_digest.validate()?;
        self.evidence.consent_digest.validate()?;
        self.evidence.scope_digest.validate()?;
        self.evidence.request_digest.validate()?;
        self.evidence
            .cursor_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        if self.evidence.stack_digest != self.stack.as_ref().map(StackSummary::digest)
            || self.evidence.event_digest != aggregate_event_digest(&self.events)
            || self.evidence.detection_digest
                != self
                    .detection
                    .as_ref()
                    .map(|value| value.progress_digest.clone())
            || self.evidence.resource_drift_digest
                != aggregate_resource_drift_digest(&self.resource_drifts)
        {
            return Err(AwsCloudFormationDriftError::TamperedEvidence);
        }
        if let Some(stack) = &self.stack {
            if stack.stack_revision != self.stack_revision
                || stack.summary_digest != stack.recomputed_digest()
            {
                return Err(AwsCloudFormationDriftError::StackRevisionDrift);
            }
            stack.stack_digest.validate()?;
            stack.summary_digest.validate()?;
            stack
                .status_reason_digest
                .as_ref()
                .map(Digest::validate)
                .transpose()?;
        }
        for event in &self.events {
            if event.stack_revision != self.stack_revision
                || event.event_digest != event.recomputed_digest()
            {
                return Err(AwsCloudFormationDriftError::TamperedEvidence);
            }
            if let Some(stack) = &self.stack
                && event.stack_digest != stack.stack_digest
            {
                return Err(AwsCloudFormationDriftError::StackRevisionDrift);
            }
            event.stack_digest.validate()?;
            event.event_digest.validate()?;
            event.event_id_digest.validate()?;
            event.logical_resource_id_digest.validate()?;
            event.resource_type_digest.validate()?;
            event
                .status_reason_digest
                .as_ref()
                .map(Digest::validate)
                .transpose()?;
        }
        if let Some(detection) = &self.detection {
            if detection.progress_digest != detection.recomputed_digest() {
                return Err(AwsCloudFormationDriftError::TamperedEvidence);
            }
            detection.detection_id_digest.validate()?;
            detection.progress_digest.validate()?;
            detection
                .status_reason_digest
                .as_ref()
                .map(Digest::validate)
                .transpose()?;
        }
        for resource in &self.resource_drifts {
            if resource.stack_revision != self.stack_revision
                || resource.drift_digest != resource.recomputed_digest()
            {
                return Err(AwsCloudFormationDriftError::TamperedEvidence);
            }
            if let Some(stack) = &self.stack
                && resource.stack_digest != stack.stack_digest
            {
                return Err(AwsCloudFormationDriftError::StackRevisionDrift);
            }
            resource.stack_digest.validate()?;
            resource.resource_digest.validate()?;
            resource.logical_resource_id_digest.validate()?;
            resource
                .physical_resource_id_digest
                .as_ref()
                .map(Digest::validate)
                .transpose()?;
            resource.resource_type_digest.validate()?;
            resource.drift_digest.validate()?;
            resource
                .property_difference_digest
                .as_ref()
                .map(Digest::validate)
                .transpose()?;
        }
        for provider_error in &self.provider_errors {
            if provider_error.failure_digest != provider_error.recomputed_digest() {
                return Err(AwsCloudFormationDriftError::TamperedEvidence);
            }
            provider_error.failure_digest.validate()?;
        }
        if self.evidence.evidence_digest == Digest::zero()
            || self.evidence.evidence_digest != self.recomputed_evidence_digest()
        {
            return Err(AwsCloudFormationDriftError::TamperedEvidence);
        }
        Ok(())
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

pub type AwsCloudFormationStackScope = AwsCloudFormationDriftScope;
pub type CloudFormationDriftScope = AwsCloudFormationDriftScope;
pub type StackNameOrId = StackName;
pub type DetectionId = StackDriftDetectionId;
pub type OpaquePageToken = OpaqueCursor;
pub type AwsCloudFormationReadRequest = CloudFormationEvidenceRequest;
pub type AwsCloudFormationDriftRequest = CloudFormationEvidenceRequest;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudFormationEvidenceRequest {
    pub scope_digest: Digest,
    pub expected_provider_digest: Digest,
    pub expected_registration_digest: Digest,
    pub logical_resource_ids: Vec<LogicalResourceId>,
    pub resource_filter: ResourceDriftFilter,
    pub page_size: u16,
    pub max_pages: u16,
    pub max_polls: u16,
    pub max_retries: u8,
    pub observed_at: DateTime<Utc>,
}

impl CloudFormationEvidenceRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &AwsCloudFormationDriftScope,
        expected_provider_digest: Digest,
        expected_registration_digest: Digest,
        logical_resource_ids: impl IntoIterator<Item = LogicalResourceId>,
        resource_filter: ResourceDriftFilter,
        page_size: u16,
        max_pages: u16,
        max_polls: u16,
        max_retries: u8,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        let logical_resource_ids = logical_resource_ids.into_iter().collect::<Vec<_>>();
        if logical_resource_ids.len() > MAX_LOGICAL_RESOURCE_IDS
            || page_size == 0
            || page_size > MAX_PAGE_SIZE
            || max_pages == 0
            || max_pages > MAX_PAGES
            || max_polls == 0
            || max_polls > MAX_POLLS
            || max_retries > crate::MAX_RETRIES
        {
            return Err(AwsCloudFormationDriftError::InvalidRequest);
        }
        expected_provider_digest.validate()?;
        expected_registration_digest.validate()?;
        Ok(Self {
            scope_digest: scope.digest(),
            expected_provider_digest,
            expected_registration_digest,
            logical_resource_ids,
            resource_filter,
            page_size,
            max_pages,
            max_polls,
            max_retries,
            observed_at,
        })
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }

    pub fn validate_against(
        &self,
        scope: &AwsCloudFormationDriftScope,
        provider_digest: &Digest,
        registration_digest: &Digest,
    ) -> Result<()> {
        if self.logical_resource_ids.len() > MAX_LOGICAL_RESOURCE_IDS
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.max_polls == 0
            || self.max_polls > MAX_POLLS
            || self.max_retries > crate::MAX_RETRIES
            || self.scope_digest != scope.digest()
            || &self.expected_provider_digest != provider_digest
            || &self.expected_registration_digest != registration_digest
        {
            return Err(AwsCloudFormationDriftError::ScopeMismatch);
        }
        Ok(())
    }
}

// Keep the API names used by adjacent AWS Layer-1 slices available to callers.
pub type AwsCloudFormationDriftEvidence = CloudFormationDriftEvidence;
pub type AwsCloudFormationEvidenceState = CloudFormationEvidenceState;
pub type AwsCloudFormationProviderErrorEvidence = ProviderErrorEvidence;

// These aliases make the typed stack revision explicit without introducing a
// second mutable revision authority.
pub type StackRevision = u64;
pub type ProviderRevision = u64;
pub type RegistrationRevision = u64;

const _: &str = CONTRACT_VERSION;
