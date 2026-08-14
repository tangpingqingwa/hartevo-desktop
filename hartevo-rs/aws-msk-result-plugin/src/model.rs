//! Typed, bounded AWS MSK scope, transport pages, and redacted evidence.
//!
//! The public model intentionally contains no credential material, bootstrap
//! endpoint, broker address, topic, partition, record, raw configuration
//! property, or raw operation message type. Those values cannot cross the
//! Layer-1 boundary because they are not representable in the evidence model.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_MARKER_BYTES: usize = 512;
pub const MAX_CLUSTERS: usize = 64;
pub const MAX_OPERATIONS: usize = 128;
pub const MAX_ITEMS_PER_PAGE: usize = 64;
pub const MAX_PAGES: u16 = 4;
pub const PAGE_SIZE: u16 = 50;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS_PER_READ: u16 = 8;
pub const MAX_RETRIES: u8 = 2;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    ControlCharacter { field: &'static str },
    #[error("{field} contains unsupported characters")]
    InvalidCharacters { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not a bounded opaque marker")]
    InvalidMarker { field: &'static str },
    #[error("{field} contains too many entries")]
    TooMany { field: &'static str },
    #[error("{field} is not allowed for this operation")]
    Unsupported { field: &'static str },
    #[error("{field} has a duplicate entry")]
    Duplicate { field: &'static str },
    #[error("{field} does not match the bound scope")]
    ScopeMismatch { field: &'static str },
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
    if value
        .chars()
        .any(|character| !(character.is_ascii_alphanumeric() || "-_.:/+=@*".contains(character)))
    {
        return Err(ModelError::InvalidCharacters { field });
    }
    Ok(())
}

fn validate_positive(value: u64, field: &'static str) -> Result<(), ModelError> {
    if value == 0 {
        Err(ModelError::MustBePositive { field })
    } else {
        Ok(())
    }
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(
            Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_text(&value, $field, MAX_IDENTIFIER_BYTES)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("digest", &Digest::from_text(self.as_str()))
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

bounded_identifier!(DeploymentId, "deployment id");
bounded_identifier!(MissionId, "Mission id");
bounded_identifier!(ProjectId, "Project id");
bounded_identifier!(WorkProductId, "Work Product id");
bounded_identifier!(ClusterArn, "MSK cluster ARN");
bounded_identifier!(ClusterName, "MSK cluster name");
bounded_identifier!(ConfigurationArn, "MSK configuration ARN");
bounded_identifier!(OperationId, "MSK operation id");
bounded_identifier!(OperationType, "MSK operation type");
bounded_identifier!(PermissionId, "permission id");
bounded_identifier!(ProviderId, "provider id");
bounded_identifier!(ProviderRevision, "provider revision");
bounded_identifier!(KafkaVersion, "Kafka version");

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct AccountId(String);

impl AccountId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() != 12 || value.bytes().any(|byte| !byte.is_ascii_digit()) {
            return Err(ModelError::Invalid {
                field: "AWS account id",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for AccountId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountId")
            .field("digest", &Digest::from_text(self.as_str()))
            .finish()
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "AWS region", 63)?;
        if value.starts_with('-') || value.ends_with('-') {
            return Err(ModelError::Invalid {
                field: "AWS region",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for AwsRegion {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsRegion")
            .field("value", &self.0)
            .finish()
    }
}

impl fmt::Display for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

pub type Region = AwsRegion;

#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        validate_positive(value, "revision")?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex_encode(Sha256::digest(bytes).as_slice()))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_parts(tag: &str, parts: &[String]) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(tag.as_bytes());
        for part in parts {
            bytes.push(0);
            bytes.extend_from_slice(part.as_bytes());
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() != 64
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(ModelError::InvalidDigest { field: "digest" });
        }
        Ok(Self(value))
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentBinding {
    pub id: DeploymentId,
    pub revision: Revision,
}

impl DeploymentBinding {
    pub const fn new(id: DeploymentId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionBinding {
    pub const fn new(id: MissionId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectBinding {
    pub const fn new(id: ProjectId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub const fn new(id: WorkProductId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClusterType {
    Provisioned,
    Serverless,
    Express,
}

impl ClusterType {
    pub fn parse_api(value: &str) -> Result<Self, ModelError> {
        match value {
            "PROVISIONED" | "Provisioned" | "provisioned" => Ok(Self::Provisioned),
            "SERVERLESS" | "Serverless" | "serverless" => Ok(Self::Serverless),
            "EXPRESS" | "Express" | "express" => Ok(Self::Express),
            _ => Err(ModelError::Unsupported {
                field: "MSK cluster type",
            }),
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClusterBinding {
    pub arn: ClusterArn,
    pub name: ClusterName,
    pub cluster_type: ClusterType,
    pub kafka_version: KafkaVersion,
    pub revision: Revision,
}

impl ClusterBinding {
    pub fn new(
        arn: ClusterArn,
        name: ClusterName,
        cluster_type: ClusterType,
        kafka_version: KafkaVersion,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        if arn.as_str().is_empty() || name.as_str().is_empty() {
            return Err(ModelError::Empty {
                field: "MSK cluster binding",
            });
        }
        Ok(Self {
            arn,
            name,
            cluster_type,
            kafka_version,
            revision,
        })
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigurationBinding {
    pub arn: ConfigurationArn,
    pub revision: Revision,
}

impl ConfigurationBinding {
    pub const fn new(arn: ConfigurationArn, revision: Revision) -> Self {
        Self { arn, revision }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationBinding {
    pub id: OperationId,
    pub revision: Revision,
}

impl OperationBinding {
    pub const fn new(id: OperationId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PermissionAction {
    ListClustersV2,
    DescribeClusterV2,
    DescribeConfigurationRevision,
    ListClusterOperations,
}

impl PermissionAction {
    pub const fn api_name(self) -> &'static str {
        match self {
            Self::ListClustersV2 => "ListClustersV2",
            Self::DescribeClusterV2 => "DescribeClusterV2",
            Self::DescribeConfigurationRevision => "DescribeConfigurationRevision",
            Self::ListClusterOperations => "ListClusterOperations",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionFence {
    pub id: PermissionId,
    pub revision: Revision,
    pub allowed_actions: BTreeSet<PermissionAction>,
}

impl PermissionFence {
    pub fn readonly(id: PermissionId, revision: Revision) -> Result<Self, ModelError> {
        Ok(Self {
            id,
            revision,
            allowed_actions: [
                PermissionAction::ListClustersV2,
                PermissionAction::DescribeClusterV2,
                PermissionAction::DescribeConfigurationRevision,
                PermissionAction::ListClusterOperations,
            ]
            .into_iter()
            .collect(),
        })
    }

    pub fn new(
        id: PermissionId,
        revision: Revision,
        allowed_actions: impl IntoIterator<Item = PermissionAction>,
    ) -> Result<Self, ModelError> {
        let allowed_actions = allowed_actions.into_iter().collect::<BTreeSet<_>>();
        if allowed_actions.is_empty() {
            return Err(ModelError::Empty {
                field: "permission allowlist",
            });
        }
        Ok(Self {
            id,
            revision,
            allowed_actions,
        })
    }

    pub fn allows(&self, action: PermissionAction) -> bool {
        self.allowed_actions.contains(&action)
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsMskScope {
    pub deployment: DeploymentBinding,
    pub mission: MissionBinding,
    pub project: ProjectBinding,
    pub work_product: WorkProductBinding,
    pub account_id: AccountId,
    pub region: AwsRegion,
    pub cluster: ClusterBinding,
    pub configuration: ConfigurationBinding,
    pub operations: Vec<OperationBinding>,
    pub permission_digest: Digest,
}

impl AwsMskScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        deployment: DeploymentBinding,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        account_id: AccountId,
        region: AwsRegion,
        cluster: ClusterBinding,
        configuration: ConfigurationBinding,
        operations: impl IntoIterator<Item = OperationBinding>,
        permission_digest: Digest,
    ) -> Result<Self, ModelError> {
        let mut operations = operations.into_iter().collect::<Vec<_>>();
        if operations.is_empty() {
            return Err(ModelError::Empty {
                field: "MSK operation allowlist",
            });
        }
        if operations.len() > MAX_OPERATIONS {
            return Err(ModelError::TooMany {
                field: "MSK operation allowlist",
            });
        }
        operations.sort_by(|left, right| left.id.cmp(&right.id));
        for pair in operations.windows(2) {
            if pair[0].id == pair[1].id {
                return Err(ModelError::Duplicate {
                    field: "MSK operation allowlist",
                });
            }
        }
        let scope = Self {
            deployment,
            mission,
            project,
            work_product,
            account_id,
            region,
            cluster,
            configuration,
            operations,
            permission_digest,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.permission_digest == Digest::zero() {
            return Err(ModelError::Invalid {
                field: "permission digest",
            });
        }
        if self.operations.is_empty() || self.operations.len() > MAX_OPERATIONS {
            return Err(ModelError::Invalid {
                field: "MSK operation allowlist",
            });
        }
        if self
            .operations
            .windows(2)
            .any(|pair| pair[0].id >= pair[1].id)
        {
            return Err(ModelError::Invalid {
                field: "sorted MSK operation allowlist",
            });
        }
        validate_scoped_arn(
            self.cluster.arn.as_str(),
            "cluster",
            &self.account_id,
            &self.region,
        )?;
        validate_scoped_arn(
            self.configuration.arn.as_str(),
            "configuration",
            &self.account_id,
            &self.region,
        )?;
        for operation in &self.operations {
            validate_scoped_arn(
                operation.id.as_str(),
                "operation",
                &self.account_id,
                &self.region,
            )?;
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }

    pub fn operation_revision(&self, operation_id: &OperationId) -> Option<Revision> {
        self.operations
            .iter()
            .find(|operation| operation.id == *operation_id)
            .map(|operation| operation.revision)
    }

    pub fn allows_operation(&self, operation_id: &OperationId) -> bool {
        self.operation_revision(operation_id).is_some()
    }
}

fn validate_scoped_arn(
    value: &str,
    resource_kind: &'static str,
    account: &AccountId,
    region: &AwsRegion,
) -> Result<(), ModelError> {
    if !value.starts_with("arn:") {
        return Ok(());
    }
    let parts = value.split(':').collect::<Vec<_>>();
    let resource_matches = parts.get(5).is_some_and(|resource| {
        if resource_kind == "operation" {
            resource.starts_with("operation") || resource.starts_with("cluster-operation")
        } else {
            resource.starts_with(resource_kind)
        }
    });
    if parts.len() < 6
        || parts[2] != "kafka"
        || parts[3] != region.as_str()
        || parts[4] != account.as_str()
        || !resource_matches
    {
        return Err(ModelError::ScopeMismatch {
            field: "account or region scoped ARN",
        });
    }
    Ok(())
}

/// A SigV4 reference is reduced to a digest before it enters the service.
/// Neither the supplied reference nor signing material is retained.
#[derive(Clone, Eq, PartialEq)]
pub struct SigV4SecretReference {
    digest: Digest,
    region: AwsRegion,
    scope_digest: Digest,
    revision: Revision,
}

impl SigV4SecretReference {
    pub fn new(
        reference: impl AsRef<str>,
        region: impl AsRef<str>,
        scope_digest: Digest,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        let value = reference.as_ref();
        validate_text(value, "SigV4 secret reference", MAX_IDENTIFIER_BYTES)?;
        let region = AwsRegion::new(region.as_ref())?;
        if scope_digest == Digest::zero() {
            return Err(ModelError::Invalid {
                field: "secret reference scope digest",
            });
        }
        let digest = Digest::from_parts(
            "hartevo-aws-msk-sigv4-secret/v1",
            &[
                "kafka".to_owned(),
                region.as_str().to_owned(),
                scope_digest.to_string(),
                revision.get().to_string(),
                value.to_owned(),
            ],
        );
        Ok(Self {
            digest,
            region,
            scope_digest,
            revision,
        })
    }

    pub fn for_msk(reference: impl AsRef<str>, scope: &AwsMskScope) -> Result<Self, ModelError> {
        Self::new(
            reference,
            scope.region.clone(),
            scope.digest(),
            scope.cluster.revision,
        )
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub const fn signing_service(&self) -> &'static str {
        "kafka"
    }

    pub fn signing_region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }
}

impl fmt::Debug for SigV4SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigV4SecretReference")
            .field("value", &"<opaque>")
            .field("signing_service", &"kafka")
            .field("signing_region", &self.region)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("digest", &self.digest)
            .finish()
    }
}

impl Serialize for SigV4SecretReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("SigV4SecretReference", 1)?;
        value.serialize_field("opaque", &true)?;
        value.end()
    }
}

pub type SecretReference = SigV4SecretReference;

#[derive(Clone, Eq, PartialEq)]
pub struct OpaquePageMarker {
    token_digest: Digest,
    binding_digest: Option<Digest>,
    expires_at: Option<DateTime<Utc>>,
}

impl OpaquePageMarker {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        validate_text(value, "opaque page marker", MAX_MARKER_BYTES)?;
        Ok(Self {
            token_digest: Digest::from_parts("hartevo-aws-msk-page-marker/v1", &[value.to_owned()]),
            binding_digest: None,
            expires_at: None,
        })
    }

    pub fn with_expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn bind(&self, binding_digest: &Digest) -> Self {
        let mut marker = self.clone();
        marker.binding_digest = Some(binding_digest.clone());
        marker
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn binding_digest(&self) -> Option<&Digest> {
        self.binding_digest.as_ref()
    }

    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }

    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|expires_at| expires_at <= now)
    }
}

impl fmt::Debug for OpaquePageMarker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageMarker")
            .field("token", &"<opaque>")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Serialize for OpaquePageMarker {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("OpaquePageMarker", 3)?;
        value.serialize_field("opaque", &true)?;
        value.serialize_field("tokenDigest", &self.token_digest)?;
        value.serialize_field("bindingDigest", &self.binding_digest)?;
        value.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadBounds {
    pub page_size: u16,
    pub max_pages: u16,
    pub max_items: u16,
    pub max_response_bytes: usize,
    pub max_retries: u8,
}

impl Default for ReadBounds {
    fn default() -> Self {
        Self {
            page_size: PAGE_SIZE,
            max_pages: MAX_PAGES,
            max_items: MAX_CLUSTERS as u16,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_retries: MAX_RETRIES,
        }
    }
}

impl ReadBounds {
    pub fn new(page_size: u16, max_pages: u16, max_items: u16) -> Result<Self, ModelError> {
        let bounds = Self {
            page_size,
            max_pages,
            max_items,
            ..Self::default()
        };
        bounds.validate()
    }

    pub fn with_response_bytes(mut self, max_response_bytes: usize) -> Result<Self, ModelError> {
        self.max_response_bytes = max_response_bytes;
        self.validate()
    }

    pub fn with_retries(mut self, max_retries: u8) -> Result<Self, ModelError> {
        self.max_retries = max_retries;
        self.validate()
    }

    pub fn validate(self) -> Result<Self, ModelError> {
        if self.page_size == 0
            || self.page_size > PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.max_items == 0
            || usize::from(self.max_items) > MAX_OPERATIONS.max(MAX_CLUSTERS)
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.max_retries > MAX_RETRIES
        {
            return Err(ModelError::Invalid {
                field: "MSK read bounds",
            });
        }
        Ok(self)
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "PascalCase")]
pub enum AwsMskReadOperation {
    ListClustersV2,
    DescribeClusterV2,
    DescribeConfigurationRevision,
    ListClusterOperations,
}

impl AwsMskReadOperation {
    pub const fn permission(self) -> PermissionAction {
        match self {
            Self::ListClustersV2 => PermissionAction::ListClustersV2,
            Self::DescribeClusterV2 => PermissionAction::DescribeClusterV2,
            Self::DescribeConfigurationRevision => PermissionAction::DescribeConfigurationRevision,
            Self::ListClusterOperations => PermissionAction::ListClusterOperations,
        }
    }

    pub const fn api_name(self) -> &'static str {
        self.permission().api_name()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsMskReadRequest {
    pub operation: AwsMskReadOperation,
    pub account_id: AccountId,
    pub region: AwsRegion,
    pub cluster_arn: Option<ClusterArn>,
    pub cluster_name_filter: Option<ClusterName>,
    pub cluster_type_filter: Option<ClusterType>,
    pub configuration_arn: Option<ConfigurationArn>,
    pub configuration_revision: Option<Revision>,
    pub marker: Option<OpaquePageMarker>,
    pub page_size: u16,
    pub max_pages: u16,
    pub max_items: u16,
    pub max_response_bytes: usize,
    pub max_retries: u8,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadBinding<'a> {
    operation: AwsMskReadOperation,
    account_id: &'a AccountId,
    region: &'a AwsRegion,
    cluster_arn: &'a Option<ClusterArn>,
    cluster_name_filter: &'a Option<ClusterName>,
    cluster_type_filter: &'a Option<ClusterType>,
    configuration_arn: &'a Option<ConfigurationArn>,
    configuration_revision: Option<Revision>,
    page_size: u16,
    max_pages: u16,
    max_items: u16,
    max_response_bytes: usize,
    max_retries: u8,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
}

impl AwsMskReadRequest {
    pub fn list_clusters(scope: &AwsMskScope, bounds: ReadBounds) -> Result<Self, ModelError> {
        Self::new(
            AwsMskReadOperation::ListClustersV2,
            scope,
            Some(scope.cluster.name.clone()),
            Some(scope.cluster.cluster_type),
            None,
            None,
            bounds,
            None,
        )
    }

    pub fn list_clusters_v2(scope: &AwsMskScope, bounds: ReadBounds) -> Result<Self, ModelError> {
        Self::list_clusters(scope, bounds)
    }

    pub fn describe_cluster(scope: &AwsMskScope, bounds: ReadBounds) -> Result<Self, ModelError> {
        Self::new(
            AwsMskReadOperation::DescribeClusterV2,
            scope,
            None,
            None,
            Some(scope.cluster.arn.clone()),
            None,
            bounds,
            None,
        )
    }

    pub fn describe_cluster_v2(
        scope: &AwsMskScope,
        bounds: ReadBounds,
    ) -> Result<Self, ModelError> {
        Self::describe_cluster(scope, bounds)
    }

    pub fn describe_configuration_revision(
        scope: &AwsMskScope,
        bounds: ReadBounds,
    ) -> Result<Self, ModelError> {
        Self::new(
            AwsMskReadOperation::DescribeConfigurationRevision,
            scope,
            None,
            None,
            None,
            Some((
                scope.configuration.arn.clone(),
                scope.configuration.revision,
            )),
            bounds,
            None,
        )
    }

    pub fn describe_configuration(
        scope: &AwsMskScope,
        bounds: ReadBounds,
    ) -> Result<Self, ModelError> {
        Self::describe_configuration_revision(scope, bounds)
    }

    pub fn list_cluster_operations(
        scope: &AwsMskScope,
        bounds: ReadBounds,
    ) -> Result<Self, ModelError> {
        Self::new(
            AwsMskReadOperation::ListClusterOperations,
            scope,
            None,
            None,
            Some(scope.cluster.arn.clone()),
            None,
            bounds,
            None,
        )
    }

    pub fn list_operations(scope: &AwsMskScope, bounds: ReadBounds) -> Result<Self, ModelError> {
        Self::list_cluster_operations(scope, bounds)
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        operation: AwsMskReadOperation,
        scope: &AwsMskScope,
        cluster_name_filter: Option<ClusterName>,
        cluster_type_filter: Option<ClusterType>,
        cluster_arn: Option<ClusterArn>,
        configuration: Option<(ConfigurationArn, Revision)>,
        bounds: ReadBounds,
        marker: Option<OpaquePageMarker>,
    ) -> Result<Self, ModelError> {
        let bounds = bounds.validate()?;
        let (configuration_arn, configuration_revision) =
            configuration.map_or((None, None), |(arn, revision)| (Some(arn), Some(revision)));
        let mut request = Self {
            operation,
            account_id: scope.account_id.clone(),
            region: scope.region.clone(),
            cluster_arn,
            cluster_name_filter,
            cluster_type_filter,
            configuration_arn,
            configuration_revision,
            marker: None,
            page_size: bounds.page_size,
            max_pages: bounds.max_pages,
            max_items: bounds.max_items,
            max_response_bytes: bounds.max_response_bytes,
            max_retries: bounds.max_retries,
            scope_digest: scope.digest(),
            permission_digest: scope.permission_digest.clone(),
        };
        request.marker = request.bind_marker(marker)?;
        Ok(request)
    }

    fn bind_marker(
        &self,
        marker: Option<OpaquePageMarker>,
    ) -> Result<Option<OpaquePageMarker>, ModelError> {
        let Some(marker) = marker else {
            return Ok(None);
        };
        let binding = self.query_digest();
        if let Some(existing) = marker.binding_digest()
            && existing != &binding
        {
            return Err(ModelError::ScopeMismatch {
                field: "marker query binding",
            });
        }
        Ok(Some(marker.bind(&binding)))
    }

    pub fn with_marker(&self, marker: Option<OpaquePageMarker>) -> Result<Self, ModelError> {
        let mut request = self.clone();
        request.marker = request.bind_marker(marker)?;
        Ok(request)
    }

    pub fn with_next_token(&self, marker: Option<OpaquePageMarker>) -> Result<Self, ModelError> {
        self.with_marker(marker)
    }

    pub fn query_digest(&self) -> Digest {
        digest_serialized(&ReadBinding {
            operation: self.operation,
            account_id: &self.account_id,
            region: &self.region,
            cluster_arn: &self.cluster_arn,
            cluster_name_filter: &self.cluster_name_filter,
            cluster_type_filter: &self.cluster_type_filter,
            configuration_arn: &self.configuration_arn,
            configuration_revision: self.configuration_revision,
            page_size: self.page_size,
            max_pages: self.max_pages,
            max_items: self.max_items,
            max_response_bytes: self.max_response_bytes,
            max_retries: self.max_retries,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
        })
    }

    pub fn request_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-aws-msk-read-request/v1",
            &[
                self.query_digest().to_string(),
                self.marker.as_ref().map_or_else(
                    || Digest::zero().to_string(),
                    |marker| marker.token_digest().to_string(),
                ),
            ],
        )
    }

    pub fn validate_against(
        &self,
        scope: &AwsMskScope,
        permission: &PermissionFence,
    ) -> Result<(), ModelError> {
        if self.scope_digest != scope.digest() {
            return Err(ModelError::ScopeMismatch {
                field: "scope digest",
            });
        }
        if self.permission_digest != permission.digest()
            || self.permission_digest != scope.permission_digest
        {
            return Err(ModelError::ScopeMismatch {
                field: "permission digest",
            });
        }
        if self.account_id != scope.account_id || self.region != scope.region {
            return Err(ModelError::ScopeMismatch {
                field: "AWS account or region",
            });
        }
        if !permission.allows(self.operation.permission()) {
            return Err(ModelError::ScopeMismatch {
                field: "permission action",
            });
        }
        match self.operation {
            AwsMskReadOperation::ListClustersV2 => {
                if self.cluster_name_filter.as_ref() != Some(&scope.cluster.name)
                    || self.cluster_type_filter != Some(scope.cluster.cluster_type)
                    || self.cluster_arn.is_some()
                    || self.configuration_arn.is_some()
                    || self.configuration_revision.is_some()
                {
                    return Err(ModelError::ScopeMismatch {
                        field: "ListClustersV2 exact cluster filter",
                    });
                }
            }
            AwsMskReadOperation::DescribeClusterV2 | AwsMskReadOperation::ListClusterOperations => {
                if self.cluster_arn.as_ref() != Some(&scope.cluster.arn)
                    || self.cluster_name_filter.is_some()
                    || self.cluster_type_filter.is_some()
                    || self.configuration_arn.is_some()
                    || self.configuration_revision.is_some()
                {
                    return Err(ModelError::ScopeMismatch {
                        field: "MSK cluster ARN",
                    });
                }
            }
            AwsMskReadOperation::DescribeConfigurationRevision => {
                if self.configuration_arn.as_ref() != Some(&scope.configuration.arn)
                    || self.configuration_revision != Some(scope.configuration.revision)
                    || self.cluster_arn.is_some()
                    || self.cluster_name_filter.is_some()
                    || self.cluster_type_filter.is_some()
                {
                    return Err(ModelError::ScopeMismatch {
                        field: "MSK configuration revision",
                    });
                }
            }
        }
        if self.page_size == 0
            || self.page_size > PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.max_items == 0
            || usize::from(self.max_items) > MAX_OPERATIONS.max(MAX_CLUSTERS)
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.max_retries > MAX_RETRIES
        {
            return Err(ModelError::Invalid {
                field: "MSK read bounds",
            });
        }
        if let Some(marker) = &self.marker
            && marker.binding_digest() != Some(&self.query_digest())
        {
            return Err(ModelError::ScopeMismatch {
                field: "marker query binding",
            });
        }
        Ok(())
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum TriState {
    Enabled,
    Disabled,
    Unknown,
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ClientBrokerEncryption {
    Tls,
    TlsPlaintext,
    Plaintext,
    Unknown,
}

impl ClientBrokerEncryption {
    pub fn parse_api(value: &str) -> Self {
        match value {
            "TLS" => Self::Tls,
            "TLS_PLAINTEXT" => Self::TlsPlaintext,
            "PLAINTEXT" => Self::Plaintext,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityPosture {
    pub encryption_at_rest: TriState,
    pub in_cluster_encryption: TriState,
    pub client_broker_encryption: ClientBrokerEncryption,
    pub tls_authentication: TriState,
    pub sasl_iam_authentication: TriState,
    pub sasl_scram_authentication: TriState,
    pub unauthenticated_access: TriState,
}

impl Default for SecurityPosture {
    fn default() -> Self {
        Self {
            encryption_at_rest: TriState::Unknown,
            in_cluster_encryption: TriState::Unknown,
            client_broker_encryption: ClientBrokerEncryption::Unknown,
            tls_authentication: TriState::Unknown,
            sasl_iam_authentication: TriState::Unknown,
            sasl_scram_authentication: TriState::Unknown,
            unauthenticated_access: TriState::Unknown,
        }
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum BrokerCountClass {
    None,
    Single,
    Small,
    Medium,
    Large,
    Unknown,
}

impl BrokerCountClass {
    pub const fn from_count(count: Option<u32>) -> Self {
        match count {
            Some(0) => Self::None,
            Some(1) => Self::Single,
            Some(2..=3) => Self::Small,
            Some(4..=9) => Self::Medium,
            Some(_) => Self::Large,
            None => Self::Unknown,
        }
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClusterState {
    Provisioning,
    Active,
    Updating,
    Deleting,
    Failed,
    #[serde(other)]
    Unknown,
}

impl ClusterState {
    pub fn parse_api(value: &str) -> Self {
        match value {
            "PROVISIONING" | "CREATING" => Self::Provisioning,
            "ACTIVE" => Self::Active,
            "UPDATING" => Self::Updating,
            "DELETING" => Self::Deleting,
            "FAILED" => Self::Failed,
            _ => Self::Unknown,
        }
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessState {
    Ready,
    NotReady,
    Partial,
    InsufficientData,
    AccessLoss,
    ProviderUnknown,
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationState {
    Pending,
    InProgress,
    Successful,
    Failed,
    Cancelling,
    Cancelled,
    #[serde(other)]
    Unknown,
}

impl OperationState {
    pub fn parse_api(value: &str) -> Self {
        match value {
            "PENDING" => Self::Pending,
            "IN_PROGRESS" => Self::InProgress,
            "SUCCESS" | "SUCCEEDED" | "SUCCESSFUL" => Self::Successful,
            "FAILED" => Self::Failed,
            "CANCELLING" | "CANCELING" => Self::Cancelling,
            "CANCELLED" | "CANCELED" => Self::Cancelled,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigurationProjection {
    pub arn: Option<ConfigurationArn>,
    pub revision: Option<Revision>,
    pub readiness: ReadinessState,
}

impl Default for ConfigurationProjection {
    fn default() -> Self {
        Self {
            arn: None,
            revision: None,
            readiness: ReadinessState::InsufficientData,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MskClusterObservation {
    pub arn: ClusterArn,
    pub name: ClusterName,
    pub cluster_type: ClusterType,
    pub kafka_version: KafkaVersion,
    pub cluster_revision: Option<Revision>,
    pub state: ClusterState,
    pub broker_count_class: BrokerCountClass,
    pub security_posture: SecurityPosture,
    pub configuration: ConfigurationProjection,
    pub creation_time: Option<DateTime<Utc>>,
    pub observation_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClusterObservationBody<'a> {
    arn: &'a ClusterArn,
    name: &'a ClusterName,
    cluster_type: ClusterType,
    kafka_version: &'a KafkaVersion,
    cluster_revision: &'a Option<Revision>,
    state: ClusterState,
    broker_count_class: BrokerCountClass,
    security_posture: &'a SecurityPosture,
    configuration: &'a ConfigurationProjection,
    creation_time: &'a Option<DateTime<Utc>>,
}

impl MskClusterObservation {
    pub fn new(
        arn: ClusterArn,
        name: ClusterName,
        cluster_type: ClusterType,
        kafka_version: KafkaVersion,
        state: ClusterState,
        broker_count_class: BrokerCountClass,
        security_posture: SecurityPosture,
        configuration: ConfigurationProjection,
        creation_time: Option<DateTime<Utc>>,
    ) -> Self {
        let mut observation = Self {
            arn,
            name,
            cluster_type,
            kafka_version,
            cluster_revision: None,
            state,
            broker_count_class,
            security_posture,
            configuration,
            creation_time,
            observation_digest: Digest::zero(),
        };
        observation.observation_digest = observation.recomputed_digest();
        observation
    }

    pub fn with_revision(mut self, revision: Revision) -> Self {
        self.cluster_revision = Some(revision);
        self.observation_digest = self.recomputed_digest();
        self
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&ClusterObservationBody {
            arn: &self.arn,
            name: &self.name,
            cluster_type: self.cluster_type,
            kafka_version: &self.kafka_version,
            cluster_revision: &self.cluster_revision,
            state: self.state,
            broker_count_class: self.broker_count_class,
            security_posture: &self.security_posture,
            configuration: &self.configuration,
            creation_time: &self.creation_time,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.observation_digest != self.recomputed_digest() {
            return Err(ModelError::Invalid {
                field: "cluster observation digest",
            });
        }
        Ok(())
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum PropertyCountClass {
    Empty,
    Small,
    Medium,
    Large,
    Unknown,
}

impl PropertyCountClass {
    pub const fn from_count(count: usize) -> Self {
        match count {
            0 => Self::Empty,
            1..=16 => Self::Small,
            17..=128 => Self::Medium,
            _ => Self::Large,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MskConfigurationObservation {
    pub arn: ConfigurationArn,
    pub revision: Revision,
    pub properties_present: bool,
    pub property_count_class: PropertyCountClass,
    pub readiness: ReadinessState,
    pub observation_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigurationObservationBody<'a> {
    arn: &'a ConfigurationArn,
    revision: Revision,
    properties_present: bool,
    property_count_class: PropertyCountClass,
    readiness: ReadinessState,
}

impl MskConfigurationObservation {
    pub fn new(
        arn: ConfigurationArn,
        revision: Revision,
        properties_present: bool,
        property_count_class: PropertyCountClass,
        readiness: ReadinessState,
    ) -> Self {
        let mut observation = Self {
            arn,
            revision,
            properties_present,
            property_count_class,
            readiness,
            observation_digest: Digest::zero(),
        };
        observation.observation_digest = observation.recomputed_digest();
        observation
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&ConfigurationObservationBody {
            arn: &self.arn,
            revision: self.revision,
            properties_present: self.properties_present,
            property_count_class: self.property_count_class,
            readiness: self.readiness,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.observation_digest != self.recomputed_digest() {
            return Err(ModelError::Invalid {
                field: "configuration observation digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MskOperationObservation {
    pub id: OperationId,
    pub operation_revision: Option<Revision>,
    pub operation_type: OperationType,
    pub state: OperationState,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub error_present: bool,
    pub observation_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OperationObservationBody<'a> {
    id: &'a OperationId,
    operation_revision: &'a Option<Revision>,
    operation_type: &'a OperationType,
    state: OperationState,
    start_time: &'a Option<DateTime<Utc>>,
    end_time: &'a Option<DateTime<Utc>>,
    error_present: bool,
}

impl MskOperationObservation {
    pub fn new(
        id: OperationId,
        operation_type: OperationType,
        state: OperationState,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
        error_present: bool,
    ) -> Self {
        let mut observation = Self {
            id,
            operation_revision: None,
            operation_type,
            state,
            start_time,
            end_time,
            error_present,
            observation_digest: Digest::zero(),
        };
        observation.observation_digest = observation.recomputed_digest();
        observation
    }

    pub fn with_revision(mut self, revision: Revision) -> Self {
        self.operation_revision = Some(revision);
        self.observation_digest = self.recomputed_digest();
        self
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&OperationObservationBody {
            id: &self.id,
            operation_revision: &self.operation_revision,
            operation_type: &self.operation_type,
            state: self.state,
            start_time: &self.start_time,
            end_time: &self.end_time,
            error_present: self.error_present,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if let (Some(start), Some(end)) = (self.start_time, self.end_time)
            && end < start
        {
            return Err(ModelError::Invalid {
                field: "operation timestamp ordering",
            });
        }
        if self.observation_digest != self.recomputed_digest() {
            return Err(ModelError::Invalid {
                field: "operation observation digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    PageBudget,
    ResponseTooLarge,
    MarkerReplay,
    MarkerExpired,
    MissingCluster,
    ClusterReplacement,
    ClusterRevisionDrift,
    ConfigurationRevisionDrift,
    OperationRevisionDrift,
    MissingOperation,
    UnsupportedState,
    ProviderConflict,
    Truncated,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    InvalidRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    MarkerExpired,
    RateLimited,
    ServerFailure,
    Timeout,
    BlockedEnvironment,
    MalformedResponse,
    Conflict,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderErrorEvidence {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u64>,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransportError {
    #[error("AWS MSK provider returned HTTP 400")]
    InvalidRequest,
    #[error("AWS MSK provider rejected the request")]
    Unauthorized,
    #[error("AWS MSK provider denied the request")]
    Forbidden,
    #[error("AWS MSK resource was not found")]
    NotFound,
    #[error("AWS MSK pagination marker expired")]
    MarkerExpired,
    #[error("AWS MSK provider rate limited the request")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("AWS MSK provider returned a server failure")]
    ServerFailure { status_code: Option<u16> },
    #[error("AWS MSK provider timed out")]
    Timeout,
    #[error("AWS MSK native transport is unavailable in BLOCKED_ENV")]
    BlockedEnvironment,
    #[error("AWS MSK provider response was malformed")]
    MalformedResponse,
    #[error("AWS MSK provider returned a conflict")]
    Conflict,
    #[error("AWS MSK provider returned an unknown error")]
    Unknown,
}

impl TransportError {
    pub const fn kind(&self) -> ProviderErrorKind {
        match self {
            Self::InvalidRequest => ProviderErrorKind::InvalidRequest,
            Self::Unauthorized => ProviderErrorKind::Unauthorized,
            Self::Forbidden => ProviderErrorKind::Forbidden,
            Self::NotFound => ProviderErrorKind::NotFound,
            Self::MarkerExpired => ProviderErrorKind::MarkerExpired,
            Self::RateLimited { .. } => ProviderErrorKind::RateLimited,
            Self::ServerFailure { .. } => ProviderErrorKind::ServerFailure,
            Self::Timeout => ProviderErrorKind::Timeout,
            Self::BlockedEnvironment => ProviderErrorKind::BlockedEnvironment,
            Self::MalformedResponse => ProviderErrorKind::MalformedResponse,
            Self::Conflict => ProviderErrorKind::Conflict,
            Self::Unknown => ProviderErrorKind::Unknown,
        }
    }

    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::InvalidRequest | Self::MarkerExpired => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::RateLimited { .. } => Some(429),
            Self::ServerFailure { status_code } => *status_code,
            Self::Conflict => Some(409),
            Self::Timeout | Self::BlockedEnvironment | Self::MalformedResponse | Self::Unknown => {
                None
            }
        }
    }

    pub const fn retry_after_seconds(&self) -> Option<u64> {
        match self {
            Self::RateLimited {
                retry_after_seconds,
            } => *retry_after_seconds,
            _ => None,
        }
    }

    pub const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. } | Self::ServerFailure { .. } | Self::Timeout
        )
    }

    pub const fn evidence(&self) -> ProviderErrorEvidence {
        ProviderErrorEvidence {
            kind: self.kind(),
            status_code: self.status_code(),
            retry_after_seconds: self.retry_after_seconds(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Fake,
    Recording,
    Loopback,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsMskReadPage {
    pub operation: AwsMskReadOperation,
    pub query_digest: Digest,
    pub page_number: u16,
    pub clusters: Vec<MskClusterObservation>,
    pub cluster: Option<MskClusterObservation>,
    pub configuration: Option<MskConfigurationObservation>,
    pub operations: Vec<MskOperationObservation>,
    pub next_marker: Option<OpaquePageMarker>,
    pub response_bytes: usize,
    pub provider_revision: ProviderRevision,
    pub page_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadPageBody<'a> {
    operation: AwsMskReadOperation,
    query_digest: &'a Digest,
    page_number: u16,
    clusters: &'a [MskClusterObservation],
    cluster: &'a Option<MskClusterObservation>,
    configuration: &'a Option<MskConfigurationObservation>,
    operations: &'a [MskOperationObservation],
    next_marker: &'a Option<OpaquePageMarker>,
    response_bytes: usize,
    provider_revision: &'a ProviderRevision,
}

impl AwsMskReadPage {
    pub fn list_clusters(
        request: &AwsMskReadRequest,
        page_number: u16,
        clusters: Vec<MskClusterObservation>,
        next_marker: Option<OpaquePageMarker>,
        response_bytes: usize,
        provider_revision: ProviderRevision,
    ) -> Result<Self, ModelError> {
        Self::new(
            request,
            page_number,
            clusters,
            None,
            None,
            Vec::new(),
            next_marker,
            response_bytes,
            provider_revision,
        )
    }

    pub fn list_clusters_v2(
        request: &AwsMskReadRequest,
        page_number: u16,
        clusters: Vec<MskClusterObservation>,
        next_marker: Option<OpaquePageMarker>,
        response_bytes: usize,
        provider_revision: ProviderRevision,
    ) -> Result<Self, ModelError> {
        Self::list_clusters(
            request,
            page_number,
            clusters,
            next_marker,
            response_bytes,
            provider_revision,
        )
    }

    pub fn describe_cluster(
        request: &AwsMskReadRequest,
        page_number: u16,
        cluster: MskClusterObservation,
        response_bytes: usize,
        provider_revision: ProviderRevision,
    ) -> Result<Self, ModelError> {
        Self::new(
            request,
            page_number,
            Vec::new(),
            Some(cluster),
            None,
            Vec::new(),
            None,
            response_bytes,
            provider_revision,
        )
    }

    pub fn describe_cluster_v2(
        request: &AwsMskReadRequest,
        page_number: u16,
        cluster: MskClusterObservation,
        response_bytes: usize,
        provider_revision: ProviderRevision,
    ) -> Result<Self, ModelError> {
        Self::describe_cluster(
            request,
            page_number,
            cluster,
            response_bytes,
            provider_revision,
        )
    }

    pub fn describe_configuration_revision(
        request: &AwsMskReadRequest,
        page_number: u16,
        configuration: MskConfigurationObservation,
        response_bytes: usize,
        provider_revision: ProviderRevision,
    ) -> Result<Self, ModelError> {
        Self::new(
            request,
            page_number,
            Vec::new(),
            None,
            Some(configuration),
            Vec::new(),
            None,
            response_bytes,
            provider_revision,
        )
    }

    pub fn describe_configuration(
        request: &AwsMskReadRequest,
        page_number: u16,
        configuration: MskConfigurationObservation,
        response_bytes: usize,
        provider_revision: ProviderRevision,
    ) -> Result<Self, ModelError> {
        Self::describe_configuration_revision(
            request,
            page_number,
            configuration,
            response_bytes,
            provider_revision,
        )
    }

    pub fn list_cluster_operations(
        request: &AwsMskReadRequest,
        page_number: u16,
        operations: Vec<MskOperationObservation>,
        next_marker: Option<OpaquePageMarker>,
        response_bytes: usize,
        provider_revision: ProviderRevision,
    ) -> Result<Self, ModelError> {
        Self::new(
            request,
            page_number,
            Vec::new(),
            None,
            None,
            operations,
            next_marker,
            response_bytes,
            provider_revision,
        )
    }

    pub fn list_operations(
        request: &AwsMskReadRequest,
        page_number: u16,
        operations: Vec<MskOperationObservation>,
        next_marker: Option<OpaquePageMarker>,
        response_bytes: usize,
        provider_revision: ProviderRevision,
    ) -> Result<Self, ModelError> {
        Self::list_cluster_operations(
            request,
            page_number,
            operations,
            next_marker,
            response_bytes,
            provider_revision,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        request: &AwsMskReadRequest,
        page_number: u16,
        clusters: Vec<MskClusterObservation>,
        cluster: Option<MskClusterObservation>,
        configuration: Option<MskConfigurationObservation>,
        operations: Vec<MskOperationObservation>,
        next_marker: Option<OpaquePageMarker>,
        response_bytes: usize,
        provider_revision: ProviderRevision,
    ) -> Result<Self, ModelError> {
        if page_number == 0 {
            return Err(ModelError::Invalid {
                field: "MSK page number",
            });
        }
        if clusters.len() > MAX_ITEMS_PER_PAGE || operations.len() > MAX_ITEMS_PER_PAGE {
            return Err(ModelError::TooMany {
                field: "MSK items per page",
            });
        }
        if response_bytes == 0 || response_bytes > MAX_RESPONSE_BYTES {
            return Err(ModelError::Invalid {
                field: "MSK provider response bytes",
            });
        }
        let expected = request.operation;
        let valid_shape = match expected {
            AwsMskReadOperation::ListClustersV2 => {
                cluster.is_none() && configuration.is_none() && operations.is_empty()
            }
            AwsMskReadOperation::DescribeClusterV2 => {
                clusters.is_empty()
                    && cluster.is_some()
                    && configuration.is_none()
                    && operations.is_empty()
            }
            AwsMskReadOperation::DescribeConfigurationRevision => {
                clusters.is_empty()
                    && cluster.is_none()
                    && configuration.is_some()
                    && operations.is_empty()
            }
            AwsMskReadOperation::ListClusterOperations => {
                clusters.is_empty() && cluster.is_none() && configuration.is_none()
            }
        };
        if !valid_shape {
            return Err(ModelError::Invalid {
                field: "MSK page payload shape",
            });
        }
        for item in &clusters {
            item.validate()?;
        }
        if let Some(item) = &cluster {
            item.validate()?;
        }
        if let Some(item) = &configuration {
            item.validate()?;
        }
        for item in &operations {
            item.validate()?;
        }
        let query_digest = request.query_digest();
        let next_marker = next_marker
            .map(|marker| {
                if let Some(existing) = marker.binding_digest()
                    && existing != &query_digest
                {
                    return Err(ModelError::ScopeMismatch {
                        field: "next marker query binding",
                    });
                }
                Ok(marker.bind(&query_digest))
            })
            .transpose()?;
        let mut page = Self {
            operation: expected,
            query_digest,
            page_number,
            clusters,
            cluster,
            configuration,
            operations,
            next_marker,
            response_bytes,
            provider_revision,
            page_digest: Digest::zero(),
        };
        page.page_digest = page.recomputed_digest();
        Ok(page)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&ReadPageBody {
            operation: self.operation,
            query_digest: &self.query_digest,
            page_number: self.page_number,
            clusters: &self.clusters,
            cluster: &self.cluster,
            configuration: &self.configuration,
            operations: &self.operations,
            next_marker: &self.next_marker,
            response_bytes: self.response_bytes,
            provider_revision: &self.provider_revision,
        })
    }

    pub fn validate_for(&self, request: &AwsMskReadRequest) -> Result<(), ModelError> {
        if self.operation != request.operation
            || self.query_digest != request.query_digest()
            || self.page_digest != self.recomputed_digest()
            || self.page_number == 0
            || self.response_bytes == 0
            || self.response_bytes > request.max_response_bytes
        {
            return Err(ModelError::Invalid {
                field: "MSK page binding",
            });
        }
        if self.clusters.len() > MAX_ITEMS_PER_PAGE || self.operations.len() > MAX_ITEMS_PER_PAGE {
            return Err(ModelError::TooMany {
                field: "MSK items per page",
            });
        }
        if let Some(marker) = &self.next_marker
            && marker.binding_digest() != Some(&request.query_digest())
        {
            return Err(ModelError::ScopeMismatch {
                field: "next marker query binding",
            });
        }
        for item in &self.clusters {
            item.validate()?;
        }
        if let Some(item) = &self.cluster {
            item.validate()?;
        }
        if let Some(item) = &self.configuration {
            item.validate()?;
        }
        for item in &self.operations {
            item.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsMskEvidence {
    pub operation: AwsMskReadOperation,
    pub state: ReadinessState,
    pub cluster_readiness: ReadinessState,
    pub configuration_readiness: ReadinessState,
    pub operation_readiness: ReadinessState,
    pub clusters: Vec<MskClusterObservation>,
    pub cluster: Option<MskClusterObservation>,
    pub configuration: Option<MskConfigurationObservation>,
    pub operations: Vec<MskOperationObservation>,
    pub partial_reason: Option<PartialReason>,
    pub page_count: u16,
    pub request_count: u16,
    pub retry_count: u8,
    pub truncated: bool,
    pub query_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub cluster_revision: Revision,
    pub configuration_revision: Revision,
    pub operation_scope_digest: Digest,
    pub provider_digest: Digest,
    pub provider_revision: ProviderRevision,
    pub api_digest: Digest,
    pub contract_digest: Digest,
    pub page_digests: Vec<Digest>,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub evidence_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceBody<'a> {
    operation: AwsMskReadOperation,
    state: ReadinessState,
    cluster_readiness: ReadinessState,
    configuration_readiness: ReadinessState,
    operation_readiness: ReadinessState,
    clusters: &'a [MskClusterObservation],
    cluster: &'a Option<MskClusterObservation>,
    configuration: &'a Option<MskConfigurationObservation>,
    operations: &'a [MskOperationObservation],
    partial_reason: Option<PartialReason>,
    page_count: u16,
    request_count: u16,
    retry_count: u8,
    truncated: bool,
    query_digest: &'a Digest,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
    cluster_revision: Revision,
    configuration_revision: Revision,
    operation_scope_digest: &'a Digest,
    provider_digest: &'a Digest,
    provider_revision: &'a ProviderRevision,
    api_digest: &'a Digest,
    contract_digest: &'a Digest,
    page_digests: &'a [Digest],
    provider_errors: &'a [ProviderErrorEvidence],
    provenance: TransportProvenance,
    connected: bool,
    native: bool,
    first_party: bool,
}

impl AwsMskEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation: AwsMskReadOperation,
        state: ReadinessState,
        cluster_readiness: ReadinessState,
        configuration_readiness: ReadinessState,
        operation_readiness: ReadinessState,
        clusters: Vec<MskClusterObservation>,
        cluster: Option<MskClusterObservation>,
        configuration: Option<MskConfigurationObservation>,
        operations: Vec<MskOperationObservation>,
        partial_reason: Option<PartialReason>,
        page_count: u16,
        request_count: u16,
        retry_count: u8,
        truncated: bool,
        query_digest: Digest,
        scope_digest: Digest,
        permission_digest: Digest,
        cluster_revision: Revision,
        configuration_revision: Revision,
        operation_scope_digest: Digest,
        provider_digest: Digest,
        provider_revision: ProviderRevision,
        api_digest: Digest,
        contract_digest: Digest,
        page_digests: Vec<Digest>,
        provider_errors: Vec<ProviderErrorEvidence>,
        provenance: TransportProvenance,
    ) -> Self {
        let mut evidence = Self {
            operation,
            state,
            cluster_readiness,
            configuration_readiness,
            operation_readiness,
            clusters,
            cluster,
            configuration,
            operations,
            partial_reason,
            page_count,
            request_count,
            retry_count,
            truncated,
            query_digest,
            scope_digest,
            permission_digest,
            cluster_revision,
            configuration_revision,
            operation_scope_digest,
            provider_digest,
            provider_revision,
            api_digest,
            contract_digest,
            page_digests,
            provider_errors,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            evidence_digest: Digest::zero(),
        };
        evidence.evidence_digest = evidence.recomputed_digest();
        evidence
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&EvidenceBody {
            operation: self.operation,
            state: self.state,
            cluster_readiness: self.cluster_readiness,
            configuration_readiness: self.configuration_readiness,
            operation_readiness: self.operation_readiness,
            clusters: &self.clusters,
            cluster: &self.cluster,
            configuration: &self.configuration,
            operations: &self.operations,
            partial_reason: self.partial_reason,
            page_count: self.page_count,
            request_count: self.request_count,
            retry_count: self.retry_count,
            truncated: self.truncated,
            query_digest: &self.query_digest,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            cluster_revision: self.cluster_revision,
            configuration_revision: self.configuration_revision,
            operation_scope_digest: &self.operation_scope_digest,
            provider_digest: &self.provider_digest,
            provider_revision: &self.provider_revision,
            api_digest: &self.api_digest,
            contract_digest: &self.contract_digest,
            page_digests: &self.page_digests,
            provider_errors: &self.provider_errors,
            provenance: self.provenance,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.clusters.len() > MAX_CLUSTERS
            || self.operations.len() > MAX_OPERATIONS
            || self.evidence_digest != self.recomputed_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
        {
            return Err(ModelError::Invalid {
                field: "MSK evidence digest or authority",
            });
        }
        for cluster in &self.clusters {
            cluster.validate()?;
        }
        if let Some(cluster) = &self.cluster {
            cluster.validate()?;
        }
        if let Some(configuration) = &self.configuration {
            configuration.validate()?;
        }
        for operation in &self.operations {
            operation.validate()?;
        }
        Ok(())
    }
}

pub fn digest_serialized<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("bounded AWS MSK values serialize");
    Digest::from_bytes(&bytes)
}

pub fn sort_clusters(clusters: &mut [MskClusterObservation]) {
    clusters.sort_by(|left, right| {
        left.arn
            .cmp(&right.arn)
            .then_with(|| left.observation_digest.cmp(&right.observation_digest))
    });
}

pub fn sort_operations(operations: &mut [MskOperationObservation]) {
    operations.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| right.start_time.cmp(&left.start_time))
            .then_with(|| left.observation_digest.cmp(&right.observation_digest))
    });
}

pub fn operation_map(
    operations: &[MskOperationObservation],
) -> BTreeMap<OperationId, MskOperationObservation> {
    operations
        .iter()
        .cloned()
        .map(|operation| (operation.id.clone(), operation))
        .collect()
}

pub type MskClusterBinding = ClusterBinding;
pub type MskConfigurationBinding = ConfigurationBinding;
pub type MskOperationBinding = OperationBinding;
pub type AwsMskResourceScope = AwsMskScope;
pub type ListClustersV2Request = AwsMskReadRequest;
pub type DescribeClusterV2Request = AwsMskReadRequest;
pub type DescribeConfigurationRevisionRequest = AwsMskReadRequest;
pub type ListClusterOperationsRequest = AwsMskReadRequest;
pub type ListClustersV2Page = AwsMskReadPage;
pub type DescribeClusterV2Page = AwsMskReadPage;
pub type DescribeConfigurationRevisionPage = AwsMskReadPage;
pub type ListClusterOperationsPage = AwsMskReadPage;
