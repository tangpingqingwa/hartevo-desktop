use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{AwsFirehoseError, Result};
use crate::{LAYER1_PERMISSIONS, MAX_ALLOWLISTED_STREAMS, MAX_IDENTIFIER_BYTES};

pub const MAX_STREAM_NAME_BYTES: usize = 64;
pub const MAX_ACCOUNT_ID_BYTES: usize = 12;
pub const MAX_REGION_BYTES: usize = 32;
pub const MAX_SECRET_REFERENCE_BYTES: usize = 512;

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
            Err(AwsFirehoseError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsFirehoseError::InvalidDigest)
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

macro_rules! identifier_type {
    ($name:ident, $field:literal, $max:expr) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if valid_identifier(&value, $max) {
                    Ok(Self(value))
                } else {
                    Err(AwsFirehoseError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("aws-firehose-", $field, "/v1"),
                    &[("value", self.0.clone())],
                )
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if valid_identifier(&self.0, $max) {
                    Ok(())
                } else {
                    Err(AwsFirehoseError::InvalidIdentifier { field: $field })
                }
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

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

identifier_type!(AwsRegion, "aws_region", MAX_REGION_BYTES);
identifier_type!(
    DeliveryStreamName,
    "delivery_stream_name",
    MAX_STREAM_NAME_BYTES
);
identifier_type!(StreamVersionId, "stream_version_id", MAX_IDENTIFIER_BYTES);
identifier_type!(DestinationId, "destination_id", MAX_IDENTIFIER_BYTES);
identifier_type!(ProjectId, "project_id", MAX_IDENTIFIER_BYTES);
identifier_type!(MissionId, "mission_id", MAX_IDENTIFIER_BYTES);
identifier_type!(WorkProductId, "work_product_id", MAX_IDENTIFIER_BYTES);

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AwsAccountId(String);

impl AwsAccountId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() == MAX_ACCOUNT_ID_BYTES && value.bytes().all(|byte| byte.is_ascii_digit()) {
            Ok(Self(value))
        } else {
            Err(AwsFirehoseError::InvalidIdentifier {
                field: "aws_account_id",
            })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("aws-firehose-account/v1", &[("value", self.0.clone())])
    }

    pub(crate) fn validate(&self) -> Result<()> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

impl fmt::Debug for AwsAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AwsAccountId")
            .field(&format_args!("{}…", &self.0[..4]))
            .finish()
    }
}

impl fmt::Display for AwsAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(AwsFirehoseError::InvalidRevision)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub(crate) const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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

    pub const fn is_non_native(self) -> bool {
        true
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StreamStatus {
    Creating,
    Active,
    Deleting,
    DeletingFailed,
    CreatingFailed,
}

impl StreamStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Creating => "CREATING",
            Self::Active => "ACTIVE",
            Self::Deleting => "DELETING",
            Self::DeletingFailed => "DELETING_FAILED",
            Self::CreatingFailed => "CREATING_FAILED",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationType {
    S3,
    ExtendedS3,
    Redshift,
    OpenSearch,
    Elasticsearch,
    HttpEndpoint,
    Splunk,
    Snowflake,
    Iceberg,
}

impl DestinationType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::S3 => "s3",
            Self::ExtendedS3 => "extended_s3",
            Self::Redshift => "redshift",
            Self::OpenSearch => "opensearch",
            Self::Elasticsearch => "elasticsearch",
            Self::HttpEndpoint => "http_endpoint",
            Self::Splunk => "splunk",
            Self::Snowflake => "snowflake",
            Self::Iceberg => "iceberg",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationHealth {
    Healthy,
    Degraded,
    Unavailable,
    Unknown,
}

impl DestinationHealth {
    pub const fn is_usable(self) -> bool {
        matches!(self, Self::Healthy)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DestinationObservation {
    pub destination_id: DestinationId,
    pub destination_type: DestinationType,
    pub health: DestinationHealth,
    pub configuration_fingerprint: Digest,
    pub encryption_fingerprint: Option<Digest>,
}

impl DestinationObservation {
    pub fn new(
        destination_id: DestinationId,
        destination_type: DestinationType,
        health: DestinationHealth,
        configuration_fingerprint: Digest,
        encryption_fingerprint: Option<Digest>,
    ) -> Result<Self> {
        destination_id.validate()?;
        configuration_fingerprint.validate()?;
        if let Some(fingerprint) = &encryption_fingerprint {
            fingerprint.validate()?;
        }
        Ok(Self {
            destination_id,
            destination_type,
            health,
            configuration_fingerprint,
            encryption_fingerprint,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-firehose-destination-observation/v1",
            &[
                ("destination_id", self.destination_id.digest().to_string()),
                (
                    "destination_type",
                    self.destination_type.as_str().to_owned(),
                ),
                ("health", format!("{:?}", self.health)),
                ("configuration", self.configuration_fingerprint.to_string()),
                (
                    "encryption",
                    self.encryption_fingerprint
                        .as_ref()
                        .map_or_else(String::new, ToString::to_string),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryStreamObservation {
    pub stream_name: DeliveryStreamName,
    pub status: StreamStatus,
    pub version_id: StreamVersionId,
    pub source_revision: Revision,
    pub destinations: Vec<DestinationObservation>,
    pub encryption_fingerprint: Option<Digest>,
    pub configuration_fingerprint: Digest,
}

impl DeliveryStreamObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        stream_name: DeliveryStreamName,
        status: StreamStatus,
        version_id: StreamVersionId,
        source_revision: Revision,
        destinations: Vec<DestinationObservation>,
        encryption_fingerprint: Option<Digest>,
        configuration_fingerprint: Digest,
    ) -> Result<Self> {
        if destinations.is_empty() {
            return Err(AwsFirehoseError::DestinationAmbiguous);
        }
        stream_name.validate()?;
        version_id.validate()?;
        if let Some(fingerprint) = &encryption_fingerprint {
            fingerprint.validate()?;
        }
        configuration_fingerprint.validate()?;
        let mut ids = BTreeSet::new();
        for destination in &destinations {
            destination.destination_id.validate()?;
            if !ids.insert(destination.destination_id.clone()) {
                return Err(AwsFirehoseError::DestinationAmbiguous);
            }
        }
        Ok(Self {
            stream_name,
            status,
            version_id,
            source_revision,
            destinations,
            encryption_fingerprint,
            configuration_fingerprint,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-firehose-stream-observation/v1",
            &[
                ("stream", self.stream_name.digest().to_string()),
                ("status", self.status.as_str().to_owned()),
                ("version", self.version_id.digest().to_string()),
                ("source_revision", self.source_revision.get().to_string()),
                (
                    "destinations",
                    self.destinations
                        .iter()
                        .map(DestinationObservation::digest)
                        .map(|digest| digest.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "encryption",
                    self.encryption_fingerprint
                        .as_ref()
                        .map_or_else(String::new, ToString::to_string),
                ),
                ("configuration", self.configuration_fingerprint.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionIdentity {
    id: MissionId,
    revision: Revision,
}

impl MissionIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        Ok(Self {
            id: MissionId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    pub fn id(&self) -> &MissionId {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-firehose-mission-binding/v1",
            &[
                ("id", self.id.digest().to_string()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectIdentity {
    id: ProjectId,
    revision: Revision,
}

impl ProjectIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        Ok(Self {
            id: ProjectId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    pub fn id(&self) -> &ProjectId {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-firehose-project-binding/v1",
            &[
                ("id", self.id.digest().to_string()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductIdentity {
    id: WorkProductId,
    revision: Revision,
}

impl WorkProductIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        Ok(Self {
            id: WorkProductId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    pub fn id(&self) -> &WorkProductId {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-firehose-work-product-binding/v1",
            &[
                ("id", self.id.digest().to_string()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    revision: Revision,
    permissions: BTreeSet<String>,
    digest: Digest,
}

impl PermissionSnapshot {
    pub fn new<I, S>(revision: u64, permissions: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let revision = Revision::new(revision)?;
        let permissions = permissions
            .into_iter()
            .map(Into::into)
            .collect::<BTreeSet<_>>();
        let expected = LAYER1_PERMISSIONS
            .iter()
            .map(|permission| (*permission).to_owned())
            .collect::<BTreeSet<_>>();
        if permissions != expected {
            return Err(AwsFirehoseError::InvalidPermissionSnapshot);
        }
        let digest = Self::compute_digest(revision, &permissions);
        Ok(Self {
            revision,
            permissions,
            digest,
        })
    }

    pub fn layer_one(revision: u64) -> Result<Self> {
        Self::new(revision, LAYER1_PERMISSIONS)
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let expected = LAYER1_PERMISSIONS
            .iter()
            .map(|permission| (*permission).to_owned())
            .collect::<BTreeSet<_>>();
        let recomputed = Self::compute_digest(self.revision, &self.permissions);
        if self.permissions != expected || self.digest != recomputed {
            return Err(AwsFirehoseError::InvalidPermissionSnapshot);
        }
        Ok(())
    }

    fn compute_digest(revision: Revision, permissions: &BTreeSet<String>) -> Digest {
        Digest::from_parts(
            "aws-firehose-permission-snapshot/v1",
            &[
                ("revision", revision.get().to_string()),
                (
                    "permissions",
                    permissions.iter().cloned().collect::<Vec<_>>().join(","),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsFirehoseProviderScope {
    account: AwsAccountId,
    region: AwsRegion,
    allowlisted_streams: BTreeSet<DeliveryStreamName>,
    target_stream: DeliveryStreamName,
    stream_version_id: StreamVersionId,
    source_revision: Revision,
    provider_scope_digest: Digest,
}

impl AwsFirehoseProviderScope {
    pub fn new<I>(
        account: AwsAccountId,
        region: AwsRegion,
        allowlisted_streams: I,
        target_stream: DeliveryStreamName,
        stream_version_id: StreamVersionId,
        source_revision: Revision,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = DeliveryStreamName>,
    {
        let allowlisted_streams = allowlisted_streams.into_iter().collect::<BTreeSet<_>>();
        if allowlisted_streams.is_empty()
            || allowlisted_streams.len() > MAX_ALLOWLISTED_STREAMS
            || !allowlisted_streams.contains(&target_stream)
        {
            return Err(AwsFirehoseError::InvalidProviderScope);
        }
        let provider_scope_digest = Digest::from_parts(
            "aws-firehose-provider-scope/v1",
            &[
                ("account", account.digest().to_string()),
                ("region", region.as_str().to_owned()),
                (
                    "allowlist",
                    allowlisted_streams
                        .iter()
                        .map(DeliveryStreamName::digest)
                        .map(|digest| digest.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("target", target_stream.digest().to_string()),
                ("version", stream_version_id.digest().to_string()),
                ("source_revision", source_revision.get().to_string()),
            ],
        );
        Ok(Self {
            account,
            region,
            allowlisted_streams,
            target_stream,
            stream_version_id,
            source_revision,
            provider_scope_digest,
        })
    }

    pub fn account(&self) -> &AwsAccountId {
        &self.account
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn allowlisted_streams(&self) -> &BTreeSet<DeliveryStreamName> {
        &self.allowlisted_streams
    }

    pub fn target_stream(&self) -> &DeliveryStreamName {
        &self.target_stream
    }

    pub fn stream_version_id(&self) -> &StreamVersionId {
        &self.stream_version_id
    }

    pub const fn source_revision(&self) -> Revision {
        self.source_revision
    }

    pub fn digest(&self) -> &Digest {
        &self.provider_scope_digest
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.account.validate()?;
        self.region.validate()?;
        self.target_stream.validate()?;
        self.stream_version_id.validate()?;
        if self.allowlisted_streams.is_empty()
            || self.allowlisted_streams.len() > MAX_ALLOWLISTED_STREAMS
            || !self.allowlisted_streams.contains(&self.target_stream)
        {
            return Err(AwsFirehoseError::InvalidProviderScope);
        }
        let recomputed = Self::new(
            self.account.clone(),
            self.region.clone(),
            self.allowlisted_streams.clone(),
            self.target_stream.clone(),
            self.stream_version_id.clone(),
            self.source_revision,
        )?;
        if recomputed.provider_scope_digest != self.provider_scope_digest {
            return Err(AwsFirehoseError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsFirehoseDeliveryScope {
    provider_scope: AwsFirehoseProviderScope,
    mission: MissionIdentity,
    project: ProjectIdentity,
    work_product: WorkProductIdentity,
    permission_snapshot: PermissionSnapshot,
    scope_digest: Digest,
}

impl AwsFirehoseDeliveryScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        allowlisted_streams: impl IntoIterator<Item = DeliveryStreamName>,
        target_stream: DeliveryStreamName,
        stream_version_id: StreamVersionId,
        source_revision: Revision,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
        permission_snapshot: PermissionSnapshot,
    ) -> Result<Self> {
        let provider_scope = AwsFirehoseProviderScope::new(
            account,
            region,
            allowlisted_streams,
            target_stream,
            stream_version_id,
            source_revision,
        )?;
        Self::from_provider_scope(
            provider_scope,
            mission,
            project,
            work_product,
            permission_snapshot,
        )
    }

    pub fn from_provider_scope(
        provider_scope: AwsFirehoseProviderScope,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
        permission_snapshot: PermissionSnapshot,
    ) -> Result<Self> {
        provider_scope.validate()?;
        permission_snapshot.validate()?;
        let scope_digest = Digest::from_parts(
            "aws-firehose-delivery-scope/v1",
            &[
                ("provider_scope", provider_scope.digest().to_string()),
                ("mission", mission.digest().to_string()),
                ("project", project.digest().to_string()),
                ("work_product", work_product.digest().to_string()),
                ("permission", permission_snapshot.digest().to_string()),
            ],
        );
        Ok(Self {
            provider_scope,
            mission,
            project,
            work_product,
            permission_snapshot,
            scope_digest,
        })
    }

    pub fn provider_scope(&self) -> &AwsFirehoseProviderScope {
        &self.provider_scope
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

    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.provider_scope.validate()?;
        self.permission_snapshot.validate()?;
        self.mission.id.validate()?;
        self.project.id.validate()?;
        self.work_product.id.validate()?;
        let recomputed = Self::from_provider_scope(
            self.provider_scope.clone(),
            self.mission.clone(),
            self.project.clone(),
            self.work_product.clone(),
            self.permission_snapshot.clone(),
        )?;
        if recomputed.scope_digest != self.scope_digest {
            return Err(AwsFirehoseError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretScheme {
    Sigv4,
}

/// Opaque host-keyring reference. The raw handle is deliberately private and
/// this type intentionally does not implement `Serialize` or `Deserialize`.
pub struct SecretReference {
    handle: String,
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    scheme: SecretScheme,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            handle: self.handle.clone(),
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            scheme: self.scheme,
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
            .field("scheme", &self.scheme)
            .field("revoked", &self.revoked)
            .finish_non_exhaustive()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.scheme == other.scheme
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl Drop for SecretReference {
    fn drop(&mut self) {
        self.handle.zeroize();
    }
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &AwsFirehoseDeliveryScope,
        credential_revision: u64,
    ) -> Result<Self> {
        Self::sigv4(reference_id, scope, credential_revision)
    }

    pub fn sigv4(
        reference_id: impl Into<String>,
        scope: &AwsFirehoseDeliveryScope,
        credential_revision: u64,
    ) -> Result<Self> {
        let handle = reference_id.into();
        if !valid_text(&handle, MAX_SECRET_REFERENCE_BYTES, false) {
            return Err(AwsFirehoseError::InvalidSecretReference);
        }
        scope.validate()?;
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.digest().clone();
        let reference_digest = Digest::from_parts(
            "aws-firehose-secret-reference/v1",
            &[
                ("handle", handle.clone()),
                ("scope", scope_digest.to_string()),
                ("revision", credential_revision.get().to_string()),
                ("scheme", "sigv4".to_owned()),
            ],
        );
        Ok(Self {
            handle,
            reference_digest,
            scope_digest,
            credential_revision,
            scheme: SecretScheme::Sigv4,
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

    pub const fn scheme(&self) -> SecretScheme {
        self.scheme
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            Err(AwsFirehoseError::InvalidSecretReference)
        } else {
            self.revoked = true;
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentScope {
    id_digest: Digest,
    revision: Revision,
    expires_at_epoch_seconds: u64,
    revoked: bool,
}

impl ConsentScope {
    pub fn for_layer_one(
        id: impl Into<String>,
        revision: u64,
        expires_at_epoch_seconds: u64,
    ) -> Result<Self> {
        let id = id.into();
        if !valid_identifier(&id, MAX_IDENTIFIER_BYTES) || expires_at_epoch_seconds == 0 {
            return Err(AwsFirehoseError::InvalidConsent);
        }
        let revision = Revision::new(revision)?;
        Ok(Self {
            id_digest: Digest::from_parts(
                "aws-firehose-consent-id/v1",
                &[("id", id), ("revision", revision.get().to_string())],
            ),
            revision,
            expires_at_epoch_seconds,
            revoked: false,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-firehose-consent-scope/v1",
            &[
                ("id", self.id_digest.to_string()),
                ("revision", self.revision.get().to_string()),
                ("expires", self.expires_at_epoch_seconds.to_string()),
                ("revoked", self.revoked.to_string()),
            ],
        )
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub const fn expires_at_epoch_seconds(&self) -> u64 {
        self.expires_at_epoch_seconds
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub const fn is_active_at(&self, now_epoch_seconds: u64) -> bool {
        !self.revoked && now_epoch_seconds < self.expires_at_epoch_seconds
    }

    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            Err(AwsFirehoseError::ConsentRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionProjection {
    pub id_digest: Digest,
    pub revision: Revision,
}

impl From<&MissionIdentity> for MissionProjection {
    fn from(value: &MissionIdentity) -> Self {
        Self {
            id_digest: value.id.digest(),
            revision: value.revision,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectProjection {
    pub id_digest: Digest,
    pub revision: Revision,
}

impl From<&ProjectIdentity> for ProjectProjection {
    fn from(value: &ProjectIdentity) -> Self {
        Self {
            id_digest: value.id.digest(),
            revision: value.revision,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductProjection {
    pub id_digest: Digest,
    pub revision: Revision,
}

impl From<&WorkProductIdentity> for WorkProductProjection {
    fn from(value: &WorkProductIdentity) -> Self {
        Self {
            id_digest: value.id.digest(),
            revision: value.revision,
        }
    }
}
