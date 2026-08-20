use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{AwsKinesisStreamResultError, Result};
use crate::{
    LAYER1_PERMISSIONS, MAX_IDENTIFIER_BYTES, MAX_MONITORING_METRICS, MAX_PAGES,
    MAX_RESPONSE_BYTES, MAX_SHARDS, NEXT_TOKEN_TTL_SECONDS,
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
        if crate::valid_digest(&value) {
            Ok(Self(value))
        } else {
            Err(AwsKinesisStreamResultError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if crate::valid_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsKinesisStreamResultError::InvalidDigest)
        }
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

fn valid_text(value: &str, maximum: usize, allow_internal_whitespace: bool) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && (allow_internal_whitespace || !value.chars().any(char::is_whitespace))
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    valid_text(value, maximum, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:@/+~-".contains(&byte))
}

fn valid_arn(value: &str, service: &str) -> bool {
    valid_text(value, 2_048, false) && value.starts_with("arn:") && value.contains(service)
}

fn digest_value(domain: &str, value: &str) -> Digest {
    Digest::from_parts(domain, &[("value", value.to_owned())])
}

macro_rules! redacted_text {
    ($name:ident, $field:literal, $validator:expr, $domain:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(AwsKinesisStreamResultError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                digest_value($domain, &self.0)
            }

            pub fn redacted(&self) -> String {
                format!("{}:{}", $field, &self.digest().as_str()[..16])
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(AwsKinesisStreamResultError::InvalidIdentifier { field: $field })
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
    };
}

redacted_text!(
    AwsAccountId,
    "account",
    |value: &str| value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit()),
    "aws-kinesis-account/v1"
);
redacted_text!(
    AwsRegion,
    "region",
    |value: &str| valid_identifier(value, 64),
    "aws-kinesis-region/v1"
);
redacted_text!(
    StreamArn,
    "stream-arn",
    |value: &str| valid_arn(value, ":kinesis:"),
    "aws-kinesis-stream-arn/v1"
);
redacted_text!(
    StreamName,
    "stream-name",
    |value: &str| {
        (1..=128).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    },
    "aws-kinesis-stream-name/v1"
);
redacted_text!(
    ConsumerArn,
    "consumer-arn",
    |value: &str| valid_arn(value, ":kinesis:") && value.contains("/consumer/"),
    "aws-kinesis-consumer-arn/v1"
);
redacted_text!(
    ConsumerName,
    "consumer-name",
    |value: &str| {
        (1..=128).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    },
    "aws-kinesis-consumer-name/v1"
);
redacted_text!(
    ShardId,
    "shard-id",
    |value: &str| {
        (1..=128).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    },
    "aws-kinesis-shard-id/v1"
);

#[derive(Clone, Eq, PartialEq)]
pub struct StreamIdentity {
    arn: StreamArn,
    name: StreamName,
}

impl StreamIdentity {
    pub fn new(arn: StreamArn, name: StreamName) -> Result<Self> {
        let identity = Self { arn, name };
        identity.validate()?;
        Ok(identity)
    }

    pub fn arn(&self) -> &StreamArn {
        &self.arn
    }
    pub fn name(&self) -> &StreamName {
        &self.name
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-kinesis-stream-identity/v1",
            &[
                ("arn", self.arn.digest().as_str().to_owned()),
                ("name", self.name.digest().as_str().to_owned()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.arn.validate()?;
        self.name.validate()
    }
}

impl fmt::Debug for StreamIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StreamIdentity")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct StreamVersion(i64);

impl StreamVersion {
    pub fn new(creation_timestamp_epoch_seconds: i64) -> Result<Self> {
        if creation_timestamp_epoch_seconds <= 0 {
            return Err(AwsKinesisStreamResultError::InvalidScope);
        }
        Ok(Self(creation_timestamp_epoch_seconds))
    }

    pub const fn value(self) -> i64 {
        self.0
    }

    pub fn digest(self) -> Digest {
        Digest::from_parts(
            "aws-kinesis-stream-version/v1",
            &[("creation_timestamp", self.0.to_string())],
        )
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ConsumerIdentity {
    arn: ConsumerArn,
    name: ConsumerName,
}

impl ConsumerIdentity {
    pub fn new(arn: ConsumerArn, name: ConsumerName) -> Result<Self> {
        let identity = Self { arn, name };
        identity.validate()?;
        Ok(identity)
    }

    pub fn arn(&self) -> &ConsumerArn {
        &self.arn
    }
    pub fn name(&self) -> &ConsumerName {
        &self.name
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-kinesis-consumer-identity/v1",
            &[
                ("arn", self.arn.digest().as_str().to_owned()),
                ("name", self.name.digest().as_str().to_owned()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.arn.validate()?;
        self.name.validate()
    }
}

impl fmt::Debug for ConsumerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsumerIdentity")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct MissionIdentity {
    id: String,
    revision: u64,
}

macro_rules! scoped_identity {
    ($name:ident, $domain:literal, $label:literal) => {
        impl $name {
            pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
                let id = id.into();
                if !valid_identifier(&id, MAX_IDENTIFIER_BYTES) || revision == 0 {
                    return Err(AwsKinesisStreamResultError::InvalidScope);
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
                    $domain,
                    &[
                        ("id", self.id.clone()),
                        ("revision", self.revision.to_string()),
                    ],
                )
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if valid_identifier(&self.id, MAX_IDENTIFIER_BYTES) && self.revision != 0 {
                    Ok(())
                } else {
                    Err(AwsKinesisStreamResultError::InvalidScope)
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct($label)
                    .field("digest", &self.digest())
                    .field("revision", &self.revision)
                    .finish()
            }
        }
    };
}

scoped_identity!(MissionIdentity, "aws-kinesis-mission/v1", "MissionIdentity");

#[derive(Clone, Eq, PartialEq)]
pub struct ProjectIdentity {
    id: String,
    revision: u64,
}

scoped_identity!(ProjectIdentity, "aws-kinesis-project/v1", "ProjectIdentity");

#[derive(Clone, Eq, PartialEq)]
pub struct WorkProductIdentity {
    id: String,
    revision: u64,
}

scoped_identity!(
    WorkProductIdentity,
    "aws-kinesis-work-product/v1",
    "WorkProductIdentity"
);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardFilterKind {
    AtTrimHorizon,
    FromTrimHorizon,
    AtLatest,
    AfterShardId,
    AtTimestamp,
    FromTimestamp,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShardFilter {
    pub kind: ShardFilterKind,
    pub shard_id_digest: Option<Digest>,
    pub timestamp_epoch_seconds: Option<i64>,
}

impl ShardFilter {
    pub fn new(
        kind: ShardFilterKind,
        shard_id: Option<impl Into<String>>,
        timestamp_epoch_seconds: Option<i64>,
    ) -> Result<Self> {
        let shard_id_digest = shard_id
            .map(Into::into)
            .map(|value| {
                ShardId::new(value)
                    .map(|id| id.digest())
                    .map_err(|_| AwsKinesisStreamResultError::InvalidFilter)
            })
            .transpose()?;
        let requires_id = matches!(kind, ShardFilterKind::AfterShardId);
        let requires_timestamp = matches!(
            kind,
            ShardFilterKind::AtTimestamp | ShardFilterKind::FromTimestamp
        );
        if requires_id != shard_id_digest.is_some()
            || requires_timestamp != timestamp_epoch_seconds.is_some()
            || (!requires_id && shard_id_digest.is_some())
            || (!requires_timestamp && timestamp_epoch_seconds.is_some())
            || timestamp_epoch_seconds.is_some_and(|timestamp| timestamp <= 0)
        {
            return Err(AwsKinesisStreamResultError::InvalidFilter);
        }
        Ok(Self {
            kind,
            shard_id_digest,
            timestamp_epoch_seconds,
        })
    }

    pub fn at_trim_horizon() -> Self {
        Self::new(ShardFilterKind::AtTrimHorizon, None::<String>, None).expect("valid filter")
    }

    pub fn from_trim_horizon() -> Self {
        Self::new(ShardFilterKind::FromTrimHorizon, None::<String>, None).expect("valid filter")
    }

    pub fn at_latest() -> Self {
        Self::new(ShardFilterKind::AtLatest, None::<String>, None).expect("valid filter")
    }

    pub fn after_shard_id(shard_id: impl Into<String>) -> Result<Self> {
        Self::new(ShardFilterKind::AfterShardId, Some(shard_id), None)
    }

    pub fn at_timestamp(timestamp_epoch_seconds: i64) -> Result<Self> {
        Self::new(
            ShardFilterKind::AtTimestamp,
            None::<String>,
            Some(timestamp_epoch_seconds),
        )
    }

    pub fn from_timestamp(timestamp_epoch_seconds: i64) -> Result<Self> {
        Self::new(
            ShardFilterKind::FromTimestamp,
            None::<String>,
            Some(timestamp_epoch_seconds),
        )
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-kinesis-shard-filter/v1",
            &[
                ("kind", format!("{:?}", self.kind)),
                (
                    "shard_id",
                    self.shard_id_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "timestamp",
                    self.timestamp_epoch_seconds
                        .map_or_else(String::new, |value| value.to_string()),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let requires_id = matches!(self.kind, ShardFilterKind::AfterShardId);
        let requires_timestamp = matches!(
            self.kind,
            ShardFilterKind::AtTimestamp | ShardFilterKind::FromTimestamp
        );
        if requires_id != self.shard_id_digest.is_some()
            || requires_timestamp != self.timestamp_epoch_seconds.is_some()
            || self
                .timestamp_epoch_seconds
                .is_some_and(|timestamp| timestamp <= 0)
        {
            return Err(AwsKinesisStreamResultError::InvalidFilter);
        }
        self.shard_id_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()
            .map(|_| ())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsKinesisStreamScope {
    account: AwsAccountId,
    region: AwsRegion,
    stream: StreamIdentity,
    stream_version: StreamVersion,
    shard_filter: ShardFilter,
    consumer: Option<ConsumerIdentity>,
    mission: MissionIdentity,
    project: ProjectIdentity,
    work_product: WorkProductIdentity,
}

impl AwsKinesisStreamScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        stream: StreamIdentity,
        stream_version: StreamVersion,
        shard_filter: ShardFilter,
        consumer: Option<ConsumerIdentity>,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let scope = Self {
            account,
            region,
            stream,
            stream_version,
            shard_filter,
            consumer,
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
    pub fn stream(&self) -> &StreamIdentity {
        &self.stream
    }
    pub fn stream_version(&self) -> StreamVersion {
        self.stream_version
    }
    pub fn shard_filter(&self) -> &ShardFilter {
        &self.shard_filter
    }
    pub fn consumer(&self) -> Option<&ConsumerIdentity> {
        self.consumer.as_ref()
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
            "aws-kinesis-stream-scope/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                ("stream", self.stream.digest().as_str().to_owned()),
                ("version", self.stream_version.digest().as_str().to_owned()),
                ("filter", self.shard_filter.digest().as_str().to_owned()),
                (
                    "consumer",
                    self.consumer
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                ("mission", self.mission.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.account.validate()?;
        self.region.validate()?;
        self.stream.validate()?;
        if !stream_arn_matches(
            self.stream.arn().as_str(),
            self.account.as_str(),
            self.region.as_str(),
            self.stream.name().as_str(),
        ) {
            return Err(AwsKinesisStreamResultError::InvalidScope);
        }
        if self.stream_version.value() <= 0 {
            return Err(AwsKinesisStreamResultError::InvalidScope);
        }
        self.shard_filter.validate()?;
        if let Some(consumer) = &self.consumer {
            consumer.validate()?;
            if !consumer_arn_matches(
                consumer.arn().as_str(),
                self.account.as_str(),
                self.region.as_str(),
                self.stream.name().as_str(),
                consumer.name().as_str(),
            ) {
                return Err(AwsKinesisStreamResultError::InvalidScope);
            }
        }
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()
    }
}

fn stream_arn_matches(arn: &str, account: &str, region: &str, stream_name: &str) -> bool {
    let parts = arn.splitn(6, ':').collect::<Vec<_>>();
    parts.len() == 6
        && parts[0] == "arn"
        && !parts[1].is_empty()
        && parts[2] == "kinesis"
        && parts[3] == region
        && parts[4] == account
        && parts[5] == format!("stream/{stream_name}")
}

fn consumer_arn_matches(
    arn: &str,
    account: &str,
    region: &str,
    stream_name: &str,
    consumer_name: &str,
) -> bool {
    let parts = arn.splitn(6, ':').collect::<Vec<_>>();
    let resource_prefix = format!("stream/{stream_name}/consumer/{consumer_name}:");
    parts.len() == 6
        && parts[0] == "arn"
        && !parts[1].is_empty()
        && parts[2] == "kinesis"
        && parts[3] == region
        && parts[4] == account
        && parts[5]
            .strip_prefix(&resource_prefix)
            .is_some_and(|suffix| {
                !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
            })
}

impl fmt::Debug for AwsKinesisStreamScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsKinesisStreamScope")
            .field("digest", &self.digest())
            .field("account", &self.account)
            .field("region", &self.region)
            .field("stream", &self.stream)
            .field("stream_version", &self.stream_version)
            .field("shard_filter", &self.shard_filter)
            .field("consumer", &self.consumer)
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

/// Opaque SigV4 reference. The caller handle is hashed and dropped; this
/// type intentionally does not implement `Serialize`.
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
            return Err(AwsKinesisStreamResultError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_parts(
            "aws-kinesis-opaque-sigv4-reference/v1",
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
            scope_digest: Digest::from_text("unbound-aws-kinesis-secret-scope"),
            revision,
            revoked: false,
        })
    }

    pub fn sigv4(
        opaque_handle: impl Into<String>,
        scope: &AwsKinesisStreamScope,
        revision: u64,
    ) -> Result<Self> {
        let mut reference = Self::new(opaque_handle, revision)?;
        reference.scope_digest = scope.digest();
        reference.reference_digest = Digest::from_parts(
            "aws-kinesis-opaque-sigv4-reference/v1",
            &[
                ("kind", "sigv4_credential".to_owned()),
                ("reference", reference.reference_digest.as_str().to_owned()),
                ("scope", reference.scope_digest.as_str().to_owned()),
                ("revision", revision.to_string()),
            ],
        );
        Ok(reference)
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
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub(crate) fn validate(&self, scope: &AwsKinesisStreamScope) -> Result<()> {
        if !matches!(self.kind, SecretKind::Sigv4Credential)
            || self.revision == 0
            || self.revoked
            || self.scope_digest != scope.digest()
        {
            return Err(AwsKinesisStreamResultError::InvalidSecretReference);
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
    pub const fn claims_connected(self) -> bool {
        false
    }
    pub const fn claims_first_party(self) -> bool {
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
        let snapshot = Self {
            revision,
            permissions: permissions.into_iter().map(Into::into).collect(),
        };
        snapshot.validate()?;
        Ok(snapshot)
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
            "aws-kinesis-permissions/v1",
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
            Err(AwsKinesisStreamResultError::InvalidPermissionSnapshot)
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
        let consent = Self {
            id: id.into(),
            revision,
            permissions: permissions.into_iter().map(Into::into).collect(),
            expires_at,
            revoked: false,
        };
        consent.validate()?;
        Ok(consent)
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
            "aws-kinesis-consent/v1",
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
            Err(AwsKinesisStreamResultError::InvalidConsent)
        } else {
            Ok(())
        }
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StreamStatus {
    Creating,
    Active,
    Updating,
    Deleting,
    Unknown,
}

impl StreamStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Creating => "CREATING",
            Self::Active => "ACTIVE",
            Self::Updating => "UPDATING",
            Self::Deleting => "DELETING",
            Self::Unknown => "UNKNOWN",
        }
    }

    pub fn from_api(value: &str) -> Self {
        match value {
            "CREATING" => Self::Creating,
            "ACTIVE" => Self::Active,
            "UPDATING" => Self::Updating,
            "DELETING" => Self::Deleting,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamMode {
    Provisioned,
    OnDemand,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EncryptionType {
    None,
    Kms,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptionProjection {
    pub encrypted: bool,
    pub encryption_type: EncryptionType,
    pub key_reference_digest: Option<Digest>,
}

impl EncryptionProjection {
    fn from_input(encryption_type: EncryptionType, key_id: Option<String>) -> Result<Self> {
        let key_reference_digest = key_id
            .map(|key| {
                if valid_text(&key, 2_048, false) {
                    Ok(digest_value(
                        "aws-kinesis-encryption-key-reference/v1",
                        &key,
                    ))
                } else {
                    Err(AwsKinesisStreamResultError::InvalidIdentifier {
                        field: "encryption-key-id",
                    })
                }
            })
            .transpose()?;
        let encrypted = !matches!(encryption_type, EncryptionType::None);
        if encrypted != key_reference_digest.is_some() {
            return Err(AwsKinesisStreamResultError::InvalidScope);
        }
        Ok(Self {
            encrypted,
            encryption_type,
            key_reference_digest,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-kinesis-encryption/v1",
            &[
                ("encrypted", self.encrypted.to_string()),
                ("type", format!("{:?}", self.encryption_type)),
                (
                    "key",
                    self.key_reference_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let encryption_requires_key = !matches!(self.encryption_type, EncryptionType::None);
        if self.encrypted != encryption_requires_key
            || self.encrypted != self.key_reference_digest.is_some()
        {
            return Err(AwsKinesisStreamResultError::TamperedEvidence);
        }
        self.key_reference_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()
            .map(|_| ())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitoringProjection {
    pub enabled: bool,
    pub metric_count: u16,
    pub metrics_digest: Option<Digest>,
}

impl MonitoringProjection {
    fn from_metrics(metrics: &[String]) -> Result<Self> {
        if metrics.len() > MAX_MONITORING_METRICS
            || metrics.iter().any(|metric| !valid_identifier(metric, 128))
        {
            return Err(AwsKinesisStreamResultError::InvalidScope);
        }
        let metrics_digest = (!metrics.is_empty()).then(|| {
            Digest::from_parts(
                "aws-kinesis-enhanced-monitoring/v1",
                &[("metrics", metrics.join("\n"))],
            )
        });
        Ok(Self {
            enabled: !metrics.is_empty(),
            metric_count: u16::try_from(metrics.len()).unwrap_or(u16::MAX),
            metrics_digest,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-kinesis-monitoring/v1",
            &[
                ("enabled", self.enabled.to_string()),
                ("count", self.metric_count.to_string()),
                (
                    "metrics",
                    self.metrics_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.metric_count as usize > MAX_MONITORING_METRICS
            || self.enabled != (self.metric_count != 0)
            || self.enabled != self.metrics_digest.is_some()
        {
            return Err(AwsKinesisStreamResultError::TamperedEvidence);
        }
        self.metrics_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()
            .map(|_| ())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct StreamSummaryInput {
    pub status: StreamStatus,
    pub mode: StreamMode,
    pub retention_period_hours: u32,
    pub open_shard_count: u32,
    pub creation_timestamp_epoch_seconds: i64,
    pub monitoring_metrics: Vec<String>,
    pub encryption_type: EncryptionType,
    pub encryption_key_id: Option<String>,
    pub max_record_size_kib: Option<u32>,
}

impl fmt::Debug for StreamSummaryInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StreamSummaryInput")
            .field("status", &self.status)
            .field("mode", &self.mode)
            .field("retention_period_hours", &self.retention_period_hours)
            .field("open_shard_count", &self.open_shard_count)
            .field(
                "creation_timestamp_epoch_seconds",
                &self.creation_timestamp_epoch_seconds,
            )
            .field("monitoring_metric_count", &self.monitoring_metrics.len())
            .field("encryption_type", &self.encryption_type)
            .field(
                "encryption_key_digest",
                &self
                    .encryption_key_id
                    .as_deref()
                    .map(|key| digest_value("aws-kinesis-encryption-key-reference/v1", key)),
            )
            .field("max_record_size_kib", &self.max_record_size_kib)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct StreamSummary {
    stream: StreamIdentity,
    version: StreamVersion,
    status: StreamStatus,
    mode: StreamMode,
    retention_period_hours: u32,
    open_shard_count: u32,
    creation_timestamp_epoch_seconds: i64,
    monitoring: MonitoringProjection,
    encryption: EncryptionProjection,
    max_record_size_kib: Option<u32>,
}

impl StreamSummary {
    pub fn new(scope: &AwsKinesisStreamScope, input: StreamSummaryInput) -> Result<Self> {
        if input.creation_timestamp_epoch_seconds != scope.stream_version.value()
            || input.retention_period_hours == 0
            || input.retention_period_hours > 8_760
            || input.open_shard_count > MAX_SHARDS as u32
            || input
                .max_record_size_kib
                .is_some_and(|size| size == 0 || size > 1_024)
        {
            return Err(AwsKinesisStreamResultError::StreamDrift);
        }
        let summary = Self {
            stream: scope.stream.clone(),
            version: scope.stream_version,
            status: input.status,
            mode: input.mode,
            retention_period_hours: input.retention_period_hours,
            open_shard_count: input.open_shard_count,
            creation_timestamp_epoch_seconds: input.creation_timestamp_epoch_seconds,
            monitoring: MonitoringProjection::from_metrics(&input.monitoring_metrics)?,
            encryption: EncryptionProjection::from_input(
                input.encryption_type,
                input.encryption_key_id,
            )?,
            max_record_size_kib: input.max_record_size_kib,
        };
        summary.validate_against(scope)?;
        Ok(summary)
    }

    pub fn status(&self) -> StreamStatus {
        self.status
    }
    pub fn mode(&self) -> StreamMode {
        self.mode
    }
    pub const fn retention_period_hours(&self) -> u32 {
        self.retention_period_hours
    }
    pub const fn open_shard_count(&self) -> u32 {
        self.open_shard_count
    }
    pub const fn creation_timestamp_epoch_seconds(&self) -> i64 {
        self.creation_timestamp_epoch_seconds
    }
    pub fn monitoring(&self) -> &MonitoringProjection {
        &self.monitoring
    }
    pub fn encryption(&self) -> &EncryptionProjection {
        &self.encryption
    }
    pub const fn max_record_size_kib(&self) -> Option<u32> {
        self.max_record_size_kib
    }

    pub fn digest(&self) -> Digest {
        stream_summary_digest(
            &self.stream,
            self.version,
            self.status,
            self.mode,
            self.retention_period_hours,
            self.open_shard_count,
            self.creation_timestamp_epoch_seconds,
            &self.monitoring,
            &self.encryption,
            self.max_record_size_kib,
        )
    }

    pub fn validate_against(&self, scope: &AwsKinesisStreamScope) -> Result<()> {
        if self.stream != scope.stream
            || self.version != scope.stream_version
            || self.creation_timestamp_epoch_seconds != scope.stream_version.value()
        {
            return Err(AwsKinesisStreamResultError::StreamDrift);
        }
        self.monitoring.validate()?;
        self.encryption.validate()?;
        Ok(())
    }
}

fn stream_summary_digest(
    stream: &StreamIdentity,
    version: StreamVersion,
    status: StreamStatus,
    mode: StreamMode,
    retention_period_hours: u32,
    open_shard_count: u32,
    creation_timestamp_epoch_seconds: i64,
    monitoring: &MonitoringProjection,
    encryption: &EncryptionProjection,
    max_record_size_kib: Option<u32>,
) -> Digest {
    Digest::from_parts(
        "aws-kinesis-stream-summary/v1",
        &[
            ("stream", stream.digest().as_str().to_owned()),
            ("version", version.digest().as_str().to_owned()),
            ("status", status.as_str().to_owned()),
            ("mode", format!("{mode:?}")),
            ("retention", retention_period_hours.to_string()),
            ("open_shards", open_shard_count.to_string()),
            ("creation", creation_timestamp_epoch_seconds.to_string()),
            ("monitoring", monitoring.digest().as_str().to_owned()),
            ("encryption", encryption.digest().as_str().to_owned()),
            (
                "max_record_size",
                max_record_size_kib.map_or_else(String::new, |value| value.to_string()),
            ),
        ],
    )
}

impl fmt::Debug for StreamSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StreamSummary")
            .field("digest", &self.digest())
            .field("status", &self.status)
            .field("mode", &self.mode)
            .field("retention_period_hours", &self.retention_period_hours)
            .field("open_shard_count", &self.open_shard_count)
            .field("monitoring", &self.monitoring)
            .field("encryption", &self.encryption)
            .finish()
    }
}

impl Serialize for StreamSummary {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("StreamSummary", 10)?;
        state.serialize_field("streamDigest", &self.stream.digest())?;
        state.serialize_field("streamVersionDigest", &self.version.digest())?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("mode", &self.mode)?;
        state.serialize_field("retentionPeriodHours", &self.retention_period_hours)?;
        state.serialize_field("openShardCount", &self.open_shard_count)?;
        state.serialize_field(
            "creationTimestampEpochSeconds",
            &self.creation_timestamp_epoch_seconds,
        )?;
        state.serialize_field("monitoring", &self.monitoring)?;
        state.serialize_field("encryption", &self.encryption)?;
        state.serialize_field("maxRecordSizeKiB", &self.max_record_size_kib)?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ShardMetadataInput {
    pub shard_id: String,
    pub parent_shard_id: Option<String>,
    pub adjacent_parent_shard_id: Option<String>,
}

impl fmt::Debug for ShardMetadataInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShardMetadataInput")
            .field("shard_id", &redact_shard_id(&self.shard_id))
            .field(
                "parent_shard_id",
                &self.parent_shard_id.as_deref().map(redact_shard_id),
            )
            .field(
                "adjacent_parent_shard_id",
                &self
                    .adjacent_parent_shard_id
                    .as_deref()
                    .map(redact_shard_id),
            )
            .finish()
    }
}

fn redact_shard_id(value: &str) -> String {
    ShardId::new(value.to_owned()).map_or_else(
        |_| "shard-id:invalid".to_owned(),
        |shard_id| format!("shard-id:{}", &shard_id.digest().as_str()[..16]),
    )
}

impl ShardMetadataInput {
    pub fn new(
        shard_id: impl Into<String>,
        parent_shard_id: Option<impl Into<String>>,
        adjacent_parent_shard_id: Option<impl Into<String>>,
    ) -> Self {
        Self {
            shard_id: shard_id.into(),
            parent_shard_id: parent_shard_id.map(Into::into),
            adjacent_parent_shard_id: adjacent_parent_shard_id.map(Into::into),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShardLineageProjection {
    pub shard_id_digest: Digest,
    pub parent_shard_id_digest: Option<Digest>,
    pub adjacent_parent_shard_id_digest: Option<Digest>,
    pub lineage_digest: Digest,
}

impl ShardLineageProjection {
    pub fn from_input(input: ShardMetadataInput) -> Result<Self> {
        let shard_id = ShardId::new(input.shard_id)?;
        shard_id.validate()?;
        let parent_shard_id_digest = input
            .parent_shard_id
            .map(ShardId::new)
            .transpose()?
            .map(|value| value.digest());
        let adjacent_parent_shard_id_digest = input
            .adjacent_parent_shard_id
            .map(ShardId::new)
            .transpose()?
            .map(|value| value.digest());
        let shard_id_digest = shard_id.digest();
        let lineage_digest = Digest::from_parts(
            "aws-kinesis-shard-lineage/v1",
            &[
                ("shard", shard_id_digest.as_str().to_owned()),
                (
                    "parent",
                    parent_shard_id_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "adjacent_parent",
                    adjacent_parent_shard_id_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
            ],
        );
        Ok(Self {
            shard_id_digest,
            parent_shard_id_digest,
            adjacent_parent_shard_id_digest,
            lineage_digest,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.shard_id_digest.validate()?;
        self.parent_shard_id_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.adjacent_parent_shard_id_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        let expected = Digest::from_parts(
            "aws-kinesis-shard-lineage/v1",
            &[
                ("shard", self.shard_id_digest.as_str().to_owned()),
                (
                    "parent",
                    self.parent_shard_id_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "adjacent_parent",
                    self.adjacent_parent_shard_id_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
            ],
        );
        if self.lineage_digest != expected {
            return Err(AwsKinesisStreamResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConsumerStatus {
    Creating,
    Active,
    Deleting,
    Deregistered,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumerMetadataInput {
    pub status: ConsumerStatus,
    pub creation_timestamp_epoch_seconds: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsumerProjection {
    pub consumer_digest: Digest,
    pub consumer_name_digest: Digest,
    pub status: ConsumerStatus,
    pub creation_timestamp_epoch_seconds: i64,
    pub metadata_digest: Digest,
}

impl ConsumerProjection {
    pub fn new(scope: &AwsKinesisStreamScope, input: ConsumerMetadataInput) -> Result<Self> {
        let consumer = scope
            .consumer()
            .ok_or(AwsKinesisStreamResultError::ConsumerDrift)?;
        if input.creation_timestamp_epoch_seconds <= 0 {
            return Err(AwsKinesisStreamResultError::ConsumerDrift);
        }
        let consumer_digest = consumer.digest();
        let consumer_name_digest = consumer.name().digest();
        let metadata_digest = Digest::from_parts(
            "aws-kinesis-consumer-metadata/v1",
            &[
                ("consumer", consumer_digest.as_str().to_owned()),
                ("name", consumer_name_digest.as_str().to_owned()),
                ("status", format!("{:?}", input.status)),
                (
                    "created",
                    input.creation_timestamp_epoch_seconds.to_string(),
                ),
            ],
        );
        Ok(Self {
            consumer_digest,
            consumer_name_digest,
            status: input.status,
            creation_timestamp_epoch_seconds: input.creation_timestamp_epoch_seconds,
            metadata_digest,
        })
    }

    pub fn validate_against(&self, scope: &AwsKinesisStreamScope) -> Result<()> {
        let consumer = scope
            .consumer()
            .ok_or(AwsKinesisStreamResultError::ConsumerDrift)?;
        if self.consumer_digest != consumer.digest()
            || self.consumer_name_digest != consumer.name().digest()
            || self.creation_timestamp_epoch_seconds <= 0
        {
            return Err(AwsKinesisStreamResultError::ConsumerDrift);
        }
        let expected = Digest::from_parts(
            "aws-kinesis-consumer-metadata/v1",
            &[
                ("consumer", self.consumer_digest.as_str().to_owned()),
                ("name", self.consumer_name_digest.as_str().to_owned()),
                ("status", format!("{:?}", self.status)),
                ("created", self.creation_timestamp_epoch_seconds.to_string()),
            ],
        );
        if self.metadata_digest != expected {
            return Err(AwsKinesisStreamResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamProjection {
    pub stream_digest: Digest,
    pub stream_version_digest: Digest,
    pub status: StreamStatus,
    pub mode: StreamMode,
    pub retention_period_hours: u32,
    pub open_shard_count: u32,
    pub monitoring: MonitoringProjection,
    pub encryption: EncryptionProjection,
    pub shard_count: u32,
    pub shard_lineage: Vec<ShardLineageProjection>,
    pub topology_digest: Digest,
    pub consumer: Option<ConsumerProjection>,
    pub summary_digest: Digest,
}

impl StreamProjection {
    pub fn from_parts(
        scope: &AwsKinesisStreamScope,
        summary: &StreamSummary,
        shards: Vec<ShardLineageProjection>,
        consumer: Option<ConsumerProjection>,
    ) -> Result<Self> {
        summary.validate_against(scope)?;
        if shards.len() > MAX_SHARDS {
            return Err(AwsKinesisStreamResultError::PartialEvidence);
        }
        for shard in &shards {
            shard.validate()?;
        }
        if let Some(metadata) = &consumer {
            metadata.validate_against(scope)?;
        }
        let summary_digest = summary.digest();
        let topology_digest = topology_digest(&summary_digest, &shards, consumer.as_ref());
        Ok(Self {
            stream_digest: scope.stream.digest(),
            stream_version_digest: scope.stream_version.digest(),
            status: summary.status,
            mode: summary.mode,
            retention_period_hours: summary.retention_period_hours,
            open_shard_count: summary.open_shard_count,
            monitoring: summary.monitoring.clone(),
            encryption: summary.encryption.clone(),
            shard_count: u32::try_from(shards.len()).unwrap_or(u32::MAX),
            shard_lineage: shards,
            topology_digest,
            consumer,
            summary_digest,
        })
    }

    pub fn validate(&self, scope: &AwsKinesisStreamScope) -> Result<()> {
        if self.stream_digest != scope.stream.digest()
            || self.stream_version_digest != scope.stream_version.digest()
            || self.shard_count as usize != self.shard_lineage.len()
            || self.shard_lineage.len() > MAX_SHARDS
        {
            return Err(AwsKinesisStreamResultError::ScopeMismatch);
        }
        self.summary_digest.validate()?;
        self.topology_digest.validate()?;
        self.monitoring.validate()?;
        self.encryption.validate()?;
        for shard in &self.shard_lineage {
            shard.validate()?;
        }
        if let Some(consumer) = &self.consumer {
            consumer.validate_against(scope)?;
        }
        if self.topology_digest
            != topology_digest(
                &self.summary_digest,
                &self.shard_lineage,
                self.consumer.as_ref(),
            )
        {
            return Err(AwsKinesisStreamResultError::TamperedEvidence);
        }
        Ok(())
    }
}

fn topology_digest(
    summary_digest: &Digest,
    shards: &[ShardLineageProjection],
    consumer: Option<&ConsumerProjection>,
) -> Digest {
    Digest::from_parts(
        "aws-kinesis-topology/v1",
        &[
            ("stream", summary_digest.as_str().to_owned()),
            (
                "lineage",
                shards
                    .iter()
                    .map(|value| value.lineage_digest.as_str())
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
            (
                "consumer",
                consumer.map_or_else(String::new, |value| {
                    value.metadata_digest.as_str().to_owned()
                }),
            ),
        ],
    )
}

impl From<StreamStatus> for KinesisEvidenceState {
    fn from(status: StreamStatus) -> Self {
        match status {
            StreamStatus::Creating => Self::Creating,
            StreamStatus::Active => Self::Active,
            StreamStatus::Updating => Self::Updating,
            StreamStatus::Deleting => Self::Deleting,
            StreamStatus::Unknown => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KinesisEvidenceState {
    Creating,
    Active,
    Updating,
    Deleting,
    Partial,
    TokenExpired,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
}

impl KinesisEvidenceState {
    pub const fn is_review_complete(self) -> bool {
        matches!(
            self,
            Self::Creating | Self::Active | Self::Updating | Self::Deleting
        )
    }

    pub const fn is_non_adoptable(self) -> bool {
        true
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
    pub filter_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub summary_digest: Option<Digest>,
    pub shards_digest: Option<Digest>,
    pub consumer_digest: Option<Digest>,
    pub topology_digest: Option<Digest>,
    pub encryption_digest: Option<Digest>,
    pub evidence_digest: Digest,
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

pub(crate) fn mission_projection(value: &MissionIdentity) -> MissionProjection {
    MissionProjection {
        id_digest: value.digest(),
        revision: value.revision,
    }
}

pub(crate) fn project_projection(value: &ProjectIdentity) -> ProjectProjection {
    ProjectProjection {
        id_digest: value.digest(),
        revision: value.revision,
    }
}

pub(crate) fn work_product_projection(value: &WorkProductIdentity) -> WorkProductProjection {
    WorkProductProjection {
        id_digest: value.digest(),
        revision: value.revision,
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct Cursor {
    scope_digest: Digest,
    filter_digest: Digest,
    token_digest: Digest,
    page_number: u16,
    expires_at: DateTime<Utc>,
}

impl Cursor {
    pub fn new(
        token: impl AsRef<str>,
        scope: &AwsKinesisStreamScope,
        filter: &ShardFilter,
        page_number: u16,
    ) -> Result<Self> {
        Self::new_at(token, scope, filter, page_number, Utc::now())
    }

    pub fn new_at(
        token: impl AsRef<str>,
        scope: &AwsKinesisStreamScope,
        filter: &ShardFilter,
        page_number: u16,
        issued_at: DateTime<Utc>,
    ) -> Result<Self> {
        let token = token.as_ref();
        if !valid_text(token, 1_048_576, false)
            || page_number == 0
            || page_number > MAX_PAGES.saturating_add(1)
        {
            return Err(AwsKinesisStreamResultError::InvalidRequest);
        }
        scope.validate()?;
        filter.validate()?;
        Ok(Self {
            scope_digest: scope.digest(),
            filter_digest: filter.digest(),
            token_digest: Digest::from_parts(
                "aws-kinesis-opaque-next-token/v1",
                &[("token", token.to_owned())],
            ),
            page_number,
            expires_at: issued_at + Duration::seconds(NEXT_TOKEN_TTL_SECONDS),
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }
    pub fn filter_digest(&self) -> &Digest {
        &self.filter_digest
    }
    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }
    pub const fn page_number(&self) -> u16 {
        self.page_number
    }
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn validate_against(
        &self,
        scope: &AwsKinesisStreamScope,
        filter: &ShardFilter,
        observed_at: DateTime<Utc>,
    ) -> Result<()> {
        if self.scope_digest != scope.digest() || self.filter_digest != filter.digest() {
            return Err(AwsKinesisStreamResultError::CursorMismatch);
        }
        if observed_at >= self.expires_at {
            return Err(AwsKinesisStreamResultError::CursorExpired);
        }
        self.token_digest.validate()
    }
}

impl fmt::Debug for Cursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Cursor")
            .field("scope_digest", &self.scope_digest)
            .field("filter_digest", &self.filter_digest)
            .field("token_digest", &self.token_digest)
            .field("page_number", &self.page_number)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Serialize for Cursor {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("Cursor", 4)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("filterDigest", &self.filter_digest)?;
        state.serialize_field("tokenDigest", &self.token_digest)?;
        state.serialize_field("pageNumber", &self.page_number)?;
        state.end()
    }
}

pub(crate) fn validate_response_bytes(response_bytes: u64) -> Result<()> {
    if response_bytes > MAX_RESPONSE_BYTES {
        Err(AwsKinesisStreamResultError::ResponseTooLarge)
    } else {
        Ok(())
    }
}

pub(crate) fn shards_digest(shards: &[ShardLineageProjection]) -> Digest {
    Digest::from_parts(
        "aws-kinesis-shards/v1",
        &[(
            "lineage",
            shards
                .iter()
                .map(|value| value.lineage_digest.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
        )],
    )
}
