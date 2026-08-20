//! Typed, bounded AWS SQS queue and dead-letter posture models.
//!
//! The model deliberately has no message, message-attribute, queue-policy
//! body, credential, signer, HTTP, or queue-mutation type. Provider responses
//! are reduced to digest-bound queue metadata before they can become evidence.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{AwsSqsQueueError, Result};
use crate::{
    LAYER1_PERMISSIONS, MAX_APPROXIMATE_COUNT, MAX_COUNT_AGE_SECONDS, MAX_IDENTIFIER_BYTES,
    MAX_PAGE_SIZE, MAX_PAGES,
};

pub const MAX_QUEUE_NAME_BYTES: usize = 80;
pub const MAX_QUEUE_URL_BYTES: usize = 2_048;
pub const MAX_ARN_BYTES: usize = 2_048;
pub const MAX_TOKEN_BYTES: usize = 4_096;
pub const MAX_DEAD_LETTER_SOURCES: usize = 100;
pub const MAX_PERMISSION_ENTRIES: usize = 16;
pub const MAX_RETENTION_SECONDS: u64 = 14 * 24 * 60 * 60;

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

// `Deserialize` is intentionally only used for already-redacted digest
// envelopes. Secrets and raw provider values have no Deserialize impl.
use serde::Deserialize;

impl Digest {
    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

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
            Err(AwsSqsQueueError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsSqsQueueError::InvalidDigest)
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
        self.0.fmt(formatter)
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

fn valid_text(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_identifier(value: &str, max: usize) -> bool {
    valid_text(value, max)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn digest_redacted(domain: &str, value: &str) -> Digest {
    Digest::from_parts(domain, &[("value", value.to_owned())])
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal, $domain:literal, $validator:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(AwsSqsQueueError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                digest_redacted($domain, &self.0)
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(AwsSqsQueueError::InvalidIdentifier { field: $field })
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&format_args!(
                        "{}:{}",
                        $field,
                        &self.digest().as_str()[..16]
                    ))
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.digest().as_str())
            }
        }
    };
}

bounded_identifier!(
    AwsAccountId,
    "AWS account id",
    "aws-sqs-account/v1",
    |value: &str| value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit())
);
bounded_identifier!(
    AwsRegion,
    "AWS region",
    "aws-sqs-region/v1",
    |value: &str| valid_identifier(value, 64)
);
bounded_identifier!(
    QueueName,
    "queue name",
    "aws-sqs-queue-name/v1",
    |value: &str| (1..=MAX_QUEUE_NAME_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') })
        && (!value.contains('.') || value.strip_suffix(".fifo").is_some())
);

impl QueueName {
    pub fn is_fifo(&self) -> bool {
        self.0.strip_suffix(".fifo").is_some()
    }
}
bounded_identifier!(
    DeploymentId,
    "consumer deployment id",
    "aws-sqs-deployment/v1",
    |value: &str| valid_identifier(value, MAX_IDENTIFIER_BYTES)
);
bounded_identifier!(
    MissionId,
    "Mission id",
    "aws-sqs-mission/v1",
    |value: &str| valid_identifier(value, MAX_IDENTIFIER_BYTES)
);
bounded_identifier!(
    ProjectId,
    "Project id",
    "aws-sqs-project/v1",
    |value: &str| valid_identifier(value, MAX_IDENTIFIER_BYTES)
);
bounded_identifier!(
    WorkProductId,
    "Work Product id",
    "aws-sqs-work-product/v1",
    |value: &str| valid_identifier(value, MAX_IDENTIFIER_BYTES)
);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(AwsSqsQueueError::InvalidIdentifier { field: "revision" })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct QueueUrl(String);

impl QueueUrl {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if !valid_text(&value, MAX_QUEUE_URL_BYTES)
            || !value.starts_with("https://sqs.")
            || !value.contains(".amazonaws.com/")
            || value.contains('?')
            || value.ends_with('/')
        {
            return Err(AwsSqsQueueError::InvalidIdentifier { field: "queue URL" });
        }
        let result = Self(value);
        result.validate_parts()?;
        Ok(result)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        digest_redacted("aws-sqs-queue-url/v1", &self.0)
    }

    pub fn queue_name(&self) -> Result<QueueName> {
        let value = self
            .0
            .rsplit('/')
            .next()
            .ok_or(AwsSqsQueueError::InvalidIdentifier { field: "queue URL" })?;
        QueueName::new(value)
    }

    pub fn account_id(&self) -> Result<AwsAccountId> {
        let value = self
            .0
            .split(".amazonaws.com/")
            .nth(1)
            .and_then(|path| path.split('/').next())
            .ok_or(AwsSqsQueueError::InvalidIdentifier { field: "queue URL" })?;
        AwsAccountId::new(value)
    }

    pub fn region(&self) -> Result<AwsRegion> {
        let host = self
            .0
            .strip_prefix("https://sqs.")
            .and_then(|value| value.split(".amazonaws.com/").next())
            .ok_or(AwsSqsQueueError::InvalidIdentifier { field: "queue URL" })?;
        AwsRegion::new(host)
    }

    fn validate_parts(&self) -> Result<()> {
        self.queue_name()?.validate()?;
        self.account_id()?.validate()?;
        self.region()?.validate()
    }
}

impl fmt::Debug for QueueUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("QueueUrl")
            .field(&format_args!("digest:{}", &self.digest().as_str()[..16]))
            .finish()
    }
}

impl Serialize for QueueUrl {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.digest().as_str())
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct QueueArn(String);

impl QueueArn {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if !valid_text(&value, MAX_ARN_BYTES) || !value.starts_with("arn:") {
            return Err(AwsSqsQueueError::InvalidIdentifier { field: "queue ARN" });
        }
        let result = Self(value);
        result.validate_parts()?;
        Ok(result)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        digest_redacted("aws-sqs-queue-arn/v1", &self.0)
    }

    pub fn queue_name(&self) -> Result<QueueName> {
        self.0
            .rsplit(':')
            .next()
            .ok_or(AwsSqsQueueError::InvalidIdentifier { field: "queue ARN" })
            .and_then(QueueName::new)
    }

    pub fn region(&self) -> Result<AwsRegion> {
        self.0
            .split(':')
            .nth(3)
            .ok_or(AwsSqsQueueError::InvalidIdentifier { field: "queue ARN" })
            .and_then(AwsRegion::new)
    }

    pub fn account_id(&self) -> Result<AwsAccountId> {
        self.0
            .split(':')
            .nth(4)
            .ok_or(AwsSqsQueueError::InvalidIdentifier { field: "queue ARN" })
            .and_then(AwsAccountId::new)
    }

    fn validate_parts(&self) -> Result<()> {
        let pieces = self.0.split(':').collect::<Vec<_>>();
        if pieces.len() != 6 || pieces[2] != "sqs" {
            return Err(AwsSqsQueueError::InvalidIdentifier { field: "queue ARN" });
        }
        self.region()?.validate()?;
        self.account_id()?.validate()?;
        self.queue_name()?.validate()
    }
}

impl fmt::Debug for QueueArn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("QueueArn")
            .field(&format_args!("digest:{}", &self.digest().as_str()[..16]))
            .finish()
    }
}

impl Serialize for QueueArn {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.digest().as_str())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct QueueIdentity {
    name: QueueName,
    url: Option<QueueUrl>,
    arn: Option<QueueArn>,
}

impl QueueIdentity {
    pub fn new(name: QueueName, url: Option<QueueUrl>, arn: Option<QueueArn>) -> Result<Self> {
        if url
            .as_ref()
            .is_some_and(|value| value.queue_name().ok().as_ref() != Some(&name))
            || arn
                .as_ref()
                .is_some_and(|value| value.queue_name().ok().as_ref() != Some(&name))
        {
            return Err(AwsSqsQueueError::QueueMismatch);
        }
        if url.is_none() && arn.is_none() {
            return Err(AwsSqsQueueError::InvalidScope);
        }
        Ok(Self { name, url, arn })
    }

    pub fn from_strings(
        name: impl Into<String>,
        url: Option<impl Into<String>>,
        arn: Option<impl Into<String>>,
    ) -> Result<Self> {
        Self::new(
            QueueName::new(name)?,
            url.map(|value| QueueUrl::new(value.into())).transpose()?,
            arn.map(|value| QueueArn::new(value.into())).transpose()?,
        )
    }

    pub fn for_name(name: QueueName, url: QueueUrl) -> Result<Self> {
        Self::new(name, Some(url), None)
    }

    pub fn from_url(url: QueueUrl) -> Result<Self> {
        let name = url.queue_name()?;
        Self::new(name, Some(url), None)
    }

    pub fn from_arn(arn: QueueArn) -> Result<Self> {
        let name = arn.queue_name()?;
        Self::new(name, None, Some(arn))
    }

    pub fn name(&self) -> &QueueName {
        &self.name
    }

    pub fn url(&self) -> Option<&QueueUrl> {
        self.url.as_ref()
    }

    pub fn arn(&self) -> Option<&QueueArn> {
        self.arn.as_ref()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-sqs-queue-identity/v1",
            &[
                ("name", self.name.digest().as_str().to_owned()),
                (
                    "url",
                    self.url
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                (
                    "arn",
                    self.arn
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
            ],
        )
    }

    pub fn validate_for(&self, account: &AwsAccountId, region: &AwsRegion) -> Result<()> {
        self.name.validate()?;
        if let Some(url) = &self.url {
            if url.account_id()? != *account || url.region()? != *region {
                return Err(AwsSqsQueueError::ScopeMismatch);
            }
        }
        if let Some(arn) = &self.arn {
            if arn.account_id()? != *account || arn.region()? != *region {
                return Err(AwsSqsQueueError::ScopeMismatch);
            }
        }
        Ok(())
    }

    pub(crate) fn matches_expected(&self, expected: &Self) -> bool {
        self.name == expected.name
            && expected
                .url
                .as_ref()
                .is_none_or(|value| self.url.as_ref() == Some(value))
            && expected
                .arn
                .as_ref()
                .is_none_or(|value| self.arn.as_ref() == Some(value))
    }
}

impl fmt::Debug for QueueIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QueueIdentity")
            .field("name_digest", &self.name.digest())
            .field("url_digest", &self.url.as_ref().map(QueueUrl::digest))
            .field("arn_digest", &self.arn.as_ref().map(QueueArn::digest))
            .finish()
    }
}

impl Serialize for QueueIdentity {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("QueueIdentity", 3)?;
        state.serialize_field("nameDigest", &self.name.digest())?;
        state.serialize_field("urlDigest", &self.url.as_ref().map(QueueUrl::digest))?;
        state.serialize_field("arnDigest", &self.arn.as_ref().map(QueueArn::digest))?;
        state.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueKind {
    Standard,
    Fifo,
}

impl QueueKind {
    pub const fn is_fifo(self) -> bool {
        matches!(self, Self::Fifo)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionPosture {
    NotEncrypted,
    SqsManaged,
    KmsManaged { key_reference_digest: Digest },
    Unknown,
}

impl EncryptionPosture {
    pub fn kms_managed(key_reference: impl AsRef<str>) -> Result<Self> {
        if !valid_text(key_reference.as_ref(), MAX_IDENTIFIER_BYTES) {
            return Err(AwsSqsQueueError::InvalidIdentifier {
                field: "KMS key reference",
            });
        }
        Ok(Self::KmsManaged {
            key_reference_digest: digest_redacted(
                "aws-sqs-kms-key-reference/v1",
                key_reference.as_ref(),
            ),
        })
    }

    pub fn key_reference_digest(&self) -> Option<&Digest> {
        match self {
            Self::KmsManaged {
                key_reference_digest,
            } => Some(key_reference_digest),
            Self::NotEncrypted | Self::SqsManaged | Self::Unknown => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedrivePolicyInput {
    dead_letter_target: QueueArn,
    max_receive_count: u32,
}

impl RedrivePolicyInput {
    pub fn new(dead_letter_target: QueueArn, max_receive_count: u32) -> Result<Self> {
        if max_receive_count == 0 {
            return Err(AwsSqsQueueError::InvalidIdentifier {
                field: "maxReceiveCount",
            });
        }
        Ok(Self {
            dead_letter_target,
            max_receive_count,
        })
    }

    pub fn dead_letter_target(&self) -> &QueueArn {
        &self.dead_letter_target
    }

    pub const fn max_receive_count(&self) -> u32 {
        self.max_receive_count
    }

    fn posture(&self) -> RedrivePosture {
        RedrivePosture::Configured {
            dead_letter_target_arn_digest: self.dead_letter_target.digest(),
            max_receive_count: self.max_receive_count,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedrivePosture {
    NotConfigured,
    Configured {
        dead_letter_target_arn_digest: Digest,
        max_receive_count: u32,
    },
    Unknown,
}

impl RedrivePosture {
    pub const fn target_digest(&self) -> Option<&Digest> {
        match self {
            Self::Configured {
                dead_letter_target_arn_digest,
                ..
            } => Some(dead_letter_target_arn_digest),
            Self::NotConfigured | Self::Unknown => None,
        }
    }

    pub const fn is_configured(&self) -> bool {
        matches!(self, Self::Configured { .. })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RedriveAllowPolicyInput {
    AllowAll,
    DenyAll,
    ByQueue { source_queue_digests: Vec<Digest> },
    Unknown,
}

impl RedriveAllowPolicyInput {
    fn posture(&self) -> RedriveAllowPosture {
        match self {
            Self::AllowAll => RedriveAllowPosture::AllowAll,
            Self::DenyAll => RedriveAllowPosture::DenyAll,
            Self::ByQueue {
                source_queue_digests,
            } => RedriveAllowPosture::ByQueue {
                source_queue_count: u16::try_from(source_queue_digests.len()).unwrap_or(u16::MAX),
                source_queue_digests: source_queue_digests.clone(),
            },
            Self::Unknown => RedriveAllowPosture::Unknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedriveAllowPosture {
    AllowAll,
    DenyAll,
    ByQueue {
        source_queue_count: u16,
        source_queue_digests: Vec<Digest>,
    },
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApproximateQueueCounts {
    pub approximate_number_of_messages: u64,
    pub approximate_number_of_messages_not_visible: u64,
    pub approximate_number_of_messages_delayed: u64,
    pub observed_at: DateTime<Utc>,
    pub eventually_consistent: bool,
    pub delivery_proof: bool,
}

impl ApproximateQueueCounts {
    pub fn new(
        approximate_number_of_messages: u64,
        approximate_number_of_messages_not_visible: u64,
        approximate_number_of_messages_delayed: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        for value in [
            approximate_number_of_messages,
            approximate_number_of_messages_not_visible,
            approximate_number_of_messages_delayed,
        ] {
            if value > MAX_APPROXIMATE_COUNT {
                return Err(AwsSqsQueueError::InvalidRequest);
            }
        }
        Ok(Self {
            approximate_number_of_messages,
            approximate_number_of_messages_not_visible,
            approximate_number_of_messages_delayed,
            observed_at,
            eventually_consistent: true,
            delivery_proof: false,
        })
    }

    pub fn age_at(&self, observed_at: DateTime<Utc>) -> Option<u64> {
        let duration = observed_at.signed_duration_since(self.observed_at);
        if duration < Duration::zero() {
            None
        } else {
            u64::try_from(duration.num_seconds()).ok()
        }
    }

    pub fn is_fresh_at(&self, observed_at: DateTime<Utc>) -> bool {
        self.age_at(observed_at)
            .is_some_and(|age| age <= MAX_COUNT_AGE_SECONDS)
    }

    pub const fn is_approximate(&self) -> bool {
        self.eventually_consistent && !self.delivery_proof
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueueAttributesInput {
    identity: QueueIdentity,
    kind: QueueKind,
    content_based_deduplication: bool,
    encryption: EncryptionPosture,
    redrive: Option<RedrivePolicyInput>,
    redrive_allow: RedriveAllowPolicyInput,
    counts: ApproximateQueueCounts,
    created_at: DateTime<Utc>,
    last_modified_at: DateTime<Utc>,
    visibility_timeout_seconds: u32,
    message_retention_period_seconds: u64,
    delay_seconds: u32,
    receive_message_wait_time_seconds: u32,
}

impl QueueAttributesInput {
    pub fn new(
        identity: QueueIdentity,
        kind: QueueKind,
        counts: ApproximateQueueCounts,
        created_at: DateTime<Utc>,
        last_modified_at: DateTime<Utc>,
    ) -> Result<Self> {
        let result = Self {
            identity,
            kind,
            content_based_deduplication: false,
            encryption: EncryptionPosture::Unknown,
            redrive: None,
            redrive_allow: RedriveAllowPolicyInput::Unknown,
            counts,
            created_at,
            last_modified_at,
            visibility_timeout_seconds: 30,
            message_retention_period_seconds: 4 * 24 * 60 * 60,
            delay_seconds: 0,
            receive_message_wait_time_seconds: 0,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn for_standard(
        identity: QueueIdentity,
        counts: ApproximateQueueCounts,
        created_at: DateTime<Utc>,
        last_modified_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new(
            identity,
            QueueKind::Standard,
            counts,
            created_at,
            last_modified_at,
        )
    }

    pub fn for_fifo(
        identity: QueueIdentity,
        counts: ApproximateQueueCounts,
        created_at: DateTime<Utc>,
        last_modified_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new(
            identity,
            QueueKind::Fifo,
            counts,
            created_at,
            last_modified_at,
        )
    }

    #[must_use]
    pub fn with_content_based_deduplication(mut self, enabled: bool) -> Self {
        self.content_based_deduplication = enabled;
        self
    }

    #[must_use]
    pub fn with_encryption(mut self, encryption: EncryptionPosture) -> Self {
        self.encryption = encryption;
        self
    }

    #[must_use]
    pub fn with_redrive(mut self, redrive: RedrivePolicyInput) -> Self {
        self.redrive = Some(redrive);
        self
    }

    #[must_use]
    pub fn with_redrive_allow(mut self, redrive_allow: RedriveAllowPolicyInput) -> Self {
        self.redrive_allow = redrive_allow;
        self
    }

    pub fn with_timing(
        mut self,
        visibility_timeout_seconds: u32,
        message_retention_period_seconds: u64,
        delay_seconds: u32,
        receive_message_wait_time_seconds: u32,
    ) -> Result<Self> {
        if visibility_timeout_seconds == 0
            || visibility_timeout_seconds > 12 * 60 * 60
            || message_retention_period_seconds == 0
            || message_retention_period_seconds > MAX_RETENTION_SECONDS
            || delay_seconds > 15 * 60
            || receive_message_wait_time_seconds > 20
        {
            return Err(AwsSqsQueueError::InvalidRequest);
        }
        self.visibility_timeout_seconds = visibility_timeout_seconds;
        self.message_retention_period_seconds = message_retention_period_seconds;
        self.delay_seconds = delay_seconds;
        self.receive_message_wait_time_seconds = receive_message_wait_time_seconds;
        Ok(self)
    }

    pub fn identity(&self) -> &QueueIdentity {
        &self.identity
    }

    pub fn kind(&self) -> QueueKind {
        self.kind
    }

    pub fn counts(&self) -> &ApproximateQueueCounts {
        &self.counts
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub fn last_modified_at(&self) -> DateTime<Utc> {
        self.last_modified_at
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.identity.name.validate()?;
        if self.created_at > self.last_modified_at
            || self.visibility_timeout_seconds == 0
            || self.message_retention_period_seconds == 0
            || self.message_retention_period_seconds > MAX_RETENTION_SECONDS
            || self.delay_seconds > 15 * 60
            || self.receive_message_wait_time_seconds > 20
            || !self.counts.eventually_consistent
            || self.counts.delivery_proof
            || self.counts.approximate_number_of_messages > MAX_APPROXIMATE_COUNT
            || self.counts.approximate_number_of_messages_not_visible > MAX_APPROXIMATE_COUNT
            || self.counts.approximate_number_of_messages_delayed > MAX_APPROXIMATE_COUNT
        {
            return Err(AwsSqsQueueError::InvalidRequest);
        }
        if let Some(redrive) = &self.redrive {
            redrive.dead_letter_target.validate_parts()?;
        }
        if let RedriveAllowPolicyInput::ByQueue {
            source_queue_digests,
        } = &self.redrive_allow
        {
            if source_queue_digests.len() > MAX_DEAD_LETTER_SOURCES
                || source_queue_digests
                    .iter()
                    .any(|digest| digest.validate().is_err())
            {
                return Err(AwsSqsQueueError::InvalidRequest);
            }
        }
        Ok(())
    }

    pub(crate) fn project(&self) -> QueueAttributesProjection {
        QueueAttributesProjection {
            identity: self.identity.clone(),
            kind: self.kind,
            content_based_deduplication: self.content_based_deduplication,
            encryption: self.encryption.clone(),
            redrive: self
                .redrive
                .as_ref()
                .map_or(RedrivePosture::NotConfigured, RedrivePolicyInput::posture),
            redrive_allow: self.redrive_allow.posture(),
            counts: self.counts.clone(),
            created_at: self.created_at,
            last_modified_at: self.last_modified_at,
            visibility_timeout_seconds: self.visibility_timeout_seconds,
            message_retention_period_seconds: self.message_retention_period_seconds,
            delay_seconds: self.delay_seconds,
            receive_message_wait_time_seconds: self.receive_message_wait_time_seconds,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueueAttributesProjection {
    pub(crate) identity: QueueIdentity,
    pub kind: QueueKind,
    pub content_based_deduplication: bool,
    pub encryption: EncryptionPosture,
    pub redrive: RedrivePosture,
    pub redrive_allow: RedriveAllowPosture,
    pub counts: ApproximateQueueCounts,
    pub created_at: DateTime<Utc>,
    pub last_modified_at: DateTime<Utc>,
    pub visibility_timeout_seconds: u32,
    pub message_retention_period_seconds: u64,
    pub delay_seconds: u32,
    pub receive_message_wait_time_seconds: u32,
}

impl QueueAttributesProjection {
    pub fn identity(&self) -> &QueueIdentity {
        &self.identity
    }

    pub fn queue_digest(&self) -> Digest {
        self.identity.digest()
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }

    pub fn matches_scope(&self, scope: &AwsSqsQueueScope) -> bool {
        self.identity.matches_expected(&scope.queue)
    }

    pub fn dlq_digest(&self) -> Option<&Digest> {
        self.redrive.target_digest()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueueSummary {
    pub queue_name_digest: Digest,
    pub queue_url_digest: Digest,
}

impl QueueSummary {
    pub fn new(queue_url: QueueUrl) -> Result<Self> {
        Ok(Self {
            queue_name_digest: queue_url.queue_name()?.digest(),
            queue_url_digest: queue_url.digest(),
        })
    }

    pub fn for_scope(scope: &AwsSqsQueueScope) -> Result<Self> {
        scope
            .queue
            .url()
            .cloned()
            .map_or_else(|| Err(AwsSqsQueueError::InvalidRequest), Self::new)
    }

    pub fn matches_scope(&self, scope: &AwsSqsQueueScope) -> bool {
        self.queue_name_digest == scope.queue.name.digest()
            && scope
                .queue
                .url()
                .is_none_or(|url| self.queue_url_digest == url.digest())
    }

    pub fn matches_name(&self, scope: &AwsSqsQueueScope) -> bool {
        self.queue_name_digest == scope.queue.name.digest()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeadLetterSourceProjection {
    pub queue_digest: Digest,
    pub queue_name_digest: Digest,
    pub queue_url_digest: Digest,
}

impl DeadLetterSourceProjection {
    pub fn new(identity: &QueueIdentity) -> Self {
        Self {
            queue_digest: identity.digest(),
            queue_name_digest: identity.name.digest(),
            queue_url_digest: identity.url().map_or_else(Digest::zero, QueueUrl::digest),
        }
    }

    pub fn matches_scope(&self, scope: &AwsSqsQueueScope) -> bool {
        self.queue_name_digest == scope.queue.name.digest()
            && scope
                .queue
                .url()
                .is_none_or(|url| self.queue_url_digest == url.digest())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ConsumerDeployment {
    deployment_id: DeploymentId,
    revision: Revision,
}

impl ConsumerDeployment {
    pub fn new(deployment_id: DeploymentId, revision: Revision) -> Result<Self> {
        deployment_id.validate()?;
        Ok(Self {
            deployment_id,
            revision,
        })
    }

    pub fn deployment_id(&self) -> &DeploymentId {
        &self.deployment_id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-sqs-consumer-deployment/v1",
            &[
                ("id", self.deployment_id.digest().as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

impl fmt::Debug for ConsumerDeployment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsumerDeployment")
            .field("deployment_digest", &self.digest())
            .field("revision", &self.revision)
            .finish()
    }
}

impl Serialize for ConsumerDeployment {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ConsumerDeployment", 2)?;
        state.serialize_field("deploymentDigest", &self.deployment_id.digest())?;
        state.serialize_field("revision", &self.revision)?;
        state.end()
    }
}

macro_rules! scoped_identity {
    ($name:ident, $id:ident, $domain:literal) => {
        #[derive(Clone, Eq, PartialEq)]
        pub struct $name {
            id: $id,
            revision: Revision,
        }

        impl $name {
            pub fn new(id: $id, revision: Revision) -> Result<Self> {
                id.validate()?;
                Ok(Self { id, revision })
            }

            pub fn id(&self) -> &$id {
                &self.id
            }

            pub const fn revision(&self) -> Revision {
                self.revision
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    $domain,
                    &[
                        ("id", self.id.digest().as_str().to_owned()),
                        ("revision", self.revision.get().to_string()),
                    ],
                )
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("id_digest", &self.id.digest())
                    .field("revision", &self.revision)
                    .finish()
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mut state = serializer.serialize_struct(stringify!($name), 2)?;
                state.serialize_field("idDigest", &self.id.digest())?;
                state.serialize_field("revision", &self.revision)?;
                state.end()
            }
        }
    };
}

scoped_identity!(MissionIdentity, MissionId, "aws-sqs-mission-scope/v1");
scoped_identity!(ProjectIdentity, ProjectId, "aws-sqs-project-scope/v1");
scoped_identity!(
    WorkProductIdentity,
    WorkProductId,
    "aws-sqs-work-product-scope/v1"
);

#[derive(Clone, Eq, PartialEq)]
pub struct AwsSqsQueueScope {
    account: AwsAccountId,
    region: AwsRegion,
    queue: QueueIdentity,
    dead_letter_queue: Option<QueueIdentity>,
    consumer_deployment: ConsumerDeployment,
    mission: MissionIdentity,
    project: ProjectIdentity,
    work_product: WorkProductIdentity,
}

impl AwsSqsQueueScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        queue: QueueIdentity,
        dead_letter_queue: Option<QueueIdentity>,
        consumer_deployment: ConsumerDeployment,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let result = Self {
            account,
            region,
            queue,
            dead_letter_queue,
            consumer_deployment,
            mission,
            project,
            work_product,
        };
        result.validate()?;
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn for_queue(
        account: AwsAccountId,
        region: AwsRegion,
        queue: QueueIdentity,
        dead_letter_queue: Option<QueueIdentity>,
        consumer_deployment: ConsumerDeployment,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        Self::new(
            account,
            region,
            queue,
            dead_letter_queue,
            consumer_deployment,
            mission,
            project,
            work_product,
        )
    }

    pub fn account(&self) -> &AwsAccountId {
        &self.account
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn queue(&self) -> &QueueIdentity {
        &self.queue
    }

    pub fn dead_letter_queue(&self) -> Option<&QueueIdentity> {
        self.dead_letter_queue.as_ref()
    }

    pub fn consumer_deployment(&self) -> &ConsumerDeployment {
        &self.consumer_deployment
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

    pub fn queue_digest(&self) -> Digest {
        self.queue.digest()
    }

    pub fn dead_letter_relationship_digest(&self) -> Option<Digest> {
        self.dead_letter_queue.as_ref().map(QueueIdentity::digest)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-sqs-queue-scope/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                ("queue", self.queue.digest().as_str().to_owned()),
                (
                    "dead_letter_queue",
                    self.dead_letter_queue
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                (
                    "deployment",
                    self.consumer_deployment.digest().as_str().to_owned(),
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
        self.queue.validate_for(&self.account, &self.region)?;
        if let Some(dead_letter_queue) = &self.dead_letter_queue {
            dead_letter_queue.validate_for(&self.account, &self.region)?;
        }
        if self
            .dead_letter_queue
            .as_ref()
            .is_some_and(|dead_letter_queue| dead_letter_queue.name == self.queue.name)
        {
            return Err(AwsSqsQueueError::InvalidScope);
        }
        Ok(())
    }
}

impl fmt::Debug for AwsSqsQueueScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsSqsQueueScope")
            .field("account_digest", &self.account.digest())
            .field("region", &self.region)
            .field("queue_digest", &self.queue.digest())
            .field(
                "dead_letter_queue_digest",
                &self.dead_letter_queue.as_ref().map(QueueIdentity::digest),
            )
            .field("consumer_deployment", &self.consumer_deployment)
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .finish()
    }
}

impl Serialize for AwsSqsQueueScope {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AwsSqsQueueScope", 8)?;
        state.serialize_field("accountDigest", &self.account.digest())?;
        state.serialize_field("regionDigest", &self.region.digest())?;
        state.serialize_field("queue", &self.queue)?;
        state.serialize_field(
            "deadLetterQueue",
            &self.dead_letter_queue.as_ref().map(QueueIdentity::digest),
        )?;
        state.serialize_field("consumerDeployment", &self.consumer_deployment)?;
        state.serialize_field("mission", &self.mission)?;
        state.serialize_field("project", &self.project)?;
        state.serialize_field("workProduct", &self.work_product)?;
        state.end()
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
    pub fn for_layer_one(revision: u64) -> Result<Self> {
        Self::new(
            revision,
            LAYER1_PERMISSIONS.iter().map(|value| (*value).to_owned()),
        )
    }

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
        if permissions.is_empty()
            || permissions.len() > MAX_PERMISSION_ENTRIES
            || permissions
                .iter()
                .any(|permission| !valid_text(permission, MAX_IDENTIFIER_BYTES))
        {
            return Err(AwsSqsQueueError::InvalidPermissionSnapshot);
        }
        let digest = Digest::from_parts(
            "aws-sqs-permission-snapshot/v1",
            &[
                ("revision", revision.get().to_string()),
                (
                    "permissions",
                    permissions.iter().cloned().collect::<Vec<_>>().join("\n"),
                ),
            ],
        );
        Ok(Self {
            revision,
            permissions,
            digest,
        })
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
        let expected = Self::new(self.revision.get(), self.permissions.clone())?;
        if self.digest != expected.digest
            || self.permissions
                != LAYER1_PERMISSIONS
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect::<BTreeSet<_>>()
        {
            return Err(AwsSqsQueueError::InvalidPermissionSnapshot);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    handle: String,
    scope_digest: Digest,
    signing_region: AwsRegion,
    revision: Revision,
    digest: Digest,
}

impl SecretReference {
    pub fn new(handle: impl Into<String>, scope: &AwsSqsQueueScope, revision: u64) -> Result<Self> {
        let handle = handle.into();
        if !valid_text(&handle, MAX_IDENTIFIER_BYTES) {
            return Err(AwsSqsQueueError::InvalidSecretReference);
        }
        let revision = Revision::new(revision)?;
        let digest = Digest::from_parts(
            "aws-sqs-sigv4-secret-reference/v1",
            &[
                ("handle", Digest::from_text(&handle).as_str().to_owned()),
                ("scope", scope.digest().as_str().to_owned()),
                ("region", scope.region.digest().as_str().to_owned()),
                ("revision", revision.get().to_string()),
                ("scheme", "aws_sigv4".to_owned()),
            ],
        );
        Ok(Self {
            handle,
            scope_digest: scope.digest(),
            signing_region: scope.region.clone(),
            revision,
            digest,
        })
    }

    pub fn for_scope(handle: impl Into<String>, scope: &AwsSqsQueueScope) -> Result<Self> {
        Self::new(handle, scope, 1)
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn signing_region(&self) -> &AwsRegion {
        &self.signing_region
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub(crate) fn validate(&self, scope: &AwsSqsQueueScope) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.signing_region != *scope.region()
            || self.handle.is_empty()
            || !valid_text(&self.handle, MAX_IDENTIFIER_BYTES)
            || self.digest != Self::new(self.handle.clone(), scope, self.revision.get())?.digest
        {
            return Err(AwsSqsQueueError::InvalidSecretReference);
        }
        Ok(())
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("scheme", &"aws_sigv4")
            .field("digest", &self.digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .finish()
    }
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SecretReference", 1)?;
        state.serialize_field("opaque", &true)?;
        state.end()
    }
}

impl Drop for SecretReference {
    fn drop(&mut self) {
        self.handle.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Loopback,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }

    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct QueueListFilter {
    queue_name_prefix: Option<String>,
    max_results: u16,
}

impl QueueListFilter {
    pub fn new(queue_name_prefix: Option<String>, max_results: u16) -> Result<Self> {
        if max_results == 0 || max_results > MAX_PAGE_SIZE {
            return Err(AwsSqsQueueError::InvalidRequest);
        }
        if let Some(prefix) = &queue_name_prefix
            && QueueName::new(prefix.clone()).is_err()
        {
            return Err(AwsSqsQueueError::InvalidRequest);
        }
        Ok(Self {
            queue_name_prefix,
            max_results,
        })
    }

    pub fn for_scope(scope: &AwsSqsQueueScope, max_results: u16) -> Result<Self> {
        Self::new(Some(scope.queue.name.as_str().to_owned()), max_results)
    }

    pub fn queue_name_prefix(&self) -> Option<&str> {
        self.queue_name_prefix.as_deref()
    }

    pub const fn max_results(&self) -> u16 {
        self.max_results
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-sqs-list-queues-filter/v1",
            &[
                ("prefix", self.queue_name_prefix.clone().unwrap_or_default()),
                ("max_results", self.max_results.to_string()),
            ],
        )
    }

    pub(crate) fn validate_against(&self, scope: &AwsSqsQueueScope) -> Result<()> {
        if self.max_results == 0 || self.max_results > MAX_PAGE_SIZE {
            return Err(AwsSqsQueueError::InvalidRequest);
        }
        if self.queue_name_prefix.as_deref() != Some(scope.queue.name.as_str()) {
            return Err(AwsSqsQueueError::ScopeMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for QueueListFilter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QueueListFilter")
            .field(
                "queue_name_prefix_digest",
                &self.queue_name_prefix.as_ref().map(Digest::from_text),
            )
            .field("max_results", &self.max_results)
            .field("filter_digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct Cursor {
    token_digest: Digest,
    scope_digest: Digest,
    filter_digest: Digest,
    page_number: u16,
}

impl Cursor {
    pub fn new(
        token: impl AsRef<str>,
        scope: &AwsSqsQueueScope,
        filter: &QueueListFilter,
        page_number: u16,
    ) -> Result<Self> {
        if !valid_text(token.as_ref(), MAX_TOKEN_BYTES)
            || page_number == 0
            || page_number > MAX_PAGES
        {
            return Err(AwsSqsQueueError::InvalidRequest);
        }
        filter.validate_against(scope)?;
        Ok(Self {
            token_digest: Digest::from_text(token.as_ref()),
            scope_digest: scope.digest(),
            filter_digest: filter.digest(),
            page_number,
        })
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub(crate) fn validate_against(
        &self,
        scope: &AwsSqsQueueScope,
        filter: &QueueListFilter,
    ) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.filter_digest != filter.digest()
            || self.page_number == 0
            || self.page_number > MAX_PAGES
        {
            return Err(AwsSqsQueueError::CursorMismatch);
        }
        self.token_digest.validate()
    }
}

impl fmt::Debug for Cursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Cursor")
            .field("token_digest", &self.token_digest)
            .field("scope_digest", &self.scope_digest)
            .field("filter_digest", &self.filter_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

impl Serialize for Cursor {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Cursor", 1)?;
        state.serialize_field("opaque", &true)?;
        state.end()
    }
}

pub(crate) fn digest_serialized<T: Serialize>(value: &T) -> Digest {
    Digest::from_bytes(&serde_json::to_vec(value).unwrap_or_default())
}
