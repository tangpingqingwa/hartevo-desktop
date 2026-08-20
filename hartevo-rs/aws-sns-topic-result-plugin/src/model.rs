use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{AwsSnsTopicError, Result};
use crate::{LAYER1_PERMISSIONS, MAX_IDENTIFIER_BYTES};

pub const MAX_SUBSCRIPTIONS: usize = 200;

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
            Err(AwsSnsTopicError::InvalidDigest)
        }
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsSnsTopicError::InvalidDigest)
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

fn valid_arn(value: &str) -> bool {
    valid_text(value, MAX_IDENTIFIER_BYTES, false) && value.starts_with("arn:")
}

macro_rules! redacted_text {
    ($name:ident, $field:literal, $validator:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(AwsSnsTopicError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("aws-sns-", $field, "/v1"),
                    &[("value", self.0.clone())],
                )
            }

            pub fn redacted(&self) -> String {
                format!("{}:{}", $field, &self.digest().as_str()[..16])
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(AwsSnsTopicError::InvalidIdentifier { field: $field })
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

redacted_text!(AwsAccountId, "account", |value: &str| value.len() == 12
    && value.bytes().all(|byte| byte.is_ascii_digit()));
redacted_text!(AwsRegion, "region", |value: &str| valid_identifier(
    value, 64
));
redacted_text!(TopicArn, "topic-arn", valid_arn);
redacted_text!(SubscriptionArn, "subscription-arn", valid_arn);
redacted_text!(DeploymentId, "deployment-id", |value: &str| {
    valid_identifier(value, MAX_IDENTIFIER_BYTES)
});
redacted_text!(MissionId, "mission-id", |value: &str| {
    valid_identifier(value, MAX_IDENTIFIER_BYTES)
});
redacted_text!(ProjectId, "project-id", |value: &str| {
    valid_identifier(value, MAX_IDENTIFIER_BYTES)
});
redacted_text!(WorkProductId, "work-product-id", |value: &str| {
    valid_identifier(value, MAX_IDENTIFIER_BYTES)
});

#[derive(Clone, Eq, PartialEq)]
pub struct TopicIdentity {
    arn: TopicArn,
}

impl TopicIdentity {
    pub fn new(arn: TopicArn) -> Self {
        Self { arn }
    }

    pub fn arn(&self) -> &TopicArn {
        &self.arn
    }

    pub fn digest(&self) -> Digest {
        self.arn.digest()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.arn.validate()
    }
}

impl fmt::Debug for TopicIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TopicIdentity")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SubscriptionIdentity {
    arn: SubscriptionArn,
}

impl SubscriptionIdentity {
    pub fn new(arn: SubscriptionArn) -> Self {
        Self { arn }
    }

    pub fn arn(&self) -> &SubscriptionArn {
        &self.arn
    }

    pub fn digest(&self) -> Digest {
        self.arn.digest()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.arn.validate()
    }
}

impl fmt::Debug for SubscriptionIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubscriptionIdentity")
            .field("digest", &self.digest())
            .finish()
    }
}

macro_rules! revision_identity {
    ($name:ident, $id:ident, $domain:literal) => {
        #[derive(Clone, Eq, PartialEq)]
        pub struct $name {
            id: $id,
            revision: u64,
        }

        impl $name {
            pub fn new(id: $id, revision: u64) -> Result<Self> {
                if revision == 0 {
                    return Err(AwsSnsTopicError::InvalidScope);
                }
                Ok(Self { id, revision })
            }

            pub fn id(&self) -> &$id {
                &self.id
            }

            pub const fn revision(&self) -> u64 {
                self.revision
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    $domain,
                    &[
                        ("id", self.id.as_str().to_owned()),
                        ("revision", self.revision.to_string()),
                    ],
                )
            }

            pub(crate) fn validate(&self) -> Result<()> {
                self.id.validate()?;
                if self.revision == 0 {
                    Err(AwsSnsTopicError::InvalidScope)
                } else {
                    Ok(())
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("digest", &self.digest())
                    .field("revision", &self.revision)
                    .finish()
            }
        }
    };
}

revision_identity!(
    ConsumerDeploymentIdentity,
    DeploymentId,
    "aws-sns-deployment/v1"
);
revision_identity!(MissionIdentity, MissionId, "aws-sns-mission/v1");
revision_identity!(ProjectIdentity, ProjectId, "aws-sns-project/v1");
revision_identity!(
    WorkProductIdentity,
    WorkProductId,
    "aws-sns-work-product/v1"
);

#[derive(Clone, Eq, PartialEq)]
pub struct AwsSnsTopicScope {
    account: AwsAccountId,
    region: AwsRegion,
    topic: TopicIdentity,
    subscriptions: Vec<SubscriptionIdentity>,
    deployment: ConsumerDeploymentIdentity,
    mission: MissionIdentity,
    project: ProjectIdentity,
    work_product: WorkProductIdentity,
}

impl AwsSnsTopicScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        topic: TopicIdentity,
        subscriptions: Vec<SubscriptionIdentity>,
        deployment: ConsumerDeploymentIdentity,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let scope = Self {
            account,
            region,
            topic,
            subscriptions,
            deployment,
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

    pub fn topic(&self) -> &TopicIdentity {
        &self.topic
    }

    pub fn subscriptions(&self) -> &[SubscriptionIdentity] {
        &self.subscriptions
    }

    pub fn deployment(&self) -> &ConsumerDeploymentIdentity {
        &self.deployment
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

    pub fn is_topic_allowlisted(&self, topic: &TopicIdentity) -> bool {
        self.topic.digest() == topic.digest()
    }

    pub fn is_subscription_allowlisted(&self, subscription: &SubscriptionIdentity) -> bool {
        self.subscriptions
            .iter()
            .any(|allowed| allowed.digest() == subscription.digest())
    }

    pub fn subscription_digests(&self) -> Vec<Digest> {
        self.subscriptions
            .iter()
            .map(SubscriptionIdentity::digest)
            .collect()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-sns-topic-scope/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                ("topic", self.topic.digest().as_str().to_owned()),
                (
                    "subscriptions",
                    self.subscription_digests()
                        .iter()
                        .map(Digest::as_str)
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("deployment", self.deployment.digest().as_str().to_owned()),
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
        self.topic.validate()?;
        if self.subscriptions.is_empty() || self.subscriptions.len() > MAX_SUBSCRIPTIONS {
            return Err(AwsSnsTopicError::InvalidScope);
        }
        let mut seen = BTreeSet::new();
        for subscription in &self.subscriptions {
            subscription.validate()?;
            if !seen.insert(subscription.digest()) {
                return Err(AwsSnsTopicError::InvalidScope);
            }
        }
        self.deployment.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()
    }
}

impl From<&AwsSnsTopicScope> for AwsSnsTopicScope {
    fn from(scope: &AwsSnsTopicScope) -> Self {
        scope.clone()
    }
}

impl fmt::Debug for AwsSnsTopicScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsSnsTopicScope")
            .field("digest", &self.digest())
            .field("account", &self.account)
            .field("region", &self.region)
            .field("topic", &self.topic)
            .field("subscription_digests", &self.subscription_digests())
            .field("deployment", &self.deployment)
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

/// Opaque SigV4 reference. The caller handle is hashed and dropped; the raw
/// handle is never serializable, displayable, or present in `Debug` output.
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
            return Err(AwsSnsTopicError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_parts(
            "aws-sns-opaque-sigv4-reference/v1",
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
            scope_digest: Digest::from_text("unbound-aws-sns-secret-scope"),
            revision,
            revoked: false,
        })
    }

    pub fn for_scope(
        opaque_handle: impl Into<String>,
        scope: &AwsSnsTopicScope,
        revision: u64,
    ) -> Result<Self> {
        let mut reference = Self::new(opaque_handle, revision)?;
        reference.scope_digest = scope.digest();
        reference.reference_digest = Digest::from_parts(
            "aws-sns-opaque-sigv4-reference/v1",
            &[
                ("kind", "sigv4_credential".to_owned()),
                ("reference", reference.reference_digest.as_str().to_owned()),
                ("scope", reference.scope_digest.as_str().to_owned()),
                ("revision", revision.to_string()),
            ],
        );
        Ok(reference)
    }

    pub fn sigv4(
        opaque_handle: impl Into<String>,
        scope: &AwsSnsTopicScope,
        revision: u64,
    ) -> Result<Self> {
        Self::for_scope(opaque_handle, scope, revision)
    }

    pub fn kind(&self) -> SecretKind {
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

    pub(crate) fn validate(&self, scope: &AwsSnsTopicScope) -> Result<()> {
        if !matches!(self.kind, SecretKind::Sigv4Credential)
            || self.revision == 0
            || self.revoked
            || self.scope_digest != scope.digest()
        {
            return Err(AwsSnsTopicError::InvalidSecretReference);
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }

    pub const fn is_native(&self) -> bool {
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
            "aws-sns-permissions/v1",
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
            Err(AwsSnsTopicError::InvalidPermissionSnapshot)
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
            "aws-sns-consent/v1",
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
            Err(AwsSnsTopicError::InvalidConsent)
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
#[serde(rename_all = "snake_case")]
pub enum ContentProtection {
    Unencrypted,
    AwsManagedKey,
    CustomerManagedKey,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TopicPosture {
    pub fifo: bool,
    pub content_based_deduplication: Option<bool>,
    pub content_protection: ContentProtection,
    pub key_reference_digest: Option<Digest>,
    pub delivery_policy_digest: Option<Digest>,
}

impl TopicPosture {
    pub fn new(
        fifo: bool,
        content_based_deduplication: Option<bool>,
        kms_master_key: Option<String>,
        delivery_policy_json: Option<String>,
    ) -> Result<Self> {
        let key_reference_digest = kms_master_key
            .map(|value| {
                if valid_text(&value, MAX_IDENTIFIER_BYTES, false) {
                    Ok(Digest::from_parts(
                        "aws-sns-kms-key-reference/v1",
                        &[("value", value)],
                    ))
                } else {
                    Err(AwsSnsTopicError::InvalidIdentifier {
                        field: "kms-master-key",
                    })
                }
            })
            .transpose()?;
        let content_protection = if key_reference_digest.is_some() {
            ContentProtection::CustomerManagedKey
        } else {
            ContentProtection::Unencrypted
        };
        let delivery_policy_digest = delivery_policy_json
            .map(|value| Digest::from_parts("aws-sns-delivery-policy/v1", &[("json", value)]));
        Ok(Self {
            fifo,
            content_based_deduplication,
            content_protection,
            key_reference_digest,
            delivery_policy_digest,
        })
    }

    pub fn fixture() -> Self {
        Self {
            fifo: false,
            content_based_deduplication: Some(false),
            content_protection: ContentProtection::Unknown,
            key_reference_digest: None,
            delivery_policy_digest: None,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-sns-topic-posture/v1",
            &[
                ("fifo", self.fifo.to_string()),
                (
                    "content_based_deduplication",
                    self.content_based_deduplication
                        .map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
                ),
                (
                    "content_protection",
                    format!("{:?}", self.content_protection),
                ),
                (
                    "key",
                    self.key_reference_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "delivery_policy",
                    self.delivery_policy_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionProtocol {
    Sqs,
    Lambda,
    Http,
    Https,
    Email,
    EmailJson,
    Sms,
    Application,
    Firehose,
    Unknown,
}

impl SubscriptionProtocol {
    pub fn from_raw(value: &str) -> Self {
        match value {
            "sqs" => Self::Sqs,
            "lambda" => Self::Lambda,
            "http" => Self::Http,
            "https" => Self::Https,
            "email" => Self::Email,
            "email-json" => Self::EmailJson,
            "sms" => Self::Sms,
            "application" => Self::Application,
            "firehose" => Self::Firehose,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationState {
    Confirmed,
    Pending,
    NotApplicable,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointClass {
    Queue,
    Function,
    Http,
    Email,
    Sms,
    Application,
    Firehose,
    Unknown,
}

impl EndpointClass {
    const fn from_protocol(protocol: SubscriptionProtocol) -> Self {
        match protocol {
            SubscriptionProtocol::Sqs => Self::Queue,
            SubscriptionProtocol::Lambda => Self::Function,
            SubscriptionProtocol::Http | SubscriptionProtocol::Https => Self::Http,
            SubscriptionProtocol::Email | SubscriptionProtocol::EmailJson => Self::Email,
            SubscriptionProtocol::Sms => Self::Sms,
            SubscriptionProtocol::Application => Self::Application,
            SubscriptionProtocol::Firehose => Self::Firehose,
            SubscriptionProtocol::Unknown => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionPosture {
    pub subscription_digest: Digest,
    pub protocol: SubscriptionProtocol,
    pub confirmation: ConfirmationState,
    pub redrive_policy_digest: Option<Digest>,
    pub filter_policy_digest: Option<Digest>,
    pub endpoint_class: EndpointClass,
}

impl SubscriptionPosture {
    pub fn new(
        subscription: &SubscriptionIdentity,
        protocol: impl AsRef<str>,
        confirmation: ConfirmationState,
        redrive_policy_json: Option<String>,
        filter_policy_json: Option<String>,
    ) -> Result<Self> {
        let protocol = SubscriptionProtocol::from_raw(protocol.as_ref());
        let redrive_policy_digest = redrive_policy_json
            .map(|value| Digest::from_parts("aws-sns-redrive-policy/v1", &[("json", value)]));
        let filter_policy_digest = filter_policy_json
            .map(|value| Digest::from_parts("aws-sns-filter-policy/v1", &[("json", value)]));
        Ok(Self {
            subscription_digest: subscription.digest(),
            protocol,
            confirmation,
            redrive_policy_digest,
            filter_policy_digest,
            endpoint_class: EndpointClass::from_protocol(protocol),
        })
    }

    pub fn fixture(subscription: &SubscriptionIdentity) -> Self {
        Self {
            subscription_digest: subscription.digest(),
            protocol: SubscriptionProtocol::Sqs,
            confirmation: ConfirmationState::Confirmed,
            redrive_policy_digest: None,
            filter_policy_digest: None,
            endpoint_class: EndpointClass::Queue,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-sns-subscription-posture/v1",
            &[
                ("subscription", self.subscription_digest.as_str().to_owned()),
                ("protocol", format!("{:?}", self.protocol)),
                ("confirmation", format!("{:?}", self.confirmation)),
                (
                    "redrive",
                    self.redrive_policy_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "filter",
                    self.filter_policy_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("endpoint_class", format!("{:?}", self.endpoint_class)),
            ],
        )
    }
}
