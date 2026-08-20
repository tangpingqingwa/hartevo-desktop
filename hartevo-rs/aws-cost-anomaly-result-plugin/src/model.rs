use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{AwsCostAnomalyError, Result};
use crate::{
    LAYER1_PERMISSIONS, MAX_ARN_BYTES, MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE, MAX_PAGES,
    MAX_RESPONSE_BYTES, MAX_RETENTION_DAYS,
};

pub const MAX_MONITOR_NAME_BYTES: usize = 256;
pub const MAX_ANOMALY_DIMENSIONS: usize = 64;
pub const MAX_SUBSCRIBERS: usize = 256;

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
            Err(AwsCostAnomalyError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsCostAnomalyError::InvalidDigest)
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
    valid_text(value, MAX_ARN_BYTES, false) && value.starts_with("arn:")
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
                    Err(AwsCostAnomalyError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("aws-cost-anomaly-", $field, "/v1"),
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
                    Err(AwsCostAnomalyError::InvalidIdentifier { field: $field })
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
redacted_text!(MonitorArn, "monitor-arn", valid_arn);
redacted_text!(SubscriptionArn, "subscription-arn", valid_arn);
redacted_text!(AnomalyId, "anomaly-id", |value: &str| valid_identifier(
    value,
    MAX_IDENTIFIER_BYTES
));
redacted_text!(DeploymentId, "deployment-id", |value: &str| {
    valid_identifier(value, MAX_IDENTIFIER_BYTES)
});
redacted_text!(ServiceName, "service-name", |value: &str| valid_identifier(
    value,
    MAX_IDENTIFIER_BYTES
));

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CursorOperation {
    Anomalies,
    Monitors,
    Subscriptions,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Sigv4Credential,
}

/// An opaque SigV4 reference. The supplied handle is hashed and zeroized
/// immediately; it is never retained, serialized, displayed, or debugged.
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
            return Err(AwsCostAnomalyError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_parts(
            "aws-cost-anomaly-opaque-sigv4-reference/v1",
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
            scope_digest: Digest::from_text("unbound-aws-cost-anomaly-secret-scope"),
            revision,
            revoked: false,
        })
    }

    pub fn sigv4(
        opaque_handle: impl Into<String>,
        scope: &AwsCostAnomalyScope,
        revision: u64,
    ) -> Result<Self> {
        let mut reference = Self::new(opaque_handle, revision)?;
        reference.scope_digest = scope.digest();
        reference.reference_digest = Digest::from_parts(
            "aws-cost-anomaly-opaque-sigv4-reference/v1",
            &[
                ("kind", "sigv4_credential".to_owned()),
                ("reference", reference.reference_digest.as_str().to_owned()),
                ("scope", reference.scope_digest.as_str().to_owned()),
                ("revision", revision.to_string()),
            ],
        );
        Ok(reference)
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

    pub(crate) fn validate(&self, scope: &AwsCostAnomalyScope) -> Result<()> {
        if !matches!(self.kind, SecretKind::Sigv4Credential)
            || self.revision == 0
            || self.revoked
            || self.scope_digest != scope.digest()
        {
            return Err(AwsCostAnomalyError::InvalidSecretReference);
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
pub struct AnomalyWindow {
    pub start_date: DateTime<Utc>,
    pub end_date: DateTime<Utc>,
}

impl AnomalyWindow {
    pub fn new(start_date: DateTime<Utc>, end_date: DateTime<Utc>) -> Result<Self> {
        if start_date > end_date || end_date - start_date > Duration::days(MAX_RETENTION_DAYS) {
            return Err(AwsCostAnomalyError::InvalidScope);
        }
        Ok(Self {
            start_date,
            end_date,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cost-anomaly-window/v1",
            &[
                ("start", self.start_date.to_rfc3339()),
                ("end", self.end_date.to_rfc3339()),
            ],
        )
    }

    pub fn validate_retention_at(&self, observed_at: DateTime<Utc>) -> Result<()> {
        let earliest = observed_at - Duration::days(MAX_RETENTION_DAYS);
        if self.start_date < earliest || self.end_date > observed_at {
            Err(AwsCostAnomalyError::RetentionExpired)
        } else {
            Ok(())
        }
    }

    pub fn contains(&self, other: &Self) -> bool {
        self.start_date <= other.start_date && self.end_date >= other.end_date
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AnomalyIdentity {
    id: AnomalyId,
    window: AnomalyWindow,
}

impl AnomalyIdentity {
    pub fn new(id: AnomalyId, window: AnomalyWindow) -> Result<Self> {
        id.validate()?;
        Ok(Self { id, window })
    }

    pub fn id(&self) -> &AnomalyId {
        &self.id
    }

    pub fn window(&self) -> &AnomalyWindow {
        &self.window
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cost-anomaly-identity/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("window", self.window.digest().as_str().to_owned()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.id.validate()
    }
}

impl fmt::Debug for AnomalyIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnomalyIdentity")
            .field("digest", &self.digest())
            .field("window", &self.window)
            .finish()
    }
}

macro_rules! revisioned_identity {
    ($name:ident, $id_name:ident, $domain:literal, $field:literal) => {
        #[derive(Clone, Eq, PartialEq)]
        pub struct $name {
            id: $id_name,
            revision: u64,
        }

        impl $name {
            pub fn new(id: $id_name, revision: u64) -> Result<Self> {
                if revision == 0 {
                    return Err(AwsCostAnomalyError::InvalidScope);
                }
                id.validate()?;
                Ok(Self { id, revision })
            }

            pub fn id(&self) -> &$id_name {
                &self.id
            }

            pub const fn revision(&self) -> u64 {
                self.revision
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    $domain,
                    &[
                        ($field, self.id.digest().as_str().to_owned()),
                        ("revision", self.revision.to_string()),
                    ],
                )
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if self.revision == 0 {
                    Err(AwsCostAnomalyError::InvalidScope)
                } else {
                    self.id.validate()
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

redacted_text!(MissionId, "mission-id", |value: &str| valid_identifier(
    value,
    MAX_IDENTIFIER_BYTES
));
redacted_text!(ProjectId, "project-id", |value: &str| valid_identifier(
    value,
    MAX_IDENTIFIER_BYTES
));
redacted_text!(WorkProductId, "work-product-id", |value: &str| {
    valid_identifier(value, MAX_IDENTIFIER_BYTES)
});

revisioned_identity!(
    MissionIdentity,
    MissionId,
    "aws-cost-anomaly-mission/v1",
    "id"
);
revisioned_identity!(
    ProjectIdentity,
    ProjectId,
    "aws-cost-anomaly-project/v1",
    "id"
);
revisioned_identity!(
    WorkProductIdentity,
    WorkProductId,
    "aws-cost-anomaly-work-product/v1",
    "id"
);

revisioned_identity!(
    DeploymentIdentity,
    DeploymentId,
    "aws-cost-anomaly-deployment/v1",
    "deployment"
);
revisioned_identity!(
    ServiceRevisionIdentity,
    ServiceName,
    "aws-cost-anomaly-service-revision/v1",
    "service"
);

#[derive(Clone, Eq, PartialEq)]
pub struct AwsCostAnomalyScope {
    management_account: AwsAccountId,
    account: AwsAccountId,
    region: AwsRegion,
    monitor: MonitorArn,
    anomaly: AnomalyIdentity,
    deployment: DeploymentIdentity,
    service_revision: ServiceRevisionIdentity,
    subscription: SubscriptionArn,
    mission: MissionIdentity,
    project: ProjectIdentity,
    work_product: WorkProductIdentity,
}

impl AwsCostAnomalyScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        management_account: AwsAccountId,
        account: AwsAccountId,
        region: AwsRegion,
        monitor: MonitorArn,
        anomaly: AnomalyIdentity,
        deployment: DeploymentIdentity,
        service_revision: ServiceRevisionIdentity,
        subscription: SubscriptionArn,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let scope = Self {
            management_account,
            account,
            region,
            monitor,
            anomaly,
            deployment,
            service_revision,
            subscription,
            mission,
            project,
            work_product,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn management_account(&self) -> &AwsAccountId {
        &self.management_account
    }

    pub fn account(&self) -> &AwsAccountId {
        &self.account
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn monitor(&self) -> &MonitorArn {
        &self.monitor
    }

    pub fn anomaly(&self) -> &AnomalyIdentity {
        &self.anomaly
    }

    pub fn deployment(&self) -> &DeploymentIdentity {
        &self.deployment
    }

    pub fn service_revision(&self) -> &ServiceRevisionIdentity {
        &self.service_revision
    }

    pub fn subscription(&self) -> &SubscriptionArn {
        &self.subscription
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
            "aws-cost-anomaly-scope/v1",
            &[
                (
                    "management_account",
                    self.management_account.digest().as_str().to_owned(),
                ),
                ("account", self.account.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                ("monitor", self.monitor.digest().as_str().to_owned()),
                ("anomaly", self.anomaly.digest().as_str().to_owned()),
                ("deployment", self.deployment.digest().as_str().to_owned()),
                (
                    "service_revision",
                    self.service_revision.digest().as_str().to_owned(),
                ),
                (
                    "subscription",
                    self.subscription.digest().as_str().to_owned(),
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
        self.management_account.validate()?;
        self.account.validate()?;
        self.region.validate()?;
        self.monitor.validate()?;
        self.anomaly.validate()?;
        self.deployment.validate()?;
        self.service_revision.validate()?;
        self.subscription.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()
    }
}

impl fmt::Debug for AwsCostAnomalyScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCostAnomalyScope")
            .field("digest", &self.digest())
            .field("management_account", &self.management_account)
            .field("account", &self.account)
            .field("region", &self.region)
            .field("monitor", &self.monitor)
            .field("anomaly", &self.anomaly)
            .field("deployment", &self.deployment)
            .field("service_revision", &self.service_revision)
            .field("subscription", &self.subscription)
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .finish()
    }
}

impl Serialize for AwsCostAnomalyScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsCostAnomalyScope", 13)?;
        state.serialize_field("scopeDigest", &self.digest())?;
        state.serialize_field("managementAccountDigest", &self.management_account.digest())?;
        state.serialize_field("accountDigest", &self.account.digest())?;
        state.serialize_field("regionDigest", &self.region.digest())?;
        state.serialize_field("monitorDigest", &self.monitor.digest())?;
        state.serialize_field("anomalyDigest", &self.anomaly.digest())?;
        state.serialize_field("anomalyWindow", self.anomaly.window())?;
        state.serialize_field("deploymentDigest", &self.deployment.digest())?;
        state.serialize_field("serviceRevisionDigest", &self.service_revision.digest())?;
        state.serialize_field("subscriptionDigest", &self.subscription.digest())?;
        state.serialize_field("missionDigest", &self.mission.digest())?;
        state.serialize_field("projectDigest", &self.project.digest())?;
        state.serialize_field("workProductDigest", &self.work_product.digest())?;
        state.end()
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
            "aws-cost-anomaly-permissions/v1",
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
            Err(AwsCostAnomalyError::InvalidPermissionSnapshot)
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
            "aws-cost-anomaly-consent/v1",
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
            Err(AwsCostAnomalyError::InvalidConsent)
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
pub enum AnomalyImpactBand {
    None,
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

impl AnomalyImpactBand {
    pub(crate) const fn from_impact_usd(value: Option<u64>) -> Self {
        match value {
            None | Some(0) => Self::Unknown,
            Some(1..=99) => Self::Low,
            Some(100..=999) => Self::Medium,
            Some(1_000..=9_999) => Self::High,
            Some(_) => Self::Critical,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyFeedback {
    Positive,
    Negative,
    NotProvided,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitorType {
    Dimensional,
    Custom,
    Service,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitorStatus {
    Active,
    Inactive,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionFrequency {
    Daily,
    Weekly,
    Monthly,
    None,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    Active,
    Inactive,
    Unknown,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AnomalyMetadata {
    identity: AnomalyIdentity,
    monitor: MonitorArn,
    impact_band: AnomalyImpactBand,
    feedback: AnomalyFeedback,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AnomalyMetadataInput {
    pub anomaly_id: AnomalyId,
    pub monitor_arn: MonitorArn,
    pub window: AnomalyWindow,
    pub impact_usd: Option<u64>,
    pub feedback: AnomalyFeedback,
    /// Accepted only at the ephemeral input boundary and immediately dropped.
    pub root_cause_dimensions: Vec<String>,
}

impl fmt::Debug for AnomalyMetadataInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnomalyMetadataInput")
            .field("anomaly_id_digest", &self.anomaly_id.digest())
            .field("monitor_digest", &self.monitor_arn.digest())
            .field("window", &self.window)
            .field(
                "impact_band",
                &AnomalyImpactBand::from_impact_usd(self.impact_usd),
            )
            .field(
                "root_cause_dimension_count",
                &self.root_cause_dimensions.len(),
            )
            .field("feedback", &self.feedback)
            .finish()
    }
}

impl AnomalyMetadata {
    pub fn new(scope: &AwsCostAnomalyScope, input: AnomalyMetadataInput) -> Result<Self> {
        if input.root_cause_dimensions.len() > MAX_ANOMALY_DIMENSIONS
            || input
                .root_cause_dimensions
                .iter()
                .any(|value| !valid_text(value, MAX_IDENTIFIER_BYTES, true))
        {
            return Err(AwsCostAnomalyError::InvalidRequest);
        }
        let identity = AnomalyIdentity::new(input.anomaly_id, input.window)?;
        let metadata = Self {
            identity,
            monitor: input.monitor_arn,
            impact_band: AnomalyImpactBand::from_impact_usd(input.impact_usd),
            feedback: input.feedback,
        };
        metadata.validate_against(scope)?;
        Ok(metadata)
    }

    pub fn identity(&self) -> &AnomalyIdentity {
        &self.identity
    }

    pub fn monitor(&self) -> &MonitorArn {
        &self.monitor
    }

    pub const fn impact_band(&self) -> AnomalyImpactBand {
        self.impact_band
    }

    pub const fn feedback(&self) -> AnomalyFeedback {
        self.feedback
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cost-anomaly-metadata/v1",
            &[
                ("identity", self.identity.digest().as_str().to_owned()),
                ("monitor", self.monitor.digest().as_str().to_owned()),
                ("impact_band", format!("{:?}", self.impact_band)),
                ("feedback", format!("{:?}", self.feedback)),
            ],
        )
    }

    pub fn validate_against(&self, scope: &AwsCostAnomalyScope) -> Result<()> {
        if self.monitor != *scope.monitor() || self.identity != *scope.anomaly() {
            Err(AwsCostAnomalyError::ScopeMismatch)
        } else {
            Ok(())
        }
    }

    pub fn validate_list_item_against(
        &self,
        scope: &AwsCostAnomalyScope,
        filter: &AnomalyFilter,
    ) -> Result<()> {
        if self.monitor != *scope.monitor()
            || self.identity.window().start_date < filter.start_date
            || self.identity.window().end_date > filter.end_date
        {
            Err(AwsCostAnomalyError::FilterMismatch)
        } else {
            self.identity.validate()
        }
    }
}

impl fmt::Debug for AnomalyMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnomalyMetadata")
            .field("digest", &self.digest())
            .field("anomaly_id_digest", &self.identity.id().digest())
            .field("monitor_digest", &self.monitor.digest())
            .field("window", self.identity.window())
            .field("impact_band", &self.impact_band)
            .field("feedback", &self.feedback)
            .finish()
    }
}

impl Serialize for AnomalyMetadata {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AnomalyMetadata", 6)?;
        state.serialize_field("anomalyIdDigest", &self.identity.id().digest())?;
        state.serialize_field("monitorDigest", &self.monitor.digest())?;
        state.serialize_field("window", self.identity.window())?;
        state.serialize_field("impactBand", &self.impact_band)?;
        state.serialize_field("feedback", &self.feedback)?;
        state.serialize_field("metadataDigest", &self.digest())?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct MonitorMetadata {
    arn: MonitorArn,
    name_digest: Digest,
    monitor_type: MonitorType,
    status: MonitorStatus,
    evaluation_start: Option<DateTime<Utc>>,
    evaluation_end: Option<DateTime<Utc>>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct MonitorMetadataInput {
    pub monitor_arn: MonitorArn,
    pub monitor_name: String,
    pub monitor_type: MonitorType,
    pub status: MonitorStatus,
    pub evaluation_start: Option<DateTime<Utc>>,
    pub evaluation_end: Option<DateTime<Utc>>,
}

impl fmt::Debug for MonitorMetadataInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MonitorMetadataInput")
            .field("monitor_digest", &self.monitor_arn.digest())
            .field(
                "monitor_name_digest",
                &Digest::from_text(&self.monitor_name),
            )
            .field("monitor_type", &self.monitor_type)
            .field("status", &self.status)
            .field("evaluation_start", &self.evaluation_start)
            .field("evaluation_end", &self.evaluation_end)
            .finish()
    }
}

impl MonitorMetadata {
    pub fn new(scope: &AwsCostAnomalyScope, input: MonitorMetadataInput) -> Result<Self> {
        if !valid_text(&input.monitor_name, MAX_MONITOR_NAME_BYTES, true) {
            return Err(AwsCostAnomalyError::InvalidText {
                field: "monitor-name",
            });
        }
        if let (Some(start), Some(end)) = (input.evaluation_start, input.evaluation_end)
            && start > end
        {
            return Err(AwsCostAnomalyError::InvalidScope);
        }
        let metadata = Self {
            arn: input.monitor_arn,
            name_digest: Digest::from_parts(
                "aws-cost-anomaly-monitor-name/v1",
                &[("name", input.monitor_name)],
            ),
            monitor_type: input.monitor_type,
            status: input.status,
            evaluation_start: input.evaluation_start,
            evaluation_end: input.evaluation_end,
        };
        metadata.validate_against(scope)?;
        Ok(metadata)
    }

    pub fn arn(&self) -> &MonitorArn {
        &self.arn
    }

    pub fn name_digest(&self) -> &Digest {
        &self.name_digest
    }

    pub const fn monitor_type(&self) -> MonitorType {
        self.monitor_type
    }

    pub const fn status(&self) -> MonitorStatus {
        self.status
    }

    pub fn evaluation_start(&self) -> Option<DateTime<Utc>> {
        self.evaluation_start
    }

    pub fn evaluation_end(&self) -> Option<DateTime<Utc>> {
        self.evaluation_end
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cost-anomaly-monitor-metadata/v1",
            &[
                ("arn", self.arn.digest().as_str().to_owned()),
                ("name", self.name_digest.as_str().to_owned()),
                ("type", format!("{:?}", self.monitor_type)),
                ("status", format!("{:?}", self.status)),
                (
                    "evaluation_start",
                    self.evaluation_start
                        .map_or_else(String::new, |date| date.to_rfc3339()),
                ),
                (
                    "evaluation_end",
                    self.evaluation_end
                        .map_or_else(String::new, |date| date.to_rfc3339()),
                ),
            ],
        )
    }

    pub fn validate_against(&self, scope: &AwsCostAnomalyScope) -> Result<()> {
        if self.arn != *scope.monitor() {
            Err(AwsCostAnomalyError::MonitorMismatch)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for MonitorMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MonitorMetadata")
            .field("digest", &self.digest())
            .field("monitor_digest", &self.arn.digest())
            .field("name_digest", &self.name_digest)
            .field("monitor_type", &self.monitor_type)
            .field("status", &self.status)
            .field("evaluation_start", &self.evaluation_start)
            .field("evaluation_end", &self.evaluation_end)
            .finish()
    }
}

impl Serialize for MonitorMetadata {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("MonitorMetadata", 7)?;
        state.serialize_field("monitorDigest", &self.arn.digest())?;
        state.serialize_field("nameDigest", &self.name_digest)?;
        state.serialize_field("monitorType", &self.monitor_type)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("evaluationStart", &self.evaluation_start)?;
        state.serialize_field("evaluationEnd", &self.evaluation_end)?;
        state.serialize_field("metadataDigest", &self.digest())?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SubscriptionMetadata {
    arn: SubscriptionArn,
    frequency: SubscriptionFrequency,
    status: SubscriptionStatus,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SubscriptionMetadataInput {
    pub subscription_arn: SubscriptionArn,
    pub frequency: SubscriptionFrequency,
    pub status: SubscriptionStatus,
    /// Addresses are accepted only to model provider redaction, then dropped.
    pub subscriber_addresses: Vec<String>,
}

impl fmt::Debug for SubscriptionMetadataInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubscriptionMetadataInput")
            .field("subscription_digest", &self.subscription_arn.digest())
            .field("frequency", &self.frequency)
            .field("status", &self.status)
            .field("subscriber_count", &self.subscriber_addresses.len())
            .finish()
    }
}

impl SubscriptionMetadata {
    pub fn new(scope: &AwsCostAnomalyScope, input: SubscriptionMetadataInput) -> Result<Self> {
        if input.subscriber_addresses.len() > MAX_SUBSCRIBERS
            || input
                .subscriber_addresses
                .iter()
                .any(|value| !valid_text(value, MAX_IDENTIFIER_BYTES, true))
        {
            return Err(AwsCostAnomalyError::InvalidRequest);
        }
        let metadata = Self {
            arn: input.subscription_arn,
            frequency: input.frequency,
            status: input.status,
        };
        metadata.validate_against(scope)?;
        Ok(metadata)
    }

    pub fn arn(&self) -> &SubscriptionArn {
        &self.arn
    }

    pub const fn frequency(&self) -> SubscriptionFrequency {
        self.frequency
    }

    pub const fn status(&self) -> SubscriptionStatus {
        self.status
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cost-anomaly-subscription-metadata/v1",
            &[
                ("arn", self.arn.digest().as_str().to_owned()),
                ("frequency", format!("{:?}", self.frequency)),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }

    pub fn validate_against(&self, scope: &AwsCostAnomalyScope) -> Result<()> {
        if self.arn != *scope.subscription() {
            Err(AwsCostAnomalyError::ScopeMismatch)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for SubscriptionMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubscriptionMetadata")
            .field("digest", &self.digest())
            .field("subscription_digest", &self.arn.digest())
            .field("frequency", &self.frequency)
            .field("status", &self.status)
            .finish()
    }
}

impl Serialize for SubscriptionMetadata {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("SubscriptionMetadata", 4)?;
        state.serialize_field("subscriptionDigest", &self.arn.digest())?;
        state.serialize_field("frequency", &self.frequency)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("metadataDigest", &self.digest())?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AnomalyFilter {
    scope_digest: Digest,
    monitor_digest: Digest,
    start_date: DateTime<Utc>,
    end_date: DateTime<Utc>,
    max_results: u16,
}

impl AnomalyFilter {
    pub fn new(
        scope: &AwsCostAnomalyScope,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
        max_results: u16,
    ) -> Result<Self> {
        if max_results == 0 || max_results > MAX_PAGE_SIZE || start_date > end_date {
            return Err(AwsCostAnomalyError::InvalidRequest);
        }
        let filter = Self {
            scope_digest: scope.digest(),
            monitor_digest: scope.monitor().digest(),
            start_date,
            end_date,
            max_results,
        };
        filter.validate_against(scope)?;
        Ok(filter)
    }

    pub fn for_scope(scope: &AwsCostAnomalyScope, max_results: u16) -> Result<Self> {
        Self::new(
            scope,
            scope.anomaly().window().start_date,
            scope.anomaly().window().end_date,
            max_results,
        )
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn monitor_digest(&self) -> &Digest {
        &self.monitor_digest
    }

    pub const fn start_date(&self) -> DateTime<Utc> {
        self.start_date
    }

    pub const fn end_date(&self) -> DateTime<Utc> {
        self.end_date
    }

    pub const fn max_results(&self) -> u16 {
        self.max_results
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cost-anomaly-filter/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("monitor", self.monitor_digest.as_str().to_owned()),
                ("start", self.start_date.to_rfc3339()),
                ("end", self.end_date.to_rfc3339()),
                ("max_results", self.max_results.to_string()),
            ],
        )
    }

    pub fn validate_against(&self, scope: &AwsCostAnomalyScope) -> Result<()> {
        let window = scope.anomaly().window();
        if self.scope_digest != scope.digest()
            || self.monitor_digest != scope.monitor().digest()
            || self.start_date < window.start_date
            || self.end_date > window.end_date
            || self.start_date > self.end_date
            || self.max_results == 0
            || self.max_results > MAX_PAGE_SIZE
        {
            Err(AwsCostAnomalyError::FilterMismatch)
        } else {
            Ok(())
        }
    }
}

impl CursorBinding for AnomalyFilter {
    fn cursor_operation(&self) -> CursorOperation {
        CursorOperation::Anomalies
    }

    fn binding_digest(&self) -> Digest {
        self.digest()
    }
}

impl fmt::Debug for AnomalyFilter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnomalyFilter")
            .field("digest", &self.digest())
            .field("start_date", &self.start_date)
            .field("end_date", &self.end_date)
            .field("max_results", &self.max_results)
            .finish()
    }
}

impl Serialize for AnomalyFilter {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AnomalyFilter", 5)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("monitorDigest", &self.monitor_digest)?;
        state.serialize_field("startDate", &self.start_date)?;
        state.serialize_field("endDate", &self.end_date)?;
        state.serialize_field("maxResults", &self.max_results)?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct MonitorFilter {
    scope_digest: Digest,
    monitor_digest: Digest,
    max_results: u16,
}

impl MonitorFilter {
    pub fn for_scope(scope: &AwsCostAnomalyScope, max_results: u16) -> Result<Self> {
        if max_results == 0 || max_results > MAX_PAGE_SIZE {
            return Err(AwsCostAnomalyError::InvalidRequest);
        }
        Ok(Self {
            scope_digest: scope.digest(),
            monitor_digest: scope.monitor().digest(),
            max_results,
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn monitor_digest(&self) -> &Digest {
        &self.monitor_digest
    }

    pub const fn max_results(&self) -> u16 {
        self.max_results
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cost-anomaly-monitor-filter/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("monitor", self.monitor_digest.as_str().to_owned()),
                ("max_results", self.max_results.to_string()),
            ],
        )
    }

    pub fn validate_against(&self, scope: &AwsCostAnomalyScope) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.monitor_digest != scope.monitor().digest()
            || self.max_results == 0
            || self.max_results > MAX_PAGE_SIZE
        {
            Err(AwsCostAnomalyError::MonitorMismatch)
        } else {
            Ok(())
        }
    }
}

impl CursorBinding for MonitorFilter {
    fn cursor_operation(&self) -> CursorOperation {
        CursorOperation::Monitors
    }

    fn binding_digest(&self) -> Digest {
        self.digest()
    }
}

impl fmt::Debug for MonitorFilter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MonitorFilter")
            .field("digest", &self.digest())
            .field("max_results", &self.max_results)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct SubscriptionFilter {
    scope_digest: Digest,
    subscription_digest: Digest,
    max_results: u16,
}

impl SubscriptionFilter {
    pub fn for_scope(scope: &AwsCostAnomalyScope, max_results: u16) -> Result<Self> {
        if max_results == 0 || max_results > MAX_PAGE_SIZE {
            return Err(AwsCostAnomalyError::InvalidRequest);
        }
        Ok(Self {
            scope_digest: scope.digest(),
            subscription_digest: scope.subscription().digest(),
            max_results,
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn subscription_digest(&self) -> &Digest {
        &self.subscription_digest
    }

    pub const fn max_results(&self) -> u16 {
        self.max_results
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cost-anomaly-subscription-filter/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("subscription", self.subscription_digest.as_str().to_owned()),
                ("max_results", self.max_results.to_string()),
            ],
        )
    }

    pub fn validate_against(&self, scope: &AwsCostAnomalyScope) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.subscription_digest != scope.subscription().digest()
            || self.max_results == 0
            || self.max_results > MAX_PAGE_SIZE
        {
            Err(AwsCostAnomalyError::ScopeMismatch)
        } else {
            Ok(())
        }
    }
}

impl CursorBinding for SubscriptionFilter {
    fn cursor_operation(&self) -> CursorOperation {
        CursorOperation::Subscriptions
    }

    fn binding_digest(&self) -> Digest {
        self.digest()
    }
}

impl fmt::Debug for SubscriptionFilter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubscriptionFilter")
            .field("digest", &self.digest())
            .field("max_results", &self.max_results)
            .finish()
    }
}

pub trait CursorBinding {
    fn cursor_operation(&self) -> CursorOperation;
    fn binding_digest(&self) -> Digest;
}

#[derive(Clone, Eq, PartialEq)]
pub struct Cursor {
    scope_digest: Digest,
    filter_digest: Digest,
    operation: CursorOperation,
    token_digest: Digest,
    page_number: u16,
}

impl Cursor {
    pub fn new<B: CursorBinding>(
        opaque_token: impl Into<String>,
        scope: &AwsCostAnomalyScope,
        binding: &B,
        page_number: u16,
    ) -> Result<Self> {
        let token = opaque_token.into();
        if !valid_text(&token, MAX_IDENTIFIER_BYTES, true)
            || page_number == 0
            || page_number > MAX_PAGES
        {
            return Err(AwsCostAnomalyError::InvalidRequest);
        }
        Ok(Self {
            scope_digest: scope.digest(),
            filter_digest: binding.binding_digest(),
            operation: binding.cursor_operation(),
            token_digest: Digest::from_parts("aws-cost-anomaly-next-token/v1", &[("token", token)]),
            page_number,
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn filter_digest(&self) -> &Digest {
        &self.filter_digest
    }

    pub const fn operation(&self) -> CursorOperation {
        self.operation
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn validate_against<B: CursorBinding>(
        &self,
        scope: &AwsCostAnomalyScope,
        binding: &B,
    ) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.filter_digest != binding.binding_digest()
            || self.operation != binding.cursor_operation()
            || self.page_number == 0
            || self.page_number > MAX_PAGES
        {
            Err(AwsCostAnomalyError::CursorMismatch)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for Cursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Cursor")
            .field("scope_digest", &self.scope_digest)
            .field("filter_digest", &self.filter_digest)
            .field("operation", &self.operation)
            .field("token_digest", &self.token_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

impl Serialize for Cursor {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("Cursor", 5)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("filterDigest", &self.filter_digest)?;
        state.serialize_field("operation", &self.operation)?;
        state.serialize_field("tokenDigest", &self.token_digest)?;
        state.serialize_field("pageNumber", &self.page_number)?;
        state.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyEvidenceState {
    AnomalyDetected,
    NoAnomaly,
    MonitorActive,
    MonitorInactive,
    SubscriptionActive,
    SubscriptionInactive,
    Partial,
    RetentionExpired,
    NotFound,
    AccessLoss,
    Throttled,
    ProviderUnknown,
    RegistrationRevoked,
}

impl AnomalyEvidenceState {
    pub const fn is_review_complete(self) -> bool {
        matches!(
            self,
            Self::AnomalyDetected
                | Self::NoAnomaly
                | Self::MonitorActive
                | Self::SubscriptionActive
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
    pub monitor_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub anomalies_digest: Option<Digest>,
    pub monitors_digest: Option<Digest>,
    pub subscriptions_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnomalyProjection {
    pub anomaly_id_digest: Digest,
    pub monitor_digest: Digest,
    pub window: AnomalyWindow,
    pub impact_band: AnomalyImpactBand,
    pub feedback: AnomalyFeedback,
}

impl From<&AnomalyMetadata> for AnomalyProjection {
    fn from(metadata: &AnomalyMetadata) -> Self {
        Self {
            anomaly_id_digest: metadata.identity.id().digest(),
            monitor_digest: metadata.monitor.digest(),
            window: metadata.identity.window().clone(),
            impact_band: metadata.impact_band,
            feedback: metadata.feedback,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorProjection {
    pub monitor_digest: Digest,
    pub name_digest: Digest,
    pub monitor_type: MonitorType,
    pub status: MonitorStatus,
    pub evaluation_start: Option<DateTime<Utc>>,
    pub evaluation_end: Option<DateTime<Utc>>,
}

impl From<&MonitorMetadata> for MonitorProjection {
    fn from(metadata: &MonitorMetadata) -> Self {
        Self {
            monitor_digest: metadata.arn.digest(),
            name_digest: metadata.name_digest.clone(),
            monitor_type: metadata.monitor_type,
            status: metadata.status,
            evaluation_start: metadata.evaluation_start,
            evaluation_end: metadata.evaluation_end,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionProjection {
    pub subscription_digest: Digest,
    pub frequency: SubscriptionFrequency,
    pub status: SubscriptionStatus,
}

impl From<&SubscriptionMetadata> for SubscriptionProjection {
    fn from(metadata: &SubscriptionMetadata) -> Self {
        Self {
            subscription_digest: metadata.arn.digest(),
            frequency: metadata.frequency,
            status: metadata.status,
        }
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

pub(crate) fn mission_projection(mission: &MissionIdentity) -> MissionProjection {
    MissionProjection {
        id_digest: mission.digest(),
        revision: mission.revision(),
    }
}

pub(crate) fn project_projection(project: &ProjectIdentity) -> ProjectProjection {
    ProjectProjection {
        id_digest: project.digest(),
        revision: project.revision(),
    }
}

pub(crate) fn work_product_projection(work_product: &WorkProductIdentity) -> WorkProductProjection {
    WorkProductProjection {
        id_digest: work_product.digest(),
        revision: work_product.revision(),
    }
}

pub(crate) fn validate_response_bytes(response_bytes: u64) -> Result<()> {
    if response_bytes > MAX_RESPONSE_BYTES {
        Err(AwsCostAnomalyError::PartialEvidence)
    } else {
        Ok(())
    }
}
