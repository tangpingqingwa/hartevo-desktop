use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{AwsAppConfigDeploymentError, Result};
use crate::{
    LAYER1_PERMISSIONS, MAX_EVENTS, MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE, MAX_PAGES,
    MAX_RESPONSE_BYTES,
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
            Err(AwsAppConfigDeploymentError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsAppConfigDeploymentError::InvalidDigest)
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

macro_rules! bounded_identifier {
    ($name:ident, $field:literal, $domain:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if valid_identifier(&value, MAX_IDENTIFIER_BYTES) {
                    Ok(Self(value))
                } else {
                    Err(AwsAppConfigDeploymentError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts($domain, &[("value", self.0.clone())])
            }

            pub fn redacted(&self) -> String {
                format!("{}:{}", $field, &self.digest().as_str()[..16])
            }

            pub fn validate(&self) -> Result<()> {
                if valid_identifier(&self.0, MAX_IDENTIFIER_BYTES) {
                    Ok(())
                } else {
                    Err(AwsAppConfigDeploymentError::InvalidIdentifier { field: $field })
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

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AwsAccountId(String);

impl AwsAccountId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit()) {
            Ok(Self(value))
        } else {
            Err(AwsAppConfigDeploymentError::InvalidIdentifier {
                field: "aws-account-id",
            })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("aws-appconfig-account/v1", &[("value", self.0.clone())])
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(self.0.clone()).map(|_| ())
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

bounded_identifier!(AwsRegion, "aws-region", "aws-appconfig-region/v1");
bounded_identifier!(
    AppConfigApplicationId,
    "application-id",
    "aws-appconfig-application/v1"
);
bounded_identifier!(
    AppConfigEnvironmentId,
    "environment-id",
    "aws-appconfig-environment/v1"
);
bounded_identifier!(
    AppConfigDeploymentId,
    "deployment-id",
    "aws-appconfig-deployment/v1"
);
bounded_identifier!(
    AppConfigConfigurationProfileId,
    "configuration-profile-id",
    "aws-appconfig-configuration-profile/v1"
);
bounded_identifier!(
    AppConfigConfigurationVersion,
    "configuration-version",
    "aws-appconfig-configuration-version/v1"
);
bounded_identifier!(
    DeploymentStrategyId,
    "deployment-strategy-id",
    "aws-appconfig-deployment-strategy/v1"
);

pub type ApplicationId = AppConfigApplicationId;
pub type EnvironmentId = AppConfigEnvironmentId;
pub type DeploymentId = AppConfigDeploymentId;
pub type ConfigurationProfileId = AppConfigConfigurationProfileId;
pub type ConfigurationVersion = AppConfigConfigurationVersion;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionIdentity {
    id: String,
    revision: u64,
}

impl MissionIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let identity = Self {
            id: id.into(),
            revision,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-appconfig-mission/v1",
            &[
                ("id", self.id.clone()),
                ("revision", self.revision.to_string()),
            ],
        )
    }

    fn validate(&self) -> Result<()> {
        if valid_identifier(&self.id, MAX_IDENTIFIER_BYTES) && self.revision > 0 {
            Ok(())
        } else {
            Err(AwsAppConfigDeploymentError::InvalidIdentifier {
                field: "mission-id",
            })
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectIdentity {
    id: String,
    revision: u64,
}

impl ProjectIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let identity = Self {
            id: id.into(),
            revision,
        };
        if valid_identifier(&identity.id, MAX_IDENTIFIER_BYTES) && identity.revision > 0 {
            Ok(identity)
        } else {
            Err(AwsAppConfigDeploymentError::InvalidIdentifier {
                field: "project-id",
            })
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-appconfig-project/v1",
            &[
                ("id", self.id.clone()),
                ("revision", self.revision.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductIdentity {
    id: String,
    revision: u64,
}

impl WorkProductIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let identity = Self {
            id: id.into(),
            revision,
        };
        if valid_identifier(&identity.id, MAX_IDENTIFIER_BYTES) && identity.revision > 0 {
            Ok(identity)
        } else {
            Err(AwsAppConfigDeploymentError::InvalidIdentifier {
                field: "work-product-id",
            })
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-appconfig-work-product/v1",
            &[
                ("id", self.id.clone()),
                ("revision", self.revision.to_string()),
            ],
        )
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

pub fn mission_projection(identity: &MissionIdentity) -> MissionProjection {
    MissionProjection {
        id_digest: identity.digest(),
        revision: identity.revision,
    }
}

pub fn project_projection(identity: &ProjectIdentity) -> ProjectProjection {
    ProjectProjection {
        id_digest: identity.digest(),
        revision: identity.revision,
    }
}

pub fn work_product_projection(identity: &WorkProductIdentity) -> WorkProductProjection {
    WorkProductProjection {
        id_digest: identity.digest(),
        revision: identity.revision,
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsAppConfigDeploymentScope {
    account: AwsAccountId,
    region: AwsRegion,
    application: AppConfigApplicationId,
    environment: AppConfigEnvironmentId,
    deployment: AppConfigDeploymentId,
    configuration_profile: AppConfigConfigurationProfileId,
    configuration_version: AppConfigConfigurationVersion,
    mission: MissionIdentity,
    project: ProjectIdentity,
    work_product: WorkProductIdentity,
}

impl AwsAppConfigDeploymentScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        application: AppConfigApplicationId,
        environment: AppConfigEnvironmentId,
        deployment: AppConfigDeploymentId,
        configuration_profile: AppConfigConfigurationProfileId,
        configuration_version: AppConfigConfigurationVersion,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let scope = Self {
            account,
            region,
            application,
            environment,
            deployment,
            configuration_profile,
            configuration_version,
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

    pub fn application(&self) -> &AppConfigApplicationId {
        &self.application
    }

    pub fn environment(&self) -> &AppConfigEnvironmentId {
        &self.environment
    }

    pub fn deployment(&self) -> &AppConfigDeploymentId {
        &self.deployment
    }

    pub fn configuration_profile(&self) -> &AppConfigConfigurationProfileId {
        &self.configuration_profile
    }

    pub fn configuration_version(&self) -> &AppConfigConfigurationVersion {
        &self.configuration_version
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
            "aws-appconfig-deployment-scope/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                ("application", self.application.digest().as_str().to_owned()),
                ("environment", self.environment.digest().as_str().to_owned()),
                ("deployment", self.deployment.digest().as_str().to_owned()),
                (
                    "configuration_profile",
                    self.configuration_profile.digest().as_str().to_owned(),
                ),
                (
                    "configuration_version",
                    self.configuration_version.digest().as_str().to_owned(),
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

    pub fn validate(&self) -> Result<()> {
        self.account.validate()?;
        self.region.validate()?;
        self.application.validate()?;
        self.environment.validate()?;
        self.deployment.validate()?;
        self.configuration_profile.validate()?;
        self.configuration_version.validate()?;
        self.mission.validate()?;
        if !valid_identifier(self.project.id(), MAX_IDENTIFIER_BYTES)
            || self.project.revision() == 0
            || !valid_identifier(self.work_product.id(), MAX_IDENTIFIER_BYTES)
            || self.work_product.revision() == 0
        {
            return Err(AwsAppConfigDeploymentError::InvalidScope);
        }
        Ok(())
    }
}

impl fmt::Debug for AwsAppConfigDeploymentScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsAppConfigDeploymentScope")
            .field("digest", &self.digest())
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .finish()
    }
}

pub type AwsAppConfigScope = AwsAppConfigDeploymentScope;
pub type AppConfigDeploymentScope = AwsAppConfigDeploymentScope;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Sigv4Credential,
}

/// Opaque SigV4 reference. The supplied handle is hashed and zeroized; the
/// handle is never retained, serialized, displayed, or included in evidence.
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
            return Err(AwsAppConfigDeploymentError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_parts(
            "aws-appconfig-opaque-sigv4-reference/v1",
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
            scope_digest: Digest::from_text("unbound-aws-appconfig-secret-scope"),
            revision,
            revoked: false,
        })
    }

    pub fn sigv4(
        opaque_handle: impl Into<String>,
        scope: &AwsAppConfigDeploymentScope,
        revision: u64,
    ) -> Result<Self> {
        let mut reference = Self::new(opaque_handle, revision)?;
        reference.scope_digest = scope.digest();
        reference.reference_digest = Digest::from_parts(
            "aws-appconfig-opaque-sigv4-reference/v1",
            &[
                ("kind", "sigv4_credential".to_owned()),
                ("reference", reference.reference_digest.as_str().to_owned()),
                ("scope", reference.scope_digest.as_str().to_owned()),
                ("revision", revision.to_string()),
            ],
        );
        Ok(reference)
    }

    pub fn for_scope(
        opaque_handle: impl Into<String>,
        scope: &AwsAppConfigDeploymentScope,
        revision: u64,
    ) -> Result<Self> {
        Self::sigv4(opaque_handle, scope, revision)
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

    pub(crate) fn validate(&self, scope: &AwsAppConfigDeploymentScope) -> Result<()> {
        if !matches!(self.kind, SecretKind::Sigv4Credential)
            || self.revision == 0
            || self.revoked
            || self.scope_digest != scope.digest()
        {
            return Err(AwsAppConfigDeploymentError::InvalidSecretReference);
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

    pub const fn is_connected(&self) -> bool {
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
            "aws-appconfig-permissions/v1",
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
            Err(AwsAppConfigDeploymentError::InvalidPermissionSnapshot)
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
            "aws-appconfig-consent/v1",
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
            Err(AwsAppConfigDeploymentError::InvalidConsent)
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
pub enum AppConfigDeploymentState {
    Baking,
    Validating,
    Deploying,
    Complete,
    RollingBack,
    RolledBack,
    Reverted,
    DeploymentError,
    RollbackError,
    Stopped,
}

impl AppConfigDeploymentState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Baking => "baking",
            Self::Validating => "validating",
            Self::Deploying => "deploying",
            Self::Complete => "complete",
            Self::RollingBack => "rolling_back",
            Self::RolledBack => "rolled_back",
            Self::Reverted => "reverted",
            Self::DeploymentError => "deployment_error",
            Self::RollbackError => "rollback_error",
            Self::Stopped => "stopped",
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Complete
                | Self::RolledBack
                | Self::Reverted
                | Self::DeploymentError
                | Self::RollbackError
                | Self::Stopped
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentEventClassification {
    Started,
    Progressed,
    Completed,
    RollingBack,
    RolledBack,
    Failed,
    Stopped,
    Provider,
    Unknown,
}

impl DeploymentEventClassification {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Progressed => "progressed",
            Self::Completed => "completed",
            Self::RollingBack => "rolling_back",
            Self::RolledBack => "rolled_back",
            Self::Failed => "failed",
            Self::Stopped => "stopped",
            Self::Provider => "provider",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentEvent {
    pub sequence: u32,
    pub classification: DeploymentEventClassification,
    pub occurred_at: DateTime<Utc>,
    pub event_digest: Digest,
}

impl DeploymentEvent {
    pub fn new(
        sequence: u32,
        classification: DeploymentEventClassification,
        occurred_at: DateTime<Utc>,
        detail: impl Into<String>,
    ) -> Result<Self> {
        let mut detail = detail.into();
        if sequence == 0 || !valid_text(&detail, MAX_IDENTIFIER_BYTES * 4, true) {
            detail.zeroize();
            return Err(AwsAppConfigDeploymentError::InvalidText {
                field: "event-detail",
            });
        }
        let event_digest = Digest::from_parts(
            "aws-appconfig-deployment-event/v1",
            &[
                ("sequence", sequence.to_string()),
                ("classification", classification.as_str().to_owned()),
                ("occurred_at", occurred_at.to_rfc3339()),
                ("detail", detail.clone()),
            ],
        );
        detail.zeroize();
        Ok(Self {
            sequence,
            classification,
            occurred_at,
            event_digest,
        })
    }

    pub fn from_detail(
        sequence: u32,
        classification: DeploymentEventClassification,
        occurred_at: DateTime<Utc>,
        detail: impl Into<String>,
    ) -> Result<Self> {
        Self::new(sequence, classification, occurred_at, detail)
    }

    pub fn validate(&self) -> Result<()> {
        if self.sequence == 0 || self.event_digest.validate().is_err() {
            return Err(AwsAppConfigDeploymentError::InvalidScope);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentStrategy {
    pub id: DeploymentStrategyId,
    pub name_digest: Option<Digest>,
}

impl DeploymentStrategy {
    pub fn new(id: DeploymentStrategyId, name: Option<String>) -> Result<Self> {
        id.validate()?;
        let name_digest = name.map(|mut value| {
            let digest = Digest::from_parts(
                "aws-appconfig-deployment-strategy-name/v1",
                &[("name", value.clone())],
            );
            value.zeroize();
            digest
        });
        Ok(Self { id, name_digest })
    }

    pub fn without_name(id: DeploymentStrategyId) -> Result<Self> {
        Self::new(id, None)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-appconfig-deployment-strategy-projection/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                (
                    "name",
                    self.name_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentMetadataInput {
    pub deployment: AppConfigDeploymentId,
    pub configuration_profile: AppConfigConfigurationProfileId,
    pub configuration_version: AppConfigConfigurationVersion,
    pub strategy: DeploymentStrategy,
    pub state: AppConfigDeploymentState,
    pub percentage_complete: f64,
    pub started_at: DateTime<Utc>,
    pub last_updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub events: Vec<DeploymentEvent>,
    pub events_truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentMetadata {
    pub application: AppConfigApplicationId,
    pub environment: AppConfigEnvironmentId,
    pub deployment: AppConfigDeploymentId,
    pub configuration_profile: AppConfigConfigurationProfileId,
    pub configuration_version: AppConfigConfigurationVersion,
    pub strategy: DeploymentStrategy,
    pub state: AppConfigDeploymentState,
    pub percentage_complete: f64,
    pub started_at: DateTime<Utc>,
    pub last_updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub events: Vec<DeploymentEvent>,
    pub events_truncated: bool,
    pub metadata_digest: Digest,
}

impl Eq for DeploymentMetadata {}

impl DeploymentMetadata {
    pub fn new(
        scope: &AwsAppConfigDeploymentScope,
        input: DeploymentMetadataInput,
    ) -> Result<Self> {
        let metadata = Self::from_input(scope, input);
        metadata.validate_against(scope)?;
        Ok(metadata)
    }

    pub fn new_list_item(
        scope: &AwsAppConfigDeploymentScope,
        input: DeploymentMetadataInput,
    ) -> Result<Self> {
        let metadata = Self::from_input(scope, input);
        metadata.validate_list_item_against(scope)?;
        Ok(metadata)
    }

    fn from_input(scope: &AwsAppConfigDeploymentScope, input: DeploymentMetadataInput) -> Self {
        let mut metadata = Self {
            application: scope.application.clone(),
            environment: scope.environment.clone(),
            deployment: input.deployment,
            configuration_profile: input.configuration_profile,
            configuration_version: input.configuration_version,
            strategy: input.strategy,
            state: input.state,
            percentage_complete: input.percentage_complete,
            started_at: input.started_at,
            last_updated_at: input.last_updated_at,
            completed_at: input.completed_at,
            events: input.events,
            events_truncated: input.events_truncated,
            metadata_digest: Digest::from_text("unsealed-aws-appconfig-deployment-metadata"),
        };
        metadata.metadata_digest = metadata.calculate_digest();
        metadata
    }

    pub fn digest(&self) -> Digest {
        self.metadata_digest.clone()
    }

    pub fn validate_list_item_against(&self, scope: &AwsAppConfigDeploymentScope) -> Result<()> {
        if self.application != scope.application || self.environment != scope.environment {
            return Err(AwsAppConfigDeploymentError::ScopeMismatch);
        }
        self.validate_common()?;
        if self.metadata_digest != self.calculate_digest() {
            return Err(AwsAppConfigDeploymentError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn validate_against(&self, scope: &AwsAppConfigDeploymentScope) -> Result<()> {
        self.validate_list_item_against(scope)?;
        if self.deployment != scope.deployment
            || self.configuration_profile != scope.configuration_profile
            || self.configuration_version != scope.configuration_version
        {
            return Err(AwsAppConfigDeploymentError::DeploymentReplaced);
        }
        Ok(())
    }

    pub const fn events_are_complete(&self) -> bool {
        !self.events_truncated
    }

    fn validate_common(&self) -> Result<()> {
        self.application.validate()?;
        self.environment.validate()?;
        self.deployment.validate()?;
        self.configuration_profile.validate()?;
        self.configuration_version.validate()?;
        self.strategy.id.validate()?;
        if !self.percentage_complete.is_finite()
            || !(0.0..=100.0).contains(&self.percentage_complete)
            || self.started_at > self.last_updated_at
            || self.events.len() > MAX_EVENTS
        {
            return Err(AwsAppConfigDeploymentError::InvalidScope);
        }
        if self.state == AppConfigDeploymentState::Complete
            && (self.percentage_complete - 100.0).abs() > f64::EPSILON
        {
            return Err(AwsAppConfigDeploymentError::InvalidScope);
        }
        if self.state.is_terminal() && self.completed_at.is_none() {
            return Err(AwsAppConfigDeploymentError::InvalidScope);
        }
        if let Some(completed_at) = self.completed_at
            && (completed_at < self.started_at || completed_at > self.last_updated_at)
        {
            return Err(AwsAppConfigDeploymentError::InvalidScope);
        }
        let mut previous_sequence = 0;
        let mut previous_time = self.started_at;
        for event in &self.events {
            event.validate()?;
            if event.sequence <= previous_sequence || event.occurred_at < previous_time {
                return Err(AwsAppConfigDeploymentError::InvalidScope);
            }
            previous_sequence = event.sequence;
            previous_time = event.occurred_at;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-appconfig-deployment-metadata/v1",
            &[
                ("application", self.application.digest().as_str().to_owned()),
                ("environment", self.environment.digest().as_str().to_owned()),
                ("deployment", self.deployment.digest().as_str().to_owned()),
                (
                    "configuration_profile",
                    self.configuration_profile.digest().as_str().to_owned(),
                ),
                (
                    "configuration_version",
                    self.configuration_version.digest().as_str().to_owned(),
                ),
                ("strategy", self.strategy.digest().as_str().to_owned()),
                ("state", self.state.as_str().to_owned()),
                ("percentage", format!("{:.6}", self.percentage_complete)),
                ("started_at", self.started_at.to_rfc3339()),
                ("last_updated_at", self.last_updated_at.to_rfc3339()),
                (
                    "completed_at",
                    self.completed_at
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                (
                    "events",
                    self.events
                        .iter()
                        .map(|event| event.event_digest.as_str())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("events_truncated", self.events_truncated.to_string()),
            ],
        )
    }

    pub fn projection(&self) -> DeploymentProjection {
        DeploymentProjection {
            application: self.application.clone(),
            environment: self.environment.clone(),
            deployment: self.deployment.clone(),
            configuration_profile: self.configuration_profile.clone(),
            configuration_version: self.configuration_version.clone(),
            strategy: self.strategy.clone(),
            state: self.state,
            percentage_complete: self.percentage_complete,
            started_at: self.started_at,
            last_updated_at: self.last_updated_at,
            completed_at: self.completed_at,
            event_digests: self
                .events
                .iter()
                .map(|event| event.event_digest.clone())
                .collect(),
            events_truncated: self.events_truncated,
            metadata_digest: self.metadata_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentProjection {
    pub application: AppConfigApplicationId,
    pub environment: AppConfigEnvironmentId,
    pub deployment: AppConfigDeploymentId,
    pub configuration_profile: AppConfigConfigurationProfileId,
    pub configuration_version: AppConfigConfigurationVersion,
    pub strategy: DeploymentStrategy,
    pub state: AppConfigDeploymentState,
    pub percentage_complete: f64,
    pub started_at: DateTime<Utc>,
    pub last_updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub event_digests: Vec<Digest>,
    pub events_truncated: bool,
    pub metadata_digest: Digest,
}

impl Eq for DeploymentProjection {}

impl DeploymentProjection {
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-appconfig-deployment-projection/v1",
            &[
                ("metadata", self.metadata_digest.as_str().to_owned()),
                ("state", self.state.as_str().to_owned()),
                ("percentage", format!("{:.6}", self.percentage_complete)),
                (
                    "events",
                    self.event_digests
                        .iter()
                        .map(|digest| digest.as_str())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("truncated", self.events_truncated.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentFilter {
    pub application_digest: Digest,
    pub environment_digest: Digest,
    pub max_results: u16,
}

impl DeploymentFilter {
    pub fn for_scope(scope: &AwsAppConfigDeploymentScope, max_results: u16) -> Result<Self> {
        let filter = Self {
            application_digest: scope.application.digest(),
            environment_digest: scope.environment.digest(),
            max_results,
        };
        filter.validate_against(scope)?;
        Ok(filter)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-appconfig-deployment-filter/v1",
            &[
                ("application", self.application_digest.as_str().to_owned()),
                ("environment", self.environment_digest.as_str().to_owned()),
                ("max_results", self.max_results.to_string()),
            ],
        )
    }

    pub fn validate_against(&self, scope: &AwsAppConfigDeploymentScope) -> Result<()> {
        if self.application_digest != scope.application.digest()
            || self.environment_digest != scope.environment.digest()
            || self.max_results == 0
            || self.max_results > MAX_PAGE_SIZE
        {
            return Err(AwsAppConfigDeploymentError::FilterMismatch);
        }
        Ok(())
    }
}

pub type AppConfigDeploymentFilter = DeploymentFilter;

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cursor {
    token_digest: Digest,
    scope_digest: Digest,
    filter_digest: Digest,
    page_number: u16,
}

impl Cursor {
    pub fn new(
        opaque_token: impl Into<String>,
        scope: &AwsAppConfigDeploymentScope,
        filter: &DeploymentFilter,
        page_number: u16,
    ) -> Result<Self> {
        let mut token = opaque_token.into();
        if !valid_text(&token, MAX_IDENTIFIER_BYTES * 4, true)
            || !(2..=MAX_PAGES).contains(&page_number)
        {
            token.zeroize();
            return Err(AwsAppConfigDeploymentError::InvalidRequest);
        }
        let cursor = Self {
            token_digest: Digest::from_text(&token),
            scope_digest: scope.digest(),
            filter_digest: filter.digest(),
            page_number,
        };
        token.zeroize();
        cursor.validate_against(scope, filter)?;
        Ok(cursor)
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn filter_digest(&self) -> &Digest {
        &self.filter_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn validate_against(
        &self,
        scope: &AwsAppConfigDeploymentScope,
        filter: &DeploymentFilter,
    ) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.filter_digest != filter.digest()
            || self.page_number < 2
            || self.page_number > MAX_PAGES
        {
            return Err(AwsAppConfigDeploymentError::CursorMismatch);
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

pub fn validate_response_bytes(response_bytes: u64) -> Result<()> {
    if response_bytes == 0 || response_bytes > MAX_RESPONSE_BYTES {
        Err(AwsAppConfigDeploymentError::PartialEvidence)
    } else {
        Ok(())
    }
}
