use std::{
    collections::BTreeSet,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    CONSUMER_ID, CONTRACT_VERSION, PROVIDER_ID, PROVIDER_VERSION, SCHEMA_VERSION, SERVICE_ID,
};

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_URL_BYTES: usize = 2_048;
pub const MAX_OUTPUT_URLS: usize = 16;
pub const MAX_PAGE_TOKEN_BYTES: usize = 4_096;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_RUNTIME_METRIC_MILLIS: u64 = 86_400_000;
pub const MAX_RETRY_ATTEMPTS: u8 = 4;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("{0} is empty, malformed, or exceeds the safety bound")]
    InvalidIdentifier(&'static str),
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("the value is outside the bounded Layer-1 contract shape")]
    InvalidBound,
    #[error("the API host is not the official Replicate host")]
    InvalidApiHost,
    #[error("the output URL must be an HTTPS URL without embedded credentials")]
    InvalidOutputUrl,
    #[error("the scope is missing a required permission or exact binding")]
    InvalidScope,
    #[error("the prediction response is malformed or incomplete")]
    InvalidResponse,
    #[error("the page token is empty or exceeds the safety bound")]
    InvalidPageToken,
    #[error("the registration is invalid")]
    InvalidRegistration,
    #[error("the registration or secret reference is already revoked")]
    AlreadyRevoked,
    #[error("the computed digest does not match the supplied value")]
    DigestMismatch,
}

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

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if Self::is_valid_text(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_valid(&self) -> bool {
        Self::is_valid_text(&self.0)
    }

    pub(crate) fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field);
        }
        Self::from_bytes(&bytes)
    }

    fn is_valid_text(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

fn valid_identifier(value: &str, allow_slash: bool) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && !value.chars().any(char::is_control)
        && !value.chars().any(char::is_whitespace)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':')
                || (allow_slash && byte == b'/')
        })
        && !value.starts_with('.')
        && !value.ends_with('.')
}

macro_rules! identifier_type {
    ($name:ident, $label:literal, $allow_slash:expr) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if valid_identifier(&value, $allow_slash) {
                    Ok(Self(value))
                } else {
                    Err(ModelError::InvalidIdentifier($label))
                }
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
    };
}

identifier_type!(AccountId, "account id", false);
identifier_type!(ModelId, "model id", true);
identifier_type!(ModelVersion, "model version", false);
identifier_type!(DeploymentId, "deployment id", false);
identifier_type!(PredictionId, "prediction id", false);
identifier_type!(ProjectId, "Project id", false);
identifier_type!(MissionId, "Mission id", false);
identifier_type!(WorkProductId, "Work Product id", false);

pub type ReplicateAccountId = AccountId;
pub type ReplicateModelId = ModelId;
pub type ReplicatePredictionId = PredictionId;
pub type VersionOrDeployment = ModelTarget;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Timestamp(u64);

impl Timestamp {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn seconds(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginVersion {
    major: u16,
    minor: u16,
    patch: u16,
}

impl PluginVersion {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub const fn major(self) -> u16 {
        self.major
    }

    pub const fn minor(self) -> u16 {
        self.minor
    }

    pub const fn patch(self) -> u16 {
        self.patch
    }
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiHost(String);

impl ApiHost {
    pub const OFFICIAL: &'static str = "https://api.replicate.com";

    pub fn official() -> Self {
        Self(Self::OFFICIAL.to_owned())
    }

    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value == Self::OFFICIAL {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidApiHost)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum ModelTarget {
    Version {
        model_id: ModelId,
        version: ModelVersion,
    },
    Deployment {
        model_id: ModelId,
        deployment_id: DeploymentId,
    },
}

impl ModelTarget {
    pub fn version(model_id: ModelId, version: ModelVersion) -> Self {
        Self::Version { model_id, version }
    }

    pub fn deployment(model_id: ModelId, deployment_id: DeploymentId) -> Self {
        Self::Deployment {
            model_id,
            deployment_id,
        }
    }

    pub fn model_id(&self) -> &ModelId {
        match self {
            Self::Version { model_id, .. } | Self::Deployment { model_id, .. } => model_id,
        }
    }

    pub fn model_version(&self) -> Option<&ModelVersion> {
        match self {
            Self::Version { version, .. } => Some(version),
            Self::Deployment { .. } => None,
        }
    }

    pub fn deployment_id(&self) -> Option<&DeploymentId> {
        match self {
            Self::Version { .. } => None,
            Self::Deployment { deployment_id, .. } => Some(deployment_id),
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "replicate-version-or-deployment/v1",
            &[serde_json::to_string(self).expect("model target serializes")],
        )
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelBinding {
    target: ModelTarget,
    model_digest: Digest,
    version_or_deployment_digest: Digest,
}

impl ModelBinding {
    pub fn new(target: ModelTarget, model_digest: Digest) -> Result<Self, ModelError> {
        if !model_digest.is_valid() {
            return Err(ModelError::InvalidDigest);
        }
        let version_or_deployment_digest = target.digest();
        Ok(Self {
            target,
            model_digest,
            version_or_deployment_digest,
        })
    }

    pub fn target(&self) -> &ModelTarget {
        &self.target
    }

    pub fn model_id(&self) -> &ModelId {
        self.target.model_id()
    }

    pub fn model_digest(&self) -> &Digest {
        &self.model_digest
    }

    pub fn version_or_deployment_digest(&self) -> &Digest {
        &self.version_or_deployment_digest
    }

    pub fn binding_digest(&self) -> Digest {
        Digest::from_fields(
            "replicate-model-binding/v1",
            &[
                self.model_digest.as_str().to_owned(),
                self.version_or_deployment_digest.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderPredictionStatus {
    Starting,
    Processing,
    Succeeded,
    Failed,
    Canceled,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PredictionStatus {
    Starting,
    Processing,
    Succeeded,
    Failed,
    Canceled,
    DataRemoved,
    ProviderUnknown,
}

impl PredictionStatus {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Canceled | Self::DataRemoved
        )
    }

    pub fn can_follow(previous: Self, current: Self) -> bool {
        if matches!(previous, Self::ProviderUnknown)
            || matches!(current, Self::ProviderUnknown)
            || previous == current
        {
            return true;
        }
        if previous == Self::DataRemoved {
            return false;
        }
        if current == Self::DataRemoved {
            return previous.is_terminal();
        }
        match previous {
            Self::Starting => true,
            Self::Processing => current.is_terminal(),
            Self::Succeeded | Self::Failed | Self::Canceled => false,
            Self::DataRemoved | Self::ProviderUnknown => false,
        }
    }

    pub const fn from_provider(status: ProviderPredictionStatus, data_removed: bool) -> Self {
        if data_removed {
            return Self::DataRemoved;
        }
        match status {
            ProviderPredictionStatus::Starting => Self::Starting,
            ProviderPredictionStatus::Processing => Self::Processing,
            ProviderPredictionStatus::Succeeded => Self::Succeeded,
            ProviderPredictionStatus::Failed => Self::Failed,
            ProviderPredictionStatus::Canceled => Self::Canceled,
            ProviderPredictionStatus::Unknown => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum StatusExpectation {
    Any,
    Exact { status: PredictionStatus },
}

impl StatusExpectation {
    pub fn accepts(&self, status: PredictionStatus) -> bool {
        match self {
            Self::Any => true,
            Self::Exact { status: expected } => *expected == status,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricScope {
    metric_revision: Revision,
    max_predict_time_millis: Option<u64>,
    max_total_time_millis: Option<u64>,
    metric_digest: Digest,
}

impl MetricScope {
    pub fn new(
        metric_revision: Revision,
        max_predict_time_millis: Option<u64>,
        max_total_time_millis: Option<u64>,
    ) -> Result<Self, ModelError> {
        if max_predict_time_millis.is_some_and(|value| value > MAX_RUNTIME_METRIC_MILLIS)
            || max_total_time_millis.is_some_and(|value| value > MAX_RUNTIME_METRIC_MILLIS)
        {
            return Err(ModelError::InvalidBound);
        }
        let metric_digest = Digest::from_fields(
            "replicate-metric-scope/v1",
            &[
                metric_revision.get().to_string(),
                max_predict_time_millis.map_or_else(|| "none".to_owned(), |v| v.to_string()),
                max_total_time_millis.map_or_else(|| "none".to_owned(), |v| v.to_string()),
            ],
        );
        Ok(Self {
            metric_revision,
            max_predict_time_millis,
            max_total_time_millis,
            metric_digest,
        })
    }

    pub const fn metric_revision(&self) -> Revision {
        self.metric_revision
    }

    pub const fn max_predict_time_millis(&self) -> Option<u64> {
        self.max_predict_time_millis
    }

    pub const fn max_total_time_millis(&self) -> Option<u64> {
        self.max_total_time_millis
    }

    pub fn metric_digest(&self) -> &Digest {
        &self.metric_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputUrlExpiryScope {
    require_url_expiry: bool,
    expected_expires_at: Option<Timestamp>,
    max_ttl_seconds: u64,
    expected_content_digest: Option<Digest>,
    output_url_expiry_digest: Digest,
}

impl OutputUrlExpiryScope {
    pub fn new(
        require_url_expiry: bool,
        expected_expires_at: Option<Timestamp>,
        max_ttl_seconds: u64,
        expected_content_digest: Option<Digest>,
    ) -> Result<Self, ModelError> {
        if max_ttl_seconds > 86_400
            || expected_content_digest
                .as_ref()
                .is_some_and(|d| !d.is_valid())
        {
            return Err(ModelError::InvalidBound);
        }
        let output_url_expiry_digest = Digest::from_fields(
            "replicate-output-url-expiry/v1",
            &[
                require_url_expiry.to_string(),
                expected_expires_at.map_or_else(|| "none".to_owned(), |v| v.seconds().to_string()),
                max_ttl_seconds.to_string(),
                expected_content_digest
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |v| v.as_str().to_owned()),
            ],
        );
        Ok(Self {
            require_url_expiry,
            expected_expires_at,
            max_ttl_seconds,
            expected_content_digest,
            output_url_expiry_digest,
        })
    }

    pub const fn require_url_expiry(&self) -> bool {
        self.require_url_expiry
    }

    pub const fn expected_expires_at(&self) -> Option<Timestamp> {
        self.expected_expires_at
    }

    pub const fn max_ttl_seconds(&self) -> u64 {
        self.max_ttl_seconds
    }

    pub fn expected_content_digest(&self) -> Option<&Digest> {
        self.expected_content_digest.as_ref()
    }

    pub fn digest(&self) -> &Digest {
        &self.output_url_expiry_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PredictionScope {
    prediction_id: PredictionId,
    model: ModelBinding,
    expected_status: StatusExpectation,
    metric_scope: MetricScope,
    output_url_expiry: OutputUrlExpiryScope,
}

impl PredictionScope {
    pub fn new(
        prediction_id: PredictionId,
        model: ModelBinding,
        expected_status: StatusExpectation,
        metric_scope: MetricScope,
        output_url_expiry: OutputUrlExpiryScope,
    ) -> Self {
        Self {
            prediction_id,
            model,
            expected_status,
            metric_scope,
            output_url_expiry,
        }
    }

    pub fn prediction_id(&self) -> &PredictionId {
        &self.prediction_id
    }

    pub fn model(&self) -> &ModelBinding {
        &self.model
    }

    pub fn expected_status(&self) -> &StatusExpectation {
        &self.expected_status
    }

    pub fn metric_scope(&self) -> &MetricScope {
        &self.metric_scope
    }

    pub fn output_url_expiry(&self) -> &OutputUrlExpiryScope {
        &self.output_url_expiry
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "replicate-prediction-scope/v1",
            &[
                self.prediction_id.as_str().to_owned(),
                self.model.binding_digest().as_str().to_owned(),
                serde_json::to_string(&self.expected_status)
                    .expect("status expectation serializes"),
                self.metric_scope.metric_digest().as_str().to_owned(),
                self.output_url_expiry.digest().as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectScope {
    project_id: ProjectId,
    project_revision: Revision,
}

impl ProjectScope {
    pub fn new(project_id: ProjectId, project_revision: Revision) -> Self {
        Self {
            project_id,
            project_revision,
        }
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub const fn project_revision(&self) -> Revision {
        self.project_revision
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionScope {
    mission_id: MissionId,
    mission_revision: Revision,
}

impl MissionScope {
    pub fn new(mission_id: MissionId, mission_revision: Revision) -> Self {
        Self {
            mission_id,
            mission_revision,
        }
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub const fn mission_revision(&self) -> Revision {
        self.mission_revision
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductScope {
    work_product_id: WorkProductId,
    work_product_revision: Revision,
}

impl WorkProductScope {
    pub fn new(work_product_id: WorkProductId, work_product_revision: Revision) -> Self {
        Self {
            work_product_id,
            work_product_revision,
        }
    }

    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product_id
    }

    pub const fn work_product_revision(&self) -> Revision {
        self.work_product_revision
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionScope {
    permissions: BTreeSet<String>,
    permission_revision: Revision,
    permission_digest: Digest,
}

impl PermissionScope {
    pub fn new(
        permissions: impl IntoIterator<Item = String>,
        permission_revision: Revision,
    ) -> Result<Self, ModelError> {
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        if permissions.is_empty()
            || permissions
                .iter()
                .any(|permission| !valid_identifier(permission, true))
            || !permissions.contains("predictions.read")
        {
            return Err(ModelError::InvalidScope);
        }
        let permission_digest = Digest::from_fields(
            "replicate-permissions/v1",
            &[
                permissions.iter().cloned().collect::<Vec<_>>().join(","),
                permission_revision.get().to_string(),
            ],
        );
        Ok(Self {
            permissions,
            permission_revision,
            permission_digest,
        })
    }

    pub fn read_only_default(permission_revision: Revision) -> Result<Self, ModelError> {
        Self::new(
            [
                "predictions.read".to_owned(),
                "predictions.list_optional".to_owned(),
            ],
            permission_revision,
        )
    }

    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    pub const fn permission_revision(&self) -> Revision {
        self.permission_revision
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicateScope {
    api_host: ApiHost,
    account_id: AccountId,
    prediction: PredictionScope,
    project: ProjectScope,
    mission: MissionScope,
    work_product: WorkProductScope,
    permissions: PermissionScope,
    scope_revision: Revision,
    api_digest: Digest,
    revision_digest: Digest,
    scope_digest: Digest,
}

impl ReplicateScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        api_host: ApiHost,
        account_id: AccountId,
        prediction: PredictionScope,
        project: ProjectScope,
        mission: MissionScope,
        work_product: WorkProductScope,
        permissions: PermissionScope,
        scope_revision: Revision,
    ) -> Self {
        let api_digest = Digest::from_fields(
            "replicate-api/v1",
            &[
                api_host.as_str().to_owned(),
                "GET /v1/predictions/{prediction_id}".to_owned(),
                "GET /v1/predictions".to_owned(),
            ],
        );
        let revision_digest = Digest::from_fields(
            "replicate-revisions/v1",
            &[
                project.project_revision().get().to_string(),
                mission.mission_revision().get().to_string(),
                work_product.work_product_revision().get().to_string(),
                permissions.permission_revision().get().to_string(),
                scope_revision.get().to_string(),
            ],
        );
        let scope_digest = Digest::from_fields(
            "replicate-scope/v1",
            &[
                api_digest.as_str().to_owned(),
                account_id.as_str().to_owned(),
                prediction.digest().as_str().to_owned(),
                project.project_id().as_str().to_owned(),
                project.project_revision().get().to_string(),
                mission.mission_id().as_str().to_owned(),
                mission.mission_revision().get().to_string(),
                work_product.work_product_id().as_str().to_owned(),
                work_product.work_product_revision().get().to_string(),
                permissions.permission_digest().as_str().to_owned(),
                revision_digest.as_str().to_owned(),
                scope_revision.get().to_string(),
            ],
        );
        Self {
            api_host,
            account_id,
            prediction,
            project,
            mission,
            work_product,
            permissions,
            scope_revision,
            api_digest,
            revision_digest,
            scope_digest,
        }
    }

    pub fn api_host(&self) -> &ApiHost {
        &self.api_host
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn prediction(&self) -> &PredictionScope {
        &self.prediction
    }

    pub fn project(&self) -> &ProjectScope {
        &self.project
    }

    pub fn mission(&self) -> &MissionScope {
        &self.mission
    }

    pub fn work_product(&self) -> &WorkProductScope {
        &self.work_product
    }

    pub fn permissions(&self) -> &PermissionScope {
        &self.permissions
    }

    pub const fn scope_revision(&self) -> Revision {
        self.scope_revision
    }

    pub fn api_digest(&self) -> &Digest {
        &self.api_digest
    }

    pub fn model_digest(&self) -> &Digest {
        self.prediction.model().model_digest()
    }

    pub fn version_or_deployment_digest(&self) -> &Digest {
        self.prediction.model().version_or_deployment_digest()
    }

    pub fn permission_digest(&self) -> &Digest {
        self.permissions.permission_digest()
    }

    pub fn revision_digest(&self) -> &Digest {
        &self.revision_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn digest_set(&self, provider_digest: Digest) -> ReplicateDigestSet {
        ReplicateDigestSet {
            provider_digest,
            api_digest: self.api_digest.clone(),
            model_digest: self.model_digest().clone(),
            version_or_deployment_digest: self.version_or_deployment_digest().clone(),
            permission_digest: self.permission_digest().clone(),
            scope_digest: self.scope_digest.clone(),
            revision_digest: self.revision_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicateDigestSet {
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub model_digest: Digest,
    pub version_or_deployment_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretKind {
    ApiToken,
}

/// Opaque reference to a host-managed Replicate API token. The raw reference
/// id and token material never appear in this type's serialization or Debug
/// output; the type intentionally implements neither Serialize nor Deserialize.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    kind: SecretKind,
    revoked: Arc<AtomicBool>,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            kind: self.kind,
            revoked: Arc::clone(&self.revoked),
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
            .field("kind", &self.kind)
            .field("revoked", &self.is_revoked())
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.kind == other.kind
            && self.is_revoked() == other.is_revoked()
    }
}

impl Eq for SecretReference {}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &ReplicateScope,
        credential_revision: Revision,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_identifier(&reference_id, false) {
            return Err(ModelError::InvalidIdentifier("API-token secret reference"));
        }
        let reference_digest = Digest::from_fields(
            "replicate-api-token-secret-reference/v1",
            &[
                reference_id,
                scope.scope_digest().as_str().to_owned(),
                credential_revision.get().to_string(),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest: scope.scope_digest().clone(),
            credential_revision,
            kind: SecretKind::ApiToken,
            revoked: Arc::new(AtomicBool::new(false)),
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

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }

    pub fn revoke(&self) -> Result<(), ModelError> {
        self.revoked
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| ModelError::AlreadyRevoked)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

pub struct ReplicateProviderDefinition {
    pub provider_id: String,
    pub provider_version: PluginVersion,
    pub service_id: String,
    pub consumer_id: String,
    pub schema_version: String,
    pub contract_version: String,
    pub digests: ReplicateDigestSet,
    pub native: bool,
}

impl Clone for ReplicateProviderDefinition {
    fn clone(&self) -> Self {
        Self {
            provider_id: self.provider_id.clone(),
            provider_version: self.provider_version,
            service_id: self.service_id.clone(),
            consumer_id: self.consumer_id.clone(),
            schema_version: self.schema_version.clone(),
            contract_version: self.contract_version.clone(),
            digests: self.digests.clone(),
            native: self.native,
        }
    }
}

impl fmt::Debug for ReplicateProviderDefinition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplicateProviderDefinition")
            .field("provider_id", &self.provider_id)
            .field("provider_version", &self.provider_version)
            .field("service_id", &self.service_id)
            .field("consumer_id", &self.consumer_id)
            .field("schema_version", &self.schema_version)
            .field("contract_version", &self.contract_version)
            .field("digests", &self.digests)
            .field("native", &self.native)
            .finish()
    }
}

impl PartialEq for ReplicateProviderDefinition {
    fn eq(&self, other: &Self) -> bool {
        self.provider_id == other.provider_id
            && self.provider_version == other.provider_version
            && self.service_id == other.service_id
            && self.consumer_id == other.consumer_id
            && self.schema_version == other.schema_version
            && self.contract_version == other.contract_version
            && self.digests == other.digests
            && self.native == other.native
    }
}

impl Eq for ReplicateProviderDefinition {}

impl Serialize for ReplicateProviderDefinition {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Definition<'a> {
            provider_id: &'a str,
            provider_version: PluginVersion,
            service_id: &'a str,
            consumer_id: &'a str,
            schema_version: &'a str,
            contract_version: &'a str,
            digests: &'a ReplicateDigestSet,
            native: bool,
        }
        Definition {
            provider_id: &self.provider_id,
            provider_version: self.provider_version,
            service_id: &self.service_id,
            consumer_id: &self.consumer_id,
            schema_version: &self.schema_version,
            contract_version: &self.contract_version,
            digests: &self.digests,
            native: self.native,
        }
        .serialize(serializer)
    }
}

impl ReplicateProviderDefinition {
    pub fn for_scope(scope: &ReplicateScope) -> Self {
        let provider_digest = Digest::from_fields(
            "replicate-provider/v1",
            &[
                PROVIDER_ID.to_owned(),
                PROVIDER_VERSION.to_string(),
                ApiHost::OFFICIAL.to_owned(),
                "prediction-read-only".to_owned(),
            ],
        );
        Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: PROVIDER_VERSION,
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            schema_version: SCHEMA_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            digests: scope.digest_set(provider_digest),
            native: false,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "replicate-provider-definition/v1",
            &[
                self.provider_id.clone(),
                format!(
                    "{}.{}.{}",
                    self.provider_version.major(),
                    self.provider_version.minor(),
                    self.provider_version.patch()
                ),
                self.service_id.clone(),
                self.consumer_id.clone(),
                self.schema_version.clone(),
                self.contract_version.clone(),
                self.digests.provider_digest.as_str().to_owned(),
                self.digests.api_digest.as_str().to_owned(),
                self.digests.model_digest.as_str().to_owned(),
                self.digests
                    .version_or_deployment_digest
                    .as_str()
                    .to_owned(),
                self.digests.permission_digest.as_str().to_owned(),
                self.digests.scope_digest.as_str().to_owned(),
                self.digests.revision_digest.as_str().to_owned(),
                self.native.to_string(),
            ],
        )
    }

    pub fn digests(&self) -> &ReplicateDigestSet {
        &self.digests
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.digests.provider_digest
    }

    pub fn api_digest(&self) -> &Digest {
        &self.digests.api_digest
    }

    pub fn model_digest(&self) -> &Digest {
        &self.digests.model_digest
    }

    pub fn version_or_deployment_digest(&self) -> &Digest {
        &self.digests.version_or_deployment_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.digests.permission_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.digests.scope_digest
    }

    pub fn revision_digest(&self) -> &Digest {
        &self.digests.revision_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationReceipt {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub revocation_revision: Revision,
}

pub struct ReplicateRegistration {
    scope: ReplicateScope,
    provider_definition: ReplicateProviderDefinition,
    implementation_digest: Digest,
    secret_reference_digest: Digest,
    registration_revision: Revision,
    registration_digest: Digest,
    state: Arc<AtomicU8>,
}

impl Clone for ReplicateRegistration {
    fn clone(&self) -> Self {
        Self {
            scope: self.scope.clone(),
            provider_definition: self.provider_definition.clone(),
            implementation_digest: self.implementation_digest.clone(),
            secret_reference_digest: self.secret_reference_digest.clone(),
            registration_revision: self.registration_revision,
            registration_digest: self.registration_digest.clone(),
            state: Arc::clone(&self.state),
        }
    }
}

impl fmt::Debug for ReplicateRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplicateRegistration")
            .field("scope_digest", &self.scope.scope_digest())
            .field("provider_definition", &self.provider_definition)
            .field("implementation_digest", &self.implementation_digest)
            .field("secret_reference_digest", &self.secret_reference_digest)
            .field("registration_revision", &self.registration_revision)
            .field("registration_digest", &self.registration_digest)
            .field("state", &self.state())
            .finish()
    }
}

impl PartialEq for ReplicateRegistration {
    fn eq(&self, other: &Self) -> bool {
        self.scope == other.scope
            && self.provider_definition == other.provider_definition
            && self.implementation_digest == other.implementation_digest
            && self.secret_reference_digest == other.secret_reference_digest
            && self.registration_revision == other.registration_revision
            && self.registration_digest == other.registration_digest
            && self.state() == other.state()
    }
}

impl Eq for ReplicateRegistration {}

impl ReplicateRegistration {
    pub fn register(
        scope: ReplicateScope,
        secret: &SecretReference,
        implementation_digest: Digest,
    ) -> Result<Self, ModelError> {
        if secret.is_revoked() || secret.scope_digest() != scope.scope_digest() {
            return Err(ModelError::InvalidRegistration);
        }
        if !implementation_digest.is_valid() {
            return Err(ModelError::InvalidDigest);
        }
        let provider_definition = ReplicateProviderDefinition::for_scope(&scope);
        let registration_revision = scope.scope_revision();
        let registration_digest = Digest::from_fields(
            "replicate-registration/v1",
            &[
                provider_definition.digest().as_str().to_owned(),
                implementation_digest.as_str().to_owned(),
                secret.reference_digest().as_str().to_owned(),
                scope.scope_digest().as_str().to_owned(),
                registration_revision.get().to_string(),
            ],
        );
        Ok(Self {
            scope,
            provider_definition,
            implementation_digest,
            secret_reference_digest: secret.reference_digest().clone(),
            registration_revision,
            registration_digest,
            state: Arc::new(AtomicU8::new(0)),
        })
    }

    pub fn scope(&self) -> &ReplicateScope {
        &self.scope
    }

    pub fn provider_definition(&self) -> &ReplicateProviderDefinition {
        &self.provider_definition
    }

    pub fn implementation_digest(&self) -> &Digest {
        &self.implementation_digest
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        &self.secret_reference_digest
    }

    pub const fn registration_revision(&self) -> Revision {
        self.registration_revision
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn state(&self) -> RegistrationState {
        if self.state.load(Ordering::Acquire) == 0 {
            RegistrationState::Active
        } else {
            RegistrationState::Revoked
        }
    }

    pub fn is_active(&self) -> bool {
        self.state() == RegistrationState::Active
    }

    pub fn ensure_active(&self) -> Result<(), ModelError> {
        if self.is_active() {
            Ok(())
        } else {
            Err(ModelError::AlreadyRevoked)
        }
    }

    pub fn verify_digest(&self) -> bool {
        let expected = Digest::from_fields(
            "replicate-registration/v1",
            &[
                self.provider_definition.digest().as_str().to_owned(),
                self.implementation_digest.as_str().to_owned(),
                self.secret_reference_digest.as_str().to_owned(),
                self.scope.scope_digest().as_str().to_owned(),
                self.registration_revision.get().to_string(),
            ],
        );
        expected == self.registration_digest
    }

    pub fn revoke(&self) -> Result<RevocationReceipt, ModelError> {
        self.state
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ModelError::AlreadyRevoked)?;
        Ok(RevocationReceipt {
            registration_digest: self.registration_digest.clone(),
            scope_digest: self.scope.scope_digest().clone(),
            revocation_revision: self.registration_revision,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeMetrics {
    pub predict_time_millis: Option<u64>,
    pub total_time_millis: Option<u64>,
    pub metric_digest: Digest,
}

impl RuntimeMetrics {
    pub fn new(
        predict_time_millis: Option<u64>,
        total_time_millis: Option<u64>,
    ) -> Result<Self, ModelError> {
        if predict_time_millis.is_some_and(|v| v > MAX_RUNTIME_METRIC_MILLIS)
            || total_time_millis.is_some_and(|v| v > MAX_RUNTIME_METRIC_MILLIS)
        {
            return Err(ModelError::InvalidBound);
        }
        let metric_digest = Digest::from_fields(
            "replicate-runtime-metrics/v1",
            &[
                predict_time_millis.map_or_else(|| "none".to_owned(), |v| v.to_string()),
                total_time_millis.map_or_else(|| "none".to_owned(), |v| v.to_string()),
            ],
        );
        Ok(Self {
            predict_time_millis,
            total_time_millis,
            metric_digest,
        })
    }

    pub fn empty() -> Self {
        Self::new(None, None).expect("empty runtime metrics are valid")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputUrlEvidence {
    pub url_digest: Digest,
    pub expires_at: Option<Timestamp>,
    pub expired: bool,
}

impl OutputUrlEvidence {
    pub fn from_url(
        url: impl AsRef<str>,
        expires_at: Option<Timestamp>,
        observed_at: Timestamp,
    ) -> Result<Self, ModelError> {
        let url = url.as_ref();
        if url.len() > MAX_URL_BYTES
            || !url.starts_with("https://")
            || url.contains('@')
            || url.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidOutputUrl);
        }
        Ok(Self {
            url_digest: Digest::from_text(url),
            expires_at,
            expired: expires_at.is_some_and(|expiry| expiry.seconds() <= observed_at.seconds()),
        })
    }

    pub fn from_digest(
        url_digest: Digest,
        expires_at: Option<Timestamp>,
        expired: bool,
    ) -> Result<Self, ModelError> {
        if !url_digest.is_valid() {
            return Err(ModelError::InvalidDigest);
        }
        Ok(Self {
            url_digest,
            expires_at,
            expired,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputEvidence {
    pub content_digest: Option<Digest>,
    pub urls: Vec<OutputUrlEvidence>,
    pub data_removed: bool,
    pub url_expired: bool,
    pub output_digest: Digest,
}

impl OutputEvidence {
    pub fn new(
        content_digest: Option<Digest>,
        urls: Vec<OutputUrlEvidence>,
        data_removed: bool,
    ) -> Result<Self, ModelError> {
        if urls.len() > MAX_OUTPUT_URLS
            || content_digest
                .as_ref()
                .is_some_and(|digest| !digest.is_valid())
        {
            return Err(ModelError::InvalidBound);
        }
        let url_expired = urls.iter().any(|url| url.expired);
        let output_digest = Digest::from_fields(
            "replicate-output-evidence/v1",
            &[
                content_digest
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned()),
                urls.iter()
                    .map(|url| {
                        format!(
                            "{}:{}:{}",
                            url.url_digest,
                            url.expires_at.map_or_else(
                                || "none".to_owned(),
                                |value| value.seconds().to_string()
                            ),
                            url.expired
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(","),
                data_removed.to_string(),
                url_expired.to_string(),
            ],
        );
        Ok(Self {
            content_digest,
            urls,
            data_removed,
            url_expired,
            output_digest,
        })
    }

    pub fn empty(data_removed: bool) -> Self {
        Self::new(None, Vec::new(), data_removed).expect("empty output evidence is valid")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionState {
    None,
    Redacted,
    Truncated,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderErrorEvidence {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retry_after_millis: Option<u64>,
    pub message: String,
    pub message_digest: Digest,
    pub redaction: RedactionState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    Timeout,
    ServerError,
    Malformed,
    Partial,
    BlockedEnv,
    AccountDrift,
    PredictionDrift,
    ModelDrift,
    VersionOrDeploymentDrift,
    StatusDrift,
    MetricDrift,
    OutputUrlExpiryMismatch,
    OutputContentDigestMismatch,
    PermissionDrift,
    ScopeDrift,
    RevisionDrift,
    ReplayDetected,
    TamperedEvidence,
    Revoked,
    ProviderUnknown,
}

impl ProviderErrorEvidence {
    pub fn redacted(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        retry_after_millis: Option<u64>,
        untrusted_message: impl AsRef<str>,
    ) -> Self {
        let untrusted_message = untrusted_message.as_ref();
        Self {
            kind,
            status_code,
            retry_after_millis,
            message: "REDACTED_PROVIDER_ERROR".to_owned(),
            message_digest: Digest::from_text(untrusted_message),
            redaction: RedactionState::Redacted,
        }
    }

    pub(crate) fn from_digest(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        retry_after_millis: Option<u64>,
        message_digest: Digest,
    ) -> Self {
        Self {
            kind,
            status_code,
            retry_after_millis,
            message: "REDACTED_PROVIDER_ERROR".to_owned(),
            message_digest,
            redaction: RedactionState::Redacted,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetryEvidence {
    pub operation: String,
    pub attempt: u8,
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub backoff_millis: u64,
    pub error_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicatePredictionRecord {
    pub account_id: AccountId,
    pub prediction_id: PredictionId,
    pub model: ModelBinding,
    pub provider_status: ProviderPredictionStatus,
    pub metrics: RuntimeMetrics,
    pub output: OutputEvidence,
    pub observed_at: Timestamp,
    pub partial: bool,
    pub response_digest: Digest,
}

impl ReplicatePredictionRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AccountId,
        prediction_id: PredictionId,
        model: ModelBinding,
        provider_status: ProviderPredictionStatus,
        metrics: RuntimeMetrics,
        output: OutputEvidence,
        observed_at: Timestamp,
        partial: bool,
    ) -> Self {
        let response_digest = Self::calculate_digest(
            &account_id,
            &prediction_id,
            &model,
            provider_status,
            &metrics,
            &output,
            observed_at,
            partial,
        );
        Self {
            account_id,
            prediction_id,
            model,
            provider_status,
            metrics,
            output,
            observed_at,
            partial,
            response_digest,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn calculate_digest(
        account_id: &AccountId,
        prediction_id: &PredictionId,
        model: &ModelBinding,
        provider_status: ProviderPredictionStatus,
        metrics: &RuntimeMetrics,
        output: &OutputEvidence,
        observed_at: Timestamp,
        partial: bool,
    ) -> Digest {
        Digest::from_fields(
            "replicate-prediction-response/v1",
            &[
                account_id.as_str().to_owned(),
                prediction_id.as_str().to_owned(),
                model.binding_digest().as_str().to_owned(),
                format!("{provider_status:?}"),
                metrics.metric_digest.as_str().to_owned(),
                output.output_digest.as_str().to_owned(),
                observed_at.seconds().to_string(),
                partial.to_string(),
            ],
        )
    }

    pub fn verify_digest(&self) -> bool {
        Self::calculate_digest(
            &self.account_id,
            &self.prediction_id,
            &self.model,
            self.provider_status,
            &self.metrics,
            &self.output,
            self.observed_at,
            self.partial,
        ) == self.response_digest
    }

    pub fn status(&self) -> PredictionStatus {
        PredictionStatus::from_provider(self.provider_status, self.output.data_removed)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaquePageToken {
    raw: String,
}

impl OpaquePageToken {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let raw = value.into();
        if raw.is_empty() || raw.len() > MAX_PAGE_TOKEN_BYTES || raw.chars().any(char::is_control) {
            return Err(ModelError::InvalidPageToken);
        }
        Ok(Self { raw })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(&self.raw)
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

impl Serialize for OpaquePageToken {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.digest().as_str())
    }
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("digest", &self.digest())
            .finish()
    }
}
