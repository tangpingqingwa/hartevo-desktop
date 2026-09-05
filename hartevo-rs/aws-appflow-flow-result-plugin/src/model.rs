use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{AwsAppFlowResultError, Result};
use crate::{
    MAX_COUNTER_VALUE, MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES,
};

pub const MAX_FLOW_NAME_BYTES: usize = 256;
pub const MAX_FLOW_ARN_BYTES: usize = 512;
pub const MAX_EXECUTION_ID_BYTES: usize = 256;
pub const MAX_DURATION_MS: u64 = 86_400_000 * 366;

/// Lowercase SHA-256 over length-prefixed fields. Raw provider values are
/// hashed at the projection boundary and are never used as evidence fields.
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

    pub fn from_serializable<T: Serialize + ?Sized>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("bounded AppFlow values serialize");
        Self::from_bytes(&bytes)
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
        let digest = Self(value.into());
        digest.validate()?;
        Ok(digest)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_valid(&self) -> bool {
        self.0.len() == 64
            && self
                .0
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.is_valid() {
            Ok(())
        } else {
            Err(AwsAppFlowResultError::InvalidDigest)
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

fn valid_text(value: &str, max_bytes: usize, internal_whitespace: bool) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && (internal_whitespace || !value.chars().any(char::is_whitespace))
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    valid_text(value, max_bytes, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_flow_name(value: &str) -> bool {
    valid_text(value, MAX_FLOW_NAME_BYTES, false)
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'!' | b'@' | b'#' | b'.' | b'-')
        })
}

fn valid_appflow_arn(value: &str) -> bool {
    valid_text(value, MAX_FLOW_ARN_BYTES, false) && value.starts_with("arn:aws:appflow:")
}

macro_rules! redacted_identifier {
    ($name:ident, $field:literal, $domain:literal, $validator:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(AwsAppFlowResultError::InvalidIdentifier)
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts($domain, &[("value", self.0.clone())])
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(AwsAppFlowResultError::InvalidIdentifier)
                }
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

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("digest", &self.digest())
                    .finish()
            }
        }

        const _: &str = $field;
    };
}

redacted_identifier!(
    AwsAccountId,
    "account",
    "aws-appflow-account/v1",
    |value: &str| { value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit()) }
);
redacted_identifier!(
    AwsRegion,
    "region",
    "aws-appflow-region/v1",
    |value: &str| { valid_identifier(value, 64) }
);
redacted_identifier!(FlowName, "flow", "aws-appflow-flow/v1", valid_flow_name);
redacted_identifier!(
    ExecutionId,
    "execution",
    "aws-appflow-execution/v1",
    |value: &str| { valid_identifier(value, MAX_EXECUTION_ID_BYTES) }
);
redacted_identifier!(
    ProjectId,
    "project",
    "aws-appflow-project/v1",
    |value: &str| { valid_identifier(value, MAX_IDENTIFIER_BYTES) }
);
redacted_identifier!(
    MissionId,
    "mission",
    "aws-appflow-mission/v1",
    |value: &str| { valid_identifier(value, MAX_IDENTIFIER_BYTES) }
);
redacted_identifier!(
    WorkProductId,
    "work-product",
    "aws-appflow-work-product/v1",
    |value: &str| { valid_identifier(value, MAX_IDENTIFIER_BYTES) }
);
redacted_identifier!(
    FlowArn,
    "flow-arn",
    "aws-appflow-flow-arn/v1",
    valid_appflow_arn
);

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerType {
    OnDemand,
    Scheduled,
    Event,
    Other(Digest),
}

impl TriggerType {
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let mut value = value.into();
        let normalized = value.to_ascii_lowercase();
        let result = match normalized.as_str() {
            "ondemand" | "on_demand" | "on-demand" => Self::OnDemand,
            "scheduled" => Self::Scheduled,
            "event" => Self::Event,
            _ if valid_text(&value, MAX_IDENTIFIER_BYTES, false) => Self::Other(
                Digest::from_parts("aws-appflow-trigger/v1", &[("value", value.clone())]),
            ),
            _ => {
                value.zeroize();
                return Err(AwsAppFlowResultError::InvalidIdentifier);
            }
        };
        value.zeroize();
        Ok(result)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowStatus {
    Active,
    Deprecated,
    Deleted,
    Draft,
    Errored,
    Suspended,
    Unknown,
}

impl FlowStatus {
    pub fn parse(value: impl AsRef<str>) -> Self {
        match value.as_ref().to_ascii_lowercase().as_str() {
            "active" => Self::Active,
            "deprecated" => Self::Deprecated,
            "deleted" => Self::Deleted,
            "draft" => Self::Draft,
            "errored" | "error" => Self::Errored,
            "suspended" => Self::Suspended,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Queued,
    InProgress,
    Successful,
    Error,
    Failed,
    Canceled,
    CancelStarted,
    CancelFailed,
    Unknown,
}

impl ExecutionStatus {
    pub fn parse(value: impl AsRef<str>) -> Self {
        match value.as_ref().to_ascii_lowercase().as_str() {
            "queued" => Self::Queued,
            "inprogress" | "in_progress" | "running" => Self::InProgress,
            "successful" | "success" | "completed" => Self::Successful,
            "error" => Self::Error,
            "failed" | "failure" => Self::Failed,
            "canceled" | "cancelled" => Self::Canceled,
            "cancelstarted" | "cancel_started" => Self::CancelStarted,
            "cancelfailed" | "cancel_failed" => Self::CancelFailed,
            _ => Self::Unknown,
        }
    }

    pub const fn evidence_state(self) -> ExecutionEvidenceState {
        match self {
            Self::Successful => ExecutionEvidenceState::Completed,
            Self::Queued | Self::InProgress | Self::CancelStarted => {
                ExecutionEvidenceState::InProgress
            }
            Self::Error | Self::Failed | Self::Canceled | Self::CancelFailed => {
                ExecutionEvidenceState::Failed
            }
            Self::Unknown => ExecutionEvidenceState::ProviderUnknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionEvidenceState {
    Completed,
    InProgress,
    Failed,
    Partial,
    NotFound,
    AccessLoss,
    Throttled,
    ProviderUnknown,
    Tamper,
    Replay,
}

impl ExecutionEvidenceState {
    pub const fn is_non_adoptable(self) -> bool {
        true
    }

    pub const fn is_review_eligible(self) -> bool {
        matches!(self, Self::Completed)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    None,
    Validation,
    Authentication,
    Authorization,
    NotFound,
    Conflict,
    RateLimited,
    Server,
    Timeout,
    Malformed,
    AccessLoss,
    BlockedEnv,
    Replay,
    Tamper,
    ProviderUnknown,
}

impl ErrorClass {
    pub fn from_message(value: impl AsRef<str>) -> Self {
        let value = value.as_ref().to_ascii_lowercase();
        if value.is_empty() {
            return Self::None;
        }
        if value.contains("unauthor") || value.contains("credential") {
            Self::Authentication
        } else if value.contains("forbidden") || value.contains("access") {
            Self::Authorization
        } else if value.contains("not found") || value.contains("missing") {
            Self::NotFound
        } else if value.contains("thrott") || value.contains("rate") {
            Self::RateLimited
        } else if value.contains("timeout") {
            Self::Timeout
        } else if value.contains("malformed") || value.contains("invalid") {
            Self::Malformed
        } else if value.contains("conflict") {
            Self::Conflict
        } else {
            Self::ProviderUnknown
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FailureProjection {
    pub class: ErrorClass,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoundedCounter {
    pub value: u64,
    pub truncated: bool,
}

impl BoundedCounter {
    pub const fn from_raw(value: u64) -> Self {
        if value > MAX_COUNTER_VALUE {
            Self {
                value: MAX_COUNTER_VALUE,
                truncated: true,
            }
        } else {
            Self {
                value,
                truncated: false,
            }
        }
    }

    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.value <= MAX_COUNTER_VALUE {
            Ok(())
        } else {
            Err(AwsAppFlowResultError::InvalidCounter)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TimingProjection {
    pub started_at_ms: Option<u64>,
    pub ended_at_ms: Option<u64>,
    pub duration_ms: Option<u64>,
}

impl TimingProjection {
    pub fn new(started_at_ms: Option<u64>, ended_at_ms: Option<u64>) -> Result<Self> {
        let duration_ms = match (started_at_ms, ended_at_ms) {
            (Some(start), Some(end)) if end >= start => {
                let duration = end - start;
                if duration > MAX_DURATION_MS {
                    return Err(AwsAppFlowResultError::InvalidTiming);
                }
                Some(duration)
            }
            (Some(_), Some(_)) => return Err(AwsAppFlowResultError::InvalidTiming),
            _ => None,
        };
        Ok(Self {
            started_at_ms,
            ended_at_ms,
            duration_ms,
        })
    }
}

#[derive(Clone, Debug)]
pub struct AppFlowScopeInput {
    pub account_id: String,
    pub region: String,
    pub flow_name: String,
    pub execution_id: String,
    pub source_connector: String,
    pub target_connector: String,
    pub trigger_type: String,
    pub flow_revision: u64,
    pub execution_revision: u64,
    pub project_id: String,
    pub project_revision: u64,
    pub mission_id: String,
    pub mission_revision: u64,
    pub work_product_id: String,
    pub work_product_revision: u64,
    pub consent_digest: Digest,
}

/// Exact AppFlow plus Project/Mission/Work Product scope. Only redacted
/// identifier wrappers and endpoint digests are retained by this type.
#[derive(Clone, Eq, PartialEq)]
pub struct AwsAppFlowScope {
    account: AwsAccountId,
    region: AwsRegion,
    flow: FlowName,
    execution: ExecutionId,
    source_digest: Digest,
    target_digest: Digest,
    trigger: TriggerType,
    flow_revision: u64,
    execution_revision: u64,
    project: ProjectId,
    project_revision: u64,
    mission: MissionId,
    mission_revision: u64,
    work_product: WorkProductId,
    work_product_revision: u64,
    consent_digest: Digest,
    scope_digest: Digest,
}

impl AwsAppFlowScope {
    pub fn new(mut input: AppFlowScopeInput) -> Result<Self> {
        let account = AwsAccountId::new(std::mem::take(&mut input.account_id))?;
        let region = AwsRegion::new(std::mem::take(&mut input.region))?;
        let flow = FlowName::new(std::mem::take(&mut input.flow_name))?;
        let execution = ExecutionId::new(std::mem::take(&mut input.execution_id))?;
        let source_digest = endpoint_digest("source", std::mem::take(&mut input.source_connector))?;
        let target_digest = endpoint_digest("target", std::mem::take(&mut input.target_connector))?;
        let trigger = TriggerType::parse(std::mem::take(&mut input.trigger_type))?;
        let project = ProjectId::new(std::mem::take(&mut input.project_id))?;
        let mission = MissionId::new(std::mem::take(&mut input.mission_id))?;
        let work_product = WorkProductId::new(std::mem::take(&mut input.work_product_id))?;
        if input.flow_revision == 0
            || input.execution_revision == 0
            || input.project_revision == 0
            || input.mission_revision == 0
            || input.work_product_revision == 0
        {
            return Err(AwsAppFlowResultError::InvalidScope);
        }
        input.consent_digest.validate()?;
        let mut scope = Self {
            account,
            region,
            flow,
            execution,
            source_digest,
            target_digest,
            trigger,
            flow_revision: input.flow_revision,
            execution_revision: input.execution_revision,
            project,
            project_revision: input.project_revision,
            mission,
            mission_revision: input.mission_revision,
            work_product,
            work_product_revision: input.work_product_revision,
            consent_digest: input.consent_digest,
            scope_digest: Digest::from_text("uninitialized-appflow-scope"),
        };
        scope.scope_digest = scope.compute_digest();
        scope.validate()?;
        Ok(scope)
    }

    pub fn digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    pub fn account(&self) -> &AwsAccountId {
        &self.account
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn flow(&self) -> &FlowName {
        &self.flow
    }

    pub fn execution(&self) -> &ExecutionId {
        &self.execution
    }

    pub fn account_digest(&self) -> Digest {
        self.account.digest()
    }

    pub fn region_digest(&self) -> Digest {
        self.region.digest()
    }

    pub fn flow_digest(&self) -> Digest {
        self.flow.digest()
    }

    pub fn execution_digest(&self) -> Digest {
        self.execution.digest()
    }

    pub fn source_digest(&self) -> &Digest {
        &self.source_digest
    }

    pub fn target_digest(&self) -> &Digest {
        &self.target_digest
    }

    pub fn trigger(&self) -> &TriggerType {
        &self.trigger
    }

    pub fn trigger_digest(&self) -> Digest {
        self.trigger.digest()
    }

    pub fn flow_revision(&self) -> u64 {
        self.flow_revision
    }

    pub fn execution_revision(&self) -> u64 {
        self.execution_revision
    }

    pub fn project(&self) -> &ProjectId {
        &self.project
    }

    pub fn project_revision(&self) -> u64 {
        self.project_revision
    }

    pub fn mission(&self) -> &MissionId {
        &self.mission
    }

    pub fn mission_revision(&self) -> u64 {
        self.mission_revision
    }

    pub fn work_product(&self) -> &WorkProductId {
        &self.work_product
    }

    pub fn work_product_revision(&self) -> u64 {
        self.work_product_revision
    }

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub fn validate(&self) -> Result<()> {
        self.account.validate()?;
        self.region.validate()?;
        self.flow.validate()?;
        self.execution.validate()?;
        self.project.validate()?;
        self.mission.validate()?;
        self.work_product.validate()?;
        self.source_digest.validate()?;
        self.target_digest.validate()?;
        self.consent_digest.validate()?;
        if self.flow_revision == 0
            || self.execution_revision == 0
            || self.project_revision == 0
            || self.mission_revision == 0
            || self.work_product_revision == 0
            || self.compute_digest() != self.scope_digest
        {
            return Err(AwsAppFlowResultError::InvalidScope);
        }
        Ok(())
    }

    pub(crate) fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-appflow-scope/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                ("flow", self.flow.digest().as_str().to_owned()),
                ("execution", self.execution.digest().as_str().to_owned()),
                ("source", self.source_digest.as_str().to_owned()),
                ("target", self.target_digest.as_str().to_owned()),
                ("trigger", self.trigger.digest().as_str().to_owned()),
                ("flow_revision", self.flow_revision.to_string()),
                ("execution_revision", self.execution_revision.to_string()),
                ("project", self.project.digest().as_str().to_owned()),
                ("project_revision", self.project_revision.to_string()),
                ("mission", self.mission.digest().as_str().to_owned()),
                ("mission_revision", self.mission_revision.to_string()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
                (
                    "work_product_revision",
                    self.work_product_revision.to_string(),
                ),
                ("consent", self.consent_digest.as_str().to_owned()),
            ],
        )
    }
}

impl Serialize for AwsAppFlowScope {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AwsAppFlowScope", 17)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("accountDigest", &self.account_digest())?;
        state.serialize_field("regionDigest", &self.region_digest())?;
        state.serialize_field("flowDigest", &self.flow_digest())?;
        state.serialize_field("executionDigest", &self.execution_digest())?;
        state.serialize_field("sourceDigest", &self.source_digest)?;
        state.serialize_field("targetDigest", &self.target_digest)?;
        state.serialize_field("triggerDigest", &self.trigger_digest())?;
        state.serialize_field("flowRevision", &self.flow_revision)?;
        state.serialize_field("executionRevision", &self.execution_revision)?;
        state.serialize_field("projectDigest", &self.project.digest())?;
        state.serialize_field("projectRevision", &self.project_revision)?;
        state.serialize_field("missionDigest", &self.mission.digest())?;
        state.serialize_field("missionRevision", &self.mission_revision)?;
        state.serialize_field("workProductDigest", &self.work_product.digest())?;
        state.serialize_field("workProductRevision", &self.work_product_revision)?;
        state.serialize_field("consentDigest", &self.consent_digest)?;
        state.end()
    }
}

impl fmt::Debug for AwsAppFlowScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsAppFlowScope")
            .field("scope_digest", &self.scope_digest)
            .field("account", &self.account)
            .field("region", &self.region)
            .field("flow", &self.flow)
            .field("execution", &self.execution)
            .field("source_digest", &self.source_digest)
            .field("target_digest", &self.target_digest)
            .field("trigger", &self.trigger)
            .field("flow_revision", &self.flow_revision)
            .field("execution_revision", &self.execution_revision)
            .field("project", &self.project)
            .field("mission", &self.mission)
            .field("work_product", &self.work_product)
            .finish()
    }
}

fn endpoint_digest(kind: &str, mut value: String) -> Result<Digest> {
    if !valid_text(&value, MAX_IDENTIFIER_BYTES, true) {
        value.zeroize();
        return Err(AwsAppFlowResultError::InvalidIdentifier);
    }
    let digest = Digest::from_parts(
        &format!("aws-appflow-{kind}-connector/v1"),
        &[("value", value.clone())],
    );
    value.zeroize();
    Ok(digest)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Sigv4Credential,
}

/// Opaque host-owned SigV4 reference. The supplied handle is hashed and
/// dropped; this type has no raw handle field and intentionally has no
/// `Serialize` implementation.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    scope_digest: Digest,
    revision: u64,
    revoked: bool,
}

impl SecretReference {
    pub fn sigv4(
        opaque_handle: impl Into<String>,
        scope: &AwsAppFlowScope,
        revision: u64,
    ) -> Result<Self> {
        scope.validate()?;
        let mut handle = opaque_handle.into();
        if !valid_text(&handle, MAX_IDENTIFIER_BYTES, true) || revision == 0 {
            handle.zeroize();
            return Err(AwsAppFlowResultError::InvalidSecretReference);
        }
        let handle_digest = Digest::from_parts(
            "aws-appflow-opaque-sigv4-reference/v1",
            &[
                ("kind", "sigv4_credential".to_owned()),
                ("handle", handle.clone()),
                ("revision", revision.to_string()),
            ],
        );
        handle.zeroize();
        let scope_digest = scope.digest();
        let reference_digest = Digest::from_parts(
            "aws-appflow-opaque-sigv4-reference-bound/v1",
            &[
                ("reference", handle_digest.as_str().to_owned()),
                ("scope", scope_digest.as_str().to_owned()),
                ("revision", revision.to_string()),
            ],
        );
        Ok(Self {
            kind: SecretKind::Sigv4Credential,
            reference_digest,
            scope_digest,
            revision,
            revoked: false,
        })
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

    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            return Err(AwsAppFlowResultError::SecretRevoked);
        }
        self.revoked = true;
        Ok(())
    }

    pub(crate) fn validate(&self, scope: &AwsAppFlowScope) -> Result<()> {
        if self.kind != SecretKind::Sigv4Credential
            || self.revision == 0
            || self.revoked
            || self.scope_digest != scope.digest()
        {
            return Err(AwsAppFlowResultError::InvalidSecretReference);
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
    pub const fn is_connected(&self) -> bool {
        false
    }

    pub const fn is_native(&self) -> bool {
        false
    }

    pub const fn is_first_party(&self) -> bool {
        false
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    pub revision: u64,
    pub permissions: BTreeSet<String>,
    pub digest: Digest,
}

impl PermissionSnapshot {
    pub fn for_layer_one(revision: u64) -> Self {
        let permissions = [
            "appflow:ListFlows",
            "appflow:DescribeFlow",
            "appflow:DescribeFlowExecutionRecords",
            "mission.scope",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
        let digest = Digest::from_serializable(&(revision, &permissions));
        Self {
            revision,
            permissions,
            digest,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.revision == 0 || *self != Self::for_layer_one(self.revision) {
            return Err(AwsAppFlowResultError::PermissionDrift);
        }
        self.digest.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    pub consent_digest: Digest,
    pub revision: u64,
    pub expires_at_ms: u64,
}

impl ConsentScope {
    pub fn new(consent_id: impl Into<String>, revision: u64, expires_at_ms: u64) -> Result<Self> {
        let mut consent_id = consent_id.into();
        if !valid_identifier(&consent_id, MAX_IDENTIFIER_BYTES)
            || revision == 0
            || expires_at_ms == 0
        {
            consent_id.zeroize();
            return Err(AwsAppFlowResultError::InvalidScope);
        }
        let consent_digest = Digest::from_parts(
            "aws-appflow-consent/v1",
            &[
                ("id", consent_id.clone()),
                ("revision", revision.to_string()),
                ("expires", expires_at_ms.to_string()),
            ],
        );
        consent_id.zeroize();
        Ok(Self {
            consent_digest,
            revision,
            expires_at_ms,
        })
    }

    pub fn for_layer_one(
        consent_id: impl Into<String>,
        revision: u64,
        expires_at_ms: u64,
    ) -> Result<Self> {
        Self::new(consent_id, revision, expires_at_ms)
    }

    pub fn digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub fn validate_at(&self, now_ms: u64) -> Result<()> {
        if self.revision == 0 || self.expires_at_ms <= now_ms {
            Err(AwsAppFlowResultError::InvalidScope)
        } else {
            self.consent_digest.validate()
        }
    }
}

fn require_scope(scope: &AwsAppFlowScope, scope_digest: &Digest) -> Result<()> {
    if &scope.digest() == scope_digest {
        Ok(())
    } else {
        Err(AwsAppFlowResultError::ScopeMismatch)
    }
}

#[derive(Clone, Debug)]
pub struct FlowDefinitionInput {
    pub flow_name: String,
    pub flow_arn: String,
    pub source_connector: String,
    pub target_connector: String,
    pub trigger_type: String,
    pub status: String,
    pub flow_revision: u64,
    pub updated_at_ms: Option<u64>,
    pub last_execution_status: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FlowListItemProjection {
    pub flow_digest: Digest,
    pub flow_arn_digest: Digest,
    pub source_digest: Digest,
    pub target_digest: Digest,
    pub trigger: TriggerType,
    pub status: FlowStatus,
    pub flow_revision: u64,
    pub updated_at_ms: Option<u64>,
    pub last_execution_status: Option<ExecutionStatus>,
}

impl FlowListItemProjection {
    pub fn from_input(scope: &AwsAppFlowScope, mut input: FlowDefinitionInput) -> Result<Self> {
        scope.validate()?;
        if input.flow_revision == 0 || input.flow_revision != scope.flow_revision() {
            return Err(AwsAppFlowResultError::RevisionMismatch);
        }
        let flow_name = std::mem::take(&mut input.flow_name);
        if flow_name != scope.flow().as_str() {
            return Err(AwsAppFlowResultError::ScopeMismatch);
        }
        let mut flow_arn = std::mem::take(&mut input.flow_arn);
        if !valid_appflow_arn(&flow_arn) {
            flow_arn.zeroize();
            return Err(AwsAppFlowResultError::InvalidIdentifier);
        }
        let flow_arn_digest =
            Digest::from_parts("aws-appflow-flow-arn/v1", &[("arn", flow_arn.clone())]);
        flow_arn.zeroize();
        let source_digest = endpoint_digest("source", std::mem::take(&mut input.source_connector))?;
        let target_digest = endpoint_digest("target", std::mem::take(&mut input.target_connector))?;
        if source_digest != *scope.source_digest() || target_digest != *scope.target_digest() {
            return Err(AwsAppFlowResultError::ScopeMismatch);
        }
        let trigger = TriggerType::parse(std::mem::take(&mut input.trigger_type))?;
        if trigger != *scope.trigger() {
            return Err(AwsAppFlowResultError::ScopeMismatch);
        }
        let last_execution_status = input
            .last_execution_status
            .as_deref()
            .map(ExecutionStatus::parse);
        Ok(Self {
            flow_digest: scope.flow_digest(),
            flow_arn_digest,
            source_digest,
            target_digest,
            trigger,
            status: FlowStatus::parse(&input.status),
            flow_revision: input.flow_revision,
            updated_at_ms: input.updated_at_ms,
            last_execution_status,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FlowDefinitionProjection {
    pub flow_digest: Digest,
    pub flow_arn_digest: Digest,
    pub source_digest: Digest,
    pub target_digest: Digest,
    pub trigger: TriggerType,
    pub status: FlowStatus,
    pub flow_revision: u64,
    pub updated_at_ms: Option<u64>,
}

impl FlowDefinitionProjection {
    pub fn from_input(scope: &AwsAppFlowScope, input: FlowDefinitionInput) -> Result<Self> {
        let item = FlowListItemProjection::from_input(scope, input)?;
        Ok(Self {
            flow_digest: item.flow_digest,
            flow_arn_digest: item.flow_arn_digest,
            source_digest: item.source_digest,
            target_digest: item.target_digest,
            trigger: item.trigger,
            status: item.status,
            flow_revision: item.flow_revision,
            updated_at_ms: item.updated_at_ms,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug)]
pub struct ExecutionRecordInput {
    pub execution_id: String,
    pub flow_name: String,
    pub source_connector: String,
    pub target_connector: String,
    pub trigger_type: String,
    pub status: String,
    pub started_at_ms: Option<u64>,
    pub ended_at_ms: Option<u64>,
    pub records_processed: u64,
    pub bytes_processed: u64,
    pub bytes_written: u64,
    pub put_failures: u64,
    pub error_message: Option<String>,
    pub flow_revision: u64,
    pub execution_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionRecordProjection {
    pub execution_digest: Digest,
    pub flow_digest: Digest,
    pub source_digest: Digest,
    pub target_digest: Digest,
    pub trigger: TriggerType,
    pub status: ExecutionStatus,
    pub timing: TimingProjection,
    pub records_processed: BoundedCounter,
    pub bytes_processed: BoundedCounter,
    pub bytes_written: BoundedCounter,
    pub put_failures: BoundedCounter,
    pub error_class: ErrorClass,
    pub flow_revision: u64,
    pub execution_revision: u64,
}

impl ExecutionRecordProjection {
    pub fn from_input(scope: &AwsAppFlowScope, mut input: ExecutionRecordInput) -> Result<Self> {
        scope.validate()?;
        if input.flow_revision != scope.flow_revision()
            || input.execution_revision != scope.execution_revision()
        {
            return Err(AwsAppFlowResultError::RevisionMismatch);
        }
        let execution_id = std::mem::take(&mut input.execution_id);
        if execution_id != scope.execution().as_str() {
            return Err(AwsAppFlowResultError::ScopeMismatch);
        }
        let flow_name = std::mem::take(&mut input.flow_name);
        if flow_name != scope.flow().as_str() {
            return Err(AwsAppFlowResultError::ScopeMismatch);
        }
        let source_digest = endpoint_digest("source", std::mem::take(&mut input.source_connector))?;
        let target_digest = endpoint_digest("target", std::mem::take(&mut input.target_connector))?;
        if source_digest != *scope.source_digest() || target_digest != *scope.target_digest() {
            return Err(AwsAppFlowResultError::ScopeMismatch);
        }
        let trigger = TriggerType::parse(std::mem::take(&mut input.trigger_type))?;
        if trigger != *scope.trigger() {
            return Err(AwsAppFlowResultError::ScopeMismatch);
        }
        let status = ExecutionStatus::parse(&input.status);
        let error_class = input
            .error_message
            .take()
            .map_or(ErrorClass::None, |mut raw| {
                let class = ErrorClass::from_message(&raw);
                raw.zeroize();
                class
            });
        let timing = TimingProjection::new(input.started_at_ms, input.ended_at_ms)?;
        Ok(Self {
            execution_digest: scope.execution_digest(),
            flow_digest: scope.flow_digest(),
            source_digest,
            target_digest,
            trigger,
            status,
            timing,
            records_processed: BoundedCounter::from_raw(input.records_processed),
            bytes_processed: BoundedCounter::from_raw(input.bytes_processed),
            bytes_written: BoundedCounter::from_raw(input.bytes_written),
            put_failures: BoundedCounter::from_raw(input.put_failures),
            error_class,
            flow_revision: input.flow_revision,
            execution_revision: input.execution_revision,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    pub fn counters_truncated(&self) -> bool {
        self.records_processed.is_truncated()
            || self.bytes_processed.is_truncated()
            || self.bytes_written.is_truncated()
            || self.put_failures.is_truncated()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum AppFlowOperation {
    ListFlows,
    DescribeFlow,
    DescribeFlowExecutionRecords,
}

impl AppFlowOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListFlows => "ListFlows",
            Self::DescribeFlow => "DescribeFlow",
            Self::DescribeFlowExecutionRecords => "DescribeFlowExecutionRecords",
        }
    }

    pub const fn permission(self) -> &'static str {
        match self {
            Self::ListFlows => "appflow:ListFlows",
            Self::DescribeFlow => "appflow:DescribeFlow",
            Self::DescribeFlowExecutionRecords => "appflow:DescribeFlowExecutionRecords",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct Cursor {
    token_digest: Digest,
    binding_digest: Digest,
    scope_digest: Digest,
    filter_digest: Digest,
    operation: AppFlowOperation,
    page: u16,
    flow_revision: u64,
    execution_revision: u64,
}

impl Cursor {
    pub fn new(
        opaque_token: impl Into<String>,
        scope: &AwsAppFlowScope,
        operation: AppFlowOperation,
        page: u16,
    ) -> Result<Self> {
        let filter_digest = match operation {
            AppFlowOperation::ListFlows => Digest::from_parts(
                "aws-appflow-list-flows-filter/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("page_size", MAX_PAGE_SIZE.to_string()),
                ],
            ),
            AppFlowOperation::DescribeFlow => Digest::from_parts(
                "aws-appflow-describe-flow-filter/v1",
                &[("flow", scope.flow_digest().as_str().to_owned())],
            ),
            AppFlowOperation::DescribeFlowExecutionRecords => Digest::from_parts(
                "aws-appflow-execution-record-filter/v1",
                &[
                    ("flow", scope.flow_digest().as_str().to_owned()),
                    ("execution", scope.execution_digest().as_str().to_owned()),
                    ("page_size", MAX_PAGE_SIZE.to_string()),
                ],
            ),
        };
        Self::from_token(
            opaque_token.into(),
            scope.digest(),
            filter_digest,
            operation,
            page,
            scope.flow_revision(),
            scope.execution_revision(),
        )
    }

    pub(crate) fn from_token(
        mut opaque_token: String,
        scope_digest: Digest,
        filter_digest: Digest,
        operation: AppFlowOperation,
        page: u16,
        flow_revision: u64,
        execution_revision: u64,
    ) -> Result<Self> {
        if !valid_text(&opaque_token, 2048, false)
            || page == 0
            || page > MAX_PAGES.saturating_add(1)
            || flow_revision == 0
            || execution_revision == 0
        {
            opaque_token.zeroize();
            return Err(AwsAppFlowResultError::PaginationLimit);
        }
        let token_digest = Digest::from_parts(
            "aws-appflow-opaque-cursor-token/v1",
            &[("token", opaque_token.clone())],
        );
        opaque_token.zeroize();
        let binding_digest = Digest::from_parts(
            "aws-appflow-cursor-binding/v1",
            &[
                ("token", token_digest.as_str().to_owned()),
                ("scope", scope_digest.as_str().to_owned()),
                ("filter", filter_digest.as_str().to_owned()),
                ("operation", operation.as_str().to_owned()),
                ("page", page.to_string()),
                ("flow_revision", flow_revision.to_string()),
                ("execution_revision", execution_revision.to_string()),
            ],
        );
        Ok(Self {
            token_digest,
            binding_digest,
            scope_digest,
            filter_digest,
            operation,
            page,
            flow_revision,
            execution_revision,
        })
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub fn page(&self) -> u16 {
        self.page
    }

    pub fn operation(&self) -> AppFlowOperation {
        self.operation
    }

    pub(crate) fn validate_for(
        &self,
        scope_digest: &Digest,
        filter_digest: &Digest,
        operation: AppFlowOperation,
        flow_revision: u64,
        execution_revision: u64,
    ) -> Result<()> {
        if &self.scope_digest != scope_digest
            || &self.filter_digest != filter_digest
            || self.operation != operation
            || self.flow_revision != flow_revision
            || self.execution_revision != execution_revision
            || self.page == 0
        {
            return Err(AwsAppFlowResultError::CursorMismatch);
        }
        Ok(())
    }
}

impl Serialize for Cursor {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("OpaqueCursor", 5)?;
        state.serialize_field("tokenDigest", &self.token_digest)?;
        state.serialize_field("bindingDigest", &self.binding_digest)?;
        state.serialize_field("operation", &self.operation)?;
        state.serialize_field("page", &self.page)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.end()
    }
}

impl fmt::Debug for Cursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest)
            .field("operation", &self.operation)
            .field("page", &self.page)
            .field("scope_digest", &self.scope_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListFlowsRequest {
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub max_page_size: u16,
    pub page: u16,
    pub flow_revision: u64,
    pub execution_revision: u64,
    pub cursor: Option<Cursor>,
}

impl ListFlowsRequest {
    pub fn new(
        scope: &AwsAppFlowScope,
        max_page_size: u16,
        cursor: Option<Cursor>,
    ) -> Result<Self> {
        bounded_page_size(max_page_size)?;
        let filter_digest = Digest::from_parts(
            "aws-appflow-list-flows-filter/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("page_size", max_page_size.to_string()),
            ],
        );
        let page = cursor.as_ref().map_or(1, Cursor::page);
        if let Some(cursor) = &cursor {
            cursor.validate_for(
                &scope.digest(),
                &filter_digest,
                AppFlowOperation::ListFlows,
                scope.flow_revision(),
                scope.execution_revision(),
            )?;
        }
        Ok(Self {
            scope_digest: scope.digest(),
            filter_digest,
            max_page_size,
            page,
            flow_revision: scope.flow_revision(),
            execution_revision: scope.execution_revision(),
            cursor,
        })
    }

    pub fn request_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/list-flows?maxResults={}&page={}&cursorDigest={}",
            self.max_page_size,
            self.page,
            self.cursor
                .as_ref()
                .map_or("none", |cursor| cursor.token_digest().as_str())
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DescribeFlowRequest {
    pub scope_digest: Digest,
    pub flow_digest: Digest,
    pub flow_revision: u64,
    pub execution_revision: u64,
}

impl DescribeFlowRequest {
    pub fn new(scope: &AwsAppFlowScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope_digest: scope.digest(),
            flow_digest: scope.flow_digest(),
            flow_revision: scope.flow_revision(),
            execution_revision: scope.execution_revision(),
        })
    }

    pub fn request_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/describe-flow?flowDigest={}&flowRevision={}",
            self.flow_digest.as_str(),
            self.flow_revision
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DescribeFlowExecutionRecordsRequest {
    pub scope_digest: Digest,
    pub flow_digest: Digest,
    pub execution_digest: Digest,
    pub filter_digest: Digest,
    pub max_page_size: u16,
    pub page: u16,
    pub flow_revision: u64,
    pub execution_revision: u64,
    pub cursor: Option<Cursor>,
}

impl DescribeFlowExecutionRecordsRequest {
    pub fn new(
        scope: &AwsAppFlowScope,
        max_page_size: u16,
        cursor: Option<Cursor>,
    ) -> Result<Self> {
        bounded_page_size(max_page_size)?;
        let filter_digest = Digest::from_parts(
            "aws-appflow-execution-record-filter/v1",
            &[
                ("flow", scope.flow_digest().as_str().to_owned()),
                ("execution", scope.execution_digest().as_str().to_owned()),
                ("page_size", max_page_size.to_string()),
            ],
        );
        let page = cursor.as_ref().map_or(1, Cursor::page);
        if let Some(cursor) = &cursor {
            cursor.validate_for(
                &scope.digest(),
                &filter_digest,
                AppFlowOperation::DescribeFlowExecutionRecords,
                scope.flow_revision(),
                scope.execution_revision(),
            )?;
        }
        Ok(Self {
            scope_digest: scope.digest(),
            flow_digest: scope.flow_digest(),
            execution_digest: scope.execution_digest(),
            filter_digest,
            max_page_size,
            page,
            flow_revision: scope.flow_revision(),
            execution_revision: scope.execution_revision(),
            cursor,
        })
    }

    pub fn request_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/describe-flow-execution-records?flowDigest={}&executionDigest={}&maxResults={}&page={}&cursorDigest={}",
            self.flow_digest.as_str(),
            self.execution_digest.as_str(),
            self.max_page_size,
            self.page,
            self.cursor
                .as_ref()
                .map_or("none", |cursor| cursor.token_digest().as_str())
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListFlowsResponse {
    pub items: Vec<FlowListItemProjection>,
    pub next_cursor: Option<Cursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub declared_digest: Digest,
}

impl ListFlowsResponse {
    pub fn new(
        request: &ListFlowsRequest,
        items: Vec<FlowListItemProjection>,
        next_token: Option<String>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_size(response_bytes)?;
        if items.len() > usize::from(request.max_page_size) {
            return Err(AwsAppFlowResultError::PaginationLimit);
        }
        let next_cursor = next_token
            .map(|token| {
                Cursor::from_token(
                    token,
                    request.scope_digest.clone(),
                    request.filter_digest.clone(),
                    AppFlowOperation::ListFlows,
                    request.page.saturating_add(1),
                    request.flow_revision,
                    request.execution_revision,
                )
            })
            .transpose()?;
        let declared_digest = Digest::from_serializable(&(
            request.request_digest(),
            &items,
            &next_cursor,
            response_bytes,
            &provenance,
        ));
        Ok(Self {
            items,
            next_cursor,
            response_bytes,
            provenance,
            declared_digest,
        })
    }

    pub fn validate_integrity(&self, request: &ListFlowsRequest) -> Result<()> {
        validate_response_size(self.response_bytes)?;
        let expected = Digest::from_serializable(&(
            request.request_digest(),
            &self.items,
            &self.next_cursor,
            self.response_bytes,
            &self.provenance,
        ));
        if expected != self.declared_digest {
            return Err(AwsAppFlowResultError::ResponseTampered);
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate_for(
                &request.scope_digest,
                &request.filter_digest,
                AppFlowOperation::ListFlows,
                request.flow_revision,
                request.execution_revision,
            )?;
        }
        Ok(())
    }

    #[must_use]
    pub fn with_declared_digest(mut self, declared_digest: Digest) -> Self {
        self.declared_digest = declared_digest;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DescribeFlowResponse {
    pub flow: FlowDefinitionProjection,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub declared_digest: Digest,
}

impl DescribeFlowResponse {
    pub fn new(
        request: &DescribeFlowRequest,
        flow: FlowDefinitionProjection,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_size(response_bytes)?;
        if flow.flow_digest != request.flow_digest || flow.flow_revision != request.flow_revision {
            return Err(AwsAppFlowResultError::ScopeMismatch);
        }
        let declared_digest = Digest::from_serializable(&(
            request.request_digest(),
            &flow,
            response_bytes,
            &provenance,
        ));
        Ok(Self {
            flow,
            response_bytes,
            provenance,
            declared_digest,
        })
    }

    pub fn validate_integrity(&self, request: &DescribeFlowRequest) -> Result<()> {
        validate_response_size(self.response_bytes)?;
        if self.flow.flow_digest != request.flow_digest
            || self.flow.flow_revision != request.flow_revision
        {
            return Err(AwsAppFlowResultError::ScopeMismatch);
        }
        let expected = Digest::from_serializable(&(
            request.request_digest(),
            &self.flow,
            self.response_bytes,
            &self.provenance,
        ));
        if expected != self.declared_digest {
            return Err(AwsAppFlowResultError::ResponseTampered);
        }
        Ok(())
    }

    #[must_use]
    pub fn with_declared_digest(mut self, declared_digest: Digest) -> Self {
        self.declared_digest = declared_digest;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DescribeFlowExecutionRecordsResponse {
    pub records: Vec<ExecutionRecordProjection>,
    pub next_cursor: Option<Cursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub declared_digest: Digest,
}

impl DescribeFlowExecutionRecordsResponse {
    pub fn new(
        request: &DescribeFlowExecutionRecordsRequest,
        records: Vec<ExecutionRecordProjection>,
        next_token: Option<String>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_size(response_bytes)?;
        if records.len() > usize::from(request.max_page_size) {
            return Err(AwsAppFlowResultError::PaginationLimit);
        }
        if records.iter().any(|record| {
            record.flow_digest != request.flow_digest
                || record.execution_digest != request.execution_digest
                || record.flow_revision != request.flow_revision
                || record.execution_revision != request.execution_revision
        }) {
            return Err(AwsAppFlowResultError::ScopeMismatch);
        }
        let next_cursor = next_token
            .map(|token| {
                Cursor::from_token(
                    token,
                    request.scope_digest.clone(),
                    request.filter_digest.clone(),
                    AppFlowOperation::DescribeFlowExecutionRecords,
                    request.page.saturating_add(1),
                    request.flow_revision,
                    request.execution_revision,
                )
            })
            .transpose()?;
        let declared_digest = Digest::from_serializable(&(
            request.request_digest(),
            &records,
            &next_cursor,
            response_bytes,
            &provenance,
        ));
        Ok(Self {
            records,
            next_cursor,
            response_bytes,
            provenance,
            declared_digest,
        })
    }

    pub fn validate_integrity(&self, request: &DescribeFlowExecutionRecordsRequest) -> Result<()> {
        validate_response_size(self.response_bytes)?;
        if self.records.iter().any(|record| {
            record.flow_digest != request.flow_digest
                || record.execution_digest != request.execution_digest
                || record.flow_revision != request.flow_revision
                || record.execution_revision != request.execution_revision
        }) {
            return Err(AwsAppFlowResultError::ScopeMismatch);
        }
        let expected = Digest::from_serializable(&(
            request.request_digest(),
            &self.records,
            &self.next_cursor,
            self.response_bytes,
            &self.provenance,
        ));
        if expected != self.declared_digest {
            return Err(AwsAppFlowResultError::ResponseTampered);
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate_for(
                &request.scope_digest,
                &request.filter_digest,
                AppFlowOperation::DescribeFlowExecutionRecords,
                request.flow_revision,
                request.execution_revision,
            )?;
        }
        Ok(())
    }

    #[must_use]
    pub fn with_declared_digest(mut self, declared_digest: Digest) -> Self {
        self.declared_digest = declared_digest;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub flow_digest: Digest,
    pub execution_digest: Digest,
    pub list_digest: Digest,
    pub describe_digest: Digest,
    pub records_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    pub fn compute_evidence_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.plugin_version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.permission_digest,
            &self.consent_digest,
            &self.scope_digest,
            &self.flow_digest,
            &self.execution_digest,
            &self.list_digest,
            &self.describe_digest,
            &self.records_digest,
            &self.cursor_digest,
        ))
    }

    pub fn validate(&self) -> Result<()> {
        for digest in [
            &self.plugin_version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.permission_digest,
            &self.consent_digest,
            &self.scope_digest,
            &self.flow_digest,
            &self.execution_digest,
            &self.list_digest,
            &self.describe_digest,
            &self.records_digest,
            &self.evidence_digest,
        ] {
            digest.validate()?;
        }
        if let Some(cursor) = &self.cursor_digest {
            cursor.validate()?;
        }
        if self.compute_evidence_digest() != self.evidence_digest {
            return Err(AwsAppFlowResultError::InvalidDigest);
        }
        Ok(())
    }
}

fn bounded_page_size(value: u16) -> Result<()> {
    if value == 0 || value > MAX_PAGE_SIZE {
        Err(AwsAppFlowResultError::PaginationLimit)
    } else {
        Ok(())
    }
}

fn validate_response_size(value: u64) -> Result<()> {
    if value > MAX_RESPONSE_BYTES {
        Err(AwsAppFlowResultError::ResponseTooLarge)
    } else {
        Ok(())
    }
}

#[allow(dead_code)]
fn require_scope_for_tests(scope: &AwsAppFlowScope, scope_digest: &Digest) -> Result<()> {
    require_scope(scope, scope_digest)
}
