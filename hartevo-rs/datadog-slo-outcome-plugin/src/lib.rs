//! Layer 1 Datadog SLO outcome-evidence plugin.
//!
//! The crate is a standalone, Rust-owned seam for bounded SLO definition,
//! history, status, monitor-transition, correction, and downtime evidence.
//! It deliberately stops at read/proposal/recording.  The only transports in
//! this crate are recording, fake, fixture, loopback, and `BLOCKED_ENV`
//! transports; none can claim Connected or native evidence.

#![forbid(unsafe_code)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::if_not_else)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::use_self)]

use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
    sync::{Arc, Mutex},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const DATADOG_SLO_OUTCOME_SCHEMA_VERSION: &str = "hartevo.datadog-slo-outcome/v1";
pub const DATADOG_SLO_OUTCOME_CONTRACT_PATH: &str =
    "contracts/plugins/datadog-slo-outcome/datadog-slo-outcome.v1.json";
pub const DATADOG_SLO_OUTCOME_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/datadog-slo-outcome/datadog-slo-outcome.v1.json");

pub const SLO_OUTCOME_EVIDENCE_SERVICE_ID: &str = "datadog.slo-outcome-evidence.read";
pub const DATADOG_SLO_OUTCOME_SERVICE_ID: &str = SLO_OUTCOME_EVIDENCE_SERVICE_ID;
pub const DATADOG_SLO_PROVIDER_ID: &str = "datadog.slo.outcome";
pub const MISSION_SLO_OUTCOME_CONSUMER_ID: &str = "mission.slo-outcome-evidence.consumer";
pub const DATADOG_SLO_PROVIDER_IMPLEMENTATION: &str = "DatadogSloProvider";
pub const DATADOG_SLO_STATUS_API_VERSION: &str = "v2_public_beta";

pub const MAX_OBSERVATION_WINDOW_SECONDS: i64 = 7_776_000;
pub const MAX_HISTORY_POINTS: usize = 10_000;
pub const MAX_MONITORS: usize = 100;
pub const MAX_GROUPS: usize = 100;
pub const MAX_TRANSITIONS: usize = 10_000;
pub const MAX_CORRECTIONS: usize = 100;
pub const MAX_DOWNTIMES: usize = 100;
pub const MAX_ERRORS: usize = 100;
pub const MAX_ALLOWLISTED_TAGS: usize = 32;
pub const MAX_IDENTIFIER_BYTES: usize = 256;

pub type Digest = String;

/// Return a lowercase SHA-256 digest.
#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    format!("{:x}", Sha256::digest(bytes))
}

/// Hash a serde value in its canonical declared field order.
#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("typed Datadog value serializes");
    sha256_digest(&bytes)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_digest(value: &str, label: &'static str) -> Result<(), DatadogSloError> {
    if !is_sha256(value) {
        return Err(DatadogSloError::InvalidDigest { label });
    }
    Ok(())
}

fn validate_identifier(value: &str, label: &'static str) -> Result<(), DatadogSloError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:@/+~-".contains(&byte))
    {
        return Err(DatadogSloError::InvalidIdentifier { label });
    }
    Ok(())
}

fn validate_host(value: &str) -> Result<String, DatadogSloError> {
    let remainder = value
        .strip_prefix("https://")
        .ok_or(DatadogSloError::InvalidSiteHost)?;
    if remainder.is_empty()
        || remainder.contains('/')
        || remainder.contains('?')
        || remainder.contains('#')
        || remainder.contains(':')
        || remainder.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(DatadogSloError::InvalidSiteHost);
    }
    let host = remainder.to_ascii_lowercase();
    if !host.contains('.')
        || host.starts_with('.')
        || host.ends_with('.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(DatadogSloError::InvalidSiteHost);
    }
    Ok(format!("https://{host}"))
}

fn validate_finite_percentage(value: f64, label: &'static str) -> Result<(), DatadogSloError> {
    if !value.is_finite() || !(0.0..=100.0).contains(&value) {
        return Err(DatadogSloError::InvalidPercentage { label });
    }
    Ok(())
}

fn validate_optional_percentage(
    value: Option<f64>,
    label: &'static str,
) -> Result<(), DatadogSloError> {
    if let Some(value) = value {
        validate_finite_percentage(value, label)?;
    }
    Ok(())
}

fn same_percentage(left: f64, right: f64) -> bool {
    left.to_bits() == right.to_bits()
}

fn same_optional_percentage(left: Option<f64>, right: Option<f64>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => same_percentage(left, right),
        (None, None) => true,
        _ => false,
    }
}

fn validate_bounded_list<T>(
    values: &[T],
    maximum: usize,
    label: &'static str,
) -> Result<(), DatadogSloError> {
    if values.len() > maximum {
        return Err(DatadogSloError::BoundExceeded { label, maximum });
    }
    Ok(())
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DatadogSloError {
    #[error("{label} is empty, invalid, or too long")]
    InvalidIdentifier { label: &'static str },
    #[error("{label} is not a lowercase SHA-256 digest")]
    InvalidDigest { label: &'static str },
    #[error("the Datadog API host must be a valid HTTPS origin")]
    InvalidSiteHost,
    #[error("the observation window must be closed, positive, and bounded")]
    InvalidObservationWindow,
    #[error("the Datadog SLO scope is invalid")]
    InvalidScope,
    #[error("the Datadog permission snapshot is invalid or over-privileged")]
    InvalidPermissionSnapshot,
    #[error("the SLO definition is invalid")]
    InvalidDefinition,
    #[error("the SLO target, warning, or error-budget percentage is invalid ({label})")]
    InvalidPercentage { label: &'static str },
    #[error("the SLO query form is invalid")]
    InvalidQueryForm,
    #[error("the bounded evidence list {label} exceeded {maximum} items")]
    BoundExceeded { label: &'static str, maximum: usize },
    #[error("the monitor tag key is not allowlisted")]
    UnallowlistedMonitorTag,
    #[error("the monitor detail is invalid")]
    InvalidMonitorDetail,
    #[error("a version, contract digest, or scope-bound registration is required")]
    RegistrationRequired,
    #[error("the registration has been revoked")]
    RegistrationRevoked,
    #[error("the registration does not match the current definition or exact scope")]
    RegistrationMismatch,
    #[error("the observation proposal does not match the registered scope")]
    ProposalBindingMismatch,
    #[error("the bounded read request failed its tamper check")]
    RequestTampered,
    #[error("the returned site does not match the registered site or API host")]
    SiteMismatch,
    #[error("the returned organization does not match the registered organization")]
    OrganizationMismatch,
    #[error("the returned SLO does not match the exact registered SLO")]
    SloMismatch,
    #[error("the returned SLO type does not match the typed query form")]
    SloTypeMismatch,
    #[error("the returned SLO definition fingerprint does not match")]
    DefinitionMismatch,
    #[error("the returned SLO query fingerprint does not match")]
    QueryMismatch,
    #[error("the returned observation window is not the exact closed proposal window")]
    WindowMismatch,
    #[error("the deployment, release, Mission, or project fence does not match")]
    IdentityBindingMismatch,
    #[error("the SLO target does not match the proposal")]
    TargetMismatch,
    #[error("the SLO warning threshold does not match the proposal")]
    WarningMismatch,
    #[error("the SLO error-budget timeframe or target does not match the proposal")]
    ErrorBudgetMismatch,
    #[error("the monitor or group scope does not match the registered SLO")]
    MonitorScopeMismatch,
    #[error("the Datadog public-beta status API version drifted")]
    PublicBetaStatusDrift,
    #[error("the Datadog response fingerprint failed its tamper check")]
    ResponseTampered,
    #[error("the observation receipt failed its tamper check")]
    ReceiptTampered,
    #[error("the Mission Outcome consumer binding is invalid")]
    ConsumerBindingMismatch,
    #[error("fixture, recording, fake, loopback, or BLOCKED_ENV evidence cannot be native")]
    NativeClassificationMismatch,
    #[error("Datadog transport failed: {0}")]
    Transport(#[from] DatadogTransportError),
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DatadogTransportError {
    #[error("BLOCKED_ENV: native Datadog credentials or HTTPS host are unavailable")]
    BlockedEnv,
    #[error("Datadog returned HTTP 401")]
    Unauthorized401,
    #[error("Datadog returned HTTP 403")]
    Forbidden403,
    #[error("Datadog returned HTTP 404")]
    NotFound404,
    #[error("Datadog returned HTTP 429")]
    RateLimited429 { retry_after_seconds: Option<u64> },
    #[error("Datadog request timed out")]
    Timeout,
    #[error("Datadog returned HTTP {status}")]
    Server5xx { status: u16 },
    #[error("Datadog response site or API host did not match the exact scope")]
    SiteMismatch,
    #[error("Datadog public-beta response schema or version drifted")]
    PublicBetaDrift,
    #[error("Datadog response was invalid or exceeded the bounded response contract")]
    InvalidResponse,
    #[error("Datadog response fingerprint was tampered")]
    ResponseTampered,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl PluginVersion {
    pub const V1: Self = Self {
        major: 1,
        minor: 0,
        patch: 0,
    };
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    ReadOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    OAuth,
    ApplicationKey,
}

impl SecretKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::OAuth => "oauth",
            Self::ApplicationKey => "application_key",
        }
    }
}

/// An opaque host-owned reference to OAuth or application-key material.
///
/// The handle is deliberately private and this type intentionally does not
/// implement `Serialize` or `Display`.  It can be bound by digest and
/// revision, but credential bytes and the opaque handle never enter a
/// contract, provider response, debug log, or receipt.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    opaque_id: String,
    revision: u64,
}

impl SecretReference {
    pub fn oauth(opaque_id: impl Into<String>, revision: u64) -> Result<Self, DatadogSloError> {
        Self::new(SecretKind::OAuth, opaque_id, revision)
    }

    pub fn application_key(
        opaque_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, DatadogSloError> {
        Self::new(SecretKind::ApplicationKey, opaque_id, revision)
    }

    pub fn app_key(opaque_id: impl Into<String>, revision: u64) -> Result<Self, DatadogSloError> {
        Self::application_key(opaque_id, revision)
    }

    fn new(
        kind: SecretKind,
        opaque_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, DatadogSloError> {
        let opaque_id = opaque_id.into();
        if revision == 0
            || opaque_id.is_empty()
            || opaque_id.len() > MAX_IDENTIFIER_BYTES
            || opaque_id.trim() != opaque_id
            || opaque_id.chars().any(char::is_control)
        {
            return Err(DatadogSloError::InvalidIdentifier {
                label: "secret reference",
            });
        }
        Ok(Self {
            kind,
            opaque_id,
            revision,
        })
    }

    #[must_use]
    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        sha256_digest(
            format!(
                "datadog-secret-reference|{}|{}|{}",
                self.kind.label(),
                self.revision,
                self.opaque_id
            )
            .as_bytes(),
        )
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("revision", &self.revision)
            .field("opaque_id", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DatadogPermission {
    SlosRead,
    MonitorsRead,
}

impl DatadogPermission {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SlosRead => "slos_read",
            Self::MonitorsRead => "monitors_read",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    pub auth_kind: SecretKind,
    pub permissions: BTreeSet<DatadogPermission>,
    pub site: String,
    pub api_host: String,
    pub organization_id: String,
    pub revision: u64,
}

impl PermissionSnapshot {
    pub fn new(
        auth_kind: SecretKind,
        permissions: BTreeSet<DatadogPermission>,
        site: impl Into<String>,
        api_host: impl Into<String>,
        organization_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, DatadogSloError> {
        let snapshot = Self {
            auth_kind,
            permissions,
            site: site.into(),
            api_host: validate_host(&api_host.into())?,
            organization_id: organization_id.into(),
            revision,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn least_privilege(
        secret: &SecretReference,
        site: impl Into<String>,
        api_host: impl Into<String>,
        organization_id: impl Into<String>,
        monitor_slo: bool,
    ) -> Result<Self, DatadogSloError> {
        let mut permissions = BTreeSet::from([DatadogPermission::SlosRead]);
        if monitor_slo {
            permissions.insert(DatadogPermission::MonitorsRead);
        }
        Self::new(
            secret.kind(),
            permissions,
            site,
            api_host,
            organization_id,
            secret.revision(),
        )
    }

    pub fn validate(&self) -> Result<(), DatadogSloError> {
        validate_identifier(&self.site, "site")?;
        validate_host(&self.api_host)?;
        validate_identifier(&self.organization_id, "organization")?;
        if self.revision == 0 || !self.permissions.contains(&DatadogPermission::SlosRead) {
            return Err(DatadogSloError::InvalidPermissionSnapshot);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    #[must_use]
    pub fn has(&self, permission: DatadogPermission) -> bool {
        self.permissions.contains(&permission)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SloType {
    Metric,
    Monitor,
    TimeSlice,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SloTimeframe {
    SevenDays,
    ThirtyDays,
    NinetyDays,
    Custom,
}

impl SloTimeframe {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SevenDays => "7d",
            Self::ThirtyDays => "30d",
            Self::NinetyDays => "90d",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrectionPolicy {
    Apply,
    Exclude,
}

impl CorrectionPolicy {
    pub const ON: Self = Self::Apply;
    pub const OFF: Self = Self::Exclude;

    #[must_use]
    pub const fn applies(self) -> bool {
        matches!(self, Self::Apply)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DowntimePolicy {
    Surface,
    FailClosed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityBinding {
    pub id: String,
    pub revision: u64,
}

impl IdentityBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, DatadogSloError> {
        let binding = Self {
            id: id.into(),
            revision,
        };
        binding.validate("identity")?;
        Ok(binding)
    }

    fn validate(&self, label: &'static str) -> Result<(), DatadogSloError> {
        validate_identifier(&self.id, label)?;
        if self.revision == 0 {
            return Err(DatadogSloError::InvalidIdentifier { label });
        }
        Ok(())
    }
}

pub type DeploymentBinding = IdentityBinding;
pub type ReleaseBinding = IdentityBinding;
pub type MissionBinding = IdentityBinding;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum SloQueryForm {
    Metric {
        numerator_fingerprint: Digest,
        denominator_fingerprint: Digest,
        #[serde(default)]
        group_by: Vec<String>,
    },
    Monitor {
        monitor_ids: Vec<String>,
        #[serde(default)]
        group_ids: Vec<String>,
    },
    TimeSlice {
        good_slice_fingerprint: Digest,
        bad_slice_fingerprint: Digest,
    },
}

impl SloQueryForm {
    pub fn validate(&self) -> Result<(), DatadogSloError> {
        match self {
            Self::Metric {
                numerator_fingerprint,
                denominator_fingerprint,
                group_by,
            } => {
                validate_digest(numerator_fingerprint, "numerator query")?;
                validate_digest(denominator_fingerprint, "denominator query")?;
                validate_bounded_list(group_by, MAX_GROUPS, "group_by")?;
                for field in group_by {
                    validate_identifier(field, "group_by field")?;
                }
            }
            Self::Monitor {
                monitor_ids,
                group_ids,
            } => {
                validate_bounded_list(monitor_ids, MAX_MONITORS, "monitor ids")?;
                validate_bounded_list(group_ids, MAX_GROUPS, "group ids")?;
                if monitor_ids.is_empty() {
                    return Err(DatadogSloError::InvalidQueryForm);
                }
                for id in monitor_ids {
                    validate_identifier(id, "monitor id")?;
                }
                for id in group_ids {
                    validate_identifier(id, "group id")?;
                }
            }
            Self::TimeSlice {
                good_slice_fingerprint,
                bad_slice_fingerprint,
            } => {
                validate_digest(good_slice_fingerprint, "good time-slice query")?;
                validate_digest(bad_slice_fingerprint, "bad time-slice query")?;
            }
        }
        Ok(())
    }

    #[must_use]
    pub const fn slo_type(&self) -> SloType {
        match self {
            Self::Metric { .. } => SloType::Metric,
            Self::Monitor { .. } => SloType::Monitor,
            Self::TimeSlice { .. } => SloType::TimeSlice,
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    #[must_use]
    pub fn monitor_ids(&self) -> Vec<String> {
        match self {
            Self::Monitor { monitor_ids, .. } => monitor_ids.clone(),
            _ => Vec::new(),
        }
    }

    #[must_use]
    pub fn group_ids(&self) -> Vec<String> {
        match self {
            Self::Metric { .. } | Self::TimeSlice { .. } => Vec::new(),
            Self::Monitor { group_ids, .. } => group_ids.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DatadogSloScopeSpec {
    pub site: String,
    pub api_host: String,
    pub organization_id: String,
    pub slo_id: String,
    pub slo_type: SloType,
    pub definition_digest: Digest,
    pub query: SloQueryForm,
    pub target: f64,
    pub warning: Option<f64>,
    pub error_budget_timeframe: SloTimeframe,
    pub error_budget_target: f64,
    pub correction_policy: CorrectionPolicy,
    pub downtime_policy: DowntimePolicy,
    pub project_id: String,
    pub deployment: DeploymentBinding,
    pub release: ReleaseBinding,
    pub mission: MissionBinding,
    pub policy_revision: u64,
    pub permission_snapshot: PermissionSnapshot,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DatadogSloScope {
    pub site: String,
    pub api_host: String,
    pub organization_id: String,
    pub slo_id: String,
    pub slo_type: SloType,
    pub definition_digest: Digest,
    pub query_digest: Digest,
    pub query: SloQueryForm,
    pub target: f64,
    pub warning: Option<f64>,
    pub error_budget_timeframe: SloTimeframe,
    pub error_budget_target: f64,
    pub correction_policy: CorrectionPolicy,
    pub downtime_policy: DowntimePolicy,
    pub project_id: String,
    pub deployment: DeploymentBinding,
    pub release: ReleaseBinding,
    pub mission: MissionBinding,
    pub policy_revision: u64,
    pub permission_snapshot: PermissionSnapshot,
    pub secret_kind: SecretKind,
    pub secret_revision: u64,
    pub secret_reference_digest: Digest,
}

impl DatadogSloScope {
    pub fn new(
        spec: DatadogSloScopeSpec,
        secret_reference: &SecretReference,
    ) -> Result<Self, DatadogSloError> {
        spec.query.validate()?;
        let scope = Self {
            site: spec.site,
            api_host: validate_host(&spec.api_host)?,
            organization_id: spec.organization_id,
            slo_id: spec.slo_id,
            slo_type: spec.slo_type,
            definition_digest: spec.definition_digest,
            query_digest: spec.query.digest(),
            query: spec.query,
            target: spec.target,
            warning: spec.warning,
            error_budget_timeframe: spec.error_budget_timeframe,
            error_budget_target: spec.error_budget_target,
            correction_policy: spec.correction_policy,
            downtime_policy: spec.downtime_policy,
            project_id: spec.project_id,
            deployment: spec.deployment,
            release: spec.release,
            mission: spec.mission,
            policy_revision: spec.policy_revision,
            permission_snapshot: spec.permission_snapshot,
            secret_kind: secret_reference.kind(),
            secret_revision: secret_reference.revision(),
            secret_reference_digest: secret_reference.digest(),
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), DatadogSloError> {
        validate_identifier(&self.site, "site")?;
        let host = validate_host(&self.api_host)?;
        if host != self.api_host {
            return Err(DatadogSloError::InvalidSiteHost);
        }
        validate_identifier(&self.organization_id, "organization")?;
        validate_identifier(&self.slo_id, "SLO id")?;
        validate_digest(&self.definition_digest, "definition")?;
        self.query.validate()?;
        if self.query.slo_type() != self.slo_type || self.query.digest() != self.query_digest {
            return Err(DatadogSloError::InvalidQueryForm);
        }
        validate_finite_percentage(self.target, "target")?;
        validate_optional_percentage(self.warning, "warning")?;
        validate_finite_percentage(self.error_budget_target, "error budget target")?;
        if let Some(warning) = self.warning
            && warning < self.target
        {
            return Err(DatadogSloError::InvalidPercentage { label: "warning" });
        }
        validate_identifier(&self.project_id, "project")?;
        self.deployment.validate("deployment")?;
        self.release.validate("release")?;
        self.mission.validate("mission")?;
        if self.policy_revision == 0
            || self.secret_revision == 0
            || !is_sha256(&self.secret_reference_digest)
        {
            return Err(DatadogSloError::InvalidScope);
        }
        self.permission_snapshot.validate()?;
        if self.permission_snapshot.auth_kind != self.secret_kind
            || self.permission_snapshot.revision != self.secret_revision
            || self.permission_snapshot.site != self.site
            || self.permission_snapshot.api_host != self.api_host
            || self.permission_snapshot.organization_id != self.organization_id
            || self.permission_snapshot.permissions
                != if self.slo_type == SloType::Monitor {
                    BTreeSet::from([DatadogPermission::SlosRead, DatadogPermission::MonitorsRead])
                } else {
                    BTreeSet::from([DatadogPermission::SlosRead])
                }
        {
            return Err(DatadogSloError::InvalidPermissionSnapshot);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    #[must_use]
    pub fn monitor_ids(&self) -> Vec<String> {
        self.query.monitor_ids()
    }

    #[must_use]
    pub fn group_ids(&self) -> Vec<String> {
        self.query.group_ids()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum SloDefinition {
    Metric {
        numerator_fingerprint: Digest,
        denominator_fingerprint: Digest,
        #[serde(default)]
        group_by: Vec<String>,
    },
    Monitor {
        monitor_ids: Vec<String>,
        #[serde(default)]
        group_ids: Vec<String>,
    },
    TimeSlice {
        good_slice_fingerprint: Digest,
        bad_slice_fingerprint: Digest,
    },
}

impl SloDefinition {
    pub fn validate(&self) -> Result<(), DatadogSloError> {
        let form = self.as_query_form();
        form.validate()
    }

    #[must_use]
    pub const fn slo_type(&self) -> SloType {
        match self {
            Self::Metric { .. } => SloType::Metric,
            Self::Monitor { .. } => SloType::Monitor,
            Self::TimeSlice { .. } => SloType::TimeSlice,
        }
    }

    #[must_use]
    pub fn as_query_form(&self) -> SloQueryForm {
        match self {
            Self::Metric {
                numerator_fingerprint,
                denominator_fingerprint,
                group_by,
            } => SloQueryForm::Metric {
                numerator_fingerprint: numerator_fingerprint.clone(),
                denominator_fingerprint: denominator_fingerprint.clone(),
                group_by: group_by.clone(),
            },
            Self::Monitor {
                monitor_ids,
                group_ids,
            } => SloQueryForm::Monitor {
                monitor_ids: monitor_ids.clone(),
                group_ids: group_ids.clone(),
            },
            Self::TimeSlice {
                good_slice_fingerprint,
                bad_slice_fingerprint,
            } => SloQueryForm::TimeSlice {
                good_slice_fingerprint: good_slice_fingerprint.clone(),
                bad_slice_fingerprint: bad_slice_fingerprint.clone(),
            },
        }
    }

    #[must_use]
    pub fn query_digest(&self) -> Digest {
        self.as_query_form().digest()
    }

    #[must_use]
    pub fn monitor_ids(&self) -> Vec<String> {
        self.as_query_form().monitor_ids()
    }

    #[must_use]
    pub fn group_ids(&self) -> Vec<String> {
        self.as_query_form().group_ids()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SloThreshold {
    pub timeframe: SloTimeframe,
    pub target: f64,
    pub warning: Option<f64>,
}

impl SloThreshold {
    pub fn new(
        timeframe: SloTimeframe,
        target: f64,
        warning: Option<f64>,
    ) -> Result<Self, DatadogSloError> {
        validate_finite_percentage(target, "threshold target")?;
        validate_optional_percentage(warning, "threshold warning")?;
        if let Some(warning) = warning
            && warning < target
        {
            return Err(DatadogSloError::InvalidPercentage {
                label: "threshold warning",
            });
        }
        Ok(Self {
            timeframe,
            target,
            warning,
        })
    }

    fn validate(&self) -> Result<(), DatadogSloError> {
        validate_finite_percentage(self.target, "threshold target")?;
        validate_optional_percentage(self.warning, "threshold warning")?;
        if let Some(warning) = self.warning
            && warning < self.target
        {
            return Err(DatadogSloError::InvalidPercentage {
                label: "threshold warning",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SloSnapshot {
    pub site: String,
    pub api_host: String,
    pub organization_id: String,
    pub slo_id: String,
    pub slo_type: SloType,
    pub name_digest: Option<Digest>,
    pub definition_digest: Digest,
    pub query_digest: Digest,
    pub definition: SloDefinition,
    pub target: f64,
    pub warning: Option<f64>,
    pub thresholds: Vec<SloThreshold>,
    pub status_api_version: String,
}

impl SloSnapshot {
    pub fn new(
        site: impl Into<String>,
        api_host: impl Into<String>,
        organization_id: impl Into<String>,
        slo_id: impl Into<String>,
        name_digest: Option<Digest>,
        definition: SloDefinition,
        target: f64,
        warning: Option<f64>,
        thresholds: Vec<SloThreshold>,
    ) -> Result<Self, DatadogSloError> {
        let site = site.into();
        let organization_id = organization_id.into();
        let slo_id = slo_id.into();
        definition.validate()?;
        let api_host = validate_host(&api_host.into())?;
        validate_identifier(&site, "site")?;
        validate_identifier(&organization_id, "organization")?;
        validate_identifier(&slo_id, "SLO id")?;
        if let Some(name_digest) = &name_digest {
            validate_digest(name_digest, "SLO name")?;
        }
        validate_finite_percentage(target, "target")?;
        validate_optional_percentage(warning, "warning")?;
        validate_bounded_list(&thresholds, 16, "thresholds")?;
        if thresholds.is_empty() {
            return Err(DatadogSloError::InvalidDefinition);
        }
        if let Some(warning) = warning
            && warning < target
        {
            return Err(DatadogSloError::InvalidPercentage { label: "warning" });
        }
        let snapshot = Self {
            site,
            api_host,
            organization_id,
            slo_id: slo_id.clone(),
            slo_type: definition.slo_type(),
            name_digest,
            definition_digest: sha256_digest(
                serde_json::to_vec(&SloDefinitionFingerprint {
                    slo_id: &slo_id,
                    slo_type: definition.slo_type(),
                    definition: &definition,
                })
                .expect("SLO definition fingerprint serializes")
                .as_slice(),
            ),
            query_digest: definition.query_digest(),
            definition,
            target,
            warning,
            thresholds,
            status_api_version: DATADOG_SLO_STATUS_API_VERSION.into(),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn with_status_api_version(mut self, version: impl Into<String>) -> Self {
        self.status_api_version = version.into();
        self
    }

    pub fn validate(&self) -> Result<(), DatadogSloError> {
        validate_identifier(&self.site, "site")?;
        validate_host(&self.api_host)?;
        validate_identifier(&self.organization_id, "organization")?;
        validate_identifier(&self.slo_id, "SLO id")?;
        if let Some(name_digest) = &self.name_digest {
            validate_digest(name_digest, "SLO name")?;
        }
        self.definition.validate()?;
        if self.definition.slo_type() != self.slo_type
            || self.definition.query_digest() != self.query_digest
            || self.definition_digest != self.computed_definition_digest()
        {
            return Err(DatadogSloError::InvalidDefinition);
        }
        validate_digest(&self.definition_digest, "definition")?;
        validate_finite_percentage(self.target, "target")?;
        validate_optional_percentage(self.warning, "warning")?;
        validate_bounded_list(&self.thresholds, 16, "thresholds")?;
        if self.thresholds.is_empty() {
            return Err(DatadogSloError::InvalidDefinition);
        }
        for threshold in &self.thresholds {
            threshold.validate()?;
        }
        if self.status_api_version.is_empty() || self.status_api_version.len() > 64 {
            return Err(DatadogSloError::PublicBetaStatusDrift);
        }
        Ok(())
    }

    #[must_use]
    pub fn monitor_ids(&self) -> Vec<String> {
        self.definition.monitor_ids()
    }

    #[must_use]
    pub fn group_ids(&self) -> Vec<String> {
        self.definition.group_ids()
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    fn computed_definition_digest(&self) -> Digest {
        sha256_digest(
            serde_json::to_vec(&SloDefinitionFingerprint {
                slo_id: &self.slo_id,
                slo_type: self.slo_type,
                definition: &self.definition,
            })
            .expect("SLO definition fingerprint serializes")
            .as_slice(),
        )
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SloDefinitionFingerprint<'a> {
    slo_id: &'a str,
    slo_type: SloType,
    definition: &'a SloDefinition,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservationWindow {
    pub from: DateTime<Utc>,
    pub until: DateTime<Utc>,
    pub closed: bool,
}

impl ObservationWindow {
    pub fn new(from: DateTime<Utc>, until: DateTime<Utc>) -> Result<Self, DatadogSloError> {
        let window = Self {
            from,
            until,
            closed: true,
        };
        window.validate()?;
        Ok(window)
    }

    pub fn closed(from: DateTime<Utc>, until: DateTime<Utc>) -> Result<Self, DatadogSloError> {
        Self::new(from, until)
    }

    pub fn validate(&self) -> Result<(), DatadogSloError> {
        let seconds = self.until.signed_duration_since(self.from).num_seconds();
        if !self.closed
            || seconds <= 0
            || seconds > MAX_OBSERVATION_WINDOW_SECONDS
            || self.from.timestamp() < 0
        {
            return Err(DatadogSloError::InvalidObservationWindow);
        }
        Ok(())
    }

    #[must_use]
    pub fn duration_seconds(&self) -> i64 {
        self.until.signed_duration_since(self.from).num_seconds()
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservationProposal {
    pub site: String,
    pub api_host: String,
    pub organization_id: String,
    pub slo_id: String,
    pub slo_type: SloType,
    pub definition_digest: Digest,
    pub query_digest: Digest,
    pub query: SloQueryForm,
    pub window: ObservationWindow,
    pub target: f64,
    pub warning: Option<f64>,
    pub error_budget_timeframe: SloTimeframe,
    pub error_budget_target: f64,
    pub correction_policy: CorrectionPolicy,
    pub downtime_policy: DowntimePolicy,
    pub project_id: String,
    pub deployment: DeploymentBinding,
    pub release: ReleaseBinding,
    pub mission: MissionBinding,
    pub policy_revision: u64,
    pub scope_digest: Digest,
    pub proposal_digest: Digest,
}

impl ObservationProposal {
    fn from_scope(
        scope: &DatadogSloScope,
        window: ObservationWindow,
    ) -> Result<Self, DatadogSloError> {
        scope.validate()?;
        window.validate()?;
        let mut proposal = Self {
            site: scope.site.clone(),
            api_host: scope.api_host.clone(),
            organization_id: scope.organization_id.clone(),
            slo_id: scope.slo_id.clone(),
            slo_type: scope.slo_type,
            definition_digest: scope.definition_digest.clone(),
            query_digest: scope.query_digest.clone(),
            query: scope.query.clone(),
            window,
            target: scope.target,
            warning: scope.warning,
            error_budget_timeframe: scope.error_budget_timeframe,
            error_budget_target: scope.error_budget_target,
            correction_policy: scope.correction_policy,
            downtime_policy: scope.downtime_policy,
            project_id: scope.project_id.clone(),
            deployment: scope.deployment.clone(),
            release: scope.release.clone(),
            mission: scope.mission.clone(),
            policy_revision: scope.policy_revision,
            scope_digest: scope.digest(),
            proposal_digest: String::new(),
        };
        proposal.proposal_digest = proposal.computed_digest();
        Ok(proposal)
    }

    pub fn validate_against(&self, scope: &DatadogSloScope) -> Result<(), DatadogSloError> {
        self.window.validate()?;
        if self.site != scope.site
            || self.api_host != scope.api_host
            || self.organization_id != scope.organization_id
            || self.slo_id != scope.slo_id
            || self.slo_type != scope.slo_type
            || self.definition_digest != scope.definition_digest
            || self.query_digest != scope.query_digest
            || self.query != scope.query
            || !same_percentage(self.target, scope.target)
            || !same_optional_percentage(self.warning, scope.warning)
            || self.error_budget_timeframe != scope.error_budget_timeframe
            || !same_percentage(self.error_budget_target, scope.error_budget_target)
            || self.correction_policy != scope.correction_policy
            || self.downtime_policy != scope.downtime_policy
            || self.project_id != scope.project_id
            || self.deployment != scope.deployment
            || self.release != scope.release
            || self.mission != scope.mission
            || self.policy_revision != scope.policy_revision
            || self.scope_digest != scope.digest()
            || self.proposal_digest != self.computed_digest()
        {
            return Err(DatadogSloError::ProposalBindingMismatch);
        }
        Ok(())
    }

    fn computed_digest(&self) -> Digest {
        canonical_digest(&ObservationProposalFingerprint::from(self))
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }
}

#[derive(Serialize)]
struct ObservationProposalFingerprint<'a> {
    site: &'a str,
    api_host: &'a str,
    organization_id: &'a str,
    slo_id: &'a str,
    slo_type: SloType,
    definition_digest: &'a str,
    query_digest: &'a str,
    query: &'a SloQueryForm,
    window: &'a ObservationWindow,
    target: f64,
    warning: Option<f64>,
    error_budget_timeframe: SloTimeframe,
    error_budget_target: f64,
    correction_policy: CorrectionPolicy,
    downtime_policy: DowntimePolicy,
    project_id: &'a str,
    deployment: &'a DeploymentBinding,
    release: &'a ReleaseBinding,
    mission: &'a MissionBinding,
    policy_revision: u64,
    scope_digest: &'a str,
}

impl<'a> From<&'a ObservationProposal> for ObservationProposalFingerprint<'a> {
    fn from(proposal: &'a ObservationProposal) -> Self {
        Self {
            site: &proposal.site,
            api_host: &proposal.api_host,
            organization_id: &proposal.organization_id,
            slo_id: &proposal.slo_id,
            slo_type: proposal.slo_type,
            definition_digest: &proposal.definition_digest,
            query_digest: &proposal.query_digest,
            query: &proposal.query,
            window: &proposal.window,
            target: proposal.target,
            warning: proposal.warning,
            error_budget_timeframe: proposal.error_budget_timeframe,
            error_budget_target: proposal.error_budget_target,
            correction_policy: proposal.correction_policy,
            downtime_policy: proposal.downtime_policy,
            project_id: &proposal.project_id,
            deployment: &proposal.deployment,
            release: &proposal.release,
            mission: &proposal.mission,
            policy_revision: proposal.policy_revision,
            scope_digest: &proposal.scope_digest,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SloOutcomeEvidenceServiceDefinition {
    pub id: String,
    pub version: PluginVersion,
    pub access: AccessMode,
    pub contract_digest: Digest,
    pub authority: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DatadogSloProviderDefinition {
    pub id: String,
    pub service_id: String,
    pub version: PluginVersion,
    pub implementation: String,
    pub scope: Vec<String>,
    pub authentication: Vec<String>,
    pub permissions: Vec<String>,
    pub transport: Vec<String>,
    pub reversible: bool,
    pub revocable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionSloOutcomeConsumerDefinition {
    pub id: String,
    pub service_id: String,
    pub version: PluginVersion,
    pub kind: String,
    pub binding: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DatadogSloOutcomePluginDefinition {
    pub schema_version: String,
    pub plugin_id: String,
    pub version: PluginVersion,
    pub contract_digest: Digest,
    pub service: SloOutcomeEvidenceServiceDefinition,
    pub provider: DatadogSloProviderDefinition,
    pub consumer: MissionSloOutcomeConsumerDefinition,
    pub reversible: bool,
    pub writes: bool,
    pub arbitrary_queries: bool,
    pub native: bool,
}

impl DatadogSloOutcomePluginDefinition {
    pub fn layer1() -> Result<Self, DatadogSloError> {
        let contract_digest = sha256_digest(DATADOG_SLO_OUTCOME_CONTRACT_JSON.as_bytes());
        let definition = Self {
            schema_version: DATADOG_SLO_OUTCOME_SCHEMA_VERSION.into(),
            plugin_id: DATADOG_SLO_PROVIDER_ID.into(),
            version: PluginVersion::V1,
            contract_digest: contract_digest.clone(),
            service: SloOutcomeEvidenceServiceDefinition {
                id: SLO_OUTCOME_EVIDENCE_SERVICE_ID.into(),
                version: PluginVersion::V1,
                access: AccessMode::ReadOnly,
                contract_digest,
                authority: "read_only_observational_evidence".into(),
            },
            provider: DatadogSloProviderDefinition {
                id: DATADOG_SLO_PROVIDER_ID.into(),
                service_id: SLO_OUTCOME_EVIDENCE_SERVICE_ID.into(),
                version: PluginVersion::V1,
                implementation: DATADOG_SLO_PROVIDER_IMPLEMENTATION.into(),
                scope: vec![
                    "site".into(),
                    "api_host".into(),
                    "organization_id".into(),
                    "slo_id".into(),
                    "slo_type".into(),
                    "definition_digest".into(),
                    "query_digest".into(),
                    "monitor_ids".into(),
                    "group_ids".into(),
                    "correction_policy".into(),
                    "downtime_policy".into(),
                    "project_id".into(),
                    "deployment_id".into(),
                    "deployment_revision".into(),
                    "release_id".into(),
                    "release_revision".into(),
                    "mission_id".into(),
                    "mission_revision".into(),
                    "observation_window".into(),
                    "policy_revision".into(),
                    "permission_snapshot".into(),
                    "registration_digest".into(),
                ],
                authentication: vec![
                    "oauth_secret_reference".into(),
                    "application_key_secret_reference".into(),
                ],
                permissions: vec!["slos_read".into(), "monitors_read".into()],
                transport: vec![
                    "recording".into(),
                    "fake".into(),
                    "fixture".into(),
                    "loopback".into(),
                    "blocked_env".into(),
                ],
                reversible: true,
                revocable: true,
            },
            consumer: MissionSloOutcomeConsumerDefinition {
                id: MISSION_SLO_OUTCOME_CONSUMER_ID.into(),
                service_id: SLO_OUTCOME_EVIDENCE_SERVICE_ID.into(),
                version: PluginVersion::V1,
                kind: "mission_outcome_evidence_proposal".into(),
                binding: vec![
                    "site".into(),
                    "api_host".into(),
                    "organization_id".into(),
                    "slo_id".into(),
                    "slo_type".into(),
                    "definition_digest".into(),
                    "query_digest".into(),
                    "observation_window".into(),
                    "project_id".into(),
                    "deployment_id".into(),
                    "deployment_revision".into(),
                    "release_id".into(),
                    "release_revision".into(),
                    "mission_id".into(),
                    "mission_revision".into(),
                    "registration_digest".into(),
                    "source_result_digest".into(),
                    "policy_revision".into(),
                ],
            },
            reversible: true,
            writes: false,
            arbitrary_queries: false,
            native: false,
        };
        definition.validate()?;
        Ok(definition)
    }

    pub fn validate(&self) -> Result<(), DatadogSloError> {
        if self.schema_version != DATADOG_SLO_OUTCOME_SCHEMA_VERSION
            || self.plugin_id != DATADOG_SLO_PROVIDER_ID
            || self.version != PluginVersion::V1
            || !is_sha256(&self.contract_digest)
            || self.service.id != SLO_OUTCOME_EVIDENCE_SERVICE_ID
            || self.service.version != PluginVersion::V1
            || self.service.access != AccessMode::ReadOnly
            || self.service.contract_digest != self.contract_digest
            || self.provider.id != DATADOG_SLO_PROVIDER_ID
            || self.provider.service_id != self.service.id
            || self.provider.version != PluginVersion::V1
            || self.provider.implementation != DATADOG_SLO_PROVIDER_IMPLEMENTATION
            || self.provider.authentication.len() != 2
            || self.provider.permissions != vec!["slos_read", "monitors_read"]
            || self.provider.transport.len() != 5
            || !self.provider.reversible
            || !self.provider.revocable
            || self.consumer.id != MISSION_SLO_OUTCOME_CONSUMER_ID
            || self.consumer.service_id != self.service.id
            || self.consumer.version != PluginVersion::V1
            || !self.reversible
            || self.writes
            || self.arbitrary_queries
            || self.native
        {
            return Err(DatadogSloError::InvalidDefinition);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn bind(
        &self,
        scope: DatadogSloScope,
        registration_revision: u64,
    ) -> Result<RegistrationReceipt, DatadogSloError> {
        self.validate()?;
        scope.validate()?;
        if registration_revision == 0 {
            return Err(DatadogSloError::RegistrationMismatch);
        }
        let mut registration = RegistrationReceipt {
            plugin_id: self.plugin_id.clone(),
            service_id: self.service.id.clone(),
            provider_id: self.provider.id.clone(),
            version: self.version,
            contract_digest: self.contract_digest.clone(),
            scope_digest: scope.digest(),
            permission_digest: scope.permission_snapshot.digest(),
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: String::new(),
        };
        registration.registration_digest = registration.computed_digest();
        registration.validate(self, &scope)?;
        Ok(registration)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationReceipt {
    pub plugin_id: String,
    pub service_id: String,
    pub provider_id: String,
    pub version: PluginVersion,
    pub contract_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub registration_revision: u64,
    pub status: RegistrationStatus,
    pub registration_digest: Digest,
}

impl RegistrationReceipt {
    fn computed_digest(&self) -> Digest {
        canonical_digest(&RegistrationFingerprint {
            plugin_id: &self.plugin_id,
            service_id: &self.service_id,
            provider_id: &self.provider_id,
            version: self.version,
            contract_digest: &self.contract_digest,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            registration_revision: self.registration_revision,
            status: self.status,
        })
    }

    pub fn validate(
        &self,
        definition: &DatadogSloOutcomePluginDefinition,
        scope: &DatadogSloScope,
    ) -> Result<(), DatadogSloError> {
        definition.validate()?;
        scope.validate()?;
        if self.plugin_id != definition.plugin_id
            || self.service_id != definition.service.id
            || self.provider_id != definition.provider.id
            || self.version != definition.version
            || self.contract_digest != definition.contract_digest
            || self.scope_digest != scope.digest()
            || self.permission_digest != scope.permission_snapshot.digest()
            || self.registration_revision == 0
            || !is_sha256(&self.registration_digest)
            || self.registration_digest != self.computed_digest()
        {
            return Err(DatadogSloError::RegistrationMismatch);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> RevocationReceipt {
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.computed_digest();
        RevocationReceipt {
            registration_digest: self.registration_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            registration_revision: self.registration_revision,
            status: RegistrationStatus::Revoked,
        }
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == RegistrationStatus::Active
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationReceipt {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub registration_revision: u64,
    pub status: RegistrationStatus,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationFingerprint<'a> {
    plugin_id: &'a str,
    service_id: &'a str,
    provider_id: &'a str,
    version: PluginVersion,
    contract_digest: &'a str,
    scope_digest: &'a str,
    permission_digest: &'a str,
    registration_revision: u64,
    status: RegistrationStatus,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SliPointState {
    Good,
    Bad,
    NoData,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SliPoint {
    pub at: DateTime<Utc>,
    pub state: SliPointState,
    pub sli: Option<f64>,
    pub group_id: Option<String>,
    pub monitor_id: Option<String>,
}

impl SliPoint {
    pub fn new(
        at: DateTime<Utc>,
        state: SliPointState,
        sli: Option<f64>,
        group_id: Option<String>,
        monitor_id: Option<String>,
    ) -> Result<Self, DatadogSloError> {
        if let Some(value) = sli {
            validate_finite_percentage(value, "SLI")?;
        }
        if state == SliPointState::NoData && sli.is_some() {
            return Err(DatadogSloError::InvalidDefinition);
        }
        if let Some(group_id) = &group_id {
            validate_identifier(group_id, "group id")?;
        }
        if let Some(monitor_id) = &monitor_id {
            validate_identifier(monitor_id, "monitor id")?;
        }
        Ok(Self {
            at,
            state,
            sli,
            group_id,
            monitor_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceError {
    pub code: String,
    pub status: Option<u16>,
    pub detail_digest: Digest,
}

impl EvidenceError {
    pub fn new(
        code: impl Into<String>,
        status: Option<u16>,
        detail: impl AsRef<[u8]>,
    ) -> Result<Self, DatadogSloError> {
        let code = code.into();
        validate_identifier(&code, "evidence error code")?;
        Ok(Self {
            code,
            status,
            detail_digest: sha256_digest(detail.as_ref()),
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SloHistory {
    pub window: ObservationWindow,
    pub expected_points: u32,
    pub observed_points: u32,
    pub points: Vec<SliPoint>,
    pub errors: Vec<EvidenceError>,
    pub corrections_applied: bool,
    pub history_digest: Digest,
}

impl SloHistory {
    pub fn new(
        window: ObservationWindow,
        expected_points: u32,
        points: Vec<SliPoint>,
        errors: Vec<EvidenceError>,
        corrections_applied: bool,
    ) -> Result<Self, DatadogSloError> {
        window.validate()?;
        validate_bounded_list(&points, MAX_HISTORY_POINTS, "history points")?;
        validate_bounded_list(&errors, MAX_ERRORS, "history errors")?;
        if points.len() > u32::MAX as usize {
            return Err(DatadogSloError::BoundExceeded {
                label: "history points",
                maximum: MAX_HISTORY_POINTS,
            });
        }
        for point in &points {
            if point.at < window.from || point.at > window.until {
                return Err(DatadogSloError::WindowMismatch);
            }
        }
        let observed_points = points.len() as u32;
        let mut history = Self {
            window,
            expected_points,
            observed_points,
            points,
            errors,
            corrections_applied,
            history_digest: String::new(),
        };
        history.history_digest = history.computed_digest();
        Ok(history)
    }

    pub fn validate(&self) -> Result<(), DatadogSloError> {
        self.window.validate()?;
        validate_bounded_list(&self.points, MAX_HISTORY_POINTS, "history points")?;
        validate_bounded_list(&self.errors, MAX_ERRORS, "history errors")?;
        if self.observed_points != self.points.len() as u32
            || self.history_digest != self.computed_digest()
        {
            return Err(DatadogSloError::ResponseTampered);
        }
        for point in &self.points {
            if point.at < self.window.from || point.at > self.window.until {
                return Err(DatadogSloError::WindowMismatch);
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn is_no_data(&self) -> bool {
        self.points.is_empty()
            || self
                .points
                .iter()
                .all(|point| point.state == SliPointState::NoData)
    }

    #[must_use]
    pub fn is_partial(&self) -> bool {
        !self.errors.is_empty()
            || (!self.points.is_empty() && self.observed_points < self.expected_points)
    }

    fn computed_digest(&self) -> Digest {
        canonical_digest(&HistoryFingerprint {
            window: &self.window,
            expected_points: self.expected_points,
            observed_points: self.observed_points,
            points: &self.points,
            errors: &self.errors,
            corrections_applied: self.corrections_applied,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HistoryFingerprint<'a> {
    window: &'a ObservationWindow,
    expected_points: u32,
    observed_points: u32,
    points: &'a [SliPoint],
    errors: &'a [EvidenceError],
    corrections_applied: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DatadogSloState {
    Ok,
    Warning,
    Breached,
    NoData,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SloStatusSnapshot {
    pub window: ObservationWindow,
    pub state: DatadogSloState,
    pub sli: Option<f64>,
    pub span_precision_seconds: u64,
    pub error_budget_timeframe: SloTimeframe,
    pub error_budget_remaining: Option<f64>,
    pub raw_error_budget_remaining_seconds: Option<f64>,
    pub target: f64,
    pub warning: Option<f64>,
    pub api_version: String,
    pub errors: Vec<EvidenceError>,
    pub status_digest: Digest,
}

impl SloStatusSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        window: ObservationWindow,
        state: DatadogSloState,
        sli: Option<f64>,
        span_precision_seconds: u64,
        error_budget_timeframe: SloTimeframe,
        error_budget_remaining: Option<f64>,
        raw_error_budget_remaining_seconds: Option<f64>,
        target: f64,
        warning: Option<f64>,
        errors: Vec<EvidenceError>,
    ) -> Result<Self, DatadogSloError> {
        window.validate()?;
        if let Some(sli) = sli {
            validate_finite_percentage(sli, "SLI")?;
        }
        validate_optional_percentage(error_budget_remaining, "error budget remaining")?;
        if let Some(seconds) = raw_error_budget_remaining_seconds
            && !seconds.is_finite()
        {
            return Err(DatadogSloError::InvalidPercentage {
                label: "raw error budget remaining",
            });
        }
        validate_finite_percentage(target, "status target")?;
        validate_optional_percentage(warning, "status warning")?;
        validate_bounded_list(&errors, MAX_ERRORS, "status errors")?;
        let mut status = Self {
            window,
            state,
            sli,
            span_precision_seconds,
            error_budget_timeframe,
            error_budget_remaining,
            raw_error_budget_remaining_seconds,
            target,
            warning,
            api_version: DATADOG_SLO_STATUS_API_VERSION.into(),
            errors,
            status_digest: String::new(),
        };
        status.status_digest = status.computed_digest();
        Ok(status)
    }

    pub fn with_api_version(mut self, api_version: impl Into<String>) -> Self {
        self.api_version = api_version.into();
        self.status_digest = self.computed_digest();
        self
    }

    pub fn validate(&self) -> Result<(), DatadogSloError> {
        self.window.validate()?;
        if let Some(sli) = self.sli {
            validate_finite_percentage(sli, "SLI")?;
        }
        validate_optional_percentage(self.error_budget_remaining, "error budget remaining")?;
        validate_finite_percentage(self.target, "status target")?;
        validate_optional_percentage(self.warning, "status warning")?;
        validate_bounded_list(&self.errors, MAX_ERRORS, "status errors")?;
        if self.api_version != DATADOG_SLO_STATUS_API_VERSION {
            return Err(DatadogSloError::PublicBetaStatusDrift);
        }
        if self.status_digest != self.computed_digest() {
            return Err(DatadogSloError::ResponseTampered);
        }
        Ok(())
    }

    fn computed_digest(&self) -> Digest {
        canonical_digest(&StatusFingerprint {
            window: &self.window,
            state: self.state,
            sli: self.sli,
            span_precision_seconds: self.span_precision_seconds,
            error_budget_timeframe: self.error_budget_timeframe,
            error_budget_remaining: self.error_budget_remaining,
            raw_error_budget_remaining_seconds: self.raw_error_budget_remaining_seconds,
            target: self.target,
            warning: self.warning,
            api_version: &self.api_version,
            errors: &self.errors,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusFingerprint<'a> {
    window: &'a ObservationWindow,
    state: DatadogSloState,
    sli: Option<f64>,
    span_precision_seconds: u64,
    error_budget_timeframe: SloTimeframe,
    error_budget_remaining: Option<f64>,
    raw_error_budget_remaining_seconds: Option<f64>,
    target: f64,
    warning: Option<f64>,
    api_version: &'a str,
    errors: &'a [EvidenceError],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllowlistedMonitorTag {
    pub key: String,
    pub value: String,
}

impl AllowlistedMonitorTag {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Result<Self, DatadogSloError> {
        let key = key.into();
        let value = value.into();
        const ALLOWLIST: &[&str] = &[
            "service",
            "env",
            "environment",
            "team",
            "slo",
            "component",
            "owner",
            "tier",
        ];
        if !ALLOWLIST.contains(&key.as_str()) {
            return Err(DatadogSloError::UnallowlistedMonitorTag);
        }
        validate_identifier(&key, "monitor tag key")?;
        validate_identifier(&value, "monitor tag value")?;
        Ok(Self { key, value })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitorTransitionState {
    Uptime,
    Downtime,
    NoData,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MonitorDetail {
    pub monitor_id: String,
    pub monitor_type: String,
    pub query_digest: Digest,
    pub group_ids: Vec<String>,
    pub allowlisted_tags: Vec<AllowlistedMonitorTag>,
    pub current_state: MonitorTransitionState,
    pub detail_digest: Digest,
}

impl MonitorDetail {
    pub fn new(
        monitor_id: impl Into<String>,
        monitor_type: impl Into<String>,
        query_digest: Digest,
        group_ids: Vec<String>,
        allowlisted_tags: Vec<AllowlistedMonitorTag>,
        current_state: MonitorTransitionState,
    ) -> Result<Self, DatadogSloError> {
        let monitor_id = monitor_id.into();
        let monitor_type = monitor_type.into();
        validate_identifier(&monitor_id, "monitor id")?;
        validate_identifier(&monitor_type, "monitor type")?;
        validate_digest(&query_digest, "monitor query")?;
        validate_bounded_list(&group_ids, MAX_GROUPS, "monitor groups")?;
        validate_bounded_list(&allowlisted_tags, MAX_ALLOWLISTED_TAGS, "monitor tags")?;
        for group_id in &group_ids {
            validate_identifier(group_id, "monitor group")?;
        }
        let mut seen = BTreeSet::new();
        for tag in &allowlisted_tags {
            if !seen.insert(tag.key.clone()) {
                return Err(DatadogSloError::InvalidMonitorDetail);
            }
        }
        let mut detail = Self {
            monitor_id,
            monitor_type,
            query_digest,
            group_ids,
            allowlisted_tags,
            current_state,
            detail_digest: String::new(),
        };
        detail.detail_digest = detail.computed_digest();
        Ok(detail)
    }

    pub fn validate(&self) -> Result<(), DatadogSloError> {
        validate_identifier(&self.monitor_id, "monitor id")?;
        validate_identifier(&self.monitor_type, "monitor type")?;
        validate_digest(&self.query_digest, "monitor query")?;
        validate_bounded_list(&self.group_ids, MAX_GROUPS, "monitor groups")?;
        validate_bounded_list(&self.allowlisted_tags, MAX_ALLOWLISTED_TAGS, "monitor tags")?;
        if self.detail_digest != self.computed_digest() {
            return Err(DatadogSloError::ResponseTampered);
        }
        Ok(())
    }

    fn computed_digest(&self) -> Digest {
        canonical_digest(&MonitorDetailFingerprint {
            monitor_id: &self.monitor_id,
            monitor_type: &self.monitor_type,
            query_digest: &self.query_digest,
            group_ids: &self.group_ids,
            allowlisted_tags: &self.allowlisted_tags,
            current_state: self.current_state,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MonitorDetailFingerprint<'a> {
    monitor_id: &'a str,
    monitor_type: &'a str,
    query_digest: &'a str,
    group_ids: &'a [String],
    allowlisted_tags: &'a [AllowlistedMonitorTag],
    current_state: MonitorTransitionState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MonitorTransition {
    pub monitor_id: String,
    pub group_id: Option<String>,
    pub at: DateTime<Utc>,
    pub state: MonitorTransitionState,
}

impl MonitorTransition {
    pub fn new(
        monitor_id: impl Into<String>,
        group_id: Option<String>,
        at: DateTime<Utc>,
        state: MonitorTransitionState,
    ) -> Result<Self, DatadogSloError> {
        let monitor_id = monitor_id.into();
        validate_identifier(&monitor_id, "transition monitor")?;
        if let Some(group_id) = &group_id {
            validate_identifier(group_id, "transition group")?;
        }
        Ok(Self {
            monitor_id,
            group_id,
            at,
            state,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MonitorTransitionEvidence {
    pub window: ObservationWindow,
    pub transitions: Vec<MonitorTransition>,
    pub monitor_ids: Vec<String>,
    pub group_ids: Vec<String>,
    pub transition_digest: Digest,
}

impl MonitorTransitionEvidence {
    pub fn new(
        window: ObservationWindow,
        transitions: Vec<MonitorTransition>,
        monitor_ids: Vec<String>,
        group_ids: Vec<String>,
    ) -> Result<Self, DatadogSloError> {
        window.validate()?;
        validate_bounded_list(&transitions, MAX_TRANSITIONS, "monitor transitions")?;
        validate_bounded_list(&monitor_ids, MAX_MONITORS, "monitor ids")?;
        validate_bounded_list(&group_ids, MAX_GROUPS, "group ids")?;
        for monitor_id in &monitor_ids {
            validate_identifier(monitor_id, "monitor id")?;
        }
        for group_id in &group_ids {
            validate_identifier(group_id, "group id")?;
        }
        for transition in &transitions {
            if transition.at < window.from
                || transition.at > window.until
                || !monitor_ids.contains(&transition.monitor_id)
                || transition
                    .group_id
                    .as_ref()
                    .is_some_and(|group_id| !group_ids.contains(group_id))
            {
                return Err(DatadogSloError::MonitorScopeMismatch);
            }
        }
        let mut evidence = Self {
            window,
            transitions,
            monitor_ids,
            group_ids,
            transition_digest: String::new(),
        };
        evidence.transition_digest = evidence.computed_digest();
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<(), DatadogSloError> {
        self.window.validate()?;
        validate_bounded_list(&self.transitions, MAX_TRANSITIONS, "monitor transitions")?;
        if self.transition_digest != self.computed_digest() {
            return Err(DatadogSloError::ResponseTampered);
        }
        Ok(())
    }

    #[must_use]
    pub fn has_observation(&self) -> bool {
        !self.transitions.is_empty()
    }

    #[must_use]
    pub fn has_downtime(&self) -> bool {
        self.transitions
            .iter()
            .any(|transition| transition.state == MonitorTransitionState::Downtime)
    }

    fn computed_digest(&self) -> Digest {
        canonical_digest(&MonitorTransitionFingerprint {
            window: &self.window,
            transitions: &self.transitions,
            monitor_ids: &self.monitor_ids,
            group_ids: &self.group_ids,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MonitorTransitionFingerprint<'a> {
    window: &'a ObservationWindow,
    transitions: &'a [MonitorTransition],
    monitor_ids: &'a [String],
    group_ids: &'a [String],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CorrectionMetadata {
    pub policy: CorrectionPolicy,
    pub applied: bool,
    pub correction_ids: Vec<String>,
    pub window: ObservationWindow,
    pub correction_digest: Digest,
}

impl CorrectionMetadata {
    pub fn new(
        policy: CorrectionPolicy,
        applied: bool,
        correction_ids: Vec<String>,
        window: ObservationWindow,
    ) -> Result<Self, DatadogSloError> {
        window.validate()?;
        validate_bounded_list(&correction_ids, MAX_CORRECTIONS, "corrections")?;
        for id in &correction_ids {
            validate_identifier(id, "correction id")?;
        }
        if applied != policy.applies() {
            return Err(DatadogSloError::InvalidDefinition);
        }
        let mut metadata = Self {
            policy,
            applied,
            correction_ids,
            window,
            correction_digest: String::new(),
        };
        metadata.correction_digest = metadata.computed_digest();
        Ok(metadata)
    }

    pub fn validate(&self) -> Result<(), DatadogSloError> {
        self.window.validate()?;
        validate_bounded_list(&self.correction_ids, MAX_CORRECTIONS, "corrections")?;
        if self.applied != self.policy.applies() || self.correction_digest != self.computed_digest()
        {
            return Err(DatadogSloError::ResponseTampered);
        }
        Ok(())
    }

    fn computed_digest(&self) -> Digest {
        canonical_digest(&CorrectionFingerprint {
            policy: self.policy,
            applied: self.applied,
            correction_ids: &self.correction_ids,
            window: &self.window,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CorrectionFingerprint<'a> {
    policy: CorrectionPolicy,
    applied: bool,
    correction_ids: &'a [String],
    window: &'a ObservationWindow,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DowntimeMetadata {
    pub policy: DowntimePolicy,
    pub active: bool,
    pub downtime_ids: Vec<String>,
    pub window: ObservationWindow,
    pub downtime_digest: Digest,
}

impl DowntimeMetadata {
    pub fn new(
        policy: DowntimePolicy,
        active: bool,
        downtime_ids: Vec<String>,
        window: ObservationWindow,
    ) -> Result<Self, DatadogSloError> {
        window.validate()?;
        validate_bounded_list(&downtime_ids, MAX_DOWNTIMES, "downtimes")?;
        for id in &downtime_ids {
            validate_identifier(id, "downtime id")?;
        }
        if active == downtime_ids.is_empty() {
            return Err(DatadogSloError::InvalidDefinition);
        }
        let mut metadata = Self {
            policy,
            active,
            downtime_ids,
            window,
            downtime_digest: String::new(),
        };
        metadata.downtime_digest = metadata.computed_digest();
        Ok(metadata)
    }

    pub fn validate(&self) -> Result<(), DatadogSloError> {
        self.window.validate()?;
        validate_bounded_list(&self.downtime_ids, MAX_DOWNTIMES, "downtimes")?;
        if self.active == self.downtime_ids.is_empty()
            || self.downtime_digest != self.computed_digest()
        {
            return Err(DatadogSloError::ResponseTampered);
        }
        Ok(())
    }

    fn computed_digest(&self) -> Digest {
        canonical_digest(&DowntimeFingerprint {
            policy: self.policy,
            active: self.active,
            downtime_ids: &self.downtime_ids,
            window: &self.window,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DowntimeFingerprint<'a> {
    policy: DowntimePolicy,
    active: bool,
    downtime_ids: &'a [String],
    window: &'a ObservationWindow,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DatadogReadOperation {
    DescribeSlo,
    ReadSloEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DatadogReadRequest {
    pub operation: DatadogReadOperation,
    pub site: String,
    pub api_host: String,
    pub organization_id: String,
    pub slo_id: String,
    pub slo_type: SloType,
    pub definition_digest: Digest,
    pub query_digest: Digest,
    pub monitor_ids: Vec<String>,
    pub group_ids: Vec<String>,
    pub window: Option<ObservationWindow>,
    pub correction_policy: CorrectionPolicy,
    pub downtime_policy: DowntimePolicy,
    pub status_api_version: String,
    pub scope_digest: Digest,
    pub request_digest: Digest,
}

impl DatadogReadRequest {
    fn for_operation(
        operation: DatadogReadOperation,
        scope: &DatadogSloScope,
        proposal: &ObservationProposal,
    ) -> Result<Self, DatadogSloError> {
        proposal.validate_against(scope)?;
        let mut request = Self {
            operation,
            site: scope.site.clone(),
            api_host: scope.api_host.clone(),
            organization_id: scope.organization_id.clone(),
            slo_id: scope.slo_id.clone(),
            slo_type: scope.slo_type,
            definition_digest: scope.definition_digest.clone(),
            query_digest: scope.query_digest.clone(),
            monitor_ids: scope.monitor_ids(),
            group_ids: scope.group_ids(),
            window: Some(proposal.window.clone()),
            correction_policy: proposal.correction_policy,
            downtime_policy: proposal.downtime_policy,
            status_api_version: DATADOG_SLO_STATUS_API_VERSION.into(),
            scope_digest: scope.digest(),
            request_digest: String::new(),
        };
        request.request_digest = request.computed_digest();
        Ok(request)
    }

    fn for_describe(scope: &DatadogSloScope) -> Result<Self, DatadogSloError> {
        scope.validate()?;
        let mut request = Self {
            operation: DatadogReadOperation::DescribeSlo,
            site: scope.site.clone(),
            api_host: scope.api_host.clone(),
            organization_id: scope.organization_id.clone(),
            slo_id: scope.slo_id.clone(),
            slo_type: scope.slo_type,
            definition_digest: scope.definition_digest.clone(),
            query_digest: scope.query_digest.clone(),
            monitor_ids: scope.monitor_ids(),
            group_ids: scope.group_ids(),
            window: None,
            correction_policy: scope.correction_policy,
            downtime_policy: scope.downtime_policy,
            status_api_version: DATADOG_SLO_STATUS_API_VERSION.into(),
            scope_digest: scope.digest(),
            request_digest: String::new(),
        };
        request.request_digest = request.computed_digest();
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), DatadogSloError> {
        validate_identifier(&self.site, "site")?;
        validate_host(&self.api_host)?;
        validate_identifier(&self.organization_id, "organization")?;
        validate_identifier(&self.slo_id, "SLO id")?;
        validate_digest(&self.definition_digest, "definition")?;
        validate_digest(&self.query_digest, "query")?;
        validate_bounded_list(&self.monitor_ids, MAX_MONITORS, "monitor ids")?;
        validate_bounded_list(&self.group_ids, MAX_GROUPS, "group ids")?;
        if let Some(window) = &self.window {
            window.validate()?;
        }
        if self.status_api_version != DATADOG_SLO_STATUS_API_VERSION
            || self.request_digest != self.computed_digest()
        {
            return Err(DatadogSloError::RequestTampered);
        }
        Ok(())
    }

    fn computed_digest(&self) -> Digest {
        canonical_digest(&ReadRequestFingerprint {
            operation: self.operation,
            site: &self.site,
            api_host: &self.api_host,
            organization_id: &self.organization_id,
            slo_id: &self.slo_id,
            slo_type: self.slo_type,
            definition_digest: &self.definition_digest,
            query_digest: &self.query_digest,
            monitor_ids: &self.monitor_ids,
            group_ids: &self.group_ids,
            window: self.window.as_ref(),
            correction_policy: self.correction_policy,
            downtime_policy: self.downtime_policy,
            status_api_version: &self.status_api_version,
            scope_digest: &self.scope_digest,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadRequestFingerprint<'a> {
    operation: DatadogReadOperation,
    site: &'a str,
    api_host: &'a str,
    organization_id: &'a str,
    slo_id: &'a str,
    slo_type: SloType,
    definition_digest: &'a str,
    query_digest: &'a str,
    monitor_ids: &'a [String],
    group_ids: &'a [String],
    window: Option<&'a ObservationWindow>,
    correction_policy: CorrectionPolicy,
    downtime_policy: DowntimePolicy,
    status_api_version: &'a str,
    scope_digest: &'a str,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DatadogSloReadResponse {
    pub site: String,
    pub api_host: String,
    pub organization_id: String,
    pub snapshot: SloSnapshot,
    pub history: SloHistory,
    pub status: SloStatusSnapshot,
    pub monitors: Vec<MonitorDetail>,
    pub monitor_transitions: MonitorTransitionEvidence,
    pub corrections: CorrectionMetadata,
    pub downtime: DowntimeMetadata,
    pub response_digest: Digest,
}

impl DatadogSloReadResponse {
    pub fn new(
        snapshot: SloSnapshot,
        history: SloHistory,
        status: SloStatusSnapshot,
        monitors: Vec<MonitorDetail>,
        monitor_transitions: MonitorTransitionEvidence,
        corrections: CorrectionMetadata,
        downtime: DowntimeMetadata,
    ) -> Result<Self, DatadogSloError> {
        snapshot.validate()?;
        history.validate()?;
        status.validate()?;
        validate_bounded_list(&monitors, MAX_MONITORS, "monitor details")?;
        for monitor in &monitors {
            monitor.validate()?;
        }
        monitor_transitions.validate()?;
        corrections.validate()?;
        downtime.validate()?;
        let mut response = Self {
            site: snapshot.site.clone(),
            api_host: snapshot.api_host.clone(),
            organization_id: snapshot.organization_id.clone(),
            snapshot,
            history,
            status,
            monitors,
            monitor_transitions,
            corrections,
            downtime,
            response_digest: String::new(),
        };
        response.response_digest = response.computed_digest();
        Ok(response)
    }

    pub fn validate(&self) -> Result<(), DatadogSloError> {
        self.snapshot.validate()?;
        self.history.validate()?;
        self.status.validate()?;
        validate_bounded_list(&self.monitors, MAX_MONITORS, "monitor details")?;
        for monitor in &self.monitors {
            monitor.validate()?;
        }
        self.monitor_transitions.validate()?;
        self.corrections.validate()?;
        self.downtime.validate()?;
        if self.site != self.snapshot.site
            || self.api_host != self.snapshot.api_host
            || self.organization_id != self.snapshot.organization_id
            || self.response_digest != self.computed_digest()
        {
            return Err(DatadogSloError::ResponseTampered);
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        scope: &DatadogSloScope,
        proposal: &ObservationProposal,
    ) -> Result<(), DatadogSloError> {
        self.validate()?;
        proposal.validate_against(scope)?;
        if self.site != scope.site || self.api_host != scope.api_host {
            return Err(DatadogSloError::SiteMismatch);
        }
        if self.organization_id != scope.organization_id {
            return Err(DatadogSloError::OrganizationMismatch);
        }
        if self.snapshot.slo_id != scope.slo_id {
            return Err(DatadogSloError::SloMismatch);
        }
        if self.snapshot.slo_type != scope.slo_type {
            return Err(DatadogSloError::SloTypeMismatch);
        }
        if self.snapshot.definition_digest != scope.definition_digest {
            return Err(DatadogSloError::DefinitionMismatch);
        }
        if self.snapshot.query_digest != scope.query_digest {
            return Err(DatadogSloError::QueryMismatch);
        }
        if self.history.window != proposal.window
            || self.status.window != proposal.window
            || self.monitor_transitions.window != proposal.window
            || self.corrections.window != proposal.window
            || self.downtime.window != proposal.window
        {
            return Err(DatadogSloError::WindowMismatch);
        }
        if !same_percentage(self.snapshot.target, proposal.target)
            || !same_percentage(self.status.target, proposal.target)
        {
            return Err(DatadogSloError::TargetMismatch);
        }
        if self.snapshot.warning != proposal.warning || self.status.warning != proposal.warning {
            return Err(DatadogSloError::WarningMismatch);
        }
        if self.status.error_budget_timeframe != proposal.error_budget_timeframe
            || self.history.corrections_applied != proposal.correction_policy.applies()
        {
            return Err(DatadogSloError::ErrorBudgetMismatch);
        }
        if self.corrections.policy != proposal.correction_policy
            || self.corrections.applied != proposal.correction_policy.applies()
            || self.downtime.policy != proposal.downtime_policy
        {
            return Err(DatadogSloError::ProposalBindingMismatch);
        }
        if self.snapshot.monitor_ids() != scope.monitor_ids()
            || self.snapshot.group_ids() != scope.group_ids()
            || self
                .monitors
                .iter()
                .map(|monitor| monitor.monitor_id.clone())
                .collect::<BTreeSet<_>>()
                != scope.monitor_ids().into_iter().collect::<BTreeSet<_>>()
            || self
                .monitor_transitions
                .monitor_ids
                .iter()
                .collect::<BTreeSet<_>>()
                != scope.monitor_ids().iter().collect::<BTreeSet<_>>()
            || self
                .monitor_transitions
                .group_ids
                .iter()
                .collect::<BTreeSet<_>>()
                != scope.group_ids().iter().collect::<BTreeSet<_>>()
        {
            return Err(DatadogSloError::MonitorScopeMismatch);
        }
        if self.status.api_version != DATADOG_SLO_STATUS_API_VERSION
            || self.snapshot.status_api_version != DATADOG_SLO_STATUS_API_VERSION
        {
            return Err(DatadogSloError::PublicBetaStatusDrift);
        }
        Ok(())
    }

    pub fn tampered(mut self) -> Self {
        self.response_digest = "0".repeat(64);
        self
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.response_digest
    }

    fn computed_digest(&self) -> Digest {
        canonical_digest(&ReadResponseFingerprint {
            site: &self.site,
            api_host: &self.api_host,
            organization_id: &self.organization_id,
            snapshot: &self.snapshot,
            history: &self.history,
            status: &self.status,
            monitors: &self.monitors,
            monitor_transitions: &self.monitor_transitions,
            corrections: &self.corrections,
            downtime: &self.downtime,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadResponseFingerprint<'a> {
    site: &'a str,
    api_host: &'a str,
    organization_id: &'a str,
    snapshot: &'a SloSnapshot,
    history: &'a SloHistory,
    status: &'a SloStatusSnapshot,
    monitors: &'a [MonitorDetail],
    monitor_transitions: &'a MonitorTransitionEvidence,
    corrections: &'a CorrectionMetadata,
    downtime: &'a DowntimeMetadata,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    NativeHttps,
    Recording,
    Fake,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    #[must_use]
    pub const fn is_native(self) -> bool {
        matches!(self, Self::NativeHttps)
    }

    #[must_use]
    pub const fn is_connected(self) -> bool {
        matches!(self, Self::NativeHttps)
    }
}

pub trait DatadogSloTransport: fmt::Debug + Send + Sync {
    fn provenance(&self) -> TransportProvenance;

    fn read(
        &self,
        request: &DatadogReadRequest,
    ) -> Result<DatadogSloReadResponse, DatadogTransportError>;
}

#[derive(Clone, Debug)]
pub enum RecordedFault {
    Unauthorized401,
    Forbidden403,
    NotFound404,
    RateLimited429 { retry_after_seconds: Option<u64> },
    Timeout,
    Server5xx { status: u16 },
    SiteMismatch,
    PublicBetaDrift,
    InvalidResponse,
    ResponseTampered,
}

impl RecordedFault {
    fn error(&self) -> DatadogTransportError {
        match self {
            Self::Unauthorized401 => DatadogTransportError::Unauthorized401,
            Self::Forbidden403 => DatadogTransportError::Forbidden403,
            Self::NotFound404 => DatadogTransportError::NotFound404,
            Self::RateLimited429 {
                retry_after_seconds,
            } => DatadogTransportError::RateLimited429 {
                retry_after_seconds: *retry_after_seconds,
            },
            Self::Timeout => DatadogTransportError::Timeout,
            Self::Server5xx { status } => DatadogTransportError::Server5xx { status: *status },
            Self::SiteMismatch => DatadogTransportError::SiteMismatch,
            Self::PublicBetaDrift => DatadogTransportError::PublicBetaDrift,
            Self::InvalidResponse => DatadogTransportError::InvalidResponse,
            Self::ResponseTampered => DatadogTransportError::ResponseTampered,
        }
    }
}

#[derive(Debug, Default)]
struct TransportBuffer {
    responses: VecDeque<Result<DatadogSloReadResponse, DatadogTransportError>>,
    requests: Vec<DatadogReadRequest>,
}

impl TransportBuffer {
    fn with_response(response: DatadogSloReadResponse) -> Self {
        Self {
            responses: VecDeque::from([Ok(response)]),
            requests: Vec::new(),
        }
    }

    fn push_response(&mut self, response: DatadogSloReadResponse) {
        self.responses.push_back(Ok(response));
    }

    fn push_error(&mut self, error: DatadogTransportError) {
        self.responses.push_back(Err(error));
    }

    fn read(
        &mut self,
        request: &DatadogReadRequest,
    ) -> Result<DatadogSloReadResponse, DatadogTransportError> {
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .unwrap_or(Err(DatadogTransportError::InvalidResponse))
    }
}

macro_rules! recorded_transport {
    ($name:ident, $provenance:expr, $constructor:ident) => {
        #[derive(Clone)]
        pub struct $name {
            buffer: Arc<Mutex<TransportBuffer>>,
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .finish_non_exhaustive()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::empty()
            }
        }

        impl $name {
            pub fn new() -> Self {
                Self::empty()
            }

            pub fn $constructor(response: DatadogSloReadResponse) -> Self {
                Self {
                    buffer: Arc::new(Mutex::new(TransportBuffer::with_response(response))),
                }
            }

            pub fn empty() -> Self {
                Self {
                    buffer: Arc::new(Mutex::new(TransportBuffer::default())),
                }
            }

            pub fn push_response(&self, response: DatadogSloReadResponse) {
                self.buffer
                    .lock()
                    .expect("transport buffer lock")
                    .push_response(response);
            }

            pub fn push_fault(&self, fault: RecordedFault) {
                self.buffer
                    .lock()
                    .expect("transport buffer lock")
                    .push_error(fault.error());
            }

            pub fn requests(&self) -> Vec<DatadogReadRequest> {
                self.buffer
                    .lock()
                    .expect("transport buffer lock")
                    .requests
                    .clone()
            }
        }

        impl DatadogSloTransport for $name {
            fn provenance(&self) -> TransportProvenance {
                $provenance
            }

            fn read(
                &self,
                request: &DatadogReadRequest,
            ) -> Result<DatadogSloReadResponse, DatadogTransportError> {
                request
                    .validate()
                    .map_err(|_| DatadogTransportError::InvalidResponse)?;
                self.buffer
                    .lock()
                    .expect("transport buffer lock")
                    .read(request)
            }
        }
    };
}

recorded_transport!(
    RecordingDatadogSloTransport,
    TransportProvenance::Recording,
    from_response
);
recorded_transport!(
    FakeDatadogSloTransport,
    TransportProvenance::Fake,
    from_response
);
recorded_transport!(
    FixtureDatadogSloTransport,
    TransportProvenance::Fixture,
    from_response
);
recorded_transport!(
    LoopbackDatadogSloTransport,
    TransportProvenance::Loopback,
    from_response
);

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvDatadogSloTransport;

impl DatadogSloTransport for BlockedEnvDatadogSloTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read(
        &self,
        _request: &DatadogReadRequest,
    ) -> Result<DatadogSloReadResponse, DatadogTransportError> {
        Err(DatadogTransportError::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceProjection {
    Healthy,
    Breached,
    Warning,
    NoData,
    Partial,
    Corrected,
    Downtime,
    ProviderUnknown,
}

pub type OutcomeEvidenceProjection = EvidenceProjection;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClassification {
    Native,
    Recording,
    Fake,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl From<TransportProvenance> for EvidenceClassification {
    fn from(value: TransportProvenance) -> Self {
        match value {
            TransportProvenance::NativeHttps => Self::Native,
            TransportProvenance::Recording => Self::Recording,
            TransportProvenance::Fake => Self::Fake,
            TransportProvenance::Fixture => Self::Fixture,
            TransportProvenance::Loopback => Self::Loopback,
            TransportProvenance::BlockedEnv => Self::BlockedEnv,
        }
    }
}

impl EvidenceClassification {
    #[must_use]
    pub const fn is_native(self) -> bool {
        matches!(self, Self::Native)
    }

    #[must_use]
    pub const fn is_connected(self) -> bool {
        matches!(self, Self::Native)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SliEvidence {
    pub value: Option<f64>,
    pub target: f64,
    pub warning: Option<f64>,
    pub complete: bool,
    pub no_data: bool,
    pub history_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ErrorBudgetEvidence {
    pub timeframe: SloTimeframe,
    pub target: f64,
    pub remaining: Option<f64>,
    pub raw_remaining_seconds: Option<f64>,
    pub calculation_error: bool,
    pub status_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SloEvidenceReading {
    pub proposal: ObservationProposal,
    pub snapshot: SloSnapshot,
    pub sli: SliEvidence,
    pub error_budget: ErrorBudgetEvidence,
    pub monitor_transitions: MonitorTransitionEvidence,
    pub corrections: CorrectionMetadata,
    pub downtime: DowntimeMetadata,
    pub projection: EvidenceProjection,
    pub classification: EvidenceClassification,
    pub native: bool,
    pub connected: bool,
    pub absence_is_success: bool,
    pub source_result_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
}

impl SloEvidenceReading {
    fn from_response(
        scope: &DatadogSloScope,
        registration: &RegistrationReceipt,
        proposal: &ObservationProposal,
        response: DatadogSloReadResponse,
        provenance: TransportProvenance,
    ) -> Result<Self, DatadogSloError> {
        response.validate_against(scope, proposal)?;
        let classification = EvidenceClassification::from(provenance);
        if provenance.is_native()
            || classification.is_native() != provenance.is_native()
            || classification.is_connected() != provenance.is_connected()
        {
            return Err(DatadogSloError::NativeClassificationMismatch);
        }
        let no_data = response.history.is_no_data()
            || response.status.state == DatadogSloState::NoData
            || (scope.slo_type == SloType::Monitor
                && !response.monitor_transitions.has_observation());
        let partial = response.history.is_partial() || !response.status.errors.is_empty();
        let projection = if response.downtime.active || response.monitor_transitions.has_downtime()
        {
            EvidenceProjection::Downtime
        } else if response.corrections.applied {
            EvidenceProjection::Corrected
        } else if partial {
            EvidenceProjection::Partial
        } else if no_data {
            EvidenceProjection::NoData
        } else {
            match response.status.state {
                DatadogSloState::Ok => EvidenceProjection::Healthy,
                DatadogSloState::Warning => EvidenceProjection::Warning,
                DatadogSloState::Breached => EvidenceProjection::Breached,
                DatadogSloState::NoData => EvidenceProjection::NoData,
                DatadogSloState::Unknown => EvidenceProjection::ProviderUnknown,
            }
        };
        let sli = SliEvidence {
            value: response.status.sli,
            target: proposal.target,
            warning: proposal.warning,
            complete: !partial && !no_data,
            no_data,
            history_digest: response.history.history_digest.clone(),
        };
        let error_budget = ErrorBudgetEvidence {
            timeframe: response.status.error_budget_timeframe,
            target: proposal.error_budget_target,
            remaining: response.status.error_budget_remaining,
            raw_remaining_seconds: response.status.raw_error_budget_remaining_seconds,
            calculation_error: response
                .status
                .errors
                .iter()
                .any(|error| error.code == "error_budget_calculation"),
            status_digest: response.status.status_digest.clone(),
        };
        let mut reading = Self {
            proposal: proposal.clone(),
            snapshot: response.snapshot,
            sli,
            error_budget,
            monitor_transitions: response.monitor_transitions,
            corrections: response.corrections,
            downtime: response.downtime,
            projection,
            classification,
            native: provenance.is_native(),
            connected: provenance.is_connected(),
            absence_is_success: false,
            source_result_digest: response.response_digest,
            registration_digest: registration.registration_digest.clone(),
            evidence_digest: String::new(),
        };
        reading.evidence_digest = reading.computed_digest();
        reading.validate(scope, registration)?;
        Ok(reading)
    }

    pub fn validate(
        &self,
        scope: &DatadogSloScope,
        registration: &RegistrationReceipt,
    ) -> Result<(), DatadogSloError> {
        self.proposal.validate_against(scope)?;
        if self.registration_digest != registration.registration_digest
            || !is_sha256(&self.source_result_digest)
            || self.evidence_digest != self.computed_digest()
            || self.absence_is_success
            || self.native != self.classification.is_native()
            || self.connected != self.classification.is_connected()
        {
            return Err(DatadogSloError::ReceiptTampered);
        }
        if !self.native && !self.connected && self.classification == EvidenceClassification::Native
        {
            return Err(DatadogSloError::NativeClassificationMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn is_native(&self) -> bool {
        self.native
    }

    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    fn computed_digest(&self) -> Digest {
        canonical_digest(&EvidenceFingerprint {
            proposal: &self.proposal,
            snapshot: &self.snapshot,
            sli: &self.sli,
            error_budget: &self.error_budget,
            monitor_transitions: &self.monitor_transitions,
            corrections: &self.corrections,
            downtime: &self.downtime,
            projection: self.projection,
            classification: self.classification,
            native: self.native,
            connected: self.connected,
            absence_is_success: self.absence_is_success,
            source_result_digest: &self.source_result_digest,
            registration_digest: &self.registration_digest,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceFingerprint<'a> {
    proposal: &'a ObservationProposal,
    snapshot: &'a SloSnapshot,
    sli: &'a SliEvidence,
    error_budget: &'a ErrorBudgetEvidence,
    monitor_transitions: &'a MonitorTransitionEvidence,
    corrections: &'a CorrectionMetadata,
    downtime: &'a DowntimeMetadata,
    projection: EvidenceProjection,
    classification: EvidenceClassification,
    native: bool,
    connected: bool,
    absence_is_success: bool,
    source_result_digest: &'a str,
    registration_digest: &'a str,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationReceiptStatus {
    Recorded,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservationReceipt {
    pub evidence: SloEvidenceReading,
    pub status: ObservationReceiptStatus,
    pub durable: bool,
    pub native: bool,
    pub connected: bool,
    pub receipt_digest: Digest,
}

impl ObservationReceipt {
    fn from_evidence(evidence: SloEvidenceReading) -> Self {
        let mut receipt = Self {
            native: evidence.native,
            connected: evidence.connected,
            evidence,
            status: ObservationReceiptStatus::Recorded,
            durable: false,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.computed_digest();
        receipt
    }

    pub fn validate(
        &self,
        scope: &DatadogSloScope,
        registration: &RegistrationReceipt,
    ) -> Result<(), DatadogSloError> {
        self.evidence.validate(scope, registration)?;
        if self.status != ObservationReceiptStatus::Recorded
            || self.durable
            || self.native != self.evidence.native
            || self.connected != self.evidence.connected
            || self.receipt_digest != self.computed_digest()
        {
            return Err(DatadogSloError::ReceiptTampered);
        }
        Ok(())
    }

    pub fn revoke(&mut self) {
        self.status = ObservationReceiptStatus::Revoked;
        self.receipt_digest = self.computed_digest();
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.receipt_digest
    }

    fn computed_digest(&self) -> Digest {
        canonical_digest(&ReceiptFingerprint {
            evidence: &self.evidence,
            status: self.status,
            durable: self.durable,
            native: self.native,
            connected: self.connected,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptFingerprint<'a> {
    evidence: &'a SloEvidenceReading,
    status: ObservationReceiptStatus,
    durable: bool,
    native: bool,
    connected: bool,
}

pub struct DatadogSloProvider<T = BlockedEnvDatadogSloTransport>
where
    T: DatadogSloTransport,
{
    transport: T,
    definition: DatadogSloOutcomePluginDefinition,
    scope: DatadogSloScope,
    secret_reference: SecretReference,
    registration: Arc<Mutex<RegistrationReceipt>>,
}

impl<T> fmt::Debug for DatadogSloProvider<T>
where
    T: DatadogSloTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatadogSloProvider")
            .field("transport", &self.transport)
            .field("definition", &self.definition)
            .field("scope", &self.scope)
            .field("secret_reference", &self.secret_reference)
            .field("registration", &"<redacted-registration>")
            .finish()
    }
}

impl<T> DatadogSloProvider<T>
where
    T: DatadogSloTransport,
{
    pub fn new(
        transport: T,
        scope: DatadogSloScope,
        secret_reference: SecretReference,
        registration_revision: u64,
    ) -> Result<Self, DatadogSloError> {
        let definition = DatadogSloOutcomePluginDefinition::layer1()?;
        scope.validate()?;
        if secret_reference.kind() != scope.secret_kind
            || secret_reference.revision() != scope.secret_revision
            || secret_reference.digest() != scope.secret_reference_digest
        {
            return Err(DatadogSloError::RegistrationMismatch);
        }
        let registration = definition.bind(scope.clone(), registration_revision)?;
        Ok(Self {
            transport,
            definition,
            scope,
            secret_reference,
            registration: Arc::new(Mutex::new(registration)),
        })
    }

    pub fn for_scope(
        transport: T,
        scope: DatadogSloScope,
        secret_reference: SecretReference,
        registration_revision: u64,
    ) -> Result<Self, DatadogSloError> {
        Self::new(transport, scope, secret_reference, registration_revision)
    }

    #[must_use]
    pub fn definition(&self) -> &DatadogSloOutcomePluginDefinition {
        &self.definition
    }

    #[must_use]
    pub fn scope(&self) -> &DatadogSloScope {
        &self.scope
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn registration(&self) -> Result<RegistrationReceipt, DatadogSloError> {
        self.registration
            .lock()
            .map(|registration| registration.clone())
            .map_err(|_| DatadogSloError::RegistrationRequired)
    }

    pub fn revoke(&self) -> Result<RevocationReceipt, DatadogSloError> {
        let mut registration = self
            .registration
            .lock()
            .map_err(|_| DatadogSloError::RegistrationRequired)?;
        Ok(registration.revoke())
    }

    pub fn compile_observation_proposal(
        &self,
        window: ObservationWindow,
    ) -> Result<ObservationProposal, DatadogSloError> {
        self.ensure_active_registration()?;
        ObservationProposal::from_scope(&self.scope, window)
    }

    /// Describe one exact SLO definition.  The request has no observation
    /// window because definition reads do not broaden the evidence window.
    pub fn describe_slo(&self) -> Result<SloSnapshot, DatadogSloError> {
        self.ensure_active_registration()?;
        let request = DatadogReadRequest::for_describe(&self.scope)?;
        let response = self.transport.read(&request)?;
        response.validate()?;
        if response.site != self.scope.site
            || response.api_host != self.scope.api_host
            || response.organization_id != self.scope.organization_id
            || response.snapshot.slo_id != self.scope.slo_id
            || response.snapshot.slo_type != self.scope.slo_type
            || response.snapshot.definition_digest != self.scope.definition_digest
            || response.snapshot.query_digest != self.scope.query_digest
        {
            return Err(DatadogSloError::RegistrationMismatch);
        }
        Ok(response.snapshot)
    }

    pub fn read_slo_evidence(
        &self,
        proposal: &ObservationProposal,
    ) -> Result<SloEvidenceReading, DatadogSloError> {
        let registration = self.active_registration()?;
        proposal.validate_against(&self.scope)?;
        let request = DatadogReadRequest::for_operation(
            DatadogReadOperation::ReadSloEvidence,
            &self.scope,
            proposal,
        )?;
        let response = self.transport.read(&request)?;
        SloEvidenceReading::from_response(
            &self.scope,
            &registration,
            proposal,
            response,
            self.transport.provenance(),
        )
    }

    pub fn read_slo_evidence_for(
        &self,
        window: ObservationWindow,
    ) -> Result<SloEvidenceReading, DatadogSloError> {
        let proposal = self.compile_observation_proposal(window)?;
        self.read_slo_evidence(&proposal)
    }

    pub fn record_observation_receipt(
        &self,
        evidence: SloEvidenceReading,
    ) -> Result<ObservationReceipt, DatadogSloError> {
        let registration = self.active_registration()?;
        evidence.validate(&self.scope, &registration)?;
        Ok(ObservationReceipt::from_evidence(evidence))
    }

    pub fn verify_outcome_evidence(
        &self,
        receipt: &ObservationReceipt,
    ) -> Result<EvidenceVerification, DatadogSloError> {
        let registration = self.active_registration()?;
        receipt.validate(&self.scope, &registration)?;
        Ok(EvidenceVerification {
            receipt_digest: receipt.receipt_digest.clone(),
            evidence_digest: receipt.evidence.evidence_digest.clone(),
            registration_digest: registration.registration_digest,
            verified: true,
            native: false,
            connected: false,
            adoptable: false,
        })
    }

    fn active_registration(&self) -> Result<RegistrationReceipt, DatadogSloError> {
        let registration = self
            .registration
            .lock()
            .map_err(|_| DatadogSloError::RegistrationRequired)?
            .clone();
        if !registration.is_active() {
            return Err(DatadogSloError::RegistrationRevoked);
        }
        registration.validate(&self.definition, &self.scope)?;
        Ok(registration)
    }

    fn ensure_active_registration(&self) -> Result<(), DatadogSloError> {
        self.active_registration().map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceVerification {
    pub receipt_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub verified: bool,
    pub native: bool,
    pub connected: bool,
    pub adoptable: bool,
}

pub struct SloOutcomeEvidenceService<T = BlockedEnvDatadogSloTransport>
where
    T: DatadogSloTransport,
{
    provider: DatadogSloProvider<T>,
}

impl<T> fmt::Debug for SloOutcomeEvidenceService<T>
where
    T: DatadogSloTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SloOutcomeEvidenceService")
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T> SloOutcomeEvidenceService<T>
where
    T: DatadogSloTransport,
{
    pub fn new(provider: DatadogSloProvider<T>) -> Self {
        Self { provider }
    }

    #[must_use]
    pub fn provider(&self) -> &DatadogSloProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn definition(&self) -> &DatadogSloOutcomePluginDefinition {
        self.provider.definition()
    }

    pub fn describe_slo(&self) -> Result<SloSnapshot, DatadogSloError> {
        self.provider.describe_slo()
    }

    pub fn compile_observation_proposal(
        &self,
        window: ObservationWindow,
    ) -> Result<ObservationProposal, DatadogSloError> {
        self.provider.compile_observation_proposal(window)
    }

    pub fn read_slo_evidence(
        &self,
        proposal: &ObservationProposal,
    ) -> Result<SloEvidenceReading, DatadogSloError> {
        self.provider.read_slo_evidence(proposal)
    }

    pub fn record_observation_receipt(
        &self,
        evidence: SloEvidenceReading,
    ) -> Result<ObservationReceipt, DatadogSloError> {
        self.provider.record_observation_receipt(evidence)
    }

    pub fn verify_outcome_evidence(
        &self,
        receipt: &ObservationReceipt,
    ) -> Result<EvidenceVerification, DatadogSloError> {
        self.provider.verify_outcome_evidence(receipt)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutcomeEvidenceProposal {
    pub consumer_id: String,
    pub service_id: String,
    pub version: PluginVersion,
    pub site: String,
    pub api_host: String,
    pub organization_id: String,
    pub slo_id: String,
    pub slo_type: SloType,
    pub definition_digest: Digest,
    pub query_digest: Digest,
    pub window: ObservationWindow,
    pub project_id: String,
    pub deployment: DeploymentBinding,
    pub release: ReleaseBinding,
    pub mission: MissionBinding,
    pub policy_revision: u64,
    pub projection: EvidenceProjection,
    pub sli: Option<SliEvidence>,
    pub error_budget: Option<ErrorBudgetEvidence>,
    pub monitor_transitions: Option<MonitorTransitionEvidence>,
    pub corrections: Option<CorrectionMetadata>,
    pub downtime: Option<DowntimeMetadata>,
    pub classification: EvidenceClassification,
    pub native: bool,
    pub connected: bool,
    pub absence_is_success: bool,
    pub source_result_digest: Option<Digest>,
    pub registration_digest: Digest,
    pub blocker_code: Option<String>,
    pub proposal_digest: Digest,
}

impl OutcomeEvidenceProposal {
    fn from_receipt(receipt: &ObservationReceipt, verification: &EvidenceVerification) -> Self {
        let evidence = &receipt.evidence;
        let mut proposal = Self {
            consumer_id: MISSION_SLO_OUTCOME_CONSUMER_ID.into(),
            service_id: SLO_OUTCOME_EVIDENCE_SERVICE_ID.into(),
            version: PluginVersion::V1,
            site: evidence.proposal.site.clone(),
            api_host: evidence.proposal.api_host.clone(),
            organization_id: evidence.proposal.organization_id.clone(),
            slo_id: evidence.proposal.slo_id.clone(),
            slo_type: evidence.proposal.slo_type,
            definition_digest: evidence.proposal.definition_digest.clone(),
            query_digest: evidence.proposal.query_digest.clone(),
            window: evidence.proposal.window.clone(),
            project_id: evidence.proposal.project_id.clone(),
            deployment: evidence.proposal.deployment.clone(),
            release: evidence.proposal.release.clone(),
            mission: evidence.proposal.mission.clone(),
            policy_revision: evidence.proposal.policy_revision,
            projection: evidence.projection,
            sli: Some(evidence.sli.clone()),
            error_budget: Some(evidence.error_budget.clone()),
            monitor_transitions: Some(evidence.monitor_transitions.clone()),
            corrections: Some(evidence.corrections.clone()),
            downtime: Some(evidence.downtime.clone()),
            classification: evidence.classification,
            native: evidence.native,
            connected: evidence.connected,
            absence_is_success: false,
            source_result_digest: Some(evidence.source_result_digest.clone()),
            registration_digest: verification.registration_digest.clone(),
            blocker_code: None,
            proposal_digest: String::new(),
        };
        proposal.proposal_digest = proposal.computed_digest();
        proposal
    }

    fn provider_unknown(
        proposal: &ObservationProposal,
        registration_digest: Digest,
        blocker_code: String,
    ) -> Self {
        let mut outcome = Self {
            consumer_id: MISSION_SLO_OUTCOME_CONSUMER_ID.into(),
            service_id: SLO_OUTCOME_EVIDENCE_SERVICE_ID.into(),
            version: PluginVersion::V1,
            site: proposal.site.clone(),
            api_host: proposal.api_host.clone(),
            organization_id: proposal.organization_id.clone(),
            slo_id: proposal.slo_id.clone(),
            slo_type: proposal.slo_type,
            definition_digest: proposal.definition_digest.clone(),
            query_digest: proposal.query_digest.clone(),
            window: proposal.window.clone(),
            project_id: proposal.project_id.clone(),
            deployment: proposal.deployment.clone(),
            release: proposal.release.clone(),
            mission: proposal.mission.clone(),
            policy_revision: proposal.policy_revision,
            projection: EvidenceProjection::ProviderUnknown,
            sli: None,
            error_budget: None,
            monitor_transitions: None,
            corrections: None,
            downtime: None,
            classification: EvidenceClassification::BlockedEnv,
            native: false,
            connected: false,
            absence_is_success: false,
            source_result_digest: None,
            registration_digest,
            blocker_code: Some(blocker_code),
            proposal_digest: String::new(),
        };
        outcome.proposal_digest = outcome.computed_digest();
        outcome
    }

    pub fn validate(&self) -> Result<(), DatadogSloError> {
        validate_identifier(&self.consumer_id, "consumer")?;
        validate_identifier(&self.service_id, "service")?;
        validate_identifier(&self.site, "site")?;
        validate_host(&self.api_host)?;
        validate_identifier(&self.organization_id, "organization")?;
        validate_identifier(&self.slo_id, "SLO id")?;
        validate_digest(&self.definition_digest, "definition")?;
        validate_digest(&self.query_digest, "query")?;
        self.window.validate()?;
        self.deployment.validate("deployment")?;
        self.release.validate("release")?;
        self.mission.validate("mission")?;
        validate_digest(&self.registration_digest, "registration")?;
        if let Some(source_result_digest) = &self.source_result_digest {
            validate_digest(source_result_digest, "source result")?;
        }
        if self.consumer_id != MISSION_SLO_OUTCOME_CONSUMER_ID
            || self.service_id != SLO_OUTCOME_EVIDENCE_SERVICE_ID
            || self.version != PluginVersion::V1
            || self.absence_is_success
            || self.native != self.classification.is_native()
            || self.connected != self.classification.is_connected()
            || self.proposal_digest != self.computed_digest()
        {
            return Err(DatadogSloError::ConsumerBindingMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    fn computed_digest(&self) -> Digest {
        canonical_digest(&OutcomeProposalFingerprint {
            consumer_id: &self.consumer_id,
            service_id: &self.service_id,
            version: self.version,
            site: &self.site,
            api_host: &self.api_host,
            organization_id: &self.organization_id,
            slo_id: &self.slo_id,
            slo_type: self.slo_type,
            definition_digest: &self.definition_digest,
            query_digest: &self.query_digest,
            window: &self.window,
            project_id: &self.project_id,
            deployment: &self.deployment,
            release: &self.release,
            mission: &self.mission,
            policy_revision: self.policy_revision,
            projection: self.projection,
            sli: self.sli.as_ref(),
            error_budget: self.error_budget.as_ref(),
            monitor_transitions: self.monitor_transitions.as_ref(),
            corrections: self.corrections.as_ref(),
            downtime: self.downtime.as_ref(),
            classification: self.classification,
            native: self.native,
            connected: self.connected,
            absence_is_success: self.absence_is_success,
            source_result_digest: self.source_result_digest.as_deref(),
            registration_digest: &self.registration_digest,
            blocker_code: self.blocker_code.as_deref(),
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OutcomeProposalFingerprint<'a> {
    consumer_id: &'a str,
    service_id: &'a str,
    version: PluginVersion,
    site: &'a str,
    api_host: &'a str,
    organization_id: &'a str,
    slo_id: &'a str,
    slo_type: SloType,
    definition_digest: &'a str,
    query_digest: &'a str,
    window: &'a ObservationWindow,
    project_id: &'a str,
    deployment: &'a DeploymentBinding,
    release: &'a ReleaseBinding,
    mission: &'a MissionBinding,
    policy_revision: u64,
    projection: EvidenceProjection,
    sli: Option<&'a SliEvidence>,
    error_budget: Option<&'a ErrorBudgetEvidence>,
    monitor_transitions: Option<&'a MonitorTransitionEvidence>,
    corrections: Option<&'a CorrectionMetadata>,
    downtime: Option<&'a DowntimeMetadata>,
    classification: EvidenceClassification,
    native: bool,
    connected: bool,
    absence_is_success: bool,
    source_result_digest: Option<&'a str>,
    registration_digest: &'a str,
    blocker_code: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MissionSloOutcomeConsumer;

pub type MissionOutcomeEvidenceConsumer = MissionSloOutcomeConsumer;

impl MissionSloOutcomeConsumer {
    #[must_use]
    pub fn definition(&self) -> MissionSloOutcomeConsumerDefinition {
        MissionSloOutcomeConsumerDefinition {
            id: MISSION_SLO_OUTCOME_CONSUMER_ID.into(),
            service_id: SLO_OUTCOME_EVIDENCE_SERVICE_ID.into(),
            version: PluginVersion::V1,
            kind: "mission_outcome_evidence_proposal".into(),
            binding: vec![
                "site".into(),
                "api_host".into(),
                "organization_id".into(),
                "slo_id".into(),
                "slo_type".into(),
                "definition_digest".into(),
                "query_digest".into(),
                "observation_window".into(),
                "project_id".into(),
                "deployment_id".into(),
                "deployment_revision".into(),
                "release_id".into(),
                "release_revision".into(),
                "mission_id".into(),
                "mission_revision".into(),
                "registration_digest".into(),
                "source_result_digest".into(),
                "policy_revision".into(),
            ],
        }
    }

    pub fn consume(
        &self,
        receipt: &ObservationReceipt,
        verification: &EvidenceVerification,
    ) -> Result<OutcomeEvidenceProposal, DatadogSloError> {
        if !verification.verified
            || verification.receipt_digest != receipt.receipt_digest
            || verification.evidence_digest != receipt.evidence.evidence_digest
            || verification.registration_digest != receipt.evidence.registration_digest
            || verification.native
            || verification.connected
            || verification.adoptable
        {
            return Err(DatadogSloError::ConsumerBindingMismatch);
        }
        let proposal = OutcomeEvidenceProposal::from_receipt(receipt, verification);
        proposal.validate()?;
        Ok(proposal)
    }

    pub fn propose_outcome_evidence(
        &self,
        receipt: &ObservationReceipt,
        verification: &EvidenceVerification,
    ) -> Result<OutcomeEvidenceProposal, DatadogSloError> {
        self.consume(receipt, verification)
    }

    pub fn provider_unknown(
        &self,
        proposal: &ObservationProposal,
        registration_digest: Digest,
        error: &DatadogTransportError,
    ) -> Result<OutcomeEvidenceProposal, DatadogSloError> {
        proposal.window.validate()?;
        validate_digest(&registration_digest, "registration")?;
        let outcome = OutcomeEvidenceProposal::provider_unknown(
            proposal,
            registration_digest,
            transport_error_code(error),
        );
        outcome.validate()?;
        Ok(outcome)
    }
}

fn transport_error_code(error: &DatadogTransportError) -> String {
    match error {
        DatadogTransportError::BlockedEnv => "BLOCKED_ENV".into(),
        DatadogTransportError::Unauthorized401 => "HTTP_401".into(),
        DatadogTransportError::Forbidden403 => "HTTP_403".into(),
        DatadogTransportError::NotFound404 => "HTTP_404".into(),
        DatadogTransportError::RateLimited429 { .. } => "HTTP_429".into(),
        DatadogTransportError::Timeout => "TIMEOUT".into(),
        DatadogTransportError::Server5xx { status } => format!("HTTP_{status}"),
        DatadogTransportError::SiteMismatch => "SITE_MISMATCH".into(),
        DatadogTransportError::PublicBetaDrift => "PUBLIC_BETA_STATUS_DRIFT".into(),
        DatadogTransportError::InvalidResponse => "INVALID_RESPONSE".into(),
        DatadogTransportError::ResponseTampered => "RESPONSE_TAMPERED".into(),
    }
}
