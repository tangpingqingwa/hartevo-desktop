//! Public data model, scope fences, digests, and Layer-1 error boundaries.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_PAGES: u16 = 8;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_ALERT_INSTANCES: usize = 100;
pub const MAX_RULES: usize = 100;
pub const MAX_RULE_GROUPS: usize = 100;
pub const MAX_LABELS: usize = 32;
pub const MAX_LABEL_BYTES: usize = 256;
pub const MAX_NUMERIC_EVIDENCE: usize = 32;
pub const MAX_INCIDENT_TRANSITIONS: usize = 1_000;
pub const MAX_IDENTIFIER_BYTES: usize = 256;

pub type Digest = String;

/// Return a lowercase SHA-256 digest.
#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    format!("{:x}", Sha256::digest(bytes))
}

/// Hash a serde value using its canonical serialized representation.
#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("Grafana typed value serializes");
    sha256_digest(&bytes)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_digest(value: &str, label: &'static str) -> Result<(), AlertResultError> {
    if is_digest(value) {
        Ok(())
    } else {
        Err(AlertResultError::InvalidDigest { label })
    }
}

pub(crate) fn validate_identifier(
    value: &str,
    label: &'static str,
) -> Result<(), AlertResultError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(AlertResultError::InvalidIdentifier { label });
    }
    Ok(())
}

pub(crate) fn validate_bounded_text(
    value: &str,
    label: &'static str,
    maximum: usize,
) -> Result<(), AlertResultError> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(AlertResultError::InvalidText { label });
    }
    Ok(())
}

fn validate_host(value: &str) -> Result<String, AlertResultError> {
    let remainder = value
        .strip_prefix("https://")
        .ok_or(AlertResultError::InvalidApiHost)?;
    if remainder.is_empty()
        || remainder.contains('/')
        || remainder.contains('?')
        || remainder.contains('#')
        || remainder.contains(':')
        || remainder.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(AlertResultError::InvalidApiHost);
    }
    let host = remainder.to_ascii_lowercase();
    if host != "localhost"
        && !host.contains('.')
        && !host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return Err(AlertResultError::InvalidApiHost);
    }
    if host.starts_with('.')
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
        return Err(AlertResultError::InvalidApiHost);
    }
    Ok(format!("https://{host}"))
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    ServiceAccountToken,
}

impl SecretKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ServiceAccountToken => "service_account_token",
        }
    }
}

/// An opaque host-owned reference to a Grafana service-account token.
///
/// The opaque identifier is intentionally private and this type does not
/// implement serialization or Display. Only a digest of the reference can
/// enter a proposal, registration, request, or evidence record.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    opaque_id: String,
    revision: u64,
}

impl SecretReference {
    pub fn service_account_token(
        opaque_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, AlertResultError> {
        let opaque_id = opaque_id.into();
        if revision == 0
            || opaque_id.is_empty()
            || opaque_id.len() > MAX_IDENTIFIER_BYTES
            || opaque_id.trim() != opaque_id
            || opaque_id.chars().any(char::is_control)
        {
            return Err(AlertResultError::InvalidIdentifier {
                label: "service-account-token secret reference",
            });
        }
        Ok(Self {
            kind: SecretKind::ServiceAccountToken,
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
                "grafana-secret-reference|{}|{}|{}",
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

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityBinding {
    id: String,
    revision: u64,
}

impl IdentityBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, AlertResultError> {
        let id = id.into();
        validate_identifier(&id, "identity")?;
        if revision == 0 {
            return Err(AlertResultError::InvalidRevision { label: "identity" });
        }
        Ok(Self { id, revision })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

pub type ProjectBinding = IdentityBinding;
pub type MissionBinding = IdentityBinding;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudStack {
    id: String,
    revision: u64,
    api_host: String,
}

impl CloudStack {
    pub fn new(
        id: impl Into<String>,
        revision: u64,
        api_host: impl Into<String>,
    ) -> Result<Self, AlertResultError> {
        let id = id.into();
        let api_host = validate_host(&api_host.into())?;
        validate_identifier(&id, "Cloud stack")?;
        if revision == 0 {
            return Err(AlertResultError::InvalidRevision {
                label: "Cloud stack",
            });
        }
        Ok(Self {
            id,
            revision,
            api_host,
        })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn api_host(&self) -> &str {
        &self.api_host
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrafanaApiDefinition {
    http_api_revision: String,
    alerting_api_revision: String,
}

impl GrafanaApiDefinition {
    #[must_use]
    pub fn layer1() -> Self {
        Self {
            http_api_revision: "grafana-http-api-v1".into(),
            alerting_api_revision: "grafana-alerting-api-v1".into(),
        }
    }

    pub fn new(
        http_api_revision: impl Into<String>,
        alerting_api_revision: impl Into<String>,
    ) -> Result<Self, AlertResultError> {
        let http_api_revision = http_api_revision.into();
        let alerting_api_revision = alerting_api_revision.into();
        validate_identifier(&http_api_revision, "HTTP API revision")?;
        validate_identifier(&alerting_api_revision, "alerting API revision")?;
        Ok(Self {
            http_api_revision,
            alerting_api_revision,
        })
    }

    #[must_use]
    pub fn http_api_revision(&self) -> &str {
        &self.http_api_revision
    }

    #[must_use]
    pub fn alerting_api_revision(&self) -> &str {
        &self.alerting_api_revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GrafanaPermission {
    AlertRulesRead,
    RuleGroupsRead,
    AlertInstancesRead,
}

impl GrafanaPermission {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AlertRulesRead => "alert_rules_read",
            Self::RuleGroupsRead => "rule_groups_read",
            Self::AlertInstancesRead => "alert_instances_read",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrafanaPermissionSnapshot {
    permissions: Vec<GrafanaPermission>,
    revision: u64,
}

impl GrafanaPermissionSnapshot {
    pub fn least_privilege(revision: u64) -> Result<Self, AlertResultError> {
        Self::new(
            vec![
                GrafanaPermission::AlertRulesRead,
                GrafanaPermission::RuleGroupsRead,
                GrafanaPermission::AlertInstancesRead,
            ],
            revision,
        )
    }

    pub fn new(
        permissions: Vec<GrafanaPermission>,
        revision: u64,
    ) -> Result<Self, AlertResultError> {
        let snapshot = Self {
            permissions,
            revision,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn validate(&self) -> Result<(), AlertResultError> {
        if self.revision == 0
            || self.permissions.len() != 3
            || self.permissions.iter().collect::<BTreeSet<_>>().len() != 3
            || !self.has(GrafanaPermission::AlertRulesRead)
            || !self.has(GrafanaPermission::RuleGroupsRead)
            || !self.has(GrafanaPermission::AlertInstancesRead)
        {
            return Err(AlertResultError::InvalidPermissionSnapshot);
        }
        Ok(())
    }

    #[must_use]
    pub fn permissions(&self) -> &[GrafanaPermission] {
        &self.permissions
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn has(&self, permission: GrafanaPermission) -> bool {
        self.permissions.contains(&permission)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrafanaAlertScopeSpec {
    pub cloud_stack: CloudStack,
    pub organization: IdentityBinding,
    pub folder: IdentityBinding,
    pub rule: IdentityBinding,
    pub rule_group: IdentityBinding,
    pub alert_instance: IdentityBinding,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub deployment: IdentityBinding,
    pub release: IdentityBinding,
    pub api: GrafanaApiDefinition,
    pub permissions: GrafanaPermissionSnapshot,
    pub secret_reference: SecretReference,
}

impl GrafanaAlertScopeSpec {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cloud_stack: CloudStack,
        organization: IdentityBinding,
        folder: IdentityBinding,
        rule: IdentityBinding,
        rule_group: IdentityBinding,
        alert_instance: IdentityBinding,
        project: ProjectBinding,
        mission: MissionBinding,
        deployment: IdentityBinding,
        release: IdentityBinding,
        api: GrafanaApiDefinition,
        permissions: GrafanaPermissionSnapshot,
        secret_reference: SecretReference,
    ) -> Self {
        Self {
            cloud_stack,
            organization,
            folder,
            rule,
            rule_group,
            alert_instance,
            project,
            mission,
            deployment,
            release,
            api,
            permissions,
            secret_reference,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrafanaAlertScope {
    spec: GrafanaAlertScopeSpec,
    label_allowlist: BTreeSet<String>,
    redacted_label_keys: BTreeSet<String>,
}

impl GrafanaAlertScope {
    pub fn new(spec: GrafanaAlertScopeSpec) -> Result<Self, AlertResultError> {
        let scope = Self {
            spec,
            label_allowlist: default_label_allowlist(),
            redacted_label_keys: default_redacted_label_keys(),
        };
        scope.validate()?;
        Ok(scope)
    }

    #[must_use]
    pub fn with_label_allowlist(mut self, keys: impl IntoIterator<Item = String>) -> Self {
        self.label_allowlist = keys.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_redacted_label_keys(mut self, keys: impl IntoIterator<Item = String>) -> Self {
        self.redacted_label_keys = keys.into_iter().collect();
        self
    }

    pub fn validate(&self) -> Result<(), AlertResultError> {
        self.spec.permissions.validate()?;
        if self.label_allowlist.is_empty() || self.label_allowlist.len() > MAX_LABELS {
            return Err(AlertResultError::BoundExceeded {
                label: "label allowlist",
                maximum: MAX_LABELS,
            });
        }
        for key in self
            .label_allowlist
            .iter()
            .chain(self.redacted_label_keys.iter())
        {
            validate_identifier(key, "label key")?;
        }
        Ok(())
    }

    #[must_use]
    pub fn spec(&self) -> &GrafanaAlertScopeSpec {
        &self.spec
    }

    #[must_use]
    pub fn cloud_stack(&self) -> &CloudStack {
        &self.spec.cloud_stack
    }

    #[must_use]
    pub fn organization(&self) -> &IdentityBinding {
        &self.spec.organization
    }

    #[must_use]
    pub fn folder(&self) -> &IdentityBinding {
        &self.spec.folder
    }

    #[must_use]
    pub fn rule(&self) -> &IdentityBinding {
        &self.spec.rule
    }

    #[must_use]
    pub fn rule_group(&self) -> &IdentityBinding {
        &self.spec.rule_group
    }

    #[must_use]
    pub fn alert_instance(&self) -> &IdentityBinding {
        &self.spec.alert_instance
    }

    #[must_use]
    pub fn project(&self) -> &ProjectBinding {
        &self.spec.project
    }

    #[must_use]
    pub fn mission(&self) -> &MissionBinding {
        &self.spec.mission
    }

    #[must_use]
    pub fn deployment(&self) -> &IdentityBinding {
        &self.spec.deployment
    }

    #[must_use]
    pub fn release(&self) -> &IdentityBinding {
        &self.spec.release
    }

    #[must_use]
    pub fn api(&self) -> &GrafanaApiDefinition {
        &self.spec.api
    }

    #[must_use]
    pub fn permissions(&self) -> &GrafanaPermissionSnapshot {
        &self.spec.permissions
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.spec.secret_reference
    }

    #[must_use]
    pub fn label_allowlist(&self) -> &BTreeSet<String> {
        &self.label_allowlist
    }

    #[must_use]
    pub fn is_redacted_label_key(&self, key: &str) -> bool {
        self.redacted_label_keys.contains(key)
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        sha256_digest(
            b"grafana.alert-result|GrafanaProvider|1.0.0|grafana-alert-result-provider-v1",
        )
    }

    #[must_use]
    pub fn api_digest(&self) -> Digest {
        self.spec.api.digest()
    }

    #[must_use]
    pub fn permission_digest(&self) -> Digest {
        self.spec.permissions.digest()
    }

    #[must_use]
    pub fn revision_digest(&self) -> Digest {
        canonical_digest(&(
            self.spec.cloud_stack.revision(),
            self.spec.organization.revision(),
            self.spec.folder.revision(),
            self.spec.rule.revision(),
            self.spec.rule_group.revision(),
            self.spec.alert_instance.revision(),
            self.spec.project.revision(),
            self.spec.mission.revision(),
            self.spec.deployment.revision(),
            self.spec.release.revision(),
            self.spec.permissions.revision(),
            self.spec.secret_reference.revision(),
        ))
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        let fingerprint = (
            self.spec.cloud_stack.digest(),
            self.spec.organization.digest(),
            self.spec.folder.digest(),
            self.spec.rule.digest(),
            self.spec.rule_group.digest(),
            self.spec.alert_instance.digest(),
            self.spec.project.digest(),
            self.spec.mission.digest(),
            self.spec.deployment.digest(),
            self.spec.release.digest(),
            self.api_digest(),
            self.permission_digest(),
            self.revision_digest(),
            self.spec.secret_reference.digest(),
            self.label_allowlist.clone(),
            self.redacted_label_keys.clone(),
        );
        canonical_digest(&fingerprint)
    }
}

fn default_label_allowlist() -> BTreeSet<String> {
    [
        "alertname",
        "environment",
        "folder",
        "grafana_folder",
        "instance",
        "namespace",
        "rule_uid",
        "service",
        "severity",
        "team",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn default_redacted_label_keys() -> BTreeSet<String> {
    ["api_key", "authorization", "password", "secret", "token"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GrafanaAlertResultErrorCode {
    InvalidIdentifier,
    InvalidText,
    InvalidDigest,
    InvalidApiHost,
    InvalidRevision,
    InvalidScope,
    InvalidPermissionSnapshot,
    InvalidApiDefinition,
    BoundExceeded,
    UnsupportedOperation,
    ForbiddenOperation,
    InvalidPage,
    RegistrationRequired,
    RegistrationRevoked,
    RegistrationMismatch,
    ProposalBindingMismatch,
    ScopeMismatch,
    MissionStale,
    EvaluationTimestampRegression,
    ReplayDetected,
    RequestTampered,
    ResponseTampered,
    MalformedResponse,
    RedactionViolation,
    ConsumerBindingMismatch,
    NativeClassificationMismatch,
    Transport,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GrafanaTransportError {
    #[error("BLOCKED_ENV: native Grafana credentials or HTTPS transport are unavailable")]
    BlockedEnv,
    #[error("Grafana returned HTTP 401")]
    Unauthorized401,
    #[error("Grafana returned HTTP 403")]
    Forbidden403,
    #[error("Grafana returned HTTP 404")]
    NotFound404,
    #[error("Grafana returned HTTP 409")]
    Conflict409,
    #[error("Grafana returned HTTP 429")]
    RateLimited429 { retry_after_seconds: Option<u64> },
    #[error("Grafana request timed out")]
    Timeout,
    #[error("Grafana returned HTTP {status}")]
    Server5xx { status: u16 },
    #[error("Grafana transport is unavailable")]
    TransportUnavailable,
    #[error("Grafana response was malformed or exceeded the bounded response contract")]
    MalformedResponse,
    #[error("Grafana response was partial and could not satisfy the exact scope")]
    PartialResponse,
    #[error("Grafana request path is not in the read allowlist")]
    NotAllowlistedPath,
    #[error("Grafana response request binding was tampered")]
    RequestTampered,
    #[error("Grafana response digest was tampered")]
    ResponseTampered,
    #[error("Grafana response scope or revision binding drifted")]
    ScopeMismatch,
}

impl GrafanaTransportError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::BlockedEnv => "BLOCKED_ENV",
            Self::Unauthorized401 => "HTTP_401",
            Self::Forbidden403 => "HTTP_403",
            Self::NotFound404 => "HTTP_404",
            Self::Conflict409 => "HTTP_409",
            Self::RateLimited429 { .. } => "HTTP_429",
            Self::Timeout => "TIMEOUT",
            Self::Server5xx { .. } => "HTTP_5XX",
            Self::TransportUnavailable => "TRANSPORT_UNAVAILABLE",
            Self::MalformedResponse => "MALFORMED_RESPONSE",
            Self::PartialResponse => "PARTIAL_RESPONSE",
            Self::NotAllowlistedPath => "NOT_ALLOWLISTED_PATH",
            Self::RequestTampered => "REQUEST_TAMPERED",
            Self::ResponseTampered => "RESPONSE_TAMPERED",
            Self::ScopeMismatch => "SCOPE_MISMATCH",
        }
    }

    #[must_use]
    pub const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited429 { .. }
                | Self::Timeout
                | Self::Server5xx { .. }
                | Self::TransportUnavailable
        )
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AlertResultError {
    #[error("{label} is empty, invalid, or too long")]
    InvalidIdentifier { label: &'static str },
    #[error("{label} is empty, contains controls, or exceeds its bound")]
    InvalidText { label: &'static str },
    #[error("{label} is not a lowercase SHA-256 digest")]
    InvalidDigest { label: &'static str },
    #[error("the Grafana API host must be an HTTPS origin")]
    InvalidApiHost,
    #[error("{label} must be a positive revision")]
    InvalidRevision { label: &'static str },
    #[error("the Grafana alert-result scope is invalid")]
    InvalidScope,
    #[error("the Grafana permission snapshot is invalid or over-privileged")]
    InvalidPermissionSnapshot,
    #[error("the Grafana API definition is invalid")]
    InvalidApiDefinition,
    #[error("the bounded list {label} exceeded {maximum} items")]
    BoundExceeded { label: &'static str, maximum: usize },
    #[error("the requested Grafana operation is unsupported")]
    UnsupportedOperation,
    #[error("the requested Grafana operation is outside the read allowlist")]
    ForbiddenOperation,
    #[error("the Grafana page is invalid or exceeds the bounded page policy")]
    InvalidPage,
    #[error("a registration is required")]
    RegistrationRequired,
    #[error("the Grafana registration has been revoked")]
    RegistrationRevoked,
    #[error("the Grafana registration does not match the exact scope or revision")]
    RegistrationMismatch,
    #[error("the alert-result proposal is not bound to the active registration")]
    ProposalBindingMismatch,
    #[error("the Grafana response does not match the exact scope")]
    ScopeMismatch,
    #[error("the Grafana response Cloud stack drifted")]
    CloudStackMismatch,
    #[error("the Grafana response organization drifted")]
    OrganizationMismatch,
    #[error("the Grafana response folder drifted")]
    FolderMismatch,
    #[error("the Grafana response alert rule drifted")]
    RuleMismatch,
    #[error("the Grafana response rule group drifted")]
    RuleGroupMismatch,
    #[error("the Grafana response alert instance drifted")]
    AlertInstanceMismatch,
    #[error("the Project binding drifted")]
    ProjectMismatch,
    #[error("the Mission binding is stale")]
    MissionStale,
    #[error("the deployment binding drifted")]
    DeploymentMismatch,
    #[error("the release binding drifted")]
    ReleaseMismatch,
    #[error("an alert evaluation timestamp regressed")]
    EvaluationTimestampRegression,
    #[error("the bounded response was replayed")]
    ReplayDetected,
    #[error("the bounded request fingerprint was tampered")]
    RequestTampered,
    #[error("the bounded response fingerprint was tampered")]
    ResponseTampered,
    #[error("the Grafana response was malformed")]
    MalformedResponse,
    #[error("a redacted provider value crossed the evidence boundary")]
    RedactionViolation,
    #[error("the Mission consumer binding is invalid")]
    ConsumerBindingMismatch,
    #[error("fixture, recording, fake, loopback, or BLOCKED_ENV evidence cannot be native")]
    NativeClassificationMismatch,
    #[error("Grafana transport failed: {0}")]
    Transport(#[from] GrafanaTransportError),
}

impl AlertResultError {
    #[must_use]
    pub const fn code(&self) -> GrafanaAlertResultErrorCode {
        match self {
            Self::InvalidIdentifier { .. } => GrafanaAlertResultErrorCode::InvalidIdentifier,
            Self::InvalidText { .. } => GrafanaAlertResultErrorCode::InvalidText,
            Self::InvalidDigest { .. } => GrafanaAlertResultErrorCode::InvalidDigest,
            Self::InvalidApiHost => GrafanaAlertResultErrorCode::InvalidApiHost,
            Self::InvalidRevision { .. } => GrafanaAlertResultErrorCode::InvalidRevision,
            Self::InvalidScope => GrafanaAlertResultErrorCode::InvalidScope,
            Self::InvalidPermissionSnapshot => {
                GrafanaAlertResultErrorCode::InvalidPermissionSnapshot
            }
            Self::InvalidApiDefinition => GrafanaAlertResultErrorCode::InvalidApiDefinition,
            Self::BoundExceeded { .. } => GrafanaAlertResultErrorCode::BoundExceeded,
            Self::UnsupportedOperation => GrafanaAlertResultErrorCode::UnsupportedOperation,
            Self::ForbiddenOperation => GrafanaAlertResultErrorCode::ForbiddenOperation,
            Self::InvalidPage => GrafanaAlertResultErrorCode::InvalidPage,
            Self::RegistrationRequired => GrafanaAlertResultErrorCode::RegistrationRequired,
            Self::RegistrationRevoked => GrafanaAlertResultErrorCode::RegistrationRevoked,
            Self::RegistrationMismatch => GrafanaAlertResultErrorCode::RegistrationMismatch,
            Self::ProposalBindingMismatch => GrafanaAlertResultErrorCode::ProposalBindingMismatch,
            Self::ScopeMismatch
            | Self::CloudStackMismatch
            | Self::OrganizationMismatch
            | Self::FolderMismatch
            | Self::RuleMismatch
            | Self::RuleGroupMismatch
            | Self::AlertInstanceMismatch
            | Self::ProjectMismatch
            | Self::DeploymentMismatch
            | Self::ReleaseMismatch => GrafanaAlertResultErrorCode::ScopeMismatch,
            Self::MissionStale => GrafanaAlertResultErrorCode::MissionStale,
            Self::EvaluationTimestampRegression => {
                GrafanaAlertResultErrorCode::EvaluationTimestampRegression
            }
            Self::ReplayDetected => GrafanaAlertResultErrorCode::ReplayDetected,
            Self::RequestTampered => GrafanaAlertResultErrorCode::RequestTampered,
            Self::ResponseTampered => GrafanaAlertResultErrorCode::ResponseTampered,
            Self::MalformedResponse => GrafanaAlertResultErrorCode::MalformedResponse,
            Self::RedactionViolation => GrafanaAlertResultErrorCode::RedactionViolation,
            Self::ConsumerBindingMismatch => GrafanaAlertResultErrorCode::ConsumerBindingMismatch,
            Self::NativeClassificationMismatch => {
                GrafanaAlertResultErrorCode::NativeClassificationMismatch
            }
            Self::Transport(_) => GrafanaAlertResultErrorCode::Transport,
        }
    }
}

pub type GrafanaAlertResultError = AlertResultError;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GrafanaRegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrafanaRegistration {
    plugin_version: PluginVersion,
    contract_digest: Digest,
    provider_digest: Digest,
    api_digest: Digest,
    permission_digest: Digest,
    scope_digest: Digest,
    revision_digest: Digest,
    registration_digest: Digest,
    state: GrafanaRegistrationState,
    revocation_digest: Option<Digest>,
}

impl GrafanaRegistration {
    pub fn new(
        scope: &GrafanaAlertScope,
        contract_digest: Digest,
        plugin_version: PluginVersion,
    ) -> Result<Self, AlertResultError> {
        validate_digest(&contract_digest, "contract")?;
        scope.validate()?;
        let provider_digest = scope.provider_digest();
        let api_digest = scope.api_digest();
        let permission_digest = scope.permission_digest();
        let scope_digest = scope.digest();
        let revision_digest = scope.revision_digest();
        let registration_digest = canonical_digest(&(
            plugin_version,
            contract_digest.clone(),
            provider_digest.clone(),
            api_digest.clone(),
            permission_digest.clone(),
            scope_digest.clone(),
            revision_digest.clone(),
        ));
        Ok(Self {
            plugin_version,
            contract_digest,
            provider_digest,
            api_digest,
            permission_digest,
            scope_digest,
            revision_digest,
            registration_digest,
            state: GrafanaRegistrationState::Active,
            revocation_digest: None,
        })
    }

    pub fn validate_against(
        &self,
        scope: &GrafanaAlertScope,
        contract_digest: &str,
        plugin_version: PluginVersion,
    ) -> Result<(), AlertResultError> {
        if self.state == GrafanaRegistrationState::Revoked {
            return Err(AlertResultError::RegistrationRevoked);
        }
        let expected = Self::new(scope, contract_digest.to_owned(), plugin_version)?;
        if self.plugin_version != expected.plugin_version
            || self.contract_digest != expected.contract_digest
            || self.provider_digest != expected.provider_digest
            || self.api_digest != expected.api_digest
            || self.permission_digest != expected.permission_digest
            || self.scope_digest != expected.scope_digest
            || self.revision_digest != expected.revision_digest
            || self.registration_digest != expected.registration_digest
        {
            return Err(AlertResultError::RegistrationMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn plugin_version(&self) -> PluginVersion {
        self.plugin_version
    }

    #[must_use]
    pub fn contract_digest(&self) -> &str {
        &self.contract_digest
    }

    #[must_use]
    pub fn provider_digest(&self) -> &str {
        &self.provider_digest
    }

    #[must_use]
    pub fn api_digest(&self) -> &str {
        &self.api_digest
    }

    #[must_use]
    pub fn permission_digest(&self) -> &str {
        &self.permission_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    #[must_use]
    pub fn revision_digest(&self) -> &str {
        &self.revision_digest
    }

    #[must_use]
    pub fn registration_digest(&self) -> &str {
        &self.registration_digest
    }

    #[must_use]
    pub const fn state(&self) -> GrafanaRegistrationState {
        self.state
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.state, GrafanaRegistrationState::Active)
    }

    pub fn revoke(
        &mut self,
        reason: impl AsRef<str>,
    ) -> Result<GrafanaRevocationReceipt, AlertResultError> {
        if !self.is_active() {
            return Err(AlertResultError::RegistrationRevoked);
        }
        validate_bounded_text(reason.as_ref(), "revocation reason", MAX_LABEL_BYTES)?;
        let revocation_digest =
            canonical_digest(&(self.registration_digest.clone(), reason.as_ref()));
        self.state = GrafanaRegistrationState::Revoked;
        self.revocation_digest = Some(revocation_digest.clone());
        Ok(GrafanaRevocationReceipt {
            registration_digest: self.registration_digest.clone(),
            revocation_digest,
            reason_digest: sha256_digest(reason.as_ref().as_bytes()),
        })
    }

    pub fn restore(&mut self) -> Result<(), AlertResultError> {
        if self.revocation_digest.is_none() {
            return Err(AlertResultError::RegistrationMismatch);
        }
        self.state = GrafanaRegistrationState::Active;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrafanaRevocationReceipt {
    pub registration_digest: Digest,
    pub revocation_digest: Digest,
    pub reason_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertResultReadOperation {
    DescribeAlertRule,
    ReadAlertRuleMetadata,
    ReadRuleGroupMetadata,
    ReadAlertInstances,
}

impl AlertResultReadOperation {
    #[must_use]
    pub const fn required_permission(self) -> GrafanaPermission {
        match self {
            Self::DescribeAlertRule | Self::ReadAlertRuleMetadata => {
                GrafanaPermission::AlertRulesRead
            }
            Self::ReadRuleGroupMetadata => GrafanaPermission::RuleGroupsRead,
            Self::ReadAlertInstances => GrafanaPermission::AlertInstancesRead,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DescribeAlertRule => "describe_alert_rule",
            Self::ReadAlertRuleMetadata => "read_alert_rule_metadata",
            Self::ReadRuleGroupMetadata => "read_rule_group_metadata",
            Self::ReadAlertInstances => "read_alert_instances",
        }
    }

    #[must_use]
    pub const fn is_rule(self) -> bool {
        matches!(self, Self::DescribeAlertRule | Self::ReadAlertRuleMetadata)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertResultProposal {
    pub operation: AlertResultReadOperation,
    pub page_size: u16,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub registration_digest: Digest,
    pub project: IdentityBinding,
    pub mission: IdentityBinding,
    pub deployment: IdentityBinding,
    pub release: IdentityBinding,
    pub proposal_digest: Digest,
}

impl AlertResultProposal {
    pub fn new(
        scope: &GrafanaAlertScope,
        registration: &GrafanaRegistration,
        operation: AlertResultReadOperation,
        page_size: u16,
    ) -> Result<Self, AlertResultError> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(AlertResultError::InvalidPage);
        }
        if !scope.permissions().has(operation.required_permission()) {
            return Err(AlertResultError::ForbiddenOperation);
        }
        let mut proposal = Self {
            operation,
            page_size,
            provider_digest: scope.provider_digest(),
            api_digest: scope.api_digest(),
            permission_digest: scope.permission_digest(),
            scope_digest: scope.digest(),
            revision_digest: scope.revision_digest(),
            registration_digest: registration.registration_digest().to_owned(),
            project: scope.project().clone(),
            mission: scope.mission().clone(),
            deployment: scope.deployment().clone(),
            release: scope.release().clone(),
            proposal_digest: String::new(),
        };
        proposal.proposal_digest = proposal.compute_digest();
        Ok(proposal)
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&(
            self.operation,
            self.page_size,
            &self.provider_digest,
            &self.api_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.revision_digest,
            &self.registration_digest,
            &self.project,
            &self.mission,
            &self.deployment,
            &self.release,
        ))
    }

    pub fn verify_integrity(&self) -> Result<(), AlertResultError> {
        validate_digest(&self.provider_digest, "provider")?;
        validate_digest(&self.api_digest, "API")?;
        validate_digest(&self.permission_digest, "permission")?;
        validate_digest(&self.scope_digest, "scope")?;
        validate_digest(&self.revision_digest, "revision")?;
        validate_digest(&self.registration_digest, "registration")?;
        validate_digest(&self.proposal_digest, "proposal")?;
        if self.proposal_digest != self.compute_digest() {
            return Err(AlertResultError::RequestTampered);
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        scope: &GrafanaAlertScope,
        registration: &GrafanaRegistration,
    ) -> Result<(), AlertResultError> {
        self.verify_integrity()?;
        if self.registration_digest != registration.registration_digest()
            || self.provider_digest != scope.provider_digest()
            || self.api_digest != scope.api_digest()
            || self.permission_digest != scope.permission_digest()
            || self.scope_digest != scope.digest()
            || self.revision_digest != scope.revision_digest()
            || self.project != *scope.project()
            || self.mission != *scope.mission()
            || self.deployment != *scope.deployment()
            || self.release != *scope.release()
        {
            return Err(AlertResultError::ProposalBindingMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.proposal_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowlistedLabel {
    pub key: String,
    pub value: String,
}

impl AllowlistedLabel {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Result<Self, AlertResultError> {
        let key = key.into();
        let value = value.into();
        validate_identifier(&key, "label key")?;
        validate_bounded_text(&value, "label value", MAX_LABEL_BYTES)?;
        Ok(Self { key, value })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NumericEvidenceDigest {
    pub name: String,
    pub value_digest: Digest,
}

impl NumericEvidenceDigest {
    pub fn from_value(name: impl Into<String>, value: &str) -> Result<Self, AlertResultError> {
        let name = name.into();
        validate_identifier(&name, "numeric evidence name")?;
        let value = value.trim();
        let parsed = value.parse::<f64>().ok();
        if value.is_empty()
            || value.len() > MAX_LABEL_BYTES
            || parsed.is_none()
            || !parsed.is_some_and(f64::is_finite)
        {
            return Err(AlertResultError::InvalidText {
                label: "numeric evidence value",
            });
        }
        Ok(Self {
            value_digest: sha256_digest(format!("grafana-numeric|{name}|{value}").as_bytes()),
            name,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertState {
    Normal,
    Pending,
    Alerting,
    Recovering,
    NoData,
    Error,
    Unknown,
}

impl AlertState {
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value.to_ascii_lowercase().replace(['-', ' '], "_").as_str() {
            "normal" | "ok" | "inactive" => Self::Normal,
            "pending" => Self::Pending,
            "alerting" | "firing" => Self::Alerting,
            "recovering" | "recovered" => Self::Recovering,
            "no_data" | "nodata" => Self::NoData,
            "error" | "err" => Self::Error,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn incident_state(self) -> IncidentState {
        match self {
            Self::Normal | Self::Recovering => IncidentState::Closed,
            Self::Pending | Self::Alerting => IncidentState::Open,
            Self::NoData | Self::Error | Self::Unknown => IncidentState::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentState {
    Closed,
    Open,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IncidentStateTransition {
    pub from: IncidentState,
    pub to: IncidentState,
    pub at: Option<DateTime<Utc>>,
    pub transition_digest: Digest,
}

impl IncidentStateTransition {
    #[must_use]
    pub fn new(from: IncidentState, to: IncidentState, at: Option<DateTime<Utc>>) -> Self {
        let transition_digest = canonical_digest(&(from, to, at));
        Self {
            from,
            to,
            at,
            transition_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertRuleMetadata {
    pub cloud_stack_id: String,
    pub organization_id: String,
    pub folder_id: String,
    pub rule_uid: String,
    pub rule_group_id: String,
    pub title: String,
    pub version: Option<u64>,
    pub updated_at: Option<DateTime<Utc>>,
    pub labels: Vec<AllowlistedLabel>,
    pub metadata_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleGroupMetadata {
    pub cloud_stack_id: String,
    pub organization_id: String,
    pub folder_id: String,
    pub rule_group_id: String,
    pub rule_uids: Vec<String>,
    pub interval_seconds: Option<u64>,
    pub version: Option<u64>,
    pub updated_at: Option<DateTime<Utc>>,
    pub metadata_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertInstanceObservation {
    pub cloud_stack_id: String,
    pub organization_id: String,
    pub folder_id: String,
    pub rule_uid: String,
    pub rule_group_id: String,
    pub alert_instance_id: String,
    pub state: AlertState,
    pub incident_state: IncidentState,
    pub evaluation_at: Option<DateTime<Utc>>,
    pub labels: Vec<AllowlistedLabel>,
    pub numeric_evidence: Vec<NumericEvidenceDigest>,
    pub observation_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClassification {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl EvidenceClassification {
    #[must_use]
    pub const fn native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn connected(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    #[must_use]
    pub const fn native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn connected(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrafanaErrorProjection {
    pub code: String,
    pub http_status: Option<u16>,
    pub retryable: bool,
    pub error_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertResultProjection {
    pub states: Vec<AlertState>,
    pub partial: bool,
    pub evaluation_timestamps: Vec<DateTime<Utc>>,
    pub numeric_evidence_digests: Vec<Digest>,
    pub incident_transitions: Vec<IncidentStateTransition>,
    pub provider_error: Option<GrafanaErrorProjection>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertResultEvidence {
    pub operation: AlertResultReadOperation,
    pub rule: Option<AlertRuleMetadata>,
    pub rule_group: Option<RuleGroupMetadata>,
    pub alert_instances: Vec<AlertInstanceObservation>,
    pub projection: AlertResultProjection,
    pub partial: bool,
    pub observed_at: DateTime<Utc>,
    pub response_status: u16,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub proposal_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub provenance: EvidenceClassification,
    pub connected: bool,
    pub native: bool,
    pub proposal_only: bool,
    pub evidence_digest: Digest,
}

pub(crate) struct AlertResultEvidenceParts {
    pub operation: AlertResultReadOperation,
    pub rule: Option<AlertRuleMetadata>,
    pub rule_group: Option<RuleGroupMetadata>,
    pub alert_instances: Vec<AlertInstanceObservation>,
    pub projection: AlertResultProjection,
    pub partial: bool,
    pub observed_at: DateTime<Utc>,
    pub response_status: u16,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub proposal_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub provenance: EvidenceClassification,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AlertResultEvidenceFingerprint<'a> {
    operation: AlertResultReadOperation,
    rule: &'a Option<AlertRuleMetadata>,
    rule_group: &'a Option<RuleGroupMetadata>,
    alert_instances: &'a [AlertInstanceObservation],
    projection: &'a AlertResultProjection,
    partial: bool,
    observed_at: DateTime<Utc>,
    response_status: u16,
    request_digest: &'a str,
    response_digest: &'a str,
    proposal_digest: &'a str,
    registration_digest: &'a str,
    provider_digest: &'a str,
    api_digest: &'a str,
    permission_digest: &'a str,
    scope_digest: &'a str,
    revision_digest: &'a str,
    provenance: EvidenceClassification,
    connected: bool,
    native: bool,
    proposal_only: bool,
}

impl AlertResultEvidence {
    pub(crate) fn from_parts(parts: AlertResultEvidenceParts) -> Self {
        let mut evidence = Self {
            operation: parts.operation,
            rule: parts.rule,
            rule_group: parts.rule_group,
            alert_instances: parts.alert_instances,
            projection: parts.projection,
            partial: parts.partial,
            observed_at: parts.observed_at,
            response_status: parts.response_status,
            request_digest: parts.request_digest,
            response_digest: parts.response_digest,
            proposal_digest: parts.proposal_digest,
            registration_digest: parts.registration_digest,
            provider_digest: parts.provider_digest,
            api_digest: parts.api_digest,
            permission_digest: parts.permission_digest,
            scope_digest: parts.scope_digest,
            revision_digest: parts.revision_digest,
            provenance: parts.provenance,
            connected: false,
            native: false,
            proposal_only: true,
            evidence_digest: String::new(),
        };
        evidence.evidence_digest = evidence.compute_digest();
        evidence
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&AlertResultEvidenceFingerprint {
            operation: self.operation,
            rule: &self.rule,
            rule_group: &self.rule_group,
            alert_instances: &self.alert_instances,
            projection: &self.projection,
            partial: self.partial,
            observed_at: self.observed_at,
            response_status: self.response_status,
            request_digest: &self.request_digest,
            response_digest: &self.response_digest,
            proposal_digest: &self.proposal_digest,
            registration_digest: &self.registration_digest,
            provider_digest: &self.provider_digest,
            api_digest: &self.api_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            revision_digest: &self.revision_digest,
            provenance: self.provenance,
            connected: self.connected,
            native: self.native,
            proposal_only: self.proposal_only,
        })
    }

    pub fn verify_integrity(&self) -> Result<(), AlertResultError> {
        for (value, label) in [
            (&self.request_digest, "request"),
            (&self.response_digest, "response"),
            (&self.proposal_digest, "proposal"),
            (&self.registration_digest, "registration"),
            (&self.provider_digest, "provider"),
            (&self.api_digest, "API"),
            (&self.permission_digest, "permission"),
            (&self.scope_digest, "scope"),
            (&self.revision_digest, "revision"),
            (&self.evidence_digest, "evidence"),
        ] {
            validate_digest(value, label)?;
        }
        if self.connected || self.native || !self.proposal_only {
            return Err(AlertResultError::NativeClassificationMismatch);
        }
        if self.evidence_digest != self.compute_digest() {
            return Err(AlertResultError::ResponseTampered);
        }
        if self.alert_instances.len() > MAX_ALERT_INSTANCES
            || self.projection.evaluation_timestamps.len() > MAX_ALERT_INSTANCES
            || self.projection.incident_transitions.len() > MAX_INCIDENT_TRANSITIONS
        {
            return Err(AlertResultError::BoundExceeded {
                label: "alert-result evidence",
                maximum: MAX_ALERT_INSTANCES,
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn state(&self) -> AlertState {
        self.projection
            .states
            .first()
            .copied()
            .unwrap_or(AlertState::Unknown)
    }

    #[must_use]
    pub fn is_native(&self) -> bool {
        self.native
    }

    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    #[must_use]
    pub fn classification(&self) -> EvidenceClassification {
        self.provenance
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.evidence_digest
    }
}

fn sort_and_dedup_labels(labels: &mut Vec<AllowlistedLabel>) {
    labels.sort_by(|left, right| left.key.cmp(&right.key));
    labels.dedup_by(|left, right| left.key == right.key);
}

pub(crate) fn normalize_labels(labels: &mut Vec<AllowlistedLabel>) {
    sort_and_dedup_labels(labels);
}

pub(crate) fn projection_from_observations(
    observations: &[AlertInstanceObservation],
    partial: bool,
    transitions: Vec<IncidentStateTransition>,
) -> AlertResultProjection {
    let mut states = observations
        .iter()
        .map(|item| item.state)
        .collect::<Vec<_>>();
    states.sort_unstable();
    states.dedup();
    let mut evaluation_timestamps = observations
        .iter()
        .filter_map(|item| item.evaluation_at)
        .collect::<Vec<_>>();
    evaluation_timestamps.sort_unstable();
    evaluation_timestamps.dedup();
    let mut numeric_evidence_digests = observations
        .iter()
        .flat_map(|item| {
            item.numeric_evidence
                .iter()
                .map(|evidence| evidence.value_digest.clone())
        })
        .collect::<Vec<_>>();
    numeric_evidence_digests.sort_unstable();
    numeric_evidence_digests.dedup();
    AlertResultProjection {
        states,
        partial,
        evaluation_timestamps,
        numeric_evidence_digests,
        incident_transitions: transitions,
        provider_error: None,
    }
}

pub(crate) fn error_projection(error: &GrafanaTransportError) -> GrafanaErrorProjection {
    let status = match error {
        GrafanaTransportError::Unauthorized401 => Some(401),
        GrafanaTransportError::Forbidden403 => Some(403),
        GrafanaTransportError::NotFound404 => Some(404),
        GrafanaTransportError::Conflict409 => Some(409),
        GrafanaTransportError::RateLimited429 { .. } => Some(429),
        GrafanaTransportError::Server5xx { status } => Some(*status),
        _ => None,
    };
    GrafanaErrorProjection {
        code: error.code().to_owned(),
        http_status: status,
        retryable: error.retryable(),
        error_digest: sha256_digest(error.to_string().as_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::*;

    #[test]
    fn secret_debug_and_serialization_do_not_expose_opaque_material() {
        let secret = SecretReference::service_account_token("token-value", 3).unwrap();
        let debug = format!("{secret:?}");
        assert!(!debug.contains("token-value"));
        let scope = test_scope(secret.clone());
        let debug_scope = format!("{scope:?}");
        assert!(!debug_scope.contains("token-value"));
        assert_eq!(secret.kind(), SecretKind::ServiceAccountToken);
        assert_eq!(secret.revision(), 3);
        assert_ne!(secret.digest(), sha256_digest(b"token-value"));
    }

    #[test]
    fn scope_binds_all_required_entities_and_revision_digests() {
        let scope = test_scope(SecretReference::service_account_token("opaque", 1).unwrap());
        assert_ne!(scope.digest(), scope.provider_digest());
        assert_ne!(scope.digest(), scope.revision_digest());
        assert_ne!(scope.api_digest(), scope.permission_digest());
        assert_eq!(scope.mission().id(), "mission-1");
        assert_eq!(scope.alert_instance().id(), "instance-1");
    }

    #[test]
    fn alert_states_cover_the_contract_projection() {
        assert_eq!(AlertState::parse("Normal"), AlertState::Normal);
        assert_eq!(AlertState::parse("pending"), AlertState::Pending);
        assert_eq!(AlertState::parse("Alerting"), AlertState::Alerting);
        assert_eq!(AlertState::parse("recovering"), AlertState::Recovering);
        assert_eq!(AlertState::parse("no_data"), AlertState::NoData);
        assert_eq!(AlertState::parse("error"), AlertState::Error);
        assert_eq!(AlertState::parse("provider-new-state"), AlertState::Unknown);
    }

    #[test]
    fn numeric_evidence_stores_only_a_digest() {
        let evidence = NumericEvidenceDigest::from_value("value", "12.5").unwrap();
        let serialized = serde_json::to_string(&evidence).unwrap();
        assert!(!serialized.contains("12.5"));
        assert_eq!(evidence.name, "value");
        assert!(is_digest(&evidence.value_digest));
    }

    #[test]
    fn incident_transition_is_digest_bound() {
        let at = Utc.with_ymd_and_hms(2026, 8, 14, 0, 0, 0).unwrap();
        let transition =
            IncidentStateTransition::new(IncidentState::Closed, IncidentState::Open, Some(at));
        assert!(is_digest(&transition.transition_digest));
    }

    fn test_scope(secret_reference: SecretReference) -> GrafanaAlertScope {
        let binding = |id: &str| IdentityBinding::new(id, 1).unwrap();
        GrafanaAlertScope::new(GrafanaAlertScopeSpec::new(
            CloudStack::new("stack-1", 1, "https://grafana.example.com").unwrap(),
            binding("org-1"),
            binding("folder-1"),
            binding("rule-1"),
            binding("group-1"),
            binding("instance-1"),
            binding("project-1"),
            binding("mission-1"),
            binding("deploy-1"),
            binding("release-1"),
            GrafanaApiDefinition::layer1(),
            GrafanaPermissionSnapshot::least_privilege(1).unwrap(),
            secret_reference,
        ))
        .unwrap()
    }
}
