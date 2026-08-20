use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroizing;

use crate::error::{GcpMonitoringAlertError, Result};
use crate::{
    CONSUMER_ID, CONTRACT_SCHEMA, CONTRACT_VERSION, MAX_ALERT_COUNT, MAX_IDENTIFIER_BYTES,
    MAX_LABEL_COUNT, MAX_PAGE_SIZE, MAX_PAGE_TOKEN_BYTES, MAX_PAGES, MAX_POLICY_COUNT,
    MAX_RESPONSE_BYTES, PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID, SERVICE_ID,
};

fn append_field(bytes: &mut Vec<u8>, field: &str) {
    bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
    bytes.extend_from_slice(field.as_bytes());
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_text(value: &str, max_bytes: usize, whitespace: bool) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && (whitespace || !value.chars().any(char::is_whitespace))
}

fn valid_identifier(value: &str) -> bool {
    valid_text(value, MAX_IDENTIFIER_BYTES, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_project_id(value: &str) -> bool {
    (1..=63).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn valid_metric_type(value: &str) -> bool {
    valid_text(value, 512, false)
        && value.contains('/')
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-' | b'.' | b':')
        })
}

fn valid_resource_type(value: &str) -> bool {
    valid_text(value, 128, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/'))
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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
        if valid_digest(&value) {
            Ok(Self(value))
        } else {
            Err(GcpMonitoringAlertError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

macro_rules! identifier {
    ($name:ident, $field:literal, $validator:expr) => {
        #[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(GcpMonitoringAlertError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("gcp-monitoring-", $field, "/v1"),
                    &[("value", self.0.clone())],
                )
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.digest())
                    .finish()
            }
        }
    };
}

identifier!(ProjectId, "project-id", valid_project_id);
identifier!(MetricsScopeId, "metrics-scope-id", valid_project_id);
identifier!(AlertPolicyId, "alert-policy-id", valid_identifier);
identifier!(AlertId, "alert-id", valid_identifier);
identifier!(ResourceType, "resource-type", valid_resource_type);
identifier!(MetricType, "metric-type", valid_metric_type);
identifier!(MissionId, "mission-id", valid_identifier);
identifier!(ProjectScopeId, "project-scope-id", valid_identifier);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(GcpMonitoringAlertError::InvalidRevision)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct Timestamp(String);

impl Timestamp {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        DateTime::<FixedOffset>::parse_from_rfc3339(&value)
            .map_err(|_| GcpMonitoringAlertError::InvalidTimestamp)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Timestamp").field(&self.0).finish()
    }
}

impl Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaquePageToken(String);

impl OpaquePageToken {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_PAGE_TOKEN_BYTES
            || value.chars().any(char::is_whitespace)
        {
            Err(GcpMonitoringAlertError::InvalidPageToken)
        } else {
            Ok(Self(value))
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-monitoring-alert-page-token/v1",
            &[("token", self.0.clone())],
        )
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GoogleAuthKind {
    OAuth,
    ServiceAccount,
}

/// Opaque host-keyring reference. The reference value is never serialized or
/// exposed through `Debug`; only its digest binds a proposal to it.
pub struct SecretReference {
    opaque_reference: Zeroizing<String>,
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    auth_kind: GoogleAuthKind,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            opaque_reference: self.opaque_reference.clone(),
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            auth_kind: self.auth_kind,
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
            .field("auth_kind", &self.auth_kind)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.auth_kind == other.auth_kind
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &GcpMonitoringAlertScope,
        credential_revision: u64,
        auth_kind: GoogleAuthKind,
    ) -> Result<Self> {
        let reference_id = reference_id.into();
        if !valid_text(&reference_id, MAX_IDENTIFIER_BYTES, true) {
            return Err(GcpMonitoringAlertError::InvalidIdentifier {
                field: "secret-reference",
            });
        }
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.scope_digest();
        let reference_digest = Digest::from_parts(
            "gcp-monitoring-secret-reference/v1",
            &[
                ("reference", reference_id.clone()),
                ("scope", scope_digest.as_str().to_owned()),
                ("revision", credential_revision.get().to_string()),
                ("auth", format!("{auth_kind:?}")),
            ],
        );
        Ok(Self {
            opaque_reference: Zeroizing::new(reference_id),
            reference_digest,
            scope_digest,
            credential_revision,
            auth_kind,
            revoked: false,
        })
    }

    pub fn oauth(
        reference_id: impl Into<String>,
        scope: &GcpMonitoringAlertScope,
        credential_revision: u64,
    ) -> Result<Self> {
        Self::new(
            reference_id,
            scope,
            credential_revision,
            GoogleAuthKind::OAuth,
        )
    }

    pub fn service_account(
        reference_id: impl Into<String>,
        scope: &GcpMonitoringAlertScope,
        credential_revision: u64,
    ) -> Result<Self> {
        Self::new(
            reference_id,
            scope,
            credential_revision,
            GoogleAuthKind::ServiceAccount,
        )
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn auth_kind(&self) -> GoogleAuthKind {
        self.auth_kind
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            Err(GcpMonitoringAlertError::AlreadyReversed)
        } else {
            self.revoked = true;
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyState {
    Enabled,
    Disabled,
    Invalid,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    #[serde(rename = "SEVERITY_UNSPECIFIED")]
    Unspecified,
    Critical,
    Error,
    Warning,
    Info,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AlertState {
    #[serde(rename = "STATE_UNSPECIFIED")]
    Unspecified,
    Open,
    Closed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertStateFilter {
    OpenOnly,
    ClosedOnly,
    Any,
}

impl AlertStateFilter {
    pub const fn matches(self, state: AlertState) -> bool {
        match self {
            Self::OpenOnly => matches!(state, AlertState::Open),
            Self::ClosedOnly => matches!(state, AlertState::Closed),
            Self::Any => true,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeverityFilter {
    Any,
    Critical,
    Error,
    Warning,
    Info,
    Unspecified,
}

impl SeverityFilter {
    pub const fn matches(self, severity: Severity) -> bool {
        match self {
            Self::Any => true,
            Self::Critical => matches!(severity, Severity::Critical),
            Self::Error => matches!(severity, Severity::Error),
            Self::Warning => matches!(severity, Severity::Warning),
            Self::Info => matches!(severity, Severity::Info),
            Self::Unspecified => matches!(severity, Severity::Unspecified),
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactedLabels {
    pub count: usize,
    pub key_digests: Vec<Digest>,
    pub value_digests: Vec<Digest>,
    pub set_digest: Digest,
}

impl RedactedLabels {
    pub fn empty() -> Self {
        Self::from_map(&BTreeMap::new()).expect("empty label set is valid")
    }

    pub fn from_map(labels: &BTreeMap<String, String>) -> Result<Self> {
        if labels.len() > MAX_LABEL_COUNT
            || labels
                .iter()
                .any(|(key, value)| !valid_text(key, 256, false) || !valid_text(value, 1024, true))
        {
            return Err(GcpMonitoringAlertError::InvalidLabels);
        }
        let mut key_digests = Vec::with_capacity(labels.len());
        let mut value_digests = Vec::with_capacity(labels.len());
        let mut pair_digests = Vec::with_capacity(labels.len());
        for (key, value) in labels {
            let key_digest =
                Digest::from_parts("gcp-monitoring-label-key/v1", &[("key", key.clone())]);
            let value_digest =
                Digest::from_parts("gcp-monitoring-label-value/v1", &[("value", value.clone())]);
            key_digests.push(key_digest.clone());
            value_digests.push(value_digest.clone());
            pair_digests.push(Digest::from_parts(
                "gcp-monitoring-label-pair/v1",
                &[
                    ("key", key_digest.as_str().to_owned()),
                    ("value", value_digest.as_str().to_owned()),
                ],
            ));
        }
        let set_digest = Digest::from_parts(
            "gcp-monitoring-label-set/v1",
            &[(
                "pairs",
                pair_digests
                    .iter()
                    .map(Digest::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            )],
        );
        Ok(Self {
            count: labels.len(),
            key_digests,
            value_digests,
            set_digest,
        })
    }

    pub const fn count(&self) -> usize {
        self.count
    }

    pub fn digest(&self) -> &Digest {
        &self.set_digest
    }

    pub fn validate(&self) -> Result<()> {
        if self.count > MAX_LABEL_COUNT
            || self.key_digests.len() != self.count
            || self.value_digests.len() != self.count
        {
            return Err(GcpMonitoringAlertError::TamperedEvidence);
        }
        let pairs = self
            .key_digests
            .iter()
            .zip(&self.value_digests)
            .map(|(key, value)| {
                Digest::from_parts(
                    "gcp-monitoring-label-pair/v1",
                    &[
                        ("key", key.as_str().to_owned()),
                        ("value", value.as_str().to_owned()),
                    ],
                )
            })
            .collect::<Vec<_>>();
        let expected = Digest::from_parts(
            "gcp-monitoring-label-set/v1",
            &[(
                "pairs",
                pairs
                    .iter()
                    .map(Digest::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            )],
        );
        if expected != self.set_digest {
            Err(GcpMonitoringAlertError::TamperedEvidence)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceIdentity {
    pub resource_type: ResourceType,
    pub labels: RedactedLabels,
    pub resource_digest: Digest,
}

impl ResourceIdentity {
    pub fn new(resource_type: ResourceType, labels: BTreeMap<String, String>) -> Result<Self> {
        let labels = RedactedLabels::from_map(&labels)?;
        let resource_digest = Digest::from_parts(
            "gcp-monitoring-resource/v1",
            &[
                ("type", resource_type.as_str().to_owned()),
                ("labels", labels.digest().as_str().to_owned()),
            ],
        );
        Ok(Self {
            resource_type,
            labels,
            resource_digest,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.resource_digest
    }

    pub fn validate(&self) -> Result<()> {
        self.labels.validate()?;
        let expected = Digest::from_parts(
            "gcp-monitoring-resource/v1",
            &[
                ("type", self.resource_type.as_str().to_owned()),
                ("labels", self.labels.digest().as_str().to_owned()),
            ],
        );
        if expected != self.resource_digest {
            Err(GcpMonitoringAlertError::TamperedEvidence)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricIdentity {
    pub metric_type: MetricType,
    pub labels: RedactedLabels,
    pub metric_digest: Digest,
}

impl MetricIdentity {
    pub fn new(metric_type: MetricType, labels: BTreeMap<String, String>) -> Result<Self> {
        let labels = RedactedLabels::from_map(&labels)?;
        let metric_digest = Digest::from_parts(
            "gcp-monitoring-metric/v1",
            &[
                ("type", metric_type.as_str().to_owned()),
                ("labels", labels.digest().as_str().to_owned()),
            ],
        );
        Ok(Self {
            metric_type,
            labels,
            metric_digest,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.metric_digest
    }

    pub fn validate(&self) -> Result<()> {
        self.labels.validate()?;
        let expected = Digest::from_parts(
            "gcp-monitoring-metric/v1",
            &[
                ("type", self.metric_type.as_str().to_owned()),
                ("labels", self.labels.digest().as_str().to_owned()),
            ],
        );
        if expected != self.metric_digest {
            Err(GcpMonitoringAlertError::TamperedEvidence)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricsScope {
    pub scoping_project: ProjectId,
    pub monitored_projects: BTreeSet<ProjectId>,
    pub scope_name: String,
    pub scope_digest: Digest,
}

impl MetricsScope {
    pub fn new(
        scoping_project: ProjectId,
        monitored_projects: impl IntoIterator<Item = ProjectId>,
    ) -> Result<Self> {
        let mut monitored_projects = monitored_projects.into_iter().collect::<BTreeSet<_>>();
        monitored_projects.insert(scoping_project.clone());
        if monitored_projects.is_empty() || monitored_projects.len() > MAX_POLICY_COUNT {
            return Err(GcpMonitoringAlertError::InvalidScope);
        }
        let scope_name = format!(
            "locations/global/metricsScopes/{}",
            scoping_project.as_str()
        );
        let scope_digest = Digest::from_parts(
            "gcp-monitoring-metrics-scope/v1",
            &[
                ("name", scope_name.clone()),
                (
                    "projects",
                    monitored_projects
                        .iter()
                        .map(ProjectId::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        );
        Ok(Self {
            scoping_project,
            monitored_projects,
            scope_name,
            scope_digest,
        })
    }

    pub fn name(&self) -> &str {
        &self.scope_name
    }

    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn contains_project(&self, project: &ProjectId) -> bool {
        self.monitored_projects.contains(project)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpProjectScope {
    pub project_id: ProjectId,
    pub project_digest: Digest,
}

impl GcpProjectScope {
    pub fn new(project_id: ProjectId) -> Self {
        let project_digest = project_id.digest();
        Self {
            project_id,
            project_digest,
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.project_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertPolicyScope {
    pub allowlisted_policy_ids: BTreeSet<AlertPolicyId>,
    pub max_policies: u16,
    pub scope_digest: Digest,
}

impl AlertPolicyScope {
    pub fn new(
        allowlisted_policy_ids: impl IntoIterator<Item = AlertPolicyId>,
        max_policies: u16,
    ) -> Result<Self> {
        let allowlisted_policy_ids = allowlisted_policy_ids.into_iter().collect::<BTreeSet<_>>();
        if allowlisted_policy_ids.is_empty()
            || max_policies == 0
            || max_policies > MAX_PAGE_SIZE
            || allowlisted_policy_ids.len() > usize::from(max_policies)
        {
            return Err(GcpMonitoringAlertError::InvalidBound);
        }
        let scope_digest = Digest::from_parts(
            "gcp-monitoring-policy-scope/v1",
            &[
                (
                    "allowlist",
                    allowlisted_policy_ids
                        .iter()
                        .map(AlertPolicyId::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("max", max_policies.to_string()),
            ],
        );
        Ok(Self {
            allowlisted_policy_ids,
            max_policies,
            scope_digest,
        })
    }

    pub fn contains(&self, policy_id: &AlertPolicyId) -> bool {
        self.allowlisted_policy_ids.contains(policy_id)
    }

    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertScope {
    pub allowlisted_alert_ids: BTreeSet<AlertId>,
    pub state_filter: AlertStateFilter,
    pub severity_filter: SeverityFilter,
    pub max_alerts: u16,
    pub scope_digest: Digest,
}

impl AlertScope {
    pub fn new(
        allowlisted_alert_ids: impl IntoIterator<Item = AlertId>,
        state_filter: AlertStateFilter,
        severity_filter: SeverityFilter,
        max_alerts: u16,
    ) -> Result<Self> {
        let allowlisted_alert_ids = allowlisted_alert_ids.into_iter().collect::<BTreeSet<_>>();
        if max_alerts == 0
            || max_alerts > MAX_PAGE_SIZE
            || usize::from(max_alerts) > MAX_ALERT_COUNT
        {
            return Err(GcpMonitoringAlertError::InvalidBound);
        }
        let scope_digest = Digest::from_parts(
            "gcp-monitoring-alert-scope/v1",
            &[
                (
                    "allowlist",
                    allowlisted_alert_ids
                        .iter()
                        .map(AlertId::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("state", format!("{state_filter:?}")),
                ("severity", format!("{severity_filter:?}")),
                ("max", max_alerts.to_string()),
            ],
        );
        Ok(Self {
            allowlisted_alert_ids,
            state_filter,
            severity_filter,
            max_alerts,
            scope_digest,
        })
    }

    pub fn open(max_alerts: u16) -> Result<Self> {
        Self::new(
            BTreeSet::new(),
            AlertStateFilter::OpenOnly,
            SeverityFilter::Any,
            max_alerts,
        )
    }

    pub fn contains(&self, alert_id: &AlertId) -> bool {
        self.allowlisted_alert_ids.is_empty() || self.allowlisted_alert_ids.contains(alert_id)
    }

    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceScope {
    pub allowlisted_resources: BTreeSet<ResourceIdentity>,
    pub max_resources: u16,
    pub scope_digest: Digest,
}

impl ResourceScope {
    pub fn new(
        allowlisted_resources: impl IntoIterator<Item = ResourceIdentity>,
        max_resources: u16,
    ) -> Result<Self> {
        let allowlisted_resources = allowlisted_resources.into_iter().collect::<BTreeSet<_>>();
        if max_resources == 0 || max_resources > MAX_PAGE_SIZE {
            return Err(GcpMonitoringAlertError::InvalidBound);
        }
        let scope_digest = Digest::from_parts(
            "gcp-monitoring-resource-scope/v1",
            &[
                (
                    "allowlist",
                    allowlisted_resources
                        .iter()
                        .map(|resource| resource.digest().as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("max", max_resources.to_string()),
            ],
        );
        Ok(Self {
            allowlisted_resources,
            max_resources,
            scope_digest,
        })
    }

    pub fn any(max_resources: u16) -> Result<Self> {
        Self::new(BTreeSet::new(), max_resources)
    }

    pub fn contains(&self, resource: &ResourceIdentity) -> bool {
        self.allowlisted_resources.is_empty() || self.allowlisted_resources.contains(resource)
    }

    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionScope {
    pub mission_id: MissionId,
    pub mission_revision: Revision,
    pub scope_digest: Digest,
}

impl MissionScope {
    pub fn new(mission_id: MissionId, mission_revision: Revision) -> Self {
        let scope_digest = Digest::from_parts(
            "gcp-monitoring-mission-scope/v1",
            &[
                ("mission", mission_id.as_str().to_owned()),
                ("revision", mission_revision.get().to_string()),
            ],
        );
        Self {
            mission_id,
            mission_revision,
            scope_digest,
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectScope {
    pub project_id: ProjectScopeId,
    pub project_revision: Revision,
    pub scope_digest: Digest,
}

impl ProjectScope {
    pub fn new(project_id: ProjectScopeId, project_revision: Revision) -> Self {
        let scope_digest = Digest::from_parts(
            "gcp-monitoring-project-scope/v1",
            &[
                ("project", project_id.as_str().to_owned()),
                ("revision", project_revision.get().to_string()),
            ],
        );
        Self {
            project_id,
            project_revision,
            scope_digest,
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpMonitoringAlertScope {
    pub metrics_scope: MetricsScope,
    pub project: GcpProjectScope,
    pub policy: AlertPolicyScope,
    pub alert: AlertScope,
    pub resource: ResourceScope,
    pub mission: MissionScope,
    pub hartevo_project: ProjectScope,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
}

impl GcpMonitoringAlertScope {
    pub fn new(
        metrics_scope: MetricsScope,
        project: GcpProjectScope,
        policy: AlertPolicyScope,
        alert: AlertScope,
        resource: ResourceScope,
        mission: MissionScope,
        hartevo_project: ProjectScope,
        permission_digest: Digest,
        consent_digest: Digest,
    ) -> Result<Self> {
        if metrics_scope.scoping_project != project.project_id {
            return Err(GcpMonitoringAlertError::InvalidScope);
        }
        let scope_digest = Digest::from_parts(
            "gcp-monitoring-alert-scope/v1",
            &[
                ("metrics", metrics_scope.digest().as_str().to_owned()),
                ("project", project.digest().as_str().to_owned()),
                ("policy", policy.digest().as_str().to_owned()),
                ("alert", alert.digest().as_str().to_owned()),
                ("resource", resource.digest().as_str().to_owned()),
                ("mission", mission.digest().as_str().to_owned()),
                (
                    "hartevo-project",
                    hartevo_project.digest().as_str().to_owned(),
                ),
                ("permission", permission_digest.as_str().to_owned()),
                ("consent", consent_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            metrics_scope,
            project,
            policy,
            alert,
            resource,
            mission,
            hartevo_project,
            permission_digest,
            consent_digest,
            scope_digest,
        })
    }

    pub fn metrics_scope(&self) -> &MetricsScope {
        &self.metrics_scope
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project.project_id
    }

    pub fn policy_scope(&self) -> &AlertPolicyScope {
        &self.policy
    }

    pub fn alert_scope(&self) -> &AlertScope {
        &self.alert
    }

    pub fn resource_scope(&self) -> &ResourceScope {
        &self.resource
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission.mission_id
    }

    pub const fn mission_revision(&self) -> Revision {
        self.mission.mission_revision
    }

    pub fn project_scope_id(&self) -> &ProjectScopeId {
        &self.hartevo_project.project_id
    }

    pub const fn project_revision(&self) -> Revision {
        self.hartevo_project.project_revision
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub fn scope_digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    pub fn fence(&self, credential_revision: Revision) -> EvidenceFence {
        EvidenceFence {
            scope_digest: self.scope_digest(),
            permission_digest: self.permission_digest.clone(),
            consent_digest: self.consent_digest.clone(),
            mission_revision: self.mission_revision(),
            project_revision: self.project_revision(),
            credential_revision,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceFence {
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub mission_revision: Revision,
    pub project_revision: Revision,
    pub credential_revision: Revision,
}

#[derive(Clone, Eq, PartialEq)]
pub struct PolicyConditionInput {
    metric_filter: Option<String>,
    log_filter: Option<String>,
    resource_labels: BTreeMap<String, String>,
    metric_labels: BTreeMap<String, String>,
}

impl PolicyConditionInput {
    pub fn metric(
        metric_filter: impl Into<String>,
        resource_labels: BTreeMap<String, String>,
        metric_labels: BTreeMap<String, String>,
    ) -> Result<Self> {
        let metric_filter = metric_filter.into();
        if !valid_text(&metric_filter, 2_048, true) {
            return Err(GcpMonitoringAlertError::InvalidPolicyCondition);
        }
        RedactedLabels::from_map(&resource_labels)?;
        RedactedLabels::from_map(&metric_labels)?;
        Ok(Self {
            metric_filter: Some(metric_filter),
            log_filter: None,
            resource_labels,
            metric_labels,
        })
    }

    pub fn log(
        log_filter: impl Into<String>,
        resource_labels: BTreeMap<String, String>,
    ) -> Result<Self> {
        let log_filter = log_filter.into();
        if !valid_text(&log_filter, 2_048, true) {
            return Err(GcpMonitoringAlertError::InvalidPolicyCondition);
        }
        RedactedLabels::from_map(&resource_labels)?;
        Ok(Self {
            metric_filter: None,
            log_filter: Some(log_filter),
            resource_labels,
            metric_labels: BTreeMap::new(),
        })
    }

    pub fn is_log_condition(&self) -> bool {
        self.log_filter.is_some()
    }

    fn digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-monitoring-policy-condition/v1",
            &[
                (
                    "metric-filter",
                    self.metric_filter
                        .as_deref()
                        .map_or_else(String::new, |filter| {
                            Digest::from_text(filter).as_str().to_owned()
                        }),
                ),
                (
                    "log-filter",
                    self.log_filter
                        .as_deref()
                        .map_or_else(String::new, |filter| {
                            Digest::from_text(filter).as_str().to_owned()
                        }),
                ),
                (
                    "resource-labels",
                    RedactedLabels::from_map(&self.resource_labels).map_or_else(
                        |_| String::new(),
                        |labels| labels.digest().as_str().to_owned(),
                    ),
                ),
                (
                    "metric-labels",
                    RedactedLabels::from_map(&self.metric_labels).map_or_else(
                        |_| String::new(),
                        |labels| labels.digest().as_str().to_owned(),
                    ),
                ),
            ],
        )
    }
}

impl fmt::Debug for PolicyConditionInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PolicyConditionInput")
            .field("condition_digest", &self.digest())
            .field("is_log_condition", &self.is_log_condition())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AlertPolicyInput {
    policy_id: AlertPolicyId,
    display_name: String,
    state: PolicyState,
    severity: Severity,
    conditions: Vec<PolicyConditionInput>,
    notification_channel_count: u16,
}

impl AlertPolicyInput {
    pub fn new(
        policy_id: AlertPolicyId,
        display_name: impl Into<String>,
        enabled: Option<bool>,
        severity: Severity,
        conditions: Vec<PolicyConditionInput>,
        notification_channel_count: u16,
    ) -> Result<Self> {
        let state = match enabled {
            Some(true) => PolicyState::Enabled,
            Some(false) => PolicyState::Disabled,
            None => PolicyState::Unknown,
        };
        Self::with_state(
            policy_id,
            display_name,
            state,
            severity,
            conditions,
            notification_channel_count,
        )
    }

    pub fn with_state(
        policy_id: AlertPolicyId,
        display_name: impl Into<String>,
        state: PolicyState,
        severity: Severity,
        conditions: Vec<PolicyConditionInput>,
        notification_channel_count: u16,
    ) -> Result<Self> {
        let display_name = display_name.into();
        if !valid_text(&display_name, 512, true)
            || conditions.is_empty()
            || conditions.len() > 6
            || notification_channel_count > 100
        {
            return Err(GcpMonitoringAlertError::InvalidPolicyCondition);
        }
        Ok(Self {
            policy_id,
            display_name,
            state,
            severity,
            conditions,
            notification_channel_count,
        })
    }

    pub fn policy_id(&self) -> &AlertPolicyId {
        &self.policy_id
    }

    pub fn into_projection(self) -> AlertPolicyProjection {
        let display_name_digest = Digest::from_text(&self.display_name);
        let conditions = self
            .conditions
            .iter()
            .map(PolicyConditionProjection::from_input)
            .collect::<Vec<_>>();
        AlertPolicyProjection::from_parts(
            self.policy_id,
            display_name_digest,
            self.state,
            self.severity,
            conditions,
            self.notification_channel_count,
        )
    }
}

impl fmt::Debug for AlertPolicyInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AlertPolicyInput")
            .field("policy_id", &self.policy_id)
            .field(
                "display_name_digest",
                &Digest::from_text(&self.display_name),
            )
            .field("state", &self.state)
            .field("severity", &self.severity)
            .field("conditions", &self.conditions)
            .field(
                "notification_channel_count",
                &self.notification_channel_count,
            )
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyConditionProjection {
    pub condition_digest: Digest,
    pub filter_digest: Digest,
    pub kind: String,
    pub resource_labels: RedactedLabels,
    pub metric_labels: RedactedLabels,
}

impl PolicyConditionProjection {
    fn from_input(input: &PolicyConditionInput) -> Self {
        let kind = if input.is_log_condition() {
            "log_match".to_owned()
        } else {
            "metric_condition".to_owned()
        };
        let filter_digest = input
            .metric_filter
            .as_deref()
            .or(input.log_filter.as_deref())
            .map_or_else(|| Digest::from_text("empty-filter"), Digest::from_text);
        Self {
            condition_digest: input.digest(),
            filter_digest,
            kind,
            resource_labels: RedactedLabels::from_map(&input.resource_labels)
                .unwrap_or_else(|_| RedactedLabels::empty()),
            metric_labels: RedactedLabels::from_map(&input.metric_labels)
                .unwrap_or_else(|_| RedactedLabels::empty()),
        }
    }

    fn validate(&self) -> Result<()> {
        self.resource_labels.validate()?;
        self.metric_labels.validate()?;
        let (metric_filter, log_filter) = match self.kind.as_str() {
            "metric_condition" => (self.filter_digest.as_str(), ""),
            "log_match" => ("", self.filter_digest.as_str()),
            _ => return Err(GcpMonitoringAlertError::TamperedEvidence),
        };
        let expected = Digest::from_parts(
            "gcp-monitoring-policy-condition/v1",
            &[
                ("metric-filter", metric_filter.to_owned()),
                ("log-filter", log_filter.to_owned()),
                (
                    "resource-labels",
                    self.resource_labels.digest().as_str().to_owned(),
                ),
                (
                    "metric-labels",
                    self.metric_labels.digest().as_str().to_owned(),
                ),
            ],
        );
        if expected != self.condition_digest {
            Err(GcpMonitoringAlertError::TamperedEvidence)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertPolicyProjection {
    pub policy_id: AlertPolicyId,
    pub policy_digest: Digest,
    pub display_name_digest: Digest,
    pub state: PolicyState,
    pub severity: Severity,
    pub condition_count: u8,
    pub conditions: Vec<PolicyConditionProjection>,
    pub notification_channel_count: u16,
}

impl AlertPolicyProjection {
    fn from_parts(
        policy_id: AlertPolicyId,
        display_name_digest: Digest,
        state: PolicyState,
        severity: Severity,
        conditions: Vec<PolicyConditionProjection>,
        notification_channel_count: u16,
    ) -> Self {
        let policy_digest = Digest::from_parts(
            "gcp-monitoring-alert-policy/v1",
            &[
                ("id", policy_id.as_str().to_owned()),
                ("display", display_name_digest.as_str().to_owned()),
                ("state", format!("{state:?}")),
                ("severity", format!("{severity:?}")),
                (
                    "conditions",
                    conditions
                        .iter()
                        .map(|condition| condition.condition_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("channels", notification_channel_count.to_string()),
            ],
        );
        Self {
            policy_id,
            policy_digest,
            display_name_digest,
            state,
            severity,
            condition_count: u8::try_from(conditions.len()).unwrap_or(u8::MAX),
            conditions,
            notification_channel_count,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.conditions.is_empty() || self.conditions.len() != usize::from(self.condition_count)
        {
            return Err(GcpMonitoringAlertError::InvalidResponseShape);
        }
        for condition in &self.conditions {
            condition.validate()?;
        }
        let expected = Self::from_parts(
            self.policy_id.clone(),
            self.display_name_digest.clone(),
            self.state,
            self.severity,
            self.conditions.clone(),
            self.notification_channel_count,
        );
        if expected.policy_digest != self.policy_digest {
            return Err(GcpMonitoringAlertError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AlertInput {
    alert_id: AlertId,
    state: AlertState,
    open_time: Timestamp,
    close_time: Option<Timestamp>,
    policy_id: AlertPolicyId,
    policy_display_name: String,
    severity: Severity,
    resource: Option<(ResourceType, BTreeMap<String, String>)>,
    metric: Option<(MetricType, BTreeMap<String, String>)>,
    log_labels: BTreeMap<String, String>,
}

impl AlertInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        alert_id: AlertId,
        state: AlertState,
        open_time: Timestamp,
        close_time: Option<Timestamp>,
        policy_id: AlertPolicyId,
        policy_display_name: impl Into<String>,
        severity: Severity,
        resource: Option<(ResourceType, BTreeMap<String, String>)>,
        metric: Option<(MetricType, BTreeMap<String, String>)>,
        log_labels: BTreeMap<String, String>,
    ) -> Result<Self> {
        let policy_display_name = policy_display_name.into();
        if !valid_text(&policy_display_name, 512, true) {
            return Err(GcpMonitoringAlertError::InvalidIdentifier {
                field: "alert-policy-display-name",
            });
        }
        if let Some((resource_type, labels)) = &resource {
            if !valid_resource_type(resource_type.as_str()) {
                return Err(GcpMonitoringAlertError::InvalidIdentifier {
                    field: "resource-type",
                });
            }
            RedactedLabels::from_map(labels)?;
        }
        if let Some((metric_type, labels)) = &metric {
            if !valid_metric_type(metric_type.as_str()) {
                return Err(GcpMonitoringAlertError::InvalidIdentifier {
                    field: "metric-type",
                });
            }
            RedactedLabels::from_map(labels)?;
        }
        RedactedLabels::from_map(&log_labels)?;
        if state == AlertState::Closed && close_time.is_none() {
            return Err(GcpMonitoringAlertError::InvalidTimestamp);
        }
        Ok(Self {
            alert_id,
            state,
            open_time,
            close_time,
            policy_id,
            policy_display_name,
            severity,
            resource,
            metric,
            log_labels,
        })
    }

    pub fn alert_id(&self) -> &AlertId {
        &self.alert_id
    }

    pub fn into_projection(self) -> Result<AlertProjection> {
        let resource = self
            .resource
            .map(|(resource_type, labels)| ResourceIdentity::new(resource_type, labels))
            .transpose()?;
        let metric = self
            .metric
            .map(|(metric_type, labels)| MetricIdentity::new(metric_type, labels))
            .transpose()?;
        let log_labels = RedactedLabels::from_map(&self.log_labels)?;
        let policy_snapshot_digest = Digest::from_parts(
            "gcp-monitoring-alert-policy-snapshot/v1",
            &[
                ("policy", self.policy_id.as_str().to_owned()),
                (
                    "display",
                    Digest::from_text(self.policy_display_name)
                        .as_str()
                        .to_owned(),
                ),
                ("severity", format!("{:?}", self.severity)),
            ],
        );
        Ok(AlertProjection::from_parts(
            self.alert_id,
            self.state,
            self.open_time,
            self.close_time,
            self.policy_id,
            policy_snapshot_digest,
            self.severity,
            resource,
            metric,
            log_labels,
        ))
    }
}

impl fmt::Debug for AlertInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AlertInput")
            .field("alert_id", &self.alert_id)
            .field("state", &self.state)
            .field("open_time", &self.open_time)
            .field("close_time", &self.close_time)
            .field("policy_id", &self.policy_id)
            .field(
                "policy_display_name_digest",
                &Digest::from_text(&self.policy_display_name),
            )
            .field("severity", &self.severity)
            .field(
                "resource",
                &self
                    .resource
                    .as_ref()
                    .map(|(kind, labels)| (kind, RedactedLabels::from_map(labels).ok())),
            )
            .field(
                "metric",
                &self
                    .metric
                    .as_ref()
                    .map(|(kind, labels)| (kind, RedactedLabels::from_map(labels).ok())),
            )
            .field(
                "log_label_digest",
                &RedactedLabels::from_map(&self.log_labels).map(|labels| labels.digest().clone()),
            )
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertProjection {
    pub alert_id: AlertId,
    pub alert_digest: Digest,
    pub state: AlertState,
    pub open_time: Timestamp,
    pub close_time: Option<Timestamp>,
    pub policy_id: AlertPolicyId,
    pub policy_snapshot_digest: Digest,
    pub severity: Severity,
    pub resource: Option<ResourceIdentity>,
    pub metric: Option<MetricIdentity>,
    pub log_labels: RedactedLabels,
}

impl AlertProjection {
    fn from_parts(
        alert_id: AlertId,
        state: AlertState,
        open_time: Timestamp,
        close_time: Option<Timestamp>,
        policy_id: AlertPolicyId,
        policy_snapshot_digest: Digest,
        severity: Severity,
        resource: Option<ResourceIdentity>,
        metric: Option<MetricIdentity>,
        log_labels: RedactedLabels,
    ) -> Self {
        let alert_digest = Digest::from_parts(
            "gcp-monitoring-alert/v1",
            &[
                ("id", alert_id.as_str().to_owned()),
                ("state", format!("{state:?}")),
                ("open", open_time.as_str().to_owned()),
                (
                    "close",
                    close_time
                        .as_ref()
                        .map_or_else(String::new, |timestamp| timestamp.as_str().to_owned()),
                ),
                ("policy", policy_id.as_str().to_owned()),
                ("snapshot", policy_snapshot_digest.as_str().to_owned()),
                ("severity", format!("{severity:?}")),
                (
                    "resource",
                    resource
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                (
                    "metric",
                    metric
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                ("logs", log_labels.digest().as_str().to_owned()),
            ],
        );
        Self {
            alert_id,
            alert_digest,
            state,
            open_time,
            close_time,
            policy_id,
            policy_snapshot_digest,
            severity,
            resource,
            metric,
            log_labels,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(resource) = &self.resource {
            resource.validate()?;
        }
        if let Some(metric) = &self.metric {
            metric.validate()?;
        }
        self.log_labels.validate()?;
        let expected = Self::from_parts(
            self.alert_id.clone(),
            self.state,
            self.open_time.clone(),
            self.close_time.clone(),
            self.policy_id.clone(),
            self.policy_snapshot_digest.clone(),
            self.severity,
            self.resource.clone(),
            self.metric.clone(),
            self.log_labels.clone(),
        );
        if expected.alert_digest != self.alert_digest {
            return Err(GcpMonitoringAlertError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderErrorEvidence {
    pub kind: String,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub attempt: u8,
    pub diagnostic_digest: Digest,
    pub blocked_env: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionEvidence {
    pub permissions: Vec<String>,
    pub permission_digest: Digest,
}

impl PermissionEvidence {
    pub fn layer_one() -> Self {
        let permissions = vec![
            "monitoring.alertPolicies.list".to_owned(),
            "monitoring.alertPolicies.get".to_owned(),
            "monitoring.alerts.list".to_owned(),
            "monitoring.alerts.get".to_owned(),
            "mission.scope".to_owned(),
        ];
        let permission_digest = Digest::from_parts(
            "gcp-monitoring-permissions/v1",
            &[("permissions", permissions.join(","))],
        );
        Self {
            permissions,
            permission_digest,
        }
    }
}

impl Default for PermissionEvidence {
    fn default() -> Self {
        Self::layer_one()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BoundedReadLimits {
    pub max_pages: u16,
    pub page_size: u16,
    pub max_policies: usize,
    pub max_alerts: usize,
    pub max_response_bytes: u64,
}

impl BoundedReadLimits {
    pub fn new(
        max_pages: u16,
        page_size: u16,
        max_policies: usize,
        max_alerts: usize,
        max_response_bytes: u64,
    ) -> Result<Self> {
        if max_pages == 0
            || max_pages > MAX_PAGES
            || page_size == 0
            || page_size > MAX_PAGE_SIZE
            || max_policies == 0
            || max_policies > MAX_POLICY_COUNT
            || max_alerts == 0
            || max_alerts > MAX_POLICY_COUNT
            || max_response_bytes == 0
            || max_response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(GcpMonitoringAlertError::InvalidBound);
        }
        Ok(Self {
            max_pages,
            page_size,
            max_policies,
            max_alerts,
            max_response_bytes,
        })
    }
}

impl Default for BoundedReadLimits {
    fn default() -> Self {
        Self {
            max_pages: 4,
            page_size: 25,
            max_policies: 25,
            max_alerts: 25,
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationBinding {
    pub api_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeSummary {
    pub metrics_scope_digest: Digest,
    pub project_digest: Digest,
    pub policy_scope_digest: Digest,
    pub alert_scope_digest: Digest,
    pub resource_scope_digest: Digest,
    pub mission_scope_digest: Digest,
    pub hartevo_project_scope_digest: Digest,
}

impl ScopeSummary {
    pub fn from_scope(scope: &GcpMonitoringAlertScope) -> Self {
        Self {
            metrics_scope_digest: scope.metrics_scope.digest().clone(),
            project_digest: scope.project.digest().clone(),
            policy_scope_digest: scope.policy.digest().clone(),
            alert_scope_digest: scope.alert.digest().clone(),
            resource_scope_digest: scope.resource.digest().clone(),
            mission_scope_digest: scope.mission.digest().clone(),
            hartevo_project_scope_digest: scope.hartevo_project.digest().clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractBinding {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub api_revision: String,
}

impl Default for ContractBinding {
    fn default() -> Self {
        Self {
            schema_version: CONTRACT_SCHEMA.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            api_revision: PROVIDER_API_REVISION.to_owned(),
        }
    }
}
