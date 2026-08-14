//! Typed identities, exact scope, bounded measures, and non-native provenance.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    MAX_DATE_BYTES, MAX_HOST_BYTES, MAX_IDENTIFIER_BYTES, MAX_MEASURES, MAX_METRIC_KEYS,
    MAX_TEXT_BYTES, Result, SonarQubeQualityResultError, digest_serialized, validate_digest,
    validate_identifier, validate_text,
};

/// A version used by the contract and registration binding.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Version {
    major: u16,
    minor: u16,
    patch: u16,
}

impl Version {
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

impl fmt::Display for Version {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// A lower-case SHA-256 digest used as a scope, response, proposal, and
/// registration fence.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_digest(&value, "digest")?;
        Ok(Self(value))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self(crate::sha256_hex(value.as_ref()))
    }

    pub fn from_serialized<T: Serialize>(value: &T) -> Self {
        Self(digest_serialized(value))
    }

    pub fn from_parts(label: &str, values: &[(&str, String)]) -> Self {
        let mut canonical = String::with_capacity(64 + values.len() * 32);
        canonical.push_str(label);
        for (name, value) in values {
            canonical.push('|');
            canonical.push_str(name);
            canonical.push(':');
            canonical.push_str(&value.len().to_string());
            canonical.push(':');
            canonical.push_str(value);
        }
        Self::from_text(canonical)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        validate_digest(&self.0, "digest")
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

macro_rules! define_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                validate_identifier(&value, $field, MAX_IDENTIFIER_BYTES)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn validate(&self) -> Result<()> {
                validate_identifier(&self.0, $field, MAX_IDENTIFIER_BYTES)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

define_identifier!(RegistrationId, "registrationId");
define_identifier!(MissionId, "missionId");
define_identifier!(ProjectId, "projectId");
define_identifier!(WorkProductId, "workProductId");
define_identifier!(OrganizationId, "organizationId");
define_identifier!(SonarProjectKey, "sonarProjectKey");
define_identifier!(AnalysisKey, "analysisKey");
define_identifier!(SourceRevision, "sourceRevision");
define_identifier!(QualityGateId, "qualityGateId");

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct QualityGateName(String);

impl QualityGateName {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_text(&value, "qualityGateName", MAX_TEXT_BYTES, false)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        validate_text(&self.0, "qualityGateName", MAX_TEXT_BYTES, false)
    }
}

impl fmt::Display for QualityGateName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// An exact HTTPS origin. Credentials, paths, queries, fragments, and
/// non-HTTPS origins are intentionally not representable.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostIdentity {
    pub origin: String,
}

impl HostIdentity {
    pub fn new(origin: impl Into<String>) -> Result<Self> {
        let identity = Self {
            origin: origin.into(),
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<()> {
        validate_text(&self.origin, "hostOrigin", MAX_HOST_BYTES, false)?;
        let host_part = self.origin.strip_prefix("https://");
        let valid_origin = host_part.is_some_and(|host| {
            !host.is_empty()
                && !host.ends_with('/')
                && !host
                    .chars()
                    .any(|character| matches!(character, '/' | '?' | '#' | '@'))
        });
        if valid_origin {
            Ok(())
        } else {
            Err(SonarQubeQualityResultError::InvalidHost)
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

/// SonarQube branch or pull-request selection is a tagged union so a branch
/// key can never be silently interpreted as a pull request key.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(
    rename_all = "camelCase",
    tag = "kind",
    content = "key",
    deny_unknown_fields
)]
pub enum BranchOrPullRequest {
    Branch(String),
    PullRequest(String),
}

impl BranchOrPullRequest {
    pub fn branch(key: impl Into<String>) -> Result<Self> {
        let key = key.into();
        validate_identifier(&key, "branchKey", MAX_IDENTIFIER_BYTES)?;
        Ok(Self::Branch(key))
    }

    pub fn pull_request(key: impl Into<String>) -> Result<Self> {
        let key = key.into();
        validate_identifier(&key, "pullRequestKey", MAX_IDENTIFIER_BYTES)?;
        Ok(Self::PullRequest(key))
    }

    pub fn key(&self) -> &str {
        match self {
            Self::Branch(key) | Self::PullRequest(key) => key,
        }
    }

    pub const fn query_name(&self) -> &'static str {
        match self {
            Self::Branch(_) => "branch",
            Self::PullRequest(_) => "pullRequest",
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Branch(key) => validate_identifier(key, "branchKey", MAX_IDENTIFIER_BYTES),
            Self::PullRequest(key) => {
                validate_identifier(key, "pullRequestKey", MAX_IDENTIFIER_BYTES)
            }
        }
    }
}

/// SonarQube analysis dates are retained as bounded provider metadata, not
/// parsed into a host clock or used as a freshness claim.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AnalysisDate(String);

impl AnalysisDate {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_text(&value, "analysisDate", MAX_DATE_BYTES, false)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AnalysisDate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalysisIdentity {
    pub key: AnalysisKey,
    pub date: AnalysisDate,
    pub source_revision: SourceRevision,
}

impl AnalysisIdentity {
    pub fn new(
        key: AnalysisKey,
        date: AnalysisDate,
        source_revision: SourceRevision,
    ) -> Result<Self> {
        let identity = Self {
            key,
            date,
            source_revision,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<()> {
        self.key.validate()?;
        validate_text(self.date.as_str(), "analysisDate", MAX_DATE_BYTES, false)?;
        self.source_revision.validate()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualityGateIdentity {
    pub id: QualityGateId,
    pub name: QualityGateName,
}

impl QualityGateIdentity {
    pub fn new(id: QualityGateId, name: QualityGateName) -> Result<Self> {
        let identity = Self { id, name };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<()> {
        self.id.validate()?;
        self.name.validate()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

/// Base metric keys are deliberately finite. New-code API keys are derived by
/// `MeasureSelector`, so callers cannot smuggle an arbitrary metric catalog.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct MetricKey(String);

const ALLOWED_METRIC_KEYS: &[&str] = &[
    "alert_status",
    "bugs",
    "code_smells",
    "complexity",
    "coverage",
    "duplicated_lines_density",
    "duplicated_lines",
    "lines_to_cover",
    "ncloc",
    "reliability_rating",
    "security_hotspots",
    "security_hotspots_reviewed",
    "security_rating",
    "sqale_index",
    "sqale_rating",
    "tests",
    "uncovered_lines",
    "vulnerabilities",
    "quality_gate_details",
];

impl MetricKey {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let base = value.strip_prefix("new_").unwrap_or(&value);
        validate_identifier(base, "metricKey", MAX_IDENTIFIER_BYTES)?;
        if ALLOWED_METRIC_KEYS.contains(&base) {
            Ok(Self(base.to_owned()))
        } else {
            Err(SonarQubeQualityResultError::MetricNotAllowlisted)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn api_key(&self, basis: MeasureBasis) -> String {
        match basis {
            MeasureBasis::NewCode => format!("new_{}", self.0),
            MeasureBasis::Overall => self.0.clone(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if ALLOWED_METRIC_KEYS.contains(&self.0.as_str()) {
            Ok(())
        } else {
            Err(SonarQubeQualityResultError::MetricNotAllowlisted)
        }
    }
}

impl<'de> Deserialize<'de> for MetricKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for MetricKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeasureBasis {
    NewCode,
    Overall,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MeasureSelector {
    pub metric: MetricKey,
    pub basis: MeasureBasis,
}

impl MeasureSelector {
    pub fn new(metric: MetricKey, basis: MeasureBasis) -> Result<Self> {
        let selector = Self { metric, basis };
        selector.validate()?;
        Ok(selector)
    }

    pub fn api_key(&self) -> String {
        self.metric.api_key(self.basis)
    }

    pub fn validate(&self) -> Result<()> {
        self.metric.validate()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct MeasureValue(String);

impl MeasureValue {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_text(&value, "measureValue", MAX_TEXT_BYTES, false)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Measure {
    pub selector: MeasureSelector,
    pub value: MeasureValue,
    pub best_value: Option<bool>,
}

impl Measure {
    pub fn new(
        selector: MeasureSelector,
        value: MeasureValue,
        best_value: Option<bool>,
    ) -> Result<Self> {
        let measure = Self {
            selector,
            value,
            best_value,
        };
        measure.validate()?;
        Ok(measure)
    }

    pub fn validate(&self) -> Result<()> {
        self.selector.validate()?;
        validate_text(self.value.as_str(), "measureValue", MAX_TEXT_BYTES, false)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionStatus {
    Ok,
    Error,
    NoValue,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonOperator {
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    Equals,
    NotEquals,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QualityGateStatus {
    Ok,
    Warn,
    Error,
    None,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualityGateCondition {
    pub selector: MeasureSelector,
    pub status: ConditionStatus,
    pub operator: ComparisonOperator,
    pub error_threshold: MeasureValue,
    pub actual_value: Option<MeasureValue>,
}

impl QualityGateCondition {
    pub fn new(
        selector: MeasureSelector,
        status: ConditionStatus,
        operator: ComparisonOperator,
        error_threshold: MeasureValue,
        actual_value: Option<MeasureValue>,
    ) -> Result<Self> {
        let condition = Self {
            selector,
            status,
            operator,
            error_threshold,
            actual_value,
        };
        condition.validate()?;
        Ok(condition)
    }

    pub fn validate(&self) -> Result<()> {
        self.selector.validate()?;
        validate_text(
            self.error_threshold.as_str(),
            "errorThreshold",
            MAX_TEXT_BYTES,
            false,
        )?;
        if let Some(actual) = &self.actual_value {
            validate_text(actual.as_str(), "actualValue", MAX_TEXT_BYTES, false)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScope {
    pub mission_id: MissionId,
    pub mission_revision: u64,
    pub project_id: ProjectId,
    pub project_revision: u64,
    pub work_product_id: WorkProductId,
    pub work_product_revision: u64,
    pub policy_digest: Digest,
    pub consent_digest: Digest,
}

impl MissionScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mission_id: MissionId,
        mission_revision: u64,
        project_id: ProjectId,
        project_revision: u64,
        work_product_id: WorkProductId,
        work_product_revision: u64,
        policy_digest: Digest,
        consent_digest: Digest,
    ) -> Result<Self> {
        let scope = Self {
            mission_id,
            mission_revision,
            project_id,
            project_revision,
            work_product_id,
            work_product_revision,
            policy_digest,
            consent_digest,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<()> {
        self.mission_id.validate()?;
        self.project_id.validate()?;
        self.work_product_id.validate()?;
        if self.mission_revision == 0
            || self.project_revision == 0
            || self.work_product_revision == 0
        {
            return Err(SonarQubeQualityResultError::InvalidScope);
        }
        self.policy_digest.validate()?;
        self.consent_digest.validate()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    ProjectRead,
    AnalysisRead,
    QualityGateRead,
    MeasureRead,
}

impl Permission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProjectRead => "project:read",
            Self::AnalysisRead => "analysis:read",
            Self::QualityGateRead => "quality_gate:read",
            Self::MeasureRead => "measure:read",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    pub permissions: Vec<Permission>,
    permission_digest: Digest,
}

impl PermissionSnapshot {
    pub fn read_only() -> Self {
        Self::new(vec![
            Permission::ProjectRead,
            Permission::AnalysisRead,
            Permission::QualityGateRead,
            Permission::MeasureRead,
        ])
    }

    pub fn new(mut permissions: Vec<Permission>) -> Self {
        permissions.sort_unstable();
        permissions.dedup();
        let permission_digest = Digest::from_serialized(&permissions);
        Self {
            permissions,
            permission_digest,
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn allows(&self, permission: Permission) -> bool {
        self.permissions.contains(&permission)
    }

    pub fn validate(&self) -> Result<()> {
        let expected = [
            Permission::ProjectRead,
            Permission::AnalysisRead,
            Permission::QualityGateRead,
            Permission::MeasureRead,
        ];
        if self.permissions.as_slice() != expected
            || self.permission_digest != Digest::from_serialized(&self.permissions)
        {
            Err(SonarQubeQualityResultError::InvalidPermissionSnapshot)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Bearer,
}

/// Opaque bearer credential handle. It deliberately implements no serde
/// traits and never stores the caller's handle or token, only a digest.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    kind: SecretKind,
    revision: u64,
    revoked: bool,
}

impl SecretReference {
    pub fn new(opaque_reference: impl AsRef<str>, revision: u64) -> Result<Self> {
        let opaque_reference = opaque_reference.as_ref();
        validate_text(
            opaque_reference,
            "opaqueSecretReference",
            MAX_IDENTIFIER_BYTES,
            false,
        )?;
        if revision == 0 {
            return Err(SonarQubeQualityResultError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_parts(
            "sonarqube-bearer-secret-reference/v1",
            &[("opaque_reference", opaque_reference.to_owned())],
        );
        Ok(Self {
            reference_digest,
            kind: SecretKind::Bearer,
            revision,
            revoked: false,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
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

    pub fn validate(&self) -> Result<()> {
        self.validate_shape()?;
        if self.revoked {
            Err(SonarQubeQualityResultError::SecretRevoked)
        } else {
            Ok(())
        }
    }

    pub(crate) fn validate_shape(&self) -> Result<()> {
        self.reference_digest.validate()?;
        if self.kind != SecretKind::Bearer || self.revision == 0 {
            Err(SonarQubeQualityResultError::InvalidSecretReference)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("kind", &self.kind)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }

    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionState {
    Pass,
    Error,
    Warn,
    NoAnalysis,
    Stale,
    Partial,
    AccessLoss,
    ProviderUnknown,
}

/// The complete SonarQube plus Hartevo binding. The analysis is the expected
/// analysis identity; a missing one projects `NoAnalysis`, while a matching
/// key with a different date or source revision projects `Stale`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SonarQubeQualityScope {
    pub host: HostIdentity,
    pub organization: OrganizationId,
    pub project: SonarProjectKey,
    pub branch_or_pull_request: BranchOrPullRequest,
    pub analysis: AnalysisIdentity,
    pub quality_gate: QualityGateIdentity,
    pub measures: Vec<MeasureSelector>,
    pub mission: MissionScope,
}

impl SonarQubeQualityScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host: HostIdentity,
        organization: OrganizationId,
        project: SonarProjectKey,
        branch_or_pull_request: BranchOrPullRequest,
        analysis: AnalysisIdentity,
        quality_gate: QualityGateIdentity,
        mut measures: Vec<MeasureSelector>,
        mission: MissionScope,
    ) -> Result<Self> {
        measures.sort_unstable();
        measures.dedup();
        let scope = Self {
            host,
            organization,
            project,
            branch_or_pull_request,
            analysis,
            quality_gate,
            measures,
            mission,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<()> {
        self.host.validate()?;
        self.organization.validate()?;
        self.project.validate()?;
        self.branch_or_pull_request.validate()?;
        self.analysis.validate()?;
        self.quality_gate.validate()?;
        self.mission.validate()?;
        if self.measures.is_empty() || self.measures.len() > MAX_MEASURES {
            return Err(SonarQubeQualityResultError::InvalidScope);
        }
        if self
            .measures
            .iter()
            .any(|selector| selector.validate().is_err())
        {
            return Err(SonarQubeQualityResultError::MetricNotAllowlisted);
        }
        let metric_keys: BTreeSet<_> = self.measures.iter().map(MeasureSelector::api_key).collect();
        if metric_keys.len() > MAX_METRIC_KEYS || metric_keys.len() != self.measures.len() {
            return Err(SonarQubeQualityResultError::InvalidScope);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }

    pub fn measure_selection_digest(&self) -> Digest {
        Digest::from_serialized(&self.measures)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Unmounted,
    Revoked,
}
