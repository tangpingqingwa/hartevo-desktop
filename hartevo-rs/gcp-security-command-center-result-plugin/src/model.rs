//! Bounded, serializable domain projections for the Security Command Center
//! Layer-1 result slice.
//!
//! This module intentionally has no representation for a Google provider
//! payload, credential bytes, source properties, security marks, or PII. The
//! only finding data that can cross the provider boundary is the normalized
//! metadata needed to reason about a bounded observation.

use std::{collections::BTreeSet, fmt, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_FILTER_BYTES: usize = 2_048;
pub const MAX_FILTER_VALUES: usize = 16;
pub const MAX_FINDINGS: usize = 500;
pub const MAX_GROUPS: usize = 200;
pub const MAX_PAGES: u16 = 4;
pub const MAX_PAGE_SIZE: u32 = 100;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} is too long")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    InvalidWhitespace { field: &'static str },
    #[error("{field} contains a value that is not allowed in a bounded filter")]
    UnsafeFilterValue { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is outside the Layer-1 bound")]
    OutOfBounds { field: &'static str },
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("a Security Command Center scope must include a findings.list permission")]
    MissingListPermission,
    #[error("the redaction fence was not satisfied")]
    RedactionViolation,
    #[error("the normalized response failed its digest fence")]
    ResponseTampered,
    #[error("the evidence failed its digest fence")]
    EvidenceTampered,
    #[error("the receipt failed its digest fence")]
    ReceiptTampered,
}

fn validate_bounded_text(
    value: &str,
    field: &'static str,
    allow_internal_whitespace: bool,
) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::InvalidWhitespace { field });
    }
    if !allow_internal_whitespace && value.chars().any(char::is_whitespace) {
        return Err(ModelError::Invalid { field });
    }
    Ok(())
}

fn validate_positive(value: u64, field: &'static str) -> Result<(), ModelError> {
    if value == 0 {
        Err(ModelError::MustBePositive { field })
    } else {
        Ok(())
    }
}

macro_rules! bounded_string {
    ($name:ident, $field:literal, $allow_internal_whitespace:expr) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_bounded_text(&value, $field, $allow_internal_whitespace)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                sha256_digest(self.0.as_bytes())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = ModelError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(format!("{:x}", Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_lowercase();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ModelError::InvalidDigest {
                field: "SHA-256 digest",
            });
        }
        Ok(Self(value))
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

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for Digest {
    type Err = ModelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

pub fn digest_serializable<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("bounded contract values serialize");
    sha256_digest(&bytes)
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

    pub fn digest(self) -> Digest {
        digest_serializable(&self)
    }
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        validate_positive(value, "revision")?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

bounded_string!(OrganizationId, "organization id", false);
bounded_string!(FolderId, "folder id", false);
bounded_string!(ProjectId, "GCP project id", false);
bounded_string!(SourceId, "source id", false);
bounded_string!(Location, "location", false);
bounded_string!(FindingId, "finding id", false);
bounded_string!(ResourceName, "resource name", false);
bounded_string!(Category, "finding category", false);
bounded_string!(HartevoProjectId, "Hartevo Project id", false);
bounded_string!(MissionId, "Mission id", false);
bounded_string!(WorkProductId, "Work Product id", false);
bounded_string!(ProviderRevision, "provider revision", false);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    OAuth,
    ServiceAccount,
}

impl SecretKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OAuth => "oauth",
            Self::ServiceAccount => "service_account",
        }
    }
}

/// A host-owned credential handle. It is intentionally not serializable and
/// its opaque identifier is never exposed through `Debug`, `Display`, or an
/// accessor. Layer 1 only binds its digest and revision into registration.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    opaque_id: String,
    credential_revision: u64,
}

impl SecretReference {
    pub fn oauth(
        opaque_id: impl Into<String>,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(SecretKind::OAuth, opaque_id, credential_revision)
    }

    pub fn service_account(
        opaque_id: impl Into<String>,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(SecretKind::ServiceAccount, opaque_id, credential_revision)
    }

    pub fn new(
        kind: SecretKind,
        opaque_id: impl Into<String>,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let opaque_id = opaque_id.into();
        validate_bounded_text(&opaque_id, "secret reference", false)?;
        validate_positive(credential_revision, "credential revision")?;
        Ok(Self {
            kind,
            opaque_id,
            credential_revision,
        })
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(&SecretDigestView {
            kind: self.kind,
            credential_revision: self.credential_revision,
            opaque_id: &self.opaque_id,
        })
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("credential_revision", &self.credential_revision)
            .field("opaque_id", &"<redacted>")
            .finish()
    }
}

#[derive(Serialize)]
struct SecretDigestView<'a> {
    kind: SecretKind,
    credential_revision: u64,
    opaque_id: &'a str,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityCenterTarget {
    Organization(OrganizationId),
    Folder(FolderId),
    Project(ProjectId),
}

impl SecurityCenterTarget {
    pub fn parent_path(&self, location: &Location, source: &SourceId) -> String {
        match self {
            Self::Organization(id) => {
                format!("organizations/{id}/locations/{location}/sources/{source}")
            }
            Self::Folder(id) => format!("folders/{id}/locations/{location}/sources/{source}"),
            Self::Project(id) => format!("projects/{id}/locations/{location}/sources/{source}"),
        }
    }

    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Organization(_) => "organization",
            Self::Folder(_) => "folder",
            Self::Project(_) => "project",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectScope {
    pub id: HartevoProjectId,
    pub revision: Revision,
}

impl ProjectScope {
    pub fn new(id: HartevoProjectId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScope {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionScope {
    pub fn new(id: MissionId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductScope {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductScope {
    pub fn new(id: WorkProductId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GcpSecurityCenterPermission {
    FindingsList,
    FindingsGroup,
}

impl GcpSecurityCenterPermission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FindingsList => "securitycenter.findings.list",
            Self::FindingsGroup => "securitycenter.findings.group",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    pub revision: Revision,
    pub permissions: Vec<GcpSecurityCenterPermission>,
    pub digest: Digest,
}

impl PermissionSnapshot {
    pub fn new(
        revision: Revision,
        permissions: impl IntoIterator<Item = GcpSecurityCenterPermission>,
    ) -> Result<Self, ModelError> {
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        if !permissions.contains(&GcpSecurityCenterPermission::FindingsList) {
            return Err(ModelError::MissingListPermission);
        }
        let permissions = permissions.into_iter().collect::<Vec<_>>();
        let digest = digest_serializable(&PermissionDigestView {
            revision,
            permissions: &permissions,
        });
        Ok(Self {
            revision,
            permissions,
            digest,
        })
    }

    pub fn least_privilege(revision: Revision, include_group: bool) -> Result<Self, ModelError> {
        let permissions = if include_group {
            vec![
                GcpSecurityCenterPermission::FindingsList,
                GcpSecurityCenterPermission::FindingsGroup,
            ]
        } else {
            vec![GcpSecurityCenterPermission::FindingsList]
        };
        Self::new(revision, permissions)
    }

    pub fn contains(&self, permission: GcpSecurityCenterPermission) -> bool {
        self.permissions.contains(&permission)
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = digest_serializable(&PermissionDigestView {
            revision: self.revision,
            permissions: &self.permissions,
        });
        if self.digest != expected {
            return Err(ModelError::EvidenceTampered);
        }
        if !self.contains(GcpSecurityCenterPermission::FindingsList) {
            return Err(ModelError::MissingListPermission);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct PermissionDigestView<'a> {
    revision: Revision,
    permissions: &'a [GcpSecurityCenterPermission],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpSecurityCenterScopeInput {
    pub target: SecurityCenterTarget,
    pub source_id: SourceId,
    pub location: Location,
    pub finding_id: Option<FindingId>,
    pub resource_name: Option<ResourceName>,
    pub project: ProjectScope,
    pub mission: MissionScope,
    pub work_product: WorkProductScope,
    pub permissions: PermissionSnapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpSecurityCenterScope {
    target: SecurityCenterTarget,
    source_id: SourceId,
    location: Location,
    finding_id: Option<FindingId>,
    resource_name: Option<ResourceName>,
    project: ProjectScope,
    mission: MissionScope,
    work_product: WorkProductScope,
    permissions: PermissionSnapshot,
    scope_digest: Digest,
}

impl GcpSecurityCenterScope {
    pub fn new(input: GcpSecurityCenterScopeInput) -> Result<Self, ModelError> {
        input.permissions.validate()?;
        let scope_digest = digest_serializable(&ScopeDigestView {
            target: &input.target,
            source_id: &input.source_id,
            location: &input.location,
            finding_id: &input.finding_id,
            resource_name: &input.resource_name,
            project: &input.project,
            mission: &input.mission,
            work_product: &input.work_product,
            permissions: &input.permissions,
        });
        Ok(Self {
            target: input.target,
            source_id: input.source_id,
            location: input.location,
            finding_id: input.finding_id,
            resource_name: input.resource_name,
            project: input.project,
            mission: input.mission,
            work_product: input.work_product,
            permissions: input.permissions,
            scope_digest,
        })
    }

    pub fn target(&self) -> &SecurityCenterTarget {
        &self.target
    }

    pub fn source_id(&self) -> &SourceId {
        &self.source_id
    }

    pub fn location(&self) -> &Location {
        &self.location
    }

    pub fn finding_id(&self) -> Option<&FindingId> {
        self.finding_id.as_ref()
    }

    pub fn resource_name(&self) -> Option<&ResourceName> {
        self.resource_name.as_ref()
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

    pub fn permissions(&self) -> &PermissionSnapshot {
        &self.permissions
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn parent_path(&self) -> String {
        self.target.parent_path(&self.location, &self.source_id)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.permissions.validate()?;
        let expected = digest_serializable(&ScopeDigestView {
            target: &self.target,
            source_id: &self.source_id,
            location: &self.location,
            finding_id: &self.finding_id,
            resource_name: &self.resource_name,
            project: &self.project,
            mission: &self.mission,
            work_product: &self.work_product,
            permissions: &self.permissions,
        });
        if self.scope_digest != expected {
            return Err(ModelError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct ScopeDigestView<'a> {
    target: &'a SecurityCenterTarget,
    source_id: &'a SourceId,
    location: &'a Location,
    finding_id: &'a Option<FindingId>,
    resource_name: &'a Option<ResourceName>,
    project: &'a ProjectScope,
    mission: &'a MissionScope,
    work_product: &'a WorkProductScope,
    permissions: &'a PermissionSnapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventTimeRange {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
}

impl EventTimeRange {
    pub fn new(from: DateTime<Utc>, to: DateTime<Utc>) -> Result<Self, ModelError> {
        if to <= from {
            return Err(ModelError::Invalid {
                field: "event time range",
            });
        }
        Ok(Self { from, to })
    }

    fn contains(&self, value: DateTime<Utc>) -> bool {
        value >= self.from && value <= self.to
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingState {
    Active,
    Inactive,
}

impl FindingState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Inactive => "INACTIVE",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Unspecified,
}

impl FindingSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
            Self::Unspecified => "SEVERITY_UNSPECIFIED",
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingFilter {
    states: Vec<FindingState>,
    severities: Vec<FindingSeverity>,
    categories: Vec<Category>,
    source_id: Option<SourceId>,
    resource_name: Option<ResourceName>,
    event_time: Option<EventTimeRange>,
}

impl FindingFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_states(
        mut self,
        states: impl IntoIterator<Item = FindingState>,
    ) -> Result<Self, ModelError> {
        self.states = bounded_values(states, "finding states")?;
        Ok(self)
    }

    pub fn with_severities(
        mut self,
        severities: impl IntoIterator<Item = FindingSeverity>,
    ) -> Result<Self, ModelError> {
        self.severities = bounded_values(severities, "finding severities")?;
        Ok(self)
    }

    pub fn with_categories(
        mut self,
        categories: impl IntoIterator<Item = Category>,
    ) -> Result<Self, ModelError> {
        let categories = categories.into_iter().collect::<Vec<_>>();
        if categories.is_empty() || categories.len() > MAX_FILTER_VALUES {
            return Err(ModelError::OutOfBounds {
                field: "finding categories",
            });
        }
        for category in &categories {
            validate_filter_literal(category.as_str(), "finding category")?;
        }
        self.categories = categories;
        Ok(self)
    }

    #[must_use]
    pub fn for_source(mut self, source_id: SourceId) -> Self {
        self.source_id = Some(source_id);
        self
    }

    pub fn for_resource(mut self, resource_name: ResourceName) -> Result<Self, ModelError> {
        validate_filter_literal(resource_name.as_str(), "resource name")?;
        self.resource_name = Some(resource_name);
        Ok(self)
    }

    #[must_use]
    pub fn with_event_time(mut self, event_time: EventTimeRange) -> Self {
        self.event_time = Some(event_time);
        self
    }

    pub fn states(&self) -> &[FindingState] {
        &self.states
    }

    pub fn severities(&self) -> &[FindingSeverity] {
        &self.severities
    }

    pub fn categories(&self) -> &[Category] {
        &self.categories
    }

    pub fn source_id(&self) -> Option<&SourceId> {
        self.source_id.as_ref()
    }

    pub fn resource_name(&self) -> Option<&ResourceName> {
        self.resource_name.as_ref()
    }

    pub fn event_time(&self) -> Option<&EventTimeRange> {
        self.event_time.as_ref()
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.states.len() > MAX_FILTER_VALUES
            || self.severities.len() > MAX_FILTER_VALUES
            || self.categories.len() > MAX_FILTER_VALUES
        {
            return Err(ModelError::OutOfBounds {
                field: "finding filter values",
            });
        }
        if let Some(category) = self.categories.first() {
            validate_filter_literal(category.as_str(), "finding category")?;
        }
        if let Some(resource) = &self.resource_name {
            validate_filter_literal(resource.as_str(), "resource name")?;
        }
        if self.to_api_filter().len() > MAX_FILTER_BYTES {
            return Err(ModelError::OutOfBounds {
                field: "finding filter bytes",
            });
        }
        Ok(())
    }

    pub fn to_api_filter(&self) -> String {
        let mut clauses = Vec::new();
        if !self.states.is_empty() {
            clauses.push(format!(
                "state = ({})",
                self.states
                    .iter()
                    .map(|state| format!("\"{}\"", state.as_str()))
                    .collect::<Vec<_>>()
                    .join(" OR ")
            ));
        }
        if !self.severities.is_empty() {
            clauses.push(format!(
                "severity = ({})",
                self.severities
                    .iter()
                    .map(|severity| format!("\"{}\"", severity.as_str()))
                    .collect::<Vec<_>>()
                    .join(" OR ")
            ));
        }
        if !self.categories.is_empty() {
            clauses.push(format!(
                "category = ({})",
                self.categories
                    .iter()
                    .map(|category| format!("\"{}\"", category.as_str()))
                    .collect::<Vec<_>>()
                    .join(" OR ")
            ));
        }
        if let Some(source_id) = &self.source_id {
            clauses.push(format!("source_name = \"{source_id}\""));
        }
        if let Some(resource_name) = &self.resource_name {
            clauses.push(format!("resource_name = \"{resource_name}\""));
        }
        if let Some(event_time) = &self.event_time {
            clauses.push(format!(
                "event_time >= \"{}\" AND event_time <= \"{}\"",
                event_time.from.to_rfc3339(),
                event_time.to.to_rfc3339()
            ));
        }
        clauses.join(" AND ")
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }

    fn matches(&self, finding: &FindingRecord) -> bool {
        (self.states.is_empty() || self.states.contains(&finding.state))
            && (self.severities.is_empty() || self.severities.contains(&finding.severity))
            && (self.categories.is_empty() || self.categories.contains(&finding.category))
            && self
                .source_id
                .as_ref()
                .is_none_or(|source| source == &finding.source_id)
            && self
                .resource_name
                .as_ref()
                .is_none_or(|resource| resource == &finding.resource_name)
            && self
                .event_time
                .as_ref()
                .is_none_or(|range| range.contains(finding.event_time))
    }
}

fn bounded_values<T: Ord>(
    values: impl IntoIterator<Item = T>,
    field: &'static str,
) -> Result<Vec<T>, ModelError> {
    let values = values.into_iter().collect::<BTreeSet<_>>();
    if values.is_empty() || values.len() > MAX_FILTER_VALUES {
        return Err(ModelError::OutOfBounds { field });
    }
    Ok(values.into_iter().collect())
}

fn validate_filter_literal(value: &str, field: &'static str) -> Result<(), ModelError> {
    let lower = value.to_ascii_lowercase();
    if value.contains('"')
        || value.contains('\\')
        || lower.contains("sourceproperties")
        || lower.contains("securitymarks")
        || lower.contains("source_properties")
        || lower.contains("security_marks")
        || lower.contains("email")
        || lower.contains("phone")
        || lower.contains('@')
    {
        return Err(ModelError::UnsafeFilterValue { field });
    }
    Ok(())
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaquePageToken(String);

impl OpaquePageToken {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_bounded_text(&value, "page token", false)?;
        Ok(Self(value))
    }

    pub fn digest(&self) -> Digest {
        sha256_digest(self.0.as_bytes())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
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

#[allow(clippy::struct_field_names)]
#[derive(Clone, Eq, PartialEq)]
pub struct PageBinding {
    page_number: u16,
    page_size: u32,
    page_token: Option<OpaquePageToken>,
    page_digest: Digest,
}

impl PageBinding {
    pub fn new(
        page_number: u16,
        page_size: u32,
        page_token: Option<OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        if page_number == 0 || page_number > MAX_PAGES {
            return Err(ModelError::OutOfBounds {
                field: "page number",
            });
        }
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(ModelError::OutOfBounds { field: "page size" });
        }
        let page_digest = digest_serializable(&PageDigestView {
            page_number,
            page_size,
            page_token_digest: page_token.as_ref().map(OpaquePageToken::digest),
        });
        Ok(Self {
            page_number,
            page_size,
            page_token,
            page_digest,
        })
    }

    pub fn first(page_size: u32) -> Result<Self, ModelError> {
        Self::new(1, page_size, None)
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub const fn page_size(&self) -> u32 {
        self.page_size
    }

    pub fn page_token(&self) -> Option<&OpaquePageToken> {
        self.page_token.as_ref()
    }

    pub fn digest(&self) -> &Digest {
        &self.page_digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = digest_serializable(&PageDigestView {
            page_number: self.page_number,
            page_size: self.page_size,
            page_token_digest: self.page_token.as_ref().map(OpaquePageToken::digest),
        });
        if self.page_digest != expected {
            return Err(ModelError::EvidenceTampered);
        }
        Ok(())
    }
}

impl fmt::Debug for PageBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PageBinding")
            .field("page_number", &self.page_number)
            .field("page_size", &self.page_size)
            .field(
                "page_token",
                &self.page_token.as_ref().map(OpaquePageToken::digest),
            )
            .field("page_digest", &self.page_digest)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestBounds {
    pub max_response_bytes: usize,
    pub max_findings: usize,
    pub max_groups: usize,
    pub max_pages: u16,
    pub page_size: u32,
}

impl Default for RequestBounds {
    fn default() -> Self {
        Self {
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_findings: MAX_FINDINGS,
            max_groups: MAX_GROUPS,
            max_pages: MAX_PAGES,
            page_size: MAX_PAGE_SIZE,
        }
    }
}

impl RequestBounds {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.max_response_bytes == 0 || self.max_response_bytes > MAX_RESPONSE_BYTES {
            return Err(ModelError::OutOfBounds {
                field: "max response bytes",
            });
        }
        if self.max_findings == 0 || self.max_findings > MAX_FINDINGS {
            return Err(ModelError::OutOfBounds {
                field: "max findings",
            });
        }
        if self.max_groups == 0 || self.max_groups > MAX_GROUPS {
            return Err(ModelError::OutOfBounds {
                field: "max groups",
            });
        }
        if self.max_pages == 0 || self.max_pages > MAX_PAGES {
            return Err(ModelError::OutOfBounds { field: "max pages" });
        }
        if self.page_size == 0 || self.page_size > MAX_PAGE_SIZE {
            return Err(ModelError::OutOfBounds { field: "page size" });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindingsListRequest {
    scope_digest: Digest,
    target: SecurityCenterTarget,
    source_id: SourceId,
    location: Location,
    filter: FindingFilter,
    page: PageBinding,
    bounds: RequestBounds,
    request_digest: Digest,
}

impl FindingsListRequest {
    pub fn new(
        scope: &GcpSecurityCenterScope,
        filter: FindingFilter,
        page: PageBinding,
        bounds: RequestBounds,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        filter.validate()?;
        page.validate()?;
        bounds.validate()?;
        let request_digest = digest_serializable(&RequestDigestView {
            operation: "findings.list",
            scope_digest: scope.scope_digest(),
            target: scope.target(),
            source_id: scope.source_id(),
            location: scope.location(),
            filter_digest: filter.digest(),
            page_digest: page.digest().clone(),
            bounds,
        });
        Ok(Self {
            scope_digest: scope.scope_digest().clone(),
            target: scope.target().clone(),
            source_id: scope.source_id().clone(),
            location: scope.location().clone(),
            filter,
            page,
            bounds,
            request_digest,
        })
    }

    pub fn bounded(
        scope: &GcpSecurityCenterScope,
        filter: FindingFilter,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            filter,
            PageBinding::first(RequestBounds::default().page_size)?,
            RequestBounds::default(),
        )
    }

    pub const fn operation(&self) -> &'static str {
        "findings.list"
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn target(&self) -> &SecurityCenterTarget {
        &self.target
    }

    pub fn source_id(&self) -> &SourceId {
        &self.source_id
    }

    pub fn location(&self) -> &Location {
        &self.location
    }

    pub fn filter(&self) -> &FindingFilter {
        &self.filter
    }

    pub fn page(&self) -> &PageBinding {
        &self.page
    }

    pub const fn bounds(&self) -> RequestBounds {
        self.bounds
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupBy {
    Category,
    Resource,
    State,
    Severity,
    Source,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupFindingsRequest {
    scope_digest: Digest,
    target: SecurityCenterTarget,
    source_id: SourceId,
    location: Location,
    group_by: GroupBy,
    filter: FindingFilter,
    page: PageBinding,
    bounds: RequestBounds,
    request_digest: Digest,
}

impl GroupFindingsRequest {
    pub fn new(
        scope: &GcpSecurityCenterScope,
        group_by: GroupBy,
        filter: FindingFilter,
        page: PageBinding,
        bounds: RequestBounds,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        if !scope
            .permissions()
            .contains(GcpSecurityCenterPermission::FindingsGroup)
        {
            return Err(ModelError::Invalid {
                field: "findings.group permission",
            });
        }
        filter.validate()?;
        page.validate()?;
        bounds.validate()?;
        let request_digest = digest_serializable(&GroupRequestDigestView {
            operation: "findings.group",
            scope_digest: scope.scope_digest(),
            target: scope.target(),
            source_id: scope.source_id(),
            location: scope.location(),
            group_by,
            filter_digest: filter.digest(),
            page_digest: page.digest().clone(),
            bounds,
        });
        Ok(Self {
            scope_digest: scope.scope_digest().clone(),
            target: scope.target().clone(),
            source_id: scope.source_id().clone(),
            location: scope.location().clone(),
            group_by,
            filter,
            page,
            bounds,
            request_digest,
        })
    }

    pub const fn operation(&self) -> &'static str {
        "findings.group"
    }

    pub const fn group_by(&self) -> GroupBy {
        self.group_by
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn target(&self) -> &SecurityCenterTarget {
        &self.target
    }

    pub fn source_id(&self) -> &SourceId {
        &self.source_id
    }

    pub fn location(&self) -> &Location {
        &self.location
    }

    pub fn filter(&self) -> &FindingFilter {
        &self.filter
    }

    pub fn page(&self) -> &PageBinding {
        &self.page
    }

    pub const fn bounds(&self) -> RequestBounds {
        self.bounds
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
}

#[allow(clippy::struct_field_names)]
#[derive(Serialize)]
struct PageDigestView {
    page_number: u16,
    page_size: u32,
    page_token_digest: Option<Digest>,
}

#[derive(Serialize)]
struct RequestDigestView<'a> {
    operation: &'static str,
    scope_digest: &'a Digest,
    target: &'a SecurityCenterTarget,
    source_id: &'a SourceId,
    location: &'a Location,
    filter_digest: Digest,
    page_digest: Digest,
    bounds: RequestBounds,
}

#[derive(Serialize)]
struct GroupRequestDigestView<'a> {
    operation: &'static str,
    scope_digest: &'a Digest,
    target: &'a SecurityCenterTarget,
    source_id: &'a SourceId,
    location: &'a Location,
    group_by: GroupBy,
    filter_digest: Digest,
    page_digest: Digest,
    bounds: RequestBounds,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionMetadata {
    pub source_properties_redacted: bool,
    pub security_marks_redacted: bool,
    pub pii_redacted: bool,
    pub raw_provider_payload_retained: bool,
}

impl RedactionMetadata {
    pub const fn safe() -> Self {
        Self {
            source_properties_redacted: true,
            security_marks_redacted: true,
            pii_redacted: true,
            raw_provider_payload_retained: false,
        }
    }

    pub const fn is_safe(self) -> bool {
        self.source_properties_redacted
            && self.security_marks_redacted
            && self.pii_redacted
            && !self.raw_provider_payload_retained
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingRecord {
    pub finding_id: FindingId,
    pub source_id: SourceId,
    pub resource_name: ResourceName,
    pub category: Category,
    pub state: FindingState,
    pub severity: FindingSeverity,
    pub event_time: DateTime<Utc>,
    pub redaction: RedactionMetadata,
    pub finding_digest: Digest,
}

impl FindingRecord {
    pub fn new(
        finding_id: FindingId,
        source_id: SourceId,
        resource_name: ResourceName,
        category: Category,
        state: FindingState,
        severity: FindingSeverity,
        event_time: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        Self::with_redaction(
            finding_id,
            source_id,
            resource_name,
            category,
            state,
            severity,
            event_time,
            RedactionMetadata::safe(),
        )
    }

    pub fn with_redaction(
        finding_id: FindingId,
        source_id: SourceId,
        resource_name: ResourceName,
        category: Category,
        state: FindingState,
        severity: FindingSeverity,
        event_time: DateTime<Utc>,
        redaction: RedactionMetadata,
    ) -> Result<Self, ModelError> {
        if !redaction.is_safe() {
            return Err(ModelError::RedactionViolation);
        }
        let finding_digest = digest_serializable(&FindingDigestView {
            finding_id: &finding_id,
            source_id: &source_id,
            resource_name: &resource_name,
            category: &category,
            state,
            severity,
            event_time,
            redaction,
        });
        Ok(Self {
            finding_id,
            source_id,
            resource_name,
            category,
            state,
            severity,
            event_time,
            redaction,
            finding_digest,
        })
    }

    pub fn calculate_digest(&self) -> Digest {
        digest_serializable(&FindingDigestView {
            finding_id: &self.finding_id,
            source_id: &self.source_id,
            resource_name: &self.resource_name,
            category: &self.category,
            state: self.state,
            severity: self.severity,
            event_time: self.event_time,
            redaction: self.redaction,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if !self.redaction.is_safe() {
            return Err(ModelError::RedactionViolation);
        }
        if self.finding_digest != self.calculate_digest() {
            return Err(ModelError::ResponseTampered);
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        scope: &GcpSecurityCenterScope,
        filter: &FindingFilter,
    ) -> Result<(), ModelError> {
        self.validate()?;
        if self.source_id != *scope.source_id()
            || scope
                .finding_id()
                .is_some_and(|finding_id| finding_id != &self.finding_id)
            || scope
                .resource_name()
                .is_some_and(|resource| resource != &self.resource_name)
            || !filter.matches(self)
        {
            return Err(ModelError::ResponseTampered);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct FindingDigestView<'a> {
    finding_id: &'a FindingId,
    source_id: &'a SourceId,
    resource_name: &'a ResourceName,
    category: &'a Category,
    state: FindingState,
    severity: FindingSeverity,
    event_time: DateTime<Utc>,
    redaction: RedactionMetadata,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupKey {
    Category(Category),
    Resource(ResourceName),
    State(FindingState),
    Severity(FindingSeverity),
    Source(SourceId),
}

impl GroupKey {
    pub const fn group_by(&self) -> GroupBy {
        match self {
            Self::Category(_) => GroupBy::Category,
            Self::Resource(_) => GroupBy::Resource,
            Self::State(_) => GroupBy::State,
            Self::Severity(_) => GroupBy::Severity,
            Self::Source(_) => GroupBy::Source,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupFindingBucket {
    pub group_by: GroupBy,
    pub key: GroupKey,
    pub finding_count: u64,
    pub metadata_digest: Digest,
    pub redaction: RedactionMetadata,
}

impl GroupFindingBucket {
    pub fn new(group_by: GroupBy, key: GroupKey, finding_count: u64) -> Result<Self, ModelError> {
        validate_positive(finding_count, "group finding count")?;
        if key.group_by() != group_by {
            return Err(ModelError::Invalid { field: "group key" });
        }
        let redaction = RedactionMetadata::safe();
        let metadata_digest = digest_serializable(&GroupBucketDigestView {
            group_by,
            key: &key,
            finding_count,
            redaction,
        });
        Ok(Self {
            group_by,
            key,
            finding_count,
            metadata_digest,
            redaction,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.finding_count == 0 || !self.redaction.is_safe() {
            return Err(ModelError::RedactionViolation);
        }
        let expected = digest_serializable(&GroupBucketDigestView {
            group_by: self.group_by,
            key: &self.key,
            finding_count: self.finding_count,
            redaction: self.redaction,
        });
        if self.metadata_digest != expected || self.key.group_by() != self.group_by {
            return Err(ModelError::ResponseTampered);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct GroupBucketDigestView<'a> {
    group_by: GroupBy,
    key: &'a GroupKey,
    finding_count: u64,
    redaction: RedactionMetadata,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    Unauthorized,
    Forbidden,
    NotFound,
    RateLimited,
    Timeout,
    Server,
    InvalidResponse,
    BlockedEnv,
    NoFixtureResponse,
    BoundExceeded,
    PageLoop,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderErrorEvidence {
    pub kind: ProviderErrorKind,
    pub retryable: bool,
    pub access_lost: bool,
    pub blocked_env: bool,
    pub error_digest: Digest,
}

impl ProviderErrorEvidence {
    pub fn new(
        kind: ProviderErrorKind,
        retryable: bool,
        access_lost: bool,
        blocked_env: bool,
    ) -> Self {
        let error_digest = digest_serializable(&(kind, retryable, access_lost, blocked_env));
        Self {
            kind,
            retryable,
            access_lost,
            blocked_env,
            error_digest,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceProjection {
    Complete,
    Partial(PartialReason),
    AccessLost,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    NextPage,
    ProviderReportedPartial,
    BoundExceeded,
    ProviderWarning,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceAuthority {
    pub connected: bool,
    pub native: bool,
    pub durable_receipt: bool,
    pub truth_authority: bool,
    pub adopted: bool,
}

impl EvidenceAuthority {
    pub const fn layer1() -> Self {
        Self {
            connected: false,
            native: false,
            durable_receipt: false,
            truth_authority: false,
            adopted: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_revision_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceOperation {
    FindingsList,
    FindingsGroup,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingsListEvidence {
    pub operation: EvidenceOperation,
    pub projection: EvidenceProjection,
    pub classification: TransportProvenance,
    pub findings: Vec<FindingRecord>,
    pub errors: Vec<ProviderErrorEvidence>,
    pub redacted_fields: Vec<String>,
    pub has_next_page: bool,
    pub registration_digest: Digest,
    pub registration_revision: u64,
    pub provider_revision: ProviderRevision,
    pub filter_digest: Digest,
    pub page_digest: Digest,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub digests: EvidenceDigests,
    pub evidence_digest: Digest,
    pub authority: EvidenceAuthority,
}

impl FindingsListEvidence {
    pub fn calculate_evidence_digest(&self) -> Digest {
        digest_serializable(&ListEvidenceDigestView {
            operation: &self.operation,
            projection: &self.projection,
            classification: self.classification,
            findings: &self.findings,
            errors: &self.errors,
            redacted_fields: &self.redacted_fields,
            has_next_page: self.has_next_page,
            registration_digest: &self.registration_digest,
            registration_revision: self.registration_revision,
            provider_revision: &self.provider_revision,
            filter_digest: &self.filter_digest,
            page_digest: &self.page_digest,
            request_digest: &self.request_digest,
            response_digest: &self.response_digest,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            authority: self.authority,
        })
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        if self.operation != EvidenceOperation::FindingsList
            || self.evidence_digest != self.calculate_evidence_digest()
            || self.digests.evidence_digest != self.evidence_digest
            || self.digests.scope_digest != self.scope_digest
            || self.digests.permission_digest != self.permission_digest
            || self.digests.request_digest != self.request_digest
            || self.digests.response_digest != self.response_digest
        {
            return Err(ModelError::EvidenceTampered);
        }
        for finding in &self.findings {
            finding.validate()?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct ListEvidenceDigestView<'a> {
    operation: &'a EvidenceOperation,
    projection: &'a EvidenceProjection,
    classification: TransportProvenance,
    findings: &'a [FindingRecord],
    errors: &'a [ProviderErrorEvidence],
    redacted_fields: &'a [String],
    has_next_page: bool,
    registration_digest: &'a Digest,
    registration_revision: u64,
    provider_revision: &'a ProviderRevision,
    filter_digest: &'a Digest,
    page_digest: &'a Digest,
    request_digest: &'a Digest,
    response_digest: &'a Digest,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
    authority: EvidenceAuthority,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingsGroupEvidence {
    pub operation: EvidenceOperation,
    pub projection: EvidenceProjection,
    pub classification: TransportProvenance,
    pub groups: Vec<GroupFindingBucket>,
    pub errors: Vec<ProviderErrorEvidence>,
    pub redacted_fields: Vec<String>,
    pub has_next_page: bool,
    pub group_by: GroupBy,
    pub registration_digest: Digest,
    pub registration_revision: u64,
    pub provider_revision: ProviderRevision,
    pub filter_digest: Digest,
    pub page_digest: Digest,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub digests: EvidenceDigests,
    pub evidence_digest: Digest,
    pub authority: EvidenceAuthority,
}

impl FindingsGroupEvidence {
    pub fn calculate_evidence_digest(&self) -> Digest {
        digest_serializable(&GroupEvidenceDigestView {
            operation: &self.operation,
            projection: &self.projection,
            classification: self.classification,
            groups: &self.groups,
            errors: &self.errors,
            redacted_fields: &self.redacted_fields,
            has_next_page: self.has_next_page,
            group_by: self.group_by,
            registration_digest: &self.registration_digest,
            registration_revision: self.registration_revision,
            provider_revision: &self.provider_revision,
            filter_digest: &self.filter_digest,
            page_digest: &self.page_digest,
            request_digest: &self.request_digest,
            response_digest: &self.response_digest,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            authority: self.authority,
        })
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        if self.operation != EvidenceOperation::FindingsGroup
            || self.evidence_digest != self.calculate_evidence_digest()
            || self.digests.evidence_digest != self.evidence_digest
            || self.digests.scope_digest != self.scope_digest
            || self.digests.permission_digest != self.permission_digest
            || self.digests.request_digest != self.request_digest
            || self.digests.response_digest != self.response_digest
        {
            return Err(ModelError::EvidenceTampered);
        }
        for group in &self.groups {
            group.validate()?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct GroupEvidenceDigestView<'a> {
    operation: &'a EvidenceOperation,
    projection: &'a EvidenceProjection,
    classification: TransportProvenance,
    groups: &'a [GroupFindingBucket],
    errors: &'a [ProviderErrorEvidence],
    redacted_fields: &'a [String],
    has_next_page: bool,
    group_by: GroupBy,
    registration_digest: &'a Digest,
    registration_revision: u64,
    provider_revision: &'a ProviderRevision,
    filter_digest: &'a Digest,
    page_digest: &'a Digest,
    request_digest: &'a Digest,
    response_digest: &'a Digest,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
    authority: EvidenceAuthority,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Recorded,
    Partial,
    AccessLost,
    ProviderUnknown,
}

impl ReceiptStatus {
    pub fn from_projection(projection: &EvidenceProjection) -> Self {
        match projection {
            EvidenceProjection::Complete => Self::Recorded,
            EvidenceProjection::Partial(_) => Self::Partial,
            EvidenceProjection::AccessLost => Self::AccessLost,
            EvidenceProjection::ProviderUnknown => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingsListReceipt {
    pub status: ReceiptStatus,
    pub evidence: FindingsListEvidence,
    pub evidence_digest: Digest,
    pub receipt_digest: Digest,
    pub durable: bool,
    pub raw_provider_payload_retained: bool,
}

impl FindingsListReceipt {
    pub fn new(evidence: FindingsListEvidence) -> Result<Self, ModelError> {
        evidence.validate_integrity()?;
        let status = ReceiptStatus::from_projection(&evidence.projection);
        let evidence_digest = evidence.evidence_digest.clone();
        let receipt_digest = digest_serializable(&ReceiptDigestView {
            status,
            evidence_digest: &evidence_digest,
            durable: false,
            raw_provider_payload_retained: false,
        });
        Ok(Self {
            status,
            evidence,
            evidence_digest,
            receipt_digest,
            durable: false,
            raw_provider_payload_retained: false,
        })
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        if self.durable || self.raw_provider_payload_retained {
            return Err(ModelError::ReceiptTampered);
        }
        self.evidence.validate_integrity()?;
        if self.evidence_digest != self.evidence.evidence_digest
            || self.status != ReceiptStatus::from_projection(&self.evidence.projection)
            || self.receipt_digest
                != digest_serializable(&ReceiptDigestView {
                    status: self.status,
                    evidence_digest: &self.evidence_digest,
                    durable: self.durable,
                    raw_provider_payload_retained: self.raw_provider_payload_retained,
                })
        {
            return Err(ModelError::ReceiptTampered);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct ReceiptDigestView<'a> {
    status: ReceiptStatus,
    evidence_digest: &'a Digest,
    durable: bool,
    raw_provider_payload_retained: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingsGroupReceipt {
    pub status: ReceiptStatus,
    pub evidence: FindingsGroupEvidence,
    pub evidence_digest: Digest,
    pub receipt_digest: Digest,
    pub durable: bool,
    pub raw_provider_payload_retained: bool,
}

impl FindingsGroupReceipt {
    pub fn new(evidence: FindingsGroupEvidence) -> Result<Self, ModelError> {
        evidence.validate_integrity()?;
        let status = ReceiptStatus::from_projection(&evidence.projection);
        let evidence_digest = evidence.evidence_digest.clone();
        let receipt_digest = digest_serializable(&ReceiptDigestView {
            status,
            evidence_digest: &evidence_digest,
            durable: false,
            raw_provider_payload_retained: false,
        });
        Ok(Self {
            status,
            evidence,
            evidence_digest,
            receipt_digest,
            durable: false,
            raw_provider_payload_retained: false,
        })
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        if self.durable || self.raw_provider_payload_retained {
            return Err(ModelError::ReceiptTampered);
        }
        self.evidence.validate_integrity()?;
        if self.evidence_digest != self.evidence.evidence_digest
            || self.status != ReceiptStatus::from_projection(&self.evidence.projection)
            || self.receipt_digest
                != digest_serializable(&ReceiptDigestView {
                    status: self.status,
                    evidence_digest: &self.evidence_digest,
                    durable: self.durable,
                    raw_provider_payload_retained: self.raw_provider_payload_retained,
                })
        {
            return Err(ModelError::ReceiptTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingsListVerification {
    pub verified: bool,
    pub complete: bool,
    pub access_lost: bool,
    pub provider_unknown: bool,
    pub adoptable: bool,
    pub native: bool,
    pub connected: bool,
    pub evidence_digest: Digest,
    pub receipt_digest: Digest,
    pub verification_digest: Digest,
}

impl FindingsListVerification {
    pub fn from_receipt(receipt: &FindingsListReceipt) -> Result<Self, ModelError> {
        receipt.validate_integrity()?;
        let evidence = &receipt.evidence;
        let verification = Self {
            verified: true,
            complete: matches!(evidence.projection, EvidenceProjection::Complete),
            access_lost: matches!(evidence.projection, EvidenceProjection::AccessLost),
            provider_unknown: matches!(evidence.projection, EvidenceProjection::ProviderUnknown),
            adoptable: false,
            native: false,
            connected: false,
            evidence_digest: evidence.evidence_digest.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            verification_digest: Digest::from_text("pending-verification-digest"),
        };
        Ok(Self {
            verification_digest: digest_serializable(&VerificationDigestView {
                verified: verification.verified,
                complete: verification.complete,
                access_lost: verification.access_lost,
                provider_unknown: verification.provider_unknown,
                adoptable: verification.adoptable,
                native: verification.native,
                connected: verification.connected,
                evidence_digest: &verification.evidence_digest,
                receipt_digest: &verification.receipt_digest,
            }),
            ..verification
        })
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        let expected = digest_serializable(&VerificationDigestView {
            verified: self.verified,
            complete: self.complete,
            access_lost: self.access_lost,
            provider_unknown: self.provider_unknown,
            adoptable: self.adoptable,
            native: self.native,
            connected: self.connected,
            evidence_digest: &self.evidence_digest,
            receipt_digest: &self.receipt_digest,
        });
        if !self.verified
            || self.adoptable
            || self.native
            || self.connected
            || self.verification_digest != expected
        {
            return Err(ModelError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingsGroupVerification {
    pub verified: bool,
    pub complete: bool,
    pub access_lost: bool,
    pub provider_unknown: bool,
    pub adoptable: bool,
    pub native: bool,
    pub connected: bool,
    pub evidence_digest: Digest,
    pub receipt_digest: Digest,
    pub verification_digest: Digest,
}

impl FindingsGroupVerification {
    pub fn from_receipt(receipt: &FindingsGroupReceipt) -> Result<Self, ModelError> {
        receipt.validate_integrity()?;
        let evidence = &receipt.evidence;
        let verification = Self {
            verified: true,
            complete: matches!(evidence.projection, EvidenceProjection::Complete),
            access_lost: matches!(evidence.projection, EvidenceProjection::AccessLost),
            provider_unknown: matches!(evidence.projection, EvidenceProjection::ProviderUnknown),
            adoptable: false,
            native: false,
            connected: false,
            evidence_digest: evidence.evidence_digest.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            verification_digest: Digest::from_text("pending-verification-digest"),
        };
        Ok(Self {
            verification_digest: digest_serializable(&VerificationDigestView {
                verified: verification.verified,
                complete: verification.complete,
                access_lost: verification.access_lost,
                provider_unknown: verification.provider_unknown,
                adoptable: verification.adoptable,
                native: verification.native,
                connected: verification.connected,
                evidence_digest: &verification.evidence_digest,
                receipt_digest: &verification.receipt_digest,
            }),
            ..verification
        })
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        let expected = digest_serializable(&VerificationDigestView {
            verified: self.verified,
            complete: self.complete,
            access_lost: self.access_lost,
            provider_unknown: self.provider_unknown,
            adoptable: self.adoptable,
            native: self.native,
            connected: self.connected,
            evidence_digest: &self.evidence_digest,
            receipt_digest: &self.receipt_digest,
        });
        if !self.verified
            || self.adoptable
            || self.native
            || self.connected
            || self.verification_digest != expected
        {
            return Err(ModelError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct VerificationDigestView<'a> {
    verified: bool,
    complete: bool,
    access_lost: bool,
    provider_unknown: bool,
    adoptable: bool,
    native: bool,
    connected: bool,
    evidence_digest: &'a Digest,
    receipt_digest: &'a Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionAvailability {
    NotAdoptedLayer2,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionResultState {
    PendingDecision,
    Layer2AdoptionRequired,
    AccessLost,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionObservation {
    FindingsList(FindingsListEvidence),
    FindingsGroup(FindingsGroupEvidence),
}

/// Name used by callers that model the optional `findings.group` operation
/// directly.
pub type FindingsGroupRequest = GroupFindingsRequest;
