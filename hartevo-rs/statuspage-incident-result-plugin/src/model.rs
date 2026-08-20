use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_TEXT_BYTES: usize = 256;
pub const MAX_COMPONENTS: usize = 100;
pub const MAX_COMPONENT_GROUPS: usize = 100;
pub const MAX_INCIDENTS: usize = 100;
pub const MAX_UPDATES: usize = 100;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS_PER_MINUTE: u16 = 60;
pub const MAX_RETRY_AFTER_SECONDS: u32 = 3_600;
pub const MAX_WINDOW_DAYS: i64 = 31;
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;

pub type Digest = String;

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    hex::encode(Sha256::digest(bytes))
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("Statuspage typed value serializes");
    sha256_digest(&bytes)
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{label} is empty, malformed, or too long")]
    InvalidIdentifier { label: &'static str },
    #[error("{label} is empty, malformed, or too long")]
    InvalidText { label: &'static str },
    #[error("{label} revision must be non-zero")]
    InvalidRevision { label: &'static str },
    #[error("time window is invalid or exceeds the Layer-1 day bound")]
    InvalidTimeWindow,
    #[error("consent scope is invalid")]
    InvalidConsent,
    #[error("permission scope is invalid")]
    InvalidPermission,
    #[error("digest is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("scope is invalid: {0}")]
    InvalidScope(&'static str),
    #[error("provider response is invalid for the requested Statuspage seam")]
    InvalidProviderResponse,
    #[error("provider response contains duplicate, out-of-window, or unbounded data")]
    InvalidBoundedData,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration or secret is not revoked")]
    NotRevoked,
    #[error("registration revision overflowed")]
    RevisionOverflow,
}

fn validate_identifier(value: &str, label: &'static str) -> Result<(), ModelError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-$".contains(&byte))
    {
        return Err(ModelError::InvalidIdentifier { label });
    }
    Ok(())
}

fn validate_revision(revision: u64, label: &'static str) -> Result<(), ModelError> {
    if revision == 0 {
        Err(ModelError::InvalidRevision { label })
    } else {
        Ok(())
    }
}

fn validate_digest(value: &str) -> Result<(), ModelError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ModelError::InvalidDigest)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Identifier(String);

impl Identifier {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "identifier")?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

pub type OrganizationId = Identifier;
pub type PageId = Identifier;
pub type ComponentId = Identifier;
pub type ComponentGroupId = Identifier;
pub type IncidentId = Identifier;
pub type UpdateId = Identifier;
pub type ProjectId = Identifier;
pub type MissionId = Identifier;
pub type WorkProductId = Identifier;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        validate_revision(value, "revision")?;
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

pub type OrganizationRevision = Revision;
pub type PageRevision = Revision;
pub type ComponentRevision = Revision;
pub type ComponentGroupRevision = Revision;
pub type MissionRevision = Revision;
pub type WorkProductRevision = Revision;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceBinding {
    id: Identifier,
    revision: Revision,
}

impl ResourceBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: Identifier::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

pub type OrganizationBinding = ResourceBinding;
pub type PageBinding = ResourceBinding;
pub type ComponentBinding = ResourceBinding;
pub type ComponentGroupBinding = ResourceBinding;
pub type ProjectBinding = ResourceBinding;
pub type MissionBinding = ResourceBinding;
pub type WorkProductBinding = ResourceBinding;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TimeWindow {
    start: String,
    end: String,
    revision: Revision,
}

impl TimeWindow {
    pub fn new(
        start: impl Into<String>,
        end: impl Into<String>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let start = start.into();
        let end = end.into();
        validate_timestamp(&start)?;
        validate_timestamp(&end)?;
        validate_revision(revision, "time window")?;
        let start_day = timestamp_day(&start).ok_or(ModelError::InvalidTimeWindow)?;
        let end_day = timestamp_day(&end).ok_or(ModelError::InvalidTimeWindow)?;
        if start > end || end_day - start_day + 1 > MAX_WINDOW_DAYS {
            return Err(ModelError::InvalidTimeWindow);
        }
        Ok(Self {
            start,
            end,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn start(&self) -> &str {
        &self.start
    }

    #[must_use]
    pub fn end(&self) -> &str {
        &self.end
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn inclusive_days(&self) -> u16 {
        let start = timestamp_day(&self.start).expect("validated start timestamp");
        let end = timestamp_day(&self.end).expect("validated end timestamp");
        (end - start + 1) as u16
    }

    #[must_use]
    pub fn contains(&self, timestamp: &str) -> bool {
        timestamp_day(timestamp).is_some_and(|day| {
            let start = timestamp_day(&self.start).expect("validated start timestamp");
            let end = timestamp_day(&self.end).expect("validated end timestamp");
            day >= start && day <= end
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Self::new(self.start.clone(), self.end.clone(), self.revision.get()).map(|_| ())
    }
}

fn validate_timestamp(value: &str) -> Result<(), ModelError> {
    if value.len() < 10 || value.len() > 64 || value.chars().any(char::is_control) {
        return Err(ModelError::InvalidTimeWindow);
    }
    let bytes = value.as_bytes();
    if bytes.get(4) != Some(&b'-') || bytes.get(7) != Some(&b'-') {
        return Err(ModelError::InvalidTimeWindow);
    }
    if parse_date(value).is_none() {
        return Err(ModelError::InvalidTimeWindow);
    }
    if value.len() > 10
        && (bytes.get(10) != Some(&b'T')
            || bytes.get(13) != Some(&b':')
            || bytes.get(16) != Some(&b':'))
    {
        return Err(ModelError::InvalidTimeWindow);
    }
    Ok(())
}

fn timestamp_day(value: &str) -> Option<i64> {
    parse_date(value).map(days_from_civil)
}

fn parse_date(value: &str) -> Option<(i64, i64, i64)> {
    let bytes = value.as_bytes();
    if bytes.len() < 10
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || !bytes[..4].iter().all(u8::is_ascii_digit)
        || !bytes[5..7].iter().all(u8::is_ascii_digit)
        || !bytes[8..10].iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    let year = value[0..4].parse::<i64>().ok()?;
    let month = value[5..7].parse::<i64>().ok()?;
    let day = value[8..10].parse::<i64>().ok()?;
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        None
    } else {
        Some((year, month, day))
    }
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn days_from_civil((year, month, day): (i64, i64, i64)) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StatuspagePermission {
    ReadPage,
    ReadComponents,
    ReadComponentGroups,
    ReadIncidents,
    ReadUpdates,
    ReadMaintenance,
}

impl StatuspagePermission {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ReadPage => "read_page",
            Self::ReadComponents => "read_components",
            Self::ReadComponentGroups => "read_component_groups",
            Self::ReadIncidents => "read_incidents",
            Self::ReadUpdates => "read_updates",
            Self::ReadMaintenance => "read_maintenance",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatuspageAcl {
    permissions: BTreeSet<StatuspagePermission>,
    revision: Revision,
}

impl StatuspageAcl {
    #[must_use]
    pub fn required_permissions() -> [StatuspagePermission; 6] {
        [
            StatuspagePermission::ReadPage,
            StatuspagePermission::ReadComponents,
            StatuspagePermission::ReadComponentGroups,
            StatuspagePermission::ReadIncidents,
            StatuspagePermission::ReadUpdates,
            StatuspagePermission::ReadMaintenance,
        ]
    }

    pub fn read_only(revision: u64) -> Result<Self, ModelError> {
        Self::new(Self::required_permissions(), revision)
    }

    pub fn least_privilege(revision: u64) -> Result<Self, ModelError> {
        Self::read_only(revision)
    }

    pub fn new(
        permissions: impl IntoIterator<Item = StatuspagePermission>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let acl = Self {
            permissions: permissions.into_iter().collect(),
            revision: Revision::new(revision)?,
        };
        acl.validate()?;
        Ok(acl)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.permissions.is_empty() {
            return Err(ModelError::InvalidPermission);
        }
        validate_revision(self.revision.get(), "permission scope")
    }

    #[must_use]
    pub fn permissions(&self) -> &BTreeSet<StatuspagePermission> {
        &self.permissions
    }

    #[must_use]
    pub fn has(&self, permission: StatuspagePermission) -> bool {
        self.permissions.contains(&permission)
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

/// An opaque host-owned handle. The token or secret bytes never enter this
/// type, its Debug output, any request, or any serializable registration.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    opaque_id: String,
    revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(opaque_id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        let opaque_id = opaque_id.into();
        validate_identifier(&opaque_id, "secret reference")?;
        Ok(Self {
            opaque_id,
            revision: Revision::new(revision)?,
            revoked: false,
        })
    }

    pub fn api_credential(opaque_id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Self::new(opaque_id, revision)
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        sha256_digest(
            format!(
                "statuspage-secret-reference/v1|{}|{}",
                self.opaque_id,
                self.revision.get()
            )
            .as_bytes(),
        )
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        self.revoked = true;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if !self.revoked {
            return Err(ModelError::NotRevoked);
        }
        self.revoked = false;
        Ok(())
    }
}

#[allow(clippy::missing_fields_in_debug)]
impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("digest", &self.digest())
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    consent_digest: Digest,
    revision: Revision,
}

impl ConsentScope {
    pub fn new(reference: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        let reference = reference.into();
        validate_identifier(&reference, "consent reference")
            .map_err(|_| ModelError::InvalidConsent)?;
        Ok(Self {
            consent_digest: sha256_digest(format!("statuspage-consent/v1|{reference}").as_bytes()),
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.consent_digest
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        validate_digest(&self.consent_digest)?;
        validate_revision(self.revision.get(), "consent")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StatuspageIncidentResultScope {
    organization: OrganizationBinding,
    page: PageBinding,
    components: Vec<ComponentBinding>,
    component_groups: Vec<ComponentGroupBinding>,
    time_window: TimeWindow,
    project: ProjectBinding,
    mission: MissionBinding,
    work_product: WorkProductBinding,
    consent: ConsentScope,
    acl: StatuspageAcl,
    scope_digest: Digest,
    revision_digest: Digest,
    privacy_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatuspageIncidentResultScopeSpec {
    pub organization: OrganizationBinding,
    pub page: PageBinding,
    pub components: Vec<ComponentBinding>,
    pub component_groups: Vec<ComponentGroupBinding>,
    pub time_window: TimeWindow,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub consent: ConsentScope,
    pub acl: StatuspageAcl,
}

impl StatuspageIncidentResultScopeSpec {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization: OrganizationBinding,
        page: PageBinding,
        components: Vec<ComponentBinding>,
        component_groups: Vec<ComponentGroupBinding>,
        time_window: TimeWindow,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        consent: ConsentScope,
        acl: StatuspageAcl,
    ) -> Self {
        Self {
            organization,
            page,
            components,
            component_groups,
            time_window,
            project,
            mission,
            work_product,
            consent,
            acl,
        }
    }

    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new_groups_first(
        organization: OrganizationBinding,
        page: PageBinding,
        component_groups: Vec<ComponentGroupBinding>,
        components: Vec<ComponentBinding>,
        time_window: TimeWindow,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        consent: ConsentScope,
        acl: StatuspageAcl,
    ) -> Self {
        Self::new(
            organization,
            page,
            components,
            component_groups,
            time_window,
            project,
            mission,
            work_product,
            consent,
            acl,
        )
    }
}

impl StatuspageIncidentResultScope {
    pub fn new(spec: StatuspageIncidentResultScopeSpec) -> Result<Self, ModelError> {
        if spec.components.len() > MAX_COMPONENTS {
            return Err(ModelError::InvalidScope("components"));
        }
        if spec.component_groups.len() > MAX_COMPONENT_GROUPS {
            return Err(ModelError::InvalidScope("component groups"));
        }
        if duplicate_bindings(&spec.components) || duplicate_bindings(&spec.component_groups) {
            return Err(ModelError::InvalidScope("duplicate component binding"));
        }
        spec.time_window.validate()?;
        spec.consent.validate()?;
        spec.acl.validate()?;
        let scope_digest = scope_digest(&spec);
        let revision_digest = revision_digest(&spec);
        let privacy_digest = privacy_digest(&spec);
        Ok(Self {
            organization: spec.organization,
            page: spec.page,
            components: spec.components,
            component_groups: spec.component_groups,
            time_window: spec.time_window,
            project: spec.project,
            mission: spec.mission,
            work_product: spec.work_product,
            consent: spec.consent,
            acl: spec.acl,
            scope_digest,
            revision_digest,
            privacy_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let spec = self.spec();
        if scope_digest(&spec) != self.scope_digest {
            return Err(ModelError::InvalidScope("scope digest"));
        }
        if revision_digest(&spec) != self.revision_digest {
            return Err(ModelError::InvalidScope("revision digest"));
        }
        if privacy_digest(&spec) != self.privacy_digest {
            return Err(ModelError::InvalidScope("privacy digest"));
        }
        Ok(())
    }

    #[must_use]
    pub fn spec(&self) -> StatuspageIncidentResultScopeSpec {
        StatuspageIncidentResultScopeSpec {
            organization: self.organization.clone(),
            page: self.page.clone(),
            components: self.components.clone(),
            component_groups: self.component_groups.clone(),
            time_window: self.time_window.clone(),
            project: self.project.clone(),
            mission: self.mission.clone(),
            work_product: self.work_product.clone(),
            consent: self.consent.clone(),
            acl: self.acl.clone(),
        }
    }

    #[must_use]
    pub fn organization(&self) -> &OrganizationBinding {
        &self.organization
    }

    #[must_use]
    pub fn page(&self) -> &PageBinding {
        &self.page
    }

    #[must_use]
    pub fn components(&self) -> &[ComponentBinding] {
        &self.components
    }

    #[must_use]
    pub fn component_groups(&self) -> &[ComponentGroupBinding] {
        &self.component_groups
    }

    #[must_use]
    pub fn time_window(&self) -> &TimeWindow {
        &self.time_window
    }

    #[must_use]
    pub fn window(&self) -> &TimeWindow {
        self.time_window()
    }

    #[must_use]
    pub fn project(&self) -> &ProjectBinding {
        &self.project
    }

    #[must_use]
    pub fn mission(&self) -> &MissionBinding {
        &self.mission
    }

    #[must_use]
    pub fn work_product(&self) -> &WorkProductBinding {
        &self.work_product
    }

    #[must_use]
    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    #[must_use]
    pub fn acl(&self) -> &StatuspageAcl {
        &self.acl
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    #[must_use]
    pub fn revision_digest(&self) -> &Digest {
        &self.revision_digest
    }

    #[must_use]
    pub fn privacy_digest(&self) -> &Digest {
        &self.privacy_digest
    }

    #[must_use]
    pub fn acl_digest(&self) -> Digest {
        self.acl.digest()
    }

    #[must_use]
    pub fn consent_digest(&self) -> &Digest {
        self.consent.digest()
    }
}

fn duplicate_bindings(bindings: &[ResourceBinding]) -> bool {
    let ids = bindings
        .iter()
        .map(ResourceBinding::id)
        .collect::<BTreeSet<_>>();
    ids.len() != bindings.len()
}

fn scope_digest(spec: &StatuspageIncidentResultScopeSpec) -> Digest {
    canonical_digest(&(
        "statuspage-incident-result-scope/v1",
        &spec.organization,
        &spec.page,
        &spec.components,
        &spec.component_groups,
        &spec.time_window,
        &spec.project,
        &spec.mission,
        &spec.work_product,
        &spec.consent,
        &spec.acl,
    ))
}

fn revision_digest(spec: &StatuspageIncidentResultScopeSpec) -> Digest {
    canonical_digest(&(
        "statuspage-incident-result-revisions/v1",
        spec.organization.revision(),
        spec.page.revision(),
        spec.components
            .iter()
            .map(ResourceBinding::revision)
            .collect::<Vec<_>>(),
        spec.component_groups
            .iter()
            .map(ResourceBinding::revision)
            .collect::<Vec<_>>(),
        spec.time_window.revision(),
        spec.project.revision(),
        spec.mission.revision(),
        spec.work_product.revision(),
        spec.consent.revision(),
        spec.acl.revision(),
    ))
}

fn privacy_digest(spec: &StatuspageIncidentResultScopeSpec) -> Digest {
    canonical_digest(&(
        "statuspage-incident-result-privacy/v1",
        "secret_reference_opaque",
        "raw_response_dropped",
        "update_bodies_dropped",
        "postmortem_body_dropped",
        "internal_notes_dropped",
        "subscriber_contact_dropped",
        "provider_metadata_dropped",
        spec.consent.digest(),
    ))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    Investigating,
    Identified,
    Monitoring,
    Resolved,
    Closed,
    Scheduled,
    InProgress,
    Maintenance,
    Partial,
    AccessLost,
    ProviderUnknown,
}

impl IncidentStatus {
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "investigating" => Self::Investigating,
            "identified" => Self::Identified,
            "monitoring" => Self::Monitoring,
            "resolved" => Self::Resolved,
            "closed" => Self::Closed,
            "scheduled" => Self::Scheduled,
            "in_progress" | "in progress" => Self::InProgress,
            "maintenance" => Self::Maintenance,
            "partial" | "partial_outage" => Self::Partial,
            _ => Self::ProviderUnknown,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Investigating => "investigating",
            Self::Identified => "identified",
            Self::Monitoring => "monitoring",
            Self::Resolved => "resolved",
            Self::Closed => "closed",
            Self::Scheduled => "scheduled",
            Self::InProgress => "in_progress",
            Self::Maintenance => "maintenance",
            Self::Partial => "partial",
            Self::AccessLost => "access_lost",
            Self::ProviderUnknown => "provider_unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentStatus {
    Operational,
    DegradedPerformance,
    PartialOutage,
    MajorOutage,
    Maintenance,
    AccessLost,
    ProviderUnknown,
}

impl ComponentStatus {
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "operational" => Self::Operational,
            "degraded_performance" | "degraded performance" => Self::DegradedPerformance,
            "partial_outage" | "partial outage" => Self::PartialOutage,
            "major_outage" | "major outage" => Self::MajorOutage,
            "under_maintenance" | "maintenance" => Self::Maintenance,
            _ => Self::ProviderUnknown,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Operational => "operational",
            Self::DegradedPerformance => "degraded_performance",
            Self::PartialOutage => "partial_outage",
            Self::MajorOutage => "major_outage",
            Self::Maintenance => "maintenance",
            Self::AccessLost => "access_lost",
            Self::ProviderUnknown => "provider_unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentImpact {
    None,
    Minor,
    Major,
    Critical,
    ProviderUnknown,
}

impl IncidentImpact {
    #[must_use]
    pub fn parse(value: Option<&str>) -> Self {
        match value
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "none" => Self::None,
            "minor" => Self::Minor,
            "major" => Self::Major,
            "critical" => Self::Critical,
            _ => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceState {
    Scheduled,
    InProgress,
    Completed,
    AccessLost,
    ProviderUnknown,
}

impl MaintenanceState {
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "scheduled" => Self::Scheduled,
            "in_progress" | "in progress" | "maintenance" => Self::InProgress,
            "completed" | "resolved" | "closed" => Self::Completed,
            _ => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum StatuspageHttpMethod {
    Get,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_first_party(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StatuspageReadSeam {
    PageProfile,
    Components,
    ComponentGroups,
    Incidents,
    ScheduledMaintenances,
}

impl StatuspageReadSeam {
    #[must_use]
    pub const fn permission(self) -> StatuspagePermission {
        match self {
            Self::PageProfile => StatuspagePermission::ReadPage,
            Self::Components => StatuspagePermission::ReadComponents,
            Self::ComponentGroups => StatuspagePermission::ReadComponentGroups,
            Self::Incidents => StatuspagePermission::ReadIncidents,
            Self::ScheduledMaintenances => StatuspagePermission::ReadMaintenance,
        }
    }

    #[must_use]
    pub const fn path_template(self) -> &'static str {
        match self {
            Self::PageProfile => "/pages/{page_id}",
            Self::Components => "/pages/{page_id}/components",
            Self::ComponentGroups => "/pages/{page_id}/component-groups",
            Self::Incidents => "/pages/{page_id}/incidents",
            Self::ScheduledMaintenances => "/pages/{page_id}/incidents/scheduled",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatuspageRateLimitReceipt {
    pub limit_per_minute: u16,
    pub remaining: Option<u16>,
    pub retry_after_seconds: Option<u32>,
    pub throttled: bool,
}

impl Default for StatuspageRateLimitReceipt {
    fn default() -> Self {
        Self {
            limit_per_minute: MAX_REQUESTS_PER_MINUTE,
            remaining: None,
            retry_after_seconds: None,
            throttled: false,
        }
    }
}

impl StatuspageRateLimitReceipt {
    pub fn new(
        limit_per_minute: u16,
        remaining: Option<u16>,
        retry_after_seconds: Option<u32>,
        throttled: bool,
    ) -> Result<Self, ModelError> {
        if limit_per_minute == 0
            || limit_per_minute > MAX_REQUESTS_PER_MINUTE
            || remaining.is_some_and(|value| value > limit_per_minute)
            || retry_after_seconds.is_some_and(|value| value > MAX_RETRY_AFTER_SECONDS)
        {
            return Err(ModelError::InvalidScope("rate limit receipt"));
        }
        Ok(Self {
            limit_per_minute,
            remaining,
            retry_after_seconds,
            throttled,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatuspageRequest {
    pub method: StatuspageHttpMethod,
    pub host: String,
    pub api_revision: String,
    pub seam: StatuspageReadSeam,
    pub path: String,
    pub page_id: PageId,
    pub page: u16,
    pub per_page: u16,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub request_digest: Digest,
}

impl StatuspageRequest {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            self.method,
            &self.host,
            &self.api_revision,
            self.seam,
            &self.path,
            &self.page_id,
            self.page,
            self.per_page,
            &self.scope_digest,
            &self.consent_digest,
            &self.secret_reference_digest,
        ))
    }

    #[must_use]
    pub fn endpoint(&self) -> String {
        format!(
            "{}/{}/{}",
            self.host,
            self.api_revision,
            self.path.trim_start_matches('/')
        )
    }

    #[must_use]
    pub fn is_allowlisted(&self) -> bool {
        self.method == StatuspageHttpMethod::Get
            && self.host == "https://api.statuspage.io"
            && self.api_revision == "v1"
            && self.path
                == self
                    .seam
                    .path_template()
                    .replace("{page_id}", self.page_id.as_str())
            && self.page == 1
            && self.per_page == 100
            && self.request_digest == self.digest()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatuspageRequestReceipt {
    pub method: StatuspageHttpMethod,
    pub seam: StatuspageReadSeam,
    pub endpoint: String,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub status_code: Option<u16>,
    pub response_bytes: usize,
    pub rate_limit_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatuspagePageProfile {
    pub id: PageId,
    pub updated_at: Option<String>,
    pub time_zone: Option<String>,
    pub public_url_digest: Option<Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatuspageComponentObservation {
    pub id: ComponentId,
    pub page_id: PageId,
    pub group_id: Option<ComponentGroupId>,
    pub name_digest: Digest,
    pub status: ComponentStatus,
    pub updated_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatuspageComponentGroupObservation {
    pub id: ComponentGroupId,
    pub page_id: PageId,
    pub name_digest: Digest,
    pub component_ids: Vec<ComponentId>,
    pub updated_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatuspageAffectedComponent {
    pub component_id: ComponentId,
    pub old_status: ComponentStatus,
    pub new_status: ComponentStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatuspageIncidentUpdate {
    pub id: UpdateId,
    pub incident_id: IncidentId,
    pub status: IncidentStatus,
    pub created_at: Option<String>,
    pub display_at: Option<String>,
    pub updated_at: Option<String>,
    pub body_digest: Option<Digest>,
    pub affected_components: Vec<StatuspageAffectedComponent>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatuspageIncidentObservation {
    pub id: IncidentId,
    pub page_id: PageId,
    pub name_digest: Digest,
    pub status: IncidentStatus,
    pub impact: IncidentImpact,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub monitoring_at: Option<String>,
    pub resolved_at: Option<String>,
    pub scheduled_for: Option<String>,
    pub scheduled_until: Option<String>,
    pub component_ids: Vec<ComponentId>,
    pub updates: Vec<StatuspageIncidentUpdate>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatuspageMaintenanceObservation {
    pub incident_id: IncidentId,
    pub page_id: PageId,
    pub state: MaintenanceState,
    pub scheduled_for: Option<String>,
    pub scheduled_until: Option<String>,
    pub component_ids: Vec<ComponentId>,
    pub updates: Vec<StatuspageIncidentUpdate>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatuspageIncidentResult {
    pub page: Option<StatuspagePageProfile>,
    pub components: Vec<StatuspageComponentObservation>,
    pub component_groups: Vec<StatuspageComponentGroupObservation>,
    pub incidents: Vec<StatuspageIncidentObservation>,
    pub maintenances: Vec<StatuspageMaintenanceObservation>,
    pub partial: bool,
}

impl StatuspageIncidentResult {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            page: None,
            components: Vec::new(),
            component_groups: Vec::new(),
            incidents: Vec::new(),
            maintenances: Vec::new(),
            partial: false,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.page.is_none()
            && self.components.is_empty()
            && self.component_groups.is_empty()
            && self.incidents.is_empty()
            && self.maintenances.is_empty()
    }

    #[must_use]
    pub fn has_maintenance(&self) -> bool {
        !self.maintenances.is_empty()
            || self.incidents.iter().any(|incident| {
                matches!(
                    incident.status,
                    IncidentStatus::Maintenance
                        | IncidentStatus::Scheduled
                        | IncidentStatus::InProgress
                )
            })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Complete,
    Partial,
    Maintenance,
    Empty,
    RateLimited,
    AccessLost,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClassification {
    Normalized,
    Partial,
    Maintenance,
    Empty,
    RateLimited,
    AccessLost,
    ProviderUnknown,
    BlockedEnv,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatuspageEvidenceDigests {
    pub contract_digest: Digest,
    pub plugin_version_digest: Digest,
    pub provider_digest: Digest,
    pub registration_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub time_window_digest: Digest,
    pub page_digest: Digest,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub result_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatuspageIncidentResultEvidence {
    pub scope: StatuspageIncidentResultScope,
    pub state: EvidenceState,
    pub classification: EvidenceClassification,
    pub result: Option<StatuspageIncidentResult>,
    pub request_receipts: Vec<StatuspageRequestReceipt>,
    pub rate_limit: StatuspageRateLimitReceipt,
    pub provenance: TransportProvenance,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub digests: StatuspageEvidenceDigests,
    pub evidence_digest: Digest,
}

impl StatuspageIncidentResultEvidence {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            &self.scope,
            &self.state,
            &self.classification,
            &self.result,
            &self.request_receipts,
            &self.rate_limit,
            &self.provenance,
            self.native,
            self.connected,
            self.first_party,
            &self.digests,
        ))
    }

    #[must_use]
    pub fn is_actionable(&self) -> bool {
        matches!(
            self.state,
            EvidenceState::Complete | EvidenceState::Maintenance
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationDisposition {
    ReviewIncidentEvidence,
    ReviewMaintenance,
    NeedsMoreEvidence,
    AccessLost,
    RateLimited,
    ProviderUnknown,
    NoPublishedIncident,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatuspageIncidentResultRecommendation {
    pub disposition: RecommendationDisposition,
    pub non_mutating: bool,
    pub provider_reported_only: bool,
    pub claims_customer_wide_uptime: bool,
    pub claims_causality: bool,
    pub claims_remediation: bool,
    pub claims_business_outcome: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatuspageIncidentResultProposal {
    pub scope: StatuspageIncidentResultScope,
    pub evidence: StatuspageIncidentResultEvidence,
    pub source_evidence_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub permission_digest: Digest,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub adopts_outcome: bool,
    pub recommendation: StatuspageIncidentResultRecommendation,
    pub proposal_digest: Digest,
}

impl StatuspageIncidentResultProposal {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            &self.scope,
            &self.evidence,
            &self.source_evidence_digest,
            &self.registration_digest,
            &self.provider_digest,
            &self.contract_digest,
            &self.permission_digest,
            self.proposal_only,
            self.native,
            self.connected,
            self.first_party,
            self.adopts_outcome,
            &self.recommendation,
        ))
    }

    #[must_use]
    pub fn state(&self) -> EvidenceState {
        self.evidence.state.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservationReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub recorded: bool,
    pub durable: bool,
    pub native: bool,
    pub connected: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatuspageReadbackReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub status: String,
    pub independent_native_readback: bool,
    pub native: bool,
    pub connected: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocationReceipt {
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub revision: Revision,
    pub revoked: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatuspageRegistration {
    pub schema_version: String,
    pub contract_version: String,
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub time_window_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl StatuspageRegistration {
    pub fn bind(
        scope: &StatuspageIncidentResultScope,
        secret: &SecretReference,
        provider_digest: &Digest,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        let mut registration = Self {
            schema_version: crate::STATUSPAGE_INCIDENT_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: crate::STATUSPAGE_INCIDENT_RESULT_CONTRACT_VERSION.to_owned(),
            provider_id: crate::STATUSPAGE_PROVIDER_ID.to_owned(),
            provider_version: crate::STATUSPAGE_PROVIDER_VERSION.to_owned(),
            api_revision: crate::STATUSPAGE_API_REVISION.to_owned(),
            provider_digest: provider_digest.clone(),
            permission_digest: scope.acl_digest(),
            scope_digest: scope.digest(),
            revision_digest: scope.revision_digest().clone(),
            time_window_digest: scope.time_window().digest(),
            consent_digest: scope.consent_digest().clone(),
            secret_reference_digest: secret.digest(),
            registration_revision: Revision::new(1)?,
            state: RegistrationState::Active,
            registration_digest: String::new(),
        };
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&(
            &self.schema_version,
            &self.contract_version,
            &self.provider_id,
            &self.provider_version,
            &self.api_revision,
            &self.provider_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.revision_digest,
            &self.time_window_digest,
            &self.consent_digest,
            &self.secret_reference_digest,
            self.registration_revision,
            self.state,
        ))
    }

    pub fn validate(
        &self,
        scope: &StatuspageIncidentResultScope,
        secret: &SecretReference,
        provider_digest: &Digest,
    ) -> Result<(), ModelError> {
        scope.validate()?;
        if self.registration_digest != self.compute_digest()
            || self.provider_id != crate::STATUSPAGE_PROVIDER_ID
            || self.provider_version != crate::STATUSPAGE_PROVIDER_VERSION
            || self.api_revision != crate::STATUSPAGE_API_REVISION
            || self.provider_digest != *provider_digest
            || self.permission_digest != scope.acl_digest()
            || self.scope_digest != *scope.scope_digest()
            || self.revision_digest != *scope.revision_digest()
            || self.time_window_digest != scope.time_window().digest()
            || self.consent_digest != *scope.consent_digest()
            || self.secret_reference_digest != secret.digest()
        {
            return Err(ModelError::InvalidScope("registration digest fence"));
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocationReceipt, ModelError> {
        if self.state == RegistrationState::Revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        let previous = self.registration_digest.clone();
        self.state = RegistrationState::Revoked;
        self.registration_revision = Revision::new(
            self.registration_revision
                .get()
                .checked_add(1)
                .ok_or(ModelError::RevisionOverflow)?,
        )?;
        self.registration_digest = self.compute_digest();
        Ok(RegistrationRevocationReceipt {
            previous_registration_digest: previous,
            registration_digest: self.registration_digest.clone(),
            revision: self.registration_revision,
            revoked: true,
        })
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if self.state != RegistrationState::Revoked {
            return Err(ModelError::NotRevoked);
        }
        self.state = RegistrationState::Active;
        self.registration_revision = Revision::new(
            self.registration_revision
                .get()
                .checked_add(1)
                .ok_or(ModelError::RevisionOverflow)?,
        )?;
        self.registration_digest = self.compute_digest();
        Ok(())
    }

    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.state == RegistrationState::Revoked
    }
}

pub type StatuspageIncidentResultRegistration = StatuspageRegistration;
