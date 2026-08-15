use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_SECRET_REFERENCE_BYTES: usize = 256;
pub const MAX_QUERY_BYTES: usize = 512;
pub const MAX_DATE_WINDOW_DAYS: u16 = 366;
pub const MAX_ITEMS: usize = 100;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS_PER_MINUTE: u16 = 60;
pub const MAX_RETRY_AFTER_SECONDS: u32 = 3_600;

pub type Digest = String;

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    hex::encode(Sha256::digest(bytes))
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("bounded Looker value serializes");
    sha256_digest(&bytes)
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{label} is empty, malformed, or too long")]
    InvalidIdentifier { label: &'static str },
    #[error("Looker instance must be an HTTPS origin without credentials or a path")]
    InvalidInstance,
    #[error("{label} revision must be non-zero")]
    InvalidRevision { label: &'static str },
    #[error("date window is invalid or exceeds the Layer-1 bound")]
    InvalidDateWindow,
    #[error("digest is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("Looker permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("Looker consent scope is inactive or invalid")]
    InvalidConsent,
    #[error("Looker scope is invalid: {0}")]
    InvalidScope(&'static str),
    #[error("Looker request is invalid or outside its exact scope")]
    InvalidRequest,
    #[error("idempotency key is invalid")]
    InvalidIdempotencyKey,
    #[error("metadata aggregate is invalid or exceeds the Layer-1 bound")]
    InvalidAggregate,
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
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-$~".contains(&byte))
    {
        return Err(ModelError::InvalidIdentifier { label });
    }
    Ok(())
}

fn validate_revision(value: u64, label: &'static str) -> Result<(), ModelError> {
    if value == 0 {
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

    pub fn validate(&self, label: &'static str) -> Result<(), ModelError> {
        validate_identifier(&self.0, label)
    }
}

pub type FolderId = Identifier;
pub type DashboardId = Identifier;
pub type LookId = Identifier;
pub type QueryId = Identifier;
pub type ModelName = Identifier;
pub type ExploreName = Identifier;
pub type ProjectId = Identifier;
pub type MissionId = Identifier;
pub type WorkProductId = Identifier;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Instance {
    host: String,
}

impl Instance {
    pub fn new(host: impl Into<String>) -> Result<Self, ModelError> {
        let host = host.into();
        let authority = host.strip_prefix("https://").unwrap_or_default();
        let valid_origin = !authority.is_empty()
            && !authority.ends_with('/')
            && !authority.contains(['/', '?', '#', '@', ' '])
            && !authority.chars().any(char::is_control);
        if !valid_origin {
            return Err(ModelError::InvalidInstance);
        }
        if authority.is_empty() || authority == "." || authority.starts_with('.') {
            return Err(ModelError::InvalidInstance);
        }
        Ok(Self { host })
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Self::new(self.host.clone()).map(|_| ())
    }
}

pub type LookerInstance = Instance;
pub type InstanceId = Instance;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopeBinding {
    id: Identifier,
    revision: Revision,
}

impl ScopeBinding {
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

    pub fn validate(&self, label: &'static str) -> Result<(), ModelError> {
        self.id.validate(label)?;
        validate_revision(self.revision.get(), label)
    }
}

pub type ProjectBinding = ScopeBinding;
pub type MissionBinding = ScopeBinding;
pub type WorkProductBinding = ScopeBinding;
pub type Project = ProjectBinding;
pub type Mission = MissionBinding;
pub type WorkProduct = WorkProductBinding;

fn parse_date(value: &str) -> Option<(i32, u32, u32)> {
    if value.len() != 10
        || value.as_bytes().get(4) != Some(&b'-')
        || value.as_bytes().get(7) != Some(&b'-')
    {
        return None;
    }
    let year = value[0..4].parse::<i32>().ok()?;
    let month = value[5..7].parse::<u32>().ok()?;
    let day = value[8..10].parse::<u32>().ok()?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    (1..=9999).contains(&year).then_some(())?;
    (1..=12).contains(&month).then_some(())?;
    (1..=max_day).contains(&day).then_some((year, month, day))
}

fn days_from_civil((year, month, day): (i32, u32, u32)) -> i64 {
    let year = i64::from(year) - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DateWindow {
    start_date: String,
    end_date: String,
    days: u16,
}

impl DateWindow {
    pub fn new(
        start_date: impl Into<String>,
        end_date: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let start_date = start_date.into();
        let end_date = end_date.into();
        let start = parse_date(&start_date).ok_or(ModelError::InvalidDateWindow)?;
        let end = parse_date(&end_date).ok_or(ModelError::InvalidDateWindow)?;
        let delta = days_from_civil(end) - days_from_civil(start) + 1;
        if !(1..=i64::from(MAX_DATE_WINDOW_DAYS)).contains(&delta) {
            return Err(ModelError::InvalidDateWindow);
        }
        Ok(Self {
            start_date,
            end_date,
            days: u16::try_from(delta).map_err(|_| ModelError::InvalidDateWindow)?,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let canonical = Self::new(self.start_date.clone(), self.end_date.clone())?;
        if canonical.days != self.days {
            Err(ModelError::InvalidDateWindow)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn start_date(&self) -> &str {
        &self.start_date
    }

    #[must_use]
    pub fn end_date(&self) -> &str {
        &self.end_date
    }

    #[must_use]
    pub const fn days(&self) -> u16 {
        self.days
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LookerPermission {
    InstanceMetadata,
    FolderMetadata,
    DashboardMetadata,
    LookMetadata,
    QueryMetadata,
    ModelMetadata,
    ExploreMetadata,
    SearchMetadata,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LookerPermissionSnapshot {
    permissions: BTreeSet<LookerPermission>,
    revision: Revision,
    read_only: bool,
}

impl LookerPermissionSnapshot {
    pub fn new(
        permissions: impl IntoIterator<Item = LookerPermission>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let snapshot = Self {
            permissions: permissions.into_iter().collect(),
            revision: Revision::new(revision)?,
            read_only: true,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn read_only(revision: u64) -> Result<Self, ModelError> {
        Self::new(
            [
                LookerPermission::InstanceMetadata,
                LookerPermission::FolderMetadata,
                LookerPermission::DashboardMetadata,
                LookerPermission::LookMetadata,
                LookerPermission::QueryMetadata,
                LookerPermission::ModelMetadata,
                LookerPermission::ExploreMetadata,
                LookerPermission::SearchMetadata,
            ],
            revision,
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.permissions.is_empty() || !self.read_only || self.revision.get() == 0 {
            Err(ModelError::InvalidPermissionSnapshot)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn has(&self, permission: LookerPermission) -> bool {
        self.permissions.contains(&permission)
    }

    #[must_use]
    pub fn permissions(&self) -> &BTreeSet<LookerPermission> {
        &self.permissions
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    reference_digest: Digest,
    revision: Revision,
    active: bool,
}

impl ConsentScope {
    pub fn new(reference: impl AsRef<str>, revision: u64) -> Result<Self, ModelError> {
        let reference = reference.as_ref();
        if reference.is_empty()
            || reference.len() > MAX_IDENTIFIER_BYTES
            || reference.trim() != reference
            || reference.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidConsent);
        }
        Ok(Self {
            reference_digest: sha256_digest(
                format!("looker-consent-reference/v1|{reference}").as_bytes(),
            ),
            revision: Revision::new(revision)?,
            active: true,
        })
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        validate_digest(&self.reference_digest)?;
        validate_revision(self.revision.get(), "consent")?;
        if self.active {
            Ok(())
        } else {
            Err(ModelError::InvalidConsent)
        }
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if !self.active {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.active = false;
            Ok(())
        }
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if self.active {
            Err(ModelError::NotRevoked)
        } else {
            self.active = true;
            Ok(())
        }
    }
}

/// A client-secret reference contains only a digest of an opaque external
/// handle. The client secret itself is never accepted, stored, serialized, or
/// forwarded by this Layer-1 crate.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        client_secret_reference: impl AsRef<str>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let reference = client_secret_reference.as_ref();
        if reference.is_empty()
            || reference.len() > MAX_SECRET_REFERENCE_BYTES
            || reference.trim() != reference
            || reference.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidIdentifier {
                label: "client-secret reference",
            });
        }
        Ok(Self {
            reference_digest: sha256_digest(
                format!("looker-client-secret-reference/v1|{reference}").as_bytes(),
            ),
            revision: Revision::new(revision)?,
            revoked: false,
        })
    }

    pub fn client_secret(reference: impl AsRef<str>, revision: u64) -> Result<Self, ModelError> {
        Self::new(reference, revision)
    }

    pub fn api_credential(reference: impl AsRef<str>, revision: u64) -> Result<Self, ModelError> {
        Self::new(reference, revision)
    }

    pub fn from_digest(
        reference_digest: impl Into<String>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let reference_digest = reference_digest.into();
        validate_digest(&reference_digest)?;
        Ok(Self {
            reference_digest,
            revision: Revision::new(revision)?,
            revoked: false,
        })
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
                "looker-secret-reference/v1|{}|{}|{}",
                self.reference_digest,
                self.revision.get(),
                self.revoked
            )
            .as_bytes(),
        )
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if !self.revoked {
            Err(ModelError::NotRevoked)
        } else {
            self.revoked = false;
            Ok(())
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference", &"<redacted>")
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LookerSearchKind {
    Dashboards,
    Looks,
    Content,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LookerOperation {
    DashboardMetadata,
    LookMetadata,
    FolderMetadata,
    QueryMetadata,
    ModelMetadata,
    ExploreMetadata,
    SearchDashboards,
    SearchLooks,
    SearchContent,
    AggregateMetadata,
}

impl LookerOperation {
    #[must_use]
    pub const fn permission(self) -> LookerPermission {
        match self {
            Self::DashboardMetadata => LookerPermission::DashboardMetadata,
            Self::LookMetadata => LookerPermission::LookMetadata,
            Self::FolderMetadata => LookerPermission::FolderMetadata,
            Self::QueryMetadata => LookerPermission::QueryMetadata,
            Self::ModelMetadata => LookerPermission::ModelMetadata,
            Self::ExploreMetadata => LookerPermission::ExploreMetadata,
            Self::SearchDashboards | Self::SearchLooks | Self::SearchContent => {
                LookerPermission::SearchMetadata
            }
            Self::AggregateMetadata => LookerPermission::InstanceMetadata,
        }
    }

    #[must_use]
    pub const fn is_search(self) -> bool {
        matches!(
            self,
            Self::SearchDashboards | Self::SearchLooks | Self::SearchContent
        )
    }

    #[must_use]
    pub const fn search_kind(self) -> Option<LookerSearchKind> {
        match self {
            Self::SearchDashboards => Some(LookerSearchKind::Dashboards),
            Self::SearchLooks => Some(LookerSearchKind::Looks),
            Self::SearchContent => Some(LookerSearchKind::Content),
            _ => None,
        }
    }

    #[must_use]
    pub const fn resource_kind(self) -> LookerResourceKind {
        match self {
            Self::DashboardMetadata | Self::SearchDashboards => LookerResourceKind::Dashboard,
            Self::LookMetadata | Self::SearchLooks => LookerResourceKind::Look,
            Self::FolderMetadata => LookerResourceKind::Folder,
            Self::QueryMetadata => LookerResourceKind::Query,
            Self::ModelMetadata => LookerResourceKind::Model,
            Self::ExploreMetadata => LookerResourceKind::Explore,
            Self::SearchContent | Self::AggregateMetadata => LookerResourceKind::Content,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LookerResourceKind {
    Dashboard,
    Look,
    Folder,
    Query,
    Model,
    Explore,
    Content,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LookerAnalyticsScopeSpec {
    pub instance: Instance,
    pub folder: Option<FolderId>,
    pub dashboard: Option<DashboardId>,
    pub look: Option<LookId>,
    pub query: Option<QueryId>,
    pub model: ModelName,
    pub explore: ExploreName,
    pub date_window: DateWindow,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub permissions: LookerPermissionSnapshot,
    pub consent: ConsentScope,
    pub scope_revision: Revision,
}

#[allow(clippy::too_many_arguments)]
impl LookerAnalyticsScopeSpec {
    pub fn new(
        instance: Instance,
        folder: Option<FolderId>,
        dashboard: Option<DashboardId>,
        look: Option<LookId>,
        query: Option<QueryId>,
        model: ModelName,
        explore: ExploreName,
        date_window: DateWindow,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        permissions: LookerPermissionSnapshot,
        consent: ConsentScope,
        scope_revision: u64,
    ) -> Result<Self, ModelError> {
        let spec = Self {
            instance,
            folder,
            dashboard,
            look,
            query,
            model,
            explore,
            date_window,
            project,
            mission,
            work_product,
            permissions,
            consent,
            scope_revision: Revision::new(scope_revision)?,
        };
        spec.validate()?;
        Ok(spec)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.instance.validate()?;
        if let Some(folder) = &self.folder {
            folder.validate("folder")?;
        }
        if let Some(dashboard) = &self.dashboard {
            dashboard.validate("dashboard")?;
        }
        if let Some(look) = &self.look {
            look.validate("look")?;
        }
        if let Some(query) = &self.query {
            query.validate("query")?;
        }
        self.model.validate("model")?;
        self.explore.validate("explore")?;
        self.date_window.validate()?;
        self.project.validate("project")?;
        self.mission.validate("mission")?;
        self.work_product.validate("work product")?;
        if self.model.as_str().is_empty() || self.explore.as_str().is_empty() {
            return Err(ModelError::InvalidScope("model and explore are required"));
        }
        self.permissions.validate()?;
        self.consent.validate()?;
        validate_revision(self.scope_revision.get(), "scope")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LookerAnalyticsScope {
    spec: LookerAnalyticsScopeSpec,
    scope_digest: Digest,
    revision_digest: Digest,
}

impl LookerAnalyticsScope {
    pub fn new(spec: LookerAnalyticsScopeSpec) -> Result<Self, ModelError> {
        spec.validate()?;
        let scope_digest = canonical_digest(&("looker-scope/v1", &spec));
        let revision_digest = canonical_digest(&(
            "looker-revision-fence/v1",
            spec.scope_revision,
            spec.project.revision(),
            spec.mission.revision(),
            spec.work_product.revision(),
            spec.permissions.revision(),
            spec.consent.revision(),
        ));
        Ok(Self {
            spec,
            scope_digest,
            revision_digest,
        })
    }

    #[must_use]
    pub fn spec(&self) -> &LookerAnalyticsScopeSpec {
        &self.spec
    }

    #[must_use]
    pub fn instance(&self) -> &Instance {
        &self.spec.instance
    }

    #[must_use]
    pub fn folder(&self) -> Option<&FolderId> {
        self.spec.folder.as_ref()
    }

    #[must_use]
    pub fn dashboard(&self) -> Option<&DashboardId> {
        self.spec.dashboard.as_ref()
    }

    #[must_use]
    pub fn look(&self) -> Option<&LookId> {
        self.spec.look.as_ref()
    }

    #[must_use]
    pub fn query(&self) -> Option<&QueryId> {
        self.spec.query.as_ref()
    }

    #[must_use]
    pub fn model(&self) -> &ModelName {
        &self.spec.model
    }

    #[must_use]
    pub fn explore(&self) -> &ExploreName {
        &self.spec.explore
    }

    #[must_use]
    pub fn date_window(&self) -> &DateWindow {
        &self.spec.date_window
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
    pub fn work_product(&self) -> &WorkProductBinding {
        &self.spec.work_product
    }

    #[must_use]
    pub fn permissions(&self) -> &LookerPermissionSnapshot {
        &self.spec.permissions
    }

    #[must_use]
    pub fn consent(&self) -> &ConsentScope {
        &self.spec.consent
    }

    #[must_use]
    pub const fn scope_revision(&self) -> Revision {
        self.spec.scope_revision
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn revision_digest(&self) -> &Digest {
        &self.revision_digest
    }

    #[must_use]
    pub fn permission_digest(&self) -> Digest {
        self.permissions().digest()
    }

    #[must_use]
    pub fn consent_digest(&self) -> Digest {
        self.consent().digest()
    }

    #[must_use]
    pub fn project_digest(&self) -> Digest {
        self.project().digest()
    }

    #[must_use]
    pub fn mission_digest(&self) -> Digest {
        self.mission().digest()
    }

    #[must_use]
    pub fn work_product_digest(&self) -> Digest {
        self.work_product().digest()
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.spec.validate()?;
        if self.scope_digest != canonical_digest(&("looker-scope/v1", &self.spec))
            || self.revision_digest
                != canonical_digest(&(
                    "looker-revision-fence/v1",
                    self.spec.scope_revision,
                    self.spec.project.revision(),
                    self.spec.mission.revision(),
                    self.spec.work_product.revision(),
                    self.spec.permissions.revision(),
                    self.spec.consent.revision(),
                ))
        {
            return Err(ModelError::InvalidScope("scope digest"));
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdempotencyKey {
    digest: Digest,
}

impl IdempotencyKey {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        if value.is_empty()
            || value.len() > MAX_QUERY_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidIdempotencyKey);
        }
        Ok(Self {
            digest: sha256_digest(format!("looker-idempotency-key/v1|{value}").as_bytes()),
        })
    }

    pub fn from_digest(digest: impl Into<String>) -> Result<Self, ModelError> {
        let digest = digest.into();
        validate_digest(&digest).map_err(|_| ModelError::InvalidIdempotencyKey)?;
        Ok(Self { digest })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

impl fmt::Debug for IdempotencyKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdempotencyKey")
            .field("digest", &self.digest)
            .finish()
    }
}

/// Opaque pagination material. The raw Looker cursor is never serialized or
/// exposed; only its digest is bound to the request/evidence fence.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaquePageToken {
    digest: Digest,
}

impl OpaquePageToken {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        if value.is_empty()
            || value.len() > MAX_QUERY_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidRequest);
        }
        Ok(Self {
            digest: sha256_digest(format!("looker-page-token/v1|{value}").as_bytes()),
        })
    }

    pub fn from_digest(digest: impl Into<String>) -> Result<Self, ModelError> {
        let digest = digest.into();
        validate_digest(&digest)?;
        Ok(Self { digest })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("digest", &self.digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LookerAnalyticsRequest {
    operation: LookerOperation,
    target_id_digest: Option<Digest>,
    search_digest: Option<Digest>,
    page_token_digest: Option<Digest>,
    page_size: u16,
    scope_digest: Digest,
    revision_digest: Digest,
    date_window_digest: Digest,
    idempotency_key_digest: Digest,
}

impl LookerAnalyticsRequest {
    pub fn new(
        scope: &LookerAnalyticsScope,
        operation: LookerOperation,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::for_operation(scope, operation, idempotency_key)
    }

    fn for_operation(
        scope: &LookerAnalyticsScope,
        operation: LookerOperation,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        let target_id_digest = match operation {
            LookerOperation::DashboardMetadata => scope.dashboard().map(Identifier::digest),
            LookerOperation::LookMetadata => scope.look().map(Identifier::digest),
            LookerOperation::FolderMetadata => scope.folder().map(Identifier::digest),
            LookerOperation::QueryMetadata => scope.query().map(Identifier::digest),
            LookerOperation::ModelMetadata => Some(scope.model().digest()),
            LookerOperation::ExploreMetadata => Some(scope.explore().digest()),
            LookerOperation::SearchDashboards
            | LookerOperation::SearchLooks
            | LookerOperation::SearchContent
            | LookerOperation::AggregateMetadata => None,
        };
        if matches!(
            operation,
            LookerOperation::DashboardMetadata
                | LookerOperation::LookMetadata
                | LookerOperation::FolderMetadata
                | LookerOperation::QueryMetadata
        ) && target_id_digest.is_none()
        {
            return Err(ModelError::InvalidRequest);
        }
        Ok(Self {
            operation,
            target_id_digest,
            search_digest: None,
            page_token_digest: None,
            page_size: MAX_PAGE_SIZE,
            scope_digest: scope.scope_digest().clone(),
            revision_digest: scope.revision_digest().clone(),
            date_window_digest: scope.date_window().digest(),
            idempotency_key_digest: idempotency_key.digest().clone(),
        })
    }

    pub fn dashboard(
        scope: &LookerAnalyticsScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::for_operation(scope, LookerOperation::DashboardMetadata, idempotency_key)
    }

    pub fn look(
        scope: &LookerAnalyticsScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::for_operation(scope, LookerOperation::LookMetadata, idempotency_key)
    }

    pub fn folder(
        scope: &LookerAnalyticsScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::for_operation(scope, LookerOperation::FolderMetadata, idempotency_key)
    }

    pub fn query(
        scope: &LookerAnalyticsScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::for_operation(scope, LookerOperation::QueryMetadata, idempotency_key)
    }

    pub fn model(
        scope: &LookerAnalyticsScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::for_operation(scope, LookerOperation::ModelMetadata, idempotency_key)
    }

    pub fn explore(
        scope: &LookerAnalyticsScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::for_operation(scope, LookerOperation::ExploreMetadata, idempotency_key)
    }

    pub fn aggregate_metadata(
        scope: &LookerAnalyticsScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::for_operation(scope, LookerOperation::AggregateMetadata, idempotency_key)
    }

    pub fn search_dashboards(
        scope: &LookerAnalyticsScope,
        search_text: impl AsRef<str>,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::search_request(
            scope,
            LookerOperation::SearchDashboards,
            search_text,
            idempotency_key,
        )
    }

    pub fn search_looks(
        scope: &LookerAnalyticsScope,
        search_text: impl AsRef<str>,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::search_request(
            scope,
            LookerOperation::SearchLooks,
            search_text,
            idempotency_key,
        )
    }

    pub fn search_content(
        scope: &LookerAnalyticsScope,
        search_text: impl AsRef<str>,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::search_request(
            scope,
            LookerOperation::SearchContent,
            search_text,
            idempotency_key,
        )
    }

    pub fn search(
        scope: &LookerAnalyticsScope,
        kind: LookerSearchKind,
        search_text: impl AsRef<str>,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        let operation = match kind {
            LookerSearchKind::Dashboards => LookerOperation::SearchDashboards,
            LookerSearchKind::Looks => LookerOperation::SearchLooks,
            LookerSearchKind::Content => LookerOperation::SearchContent,
        };
        Self::search_request(scope, operation, search_text, idempotency_key)
    }

    fn search_request(
        scope: &LookerAnalyticsScope,
        operation: LookerOperation,
        search_text: impl AsRef<str>,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        let search_text = search_text.as_ref();
        if !operation.is_search()
            || search_text.is_empty()
            || search_text.len() > MAX_QUERY_BYTES
            || search_text.trim() != search_text
            || search_text.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidRequest);
        }
        let mut request = Self::for_operation(scope, operation, idempotency_key)?;
        request.search_digest = Some(sha256_digest(
            format!("looker-search/v1|{search_text}").as_bytes(),
        ));
        Ok(request)
    }

    pub fn with_page_size(mut self, page_size: u16) -> Result<Self, ModelError> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(ModelError::InvalidRequest);
        }
        self.page_size = page_size;
        Ok(self)
    }

    pub fn with_page_token(mut self, page_token: &OpaquePageToken) -> Self {
        self.page_token_digest = Some(page_token.digest().clone());
        self
    }

    #[must_use]
    pub const fn operation(&self) -> LookerOperation {
        self.operation
    }

    #[must_use]
    pub fn target_id_digest(&self) -> Option<&Digest> {
        self.target_id_digest.as_ref()
    }

    #[must_use]
    pub fn search_digest(&self) -> Option<&Digest> {
        self.search_digest.as_ref()
    }

    #[must_use]
    pub fn page_token_digest(&self) -> Option<&Digest> {
        self.page_token_digest.as_ref()
    }

    #[must_use]
    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn revision_digest(&self) -> &Digest {
        &self.revision_digest
    }

    #[must_use]
    pub fn idempotency_key_digest(&self) -> &Digest {
        &self.idempotency_key_digest
    }

    #[must_use]
    pub fn request_digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn validate(&self, scope: &LookerAnalyticsScope) -> Result<(), ModelError> {
        scope.validate()?;
        if self.scope_digest != *scope.scope_digest()
            || self.revision_digest != *scope.revision_digest()
            || self.date_window_digest != scope.date_window().digest()
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || validate_digest(&self.idempotency_key_digest).is_err()
            || self
                .page_token_digest
                .as_ref()
                .is_some_and(|digest| validate_digest(digest).is_err())
        {
            return Err(ModelError::InvalidRequest);
        }
        let expected_target = match self.operation {
            LookerOperation::DashboardMetadata => scope.dashboard().map(Identifier::digest),
            LookerOperation::LookMetadata => scope.look().map(Identifier::digest),
            LookerOperation::FolderMetadata => scope.folder().map(Identifier::digest),
            LookerOperation::QueryMetadata => scope.query().map(Identifier::digest),
            LookerOperation::ModelMetadata => Some(scope.model().digest()),
            LookerOperation::ExploreMetadata => Some(scope.explore().digest()),
            LookerOperation::SearchDashboards
            | LookerOperation::SearchLooks
            | LookerOperation::SearchContent
            | LookerOperation::AggregateMetadata => None,
        };
        if self.target_id_digest != expected_target
            || (self.operation.is_search()) != self.search_digest.is_some()
        {
            return Err(ModelError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LookerMetadataItem {
    pub kind: LookerResourceKind,
    pub id_digest: Digest,
    pub name_digest: Option<Digest>,
    pub child_count: u16,
    pub field_count: u16,
    pub source_revision: Revision,
}

impl LookerMetadataItem {
    pub fn new(
        kind: LookerResourceKind,
        id_digest: Digest,
        name_digest: Option<Digest>,
        child_count: u16,
        field_count: u16,
        source_revision: Revision,
    ) -> Result<Self, ModelError> {
        validate_digest(&id_digest)?;
        if let Some(digest) = &name_digest {
            validate_digest(digest)?;
        }
        Ok(Self {
            kind,
            id_digest,
            name_digest,
            child_count,
            field_count,
            source_revision,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LookerMetadataAggregate {
    pub operation: LookerOperation,
    pub items: Vec<LookerMetadataItem>,
    pub item_count: u16,
    pub total_count: u32,
    pub partial: bool,
    pub date_window_digest: Digest,
    pub next_page_token_digest: Option<Digest>,
}

impl LookerMetadataAggregate {
    pub fn new(
        operation: LookerOperation,
        mut items: Vec<LookerMetadataItem>,
        total_count: u32,
        partial: bool,
        date_window_digest: Digest,
        next_page_token_digest: Option<Digest>,
    ) -> Result<Self, ModelError> {
        if items.len() > MAX_ITEMS {
            return Err(ModelError::InvalidAggregate);
        }
        validate_digest(&date_window_digest)?;
        if next_page_token_digest
            .as_ref()
            .is_some_and(|digest| validate_digest(digest).is_err())
        {
            return Err(ModelError::InvalidAggregate);
        }
        items.sort_by_key(LookerMetadataItem::digest);
        let item_count = u16::try_from(items.len()).map_err(|_| ModelError::InvalidAggregate)?;
        if total_count < u32::from(item_count) {
            return Err(ModelError::InvalidAggregate);
        }
        Ok(Self {
            operation,
            items,
            item_count,
            total_count,
            partial,
            date_window_digest,
            next_page_token_digest,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    #[must_use]
    pub fn with_partial(mut self, partial: bool) -> Self {
        self.partial = partial;
        self
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionSummary {
    pub raw_response_dropped: bool,
    pub raw_query_dropped: bool,
    pub raw_secret_dropped: bool,
    pub raw_warehouse_rows_dropped: bool,
    pub raw_filter_expression_dropped: bool,
    pub raw_user_fields_dropped: bool,
    pub raw_dashboard_bodies_dropped: bool,
}

impl RedactionSummary {
    #[must_use]
    pub const fn layer1() -> Self {
        Self {
            raw_response_dropped: true,
            raw_query_dropped: true,
            raw_secret_dropped: true,
            raw_warehouse_rows_dropped: true,
            raw_filter_expression_dropped: true,
            raw_user_fields_dropped: true,
            raw_dashboard_bodies_dropped: true,
        }
    }

    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.raw_response_dropped
            && self.raw_query_dropped
            && self.raw_secret_dropped
            && self.raw_warehouse_rows_dropped
            && self.raw_filter_expression_dropped
            && self.raw_user_fields_dropped
            && self.raw_dashboard_bodies_dropped
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LookerRateLimitReceipt {
    pub limit_per_minute: u16,
    pub remaining: Option<u16>,
    pub retry_after_seconds: Option<u32>,
    pub exhausted: bool,
}

impl Default for LookerRateLimitReceipt {
    fn default() -> Self {
        Self {
            limit_per_minute: MAX_REQUESTS_PER_MINUTE,
            remaining: Some(MAX_REQUESTS_PER_MINUTE - 1),
            retry_after_seconds: None,
            exhausted: false,
        }
    }
}

impl LookerRateLimitReceipt {
    pub fn new(
        limit_per_minute: u16,
        remaining: Option<u16>,
        retry_after_seconds: Option<u32>,
        exhausted: bool,
    ) -> Result<Self, ModelError> {
        let receipt = Self {
            limit_per_minute,
            remaining,
            retry_after_seconds,
            exhausted,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.limit_per_minute == 0
            || self.limit_per_minute > MAX_REQUESTS_PER_MINUTE
            || self
                .remaining
                .is_some_and(|value| value > self.limit_per_minute)
            || self
                .retry_after_seconds
                .is_some_and(|value| value > MAX_RETRY_AFTER_SECONDS)
            || (self.exhausted && self.remaining.is_some_and(|value| value != 0))
        {
            Err(ModelError::InvalidAggregate)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LookerTransportProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl LookerTransportProvenance {
    #[must_use]
    pub const fn connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LookerEvidenceState {
    Complete,
    Empty,
    Partial,
    RateLimited,
    AccessLost,
    NotFound,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClassification {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
    RateLimited,
    Partial,
    ProviderUnknown,
}

impl From<LookerTransportProvenance> for EvidenceClassification {
    fn from(value: LookerTransportProvenance) -> Self {
        match value {
            LookerTransportProvenance::Fixture => Self::Fixture,
            LookerTransportProvenance::Recording => Self::Recording,
            LookerTransportProvenance::Fake => Self::Fake,
            LookerTransportProvenance::Loopback => Self::Loopback,
            LookerTransportProvenance::BlockedEnv => Self::BlockedEnv,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocationReceipt {
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub reversible: bool,
    pub revocable: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LookerRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub registration_digest: Digest,
    pub state: RegistrationState,
    pub reversible: bool,
    pub revocable: bool,
}

impl LookerRegistration {
    #[must_use]
    pub fn bind(
        scope: &LookerAnalyticsScope,
        secret_reference: &SecretReference,
        provider_digest: Digest,
    ) -> Self {
        let mut registration = Self {
            plugin_version: crate::LOOKER_ANALYTICS_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: crate::LOOKER_ANALYTICS_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: crate::LOOKER_PROVIDER_ID.to_owned(),
            provider_digest,
            scope_digest: scope.scope_digest().clone(),
            revision_digest: scope.revision_digest().clone(),
            permission_digest: scope.permission_digest(),
            consent_digest: scope.consent_digest(),
            secret_reference_digest: secret_reference.digest(),
            registration_revision: Revision::new(1).expect("registration revision"),
            registration_digest: String::new(),
            state: RegistrationState::Active,
            reversible: true,
            revocable: true,
        };
        registration.registration_digest = registration.compute_digest();
        registration
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&(
            "looker-registration/v1",
            &self.plugin_version,
            &self.contract_version,
            &self.contract_digest,
            &self.provider_id,
            &self.provider_digest,
            &self.scope_digest,
            &self.revision_digest,
            &self.permission_digest,
            &self.consent_digest,
            &self.secret_reference_digest,
            self.registration_revision,
            self.state,
            self.reversible,
            self.revocable,
        ))
    }

    pub fn validate(
        &self,
        scope: &LookerAnalyticsScope,
        secret_reference: &SecretReference,
        provider_digest: &Digest,
    ) -> Result<(), ModelError> {
        scope.validate()?;
        if self.state != RegistrationState::Active {
            return Err(ModelError::InvalidScope("registration revoked"));
        }
        if self.plugin_version != crate::LOOKER_ANALYTICS_RESULT_PLUGIN_VERSION
            || self.contract_version != crate::LOOKER_ANALYTICS_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_id != crate::LOOKER_PROVIDER_ID
            || &self.provider_digest != provider_digest
            || self.scope_digest != *scope.scope_digest()
            || self.revision_digest != *scope.revision_digest()
            || self.permission_digest != scope.permission_digest()
            || self.consent_digest != scope.consent_digest()
            || self.secret_reference_digest != secret_reference.digest()
            || !self.reversible
            || !self.revocable
            || self.registration_digest != self.compute_digest()
        {
            return Err(ModelError::InvalidScope("registration digest"));
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocationReceipt, ModelError> {
        if !self.revocable {
            return Err(ModelError::InvalidScope("registration is not revocable"));
        }
        if self.state == RegistrationState::Revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        let previous_registration_digest = self.registration_digest.clone();
        self.registration_revision = Revision::new(
            self.registration_revision
                .get()
                .checked_add(1)
                .ok_or(ModelError::RevisionOverflow)?,
        )?;
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.compute_digest();
        Ok(RegistrationRevocationReceipt {
            previous_registration_digest,
            registration_digest: self.registration_digest.clone(),
            registration_revision: self.registration_revision,
            reversible: self.reversible,
            revocable: self.revocable,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if !self.reversible {
            return Err(ModelError::InvalidScope("registration is not reversible"));
        }
        if self.state != RegistrationState::Revoked {
            return Err(ModelError::NotRevoked);
        }
        self.registration_revision = Revision::new(
            self.registration_revision
                .get()
                .checked_add(1)
                .ok_or(ModelError::RevisionOverflow)?,
        )?;
        self.state = RegistrationState::Active;
        self.registration_digest = self.compute_digest();
        Ok(())
    }
}
