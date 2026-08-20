use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use url::Url;

use crate::{
    CLARITY_MAX_DIMENSIONS, CLARITY_MAX_RESPONSE_BYTES, CLARITY_MAX_RESPONSE_ROWS,
    CLARITY_PRIVACY_POLICY_VERSION, CLARITY_UX_RESULT_CONTRACT_VERSION,
    CLARITY_UX_RESULT_PLUGIN_VERSION_TEXT, CLARITY_UX_RESULT_PROVIDER_ID,
};

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 128;
pub(crate) const MAX_URL_BYTES: usize = 2 * 1024;
pub(crate) const MAX_DIMENSION_LABEL_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("URL must be an HTTPS URL without credentials or a fragment")]
    InvalidUrl,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("timestamp must be non-negative")]
    InvalidTimestamp,
    #[error("time window must cover exactly 1, 2, or 3 days")]
    InvalidTimeWindow,
    #[error("at least one allowlisted metric is required")]
    EmptyMetrics,
    #[error("metric is not allowlisted")]
    InvalidMetric,
    #[error("there may be at most three dimensions")]
    TooManyDimensions,
    #[error("dimensions must be unique and allowlisted")]
    InvalidDimensions,
    #[error("dimension label is not a safe bounded label")]
    InvalidDimensionLabel,
    #[error("consent does not authorize aggregate UX evidence")]
    InvalidConsent,
    #[error("privacy policy is not the required strict redaction policy")]
    InvalidPrivacyPolicy,
    #[error("scope digest does not match")]
    ScopeMismatch,
    #[error("secret reference does not match the scope")]
    SecretScopeMismatch,
    #[error("digest does not match immutable fields")]
    DigestMismatch,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("value exceeds a contract bound")]
    BoundExceeded,
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

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field);
        }
        Self::from_bytes(&bytes)
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

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && !value.starts_with('.')
        && !value.ends_with('.')
}

macro_rules! string_identifier {
    ($name:ident) => {
        #[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if valid_identifier(&value) {
                    Ok(Self(value))
                } else {
                    Err(ModelError::InvalidIdentifier)
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_text(self.as_str())
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
    };
}

string_identifier!(ProjectId);
string_identifier!(SiteId);
string_identifier!(ApplicationId);
string_identifier!(DeploymentId);
string_identifier!(MissionId);
string_identifier!(WorkProductId);

pub type ClarityProjectId = ProjectId;
pub type AppId = ApplicationId;
pub type ClaritySiteId = SiteId;
pub type ClarityAppId = ApplicationId;
pub type ClarityDeploymentId = DeploymentId;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Timestamp(i64);

impl Timestamp {
    pub fn new(seconds: i64) -> Result<Self, ModelError> {
        if seconds < 0 {
            Err(ModelError::InvalidTimestamp)
        } else {
            Ok(Self(seconds))
        }
    }

    pub const fn seconds(self) -> i64 {
        self.0
    }

    pub const fn utc_day(self) -> i64 {
        self.0 / 86_400
    }

    pub const fn validate(self) -> Result<(), ModelError> {
        if self.0 < 0 {
            Err(ModelError::InvalidTimestamp)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct WebsiteUrl {
    digest: Digest,
}

impl WebsiteUrl {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        if value.is_empty() || value.len() > MAX_URL_BYTES {
            return Err(ModelError::InvalidUrl);
        }
        let url = Url::parse(value).map_err(|_| ModelError::InvalidUrl)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || url.username() != ""
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(ModelError::InvalidUrl);
        }
        Ok(Self {
            digest: Digest::from_text(value),
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

impl fmt::Debug for WebsiteUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebsiteUrl")
            .field("url", &"<redacted>")
            .field("digest", &self.digest)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TimeWindow(u8);

impl TimeWindow {
    pub fn new(days: u8) -> Result<Self, ModelError> {
        if (1..=3).contains(&days) {
            Ok(Self(days))
        } else {
            Err(ModelError::InvalidTimeWindow)
        }
    }

    pub const fn days(self) -> u8 {
        self.0
    }

    pub const fn validate(self) -> Result<(), ModelError> {
        if self.0 >= 1 && self.0 <= 3 {
            Ok(())
        } else {
            Err(ModelError::InvalidTimeWindow)
        }
    }

    pub fn digest(self) -> Digest {
        Digest::from_text(self.0.to_string())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Metric {
    ScrollDepth,
    EngagementTime,
    Traffic,
    PopularPages,
    Browser,
    Device,
    Os,
    CountryRegion,
    PageTitle,
    ReferrerUrl,
    DeadClickCount,
    ExcessiveScroll,
    RageClickCount,
    QuickbackClick,
    ScriptErrorCount,
    ErrorClickCount,
}

impl Metric {
    pub const fn api_name(self) -> &'static str {
        match self {
            Self::ScrollDepth => "Scroll Depth",
            Self::EngagementTime => "Engagement Time",
            Self::Traffic => "Traffic",
            Self::PopularPages => "Popular Pages",
            Self::Browser => "Browser",
            Self::Device => "Device",
            Self::Os => "OS",
            Self::CountryRegion => "Country/Region",
            Self::PageTitle => "Page Title",
            Self::ReferrerUrl => "Referrer URL",
            Self::DeadClickCount => "Dead Click Count",
            Self::ExcessiveScroll => "Excessive Scroll",
            Self::RageClickCount => "Rage Click Count",
            Self::QuickbackClick => "Quickback Click",
            Self::ScriptErrorCount => "Script Error Count",
            Self::ErrorClickCount => "Error Click Count",
        }
    }

    pub fn from_api_name(value: &str) -> Result<Self, ModelError> {
        let metric = match value {
            "Scroll Depth" => Self::ScrollDepth,
            "Engagement Time" => Self::EngagementTime,
            "Traffic" => Self::Traffic,
            "Popular Pages" => Self::PopularPages,
            "Browser" => Self::Browser,
            "Device" => Self::Device,
            "OS" => Self::Os,
            "Country/Region" => Self::CountryRegion,
            "Page Title" => Self::PageTitle,
            "Referrer URL" => Self::ReferrerUrl,
            "Dead Click Count" => Self::DeadClickCount,
            "Excessive Scroll" => Self::ExcessiveScroll,
            "Rage Click Count" => Self::RageClickCount,
            "Quickback Click" => Self::QuickbackClick,
            "Script Error Count" => Self::ScriptErrorCount,
            "Error Click Count" => Self::ErrorClickCount,
            _ => return Err(ModelError::InvalidMetric),
        };
        Ok(metric)
    }

    pub const fn sensitive(self) -> bool {
        matches!(
            self,
            Self::PopularPages | Self::PageTitle | Self::ReferrerUrl
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct MetricSet(BTreeSet<Metric>);

impl MetricSet {
    pub fn new<I>(metrics: I) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = Metric>,
    {
        let metrics = metrics.into_iter().collect::<BTreeSet<_>>();
        let result = Self(metrics);
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.0.is_empty() {
            Err(ModelError::EmptyMetrics)
        } else {
            Ok(())
        }
    }

    pub fn contains(&self, metric: Metric) -> bool {
        self.0.contains(&metric)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Metric> {
        self.0.iter()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn digest(&self) -> Digest {
        let fields = self
            .iter()
            .map(|metric| metric.api_name().to_owned())
            .collect::<Vec<_>>();
        Digest::from_fields("clarity-metrics/v1", &fields)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Dimension {
    Browser,
    Device,
    CountryRegion,
    Os,
    Source,
    Medium,
    Campaign,
    Channel,
    Url,
}

impl Dimension {
    pub const fn api_name(self) -> &'static str {
        match self {
            Self::Browser => "Browser",
            Self::Device => "Device",
            Self::CountryRegion => "Country/Region",
            Self::Os => "OS",
            Self::Source => "Source",
            Self::Medium => "Medium",
            Self::Campaign => "Campaign",
            Self::Channel => "Channel",
            Self::Url => "URL",
        }
    }

    pub const fn sensitive(self) -> bool {
        matches!(self, Self::Campaign | Self::Url)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct DimensionSet(Vec<Dimension>);

impl DimensionSet {
    pub fn new<I>(dimensions: I) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = Dimension>,
    {
        let dimensions = dimensions.into_iter().collect::<Vec<_>>();
        let result = Self(dimensions);
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.0.len() > CLARITY_MAX_DIMENSIONS {
            return Err(ModelError::TooManyDimensions);
        }
        let mut seen = BTreeSet::new();
        if self.0.iter().any(|dimension| !seen.insert(*dimension)) {
            Err(ModelError::InvalidDimensions)
        } else {
            Ok(())
        }
    }

    pub fn as_slice(&self) -> &[Dimension] {
        &self.0
    }

    pub fn iter(&self) -> impl Iterator<Item = &Dimension> {
        self.0.iter()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn digest(&self) -> Digest {
        let fields = self
            .iter()
            .map(|dimension| dimension.api_name().to_owned())
            .collect::<Vec<_>>();
        Digest::from_fields("clarity-dimensions/v1", &fields)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentPurpose {
    AggregateUxBehavior,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    consent_digest: Digest,
    purpose: ConsentPurpose,
    revision: Revision,
    aggregate_only: bool,
    recordings_allowed: bool,
    visitor_identity_allowed: bool,
    mutations_allowed: bool,
}

impl ConsentScope {
    pub fn aggregate_ux(
        consent_reference: impl AsRef<str>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        if consent_reference.as_ref().is_empty() {
            return Err(ModelError::InvalidConsent);
        }
        let revision = Revision::new(revision)?;
        let consent_digest = Digest::from_text(consent_reference.as_ref());
        let consent = Self {
            consent_digest,
            purpose: ConsentPurpose::AggregateUxBehavior,
            revision,
            aggregate_only: true,
            recordings_allowed: false,
            visitor_identity_allowed: false,
            mutations_allowed: false,
        };
        consent.validate()?;
        Ok(consent)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.purpose != ConsentPurpose::AggregateUxBehavior
            || !self.aggregate_only
            || self.recordings_allowed
            || self.visitor_identity_allowed
            || self.mutations_allowed
            || Digest::parse(self.consent_digest.as_str().to_owned()).is_err()
        {
            Err(ModelError::InvalidConsent)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "clarity-consent-scope/v1",
            &[
                self.consent_digest.as_str().to_owned(),
                format!("{:?}", self.purpose),
                self.revision.get().to_string(),
                self.aggregate_only.to_string(),
                self.recordings_allowed.to_string(),
                self.visitor_identity_allowed.to_string(),
                self.mutations_allowed.to_string(),
            ],
        )
    }

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivacyPolicy {
    version: String,
    redact_url: bool,
    redact_page_title: bool,
    redact_campaign: bool,
    redact_custom_identifiers: bool,
    redact_raw_api_body: bool,
    redact_visitor_data: bool,
    redact_session_data: bool,
    max_rows: u16,
    max_response_bytes: usize,
}

impl PrivacyPolicy {
    pub fn strict_v1() -> Self {
        Self {
            version: CLARITY_PRIVACY_POLICY_VERSION.to_owned(),
            redact_url: true,
            redact_page_title: true,
            redact_campaign: true,
            redact_custom_identifiers: true,
            redact_raw_api_body: true,
            redact_visitor_data: true,
            redact_session_data: true,
            max_rows: CLARITY_MAX_RESPONSE_ROWS,
            max_response_bytes: CLARITY_MAX_RESPONSE_BYTES,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.version != CLARITY_PRIVACY_POLICY_VERSION
            || !self.redact_url
            || !self.redact_page_title
            || !self.redact_campaign
            || !self.redact_custom_identifiers
            || !self.redact_raw_api_body
            || !self.redact_visitor_data
            || !self.redact_session_data
            || self.max_rows == 0
            || self.max_rows > CLARITY_MAX_RESPONSE_ROWS
            || self.max_response_bytes == 0
            || self.max_response_bytes > CLARITY_MAX_RESPONSE_BYTES
        {
            Err(ModelError::InvalidPrivacyPolicy)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "clarity-privacy-policy/v1",
            &[
                self.version.clone(),
                self.redact_url.to_string(),
                self.redact_page_title.to_string(),
                self.redact_campaign.to_string(),
                self.redact_custom_identifiers.to_string(),
                self.redact_raw_api_body.to_string(),
                self.redact_visitor_data.to_string(),
                self.redact_session_data.to_string(),
                self.max_rows.to_string(),
                self.max_response_bytes.to_string(),
            ],
        )
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub const fn max_rows(&self) -> u16 {
        self.max_rows
    }

    pub const fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProjectScope {
    project_id: ProjectId,
    site_id: SiteId,
    application_id: ApplicationId,
    deployment_id: DeploymentId,
    url: WebsiteUrl,
}

impl ProjectScope {
    pub fn new(
        project_id: impl Into<String>,
        site_id: impl Into<String>,
        application_id: impl Into<String>,
        deployment_id: impl Into<String>,
        url: impl AsRef<str>,
    ) -> Result<Self, ModelError> {
        Ok(Self {
            project_id: ProjectId::new(project_id)?,
            site_id: SiteId::new(site_id)?,
            application_id: ApplicationId::new(application_id)?,
            deployment_id: DeploymentId::new(deployment_id)?,
            url: WebsiteUrl::new(url)?,
        })
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn site_id(&self) -> &SiteId {
        &self.site_id
    }

    pub fn application_id(&self) -> &ApplicationId {
        &self.application_id
    }

    pub fn deployment_id(&self) -> &DeploymentId {
        &self.deployment_id
    }

    pub fn url_digest(&self) -> &Digest {
        self.url.digest()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "clarity-project-scope/v1",
            &[
                self.project_id.as_str().to_owned(),
                self.site_id.as_str().to_owned(),
                self.application_id.as_str().to_owned(),
                self.deployment_id.as_str().to_owned(),
                self.url.digest().as_str().to_owned(),
            ],
        )
    }
}

impl fmt::Debug for ProjectScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectScope")
            .field("project_id", &self.project_id)
            .field("site_id", &self.site_id)
            .field("application_id", &self.application_id)
            .field("deployment_id", &self.deployment_id)
            .field("url", &"<redacted>")
            .field("url_digest", self.url.digest())
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScope {
    mission_id: MissionId,
    revision: Revision,
}

impl MissionScope {
    pub fn new(mission_id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            mission_id: MissionId::new(mission_id)?,
            revision: Revision::new(revision)?,
        })
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "clarity-mission-scope/v1",
            &[
                self.mission_id.as_str().to_owned(),
                self.revision.get().to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductScope {
    work_product_id: WorkProductId,
    revision: Revision,
}

impl WorkProductScope {
    pub fn new(work_product_id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            work_product_id: WorkProductId::new(work_product_id)?,
            revision: Revision::new(revision)?,
        })
    }

    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product_id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "clarity-work-product-scope/v1",
            &[
                self.work_product_id.as_str().to_owned(),
                self.revision.get().to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClarityUxScope {
    project: ProjectScope,
    time_window: TimeWindow,
    metrics: MetricSet,
    dimensions: DimensionSet,
    mission: MissionScope,
    work_product: WorkProductScope,
    consent: ConsentScope,
    privacy_policy: PrivacyPolicy,
}

impl ClarityUxScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project: ProjectScope,
        time_window: TimeWindow,
        metrics: MetricSet,
        dimensions: DimensionSet,
        mission: MissionScope,
        work_product: WorkProductScope,
        consent: ConsentScope,
        privacy_policy: PrivacyPolicy,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            project,
            time_window,
            metrics,
            dimensions,
            mission,
            work_product,
            consent,
            privacy_policy,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.time_window.validate()?;
        self.metrics.validate()?;
        self.dimensions.validate()?;
        self.consent.validate()?;
        self.privacy_policy.validate()?;
        Ok(())
    }

    pub fn project(&self) -> &ProjectScope {
        &self.project
    }

    pub const fn time_window(&self) -> TimeWindow {
        self.time_window
    }

    pub fn metrics(&self) -> &MetricSet {
        &self.metrics
    }

    pub fn dimensions(&self) -> &DimensionSet {
        &self.dimensions
    }

    pub fn mission(&self) -> &MissionScope {
        &self.mission
    }

    pub fn work_product(&self) -> &WorkProductScope {
        &self.work_product
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub fn privacy_policy(&self) -> &PrivacyPolicy {
        &self.privacy_policy
    }

    pub fn project_digest(&self) -> Digest {
        self.project.digest()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "clarity-ux-scope/v1",
            &[
                self.project.digest().as_str().to_owned(),
                self.time_window.digest().as_str().to_owned(),
                self.metrics.digest().as_str().to_owned(),
                self.dimensions.digest().as_str().to_owned(),
                self.mission.digest().as_str().to_owned(),
                self.work_product.digest().as_str().to_owned(),
                self.consent.digest().as_str().to_owned(),
                self.privacy_policy.digest().as_str().to_owned(),
            ],
        )
    }
}

/// Opaque host-keyring reference. The original reference and bearer token are
/// intentionally discarded after their binding digest is computed.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        reference_id: impl AsRef<str>,
        scope: &ClarityUxScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        if !valid_identifier(reference_id.as_ref()) {
            return Err(ModelError::InvalidIdentifier);
        }
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.digest();
        let reference_digest = Digest::from_fields(
            "clarity-secret-reference/v1",
            &[
                reference_id.as_ref().to_owned(),
                scope_digest.as_str().to_owned(),
                credential_revision.get().to_string(),
                "data_export_bearer".to_owned(),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
            revoked: false,
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

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
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
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Recording,
    Fixture,
    Fake,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatus {
    Complete,
    Partial,
    Empty,
    RateLimited,
    Expired,
    AccessLost,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    Unauthorized,
    Forbidden,
    BadRequest,
    RateLimited,
    QuotaExhausted,
    Expired,
    ResponseTooLarge,
    NonPaginatedViolation,
    TruncatedResponse,
    MalformedResponse,
    BlockedEnv,
    Transport,
    ScopeDrift,
    SecretRevoked,
    PrivacyViolation,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregateMeasure {
    TotalSessions,
    BotSessions,
    DistantUsers,
    MetricCount,
    PercentageBasisPoints,
    PagesPerSessionBasisPoints,
    EngagementMilliseconds,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AggregateValue {
    pub measure: AggregateMeasure,
    pub value: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DimensionValue {
    Label(String),
    Redacted,
    NotAvailable,
}

impl DimensionValue {
    pub(crate) fn safe_label(value: &str) -> Result<Self, ModelError> {
        if value.is_empty()
            || value.len() > MAX_DIMENSION_LABEL_BYTES
            || value.chars().any(char::is_control)
            || looks_sensitive(value)
        {
            Err(ModelError::InvalidDimensionLabel)
        } else {
            Ok(Self::Label(value.to_owned()))
        }
    }

    pub(crate) fn validate(&self) -> bool {
        match self {
            Self::Label(value) => Self::safe_label(value).is_ok(),
            Self::Redacted | Self::NotAvailable => true,
        }
    }
}

fn looks_sensitive(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    lowered.contains("http://")
        || lowered.contains("https://")
        || lowered.contains("www.")
        || lowered.contains("session")
        || lowered.contains("visitor")
        || lowered.contains("custom-id")
        || lowered.contains("custom_id")
        || lowered.contains("userid")
        || lowered.contains("user_id")
        || lowered.contains("page title")
        || lowered.contains("campaign")
        || value.contains('/')
        || value.contains('?')
        || value.contains('#')
        || value.contains('@')
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AggregateRow {
    pub dimensions: Vec<DimensionValue>,
    pub values: Vec<AggregateValue>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetricEvidence {
    pub metric: Metric,
    pub rows: Vec<AggregateRow>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionSummary {
    pub url_values: u32,
    pub page_title_values: u32,
    pub campaign_values: u32,
    pub custom_identifier_values: u32,
    pub visitor_values: u32,
    pub session_values: u32,
    pub raw_api_body_dropped: bool,
}

impl RedactionSummary {
    pub const fn strict() -> Self {
        Self {
            url_values: 0,
            page_title_values: 0,
            campaign_values: 0,
            custom_identifier_values: 0,
            visitor_values: 0,
            session_values: 0,
            raw_api_body_dropped: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClarityRegistration {
    pub plugin_version: String,
    pub version_digest: Digest,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub project_digest: Digest,
    pub time_window_digest: Digest,
    pub privacy_policy_digest: Digest,
    pub consent_scope_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    pub registration_digest: Digest,
    pub revocation_digest: Digest,
    pub reversible: bool,
}

impl ClarityRegistration {
    pub fn new(
        scope: &ClarityUxScope,
        provider_digest: Digest,
        secret: &SecretReference,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        if secret.is_revoked() {
            return Err(ModelError::AlreadyRevoked);
        }
        if secret.scope_digest() != &scope.digest() {
            return Err(ModelError::SecretScopeMismatch);
        }
        let version_digest = Digest::from_text(CLARITY_UX_RESULT_PLUGIN_VERSION_TEXT);
        let contract_digest = crate::contract_digest();
        let project_digest = scope.project_digest();
        let time_window_digest = scope.time_window.digest();
        let privacy_policy_digest = scope.privacy_policy.digest();
        let consent_scope_digest = scope.consent.digest();
        let scope_digest = scope.digest();
        let registration_digest = Digest::from_fields(
            "clarity-registration/v1",
            &[
                CLARITY_UX_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
                version_digest.as_str().to_owned(),
                CLARITY_UX_RESULT_CONTRACT_VERSION.to_owned(),
                contract_digest.as_str().to_owned(),
                CLARITY_UX_RESULT_PROVIDER_ID.to_owned(),
                provider_digest.as_str().to_owned(),
                project_digest.as_str().to_owned(),
                time_window_digest.as_str().to_owned(),
                privacy_policy_digest.as_str().to_owned(),
                consent_scope_digest.as_str().to_owned(),
                scope_digest.as_str().to_owned(),
                secret.reference_digest().as_str().to_owned(),
            ],
        );
        Ok(Self {
            plugin_version: CLARITY_UX_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            version_digest,
            contract_version: CLARITY_UX_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest,
            provider_digest,
            project_digest,
            time_window_digest,
            privacy_policy_digest,
            consent_scope_digest,
            scope_digest,
            secret_reference_digest: secret.reference_digest().clone(),
            state: RegistrationState::Active,
            registration_digest,
        })
    }

    pub fn ensure_active(&self) -> Result<(), ModelError> {
        if self.state == RegistrationState::Active {
            Ok(())
        } else {
            Err(ModelError::AlreadyRevoked)
        }
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, ModelError> {
        self.ensure_active()?;
        self.state = RegistrationState::Revoked;
        let revocation_digest = Digest::from_fields(
            "clarity-registration-revocation/v1",
            &[
                self.registration_digest.as_str().to_owned(),
                "revoked".to_owned(),
            ],
        );
        Ok(RegistrationRevocation {
            registration_digest: self.registration_digest.clone(),
            revocation_digest,
            reversible: true,
        })
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn validate_against(
        &self,
        scope: &ClarityUxScope,
        provider_digest: &Digest,
        secret: &SecretReference,
    ) -> Result<(), ModelError> {
        let expected = Self::new(scope, provider_digest.clone(), secret)?;
        if self.plugin_version != expected.plugin_version
            || self.version_digest != expected.version_digest
            || self.contract_version != expected.contract_version
            || self.contract_digest != expected.contract_digest
            || self.provider_digest != expected.provider_digest
            || self.project_digest != expected.project_digest
            || self.time_window_digest != expected.time_window_digest
            || self.privacy_policy_digest != expected.privacy_policy_digest
            || self.consent_scope_digest != expected.consent_scope_digest
            || self.scope_digest != expected.scope_digest
            || self.secret_reference_digest != expected.secret_reference_digest
            || self.registration_digest != expected.registration_digest
        {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for ClarityRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClarityRegistration")
            .field("plugin_version", &self.plugin_version)
            .field("version_digest", &self.version_digest)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_digest", &self.provider_digest)
            .field("project_digest", &self.project_digest)
            .field("time_window_digest", &self.time_window_digest)
            .field("privacy_policy_digest", &self.privacy_policy_digest)
            .field("consent_scope_digest", &self.consent_scope_digest)
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference_digest", &self.secret_reference_digest)
            .field("state", &self.state)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}
