use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_TAG_BYTES: usize = 128;
pub const MAX_TAGS: usize = 4;
pub const MAX_ANALYTICS_WINDOW_DAYS: i64 = 31;
pub const MAX_DAILY_POINTS: usize = 31;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS_PER_MINUTE: u16 = 100;
pub const MAX_RETRY_AFTER_SECONDS: u32 = 3_600;
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;

pub type Digest = String;

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    hex::encode(Sha256::digest(bytes))
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("Algolia typed value serializes");
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
    #[error("analytics window is invalid or exceeds the Layer-1 day bound")]
    InvalidAnalyticsWindow,
    #[error("analytics tag is invalid")]
    InvalidTag,
    #[error("analytics ACL is missing the required analytics permission")]
    InvalidAnalyticsAcl,
    #[error("consent scope is invalid")]
    InvalidConsent,
    #[error("digest is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("scope is invalid: {0}")]
    InvalidScope(&'static str),
    #[error("metric is invalid for the provider response")]
    InvalidMetricResponse,
    #[error("provider response is malformed or outside the aggregate bounds")]
    InvalidProviderResponse,
    #[error("provider response contains duplicate or out-of-window daily data")]
    InvalidDailyData,
    #[error("rate must be finite and between zero and one")]
    InvalidRate,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is not revoked")]
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

pub type AlgoliaApplicationId = Identifier;
pub type AlgoliaIndexName = Identifier;
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

pub type IndexRevision = Revision;
pub type MissionRevision = Revision;
pub type WorkProductRevision = Revision;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityBinding {
    id: Identifier,
    revision: Revision,
}

impl IdentityBinding {
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

pub type ProjectBinding = IdentityBinding;
pub type MissionBinding = IdentityBinding;
pub type WorkProductBinding = IdentityBinding;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlgoliaRegion {
    Us,
    De,
}

impl AlgoliaRegion {
    pub fn parse(value: impl AsRef<str>) -> Result<Self, ModelError> {
        match value.as_ref().to_ascii_lowercase().as_str() {
            "us" => Ok(Self::Us),
            "de" => Ok(Self::De),
            _ => Err(ModelError::InvalidIdentifier { label: "region" }),
        }
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Us => "us",
            Self::De => "de",
        }
    }

    #[must_use]
    pub const fn host(self) -> &'static str {
        match self {
            Self::Us => "https://analytics.us.algolia.com",
            Self::De => "https://analytics.de.algolia.com",
        }
    }

    #[must_use]
    pub const fn is_https(self) -> bool {
        true
    }

    #[must_use]
    pub fn digest(self) -> Digest {
        sha256_digest(self.code().as_bytes())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalyticsWindow {
    start_date: String,
    end_date: String,
    revision: Revision,
}

impl AnalyticsWindow {
    pub fn new(
        start_date: impl Into<String>,
        end_date: impl Into<String>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let start_date = start_date.into();
        let end_date = end_date.into();
        let start = parse_date(&start_date).ok_or(ModelError::InvalidAnalyticsWindow)?;
        let end = parse_date(&end_date).ok_or(ModelError::InvalidAnalyticsWindow)?;
        validate_revision(revision, "analytics window")?;
        let length = days_from_civil(end) - days_from_civil(start) + 1;
        if length <= 0 || length > MAX_ANALYTICS_WINDOW_DAYS {
            return Err(ModelError::InvalidAnalyticsWindow);
        }
        Ok(Self {
            start_date,
            end_date,
            revision: Revision::new(revision)?,
        })
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
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn inclusive_days(&self) -> u16 {
        let start = parse_date(&self.start_date).expect("validated start date");
        let end = parse_date(&self.end_date).expect("validated end date");
        (days_from_civil(end) - days_from_civil(start) + 1) as u16
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Self::new(
            self.start_date.clone(),
            self.end_date.clone(),
            self.revision.get(),
        )
        .map(|_| ())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlgoliaSearchQualityMetric {
    SearchCount,
    NoResultRate,
    ClickThroughRate,
    ConversionRate,
}

impl AlgoliaSearchQualityMetric {
    #[must_use]
    pub const fn endpoint(self) -> &'static str {
        match self {
            Self::SearchCount => "/2/searches/count",
            Self::NoResultRate => "/2/searches/noResultRate",
            Self::ClickThroughRate => "/2/clicks/clickThroughRate",
            Self::ConversionRate => "/2/conversions/conversionRate",
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SearchCount => "search_count",
            Self::NoResultRate => "no_result_rate",
            Self::ClickThroughRate => "click_through_rate",
            Self::ConversionRate => "conversion_rate",
        }
    }

    #[must_use]
    pub fn digest(self) -> Digest {
        sha256_digest(self.label().as_bytes())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AnalyticsTag {
    digest: Digest,
}

impl AnalyticsTag {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_TAG_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidTag);
        }
        Ok(Self {
            digest: sha256_digest(format!("algolia-tag/v1|{value}").as_bytes()),
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

impl fmt::Debug for AnalyticsTag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnalyticsTag")
            .field("digest", &self.digest)
            .finish()
    }
}

impl Serialize for AnalyticsTag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.digest)
    }
}

impl<'de> Deserialize<'de> for AnalyticsTag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let digest = String::deserialize(deserializer)?;
        Self::from_digest(digest).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlgoliaAnalyticsPermission {
    Analytics,
}

impl AlgoliaAnalyticsPermission {
    #[must_use]
    pub const fn label(self) -> &'static str {
        "analytics"
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AlgoliaAnalyticsAcl {
    permissions: BTreeSet<AlgoliaAnalyticsPermission>,
    revision: Revision,
}

impl AlgoliaAnalyticsAcl {
    pub fn analytics(revision: u64) -> Result<Self, ModelError> {
        Self::new([AlgoliaAnalyticsPermission::Analytics], revision)
    }

    pub fn least_privilege(revision: u64) -> Result<Self, ModelError> {
        Self::analytics(revision)
    }

    pub fn new(
        permissions: impl IntoIterator<Item = AlgoliaAnalyticsPermission>,
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
        if self.permissions.len() != 1
            || !self
                .permissions
                .contains(&AlgoliaAnalyticsPermission::Analytics)
        {
            return Err(ModelError::InvalidAnalyticsAcl);
        }
        validate_revision(self.revision.get(), "analytics ACL")
    }

    #[must_use]
    pub fn permissions(&self) -> &BTreeSet<AlgoliaAnalyticsPermission> {
        &self.permissions
    }

    #[must_use]
    pub fn has(&self, permission: AlgoliaAnalyticsPermission) -> bool {
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

#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    opaque_id: String,
    revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(opaque_id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        let opaque_id = opaque_id.into();
        if opaque_id.is_empty()
            || opaque_id.len() > MAX_IDENTIFIER_BYTES
            || opaque_id.trim() != opaque_id
            || opaque_id.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidIdentifier {
                label: "secret reference",
            });
        }
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
                "algolia-secret-reference/v1|{}|{}",
                self.opaque_id,
                self.revision.get()
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
        if self.revoked {
            self.revoked = false;
            Ok(())
        } else {
            Err(ModelError::NotRevoked)
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("opaque_id", &"<redacted>")
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AlgoliaSearchQualityScopeSpec {
    pub region: AlgoliaRegion,
    pub application_id: AlgoliaApplicationId,
    pub index_name: AlgoliaIndexName,
    pub index_revision: IndexRevision,
    pub analytics_window: AnalyticsWindow,
    pub metric: AlgoliaSearchQualityMetric,
    pub tags: Vec<AnalyticsTag>,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub consent: ConsentScope,
    pub acl: AlgoliaAnalyticsAcl,
}

#[allow(clippy::too_many_arguments)]
impl AlgoliaSearchQualityScopeSpec {
    #[must_use]
    pub fn new(
        region: AlgoliaRegion,
        application_id: AlgoliaApplicationId,
        index_name: AlgoliaIndexName,
        index_revision: IndexRevision,
        analytics_window: AnalyticsWindow,
        metric: AlgoliaSearchQualityMetric,
        tags: Vec<AnalyticsTag>,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        consent: ConsentScope,
        acl: AlgoliaAnalyticsAcl,
    ) -> Self {
        Self {
            region,
            application_id,
            index_name,
            index_revision,
            analytics_window,
            metric,
            tags,
            project,
            mission,
            work_product,
            consent,
            acl,
        }
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
        if reference.is_empty()
            || reference.len() > MAX_IDENTIFIER_BYTES
            || reference.trim() != reference
            || reference.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidConsent);
        }
        Ok(Self {
            consent_digest: sha256_digest(format!("algolia-consent/v1|{reference}").as_bytes()),
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AlgoliaSearchQualityScope {
    region: AlgoliaRegion,
    application_id: AlgoliaApplicationId,
    index_name: AlgoliaIndexName,
    index_revision: IndexRevision,
    analytics_window: AnalyticsWindow,
    metric: AlgoliaSearchQualityMetric,
    tags: Vec<AnalyticsTag>,
    project: ProjectBinding,
    mission: MissionBinding,
    work_product: WorkProductBinding,
    consent: ConsentScope,
    acl: AlgoliaAnalyticsAcl,
    scope_digest: Digest,
    revision_digest: Digest,
    privacy_digest: Digest,
}

impl AlgoliaSearchQualityScope {
    pub fn new(spec: AlgoliaSearchQualityScopeSpec) -> Result<Self, ModelError> {
        if spec.tags.len() > MAX_TAGS {
            return Err(ModelError::InvalidScope("tags"));
        }
        if spec
            .tags
            .iter()
            .map(AnalyticsTag::digest)
            .collect::<BTreeSet<_>>()
            .len()
            != spec.tags.len()
        {
            return Err(ModelError::InvalidScope("duplicate tags"));
        }
        validate_revision(spec.index_revision.get(), "index")?;
        spec.analytics_window.validate()?;
        spec.acl.validate()?;
        spec.consent.validate()?;
        let scope_digest = scope_digest(&spec);
        let revision_digest = revision_digest(&spec);
        let privacy_digest = privacy_digest(&spec.tags);
        Ok(Self {
            region: spec.region,
            application_id: spec.application_id,
            index_name: spec.index_name,
            index_revision: spec.index_revision,
            analytics_window: spec.analytics_window,
            metric: spec.metric,
            tags: spec.tags,
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
        let expected_scope = scope_digest(&spec);
        if expected_scope != self.scope_digest {
            return Err(ModelError::InvalidScope("scope digest"));
        }
        let expected_revision = revision_digest(&spec);
        if expected_revision != self.revision_digest {
            return Err(ModelError::InvalidScope("revision digest"));
        }
        if privacy_digest(&self.tags) != self.privacy_digest {
            return Err(ModelError::InvalidScope("privacy digest"));
        }
        Ok(())
    }

    #[must_use]
    pub fn spec(&self) -> AlgoliaSearchQualityScopeSpec {
        AlgoliaSearchQualityScopeSpec {
            region: self.region,
            application_id: self.application_id.clone(),
            index_name: self.index_name.clone(),
            index_revision: self.index_revision,
            analytics_window: self.analytics_window.clone(),
            metric: self.metric,
            tags: self.tags.clone(),
            project: self.project.clone(),
            mission: self.mission.clone(),
            work_product: self.work_product.clone(),
            consent: self.consent.clone(),
            acl: self.acl.clone(),
        }
    }

    #[must_use]
    pub const fn region(&self) -> AlgoliaRegion {
        self.region
    }

    #[must_use]
    pub fn application_id(&self) -> &AlgoliaApplicationId {
        &self.application_id
    }

    #[must_use]
    pub fn application(&self) -> &AlgoliaApplicationId {
        self.application_id()
    }

    #[must_use]
    pub fn index_name(&self) -> &AlgoliaIndexName {
        &self.index_name
    }

    #[must_use]
    pub fn index(&self) -> &AlgoliaIndexName {
        self.index_name()
    }

    #[must_use]
    pub const fn index_revision(&self) -> IndexRevision {
        self.index_revision
    }

    #[must_use]
    pub fn analytics_window(&self) -> &AnalyticsWindow {
        &self.analytics_window
    }

    #[must_use]
    pub fn window(&self) -> &AnalyticsWindow {
        self.analytics_window()
    }

    #[must_use]
    pub const fn metric(&self) -> AlgoliaSearchQualityMetric {
        self.metric
    }

    #[must_use]
    pub fn tags(&self) -> &[AnalyticsTag] {
        &self.tags
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
    pub fn acl(&self) -> &AlgoliaAnalyticsAcl {
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

fn scope_digest(spec: &AlgoliaSearchQualityScopeSpec) -> Digest {
    canonical_digest(&(
        "algolia-search-quality-scope/v1",
        spec.region,
        &spec.application_id,
        &spec.index_name,
        spec.index_revision,
        &spec.analytics_window,
        spec.metric,
        spec.tags
            .iter()
            .map(AnalyticsTag::digest)
            .collect::<Vec<_>>(),
        &spec.project,
        &spec.mission,
        &spec.work_product,
        &spec.consent,
        &spec.acl,
    ))
}

fn revision_digest(spec: &AlgoliaSearchQualityScopeSpec) -> Digest {
    canonical_digest(&(
        "algolia-search-quality-revisions/v1",
        spec.index_revision,
        spec.analytics_window.revision(),
        spec.project.revision(),
        spec.mission.revision(),
        spec.work_product.revision(),
        spec.consent.revision(),
        spec.acl.revision(),
    ))
}

fn privacy_digest(tags: &[AnalyticsTag]) -> Digest {
    canonical_digest(&(
        "algolia-search-quality-privacy/v1",
        tags.iter().map(AnalyticsTag::digest).collect::<Vec<_>>(),
        "query_terms_dropped",
        "user_tokens_dropped",
        "ip_derived_identifiers_dropped",
        "object_ids_dropped",
        "event_payloads_dropped",
    ))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AlgoliaRateLimitReceipt {
    pub limit_per_minute: u16,
    pub remaining: Option<u16>,
    pub retry_after_seconds: Option<u32>,
    pub throttled: bool,
}

impl Default for AlgoliaRateLimitReceipt {
    fn default() -> Self {
        Self {
            limit_per_minute: MAX_REQUESTS_PER_MINUTE,
            remaining: None,
            retry_after_seconds: None,
            throttled: false,
        }
    }
}

impl AlgoliaRateLimitReceipt {
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AlgoliaHttpMethod {
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
    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlgoliaAnalyticsDay {
    pub date: String,
    #[serde(default)]
    pub count: Option<u64>,
    #[serde(default)]
    pub no_result_count: Option<u64>,
    #[serde(default)]
    pub click_count: Option<u64>,
    #[serde(default)]
    pub conversion_count: Option<u64>,
    #[serde(default)]
    pub tracked_search_count: Option<u64>,
    #[serde(default)]
    pub rate: Option<f64>,
}

impl AlgoliaAnalyticsDay {
    #[must_use]
    pub fn search_count(date: impl Into<String>, count: u64) -> Self {
        Self {
            date: date.into(),
            count: Some(count),
            no_result_count: None,
            click_count: None,
            conversion_count: None,
            tracked_search_count: None,
            rate: None,
        }
    }

    #[must_use]
    pub fn no_result_rate(
        date: impl Into<String>,
        count: u64,
        no_result_count: u64,
        rate: f64,
    ) -> Self {
        Self {
            date: date.into(),
            count: Some(count),
            no_result_count: Some(no_result_count),
            click_count: None,
            conversion_count: None,
            tracked_search_count: None,
            rate: Some(rate),
        }
    }

    #[must_use]
    pub fn click_through_rate(
        date: impl Into<String>,
        tracked_search_count: u64,
        click_count: u64,
        rate: f64,
    ) -> Self {
        Self {
            date: date.into(),
            count: None,
            no_result_count: None,
            click_count: Some(click_count),
            conversion_count: None,
            tracked_search_count: Some(tracked_search_count),
            rate: Some(rate),
        }
    }

    #[must_use]
    pub fn conversion_rate(
        date: impl Into<String>,
        tracked_search_count: u64,
        conversion_count: u64,
        rate: f64,
    ) -> Self {
        Self {
            date: date.into(),
            count: None,
            no_result_count: None,
            click_count: None,
            conversion_count: Some(conversion_count),
            tracked_search_count: Some(tracked_search_count),
            rate: Some(rate),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlgoliaAnalyticsPayload {
    #[serde(default)]
    pub count: Option<u64>,
    #[serde(default)]
    pub no_result_count: Option<u64>,
    #[serde(default)]
    pub click_count: Option<u64>,
    #[serde(default)]
    pub conversion_count: Option<u64>,
    #[serde(default)]
    pub tracked_search_count: Option<u64>,
    #[serde(default)]
    pub rate: Option<f64>,
    #[serde(default)]
    pub dates: Vec<AlgoliaAnalyticsDay>,
    #[serde(default)]
    pub partial: bool,
}

impl AlgoliaAnalyticsPayload {
    #[must_use]
    pub fn search_count(count: u64, dates: Vec<AlgoliaAnalyticsDay>) -> Self {
        Self {
            count: Some(count),
            no_result_count: None,
            click_count: None,
            conversion_count: None,
            tracked_search_count: None,
            rate: None,
            dates,
            partial: false,
        }
    }

    #[must_use]
    pub fn no_result_rate(
        count: u64,
        no_result_count: u64,
        rate: Option<f64>,
        dates: Vec<AlgoliaAnalyticsDay>,
    ) -> Self {
        Self {
            count: Some(count),
            no_result_count: Some(no_result_count),
            click_count: None,
            conversion_count: None,
            tracked_search_count: None,
            rate,
            dates,
            partial: false,
        }
    }

    #[must_use]
    pub fn click_through_rate(
        tracked_search_count: u64,
        click_count: u64,
        rate: Option<f64>,
        dates: Vec<AlgoliaAnalyticsDay>,
    ) -> Self {
        Self {
            count: None,
            no_result_count: None,
            click_count: Some(click_count),
            conversion_count: None,
            tracked_search_count: Some(tracked_search_count),
            rate,
            dates,
            partial: false,
        }
    }

    #[must_use]
    pub fn conversion_rate(
        tracked_search_count: u64,
        conversion_count: u64,
        rate: Option<f64>,
        dates: Vec<AlgoliaAnalyticsDay>,
    ) -> Self {
        Self {
            count: None,
            no_result_count: None,
            click_count: None,
            conversion_count: Some(conversion_count),
            tracked_search_count: Some(tracked_search_count),
            rate,
            dates,
            partial: false,
        }
    }

    pub fn normalize(
        &self,
        metric: AlgoliaSearchQualityMetric,
        window: &AnalyticsWindow,
    ) -> Result<AlgoliaSearchQualityAggregate, ModelError> {
        let (denominator, numerator) = match metric {
            AlgoliaSearchQualityMetric::SearchCount => {
                (self.count.ok_or(ModelError::InvalidMetricResponse)?, None)
            }
            AlgoliaSearchQualityMetric::NoResultRate => (
                self.count.ok_or(ModelError::InvalidMetricResponse)?,
                Some(
                    self.no_result_count
                        .ok_or(ModelError::InvalidMetricResponse)?,
                ),
            ),
            AlgoliaSearchQualityMetric::ClickThroughRate => (
                self.tracked_search_count
                    .ok_or(ModelError::InvalidMetricResponse)?,
                Some(self.click_count.ok_or(ModelError::InvalidMetricResponse)?),
            ),
            AlgoliaSearchQualityMetric::ConversionRate => (
                self.tracked_search_count
                    .ok_or(ModelError::InvalidMetricResponse)?,
                Some(
                    self.conversion_count
                        .ok_or(ModelError::InvalidMetricResponse)?,
                ),
            ),
        };
        validate_metric_values(denominator, numerator, self.rate)?;
        if self.dates.len() > MAX_DAILY_POINTS {
            return Err(ModelError::InvalidDailyData);
        }
        let mut dates = self
            .dates
            .iter()
            .map(|day| normalize_day(day, metric, window))
            .collect::<Result<Vec<_>, _>>()?;
        dates.sort_by(|left, right| left.date.cmp(&right.date));
        if dates.windows(2).any(|pair| pair[0].date == pair[1].date) {
            return Err(ModelError::InvalidDailyData);
        }
        Ok(AlgoliaSearchQualityAggregate {
            denominator,
            numerator,
            rate: validate_rate(self.rate)?,
            daily: dates,
            partial: self.partial,
        })
    }
}

fn normalize_day(
    day: &AlgoliaAnalyticsDay,
    metric: AlgoliaSearchQualityMetric,
    window: &AnalyticsWindow,
) -> Result<AlgoliaDailyAggregate, ModelError> {
    let parsed = parse_date(&day.date).ok_or(ModelError::InvalidDailyData)?;
    let start = parse_date(window.start_date()).ok_or(ModelError::InvalidDailyData)?;
    let end = parse_date(window.end_date()).ok_or(ModelError::InvalidDailyData)?;
    let ordinal = days_from_civil(parsed);
    if ordinal < days_from_civil(start) || ordinal > days_from_civil(end) {
        return Err(ModelError::InvalidDailyData);
    }
    let (denominator, numerator) = match metric {
        AlgoliaSearchQualityMetric::SearchCount => {
            (day.count.ok_or(ModelError::InvalidMetricResponse)?, None)
        }
        AlgoliaSearchQualityMetric::NoResultRate => (
            day.count.ok_or(ModelError::InvalidMetricResponse)?,
            Some(
                day.no_result_count
                    .ok_or(ModelError::InvalidMetricResponse)?,
            ),
        ),
        AlgoliaSearchQualityMetric::ClickThroughRate => (
            day.tracked_search_count
                .ok_or(ModelError::InvalidMetricResponse)?,
            Some(day.click_count.ok_or(ModelError::InvalidMetricResponse)?),
        ),
        AlgoliaSearchQualityMetric::ConversionRate => (
            day.tracked_search_count
                .ok_or(ModelError::InvalidMetricResponse)?,
            Some(
                day.conversion_count
                    .ok_or(ModelError::InvalidMetricResponse)?,
            ),
        ),
    };
    validate_metric_values(denominator, numerator, day.rate)?;
    Ok(AlgoliaDailyAggregate {
        date: day.date.clone(),
        denominator,
        numerator,
        rate: validate_rate(day.rate)?,
    })
}

fn validate_metric_values(
    denominator: u64,
    numerator: Option<u64>,
    rate: Option<f64>,
) -> Result<(), ModelError> {
    if numerator.is_some_and(|value| value > denominator) {
        return Err(ModelError::InvalidProviderResponse);
    }
    let _ = validate_rate(rate)?;
    Ok(())
}

fn validate_rate(rate: Option<f64>) -> Result<Option<f64>, ModelError> {
    if rate.is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value)) {
        Err(ModelError::InvalidRate)
    } else {
        Ok(rate)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AlgoliaDailyAggregate {
    pub date: String,
    pub denominator: u64,
    pub numerator: Option<u64>,
    pub rate: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AlgoliaSearchQualityAggregate {
    pub denominator: u64,
    pub numerator: Option<u64>,
    pub rate: Option<f64>,
    pub daily: Vec<AlgoliaDailyAggregate>,
    pub partial: bool,
}

impl AlgoliaSearchQualityAggregate {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.denominator == 0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlgoliaEvidenceState {
    Complete,
    Partial,
    Empty,
    PlanUnavailable,
    RateLimited,
    AccessLost,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClassification {
    Normalized,
    Empty,
    PlanUnavailable,
    RateLimited,
    AccessLost,
    BlockedEnv,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AlgoliaAnalyticsRequestReceipt {
    pub method: AlgoliaHttpMethod,
    pub endpoint: String,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub status_code: Option<u16>,
    pub response_bytes: usize,
    pub rate_limit_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AlgoliaEvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub acl_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub privacy_digest: Digest,
    pub registration_digest: Digest,
    pub index_digest: Digest,
    pub analytics_window_digest: Digest,
    pub metric_digest: Digest,
    pub query_digest: Digest,
    pub result_digest: Digest,
    pub response_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AlgoliaSearchQualityEvidence {
    pub state: AlgoliaEvidenceState,
    pub classification: EvidenceClassification,
    pub metric: AlgoliaSearchQualityMetric,
    pub analytics_window: AnalyticsWindow,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub privacy_digest: Digest,
    pub aggregate: Option<AlgoliaSearchQualityAggregate>,
    pub read_receipt: AlgoliaAnalyticsRequestReceipt,
    pub rate_limit: AlgoliaRateLimitReceipt,
    pub digests: AlgoliaEvidenceDigests,
    pub provenance: TransportProvenance,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub content_quality_claim: bool,
    pub relevance_causality_claim: bool,
    pub purchase_intent_claim: bool,
    pub business_success_claim: bool,
    pub evidence_digest: Digest,
}

impl AlgoliaSearchQualityEvidence {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&serde_json::json!({
            "state": &self.state,
            "classification": &self.classification,
            "metric": self.metric,
            "analyticsWindow": &self.analytics_window,
            "scopeDigest": &self.scope_digest,
            "revisionDigest": &self.revision_digest,
            "privacyDigest": &self.privacy_digest,
            "aggregate": &self.aggregate,
            "readReceipt": &self.read_receipt,
            "rateLimit": &self.rate_limit,
            "digests": &self.digests,
            "provenance": self.provenance,
            "proposalOnly": self.proposal_only,
            "native": self.native,
            "connected": self.connected,
            "contentQualityClaim": self.content_quality_claim,
            "relevanceCausalityClaim": self.relevance_causality_claim,
            "purchaseIntentClaim": self.purchase_intent_claim,
            "businessSuccessClaim": self.business_success_claim,
        }))
    }

    #[must_use]
    pub fn is_actionable(&self) -> bool {
        matches!(self.state, AlgoliaEvidenceState::Complete)
            && self
                .aggregate
                .as_ref()
                .is_some_and(|aggregate| !aggregate.is_empty())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationDisposition {
    ReviewSearchDemand,
    ReviewContentCoverage,
    ReviewResultInteraction,
    ReviewConversionSignal,
    NoRecommendationPartial,
    NoRecommendationEmpty,
    NoRecommendationPlanUnavailable,
    NoRecommendationRateLimited,
    NoRecommendationAccessLost,
    NoRecommendationProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AlgoliaSearchQualityRecommendation {
    pub disposition: RecommendationDisposition,
    pub provider_reported_only: bool,
    pub non_mutating: bool,
    pub claims_content_quality: bool,
    pub claims_relevance_causality: bool,
    pub claims_purchase_intent: bool,
    pub claims_business_success: bool,
    pub rationale_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AlgoliaSearchQualityProposal {
    pub scope: AlgoliaSearchQualityScope,
    pub evidence: AlgoliaSearchQualityEvidence,
    pub source_evidence_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub acl_digest: Digest,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub adopts_outcome: bool,
    pub recommendation: AlgoliaSearchQualityRecommendation,
    pub proposal_digest: Digest,
}

impl AlgoliaSearchQualityProposal {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            &self.scope,
            &self.evidence,
            &self.source_evidence_digest,
            &self.registration_digest,
            &self.provider_digest,
            &self.contract_digest,
            &self.acl_digest,
            self.proposal_only,
            self.native,
            self.connected,
            self.adopts_outcome,
            &self.recommendation,
        ))
    }

    #[must_use]
    pub fn state(&self) -> AlgoliaEvidenceState {
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
pub struct AlgoliaReadbackReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub status: String,
    pub independent_native_readback: bool,
    pub native: bool,
    pub connected: bool,
}

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
    if !(1..=9999).contains(&year) || !(1..=12).contains(&month) {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    (1..=days_in_month)
        .contains(&day)
        .then_some((year, month, day))
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
pub struct RegistrationRevocationReceipt {
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub reversible: bool,
    pub revocable: bool,
    pub native: bool,
    pub connected: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AlgoliaRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_digest: Digest,
    pub acl_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub privacy_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub registration_digest: Digest,
    pub state: RegistrationState,
    pub reversible: bool,
    pub revocable: bool,
}

impl AlgoliaRegistration {
    #[must_use]
    pub fn bind(
        scope: &AlgoliaSearchQualityScope,
        secret_reference: &SecretReference,
        provider_digest: Digest,
    ) -> Self {
        let mut registration = Self {
            plugin_version: crate::ALGOLIA_SEARCH_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: crate::ALGOLIA_SEARCH_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: crate::ALGOLIA_ANALYTICS_PROVIDER_ID.to_owned(),
            provider_digest,
            acl_digest: scope.acl_digest(),
            scope_digest: scope.digest(),
            revision_digest: scope.revision_digest().clone(),
            privacy_digest: scope.privacy_digest().clone(),
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
            "algolia-registration/v1",
            &self.plugin_version,
            &self.contract_version,
            &self.contract_digest,
            &self.provider_id,
            &self.provider_digest,
            &self.acl_digest,
            &self.scope_digest,
            &self.revision_digest,
            &self.privacy_digest,
            &self.secret_reference_digest,
            self.registration_revision,
            &self.state,
            self.reversible,
            self.revocable,
        ))
    }

    pub fn validate(
        &self,
        scope: &AlgoliaSearchQualityScope,
        secret_reference: &SecretReference,
        provider_digest: &Digest,
    ) -> Result<(), ModelError> {
        scope.validate()?;
        if self.state != RegistrationState::Active {
            return Err(ModelError::InvalidScope("registration revoked"));
        }
        if self.plugin_version != crate::ALGOLIA_SEARCH_RESULT_PLUGIN_VERSION
            || self.contract_version != crate::ALGOLIA_SEARCH_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_id != crate::ALGOLIA_ANALYTICS_PROVIDER_ID
            || &self.provider_digest != provider_digest
            || self.acl_digest != scope.acl_digest()
            || self.scope_digest != scope.digest()
            || self.revision_digest != *scope.revision_digest()
            || self.privacy_digest != *scope.privacy_digest()
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
            native: false,
            connected: false,
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
