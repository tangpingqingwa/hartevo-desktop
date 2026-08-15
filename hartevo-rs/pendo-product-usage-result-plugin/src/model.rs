use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_TIME_WINDOW_DAYS: i64 = 31;
pub const MAX_TIME_WINDOW_SECONDS: i64 = MAX_TIME_WINDOW_DAYS * 86_400;
pub const MAX_REQUESTS_PER_SCOPE: u16 = 10;
pub const MAX_RESPONSE_BYTES: usize = 512 * 1024;
pub const MAX_ROWS: usize = 200;
pub const MAX_BUCKETS: usize = 31;
pub const MAX_STALENESS_SECONDS: i64 = 86_400;
pub const MAX_DIAGNOSTIC_BYTES: usize = 256;

pub type Digest = String;

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    hex::encode(Sha256::digest(bytes))
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("Pendo typed value serializes");
    sha256_digest(&bytes)
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{label} is empty, malformed, or too long")]
    InvalidIdentifier { label: &'static str },
    #[error("{label} revision must be non-zero")]
    InvalidRevision { label: &'static str },
    #[error("digest is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("time window is empty or exceeds the Layer-1 bound")]
    InvalidTimeWindow,
    #[error("timestamp is invalid")]
    InvalidTimestamp,
    #[error("metric is not allowed for the selected target")]
    InvalidMetric,
    #[error("read projection is not allowed for the selected scope")]
    InvalidProjection,
    #[error("consent scope is invalid")]
    InvalidConsent,
    #[error("scope is invalid: {0}")]
    InvalidScope(&'static str),
    #[error("secret reference is not bound to the selected scope")]
    SecretScopeMismatch,
    #[error("secret reference is already revoked")]
    AlreadyRevoked,
    #[error("secret reference is not revoked")]
    NotRevoked,
    #[error("registration is already revoked")]
    RegistrationAlreadyRevoked,
    #[error("registration is not revoked")]
    RegistrationNotRevoked,
    #[error("registration revision overflowed")]
    RevisionOverflow,
    #[error("registration is invalid or revoked")]
    InvalidRegistration,
    #[error("response is too large")]
    ResponseTooLarge,
    #[error("response contains too many rows or buckets")]
    ResponseTooManyRows,
    #[error("response contains a forbidden visitor, PII, or event field")]
    PrivacyViolation,
    #[error("response contains an invalid aggregate value")]
    InvalidAggregate,
}

fn validate_identifier(value: &str, label: &'static str) -> Result<(), ModelError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
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

fn digest_text(namespace: &str, value: &str) -> Digest {
    sha256_digest(format!("{namespace}/v1|{value}").as_bytes())
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

    fn next(self) -> Result<Self, ModelError> {
        Self::new(self.0.checked_add(1).ok_or(ModelError::RevisionOverflow)?)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct BindingId(String);

impl BindingId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "binding id")?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub type ProjectId = BindingId;
pub type MissionId = BindingId;
pub type WorkProductId = BindingId;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Binding {
    id: BindingId,
    revision: Revision,
}

impl Binding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: BindingId::new(id)?,
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

pub type ProjectBinding = Binding;
pub type MissionBinding = Binding;
pub type WorkProductBinding = Binding;

/// A scope reference that stores only a domain-separated digest of the input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ScopedReference(Digest);

impl ScopedReference {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "scoped reference")?;
        Ok(Self(digest_text("pendo-scope-reference", &value)))
    }

    pub fn from_digest(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_digest(&value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.0
    }
}

pub type SubscriptionId = ScopedReference;
pub type ApplicationId = ScopedReference;
pub type AccountScope = ScopedReference;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VisitorKind {
    All,
    Identified,
    Anonymous,
}

impl VisitorKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Identified => "identified",
            Self::Anonymous => "anonymous",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Page,
    Feature,
    Guide,
}

impl TargetKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Page => "page",
            Self::Feature => "feature",
            Self::Guide => "guide",
        }
    }

    #[must_use]
    pub const fn metadata_path(self) -> &'static str {
        match self {
            Self::Page => "/api/v1/page",
            Self::Feature => "/api/v1/feature",
            Self::Guide => "/api/v1/guide",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetReference {
    kind: TargetKind,
    id_digest: Digest,
}

impl TargetReference {
    pub fn new(kind: TargetKind, value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "target reference")?;
        Ok(Self {
            kind,
            id_digest: digest_text("pendo-target", &value),
        })
    }

    pub fn from_digest(kind: TargetKind, digest: impl Into<String>) -> Result<Self, ModelError> {
        let digest = digest.into();
        validate_digest(&digest)?;
        Ok(Self {
            kind,
            id_digest: digest,
        })
    }

    pub fn page(value: impl Into<String>) -> Result<Self, ModelError> {
        Self::new(TargetKind::Page, value)
    }

    pub fn feature(value: impl Into<String>) -> Result<Self, ModelError> {
        Self::new(TargetKind::Feature, value)
    }

    pub fn guide(value: impl Into<String>) -> Result<Self, ModelError> {
        Self::new(TargetKind::Guide, value)
    }

    #[must_use]
    pub const fn kind(&self) -> TargetKind {
        self.kind
    }

    #[must_use]
    pub fn id_digest(&self) -> &Digest {
        &self.id_digest
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SegmentScope {
    digest: Digest,
    all_segments: bool,
}

impl SegmentScope {
    #[must_use]
    pub fn all() -> Self {
        Self {
            digest: digest_text("pendo-segment", "all"),
            all_segments: true,
        }
    }

    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "segment reference")?;
        Ok(Self {
            digest: digest_text("pendo-segment", &value),
            all_segments: false,
        })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    #[must_use]
    pub const fn is_all(&self) -> bool {
        self.all_segments
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Timestamp {
    unix_seconds: i64,
}

impl Timestamp {
    pub fn new(unix_seconds: i64) -> Result<Self, ModelError> {
        if unix_seconds < 0 {
            return Err(ModelError::InvalidTimestamp);
        }
        Ok(Self { unix_seconds })
    }

    #[must_use]
    pub const fn unix_seconds(self) -> i64 {
        self.unix_seconds
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TimeWindow {
    start_unix_seconds: i64,
    end_unix_seconds: i64,
}

impl TimeWindow {
    pub fn new(start_unix_seconds: i64, end_unix_seconds: i64) -> Result<Self, ModelError> {
        let window = Self {
            start_unix_seconds,
            end_unix_seconds,
        };
        window.validate()?;
        Ok(window)
    }

    pub fn for_days(end_unix_seconds: i64, days: i64) -> Result<Self, ModelError> {
        if !(1..=MAX_TIME_WINDOW_DAYS).contains(&days) {
            return Err(ModelError::InvalidTimeWindow);
        }
        let start = end_unix_seconds
            .checked_sub(days * 86_400)
            .ok_or(ModelError::InvalidTimeWindow)?;
        Self::new(start, end_unix_seconds)
    }

    fn validate(&self) -> Result<(), ModelError> {
        if self.start_unix_seconds < 0
            || self.end_unix_seconds <= self.start_unix_seconds
            || self
                .end_unix_seconds
                .checked_sub(self.start_unix_seconds)
                .is_none_or(|seconds| seconds > MAX_TIME_WINDOW_SECONDS)
        {
            return Err(ModelError::InvalidTimeWindow);
        }
        Ok(())
    }

    #[must_use]
    pub const fn start_unix_seconds(&self) -> i64 {
        self.start_unix_seconds
    }

    #[must_use]
    pub const fn end_unix_seconds(&self) -> i64 {
        self.end_unix_seconds
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    consent_digest: Digest,
    revision: Revision,
}

impl ConsentScope {
    pub fn new(value: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "consent reference")?;
        Ok(Self {
            consent_digest: digest_text("pendo-consent", &value),
            revision: Revision::new(revision)?,
        })
    }

    pub fn from_digest(digest: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        let digest = digest.into();
        validate_digest(&digest)?;
        Ok(Self {
            consent_digest: digest,
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
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionMetric {
    PageViews,
    FeatureClicks,
    GuideViews,
    UniqueVisitors,
    UniqueAccounts,
    AdoptionRate,
}

impl AdoptionMetric {
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::PageViews => "page_views",
            Self::FeatureClicks => "feature_clicks",
            Self::GuideViews => "guide_views",
            Self::UniqueVisitors => "unique_visitors",
            Self::UniqueAccounts => "unique_accounts",
            Self::AdoptionRate => "adoption_rate",
        }
    }

    #[must_use]
    pub const fn source(&self) -> &'static str {
        match self {
            Self::PageViews | Self::UniqueVisitors | Self::UniqueAccounts | Self::AdoptionRate => {
                "pageEvents"
            }
            Self::FeatureClicks => "featureEvents",
            Self::GuideViews => "guideEvents",
        }
    }

    #[must_use]
    pub const fn supports(&self, target: TargetKind) -> bool {
        match self {
            Self::PageViews => matches!(target, TargetKind::Page),
            Self::FeatureClicks => matches!(target, TargetKind::Feature),
            Self::GuideViews => matches!(target, TargetKind::Guide),
            Self::UniqueVisitors | Self::UniqueAccounts | Self::AdoptionRate => true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PendoReadProjection {
    Aggregate { metric: AdoptionMetric },
    ReportMetadata { target: TargetKind },
}

impl PendoReadProjection {
    pub fn validate(&self, target: TargetKind) -> Result<(), ModelError> {
        match self {
            Self::Aggregate { metric } if metric.supports(target) => Ok(()),
            Self::ReportMetadata { target: requested } if *requested == target => Ok(()),
            _ => Err(ModelError::InvalidProjection),
        }
    }

    #[must_use]
    pub const fn is_aggregate(&self) -> bool {
        matches!(self, Self::Aggregate { .. })
    }
}

/// The only permission set this Layer-1 crate can register: bounded reads and
/// metadata reads, with every external write capability disabled.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendoPermission {
    pub aggregate_read: bool,
    pub metadata_read: bool,
    pub external_writes: bool,
}

impl PendoPermission {
    #[must_use]
    pub const fn layer1_read_only() -> Self {
        Self {
            aggregate_read: true,
            metadata_read: true,
            external_writes: false,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if !self.aggregate_read || !self.metadata_read || self.external_writes {
            return Err(ModelError::InvalidScope("permission"));
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendoProductUsageScope {
    subscription: SubscriptionId,
    application: ApplicationId,
    account: AccountScope,
    visitor_kind: VisitorKind,
    target: TargetReference,
    segment: SegmentScope,
    time_window: TimeWindow,
    project: ProjectBinding,
    mission: MissionBinding,
    work_product: WorkProductBinding,
    consent: ConsentScope,
}

#[allow(clippy::too_many_arguments)]
impl PendoProductUsageScope {
    pub fn new(
        subscription: SubscriptionId,
        application: ApplicationId,
        account: AccountScope,
        visitor_kind: VisitorKind,
        target: TargetReference,
        segment: SegmentScope,
        time_window: TimeWindow,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        consent: ConsentScope,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            subscription,
            application,
            account,
            visitor_kind,
            target,
            segment,
            time_window,
            project,
            mission,
            work_product,
            consent,
        };
        scope.validate()?;
        Ok(scope)
    }

    fn validate(&self) -> Result<(), ModelError> {
        validate_digest(self.subscription.digest())?;
        validate_digest(self.application.digest())?;
        validate_digest(self.account.digest())?;
        validate_digest(self.target.id_digest())?;
        validate_digest(self.segment.digest())?;
        self.time_window.validate()?;
        if self.project.revision().get() == 0
            || self.mission.revision().get() == 0
            || self.work_product.revision().get() == 0
            || self.consent.revision().get() == 0
        {
            return Err(ModelError::InvalidScope("revision"));
        }
        Ok(())
    }

    #[must_use]
    pub fn subscription(&self) -> &SubscriptionId {
        &self.subscription
    }

    #[must_use]
    pub fn application(&self) -> &ApplicationId {
        &self.application
    }

    #[must_use]
    pub fn account(&self) -> &AccountScope {
        &self.account
    }

    #[must_use]
    pub const fn visitor_kind(&self) -> VisitorKind {
        self.visitor_kind
    }

    #[must_use]
    pub fn target(&self) -> &TargetReference {
        &self.target
    }

    #[must_use]
    pub fn segment(&self) -> &SegmentScope {
        &self.segment
    }

    #[must_use]
    pub fn time_window(&self) -> &TimeWindow {
        &self.time_window
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
    pub fn consent_digest(&self) -> &Digest {
        self.consent.digest()
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    #[must_use]
    pub fn revision_digest(&self) -> Digest {
        canonical_digest(&(
            self.project.revision(),
            self.mission.revision(),
            self.work_product.revision(),
            self.consent.revision(),
            self.time_window.digest(),
        ))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    opaque_locator: String,
    scope_digest: Digest,
    revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        opaque_locator: impl Into<String>,
        scope: &PendoProductUsageScope,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let opaque_locator = opaque_locator.into();
        validate_identifier(&opaque_locator, "secret reference")?;
        Ok(Self {
            opaque_locator,
            scope_digest: scope.digest(),
            revision: Revision::new(revision)?,
            revoked: false,
        })
    }

    pub fn from_scope_digest(
        opaque_locator: impl Into<String>,
        scope_digest: impl Into<String>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let opaque_locator = opaque_locator.into();
        let scope_digest = scope_digest.into();
        validate_identifier(&opaque_locator, "secret reference")?;
        validate_digest(&scope_digest)?;
        Ok(Self {
            opaque_locator,
            scope_digest,
            revision: Revision::new(revision)?,
            revoked: false,
        })
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
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
    pub fn stable_digest(&self) -> Digest {
        sha256_digest(
            format!(
                "pendo-secret-reference/v1|{}|{}|{}",
                self.scope_digest,
                self.revision.get(),
                self.opaque_locator
            )
            .as_bytes(),
        )
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(self.stable_digest(), self.revoked))
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
            .field("opaque_locator", &"<redacted>")
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Err(ser::Error::custom(
            "SecretReference is opaque and cannot be serialized",
        ))
    }
}

impl<'de> Deserialize<'de> for SecretReference {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Err(de::Error::custom(
            "SecretReference is opaque and cannot be deserialized",
        ))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendoRegistration {
    contract_version: String,
    contract_digest: Digest,
    provider_digest: Digest,
    permission_digest: Digest,
    scope_digest: Digest,
    query_digest: Digest,
    secret_reference_digest: Digest,
    state: RegistrationState,
    revision: Revision,
    registration_digest: Digest,
}

impl PendoRegistration {
    pub fn new(
        scope: &PendoProductUsageScope,
        secret: &SecretReference,
        provider_digest: Digest,
    ) -> Result<Self, ModelError> {
        if secret.scope_digest() != &scope.digest() {
            return Err(ModelError::SecretScopeMismatch);
        }
        validate_digest(&provider_digest)?;
        let permission_digest = PendoPermission::layer1_read_only().digest();
        let query_digest = canonical_digest(&(
            scope.digest(),
            &permission_digest,
            crate::PENDO_PRODUCT_USAGE_RESULT_API_REVISION,
        ));
        let mut registration = Self {
            contract_version: crate::PENDO_PRODUCT_USAGE_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_digest,
            permission_digest,
            scope_digest: scope.digest(),
            query_digest,
            secret_reference_digest: secret.digest(),
            state: RegistrationState::Active,
            revision: Revision::new(1)?,
            registration_digest: String::new(),
        };
        registration.registration_digest = registration.digest();
        Ok(registration)
    }

    #[must_use]
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    #[must_use]
    pub fn state(&self) -> RegistrationState {
        self.state
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    #[must_use]
    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    #[must_use]
    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    #[must_use]
    pub fn secret_reference_digest(&self) -> &Digest {
        &self.secret_reference_digest
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            &self.contract_version,
            &self.contract_digest,
            &self.provider_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.query_digest,
            &self.secret_reference_digest,
            self.state,
            self.revision,
        ))
    }

    pub fn validate(
        &self,
        scope: &PendoProductUsageScope,
        secret: &SecretReference,
        provider_digest: &Digest,
    ) -> Result<(), ModelError> {
        if self.state != RegistrationState::Active
            || self.registration_digest != self.digest()
            || self.contract_version != crate::PENDO_PRODUCT_USAGE_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_digest != *provider_digest
            || self.permission_digest != PendoPermission::layer1_read_only().digest()
            || self.scope_digest != scope.digest()
            || self.query_digest
                != canonical_digest(&(
                    scope.digest(),
                    &self.permission_digest,
                    crate::PENDO_PRODUCT_USAGE_RESULT_API_REVISION,
                ))
            || self.secret_reference_digest != secret.digest()
            || secret.scope_digest() != &scope.digest()
            || secret.is_revoked()
        {
            return Err(ModelError::InvalidRegistration);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, ModelError> {
        if self.state == RegistrationState::Revoked {
            return Err(ModelError::RegistrationAlreadyRevoked);
        }
        let previous_digest = self.registration_digest.clone();
        self.state = RegistrationState::Revoked;
        self.revision = self.revision.next()?;
        self.registration_digest = self.digest();
        Ok(RegistrationRevocation {
            previous_digest,
            next_digest: self.registration_digest.clone(),
            state: self.state,
            reversible: true,
        })
    }

    pub fn restore(&mut self) -> Result<RegistrationRevocation, ModelError> {
        if self.state == RegistrationState::Active {
            return Err(ModelError::RegistrationNotRevoked);
        }
        let previous_digest = self.registration_digest.clone();
        self.state = RegistrationState::Active;
        self.revision = self.revision.next()?;
        self.registration_digest = self.digest();
        Ok(RegistrationRevocation {
            previous_digest,
            next_digest: self.registration_digest.clone(),
            state: self.state,
            reversible: true,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    pub previous_digest: Digest,
    pub next_digest: Digest,
    pub state: RegistrationState,
    pub reversible: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendoUsageRequest {
    projection: PendoReadProjection,
    scope_digest: Digest,
    mission_revision: Revision,
    work_product_revision: Revision,
    consent_digest: Digest,
    requested_at: Timestamp,
}

impl PendoUsageRequest {
    pub fn new(
        scope: &PendoProductUsageScope,
        projection: PendoReadProjection,
        requested_at: Timestamp,
    ) -> Result<Self, ModelError> {
        projection.validate(scope.target().kind())?;
        let request = Self {
            projection,
            scope_digest: scope.digest(),
            mission_revision: scope.mission().revision(),
            work_product_revision: scope.work_product().revision(),
            consent_digest: scope.consent_digest().clone(),
            requested_at,
        };
        request.validate(scope)?;
        Ok(request)
    }

    pub fn aggregate(
        scope: &PendoProductUsageScope,
        metric: AdoptionMetric,
        requested_at: Timestamp,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            PendoReadProjection::Aggregate { metric },
            requested_at,
        )
    }

    pub fn report_metadata(
        scope: &PendoProductUsageScope,
        requested_at: Timestamp,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            PendoReadProjection::ReportMetadata {
                target: scope.target().kind(),
            },
            requested_at,
        )
    }

    pub fn validate(&self, scope: &PendoProductUsageScope) -> Result<(), ModelError> {
        if self.scope_digest != scope.digest()
            || self.mission_revision != scope.mission().revision()
            || self.work_product_revision != scope.work_product().revision()
            || self.consent_digest != *scope.consent_digest()
        {
            return Err(ModelError::InvalidScope("request binding"));
        }
        self.projection.validate(scope.target().kind())
    }

    #[must_use]
    pub fn projection(&self) -> &PendoReadProjection {
        &self.projection
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn mission_revision(&self) -> Revision {
        self.mission_revision
    }

    #[must_use]
    pub const fn work_product_revision(&self) -> Revision {
        self.work_product_revision
    }

    #[must_use]
    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    #[must_use]
    pub const fn requested_at(&self) -> Timestamp {
        self.requested_at
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    #[must_use]
    pub fn with_mission_revision(mut self, revision: Revision) -> Self {
        self.mission_revision = revision;
        self
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendoAggregateBucket {
    pub bucket_digest: Digest,
    pub value: u64,
}

impl PendoAggregateBucket {
    pub fn new(bucket: impl Into<String>, value: u64) -> Result<Self, ModelError> {
        let bucket = bucket.into();
        validate_identifier(&bucket, "aggregate bucket")?;
        Ok(Self {
            bucket_digest: digest_text("pendo-bucket", &bucket),
            value,
        })
    }

    pub fn from_digest(bucket_digest: impl Into<String>, value: u64) -> Result<Self, ModelError> {
        let bucket_digest = bucket_digest.into();
        validate_digest(&bucket_digest)?;
        Ok(Self {
            bucket_digest,
            value,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendoAggregate {
    pub metric: AdoptionMetric,
    pub total: u64,
    pub buckets: Vec<PendoAggregateBucket>,
    pub reported_rate_bps: Option<u16>,
    pub partial: bool,
}

impl PendoAggregate {
    pub fn new(
        metric: AdoptionMetric,
        mut buckets: Vec<PendoAggregateBucket>,
        reported_rate_bps: Option<u16>,
        partial: bool,
    ) -> Result<Self, ModelError> {
        if buckets.len() > MAX_BUCKETS || reported_rate_bps.is_some_and(|rate| rate > 10_000) {
            return Err(ModelError::ResponseTooManyRows);
        }
        buckets.sort_by(|left, right| left.bucket_digest.cmp(&right.bucket_digest));
        let mut seen = BTreeSet::new();
        let mut total = 0_u64;
        for bucket in &buckets {
            if !seen.insert(bucket.bucket_digest.clone()) {
                return Err(ModelError::InvalidAggregate);
            }
            total = total
                .checked_add(bucket.value)
                .ok_or(ModelError::InvalidAggregate)?;
        }
        Ok(Self {
            metric,
            total,
            buckets,
            reported_rate_bps,
            partial,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendoReportMetadata {
    pub target: TargetKind,
    pub target_digest: Digest,
    pub application_digest: Digest,
    pub label_digest: Option<Digest>,
    pub version_digest: Option<Digest>,
    pub updated_at: Option<Timestamp>,
    pub field_count: u16,
}

impl PendoReportMetadata {
    pub fn new(
        target: TargetKind,
        target_digest: Digest,
        application_digest: Digest,
        label_digest: Option<Digest>,
        version_digest: Option<Digest>,
        updated_at: Option<Timestamp>,
        field_count: u16,
    ) -> Result<Self, ModelError> {
        validate_digest(&target_digest)?;
        validate_digest(&application_digest)?;
        if let Some(digest) = &label_digest {
            validate_digest(digest)?;
        }
        if let Some(digest) = &version_digest {
            validate_digest(digest)?;
        }
        Ok(Self {
            target,
            target_digest,
            application_digest,
            label_digest,
            version_digest,
            updated_at,
            field_count,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionSummary {
    pub raw_response_body_dropped: bool,
    pub visitor_rows_dropped: u32,
    pub pii_values_dropped: u32,
    pub event_payloads_dropped: u32,
    pub labels_digested: u32,
    pub unknown_fields_dropped: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendoReadReceipt {
    pub method: String,
    pub path: String,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub status_code: Option<u16>,
    pub response_bytes: usize,
    pub secret_reference_digest: Digest,
    pub body_retained: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }

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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceState {
    Present,
    Partial,
    Stale,
    AccessLost,
    ProviderUnknown,
    RateLimited,
    Tampered,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceClassification {
    Present,
    Partial,
    Stale,
    AccessLost,
    BlockedEnv,
    ProviderUnknown,
    RateLimited,
    Tampered,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    BlockedEnv,
    Unauthorized,
    Forbidden,
    NotFound,
    RateLimited,
    ResponseTooLarge,
    TooManyRows,
    PrivacyViolation,
    MalformedResponse,
    Transport,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationDisposition {
    ReviewPageAdoption,
    ReviewFeatureAdoption,
    ReviewGuideAdoption,
    NoRecommendationPartial,
    NoRecommendationStale,
    NoRecommendationAccessLost,
    NoRecommendationProviderUnknown,
    NoRecommendationRateLimited,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendoUsageRecommendation {
    pub disposition: RecommendationDisposition,
    pub provider_reported_only: bool,
    pub non_mutating: bool,
    pub causal_claim: bool,
    pub outcome_authority: bool,
    pub rationale_digest: Digest,
}
