//! Typed Amplitude experiment-result contract, scope, evidence, and proposal
//! models. This module intentionally contains no HTTP client and no host
//! credential resolver.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_PAGES: u16 = 8;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_VARIANTS: usize = 32;
pub const MAX_METRICS: usize = 16;
pub const MAX_SEGMENTS: usize = 16;
pub const MAX_CONFIDENCE_METADATA: usize = 4;
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;

pub type Digest = String;

/// Return a lowercase SHA-256 digest.
#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    format!("{:x}", Sha256::digest(bytes))
}

/// Hash a serde value using its deterministic JSON representation.
///
/// # Panics
///
/// Panics only if a caller supplies a `Serialize` implementation that refuses
/// to serialize. All contract types in this crate serialize deterministically.
#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("Amplitude typed value serializes");
    sha256_digest(&bytes)
}

fn validate_identifier(value: &str, label: &'static str) -> Result<(), AmplitudeResultError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(AmplitudeResultError::InvalidIdentifier { label });
    }
    Ok(())
}

fn validate_text(
    value: &str,
    label: &'static str,
    maximum: usize,
) -> Result<(), AmplitudeResultError> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(AmplitudeResultError::InvalidText { label });
    }
    Ok(())
}

fn validate_revision(revision: u64, label: &'static str) -> Result<(), AmplitudeResultError> {
    if revision == 0 {
        return Err(AmplitudeResultError::InvalidRevision { label });
    }
    Ok(())
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
    ApiCredential,
}

impl SecretKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ApiCredential => "api_credential",
        }
    }
}

/// Opaque host-owned reference to an Amplitude credential.
///
/// The opaque identifier is private and this type deliberately does not
/// implement `Serialize`, `Deserialize`, or `Display`. Only a digest can enter
/// a registration, request, proposal, or evidence record.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    opaque_id: String,
    revision: u64,
}

impl SecretReference {
    pub fn api_credential(
        opaque_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, AmplitudeResultError> {
        let opaque_id = opaque_id.into();
        validate_revision(revision, "secret reference")?;
        if opaque_id.is_empty()
            || opaque_id.len() > MAX_IDENTIFIER_BYTES
            || opaque_id.trim() != opaque_id
            || opaque_id.chars().any(char::is_control)
        {
            return Err(AmplitudeResultError::InvalidIdentifier {
                label: "secret reference",
            });
        }
        Ok(Self {
            kind: SecretKind::ApiCredential,
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
                "amplitude-secret-reference|{}|{}|{}",
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
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, AmplitudeResultError> {
        let id = id.into();
        validate_identifier(&id, "identity")?;
        validate_revision(revision, "identity")?;
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
pub type ExperimentBinding = IdentityBinding;
pub type VariantBinding = IdentityBinding;
pub type SegmentBinding = IdentityBinding;
pub type WorkProductBinding = IdentityBinding;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricDirection {
    Increase,
    Decrease,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetricDefinition {
    id: String,
    revision: u64,
    direction: MetricDirection,
    minimum_exposure: u64,
}

impl MetricDefinition {
    pub fn new(
        id: impl Into<String>,
        revision: u64,
        direction: MetricDirection,
        minimum_exposure: u64,
    ) -> Result<Self, AmplitudeResultError> {
        let id = id.into();
        validate_identifier(&id, "metric")?;
        validate_revision(revision, "metric")?;
        if minimum_exposure == 0 {
            return Err(AmplitudeResultError::InvalidRevision {
                label: "metric minimum exposure",
            });
        }
        Ok(Self {
            id,
            revision,
            direction,
            minimum_exposure,
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
    pub const fn direction(&self) -> MetricDirection {
        self.direction
    }

    #[must_use]
    pub const fn minimum_exposure(&self) -> u64 {
        self.minimum_exposure
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExposureWindow {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    revision: u64,
}

impl ExposureWindow {
    pub fn new(
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        revision: u64,
    ) -> Result<Self, AmplitudeResultError> {
        validate_revision(revision, "exposure window")?;
        if end < start {
            return Err(AmplitudeResultError::InvalidExposureWindow);
        }
        Ok(Self {
            start,
            end,
            revision,
        })
    }

    #[must_use]
    pub const fn start(&self) -> DateTime<Utc> {
        self.start
    }

    #[must_use]
    pub const fn end(&self) -> DateTime<Utc> {
        self.end
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AmplitudeRegion {
    Default,
    Eu,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmplitudeApiDefinition {
    dashboard_rest_revision: String,
    region: AmplitudeRegion,
    host: String,
}

impl AmplitudeApiDefinition {
    #[must_use]
    pub fn layer1() -> Self {
        Self {
            dashboard_rest_revision: crate::AMPLITUDE_DASHBOARD_REST_REVISION.into(),
            region: AmplitudeRegion::Default,
            host: "https://amplitude.com".into(),
        }
    }

    pub fn for_region(region: AmplitudeRegion) -> Result<Self, AmplitudeResultError> {
        let host = match region {
            AmplitudeRegion::Default => "https://amplitude.com",
            AmplitudeRegion::Eu => "https://analytics.eu.amplitude.com",
        };
        Ok(Self {
            dashboard_rest_revision: crate::AMPLITUDE_DASHBOARD_REST_REVISION.into(),
            region,
            host: host.into(),
        })
    }

    #[must_use]
    pub fn dashboard_rest_revision(&self) -> &str {
        &self.dashboard_rest_revision
    }

    #[must_use]
    pub const fn region(&self) -> AmplitudeRegion {
        self.region
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AmplitudeCapability {
    ExperimentResultRead,
}

impl AmplitudeCapability {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ExperimentResultRead => crate::AMPLITUDE_EXPERIMENT_RESULT_CAPABILITY,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AmplitudePermission {
    ExperimentResultsRead,
    SavedChartRead,
}

impl AmplitudePermission {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ExperimentResultsRead => "experiment_results_read",
            Self::SavedChartRead => "saved_chart_read",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmplitudePermissionSnapshot {
    permissions: Vec<AmplitudePermission>,
    revision: u64,
}

impl AmplitudePermissionSnapshot {
    pub fn least_privilege(revision: u64) -> Result<Self, AmplitudeResultError> {
        Self::new(
            vec![
                AmplitudePermission::ExperimentResultsRead,
                AmplitudePermission::SavedChartRead,
            ],
            revision,
        )
    }

    pub fn new(
        permissions: Vec<AmplitudePermission>,
        revision: u64,
    ) -> Result<Self, AmplitudeResultError> {
        let snapshot = Self {
            permissions,
            revision,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn validate(&self) -> Result<(), AmplitudeResultError> {
        validate_revision(self.revision, "permission snapshot")?;
        if self.permissions.len() != 2
            || self.permissions.iter().collect::<BTreeSet<_>>().len() != 2
            || !self.has(AmplitudePermission::ExperimentResultsRead)
            || !self.has(AmplitudePermission::SavedChartRead)
        {
            return Err(AmplitudeResultError::InvalidPermissionSnapshot);
        }
        Ok(())
    }

    #[must_use]
    pub fn permissions(&self) -> &[AmplitudePermission] {
        &self.permissions
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn has(&self, permission: AmplitudePermission) -> bool {
        self.permissions.contains(&permission)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AmplitudeExperimentScopeSpec {
    pub project: ProjectBinding,
    pub experiment: ExperimentBinding,
    pub variants: Vec<VariantBinding>,
    pub metric: MetricDefinition,
    pub exposure_window: ExposureWindow,
    pub segment: SegmentBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub api: AmplitudeApiDefinition,
    pub permissions: AmplitudePermissionSnapshot,
    pub capabilities: Vec<AmplitudeCapability>,
    pub secret_reference: SecretReference,
}

#[allow(clippy::too_many_arguments)]
impl AmplitudeExperimentScopeSpec {
    #[must_use]
    pub fn new(
        project: ProjectBinding,
        experiment: ExperimentBinding,
        variants: Vec<VariantBinding>,
        metric: MetricDefinition,
        exposure_window: ExposureWindow,
        segment: SegmentBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        api: AmplitudeApiDefinition,
        permissions: AmplitudePermissionSnapshot,
        secret_reference: SecretReference,
    ) -> Self {
        Self {
            project,
            experiment,
            variants,
            metric,
            exposure_window,
            segment,
            mission,
            work_product,
            api,
            permissions,
            capabilities: vec![AmplitudeCapability::ExperimentResultRead],
            secret_reference,
        }
    }

    #[must_use]
    pub fn with_capabilities(mut self, capabilities: Vec<AmplitudeCapability>) -> Self {
        self.capabilities = capabilities;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AmplitudeExperimentScope {
    spec: AmplitudeExperimentScopeSpec,
}

impl AmplitudeExperimentScope {
    pub fn new(spec: AmplitudeExperimentScopeSpec) -> Result<Self, AmplitudeResultError> {
        let scope = Self { spec };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), AmplitudeResultError> {
        if self.spec.variants.is_empty() || self.spec.variants.len() > MAX_VARIANTS {
            return Err(AmplitudeResultError::BoundExceeded {
                label: "variants",
                maximum: MAX_VARIANTS,
            });
        }
        if self
            .spec
            .variants
            .iter()
            .map(IdentityBinding::id)
            .collect::<BTreeSet<_>>()
            .len()
            != self.spec.variants.len()
        {
            return Err(AmplitudeResultError::InvalidScope("duplicate variant"));
        }
        self.spec.permissions.validate()?;
        validate_revision(self.spec.project.revision(), "project")?;
        validate_revision(self.spec.experiment.revision(), "experiment")?;
        validate_revision(self.spec.segment.revision(), "segment")?;
        validate_revision(self.spec.mission.revision(), "mission")?;
        validate_revision(self.spec.work_product.revision(), "work product")?;
        if self.spec.capabilities.len() != 1
            || self.spec.capabilities[0] != AmplitudeCapability::ExperimentResultRead
        {
            return Err(AmplitudeResultError::InvalidCapability);
        }
        Ok(())
    }

    #[must_use]
    pub fn spec(&self) -> &AmplitudeExperimentScopeSpec {
        &self.spec
    }

    #[must_use]
    pub fn project(&self) -> &ProjectBinding {
        &self.spec.project
    }

    #[must_use]
    pub fn experiment(&self) -> &ExperimentBinding {
        &self.spec.experiment
    }

    #[must_use]
    pub fn variants(&self) -> &[VariantBinding] {
        &self.spec.variants
    }

    #[must_use]
    pub fn metric(&self) -> &MetricDefinition {
        &self.spec.metric
    }

    #[must_use]
    pub fn exposure_window(&self) -> &ExposureWindow {
        &self.spec.exposure_window
    }

    #[must_use]
    pub fn segment(&self) -> &SegmentBinding {
        &self.spec.segment
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
    pub fn api(&self) -> &AmplitudeApiDefinition {
        &self.spec.api
    }

    #[must_use]
    pub fn permissions(&self) -> &AmplitudePermissionSnapshot {
        &self.spec.permissions
    }

    #[must_use]
    pub fn capabilities(&self) -> &[AmplitudeCapability] {
        &self.spec.capabilities
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.spec.secret_reference
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        sha256_digest(
            format!(
                "{}|{}|{}",
                crate::AMPLITUDE_PROVIDER_ID,
                crate::AMPLITUDE_PROVIDER_REVISION,
                crate::AMPLITUDE_DASHBOARD_REST_REVISION
            )
            .as_bytes(),
        )
    }

    #[must_use]
    pub fn capability_digest(&self) -> Digest {
        canonical_digest(&self.spec.capabilities)
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
            self.project().revision(),
            self.experiment().revision(),
            self.variants()
                .iter()
                .map(IdentityBinding::revision)
                .collect::<Vec<_>>(),
            self.metric().revision(),
            self.exposure_window().revision(),
            self.segment().revision(),
            self.mission().revision(),
            self.work_product().revision(),
            self.permissions().revision(),
            self.secret_reference().revision(),
        ))
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            self.project().digest(),
            self.experiment().digest(),
            self.variants()
                .iter()
                .map(IdentityBinding::digest)
                .collect::<Vec<_>>(),
            self.metric().digest(),
            self.exposure_window().digest(),
            self.segment().digest(),
            self.mission().digest(),
            self.work_product().digest(),
            self.api_digest(),
            self.permission_digest(),
            self.capability_digest(),
            self.provider_digest(),
            self.revision_digest(),
            self.secret_reference().digest(),
        ))
    }

    #[must_use]
    pub fn contains_variant(&self, variant_id: &str, revision: u64) -> bool {
        self.variants()
            .iter()
            .any(|variant| variant.id() == variant_id && variant.revision() == revision)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmplitudeExperimentResultRead {
    chart_id: String,
    page: u16,
    page_size: u16,
    max_age_seconds: u32,
}

impl AmplitudeExperimentResultRead {
    pub fn saved_chart(chart_id: impl Into<String>) -> Result<Self, AmplitudeResultError> {
        Self::new(chart_id, 1, MAX_PAGE_SIZE, 86_400)
    }

    pub fn new(
        chart_id: impl Into<String>,
        page: u16,
        page_size: u16,
        max_age_seconds: u32,
    ) -> Result<Self, AmplitudeResultError> {
        let chart_id = chart_id.into();
        validate_identifier(&chart_id, "chart")?;
        if page == 0 || page > MAX_PAGES {
            return Err(AmplitudeResultError::BoundExceeded {
                label: "page",
                maximum: usize::from(MAX_PAGES),
            });
        }
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(AmplitudeResultError::BoundExceeded {
                label: "page size",
                maximum: usize::from(MAX_PAGE_SIZE),
            });
        }
        if max_age_seconds == 0 || max_age_seconds > 2_592_000 {
            return Err(AmplitudeResultError::BoundExceeded {
                label: "freshness window seconds",
                maximum: 2_592_000,
            });
        }
        Ok(Self {
            chart_id,
            page,
            page_size,
            max_age_seconds,
        })
    }

    #[must_use]
    pub fn chart_id(&self) -> &str {
        &self.chart_id
    }

    #[must_use]
    pub const fn page(&self) -> u16 {
        self.page
    }

    #[must_use]
    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    #[must_use]
    pub const fn max_age_seconds(&self) -> u32 {
        self.max_age_seconds
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderDecision {
    Significant,
    Inconclusive,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderDecisionState {
    Significant,
    Inconclusive,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfidenceMetadata {
    level: f64,
    lower: Option<f64>,
    upper: Option<f64>,
}

impl ConfidenceMetadata {
    pub fn new(
        level: f64,
        lower: Option<f64>,
        upper: Option<f64>,
    ) -> Result<Self, AmplitudeResultError> {
        if !level.is_finite()
            || !(0.0..=1.0).contains(&level)
            || lower.is_some_and(|value| !value.is_finite())
            || upper.is_some_and(|value| !value.is_finite())
            || matches!((lower, upper), (Some(low), Some(high)) if low > high)
        {
            return Err(AmplitudeResultError::InvalidConfidenceMetadata);
        }
        Ok(Self {
            level,
            lower,
            upper,
        })
    }

    #[must_use]
    pub const fn level(&self) -> f64 {
        self.level
    }

    #[must_use]
    pub const fn lower(&self) -> Option<f64> {
        self.lower
    }

    #[must_use]
    pub const fn upper(&self) -> Option<f64> {
        self.upper
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmplitudeMetricPage {
    pub metric_id: String,
    pub metric_revision: u64,
    pub value: Option<f64>,
    pub confidence: Option<ConfidenceMetadata>,
    pub decision: ProviderDecision,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmplitudeVariantPage {
    pub variant_id: String,
    pub variant_revision: u64,
    pub exposure_count: u64,
    pub metrics: Vec<AmplitudeMetricPage>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmplitudeResultPage {
    pub project_id: String,
    pub experiment_id: String,
    pub segment_id: String,
    pub segment_revision: u64,
    pub exposure_window_start: DateTime<Utc>,
    pub exposure_window_end: DateTime<Utc>,
    pub generated_at: DateTime<Utc>,
    pub page: u16,
    pub page_size: u16,
    pub total_pages: u16,
    pub partial: bool,
    pub decision: ProviderDecisionState,
    pub variants: Vec<AmplitudeVariantPage>,
}

impl AmplitudeResultPage {
    pub fn validate_bounds(&self) -> Result<(), AmplitudeResultError> {
        if self.page == 0 || self.page > MAX_PAGES {
            return Err(AmplitudeResultError::BoundExceeded {
                label: "response page",
                maximum: usize::from(MAX_PAGES),
            });
        }
        if self.page_size == 0 || self.page_size > MAX_PAGE_SIZE {
            return Err(AmplitudeResultError::BoundExceeded {
                label: "response page size",
                maximum: usize::from(MAX_PAGE_SIZE),
            });
        }
        if self.total_pages == 0 || self.total_pages > MAX_PAGES || self.page > self.total_pages {
            return Err(AmplitudeResultError::BoundExceeded {
                label: "response total pages",
                maximum: usize::from(MAX_PAGES),
            });
        }
        if self.variants.len() > MAX_VARIANTS {
            return Err(AmplitudeResultError::BoundExceeded {
                label: "response variants",
                maximum: MAX_VARIANTS,
            });
        }
        if self
            .variants
            .iter()
            .map(|variant| variant.variant_id.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            != self.variants.len()
        {
            return Err(AmplitudeResultError::InvalidProviderResponse(
                "duplicate variant",
            ));
        }
        for variant in &self.variants {
            validate_identifier(&variant.variant_id, "response variant")?;
            validate_revision(variant.variant_revision, "response variant")?;
            if variant.metrics.len() > MAX_METRICS {
                return Err(AmplitudeResultError::BoundExceeded {
                    label: "response metrics",
                    maximum: MAX_METRICS,
                });
            }
            if variant.metrics.iter().any(|metric| {
                metric.metric_id.is_empty()
                    || metric.metric_revision == 0
                    || metric.value.is_some_and(|value| !value.is_finite())
            }) {
                return Err(AmplitudeResultError::InvalidProviderResponse(
                    "invalid metric value",
                ));
            }
            if variant
                .metrics
                .iter()
                .map(|metric| metric.metric_id.as_str())
                .collect::<BTreeSet<_>>()
                .len()
                != variant.metrics.len()
            {
                return Err(AmplitudeResultError::InvalidProviderResponse(
                    "duplicate metric",
                ));
            }
            for metric in &variant.metrics {
                validate_identifier(&metric.metric_id, "response metric")?;
                validate_revision(metric.metric_revision, "response metric")?;
                if metric.confidence.is_some() && MAX_CONFIDENCE_METADATA == 0 {
                    return Err(AmplitudeResultError::InvalidProviderResponse(
                        "confidence metadata disabled",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DecisionMetadata {
    pub provider_decision: ProviderDecision,
    pub provider_reported: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmplitudeMetricResult {
    pub metric: MetricDefinition,
    pub value: Option<f64>,
    pub confidence: Option<ConfidenceMetadata>,
    pub decision: DecisionMetadata,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmplitudeVariantResult {
    pub variant: VariantBinding,
    pub exposure_count: u64,
    pub metric: AmplitudeMetricResult,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmplitudeResultProjection {
    pub project: ProjectBinding,
    pub experiment: ExperimentBinding,
    pub segment: SegmentBinding,
    pub exposure_window: ExposureWindow,
    pub metric: MetricDefinition,
    pub variants: Vec<AmplitudeVariantResult>,
    pub provider_decision: ProviderDecisionState,
    pub partial: bool,
}

impl AmplitudeResultProjection {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AmplitudeResultState {
    Significant,
    Inconclusive,
    InsufficientExposure,
    Stale,
    Partial,
    Empty,
    AccessLost,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClassification {
    Normalized,
    AccessLost,
    BlockedEnv,
    ProviderUnknown,
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
    pub const fn is_native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn replayable(self) -> bool {
        !matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportStatus {
    Ok,
    BlockedEnv,
    AccessDenied,
    NotFound,
    RateLimited,
    ProviderError,
    Timeout,
    MalformedResponse,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadReceipt {
    pub request_id: Digest,
    pub request_digest: Digest,
    pub endpoint: String,
    pub page: u16,
    pub page_size: u16,
    pub max_response_bytes: usize,
    pub cost_units: u32,
    pub response_bytes: usize,
    pub provider_request_id: Option<String>,
    pub transport_status: TransportStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResponseReceipt {
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub provider_request_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FreshnessReceipt {
    pub source_generated_at: DateTime<Utc>,
    pub observed_at: DateTime<Utc>,
    pub max_age_seconds: u32,
    pub age_seconds: u64,
    pub fresh: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordingReceipt {
    pub provenance: TransportProvenance,
    pub replayable: bool,
    pub native: bool,
    pub connected: bool,
    pub recording_digest: Digest,
}

impl RecordingReceipt {
    #[must_use]
    pub fn new(provenance: TransportProvenance, response_digest: &str) -> Self {
        let replayable = provenance.replayable();
        let recording_digest = canonical_digest(&(provenance, replayable, response_digest));
        Self {
            provenance,
            replayable,
            native: false,
            connected: false,
            recording_digest,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AmplitudeEffectReceiptStatus {
    ObservationRecorded,
    NotExecutedLayer1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmplitudeEffectReceipt {
    pub intent_digest: Digest,
    pub status: AmplitudeEffectReceiptStatus,
    pub provider_receipt_digest: Digest,
    pub native: bool,
    pub connected: bool,
    pub durable: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadbackStatus {
    VerifiedAgainstProposal,
    NotAvailableLayer1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmplitudeReadbackReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub status: ReadbackStatus,
    pub native: bool,
    pub connected: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmplitudeReadConsent {
    pub scope_digest: Digest,
    pub mission_revision: u64,
    pub capability: AmplitudeCapability,
    pub consent_revision: u64,
    pub granted: bool,
    pub native: bool,
}

impl AmplitudeReadConsent {
    #[must_use]
    pub fn for_scope(scope: &AmplitudeExperimentScope) -> Self {
        Self {
            scope_digest: scope.digest(),
            mission_revision: scope.mission().revision(),
            capability: AmplitudeCapability::ExperimentResultRead,
            consent_revision: 1,
            granted: true,
            native: false,
        }
    }

    pub fn validate(&self, scope: &AmplitudeExperimentScope) -> Result<(), AmplitudeResultError> {
        if !self.granted
            || self.native
            || self.capability != AmplitudeCapability::ExperimentResultRead
            || self.scope_digest != scope.digest()
            || self.mission_revision != scope.mission().revision()
            || self.consent_revision == 0
        {
            return Err(AmplitudeResultError::ConsentDenied);
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
pub struct AmplitudeEffectIntent {
    pub capability: AmplitudeCapability,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub request_digest: Digest,
    pub mutating: bool,
    pub native: bool,
}

impl AmplitudeEffectIntent {
    #[must_use]
    pub fn for_read(
        scope: &AmplitudeExperimentScope,
        consent: &AmplitudeReadConsent,
        operation: &AmplitudeExperimentResultRead,
    ) -> Self {
        Self {
            capability: AmplitudeCapability::ExperimentResultRead,
            scope_digest: scope.digest(),
            consent_digest: consent.digest(),
            request_digest: canonical_digest(&(scope.digest(), operation.digest())),
            mutating: false,
            native: false,
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AmplitudeRegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmplitudeRegistration {
    pub plugin_version: PluginVersion,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub capability: AmplitudeCapability,
    pub capability_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub registration_digest: Digest,
    pub state: AmplitudeRegistrationState,
    pub reversible: bool,
    pub revocable: bool,
}

impl AmplitudeRegistration {
    #[must_use]
    pub fn bind(scope: &AmplitudeExperimentScope, contract_digest: Digest) -> Self {
        let plugin_version = crate::plugin_version();
        let contract_version = crate::AMPLITUDE_EXPERIMENT_RESULT_CONTRACT_VERSION.to_owned();
        let provider_id = crate::AMPLITUDE_PROVIDER_ID.to_owned();
        let provider_revision = crate::AMPLITUDE_PROVIDER_REVISION.to_owned();
        let provider_digest = scope.provider_digest();
        let capability = AmplitudeCapability::ExperimentResultRead;
        let capability_digest = scope.capability_digest();
        let scope_digest = scope.digest();
        let revision_digest = scope.revision_digest();
        let registration_digest = canonical_digest(&(
            plugin_version,
            &contract_version,
            &contract_digest,
            &provider_id,
            &provider_revision,
            &provider_digest,
            capability,
            &capability_digest,
            &scope_digest,
            &revision_digest,
        ));
        Self {
            plugin_version,
            contract_version,
            contract_digest,
            provider_id,
            provider_revision,
            provider_digest,
            capability,
            capability_digest,
            scope_digest,
            revision_digest,
            registration_digest,
            state: AmplitudeRegistrationState::Active,
            reversible: true,
            revocable: true,
        }
    }

    pub fn validate(&self, scope: &AmplitudeExperimentScope) -> Result<(), AmplitudeResultError> {
        if self.state != AmplitudeRegistrationState::Active {
            return Err(AmplitudeResultError::RegistrationRevoked);
        }
        if self.plugin_version != crate::plugin_version()
            || self.contract_version != crate::AMPLITUDE_EXPERIMENT_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_id != crate::AMPLITUDE_PROVIDER_ID
            || self.provider_revision != crate::AMPLITUDE_PROVIDER_REVISION
            || self.provider_digest != scope.provider_digest()
            || self.capability != AmplitudeCapability::ExperimentResultRead
            || self.capability_digest != scope.capability_digest()
            || self.scope_digest != scope.digest()
            || self.revision_digest != scope.revision_digest()
            || !self.reversible
            || !self.revocable
        {
            return Err(AmplitudeResultError::RegistrationDrift);
        }
        Ok(())
    }

    pub fn revoke(
        &mut self,
        reason: impl Into<String>,
    ) -> Result<RegistrationRevocationReceipt, AmplitudeResultError> {
        if !self.revocable {
            return Err(AmplitudeResultError::RegistrationNotRevocable);
        }
        let reason = reason.into();
        validate_text(&reason, "revocation reason", MAX_DIAGNOSTIC_BYTES)?;
        self.state = AmplitudeRegistrationState::Revoked;
        Ok(RegistrationRevocationReceipt {
            registration_digest: self.registration_digest.clone(),
            reason,
            reversible: self.reversible,
            native: false,
            connected: false,
        })
    }

    pub fn restore(&mut self) -> Result<(), AmplitudeResultError> {
        if !self.reversible {
            return Err(AmplitudeResultError::RegistrationNotReversible);
        }
        self.state = AmplitudeRegistrationState::Active;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocationReceipt {
    pub registration_digest: Digest,
    pub reason: String,
    pub reversible: bool,
    pub native: bool,
    pub connected: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultRecommendationDisposition {
    ProviderReportedSignificant,
    NoRecommendationInconclusive,
    NoRecommendationInsufficientExposure,
    NoRecommendationStale,
    NoRecommendationPartial,
    NoRecommendationEmpty,
    NoRecommendationAccessLost,
    NoRecommendationProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResultRecommendation {
    pub disposition: ResultRecommendationDisposition,
    pub recommended_variant: Option<VariantBinding>,
    pub provider_reported_only: bool,
    pub statistical_claim: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmplitudeResultEvidence {
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub operation: AmplitudeExperimentResultRead,
    pub projection: Option<AmplitudeResultProjection>,
    pub state: AmplitudeResultState,
    pub classification: EvidenceClassification,
    pub read_receipt: ReadReceipt,
    pub response_receipt: Option<ResponseReceipt>,
    pub freshness: Option<FreshnessReceipt>,
    pub recording: RecordingReceipt,
    pub effect_receipt: AmplitudeEffectReceipt,
    pub native: bool,
    pub connected: bool,
}

impl AmplitudeResultEvidence {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            &self.scope_digest,
            &self.revision_digest,
            &self.operation,
            &self.projection,
            self.state,
            self.classification,
            &self.read_receipt,
            &self.response_receipt,
            &self.freshness,
            &self.recording,
            &self.effect_receipt,
            self.native,
            self.connected,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmplitudeExperimentResultProposal {
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub registration_digest: Digest,
    pub project: ProjectBinding,
    pub experiment: ExperimentBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub evidence: AmplitudeResultEvidence,
    pub source_evidence_digest: Digest,
    pub recommendation: ResultRecommendation,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub adopts_outcome: bool,
}

impl AmplitudeExperimentResultProposal {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    #[must_use]
    pub fn result_state(&self) -> AmplitudeResultState {
        self.evidence.state
    }
}

#[derive(Clone, Debug, Deserialize, Error, Eq, PartialEq)]
pub enum AmplitudeTransportError {
    #[error("Amplitude native transport is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("Amplitude transport access denied with HTTP {status}")]
    AccessDenied { status: u16 },
    #[error("Amplitude chart was not found")]
    NotFound,
    #[error("Amplitude rate limit was reached")]
    RateLimited,
    #[error("Amplitude provider returned HTTP {status}")]
    ProviderError { status: u16 },
    #[error("Amplitude transport timed out")]
    Timeout,
    #[error("Amplitude transport diagnostic is invalid")]
    InvalidDiagnostic,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AmplitudeResultError {
    #[error("invalid {label} identifier")]
    InvalidIdentifier { label: &'static str },
    #[error("invalid {label} text")]
    InvalidText { label: &'static str },
    #[error("invalid {label} revision")]
    InvalidRevision { label: &'static str },
    #[error("{label} exceeds maximum {maximum}")]
    BoundExceeded { label: &'static str, maximum: usize },
    #[error("invalid Amplitude API host")]
    InvalidApiHost,
    #[error("invalid exposure window")]
    InvalidExposureWindow,
    #[error("invalid permission snapshot")]
    InvalidPermissionSnapshot,
    #[error("invalid capability")]
    InvalidCapability,
    #[error("invalid confidence metadata")]
    InvalidConfidenceMetadata,
    #[error("invalid digest for {label}")]
    InvalidDigest { label: &'static str },
    #[error("invalid experiment scope: {0}")]
    InvalidScope(&'static str),
    #[error("invalid provider response: {0}")]
    InvalidProviderResponse(&'static str),
    #[error("malformed provider response")]
    MalformedResponse,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration binding drifted")]
    RegistrationDrift,
    #[error("registration is not revocable")]
    RegistrationNotRevocable,
    #[error("registration is not reversible")]
    RegistrationNotReversible,
    #[error("read consent was denied or stale")]
    ConsentDenied,
    #[error("Mission revision is stale")]
    StaleMission,
    #[error("Work Product revision is stale")]
    StaleWorkProduct,
    #[error("evidence does not match proposal")]
    EvidenceMismatch,
    #[error("transport error: {0}")]
    Transport(AmplitudeTransportError),
}
