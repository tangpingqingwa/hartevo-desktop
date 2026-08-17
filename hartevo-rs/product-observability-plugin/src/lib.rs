//! Layer 1 PostHog product-outcome evidence plugin.
//!
//! This crate is intentionally standalone until the Integration Manager wires
//! it into Hartevo's composition kernel. It contributes a typed service,
//! provider, and Mission Outcome consumer; it does not own Store, keyring,
//! Browser Profile, Effect, or UI authority. The provider only reads bounded
//! PostHog Query API observations and never accepts model-authored HogQL.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration as StdDuration, Instant},
};

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use reqwest::{Client, StatusCode, header};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use url::Url;

pub use serde_json::Value as JsonValue;

pub const PRODUCT_OBSERVABILITY_SCHEMA_VERSION: &str = "hartevo.product-observability/v1";
pub const PRODUCT_OBSERVABILITY_CONTRACT_PATH: &str =
    "contracts/plugins/product-observability/product-observability.v1.json";
pub const PRODUCT_OBSERVABILITY_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/product-observability/product-observability.v1.json");

pub const PRODUCT_OUTCOME_EVIDENCE_SERVICE_ID: &str = "product.outcome-evidence.read";
pub const POSTHOG_OUTCOME_PROVIDER_ID: &str = "product.observability.posthog";
pub const MISSION_OUTCOME_EVIDENCE_CONSUMER_ID: &str = "mission.outcome-evidence.consumer";
pub const POSTHOG_PROVIDER_IMPLEMENTATION: &str = "PostHogOutcomeProvider";

pub const MAX_QUERY_WINDOW_SECONDS: i64 = 86_400;
pub const MAX_PAGE_SIZE: u32 = 500;
pub const MAX_PAGES: u16 = 100;
pub const MAX_ROWS: u64 = 100_000;
pub const MAX_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_COST_UNITS: u64 = 10_000;
pub const MAX_POLLS: u16 = 20;
pub const MAX_POLL_SECONDS: u64 = 60;
pub const MAX_POLL_INTERVAL_MILLIS: u64 = 5_000;
pub const POSTHOG_QUERY_PATH_PREFIX: &str = "/api/projects/";

pub type Digest = String;

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("product observability values serialize");
    sha256_digest(&bytes)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_identifier(value: &str, label: &'static str) -> Result<(), ProductObservabilityError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(ProductObservabilityError::InvalidIdentifier { label });
    }
    Ok(())
}

fn validate_time_window(
    from: DateTime<Utc>,
    until: DateTime<Utc>,
) -> Result<(), ProductObservabilityError> {
    let duration = until.signed_duration_since(from);
    if duration <= Duration::zero() || duration > Duration::seconds(MAX_QUERY_WINDOW_SECONDS) {
        return Err(ProductObservabilityError::InvalidQueryWindow);
    }
    Ok(())
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProductObservabilityError {
    #[error("{label} is empty, invalid, or too long")]
    InvalidIdentifier { label: &'static str },
    #[error("{label} is not a lowercase SHA-256 digest")]
    InvalidDigest { label: &'static str },
    #[error("product observability scope is invalid")]
    InvalidScope,
    #[error("product observability definition is invalid")]
    InvalidDefinition,
    #[error("query window must be positive and no longer than one day")]
    InvalidQueryWindow,
    #[error("query budget is invalid")]
    InvalidBudget,
    #[error("keyset pagination bounds are invalid")]
    InvalidPagination,
    #[error("poll bounds are invalid")]
    InvalidPollPolicy,
    #[error("query template is not allowlisted")]
    UnallowlistedTemplate,
    #[error("query template does not match its exact Mission Outcome binding")]
    TemplateBindingMismatch,
}

// -------------------------------------------------------------------------
// Typed service/provider/consumer registration
// -------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    ReadOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductOutcomeEvidenceServiceDefinition {
    pub id: String,
    pub version: PluginVersion,
    pub access: AccessMode,
    pub contract_digest: Digest,
    pub authority: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PostHogProviderDefinition {
    pub id: String,
    pub service_id: String,
    pub version: PluginVersion,
    pub implementation: String,
    pub scope: Vec<String>,
    pub reversible: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionOutcomeEvidenceConsumerDefinition {
    pub id: String,
    pub service_id: String,
    pub version: PluginVersion,
    pub kind: String,
    pub exact_binding_fields: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductObservabilityPluginDefinition {
    pub schema_version: String,
    pub plugin_id: String,
    pub version: PluginVersion,
    pub contract_digest: Digest,
    pub service: ProductOutcomeEvidenceServiceDefinition,
    pub provider: PostHogProviderDefinition,
    pub consumer: MissionOutcomeEvidenceConsumerDefinition,
    pub reversible: bool,
    pub authorities: BTreeSet<String>,
}

impl ProductObservabilityPluginDefinition {
    pub fn layer1() -> Result<Self, ProductObservabilityError> {
        let contract_digest = sha256_digest(PRODUCT_OBSERVABILITY_CONTRACT_JSON.as_bytes());
        let definition = Self {
            schema_version: PRODUCT_OBSERVABILITY_SCHEMA_VERSION.into(),
            plugin_id: "product-observability.posthog".into(),
            version: PluginVersion::V1,
            contract_digest: contract_digest.clone(),
            service: ProductOutcomeEvidenceServiceDefinition {
                id: PRODUCT_OUTCOME_EVIDENCE_SERVICE_ID.into(),
                version: PluginVersion::V1,
                access: AccessMode::ReadOnly,
                contract_digest,
                authority: "read_only_observational_evidence".into(),
            },
            provider: PostHogProviderDefinition {
                id: POSTHOG_OUTCOME_PROVIDER_ID.into(),
                service_id: PRODUCT_OUTCOME_EVIDENCE_SERVICE_ID.into(),
                version: PluginVersion::V1,
                implementation: POSTHOG_PROVIDER_IMPLEMENTATION.into(),
                scope: vec![
                    "project".into(),
                    "mission".into(),
                    "provider_project".into(),
                ],
                reversible: true,
            },
            consumer: MissionOutcomeEvidenceConsumerDefinition {
                id: MISSION_OUTCOME_EVIDENCE_CONSUMER_ID.into(),
                service_id: PRODUCT_OUTCOME_EVIDENCE_SERVICE_ID.into(),
                version: PluginVersion::V1,
                kind: "mission_outcome".into(),
                exact_binding_fields: vec![
                    "mission_id".into(),
                    "mission_revision".into(),
                    "result_id".into(),
                    "result_revision".into(),
                    "deployment_id".into(),
                    "deployment_revision".into(),
                    "release_id".into(),
                    "release_revision".into(),
                ],
            },
            reversible: true,
            authorities: BTreeSet::from(["read_only_observational_evidence".into()]),
        };
        definition.validate()?;
        Ok(definition)
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    fn validate(&self) -> Result<(), ProductObservabilityError> {
        if self.schema_version != PRODUCT_OBSERVABILITY_SCHEMA_VERSION
            || self.plugin_id != "product-observability.posthog"
            || self.version != PluginVersion::V1
            || !is_sha256(&self.contract_digest)
            || self.service.id != PRODUCT_OUTCOME_EVIDENCE_SERVICE_ID
            || self.service.contract_digest != self.contract_digest
            || self.provider.id != POSTHOG_OUTCOME_PROVIDER_ID
            || self.provider.service_id != self.service.id
            || self.consumer.id != MISSION_OUTCOME_EVIDENCE_CONSUMER_ID
            || self.consumer.service_id != self.service.id
            || !self.reversible
            || self.authorities.len() != 1
        {
            return Err(ProductObservabilityError::InvalidDefinition);
        }
        Ok(())
    }

    pub fn bind(
        &self,
        scope: ProductObservabilityScope,
        generation: u64,
    ) -> Result<RegistrationReceipt, ProductObservabilityError> {
        if generation == 0 {
            return Err(ProductObservabilityError::InvalidScope);
        }
        Ok(RegistrationReceipt {
            schema_version: "hartevo.product-observability-registration/v1".into(),
            plugin_id: self.plugin_id.clone(),
            plugin_digest: self.digest(),
            scope,
            generation,
            status: RegistrationStatus::Active,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductObservabilityScope {
    pub tenant_id: String,
    pub project_id: String,
    pub mission_id: String,
    pub provider_project_id: String,
}

impl ProductObservabilityScope {
    pub fn new(
        tenant_id: impl Into<String>,
        project_id: impl Into<String>,
        mission_id: impl Into<String>,
        provider_project_id: impl Into<String>,
    ) -> Result<Self, ProductObservabilityError> {
        let scope = Self {
            tenant_id: tenant_id.into(),
            project_id: project_id.into(),
            mission_id: mission_id.into(),
            provider_project_id: provider_project_id.into(),
        };
        for (value, label) in [
            (&scope.tenant_id, "tenant_id"),
            (&scope.project_id, "project_id"),
            (&scope.mission_id, "mission_id"),
            (&scope.provider_project_id, "provider_project_id"),
        ] {
            validate_identifier(value, label)?;
        }
        Ok(scope)
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    fn validate(&self) -> Result<(), ProductObservabilityError> {
        for (value, label) in [
            (&self.tenant_id, "tenant_id"),
            (&self.project_id, "project_id"),
            (&self.mission_id, "mission_id"),
            (&self.provider_project_id, "provider_project_id"),
        ] {
            validate_identifier(value, label)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationReceipt {
    pub schema_version: String,
    pub plugin_id: String,
    pub plugin_digest: Digest,
    pub scope: ProductObservabilityScope,
    pub generation: u64,
    pub status: RegistrationStatus,
}

impl RegistrationReceipt {
    pub fn revoke(&self) -> RevocationReceipt {
        RevocationReceipt {
            registration_digest: canonical_digest(self),
            plugin_digest: self.plugin_digest.clone(),
            scope_digest: self.scope.digest(),
            generation: self.generation,
            status: RegistrationStatus::Revoked,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationReceipt {
    pub registration_digest: Digest,
    pub plugin_digest: Digest,
    pub scope_digest: Digest,
    pub generation: u64,
    pub status: RegistrationStatus,
}

// -------------------------------------------------------------------------
// Exact Mission / result / deployment / release binding
// -------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionOutcomeBinding {
    pub mission_id: String,
    pub mission_revision: u64,
    pub result_id: String,
    pub result_revision: u64,
    pub deployment_id: String,
    pub deployment_revision: u64,
    pub release_id: String,
    pub release_revision: u64,
}

impl MissionOutcomeBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mission_id: impl Into<String>,
        mission_revision: u64,
        result_id: impl Into<String>,
        result_revision: u64,
        deployment_id: impl Into<String>,
        deployment_revision: u64,
        release_id: impl Into<String>,
        release_revision: u64,
    ) -> Result<Self, ProductObservabilityError> {
        let binding = Self {
            mission_id: mission_id.into(),
            mission_revision,
            result_id: result_id.into(),
            result_revision,
            deployment_id: deployment_id.into(),
            deployment_revision,
            release_id: release_id.into(),
            release_revision,
        };
        for (value, label) in [
            (&binding.mission_id, "mission_id"),
            (&binding.result_id, "result_id"),
            (&binding.deployment_id, "deployment_id"),
            (&binding.release_id, "release_id"),
        ] {
            validate_identifier(value, label)?;
        }
        if binding.mission_revision == 0
            || binding.result_revision == 0
            || binding.deployment_revision == 0
            || binding.release_revision == 0
        {
            return Err(ProductObservabilityError::InvalidScope);
        }
        Ok(binding)
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn result_digest(&self) -> Digest {
        sha256_digest(self.result_id.as_bytes())
    }

    pub fn deployment_digest(&self) -> Digest {
        sha256_digest(self.deployment_id.as_bytes())
    }

    pub fn release_digest(&self) -> Digest {
        sha256_digest(self.release_id.as_bytes())
    }

    fn validate(&self) -> Result<(), ProductObservabilityError> {
        for (value, label) in [
            (&self.mission_id, "mission_id"),
            (&self.result_id, "result_id"),
            (&self.deployment_id, "deployment_id"),
            (&self.release_id, "release_id"),
        ] {
            validate_identifier(value, label)?;
        }
        if self.mission_revision == 0
            || self.result_revision == 0
            || self.deployment_revision == 0
            || self.release_revision == 0
        {
            return Err(ProductObservabilityError::InvalidScope);
        }
        Ok(())
    }
}

// -------------------------------------------------------------------------
// Bounded, allowlisted HogQL query model
// -------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryWindow {
    pub from: DateTime<Utc>,
    pub until: DateTime<Utc>,
}

impl QueryWindow {
    pub fn new(
        from: DateTime<Utc>,
        until: DateTime<Utc>,
    ) -> Result<Self, ProductObservabilityError> {
        validate_time_window(from, until)?;
        Ok(Self { from, until })
    }

    fn validate(&self) -> Result<(), ProductObservabilityError> {
        validate_time_window(self.from, self.until)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryBudget {
    pub max_rows: u64,
    pub max_bytes: u64,
    pub max_cost_units: u64,
}

impl QueryBudget {
    pub fn new(
        max_rows: u64,
        max_bytes: u64,
        max_cost_units: u64,
    ) -> Result<Self, ProductObservabilityError> {
        let budget = Self {
            max_rows,
            max_bytes,
            max_cost_units,
        };
        if max_rows == 0
            || max_rows > MAX_ROWS
            || max_bytes == 0
            || max_bytes > MAX_BYTES
            || max_cost_units == 0
            || max_cost_units > MAX_COST_UNITS
        {
            return Err(ProductObservabilityError::InvalidBudget);
        }
        Ok(budget)
    }

    pub const fn default_bounded() -> Self {
        Self {
            max_rows: 10_000,
            max_bytes: 4 * 1024 * 1024,
            max_cost_units: 1_000,
        }
    }

    fn validate(&self) -> Result<(), ProductObservabilityError> {
        if self.max_rows == 0
            || self.max_rows > MAX_ROWS
            || self.max_bytes == 0
            || self.max_bytes > MAX_BYTES
            || self.max_cost_units == 0
            || self.max_cost_units > MAX_COST_UNITS
        {
            return Err(ProductObservabilityError::InvalidBudget);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeysetPagination {
    pub page_size: u32,
    pub max_pages: u16,
}

impl KeysetPagination {
    pub fn new(page_size: u32, max_pages: u16) -> Result<Self, ProductObservabilityError> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE || max_pages == 0 || max_pages > MAX_PAGES {
            return Err(ProductObservabilityError::InvalidPagination);
        }
        Ok(Self {
            page_size,
            max_pages,
        })
    }

    fn validate(&self) -> Result<(), ProductObservabilityError> {
        if self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
        {
            return Err(ProductObservabilityError::InvalidPagination);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PollPolicy {
    pub max_polls: u16,
    pub max_elapsed_seconds: u64,
    pub interval_millis: u64,
}

impl PollPolicy {
    pub fn new(
        max_polls: u16,
        max_elapsed_seconds: u64,
        interval_millis: u64,
    ) -> Result<Self, ProductObservabilityError> {
        if max_polls == 0
            || max_polls > MAX_POLLS
            || max_elapsed_seconds == 0
            || max_elapsed_seconds > MAX_POLL_SECONDS
            || interval_millis > MAX_POLL_INTERVAL_MILLIS
        {
            return Err(ProductObservabilityError::InvalidPollPolicy);
        }
        Ok(Self {
            max_polls,
            max_elapsed_seconds,
            interval_millis,
        })
    }

    pub const fn immediate() -> Self {
        Self {
            max_polls: 4,
            max_elapsed_seconds: 5,
            interval_millis: 0,
        }
    }

    fn validate(&self) -> Result<(), ProductObservabilityError> {
        if self.max_polls == 0
            || self.max_polls > MAX_POLLS
            || self.max_elapsed_seconds == 0
            || self.max_elapsed_seconds > MAX_POLL_SECONDS
            || self.interval_millis > MAX_POLL_INTERVAL_MILLIS
        {
            return Err(ProductObservabilityError::InvalidPollPolicy);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PostHogQueryTemplateId {
    OutcomeByResult,
    ReliabilityByRelease,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind", deny_unknown_fields)]
pub enum PostHogQueryTemplate {
    OutcomeByResult {
        result_digest: Digest,
        deployment_digest: Digest,
        release_digest: Digest,
    },
    ReliabilityByRelease {
        deployment_digest: Digest,
        release_digest: Digest,
    },
}

impl PostHogQueryTemplate {
    pub fn outcome_by_result(binding: &MissionOutcomeBinding) -> Self {
        Self::OutcomeByResult {
            result_digest: binding.result_digest(),
            deployment_digest: binding.deployment_digest(),
            release_digest: binding.release_digest(),
        }
    }

    pub fn reliability_by_release(binding: &MissionOutcomeBinding) -> Self {
        Self::ReliabilityByRelease {
            deployment_digest: binding.deployment_digest(),
            release_digest: binding.release_digest(),
        }
    }

    pub const fn id(&self) -> PostHogQueryTemplateId {
        match self {
            Self::OutcomeByResult { .. } => PostHogQueryTemplateId::OutcomeByResult,
            Self::ReliabilityByRelease { .. } => PostHogQueryTemplateId::ReliabilityByRelease,
        }
    }

    fn validate(&self) -> Result<(), ProductObservabilityError> {
        let digests = match self {
            Self::OutcomeByResult {
                result_digest,
                deployment_digest,
                release_digest,
            } => vec![result_digest, deployment_digest, release_digest],
            Self::ReliabilityByRelease {
                deployment_digest,
                release_digest,
            } => vec![deployment_digest, release_digest],
        };
        if digests.iter().all(|digest| is_sha256(digest)) {
            Ok(())
        } else {
            Err(ProductObservabilityError::UnallowlistedTemplate)
        }
    }

    fn matches_binding(&self, binding: &MissionOutcomeBinding) -> bool {
        match self {
            Self::OutcomeByResult {
                result_digest,
                deployment_digest,
                release_digest,
            } => {
                result_digest == &binding.result_digest()
                    && deployment_digest == &binding.deployment_digest()
                    && release_digest == &binding.release_digest()
            }
            Self::ReliabilityByRelease {
                deployment_digest,
                release_digest,
            } => {
                deployment_digest == &binding.deployment_digest()
                    && release_digest == &binding.release_digest()
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeysetCursor {
    pub observed_at: DateTime<Utc>,
    pub event_id: String,
}

impl KeysetCursor {
    pub fn new(
        observed_at: DateTime<Utc>,
        event_id: impl Into<String>,
    ) -> Result<Self, ProductObservabilityError> {
        let event_id = event_id.into();
        validate_identifier(&event_id, "event_id")?;
        Ok(Self {
            observed_at,
            event_id,
        })
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PostHogQueryRequest {
    pub scope: ProductObservabilityScope,
    pub binding: MissionOutcomeBinding,
    pub template: PostHogQueryTemplate,
    pub window: QueryWindow,
    pub budget: QueryBudget,
    pub pagination: KeysetPagination,
    pub poll: PollPolicy,
    pub observed_at: DateTime<Utc>,
}

impl PostHogQueryRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: ProductObservabilityScope,
        binding: MissionOutcomeBinding,
        template: PostHogQueryTemplate,
        window: QueryWindow,
        budget: QueryBudget,
        pagination: KeysetPagination,
        poll: PollPolicy,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ProductObservabilityError> {
        scope.validate()?;
        binding.validate()?;
        window.validate()?;
        budget.validate()?;
        pagination.validate()?;
        poll.validate()?;
        template.validate()?;
        if scope.mission_id != binding.mission_id || !template.matches_binding(&binding) {
            return Err(ProductObservabilityError::TemplateBindingMismatch);
        }
        Ok(Self {
            scope,
            binding,
            template,
            window,
            budget,
            pagination,
            poll,
            observed_at,
        })
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn compile(
        &self,
        cursor: Option<KeysetCursor>,
    ) -> Result<CompiledQuery, ProductObservabilityError> {
        self.scope.validate()?;
        self.binding.validate()?;
        self.window.validate()?;
        self.budget.validate()?;
        self.pagination.validate()?;
        self.poll.validate()?;
        self.template.validate()?;
        if self.scope.mission_id != self.binding.mission_id
            || !self.template.matches_binding(&self.binding)
        {
            return Err(ProductObservabilityError::TemplateBindingMismatch);
        }
        if let Some(cursor) = cursor.as_ref() {
            validate_identifier(&cursor.event_id, "event_id")?;
        }
        let page_size = self.pagination.page_size;
        let from = hogql_literal(&self.window.from.to_rfc3339());
        let until = hogql_literal(&self.window.until.to_rfc3339());
        let cursor_predicate = cursor.as_ref().map_or_else(
            || "1 = 1".to_owned(),
            |cursor| {
                format!(
                    "(timestamp > toDateTime({}) OR (timestamp = toDateTime({}) AND uuid > {}))",
                    hogql_literal(&cursor.observed_at.to_rfc3339()),
                    hogql_literal(&cursor.observed_at.to_rfc3339()),
                    hogql_literal(&cursor.event_id),
                )
            },
        );
        let query = match &self.template {
            PostHogQueryTemplate::OutcomeByResult {
                result_digest,
                deployment_digest,
                release_digest,
            } => format!(
                "SELECT timestamp, uuid, event, properties.result_digest, properties.deployment_digest, properties.release_digest, properties.outcome_kind FROM events WHERE timestamp >= toDateTime({from}) AND timestamp < toDateTime({until}) AND properties.result_digest = {result} AND properties.deployment_digest = {deployment} AND properties.release_digest = {release} AND event IN ('hartevo.result.delivered', 'hartevo.result.adopted', 'hartevo.result.rejected', 'hartevo.deployment.observed', 'hartevo.outcome.observed') AND {cursor_predicate} ORDER BY timestamp ASC, uuid ASC LIMIT {page_size}",
                from = from,
                until = until,
                result = hogql_literal(result_digest),
                deployment = hogql_literal(deployment_digest),
                release = hogql_literal(release_digest),
            ),
            PostHogQueryTemplate::ReliabilityByRelease {
                deployment_digest,
                release_digest,
            } => format!(
                "SELECT timestamp, uuid, event, properties.deployment_digest, properties.release_digest, properties.error_kind FROM events WHERE timestamp >= toDateTime({from}) AND timestamp < toDateTime({until}) AND properties.deployment_digest = {deployment} AND properties.release_digest = {release} AND event IN ('hartevo.deployment.failed', 'hartevo.error.observed', 'hartevo.deployment.observed') AND {cursor_predicate} ORDER BY timestamp ASC, uuid ASC LIMIT {page_size}",
                from = from,
                until = until,
                deployment = hogql_literal(deployment_digest),
                release = hogql_literal(release_digest),
            ),
        };
        let mut parameters = BTreeMap::from([
            ("from".into(), self.window.from.to_rfc3339()),
            ("until".into(), self.window.until.to_rfc3339()),
            ("page_size".into(), page_size.to_string()),
            ("template".into(), format!("{:?}", self.template.id())),
            (
                "cursor".into(),
                cursor
                    .as_ref()
                    .map_or_else(String::new, KeysetCursor::digest),
            ),
        ]);
        match &self.template {
            PostHogQueryTemplate::OutcomeByResult {
                result_digest,
                deployment_digest,
                release_digest,
            } => {
                parameters.insert("result_digest".into(), result_digest.clone());
                parameters.insert("deployment_digest".into(), deployment_digest.clone());
                parameters.insert("release_digest".into(), release_digest.clone());
            }
            PostHogQueryTemplate::ReliabilityByRelease {
                deployment_digest,
                release_digest,
            } => {
                parameters.insert("deployment_digest".into(), deployment_digest.clone());
                parameters.insert("release_digest".into(), release_digest.clone());
            }
        }
        if query.contains("OFFSET") {
            return Err(ProductObservabilityError::UnallowlistedTemplate);
        }
        let query_digest = canonical_digest(&(&self.digest(), &query, &parameters));
        Ok(CompiledQuery {
            template: self.template.id(),
            query,
            parameters,
            query_digest,
            request_digest: self.digest(),
            binding_digest: self.binding.digest(),
            cursor,
            page_size,
        })
    }
}

fn hogql_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompiledQuery {
    pub template: PostHogQueryTemplateId,
    pub query: String,
    pub parameters: BTreeMap<String, String>,
    pub query_digest: Digest,
    pub request_digest: Digest,
    pub binding_digest: Digest,
    pub cursor: Option<KeysetCursor>,
    pub page_size: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PostHogQueryEnvelope {
    pub query: PostHogQueryEnvelopeBody,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PostHogQueryEnvelopeBody {
    pub kind: String,
    pub query: String,
}

impl From<&CompiledQuery> for PostHogQueryEnvelope {
    fn from(query: &CompiledQuery) -> Self {
        Self {
            query: PostHogQueryEnvelopeBody {
                kind: "HogQLQuery".into(),
                query: query.query.clone(),
            },
        }
    }
}

// -------------------------------------------------------------------------
// Provider transport and receipts
// -------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    ProductionHttps,
    ControlledLoopback,
    Fixture,
    BlockedEnv,
}

impl Provenance {
    pub const fn is_native(self) -> bool {
        matches!(self, Self::ProductionHttps)
    }

    pub const fn is_connected(self) -> bool {
        self.is_native()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Reachable,
    BlockedEnv,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProbeReceipt {
    pub provider_id: String,
    pub scope_digest: Digest,
    pub provenance: Provenance,
    pub status: ProbeStatus,
    pub connected: bool,
    pub native: bool,
    pub observed_at: DateTime<Utc>,
    pub evidence_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryState {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransportSubmission {
    pub query_id: String,
    pub submitted_at: DateTime<Utc>,
    pub response_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PostHogRowPage {
    pub rows: Vec<BTreeMap<String, Value>>,
    pub next_cursor: Option<KeysetCursor>,
    pub bytes_read: u64,
    pub cost_units: u64,
    pub declared_digest: Digest,
}

impl PostHogRowPage {
    pub fn new(
        rows: Vec<BTreeMap<String, Value>>,
        next_cursor: Option<KeysetCursor>,
        bytes_read: u64,
        cost_units: u64,
    ) -> Self {
        let canonical = Self::canonical_digest(&rows, next_cursor.as_ref(), bytes_read, cost_units);
        Self {
            rows,
            next_cursor,
            bytes_read,
            cost_units,
            declared_digest: canonical,
        }
    }

    #[must_use]
    pub fn with_declared_digest(mut self, declared_digest: impl Into<String>) -> Self {
        self.declared_digest = declared_digest.into();
        self
    }

    fn canonical_digest(
        rows: &[BTreeMap<String, Value>],
        next_cursor: Option<&KeysetCursor>,
        bytes_read: u64,
        cost_units: u64,
    ) -> Digest {
        canonical_digest(&(rows, next_cursor, bytes_read, cost_units))
    }

    pub fn verify(&self) -> Result<(), PostHogProviderError> {
        let expected = Self::canonical_digest(
            &self.rows,
            self.next_cursor.as_ref(),
            self.bytes_read,
            self.cost_units,
        );
        if expected == self.declared_digest {
            Ok(())
        } else {
            Err(PostHogProviderError::ResponseTampered {
                expected,
                actual: self.declared_digest.clone(),
            })
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransportPoll {
    pub query_id: String,
    pub state: QueryState,
    pub page: Option<PostHogRowPage>,
    pub response_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransportQueryLog {
    pub query_id: String,
    pub rows_read: u64,
    pub bytes_read: u64,
    pub cost_units: u64,
    pub log_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransportCancellation {
    pub query_id: String,
    pub cancelled_at: DateTime<Utc>,
    pub receipt_digest: Digest,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PostHogTransportError {
    #[error("PostHog native access is blocked by environment policy")]
    BlockedEnv,
    #[error("PostHog credential is unavailable")]
    MissingCredential,
    #[error("PostHog token was revoked or rejected")]
    TokenRevoked,
    #[error("PostHog request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("PostHog query exceeded provider limits")]
    QueryLimitExceeded,
    #[error("PostHog response was malformed")]
    MalformedResponse,
    #[error("PostHog query was not found")]
    QueryNotFound,
    #[error("PostHog HTTP status {status}")]
    HttpStatus {
        status: u16,
        response_digest: Digest,
    },
    #[error("PostHog transport request failed: {0}")]
    Request(String),
    #[error("PostHog transport response could not be decoded: {0}")]
    Decode(String),
}

#[async_trait]
pub trait PostHogTransport: fmt::Debug + Send + Sync {
    fn provenance(&self) -> Provenance;

    async fn probe(
        &self,
        scope: &ProductObservabilityScope,
        at: DateTime<Utc>,
    ) -> Result<ProbeStatus, PostHogTransportError>;

    async fn submit(
        &self,
        query: &CompiledQuery,
    ) -> Result<TransportSubmission, PostHogTransportError>;

    async fn poll(&self, query_id: &str) -> Result<TransportPoll, PostHogTransportError>;

    async fn query_log(&self, query_id: &str) -> Result<TransportQueryLog, PostHogTransportError>;

    async fn cancel(&self, query_id: &str) -> Result<TransportCancellation, PostHogTransportError>;
}

#[derive(Clone, Debug)]
pub struct PostHogQueryHandle {
    pub query_id: String,
    pub request_digest: Digest,
    pub query_digest: Digest,
    pub binding_digest: Digest,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PostHogProviderError {
    #[error("provider transport error: {0}")]
    Transport(#[from] PostHogTransportError),
    #[error("invalid provider request: {0}")]
    InvalidRequest(#[from] ProductObservabilityError),
    #[error("a successful PostHog authenticated probe is required before production reads")]
    ProbeRequired,
    #[error("provider polling exceeded its bound")]
    PollLimitExceeded,
    #[error("provider polling exceeded its time bound")]
    PollTimeout,
    #[error("query returned no terminal page")]
    MissingPage,
    #[error("query returned an invalid keyset cursor")]
    InvalidCursor,
    #[error("query returned a tampered response; expected {expected}, got {actual}")]
    ResponseTampered { expected: Digest, actual: Digest },
    #[error("query-log receipt was missing or inconsistent")]
    InvalidQueryLog,
    #[error("row budget exceeded")]
    RowBudgetExceeded,
    #[error("byte budget exceeded")]
    ByteBudgetExceeded,
    #[error("cost budget exceeded")]
    CostBudgetExceeded,
    #[error("page budget exceeded")]
    PageBudgetExceeded,
    #[error("query was cancelled")]
    Cancelled,
    #[error("query failed: {0}")]
    QueryFailed(String),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryReceiptStatus {
    Completed,
    Cancelled,
    BudgetExceeded,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryPageReceipt {
    pub page_number: u16,
    pub query_id: String,
    pub query_digest: Digest,
    pub response_digest: Digest,
    pub row_count: u64,
    pub bytes_read: u64,
    pub cost_units: u64,
    pub next_cursor_digest: Option<Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryReceipt {
    pub schema_version: String,
    pub provider_id: String,
    pub provenance: Provenance,
    pub scope_digest: Digest,
    pub binding_digest: Digest,
    pub request_digest: Digest,
    pub template: PostHogQueryTemplateId,
    pub observed_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub status: QueryReceiptStatus,
    pub pages: Vec<QueryPageReceipt>,
    pub rows_read: u64,
    pub bytes_read: u64,
    pub cost_units: u64,
    pub query_log_digest: Digest,
    pub result_digest: Digest,
    pub cancellation_digest: Option<Digest>,
}

impl QueryReceipt {
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PostHogQueryResult {
    pub rows: Vec<BTreeMap<String, Value>>,
    pub result_digest: Digest,
    pub receipt_digest: Digest,
    pub provenance: Provenance,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryExecution {
    pub result: Option<PostHogQueryResult>,
    pub receipt: QueryReceipt,
}

impl QueryExecution {
    pub const fn is_completed(&self) -> bool {
        matches!(self.receipt.status, QueryReceiptStatus::Completed)
    }
}

#[derive(Clone, Debug, Default)]
pub struct QueryCancellationToken(Arc<AtomicBool>);

impl QueryCancellationToken {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
pub struct PostHogOutcomeProvider<T> {
    transport: T,
    production_probe_ok: AtomicBool,
}

impl<T> PostHogOutcomeProvider<T>
where
    T: PostHogTransport,
{
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            production_probe_ok: AtomicBool::new(false),
        }
    }

    pub fn provenance(&self) -> Provenance {
        self.transport.provenance()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub async fn probe(
        &self,
        scope: &ProductObservabilityScope,
        at: DateTime<Utc>,
    ) -> Result<ProbeReceipt, PostHogProviderError> {
        let status = self.transport.probe(scope, at).await?;
        let provenance = self.transport.provenance();
        let connected = matches!(status, ProbeStatus::Reachable) && provenance.is_connected();
        self.production_probe_ok.store(connected, Ordering::Release);
        Ok(ProbeReceipt {
            provider_id: POSTHOG_OUTCOME_PROVIDER_ID.into(),
            scope_digest: scope.digest(),
            provenance,
            status: if connected {
                ProbeStatus::Reachable
            } else if provenance == Provenance::BlockedEnv {
                ProbeStatus::BlockedEnv
            } else {
                status
            },
            connected,
            native: connected && provenance.is_native(),
            observed_at: at,
            evidence_digest: canonical_digest(&(scope, provenance, connected, at)),
        })
    }

    pub async fn submit_query(
        &self,
        request: &PostHogQueryRequest,
        cursor: Option<KeysetCursor>,
    ) -> Result<PostHogQueryHandle, PostHogProviderError> {
        if self.provenance() == Provenance::ProductionHttps
            && !self.production_probe_ok.load(Ordering::Acquire)
        {
            return Err(PostHogProviderError::ProbeRequired);
        }
        let compiled = request.compile(cursor)?;
        let submission = self.transport.submit(&compiled).await?;
        validate_identifier(&submission.query_id, "query_id").map_err(|_| {
            PostHogProviderError::Transport(PostHogTransportError::MalformedResponse)
        })?;
        Ok(PostHogQueryHandle {
            query_id: submission.query_id,
            request_digest: compiled.request_digest,
            query_digest: compiled.query_digest,
            binding_digest: compiled.binding_digest,
        })
    }

    pub async fn poll_query(
        &self,
        handle: &PostHogQueryHandle,
    ) -> Result<TransportPoll, PostHogProviderError> {
        let poll = self.transport.poll(&handle.query_id).await?;
        if poll.query_id != handle.query_id {
            return Err(PostHogProviderError::Transport(
                PostHogTransportError::MalformedResponse,
            ));
        }
        Ok(poll)
    }

    pub async fn query_log(
        &self,
        handle: &PostHogQueryHandle,
    ) -> Result<TransportQueryLog, PostHogProviderError> {
        let log = self.transport.query_log(&handle.query_id).await?;
        if log.query_id != handle.query_id {
            return Err(PostHogProviderError::InvalidQueryLog);
        }
        Ok(log)
    }

    pub async fn cancel_query(
        &self,
        handle: &PostHogQueryHandle,
    ) -> Result<TransportCancellation, PostHogProviderError> {
        let cancellation = self.transport.cancel(&handle.query_id).await?;
        if cancellation.query_id != handle.query_id {
            return Err(PostHogProviderError::Transport(
                PostHogTransportError::MalformedResponse,
            ));
        }
        Ok(cancellation)
    }

    #[allow(clippy::too_many_lines)]
    pub async fn execute(
        &self,
        request: &PostHogQueryRequest,
        cancellation: &QueryCancellationToken,
    ) -> Result<QueryExecution, PostHogProviderError> {
        if self.provenance() == Provenance::ProductionHttps
            && !self.production_probe_ok.load(Ordering::Acquire)
        {
            return Err(PostHogProviderError::ProbeRequired);
        }
        let started_at = request.observed_at;
        if cancellation.is_cancelled() {
            return Ok(self.empty_execution(request, QueryReceiptStatus::Cancelled, started_at));
        }

        let mut cursor = None;
        let mut previous_cursor = None;
        let mut rows = Vec::new();
        let mut page_receipts = Vec::new();
        let mut total_bytes = 0_u64;
        let mut total_cost = 0_u64;
        let mut query_log_digests = Vec::new();
        let started = Instant::now();

        for page_number in 1..=request.pagination.max_pages {
            if cancellation.is_cancelled() {
                return Ok(self.cancelled_execution(
                    request,
                    page_receipts,
                    rows,
                    total_bytes,
                    total_cost,
                    query_log_digests,
                    started_at,
                ));
            }
            if started.elapsed() > StdDuration::from_secs(request.poll.max_elapsed_seconds) {
                return Err(PostHogProviderError::PollTimeout);
            }
            let handle = self.submit_query(request, cursor.clone()).await?;
            let poll = self
                .poll_until_terminal(request, &handle, cancellation, &started)
                .await?;
            if poll.state == QueryState::Cancelled {
                return Ok(self.cancelled_execution(
                    request,
                    page_receipts,
                    rows,
                    total_bytes,
                    total_cost,
                    query_log_digests,
                    started_at,
                ));
            }
            if poll.state == QueryState::Failed {
                return Err(PostHogProviderError::QueryFailed(handle.query_id));
            }
            let page = poll.page.ok_or(PostHogProviderError::MissingPage)?;
            page.verify()?;
            let log = self.query_log(&handle).await?;
            if log.rows_read < page.rows.len() as u64
                || log.bytes_read < page.bytes_read
                || log.cost_units < page.cost_units
            {
                return Err(PostHogProviderError::InvalidQueryLog);
            }
            total_bytes = total_bytes
                .checked_add(log.bytes_read)
                .ok_or(PostHogProviderError::ByteBudgetExceeded)?;
            total_cost = total_cost
                .checked_add(log.cost_units)
                .ok_or(PostHogProviderError::CostBudgetExceeded)?;
            if total_bytes > request.budget.max_bytes || total_cost > request.budget.max_cost_units
            {
                let _ = self.cancel_query(&handle).await;
                return Ok(self.budget_execution(
                    request,
                    page_receipts,
                    rows,
                    total_bytes,
                    total_cost,
                    query_log_digests,
                    started_at,
                ));
            }
            rows.extend(page.rows.iter().cloned());
            if rows.len() as u64 > request.budget.max_rows {
                let _ = self.cancel_query(&handle).await;
                return Ok(self.budget_execution(
                    request,
                    page_receipts,
                    rows,
                    total_bytes,
                    total_cost,
                    query_log_digests,
                    started_at,
                ));
            }
            query_log_digests.push(log.log_digest.clone());
            page_receipts.push(QueryPageReceipt {
                page_number,
                query_id: handle.query_id,
                query_digest: handle.query_digest,
                response_digest: page.declared_digest.clone(),
                row_count: page.rows.len() as u64,
                bytes_read: log.bytes_read,
                cost_units: log.cost_units,
                next_cursor_digest: page.next_cursor.as_ref().map(KeysetCursor::digest),
            });
            let next = page.next_cursor;
            if let Some(next_cursor) = next {
                if previous_cursor
                    .as_ref()
                    .is_some_and(|previous| next_cursor <= *previous)
                {
                    return Err(PostHogProviderError::InvalidCursor);
                }
                if let Some(last_row) = page.rows.last() {
                    let last_cursor =
                        row_cursor(last_row).ok_or(PostHogProviderError::InvalidCursor)?;
                    if next_cursor < last_cursor {
                        return Err(PostHogProviderError::InvalidCursor);
                    }
                }
                previous_cursor = Some(next_cursor.clone());
                cursor = Some(next_cursor);
            } else {
                let result_digest = canonical_digest(&rows);
                let receipt = QueryReceipt {
                    schema_version: "hartevo.posthog-query-receipt/v1".into(),
                    provider_id: POSTHOG_OUTCOME_PROVIDER_ID.into(),
                    provenance: self.provenance(),
                    scope_digest: request.scope.digest(),
                    binding_digest: request.binding.digest(),
                    request_digest: request.digest(),
                    template: request.template.id(),
                    observed_at: started_at,
                    completed_at: Utc::now(),
                    status: QueryReceiptStatus::Completed,
                    pages: page_receipts,
                    rows_read: rows.len() as u64,
                    bytes_read: total_bytes,
                    cost_units: total_cost,
                    query_log_digest: canonical_digest(&query_log_digests),
                    result_digest: result_digest.clone(),
                    cancellation_digest: None,
                };
                let result = PostHogQueryResult {
                    rows,
                    result_digest,
                    receipt_digest: receipt.digest(),
                    provenance: self.provenance(),
                };
                return Ok(QueryExecution {
                    result: Some(result),
                    receipt,
                });
            }
        }
        Ok(self.budget_execution(
            request,
            page_receipts,
            rows,
            total_bytes,
            total_cost,
            query_log_digests,
            started_at,
        ))
    }

    async fn poll_until_terminal(
        &self,
        request: &PostHogQueryRequest,
        handle: &PostHogQueryHandle,
        cancellation: &QueryCancellationToken,
        started: &Instant,
    ) -> Result<TransportPoll, PostHogProviderError> {
        for poll_number in 0..request.poll.max_polls {
            if cancellation.is_cancelled() {
                let _ = self.cancel_query(handle).await?;
                return Ok(TransportPoll {
                    query_id: handle.query_id.clone(),
                    state: QueryState::Cancelled,
                    page: None,
                    response_digest: canonical_digest(&("cancelled", &handle.query_id)),
                });
            }
            if started.elapsed() > StdDuration::from_secs(request.poll.max_elapsed_seconds) {
                return Err(PostHogProviderError::PollTimeout);
            }
            let poll = self.poll_query(handle).await?;
            match poll.state {
                QueryState::Completed | QueryState::Failed | QueryState::Cancelled => {
                    return Ok(poll);
                }
                QueryState::Queued | QueryState::Running => {
                    if poll_number + 1 == request.poll.max_polls {
                        let _ = self.cancel_query(handle).await;
                        return Err(PostHogProviderError::PollLimitExceeded);
                    }
                    if request.poll.interval_millis > 0 {
                        tokio::time::sleep(StdDuration::from_millis(request.poll.interval_millis))
                            .await;
                    }
                }
            }
        }
        Err(PostHogProviderError::PollLimitExceeded)
    }

    fn empty_execution(
        &self,
        request: &PostHogQueryRequest,
        status: QueryReceiptStatus,
        at: DateTime<Utc>,
    ) -> QueryExecution {
        let receipt = QueryReceipt {
            schema_version: "hartevo.posthog-query-receipt/v1".into(),
            provider_id: POSTHOG_OUTCOME_PROVIDER_ID.into(),
            provenance: self.provenance(),
            scope_digest: request.scope.digest(),
            binding_digest: request.binding.digest(),
            request_digest: request.digest(),
            template: request.template.id(),
            observed_at: at,
            completed_at: at,
            status,
            pages: Vec::new(),
            rows_read: 0,
            bytes_read: 0,
            cost_units: 0,
            query_log_digest: canonical_digest(&[] as &[Digest]),
            result_digest: canonical_digest(&[] as &[BTreeMap<String, Value>]),
            cancellation_digest: None,
        };
        QueryExecution {
            result: None,
            receipt,
        }
    }

    #[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
    fn cancelled_execution(
        &self,
        request: &PostHogQueryRequest,
        pages: Vec<QueryPageReceipt>,
        rows: Vec<BTreeMap<String, Value>>,
        bytes: u64,
        cost: u64,
        logs: Vec<Digest>,
        at: DateTime<Utc>,
    ) -> QueryExecution {
        let cancellation_digest = canonical_digest(&("cancelled", request.digest()));
        let receipt = QueryReceipt {
            schema_version: "hartevo.posthog-query-receipt/v1".into(),
            provider_id: POSTHOG_OUTCOME_PROVIDER_ID.into(),
            provenance: self.provenance(),
            scope_digest: request.scope.digest(),
            binding_digest: request.binding.digest(),
            request_digest: request.digest(),
            template: request.template.id(),
            observed_at: at,
            completed_at: Utc::now(),
            status: QueryReceiptStatus::Cancelled,
            pages,
            rows_read: rows.len() as u64,
            bytes_read: bytes,
            cost_units: cost,
            query_log_digest: canonical_digest(&logs),
            result_digest: canonical_digest(&rows),
            cancellation_digest: Some(cancellation_digest),
        };
        QueryExecution {
            result: None,
            receipt,
        }
    }

    #[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
    fn budget_execution(
        &self,
        request: &PostHogQueryRequest,
        pages: Vec<QueryPageReceipt>,
        rows: Vec<BTreeMap<String, Value>>,
        bytes: u64,
        cost: u64,
        logs: Vec<Digest>,
        at: DateTime<Utc>,
    ) -> QueryExecution {
        let receipt = QueryReceipt {
            schema_version: "hartevo.posthog-query-receipt/v1".into(),
            provider_id: POSTHOG_OUTCOME_PROVIDER_ID.into(),
            provenance: self.provenance(),
            scope_digest: request.scope.digest(),
            binding_digest: request.binding.digest(),
            request_digest: request.digest(),
            template: request.template.id(),
            observed_at: at,
            completed_at: Utc::now(),
            status: QueryReceiptStatus::BudgetExceeded,
            pages,
            rows_read: rows.len() as u64,
            bytes_read: bytes,
            cost_units: cost,
            query_log_digest: canonical_digest(&logs),
            result_digest: canonical_digest(&rows),
            cancellation_digest: None,
        };
        QueryExecution {
            result: None,
            receipt,
        }
    }
}

fn row_cursor(row: &BTreeMap<String, Value>) -> Option<KeysetCursor> {
    let observed_at = row
        .get("timestamp")
        .or_else(|| row.get("observed_at"))
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))?;
    let event_id = row
        .get("uuid")
        .or_else(|| row.get("event_id"))
        .and_then(Value::as_str)?;
    KeysetCursor::new(observed_at, event_id).ok()
}

#[async_trait]
pub trait ProductOutcomeEvidenceService: Send + Sync {
    async fn read(
        &self,
        request: &PostHogQueryRequest,
        cancellation: &QueryCancellationToken,
    ) -> Result<QueryExecution, PostHogProviderError>;
}

#[async_trait]
impl<T> ProductOutcomeEvidenceService for PostHogOutcomeProvider<T>
where
    T: PostHogTransport,
{
    async fn read(
        &self,
        request: &PostHogQueryRequest,
        cancellation: &QueryCancellationToken,
    ) -> Result<QueryExecution, PostHogProviderError> {
        self.execute(request, cancellation).await
    }
}

// -------------------------------------------------------------------------
// Official HTTPS transport
// -------------------------------------------------------------------------

#[derive(Clone)]
pub struct PostHogApiKey(String);

impl fmt::Debug for PostHogApiKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PostHogApiKey(<redacted>)")
    }
}

impl PostHogApiKey {
    pub fn new(value: impl Into<String>) -> Result<Self, PostHogTransportError> {
        let value = value.into();
        if value.trim().is_empty() || value.len() > 512 {
            return Err(PostHogTransportError::MissingCredential);
        }
        Ok(Self(value))
    }
}

#[derive(Clone)]
pub struct PostHogHttpTransport {
    client: Client,
    base_url: Url,
    project_id: String,
    api_key: PostHogApiKey,
}

impl fmt::Debug for PostHogHttpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostHogHttpTransport")
            .field("base_url", &self.base_url)
            .field("project_id", &self.project_id)
            .field("api_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl PostHogHttpTransport {
    pub fn new(
        base_url: impl AsRef<str>,
        project_id: impl Into<String>,
        api_key: PostHogApiKey,
    ) -> Result<Self, PostHogTransportError> {
        let base_url = Url::parse(base_url.as_ref())
            .map_err(|error| PostHogTransportError::Request(error.to_string()))?;
        if base_url.scheme() != "https" || base_url.host_str().is_none() {
            return Err(PostHogTransportError::Request(
                "PostHog production transport requires an HTTPS base URL".into(),
            ));
        }
        let project_id = project_id.into();
        validate_identifier(&project_id, "provider_project_id")
            .map_err(|_| PostHogTransportError::Request("invalid project id".into()))?;
        let client = Client::builder()
            .user_agent("hartevo-product-observability/1")
            .build()
            .map_err(|error| PostHogTransportError::Request(error.to_string()))?;
        Ok(Self {
            client,
            base_url,
            project_id,
            api_key,
        })
    }

    pub fn from_env() -> Result<Self, PostHogTransportError> {
        if std::env::var("HARTEVO_ENABLE_NATIVE_POSTHOG")
            .ok()
            .as_deref()
            != Some("1")
        {
            return Err(PostHogTransportError::BlockedEnv);
        }
        let project_id = std::env::var("HARTEVO_POSTHOG_PROJECT_ID")
            .map_err(|_| PostHogTransportError::BlockedEnv)?;
        let api_key = std::env::var("HARTEVO_POSTHOG_API_KEY")
            .map_err(|_| PostHogTransportError::BlockedEnv)
            .and_then(PostHogApiKey::new)?;
        let base_url = std::env::var("HARTEVO_POSTHOG_BASE_URL")
            .unwrap_or_else(|_| "https://app.posthog.com".into());
        Self::new(base_url, project_id, api_key)
    }

    fn project_url(&self, suffix: &str) -> Result<Url, PostHogTransportError> {
        let path = format!("api/projects/{}/query/{}", self.project_id, suffix);
        self.base_url
            .join(&path)
            .map_err(|error| PostHogTransportError::Request(error.to_string()))
    }

    fn auth_request(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        request.header(header::AUTHORIZATION, format!("Bearer {}", self.api_key.0))
    }

    async fn decode_response(
        response: reqwest::Response,
    ) -> Result<(Vec<u8>, StatusCode), PostHogTransportError> {
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|error| PostHogTransportError::Request(error.to_string()))?;
        Ok((bytes.to_vec(), status))
    }

    fn map_status(status: StatusCode, body: &[u8]) -> PostHogTransportError {
        match status {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => PostHogTransportError::TokenRevoked,
            StatusCode::TOO_MANY_REQUESTS => PostHogTransportError::RateLimited {
                retry_after_seconds: None,
            },
            StatusCode::BAD_REQUEST | StatusCode::PAYLOAD_TOO_LARGE => {
                PostHogTransportError::QueryLimitExceeded
            }
            _ => PostHogTransportError::HttpStatus {
                status: status.as_u16(),
                response_digest: sha256_digest(body),
            },
        }
    }
}

#[async_trait]
impl PostHogTransport for PostHogHttpTransport {
    fn provenance(&self) -> Provenance {
        Provenance::ProductionHttps
    }

    async fn probe(
        &self,
        scope: &ProductObservabilityScope,
        _at: DateTime<Utc>,
    ) -> Result<ProbeStatus, PostHogTransportError> {
        if scope.provider_project_id != self.project_id {
            return Err(PostHogTransportError::TokenRevoked);
        }
        let url = self.project_url("check_auth_for_async/")?;
        let response = self
            .auth_request(self.client.post(url).json(&json!({
                "query": {
                    "kind": "HogQLQuery",
                    "query": "SELECT 1"
                }
            })))
            .send()
            .await
            .map_err(|error| PostHogTransportError::Request(error.to_string()))?;
        let (body, status) = Self::decode_response(response).await?;
        if !status.is_success() {
            return Err(Self::map_status(status, &body));
        }
        Ok(ProbeStatus::Reachable)
    }

    async fn submit(
        &self,
        query: &CompiledQuery,
    ) -> Result<TransportSubmission, PostHogTransportError> {
        let url = self.project_url("")?;
        let response = self
            .auth_request(
                self.client
                    .post(url)
                    .json(&PostHogQueryEnvelope::from(query)),
            )
            .send()
            .await
            .map_err(|error| PostHogTransportError::Request(error.to_string()))?;
        let (body, status) = Self::decode_response(response).await?;
        let response_digest = sha256_digest(&body);
        if !status.is_success() {
            return Err(Self::map_status(status, &body));
        }
        let value: Value = serde_json::from_slice(&body)
            .map_err(|error| PostHogTransportError::Decode(error.to_string()))?;
        let query_id = value
            .get("query_id")
            .or_else(|| value.get("id"))
            .and_then(Value::as_str)
            .ok_or(PostHogTransportError::MalformedResponse)?;
        Ok(TransportSubmission {
            query_id: query_id.into(),
            submitted_at: Utc::now(),
            response_digest,
        })
    }

    async fn poll(&self, query_id: &str) -> Result<TransportPoll, PostHogTransportError> {
        validate_identifier(query_id, "query_id")
            .map_err(|_| PostHogTransportError::QueryNotFound)?;
        let url = self.project_url(&format!("{query_id}/"))?;
        let response = self
            .auth_request(self.client.get(url))
            .send()
            .await
            .map_err(|error| PostHogTransportError::Request(error.to_string()))?;
        let (body, status) = Self::decode_response(response).await?;
        let response_digest = sha256_digest(&body);
        if !status.is_success() {
            return Err(Self::map_status(status, &body));
        }
        let value: Value = serde_json::from_slice(&body)
            .map_err(|error| PostHogTransportError::Decode(error.to_string()))?;
        let state = parse_query_state(&value)?;
        let page = if state == QueryState::Completed {
            Some(parse_page(&value)?)
        } else {
            None
        };
        Ok(TransportPoll {
            query_id: query_id.into(),
            state,
            page,
            response_digest,
        })
    }

    async fn query_log(&self, query_id: &str) -> Result<TransportQueryLog, PostHogTransportError> {
        validate_identifier(query_id, "query_id")
            .map_err(|_| PostHogTransportError::QueryNotFound)?;
        let url = self.project_url(&format!("{query_id}/log/"))?;
        let response = self
            .auth_request(self.client.get(url))
            .send()
            .await
            .map_err(|error| PostHogTransportError::Request(error.to_string()))?;
        let (body, status) = Self::decode_response(response).await?;
        if !status.is_success() {
            return Err(Self::map_status(status, &body));
        }
        let value: Value = serde_json::from_slice(&body)
            .map_err(|error| PostHogTransportError::Decode(error.to_string()))?;
        Ok(TransportQueryLog {
            query_id: query_id.into(),
            rows_read: number_field(&value, &["rows_read", "rowsRead", "rows"]),
            bytes_read: number_field(&value, &["bytes_read", "bytesRead", "bytes"]),
            cost_units: number_field(&value, &["cost_units", "costUnits", "cost"]),
            log_digest: sha256_digest(&body),
        })
    }

    async fn cancel(&self, query_id: &str) -> Result<TransportCancellation, PostHogTransportError> {
        validate_identifier(query_id, "query_id")
            .map_err(|_| PostHogTransportError::QueryNotFound)?;
        let url = self.project_url(&format!("{query_id}/"))?;
        let response = self
            .auth_request(self.client.delete(url))
            .send()
            .await
            .map_err(|error| PostHogTransportError::Request(error.to_string()))?;
        let (body, status) = Self::decode_response(response).await?;
        if !status.is_success() && status != StatusCode::NO_CONTENT {
            return Err(Self::map_status(status, &body));
        }
        Ok(TransportCancellation {
            query_id: query_id.into(),
            cancelled_at: Utc::now(),
            receipt_digest: sha256_digest(&body),
        })
    }
}

fn number_field(value: &Value, names: &[&str]) -> u64 {
    names
        .iter()
        .find_map(|name| value.get(name).and_then(Value::as_u64))
        .unwrap_or(0)
}

fn parse_query_state(value: &Value) -> Result<QueryState, PostHogTransportError> {
    let status = value
        .get("status")
        .or_else(|| value.get("state"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if value.get("error").is_some() || status == "failed" || status == "error" {
        return Ok(QueryState::Failed);
    }
    if matches!(
        status.as_str(),
        "completed" | "complete" | "finished" | "success"
    ) || value.get("results").is_some()
    {
        return Ok(QueryState::Completed);
    }
    if matches!(status.as_str(), "cancelled" | "canceled") {
        return Ok(QueryState::Cancelled);
    }
    if matches!(status.as_str(), "running" | "executing") {
        return Ok(QueryState::Running);
    }
    if matches!(status.as_str(), "queued" | "pending" | "") {
        Ok(QueryState::Queued)
    } else {
        Err(PostHogTransportError::MalformedResponse)
    }
}

fn parse_page(value: &Value) -> Result<PostHogRowPage, PostHogTransportError> {
    let rows_value = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or(PostHogTransportError::MalformedResponse)?;
    let columns = value
        .get("columns")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        });
    let mut rows = Vec::with_capacity(rows_value.len());
    for row in rows_value {
        if let Some(object) = row.as_object() {
            rows.push(
                object
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
            );
        } else if let (Some(columns), Some(values)) = (columns.as_ref(), row.as_array()) {
            if columns.len() != values.len() {
                return Err(PostHogTransportError::MalformedResponse);
            }
            rows.push(
                columns
                    .iter()
                    .cloned()
                    .zip(values.iter().cloned())
                    .collect(),
            );
        } else {
            return Err(PostHogTransportError::MalformedResponse);
        }
    }
    let next_cursor = value
        .get("next_cursor")
        .or_else(|| value.get("nextCursor"))
        .and_then(Value::as_object)
        .and_then(|object| {
            let timestamp = object
                .get("observed_at")
                .or_else(|| object.get("observedAt"))
                .and_then(Value::as_str)
                .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                .map(|value| value.with_timezone(&Utc))?;
            let event_id = object
                .get("event_id")
                .or_else(|| object.get("eventId"))?
                .as_str()?;
            KeysetCursor::new(timestamp, event_id).ok()
        });
    let bytes_read = number_field(value, &["bytes_read", "bytesRead", "bytes"]);
    let cost_units = number_field(value, &["cost_units", "costUnits", "cost"]);
    Ok(PostHogRowPage::new(
        rows,
        next_cursor,
        bytes_read,
        cost_units,
    ))
}

// -------------------------------------------------------------------------
// Deterministic loopback transport
// -------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoopbackFault {
    QueryLimit,
    RateLimited,
    TokenRevoked,
    ResponseTampered,
    NeverCompletes,
}

#[derive(Debug)]
struct LoopbackQueryState {
    next_id: AtomicU64,
    pages: Vec<PostHogRowPage>,
    fault: Option<LoopbackFault>,
    queries: BTreeMap<String, LoopbackQueryRecord>,
}

#[derive(Clone, Debug)]
struct LoopbackQueryRecord {
    page_index: usize,
    polls: u16,
    cancelled: bool,
}

#[derive(Clone, Debug)]
pub struct LoopbackPostHogTransport {
    state: Arc<Mutex<LoopbackQueryState>>,
}

impl LoopbackPostHogTransport {
    pub fn new(pages: Vec<PostHogRowPage>) -> Self {
        Self {
            state: Arc::new(Mutex::new(LoopbackQueryState {
                next_id: AtomicU64::new(1),
                pages,
                fault: None,
                queries: BTreeMap::new(),
            })),
        }
    }

    pub fn demo() -> Result<Self, ProductObservabilityError> {
        let first_at = DateTime::parse_from_rfc3339("2026-08-14T00:00:00Z")
            .expect("static fixture time")
            .with_timezone(&Utc);
        let second_at = first_at + Duration::minutes(5);
        let first_cursor = KeysetCursor::new(first_at, "event-001")?;
        let mut first_row = BTreeMap::new();
        first_row.insert("timestamp".into(), Value::String(first_at.to_rfc3339()));
        first_row.insert("uuid".into(), Value::String("event-001".into()));
        first_row.insert(
            "event".into(),
            Value::String("hartevo.result.delivered".into()),
        );
        let mut second_row = BTreeMap::new();
        second_row.insert("timestamp".into(), Value::String(second_at.to_rfc3339()));
        second_row.insert("uuid".into(), Value::String("event-002".into()));
        second_row.insert(
            "event".into(),
            Value::String("hartevo.result.adopted".into()),
        );
        Ok(Self::new(vec![
            PostHogRowPage::new(vec![first_row], Some(first_cursor), 100, 2),
            PostHogRowPage::new(vec![second_row], None, 100, 2),
        ]))
    }

    #[must_use]
    pub fn with_fault(self, fault: LoopbackFault) -> Self {
        if let Ok(mut state) = self.state.lock() {
            state.fault = Some(fault);
        }
        self
    }

    pub fn tampered_response(pages: Vec<PostHogRowPage>) -> Self {
        Self::new(pages).with_fault(LoopbackFault::ResponseTampered)
    }

    fn fault(&self) -> Option<LoopbackFault> {
        self.state.lock().ok().and_then(|state| state.fault.clone())
    }
}

#[async_trait]
impl PostHogTransport for LoopbackPostHogTransport {
    fn provenance(&self) -> Provenance {
        Provenance::ControlledLoopback
    }

    async fn probe(
        &self,
        _scope: &ProductObservabilityScope,
        _at: DateTime<Utc>,
    ) -> Result<ProbeStatus, PostHogTransportError> {
        match self.fault() {
            Some(LoopbackFault::TokenRevoked) => Err(PostHogTransportError::TokenRevoked),
            _ => Ok(ProbeStatus::Reachable),
        }
    }

    async fn submit(
        &self,
        query: &CompiledQuery,
    ) -> Result<TransportSubmission, PostHogTransportError> {
        match self.fault() {
            Some(LoopbackFault::QueryLimit) => {
                return Err(PostHogTransportError::QueryLimitExceeded);
            }
            Some(LoopbackFault::RateLimited) => {
                return Err(PostHogTransportError::RateLimited {
                    retry_after_seconds: Some(1),
                });
            }
            Some(LoopbackFault::TokenRevoked) => {
                return Err(PostHogTransportError::TokenRevoked);
            }
            _ => {}
        }
        if query.query.contains("OFFSET") || query.query.contains(';') {
            return Err(PostHogTransportError::QueryLimitExceeded);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| PostHogTransportError::Request("loopback lock poisoned".into()))?;
        let page_index = query.cursor.as_ref().map_or(0, |cursor| {
            state
                .pages
                .iter()
                .position(|page| page.next_cursor.as_ref() == Some(cursor))
                .map_or(0, |index| index.saturating_add(1))
        });
        if page_index >= state.pages.len() {
            return Err(PostHogTransportError::QueryNotFound);
        }
        let sequence = state.next_id.fetch_add(1, Ordering::Relaxed);
        let query_id = format!("loopback-query-{sequence}");
        state.queries.insert(
            query_id.clone(),
            LoopbackQueryRecord {
                page_index,
                polls: 0,
                cancelled: false,
            },
        );
        Ok(TransportSubmission {
            query_id,
            submitted_at: DateTime::parse_from_rfc3339("2026-08-14T00:00:00Z")
                .expect("static fixture time")
                .with_timezone(&Utc),
            response_digest: canonical_digest(query),
        })
    }

    async fn poll(&self, query_id: &str) -> Result<TransportPoll, PostHogTransportError> {
        let fault = self.fault();
        match fault {
            Some(LoopbackFault::RateLimited) => {
                return Err(PostHogTransportError::RateLimited {
                    retry_after_seconds: Some(1),
                });
            }
            Some(LoopbackFault::TokenRevoked) => {
                return Err(PostHogTransportError::TokenRevoked);
            }
            _ => {}
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| PostHogTransportError::Request("loopback lock poisoned".into()))?;
        let (cancelled, page_index, polls) = {
            let record = state
                .queries
                .get_mut(query_id)
                .ok_or(PostHogTransportError::QueryNotFound)?;
            record.polls = record.polls.saturating_add(1);
            (record.cancelled, record.page_index, record.polls)
        };
        if cancelled {
            return Ok(TransportPoll {
                query_id: query_id.into(),
                state: QueryState::Cancelled,
                page: None,
                response_digest: canonical_digest(&("cancelled", query_id)),
            });
        }
        if fault == Some(LoopbackFault::NeverCompletes) {
            return Ok(TransportPoll {
                query_id: query_id.into(),
                state: QueryState::Running,
                page: None,
                response_digest: canonical_digest(&("running", query_id, polls)),
            });
        }
        if polls == 1 {
            return Ok(TransportPoll {
                query_id: query_id.into(),
                state: QueryState::Queued,
                page: None,
                response_digest: canonical_digest(&("queued", query_id)),
            });
        }
        let mut page = state.pages[page_index].clone();
        if fault == Some(LoopbackFault::ResponseTampered) {
            page.declared_digest = "f".repeat(64);
        }
        Ok(TransportPoll {
            query_id: query_id.into(),
            state: QueryState::Completed,
            response_digest: page.declared_digest.clone(),
            page: Some(page),
        })
    }

    async fn query_log(&self, query_id: &str) -> Result<TransportQueryLog, PostHogTransportError> {
        let state = self
            .state
            .lock()
            .map_err(|_| PostHogTransportError::Request("loopback lock poisoned".into()))?;
        let record = state
            .queries
            .get(query_id)
            .ok_or(PostHogTransportError::QueryNotFound)?;
        let page = state
            .pages
            .get(record.page_index)
            .ok_or(PostHogTransportError::QueryNotFound)?;
        Ok(TransportQueryLog {
            query_id: query_id.into(),
            rows_read: page.rows.len() as u64,
            bytes_read: page.bytes_read,
            cost_units: page.cost_units,
            log_digest: canonical_digest(&(
                query_id,
                page.rows.len(),
                page.bytes_read,
                page.cost_units,
            )),
        })
    }

    async fn cancel(&self, query_id: &str) -> Result<TransportCancellation, PostHogTransportError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| PostHogTransportError::Request("loopback lock poisoned".into()))?;
        let record = state
            .queries
            .get_mut(query_id)
            .ok_or(PostHogTransportError::QueryNotFound)?;
        record.cancelled = true;
        Ok(TransportCancellation {
            query_id: query_id.into(),
            cancelled_at: DateTime::parse_from_rfc3339("2026-08-14T00:00:00Z")
                .expect("static fixture time")
                .with_timezone(&Utc),
            receipt_digest: canonical_digest(&("cancelled", query_id)),
        })
    }
}

#[derive(Clone, Debug)]
pub struct BlockedEnvPostHogTransport;

#[async_trait]
impl PostHogTransport for BlockedEnvPostHogTransport {
    fn provenance(&self) -> Provenance {
        Provenance::BlockedEnv
    }

    async fn probe(
        &self,
        _scope: &ProductObservabilityScope,
        _at: DateTime<Utc>,
    ) -> Result<ProbeStatus, PostHogTransportError> {
        Err(PostHogTransportError::BlockedEnv)
    }

    async fn submit(
        &self,
        _query: &CompiledQuery,
    ) -> Result<TransportSubmission, PostHogTransportError> {
        Err(PostHogTransportError::BlockedEnv)
    }

    async fn poll(&self, _query_id: &str) -> Result<TransportPoll, PostHogTransportError> {
        Err(PostHogTransportError::BlockedEnv)
    }

    async fn query_log(&self, _query_id: &str) -> Result<TransportQueryLog, PostHogTransportError> {
        Err(PostHogTransportError::BlockedEnv)
    }

    async fn cancel(
        &self,
        _query_id: &str,
    ) -> Result<TransportCancellation, PostHogTransportError> {
        Err(PostHogTransportError::BlockedEnv)
    }
}

// -------------------------------------------------------------------------
// Mission Outcome evidence consumer
// -------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClassification {
    NativeRead,
    ControlledLoopback,
    Fixture,
    BlockedEnv,
}

impl From<Provenance> for EvidenceClassification {
    fn from(value: Provenance) -> Self {
        match value {
            Provenance::ProductionHttps => Self::NativeRead,
            Provenance::ControlledLoopback => Self::ControlledLoopback,
            Provenance::Fixture => Self::Fixture,
            Provenance::BlockedEnv => Self::BlockedEnv,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionOutcomeEvidence {
    pub schema_version: String,
    pub source_provider: String,
    pub binding: MissionOutcomeBinding,
    pub scope_digest: Digest,
    pub observation_window: QueryWindow,
    pub observed_at: DateTime<Utc>,
    pub query_digest: Digest,
    pub query_log_digest: Digest,
    pub result_digest: Digest,
    pub receipt_digest: Digest,
    pub evidence_digest: Digest,
    pub row_count: u64,
    pub cost_units: u64,
    pub classification: EvidenceClassification,
    pub native: bool,
    pub causal_claim: bool,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum EvidenceConsumerError {
    #[error("Mission Outcome query did not complete")]
    QueryNotCompleted,
    #[error("Mission Outcome binding does not match the query receipt")]
    BindingMismatch,
    #[error("Mission Outcome result digest does not match the receipt")]
    ResultDigestMismatch,
    #[error("evidence classification tried to promote a non-native source")]
    NativeClassificationMismatch,
    #[error("query result does not contain exact scope or receipt identity")]
    ReceiptMismatch,
}

#[derive(Clone, Debug, Default)]
pub struct MissionOutcomeEvidenceConsumer;

impl MissionOutcomeEvidenceConsumer {
    pub fn consume(
        &self,
        request: &PostHogQueryRequest,
        execution: &QueryExecution,
    ) -> Result<MissionOutcomeEvidence, EvidenceConsumerError> {
        if !execution.is_completed() {
            return Err(EvidenceConsumerError::QueryNotCompleted);
        }
        let result = execution
            .result
            .as_ref()
            .ok_or(EvidenceConsumerError::QueryNotCompleted)?;
        if execution.receipt.binding_digest != request.binding.digest()
            || execution.receipt.scope_digest != request.scope.digest()
            || execution.receipt.request_digest != request.digest()
        {
            return Err(EvidenceConsumerError::BindingMismatch);
        }
        if result.result_digest != execution.receipt.result_digest
            || result.receipt_digest != execution.receipt.digest()
        {
            return Err(EvidenceConsumerError::ResultDigestMismatch);
        }
        let classification = EvidenceClassification::from(execution.receipt.provenance);
        let native = classification == EvidenceClassification::NativeRead;
        if native != execution.receipt.provenance.is_native()
            || execution.receipt.provenance.is_connected() != native
        {
            return Err(EvidenceConsumerError::NativeClassificationMismatch);
        }
        let evidence_digest = canonical_digest(&(
            &request.binding,
            &request.scope.digest(),
            &request.window,
            &request.observed_at,
            &request.template.id(),
            &execution.receipt,
            &result.result_digest,
        ));
        Ok(MissionOutcomeEvidence {
            schema_version: "hartevo.mission-outcome-evidence/v1".into(),
            source_provider: POSTHOG_OUTCOME_PROVIDER_ID.into(),
            binding: request.binding.clone(),
            scope_digest: request.scope.digest(),
            observation_window: request.window.clone(),
            observed_at: request.observed_at,
            query_digest: execution
                .receipt
                .pages
                .first()
                .map_or_else(|| request.digest(), |page| page.query_digest.clone()),
            query_log_digest: execution.receipt.query_log_digest.clone(),
            result_digest: result.result_digest.clone(),
            receipt_digest: execution.receipt.digest(),
            evidence_digest,
            row_count: execution.receipt.rows_read,
            cost_units: execution.receipt.cost_units,
            classification,
            native,
            causal_claim: false,
        })
    }
}
