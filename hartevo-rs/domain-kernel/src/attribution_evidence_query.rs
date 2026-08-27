//! Mission-scoped, content-free attribution evidence queries.
//!
//! The query contract is a read boundary over the durable attribution spine.
//! It freezes Mission/provider/window/cursor/ledger revisions and exposes only
//! aggregate coverage, counterevidence, freshness, confidence, and digests.
//! Source payloads, provider event ids, and account contents never cross the
//! consumer response boundary.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    AttributionError, AttributionLedger, AttributionWindow, CurrencyCode, Mission, MissionId,
    ProjectId, ProviderCursor, TenantId,
};

pub const ATTRIBUTION_EVIDENCE_QUERY_SCHEMA_VERSION: &str = "hartevo-attribution-evidence-query/v1";
pub const ATTRIBUTION_EVIDENCE_QUERY_CONTRACT_VERSION: &str = "attribution-evidence-query/v1";
pub const ATTRIBUTION_EVIDENCE_QUERY_CONSUMER_MOUNT_EVENT_TYPE: &str =
    "attribution-evidence-query.consumer-mounted/v1";
pub const ATTRIBUTION_EVIDENCE_QUERY_CONSUMER_REVOKE_EVENT_TYPE: &str =
    "attribution-evidence-query.consumer-revoked/v1";
pub const ATTRIBUTION_EVIDENCE_QUERY_REQUEST_EVENT_TYPE: &str =
    "attribution-evidence-query.request/v1";
pub const ATTRIBUTION_EVIDENCE_QUERY_FEEDBACK_EVENT_TYPE: &str =
    "attribution-evidence-query.adoption-feedback/v1";

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AttributionEvidenceQueryId(String);

impl AttributionEvidenceQueryId {
    pub fn from_stable(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AttributionEvidenceQueryId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionEvidenceQueryScope {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub mission_revision: u64,
    pub mission_digest: String,
}

impl AttributionEvidenceQueryScope {
    pub fn new(
        tenant_id: TenantId,
        project_id: ProjectId,
        mission_id: MissionId,
        mission_revision: u64,
        mission_digest: impl Into<String>,
    ) -> Result<Self, AttributionEvidenceQueryError> {
        let scope = Self {
            tenant_id,
            project_id,
            mission_id,
            mission_revision,
            mission_digest: mission_digest.into(),
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn from_mission(mission: &Mission) -> Result<Self, AttributionEvidenceQueryError> {
        Self::new(
            mission.tenant_id.clone(),
            mission.project_id.clone(),
            mission.id.clone(),
            mission.revision,
            mission_digest(mission)?,
        )
    }

    pub fn validate(&self) -> Result<(), AttributionEvidenceQueryError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.mission_revision == 0
            || !is_sha256(&self.mission_digest)
        {
            return Err(AttributionEvidenceQueryError::InvalidScope);
        }
        Ok(())
    }

    pub fn validate_against_mission(
        &self,
        mission: &Mission,
    ) -> Result<(), AttributionEvidenceQueryError> {
        self.validate()?;
        if self.tenant_id != mission.tenant_id
            || self.project_id != mission.project_id
            || self.mission_id != mission.id
            || self.mission_revision != mission.revision
            || self.mission_digest != mission_digest(mission)?
        {
            return Err(AttributionEvidenceQueryError::ScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionEvidenceQueryProvider {
    pub provider: String,
    pub account_id: String,
}

impl AttributionEvidenceQueryProvider {
    pub fn new(provider: impl Into<String>, account_id: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            account_id: account_id.into(),
        }
    }

    pub fn validate(&self) -> Result<(), AttributionEvidenceQueryError> {
        if self.provider.trim().is_empty() || self.account_id.trim().is_empty() {
            return Err(AttributionEvidenceQueryError::InvalidProvider);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionEvidenceQueryWindow {
    pub version: u32,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
    pub click_lookback_seconds: u64,
    pub view_lookback_seconds: u64,
    pub window_digest: String,
}

impl AttributionEvidenceQueryWindow {
    pub fn new(
        version: u32,
        starts_at: DateTime<Utc>,
        ends_at: DateTime<Utc>,
        click_lookback_seconds: u64,
        view_lookback_seconds: u64,
    ) -> Result<Self, AttributionEvidenceQueryError> {
        let mut window = Self {
            version,
            starts_at,
            ends_at,
            click_lookback_seconds,
            view_lookback_seconds,
            window_digest: String::new(),
        };
        window.window_digest = window.content_digest()?;
        window.validate()?;
        Ok(window)
    }

    pub fn attribution_window(&self) -> AttributionWindow {
        AttributionWindow {
            version: self.version,
            click_lookback_seconds: self.click_lookback_seconds,
            view_lookback_seconds: self.view_lookback_seconds,
            effective_at: self.starts_at,
        }
    }

    pub fn validate(&self) -> Result<(), AttributionEvidenceQueryError> {
        if self.version == 0
            || self.starts_at >= self.ends_at
            || !is_sha256(&self.window_digest)
            || self.window_digest != self.content_digest()?
        {
            return Err(AttributionEvidenceQueryError::InvalidWindow);
        }
        Ok(())
    }

    fn content_digest(&self) -> Result<String, AttributionEvidenceQueryError> {
        canonical_digest(&(
            ATTRIBUTION_EVIDENCE_QUERY_CONTRACT_VERSION,
            self.version,
            self.starts_at,
            self.ends_at,
            self.click_lookback_seconds,
            self.view_lookback_seconds,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionEvidenceQueryConsumer {
    pub consumer_id: String,
    pub plugin_id: String,
    pub plugin_version: u32,
    pub manifest_digest: String,
    pub scope: AttributionEvidenceQueryScope,
    pub generation: u64,
    pub consumer_digest: String,
}

impl AttributionEvidenceQueryConsumer {
    pub fn new(
        consumer_id: impl Into<String>,
        plugin_id: impl Into<String>,
        plugin_version: u32,
        manifest_digest: impl Into<String>,
        scope: AttributionEvidenceQueryScope,
        generation: u64,
    ) -> Result<Self, AttributionEvidenceQueryError> {
        let mut consumer = Self {
            consumer_id: consumer_id.into(),
            plugin_id: plugin_id.into(),
            plugin_version,
            manifest_digest: manifest_digest.into(),
            scope,
            generation,
            consumer_digest: String::new(),
        };
        consumer.consumer_digest = consumer.content_digest()?;
        consumer.validate()?;
        Ok(consumer)
    }

    pub fn validate(&self) -> Result<(), AttributionEvidenceQueryError> {
        if self.consumer_id.trim().is_empty()
            || self.plugin_id.trim().is_empty()
            || self.plugin_version == 0
            || self.generation == 0
            || !is_sha256(&self.manifest_digest)
            || self.consumer_digest != self.content_digest()?
        {
            return Err(AttributionEvidenceQueryError::InvalidConsumer);
        }
        self.scope.validate()
    }

    fn content_digest(&self) -> Result<String, AttributionEvidenceQueryError> {
        canonical_digest(&(
            ATTRIBUTION_EVIDENCE_QUERY_CONTRACT_VERSION,
            &self.consumer_id,
            &self.plugin_id,
            self.plugin_version,
            &self.manifest_digest,
            &self.scope,
            self.generation,
        ))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionEvidenceQueryConsumerState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionEvidenceQueryConsumerRecord {
    pub consumer: AttributionEvidenceQueryConsumer,
    pub state: AttributionEvidenceQueryConsumerState,
    pub changed_at: DateTime<Utc>,
    pub reason_digest: Option<String>,
}

impl AttributionEvidenceQueryConsumerRecord {
    pub fn active(
        consumer: AttributionEvidenceQueryConsumer,
        changed_at: DateTime<Utc>,
    ) -> Result<Self, AttributionEvidenceQueryError> {
        let record = Self {
            consumer,
            state: AttributionEvidenceQueryConsumerState::Active,
            changed_at,
            reason_digest: None,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn revoked(
        &self,
        changed_at: DateTime<Utc>,
        reason_digest: String,
    ) -> Result<Self, AttributionEvidenceQueryError> {
        let record = Self {
            consumer: self.consumer.clone(),
            state: AttributionEvidenceQueryConsumerState::Revoked,
            changed_at,
            reason_digest: Some(reason_digest),
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), AttributionEvidenceQueryError> {
        self.consumer.validate()?;
        match self.state {
            AttributionEvidenceQueryConsumerState::Active if self.reason_digest.is_none() => Ok(()),
            AttributionEvidenceQueryConsumerState::Revoked
                if self.reason_digest.as_deref().is_some_and(is_sha256) =>
            {
                Ok(())
            }
            _ => Err(AttributionEvidenceQueryError::InvalidConsumerLifecycle),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionEvidenceQueryRequest {
    pub schema_version: String,
    pub query_id: AttributionEvidenceQueryId,
    pub consumer_id: String,
    pub scope: AttributionEvidenceQueryScope,
    pub provider: AttributionEvidenceQueryProvider,
    pub window: AttributionEvidenceQueryWindow,
    pub evaluated_at: DateTime<Utc>,
    pub cursor_fence: Option<ProviderCursor>,
    pub ledger_revision: u64,
    pub ledger_digest: String,
    pub request_digest: String,
}

impl AttributionEvidenceQueryRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        consumer_id: impl Into<String>,
        scope: AttributionEvidenceQueryScope,
        provider: AttributionEvidenceQueryProvider,
        window: AttributionEvidenceQueryWindow,
        evaluated_at: DateTime<Utc>,
        cursor_fence: Option<ProviderCursor>,
        ledger_revision: u64,
        ledger_digest: impl Into<String>,
    ) -> Result<Self, AttributionEvidenceQueryError> {
        let mut request = Self {
            schema_version: ATTRIBUTION_EVIDENCE_QUERY_SCHEMA_VERSION.into(),
            query_id: AttributionEvidenceQueryId::from_stable("query:pending"),
            consumer_id: consumer_id.into(),
            scope,
            provider,
            window,
            evaluated_at,
            cursor_fence,
            ledger_revision,
            ledger_digest: ledger_digest.into(),
            request_digest: String::new(),
        };
        request.request_digest = request.content_digest()?;
        request.query_id = AttributionEvidenceQueryId::from_stable(format!(
            "attribution-query:{}",
            request.request_digest
        ));
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), AttributionEvidenceQueryError> {
        if self.schema_version != ATTRIBUTION_EVIDENCE_QUERY_SCHEMA_VERSION
            || self.consumer_id.trim().is_empty()
            || self.ledger_revision == 0
            || !is_sha256(&self.ledger_digest)
            || self.request_digest != self.content_digest()?
            || self.query_id.as_str() != format!("attribution-query:{}", self.request_digest)
        {
            return Err(AttributionEvidenceQueryError::InvalidRequest);
        }
        self.scope.validate()?;
        self.provider.validate()?;
        self.window.validate()?;
        if let Some(cursor) = &self.cursor_fence {
            validate_cursor(cursor)?;
            if cursor.provider != self.provider.provider
                || cursor.account_id != self.provider.account_id
            {
                return Err(AttributionEvidenceQueryError::InvalidCursor);
            }
        }
        Ok(())
    }

    fn content_digest(&self) -> Result<String, AttributionEvidenceQueryError> {
        canonical_digest(&(
            &self.schema_version,
            &self.consumer_id,
            &self.scope,
            &self.provider,
            &self.window,
            self.evaluated_at,
            &self.cursor_fence,
            self.ledger_revision,
            &self.ledger_digest,
        ))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionEvidenceFreshnessState {
    Fresh,
    Stale,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionEvidenceFreshness {
    pub state: AttributionEvidenceFreshnessState,
    pub latest_observed_at: Option<DateTime<Utc>>,
    pub fresh_until: Option<DateTime<Utc>>,
    pub freshness_digest: String,
}

impl AttributionEvidenceFreshness {
    pub fn new(
        state: AttributionEvidenceFreshnessState,
        latest_observed_at: Option<DateTime<Utc>>,
        fresh_until: Option<DateTime<Utc>>,
    ) -> Result<Self, AttributionEvidenceQueryError> {
        let mut freshness = Self {
            state,
            latest_observed_at,
            fresh_until,
            freshness_digest: String::new(),
        };
        freshness.freshness_digest = canonical_digest(&(
            ATTRIBUTION_EVIDENCE_QUERY_CONTRACT_VERSION,
            freshness.state,
            freshness.latest_observed_at,
            freshness.fresh_until,
        ))?;
        freshness.validate()?;
        Ok(freshness)
    }

    pub fn validate(&self) -> Result<(), AttributionEvidenceQueryError> {
        if !is_sha256(&self.freshness_digest)
            || self.freshness_digest
                != canonical_digest(&(
                    ATTRIBUTION_EVIDENCE_QUERY_CONTRACT_VERSION,
                    self.state,
                    self.latest_observed_at,
                    self.fresh_until,
                ))?
            || (self.latest_observed_at.is_none()
                && self.state != AttributionEvidenceFreshnessState::Unknown)
            || (self.state == AttributionEvidenceFreshnessState::Fresh
                && self.fresh_until.is_none())
        {
            return Err(AttributionEvidenceQueryError::InvalidFreshness);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionEvidenceSourceCoverage {
    pub source_event_count: u64,
    pub first_party_event_count: u64,
    pub partner_event_count: u64,
    pub weak_provenance_event_count: u64,
    pub outcome_candidate_count: u64,
    pub verified_outcome_count: u64,
    pub coverage_digest: String,
}

impl AttributionEvidenceSourceCoverage {
    pub fn validate(&self) -> Result<(), AttributionEvidenceQueryError> {
        if !is_sha256(&self.coverage_digest)
            || self.verified_outcome_count > self.outcome_candidate_count
            || self.first_party_event_count
                + self.partner_event_count
                + self.weak_provenance_event_count
                != self.source_event_count
        {
            return Err(AttributionEvidenceQueryError::InvalidCoverage);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionEvidenceCounterevidence {
    pub unverified_outcome_count: u64,
    pub unattributed_outcome_count: u64,
    pub inactive_lineage_count: u64,
    pub correction_count: u64,
    pub reversal_count: u64,
    pub counterevidence_digest: String,
}

impl AttributionEvidenceCounterevidence {
    pub fn total(&self) -> u64 {
        self.unverified_outcome_count
            .saturating_add(self.unattributed_outcome_count)
            .saturating_add(self.inactive_lineage_count)
            .saturating_add(self.correction_count)
            .saturating_add(self.reversal_count)
    }

    pub fn validate(&self) -> Result<(), AttributionEvidenceQueryError> {
        if !is_sha256(&self.counterevidence_digest) {
            return Err(AttributionEvidenceQueryError::InvalidCounterevidence);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionEvidenceConfidence {
    High,
    Medium,
    Low,
    None,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionEvidenceQueryResponse {
    pub schema_version: String,
    pub query_id: AttributionEvidenceQueryId,
    pub request_digest: String,
    pub scope: AttributionEvidenceQueryScope,
    pub provider: AttributionEvidenceQueryProvider,
    pub window: AttributionEvidenceQueryWindow,
    pub evaluated_at: DateTime<Utc>,
    pub ledger_revision: u64,
    pub ledger_digest: String,
    pub provider_revision: u64,
    pub provider_digest: String,
    pub source_coverage: AttributionEvidenceSourceCoverage,
    pub counterevidence: AttributionEvidenceCounterevidence,
    pub freshness: AttributionEvidenceFreshness,
    pub confidence: AttributionEvidenceConfidence,
    pub adoption_feedback_digests: Vec<String>,
    pub response_digest: String,
}

impl AttributionEvidenceQueryResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &AttributionEvidenceQueryRequest,
        provider_revision: u64,
        provider_digest: impl Into<String>,
        source_coverage: AttributionEvidenceSourceCoverage,
        counterevidence: AttributionEvidenceCounterevidence,
        freshness: AttributionEvidenceFreshness,
        confidence: AttributionEvidenceConfidence,
        adoption_feedback_digests: Vec<String>,
    ) -> Result<Self, AttributionEvidenceQueryError> {
        request.validate()?;
        source_coverage.validate()?;
        counterevidence.validate()?;
        freshness.validate()?;
        let mut response = Self {
            schema_version: ATTRIBUTION_EVIDENCE_QUERY_SCHEMA_VERSION.into(),
            query_id: request.query_id.clone(),
            request_digest: request.request_digest.clone(),
            scope: request.scope.clone(),
            provider: request.provider.clone(),
            window: request.window.clone(),
            evaluated_at: request.evaluated_at,
            ledger_revision: request.ledger_revision,
            ledger_digest: request.ledger_digest.clone(),
            provider_revision,
            provider_digest: provider_digest.into(),
            source_coverage,
            counterevidence,
            freshness,
            confidence,
            adoption_feedback_digests,
            response_digest: String::new(),
        };
        response.response_digest = response.content_digest()?;
        response.validate_against_request(request)?;
        Ok(response)
    }

    pub fn validate_against_request(
        &self,
        request: &AttributionEvidenceQueryRequest,
    ) -> Result<(), AttributionEvidenceQueryError> {
        if self.schema_version != ATTRIBUTION_EVIDENCE_QUERY_SCHEMA_VERSION
            || self.query_id != request.query_id
            || self.request_digest != request.request_digest
            || self.scope != request.scope
            || self.provider != request.provider
            || self.window != request.window
            || self.evaluated_at != request.evaluated_at
            || self.ledger_revision != request.ledger_revision
            || self.ledger_digest != request.ledger_digest
            || self.provider_digest.trim().is_empty()
            || !is_sha256(&self.provider_digest)
            || self.provider_revision
                != request
                    .cursor_fence
                    .as_ref()
                    .map_or(0, |cursor| cursor.sequence)
            || self.provider_digest
                != request.cursor_fence.as_ref().map_or_else(
                    || digest_text("attribution-evidence-query:no-cursor"),
                    |cursor| cursor.batch_digest.clone(),
                )
            || self.response_digest != self.content_digest()?
            || self
                .adoption_feedback_digests
                .iter()
                .any(|digest| !is_sha256(digest))
            || self
                .adoption_feedback_digests
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(AttributionEvidenceQueryError::ResponseBindingMismatch);
        }
        self.source_coverage.validate()?;
        self.counterevidence.validate()?;
        self.freshness.validate()
    }

    pub fn ledger_digest(
        ledger: &AttributionLedger,
    ) -> Result<String, AttributionEvidenceQueryError> {
        canonical_digest(ledger)
    }

    fn content_digest(&self) -> Result<String, AttributionEvidenceQueryError> {
        canonical_digest(&(
            &self.schema_version,
            &self.query_id,
            &self.request_digest,
            &self.scope,
            &self.provider,
            &self.window,
            self.evaluated_at,
            self.ledger_revision,
            &self.ledger_digest,
            self.provider_revision,
            &self.provider_digest,
            &self.source_coverage,
            &self.counterevidence,
            &self.freshness,
            &self.confidence,
            &self.adoption_feedback_digests,
        ))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionEvidenceAdoptionDecision {
    Adopt,
    Reject,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionEvidenceAdoptionFeedback {
    pub schema_version: String,
    pub feedback_id: String,
    pub consumer_id: String,
    pub query_id: AttributionEvidenceQueryId,
    pub request_digest: String,
    pub response_digest: String,
    pub scope: AttributionEvidenceQueryScope,
    pub provider: AttributionEvidenceQueryProvider,
    pub window: AttributionEvidenceQueryWindow,
    pub ledger_revision: u64,
    pub decision: AttributionEvidenceAdoptionDecision,
    pub feedback_digest: String,
}

impl AttributionEvidenceAdoptionFeedback {
    pub fn new(
        consumer_id: impl Into<String>,
        response: &AttributionEvidenceQueryResponse,
        decision: AttributionEvidenceAdoptionDecision,
    ) -> Result<Self, AttributionEvidenceQueryError> {
        let mut feedback = Self {
            schema_version: ATTRIBUTION_EVIDENCE_QUERY_SCHEMA_VERSION.into(),
            feedback_id: String::new(),
            consumer_id: consumer_id.into(),
            query_id: response.query_id.clone(),
            request_digest: response.request_digest.clone(),
            response_digest: response.response_digest.clone(),
            scope: response.scope.clone(),
            provider: response.provider.clone(),
            window: response.window.clone(),
            ledger_revision: response.ledger_revision,
            decision,
            feedback_digest: String::new(),
        };
        feedback.feedback_digest = feedback.content_digest()?;
        feedback.feedback_id = format!("attribution-feedback:{}", feedback.feedback_digest);
        feedback.validate_against_response(response)?;
        Ok(feedback)
    }

    pub fn validate_against_response(
        &self,
        response: &AttributionEvidenceQueryResponse,
    ) -> Result<(), AttributionEvidenceQueryError> {
        if self.schema_version != ATTRIBUTION_EVIDENCE_QUERY_SCHEMA_VERSION
            || self.feedback_id != format!("attribution-feedback:{}", self.feedback_digest)
            || self.feedback_digest != self.content_digest()?
            || self.consumer_id.trim().is_empty()
            || self.query_id != response.query_id
            || self.request_digest != response.request_digest
            || self.response_digest != response.response_digest
            || self.scope != response.scope
            || self.provider != response.provider
            || self.window != response.window
            || self.ledger_revision != response.ledger_revision
        {
            return Err(AttributionEvidenceQueryError::FeedbackBindingMismatch);
        }
        self.scope.validate()?;
        self.provider.validate()?;
        self.window.validate()
    }

    fn content_digest(&self) -> Result<String, AttributionEvidenceQueryError> {
        canonical_digest(&(
            ATTRIBUTION_EVIDENCE_QUERY_CONTRACT_VERSION,
            &self.consumer_id,
            &self.query_id,
            &self.request_digest,
            &self.response_digest,
            &self.scope,
            &self.provider,
            &self.window,
            self.ledger_revision,
            self.decision,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionEvidenceQueryRecord {
    pub schema_version: String,
    pub request: AttributionEvidenceQueryRequest,
    pub response: AttributionEvidenceQueryResponse,
    pub record_digest: String,
}

impl AttributionEvidenceQueryRecord {
    pub fn new(
        request: AttributionEvidenceQueryRequest,
        response: AttributionEvidenceQueryResponse,
    ) -> Result<Self, AttributionEvidenceQueryError> {
        response.validate_against_request(&request)?;
        let mut record = Self {
            schema_version: ATTRIBUTION_EVIDENCE_QUERY_SCHEMA_VERSION.into(),
            request,
            response,
            record_digest: String::new(),
        };
        record.record_digest = record.content_digest()?;
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), AttributionEvidenceQueryError> {
        if self.schema_version != ATTRIBUTION_EVIDENCE_QUERY_SCHEMA_VERSION
            || self.record_digest != self.content_digest()?
        {
            return Err(AttributionEvidenceQueryError::RecordDigestMismatch);
        }
        self.request.validate()?;
        self.response.validate_against_request(&self.request)
    }

    fn content_digest(&self) -> Result<String, AttributionEvidenceQueryError> {
        canonical_digest(&(
            ATTRIBUTION_EVIDENCE_QUERY_CONTRACT_VERSION,
            &self.request,
            &self.response,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionEvidenceQuerySnapshot {
    pub schema_version: String,
    pub project_id: ProjectId,
    pub records: Vec<AttributionEvidenceQueryRecord>,
}

/// Durable provider boundary consumed by planning/model plugins. Implementors
/// must persist the response before returning it and must preserve the exact
/// scope, revision, cursor, and digest fences carried by each request.
pub trait AttributionEvidenceQueryService {
    type Error;

    fn mount_attribution_evidence_query_consumer(
        &mut self,
        consumer: &AttributionEvidenceQueryConsumer,
        mounted_at: DateTime<Utc>,
    ) -> Result<i64, Self::Error>;

    fn revoke_attribution_evidence_query_consumer(
        &mut self,
        project_id: &ProjectId,
        consumer_id: &str,
        reason_digest: String,
        revoked_at: DateTime<Utc>,
    ) -> Result<i64, Self::Error>;

    fn append_attribution_evidence_query(
        &mut self,
        request: &AttributionEvidenceQueryRequest,
        reporting_currency: CurrencyCode,
    ) -> Result<AttributionEvidenceQueryResponse, Self::Error>;

    fn append_attribution_evidence_adoption_feedback(
        &mut self,
        feedback: &AttributionEvidenceAdoptionFeedback,
        recorded_at: DateTime<Utc>,
    ) -> Result<AttributionEvidenceAdoptionFeedback, Self::Error>;

    fn replay_attribution_evidence_queries(
        &self,
        project_id: &ProjectId,
    ) -> Result<AttributionEvidenceQuerySnapshot, Self::Error>;
}

impl AttributionEvidenceQuerySnapshot {
    pub fn new(
        project_id: ProjectId,
        records: Vec<AttributionEvidenceQueryRecord>,
    ) -> Result<Self, AttributionEvidenceQueryError> {
        let snapshot = Self {
            schema_version: ATTRIBUTION_EVIDENCE_QUERY_SCHEMA_VERSION.into(),
            project_id,
            records,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn validate(&self) -> Result<(), AttributionEvidenceQueryError> {
        if self.schema_version != ATTRIBUTION_EVIDENCE_QUERY_SCHEMA_VERSION
            || self.project_id.as_str().trim().is_empty()
        {
            return Err(AttributionEvidenceQueryError::InvalidSnapshot);
        }
        let mut query_ids = BTreeSet::new();
        for record in &self.records {
            record.validate()?;
            if record.request.scope.project_id != self.project_id
                || !query_ids.insert(record.request.query_id.clone())
            {
                return Err(AttributionEvidenceQueryError::DuplicateQuery);
            }
        }
        Ok(())
    }
}

fn mission_digest(mission: &Mission) -> Result<String, AttributionEvidenceQueryError> {
    canonical_digest(&(
        ATTRIBUTION_EVIDENCE_QUERY_CONTRACT_VERSION,
        &mission.tenant_id,
        &mission.project_id,
        &mission.id,
        mission.revision,
        &mission.contract,
    ))
}

fn validate_cursor(cursor: &ProviderCursor) -> Result<(), AttributionEvidenceQueryError> {
    if cursor.provider.trim().is_empty()
        || cursor.account_id.trim().is_empty()
        || cursor.token.trim().is_empty()
        || cursor.observed_through > cursor.ingested_at
        || !is_sha256(&cursor.batch_digest)
    {
        return Err(AttributionEvidenceQueryError::InvalidCursor);
    }
    Ok(())
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, AttributionEvidenceQueryError> {
    let bytes = serde_json::to_vec(value).map_err(AttributionEvidenceQueryError::Serialization)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn digest_text(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

#[derive(Debug, Error)]
pub enum AttributionEvidenceQueryError {
    #[error("attribution evidence query scope is invalid")]
    InvalidScope,
    #[error("attribution evidence query scope does not match the Mission")]
    ScopeMismatch,
    #[error("attribution evidence query provider is invalid")]
    InvalidProvider,
    #[error("attribution evidence query window is invalid")]
    InvalidWindow,
    #[error("attribution evidence query consumer is invalid")]
    InvalidConsumer,
    #[error("attribution evidence query consumer lifecycle is invalid")]
    InvalidConsumerLifecycle,
    #[error("attribution evidence query request is invalid")]
    InvalidRequest,
    #[error("attribution evidence query cursor is invalid")]
    InvalidCursor,
    #[error("attribution evidence query ledger or provider revision is stale")]
    StaleRevision,
    #[error("attribution evidence query response is not bound to its request")]
    ResponseBindingMismatch,
    #[error("attribution evidence source coverage is invalid")]
    InvalidCoverage,
    #[error("attribution evidence counterevidence is invalid")]
    InvalidCounterevidence,
    #[error("attribution evidence freshness is invalid")]
    InvalidFreshness,
    #[error("attribution evidence feedback is not bound to its response")]
    FeedbackBindingMismatch,
    #[error("attribution evidence query record digest is invalid")]
    RecordDigestMismatch,
    #[error("attribution evidence query snapshot is invalid")]
    InvalidSnapshot,
    #[error("attribution evidence query is duplicated")]
    DuplicateQuery,
    #[error("attribution evidence query serialization failed: {0}")]
    Serialization(serde_json::Error),
    #[error("attribution spine is invalid: {0}")]
    AttributionSpine(String),
}

impl From<AttributionError> for AttributionEvidenceQueryError {
    fn from(error: AttributionError) -> Self {
        Self::AttributionSpine(error.to_string())
    }
}
