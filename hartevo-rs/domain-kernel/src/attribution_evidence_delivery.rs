//! Durable, content-free delivery receipts for attribution evidence queries.
//!
//! A receipt records that one exact query response was made visible to one
//! typed model invocation. It carries only identity, revision, and digest
//! bindings; provider payloads, account contents, and source event bodies are
//! intentionally outside this contract.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::attribution_evidence_query::{
    AttributionEvidenceAdoptionDecision, AttributionEvidenceAdoptionFeedback,
    AttributionEvidenceQueryConsumer, AttributionEvidenceQueryError, AttributionEvidenceQueryId,
    AttributionEvidenceQueryProvider, AttributionEvidenceQueryRequest,
    AttributionEvidenceQueryResponse, AttributionEvidenceQueryScope,
};
use crate::{CurrencyCode, ProjectId};

pub const ATTRIBUTION_EVIDENCE_DELIVERY_SCHEMA_VERSION: &str =
    "hartevo-attribution-evidence-delivery/v1";
pub const ATTRIBUTION_EVIDENCE_DELIVERY_CONTRACT_VERSION: &str = "attribution-evidence-delivery/v1";
pub const ATTRIBUTION_EVIDENCE_DELIVERY_RECEIPT_EVENT_TYPE: &str =
    "attribution-evidence-delivery.receipt/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionEvidenceModelInvocation {
    pub invocation_id: String,
    pub model_id: String,
    pub model_revision: u64,
    pub model_digest: String,
    pub input_digest: String,
    pub invocation_digest: String,
}

impl AttributionEvidenceModelInvocation {
    pub fn new(
        invocation_id: impl Into<String>,
        model_id: impl Into<String>,
        model_revision: u64,
        model_digest: impl Into<String>,
        input_digest: impl Into<String>,
    ) -> Result<Self, AttributionEvidenceDeliveryError> {
        let mut invocation = Self {
            invocation_id: invocation_id.into(),
            model_id: model_id.into(),
            model_revision,
            model_digest: model_digest.into(),
            input_digest: input_digest.into(),
            invocation_digest: String::new(),
        };
        invocation.invocation_digest = invocation.content_digest()?;
        invocation.validate()?;
        Ok(invocation)
    }

    pub fn validate(&self) -> Result<(), AttributionEvidenceDeliveryError> {
        if self.invocation_id.trim().is_empty()
            || self.model_id.trim().is_empty()
            || self.model_revision == 0
            || !is_sha256(&self.model_digest)
            || !is_sha256(&self.input_digest)
            || !is_sha256(&self.invocation_digest)
            || self.invocation_digest != self.content_digest()?
        {
            return Err(AttributionEvidenceDeliveryError::InvalidInvocation);
        }
        Ok(())
    }

    fn content_digest(&self) -> Result<String, AttributionEvidenceDeliveryError> {
        canonical_digest(&(
            ATTRIBUTION_EVIDENCE_DELIVERY_CONTRACT_VERSION,
            &self.invocation_id,
            &self.model_id,
            self.model_revision,
            &self.model_digest,
            &self.input_digest,
        ))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionEvidenceDeliveryDisposition {
    Adopted,
    Superseded,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionEvidenceDeliveryReceipt {
    pub schema_version: String,
    pub delivery_id: String,
    pub scope: AttributionEvidenceQueryScope,
    pub consumer_id: String,
    pub plugin_id: String,
    pub plugin_version: u32,
    pub consumer_generation: u64,
    pub consumer_digest: String,
    pub manifest_digest: String,
    pub model_invocation: AttributionEvidenceModelInvocation,
    pub query_id: AttributionEvidenceQueryId,
    pub query_revision: u64,
    pub query_digest: String,
    pub provider: AttributionEvidenceQueryProvider,
    pub provider_revision: u64,
    pub provider_digest: String,
    pub window_digest: String,
    pub source_coverage_revision: u64,
    pub source_coverage_digest: String,
    pub response_revision: u64,
    pub response_digest: String,
    pub feedback_digest: Option<String>,
    pub superseded_by_query_id: Option<AttributionEvidenceQueryId>,
    pub superseded_by_response_digest: Option<String>,
    pub disposition: AttributionEvidenceDeliveryDisposition,
    pub delivered_at: DateTime<Utc>,
    pub receipt_digest: String,
}

impl AttributionEvidenceDeliveryReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        delivery_id: impl Into<String>,
        consumer: &AttributionEvidenceQueryConsumer,
        model_invocation: AttributionEvidenceModelInvocation,
        request: &AttributionEvidenceQueryRequest,
        response: &AttributionEvidenceQueryResponse,
        disposition: AttributionEvidenceDeliveryDisposition,
        feedback_digest: Option<String>,
        superseded_by: Option<(AttributionEvidenceQueryId, String)>,
        delivered_at: DateTime<Utc>,
    ) -> Result<Self, AttributionEvidenceDeliveryError> {
        let (superseded_by_query_id, superseded_by_response_digest) = superseded_by
            .map_or((None, None), |(query_id, response_digest)| {
                (Some(query_id), Some(response_digest))
            });
        let mut receipt = Self {
            schema_version: ATTRIBUTION_EVIDENCE_DELIVERY_SCHEMA_VERSION.into(),
            delivery_id: delivery_id.into(),
            scope: response.scope.clone(),
            consumer_id: consumer.consumer_id.clone(),
            plugin_id: consumer.plugin_id.clone(),
            plugin_version: consumer.plugin_version,
            consumer_generation: consumer.generation,
            consumer_digest: consumer.consumer_digest.clone(),
            manifest_digest: consumer.manifest_digest.clone(),
            model_invocation,
            query_id: response.query_id.clone(),
            query_revision: request.ledger_revision,
            query_digest: request.ledger_digest.clone(),
            provider: response.provider.clone(),
            provider_revision: response.provider_revision,
            provider_digest: response.provider_digest.clone(),
            window_digest: response.window.window_digest.clone(),
            source_coverage_revision: response.ledger_revision,
            source_coverage_digest: response.source_coverage.coverage_digest.clone(),
            response_revision: response.ledger_revision,
            response_digest: response.response_digest.clone(),
            feedback_digest,
            superseded_by_query_id,
            superseded_by_response_digest,
            disposition,
            delivered_at,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.content_digest()?;
        receipt.validate_against(consumer, request, response)?;
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), AttributionEvidenceDeliveryError> {
        if self.schema_version != ATTRIBUTION_EVIDENCE_DELIVERY_SCHEMA_VERSION
            || self.delivery_id.trim().is_empty()
            || self.query_revision == 0
            || self.source_coverage_revision == 0
            || self.response_revision == 0
            || !is_sha256(&self.query_digest)
            || !is_sha256(&self.provider_digest)
            || !is_sha256(&self.window_digest)
            || !is_sha256(&self.source_coverage_digest)
            || !is_sha256(&self.response_digest)
            || !is_sha256(&self.consumer_digest)
            || !is_sha256(&self.manifest_digest)
            || self.consumer_id.trim().is_empty()
            || self.plugin_id.trim().is_empty()
            || self.plugin_version == 0
            || self.consumer_generation == 0
            || self
                .feedback_digest
                .as_ref()
                .is_some_and(|digest| !is_sha256(digest))
            || self
                .superseded_by_response_digest
                .as_ref()
                .is_some_and(|digest| !is_sha256(digest))
            || self.receipt_digest != self.content_digest()?
        {
            return Err(AttributionEvidenceDeliveryError::InvalidReceipt);
        }
        self.scope.validate()?;
        self.provider.validate()?;
        self.model_invocation.validate()?;
        if self.query_id.as_str().trim().is_empty()
            || self
                .superseded_by_query_id
                .as_ref()
                .is_some_and(|query_id| query_id.as_str().trim().is_empty())
        {
            return Err(AttributionEvidenceDeliveryError::InvalidReceipt);
        }
        if self.superseded_by_query_id.is_some() != self.superseded_by_response_digest.is_some() {
            return Err(AttributionEvidenceDeliveryError::InvalidDispositionBinding);
        }
        match self.disposition {
            AttributionEvidenceDeliveryDisposition::Adopted
            | AttributionEvidenceDeliveryDisposition::Rejected
                if self.feedback_digest.is_none() || self.superseded_by_query_id.is_some() =>
            {
                Err(AttributionEvidenceDeliveryError::InvalidDispositionBinding)
            }
            AttributionEvidenceDeliveryDisposition::Superseded
                if self.superseded_by_query_id.is_none() || self.feedback_digest.is_some() =>
            {
                Err(AttributionEvidenceDeliveryError::InvalidDispositionBinding)
            }
            _ => Ok(()),
        }
    }

    pub fn validate_against(
        &self,
        consumer: &AttributionEvidenceQueryConsumer,
        request: &AttributionEvidenceQueryRequest,
        response: &AttributionEvidenceQueryResponse,
    ) -> Result<(), AttributionEvidenceDeliveryError> {
        self.validate()?;
        consumer.validate()?;
        request.validate()?;
        response.validate_against_request(request)?;
        if self.scope != response.scope
            || self.scope != consumer.scope
            || self.consumer_id != consumer.consumer_id
            || self.plugin_id != consumer.plugin_id
            || self.plugin_version != consumer.plugin_version
            || self.consumer_generation != consumer.generation
            || self.consumer_digest != consumer.consumer_digest
            || self.manifest_digest != consumer.manifest_digest
            || self.query_id != response.query_id
            || self.query_revision != response.ledger_revision
            || self.query_digest != response.ledger_digest
            || self.provider != response.provider
            || self.provider_revision != response.provider_revision
            || self.provider_digest != response.provider_digest
            || self.window_digest != response.window.window_digest
            || self.source_coverage_revision != response.ledger_revision
            || self.source_coverage_digest != response.source_coverage.coverage_digest
            || self.response_revision != response.ledger_revision
            || self.response_digest != response.response_digest
            || self.delivered_at < response.evaluated_at
        {
            return Err(AttributionEvidenceDeliveryError::ReceiptBindingMismatch);
        }
        Ok(())
    }

    pub fn feedback_decision(
        &self,
        feedback: &AttributionEvidenceAdoptionFeedback,
    ) -> Result<(), AttributionEvidenceDeliveryError> {
        let expected = match self.disposition {
            AttributionEvidenceDeliveryDisposition::Adopted => {
                AttributionEvidenceAdoptionDecision::Adopt
            }
            AttributionEvidenceDeliveryDisposition::Rejected => {
                AttributionEvidenceAdoptionDecision::Reject
            }
            AttributionEvidenceDeliveryDisposition::Superseded => {
                return Err(AttributionEvidenceDeliveryError::InvalidDispositionBinding);
            }
        };
        if self.feedback_digest.as_deref() != Some(feedback.feedback_digest.as_str())
            || feedback.decision != expected
        {
            return Err(AttributionEvidenceDeliveryError::FeedbackBindingMismatch);
        }
        Ok(())
    }

    fn content_digest(&self) -> Result<String, AttributionEvidenceDeliveryError> {
        let mut content = self.clone();
        content.receipt_digest.clear();
        canonical_digest(&content)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionEvidenceDeliverySnapshot {
    pub schema_version: String,
    pub project_id: ProjectId,
    pub records: Vec<AttributionEvidenceDeliveryReceipt>,
}

/// Storage/provider boundary for model-visible delivery receipts.
pub trait AttributionEvidenceDeliveryService {
    type Error;

    fn append_attribution_evidence_delivery_receipt(
        &mut self,
        receipt: &AttributionEvidenceDeliveryReceipt,
        reporting_currency: CurrencyCode,
    ) -> Result<AttributionEvidenceDeliveryReceipt, Self::Error>;

    fn replay_attribution_evidence_delivery_receipts(
        &self,
        project_id: &ProjectId,
    ) -> Result<AttributionEvidenceDeliverySnapshot, Self::Error>;
}

impl AttributionEvidenceDeliverySnapshot {
    pub fn new(
        project_id: ProjectId,
        records: Vec<AttributionEvidenceDeliveryReceipt>,
    ) -> Result<Self, AttributionEvidenceDeliveryError> {
        let snapshot = Self {
            schema_version: ATTRIBUTION_EVIDENCE_DELIVERY_SCHEMA_VERSION.into(),
            project_id,
            records,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn validate(&self) -> Result<(), AttributionEvidenceDeliveryError> {
        if self.schema_version != ATTRIBUTION_EVIDENCE_DELIVERY_SCHEMA_VERSION
            || self.project_id.as_str().trim().is_empty()
        {
            return Err(AttributionEvidenceDeliveryError::InvalidSnapshot);
        }
        let mut delivery_ids = BTreeSet::new();
        let mut invocation_ids = BTreeSet::new();
        for record in &self.records {
            record.validate()?;
            if !delivery_ids.insert(record.delivery_id.clone())
                || !invocation_ids.insert(record.model_invocation.invocation_id.clone())
                || record.scope.project_id != self.project_id
            {
                return Err(AttributionEvidenceDeliveryError::DuplicateDelivery);
            }
        }
        Ok(())
    }
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, AttributionEvidenceDeliveryError> {
    let bytes =
        serde_json::to_vec(value).map_err(AttributionEvidenceDeliveryError::Serialization)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug, Error)]
pub enum AttributionEvidenceDeliveryError {
    #[error("attribution evidence delivery invocation is invalid")]
    InvalidInvocation,
    #[error("attribution evidence delivery receipt is invalid")]
    InvalidReceipt,
    #[error("attribution evidence delivery disposition binding is invalid")]
    InvalidDispositionBinding,
    #[error("attribution evidence delivery receipt does not match its query response")]
    ReceiptBindingMismatch,
    #[error("attribution evidence delivery feedback does not match its receipt")]
    FeedbackBindingMismatch,
    #[error("attribution evidence delivery snapshot is invalid")]
    InvalidSnapshot,
    #[error("attribution evidence delivery receipt is duplicated")]
    DuplicateDelivery,
    #[error("attribution evidence delivery serialization failed: {0}")]
    Serialization(serde_json::Error),
    #[error("attribution evidence query is invalid: {0}")]
    Query(String),
}

impl From<AttributionEvidenceQueryError> for AttributionEvidenceDeliveryError {
    fn from(error: AttributionEvidenceQueryError) -> Self {
        Self::Query(error.to_string())
    }
}
