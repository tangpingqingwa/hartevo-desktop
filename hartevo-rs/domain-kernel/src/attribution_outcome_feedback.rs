//! Typed feedback from an adopted or rejected attribution outcome.
//!
//! A feedback record is an input to a later evaluation window, not a rewrite
//! of the source candidate or its adoption receipt. The consumer-facing
//! projection is deliberately content-free: it carries only scope, revision,
//! decision, and cryptographic digests.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    AttributionAdoptionDecision, AttributionAdoptionReceipt, AttributionAdoptionScope,
    AttributionModelVersion, AttributionOutcomeCandidate, AttributionWindow, MissionId,
    OutcomeCandidateId, ProjectId, SourceEventId,
};

pub const ATTRIBUTION_OUTCOME_FEEDBACK_SCHEMA_VERSION: &str =
    "hartevo-attribution-outcome-feedback/v1";
pub const ATTRIBUTION_OUTCOME_FEEDBACK_CONTRACT_VERSION: &str = "attribution-outcome-feedback/v1";
pub const ATTRIBUTION_FEEDBACK_EVENT_TYPE: &str = "attribution-adoption.feedback/v1";

/// The exact next evaluation window. Its digest is derived from all temporal,
/// attribution-window, and model fields, so a consumer cannot silently switch
/// evaluation policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionFeedbackWindow {
    pub revision: u64,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
    pub attribution_window: AttributionWindow,
    pub model_version: AttributionModelVersion,
    pub window_digest: String,
}

impl AttributionFeedbackWindow {
    pub fn new(
        revision: u64,
        starts_at: DateTime<Utc>,
        ends_at: DateTime<Utc>,
        attribution_window: AttributionWindow,
        model_version: AttributionModelVersion,
    ) -> Result<Self, AttributionFeedbackError> {
        let mut window = Self {
            revision,
            starts_at,
            ends_at,
            attribution_window,
            model_version,
            window_digest: String::new(),
        };
        window.window_digest = window.content_digest()?;
        window.validate()?;
        Ok(window)
    }

    pub fn validate(&self) -> Result<(), AttributionFeedbackError> {
        if self.revision == 0
            || self.starts_at >= self.ends_at
            || !is_sha256(&self.window_digest)
            || self.window_digest != self.content_digest()?
        {
            return Err(AttributionFeedbackError::InvalidEvaluationWindow);
        }
        self.attribution_window
            .validate()
            .map_err(|error| AttributionFeedbackError::Adoption(error.to_string()))?;
        self.model_version
            .validate()
            .map_err(|error| AttributionFeedbackError::Adoption(error.to_string()))?;
        Ok(())
    }

    pub fn validate_after_receipt(
        &self,
        receipt: &AttributionAdoptionReceipt,
    ) -> Result<(), AttributionFeedbackError> {
        self.validate()?;
        if self.revision <= u64::from(receipt.window.version)
            || self.starts_at < receipt.decided_at
            || self.attribution_window.version <= receipt.window.version
        {
            return Err(AttributionFeedbackError::StaleEvaluationWindow);
        }
        Ok(())
    }

    fn content_digest(&self) -> Result<String, AttributionFeedbackError> {
        canonical_digest(&(
            ATTRIBUTION_OUTCOME_FEEDBACK_CONTRACT_VERSION,
            self.revision,
            self.starts_at,
            self.ends_at,
            &self.attribution_window,
            &self.model_version,
        ))
    }
}

/// Internal typed input for the next evaluation window. It freezes the exact
/// receipt event sequence (adoption_revision) and all evidence references,
/// while keeping source content out of the consumer signal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionFeedbackInput {
    pub schema_version: String,
    pub feedback_id: String,
    pub receipt_id: String,
    pub receipt_digest: String,
    pub adoption_revision: u64,
    pub decision: AttributionAdoptionDecision,
    pub scope: AttributionAdoptionScope,
    pub adopted_candidate_id: OutcomeCandidateId,
    pub adopted_candidate_digest: String,
    pub source_event_id: SourceEventId,
    pub evidence_root: String,
    pub next_window: AttributionFeedbackWindow,
    pub input_digest: String,
}

impl AttributionFeedbackInput {
    pub fn from_receipt(
        receipt: &AttributionAdoptionReceipt,
        adoption_revision: u64,
        next_window: AttributionFeedbackWindow,
    ) -> Result<Self, AttributionFeedbackError> {
        receipt
            .scope
            .validate()
            .map_err(|error| AttributionFeedbackError::Adoption(error.to_string()))?;
        next_window.validate_after_receipt(receipt)?;
        if adoption_revision == 0 {
            return Err(AttributionFeedbackError::InvalidAdoptionRevision);
        }
        let mut input = Self {
            schema_version: ATTRIBUTION_OUTCOME_FEEDBACK_SCHEMA_VERSION.into(),
            feedback_id: String::new(),
            receipt_id: receipt.receipt_id.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            adoption_revision,
            decision: receipt.decision,
            scope: receipt.scope.clone(),
            adopted_candidate_id: receipt.candidate_id.clone(),
            adopted_candidate_digest: receipt.candidate_digest.clone(),
            source_event_id: receipt.source_event_id.clone(),
            evidence_root: receipt.evidence_root.clone(),
            next_window,
            input_digest: String::new(),
        };
        input.input_digest = input.content_digest()?;
        input.feedback_id = format!("feedback:{}", input.input_digest);
        input.validate_against_receipt(receipt)?;
        Ok(input)
    }

    pub fn validate_against_receipt(
        &self,
        receipt: &AttributionAdoptionReceipt,
    ) -> Result<(), AttributionFeedbackError> {
        if receipt.schema_version != crate::ATTRIBUTION_OUTCOME_ADOPTION_SCHEMA_VERSION
            || receipt.receipt_id != format!("adoption-receipt:{}", receipt.receipt_digest)
            || !is_sha256(&receipt.receipt_digest)
            || receipt.provider_event_identity.validate().is_err()
            || receipt.window.validate().is_err()
            || receipt.model_version.validate().is_err()
            || self.schema_version != ATTRIBUTION_OUTCOME_FEEDBACK_SCHEMA_VERSION
            || self.feedback_id != format!("feedback:{}", self.input_digest)
            || self.input_digest != self.content_digest()?
            || self.receipt_id != receipt.receipt_id
            || self.receipt_digest != receipt.receipt_digest
            || self.adoption_revision == 0
            || self.decision != receipt.decision
            || self.scope != receipt.scope
            || self.adopted_candidate_id != receipt.candidate_id
            || self.adopted_candidate_digest != receipt.candidate_digest
            || self.source_event_id != receipt.source_event_id
            || self.evidence_root != receipt.evidence_root
        {
            return Err(AttributionFeedbackError::ReceiptBindingMismatch);
        }
        self.next_window.validate_after_receipt(receipt)?;
        if !is_sha256(&self.receipt_digest)
            || !is_sha256(&self.adopted_candidate_digest)
            || !is_sha256(&self.evidence_root)
        {
            return Err(AttributionFeedbackError::InvalidFeedbackInput);
        }
        Ok(())
    }

    fn content_digest(&self) -> Result<String, AttributionFeedbackError> {
        canonical_digest(&(
            &self.schema_version,
            &self.receipt_id,
            &self.receipt_digest,
            self.adoption_revision,
            &self.decision,
            &self.scope,
            &self.adopted_candidate_id,
            &self.adopted_candidate_digest,
            &self.source_event_id,
            &self.evidence_root,
            &self.next_window,
        ))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionFeedbackSignalKind {
    NoNewCandidate,
    NewCandidateAvailable,
}

/// Content-free signal delivered to the consumer. It contains no source
/// payload, amount, provider/account label, or event body.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionFeedbackSignal {
    pub schema_version: String,
    pub feedback_id: String,
    pub decision: AttributionAdoptionDecision,
    pub signal_kind: AttributionFeedbackSignalKind,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub goal_revision: u64,
    pub goal_digest: String,
    pub adoption_revision: u64,
    pub evaluation_window_revision: u64,
    pub evaluation_window_digest: String,
    pub model_version: AttributionModelVersion,
    pub adopted_candidate_digest: String,
    pub evidence_root: String,
    pub new_candidate_digest: Option<String>,
    pub new_evidence_root: Option<String>,
    pub signal_digest: String,
}

impl AttributionFeedbackSignal {
    pub fn from_input(
        input: &AttributionFeedbackInput,
        candidate: Option<&AttributionOutcomeCandidate>,
    ) -> Result<Self, AttributionFeedbackError> {
        input.next_window.validate()?;
        if let Some(candidate) = candidate {
            validate_new_candidate(input, candidate)?;
        }
        let mut signal = Self {
            schema_version: ATTRIBUTION_OUTCOME_FEEDBACK_SCHEMA_VERSION.into(),
            feedback_id: input.feedback_id.clone(),
            decision: input.decision,
            signal_kind: if candidate.is_some() {
                AttributionFeedbackSignalKind::NewCandidateAvailable
            } else {
                AttributionFeedbackSignalKind::NoNewCandidate
            },
            project_id: input.scope.project_id.clone(),
            mission_id: input.scope.mission_id.clone(),
            goal_revision: input.scope.goal_revision,
            goal_digest: input.scope.goal_digest.clone(),
            adoption_revision: input.adoption_revision,
            evaluation_window_revision: input.next_window.revision,
            evaluation_window_digest: input.next_window.window_digest.clone(),
            model_version: input.next_window.model_version.clone(),
            adopted_candidate_digest: input.adopted_candidate_digest.clone(),
            evidence_root: input.evidence_root.clone(),
            new_candidate_digest: candidate.map(|candidate| candidate.candidate_digest.clone()),
            new_evidence_root: candidate.map(|candidate| candidate.evidence_root.clone()),
            signal_digest: String::new(),
        };
        signal.signal_digest = signal.content_digest()?;
        signal.validate_against_input(input, candidate)?;
        Ok(signal)
    }

    pub fn validate_against_input(
        &self,
        input: &AttributionFeedbackInput,
        candidate: Option<&AttributionOutcomeCandidate>,
    ) -> Result<(), AttributionFeedbackError> {
        if self.schema_version != ATTRIBUTION_OUTCOME_FEEDBACK_SCHEMA_VERSION
            || self.feedback_id != input.feedback_id
            || self.decision != input.decision
            || self.project_id != input.scope.project_id
            || self.mission_id != input.scope.mission_id
            || self.goal_revision != input.scope.goal_revision
            || self.goal_digest != input.scope.goal_digest
            || self.adoption_revision != input.adoption_revision
            || self.evaluation_window_revision != input.next_window.revision
            || self.evaluation_window_digest != input.next_window.window_digest
            || self.model_version != input.next_window.model_version
            || self.adopted_candidate_digest != input.adopted_candidate_digest
            || self.evidence_root != input.evidence_root
            || self.signal_digest != self.content_digest()?
        {
            return Err(AttributionFeedbackError::SignalDigestMismatch);
        }
        let expected_kind = if candidate.is_some() {
            AttributionFeedbackSignalKind::NewCandidateAvailable
        } else {
            AttributionFeedbackSignalKind::NoNewCandidate
        };
        if self.signal_kind != expected_kind {
            return Err(AttributionFeedbackError::SignalDigestMismatch);
        }
        match candidate {
            Some(candidate)
                if self.new_candidate_digest.as_deref()
                    == Some(candidate.candidate_digest.as_str())
                    && self.new_evidence_root.as_deref()
                        == Some(candidate.evidence_root.as_str()) =>
            {
                validate_new_candidate(input, candidate)?;
            }
            Some(_) => return Err(AttributionFeedbackError::SignalDigestMismatch),
            None if self.new_candidate_digest.is_some() || self.new_evidence_root.is_some() => {
                return Err(AttributionFeedbackError::SignalDigestMismatch);
            }
            None => {}
        }
        Ok(())
    }

    fn content_digest(&self) -> Result<String, AttributionFeedbackError> {
        canonical_digest(&(
            &self.schema_version,
            &self.feedback_id,
            &self.decision,
            &self.signal_kind,
            &self.project_id,
            &self.mission_id,
            self.goal_revision,
            &self.goal_digest,
            self.adoption_revision,
            self.evaluation_window_revision,
            &self.evaluation_window_digest,
            &self.model_version,
            &self.adopted_candidate_digest,
            &self.evidence_root,
            &self.new_candidate_digest,
            &self.new_evidence_root,
        ))
    }
}

/// Durable feedback record. new_candidate_id is an internal exact reference;
/// the consumer only receives AttributionFeedbackSignal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionFeedbackRecord {
    pub schema_version: String,
    pub input: AttributionFeedbackInput,
    pub new_candidate_id: Option<OutcomeCandidateId>,
    pub signal: AttributionFeedbackSignal,
    pub feedback_digest: String,
}

impl AttributionFeedbackRecord {
    pub fn from_input(
        input: AttributionFeedbackInput,
        candidate: Option<&AttributionOutcomeCandidate>,
    ) -> Result<Self, AttributionFeedbackError> {
        let signal = AttributionFeedbackSignal::from_input(&input, candidate)?;
        let mut record = Self {
            schema_version: ATTRIBUTION_OUTCOME_FEEDBACK_SCHEMA_VERSION.into(),
            input,
            new_candidate_id: candidate.map(|candidate| candidate.candidate_id.clone()),
            signal,
            feedback_digest: String::new(),
        };
        record.feedback_digest = record.content_digest()?;
        record.validate(candidate)?;
        Ok(record)
    }

    pub fn validate(
        &self,
        candidate: Option<&AttributionOutcomeCandidate>,
    ) -> Result<(), AttributionFeedbackError> {
        if self.schema_version != ATTRIBUTION_OUTCOME_FEEDBACK_SCHEMA_VERSION
            || self.feedback_digest != self.content_digest()?
            || self.new_candidate_id != candidate.map(|candidate| candidate.candidate_id.clone())
        {
            return Err(AttributionFeedbackError::FeedbackDigestMismatch);
        }
        self.input.next_window.validate()?;
        self.signal.validate_against_input(&self.input, candidate)?;
        Ok(())
    }

    fn content_digest(&self) -> Result<String, AttributionFeedbackError> {
        canonical_digest(&(
            &self.schema_version,
            &self.input,
            &self.new_candidate_id,
            &self.signal,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionFeedbackSnapshot {
    pub schema_version: String,
    pub project_id: ProjectId,
    pub records: Vec<AttributionFeedbackRecord>,
}

impl AttributionFeedbackSnapshot {
    pub fn new(
        project_id: ProjectId,
        records: Vec<AttributionFeedbackRecord>,
    ) -> Result<Self, AttributionFeedbackError> {
        let snapshot = Self {
            schema_version: ATTRIBUTION_OUTCOME_FEEDBACK_SCHEMA_VERSION.into(),
            project_id,
            records,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn validate(&self) -> Result<(), AttributionFeedbackError> {
        if self.schema_version != ATTRIBUTION_OUTCOME_FEEDBACK_SCHEMA_VERSION
            || self.project_id.as_str().trim().is_empty()
        {
            return Err(AttributionFeedbackError::InvalidFeedbackSnapshot);
        }
        let mut feedback_ids = BTreeSet::new();
        let mut input_keys = BTreeSet::new();
        for record in &self.records {
            if !feedback_ids.insert(record.input.feedback_id.clone())
                || !input_keys.insert((
                    record.input.receipt_id.clone(),
                    record.input.next_window.revision,
                ))
            {
                return Err(AttributionFeedbackError::DuplicateFeedback);
            }
            if record.input.scope.project_id != self.project_id
                || record.signal.project_id != self.project_id
            {
                return Err(AttributionFeedbackError::CrossMissionScope);
            }
        }
        Ok(())
    }
}

fn validate_new_candidate(
    input: &AttributionFeedbackInput,
    candidate: &AttributionOutcomeCandidate,
) -> Result<(), AttributionFeedbackError> {
    if candidate.scope != input.scope
        || candidate.window != input.next_window.attribution_window
        || candidate.model_version != input.next_window.model_version
        || candidate.source_event_id == input.source_event_id
        || !is_sha256(&candidate.candidate_digest)
        || !is_sha256(&candidate.evidence_root)
    {
        return Err(AttributionFeedbackError::CandidateBindingMismatch);
    }
    Ok(())
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, AttributionFeedbackError> {
    let bytes = serde_json::to_vec(value).map_err(AttributionFeedbackError::Serialization)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug, Error)]
pub enum AttributionFeedbackError {
    #[error("attribution feedback evaluation window is invalid")]
    InvalidEvaluationWindow,
    #[error("attribution feedback evaluation window is stale")]
    StaleEvaluationWindow,
    #[error("attribution feedback adoption revision is invalid")]
    InvalidAdoptionRevision,
    #[error("attribution feedback input is malformed")]
    InvalidFeedbackInput,
    #[error("attribution feedback receipt binding is stale or swapped")]
    ReceiptBindingMismatch,
    #[error("attribution feedback candidate binding is stale or cross-scope")]
    CandidateBindingMismatch,
    #[error("attribution feedback signal digest is invalid")]
    SignalDigestMismatch,
    #[error("attribution feedback record digest is invalid")]
    FeedbackDigestMismatch,
    #[error("attribution feedback snapshot is invalid")]
    InvalidFeedbackSnapshot,
    #[error("attribution feedback is duplicated with different content")]
    DuplicateFeedback,
    #[error("attribution feedback crosses Project or Mission scope")]
    CrossMissionScope,
    #[error("adoption contract is invalid: {0}")]
    Adoption(String),
    #[error("attribution feedback serialization failed: {0}")]
    Serialization(serde_json::Error),
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};

    use super::*;
    use crate::{ActorId, CurrencyCode};

    fn at(minute: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 8, 0, 0)
            .single()
            .expect("time")
            + Duration::minutes(minute)
    }

    fn receipt(decision: AttributionAdoptionDecision) -> AttributionAdoptionReceipt {
        AttributionAdoptionReceipt {
            schema_version: crate::ATTRIBUTION_OUTCOME_ADOPTION_SCHEMA_VERSION.into(),
            receipt_id: format!("adoption-receipt:{}", "e".repeat(64)),
            decision,
            actor_id: ActorId::from("human-1"),
            consumer_id: "consumer".into(),
            consumer_digest: "a".repeat(64),
            scope: AttributionAdoptionScope::new(
                crate::TenantId::from("tenant-1"),
                ProjectId::from("project-1"),
                MissionId::from("mission-1"),
                1,
                "b".repeat(64),
            )
            .expect("scope"),
            candidate_id: crate::OutcomeCandidateId::from_stable("candidate:1"),
            candidate_digest: "c".repeat(64),
            source_event_id: SourceEventId::from_stable("source:1"),
            provider_event_identity: crate::ProviderEventIdentity::new("meta", "acct-1", "event-1")
                .expect("identity"),
            reporting_currency: CurrencyCode::parse("USD").expect("USD"),
            window: AttributionWindow {
                version: 1,
                click_lookback_seconds: 1,
                view_lookback_seconds: 1,
                effective_at: at(0),
            },
            model_version: AttributionModelVersion::new("model.v1").expect("model"),
            evidence_root: "d".repeat(64),
            idempotency_key: "decision-1".into(),
            decided_at: at(10),
            receipt_digest: "e".repeat(64),
        }
    }

    #[test]
    fn feedback_input_binds_receipt_and_content_free_signal() {
        let receipt = receipt(AttributionAdoptionDecision::Adopt);
        let next_window = AttributionFeedbackWindow::new(
            2,
            at(11),
            at(20),
            AttributionWindow {
                version: 2,
                click_lookback_seconds: 1,
                view_lookback_seconds: 1,
                effective_at: at(11),
            },
            AttributionModelVersion::new("model.v2").expect("model"),
        )
        .expect("window");
        let input =
            AttributionFeedbackInput::from_receipt(&receipt, 7, next_window).expect("input");
        let signal =
            AttributionFeedbackSignal::from_input(&input, None).expect("content-free signal");
        assert_eq!(
            signal.signal_kind,
            AttributionFeedbackSignalKind::NoNewCandidate
        );
        let json = serde_json::to_string(&signal).expect("json");
        assert!(!json.contains("acct-1"));
        assert!(!json.contains("event-1"));
        assert!(json.contains(&input.evidence_root));
    }

    #[test]
    fn feedback_rejects_stale_window_and_cross_scope_candidate() {
        let receipt_value = receipt(AttributionAdoptionDecision::Reject);
        let stale = AttributionFeedbackWindow::new(
            1,
            at(11),
            at(20),
            receipt_value.window.clone(),
            receipt_value.model_version.clone(),
        )
        .expect("window");
        assert!(matches!(
            AttributionFeedbackInput::from_receipt(&receipt_value, 7, stale),
            Err(AttributionFeedbackError::StaleEvaluationWindow)
        ));

        let mut tampered = receipt(AttributionAdoptionDecision::Reject);
        tampered.receipt_id = "adoption-receipt:tampered".into();
        let valid_window = AttributionFeedbackWindow::new(
            2,
            at(11),
            at(20),
            AttributionWindow {
                version: 2,
                click_lookback_seconds: 1,
                view_lookback_seconds: 1,
                effective_at: at(11),
            },
            AttributionModelVersion::new("model.v2").expect("model"),
        )
        .expect("window");
        assert!(matches!(
            AttributionFeedbackInput::from_receipt(&tampered, 7, valid_window),
            Err(AttributionFeedbackError::ReceiptBindingMismatch)
        ));
    }
}
