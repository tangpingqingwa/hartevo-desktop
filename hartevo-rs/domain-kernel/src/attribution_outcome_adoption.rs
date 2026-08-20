//! Revision-bound attribution outcome adoption contracts.
//!
//! The adoption consumer is intentionally narrower than the generic plugin
//! runtime. It consumes only an already verified provider event from the
//! attribution spine, freezes the exact Project/Mission/goal scope and
//! evidence inputs, and emits an immutable user decision receipt. It does not
//! manufacture provider facts, infer causality, or grant any runtime authority.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    ActorId, AttributionAssignment, AttributionError, AttributionLedger, AttributionWindow,
    Mission, MissionId, ObservationOrigin, OutcomeCandidate, OutcomeCandidateId, ProjectId,
    ProviderEventIdentity, SourceEventId, TenantId, VerifiedOutcome,
};

pub const ATTRIBUTION_OUTCOME_ADOPTION_SCHEMA_VERSION: &str =
    "hartevo-attribution-outcome-adoption/v1";
pub const ATTRIBUTION_OUTCOME_ADOPTION_CONTRACT_VERSION: &str = "attribution-outcome-adoption/v1";
pub const ATTRIBUTION_SPINE_CANDIDATE_EVENT_TYPE: &str = "attribution-spine.outcome-candidate/v1";
pub const ATTRIBUTION_SPINE_VERIFIED_OUTCOME_EVENT_TYPE: &str =
    "attribution-spine.verified-outcome/v1";
pub const ATTRIBUTION_ADOPTION_CONSUMER_MOUNT_EVENT_TYPE: &str =
    "attribution-adoption.consumer-mounted/v1";
pub const ATTRIBUTION_ADOPTION_CONSUMER_UNMOUNT_EVENT_TYPE: &str =
    "attribution-adoption.consumer-unmounted/v1";
pub const ATTRIBUTION_ADOPTION_CONSUMER_REVOKE_EVENT_TYPE: &str =
    "attribution-adoption.consumer-revoked/v1";
pub const ATTRIBUTION_ADOPTION_CANDIDATE_EVENT_TYPE: &str =
    "attribution-adoption.outcome-candidate/v1";
pub const ATTRIBUTION_ADOPTION_RECEIPT_EVENT_TYPE: &str = "attribution-adoption.receipt/v1";

/// A versioned attribution model identifier. A plain free-form model string
/// is not allowed to cross the adoption boundary.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AttributionModelVersion(String);

impl AttributionModelVersion {
    pub fn new(value: impl Into<String>) -> Result<Self, AttributionAdoptionError> {
        let value = value.into();
        let model = Self(value);
        model.validate()?;
        Ok(model)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<(), AttributionAdoptionError> {
        if !valid_identifier(&self.0) {
            return Err(AttributionAdoptionError::InvalidModelVersion);
        }
        Ok(())
    }
}

/// Exact Project/Mission/goal revision scope consumed by one adoption
/// consumer. The goal digest is derived from the persisted Mission contract
/// at mount time and is never guessed by the consumer.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionAdoptionScope {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub goal_revision: u64,
    pub goal_digest: String,
}

impl AttributionAdoptionScope {
    pub fn new(
        tenant_id: TenantId,
        project_id: ProjectId,
        mission_id: MissionId,
        goal_revision: u64,
        goal_digest: impl Into<String>,
    ) -> Result<Self, AttributionAdoptionError> {
        let scope = Self {
            tenant_id,
            project_id,
            mission_id,
            goal_revision,
            goal_digest: goal_digest.into(),
        };
        scope.validate()?;
        Ok(scope)
    }

    /// Builds the scope from the persisted Mission rather than accepting a
    /// caller-provided goal digest.
    pub fn from_mission(mission: &Mission) -> Result<Self, AttributionAdoptionError> {
        Self::new(
            mission.tenant_id.clone(),
            mission.project_id.clone(),
            mission.id.clone(),
            mission.revision,
            sha256(mission.contract.goal.as_bytes()),
        )
    }

    pub fn validate(&self) -> Result<(), AttributionAdoptionError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.goal_revision == 0
            || !is_sha256(&self.goal_digest)
        {
            return Err(AttributionAdoptionError::InvalidAdoptionScope);
        }
        Ok(())
    }

    pub fn validate_against_mission(
        &self,
        mission: &Mission,
    ) -> Result<(), AttributionAdoptionError> {
        self.validate()?;
        if self.tenant_id != mission.tenant_id
            || self.project_id != mission.project_id
            || self.mission_id != mission.id
            || self.goal_revision != mission.revision
            || self.goal_digest != sha256(mission.contract.goal.as_bytes())
        {
            return Err(AttributionAdoptionError::AdoptionScopeMismatch);
        }
        Ok(())
    }
}

/// Identity of the narrow attribution outcome consumer. The manifest digest
/// is the only plugin identity accepted by this slice; no connector or
/// runtime registry is implicitly consulted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionAdoptionConsumer {
    pub consumer_id: String,
    pub plugin_id: String,
    pub plugin_version: u32,
    pub manifest_digest: String,
    pub scope: AttributionAdoptionScope,
    pub generation: u64,
    pub consumer_digest: String,
}

impl AttributionAdoptionConsumer {
    pub fn new(
        consumer_id: impl Into<String>,
        plugin_id: impl Into<String>,
        plugin_version: u32,
        manifest_digest: impl Into<String>,
        scope: AttributionAdoptionScope,
        generation: u64,
    ) -> Result<Self, AttributionAdoptionError> {
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

    pub fn validate(&self) -> Result<(), AttributionAdoptionError> {
        if !valid_identifier(&self.consumer_id)
            || !valid_identifier(&self.plugin_id)
            || self.plugin_version == 0
            || self.generation == 0
            || !is_sha256(&self.manifest_digest)
            || self.consumer_digest != self.content_digest()?
        {
            return Err(AttributionAdoptionError::InvalidConsumerIdentity);
        }
        self.scope.validate()
    }

    fn content_digest(&self) -> Result<String, AttributionAdoptionError> {
        canonical_digest(&(
            ATTRIBUTION_OUTCOME_ADOPTION_CONTRACT_VERSION,
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
pub enum AttributionAdoptionConsumerState {
    Active,
    Unmounted,
    Revoked,
}

/// Durable lifecycle record for the attribution consumer. A terminal record
/// remains in replay so old receipts can still be audited, but it can never
/// authorize a new candidate or decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionAdoptionConsumerRecord {
    pub consumer: AttributionAdoptionConsumer,
    pub state: AttributionAdoptionConsumerState,
    pub changed_at: DateTime<Utc>,
    pub reason_digest: Option<String>,
}

impl AttributionAdoptionConsumerRecord {
    pub fn active(
        consumer: AttributionAdoptionConsumer,
        changed_at: DateTime<Utc>,
    ) -> Result<Self, AttributionAdoptionError> {
        let record = Self {
            consumer,
            state: AttributionAdoptionConsumerState::Active,
            changed_at,
            reason_digest: None,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn transition(
        &self,
        state: AttributionAdoptionConsumerState,
        changed_at: DateTime<Utc>,
        reason_digest: String,
    ) -> Result<Self, AttributionAdoptionError> {
        self.validate()?;
        if self.state != AttributionAdoptionConsumerState::Active
            || state == AttributionAdoptionConsumerState::Active
            || changed_at < self.changed_at
        {
            return Err(AttributionAdoptionError::InvalidConsumerTransition);
        }
        let record = Self {
            consumer: self.consumer.clone(),
            state,
            changed_at,
            reason_digest: Some(reason_digest),
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), AttributionAdoptionError> {
        self.consumer.validate()?;
        match self.state {
            AttributionAdoptionConsumerState::Active => {
                if self.reason_digest.is_some() {
                    return Err(AttributionAdoptionError::InvalidConsumerRecord);
                }
            }
            AttributionAdoptionConsumerState::Unmounted
            | AttributionAdoptionConsumerState::Revoked => {
                if self
                    .reason_digest
                    .as_deref()
                    .is_none_or(|digest| !is_sha256(digest))
                {
                    return Err(AttributionAdoptionError::InvalidConsumerRecord);
                }
            }
        }
        Ok(())
    }
}

/// The exact durable input to an adoption decision. It includes the source
/// identity and verification, not merely an amount or a provider label.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionOutcomeCandidate {
    pub schema_version: String,
    pub candidate_id: OutcomeCandidateId,
    pub consumer_id: String,
    pub consumer_digest: String,
    pub scope: AttributionAdoptionScope,
    pub reporting_currency: crate::CurrencyCode,
    pub source_event_id: SourceEventId,
    pub provider_event_identity: ProviderEventIdentity,
    pub source_candidate: OutcomeCandidate,
    pub verified_outcome: VerifiedOutcome,
    pub assignment: AttributionAssignment,
    pub source_ledger_revision: u64,
    pub projection_digest: String,
    pub window: AttributionWindow,
    pub model_version: AttributionModelVersion,
    pub evidence_root: String,
    pub candidate_digest: String,
}

impl AttributionOutcomeCandidate {
    /// Derives one deterministic candidate from the latest real, verified
    /// provider outcome in the exact Mission scope. `None` is the honest
    /// result when the ledger has no such source event.
    pub fn from_verified_ledger(
        ledger: &AttributionLedger,
        consumer: &AttributionAdoptionConsumer,
        window: AttributionWindow,
        model_version: AttributionModelVersion,
    ) -> Result<Option<Self>, AttributionAdoptionError> {
        consumer.validate()?;
        window.validate().map_err(|error| spine_error(&error))?;
        model_version.validate()?;
        if ledger.tenant_id != consumer.scope.tenant_id
            || ledger.project_id != consumer.scope.project_id
        {
            return Err(AttributionAdoptionError::AdoptionScopeMismatch);
        }
        ledger.validate().map_err(|error| spine_error(&error))?;
        let projection = ledger
            .replay(window.clone())
            .map_err(|error| spine_error(&error))?;
        let Some(assignment) =
            latest_verified_assignment(ledger, &projection, &consumer.scope.mission_id)
        else {
            return Ok(None);
        };
        let (source_event, source_candidate, verified_outcome) =
            verified_source(ledger, assignment)?;
        if source_event.mission_id.as_ref() != Some(&consumer.scope.mission_id)
            || source_candidate.source_event_id != source_event.id
            || verified_outcome.source_event_id != source_event.id
        {
            return Err(AttributionAdoptionError::AdoptionScopeMismatch);
        }
        let projection_digest = projection.digest().map_err(|error| spine_error(&error))?;
        let evidence_root = evidence_root(&EvidenceRootInput {
            consumer,
            ledger,
            source_event,
            source_candidate,
            verified_outcome,
            assignment,
            projection_digest: &projection_digest,
            window: &window,
            model_version: &model_version,
        })?;
        let candidate_id = expected_candidate_id(
            consumer,
            source_event,
            source_candidate,
            &window,
            &model_version,
        )?;
        let mut candidate = Self {
            schema_version: ATTRIBUTION_OUTCOME_ADOPTION_SCHEMA_VERSION.into(),
            candidate_id,
            consumer_id: consumer.consumer_id.clone(),
            consumer_digest: consumer.consumer_digest.clone(),
            scope: consumer.scope.clone(),
            reporting_currency: ledger.reporting_currency.clone(),
            source_event_id: source_event.id.clone(),
            provider_event_identity: source_event.identity.clone(),
            source_candidate: source_candidate.clone(),
            verified_outcome: verified_outcome.clone(),
            assignment: assignment.clone(),
            source_ledger_revision: projection.ledger_revision,
            projection_digest,
            window,
            model_version,
            evidence_root,
            candidate_digest: String::new(),
        };
        candidate.candidate_digest = candidate.content_digest()?;
        candidate.validate_with_ledger(ledger, consumer)?;
        Ok(Some(candidate))
    }

    pub fn validate_with_ledger(
        &self,
        ledger: &AttributionLedger,
        consumer: &AttributionAdoptionConsumer,
    ) -> Result<(), AttributionAdoptionError> {
        self.validate_basic(consumer)?;
        ledger.validate().map_err(|error| spine_error(&error))?;
        if ledger.tenant_id != self.scope.tenant_id
            || ledger.project_id != self.scope.project_id
            || ledger.reporting_currency != self.reporting_currency
        {
            return Err(AttributionAdoptionError::AdoptionScopeMismatch);
        }
        let source_event = ledger
            .events
            .iter()
            .find(|event| event.id == self.source_event_id)
            .ok_or(AttributionAdoptionError::CandidateSourceMismatch)?;
        let source_candidate = ledger
            .candidates
            .iter()
            .find(|candidate| candidate.id == self.source_candidate.id)
            .ok_or(AttributionAdoptionError::CandidateSourceMismatch)?;
        let verified_outcome = ledger
            .verified_outcomes
            .iter()
            .find(|verified| verified.id == self.verified_outcome.id)
            .ok_or(AttributionAdoptionError::VerifiedOutcomeMismatch)?;
        if source_event.tenant_id != self.scope.tenant_id
            || source_event.project_id != self.scope.project_id
            || source_event.mission_id.as_ref() != Some(&self.scope.mission_id)
            || source_event.identity != self.provider_event_identity
            || source_event
                .canonical_digest()
                .map_err(|error| spine_error(&error))?
                != self.source_candidate.source_event_digest
            || *source_candidate != self.source_candidate
            || *verified_outcome != self.verified_outcome
            || self.assignment.candidate_id != self.source_candidate.id
            || self.assignment.source_event_id != self.source_event_id
            || self.assignment.amount != self.source_candidate.amount
            || self.assignment.window_version != self.window.version
            || self.assignment.causal_claim
            || !matches!(
                source_event.provenance.origin,
                ObservationOrigin::FirstParty | ObservationOrigin::PartnerNetwork
            )
        {
            return Err(AttributionAdoptionError::CandidateSourceMismatch);
        }
        if self.candidate_id
            != expected_candidate_id(
                consumer,
                source_event,
                &self.source_candidate,
                &self.window,
                &self.model_version,
            )?
        {
            return Err(AttributionAdoptionError::CandidateDigestMismatch);
        }
        let expected_evidence_root = evidence_root(&EvidenceRootInput {
            consumer,
            ledger,
            source_event,
            source_candidate: &self.source_candidate,
            verified_outcome: &self.verified_outcome,
            assignment: &self.assignment,
            projection_digest: &self.projection_digest,
            window: &self.window,
            model_version: &self.model_version,
        })?;
        if self.evidence_root != expected_evidence_root
            || self.candidate_digest != self.content_digest()?
        {
            return Err(AttributionAdoptionError::CandidateDigestMismatch);
        }
        Ok(())
    }

    fn validate_basic(
        &self,
        consumer: &AttributionAdoptionConsumer,
    ) -> Result<(), AttributionAdoptionError> {
        if self.schema_version != ATTRIBUTION_OUTCOME_ADOPTION_SCHEMA_VERSION
            || self.consumer_id != consumer.consumer_id
            || self.consumer_digest != consumer.consumer_digest
            || self.scope != consumer.scope
            || self.source_event_id.as_str().trim().is_empty()
            || self.candidate_id.as_str().trim().is_empty()
            || self.source_ledger_revision == 0
            || !is_sha256(&self.projection_digest)
            || !is_sha256(&self.evidence_root)
            || !is_sha256(&self.candidate_digest)
        {
            return Err(AttributionAdoptionError::InvalidOutcomeCandidate);
        }
        self.scope.validate()?;
        self.provider_event_identity
            .validate()
            .map_err(|error| spine_error(&error))?;
        self.window
            .validate()
            .map_err(|error| spine_error(&error))?;
        self.model_version.validate()?;
        Ok(())
    }

    fn content_digest(&self) -> Result<String, AttributionAdoptionError> {
        canonical_digest(&(
            &self.schema_version,
            &self.candidate_id,
            &self.consumer_id,
            &self.consumer_digest,
            &self.scope,
            &self.reporting_currency,
            &self.source_event_id,
            &self.provider_event_identity,
            &self.source_candidate,
            &self.verified_outcome,
            &self.assignment,
            self.source_ledger_revision,
            &self.projection_digest,
            &self.window,
            &self.model_version,
            &self.evidence_root,
        ))
    }
}

/// Candidate identity and exact evidence reference carried by a user
/// adoption or rejection receipt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionAdoptionDecision {
    Adopt,
    Reject,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionAdoptionReceipt {
    pub schema_version: String,
    pub receipt_id: String,
    pub decision: AttributionAdoptionDecision,
    pub actor_id: ActorId,
    pub consumer_id: String,
    pub consumer_digest: String,
    pub scope: AttributionAdoptionScope,
    pub candidate_id: OutcomeCandidateId,
    pub candidate_digest: String,
    pub source_event_id: SourceEventId,
    pub provider_event_identity: ProviderEventIdentity,
    pub reporting_currency: crate::CurrencyCode,
    pub window: AttributionWindow,
    pub model_version: AttributionModelVersion,
    pub evidence_root: String,
    pub idempotency_key: String,
    pub decided_at: DateTime<Utc>,
    pub receipt_digest: String,
}

impl AttributionAdoptionReceipt {
    pub fn from_candidate(
        candidate: &AttributionOutcomeCandidate,
        decision: AttributionAdoptionDecision,
        actor_id: ActorId,
        idempotency_key: impl Into<String>,
        decided_at: DateTime<Utc>,
    ) -> Result<Self, AttributionAdoptionError> {
        candidate.scope.validate()?;
        if actor_id.as_str().trim().is_empty() {
            return Err(AttributionAdoptionError::InvalidReceipt);
        }
        let mut receipt = Self {
            schema_version: ATTRIBUTION_OUTCOME_ADOPTION_SCHEMA_VERSION.into(),
            receipt_id: String::new(),
            decision,
            actor_id,
            consumer_id: candidate.consumer_id.clone(),
            consumer_digest: candidate.consumer_digest.clone(),
            scope: candidate.scope.clone(),
            candidate_id: candidate.candidate_id.clone(),
            candidate_digest: candidate.candidate_digest.clone(),
            source_event_id: candidate.source_event_id.clone(),
            provider_event_identity: candidate.provider_event_identity.clone(),
            reporting_currency: candidate.reporting_currency.clone(),
            window: candidate.window.clone(),
            model_version: candidate.model_version.clone(),
            evidence_root: candidate.evidence_root.clone(),
            idempotency_key: idempotency_key.into(),
            decided_at,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.content_digest()?;
        receipt.receipt_id = format!("adoption-receipt:{}", receipt.receipt_digest);
        receipt.validate_for_candidate(candidate)?;
        Ok(receipt)
    }

    pub fn validate_for_candidate(
        &self,
        candidate: &AttributionOutcomeCandidate,
    ) -> Result<(), AttributionAdoptionError> {
        if self.schema_version != ATTRIBUTION_OUTCOME_ADOPTION_SCHEMA_VERSION
            || self.receipt_id != format!("adoption-receipt:{}", self.receipt_digest)
            || self.receipt_digest != self.content_digest()?
            || self.consumer_id != candidate.consumer_id
            || self.consumer_digest != candidate.consumer_digest
            || self.scope != candidate.scope
            || self.candidate_id != candidate.candidate_id
            || self.candidate_digest != candidate.candidate_digest
            || self.source_event_id != candidate.source_event_id
            || self.provider_event_identity != candidate.provider_event_identity
            || self.reporting_currency != candidate.reporting_currency
            || self.window != candidate.window
            || self.model_version != candidate.model_version
            || self.evidence_root != candidate.evidence_root
            || self.idempotency_key.trim().is_empty()
        {
            return Err(AttributionAdoptionError::InvalidReceipt);
        }
        self.scope.validate()?;
        self.provider_event_identity
            .validate()
            .map_err(|error| spine_error(&error))?;
        self.window
            .validate()
            .map_err(|error| spine_error(&error))?;
        self.model_version.validate()?;
        if !is_sha256(&self.candidate_digest) || !is_sha256(&self.evidence_root) {
            return Err(AttributionAdoptionError::InvalidReceipt);
        }
        Ok(())
    }

    fn content_digest(&self) -> Result<String, AttributionAdoptionError> {
        canonical_digest(&(
            &self.schema_version,
            &self.decision,
            &self.actor_id,
            &self.consumer_id,
            &self.consumer_digest,
            &self.scope,
            &self.candidate_id,
            &self.candidate_digest,
            &self.source_event_id,
            &self.provider_event_identity,
            &self.reporting_currency,
            &self.window,
            &self.model_version,
            &self.evidence_root,
            &self.idempotency_key,
            self.decided_at,
        ))
    }
}

/// Typed replay projection for the adoption event stream.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionAdoptionSnapshot {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub consumers: Vec<AttributionAdoptionConsumerRecord>,
    pub candidates: Vec<AttributionOutcomeCandidate>,
    pub receipts: Vec<AttributionAdoptionReceipt>,
}

impl AttributionAdoptionSnapshot {
    pub fn new(
        tenant_id: TenantId,
        project_id: ProjectId,
        consumers: Vec<AttributionAdoptionConsumerRecord>,
        candidates: Vec<AttributionOutcomeCandidate>,
        receipts: Vec<AttributionAdoptionReceipt>,
    ) -> Result<Self, AttributionAdoptionError> {
        let snapshot = Self {
            schema_version: ATTRIBUTION_OUTCOME_ADOPTION_SCHEMA_VERSION.into(),
            tenant_id,
            project_id,
            consumers,
            candidates,
            receipts,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn validate(&self) -> Result<(), AttributionAdoptionError> {
        if self.schema_version != ATTRIBUTION_OUTCOME_ADOPTION_SCHEMA_VERSION
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
        {
            return Err(AttributionAdoptionError::InvalidAdoptionSnapshot);
        }
        let mut consumer_ids = BTreeSet::new();
        for record in &self.consumers {
            record.validate()?;
            if record.consumer.scope.tenant_id != self.tenant_id
                || record.consumer.scope.project_id != self.project_id
                || !consumer_ids.insert(record.consumer.consumer_id.clone())
            {
                return Err(AttributionAdoptionError::AdoptionScopeMismatch);
            }
        }
        let consumers = self
            .consumers
            .iter()
            .map(|record| (record.consumer.consumer_id.clone(), &record.consumer))
            .collect::<BTreeMap<_, _>>();
        let mut candidate_ids = BTreeSet::new();
        for candidate in &self.candidates {
            let consumer = consumers
                .get(&candidate.consumer_id)
                .copied()
                .ok_or(AttributionAdoptionError::ConsumerNotMounted)?;
            candidate.validate_basic(consumer)?;
            if !candidate_ids.insert(candidate.candidate_id.clone()) {
                return Err(AttributionAdoptionError::DuplicateOutcomeCandidate);
            }
        }
        let candidates = self
            .candidates
            .iter()
            .map(|candidate| (candidate.candidate_id.clone(), candidate))
            .collect::<BTreeMap<_, _>>();
        let mut receipt_ids = BTreeSet::new();
        let mut idempotency_keys = BTreeSet::new();
        for receipt in &self.receipts {
            let candidate = candidates
                .get(&receipt.candidate_id)
                .copied()
                .ok_or(AttributionAdoptionError::ReceiptCandidateMismatch)?;
            receipt.validate_for_candidate(candidate)?;
            if !receipt_ids.insert(receipt.receipt_id.clone())
                || !idempotency_keys
                    .insert((receipt.consumer_id.clone(), receipt.idempotency_key.clone()))
            {
                return Err(AttributionAdoptionError::DuplicateAdoptionReceipt);
            }
        }
        Ok(())
    }

    pub fn validate_with_ledger(
        &self,
        ledger: &AttributionLedger,
    ) -> Result<(), AttributionAdoptionError> {
        self.validate()?;
        if ledger.tenant_id != self.tenant_id || ledger.project_id != self.project_id {
            return Err(AttributionAdoptionError::AdoptionScopeMismatch);
        }
        let consumers = self
            .consumers
            .iter()
            .map(|record| (record.consumer.consumer_id.clone(), &record.consumer))
            .collect::<BTreeMap<_, _>>();
        for candidate in &self.candidates {
            let consumer = consumers
                .get(&candidate.consumer_id)
                .copied()
                .ok_or(AttributionAdoptionError::ConsumerNotMounted)?;
            candidate.validate_with_ledger(ledger, consumer)?;
        }
        Ok(())
    }
}

/// Payload used for a durable verification event. The source candidate and
/// provider event remain resolved from the ledger, preventing a second,
/// caller-controlled identity graph.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionVerificationRecord {
    pub candidate_id: OutcomeCandidateId,
    pub verification: crate::OutcomeVerification,
}

impl AttributionVerificationRecord {
    pub fn validate(&self) -> Result<(), AttributionAdoptionError> {
        if self.candidate_id.as_str().trim().is_empty() {
            return Err(AttributionAdoptionError::InvalidVerificationRecord);
        }
        Ok(())
    }
}

struct EvidenceRootInput<'a> {
    consumer: &'a AttributionAdoptionConsumer,
    ledger: &'a AttributionLedger,
    source_event: &'a crate::SourceEvent,
    source_candidate: &'a OutcomeCandidate,
    verified_outcome: &'a VerifiedOutcome,
    assignment: &'a AttributionAssignment,
    projection_digest: &'a str,
    window: &'a AttributionWindow,
    model_version: &'a AttributionModelVersion,
}

fn evidence_root(input: &EvidenceRootInput<'_>) -> Result<String, AttributionAdoptionError> {
    canonical_digest(&(
        ATTRIBUTION_OUTCOME_ADOPTION_SCHEMA_VERSION,
        &input.consumer.consumer_digest,
        &input.consumer.scope,
        &input.ledger.reporting_currency,
        &input.source_event.id,
        input
            .source_event
            .canonical_digest()
            .map_err(|error| spine_error(&error))?,
        &input.source_event.identity,
        input.source_candidate,
        input.verified_outcome,
        input.assignment,
        input.projection_digest,
        input.window,
        input.model_version,
    ))
}

fn latest_verified_assignment<'a>(
    ledger: &'a AttributionLedger,
    projection: &'a crate::AttributionProjection,
    mission_id: &MissionId,
) -> Option<&'a AttributionAssignment> {
    projection
        .assignments
        .iter()
        .filter(|assignment| {
            ledger
                .events
                .iter()
                .find(|event| event.id == assignment.source_event_id)
                .is_some_and(|event| {
                    event.mission_id.as_ref() == Some(mission_id)
                        && matches!(
                            event.provenance.origin,
                            ObservationOrigin::FirstParty | ObservationOrigin::PartnerNetwork
                        )
                })
        })
        .max_by(|left, right| {
            let left_event = ledger
                .events
                .iter()
                .find(|event| event.id == left.source_event_id);
            let right_event = ledger
                .events
                .iter()
                .find(|event| event.id == right.source_event_id);
            left_event
                .map(|event| event.observed_at)
                .cmp(&right_event.map(|event| event.observed_at))
                .then_with(|| left.source_event_id.cmp(&right.source_event_id))
        })
}

fn verified_source<'a>(
    ledger: &'a AttributionLedger,
    assignment: &AttributionAssignment,
) -> Result<
    (
        &'a crate::SourceEvent,
        &'a OutcomeCandidate,
        &'a VerifiedOutcome,
    ),
    AttributionAdoptionError,
> {
    let source_event = ledger
        .events
        .iter()
        .find(|event| event.id == assignment.source_event_id)
        .ok_or(AttributionAdoptionError::CandidateSourceMismatch)?;
    let source_candidate = ledger
        .candidates
        .iter()
        .find(|candidate| candidate.id == assignment.candidate_id)
        .ok_or(AttributionAdoptionError::CandidateSourceMismatch)?;
    let verified_outcome = ledger
        .verified_outcomes
        .iter()
        .find(|verified| verified.candidate_id == source_candidate.id)
        .ok_or(AttributionAdoptionError::VerifiedOutcomeMismatch)?;
    Ok((source_event, source_candidate, verified_outcome))
}

fn expected_candidate_id(
    consumer: &AttributionAdoptionConsumer,
    source_event: &crate::SourceEvent,
    source_candidate: &OutcomeCandidate,
    window: &AttributionWindow,
    model_version: &AttributionModelVersion,
) -> Result<OutcomeCandidateId, AttributionAdoptionError> {
    Ok(OutcomeCandidateId::from_stable(format!(
        "adoption-candidate:{}",
        canonical_digest(&(
            &consumer.consumer_digest,
            &consumer.scope,
            &source_event.id,
            &source_event.identity,
            &source_candidate.source_event_digest,
            window,
            model_version,
        ))?
    )))
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, AttributionAdoptionError> {
    let bytes = serde_json::to_vec(value).map_err(AttributionAdoptionError::Serialization)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_identifier(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

fn spine_error(error: &AttributionError) -> AttributionAdoptionError {
    AttributionAdoptionError::AttributionSpine(error.to_string())
}

#[derive(Debug, Error)]
pub enum AttributionAdoptionError {
    #[error("attribution model version is empty or not a typed identifier")]
    InvalidModelVersion,
    #[error("attribution adoption Project/Mission/goal scope is invalid")]
    InvalidAdoptionScope,
    #[error("attribution adoption scope does not match the persisted Mission")]
    AdoptionScopeMismatch,
    #[error("attribution adoption consumer identity or digest is invalid")]
    InvalidConsumerIdentity,
    #[error("attribution adoption consumer lifecycle record is invalid")]
    InvalidConsumerRecord,
    #[error("attribution adoption consumer lifecycle transition is invalid")]
    InvalidConsumerTransition,
    #[error("attribution outcome candidate is malformed")]
    InvalidOutcomeCandidate,
    #[error("attribution outcome candidate is not bound to the exact source event")]
    CandidateSourceMismatch,
    #[error("attribution verified outcome is not bound to the exact candidate")]
    VerifiedOutcomeMismatch,
    #[error("attribution outcome candidate digest or evidence root changed")]
    CandidateDigestMismatch,
    #[error("attribution adoption receipt is malformed or stale")]
    InvalidReceipt,
    #[error("attribution adoption receipt references an unknown candidate")]
    ReceiptCandidateMismatch,
    #[error("attribution adoption consumer is not mounted")]
    ConsumerNotMounted,
    #[error("attribution adoption candidate is duplicated")]
    DuplicateOutcomeCandidate,
    #[error("attribution adoption receipt is duplicated")]
    DuplicateAdoptionReceipt,
    #[error("attribution adoption snapshot is malformed")]
    InvalidAdoptionSnapshot,
    #[error("attribution verification event is malformed")]
    InvalidVerificationRecord,
    #[error("attribution spine is invalid: {0}")]
    AttributionSpine(String),
    #[error("attribution adoption serialization failed: {0}")]
    Serialization(serde_json::Error),
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};

    use super::*;
    use crate::{
        CorrectionLineage, CurrencyCode, ObservationProvenance, ProviderEntityRef,
        ProviderEventIdentity, SourceEntityKind, SourceEvent, SourceEventLinks, VerificationMethod,
    };

    fn at(minute: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 8, 0, 0)
            .single()
            .expect("time")
            + Duration::minutes(minute)
    }

    fn source_event() -> SourceEvent {
        let provider = "meta";
        let identity = ProviderEventIdentity::new(provider, "acct-1", "order-1").expect("identity");
        let account =
            ProviderEntityRef::new(SourceEntityKind::Account, provider, "acct-1", "acct-1")
                .expect("account");
        let mut links = SourceEventLinks::new(account).expect("links");
        links.order = Some(
            ProviderEntityRef::new(SourceEntityKind::Order, provider, "acct-1", "order-1")
                .expect("order"),
        );
        SourceEvent {
            id: SourceEventId::from_stable("order-1"),
            tenant_id: TenantId::from("tenant-1"),
            project_id: ProjectId::from("project-1"),
            mission_id: Some(MissionId::from("mission-1")),
            identity,
            kind: crate::SourceEventKind::Order,
            links,
            provider_occurred_at: at(1),
            observed_at: at(2),
            ingested_at: at(3),
            amount: Some(crate::Money::new(
                10_000,
                CurrencyCode::parse("USD").expect("USD"),
            )),
            fx_quote: None,
            provenance: ObservationProvenance::new(
                ObservationOrigin::FirstParty,
                "a".repeat(64),
                at(2),
            )
            .expect("provenance"),
            lineage: CorrectionLineage::original(SourceEventId::from_stable("order-1")),
            payload_digest: "b".repeat(64),
        }
    }

    #[test]
    fn scope_consumer_candidate_and_receipt_are_content_bound() {
        let mut ledger = AttributionLedger::new(
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            CurrencyCode::parse("USD").expect("USD"),
        )
        .expect("ledger");
        let event = source_event();
        let candidate = event.outcome_candidate().expect("candidate");
        ledger.ingest_event(event).expect("event");
        ledger.register_candidate(candidate).expect("candidate");
        ledger
            .verify_candidate(
                &OutcomeCandidateId::from_stable("candidate:order-1"),
                crate::OutcomeVerification {
                    method: VerificationMethod::SignedWebhook,
                    verifier: "meta-webhook".into(),
                    independent: true,
                    verified_at: at(4),
                    evidence_digest: "c".repeat(64),
                },
            )
            .expect("verified");
        let scope = AttributionAdoptionScope::new(
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            MissionId::from("mission-1"),
            1,
            "d".repeat(64),
        )
        .expect("scope");
        let consumer = AttributionAdoptionConsumer::new(
            "market.outcome.consumer",
            "market.outcome.plugin",
            1,
            "e".repeat(64),
            scope,
            1,
        )
        .expect("consumer");
        let window = AttributionWindow {
            version: 1,
            click_lookback_seconds: 86_400,
            view_lookback_seconds: 86_400,
            effective_at: at(0),
        };
        let model = AttributionModelVersion::new("last-touch.v1").expect("model");
        let adopted =
            AttributionOutcomeCandidate::from_verified_ledger(&ledger, &consumer, window, model)
                .expect("derive")
                .expect("real event");
        adopted
            .validate_with_ledger(&ledger, &consumer)
            .expect("valid");
        let receipt = AttributionAdoptionReceipt::from_candidate(
            &adopted,
            AttributionAdoptionDecision::Adopt,
            ActorId::from("human-1"),
            "decision-1",
            at(5),
        )
        .expect("receipt");
        receipt
            .validate_for_candidate(&adopted)
            .expect("receipt valid");
        let mut tampered = adopted.clone();
        tampered.provider_event_identity.provider = "shopify".into();
        assert!(matches!(
            tampered.validate_with_ledger(&ledger, &consumer),
            Err(AttributionAdoptionError::CandidateSourceMismatch
                | AttributionAdoptionError::CandidateDigestMismatch,)
        ));
        let mut swapped = receipt;
        swapped.scope.project_id = ProjectId::from("other-project");
        assert!(swapped.validate_for_candidate(&adopted).is_err());
    }

    #[test]
    fn no_real_provider_events_returns_none() {
        let ledger = AttributionLedger::new(
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            CurrencyCode::parse("USD").expect("USD"),
        )
        .expect("ledger");
        let scope = AttributionAdoptionScope::new(
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            MissionId::from("mission-1"),
            1,
            "d".repeat(64),
        )
        .expect("scope");
        let consumer = AttributionAdoptionConsumer::new(
            "market.outcome.consumer",
            "market.outcome.plugin",
            1,
            "e".repeat(64),
            scope,
            1,
        )
        .expect("consumer");
        let window = AttributionWindow {
            version: 1,
            click_lookback_seconds: 1,
            view_lookback_seconds: 1,
            effective_at: at(0),
        };
        assert!(
            AttributionOutcomeCandidate::from_verified_ledger(
                &ledger,
                &consumer,
                window,
                AttributionModelVersion::new("last-touch.v1").expect("model"),
            )
            .expect("empty ledger")
            .is_none()
        );
    }
}
