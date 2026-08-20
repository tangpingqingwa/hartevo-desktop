//! Mission adoption boundary for committed Sorftime estimate receipts.
//!
//! The first Sorftime layer owns the provider transport and its durable
//! `Committed` receipt.  This layer only turns that receipt into a typed,
//! digest-bound estimate work product for a single Project/Mission generation.
//! It does not create provider authority, Connected state, an Effect, or an
//! Amazon first-party fact.

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{MissionId, ProjectId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::sorftime::{
    SORFTIME_PROVIDER_ID, SorftimeDataset, SorftimeEvidenceAuthority, SorftimeMarket,
    SorftimeRequestCost, SorftimeTransportKind,
};
use crate::sorftime_plugin::{
    SORFTIME_ESTIMATE_BLOCKED_ENV_STATUS, SORFTIME_ESTIMATE_CAPABILITY_ID,
    SORFTIME_ESTIMATE_CLASSIFICATION, SORFTIME_ESTIMATE_EVIDENCE_LEVEL,
    SORFTIME_ESTIMATE_LIVE_STATUS, SORFTIME_ESTIMATE_RESULT_VERSION, SorftimeCheckpointState,
    SorftimeDurableCheckpoint, SorftimeEstimateReceipt, SorftimeEstimateResult,
    SorftimeFreshnessEvidence, SorftimeQuotaEvidence, SorftimeTransportIdentity,
};
use crate::{COMMERCE_CONNECTOR_CONTRACT_JSON, SORFTIME_ADAPTER_ID};

pub const SORFTIME_ESTIMATE_WORK_PRODUCT_VERSION: &str = "sorftime-estimate-work-product/v1";
pub const SORFTIME_ESTIMATE_OUTCOME_VERSION: &str = "sorftime-estimate-outcome/v1";
pub const SORFTIME_ESTIMATE_OUTCOME_CHECKPOINT_VERSION: &str =
    "sorftime-estimate-outcome-checkpoint/v1";
pub const SORFTIME_ESTIMATE_OUTCOME_KIND: &str = "estimate_only_market_evidence";

/// The digest of the checked-in commerce read-only contract.  A packet bound
/// to an older or unrelated contract must not cross the Mission boundary.
pub fn commerce_connector_contract_digest() -> String {
    sha256(COMMERCE_CONNECTOR_CONTRACT_JSON.as_bytes())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SorftimeMissionBinding {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub generation: u64,
    pub plugin_id: String,
    pub plugin_digest: String,
    pub contract_digest: String,
}

impl SorftimeMissionBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: ProjectId,
        mission_id: MissionId,
        generation: u64,
        plugin_id: impl Into<String>,
        plugin_digest: impl Into<String>,
        contract_digest: impl Into<String>,
    ) -> Result<Self, SorftimeOutcomeError> {
        let binding = Self {
            project_id,
            mission_id,
            generation,
            plugin_id: plugin_id.into(),
            plugin_digest: plugin_digest.into(),
            contract_digest: contract_digest.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(&self) -> Result<(), SorftimeOutcomeError> {
        if self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.generation == 0
            || self.plugin_id != SORFTIME_ADAPTER_ID
            || !is_sha256(&self.plugin_digest)
            || !is_sha256(&self.contract_digest)
            || self.contract_digest != commerce_connector_contract_digest()
        {
            return Err(SorftimeOutcomeError::InvalidBinding(
                "project, mission, generation, plugin, or contract digest is invalid".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SorftimeEstimateSource {
    pub source: String,
    pub provider_id: String,
    pub plugin_id: String,
    pub plugin_digest: String,
    pub contract_digest: String,
    pub transport: SorftimeTransportIdentity,
    pub provenance_class: String,
    pub evidence_level: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SorftimeCounterevidenceKind {
    NoAmazonFirstPartyReadback,
    NoConnectedAuthority,
    NoEffectE4Authority,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SorftimeEstimateCounterevidence {
    pub kind: SorftimeCounterevidenceKind,
    pub source: String,
    pub statement: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SorftimeEstimateLimitationKind {
    EstimateOnly,
    NoAmazonSellerVendorReadback,
    FreshnessBound,
    NoExternalWrite,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SorftimeEstimateLimitation {
    pub kind: SorftimeEstimateLimitationKind,
    pub statement: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SorftimeEstimateWorkProduct {
    pub work_product_version: String,
    pub binding: SorftimeMissionBinding,
    pub source: SorftimeEstimateSource,
    pub account: crate::sorftime::SorftimeAccountId,
    pub market: SorftimeMarket,
    pub dataset: SorftimeDataset,
    pub request_id: String,
    pub provider_request_id: String,
    pub request_digest: String,
    pub response_digest: String,
    pub receipt_digest: String,
    pub classification: String,
    pub authority: SorftimeEvidenceAuthority,
    pub freshness: SorftimeFreshnessEvidence,
    pub cost: SorftimeRequestCost,
    pub quota: SorftimeQuotaEvidence,
    pub counterevidence: Vec<SorftimeEstimateCounterevidence>,
    pub limitations: Vec<SorftimeEstimateLimitation>,
    pub receipt: SorftimeEstimateReceipt,
    pub work_product_digest: String,
}

impl SorftimeEstimateWorkProduct {
    pub fn from_committed_receipt(
        binding: SorftimeMissionBinding,
        checkpoint: &SorftimeDurableCheckpoint,
    ) -> Result<Self, SorftimeOutcomeError> {
        binding.validate()?;
        let receipt = committed_receipt(checkpoint)?;
        let work_product = Self::from_receipt(binding, receipt.clone());
        work_product.validate()?;
        Ok(work_product)
    }

    pub fn is_estimate_only(&self) -> bool {
        matches!(self.authority, SorftimeEvidenceAuthority::EstimateOnly)
            && self.classification == SORFTIME_ESTIMATE_CLASSIFICATION
    }

    pub const fn is_connected(&self) -> bool {
        false
    }

    pub const fn is_first_party_amazon_fact(&self) -> bool {
        false
    }

    pub const fn has_effect_e4_authority(&self) -> bool {
        false
    }

    pub fn calculate_digest(&self) -> Result<String, SorftimeOutcomeError> {
        let mut unsigned = self.clone();
        unsigned.work_product_digest.clear();
        digest_json(&unsigned)
    }

    pub fn validate(&self) -> Result<(), SorftimeOutcomeError> {
        self.binding.validate()?;
        if self.work_product_version != SORFTIME_ESTIMATE_WORK_PRODUCT_VERSION
            || self.source.source != SORFTIME_PROVIDER_ID
            || self.source.provider_id != SORFTIME_PROVIDER_ID
            || self.source.plugin_id != self.binding.plugin_id
            || self.source.plugin_digest != self.binding.plugin_digest
            || self.source.contract_digest != self.binding.contract_digest
            || self.source.transport != self.receipt.transport
            || self.source.provenance_class != self.receipt.provenance_class
            || self.source.evidence_level != self.receipt.evidence_level
            || self.source.transport.transport != SorftimeTransportKind::Cli
            || !matches!(
                self.source.provenance_class.as_str(),
                "controlled_provider" | "production_provider"
            )
            || self.source.evidence_level != SORFTIME_ESTIMATE_EVIDENCE_LEVEL
            || self.account.as_str().trim().is_empty()
            || self.request_id.trim().is_empty()
            || self.provider_request_id.trim().is_empty()
            || !is_sha256(&self.request_digest)
            || !is_sha256(&self.response_digest)
            || !is_sha256(&self.receipt_digest)
            || self.receipt_digest != self.receipt.result_digest
            || self.provider_request_id != self.receipt.observation.provenance.request_id
            || self.work_product_digest != self.calculate_digest()?
            || self.counterevidence != expected_counterevidence()
            || self.limitations != expected_limitations()
        {
            return Err(SorftimeOutcomeError::InvalidWorkProduct(
                "work product identity, provenance, or digest is invalid".into(),
            ));
        }

        validate_receipt_identity(
            &self.receipt,
            &self.binding,
            &self.account,
            &self.market,
            self.dataset,
            &self.request_id,
            &self.request_digest,
            &self.response_digest,
            &self.classification,
            &self.freshness,
            &self.cost,
            &self.quota,
        )?;
        Ok(())
    }

    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<(), SorftimeOutcomeError> {
        self.validate()?;
        validate_freshness(&self.freshness, now)
    }

    fn from_receipt(binding: SorftimeMissionBinding, receipt: SorftimeEstimateReceipt) -> Self {
        let source = SorftimeEstimateSource {
            source: SORFTIME_PROVIDER_ID.into(),
            provider_id: SORFTIME_PROVIDER_ID.into(),
            plugin_id: binding.plugin_id.clone(),
            plugin_digest: binding.plugin_digest.clone(),
            contract_digest: binding.contract_digest.clone(),
            transport: receipt.transport.clone(),
            provenance_class: receipt.provenance_class.clone(),
            evidence_level: receipt.evidence_level.clone(),
        };
        let counterevidence = expected_counterevidence();
        let limitations = expected_limitations();
        let mut work_product = Self {
            work_product_version: SORFTIME_ESTIMATE_WORK_PRODUCT_VERSION.into(),
            binding,
            source,
            account: receipt.account.clone(),
            market: receipt.market.clone(),
            dataset: receipt.dataset,
            request_id: receipt.request_id.clone(),
            provider_request_id: receipt.observation.provenance.request_id.clone(),
            request_digest: receipt.request_digest.clone(),
            response_digest: receipt.response_digest.clone(),
            receipt_digest: receipt.result_digest.clone(),
            classification: receipt.classification.clone(),
            authority: receipt.authority,
            freshness: receipt.freshness.clone(),
            cost: receipt.cost.clone(),
            quota: receipt.quota.clone(),
            counterevidence,
            limitations,
            receipt,
            work_product_digest: String::new(),
        };
        work_product.work_product_digest = work_product
            .calculate_digest()
            .expect("typed Sorftime work product is serializable");
        work_product
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SorftimeEstimateOutcomePacket {
    pub outcome_version: String,
    pub outcome_kind: String,
    pub binding: SorftimeMissionBinding,
    pub work_product: SorftimeEstimateWorkProduct,
    pub receipt_digest: String,
    pub adopted_at: DateTime<Utc>,
    pub replayed: bool,
    pub outcome_digest: String,
}

impl SorftimeEstimateOutcomePacket {
    pub fn is_estimate_only(&self) -> bool {
        self.work_product.is_estimate_only()
    }

    pub const fn is_connected(&self) -> bool {
        false
    }

    pub const fn is_first_party_amazon_fact(&self) -> bool {
        false
    }

    pub const fn has_effect_e4_authority(&self) -> bool {
        false
    }

    pub fn calculate_digest(&self) -> Result<String, SorftimeOutcomeError> {
        let mut unsigned = self.clone();
        unsigned.outcome_digest.clear();
        unsigned.replayed = false;
        digest_json(&unsigned)
    }

    pub fn validate(&self) -> Result<(), SorftimeOutcomeError> {
        self.binding.validate()?;
        self.work_product.validate()?;
        if self.outcome_version != SORFTIME_ESTIMATE_OUTCOME_VERSION
            || self.outcome_kind != SORFTIME_ESTIMATE_OUTCOME_KIND
            || self.binding != self.work_product.binding
            || self.receipt_digest != self.work_product.receipt_digest
            || !is_sha256(&self.receipt_digest)
            || self.outcome_digest != self.calculate_digest()?
            || !self.is_estimate_only()
            || self.is_connected()
            || self.is_first_party_amazon_fact()
            || self.has_effect_e4_authority()
        {
            return Err(SorftimeOutcomeError::InvalidOutcome(
                "outcome packet is not an estimate-only digest-bound packet".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<(), SorftimeOutcomeError> {
        self.validate()?;
        self.work_product.validate_at(now)
    }

    fn new(work_product: SorftimeEstimateWorkProduct, adopted_at: DateTime<Utc>) -> Self {
        let mut packet = Self {
            outcome_version: SORFTIME_ESTIMATE_OUTCOME_VERSION.into(),
            outcome_kind: SORFTIME_ESTIMATE_OUTCOME_KIND.into(),
            binding: work_product.binding.clone(),
            receipt_digest: work_product.receipt_digest.clone(),
            work_product,
            adopted_at,
            replayed: false,
            outcome_digest: String::new(),
        };
        packet.outcome_digest = packet
            .calculate_digest()
            .expect("typed Sorftime outcome is serializable");
        packet
    }

    fn with_replayed(mut self) -> Self {
        self.replayed = true;
        self
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SorftimeOutcomeCheckpointState {
    Empty,
    InFlight,
    Committed,
    FailedClosed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SorftimeOutcomeCheckpoint {
    pub checkpoint_version: String,
    pub state: SorftimeOutcomeCheckpointState,
    pub binding: Option<SorftimeMissionBinding>,
    pub receipt_digest: Option<String>,
    pub work_product_digest: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub outcome_digest: Option<String>,
    pub terminal_error_digest: Option<String>,
    pub outcome: Option<SorftimeEstimateOutcomePacket>,
}

impl SorftimeOutcomeCheckpoint {
    pub fn empty() -> Self {
        Self {
            checkpoint_version: SORFTIME_ESTIMATE_OUTCOME_CHECKPOINT_VERSION.into(),
            state: SorftimeOutcomeCheckpointState::Empty,
            binding: None,
            receipt_digest: None,
            work_product_digest: None,
            started_at: None,
            updated_at: None,
            outcome_digest: None,
            terminal_error_digest: None,
            outcome: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.state == SorftimeOutcomeCheckpointState::Empty
    }

    /// Converts a persisted in-flight record into a terminal failed-closed
    /// record.  Callers can persist this without exposing any credential
    /// material; only the error digest is retained.
    #[must_use]
    pub fn failed_closed(&self, error: &SorftimeOutcomeError, now: DateTime<Utc>) -> Self {
        let mut checkpoint = self.clone();
        checkpoint.state = SorftimeOutcomeCheckpointState::FailedClosed;
        checkpoint.updated_at = Some(now);
        checkpoint.outcome_digest = None;
        checkpoint.outcome = None;
        checkpoint.terminal_error_digest = Some(sha256(error.to_string().as_bytes()));
        checkpoint
    }

    fn in_flight(
        binding: SorftimeMissionBinding,
        receipt_digest: String,
        work_product_digest: String,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            checkpoint_version: SORFTIME_ESTIMATE_OUTCOME_CHECKPOINT_VERSION.into(),
            state: SorftimeOutcomeCheckpointState::InFlight,
            binding: Some(binding),
            receipt_digest: Some(receipt_digest),
            work_product_digest: Some(work_product_digest),
            started_at: Some(now),
            updated_at: Some(now),
            outcome_digest: None,
            terminal_error_digest: None,
            outcome: None,
        }
    }

    fn committed(
        &self,
        outcome: SorftimeEstimateOutcomePacket,
        now: DateTime<Utc>,
    ) -> SorftimeOutcomeCheckpoint {
        let mut checkpoint = self.clone();
        checkpoint.state = SorftimeOutcomeCheckpointState::Committed;
        checkpoint.updated_at = Some(now);
        checkpoint.outcome_digest = Some(outcome.outcome_digest.clone());
        checkpoint.terminal_error_digest = None;
        checkpoint.outcome = Some(outcome);
        checkpoint
    }

    fn matches(&self, binding: &SorftimeMissionBinding, receipt_digest: &str) -> bool {
        self.binding.as_ref() == Some(binding)
            && self.receipt_digest.as_deref() == Some(receipt_digest)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SorftimeEstimateAdoptionRequest {
    pub binding: SorftimeMissionBinding,
    pub committed_receipt: SorftimeDurableCheckpoint,
}

impl SorftimeEstimateAdoptionRequest {
    pub fn new(
        binding: SorftimeMissionBinding,
        committed_receipt: SorftimeDurableCheckpoint,
    ) -> Self {
        Self {
            binding,
            committed_receipt,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SorftimePreparedOutcomeAdoption {
    binding: SorftimeMissionBinding,
    work_product: SorftimeEstimateWorkProduct,
    checkpoint: SorftimeOutcomeCheckpoint,
}

impl SorftimePreparedOutcomeAdoption {
    pub fn binding(&self) -> &SorftimeMissionBinding {
        &self.binding
    }

    pub fn work_product(&self) -> &SorftimeEstimateWorkProduct {
        &self.work_product
    }

    pub fn checkpoint(&self) -> &SorftimeOutcomeCheckpoint {
        &self.checkpoint
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SorftimeOutcomePlan {
    Adopt(Box<SorftimePreparedOutcomeAdoption>),
    Replay(Box<SorftimeEstimateOutcomePacket>),
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum SorftimeOutcomeError {
    #[error("Sorftime outcome consumer is revoked")]
    Revoked,
    #[error("Sorftime outcome consumer is unmounted")]
    Unmounted,
    #[error("Sorftime outcome binding is invalid: {0}")]
    InvalidBinding(String),
    #[error("Sorftime outcome binding does not match the consumer generation")]
    BindingMismatch,
    #[error("Sorftime outcome checkpoint version or state is unknown")]
    UnknownTerminal,
    #[error("Sorftime outcome checkpoint is already failed closed")]
    PreviouslyFailedClosed,
    #[error("Sorftime provider receipt is not committed")]
    ReceiptNotCommitted,
    #[error("Sorftime provider receipt is failed closed")]
    ReceiptFailedClosed,
    #[error("Sorftime provider receipt is in an unknown terminal state")]
    ReceiptUnknownTerminal,
    #[error("Sorftime provider receipt is invalid: {0}")]
    InvalidReceipt(String),
    #[error("Sorftime estimate work product is invalid: {0}")]
    InvalidWorkProduct(String),
    #[error("Sorftime estimate outcome is invalid: {0}")]
    InvalidOutcome(String),
    #[error("Sorftime outcome checkpoint does not match the exact adoption")]
    CheckpointMismatch,
    #[error("Sorftime estimate receipt is stale")]
    Stale,
    #[error("Sorftime estimate receipt is expired")]
    Expired,
}

#[derive(Clone, Debug)]
pub struct SorftimeEstimateOutcomeConsumer {
    binding: SorftimeMissionBinding,
    mounted: bool,
    revoked: bool,
}

impl SorftimeEstimateOutcomeConsumer {
    pub fn new(binding: SorftimeMissionBinding) -> Result<Self, SorftimeOutcomeError> {
        binding.validate()?;
        Ok(Self {
            binding,
            mounted: true,
            revoked: false,
        })
    }

    pub fn binding(&self) -> &SorftimeMissionBinding {
        &self.binding
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
        self.mounted = false;
    }

    pub fn unmount(&mut self) {
        self.mounted = false;
    }

    /// Rotating the Mission generation invalidates every prepared adoption
    /// from the old generation.  A caller can create a fresh consumer for a
    /// newly mounted plugin; this method is useful for the exact fence test.
    pub fn rotate_generation(&mut self, generation: u64) -> Result<(), SorftimeOutcomeError> {
        self.ensure_available()?;
        if generation == 0 {
            return Err(SorftimeOutcomeError::InvalidBinding(
                "generation must be non-zero".into(),
            ));
        }
        self.binding.generation = generation;
        Ok(())
    }

    pub fn prepare_adoption(
        &self,
        request: &SorftimeEstimateAdoptionRequest,
        checkpoint: SorftimeOutcomeCheckpoint,
        now: DateTime<Utc>,
    ) -> Result<SorftimeOutcomePlan, SorftimeOutcomeError> {
        self.ensure_available()?;
        if request.binding != self.binding {
            return Err(SorftimeOutcomeError::BindingMismatch);
        }
        let work_product = SorftimeEstimateWorkProduct::from_committed_receipt(
            request.binding.clone(),
            &request.committed_receipt,
        )?;
        work_product.validate_at(now)?;

        if checkpoint.checkpoint_version != SORFTIME_ESTIMATE_OUTCOME_CHECKPOINT_VERSION {
            return Err(SorftimeOutcomeError::UnknownTerminal);
        }
        match checkpoint.state {
            SorftimeOutcomeCheckpointState::Empty => Ok(SorftimeOutcomePlan::Adopt(Box::new(
                SorftimePreparedOutcomeAdoption {
                    binding: self.binding.clone(),
                    checkpoint: SorftimeOutcomeCheckpoint::in_flight(
                        self.binding.clone(),
                        work_product.receipt_digest.clone(),
                        work_product.work_product_digest.clone(),
                        now,
                    ),
                    work_product,
                },
            ))),
            SorftimeOutcomeCheckpointState::InFlight => {
                if !checkpoint.matches(&self.binding, &work_product.receipt_digest) {
                    return Err(SorftimeOutcomeError::CheckpointMismatch);
                }
                Err(SorftimeOutcomeError::UnknownTerminal)
            }
            SorftimeOutcomeCheckpointState::FailedClosed => {
                Err(SorftimeOutcomeError::PreviouslyFailedClosed)
            }
            SorftimeOutcomeCheckpointState::Committed => {
                if !checkpoint.matches(&self.binding, &work_product.receipt_digest) {
                    return Err(SorftimeOutcomeError::CheckpointMismatch);
                }
                let outcome = checkpoint
                    .outcome
                    .ok_or(SorftimeOutcomeError::UnknownTerminal)?;
                if checkpoint.outcome_digest.as_deref() != Some(outcome.outcome_digest.as_str()) {
                    return Err(SorftimeOutcomeError::CheckpointMismatch);
                }
                outcome.validate_at(now)?;
                Ok(SorftimeOutcomePlan::Replay(Box::new(
                    outcome.with_replayed(),
                )))
            }
        }
    }

    pub fn commit_adoption(
        &self,
        prepared: &SorftimePreparedOutcomeAdoption,
        now: DateTime<Utc>,
    ) -> Result<(SorftimeEstimateOutcomePacket, SorftimeOutcomeCheckpoint), SorftimeOutcomeError>
    {
        self.ensure_available()?;
        if prepared.binding != self.binding
            || prepared.checkpoint.state != SorftimeOutcomeCheckpointState::InFlight
            || !prepared
                .checkpoint
                .matches(&self.binding, &prepared.work_product.receipt_digest)
            || prepared.checkpoint.work_product_digest.as_deref()
                != Some(prepared.work_product.work_product_digest.as_str())
        {
            return Err(SorftimeOutcomeError::CheckpointMismatch);
        }
        prepared.work_product.validate_at(now)?;
        let outcome = SorftimeEstimateOutcomePacket::new(prepared.work_product.clone(), now);
        outcome.validate_at(now)?;
        let checkpoint = prepared.checkpoint.committed(outcome.clone(), now);
        Ok((outcome, checkpoint))
    }

    /// Convenience path for callers whose adoption store can atomically carry
    /// the in-flight checkpoint through this pure packet construction.  The
    /// two-phase `prepare_adoption`/`commit_adoption` path remains available
    /// for crash-safe persistence.
    pub fn adopt(
        &self,
        request: &SorftimeEstimateAdoptionRequest,
        checkpoint: SorftimeOutcomeCheckpoint,
        now: DateTime<Utc>,
    ) -> Result<(SorftimeEstimateOutcomePacket, SorftimeOutcomeCheckpoint), SorftimeOutcomeError>
    {
        match self.prepare_adoption(request, checkpoint.clone(), now)? {
            SorftimeOutcomePlan::Replay(outcome) => Ok((*outcome, checkpoint)),
            SorftimeOutcomePlan::Adopt(prepared) => self.commit_adoption(&prepared, now),
        }
    }

    fn ensure_available(&self) -> Result<(), SorftimeOutcomeError> {
        if self.revoked {
            return Err(SorftimeOutcomeError::Revoked);
        }
        if !self.mounted {
            return Err(SorftimeOutcomeError::Unmounted);
        }
        Ok(())
    }
}

fn committed_receipt(
    checkpoint: &SorftimeDurableCheckpoint,
) -> Result<&SorftimeEstimateResult, SorftimeOutcomeError> {
    match checkpoint.state {
        SorftimeCheckpointState::Committed => checkpoint
            .committed_receipt()
            .map_err(|error| SorftimeOutcomeError::InvalidReceipt(error.to_string())),
        SorftimeCheckpointState::FailedClosed => Err(SorftimeOutcomeError::ReceiptFailedClosed),
        SorftimeCheckpointState::InFlight => Err(SorftimeOutcomeError::ReceiptUnknownTerminal),
        SorftimeCheckpointState::Empty => Err(SorftimeOutcomeError::ReceiptNotCommitted),
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_receipt_identity(
    receipt: &SorftimeEstimateResult,
    binding: &SorftimeMissionBinding,
    account: &crate::sorftime::SorftimeAccountId,
    market: &SorftimeMarket,
    dataset: SorftimeDataset,
    request_id: &str,
    request_digest: &str,
    response_digest: &str,
    classification: &str,
    freshness: &SorftimeFreshnessEvidence,
    cost: &SorftimeRequestCost,
    quota: &SorftimeQuotaEvidence,
) -> Result<(), SorftimeOutcomeError> {
    receipt
        .validate_integrity()
        .map_err(|error| SorftimeOutcomeError::InvalidReceipt(error.to_string()))?;
    if receipt.replayed
        || receipt.result_version != SORFTIME_ESTIMATE_RESULT_VERSION
        || receipt.capability_id != SORFTIME_ESTIMATE_CAPABILITY_ID
        || receipt.classification != classification
        || receipt.classification != SORFTIME_ESTIMATE_CLASSIFICATION
        || !receipt.is_mission_adoptable()
        || !matches!(receipt.authority, SorftimeEvidenceAuthority::EstimateOnly)
        || receipt.connected
        || receipt.first_party_amazon_fact
        || receipt.evidence_level != SORFTIME_ESTIMATE_EVIDENCE_LEVEL
        || !matches!(
            receipt.live_validation_status.as_str(),
            SORFTIME_ESTIMATE_LIVE_STATUS | SORFTIME_ESTIMATE_BLOCKED_ENV_STATUS
        )
        || receipt.scope.project_id() != binding.project_id.as_str()
        || receipt.scope_digest != receipt.scope.digest()
        || receipt.account != *account
        || receipt.market != *market
        || receipt.dataset != dataset
        || receipt.request_id != request_id
        || receipt.request_digest != request_digest
        || receipt.response_digest != response_digest
        || receipt.observation.provenance.request_digest != request_digest
        || receipt.observation.provenance.account != *account
        || receipt.observation.provenance.market != *market
        || receipt.observation.provenance.dataset != dataset
        || receipt.observation.provenance.provider_id != SORFTIME_PROVIDER_ID
        || receipt.observation.provenance.transport != SorftimeTransportKind::Cli
        || !is_sorftime_transport(&receipt.transport)
        || !receipt.observation.is_estimate_only()
        || receipt.freshness != *freshness
        || receipt.cost != *cost
        || receipt.quota != *quota
        || receipt.freshness.observed_at != receipt.observed_at
        || receipt.quota.observed_at != receipt.observed_at
        || !is_sha256(request_digest)
        || !is_sha256(response_digest)
    {
        return Err(SorftimeOutcomeError::InvalidReceipt(
            "receipt fields are not bound to the exact estimate request".into(),
        ));
    }
    Ok(())
}

fn validate_freshness(
    freshness: &SorftimeFreshnessEvidence,
    now: DateTime<Utc>,
) -> Result<(), SorftimeOutcomeError> {
    if now < freshness.observed_at {
        return Err(SorftimeOutcomeError::Stale);
    }
    if now >= freshness.valid_until {
        return Err(SorftimeOutcomeError::Expired);
    }
    Ok(())
}

fn expected_counterevidence() -> Vec<SorftimeEstimateCounterevidence> {
    vec![
        SorftimeEstimateCounterevidence {
            kind: SorftimeCounterevidenceKind::NoAmazonFirstPartyReadback,
            source: SORFTIME_ADAPTER_ID.into(),
            statement: "Sorftime estimate data is not an Amazon SP-API seller or vendor readback."
                .into(),
        },
        SorftimeEstimateCounterevidence {
            kind: SorftimeCounterevidenceKind::NoConnectedAuthority,
            source: SORFTIME_ADAPTER_ID.into(),
            statement: "This estimate packet grants no Connected provider authority.".into(),
        },
        SorftimeEstimateCounterevidence {
            kind: SorftimeCounterevidenceKind::NoEffectE4Authority,
            source: SORFTIME_ADAPTER_ID.into(),
            statement: "This estimate packet contains no Effect Broker execution or E4 evidence."
                .into(),
        },
    ]
}

fn expected_limitations() -> Vec<SorftimeEstimateLimitation> {
    vec![
        SorftimeEstimateLimitation {
            kind: SorftimeEstimateLimitationKind::EstimateOnly,
            statement: "The provider classification is permanently estimate-only.".into(),
        },
        SorftimeEstimateLimitation {
            kind: SorftimeEstimateLimitationKind::NoAmazonSellerVendorReadback,
            statement:
                "Amazon seller, vendor, listing, order, and fulfillment state is not proven.".into(),
        },
        SorftimeEstimateLimitation {
            kind: SorftimeEstimateLimitationKind::FreshnessBound,
            statement: "The work product is adoptable only before its freshness window expires."
                .into(),
        },
        SorftimeEstimateLimitation {
            kind: SorftimeEstimateLimitationKind::NoExternalWrite,
            statement: "The packet cannot authorize an external write or Effect E4 operation."
                .into(),
        },
    ]
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_sorftime_transport(transport: &SorftimeTransportIdentity) -> bool {
    transport.provider_id == SORFTIME_PROVIDER_ID
        || transport
            .provider_id
            .strip_prefix(SORFTIME_PROVIDER_ID)
            .is_some_and(|suffix| suffix.starts_with(':'))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, SorftimeOutcomeError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| SorftimeOutcomeError::InvalidOutcome(error.to_string()))?;
    Ok(sha256(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_digest_is_stable_and_current_binding_rejects_other_contracts() {
        let digest = commerce_connector_contract_digest();
        assert!(is_sha256(&digest));
        let error = SorftimeMissionBinding::new(
            ProjectId::from("project-test"),
            MissionId::from("mission-test"),
            1,
            SORFTIME_ADAPTER_ID,
            "a".repeat(64),
            "b".repeat(64),
        )
        .expect_err("unrelated contract accepted");
        assert!(matches!(error, SorftimeOutcomeError::InvalidBinding(_)));
    }
}
