//! Mission-scoped proposal consumption and idempotent recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{AwsCostAnomalyError, Result};
use crate::model::{
    AnomalyEvidenceState, AnomalyProjection, AwsCostAnomalyScope, Digest, EvidenceDigests,
    MissionProjection, MonitorProjection, ProjectProjection, SubscriptionProjection,
    TransportProvenance, WorkProductProjection,
};
use crate::service::{AwsCostAnomalyProposal, AwsCostAnomalyRegistration};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    AnomalyDetected,
    NoAnomaly,
    MonitorActive,
    MonitorInactive,
    SubscriptionActive,
    SubscriptionInactive,
    Partial,
    RetentionExpired,
    NotFound,
    AccessLoss,
    Throttled,
    ProviderUnknown,
    RegistrationRevoked,
}

impl From<AnomalyEvidenceState> for ProposalDisposition {
    fn from(state: AnomalyEvidenceState) -> Self {
        match state {
            AnomalyEvidenceState::AnomalyDetected => Self::AnomalyDetected,
            AnomalyEvidenceState::NoAnomaly => Self::NoAnomaly,
            AnomalyEvidenceState::MonitorActive => Self::MonitorActive,
            AnomalyEvidenceState::MonitorInactive => Self::MonitorInactive,
            AnomalyEvidenceState::SubscriptionActive => Self::SubscriptionActive,
            AnomalyEvidenceState::SubscriptionInactive => Self::SubscriptionInactive,
            AnomalyEvidenceState::Partial => Self::Partial,
            AnomalyEvidenceState::RetentionExpired => Self::RetentionExpired,
            AnomalyEvidenceState::NotFound => Self::NotFound,
            AnomalyEvidenceState::AccessLoss => Self::AccessLoss,
            AnomalyEvidenceState::Throttled => Self::Throttled,
            AnomalyEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            AnomalyEvidenceState::RegistrationRevoked => Self::RegistrationRevoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsCostAnomalyResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: AnomalyEvidenceState,
    pub disposition: ProposalDisposition,
    pub anomaly: Option<AnomalyProjection>,
    pub monitor: Option<MonitorProjection>,
    pub subscription: Option<SubscriptionProjection>,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub financial_advice: bool,
    pub notification_sent: bool,
    pub billing_effect: bool,
    pub cost_causality_claim: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionAwsCostAnomalyResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsCostAnomalyResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: AnomalyEvidenceState,
    pub disposition: ProposalDisposition,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub financial_advice: bool,
    pub notification_sent: bool,
    pub billing_effect: bool,
    pub cost_causality_claim: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedAwsCostAnomalyResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &AwsCostAnomalyProposal,
        replayed: bool,
    ) -> Self {
        let mut result = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            provenance: proposal.provenance.clone(),
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            financial_advice: false,
            notification_sent: false,
            billing_effect: false,
            cost_causality_claim: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::from_text("unsealed-aws-cost-anomaly-recording"),
        };
        result.recording_digest = result.calculate_recording_digest();
        result
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.financial_advice
            || self.notification_sent
            || self.billing_effect
            || self.cost_causality_claim
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.calculate_recording_digest()
        {
            Err(AwsCostAnomalyError::TamperedEvidence)
        } else {
            Ok(())
        }
    }

    fn calculate_recording_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cost-anomaly-recording/v1",
            &[
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

/// Consumer scoped to one exact registration and Mission/Project/Work
/// Product revision fence. It has no outcome-adoption authority.
pub struct MissionAwsCostAnomalyConsumer {
    scope: AwsCostAnomalyScope,
    registration: AwsCostAnomalyRegistration,
    records: BTreeMap<Digest, RecordedAwsCostAnomalyResult>,
}

impl fmt::Debug for MissionAwsCostAnomalyConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsCostAnomalyConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsCostAnomalyConsumer {
    pub fn new(
        scope: AwsCostAnomalyScope,
        registration: AwsCostAnomalyRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(AwsCostAnomalyError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest() {
            return Err(AwsCostAnomalyError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn registration(&self) -> &AwsCostAnomalyRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &AwsCostAnomalyProposal,
    ) -> Result<MissionAwsCostAnomalyResult> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(AwsCostAnomalyError::RegistrationInactive);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.evidence_binding_digest != *self.registration.evidence_binding_digest()
            || proposal.mission.id_digest != self.scope.mission().digest()
            || proposal.mission.revision != self.scope.mission().revision()
            || proposal.project.id_digest != self.scope.project().digest()
            || proposal.project.revision != self.scope.project().revision()
            || proposal.work_product.id_digest != self.scope.work_product().digest()
            || proposal.work_product.revision != self.scope.work_product().revision()
        {
            return Err(AwsCostAnomalyError::ScopeMismatch);
        }
        Ok(MissionAwsCostAnomalyResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            mission: proposal.mission.clone(),
            project: proposal.project.clone(),
            work_product: proposal.work_product.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            anomaly: proposal.anomaly.clone(),
            monitor: proposal.monitor.clone(),
            subscription: proposal.subscription.clone(),
            evidence: proposal.evidence.clone(),
            provenance: proposal.provenance.clone(),
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            financial_advice: false,
            notification_sent: false,
            billing_effect: false,
            cost_causality_claim: false,
            outcome_adopted: false,
            work_product_adopted: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &AwsCostAnomalyProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedAwsCostAnomalyResult> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(AwsCostAnomalyError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsCostAnomalyError::RecordingConflict);
            }
            let replay = RecordedAwsCostAnomalyResult::new(key_digest, proposal, true);
            return Ok(replay);
        }
        let result = RecordedAwsCostAnomalyResult::new(key_digest.clone(), proposal, false);
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }
}
