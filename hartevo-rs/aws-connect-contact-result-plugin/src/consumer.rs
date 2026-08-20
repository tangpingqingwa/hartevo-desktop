//! Mission-scoped proposal consumption and deterministic redacted recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{AwsConnectContactResultError, Result};
use crate::model::{
    AwsConnectContactScope, ContactEvidenceState, Digest, EvidenceDigests, TransportProvenance,
};
use crate::service::{AwsConnectContactResultProposal, AwsConnectContactResultRegistration};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Completed,
    Partial,
    RetentionExpired,
    AccessLoss,
    ProviderUnknown,
    NotFound,
    Throttled,
    RegistrationRevoked,
}

impl From<ContactEvidenceState> for ProposalDisposition {
    fn from(state: ContactEvidenceState) -> Self {
        match state {
            ContactEvidenceState::Completed => Self::Completed,
            ContactEvidenceState::Partial => Self::Partial,
            ContactEvidenceState::RetentionExpired => Self::RetentionExpired,
            ContactEvidenceState::AccessLoss => Self::AccessLoss,
            ContactEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            ContactEvidenceState::NotFound => Self::NotFound,
            ContactEvidenceState::Throttled => Self::Throttled,
            ContactEvidenceState::RegistrationRevoked => Self::RegistrationRevoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsConnectContactResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub mission: crate::model::MissionProjection,
    pub project: crate::model::ProjectProjection,
    pub work_product: crate::model::WorkProductProjection,
    pub state: ContactEvidenceState,
    pub disposition: ProposalDisposition,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
    pub durable_receipt: bool,
    pub independent_readback: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionAwsConnectContactResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

/// A redacted local recording candidate. It is not a provider receipt and is
/// never sufficient for independent read-back or Work Product/Outcome adoption.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsConnectContactReceiptCandidate {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: ContactEvidenceState,
    pub disposition: ProposalDisposition,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub durable: bool,
    pub provider_receipt: bool,
    pub independent_readback: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub candidate_digest: Digest,
}

impl AwsConnectContactReceiptCandidate {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &AwsConnectContactResultProposal,
        replayed: bool,
    ) -> Self {
        let mut candidate = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            provenance: proposal.provenance.clone(),
            replayed,
            durable: false,
            provider_receipt: false,
            independent_readback: false,
            outcome_adopted: false,
            work_product_adopted: false,
            candidate_digest: Digest::from_text("unsealed-aws-connect-receipt-candidate"),
        };
        candidate.candidate_digest = candidate.calculate_digest();
        candidate
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-connect-receipt-candidate/v1",
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

    pub fn validate_integrity(&self) -> Result<()> {
        if self.durable
            || self.provider_receipt
            || self.independent_readback
            || self.outcome_adopted
            || self.work_product_adopted
            || self.candidate_digest != self.calculate_digest()
        {
            return Err(AwsConnectContactResultError::TamperedEvidence);
        }
        Ok(())
    }
}

/// Consumer scoped to one exact Amazon Connect registration and Mission fence.
pub struct MissionAwsConnectContactConsumer {
    scope: AwsConnectContactScope,
    registration: AwsConnectContactResultRegistration,
    records: BTreeMap<Digest, AwsConnectContactReceiptCandidate>,
}

impl fmt::Debug for MissionAwsConnectContactConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsConnectContactConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsConnectContactConsumer {
    pub fn new(
        scope: AwsConnectContactScope,
        registration: AwsConnectContactResultRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(AwsConnectContactResultError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest() {
            return Err(AwsConnectContactResultError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn registration(&self) -> &AwsConnectContactResultRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &AwsConnectContactScope {
        &self.scope
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &AwsConnectContactResultProposal,
    ) -> Result<MissionAwsConnectContactResult> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(AwsConnectContactResultError::RegistrationInactive);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.evidence.evidence_binding_digest
                != *self.registration.evidence_binding_digest()
            || proposal.mission.id_digest != self.scope.mission().digest()
            || proposal.mission.revision != self.scope.mission().revision()
            || proposal.project.id_digest != self.scope.project().digest()
            || proposal.project.revision != self.scope.project().revision()
            || proposal.work_product.id_digest != self.scope.work_product().digest()
            || proposal.work_product.revision != self.scope.work_product().revision()
        {
            return Err(AwsConnectContactResultError::StaleMission);
        }
        Ok(MissionAwsConnectContactResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            mission: proposal.mission.clone(),
            project: proposal.project.clone(),
            work_product: proposal.work_product.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            evidence: proposal.evidence.clone(),
            provenance: proposal.provenance.clone(),
            review_only: true,
            connected: false,
            native: false,
            provider_receipt: false,
            durable_receipt: false,
            independent_readback: false,
            outcome_adopted: false,
            work_product_adopted: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &AwsConnectContactResultProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<AwsConnectContactReceiptCandidate> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES || key.trim() != key {
            return Err(AwsConnectContactResultError::InvalidRequest);
        }
        let key_digest = Digest::from_parts(
            "aws-connect-idempotency-key/v1",
            &[
                ("key", key.to_owned()),
                ("scope", self.scope.digest().as_str().to_owned()),
            ],
        );
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsConnectContactResultError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.candidate_digest = replay.calculate_digest();
            return Ok(replay);
        }
        let candidate = AwsConnectContactReceiptCandidate::new(key_digest.clone(), proposal, false);
        candidate.validate_integrity()?;
        self.records.insert(key_digest, candidate.clone());
        Ok(candidate)
    }
}
