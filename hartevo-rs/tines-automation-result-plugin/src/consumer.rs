use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::{
    CONSUMER_ID, SERVICE_ID,
    error::{Result, TinesAutomationResultError},
    model::{
        Digest, EvidenceClassification, MissionBinding, ProjectBinding, RegistrationState,
        TinesAutomationProposal, TinesAutomationScope, TinesEvidenceState, TinesReadbackReceipt,
        TinesRegistration, TransportProvenance, WorkProductBinding,
    },
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    Partial,
    Expired,
    AccessLost,
    RateLimited,
    ProviderUnknown,
    RegistrationRevoked,
}

impl From<TinesEvidenceState> for ProposalDisposition {
    fn from(state: TinesEvidenceState) -> Self {
        match state {
            TinesEvidenceState::Queued => Self::Queued,
            TinesEvidenceState::Running => Self::Running,
            TinesEvidenceState::Succeeded => Self::Succeeded,
            TinesEvidenceState::Failed => Self::Failed,
            TinesEvidenceState::Cancelled => Self::Cancelled,
            TinesEvidenceState::Partial => Self::Partial,
            TinesEvidenceState::Expired => Self::Expired,
            TinesEvidenceState::AccessLost => Self::AccessLost,
            TinesEvidenceState::RateLimited => Self::RateLimited,
            TinesEvidenceState::ProviderUnknown => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionTinesAutomationResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub state: TinesEvidenceState,
    pub disposition: ProposalDisposition,
    pub classification: EvidenceClassification,
    pub evidence_digest: Digest,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionTinesAutomationResult {
    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedTinesAutomationResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: TinesEvidenceState,
    pub disposition: ProposalDisposition,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedTinesAutomationResult {
    fn new(idempotency_key_digest: Digest, proposal: &TinesAutomationProposal) -> Self {
        let mut result = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            provenance: proposal.evidence.provenance,
            replayed: false,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: String::new(),
        };
        result.recording_digest = result.calculate_digest();
        result
    }

    #[must_use]
    pub fn calculate_digest(&self) -> Digest {
        let mut copy = self.clone();
        copy.recording_digest.clear();
        crate::canonical_digest(&copy)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.recording_digest != self.calculate_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
        {
            return Err(TinesAutomationResultError::TamperedEvidence);
        }
        Ok(())
    }
}

pub struct MissionTinesAutomationConsumer {
    scope: TinesAutomationScope,
    registration: TinesRegistration,
    records: BTreeMap<Digest, RecordedTinesAutomationResult>,
}

impl fmt::Debug for MissionTinesAutomationConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionTinesAutomationConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionTinesAutomationConsumer {
    pub fn new(scope: TinesAutomationScope, registration: TinesRegistration) -> Result<Self> {
        validate_registration(&scope, &registration)?;
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn registration(&self) -> &TinesRegistration {
        &self.registration
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &TinesAutomationProposal,
    ) -> Result<MissionTinesAutomationResult> {
        validate_registration(&self.scope, &self.registration)?;
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.provider_id != self.registration.provider_id
        {
            return Err(TinesAutomationResultError::ScopeMismatch);
        }
        proposal.validate_integrity(&self.scope, &self.registration)?;
        proposal
            .evidence
            .validate_integrity(&self.scope, &self.registration.provider_digest)?;
        Ok(MissionTinesAutomationResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            project: proposal.project.clone(),
            mission: proposal.mission.clone(),
            work_product: proposal.work_product.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            classification: proposal.evidence.classification,
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            provenance: proposal.evidence.provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &TinesAutomationProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedTinesAutomationResult> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(TinesAutomationResultError::InvalidIdentifier {
                label: "idempotency key",
            });
        }
        let key_digest = crate::sha256_hex(key.as_bytes());
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(TinesAutomationResultError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = replay.calculate_digest();
            return Ok(replay);
        }
        let result = RecordedTinesAutomationResult::new(key_digest.clone(), proposal);
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }

    pub fn verify_recording(&self, recording: &RecordedTinesAutomationResult) -> Result<()> {
        recording.validate_integrity()
    }

    pub fn readback_seam(
        &self,
        proposal: &TinesAutomationProposal,
    ) -> Result<TinesReadbackReceipt> {
        self.consume(proposal)?;
        Ok(TinesReadbackReceipt {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            status: "verified_against_consumer_scope".to_owned(),
            independent_native_readback: false,
            provider_receipt: false,
            connected: false,
            native: false,
            first_party: false,
        })
    }
}

fn validate_registration(
    scope: &TinesAutomationScope,
    registration: &TinesRegistration,
) -> Result<()> {
    if registration.registration_digest != registration.calculate_digest()
        || registration.contract_digest != crate::contract_digest()
        || registration.scope_digest != scope.digest()
        || registration.permission_digest != scope.permissions().digest()
        || !matches!(registration.state, RegistrationState::Active)
    {
        return Err(
            if matches!(registration.state, RegistrationState::Revoked) {
                TinesAutomationResultError::RegistrationInactive
            } else {
                TinesAutomationResultError::TamperedEvidence
            },
        );
    }
    Ok(())
}
