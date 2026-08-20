//! Mission-scoped proposal consumption and idempotent recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::error::{AwsCodeArtifactProvenanceError, Result};
use crate::model::{
    AwsCodeArtifactProvenanceScope, Digest, EvidenceDigests, MissionProjection, ProjectProjection,
    TransportProvenance, WorkProductProjection,
};
use crate::service::{
    AwsCodeArtifactEvidenceState, AwsCodeArtifactProvenanceProposal,
    AwsCodeArtifactProvenanceRegistration, RegistrationStatus,
};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Completed,
    Partial,
    NotFound,
    AccessLoss,
    Throttled,
    RevisionDrift,
    ProviderUnknown,
    RegistrationRevoked,
}

impl From<AwsCodeArtifactEvidenceState> for ProposalDisposition {
    fn from(state: AwsCodeArtifactEvidenceState) -> Self {
        match state {
            AwsCodeArtifactEvidenceState::Completed => Self::Completed,
            AwsCodeArtifactEvidenceState::Partial => Self::Partial,
            AwsCodeArtifactEvidenceState::NotFound => Self::NotFound,
            AwsCodeArtifactEvidenceState::AccessLoss => Self::AccessLoss,
            AwsCodeArtifactEvidenceState::Throttled => Self::Throttled,
            AwsCodeArtifactEvidenceState::RevisionDrift => Self::RevisionDrift,
            AwsCodeArtifactEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            AwsCodeArtifactEvidenceState::RegistrationRevoked => Self::RegistrationRevoked,
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error("Mission AWS CodeArtifact consumer registration is revoked")]
    RegistrationRevoked,
    #[error("Mission AWS CodeArtifact consumer scope or revision does not match")]
    ScopeMismatch,
    #[error("Mission AWS CodeArtifact consumer proposal is stale or tampered")]
    ProposalTampered,
    #[error("Mission AWS CodeArtifact consumer cannot adopt Layer-1 evidence")]
    AdoptionAuthority,
    #[error("Mission AWS CodeArtifact consumer recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("Mission AWS CodeArtifact consumer service error: {0}")]
    Service(#[from] AwsCodeArtifactProvenanceError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsCodeArtifactResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: AwsCodeArtifactEvidenceState,
    pub disposition: ProposalDisposition,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub result_digest: Digest,
}

impl MissionAwsCodeArtifactResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codeartifact-mission-result/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("mission", self.mission.id_digest.as_str().to_owned()),
                ("mission_revision", self.mission.revision.to_string()),
                ("project", self.project.id_digest.as_str().to_owned()),
                ("project_revision", self.project.revision.to_string()),
                (
                    "work_product",
                    self.work_product.id_digest.as_str().to_owned(),
                ),
                (
                    "work_product_revision",
                    self.work_product.revision.to_string(),
                ),
                ("state", format!("{:?}", self.state)),
                (
                    "evidence",
                    self.evidence.evidence_digest.as_str().to_owned(),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
                ("review_only", self.review_only.to_string()),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("first_party", self.first_party.to_string()),
                ("provider_receipt", self.provider_receipt.to_string()),
                ("outcome_adopted", self.outcome_adopted.to_string()),
                (
                    "work_product_adopted",
                    self.work_product_adopted.to_string(),
                ),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.result_digest != self.recomputed_digest()
        {
            return Err(AwsCodeArtifactProvenanceError::TamperedEvidence);
        }
        self.scope_digest.validate()?;
        self.proposal_digest.validate()?;
        self.evidence.validate()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsCodeArtifactResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: AwsCodeArtifactEvidenceState,
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

impl RecordedAwsCodeArtifactResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &AwsCodeArtifactProvenanceProposal,
        replayed: bool,
    ) -> Self {
        let mut result = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            provenance: proposal.provenance,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::from_text("unsealed-codeartifact-recording"),
        };
        result.recording_digest = result.recomputed_digest();
        result
    }

    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codeartifact-recording/v1",
            &[
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("provenance", self.provenance.as_str().to_owned()),
                ("replayed", self.replayed.to_string()),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.recomputed_digest()
        {
            return Err(AwsCodeArtifactProvenanceError::TamperedEvidence);
        }
        Ok(())
    }
}

pub struct MissionAwsCodeArtifactConsumer {
    scope: AwsCodeArtifactProvenanceScope,
    registration: AwsCodeArtifactProvenanceRegistration,
    records: BTreeMap<Digest, RecordedAwsCodeArtifactResult>,
}

impl fmt::Debug for MissionAwsCodeArtifactConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsCodeArtifactConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsCodeArtifactConsumer {
    pub fn new(
        scope: AwsCodeArtifactProvenanceScope,
        registration: AwsCodeArtifactProvenanceRegistration,
    ) -> std::result::Result<Self, ConsumerError> {
        registration.validate().map_err(ConsumerError::Service)?;
        if registration.status() != RegistrationStatus::Active {
            return Err(ConsumerError::RegistrationRevoked);
        }
        if registration.scope_digest() != &scope.digest() {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AwsCodeArtifactProvenanceScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsCodeArtifactProvenanceRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &AwsCodeArtifactProvenanceProposal,
    ) -> std::result::Result<MissionAwsCodeArtifactResult, ConsumerError> {
        if !self.registration.is_active() {
            return Err(ConsumerError::RegistrationRevoked);
        }
        proposal
            .validate_integrity()
            .map_err(|_| ConsumerError::ProposalTampered)?;
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.evidence.plugin_version_digest != Digest::from_text(crate::PLUGIN_VERSION)
            || proposal.evidence.contract_digest != *self.registration.contract_digest()
            || proposal.evidence.provider_digest != *self.registration.provider_digest()
            || proposal.evidence.permission_digest != self.registration.permission_digest()
            || proposal.evidence.consent_digest != self.registration.consent_digest()
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.mission != MissionProjection::from(self.scope.mission())
            || proposal.project != ProjectProjection::from(self.scope.project())
            || proposal.work_product != WorkProductProjection::from(self.scope.work_product())
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if proposal.connected
            || proposal.native
            || proposal.first_party
            || proposal.provider_receipt
            || proposal.outcome_adopted
            || proposal.work_product_adopted
        {
            return Err(ConsumerError::AdoptionAuthority);
        }
        let mut result = MissionAwsCodeArtifactResult {
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
            provenance: proposal.provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            result_digest: Digest::from_text("unsealed-codeartifact-mission-result"),
        };
        result.result_digest = result.recomputed_digest();
        Ok(result)
    }

    pub fn record(
        &mut self,
        proposal: &AwsCodeArtifactProvenanceProposal,
        idempotency_key: impl AsRef<str>,
    ) -> std::result::Result<RecordedAwsCodeArtifactResult, ConsumerError> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(ConsumerError::Service(
                AwsCodeArtifactProvenanceError::InvalidRequest,
            ));
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(ConsumerError::RecordingConflict);
            }
            let replay = RecordedAwsCodeArtifactResult::new(key_digest, proposal, true);
            replay
                .validate_integrity()
                .map_err(ConsumerError::Service)?;
            return Ok(replay);
        }
        if !self.registration.is_active() {
            return Err(ConsumerError::RegistrationRevoked);
        }
        let result = RecordedAwsCodeArtifactResult::new(key_digest.clone(), proposal, false);
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }
}

pub type MissionAwsCodeArtifactProvenanceConsumer = MissionAwsCodeArtifactConsumer;
pub type MissionAwsCodeArtifactProvenanceResult = MissionAwsCodeArtifactResult;
