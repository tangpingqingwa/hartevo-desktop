//! Mission-scoped consumption and idempotent recording below kernel authority.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::model::{AwsAcmCertificateScope, Digest, TransportProvenance};
use crate::service::{
    AwsAcmCertificateEvidence, AwsAcmCertificateProposal, AwsAcmRegistration,
    CertificateEvidenceState, RegistrationState,
};
use crate::{ACM_CONSUMER_ID, ACM_SERVICE_ID};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission, Project, Work Product, certificate, or registration scope is stale")]
    StaleMission,
    #[error("AWS ACM consumer registration is revoked or reversed")]
    RegistrationRevoked,
    #[error("AWS ACM evidence is tampered or incomplete")]
    TamperedEvidence,
    #[error("AWS ACM evidence lost provider access")]
    AccessLoss,
    #[error("AWS ACM recording key conflicts with a prior proposal")]
    RecordingConflict,
    #[error("AWS ACM replay is not the original proposal")]
    Replay,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Complete,
    Partial,
    AccessLoss,
    NotFound,
    ProviderUnknown,
    RegistrationRevoked,
}

impl From<CertificateEvidenceState> for ProposalDisposition {
    fn from(value: CertificateEvidenceState) -> Self {
        match value {
            CertificateEvidenceState::Complete => Self::Complete,
            CertificateEvidenceState::Partial => Self::Partial,
            CertificateEvidenceState::AccessLoss => Self::AccessLoss,
            CertificateEvidenceState::NotFound => Self::NotFound,
            CertificateEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            CertificateEvidenceState::RegistrationRevoked => Self::RegistrationRevoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsAcmResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub certificate_digest: Digest,
    pub mission: crate::model::MissionBinding,
    pub project: crate::model::ProjectBinding,
    pub work_product: crate::model::WorkProductBinding,
    pub state: CertificateEvidenceState,
    pub disposition: ProposalDisposition,
    pub certificate: Option<crate::model::CertificateProjection>,
    pub evidence: AwsAcmCertificateEvidence,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub certification_claim: bool,
    pub outcome_adopted: bool,
}

impl MissionAwsAcmResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsAcmResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: CertificateEvidenceState,
    pub disposition: ProposalDisposition,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub certification_claim: bool,
    pub outcome_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedAwsAcmResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &AwsAcmCertificateProposal,
        replayed: bool,
    ) -> Self {
        let mut result = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.state(),
            disposition: proposal.state().into(),
            provenance: proposal.evidence.provenance,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            certification_claim: false,
            outcome_adopted: false,
            recording_digest: Digest::zero(),
        };
        result.recording_digest = result.recomputed_digest();
        result
    }

    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-acm-recording/v1",
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

    pub fn validate_integrity(&self) -> Result<(), ConsumerError> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.certification_claim
            || self.outcome_adopted
            || self.recording_digest != self.recomputed_digest()
        {
            return Err(ConsumerError::TamperedEvidence);
        }
        Ok(())
    }
}

pub struct MissionAwsAcmConsumer {
    scope: AwsAcmCertificateScope,
    registration: AwsAcmRegistration,
    records: BTreeMap<Digest, RecordedAwsAcmResult>,
}

impl fmt::Debug for MissionAwsAcmConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsAcmConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsAcmConsumer {
    pub fn new(
        scope: AwsAcmCertificateScope,
        registration: AwsAcmRegistration,
    ) -> Result<Self, ConsumerError> {
        if registration.state != RegistrationState::Active
            || registration.scope_digest != scope.digest()
            || registration.certificate_digest != scope.certificate_digest()
        {
            return Err(ConsumerError::RegistrationRevoked);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn from_scope(
        scope: &AwsAcmCertificateScope,
        registration: &AwsAcmRegistration,
    ) -> Result<Self, ConsumerError> {
        Self::new(scope.clone(), registration.clone())
    }

    pub fn registration(&self) -> &AwsAcmRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &AwsAcmCertificateProposal,
    ) -> Result<MissionAwsAcmResult, ConsumerError> {
        proposal
            .validate_integrity()
            .map_err(|_| ConsumerError::TamperedEvidence)?;
        if self.registration.state != RegistrationState::Active {
            return Err(ConsumerError::RegistrationRevoked);
        }
        if proposal.service_id != ACM_SERVICE_ID
            || proposal.consumer_id != ACM_CONSUMER_ID
            || proposal.registration_digest != self.registration.registration_digest
            || proposal.scope_digest != self.scope.digest()
            || proposal.certificate_digest != self.scope.certificate_digest()
            || proposal.mission != self.scope.mission
            || proposal.project != self.scope.project
            || proposal.work_product != self.scope.work_product
            || proposal.evidence.digests.scope_digest != self.scope.digest()
            || proposal.evidence.digests.certificate_digest != self.scope.certificate_digest()
        {
            return Err(ConsumerError::StaleMission);
        }
        if proposal.evidence.state == CertificateEvidenceState::AccessLoss {
            return Err(ConsumerError::AccessLoss);
        }
        if proposal.evidence.state != CertificateEvidenceState::Complete {
            return Err(ConsumerError::TamperedEvidence);
        }
        Ok(MissionAwsAcmResult {
            service_id: ACM_SERVICE_ID.to_owned(),
            consumer_id: ACM_CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            certificate_digest: proposal.certificate_digest.clone(),
            mission: proposal.mission.clone(),
            project: proposal.project.clone(),
            work_product: proposal.work_product.clone(),
            state: proposal.state(),
            disposition: proposal.state().into(),
            certificate: proposal.certificate().cloned(),
            evidence: proposal.evidence.clone(),
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            certification_claim: false,
            outcome_adopted: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &AwsAcmCertificateProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedAwsAcmResult, ConsumerError> {
        let _ = self.consume(proposal)?;
        let idempotency_key = idempotency_key.as_ref();
        if idempotency_key.is_empty() || idempotency_key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(ConsumerError::Replay);
        }
        let idempotency_digest = Digest::from_text(idempotency_key);
        if let Some(existing) = self.records.get(&idempotency_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(ConsumerError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = replay.recomputed_digest();
            return Ok(replay);
        }
        let result = RecordedAwsAcmResult::new(idempotency_digest.clone(), proposal, false);
        self.records.insert(idempotency_digest, result.clone());
        Ok(result)
    }
}

pub type MissionAwsAcmCertificateConsumer = MissionAwsAcmConsumer;
pub type MissionAwsAcmResultRecord = RecordedAwsAcmResult;
