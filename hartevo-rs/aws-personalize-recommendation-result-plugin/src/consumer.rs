//! Mission-bound proposal consumption and idempotent recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{AwsPersonalizeRecommendationError, Result};
use crate::model::{
    AwsPersonalizeRecommendationScope, CampaignMetadata, Digest, EvidenceDigests,
    RecommendationEvidenceState, RecommendationResult, RecommenderMetadata, TransportProvenance,
};
use crate::service::{
    AwsPersonalizeRecommendationProposal, AwsPersonalizeRecommendationRegistration,
};
use crate::{CONSUMER_ID, MAX_IDENTIFIER_BYTES, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Active,
    Pending,
    Failed,
    Expired,
    Partial,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
}

impl From<RecommendationEvidenceState> for ProposalDisposition {
    fn from(value: RecommendationEvidenceState) -> Self {
        match value {
            RecommendationEvidenceState::Active => Self::Active,
            RecommendationEvidenceState::Pending => Self::Pending,
            RecommendationEvidenceState::Failed => Self::Failed,
            RecommendationEvidenceState::Expired => Self::Expired,
            RecommendationEvidenceState::Partial => Self::Partial,
            RecommendationEvidenceState::AccessLost => Self::AccessLost,
            RecommendationEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            RecommendationEvidenceState::Tampered => Self::Tampered,
            RecommendationEvidenceState::Revoked => Self::Revoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsPersonalizeResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub campaign_metadata: Option<CampaignMetadata>,
    pub recommender_metadata: Option<RecommenderMetadata>,
    pub recommendation_result: Option<RecommendationResult>,
    pub state: RecommendationEvidenceState,
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
}

impl MissionAwsPersonalizeResult {
    pub fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn is_review_only(&self) -> bool {
        self.review_only
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.evidence.validate()?;
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
        {
            return Err(AwsPersonalizeRecommendationError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsPersonalizeResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub state: RecommendationEvidenceState,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub recording_digest: Digest,
    pub replayed: bool,
}

impl RecordedAwsPersonalizeResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &AwsPersonalizeRecommendationProposal,
        replayed: bool,
    ) -> Self {
        let recording_digest = Digest::from_parts(
            "aws-personalize-recording/v1",
            &[
                ("idempotency", idempotency_key_digest.as_str().to_owned()),
                ("proposal", proposal.proposal_digest.as_str().to_owned()),
                ("scope", proposal.scope_digest.as_str().to_owned()),
                ("state", format!("{:?}", proposal.state)),
                (
                    "evidence",
                    proposal.evidence.evidence_digest.as_str().to_owned(),
                ),
                ("provenance", proposal.provenance.as_str().to_owned()),
                ("replayed", replayed.to_string()),
            ],
        );
        Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            state: proposal.state,
            evidence: proposal.evidence.clone(),
            provenance: proposal.provenance,
            recording_digest,
            replayed,
        }
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.idempotency_key_digest.validate()?;
        self.proposal_digest.validate()?;
        self.scope_digest.validate()?;
        self.evidence.validate()?;
        let expected = Digest::from_parts(
            "aws-personalize-recording/v1",
            &[
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                (
                    "evidence",
                    self.evidence.evidence_digest.as_str().to_owned(),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
                ("replayed", self.replayed.to_string()),
            ],
        );
        if expected != self.recording_digest {
            return Err(AwsPersonalizeRecommendationError::TamperedEvidence);
        }
        Ok(())
    }
}

pub struct MissionAwsPersonalizeConsumer {
    scope: AwsPersonalizeRecommendationScope,
    registration: AwsPersonalizeRecommendationRegistration,
    records: BTreeMap<Digest, RecordedAwsPersonalizeResult>,
}

impl fmt::Debug for MissionAwsPersonalizeConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsPersonalizeConsumer")
            .field("scope", &self.scope)
            .field("registration", &self.registration)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsPersonalizeConsumer {
    pub fn new(
        scope: AwsPersonalizeRecommendationScope,
        registration: AwsPersonalizeRecommendationRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(AwsPersonalizeRecommendationError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest() {
            return Err(AwsPersonalizeRecommendationError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AwsPersonalizeRecommendationScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsPersonalizeRecommendationRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &AwsPersonalizeRecommendationProposal,
    ) -> Result<MissionAwsPersonalizeResult> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(AwsPersonalizeRecommendationError::RegistrationInactive);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.mission.id_digest != self.scope.mission().digest()
            || proposal.mission.revision != self.scope.mission().revision()
            || proposal.project.id_digest != self.scope.project().digest()
            || proposal.project.revision != self.scope.project().revision()
            || proposal.work_product.id_digest != self.scope.work_product().digest()
            || proposal.work_product.revision != self.scope.work_product().revision()
        {
            return Err(AwsPersonalizeRecommendationError::ScopeMismatch);
        }
        let result = MissionAwsPersonalizeResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            campaign_metadata: proposal.campaign_metadata.clone(),
            recommender_metadata: proposal.recommender_metadata.clone(),
            recommendation_result: proposal.recommendation_result.clone(),
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
        };
        result.validate_integrity()?;
        Ok(result)
    }

    pub fn record(
        &mut self,
        proposal: &AwsPersonalizeRecommendationProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedAwsPersonalizeResult> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty()
            || key.len() > MAX_IDENTIFIER_BYTES
            || key.trim() != key
            || key.chars().any(char::is_control)
        {
            return Err(AwsPersonalizeRecommendationError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsPersonalizeRecommendationError::RecordingConflict);
            }
            let replay = RecordedAwsPersonalizeResult::new(key_digest.clone(), proposal, true);
            return Ok(replay);
        }
        if !self.registration.is_active() {
            return Err(AwsPersonalizeRecommendationError::RegistrationInactive);
        }
        let result = RecordedAwsPersonalizeResult::new(key_digest.clone(), proposal, false);
        result.validate_integrity()?;
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }
}
