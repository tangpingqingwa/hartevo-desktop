use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{AwsCloudFrontDistributionError, Result};
use crate::model::{
    AwsCloudFrontDistributionScope, CloudFrontEvidenceState, CostReceipt, CostSummary,
    DeploymentProjection, Digest, DistributionProjection, EvidenceDigests, MissionProjection,
    ProjectProjection, RequestReceipt, TransportProvenance,
};
use crate::service::{AwsCloudFrontDistributionProposal, AwsCloudFrontDistributionRegistration};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Ready,
    InProgress,
    Disabled,
    Partial,
    AccessLoss,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Throttled,
    TimedOut,
    ConfigDrift,
    PaginationLoop,
    Tampered,
    ProviderUnknown,
    RegistrationRevoked,
}

impl From<CloudFrontEvidenceState> for ProposalDisposition {
    fn from(state: CloudFrontEvidenceState) -> Self {
        match state {
            CloudFrontEvidenceState::Ready => Self::Ready,
            CloudFrontEvidenceState::InProgress => Self::InProgress,
            CloudFrontEvidenceState::Disabled => Self::Disabled,
            CloudFrontEvidenceState::Partial => Self::Partial,
            CloudFrontEvidenceState::AccessLoss => Self::AccessLoss,
            CloudFrontEvidenceState::Unauthorized => Self::Unauthorized,
            CloudFrontEvidenceState::Forbidden => Self::Forbidden,
            CloudFrontEvidenceState::NotFound => Self::NotFound,
            CloudFrontEvidenceState::Conflict => Self::Conflict,
            CloudFrontEvidenceState::Throttled => Self::Throttled,
            CloudFrontEvidenceState::TimedOut => Self::TimedOut,
            CloudFrontEvidenceState::ConfigDrift => Self::ConfigDrift,
            CloudFrontEvidenceState::PaginationLoop => Self::PaginationLoop,
            CloudFrontEvidenceState::Tampered => Self::Tampered,
            CloudFrontEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            CloudFrontEvidenceState::RegistrationRevoked => Self::RegistrationRevoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsCloudFrontResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub distribution: Option<DistributionProjection>,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub deployment: DeploymentProjection,
    pub state: CloudFrontEvidenceState,
    pub disposition: ProposalDisposition,
    pub evidence: EvidenceDigests,
    pub request_receipts: Vec<RequestReceipt>,
    pub cost_receipts: Vec<CostReceipt>,
    pub cost_summary: CostSummary,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionAwsCloudFrontResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsCloudFrontResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: CloudFrontEvidenceState,
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

impl RecordedAwsCloudFrontResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &AwsCloudFrontDistributionProposal,
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
            recording_digest: Digest::from_text("unsealed-aws-cloudfront-recording"),
        };
        result.recording_digest = recording_digest(&result);
        result
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != recording_digest(self)
        {
            return Err(AwsCloudFrontDistributionError::TamperedEvidence);
        }
        self.idempotency_key_digest.validate()?;
        self.proposal_digest.validate()
    }
}

fn recording_digest(result: &RecordedAwsCloudFrontResult) -> Digest {
    Digest::from_parts(
        "aws-cloudfront-recording/v1",
        &[
            (
                "idempotency",
                result.idempotency_key_digest.as_str().to_owned(),
            ),
            ("proposal", result.proposal_digest.as_str().to_owned()),
            ("state", format!("{:?}", result.state)),
            ("provenance", result.provenance.as_str().to_owned()),
        ],
    )
}

/// Mission consumer bound to one exact CloudFront registration and scope.
pub struct MissionAwsCloudFrontConsumer {
    scope: AwsCloudFrontDistributionScope,
    registration: AwsCloudFrontDistributionRegistration,
    records: BTreeMap<Digest, RecordedAwsCloudFrontResult>,
}

impl fmt::Debug for MissionAwsCloudFrontConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsCloudFrontConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsCloudFrontConsumer {
    pub fn new(
        scope: AwsCloudFrontDistributionScope,
        registration: AwsCloudFrontDistributionRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(AwsCloudFrontDistributionError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest() {
            return Err(AwsCloudFrontDistributionError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn registration(&self) -> &AwsCloudFrontDistributionRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &AwsCloudFrontDistributionProposal,
    ) -> Result<MissionAwsCloudFrontResult> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(AwsCloudFrontDistributionError::RegistrationInactive);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.account_digest != self.scope.account().digest()
            || proposal.region_digest != self.scope.region().digest()
            || proposal.distribution_digest != self.scope.distribution().digest()
            || proposal.mission.id_digest != self.scope.mission().id_digest()
            || proposal.project.id_digest != self.scope.project().id_digest()
            || proposal.deployment.id_digest != self.scope.deployment().id_digest()
        {
            return Err(AwsCloudFrontDistributionError::ScopeMismatch);
        }
        Ok(MissionAwsCloudFrontResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            distribution: proposal.distribution.clone(),
            mission: proposal.mission.clone(),
            project: proposal.project.clone(),
            deployment: proposal.deployment.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            evidence: proposal.evidence.clone(),
            request_receipts: proposal.request_receipts.clone(),
            cost_receipts: proposal.cost_receipts.clone(),
            cost_summary: proposal.cost_summary.clone(),
            provenance: proposal.provenance,
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
        proposal: &AwsCloudFrontDistributionProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedAwsCloudFrontResult> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(AwsCloudFrontDistributionError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsCloudFrontDistributionError::ReplayConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = recording_digest(&replay);
            replay.validate_integrity()?;
            return Ok(replay);
        }
        let result = RecordedAwsCloudFrontResult::new(key_digest.clone(), proposal, false);
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }
}
