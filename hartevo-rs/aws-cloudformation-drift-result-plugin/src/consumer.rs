//! Mission-scoped, below-kernel consumption and idempotent recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{AwsCloudFormationDriftError, Result};
use crate::model::{
    AwsCloudFormationDriftScope, CloudFormationEvidenceState, Digest, StackDriftStatus,
    TransportProvenance,
};
use crate::service::{
    AwsCloudFormationDriftProposal, AwsCloudFormationDriftRegistration,
    RecordedAwsCloudFormationDriftResult, RegistrationStatus,
};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Completed,
    InProgress,
    Partial,
    AccessLoss,
    Throttled,
    ProviderUnknown,
    NotFound,
    RegistrationRevoked,
}

impl From<CloudFormationEvidenceState> for ProposalDisposition {
    fn from(state: CloudFormationEvidenceState) -> Self {
        match state {
            CloudFormationEvidenceState::Completed => Self::Completed,
            CloudFormationEvidenceState::InProgress => Self::InProgress,
            CloudFormationEvidenceState::Partial => Self::Partial,
            CloudFormationEvidenceState::AccessLoss => Self::AccessLoss,
            CloudFormationEvidenceState::Throttled => Self::Throttled,
            CloudFormationEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            CloudFormationEvidenceState::NotFound => Self::NotFound,
            CloudFormationEvidenceState::RegistrationRevoked => Self::RegistrationRevoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsCloudFormationDriftResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub stack_revision: u64,
    pub state: CloudFormationEvidenceState,
    pub disposition: ProposalDisposition,
    pub observed_drift_status: Option<StackDriftStatus>,
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

impl MissionAwsCloudFormationDriftResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

/// Consumer bound to one exact registration and Mission/Project/Work Product
/// revision fence. It does not grant Truth, Receipt, Outcome, or adoption
/// authority.
pub struct MissionAwsCloudFormationDriftConsumer {
    scope: AwsCloudFormationDriftScope,
    registration: AwsCloudFormationDriftRegistration,
    records: BTreeMap<Digest, RecordedAwsCloudFormationDriftResult>,
}

impl fmt::Debug for MissionAwsCloudFormationDriftConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsCloudFormationDriftConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsCloudFormationDriftConsumer {
    pub fn new(
        scope: AwsCloudFormationDriftScope,
        registration: AwsCloudFormationDriftRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(AwsCloudFormationDriftError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest() {
            return Err(AwsCloudFormationDriftError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AwsCloudFormationDriftScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsCloudFormationDriftRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &AwsCloudFormationDriftProposal,
    ) -> Result<MissionAwsCloudFormationDriftResult> {
        proposal.validate_integrity()?;
        if self.registration.status() != RegistrationStatus::Active {
            return Err(AwsCloudFormationDriftError::RegistrationInactive);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.evidence.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.evidence.provider_digest != *self.registration.provider_digest()
            || proposal.evidence.evidence.permission_digest != self.registration.permission_digest()
            || proposal.evidence.evidence.consent_digest != self.registration.consent_digest()
            || proposal.stack_digest != self.scope.stack().digest()
            || proposal.stack_revision != self.scope.stack_revision()
            || proposal.mission.id_digest != self.scope.mission().digest()
            || proposal.project.id_digest != self.scope.project().digest()
            || proposal.work_product.id_digest != self.scope.work_product().digest()
        {
            return Err(AwsCloudFormationDriftError::ScopeMismatch);
        }
        Ok(MissionAwsCloudFormationDriftResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            stack_revision: proposal.stack_revision,
            state: proposal.state,
            disposition: proposal.state.into(),
            observed_drift_status: proposal.observed_drift_status,
            evidence_digest: proposal.evidence.evidence.evidence_digest.clone(),
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
        proposal: &AwsCloudFormationDriftProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedAwsCloudFormationDriftResult> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty()
            || key.len() > crate::MAX_IDENTIFIER_BYTES
            || key.chars().any(char::is_control)
        {
            return Err(AwsCloudFormationDriftError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsCloudFormationDriftError::RecordingConflict);
            }
            let replay =
                RecordedAwsCloudFormationDriftResult::new(key_digest.clone(), proposal, true);
            self.records.insert(key_digest, replay.clone());
            return Ok(replay);
        }
        let value = RecordedAwsCloudFormationDriftResult::new(key_digest.clone(), proposal, false);
        self.records.insert(key_digest, value.clone());
        Ok(value)
    }
}

pub type MissionAwsCloudFormationDriftConsumerResult = MissionAwsCloudFormationDriftResult;
pub type MissionAwsCloudFormationConsumer = MissionAwsCloudFormationDriftConsumer;
pub type MissionAwsCloudFormationResult = MissionAwsCloudFormationDriftResult;
pub type MissionAwsCloudFormationDriftRecording = RecordedAwsCloudFormationDriftResult;
