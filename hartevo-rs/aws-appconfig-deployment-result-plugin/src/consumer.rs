//! Mission-scoped proposal consumption and idempotent recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{AwsAppConfigDeploymentError, Result};
use crate::model::{
    AwsAppConfigDeploymentScope, DeploymentProjection, Digest, TransportProvenance,
};
use crate::service::{
    AwsAppConfigDeploymentProposal, AwsAppConfigDeploymentRegistration, DeploymentEvidenceState,
    EvidenceDigests,
};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Completed,
    InProgress,
    RollingBack,
    RolledBack,
    Failed,
    Stopped,
    Partial,
    NotFound,
    AccessLoss,
    Throttled,
    ProviderUnknown,
    RegistrationRevoked,
}

impl From<DeploymentEvidenceState> for ProposalDisposition {
    fn from(state: DeploymentEvidenceState) -> Self {
        match state {
            DeploymentEvidenceState::Completed => Self::Completed,
            DeploymentEvidenceState::InProgress => Self::InProgress,
            DeploymentEvidenceState::RollingBack => Self::RollingBack,
            DeploymentEvidenceState::RolledBack => Self::RolledBack,
            DeploymentEvidenceState::Failed => Self::Failed,
            DeploymentEvidenceState::Stopped => Self::Stopped,
            DeploymentEvidenceState::Partial => Self::Partial,
            DeploymentEvidenceState::NotFound => Self::NotFound,
            DeploymentEvidenceState::AccessLoss => Self::AccessLoss,
            DeploymentEvidenceState::Throttled => Self::Throttled,
            DeploymentEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            DeploymentEvidenceState::RegistrationRevoked => Self::RegistrationRevoked,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsAppConfigResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub mission: crate::model::MissionProjection,
    pub project: crate::model::ProjectProjection,
    pub work_product: crate::model::WorkProductProjection,
    pub state: DeploymentEvidenceState,
    pub disposition: ProposalDisposition,
    pub evidence: EvidenceDigests,
    pub deployment: Option<DeploymentProjection>,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl Eq for MissionAwsAppConfigResult {}

impl MissionAwsAppConfigResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsAppConfigResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: DeploymentEvidenceState,
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

impl RecordedAwsAppConfigResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &AwsAppConfigDeploymentProposal,
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
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::from_text("unsealed-aws-appconfig-recording"),
        };
        result.recording_digest = result.calculate_digest();
        result
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.calculate_digest()
        {
            return Err(AwsAppConfigDeploymentError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-appconfig-recording/v1",
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

/// Consumer scoped to one exact AppConfig registration and Mission fence.
pub struct MissionAwsAppConfigConsumer {
    scope: AwsAppConfigDeploymentScope,
    registration: AwsAppConfigDeploymentRegistration,
    records: BTreeMap<Digest, RecordedAwsAppConfigResult>,
}

impl fmt::Debug for MissionAwsAppConfigConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsAppConfigConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsAppConfigConsumer {
    pub fn new(
        scope: AwsAppConfigDeploymentScope,
        registration: AwsAppConfigDeploymentRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(AwsAppConfigDeploymentError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest() {
            return Err(AwsAppConfigDeploymentError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AwsAppConfigDeploymentScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsAppConfigDeploymentRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &AwsAppConfigDeploymentProposal,
    ) -> Result<MissionAwsAppConfigResult> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(AwsAppConfigDeploymentError::RegistrationInactive);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.mission.id_digest != self.scope.mission().digest()
            || proposal.project.id_digest != self.scope.project().digest()
            || proposal.work_product.id_digest != self.scope.work_product().digest()
            || proposal.evidence.permission_digest != self.registration.permission_digest()
            || proposal.evidence.consent_digest != self.registration.consent_digest()
        {
            return Err(AwsAppConfigDeploymentError::ScopeMismatch);
        }
        Ok(MissionAwsAppConfigResult {
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
            deployment: proposal.deployment.clone(),
            provenance: proposal.provenance.clone(),
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
        proposal: &AwsAppConfigDeploymentProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedAwsAppConfigResult> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES || key.trim() != key {
            return Err(AwsAppConfigDeploymentError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsAppConfigDeploymentError::RecordingConflict);
            }
            return Ok(RecordedAwsAppConfigResult::new(key_digest, proposal, true));
        }
        if !self.registration.is_active() {
            return Err(AwsAppConfigDeploymentError::RegistrationInactive);
        }
        let result = RecordedAwsAppConfigResult::new(key_digest.clone(), proposal, false);
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }
}

pub type MissionAwsAppConfigDeploymentConsumer = MissionAwsAppConfigConsumer;
pub type MissionAwsAppConfigDeploymentResult = MissionAwsAppConfigResult;
