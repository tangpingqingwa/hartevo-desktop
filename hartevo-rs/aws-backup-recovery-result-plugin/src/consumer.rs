//! Mission-scoped proposal consumption and idempotent recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{AwsBackupRecoveryError, Result};
use crate::model::{
    AwsBackupRecoveryScope, Digest, EvidenceDigests, RecoveryEvidenceState, TransportProvenance,
};
use crate::service::{AwsBackupRecoveryProposal, AwsBackupRecoveryRegistration};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Completed,
    InProgress,
    Partial,
    Expired,
    Deleting,
    Stopped,
    NotFound,
    AccessLoss,
    Throttled,
    ProviderUnknown,
    RegistrationRevoked,
}

impl From<RecoveryEvidenceState> for ProposalDisposition {
    fn from(state: RecoveryEvidenceState) -> Self {
        match state {
            RecoveryEvidenceState::Completed => Self::Completed,
            RecoveryEvidenceState::InProgress => Self::InProgress,
            RecoveryEvidenceState::Partial => Self::Partial,
            RecoveryEvidenceState::Expired => Self::Expired,
            RecoveryEvidenceState::Deleting => Self::Deleting,
            RecoveryEvidenceState::Stopped => Self::Stopped,
            RecoveryEvidenceState::NotFound => Self::NotFound,
            RecoveryEvidenceState::AccessLoss => Self::AccessLoss,
            RecoveryEvidenceState::Throttled => Self::Throttled,
            RecoveryEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            RecoveryEvidenceState::RegistrationRevoked => Self::RegistrationRevoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsBackupResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub mission: crate::model::MissionProjection,
    pub project: crate::model::ProjectProjection,
    pub work_product: crate::model::WorkProductProjection,
    pub state: RecoveryEvidenceState,
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

impl MissionAwsBackupResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsBackupResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: RecoveryEvidenceState,
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

impl RecordedAwsBackupResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &AwsBackupRecoveryProposal,
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
            recording_digest: Digest::from_text("unsealed-aws-backup-recording"),
        };
        result.recording_digest = Digest::from_parts(
            "aws-backup-recording/v1",
            &[
                (
                    "idempotency",
                    result.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", result.proposal_digest.as_str().to_owned()),
                ("state", format!("{:?}", result.state)),
                ("provenance", result.provenance.as_str().to_owned()),
            ],
        );
        result
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest
                != Digest::from_parts(
                    "aws-backup-recording/v1",
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
        {
            return Err(AwsBackupRecoveryError::TamperedEvidence);
        }
        Ok(())
    }
}

/// Consumer scoped to one exact AWS Backup registration and Mission fence.
pub struct MissionAwsBackupConsumer {
    scope: AwsBackupRecoveryScope,
    registration: AwsBackupRecoveryRegistration,
    records: BTreeMap<Digest, RecordedAwsBackupResult>,
}

impl fmt::Debug for MissionAwsBackupConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsBackupConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsBackupConsumer {
    pub fn new(
        scope: AwsBackupRecoveryScope,
        registration: AwsBackupRecoveryRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(AwsBackupRecoveryError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest() {
            return Err(AwsBackupRecoveryError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn registration(&self) -> &AwsBackupRecoveryRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(&self, proposal: &AwsBackupRecoveryProposal) -> Result<MissionAwsBackupResult> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(AwsBackupRecoveryError::RegistrationInactive);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.mission.id_digest != self.scope.mission().digest()
            || proposal.project.id_digest != self.scope.project().digest()
            || proposal.work_product.id_digest != self.scope.work_product().digest()
        {
            return Err(AwsBackupRecoveryError::ScopeMismatch);
        }
        Ok(MissionAwsBackupResult {
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
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &AwsBackupRecoveryProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedAwsBackupResult> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(AwsBackupRecoveryError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsBackupRecoveryError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = Digest::from_parts(
                "aws-backup-recording/v1",
                &[
                    (
                        "idempotency",
                        replay.idempotency_key_digest.as_str().to_owned(),
                    ),
                    ("proposal", replay.proposal_digest.as_str().to_owned()),
                    ("state", format!("{:?}", replay.state)),
                    ("provenance", replay.provenance.as_str().to_owned()),
                ],
            );
            return Ok(replay);
        }
        if !self.registration.is_active() {
            return Err(AwsBackupRecoveryError::RegistrationInactive);
        }
        let result = RecordedAwsBackupResult::new(key_digest.clone(), proposal, false);
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }
}
