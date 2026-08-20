//! Mission-scoped, non-authoritative AWS IoT Device Defender consumer.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::Serialize;
use thiserror::Error;

use crate::{
    CONSUMER_ID,
    model::{AuditEvidenceState, AwsIotDeviceDefenderEvidence, AwsIotDeviceDefenderScope, Digest},
    service::{
        AwsIotDeviceDefenderProposal, AwsIotDeviceDefenderRegistration, RegistrationStatus,
        RegistrationTransitionEvidence,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission AWS IoT Device Defender consumer registration is revoked")]
    RegistrationRevoked,
    #[error("Mission AWS IoT Device Defender consumer registration is reversed")]
    RegistrationReversed,
    #[error("Mission AWS IoT Device Defender consumer registration or scope does not match")]
    ScopeMismatch,
    #[error("Mission AWS IoT Device Defender proposal is stale or tampered")]
    ProposalTampered,
    #[error("recording key is empty")]
    EmptyRecordingKey,
    #[error("recording key replay conflicts with a different proposal")]
    ReplayConflict,
    #[error("service validation failed: {0}")]
    Service(#[from] crate::AwsIotDeviceDefenderError),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionAwsIotDeviceDefenderDecisionState {
    ReviewRequired,
    Complete,
    NonCompliant,
    Unknown,
    Partial,
    AccessLoss,
    ProviderUnknown,
    NotFound,
    RetentionExpired,
    Drift,
    Throttled,
}

impl MissionAwsIotDeviceDefenderDecisionState {
    fn from_evidence(evidence: &AwsIotDeviceDefenderEvidence) -> Self {
        match evidence.state {
            AuditEvidenceState::Complete => {
                if evidence
                    .checks
                    .iter()
                    .any(|check| matches!(check.state, crate::CheckState::NonCompliant))
                {
                    Self::NonCompliant
                } else {
                    Self::Complete
                }
            }
            AuditEvidenceState::Partial | AuditEvidenceState::PaginationLoop => Self::Partial,
            AuditEvidenceState::AccessLoss => Self::AccessLoss,
            AuditEvidenceState::NotFound => Self::NotFound,
            AuditEvidenceState::RetentionExpired => Self::RetentionExpired,
            AuditEvidenceState::TaskDrift
            | AuditEvidenceState::CheckDrift
            | AuditEvidenceState::ResourceDrift => Self::Drift,
            AuditEvidenceState::Throttled => Self::Throttled,
            AuditEvidenceState::Unknown | AuditEvidenceState::ProviderUnknown => {
                Self::ProviderUnknown
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsIotDeviceDefenderResult {
    pub consumer_id: &'static str,
    pub decision_state: MissionAwsIotDeviceDefenderDecisionState,
    pub observed_audit_state: AuditEvidenceState,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub requires_human_review: bool,
    pub safe_to_promote: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopted_outcome: bool,
    pub adopted_work_product: bool,
    pub truth_authority: bool,
    pub decision_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsIotDeviceDefenderResult {
    pub recorded: bool,
    pub replayed: bool,
    pub recorded_at: DateTime<Utc>,
    pub recording_key_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub raw_finding_data_retained: bool,
    pub durable_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub receipt_digest: Digest,
}

impl RecordedAwsIotDeviceDefenderResult {
    fn new(
        proposal: &AwsIotDeviceDefenderProposal,
        recording_key: &str,
        recorded_at: DateTime<Utc>,
        replayed: bool,
    ) -> Self {
        let recording_key_digest = Digest::from_text(recording_key);
        let receipt_digest = Digest::from_parts(
            "aws-iot-device-defender-recorded-result/v1",
            &[
                replayed.to_string(),
                recorded_at.to_rfc3339(),
                recording_key_digest.to_string(),
                proposal.proposal_digest.to_string(),
                proposal.evidence.evidence_digest.to_string(),
                proposal.registration_digest.to_string(),
                proposal.scope_digest.to_string(),
            ],
        );
        Self {
            recorded: true,
            replayed,
            recorded_at,
            recording_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            raw_finding_data_retained: false,
            durable_receipt: false,
            connected: false,
            native: false,
            receipt_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionAwsIotDeviceDefenderConsumer {
    scope: AwsIotDeviceDefenderScope,
    registration: AwsIotDeviceDefenderRegistration,
    recordings: BTreeMap<String, Digest>,
}

impl MissionAwsIotDeviceDefenderConsumer {
    pub fn new(
        scope: AwsIotDeviceDefenderScope,
        registration: AwsIotDeviceDefenderRegistration,
    ) -> Result<Self, ConsumerError> {
        registration.validate()?;
        if !registration.is_active() || registration.scope_digest != scope.digest() {
            return Err(
                if matches!(registration.status, RegistrationStatus::Reversed) {
                    ConsumerError::RegistrationReversed
                } else {
                    ConsumerError::RegistrationRevoked
                },
            );
        }
        Ok(Self {
            scope,
            registration,
            recordings: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AwsIotDeviceDefenderScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsIotDeviceDefenderRegistration {
        &self.registration
    }

    pub fn consume(
        &self,
        proposal: AwsIotDeviceDefenderProposal,
    ) -> Result<MissionAwsIotDeviceDefenderResult, ConsumerError> {
        if !self.registration.is_active() {
            return Err(
                if matches!(self.registration.status, RegistrationStatus::Reversed) {
                    ConsumerError::RegistrationReversed
                } else {
                    ConsumerError::RegistrationRevoked
                },
            );
        }
        proposal
            .validate_integrity()
            .map_err(|_| ConsumerError::ProposalTampered)?;
        if proposal.registration_digest != self.registration.digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.registration_digest != self.registration.digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        let decision_state =
            MissionAwsIotDeviceDefenderDecisionState::from_evidence(&proposal.evidence);
        let decision_digest = Digest::from_parts(
            "aws-iot-device-defender-mission-decision/v1",
            &[
                self.scope.digest().to_string(),
                self.registration.digest().to_string(),
                proposal.evidence.evidence_digest.to_string(),
                proposal.proposal_digest.to_string(),
                format!("{decision_state:?}"),
            ],
        );
        Ok(MissionAwsIotDeviceDefenderResult {
            consumer_id: CONSUMER_ID,
            decision_state,
            observed_audit_state: proposal.state,
            scope_digest: self.scope.digest(),
            registration_digest: self.registration.digest(),
            evidence_digest: proposal.evidence.evidence_digest,
            proposal_digest: proposal.proposal_digest,
            requires_human_review: true,
            safe_to_promote: false,
            connected: false,
            native: false,
            first_party: false,
            adopted_outcome: false,
            adopted_work_product: false,
            truth_authority: false,
            decision_digest,
        })
    }

    pub fn verify_evidence(
        &self,
        evidence: &AwsIotDeviceDefenderEvidence,
    ) -> Result<(), ConsumerError> {
        if evidence.scope_digest != self.scope.digest()
            || evidence.registration_digest != self.registration.digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        evidence
            .validate_integrity()
            .map_err(|_| ConsumerError::ProposalTampered)
    }

    pub fn record(
        &mut self,
        proposal: &AwsIotDeviceDefenderProposal,
        recording_key: impl AsRef<str>,
    ) -> Result<RecordedAwsIotDeviceDefenderResult, ConsumerError> {
        self.record_at(proposal, recording_key, Utc::now())
    }

    pub fn record_at(
        &mut self,
        proposal: &AwsIotDeviceDefenderProposal,
        recording_key: impl AsRef<str>,
        recorded_at: DateTime<Utc>,
    ) -> Result<RecordedAwsIotDeviceDefenderResult, ConsumerError> {
        if !self.registration.is_active() {
            return Err(
                if matches!(self.registration.status, RegistrationStatus::Reversed) {
                    ConsumerError::RegistrationReversed
                } else {
                    ConsumerError::RegistrationRevoked
                },
            );
        }
        let recording_key = recording_key.as_ref();
        if recording_key.trim().is_empty() {
            return Err(ConsumerError::EmptyRecordingKey);
        }
        proposal
            .validate_integrity()
            .map_err(|_| ConsumerError::ProposalTampered)?;
        if proposal.registration_digest != self.registration.digest()
            || proposal.scope_digest != self.scope.digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        let key_digest = Digest::from_text(recording_key);
        if let Some(existing) = self.recordings.get(key_digest.as_str()) {
            if existing != &proposal.digest() {
                return Err(ConsumerError::ReplayConflict);
            }
            return Ok(RecordedAwsIotDeviceDefenderResult::new(
                proposal,
                recording_key,
                recorded_at,
                true,
            ));
        }
        self.recordings
            .insert(key_digest.as_str().to_owned(), proposal.digest());
        Ok(RecordedAwsIotDeviceDefenderResult::new(
            proposal,
            recording_key,
            recorded_at,
            false,
        ))
    }

    pub fn record_count(&self) -> usize {
        self.recordings.len()
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence, ConsumerError> {
        self.registration.revoke().map_err(ConsumerError::Service)
    }

    pub fn restore_registration(
        &mut self,
    ) -> Result<RegistrationTransitionEvidence, ConsumerError> {
        self.registration.restore().map_err(ConsumerError::Service)
    }

    pub fn reverse_registration(
        &mut self,
    ) -> Result<RegistrationTransitionEvidence, ConsumerError> {
        self.registration.reverse().map_err(ConsumerError::Service)
    }
}

pub type MissionAwsIotDeviceDefenderConsumerError = ConsumerError;
pub type MissionAwsIotDeviceDefenderMissionResult = MissionAwsIotDeviceDefenderResult;
