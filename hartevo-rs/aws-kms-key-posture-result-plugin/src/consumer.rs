//! Mission-scoped, non-authoritative consumer for KMS posture evidence.

use serde::Serialize;
use thiserror::Error;

use crate::{
    AWS_KMS_KEY_POSTURE_CONSUMER_ID,
    model::{AwsKmsScope, Digest, KmsKeyState},
    service::{
        AwsKmsKeyPostureEvidence, AwsKmsKeyPostureReadResult, AwsKmsKeyPostureRegistration,
        RegistrationState, ServiceError,
    },
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error("Mission AWS KMS consumer registration is revoked or reversed")]
    RegistrationRevoked,
    #[error("Mission AWS KMS consumer registration or scope does not match")]
    ScopeMismatch,
    #[error("Mission AWS KMS consumer evidence is stale, replayed, or tampered")]
    EvidenceTampered,
    #[error("Mission AWS KMS consumer could not validate service evidence: {0}")]
    Service(#[from] ServiceError),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionAwsKmsDecisionState {
    ReviewRequired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsKmsResult {
    pub consumer_id: &'static str,
    pub decision_state: MissionAwsKmsDecisionState,
    pub observed_key_state: KmsKeyState,
    pub key_id_digest: Digest,
    pub key_arn_digest: Option<Digest>,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub requires_human_review: bool,
    pub safe_to_promote: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub certification_claim: bool,
    pub adopted_outcome: bool,
    pub cryptographic_verification_authority: bool,
    pub decision_digest: Digest,
}

#[derive(Clone, Debug)]
pub enum MissionAwsKmsInput {
    Evidence(Box<AwsKmsKeyPostureEvidence>),
    Read(Box<AwsKmsKeyPostureReadResult>),
}

impl From<AwsKmsKeyPostureEvidence> for MissionAwsKmsInput {
    fn from(value: AwsKmsKeyPostureEvidence) -> Self {
        Self::Evidence(Box::new(value))
    }
}

impl From<&AwsKmsKeyPostureEvidence> for MissionAwsKmsInput {
    fn from(value: &AwsKmsKeyPostureEvidence) -> Self {
        Self::Evidence(Box::new(value.clone()))
    }
}

impl From<AwsKmsKeyPostureReadResult> for MissionAwsKmsInput {
    fn from(value: AwsKmsKeyPostureReadResult) -> Self {
        Self::Read(Box::new(value))
    }
}

impl From<&AwsKmsKeyPostureReadResult> for MissionAwsKmsInput {
    fn from(value: &AwsKmsKeyPostureReadResult) -> Self {
        Self::Read(Box::new(value.clone()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionAwsKmsConsumer {
    scope: AwsKmsScope,
    registration: AwsKmsKeyPostureRegistration,
}

impl MissionAwsKmsConsumer {
    pub fn new(
        scope: AwsKmsScope,
        registration: AwsKmsKeyPostureRegistration,
    ) -> Result<Self, ConsumerError> {
        if registration.state != RegistrationState::Active
            || registration.scope_digest != scope.scope_digest
            || registration.permission_digest != scope.permission_digest
            || registration.registration_digest != registration.recomputed_digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
        })
    }

    pub fn scope(&self) -> &AwsKmsScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsKmsKeyPostureRegistration {
        &self.registration
    }

    pub fn consume(
        &self,
        input: impl Into<MissionAwsKmsInput>,
    ) -> Result<MissionAwsKmsResult, ConsumerError> {
        if self.registration.state != RegistrationState::Active {
            return Err(ConsumerError::RegistrationRevoked);
        }
        let evidence = match input.into() {
            MissionAwsKmsInput::Evidence(evidence) => evidence,
            MissionAwsKmsInput::Read(result) => {
                if result.proposal.proposal_digest != result.evidence.proposal_digest {
                    return Err(ConsumerError::EvidenceTampered);
                }
                Box::new(result.evidence)
            }
        };
        evidence
            .verify()
            .map_err(|_| ConsumerError::EvidenceTampered)?;
        if evidence.scope_digest() != &self.scope.scope_digest
            || evidence.digests.permission_digest != self.registration.permission_digest
            || evidence.registration_digest != self.registration.registration_digest
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        let decision_state = MissionAwsKmsDecisionState::ReviewRequired;
        let decision_digest = Digest::from_parts(
            "hartevo-mission-aws-kms-decision/v1",
            &[
                ("scope", self.scope.scope_digest.as_str().to_owned()),
                (
                    "registration",
                    self.registration.registration_digest.as_str().to_owned(),
                ),
                (
                    "evidence",
                    evidence.digests.evidence_digest.as_str().to_owned(),
                ),
                ("decision", format!("{decision_state:?}")),
            ],
        );
        Ok(MissionAwsKmsResult {
            consumer_id: AWS_KMS_KEY_POSTURE_CONSUMER_ID,
            decision_state,
            observed_key_state: evidence.key.state,
            key_id_digest: evidence.key.key_id_digest,
            key_arn_digest: evidence.key.key_arn_digest,
            scope_digest: self.scope.scope_digest.clone(),
            registration_digest: self.registration.registration_digest.clone(),
            evidence_digest: evidence.digests.evidence_digest,
            proposal_digest: evidence.proposal_digest,
            requires_human_review: true,
            safe_to_promote: false,
            connected: false,
            native: false,
            first_party: false,
            certification_claim: false,
            adopted_outcome: false,
            cryptographic_verification_authority: false,
            decision_digest,
        })
    }

    pub fn verify_evidence(
        &self,
        evidence: &AwsKmsKeyPostureEvidence,
    ) -> Result<(), ConsumerError> {
        if self.registration.state != RegistrationState::Active {
            return Err(ConsumerError::RegistrationRevoked);
        }
        evidence
            .verify()
            .map_err(|_| ConsumerError::EvidenceTampered)?;
        if evidence.scope_digest() != &self.scope.scope_digest
            || evidence.registration_digest != self.registration.registration_digest
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(())
    }
}

impl AwsKmsKeyPostureEvidence {
    pub(crate) fn scope_digest(&self) -> &Digest {
        &self.digests.scope_digest
    }
}
