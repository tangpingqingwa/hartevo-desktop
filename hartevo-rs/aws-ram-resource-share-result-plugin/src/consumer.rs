//! Mission-facing consumer for AWS RAM review evidence.
//!
//! The consumer binds Mission, Project, Work Product, permission, scope, and
//! registration digests. It never adopts an Outcome, grants access, or becomes
//! a Truth/Verification authority.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AWS_RAM_CONSUMER_ID,
    model::{AwsRamScope, Digest, MissionBinding, RamEvidenceState},
    service::{
        AwsRamEvidence, AwsRamProposal, AwsRamRecordReceipt, AwsRamRegistration,
        AwsRamVerification, ServiceError,
    },
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error("Mission, Project, Work Product, or revision binding is stale")]
    StaleMission,
    #[error("AWS RAM consumer registration is revoked")]
    Revoked,
    #[error("AWS RAM evidence scope digest does not match the Mission scope")]
    ScopeMismatch,
    #[error("AWS RAM evidence permission fence was lost")]
    PermissionLoss,
    #[error("AWS RAM evidence is tampered")]
    TamperedEvidence,
    #[error("AWS RAM evidence cannot claim effective authorization")]
    EffectiveAuthorizationClaim,
    #[error("AWS RAM evidence is not recordable in this state")]
    StateNotRecordable,
    #[error(transparent)]
    Service(#[from] ServiceError),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionAwsRamResult {
    pub consumer_id: String,
    pub mission: MissionBinding,
    pub project: crate::model::ProjectBinding,
    pub work_product: crate::model::WorkProductBinding,
    pub evidence: AwsRamEvidence,
    pub accepted: bool,
    pub review_only: bool,
    pub adopted_outcome: bool,
    pub truth_authority: bool,
    pub effective_authorization: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub result_digest: Digest,
}

pub struct MissionAwsRamConsumer {
    mission: MissionBinding,
    project: crate::model::ProjectBinding,
    work_product: crate::model::WorkProductBinding,
    scope_digest: Digest,
    permission_digest: Digest,
    registration_digest: Option<Digest>,
    revoked: bool,
    recorded: BTreeMap<Digest, AwsRamRecordReceipt>,
}

impl std::fmt::Debug for MissionAwsRamConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionAwsRamConsumer")
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .field("scope_digest", &self.scope_digest)
            .field("permission_digest", &self.permission_digest)
            .field("registration_digest", &self.registration_digest)
            .field("revoked", &self.revoked)
            .field("recorded_count", &self.recorded.len())
            .finish()
    }
}

impl MissionAwsRamConsumer {
    pub fn new(scope: &AwsRamScope) -> Self {
        Self {
            mission: scope.mission.clone(),
            project: scope.project.clone(),
            work_product: scope.work_product.clone(),
            scope_digest: scope.scope_digest.clone(),
            permission_digest: Digest::from_text("unbound-ram-permission"),
            registration_digest: None,
            revoked: false,
            recorded: BTreeMap::new(),
        }
    }

    pub fn with_permission(scope: &AwsRamScope, permission_digest: Digest) -> Self {
        let mut consumer = Self::new(scope);
        consumer.permission_digest = permission_digest;
        consumer
    }

    pub fn from_bindings(
        mission: MissionBinding,
        project: crate::model::ProjectBinding,
        work_product: crate::model::WorkProductBinding,
        scope_digest: Digest,
        permission_digest: Digest,
    ) -> Self {
        Self {
            mission,
            project,
            work_product,
            scope_digest,
            permission_digest,
            registration_digest: None,
            revoked: false,
            recorded: BTreeMap::new(),
        }
    }

    pub fn bind_registration(
        &mut self,
        registration: &AwsRamRegistration,
    ) -> Result<(), ConsumerError> {
        if !registration.is_active() {
            return Err(ConsumerError::Revoked);
        }
        registration
            .validate()
            .map_err(|_| ConsumerError::TamperedEvidence)?;
        self.registration_digest = Some(registration.registration_digest().clone());
        self.permission_digest = registration.permission_digest().clone();
        self.scope_digest = registration.scope_digest().clone();
        Ok(())
    }

    pub fn mission(&self) -> &MissionBinding {
        &self.mission
    }

    pub fn project(&self) -> &crate::model::ProjectBinding {
        &self.project
    }

    pub fn work_product(&self) -> &crate::model::WorkProductBinding {
        &self.work_product
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        if self.revoked {
            return Err(ConsumerError::Revoked);
        }
        self.revoked = true;
        Ok(())
    }

    pub fn consume(&self, proposal: &AwsRamProposal) -> Result<MissionAwsRamResult, ConsumerError> {
        if self.revoked {
            return Err(ConsumerError::Revoked);
        }
        if let Some(registration_digest) = &self.registration_digest
            && registration_digest != &proposal.registration_digest
        {
            return Err(ConsumerError::Revoked);
        }
        if proposal.mission != self.mission
            || proposal.project != self.project
            || proposal.work_product != self.work_product
            || proposal.evidence.mission != self.mission
            || proposal.evidence.project != self.project
            || proposal.evidence.work_product != self.work_product
        {
            return Err(ConsumerError::StaleMission);
        }
        if proposal.scope_digest != self.scope_digest
            || proposal.evidence.digests.scope_digest != self.scope_digest
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if proposal.permission_digest != self.permission_digest
            || proposal.evidence.digests.permission_digest != self.permission_digest
        {
            return Err(ConsumerError::PermissionLoss);
        }
        proposal.validate_integrity().map_err(|error| match error {
            ServiceError::AuthorityEscalation => ConsumerError::EffectiveAuthorizationClaim,
            _ => ConsumerError::TamperedEvidence,
        })?;
        self.consume_evidence(&proposal.evidence)
    }

    pub fn consume_evidence(
        &self,
        evidence: &AwsRamEvidence,
    ) -> Result<MissionAwsRamResult, ConsumerError> {
        if self.revoked {
            return Err(ConsumerError::Revoked);
        }
        if evidence.mission != self.mission
            || evidence.project != self.project
            || evidence.work_product != self.work_product
        {
            return Err(ConsumerError::StaleMission);
        }
        if evidence.digests.scope_digest != self.scope_digest {
            return Err(ConsumerError::ScopeMismatch);
        }
        if evidence.digests.permission_digest != self.permission_digest {
            return Err(ConsumerError::PermissionLoss);
        }
        evidence
            .verify()
            .map_err(|_| ConsumerError::TamperedEvidence)?;
        if evidence.authority.connected
            || evidence.authority.native
            || evidence.authority.first_party
            || evidence.authority.provider_receipt
            || evidence.authority.truth_authority
            || evidence.authority.effective_authorization
            || evidence.authority.adopts_outcome
        {
            return Err(ConsumerError::EffectiveAuthorizationClaim);
        }
        if matches!(
            evidence.state,
            RamEvidenceState::Tamper | RamEvidenceState::Revoked
        ) {
            return Err(ConsumerError::StateNotRecordable);
        }
        let mut result = MissionAwsRamResult {
            consumer_id: AWS_RAM_CONSUMER_ID.to_owned(),
            mission: self.mission.clone(),
            project: self.project.clone(),
            work_product: self.work_product.clone(),
            evidence: evidence.clone(),
            accepted: evidence.state.can_be_reviewed(),
            review_only: true,
            adopted_outcome: false,
            truth_authority: false,
            effective_authorization: false,
            connected: false,
            native: false,
            first_party: false,
            result_digest: Digest::from_text("unsealed-aws-ram-mission-result"),
        };
        result.result_digest = crate::model::digest_serializable(&(
            &result.consumer_id,
            &result.mission,
            &result.project,
            &result.work_product,
            result.evidence.evidence_digest(),
            result.accepted,
            result.review_only,
            result.adopted_outcome,
            result.truth_authority,
            result.effective_authorization,
            result.connected,
            result.native,
            result.first_party,
        ))
        .map_err(|_| ConsumerError::TamperedEvidence)?;
        Ok(result)
    }

    pub fn verify_proposal(
        &self,
        proposal: &AwsRamProposal,
    ) -> Result<AwsRamVerification, ConsumerError> {
        if self.revoked {
            return Err(ConsumerError::Revoked);
        }
        if proposal.mission != self.mission
            || proposal.project != self.project
            || proposal.work_product != self.work_product
            || proposal.scope_digest != self.scope_digest
        {
            return Err(ConsumerError::StaleMission);
        }
        if proposal.permission_digest != self.permission_digest {
            return Err(ConsumerError::PermissionLoss);
        }
        proposal
            .validate_integrity()
            .map_err(|_| ConsumerError::TamperedEvidence)?;
        Ok(AwsRamVerification {
            valid: true,
            review_eligible: proposal.state.can_be_reviewed(),
            state: proposal.state,
            reason_codes: Vec::new(),
            verification_digest: Digest::from_parts(
                "aws-ram-consumer-verification/v1",
                &[proposal.proposal_digest.as_str().to_owned()],
            ),
        })
    }

    pub fn record(
        &mut self,
        proposal: &AwsRamProposal,
        idempotency_key: &str,
    ) -> Result<AwsRamRecordReceipt, ConsumerError> {
        let result = self.consume(proposal)?;
        let idempotency_digest = Digest::from_text(idempotency_key);
        if let Some(previous) = self.recorded.get(&idempotency_digest) {
            let mut replay = previous.clone();
            replay.replayed = true;
            return Ok(replay);
        }
        let record_digest = Digest::from_parts(
            "aws-ram-consumer-record/v1",
            &[
                idempotency_digest.as_str().to_owned(),
                result.evidence.evidence_digest().as_str().to_owned(),
            ],
        );
        let receipt = AwsRamRecordReceipt {
            idempotency_digest: idempotency_digest.clone(),
            evidence_digest: result.evidence.evidence_digest().clone(),
            state: result.evidence.state,
            recorded: true,
            replayed: false,
            provider_receipt: false,
            record_digest,
        };
        self.recorded.insert(idempotency_digest, receipt.clone());
        Ok(receipt)
    }
}
