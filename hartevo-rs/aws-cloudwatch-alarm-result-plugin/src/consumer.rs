//! Mission-facing CloudWatch consumer below Truth, Outcome, and SLO authority.

use serde::Serialize;
use thiserror::Error;

use crate::model::{
    AwsCloudWatchAlarmEvidence, AwsCloudWatchAlarmScope, Digest, MissionBinding, ProjectBinding,
    WorkProductBinding,
};
use crate::service::{
    AwsCloudWatchAlarmProposal, AwsCloudWatchAlarmServiceError, AwsCloudWatchReadResult,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error("Mission, Project, Work Product, consent, or revision is stale")]
    StaleMission,
    #[error("CloudWatch consumer registration is revoked")]
    Revoked,
    #[error("CloudWatch evidence scope digest does not match the Mission scope")]
    ScopeMismatch,
    #[error("CloudWatch evidence permission or query fence was lost")]
    PermissionOrQueryLoss,
    #[error("CloudWatch evidence is tampered, partial, empty, stale, or access-loss")]
    NonAdoptableEvidence,
    #[error(
        "Layer-1 CloudWatch evidence cannot claim connected, native, first-party, SLO, or Outcome authority"
    )]
    AuthorityClaim,
    #[error(transparent)]
    Service(#[from] AwsCloudWatchAlarmServiceError),
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsCloudWatchResult {
    pub consumer_id: String,
    pub mission: MissionBinding,
    pub project: ProjectBinding,
    pub work_product: WorkProductBinding,
    pub evidence: AwsCloudWatchAlarmEvidence,
    pub accepted: bool,
    pub adopted_outcome: bool,
    pub truth_authority: bool,
    pub production_slo_certification: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub result_digest: Digest,
}

pub struct MissionAwsCloudWatchConsumer {
    scope: Option<AwsCloudWatchAlarmScope>,
    mission: MissionBinding,
    project: ProjectBinding,
    work_product: WorkProductBinding,
    scope_digest: Digest,
    permission_digest: Digest,
    query_digest: Digest,
    registration_digest: Option<Digest>,
    revoked: bool,
}

impl std::fmt::Debug for MissionAwsCloudWatchConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionAwsCloudWatchConsumer")
            .field(
                "scope_digest",
                &self.scope.as_ref().map(AwsCloudWatchAlarmScope::digest),
            )
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .field("scope_digest", &self.scope_digest)
            .field("permission_digest", &self.permission_digest)
            .field("query_digest", &self.query_digest)
            .field("registration_digest", &self.registration_digest)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl MissionAwsCloudWatchConsumer {
    pub fn new(scope: &AwsCloudWatchAlarmScope) -> Self {
        let query_digest = crate::model::AwsCloudWatchReadRequest::for_scope(scope)
            .map_or_else(|_| Digest::zero(), |request| request.query_digest);
        Self {
            scope: Some(scope.clone()),
            mission: scope.mission.clone(),
            project: scope.project.clone(),
            work_product: scope.work_product.clone(),
            scope_digest: scope.digest(),
            permission_digest: scope.permission_digest.clone(),
            query_digest,
            registration_digest: None,
            revoked: false,
        }
    }

    pub fn from_bindings(
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        scope_digest: Digest,
        permission_digest: Digest,
        query_digest: Digest,
    ) -> Self {
        Self {
            scope: None,
            mission,
            project,
            work_product,
            scope_digest,
            permission_digest,
            query_digest,
            registration_digest: None,
            revoked: false,
        }
    }

    pub fn bind_registration(
        &mut self,
        registration: &crate::service::AwsCloudWatchAlarmRegistration,
    ) -> Result<(), ConsumerError> {
        if !registration.is_active()
            || registration.scope_digest != self.scope_digest
            || registration.permission_digest != self.permission_digest
            || registration.query_digest != self.query_digest
            || registration.registration_digest != registration.recomputed_digest()
        {
            return Err(ConsumerError::Revoked);
        }
        self.registration_digest = Some(registration.registration_digest.clone());
        Ok(())
    }

    pub fn mission(&self) -> &MissionBinding {
        &self.mission
    }

    pub fn project(&self) -> &ProjectBinding {
        &self.project
    }

    pub fn work_product(&self) -> &WorkProductBinding {
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

    pub fn consume(
        &self,
        result: &AwsCloudWatchReadResult,
    ) -> Result<MissionAwsCloudWatchResult, ConsumerError> {
        if self.revoked {
            return Err(ConsumerError::Revoked);
        }
        if let Some(registration_digest) = &self.registration_digest
            && registration_digest != &result.registration_digest
        {
            return Err(ConsumerError::Revoked);
        }
        self.consume_evidence(&result.evidence)
    }

    pub fn consume_proposal(
        &self,
        proposal: &AwsCloudWatchAlarmProposal,
    ) -> Result<MissionAwsCloudWatchResult, ConsumerError> {
        if self.revoked {
            return Err(ConsumerError::Revoked);
        }
        if let Some(registration_digest) = &self.registration_digest
            && registration_digest != &proposal.registration_digest
        {
            return Err(ConsumerError::Revoked);
        }
        self.consume_evidence(&proposal.evidence)
    }

    pub fn consume_evidence(
        &self,
        evidence: &AwsCloudWatchAlarmEvidence,
    ) -> Result<MissionAwsCloudWatchResult, ConsumerError> {
        if self.revoked {
            return Err(ConsumerError::Revoked);
        }
        if evidence.scope_digest != self.scope_digest {
            return Err(ConsumerError::ScopeMismatch);
        }
        if evidence.permission_digest != self.permission_digest
            || evidence.query_digest != self.query_digest
        {
            return Err(ConsumerError::PermissionOrQueryLoss);
        }
        if evidence.connected
            || evidence.native
            || evidence.first_party
            || evidence.provenance.connected()
            || evidence.provenance.native()
            || evidence.provenance.first_party()
        {
            return Err(ConsumerError::AuthorityClaim);
        }
        if let Some(scope) = &self.scope {
            evidence
                .validate(scope)
                .map_err(|_| ConsumerError::NonAdoptableEvidence)?;
        } else {
            evidence
                .validate_digest_only()
                .map_err(|_| ConsumerError::NonAdoptableEvidence)?;
        }
        if !evidence.is_adoptable() {
            return Err(ConsumerError::NonAdoptableEvidence);
        }
        let mut result = MissionAwsCloudWatchResult {
            consumer_id: crate::CONSUMER_ID.to_owned(),
            mission: self.mission.clone(),
            project: self.project.clone(),
            work_product: self.work_product.clone(),
            evidence: evidence.clone(),
            accepted: true,
            adopted_outcome: false,
            truth_authority: false,
            production_slo_certification: false,
            connected: false,
            native: false,
            first_party: false,
            result_digest: Digest::zero(),
        };
        result.result_digest = crate::model::digest_serialized(&(
            &result.consumer_id,
            &result.mission,
            &result.project,
            &result.work_product,
            &result.evidence.evidence_digest,
            result.accepted,
            result.adopted_outcome,
            result.truth_authority,
            result.production_slo_certification,
            result.connected,
            result.native,
            result.first_party,
        ));
        Ok(result)
    }

    pub fn verify_proposal(
        &self,
        proposal: &AwsCloudWatchAlarmProposal,
    ) -> Result<(), ConsumerError> {
        if self.revoked {
            return Err(ConsumerError::Revoked);
        }
        if proposal.query_digest != self.query_digest
            || proposal.evidence.scope_digest != self.scope_digest
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if let Some(scope) = &self.scope {
            proposal.validate(scope).map_err(ConsumerError::Service)
        } else {
            proposal
                .evidence
                .validate_digest_only()
                .map_err(|_| ConsumerError::NonAdoptableEvidence)
        }
    }
}

pub type MissionAwsCloudWatchAlarmConsumer = MissionAwsCloudWatchConsumer;
pub type MissionAwsCloudWatchAlarmResult = MissionAwsCloudWatchResult;

#[cfg(test)]
mod tests {
    #[test]
    fn consumer_has_no_outcome_authority() {
        let debug = crate::CONSUMER_ID.to_string();
        assert!(debug.contains("mission.aws-cloudwatch"));
        assert!(!crate::Layer1Authority::adopted_outcome());
    }
}
