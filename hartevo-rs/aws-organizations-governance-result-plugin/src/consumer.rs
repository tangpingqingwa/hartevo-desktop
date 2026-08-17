//! Mission-facing consumer that keeps AWS Organizations evidence out of Truth/Outcome authority.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    model::{AwsOrganizationsScope, Digest, MissionBinding, RegistrationState},
    service::{
        AwsOrganizationsGovernanceEvidence, AwsOrganizationsGovernanceProposal,
        AwsOrganizationsReadResult, EvidenceStatus, ServiceError,
    },
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error("Mission, Project, Work Product, consent, or Mission revision is stale")]
    StaleMission,
    #[error("consumer registration is revoked")]
    Revoked,
    #[error("AWS Organizations evidence scope digest does not match the Mission scope")]
    ScopeMismatch,
    #[error("AWS Organizations evidence permission fence was lost")]
    PermissionLoss,
    #[error("AWS Organizations hierarchy evidence is stale")]
    HierarchyDrift,
    #[error("AWS Organizations evidence is tampered or incomplete")]
    TamperedEvidence,
    #[error("Layer-1 evidence cannot claim effective authorization")]
    EffectiveAuthorizationClaim,
    #[error(transparent)]
    Service(ServiceError),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionAwsOrganizationsResult {
    pub consumer_id: String,
    pub mission: MissionBinding,
    pub evidence: AwsOrganizationsGovernanceEvidence,
    pub accepted: bool,
    pub adopted_outcome: bool,
    pub truth_authority: bool,
    pub effective_authorization: bool,
    pub result_digest: Digest,
}

pub struct MissionAwsOrganizationsConsumer {
    mission: MissionBinding,
    scope_digest: Digest,
    permission_digest: Digest,
    hierarchy_digest: Digest,
    registration_digest: Option<Digest>,
    revoked: bool,
}

impl std::fmt::Debug for MissionAwsOrganizationsConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionAwsOrganizationsConsumer")
            .field("mission", &self.mission)
            .field("scope_digest", &self.scope_digest)
            .field("permission_digest", &self.permission_digest)
            .field("hierarchy_digest", &self.hierarchy_digest)
            .field("registration_digest", &self.registration_digest)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl MissionAwsOrganizationsConsumer {
    pub fn new(scope: &AwsOrganizationsScope) -> Self {
        Self {
            mission: scope.mission.clone(),
            scope_digest: scope.scope_digest.clone(),
            permission_digest: scope.permissions.permission_digest.clone(),
            hierarchy_digest: scope.hierarchy_digest.clone(),
            registration_digest: None,
            revoked: false,
        }
    }

    pub fn from_bindings(
        mission: MissionBinding,
        scope_digest: Digest,
        permission_digest: Digest,
        hierarchy_digest: Digest,
    ) -> Self {
        Self {
            mission,
            scope_digest,
            permission_digest,
            hierarchy_digest,
            registration_digest: None,
            revoked: false,
        }
    }

    pub fn bind_registration(
        &mut self,
        registration: &crate::model::Registration,
    ) -> Result<(), ConsumerError> {
        if registration.state != RegistrationState::Active {
            return Err(ConsumerError::Revoked);
        }
        registration
            .verify()
            .map_err(|_| ConsumerError::TamperedEvidence)?;
        self.registration_digest = Some(registration.registration_digest.clone());
        Ok(())
    }

    pub fn mission(&self) -> &MissionBinding {
        &self.mission
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

    pub fn replace_mission(&mut self, mission: MissionBinding) {
        self.mission = mission;
    }

    pub fn consume(
        &self,
        result: &AwsOrganizationsReadResult,
    ) -> Result<MissionAwsOrganizationsResult, ConsumerError> {
        if self.revoked {
            return Err(ConsumerError::Revoked);
        }
        if let Some(registration_digest) = &self.registration_digest
            && registration_digest != &result.proposal.registration_digest
        {
            return Err(ConsumerError::Revoked);
        }
        if result.proposal.mission != self.mission
            || result.evidence.mission != self.mission
            || result.evidence.digests.scope_digest != self.scope_digest
        {
            return Err(ConsumerError::StaleMission);
        }
        if result.evidence.digests.permission_digest != self.permission_digest {
            return Err(ConsumerError::PermissionLoss);
        }
        if result.evidence.digests.hierarchy_digest != self.hierarchy_digest {
            return Err(ConsumerError::HierarchyDrift);
        }
        self.consume_evidence(&result.evidence)
    }

    pub fn consume_evidence(
        &self,
        evidence: &AwsOrganizationsGovernanceEvidence,
    ) -> Result<MissionAwsOrganizationsResult, ConsumerError> {
        if self.revoked {
            return Err(ConsumerError::Revoked);
        }
        if let Some(registration_digest) = &self.registration_digest
            && registration_digest != &evidence.registration_digest
        {
            return Err(ConsumerError::Revoked);
        }
        if evidence.mission != self.mission || evidence.digests.scope_digest != self.scope_digest {
            return Err(ConsumerError::StaleMission);
        }
        if evidence.digests.permission_digest != self.permission_digest {
            return Err(ConsumerError::PermissionLoss);
        }
        if evidence.digests.hierarchy_digest != self.hierarchy_digest {
            return Err(ConsumerError::HierarchyDrift);
        }
        evidence
            .verify()
            .map_err(|_| ConsumerError::TamperedEvidence)?;
        if evidence.status != EvidenceStatus::Complete {
            return Err(ConsumerError::TamperedEvidence);
        }
        if evidence.authority.effective_authorization
            || evidence.authority.connected
            || evidence.authority.native_provider
            || evidence.authority.policy_truth_authority
            || evidence.authority.durable_receipt
        {
            return Err(ConsumerError::EffectiveAuthorizationClaim);
        }
        let mut result = MissionAwsOrganizationsResult {
            consumer_id: crate::AWS_ORGANIZATIONS_GOVERNANCE_CONSUMER_ID.to_owned(),
            mission: self.mission.clone(),
            evidence: evidence.clone(),
            accepted: true,
            adopted_outcome: false,
            truth_authority: false,
            effective_authorization: false,
            result_digest: Digest::from_text("pending-mission-result-digest"),
        };
        result.result_digest = crate::model::digest_serializable(&(
            &result.consumer_id,
            &result.mission,
            &result.evidence.digests.evidence_digest,
            result.accepted,
            result.adopted_outcome,
            result.truth_authority,
            result.effective_authorization,
        ))
        .map_err(|_| ConsumerError::TamperedEvidence)?;
        Ok(result)
    }

    pub fn verify_proposal(
        &self,
        proposal: &AwsOrganizationsGovernanceProposal,
    ) -> Result<(), ConsumerError> {
        if self.revoked {
            return Err(ConsumerError::Revoked);
        }
        proposal.verify().map_err(ConsumerError::Service)?;
        if proposal.mission != self.mission || proposal.scope_digest != self.scope_digest {
            return Err(ConsumerError::StaleMission);
        }
        if proposal.permission_digest != self.permission_digest {
            return Err(ConsumerError::PermissionLoss);
        }
        if proposal.hierarchy_digest != self.hierarchy_digest {
            return Err(ConsumerError::HierarchyDrift);
        }
        Ok(())
    }
}
