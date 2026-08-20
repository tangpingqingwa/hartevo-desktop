//! Mission-facing review consumer below kernel Truth/Consent/Effect authority.

use serde::Serialize;
use thiserror::Error;

use crate::model::{AwsNetworkFirewallScope, Digest, MissionBinding, ModelError};
use crate::service::{
    AwsNetworkFirewallPostureEvidence, AwsNetworkFirewallPostureProposal,
    AwsNetworkFirewallPostureRegistration, AwsNetworkFirewallReadResult, EvidenceStatus,
    ServiceError,
};
use crate::{AWS_NETWORK_FIREWALL_CONSUMER_ID, contract_digest};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission, Project, Work Product, or revision is stale")]
    StaleMission,
    #[error("consumer registration is revoked or reversed")]
    Revoked,
    #[error("AWS Network Firewall evidence scope does not match the Mission scope")]
    ScopeMismatch,
    #[error("AWS Network Firewall evidence permission fence was lost")]
    PermissionLoss,
    #[error("AWS Network Firewall policy revision fence was lost")]
    PolicyRevisionDrift,
    #[error("AWS Network Firewall evidence is tampered, partial, or unknown")]
    TamperedEvidence,
    #[error("Layer-1 evidence cannot claim connected, native, first-party, or outcome authority")]
    NativeClaim,
    #[error(transparent)]
    Service(#[from] ServiceError),
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsNetworkFirewallResult {
    pub consumer_id: &'static str,
    pub mission: MissionBinding,
    pub evidence: AwsNetworkFirewallPostureEvidence,
    pub accepted: bool,
    pub review_only: bool,
    pub safe_to_adopt: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopted_outcome: bool,
    pub truth_authority: bool,
    pub effective_authorization: bool,
    pub result_digest: Digest,
}

pub struct MissionAwsNetworkFirewallConsumer {
    scope: AwsNetworkFirewallScope,
    registration: AwsNetworkFirewallPostureRegistration,
}

impl std::fmt::Debug for MissionAwsNetworkFirewallConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionAwsNetworkFirewallConsumer")
            .field("scope_digest", &self.scope.scope_digest)
            .field("policy_digest", &self.scope.policy_digest)
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .finish()
    }
}

impl MissionAwsNetworkFirewallConsumer {
    pub fn new<S, R>(scope: S, registration: R) -> Result<Self, ConsumerError>
    where
        S: Into<AwsNetworkFirewallScope>,
        R: Into<AwsNetworkFirewallPostureRegistration>,
    {
        let scope = scope.into();
        let registration = registration.into();
        scope.validate()?;
        if !registration.is_active()
            || registration.scope_digest() != &scope.scope_digest
            || registration.permission_digest() != &scope.permissions.permission_digest
            || registration.policy_digest() != &scope.policy_digest
        {
            return Err(ConsumerError::Revoked);
        }
        Ok(Self {
            scope,
            registration,
        })
    }

    pub fn scope(&self) -> &AwsNetworkFirewallScope {
        &self.scope
    }

    pub fn mission(&self) -> &MissionBinding {
        &self.scope.mission
    }

    pub fn registration(&self) -> &AwsNetworkFirewallPostureRegistration {
        &self.registration
    }

    pub fn consume(
        &self,
        result: &AwsNetworkFirewallReadResult,
    ) -> Result<MissionAwsNetworkFirewallResult, ConsumerError> {
        if result.proposal.mission != self.scope.mission
            || result.proposal.project != self.scope.project
            || result.proposal.work_product != self.scope.work_product
        {
            return Err(ConsumerError::StaleMission);
        }
        self.consume_evidence(&result.evidence)
    }

    pub fn consume_evidence(
        &self,
        evidence: &AwsNetworkFirewallPostureEvidence,
    ) -> Result<MissionAwsNetworkFirewallResult, ConsumerError> {
        if !self.registration.is_active() {
            return Err(ConsumerError::Revoked);
        }
        if evidence.mission != self.scope.mission
            || evidence.project != self.scope.project
            || evidence.work_product != self.scope.work_product
            || evidence.digests.scope_digest != self.scope.scope_digest
            || evidence.digests.permission_digest != self.scope.permissions.permission_digest
            || evidence.digests.policy_digest != self.scope.policy_digest
            || evidence.digests.version_digest != *self.registration.service_version_digest()
            || evidence.digests.provider_digest != *self.registration.provider_digest()
            || evidence.digests.api_digest != *self.registration.api_digest()
            || evidence.digests.contract_digest != *self.registration.contract_digest()
            || evidence.registration_digest != *self.registration.registration_digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if evidence.status != EvidenceStatus::Complete {
            return Err(ConsumerError::TamperedEvidence);
        }
        if evidence.authority.connected
            || evidence.authority.native_provider
            || evidence.authority.first_party
            || evidence.authority.durable_receipt
            || evidence.authority.effective_authorization
            || evidence.authority.policy_truth_authority
            || evidence.authority.external_writes
            || evidence.authority.kernel_outcome_adoption
            || evidence.authority.work_product_adoption
            || evidence.provenance.connected()
            || evidence.provenance.native()
            || evidence.provenance.first_party()
        {
            return Err(ConsumerError::NativeClaim);
        }
        evidence.verify()?;
        let mut result = MissionAwsNetworkFirewallResult {
            consumer_id: AWS_NETWORK_FIREWALL_CONSUMER_ID,
            mission: self.scope.mission.clone(),
            evidence: evidence.clone(),
            accepted: true,
            review_only: true,
            safe_to_adopt: false,
            connected: false,
            native: false,
            first_party: false,
            adopted_outcome: false,
            truth_authority: false,
            effective_authorization: false,
            result_digest: Digest::zero(),
        };
        result.result_digest = Digest::from_parts(
            "aws-network-firewall-mission-result/v1",
            &[
                ("consumer", result.consumer_id.to_owned()),
                ("mission", result.mission.digest().as_str().to_owned()),
                (
                    "evidence",
                    result.evidence.digests.evidence_digest.as_str().to_owned(),
                ),
                ("accepted", result.accepted.to_string()),
                ("review_only", result.review_only.to_string()),
                ("safe_to_adopt", result.safe_to_adopt.to_string()),
                ("contract", contract_digest().as_str().to_owned()),
            ],
        );
        Ok(result)
    }

    pub fn verify_proposal(
        &self,
        proposal: &AwsNetworkFirewallPostureProposal,
    ) -> Result<(), ConsumerError> {
        if proposal.mission != self.scope.mission
            || proposal.project != self.scope.project
            || proposal.work_product != self.scope.work_product
            || proposal.scope_digest != self.scope.scope_digest
        {
            return Err(ConsumerError::StaleMission);
        }
        if proposal.permission_digest != self.scope.permissions.permission_digest {
            return Err(ConsumerError::PermissionLoss);
        }
        if proposal.policy_digest != self.scope.policy_digest {
            return Err(ConsumerError::PolicyRevisionDrift);
        }
        proposal.validate()?;
        Ok(())
    }
}

impl From<&AwsNetworkFirewallScope> for AwsNetworkFirewallScope {
    fn from(value: &AwsNetworkFirewallScope) -> Self {
        value.clone()
    }
}

impl From<&AwsNetworkFirewallPostureRegistration> for AwsNetworkFirewallPostureRegistration {
    fn from(value: &AwsNetworkFirewallPostureRegistration) -> Self {
        value.clone()
    }
}

pub type MissionAwsNetworkFirewallPostureConsumer = MissionAwsNetworkFirewallConsumer;
pub type MissionAwsNetworkFirewallPostureResult = MissionAwsNetworkFirewallResult;
