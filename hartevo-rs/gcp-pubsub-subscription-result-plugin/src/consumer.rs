use serde::Serialize;
use thiserror::Error;

use crate::{
    GCP_PUBSUB_SUBSCRIPTION_RESULT_CONSUMER_ID, GCP_PUBSUB_SUBSCRIPTION_RESULT_PROVIDER_ID,
    GCP_PUBSUB_SUBSCRIPTION_RESULT_SERVICE_ID,
    model::{Digest, GcpPubsubSubscriptionScope, Revision, SubscriptionPosture},
    service::{
        GcpPubsubRegistration, GcpPubsubResultEvidence, GcpPubsubSubscriptionResultProposal,
        RegistrationStatus,
    },
};

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("registration is revoked or reversed")]
    RegistrationRevoked,
    #[error("Mission consumer scope or registration binding does not match")]
    ScopeMismatch,
    #[error("proposal service/provider/consumer binding does not match")]
    IdentityMismatch,
    #[error("proposal evidence is not bound to the consumer scope")]
    EvidenceMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectProjection {
    pub digest: Digest,
    pub bounded: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionProjection {
    pub digest: Digest,
    pub bounded: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductProjection {
    pub digest: Digest,
    pub bounded: String,
    pub revision: Revision,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionGcpPubsubResult {
    pub service_id: String,
    pub consumer_id: String,
    pub project: ProjectProjection,
    pub mission: MissionProjection,
    pub work_product: WorkProductProjection,
    pub posture: SubscriptionPosture,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence: GcpPubsubResultEvidence,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
    pub delivery_completion: bool,
    pub work_product_adopted: bool,
}

impl MissionGcpPubsubResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

pub struct MissionGcpPubsubConsumer {
    scope: GcpPubsubSubscriptionScope,
    registration_digest: Digest,
    registration_revision: Revision,
}

impl std::fmt::Debug for MissionGcpPubsubConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionGcpPubsubConsumer")
            .field("scope_digest", &self.scope.scope_digest())
            .field("registration_digest", &self.registration_digest)
            .field("registration_revision", &self.registration_revision)
            .finish()
    }
}

impl MissionGcpPubsubConsumer {
    pub fn new(
        scope: GcpPubsubSubscriptionScope,
        registration: &GcpPubsubRegistration,
    ) -> Result<Self, ConsumerError> {
        if registration.status != RegistrationStatus::Active {
            return Err(ConsumerError::RegistrationRevoked);
        }
        if registration.scope_digest != scope.scope_digest()
            || registration.service_id != GCP_PUBSUB_SUBSCRIPTION_RESULT_SERVICE_ID
            || registration.provider_id != GCP_PUBSUB_SUBSCRIPTION_RESULT_PROVIDER_ID
            || registration.consumer_id != GCP_PUBSUB_SUBSCRIPTION_RESULT_CONSUMER_ID
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration_digest: registration.registration_digest.clone(),
            registration_revision: registration.revision,
        })
    }

    pub fn scope(&self) -> &GcpPubsubSubscriptionScope {
        &self.scope
    }

    pub fn consume(
        &self,
        proposal: GcpPubsubSubscriptionResultProposal,
    ) -> Result<MissionGcpPubsubResult, ConsumerError> {
        if proposal.service_id != GCP_PUBSUB_SUBSCRIPTION_RESULT_SERVICE_ID
            || proposal.provider_id != GCP_PUBSUB_SUBSCRIPTION_RESULT_PROVIDER_ID
            || proposal.consumer_id != GCP_PUBSUB_SUBSCRIPTION_RESULT_CONSUMER_ID
        {
            return Err(ConsumerError::IdentityMismatch);
        }
        if proposal.scope_digest != self.scope.scope_digest()
            || proposal.registration_digest != self.registration_digest
            || proposal.registration_revision != self.registration_revision
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if proposal.evidence.scope_digest != self.scope.scope_digest()
            || proposal.evidence.permission_digest != *self.scope.permission_digest()
            || proposal.evidence.consent_digest != *self.scope.consent_digest()
            || proposal.evidence.work_product_revision != self.scope.work_product_revision()
            || proposal.evidence.authority.connected
            || proposal.evidence.authority.native_provider
            || proposal.evidence.authority.first_party
            || proposal.evidence.configuration_is_delivery_completion
        {
            return Err(ConsumerError::EvidenceMismatch);
        }
        Ok(MissionGcpPubsubResult {
            service_id: proposal.service_id,
            consumer_id: proposal.consumer_id,
            project: ProjectProjection {
                digest: self.scope.project().digest(),
                bounded: self.scope.project().redacted(),
            },
            mission: MissionProjection {
                digest: self.scope.mission().digest(),
                bounded: self.scope.mission().redacted(),
            },
            work_product: WorkProductProjection {
                digest: self.scope.work_product().digest(),
                bounded: self.scope.work_product().redacted(),
                revision: self.scope.work_product_revision(),
            },
            posture: proposal.posture,
            proposal_digest: proposal.proposal_digest,
            scope_digest: proposal.scope_digest,
            registration_digest: proposal.registration_digest,
            evidence: proposal.evidence,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_authority: false,
            delivery_completion: false,
            work_product_adopted: false,
        })
    }
}
