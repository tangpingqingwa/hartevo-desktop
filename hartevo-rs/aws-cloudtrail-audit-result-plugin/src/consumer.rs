//! Mission-bound CloudTrail audit evidence consumer.

use std::fmt;

use thiserror::Error;

use crate::model::{
    AuditEvidence, AuditProjection, AwsCloudTrailAuditScope, DeploymentScope, Digest,
    EffectObservation, MissionScope, ProjectScope, RedactedEventMetadata, WorkProductScope,
};
use crate::service::{AwsCloudTrailRegistration, RegistrationState};
use crate::{AWS_CLOUDTRAIL_AUDIT_PROVIDER_ID, MISSION_CLOUDTRAIL_AUDIT_CONSUMER_ID};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error("Mission CloudTrail audit consumer is revoked")]
    Revoked,
    #[error("Mission CloudTrail registration is stale, revoked, or tampered")]
    RegistrationMismatch,
    #[error("Mission CloudTrail evidence is tampered or internally inconsistent")]
    EvidenceTampered,
    #[error("Mission CloudTrail evidence does not match the exact Mission scope")]
    ScopeMismatch,
    #[error("Mission CloudTrail evidence provider or contract binding drifted")]
    BindingDrift,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionCloudTrailAuditState {
    EvidenceAvailable,
    PartialEvidence,
    RetentionUnavailable,
    AccessLost,
    ProviderUnknown,
}

impl MissionCloudTrailAuditState {
    pub const fn from_projection(projection: AuditProjection) -> Self {
        match projection {
            AuditProjection::Complete => Self::EvidenceAvailable,
            AuditProjection::Partial(_) => Self::PartialEvidence,
            AuditProjection::RetentionUnavailable => Self::RetentionUnavailable,
            AuditProjection::AccessLost => Self::AccessLost,
            AuditProjection::ProviderUnknown => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionCloudTrailAuditResult {
    pub consumer_id: &'static str,
    pub scope: AwsCloudTrailAuditScope,
    pub mission_id: String,
    pub mission_revision: u64,
    pub project_id: String,
    pub project_revision: u64,
    pub deployment_id: String,
    pub deployment_revision: u64,
    pub work_product_id: String,
    pub work_product_revision: u64,
    pub projection: AuditProjection,
    pub state: MissionCloudTrailAuditState,
    pub events: Vec<RedactedEventMetadata>,
    pub evidence: AuditEvidence,
    pub evidence_digest: Digest,
    pub effect_observation: EffectObservation,
    pub external_effect_succeeded: bool,
}

pub struct MissionCloudTrailAuditConsumer {
    scope: AwsCloudTrailAuditScope,
    registration: AwsCloudTrailRegistration,
    active: bool,
}

impl fmt::Debug for MissionCloudTrailAuditConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionCloudTrailAuditConsumer")
            .field("scope_digest", &self.scope.scope_digest())
            .field("registration", &self.registration)
            .field("active", &self.active)
            .finish()
    }
}

impl MissionCloudTrailAuditConsumer {
    pub fn new(
        scope: AwsCloudTrailAuditScope,
        registration: &AwsCloudTrailRegistration,
    ) -> Result<Self, ConsumerError> {
        if registration.state != RegistrationState::Active
            || !registration.verify_digest()
            || registration.scope_digest != scope.scope_digest()
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration: registration.clone(),
            active: true,
        })
    }

    pub fn consumer_id(&self) -> &'static str {
        MISSION_CLOUDTRAIL_AUDIT_CONSUMER_ID
    }

    pub fn registration(&self) -> &AwsCloudTrailRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &AwsCloudTrailAuditScope {
        &self.scope
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Revoked);
        }
        self.active = false;
        Ok(())
    }

    pub fn consume(
        &self,
        evidence: AuditEvidence,
    ) -> Result<MissionCloudTrailAuditResult, ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Revoked);
        }
        if self.registration.state != RegistrationState::Active
            || !self.registration.verify_digest()
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        if !evidence.verify_integrity() {
            return Err(ConsumerError::EvidenceTampered);
        }
        if evidence.scope_digest != self.registration.scope_digest
            || evidence.registration_digest != self.registration.registration_digest
            || evidence.registration_revision != self.registration.revision
            || evidence.provider_id != AWS_CLOUDTRAIL_AUDIT_PROVIDER_ID
            || evidence.digests.provider_digest != self.registration.provider_digest
            || evidence.provider_version != self.registration.provider_version
            || evidence.provider_revision != self.registration.provider_revision
            || evidence.digests.version_digest != self.registration.version_digest
            || evidence.digests.contract_digest != self.registration.contract_digest
            || evidence.digests.permission_digest != self.registration.permission_digest
            || evidence.digests.query_digest != self.registration.query_digest
        {
            return Err(ConsumerError::BindingDrift);
        }
        if evidence
            .events
            .iter()
            .any(|event| !event.matches_scope(&self.scope))
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        let state = MissionCloudTrailAuditState::from_projection(evidence.projection);
        Ok(MissionCloudTrailAuditResult {
            consumer_id: MISSION_CLOUDTRAIL_AUDIT_CONSUMER_ID,
            scope: self.scope.clone(),
            mission_id: self.scope.mission.id.clone(),
            mission_revision: self.scope.mission.revision.get(),
            project_id: self.scope.project.id.clone(),
            project_revision: self.scope.project.revision.get(),
            deployment_id: self.scope.deployment.id.clone(),
            deployment_revision: self.scope.deployment.revision.get(),
            work_product_id: self.scope.work_product.id.clone(),
            work_product_revision: self.scope.work_product.revision.get(),
            projection: evidence.projection,
            state,
            events: evidence.events.clone(),
            evidence_digest: evidence.digests.evidence_digest.clone(),
            effect_observation: evidence.effect_observation,
            external_effect_succeeded: false,
            evidence,
        })
    }

    pub fn consume_observation(
        &self,
        evidence: AuditEvidence,
    ) -> Result<MissionCloudTrailAuditResult, ConsumerError> {
        self.consume(evidence)
    }
}

// Keep the scope imports visible in this module's public API documentation;
// the consumer is explicitly bound to all four Hartevo scope dimensions.
#[allow(dead_code)]
fn _mission_scope_dimensions(
    _: &MissionScope,
    _: &ProjectScope,
    _: &DeploymentScope,
    _: &WorkProductScope,
) {
}
