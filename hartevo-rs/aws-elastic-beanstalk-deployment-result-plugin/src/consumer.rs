//! Mission-facing consumer for redacted Elastic Beanstalk evidence.
//!
//! Consumption is a typed review proposal only. It cannot adopt kernel
//! Outcome authority, certify deployment success, or turn a fixture/loopback
//! observation into a native Connected claim.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AWS_ELASTIC_BEANSTALK_CONSUMER_ID,
    model::{
        AwsElasticBeanstalkDeploymentScope, Digest, MissionBinding, Registration, RegistrationState,
    },
    service::{
        AwsElasticBeanstalkDeploymentEvidence, AwsElasticBeanstalkDeploymentProposal,
        AwsElasticBeanstalkDeploymentReadResult, AwsElasticBeanstalkDeploymentServiceError,
        EvidenceStatus,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission, Project, Work Product, consent, or Mission revision is stale")]
    StaleMission,
    #[error("consumer registration is revoked")]
    Revoked,
    #[error("Elastic Beanstalk scope digest does not match the Mission binding")]
    ScopeMismatch,
    #[error("Elastic Beanstalk version fence was lost")]
    VersionLoss,
    #[error("Elastic Beanstalk provider revision fence was lost")]
    ProviderDrift,
    #[error("Elastic Beanstalk permission fence was lost")]
    PermissionLoss,
    #[error("evidence is tampered, incomplete, or outside the read-only boundary")]
    TamperedEvidence,
    #[error("Layer-1 evidence cannot claim native or Connected authority")]
    ForbiddenAuthority,
    #[error(transparent)]
    Service(#[from] AwsElasticBeanstalkDeploymentServiceError),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionAwsElasticBeanstalkDecisionState {
    ReviewOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionAwsElasticBeanstalkResult {
    pub consumer_id: String,
    pub mission: MissionBinding,
    pub evidence: AwsElasticBeanstalkDeploymentEvidence,
    pub decision_state: MissionAwsElasticBeanstalkDecisionState,
    pub accepted: bool,
    pub adopted_outcome: bool,
    pub truth_authority: bool,
    pub connected: bool,
    pub native_provider: bool,
    pub result_digest: Digest,
}

pub struct MissionAwsElasticBeanstalkConsumer {
    mission: MissionBinding,
    scope_digest: Digest,
    version_digest: Digest,
    provider_digest: Option<Digest>,
    permission_digest: Digest,
    registration_digest: Option<Digest>,
    revoked: bool,
}

impl fmt::Debug for MissionAwsElasticBeanstalkConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsElasticBeanstalkConsumer")
            .field("mission", &self.mission)
            .field("scope_digest", &self.scope_digest)
            .field("version_digest", &self.version_digest)
            .field("provider_digest", &self.provider_digest)
            .field("permission_digest", &self.permission_digest)
            .field("registration_digest", &self.registration_digest)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl MissionAwsElasticBeanstalkConsumer {
    pub fn new(scope: &AwsElasticBeanstalkDeploymentScope) -> Self {
        Self {
            mission: scope.mission.clone(),
            scope_digest: scope.scope_digest.clone(),
            version_digest: scope.version.version_digest.clone(),
            provider_digest: None,
            permission_digest: scope.permission_digest.clone(),
            registration_digest: None,
            revoked: false,
        }
    }

    pub fn from_bindings(
        mission: MissionBinding,
        scope_digest: Digest,
        version_digest: Digest,
        provider_digest: Digest,
        permission_digest: Digest,
    ) -> Self {
        Self {
            mission,
            scope_digest,
            version_digest,
            provider_digest: Some(provider_digest),
            permission_digest,
            registration_digest: None,
            revoked: false,
        }
    }

    pub fn mission(&self) -> &MissionBinding {
        &self.mission
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn bind_registration(&mut self, registration: &Registration) -> Result<(), ConsumerError> {
        if registration.state != RegistrationState::Active {
            return Err(ConsumerError::Revoked);
        }
        registration
            .verify()
            .map_err(|_| ConsumerError::TamperedEvidence)?;
        if registration.mission != self.mission
            || registration.scope_digest != self.scope_digest
            || registration.version_digest != self.version_digest
            || registration.permission_digest != self.permission_digest
        {
            return Err(ConsumerError::StaleMission);
        }
        self.provider_digest = Some(registration.provider_digest.clone());
        self.registration_digest = Some(registration.registration_digest.clone());
        Ok(())
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
        result: &AwsElasticBeanstalkDeploymentReadResult,
    ) -> Result<MissionAwsElasticBeanstalkResult, ConsumerError> {
        if self.revoked {
            return Err(ConsumerError::Revoked);
        }
        self.verify_proposal(&result.proposal)?;
        self.consume_evidence(&result.evidence)
    }

    pub fn consume_evidence(
        &self,
        evidence: &AwsElasticBeanstalkDeploymentEvidence,
    ) -> Result<MissionAwsElasticBeanstalkResult, ConsumerError> {
        if self.revoked {
            return Err(ConsumerError::Revoked);
        }
        if let Some(registration_digest) = &self.registration_digest
            && registration_digest != &evidence.registration_digest
        {
            return Err(ConsumerError::Revoked);
        }
        if evidence.mission != self.mission {
            return Err(ConsumerError::StaleMission);
        }
        if evidence.digests.scope_digest != self.scope_digest {
            return Err(ConsumerError::ScopeMismatch);
        }
        if evidence.digests.version_digest != self.version_digest {
            return Err(ConsumerError::VersionLoss);
        }
        if let Some(provider_digest) = &self.provider_digest
            && provider_digest != &evidence.digests.provider_digest
        {
            return Err(ConsumerError::ProviderDrift);
        }
        if evidence.digests.permission_digest != self.permission_digest {
            return Err(ConsumerError::PermissionLoss);
        }
        evidence
            .verify()
            .map_err(|_| ConsumerError::TamperedEvidence)?;
        if evidence.status != EvidenceStatus::Complete || evidence.authority.is_forbidden_claim() {
            return Err(ConsumerError::ForbiddenAuthority);
        }
        let mut result = MissionAwsElasticBeanstalkResult {
            consumer_id: AWS_ELASTIC_BEANSTALK_CONSUMER_ID.to_owned(),
            mission: self.mission.clone(),
            evidence: evidence.clone(),
            decision_state: MissionAwsElasticBeanstalkDecisionState::ReviewOnly,
            accepted: true,
            adopted_outcome: false,
            truth_authority: false,
            connected: false,
            native_provider: false,
            result_digest: Digest::zero(),
        };
        result.result_digest = crate::model::digest_serializable(&(
            &result.consumer_id,
            &result.mission,
            &result.evidence.digests.evidence_digest,
            result.decision_state,
            result.accepted,
            result.adopted_outcome,
            result.truth_authority,
            result.connected,
            result.native_provider,
        ))
        .map_err(|_| ConsumerError::TamperedEvidence)?;
        Ok(result)
    }

    pub fn verify_proposal(
        &self,
        proposal: &AwsElasticBeanstalkDeploymentProposal,
    ) -> Result<(), ConsumerError> {
        if self.revoked {
            return Err(ConsumerError::Revoked);
        }
        proposal
            .verify()
            .map_err(|_| ConsumerError::TamperedEvidence)?;
        if proposal.mission != self.mission {
            return Err(ConsumerError::StaleMission);
        }
        if proposal.scope_digest != self.scope_digest {
            return Err(ConsumerError::ScopeMismatch);
        }
        if proposal.version_digest != self.version_digest {
            return Err(ConsumerError::VersionLoss);
        }
        if let Some(provider_digest) = &self.provider_digest
            && provider_digest != &proposal.provider_digest
        {
            return Err(ConsumerError::ProviderDrift);
        }
        if proposal.permission_digest != self.permission_digest {
            return Err(ConsumerError::PermissionLoss);
        }
        if let Some(registration_digest) = &self.registration_digest
            && registration_digest != &proposal.registration_digest
        {
            return Err(ConsumerError::Revoked);
        }
        Ok(())
    }
}

pub type MissionAwsElasticBeanstalkDeploymentConsumer = MissionAwsElasticBeanstalkConsumer;
pub type MissionAwsElasticBeanstalkDeploymentResult = MissionAwsElasticBeanstalkResult;

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::{
        model::{
            AccountId, ApplicationName, AwsElasticBeanstalkDeploymentScope, AwsRegion,
            DeploymentBinding, DeploymentId, DeploymentVersionBinding, EnvironmentId,
            EnvironmentName, EnvironmentRevisionProjection, EnvironmentStatus, EventKind,
            EventProjection, EventSeverity, HealthStatus, MissionId, PermissionFence, PermissionId,
            ProjectBinding, ProjectId, ReadBounds, Revision, WorkProductBinding, WorkProductId,
        },
        provider::{
            AwsElasticBeanstalkProvider, DescribeEnvironmentResourcesPage,
            DescribeEnvironmentResourcesRequest, DescribeEnvironmentsPage,
            DescribeEnvironmentsRequest, DescribeEventsPage, DescribeEventsRequest,
            FixtureAwsElasticBeanstalkTransport,
        },
        service::AwsElasticBeanstalkDeploymentService,
    };

    fn service() -> AwsElasticBeanstalkDeploymentService<FixtureAwsElasticBeanstalkTransport> {
        let permission = PermissionFence::readonly(
            PermissionId::new("permission").expect("id"),
            Revision::new(1).expect("revision"),
        )
        .expect("permission");
        let scope = AwsElasticBeanstalkDeploymentScope::new(
            DeploymentBinding::new(
                DeploymentId::new("deployment").expect("id"),
                Revision::new(1).expect("revision"),
            ),
            crate::model::MissionBinding::new(
                MissionId::new("mission").expect("id"),
                Revision::new(1).expect("revision"),
            ),
            ProjectBinding::new(
                ProjectId::new("project").expect("id"),
                Revision::new(1).expect("revision"),
            ),
            WorkProductBinding::new(
                WorkProductId::new("work").expect("id"),
                Revision::new(1).expect("revision"),
            ),
            AccountId::new("123456789012").expect("account"),
            AwsRegion::new("us-east-1").expect("region"),
            ApplicationName::new("app").expect("application"),
            vec![EnvironmentName::new("prod").expect("environment")],
            DeploymentVersionBinding::new(
                Revision::new(1).expect("revision"),
                Digest::from_text("version"),
            )
            .expect("version"),
            permission.permission_digest.clone(),
        )
        .expect("scope");
        let secret = crate::model::SecretReference::for_scope(
            "keychain-ref",
            &scope,
            crate::model::RevisionId::new("secret-r1").expect("revision"),
        )
        .expect("secret");
        let definition =
            crate::provider::AwsElasticBeanstalkProviderDefinition::new().expect("definition");
        let bounds = ReadBounds::default();
        let environment_request =
            DescribeEnvironmentsRequest::new(&scope, &bounds).expect("request");
        let resource_request =
            DescribeEnvironmentResourcesRequest::new(&scope, &bounds).expect("request");
        let event_request = DescribeEventsRequest::new(&scope, &bounds).expect("request");
        let timestamp = chrono::Utc.timestamp_opt(0, 0).single().expect("epoch");
        let environment = EnvironmentRevisionProjection::new(
            EnvironmentId::new("e-1").expect("id"),
            EnvironmentName::new("prod").expect("name"),
            Revision::new(1).expect("revision"),
            EnvironmentStatus::Ready,
            HealthStatus::Green,
            scope.version.version_digest.clone(),
            timestamp,
        )
        .expect("environment");
        let resource = crate::model::ResourceProjection::new(
            EnvironmentId::new("e-1").expect("id"),
            crate::model::ResourceKind::Instance,
            1,
            Digest::from_text("resource"),
            timestamp,
        )
        .expect("resource");
        let event = EventProjection::new(
            EnvironmentId::new("e-1").expect("id"),
            "event-1",
            Revision::new(1).expect("revision"),
            timestamp,
            EventSeverity::Info,
            EventKind::Deployment,
            "message",
        )
        .expect("event");
        let mut transport = FixtureAwsElasticBeanstalkTransport::new();
        transport.push_describe_environments(Ok(DescribeEnvironmentsPage::new(
            &environment_request,
            vec![environment],
            None,
            1,
            crate::provider::ProviderProvenance::Fixture,
            definition.api_revision.clone(),
        )
        .expect("page")));
        transport.push_describe_environment_resources(Ok(DescribeEnvironmentResourcesPage::new(
            &resource_request,
            vec![resource],
            None,
            1,
            crate::provider::ProviderProvenance::Fixture,
            definition.api_revision.clone(),
        )
        .expect("page")));
        transport.push_describe_events(Ok(DescribeEventsPage::new(
            &event_request,
            vec![event],
            None,
            1,
            crate::provider::ProviderProvenance::Fixture,
            definition.api_revision,
        )
        .expect("page")));
        let provider = AwsElasticBeanstalkProvider::new(transport).expect("provider");
        AwsElasticBeanstalkDeploymentService::new(scope, permission, secret, provider)
            .expect("service")
    }

    #[test]
    fn consumer_accepts_review_only_evidence_and_never_adopts_outcome() {
        let mut service = service();
        let result = service.read().expect("read");
        let mut consumer = MissionAwsElasticBeanstalkConsumer::new(service.scope());
        consumer
            .bind_registration(service.registration())
            .expect("registration");
        let consumed = consumer.consume(&result).expect("consume");
        assert!(consumed.accepted);
        assert_eq!(
            consumed.decision_state,
            MissionAwsElasticBeanstalkDecisionState::ReviewOnly
        );
        assert!(!consumed.adopted_outcome);
        assert!(!consumed.truth_authority);
        assert!(!consumed.connected);
        assert!(!consumed.native_provider);
    }

    #[test]
    fn consumer_rejects_permission_and_scope_drift() {
        let mut service = service();
        let result = service.read().expect("read");
        let mut consumer = MissionAwsElasticBeanstalkConsumer::new(service.scope());
        consumer
            .bind_registration(service.registration())
            .expect("registration");
        let mut evidence = result.evidence.clone();
        evidence.digests.permission_digest = Digest::from_text("drift");
        assert!(matches!(
            consumer.consume_evidence(&evidence),
            Err(ConsumerError::PermissionLoss | ConsumerError::TamperedEvidence)
        ));
        let mut other_scope = service.scope().clone();
        other_scope.scope_digest = Digest::from_text("drifted-scope");
        let other = MissionAwsElasticBeanstalkConsumer::new(&other_scope);
        assert!(matches!(
            other.consume(&result),
            Err(ConsumerError::ScopeMismatch | ConsumerError::TamperedEvidence)
        ));
    }
}
