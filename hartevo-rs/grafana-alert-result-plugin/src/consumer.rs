//! Mission consumer: a proposal-only, exact Project/Mission projection.

use serde::Serialize;
use thiserror::Error;

use crate::{
    AlertResultError, AlertResultEvidence, AlertResultProposal, AlertResultReadOperation,
    AlertState, Digest, GrafanaAlertResultService, GrafanaAlertScope, GrafanaProvider,
    GrafanaRegistration, GrafanaRevocationReceipt, IdentityBinding, IncidentStateTransition,
    MissionBinding,
};
use crate::{EvidenceClassification, GrafanaTransport};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionGrafanaAlertConsumerError {
    #[error("the Mission consumer binding is invalid")]
    BindingMismatch,
    #[error("the Mission revision is stale")]
    StaleMission,
    #[error("Grafana alert-result service failed: {0}")]
    Service(#[from] AlertResultError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAlertProjection {
    pub project: IdentityBinding,
    pub mission: MissionBinding,
    pub deployment: IdentityBinding,
    pub release: IdentityBinding,
    pub mission_revision: u64,
    pub source_evidence_digest: Digest,
    pub states: Vec<AlertState>,
    pub evaluation_timestamps: Vec<chrono::DateTime<chrono::Utc>>,
    pub numeric_evidence_digests: Vec<Digest>,
    pub incident_transitions: Vec<IncidentStateTransition>,
    pub partial: bool,
    pub provider_error_code: Option<String>,
    pub provenance: EvidenceClassification,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
}

impl MissionAlertProjection {
    fn from_evidence(
        scope: &GrafanaAlertScope,
        evidence: &AlertResultEvidence,
    ) -> Result<Self, MissionGrafanaAlertConsumerError> {
        if evidence.proposal_digest.is_empty() || evidence.scope_digest != scope.digest() {
            return Err(MissionGrafanaAlertConsumerError::BindingMismatch);
        }
        Ok(Self {
            project: scope.project().clone(),
            mission: scope.mission().clone(),
            deployment: scope.deployment().clone(),
            release: scope.release().clone(),
            mission_revision: scope.mission().revision(),
            source_evidence_digest: evidence.digest().to_owned(),
            states: evidence.projection.states.clone(),
            evaluation_timestamps: evidence.projection.evaluation_timestamps.clone(),
            numeric_evidence_digests: evidence.projection.numeric_evidence_digests.clone(),
            incident_transitions: evidence.projection.incident_transitions.clone(),
            partial: evidence.partial,
            provider_error_code: evidence
                .projection
                .provider_error
                .as_ref()
                .map(|error| error.code.clone()),
            provenance: evidence.provenance,
            proposal_only: true,
            connected: false,
            native: false,
        })
    }

    #[must_use]
    pub const fn proposal_only(&self) -> bool {
        self.proposal_only
    }

    #[must_use]
    pub const fn connected(&self) -> bool {
        self.connected
    }

    #[must_use]
    pub const fn native(&self) -> bool {
        self.native
    }
}

#[derive(Clone, Debug)]
pub struct MissionGrafanaAlertConsumer<T = crate::BlockedEnvGrafanaTransport>
where
    T: GrafanaTransport,
{
    service: GrafanaAlertResultService<T>,
}

impl<T> MissionGrafanaAlertConsumer<T>
where
    T: GrafanaTransport,
{
    pub fn new(provider: GrafanaProvider<T>) -> Result<Self, MissionGrafanaAlertConsumerError> {
        Ok(Self {
            service: GrafanaAlertResultService::new(provider)?,
        })
    }

    #[must_use]
    pub fn from_service(service: GrafanaAlertResultService<T>) -> Self {
        Self { service }
    }

    #[must_use]
    pub fn service(&self) -> &GrafanaAlertResultService<T> {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut GrafanaAlertResultService<T> {
        &mut self.service
    }

    #[must_use]
    pub fn scope(&self) -> &GrafanaAlertScope {
        self.service.scope()
    }

    #[must_use]
    pub fn registration(&self) -> &GrafanaRegistration {
        self.service.registration()
    }

    pub fn compile_alert_result_proposal(
        &self,
        operation: AlertResultReadOperation,
    ) -> Result<AlertResultProposal, MissionGrafanaAlertConsumerError> {
        Ok(self.service.compile_alert_result_proposal(operation)?)
    }

    pub fn consume(
        &mut self,
        proposal: &AlertResultProposal,
    ) -> Result<MissionAlertProjection, MissionGrafanaAlertConsumerError> {
        let current_mission = self.scope().mission().clone();
        self.consume_at_mission(proposal, &current_mission)
    }

    pub fn consume_at_mission(
        &mut self,
        proposal: &AlertResultProposal,
        current_mission: &MissionBinding,
    ) -> Result<MissionAlertProjection, MissionGrafanaAlertConsumerError> {
        if current_mission != self.scope().mission() {
            return Err(MissionGrafanaAlertConsumerError::StaleMission);
        }
        let evidence = self.service.record_alert_result_observation(proposal)?;
        self.service.verify_alert_result(proposal, &evidence)?;
        MissionAlertProjection::from_evidence(self.scope(), &evidence)
    }

    pub fn consume_alert_result(
        &mut self,
        proposal: &AlertResultProposal,
    ) -> Result<MissionAlertProjection, MissionGrafanaAlertConsumerError> {
        self.consume(proposal)
    }

    pub fn verify_alert_result(
        &self,
        proposal: &AlertResultProposal,
        evidence: &AlertResultEvidence,
    ) -> Result<(), MissionGrafanaAlertConsumerError> {
        self.service.verify_alert_result(proposal, evidence)?;
        Ok(())
    }

    pub fn revoke(
        &mut self,
        reason: impl AsRef<str>,
    ) -> Result<GrafanaRevocationReceipt, MissionGrafanaAlertConsumerError> {
        Ok(self.service.revoke(reason)?)
    }

    pub fn restore(&mut self) -> Result<(), MissionGrafanaAlertConsumerError> {
        Ok(self.service.restore()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CloudStack, GrafanaAlertScopeSpec, GrafanaApiDefinition, GrafanaPermissionSnapshot,
        IdentityBinding, RecordingGrafanaTransport, SecretReference,
    };

    #[test]
    fn stale_mission_is_rejected_before_provider_evidence_is_consumed() {
        let transport = RecordingGrafanaTransport::new();
        let provider = GrafanaProvider::new(test_scope(), transport).unwrap();
        let mut consumer = MissionGrafanaAlertConsumer::new(provider).unwrap();
        let proposal = consumer
            .compile_alert_result_proposal(AlertResultReadOperation::ReadAlertInstances)
            .unwrap();
        let stale = IdentityBinding::new("mission-1", 2).unwrap();
        assert_eq!(
            consumer.consume_at_mission(&proposal, &stale).unwrap_err(),
            MissionGrafanaAlertConsumerError::StaleMission
        );
    }

    fn test_scope() -> crate::GrafanaAlertScope {
        let binding = |id: &str| IdentityBinding::new(id, 1).unwrap();
        crate::GrafanaAlertScope::new(GrafanaAlertScopeSpec::new(
            CloudStack::new("stack-1", 1, "https://grafana.example.com").unwrap(),
            binding("org-1"),
            binding("folder-1"),
            binding("rule-1"),
            binding("group-1"),
            binding("instance-1"),
            binding("project-1"),
            binding("mission-1"),
            binding("deploy-1"),
            binding("release-1"),
            GrafanaApiDefinition::layer1(),
            GrafanaPermissionSnapshot::least_privilege(1).unwrap(),
            SecretReference::service_account_token("opaque", 1).unwrap(),
        ))
        .unwrap()
    }
}
