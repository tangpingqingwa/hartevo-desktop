//! Service seam: registration, bounded reads, monotonicity, and local replay.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};

use crate::model::{
    AlertResultEvidenceParts, MAX_INCIDENT_TRANSITIONS, error_projection,
    projection_from_observations,
};
use crate::provider::GrafanaPage;
use crate::{
    AlertInstanceObservation, AlertResultError, AlertResultEvidence, AlertResultProjection,
    AlertResultProposal, AlertResultReadOperation, AlertState, GrafanaAlertScope, GrafanaProvider,
    GrafanaRegistration, GrafanaRegistrationState, GrafanaRevocationReceipt, GrafanaTransport,
    GrafanaTransportError, IncidentState, IncidentStateTransition, MAX_ALERT_INSTANCES, MAX_PAGES,
    TransportProvenance,
};
use crate::{contract_digest, plugin_version};

#[derive(Clone, Debug)]
pub struct GrafanaAlertResultService<T = crate::BlockedEnvGrafanaTransport>
where
    T: GrafanaTransport,
{
    provider: GrafanaProvider<T>,
    registration: GrafanaRegistration,
    seen_responses: BTreeSet<crate::Digest>,
    last_evaluation: BTreeMap<String, DateTime<Utc>>,
    incident_states: BTreeMap<String, IncidentState>,
}

impl<T> GrafanaAlertResultService<T>
where
    T: GrafanaTransport,
{
    pub fn new(provider: GrafanaProvider<T>) -> Result<Self, AlertResultError> {
        let registration = provider.registration().clone();
        registration.validate_against(provider.scope(), &contract_digest(), plugin_version())?;
        Ok(Self {
            provider,
            registration,
            seen_responses: BTreeSet::new(),
            last_evaluation: BTreeMap::new(),
            incident_states: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn provider(&self) -> &GrafanaProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn scope(&self) -> &GrafanaAlertScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn registration(&self) -> &GrafanaRegistration {
        &self.registration
    }

    #[must_use]
    pub fn provenance(&self) -> TransportProvenance {
        self.provider.provenance()
    }

    #[must_use]
    pub const fn connected(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn native(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.registration.state(), GrafanaRegistrationState::Active)
    }

    fn ensure_active(&self) -> Result<(), AlertResultError> {
        if !self.is_active() {
            return Err(AlertResultError::RegistrationRevoked);
        }
        self.registration
            .validate_against(self.scope(), &contract_digest(), plugin_version())
    }

    pub fn compile_alert_result_proposal(
        &self,
        operation: AlertResultReadOperation,
    ) -> Result<AlertResultProposal, AlertResultError> {
        self.compile_alert_result_proposal_with_page_size(operation, crate::MAX_PAGE_SIZE)
    }

    pub fn compile_alert_result_proposal_with_page_size(
        &self,
        operation: AlertResultReadOperation,
        page_size: u16,
    ) -> Result<AlertResultProposal, AlertResultError> {
        self.ensure_active()?;
        AlertResultProposal::new(self.scope(), &self.registration, operation, page_size)
    }

    pub fn describe_alert_rule(&mut self) -> Result<AlertResultEvidence, AlertResultError> {
        let proposal =
            self.compile_alert_result_proposal(AlertResultReadOperation::DescribeAlertRule)?;
        self.read_alert_result(&proposal)
    }

    pub fn read_alert_rule_metadata(&mut self) -> Result<AlertResultEvidence, AlertResultError> {
        let proposal =
            self.compile_alert_result_proposal(AlertResultReadOperation::ReadAlertRuleMetadata)?;
        self.read_alert_result(&proposal)
    }

    pub fn read_rule_group_metadata(&mut self) -> Result<AlertResultEvidence, AlertResultError> {
        let proposal =
            self.compile_alert_result_proposal(AlertResultReadOperation::ReadRuleGroupMetadata)?;
        self.read_alert_result(&proposal)
    }

    pub fn read_alert_instances(&mut self) -> Result<AlertResultEvidence, AlertResultError> {
        let proposal =
            self.compile_alert_result_proposal(AlertResultReadOperation::ReadAlertInstances)?;
        self.read_alert_result(&proposal)
    }

    pub fn record_alert_result_observation(
        &mut self,
        proposal: &AlertResultProposal,
    ) -> Result<AlertResultEvidence, AlertResultError> {
        self.read_alert_result(proposal)
    }

    pub fn read_alert_result(
        &mut self,
        proposal: &AlertResultProposal,
    ) -> Result<AlertResultEvidence, AlertResultError> {
        self.ensure_active()?;
        proposal.validate_against(self.scope(), &self.registration)?;
        let mut page = 1;
        let mut continuation_digest = None;
        let mut partial = false;
        let mut rule = None;
        let mut rule_group = None;
        let mut alert_instances = Vec::new();
        let mut request_digests = Vec::new();
        let mut response_digests = Vec::new();
        let mut response_statuses = Vec::new();
        let mut previous_continuation = None;

        loop {
            let result = self
                .provider
                .read_page(proposal, page, continuation_digest.clone())?;
            partial |= result.partial();
            request_digests.push(result.request_digest().to_owned());
            response_digests.push(result.response_digest().to_owned());
            response_statuses.push(result.response_status());
            match result {
                GrafanaPage::AlertRule {
                    metadata,
                    next_page_digest,
                    ..
                } => {
                    self.validate_rule(&metadata)?;
                    rule = Some(metadata);
                    continuation_digest = next_page_digest;
                }
                GrafanaPage::RuleGroup {
                    metadata,
                    next_page_digest,
                    ..
                } => {
                    self.validate_rule_group(&metadata)?;
                    rule_group = Some(metadata);
                    continuation_digest = next_page_digest;
                }
                GrafanaPage::AlertInstances {
                    mut instances,
                    next_page_digest,
                    ..
                } => {
                    if alert_instances.len() + instances.len() > MAX_ALERT_INSTANCES {
                        return Err(AlertResultError::BoundExceeded {
                            label: "alert instances across pages",
                            maximum: MAX_ALERT_INSTANCES,
                        });
                    }
                    for instance in &instances {
                        self.validate_instance(instance)?;
                    }
                    alert_instances.append(&mut instances);
                    continuation_digest = next_page_digest;
                }
            }
            if continuation_digest.is_none() {
                break;
            }
            if page >= MAX_PAGES {
                partial = true;
                break;
            }
            if continuation_digest == previous_continuation {
                return Err(AlertResultError::ReplayDetected);
            }
            previous_continuation.clone_from(&continuation_digest);
            page += 1;
        }

        let request_digest = crate::canonical_digest(&request_digests);
        let response_digest = crate::canonical_digest(&response_digests);
        let replay_key =
            crate::canonical_digest(&(proposal.digest(), &request_digest, &response_digest));
        if !self.seen_responses.insert(replay_key) {
            return Err(AlertResultError::ReplayDetected);
        }

        let transitions = self.enrich_and_validate_temporal_state(&alert_instances)?;
        let mut projection = if alert_instances.is_empty() {
            AlertResultProjection {
                states: if proposal.operation == AlertResultReadOperation::ReadAlertInstances {
                    vec![AlertState::NoData]
                } else {
                    vec![AlertState::Unknown]
                },
                partial,
                evaluation_timestamps: Vec::new(),
                numeric_evidence_digests: Vec::new(),
                incident_transitions: transitions.clone(),
                provider_error: None,
            }
        } else {
            projection_from_observations(&alert_instances, partial, transitions.clone())
        };
        projection.partial = partial;
        let evidence = AlertResultEvidence::from_parts(AlertResultEvidenceParts {
            operation: proposal.operation,
            rule,
            rule_group,
            alert_instances,
            projection,
            partial,
            observed_at: Utc::now(),
            response_status: response_statuses.last().copied().unwrap_or(200),
            request_digest,
            response_digest,
            proposal_digest: proposal.digest().to_owned(),
            registration_digest: self.registration.registration_digest().to_owned(),
            provider_digest: self.scope().provider_digest(),
            api_digest: self.scope().api_digest(),
            permission_digest: self.scope().permission_digest(),
            scope_digest: self.scope().digest(),
            revision_digest: self.scope().revision_digest(),
            provenance: self.provenance().into(),
        });
        evidence.verify_integrity()?;
        self.commit_temporal_state(&evidence.alert_instances);
        Ok(evidence)
    }

    /// Turn a typed transport failure into an honest unknown/partial
    /// projection. It is still proposal-only evidence and never turns an HTTP
    /// failure into a provider success or a kernel receipt.
    pub fn project_transport_error(
        &self,
        proposal: &AlertResultProposal,
        error: &GrafanaTransportError,
    ) -> Result<AlertResultEvidence, AlertResultError> {
        self.ensure_active()?;
        proposal.validate_against(self.scope(), &self.registration)?;
        let error_digest = crate::sha256_digest(error.to_string().as_bytes());
        let request_digest = crate::canonical_digest(&(proposal.digest(), "transport-error"));
        let projection = AlertResultProjection {
            states: vec![AlertState::Unknown],
            partial: true,
            evaluation_timestamps: Vec::new(),
            numeric_evidence_digests: Vec::new(),
            incident_transitions: Vec::new(),
            provider_error: Some(error_projection(error)),
        };
        let evidence = AlertResultEvidence::from_parts(AlertResultEvidenceParts {
            operation: proposal.operation,
            rule: None,
            rule_group: None,
            alert_instances: Vec::new(),
            projection,
            partial: true,
            observed_at: Utc::now(),
            response_status: transport_status(error).unwrap_or(0),
            request_digest,
            response_digest: error_digest,
            proposal_digest: proposal.digest().to_owned(),
            registration_digest: self.registration.registration_digest().to_owned(),
            provider_digest: self.scope().provider_digest(),
            api_digest: self.scope().api_digest(),
            permission_digest: self.scope().permission_digest(),
            scope_digest: self.scope().digest(),
            revision_digest: self.scope().revision_digest(),
            provenance: self.provenance().into(),
        });
        evidence.verify_integrity()?;
        Ok(evidence)
    }

    pub fn verify_alert_result(
        &self,
        proposal: &AlertResultProposal,
        evidence: &AlertResultEvidence,
    ) -> Result<(), AlertResultError> {
        self.ensure_active()?;
        proposal.validate_against(self.scope(), &self.registration)?;
        evidence.verify_integrity()?;
        if evidence.operation != proposal.operation
            || evidence.proposal_digest != proposal.digest()
            || evidence.registration_digest != self.registration.registration_digest()
            || evidence.provider_digest != self.scope().provider_digest()
            || evidence.api_digest != self.scope().api_digest()
            || evidence.permission_digest != self.scope().permission_digest()
            || evidence.scope_digest != self.scope().digest()
            || evidence.revision_digest != self.scope().revision_digest()
            || evidence.connected
            || evidence.native
        {
            return Err(AlertResultError::ScopeMismatch);
        }
        Ok(())
    }

    pub fn revoke(
        &mut self,
        reason: impl AsRef<str>,
    ) -> Result<GrafanaRevocationReceipt, AlertResultError> {
        self.registration.revoke(reason)
    }

    pub fn restore(&mut self) -> Result<(), AlertResultError> {
        self.registration.restore()
    }

    fn validate_rule(&self, metadata: &crate::AlertRuleMetadata) -> Result<(), AlertResultError> {
        if metadata.cloud_stack_id != self.scope().cloud_stack().id() {
            return Err(AlertResultError::CloudStackMismatch);
        }
        if metadata.organization_id != self.scope().organization().id() {
            return Err(AlertResultError::OrganizationMismatch);
        }
        if metadata.folder_id != self.scope().folder().id() {
            return Err(AlertResultError::FolderMismatch);
        }
        if metadata.rule_uid != self.scope().rule().id() {
            return Err(AlertResultError::RuleMismatch);
        }
        if metadata.rule_group_id != self.scope().rule_group().id() {
            return Err(AlertResultError::RuleGroupMismatch);
        }
        Ok(())
    }

    fn validate_rule_group(
        &self,
        metadata: &crate::RuleGroupMetadata,
    ) -> Result<(), AlertResultError> {
        if metadata.cloud_stack_id != self.scope().cloud_stack().id() {
            return Err(AlertResultError::CloudStackMismatch);
        }
        if metadata.organization_id != self.scope().organization().id() {
            return Err(AlertResultError::OrganizationMismatch);
        }
        if metadata.folder_id != self.scope().folder().id() {
            return Err(AlertResultError::FolderMismatch);
        }
        if metadata.rule_group_id != self.scope().rule_group().id() {
            return Err(AlertResultError::RuleGroupMismatch);
        }
        Ok(())
    }

    fn validate_instance(
        &self,
        instance: &AlertInstanceObservation,
    ) -> Result<(), AlertResultError> {
        if instance.cloud_stack_id != self.scope().cloud_stack().id() {
            return Err(AlertResultError::CloudStackMismatch);
        }
        if instance.organization_id != self.scope().organization().id() {
            return Err(AlertResultError::OrganizationMismatch);
        }
        if instance.folder_id != self.scope().folder().id() {
            return Err(AlertResultError::FolderMismatch);
        }
        if instance.rule_uid != self.scope().rule().id() {
            return Err(AlertResultError::RuleMismatch);
        }
        if instance.rule_group_id != self.scope().rule_group().id() {
            return Err(AlertResultError::RuleGroupMismatch);
        }
        if instance.alert_instance_id != self.scope().alert_instance().id() {
            return Err(AlertResultError::AlertInstanceMismatch);
        }
        Ok(())
    }

    fn enrich_and_validate_temporal_state(
        &self,
        instances: &[AlertInstanceObservation],
    ) -> Result<Vec<IncidentStateTransition>, AlertResultError> {
        let mut transitions = Vec::new();
        for instance in instances {
            if let Some(evaluation_at) = instance.evaluation_at
                && self
                    .last_evaluation
                    .get(&instance.alert_instance_id)
                    .is_some_and(|previous| evaluation_at < *previous)
            {
                return Err(AlertResultError::EvaluationTimestampRegression);
            }
            if self
                .incident_states
                .get(&instance.alert_instance_id)
                .is_some_and(|previous| *previous != instance.incident_state)
            {
                let previous = self
                    .incident_states
                    .get(&instance.alert_instance_id)
                    .copied()
                    .unwrap_or(IncidentState::Unknown);
                transitions.push(IncidentStateTransition::new(
                    previous,
                    instance.incident_state,
                    instance.evaluation_at,
                ));
            }
        }
        if transitions.len() > MAX_INCIDENT_TRANSITIONS {
            return Err(AlertResultError::BoundExceeded {
                label: "incident transitions",
                maximum: MAX_INCIDENT_TRANSITIONS,
            });
        }
        Ok(transitions)
    }

    fn commit_temporal_state(&mut self, instances: &[AlertInstanceObservation]) {
        for instance in instances {
            if let Some(evaluation_at) = instance.evaluation_at {
                self.last_evaluation
                    .insert(instance.alert_instance_id.clone(), evaluation_at);
            }
            self.incident_states
                .insert(instance.alert_instance_id.clone(), instance.incident_state);
        }
    }
}

fn transport_status(error: &GrafanaTransportError) -> Option<u16> {
    match error {
        GrafanaTransportError::Unauthorized401 => Some(401),
        GrafanaTransportError::Forbidden403 => Some(403),
        GrafanaTransportError::NotFound404 => Some(404),
        GrafanaTransportError::Conflict409 => Some(409),
        GrafanaTransportError::RateLimited429 { .. } => Some(429),
        GrafanaTransportError::Server5xx { status } => Some(*status),
        _ => None,
    }
}

impl From<TransportProvenance> for crate::EvidenceClassification {
    fn from(value: TransportProvenance) -> Self {
        match value {
            TransportProvenance::Fixture => Self::Fixture,
            TransportProvenance::Recording => Self::Recording,
            TransportProvenance::Fake => Self::Fake,
            TransportProvenance::Loopback => Self::Loopback,
            TransportProvenance::BlockedEnv => Self::BlockedEnv,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CloudStack, EvidenceClassification, GrafanaAlertScopeSpec, GrafanaApiDefinition,
        GrafanaHttpResponse, GrafanaPermissionSnapshot, IdentityBinding, RecordedFault,
        RecordingGrafanaTransport, SecretReference,
    };
    use serde_json::json;

    #[test]
    fn recording_projects_states_timestamps_labels_and_numeric_digests_without_raw_values() {
        let transport = RecordingGrafanaTransport::with_json(
            200,
            instance_json("instance-1", "Alerting", "2026-08-14T00:00:02Z", true),
        );
        let provider = GrafanaProvider::new(test_scope(), transport).unwrap();
        let mut service = GrafanaAlertResultService::new(provider).unwrap();
        let evidence = service.read_alert_instances().unwrap();
        assert_eq!(evidence.state(), AlertState::Alerting);
        assert_eq!(evidence.provenance, EvidenceClassification::Recording);
        assert!(evidence.partial);
        assert_eq!(evidence.projection.evaluation_timestamps.len(), 1);
        assert_eq!(evidence.projection.numeric_evidence_digests.len(), 1);
        let serialized = serde_json::to_string(&evidence).unwrap();
        assert!(!serialized.contains("secret-value"));
        assert!(!serialized.contains("12.5"));
        assert!(serialized.contains("severity"));
    }

    #[test]
    fn pagination_is_bounded_and_uses_only_an_opaque_continuation_digest() {
        let transport = RecordingGrafanaTransport::new();
        transport.push_response(GrafanaHttpResponse::new(
            200,
            json!({
                "alerts": [],
                "nextPageToken": "opaque-page-token"
            })
            .to_string()
            .into_bytes(),
        ));
        transport.push_response(GrafanaHttpResponse::new(
            200,
            instance_json("instance-1", "Pending", "2026-08-14T00:00:02Z", false),
        ));
        let provider = GrafanaProvider::new(test_scope(), transport).unwrap();
        let mut service = GrafanaAlertResultService::new(provider).unwrap();
        let evidence = service.read_alert_instances().unwrap();
        assert_eq!(evidence.state(), AlertState::Pending);
        assert_eq!(service.provider().transport().requests().len(), 2);
        let requests = service.provider().transport().requests();
        assert!(requests[1].query.contains_key("pageTokenDigest"));
        assert!(!requests[1].query["pageTokenDigest"].contains("opaque-page-token"));
    }

    #[test]
    fn evaluation_timestamps_cannot_move_backwards() {
        let transport = RecordingGrafanaTransport::new();
        transport.push_response(GrafanaHttpResponse::new(
            200,
            instance_json("instance-1", "Alerting", "2026-08-14T00:00:03Z", false),
        ));
        transport.push_response(GrafanaHttpResponse::new(
            200,
            instance_json("instance-1", "Recovering", "2026-08-14T00:00:02Z", false),
        ));
        let provider = GrafanaProvider::new(test_scope(), transport).unwrap();
        let mut service = GrafanaAlertResultService::new(provider).unwrap();
        service.read_alert_instances().unwrap();
        assert_eq!(
            service.read_alert_instances().unwrap_err(),
            AlertResultError::EvaluationTimestampRegression
        );
    }

    #[test]
    fn requested_http_faults_are_preserved_as_typed_retryable_or_terminal_errors() {
        let faults = [
            (RecordedFault::Unauthorized401, "HTTP_401"),
            (RecordedFault::Forbidden403, "HTTP_403"),
            (RecordedFault::NotFound404, "HTTP_404"),
            (RecordedFault::Conflict409, "HTTP_409"),
            (
                RecordedFault::RateLimited429 {
                    retry_after_seconds: Some(4),
                },
                "HTTP_429",
            ),
            (RecordedFault::Timeout, "TIMEOUT"),
            (RecordedFault::Server5xx { status: 503 }, "HTTP_5XX"),
        ];
        for (fault, expected_code) in faults {
            let transport = RecordingGrafanaTransport::new();
            transport.push_fault(fault);
            let provider = GrafanaProvider::new(test_scope(), transport).unwrap();
            let mut service = GrafanaAlertResultService::new(provider).unwrap();
            let error = service.read_alert_instances().unwrap_err();
            let AlertResultError::Transport(error) = error else {
                panic!("expected typed transport error");
            };
            assert_eq!(error.code(), expected_code);
        }
    }

    #[test]
    fn malformed_partial_redacted_and_scope_drift_frames_fail_closed_or_remain_partial() {
        let malformed = RecordingGrafanaTransport::with_json(200, b"not-json".to_vec());
        let provider = GrafanaProvider::new(test_scope(), malformed).unwrap();
        let mut service = GrafanaAlertResultService::new(provider).unwrap();
        assert_eq!(
            service.read_alert_instances().unwrap_err(),
            AlertResultError::Transport(GrafanaTransportError::MalformedResponse)
        );

        let partial = RecordingGrafanaTransport::with_json(
            200,
            json!({
                "partial": true,
                "alerts": [{
                    "id": "instance-1",
                    "ruleUid": "rule-1",
                    "labels": {"secret": "secret-value"}
                }]
            })
            .to_string()
            .into_bytes(),
        );
        let provider = GrafanaProvider::new(test_scope(), partial).unwrap();
        let mut service = GrafanaAlertResultService::new(provider).unwrap();
        let evidence = service.read_alert_instances().unwrap();
        assert!(evidence.partial);
        assert_eq!(evidence.state(), AlertState::Unknown);
        assert!(
            !serde_json::to_string(&evidence)
                .unwrap()
                .contains("secret-value")
        );

        let drift = RecordingGrafanaTransport::with_json(
            200,
            json!({
                "alerts": [{
                    "id": "instance-1",
                    "ruleUid": "rule-1",
                    "stackId": "other-stack",
                    "state": "Normal"
                }]
            })
            .to_string()
            .into_bytes(),
        );
        let provider = GrafanaProvider::new(test_scope(), drift).unwrap();
        let mut service = GrafanaAlertResultService::new(provider).unwrap();
        assert_eq!(
            service.read_alert_instances().unwrap_err(),
            AlertResultError::CloudStackMismatch
        );
    }

    #[test]
    fn replay_and_response_tamper_are_rejected() {
        let transport = RecordingGrafanaTransport::new();
        let body = instance_json("instance-1", "Normal", "2026-08-14T00:00:02Z", false);
        transport.push_response(GrafanaHttpResponse::new(200, body.clone()));
        transport.push_response(GrafanaHttpResponse::new(200, body));
        let provider = GrafanaProvider::new(test_scope(), transport.clone()).unwrap();
        let mut service = GrafanaAlertResultService::new(provider).unwrap();
        service.read_alert_instances().unwrap();
        assert_eq!(
            service.read_alert_instances().unwrap_err(),
            AlertResultError::ReplayDetected
        );

        let transport = RecordingGrafanaTransport::new();
        let provider = GrafanaProvider::new(test_scope(), transport.clone()).unwrap();
        let mut service = GrafanaAlertResultService::new(provider).unwrap();
        let proposal = service
            .compile_alert_result_proposal(AlertResultReadOperation::ReadAlertInstances)
            .unwrap();
        let request = service
            .provider()
            .compile_request(&proposal, 1, None)
            .unwrap();
        transport.push_response(
            GrafanaHttpResponse::for_request(
                &request,
                200,
                instance_json("instance-1", "Normal", "2026-08-14T00:00:02Z", false),
            )
            .tampered(),
        );
        assert_eq!(
            service.read_alert_result(&proposal).unwrap_err(),
            AlertResultError::Transport(GrafanaTransportError::ResponseTampered)
        );
    }

    fn instance_json(id: &str, state: &str, evaluation_at: &str, include_secret: bool) -> Vec<u8> {
        let mut labels = serde_json::Map::from_iter([
            ("alertname".to_owned(), json!("GrafanaAlert")),
            ("severity".to_owned(), json!("critical")),
        ]);
        if include_secret {
            labels.insert("secret".to_owned(), json!("secret-value"));
        }
        json!({
            "alerts": [{
                "id": id,
                "ruleUid": "rule-1",
                "state": state,
                "activeAt": evaluation_at,
                "labels": labels,
                "value": 12.5
            }]
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn blocked_environment_is_explicit_and_non_native() {
        let provider = GrafanaProvider::for_scope(test_scope()).unwrap();
        let service = GrafanaAlertResultService::new(provider).unwrap();
        let proposal = service
            .compile_alert_result_proposal(AlertResultReadOperation::ReadAlertInstances)
            .unwrap();
        let error = service
            .provider()
            .read_page(&proposal, 1, None)
            .unwrap_err();
        assert_eq!(
            error,
            AlertResultError::Transport(GrafanaTransportError::BlockedEnv)
        );
        let evidence = service
            .project_transport_error(&proposal, &GrafanaTransportError::BlockedEnv)
            .unwrap();
        assert_eq!(evidence.state(), AlertState::Unknown);
        assert!(!evidence.native);
        assert!(!evidence.connected);
    }

    #[test]
    fn registration_revocation_is_reversible_and_closes_reads() {
        let transport = RecordingGrafanaTransport::new();
        let provider = GrafanaProvider::new(test_scope(), transport).unwrap();
        let mut service = GrafanaAlertResultService::new(provider).unwrap();
        let receipt = service.revoke("scope retired").unwrap();
        assert_eq!(
            receipt.registration_digest,
            service.registration().registration_digest()
        );
        assert!(
            service
                .compile_alert_result_proposal(AlertResultReadOperation::ReadAlertInstances)
                .is_err()
        );
        service.restore().unwrap();
        assert!(
            service
                .compile_alert_result_proposal(AlertResultReadOperation::ReadAlertInstances)
                .is_ok()
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
