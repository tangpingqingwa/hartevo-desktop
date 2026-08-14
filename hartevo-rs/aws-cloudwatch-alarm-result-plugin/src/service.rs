//! Bounded CloudWatch alarm read, proposal, recording, and verification.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::Serialize;
use thiserror::Error;

use crate::model::{
    AlarmState, AwsCloudWatchAlarmEvidence, AwsCloudWatchAlarmScope, AwsCloudWatchOperation,
    AwsCloudWatchReadRequest, Digest, EvidenceStatus, MetricDataAggregate, ModelError,
    PartialReason, PermissionAction, PermissionSnapshot, ProviderErrorEvidence, ProviderRevision,
    RedactedRequestReceipt, Revision, SecretReference, digest_serialized,
};
use crate::provider::{
    AwsCloudWatchProvider, AwsCloudWatchProviderDefinition, AwsCloudWatchProviderError,
    AwsCloudWatchTransport, AwsCloudWatchTransportError, DescribeAlarmsRequest,
    GetMetricDataRequest, ListMetricsRequest, is_access_loss, redacted_receipt,
};
use crate::{
    CONTRACT_VERSION, MAX_PAGES, MAX_REQUESTS_PER_READ, MAX_RESPONSE_BYTES, MAX_RETRIES,
    PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID, contract_digest,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RegistrationError {
    #[error("CloudWatch registration model error: {0}")]
    Model(#[from] ModelError),
    #[error("CloudWatch registration is already revoked or reversed")]
    AlreadyTerminal,
    #[error("CloudWatch registration transition is invalid")]
    InvalidTransition,
    #[error("CloudWatch registration revision overflowed")]
    RevisionOverflow,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AwsCloudWatchAlarmServiceError {
    #[error("CloudWatch service model error: {0}")]
    Model(#[from] ModelError),
    #[error("CloudWatch provider error: {0}")]
    Provider(#[from] AwsCloudWatchProviderError),
    #[error("CloudWatch registration is revoked or reversed")]
    RegistrationRevoked,
    #[error("CloudWatch registration has drifted: {0}")]
    RegistrationDrift(String),
    #[error("CloudWatch scope or permission fence mismatch: {0}")]
    ScopeMismatch(String),
    #[error("CloudWatch query, alarm, metric, or window drift detected")]
    QueryDrift,
    #[error("CloudWatch evidence is stale, incomplete, or tampered")]
    EvidenceTampered,
    #[error("CloudWatch proposal is stale or tampered")]
    ProposalTampered,
    #[error("CloudWatch record is stale or tampered")]
    RecordTampered,
    #[error("CloudWatch evidence is not adoptable")]
    EvidenceNotAdoptable,
    #[error("CloudWatch registration lifecycle error: {0}")]
    Registration(#[from] RegistrationError),
    #[error("CloudWatch SigV4 secret reference is revoked")]
    SecretRevoked,
    #[error("CloudWatch scan loop or cursor replay detected")]
    ScanLoop,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCloudWatchCapabilities {
    pub service_id: &'static str,
    pub provider_id: &'static str,
    pub operations: [&'static str; 9],
    pub allowlisted_api_operations: [&'static str; 3],
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub raw_dimensions: bool,
    pub raw_datapoints: bool,
    pub alarm_actions: bool,
    pub dashboard_mutation: bool,
    pub log_retrieval: bool,
    pub arbitrary_metric_scan: bool,
    pub production_slo_certification: bool,
    pub outcome_authority: bool,
}

impl AwsCloudWatchCapabilities {
    pub const fn layer_one() -> Self {
        Self {
            service_id: SERVICE_ID,
            provider_id: PROVIDER_ID,
            operations: [
                "describe_capabilities",
                "register",
                "revoke_registration",
                "reverse_registration",
                "restore_registration",
                "read_bounded",
                "propose",
                "record",
                "verify",
            ],
            allowlisted_api_operations: ["DescribeAlarms", "GetMetricData", "ListMetrics"],
            read_only: true,
            proposal_only: true,
            recording_only: true,
            live_execution: false,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
            raw_dimensions: false,
            raw_datapoints: false,
            alarm_actions: false,
            dashboard_mutation: false,
            log_retrieval: false,
            arbitrary_metric_scan: false,
            production_slo_certification: false,
            outcome_authority: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCloudWatchAlarmRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationBody<'a> {
    plugin_version: &'a str,
    contract_version: &'a str,
    contract_digest: &'a Digest,
    provider_id: &'a str,
    provider_version: &'a str,
    provider_revision: &'a ProviderRevision,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    query_digest: &'a Digest,
    evidence_digest: &'a Digest,
    secret_reference_digest: &'a Digest,
    registration_revision: Revision,
    state: RegistrationState,
}

impl AwsCloudWatchAlarmRegistration {
    fn new(
        scope: &AwsCloudWatchAlarmScope,
        secret_reference: &SecretReference,
        provider: &AwsCloudWatchProviderDefinition,
    ) -> Result<Self, RegistrationError> {
        let evidence_digest = Digest::from_parts(
            "hartevo-aws-cloudwatch-evidence-policy/v1",
            [
                ("contract", CONTRACT_VERSION),
                ("max_response_bytes", &MAX_RESPONSE_BYTES.to_string()),
                ("max_pages", &MAX_PAGES.to_string()),
                ("max_requests", &MAX_REQUESTS_PER_READ.to_string()),
                ("max_retries", &MAX_RETRIES.to_string()),
                ("raw_dimensions", "false"),
                ("raw_datapoints", "false"),
                ("alarm_actions", "false"),
            ],
        );
        let query_digest = AwsCloudWatchReadRequest::for_scope(scope)?.query_digest;
        let mut registration = Self {
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.provider_version.clone(),
            provider_revision: provider.provider_revision.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            permission_digest: scope.permission_digest.clone(),
            scope_digest: scope.digest(),
            query_digest,
            evidence_digest,
            secret_reference_digest: secret_reference.reference_digest().clone(),
            registration_revision: Revision::new(1)?,
            state: RegistrationState::Active,
            registration_digest: Digest::zero(),
        };
        registration.registration_digest = registration.recomputed_digest();
        Ok(registration)
    }

    pub fn is_active(&self) -> bool {
        self.state == RegistrationState::Active
    }

    pub fn is_revoked(&self) -> bool {
        self.state == RegistrationState::Revoked
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&RegistrationBody {
            plugin_version: &self.plugin_version,
            contract_version: &self.contract_version,
            contract_digest: &self.contract_digest,
            provider_id: &self.provider_id,
            provider_version: &self.provider_version,
            provider_revision: &self.provider_revision,
            provider_digest: &self.provider_digest,
            api_digest: &self.api_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            query_digest: &self.query_digest,
            evidence_digest: &self.evidence_digest,
            secret_reference_digest: &self.secret_reference_digest,
            registration_revision: self.registration_revision,
            state: self.state,
        })
    }

    pub fn validate(
        &self,
        scope: &AwsCloudWatchAlarmScope,
        secret_reference: &SecretReference,
        provider: &AwsCloudWatchProviderDefinition,
    ) -> Result<(), RegistrationError> {
        let query_digest = AwsCloudWatchReadRequest::for_scope(scope)?.query_digest;
        if self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != provider.provider_id
            || self.provider_version != provider.provider_version
            || self.provider_revision != provider.provider_revision
            || self.provider_digest != provider.provider_digest
            || self.api_digest != provider.api_digest
            || self.permission_digest != scope.permission_digest
            || self.scope_digest != scope.digest()
            || self.query_digest != query_digest
            || self.secret_reference_digest != *secret_reference.reference_digest()
            || self.registration_digest != self.recomputed_digest()
        {
            return Err(RegistrationError::Model(ModelError::ScopeMismatch {
                field: "registration digest binding",
            }));
        }
        Ok(())
    }

    fn transition(&mut self, state: RegistrationState) -> Result<(), RegistrationError> {
        if self.state != RegistrationState::Active {
            return Err(RegistrationError::AlreadyTerminal);
        }
        let next = self
            .registration_revision
            .get()
            .checked_add(1)
            .ok_or(RegistrationError::RevisionOverflow)?;
        self.registration_revision = Revision::new(next)?;
        self.state = state;
        self.registration_digest = self.recomputed_digest();
        Ok(())
    }

    fn restore(&mut self) -> Result<(), RegistrationError> {
        if self.state != RegistrationState::Reversed {
            return Err(RegistrationError::InvalidTransition);
        }
        let next = self
            .registration_revision
            .get()
            .checked_add(1)
            .ok_or(RegistrationError::RevisionOverflow)?;
        self.registration_revision = Revision::new(next)?;
        self.state = RegistrationState::Active;
        self.registration_digest = self.recomputed_digest();
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCloudWatchReadResult {
    pub evidence: AwsCloudWatchAlarmEvidence,
    pub page_digests: Vec<Digest>,
    pub registration_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCloudWatchAlarmProposal {
    pub operation: AwsCloudWatchOperation,
    pub evidence: AwsCloudWatchAlarmEvidence,
    pub proposed_at: DateTime<Utc>,
    pub registration_digest: Digest,
    pub query_digest: Digest,
    pub proposal_digest: Digest,
    pub read_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub production_slo_certification: bool,
    pub adopted_outcome: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposalBody<'a> {
    operation: AwsCloudWatchOperation,
    evidence: &'a AwsCloudWatchAlarmEvidence,
    proposed_at: &'a DateTime<Utc>,
    registration_digest: &'a Digest,
    query_digest: &'a Digest,
    read_only: bool,
    live_execution: bool,
    connected: bool,
    native: bool,
    first_party: bool,
    production_slo_certification: bool,
    adopted_outcome: bool,
}

impl AwsCloudWatchAlarmProposal {
    fn new(
        evidence: AwsCloudWatchAlarmEvidence,
        proposed_at: DateTime<Utc>,
        registration_digest: Digest,
    ) -> Self {
        let mut proposal = Self {
            operation: AwsCloudWatchOperation::DescribeAlarms,
            query_digest: evidence.query_digest.clone(),
            evidence,
            proposed_at,
            registration_digest,
            proposal_digest: Digest::zero(),
            read_only: true,
            live_execution: false,
            connected: false,
            native: false,
            first_party: false,
            production_slo_certification: false,
            adopted_outcome: false,
        };
        proposal.proposal_digest = proposal.recomputed_digest();
        proposal
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&ProposalBody {
            operation: self.operation,
            evidence: &self.evidence,
            proposed_at: &self.proposed_at,
            registration_digest: &self.registration_digest,
            query_digest: &self.query_digest,
            read_only: self.read_only,
            live_execution: self.live_execution,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
            production_slo_certification: self.production_slo_certification,
            adopted_outcome: self.adopted_outcome,
        })
    }

    pub fn validate(
        &self,
        scope: &AwsCloudWatchAlarmScope,
    ) -> Result<(), AwsCloudWatchAlarmServiceError> {
        self.evidence
            .validate(scope)
            .map_err(|_| AwsCloudWatchAlarmServiceError::EvidenceTampered)?;
        if self.query_digest != self.evidence.query_digest
            || !self.read_only
            || self.live_execution
            || self.connected
            || self.native
            || self.first_party
            || self.production_slo_certification
            || self.adopted_outcome
            || self.proposal_digest != self.recomputed_digest()
        {
            return Err(AwsCloudWatchAlarmServiceError::ProposalTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCloudWatchAlarmRecordReceipt {
    pub recorded: bool,
    pub recorded_at: DateTime<Utc>,
    pub alarm_state: Option<AlarmState>,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub retained_datapoint_count: u32,
    pub raw_dimensions_retained: bool,
    pub raw_datapoints_retained: bool,
    pub alarm_actions_retained: bool,
    pub durable_provider_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub receipt_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordBody<'a> {
    recorded: bool,
    recorded_at: &'a DateTime<Utc>,
    alarm_state: Option<AlarmState>,
    proposal_digest: &'a Digest,
    evidence_digest: &'a Digest,
    registration_digest: &'a Digest,
    scope_digest: &'a Digest,
    query_digest: &'a Digest,
    retained_datapoint_count: u32,
    raw_dimensions_retained: bool,
    raw_datapoints_retained: bool,
    alarm_actions_retained: bool,
    durable_provider_receipt: bool,
    connected: bool,
    native: bool,
    first_party: bool,
}

impl AwsCloudWatchAlarmRecordReceipt {
    fn new(proposal: &AwsCloudWatchAlarmProposal, recorded_at: DateTime<Utc>) -> Self {
        let retained_datapoint_count = proposal
            .evidence
            .metric_data
            .as_ref()
            .map_or(0, |metric| metric.datapoint_count);
        let mut receipt = Self {
            recorded: true,
            recorded_at,
            alarm_state: proposal.evidence.alarm_state,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.evidence.scope_digest.clone(),
            query_digest: proposal.query_digest.clone(),
            retained_datapoint_count,
            raw_dimensions_retained: false,
            raw_datapoints_retained: false,
            alarm_actions_retained: false,
            durable_provider_receipt: false,
            connected: false,
            native: false,
            first_party: false,
            receipt_digest: Digest::zero(),
        };
        receipt.receipt_digest = receipt.recomputed_digest();
        receipt
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&RecordBody {
            recorded: self.recorded,
            recorded_at: &self.recorded_at,
            alarm_state: self.alarm_state,
            proposal_digest: &self.proposal_digest,
            evidence_digest: &self.evidence_digest,
            registration_digest: &self.registration_digest,
            scope_digest: &self.scope_digest,
            query_digest: &self.query_digest,
            retained_datapoint_count: self.retained_datapoint_count,
            raw_dimensions_retained: self.raw_dimensions_retained,
            raw_datapoints_retained: self.raw_datapoints_retained,
            alarm_actions_retained: self.alarm_actions_retained,
            durable_provider_receipt: self.durable_provider_receipt,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCloudWatchAlarmVerifiedRecord {
    pub verified: bool,
    pub alarm_state: Option<AlarmState>,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub verification_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopted_outcome: bool,
    pub production_slo_certification: bool,
}

#[derive(Clone)]
pub struct AwsCloudWatchAlarmService<T>
where
    T: AwsCloudWatchTransport,
{
    scope: AwsCloudWatchAlarmScope,
    permission: PermissionSnapshot,
    secret_reference: SecretReference,
    provider: AwsCloudWatchProvider<T>,
    registration: AwsCloudWatchAlarmRegistration,
}

impl<T: AwsCloudWatchTransport> fmt::Debug for AwsCloudWatchAlarmService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCloudWatchAlarmService")
            .field("scope_digest", &self.scope.digest())
            .field("permission_digest", &self.permission.digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .finish()
    }
}

impl<T: AwsCloudWatchTransport> AwsCloudWatchAlarmService<T> {
    pub fn register(
        scope: AwsCloudWatchAlarmScope,
        secret_reference: SecretReference,
        permission: PermissionSnapshot,
        provider: AwsCloudWatchProvider<T>,
    ) -> Result<Self, AwsCloudWatchAlarmServiceError> {
        Self::new(scope, secret_reference, permission, provider)
    }

    pub fn new(
        scope: AwsCloudWatchAlarmScope,
        secret_reference: SecretReference,
        permission: PermissionSnapshot,
        provider: AwsCloudWatchProvider<T>,
    ) -> Result<Self, AwsCloudWatchAlarmServiceError> {
        scope.validate()?;
        if scope.permission_digest != permission.digest() {
            return Err(AwsCloudWatchAlarmServiceError::ScopeMismatch(
                "permission digest".to_owned(),
            ));
        }
        if !permission.allows(PermissionAction::DescribeAlarms)
            || !permission.allows(PermissionAction::GetMetricData)
            || (scope.allow_metric_discovery && !permission.allows(PermissionAction::ListMetrics))
        {
            return Err(AwsCloudWatchAlarmServiceError::ScopeMismatch(
                "required CloudWatch read permissions".to_owned(),
            ));
        }
        secret_reference
            .validate(&scope)
            .map_err(|error| match error {
                ModelError::SecretRevoked => AwsCloudWatchAlarmServiceError::SecretRevoked,
                other => AwsCloudWatchAlarmServiceError::Model(other),
            })?;
        provider.definition().validate()?;
        let registration =
            AwsCloudWatchAlarmRegistration::new(&scope, &secret_reference, provider.definition())?;
        Ok(Self {
            scope,
            permission,
            secret_reference,
            provider,
            registration,
        })
    }

    pub const fn describe_capabilities() -> AwsCloudWatchCapabilities {
        AwsCloudWatchCapabilities::layer_one()
    }

    pub fn scope(&self) -> &AwsCloudWatchAlarmScope {
        &self.scope
    }

    pub fn permission(&self) -> &PermissionSnapshot {
        &self.permission
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &AwsCloudWatchProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsCloudWatchProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AwsCloudWatchAlarmRegistration {
        &self.registration
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    pub fn revoke_secret_reference(&mut self) {
        self.secret_reference.revoke();
    }

    pub fn revoke_registration(&mut self) -> Result<(), AwsCloudWatchAlarmServiceError> {
        self.registration.transition(RegistrationState::Revoked)?;
        Ok(())
    }

    pub fn reverse_registration(&mut self) -> Result<(), AwsCloudWatchAlarmServiceError> {
        self.registration.transition(RegistrationState::Reversed)?;
        Ok(())
    }

    pub fn restore_registration(&mut self) -> Result<(), AwsCloudWatchAlarmServiceError> {
        self.registration.restore()?;
        Ok(())
    }

    pub fn default_read_request(
        &self,
    ) -> Result<AwsCloudWatchReadRequest, AwsCloudWatchAlarmServiceError> {
        Ok(AwsCloudWatchReadRequest::for_scope(&self.scope)?)
    }

    pub fn read_bounded(
        &mut self,
    ) -> Result<AwsCloudWatchReadResult, AwsCloudWatchAlarmServiceError> {
        let request = self.default_read_request()?;
        self.read(request)
    }

    pub fn read(
        &mut self,
        request: AwsCloudWatchReadRequest,
    ) -> Result<AwsCloudWatchReadResult, AwsCloudWatchAlarmServiceError> {
        self.ensure_active_and_bound()?;
        request.validate_against(&self.scope)?;

        let mut alarm = None;
        let mut metric_data = None;
        let mut receipts = Vec::new();
        let mut provider_errors = Vec::new();
        let mut page_digests = Vec::new();
        let mut seen_cursors = BTreeSet::new();
        let mut page_count = 0_u16;
        let mut request_count = 0_u16;
        let mut retry_count = 0_u8;
        let mut response_bytes = 0_usize;
        let mut status = EvidenceStatus::Complete;
        let mut partial_reason = None;

        let mut describe_request = DescribeAlarmsRequest::for_scope(&self.scope)?;
        'describe: loop {
            if request_count >= request.max_requests() {
                status = EvidenceStatus::Partial;
                partial_reason = Some(PartialReason::RequestBudget);
                break;
            }
            let mut attempt = 0_u8;
            loop {
                request_count = request_count.saturating_add(1);
                attempt = attempt.saturating_add(1);
                match self.provider.describe_alarms(&describe_request) {
                    Ok(response) => {
                        page_count = page_count.max(response.page_number);
                        response_bytes = response_bytes.saturating_add(response.response_bytes);
                        if response_bytes > request.max_response_bytes {
                            status = EvidenceStatus::Partial;
                            partial_reason = Some(PartialReason::ResponseTooLarge);
                            break 'describe;
                        }
                        page_digests.push(response.response_digest.clone());
                        receipts.push(redacted_receipt(
                            AwsCloudWatchOperation::DescribeAlarms,
                            response.request_digest.clone(),
                            response.response_digest.clone(),
                            &response.cost,
                            response.response_bytes,
                            attempt,
                            describe_request
                                .cursor
                                .as_ref()
                                .map(|cursor| cursor.token_digest().clone()),
                        )?);
                        if response.alarms.is_empty() {
                            status = EvidenceStatus::Empty;
                            partial_reason = Some(PartialReason::MissingAlarm);
                            break 'describe;
                        }
                        let candidate = response.alarms[0].clone();
                        if alarm.is_some() {
                            status = EvidenceStatus::Stale;
                            partial_reason = Some(PartialReason::StaleAlarmRevision);
                            break 'describe;
                        }
                        candidate
                            .validate_against(&self.scope)
                            .map_err(|_| AwsCloudWatchAlarmServiceError::QueryDrift)?;
                        alarm = Some(candidate);
                        let Some(cursor) = response.next_cursor else {
                            break 'describe;
                        };
                        if !seen_cursors.insert(cursor.token_digest().clone()) {
                            status = EvidenceStatus::Partial;
                            partial_reason = Some(PartialReason::ScanLoop);
                            break 'describe;
                        }
                        if response.page_number >= request.max_pages {
                            status = EvidenceStatus::Partial;
                            partial_reason = Some(PartialReason::PageBudget);
                            break 'describe;
                        }
                        describe_request = describe_request.with_cursor(cursor)?;
                        break;
                    }
                    Err(AwsCloudWatchProviderError::Transport(error)) => {
                        provider_errors.push(error.evidence());
                        if error.retryable() && attempt <= request.max_retries {
                            retry_count = retry_count.saturating_add(1);
                            continue;
                        }
                        status = status_for_transport(&error);
                        partial_reason = Some(if is_access_loss(&error) {
                            PartialReason::AccessLoss
                        } else {
                            PartialReason::ProviderError
                        });
                        break 'describe;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }

        if status == EvidenceStatus::Complete && request.discover_metrics {
            let mut discovery_request = ListMetricsRequest::for_scope(&self.scope)?;
            let mut discovered = false;
            'discovery: loop {
                if request_count >= request.max_requests() {
                    status = EvidenceStatus::Partial;
                    partial_reason = Some(PartialReason::RequestBudget);
                    break;
                }
                let mut attempt = 0_u8;
                loop {
                    request_count = request_count.saturating_add(1);
                    attempt = attempt.saturating_add(1);
                    match self.provider.list_metrics(&discovery_request) {
                        Ok(response) => {
                            page_count = page_count.max(response.page_number);
                            response_bytes = response_bytes.saturating_add(response.response_bytes);
                            if response_bytes > request.max_response_bytes {
                                status = EvidenceStatus::Partial;
                                partial_reason = Some(PartialReason::ResponseTooLarge);
                                break 'discovery;
                            }
                            page_digests.push(response.response_digest.clone());
                            receipts.push(redacted_receipt(
                                AwsCloudWatchOperation::ListMetrics,
                                response.request_digest.clone(),
                                response.response_digest.clone(),
                                &response.cost,
                                response.response_bytes,
                                attempt,
                                discovery_request
                                    .cursor
                                    .as_ref()
                                    .map(|cursor| cursor.token_digest().clone()),
                            )?);
                            if response.metrics.is_empty() {
                                status = EvidenceStatus::Empty;
                                partial_reason = Some(PartialReason::MissingMetricData);
                                break 'discovery;
                            }
                            for metric in &response.metrics {
                                if metric != &self.scope.metric {
                                    status = EvidenceStatus::Stale;
                                    partial_reason = Some(PartialReason::MetricDrift);
                                    break 'discovery;
                                }
                                if discovered {
                                    status = EvidenceStatus::Partial;
                                    partial_reason = Some(PartialReason::CursorReplay);
                                    break 'discovery;
                                }
                                discovered = true;
                            }
                            let Some(cursor) = response.next_cursor else {
                                break 'discovery;
                            };
                            if !seen_cursors.insert(cursor.token_digest().clone()) {
                                status = EvidenceStatus::Partial;
                                partial_reason = Some(PartialReason::ScanLoop);
                                break 'discovery;
                            }
                            if response.page_number >= request.max_pages {
                                status = EvidenceStatus::Partial;
                                partial_reason = Some(PartialReason::PageBudget);
                                break 'discovery;
                            }
                            discovery_request = discovery_request.with_cursor(cursor)?;
                            break;
                        }
                        Err(AwsCloudWatchProviderError::Transport(error)) => {
                            provider_errors.push(error.evidence());
                            if error.retryable() && attempt <= request.max_retries {
                                retry_count = retry_count.saturating_add(1);
                                continue;
                            }
                            status = status_for_transport(&error);
                            partial_reason = Some(if is_access_loss(&error) {
                                PartialReason::AccessLoss
                            } else {
                                PartialReason::ProviderError
                            });
                            break 'discovery;
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
            }
            if status == EvidenceStatus::Complete && !discovered {
                status = EvidenceStatus::Empty;
                partial_reason = Some(PartialReason::MissingMetricData);
            }
        }

        if status == EvidenceStatus::Complete {
            let mut metric_request = GetMetricDataRequest::for_scope(&self.scope)?;
            'metric: loop {
                if request_count >= request.max_requests() {
                    status = EvidenceStatus::Partial;
                    partial_reason = Some(PartialReason::RequestBudget);
                    break;
                }
                let mut attempt = 0_u8;
                loop {
                    request_count = request_count.saturating_add(1);
                    attempt = attempt.saturating_add(1);
                    match self.provider.get_metric_data(&metric_request) {
                        Ok(response) => {
                            page_count = page_count.max(response.page_number);
                            response_bytes = response_bytes.saturating_add(response.response_bytes);
                            if response_bytes > request.max_response_bytes {
                                status = EvidenceStatus::Partial;
                                partial_reason = Some(PartialReason::ResponseTooLarge);
                                break 'metric;
                            }
                            page_digests.push(response.response_digest.clone());
                            receipts.push(redacted_receipt(
                                AwsCloudWatchOperation::GetMetricData,
                                response.request_digest.clone(),
                                response.response_digest.clone(),
                                &response.cost,
                                response.response_bytes,
                                attempt,
                                metric_request
                                    .cursor
                                    .as_ref()
                                    .map(|cursor| cursor.token_digest().clone()),
                            )?);
                            if response.aggregates.is_empty() {
                                status = EvidenceStatus::Empty;
                                partial_reason = Some(PartialReason::MissingMetricData);
                                break 'metric;
                            }
                            let candidate = response.aggregates[0].clone();
                            metric_data = Some(match metric_data.take() {
                                None => candidate,
                                Some(existing) => combine_metric_data(&existing, &candidate)?,
                            });
                            let Some(cursor) = response.next_cursor else {
                                break 'metric;
                            };
                            if !seen_cursors.insert(cursor.token_digest().clone()) {
                                status = EvidenceStatus::Partial;
                                partial_reason = Some(PartialReason::ScanLoop);
                                break 'metric;
                            }
                            if response.page_number >= request.max_pages {
                                status = EvidenceStatus::Partial;
                                partial_reason = Some(PartialReason::PageBudget);
                                break 'metric;
                            }
                            metric_request = metric_request.with_cursor(cursor)?;
                            break;
                        }
                        Err(AwsCloudWatchProviderError::Transport(error)) => {
                            provider_errors.push(error.evidence());
                            if error.retryable() && attempt <= request.max_retries {
                                retry_count = retry_count.saturating_add(1);
                                continue;
                            }
                            status = status_for_transport(&error);
                            partial_reason = Some(if is_access_loss(&error) {
                                PartialReason::AccessLoss
                            } else {
                                PartialReason::ProviderError
                            });
                            break 'metric;
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
            }
        }

        if status == EvidenceStatus::Complete && (alarm.is_none() || metric_data.is_none()) {
            status = EvidenceStatus::Empty;
            partial_reason = Some(if alarm.is_none() {
                PartialReason::MissingAlarm
            } else {
                PartialReason::MissingMetricData
            });
        }
        let evidence = self.build_evidence(
            &request,
            status,
            partial_reason,
            alarm,
            metric_data,
            receipts,
            provider_errors,
            page_count,
            request_count,
            retry_count,
            response_bytes,
        )?;
        Ok(AwsCloudWatchReadResult {
            evidence,
            page_digests,
            registration_digest: self.registration.registration_digest.clone(),
        })
    }

    pub fn propose(
        &mut self,
        proposed_at: DateTime<Utc>,
    ) -> Result<AwsCloudWatchAlarmProposal, AwsCloudWatchAlarmServiceError> {
        let result = self.read_bounded()?;
        Ok(AwsCloudWatchAlarmProposal::new(
            result.evidence,
            proposed_at,
            self.registration.registration_digest.clone(),
        ))
    }

    pub fn propose_at(
        &mut self,
        proposed_at: DateTime<Utc>,
    ) -> Result<AwsCloudWatchAlarmProposal, AwsCloudWatchAlarmServiceError> {
        self.propose(proposed_at)
    }

    pub fn record(
        &self,
        proposal: &AwsCloudWatchAlarmProposal,
    ) -> Result<AwsCloudWatchAlarmRecordReceipt, AwsCloudWatchAlarmServiceError> {
        self.record_at(proposal, Utc::now())
    }

    pub fn record_at(
        &self,
        proposal: &AwsCloudWatchAlarmProposal,
        recorded_at: DateTime<Utc>,
    ) -> Result<AwsCloudWatchAlarmRecordReceipt, AwsCloudWatchAlarmServiceError> {
        self.ensure_active_and_bound()?;
        self.verify_proposal(proposal)?;
        if !proposal.evidence.is_adoptable() {
            return Err(AwsCloudWatchAlarmServiceError::EvidenceNotAdoptable);
        }
        Ok(AwsCloudWatchAlarmRecordReceipt::new(proposal, recorded_at))
    }

    pub fn verify(
        &self,
        receipt: &AwsCloudWatchAlarmRecordReceipt,
    ) -> Result<AwsCloudWatchAlarmVerifiedRecord, AwsCloudWatchAlarmServiceError> {
        self.ensure_active_and_bound()?;
        if !receipt.recorded
            || receipt.registration_digest != self.registration.registration_digest
            || receipt.scope_digest != self.scope.digest()
            || receipt.query_digest != self.registration.query_digest
            || receipt.raw_dimensions_retained
            || receipt.raw_datapoints_retained
            || receipt.alarm_actions_retained
            || receipt.durable_provider_receipt
            || receipt.connected
            || receipt.native
            || receipt.first_party
            || receipt.receipt_digest != receipt.recomputed_digest()
        {
            return Err(AwsCloudWatchAlarmServiceError::RecordTampered);
        }
        let verification_digest = Digest::from_parts(
            "hartevo-aws-cloudwatch-verified-record/v1",
            [
                ("receipt", receipt.receipt_digest.as_str()),
                ("registration", receipt.registration_digest.as_str()),
                ("scope", receipt.scope_digest.as_str()),
                ("query", receipt.query_digest.as_str()),
            ],
        );
        Ok(AwsCloudWatchAlarmVerifiedRecord {
            verified: true,
            alarm_state: receipt.alarm_state,
            proposal_digest: receipt.proposal_digest.clone(),
            evidence_digest: receipt.evidence_digest.clone(),
            registration_digest: receipt.registration_digest.clone(),
            verification_digest,
            connected: false,
            native: false,
            first_party: false,
            adopted_outcome: false,
            production_slo_certification: false,
        })
    }

    pub fn verify_proposal(
        &self,
        proposal: &AwsCloudWatchAlarmProposal,
    ) -> Result<(), AwsCloudWatchAlarmServiceError> {
        self.ensure_active_and_bound()?;
        proposal.validate(&self.scope)?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.query_digest != self.registration.query_digest
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.permission_digest != self.permission.digest()
            || proposal.evidence.provider_digest != self.provider.definition().provider_digest
            || proposal.evidence.provider_revision != self.provider.definition().provider_revision
            || proposal.evidence.api_digest != self.provider.definition().api_digest
            || proposal.evidence.contract_digest != contract_digest()
            || proposal.evidence.evidence_digest.is_zero()
        {
            return Err(AwsCloudWatchAlarmServiceError::ProposalTampered);
        }
        Ok(())
    }

    fn ensure_active_and_bound(&self) -> Result<(), AwsCloudWatchAlarmServiceError> {
        if !self.registration.is_active() {
            return Err(AwsCloudWatchAlarmServiceError::RegistrationRevoked);
        }
        if self.secret_reference.is_revoked() {
            return Err(AwsCloudWatchAlarmServiceError::SecretRevoked);
        }
        self.secret_reference
            .validate(&self.scope)
            .map_err(|_| AwsCloudWatchAlarmServiceError::SecretRevoked)?;
        self.provider.definition().validate().map_err(|error| {
            AwsCloudWatchAlarmServiceError::RegistrationDrift(error.to_string())
        })?;
        self.registration
            .validate(
                &self.scope,
                &self.secret_reference,
                self.provider.definition(),
            )
            .map_err(|error| AwsCloudWatchAlarmServiceError::RegistrationDrift(error.to_string()))
    }

    fn build_evidence(
        &self,
        request: &AwsCloudWatchReadRequest,
        status: EvidenceStatus,
        partial_reason: Option<PartialReason>,
        alarm: Option<crate::model::AlarmSnapshot>,
        metric_data: Option<MetricDataAggregate>,
        request_receipts: Vec<RedactedRequestReceipt>,
        provider_errors: Vec<ProviderErrorEvidence>,
        page_count: u16,
        request_count: u16,
        retry_count: u8,
        response_bytes: usize,
    ) -> Result<AwsCloudWatchAlarmEvidence, AwsCloudWatchAlarmServiceError> {
        let alarm_state = alarm.as_ref().map(|value| value.state);
        let mut evidence = AwsCloudWatchAlarmEvidence {
            status,
            partial_reason,
            alarm,
            metric_data,
            alarm_state,
            scope_digest: self.scope.digest(),
            permission_digest: self.permission.digest(),
            query_digest: request.query_digest.clone(),
            window_digest: self.scope.window.digest(),
            provider_digest: self.provider.definition().provider_digest.clone(),
            provider_revision: self.provider.definition().provider_revision.clone(),
            api_digest: self.provider.definition().api_digest.clone(),
            contract_digest: contract_digest(),
            request_receipts,
            provider_errors,
            page_count,
            request_count,
            retry_count,
            response_bytes,
            truncated: status != EvidenceStatus::Complete,
            discovery_used: request.discover_metrics,
            provenance: self.provider.provenance(),
            connected: false,
            native: false,
            first_party: false,
            evidence_digest: Digest::zero(),
        };
        evidence.evidence_digest = evidence.recomputed_digest();
        evidence
            .validate(&self.scope)
            .map_err(|_| AwsCloudWatchAlarmServiceError::EvidenceTampered)?;
        Ok(evidence)
    }
}

fn status_for_transport(error: &AwsCloudWatchTransportError) -> EvidenceStatus {
    if is_access_loss(error) {
        EvidenceStatus::AccessLoss
    } else {
        EvidenceStatus::ProviderUnknown
    }
}

fn combine_metric_data(
    left: &MetricDataAggregate,
    right: &MetricDataAggregate,
) -> Result<MetricDataAggregate, AwsCloudWatchAlarmServiceError> {
    if left.metric != right.metric || left.window != right.window {
        return Err(AwsCloudWatchAlarmServiceError::QueryDrift);
    }
    let datapoint_count = left
        .datapoint_count
        .checked_add(right.datapoint_count)
        .ok_or(AwsCloudWatchAlarmServiceError::EvidenceTampered)?;
    let average = (left.sum + right.sum) / f64::from(datapoint_count);
    MetricDataAggregate::new(
        left.metric.clone(),
        left.window.clone(),
        datapoint_count,
        left.minimum.min(right.minimum),
        left.maximum.max(right.maximum),
        left.sum + right.sum,
        average,
        Digest::from_parts(
            "hartevo-aws-cloudwatch-datapoints-pages/v1",
            [
                ("left", left.datapoints_digest.as_str()),
                ("right", right.datapoints_digest.as_str()),
            ],
        ),
    )
    .map_err(Into::into)
}

pub type AwsCloudWatchService<T> = AwsCloudWatchAlarmService<T>;
pub type AwsCloudWatchRegistration = AwsCloudWatchAlarmRegistration;
pub type AwsCloudWatchProposal = AwsCloudWatchAlarmProposal;
pub type AwsCloudWatchRecordReceipt = AwsCloudWatchAlarmRecordReceipt;
pub type AwsCloudWatchVerifiedRecord = AwsCloudWatchAlarmVerifiedRecord;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    use crate::model::TransportProvenance;
    use crate::model::{
        AlarmIdentity, AlarmName, AwsAccountId, AwsRegion, DeploymentBinding, MetricIdentity,
        MetricName, MetricNamespace, MetricWindow, MissionBinding, PermissionId,
        PermissionSnapshot, ProjectBinding, WorkProductBinding,
    };
    use crate::provider::FixtureTransport;

    fn scope(discover: bool) -> AwsCloudWatchAlarmScope {
        let permissions = PermissionSnapshot::readonly(
            PermissionId::new("cloudwatch-read").expect("permission"),
            Revision::new(1).expect("revision"),
        )
        .expect("permissions");
        let metric = MetricIdentity::from_dimensions(
            MetricNamespace::new("AWS/Lambda").expect("namespace"),
            MetricName::new("Errors").expect("metric"),
            "Sum",
            60,
            [("FunctionName", "fixture")],
        )
        .expect("metric");
        AwsCloudWatchAlarmScope::new(
            DeploymentBinding::new(
                crate::model::DeploymentId::new("deployment").expect("deployment"),
                Revision::new(1).expect("revision"),
            ),
            MissionBinding::new(
                crate::model::MissionId::new("mission").expect("mission"),
                Revision::new(1).expect("revision"),
            ),
            ProjectBinding::new(
                crate::model::ProjectId::new("project").expect("project"),
                Revision::new(1).expect("revision"),
            ),
            WorkProductBinding::new(
                crate::model::WorkProductId::new("work-product").expect("work product"),
                Revision::new(1).expect("revision"),
            ),
            AwsAccountId::new("123456789012").expect("account"),
            AwsRegion::new("us-east-1").expect("region"),
            AlarmIdentity::new(
                AlarmName::new("fixture-alarm").expect("alarm"),
                Revision::new(1).expect("revision"),
            )
            .expect("alarm identity"),
            metric,
            MetricWindow::new(
                chrono::Utc.with_ymd_and_hms(2026, 8, 15, 0, 0, 0).unwrap(),
                chrono::Utc.with_ymd_and_hms(2026, 8, 15, 1, 0, 0).unwrap(),
            )
            .expect("window"),
            permissions.digest(),
            discover,
        )
        .expect("scope")
    }

    #[test]
    fn fixture_round_trip_is_bounded_and_below_kernel() {
        let scope = scope(true);
        let permission = PermissionSnapshot::readonly(
            PermissionId::new("cloudwatch-read").expect("permission"),
            Revision::new(1).expect("revision"),
        )
        .expect("permissions");
        let transport = FixtureTransport::for_scope(&scope, chrono::Utc::now());
        let provider = AwsCloudWatchProvider::new(transport).expect("provider");
        let secret = SecretReference::new("opaque-handle", &scope, 1).expect("secret");
        let mut service =
            AwsCloudWatchAlarmService::new(scope.clone(), secret, permission, provider)
                .expect("service");
        let result = service.read_bounded().expect("read");
        assert_eq!(result.evidence.status, EvidenceStatus::Complete);
        assert_eq!(result.evidence.alarm_state, Some(AlarmState::Ok));
        assert!(!result.evidence.connected);
        assert!(!result.evidence.native);
        assert!(!result.evidence.first_party);
        assert!(result.evidence.is_adoptable());
        let proposal = service.propose(chrono::Utc::now()).expect("proposal");
        let receipt = service.record(&proposal).expect("receipt");
        let verified = service.verify(&receipt).expect("verified");
        assert!(verified.verified);
        assert!(!verified.adopted_outcome);
        assert!(!verified.production_slo_certification);
    }

    #[test]
    fn blocked_environment_is_provider_unknown_not_native() {
        let scope = scope(false);
        let permission = PermissionSnapshot::readonly(
            PermissionId::new("cloudwatch-read").expect("permission"),
            Revision::new(1).expect("revision"),
        )
        .expect("permissions");
        let provider = AwsCloudWatchProvider::default();
        let secret = SecretReference::new("opaque-handle", &scope, 1).expect("secret");
        let mut service =
            AwsCloudWatchAlarmService::new(scope, secret, permission, provider).expect("service");
        let result = service.read_bounded().expect("bounded failure evidence");
        assert_eq!(result.evidence.status, EvidenceStatus::ProviderUnknown);
        assert_eq!(result.evidence.provenance, TransportProvenance::BlockedEnv);
        assert!(!result.evidence.connected);
        assert!(!result.evidence.native);
        assert!(!result.evidence.first_party);
        assert!(!result.evidence.is_adoptable());
    }

    #[test]
    fn revocation_is_fail_closed() {
        let scope = scope(false);
        let permission = PermissionSnapshot::readonly(
            PermissionId::new("cloudwatch-read").expect("permission"),
            Revision::new(1).expect("revision"),
        )
        .expect("permissions");
        let provider =
            AwsCloudWatchProvider::new(FixtureTransport::for_scope(&scope, chrono::Utc::now()))
                .expect("provider");
        let secret = SecretReference::new("opaque-handle", &scope, 1).expect("secret");
        let mut service =
            AwsCloudWatchAlarmService::new(scope, secret, permission, provider).expect("service");
        service.revoke_registration().expect("revoke");
        assert!(matches!(
            service.read_bounded(),
            Err(AwsCloudWatchAlarmServiceError::RegistrationRevoked)
        ));
    }
}
