//! Bounded CloudWatch Logs read, proposal, recording, and verification service.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Utc};
use serde::Serialize;
use thiserror::Error;

use crate::{
    AWS_CLOUDWATCH_LOGS_CONTRACT_VERSION, AWS_CLOUDWATCH_LOGS_PLUGIN_VERSION,
    AWS_CLOUDWATCH_LOGS_PROVIDER_ID, AWS_CLOUDWATCH_LOGS_SERVICE_ID, contract_digest,
    model::{
        AwsCloudWatchLogsScope, Digest, ErrorClass, EvidenceState, FieldName,
        MAX_CORRELATION_FINGERPRINTS, MAX_ERROR_CLASSES, MAX_FIELD_NAMES, MAX_PAGES,
        MAX_RESPONSE_BYTES, MAX_RESULTS, ModelError, PermissionAction, PermissionFence,
        ProviderErrorEvidence, QueryExecutionStatus, RegistrationState, Revision, SecretReference,
        TransportError, TransportProvenance, digest_serialized,
    },
    provider::{
        AwsCloudWatchLogsProvider, AwsCloudWatchLogsProviderIdentity, DescribeQueriesRequest,
        GetQueryResultsRequest, QueryExecutionSummary, StartQueryRequest, StartQueryResponse,
        is_access_loss, provider_error_evidence, status_to_evidence,
    },
    query::{CloudWatchLogsQuery, QueryProposalRequest},
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegistrationError {
    #[error("registration model error: {0}")]
    Model(#[from] ModelError),
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration revision overflow")]
    RevisionOverflow,
    #[error("registration is not reversible in its current state")]
    NotReversible,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsCloudWatchLogsServiceError {
    #[error("CloudWatch Logs registration is revoked or reversed")]
    RegistrationRevoked,
    #[error("CloudWatch Logs SecretReference is revoked")]
    SecretRevoked,
    #[error("CloudWatch Logs registration has drifted: {0}")]
    RegistrationDrift(String),
    #[error("CloudWatch Logs scope or permission fence mismatch: {0}")]
    ScopeMismatch(String),
    #[error("CloudWatch Logs query is stale, unallowlisted, or tampered")]
    QueryTampered,
    #[error("CloudWatch Logs evidence is stale or tampered")]
    EvidenceTampered,
    #[error("CloudWatch Logs proposal is stale or tampered")]
    ProposalTampered,
    #[error("CloudWatch Logs record is stale or tampered")]
    RecordTampered,
    #[error("CloudWatch Logs query page token was replayed")]
    ReplayDetected,
    #[error("CloudWatch Logs registration lifecycle error: {0}")]
    Registration(#[from] RegistrationError),
    #[error("CloudWatch Logs provider definition error: {0}")]
    ProviderDefinition(#[from] crate::provider::ProviderDefinitionError),
    #[error("CloudWatch Logs provider transport error: {0}")]
    Provider(#[from] TransportError),
    #[error("CloudWatch Logs model error: {0}")]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCloudWatchLogsCapabilities {
    pub service_id: &'static str,
    pub provider_id: &'static str,
    pub operations: [&'static str; 9],
    pub allowlisted_api_operations: [&'static str; 3],
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub raw_log_events: bool,
    pub raw_query_text: bool,
    pub outcome_authority: bool,
}

impl AwsCloudWatchLogsCapabilities {
    pub const fn layer_one() -> Self {
        Self {
            service_id: AWS_CLOUDWATCH_LOGS_SERVICE_ID,
            provider_id: AWS_CLOUDWATCH_LOGS_PROVIDER_ID,
            operations: [
                "describe_capabilities",
                "register",
                "reverse_registration",
                "restore_registration",
                "revoke_registration",
                "read_bounded",
                "propose",
                "record",
                "verify",
            ],
            allowlisted_api_operations: ["StartQuery", "GetQueryResults", "DescribeQueries"],
            read_only: true,
            proposal_only: true,
            live_execution: false,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
            raw_log_events: false,
            raw_query_text: false,
            outcome_authority: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCloudWatchLogsRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: crate::ProviderId,
    pub provider_version: String,
    pub provider_revision: crate::ProviderRevision,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub query_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
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
    provider_id: &'a crate::ProviderId,
    provider_version: &'a str,
    provider_revision: &'a crate::ProviderRevision,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    query_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    evidence_digest: &'a Digest,
    secret_reference_digest: &'a Digest,
    registration_revision: Revision,
    state: RegistrationState,
}

impl AwsCloudWatchLogsRegistration {
    pub(crate) fn new(
        scope: &AwsCloudWatchLogsScope,
        permission: &PermissionFence,
        secret: &SecretReference,
        provider: &AwsCloudWatchLogsProviderIdentity,
    ) -> Result<Self, RegistrationError> {
        let query_digest = query_policy_digest(scope);
        let evidence_digest = evidence_policy_digest();
        let mut registration = Self {
            plugin_version: AWS_CLOUDWATCH_LOGS_PLUGIN_VERSION.to_owned(),
            contract_version: AWS_CLOUDWATCH_LOGS_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.version.clone(),
            provider_revision: provider.api_revision.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            query_digest,
            permission_digest: permission.digest(),
            scope_digest: scope.digest(),
            evidence_digest,
            secret_reference_digest: secret.digest().clone(),
            registration_revision: Revision::new(1)?,
            state: RegistrationState::Active,
            registration_digest: Digest::zero(),
        };
        registration.registration_digest = registration.recomputed_digest();
        Ok(registration)
    }

    pub fn is_active(&self) -> bool {
        self.state.is_active()
    }

    pub fn is_reversed(&self) -> bool {
        self.state == RegistrationState::Reversed
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
            query_digest: &self.query_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            evidence_digest: &self.evidence_digest,
            secret_reference_digest: &self.secret_reference_digest,
            registration_revision: self.registration_revision,
            state: self.state,
        })
    }

    pub fn validate(
        &self,
        scope: &AwsCloudWatchLogsScope,
        permission: &PermissionFence,
        secret: &SecretReference,
        provider: &AwsCloudWatchLogsProviderIdentity,
    ) -> Result<(), RegistrationError> {
        if self.plugin_version != AWS_CLOUDWATCH_LOGS_PLUGIN_VERSION
            || self.contract_version != AWS_CLOUDWATCH_LOGS_CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != provider.provider_id
            || self.provider_version != provider.version
            || self.provider_revision != provider.api_revision
            || self.provider_digest != provider.provider_digest
            || self.api_digest != provider.api_digest
            || self.query_digest != query_policy_digest(scope)
            || self.permission_digest != permission.digest()
            || self.scope_digest != scope.digest()
            || self.evidence_digest != evidence_policy_digest()
            || self.secret_reference_digest != *secret.digest()
            || self.registration_digest != self.recomputed_digest()
        {
            return Err(RegistrationError::Model(ModelError::ScopeMismatch {
                field: "registration digest binding",
            }));
        }
        Ok(())
    }

    fn next_revision(&mut self) -> Result<(), RegistrationError> {
        let next = self
            .registration_revision
            .get()
            .checked_add(1)
            .ok_or(RegistrationError::RevisionOverflow)?;
        self.registration_revision = Revision::new(next)?;
        Ok(())
    }

    fn revoke(&mut self) -> Result<(), RegistrationError> {
        if self.state == RegistrationState::Revoked {
            return Err(RegistrationError::AlreadyRevoked);
        }
        self.next_revision()?;
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.recomputed_digest();
        Ok(())
    }

    fn reverse(&mut self) -> Result<(), RegistrationError> {
        if self.state != RegistrationState::Active {
            return Err(RegistrationError::NotReversible);
        }
        self.next_revision()?;
        self.state = RegistrationState::Reversed;
        self.registration_digest = self.recomputed_digest();
        Ok(())
    }

    fn restore(&mut self) -> Result<(), RegistrationError> {
        if self.state != RegistrationState::Reversed {
            return Err(RegistrationError::NotReversible);
        }
        self.next_revision()?;
        self.state = RegistrationState::Active;
        self.registration_digest = self.recomputed_digest();
        Ok(())
    }
}

impl From<&AwsCloudWatchLogsRegistration> for AwsCloudWatchLogsRegistration {
    fn from(value: &AwsCloudWatchLogsRegistration) -> Self {
        value.clone()
    }
}

impl From<&AwsCloudWatchLogsProposal> for AwsCloudWatchLogsProposal {
    fn from(value: &AwsCloudWatchLogsProposal) -> Self {
        value.clone()
    }
}

fn query_policy_digest(scope: &AwsCloudWatchLogsScope) -> Digest {
    Digest::from_parts(
        "hartevo-aws-cloudwatch-logs-query-policy/v1",
        &scope
            .query_templates
            .iter()
            .map(|template| template.as_str().to_owned())
            .chain(
                scope
                    .log_groups
                    .iter()
                    .map(|group| group.as_str().to_owned()),
            )
            .collect::<Vec<_>>(),
    )
}

pub(crate) fn evidence_policy_digest() -> Digest {
    Digest::from_parts(
        "hartevo-aws-cloudwatch-logs-evidence-policy/v1",
        &[
            AWS_CLOUDWATCH_LOGS_CONTRACT_VERSION.to_owned(),
            MAX_RESULTS.to_string(),
            MAX_PAGES.to_string(),
            MAX_RESPONSE_BYTES.to_string(),
            MAX_FIELD_NAMES.to_string(),
            MAX_ERROR_CLASSES.to_string(),
            MAX_CORRELATION_FINGERPRINTS.to_string(),
            "raw-log-events-excluded".to_owned(),
            "raw-query-text-excluded".to_owned(),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCloudWatchLogsEvidence {
    pub state: EvidenceState,
    pub partial_reason: Option<crate::PartialReason>,
    pub query_digest: Digest,
    pub config_digest: Digest,
    pub template_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub provider_digest: Digest,
    pub provider_revision: crate::ProviderRevision,
    pub api_digest: Digest,
    pub contract_digest: Digest,
    pub registration_digest: Digest,
    pub query_id_digest: Option<Digest>,
    pub execution_status: QueryExecutionStatus,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub page_count: u8,
    pub request_count: u16,
    pub retry_count: u8,
    pub response_bytes: usize,
    pub event_count: u64,
    pub bytes_scanned: u64,
    pub field_names: Vec<FieldName>,
    pub error_class_counts: BTreeMap<ErrorClass, u64>,
    pub correlation_fingerprint_digests: Vec<Digest>,
    pub page_token_digests: Vec<Digest>,
    pub summary_digest: Digest,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub truncated: bool,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub evidence_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceBody<'a> {
    state: EvidenceState,
    partial_reason: Option<crate::PartialReason>,
    query_digest: &'a Digest,
    config_digest: &'a Digest,
    template_digest: &'a Digest,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
    provider_digest: &'a Digest,
    provider_revision: &'a crate::ProviderRevision,
    api_digest: &'a Digest,
    contract_digest: &'a Digest,
    registration_digest: &'a Digest,
    query_id_digest: &'a Option<Digest>,
    execution_status: QueryExecutionStatus,
    started_at: &'a Option<DateTime<Utc>>,
    finished_at: &'a Option<DateTime<Utc>>,
    page_count: u8,
    request_count: u16,
    retry_count: u8,
    response_bytes: usize,
    event_count: u64,
    bytes_scanned: u64,
    field_names: &'a [FieldName],
    error_class_counts: &'a BTreeMap<ErrorClass, u64>,
    correlation_fingerprint_digests: &'a [Digest],
    page_token_digests: &'a [Digest],
    summary_digest: &'a Digest,
    provider_errors: &'a [ProviderErrorEvidence],
    truncated: bool,
    provenance: TransportProvenance,
    connected: bool,
    native: bool,
    first_party: bool,
}

impl AwsCloudWatchLogsEvidence {
    #[allow(clippy::too_many_arguments)]
    fn new(
        state: EvidenceState,
        partial_reason: Option<crate::PartialReason>,
        query: &CloudWatchLogsQuery,
        registration: &AwsCloudWatchLogsRegistration,
        provider: &AwsCloudWatchLogsProviderIdentity,
        query_id_digest: Option<Digest>,
        execution_status: QueryExecutionStatus,
        started_at: Option<DateTime<Utc>>,
        finished_at: Option<DateTime<Utc>>,
        page_count: u8,
        request_count: u16,
        retry_count: u8,
        response_bytes: usize,
        event_count: u64,
        bytes_scanned: u64,
        field_names: Vec<FieldName>,
        error_class_counts: BTreeMap<ErrorClass, u64>,
        correlation_fingerprint_digests: Vec<Digest>,
        page_token_digests: Vec<Digest>,
        summary_digest: Digest,
        provider_errors: Vec<ProviderErrorEvidence>,
        truncated: bool,
    ) -> Self {
        let mut evidence = Self {
            state,
            partial_reason,
            query_digest: query.query_digest.clone(),
            config_digest: query.config_digest.clone(),
            template_digest: query.template_digest().clone(),
            scope_digest: query.scope_digest.clone(),
            permission_digest: query.permission_digest.clone(),
            provider_digest: provider.provider_digest.clone(),
            provider_revision: provider.api_revision.clone(),
            api_digest: provider.api_digest.clone(),
            contract_digest: contract_digest(),
            registration_digest: registration.registration_digest.clone(),
            query_id_digest,
            execution_status,
            started_at,
            finished_at,
            page_count,
            request_count,
            retry_count,
            response_bytes,
            event_count,
            bytes_scanned,
            field_names,
            error_class_counts,
            correlation_fingerprint_digests,
            page_token_digests,
            summary_digest,
            provider_errors,
            truncated,
            provenance: provider.provenance,
            connected: false,
            native: false,
            first_party: false,
            evidence_digest: Digest::zero(),
        };
        evidence.field_names.sort();
        evidence.field_names.dedup();
        evidence.correlation_fingerprint_digests.sort();
        evidence.correlation_fingerprint_digests.dedup();
        evidence.page_token_digests.dedup();
        evidence.evidence_digest = evidence.recomputed_digest();
        evidence
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&EvidenceBody {
            state: self.state,
            partial_reason: self.partial_reason,
            query_digest: &self.query_digest,
            config_digest: &self.config_digest,
            template_digest: &self.template_digest,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            provider_digest: &self.provider_digest,
            provider_revision: &self.provider_revision,
            api_digest: &self.api_digest,
            contract_digest: &self.contract_digest,
            registration_digest: &self.registration_digest,
            query_id_digest: &self.query_id_digest,
            execution_status: self.execution_status,
            started_at: &self.started_at,
            finished_at: &self.finished_at,
            page_count: self.page_count,
            request_count: self.request_count,
            retry_count: self.retry_count,
            response_bytes: self.response_bytes,
            event_count: self.event_count,
            bytes_scanned: self.bytes_scanned,
            field_names: &self.field_names,
            error_class_counts: &self.error_class_counts,
            correlation_fingerprint_digests: &self.correlation_fingerprint_digests,
            page_token_digests: &self.page_token_digests,
            summary_digest: &self.summary_digest,
            provider_errors: &self.provider_errors,
            truncated: self.truncated,
            provenance: self.provenance,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
        })
    }

    pub fn validate(&self) -> Result<(), AwsCloudWatchLogsServiceError> {
        if self.page_count > MAX_PAGES
            || self.response_bytes > MAX_RESPONSE_BYTES
            || usize::try_from(self.event_count).unwrap_or(usize::MAX) > MAX_RESULTS
            || self.field_names.len() > MAX_FIELD_NAMES
            || self.error_class_counts.len() > MAX_ERROR_CLASSES
            || self.correlation_fingerprint_digests.len() > MAX_CORRELATION_FINGERPRINTS
            || self.connected
            || self.native
            || self.first_party
            || self.evidence_digest != self.recomputed_digest()
        {
            return Err(AwsCloudWatchLogsServiceError::EvidenceTampered);
        }
        Ok(())
    }

    pub fn is_adoptable(&self) -> bool {
        !self.state.is_non_adoptable()
            && !self.truncated
            && !self.connected
            && !self.native
            && !self.first_party
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsCloudWatchLogsReadResult {
    pub evidence: AwsCloudWatchLogsEvidence,
    pub page_digests: Vec<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCloudWatchLogsProposal {
    pub query: CloudWatchLogsQuery,
    pub state: EvidenceState,
    pub evidence: AwsCloudWatchLogsEvidence,
    pub proposed_at: DateTime<Utc>,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub read_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub outcome_adopted: bool,
    pub proposal_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposalBody<'a> {
    query: &'a CloudWatchLogsQuery,
    state: EvidenceState,
    evidence: &'a AwsCloudWatchLogsEvidence,
    proposed_at: &'a DateTime<Utc>,
    registration_digest: &'a Digest,
    registration_revision: Revision,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    read_only: bool,
    live_execution: bool,
    connected: bool,
    native: bool,
    first_party: bool,
    outcome_adopted: bool,
}

impl AwsCloudWatchLogsProposal {
    fn new(
        query: CloudWatchLogsQuery,
        evidence: AwsCloudWatchLogsEvidence,
        proposed_at: DateTime<Utc>,
        registration: &AwsCloudWatchLogsRegistration,
        provider: &AwsCloudWatchLogsProviderIdentity,
    ) -> Self {
        let mut proposal = Self {
            state: evidence.state,
            query,
            evidence,
            proposed_at,
            registration_digest: registration.registration_digest.clone(),
            registration_revision: registration.registration_revision,
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            read_only: true,
            live_execution: false,
            connected: false,
            native: false,
            first_party: false,
            outcome_adopted: false,
            proposal_digest: Digest::zero(),
        };
        proposal.proposal_digest = proposal.recomputed_digest();
        proposal
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&ProposalBody {
            query: &self.query,
            state: self.state,
            evidence: &self.evidence,
            proposed_at: &self.proposed_at,
            registration_digest: &self.registration_digest,
            registration_revision: self.registration_revision,
            provider_digest: &self.provider_digest,
            api_digest: &self.api_digest,
            read_only: self.read_only,
            live_execution: self.live_execution,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
            outcome_adopted: self.outcome_adopted,
        })
    }

    pub fn validate(&self) -> Result<(), AwsCloudWatchLogsServiceError> {
        self.evidence.validate()?;
        if self.state != self.evidence.state
            || !self.read_only
            || self.live_execution
            || self.connected
            || self.native
            || self.first_party
            || self.outcome_adopted
            || self.proposal_digest != self.recomputed_digest()
        {
            return Err(AwsCloudWatchLogsServiceError::ProposalTampered);
        }
        Ok(())
    }

    pub fn is_adoptable(&self) -> bool {
        false
    }

    pub fn is_complete_bounded(&self) -> bool {
        self.evidence.is_adoptable()
    }

    pub fn status(&self) -> EvidenceState {
        self.state
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCloudWatchLogsRecordReceipt {
    pub recorded: bool,
    pub recorded_at: DateTime<Utc>,
    pub state: EvidenceState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub retained_raw_events: bool,
    pub durable_provider_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub outcome_adopted: bool,
    pub receipt_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordBody<'a> {
    recorded: bool,
    recorded_at: &'a DateTime<Utc>,
    state: EvidenceState,
    proposal_digest: &'a Digest,
    evidence_digest: &'a Digest,
    registration_digest: &'a Digest,
    scope_digest: &'a Digest,
    retained_raw_events: bool,
    durable_provider_receipt: bool,
    connected: bool,
    native: bool,
    first_party: bool,
    outcome_adopted: bool,
}

impl AwsCloudWatchLogsRecordReceipt {
    fn new(proposal: &AwsCloudWatchLogsProposal, recorded_at: DateTime<Utc>) -> Self {
        let mut receipt = Self {
            recorded: true,
            recorded_at,
            state: proposal.state,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.evidence.scope_digest.clone(),
            retained_raw_events: false,
            durable_provider_receipt: false,
            connected: false,
            native: false,
            first_party: false,
            outcome_adopted: false,
            receipt_digest: Digest::zero(),
        };
        receipt.receipt_digest = receipt.recomputed_digest();
        receipt
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&RecordBody {
            recorded: self.recorded,
            recorded_at: &self.recorded_at,
            state: self.state,
            proposal_digest: &self.proposal_digest,
            evidence_digest: &self.evidence_digest,
            registration_digest: &self.registration_digest,
            scope_digest: &self.scope_digest,
            retained_raw_events: self.retained_raw_events,
            durable_provider_receipt: self.durable_provider_receipt,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
            outcome_adopted: self.outcome_adopted,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCloudWatchLogsVerifiedRecord {
    pub verified: bool,
    pub state: EvidenceState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub verification_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopted_outcome: bool,
}

pub struct AwsCloudWatchLogsService<T>
where
    T: crate::AwsCloudWatchLogsTransport,
{
    scope: AwsCloudWatchLogsScope,
    permission: PermissionFence,
    secret_reference: SecretReference,
    provider: AwsCloudWatchLogsProvider<T>,
    registration: AwsCloudWatchLogsRegistration,
}

impl<T> fmt::Debug for AwsCloudWatchLogsService<T>
where
    T: crate::AwsCloudWatchLogsTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCloudWatchLogsService")
            .field("scope_digest", &self.scope.digest())
            .field("permission_digest", &self.permission.digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .finish()
    }
}

impl<T> AwsCloudWatchLogsService<T>
where
    T: crate::AwsCloudWatchLogsTransport,
{
    pub fn register(
        scope: AwsCloudWatchLogsScope,
        secret_reference: SecretReference,
        permission: PermissionFence,
        provider: AwsCloudWatchLogsProvider<T>,
    ) -> Result<Self, AwsCloudWatchLogsServiceError> {
        Self::new(scope, secret_reference, permission, provider)
    }

    pub fn new(
        scope: AwsCloudWatchLogsScope,
        secret_reference: SecretReference,
        permission: PermissionFence,
        provider: AwsCloudWatchLogsProvider<T>,
    ) -> Result<Self, AwsCloudWatchLogsServiceError> {
        scope.validate()?;
        if scope.permission_digest != permission.digest() {
            return Err(AwsCloudWatchLogsServiceError::ScopeMismatch(
                "permission digest".to_owned(),
            ));
        }
        for action in [
            PermissionAction::StartQuery,
            PermissionAction::GetQueryResults,
            PermissionAction::DescribeQueries,
        ] {
            if !permission.allows(action) {
                return Err(AwsCloudWatchLogsServiceError::ScopeMismatch(
                    "all CloudWatch Logs read permissions are required".to_owned(),
                ));
            }
        }
        if secret_reference.scope_digest() != &scope.digest()
            || secret_reference.signing_region() != &scope.region
            || secret_reference.signing_service() != "logs"
        {
            return Err(AwsCloudWatchLogsServiceError::ScopeMismatch(
                "SigV4 secret reference binding".to_owned(),
            ));
        }
        let registration = AwsCloudWatchLogsRegistration::new(
            &scope,
            &permission,
            &secret_reference,
            provider.identity(),
        )?;
        Ok(Self {
            scope,
            permission,
            secret_reference,
            provider,
            registration,
        })
    }

    pub const fn describe_capabilities() -> AwsCloudWatchLogsCapabilities {
        AwsCloudWatchLogsCapabilities::layer_one()
    }

    pub fn scope(&self) -> &AwsCloudWatchLogsScope {
        &self.scope
    }

    pub fn permission(&self) -> &PermissionFence {
        &self.permission
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &AwsCloudWatchLogsProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsCloudWatchLogsProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AwsCloudWatchLogsRegistration {
        &self.registration
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active() && !self.secret_reference.is_revoked()
    }

    pub fn revoke_secret(&mut self) -> Result<(), AwsCloudWatchLogsServiceError> {
        self.secret_reference.revoke()?;
        Ok(())
    }

    pub fn revoke_registration(&mut self) -> Result<(), AwsCloudWatchLogsServiceError> {
        self.registration.revoke()?;
        Ok(())
    }

    pub fn reverse_registration(&mut self) -> Result<(), AwsCloudWatchLogsServiceError> {
        self.registration.reverse()?;
        Ok(())
    }

    pub fn restore_registration(&mut self) -> Result<(), AwsCloudWatchLogsServiceError> {
        self.registration.restore()?;
        Ok(())
    }

    pub fn read(
        &mut self,
        query: &CloudWatchLogsQuery,
    ) -> Result<AwsCloudWatchLogsReadResult, AwsCloudWatchLogsServiceError> {
        self.ensure_active_and_bound()?;
        query
            .validate_against(&self.scope, &self.permission)
            .map_err(|_| AwsCloudWatchLogsServiceError::QueryTampered)?;
        let start_request = StartQueryRequest::from_query(
            &self.scope,
            &self.permission,
            &self.secret_reference,
            query,
        );
        let start = match self.provider.start_query(&start_request) {
            Ok(response) => response,
            Err(error) => {
                if error.kind == crate::ProviderErrorKind::MalformedResponse {
                    return Err(AwsCloudWatchLogsServiceError::EvidenceTampered);
                }
                return Ok(self.error_result(query, EvidenceState::from_error(&error), error));
            }
        };
        let query_id = start.query_id.clone();
        let describe_request = DescribeQueriesRequest::from_query(
            &self.scope,
            &self.permission,
            &self.secret_reference,
            query,
        );
        let described = match self.provider.describe_queries(&describe_request) {
            Ok(response) => response,
            Err(error) => {
                if error.kind == crate::ProviderErrorKind::MalformedResponse {
                    return Err(AwsCloudWatchLogsServiceError::EvidenceTampered);
                }
                return Ok(self.error_result_from_start(
                    query,
                    &start,
                    EvidenceState::from_error(&error),
                    error,
                ));
            }
        };
        let execution = described
            .queries
            .iter()
            .find(|candidate| candidate.query_id == query_id)
            .ok_or_else(|| {
                AwsCloudWatchLogsServiceError::ScopeMismatch(
                    "DescribeQueries omitted the started query".to_owned(),
                )
            })?;
        validate_execution(query, &start, execution)?;
        let status = execution.status;
        if status != QueryExecutionStatus::Complete {
            let state = status_to_evidence(status);
            return Ok(self.finish_result(
                query,
                state,
                None,
                &start,
                execution,
                0,
                0,
                0,
                0,
                0,
                0,
                Vec::new(),
                BTreeMap::new(),
                Vec::new(),
                Vec::new(),
                Digest::from_text("no-result-summary"),
                Vec::new(),
                false,
            ));
        }

        let mut page_number = 1_u8;
        let mut cursor = None;
        let mut seen_tokens = BTreeSet::new();
        let mut page_digests = Vec::new();
        let mut page_token_digests = Vec::new();
        let mut field_names = Vec::new();
        let mut error_class_counts = BTreeMap::new();
        let mut correlation_fingerprint_digests = Vec::new();
        let mut event_count = 0_u64;
        let mut bytes_scanned = 0_u64;
        let mut response_bytes = 0_usize;
        let mut partial_reason = None;
        let mut state = EvidenceState::Complete;
        let mut provider_errors = Vec::new();
        let mut summary_digest_parts = Vec::new();

        loop {
            let get_request = GetQueryResultsRequest::from_query(
                &self.scope,
                &self.permission,
                &self.secret_reference,
                query,
                query_id.clone(),
                page_number,
                cursor.clone(),
            );
            let response = match self.provider.get_query_results(&get_request) {
                Ok(response) => response,
                Err(error) => {
                    if matches!(error.kind, crate::ProviderErrorKind::MalformedResponse) {
                        return Err(AwsCloudWatchLogsServiceError::EvidenceTampered);
                    }
                    state = EvidenceState::from_error(&error);
                    partial_reason = Some(if error.kind == crate::ProviderErrorKind::Timeout {
                        crate::PartialReason::Timeout
                    } else {
                        crate::PartialReason::ProviderError
                    });
                    provider_errors.push(provider_error_evidence(&error));
                    break;
                }
            };
            page_digests.push(response.response_digest.clone());
            summary_digest_parts.push(response.summary.summary_digest.to_string());
            response_bytes = response_bytes.saturating_add(response.response_bytes);
            if response_bytes > query.bounds.max_response_bytes {
                state = EvidenceState::Partial;
                partial_reason = Some(crate::PartialReason::ResponseTooLarge);
                break;
            }
            event_count = event_count.saturating_add(response.summary.event_count);
            bytes_scanned = bytes_scanned.saturating_add(response.summary.bytes_scanned);
            field_names.extend(response.summary.field_names);
            for (class, count) in response.summary.error_class_counts {
                let entry = error_class_counts.entry(class).or_insert(0_u64);
                *entry = entry.saturating_add(count);
            }
            correlation_fingerprint_digests
                .extend(response.summary.correlation_fingerprint_digests);
            if event_count > u64::from(query.bounds.max_results) {
                event_count = u64::from(query.bounds.max_results);
                state = EvidenceState::Partial;
                partial_reason = Some(crate::PartialReason::ResultBudget);
                break;
            }
            if response.status.is_running() {
                state = EvidenceState::Running;
                partial_reason = Some(crate::PartialReason::QueryStillRunning);
                break;
            }
            if response.status.is_expired() {
                state = EvidenceState::Expired;
                partial_reason = Some(crate::PartialReason::Timeout);
                break;
            }
            if matches!(
                response.status,
                QueryExecutionStatus::Failed | QueryExecutionStatus::Cancelled
            ) {
                state = EvidenceState::Failed;
                partial_reason = Some(crate::PartialReason::ProviderError);
                break;
            }
            if response.status == QueryExecutionStatus::Unknown {
                state = EvidenceState::ProviderUnknown;
                partial_reason = Some(crate::PartialReason::ProviderError);
                break;
            }
            let Some(next_token) = response.next_page_token else {
                break;
            };
            let token_digest = next_token.digest();
            if !seen_tokens.insert(token_digest.clone()) {
                state = EvidenceState::Replay;
                partial_reason = Some(crate::PartialReason::QueryDrift);
                break;
            }
            page_token_digests.push(token_digest);
            if page_number >= query.bounds.max_pages {
                state = EvidenceState::Partial;
                partial_reason = Some(crate::PartialReason::PageBudget);
                break;
            }
            cursor = Some(next_token);
            page_number = page_number.saturating_add(1);
        }

        field_names.sort();
        field_names.dedup();
        correlation_fingerprint_digests.sort();
        correlation_fingerprint_digests.dedup();
        let summary_digest = Digest::from_parts(
            "hartevo-aws-cloudwatch-logs-summary-set/v1",
            &summary_digest_parts,
        );
        let result = self.finish_result(
            query,
            state,
            partial_reason,
            &start,
            execution,
            page_number.min(query.bounds.max_pages),
            u16::from(page_number),
            0,
            response_bytes,
            event_count,
            bytes_scanned,
            field_names,
            error_class_counts,
            correlation_fingerprint_digests,
            page_token_digests,
            summary_digest,
            provider_errors,
            state != EvidenceState::Complete,
        );
        Ok(AwsCloudWatchLogsReadResult {
            evidence: result.evidence,
            page_digests,
        })
    }

    pub fn read_bounded(
        &mut self,
        query: &CloudWatchLogsQuery,
    ) -> Result<AwsCloudWatchLogsReadResult, AwsCloudWatchLogsServiceError> {
        self.read(query)
    }

    pub fn propose(
        &mut self,
        query: CloudWatchLogsQuery,
        proposed_at: DateTime<Utc>,
    ) -> Result<AwsCloudWatchLogsProposal, AwsCloudWatchLogsServiceError> {
        let result = self.read(&query)?;
        Ok(AwsCloudWatchLogsProposal::new(
            query,
            result.evidence,
            proposed_at,
            &self.registration,
            self.provider.identity(),
        ))
    }

    pub fn propose_request(
        &mut self,
        request: QueryProposalRequest,
        proposed_at: DateTime<Utc>,
    ) -> Result<AwsCloudWatchLogsProposal, AwsCloudWatchLogsServiceError> {
        let query = request.compile(&self.scope, &self.permission)?;
        self.propose(query, proposed_at)
    }

    pub fn record(
        &self,
        proposal: &AwsCloudWatchLogsProposal,
    ) -> Result<AwsCloudWatchLogsRecordReceipt, AwsCloudWatchLogsServiceError> {
        self.record_at(proposal, Utc::now())
    }

    pub fn record_at(
        &self,
        proposal: &AwsCloudWatchLogsProposal,
        recorded_at: DateTime<Utc>,
    ) -> Result<AwsCloudWatchLogsRecordReceipt, AwsCloudWatchLogsServiceError> {
        self.verify_proposal(proposal)?;
        Ok(AwsCloudWatchLogsRecordReceipt::new(proposal, recorded_at))
    }

    pub fn verify(
        &self,
        receipt: &AwsCloudWatchLogsRecordReceipt,
    ) -> Result<AwsCloudWatchLogsVerifiedRecord, AwsCloudWatchLogsServiceError> {
        self.ensure_active_and_bound()?;
        if !receipt.recorded
            || receipt.registration_digest != self.registration.registration_digest
            || receipt.scope_digest != self.scope.digest()
            || receipt.receipt_digest != receipt.recomputed_digest()
            || receipt.retained_raw_events
            || receipt.durable_provider_receipt
            || receipt.connected
            || receipt.native
            || receipt.first_party
            || receipt.outcome_adopted
        {
            return Err(AwsCloudWatchLogsServiceError::RecordTampered);
        }
        let verification_digest = Digest::from_parts(
            "hartevo-aws-cloudwatch-logs-verified-record/v1",
            &[
                receipt.receipt_digest.to_string(),
                self.registration.registration_digest.to_string(),
                self.scope.digest().to_string(),
            ],
        );
        Ok(AwsCloudWatchLogsVerifiedRecord {
            verified: true,
            state: receipt.state,
            proposal_digest: receipt.proposal_digest.clone(),
            evidence_digest: receipt.evidence_digest.clone(),
            registration_digest: receipt.registration_digest.clone(),
            verification_digest,
            connected: false,
            native: false,
            first_party: false,
            adopted_outcome: false,
        })
    }

    pub fn verify_proposal(
        &self,
        proposal: &AwsCloudWatchLogsProposal,
    ) -> Result<(), AwsCloudWatchLogsServiceError> {
        self.ensure_active_and_bound()?;
        proposal.validate()?;
        proposal
            .query
            .validate_against(&self.scope, &self.permission)
            .map_err(|_| AwsCloudWatchLogsServiceError::QueryTampered)?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.registration_revision
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.permission_digest != self.permission.digest()
            || proposal.evidence.provider_digest != self.provider.identity().provider_digest
            || proposal.evidence.provider_revision != self.provider.identity().api_revision
            || proposal.evidence.api_digest != self.provider.identity().api_digest
            || proposal.evidence.contract_digest != contract_digest()
            || proposal.evidence.registration_digest != self.registration.registration_digest
            || proposal.provider_digest != self.provider.identity().provider_digest
            || proposal.api_digest != self.provider.identity().api_digest
        {
            return Err(AwsCloudWatchLogsServiceError::ProposalTampered);
        }
        Ok(())
    }

    fn ensure_active_and_bound(&self) -> Result<(), AwsCloudWatchLogsServiceError> {
        if !self.registration.is_active() {
            return Err(AwsCloudWatchLogsServiceError::RegistrationRevoked);
        }
        if self.secret_reference.is_revoked() {
            return Err(AwsCloudWatchLogsServiceError::SecretRevoked);
        }
        self.registration
            .validate(
                &self.scope,
                &self.permission,
                &self.secret_reference,
                self.provider.identity(),
            )
            .map_err(|error| AwsCloudWatchLogsServiceError::RegistrationDrift(error.to_string()))
    }

    fn error_result(
        &self,
        query: &CloudWatchLogsQuery,
        state: EvidenceState,
        error: TransportError,
    ) -> AwsCloudWatchLogsReadResult {
        let provider_errors = vec![provider_error_evidence(&error)];
        self.finish_result_without_execution(
            query,
            state,
            Some(crate::PartialReason::ProviderError),
            provider_errors,
        )
    }

    fn error_result_from_start(
        &self,
        query: &CloudWatchLogsQuery,
        start: &StartQueryResponse,
        state: EvidenceState,
        error: TransportError,
    ) -> AwsCloudWatchLogsReadResult {
        let execution = QueryExecutionSummary::from_start(start);
        let provider_errors = vec![provider_error_evidence(&error)];
        self.finish_result(
            query,
            state,
            Some(crate::PartialReason::ProviderError),
            start,
            &execution,
            0,
            2,
            0,
            0,
            0,
            0,
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
            Vec::new(),
            Digest::from_text("no-result-summary"),
            provider_errors,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_result(
        &self,
        query: &CloudWatchLogsQuery,
        state: EvidenceState,
        partial_reason: Option<crate::PartialReason>,
        start: &StartQueryResponse,
        execution: &QueryExecutionSummary,
        page_count: u8,
        request_count: u16,
        retry_count: u8,
        response_bytes: usize,
        event_count: u64,
        bytes_scanned: u64,
        field_names: Vec<FieldName>,
        error_class_counts: BTreeMap<ErrorClass, u64>,
        correlation_fingerprint_digests: Vec<Digest>,
        page_token_digests: Vec<Digest>,
        summary_digest: Digest,
        provider_errors: Vec<ProviderErrorEvidence>,
        truncated: bool,
    ) -> AwsCloudWatchLogsReadResult {
        let evidence = AwsCloudWatchLogsEvidence::new(
            state,
            partial_reason,
            query,
            &self.registration,
            self.provider.identity(),
            Some(start.query_id.digest()),
            execution.status,
            Some(execution.started_at),
            execution.finished_at,
            page_count,
            request_count,
            retry_count,
            response_bytes,
            event_count,
            bytes_scanned,
            field_names,
            error_class_counts,
            correlation_fingerprint_digests,
            page_token_digests,
            summary_digest,
            provider_errors,
            truncated,
        );
        AwsCloudWatchLogsReadResult {
            evidence,
            page_digests: Vec::new(),
        }
    }

    fn finish_result_without_execution(
        &self,
        query: &CloudWatchLogsQuery,
        state: EvidenceState,
        partial_reason: Option<crate::PartialReason>,
        provider_errors: Vec<ProviderErrorEvidence>,
    ) -> AwsCloudWatchLogsReadResult {
        let evidence = AwsCloudWatchLogsEvidence::new(
            state,
            partial_reason,
            query,
            &self.registration,
            self.provider.identity(),
            None,
            QueryExecutionStatus::Unknown,
            None,
            None,
            0,
            1,
            0,
            0,
            0,
            0,
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
            Vec::new(),
            Digest::from_text("no-result-summary"),
            provider_errors,
            true,
        );
        AwsCloudWatchLogsReadResult {
            evidence,
            page_digests: Vec::new(),
        }
    }
}

fn validate_execution(
    query: &CloudWatchLogsQuery,
    start: &StartQueryResponse,
    execution: &QueryExecutionSummary,
) -> Result<(), AwsCloudWatchLogsServiceError> {
    if execution.query_id != start.query_id
        || execution.query_digest != query.query_digest
        || execution.config_digest != query.config_digest
        || execution.scope_digest != query.scope_digest
        || execution.service_revision != query.service_revision
        || execution.deployment_revision != query.deployment_revision
    {
        return Err(AwsCloudWatchLogsServiceError::EvidenceTampered);
    }
    Ok(())
}

impl EvidenceState {
    fn from_error(error: &TransportError) -> Self {
        if is_access_loss(error) {
            Self::AccessLoss
        } else if error.kind == crate::ProviderErrorKind::Timeout {
            Self::Partial
        } else if error.kind == crate::ProviderErrorKind::MalformedResponse {
            Self::Tampered
        } else {
            Self::ProviderUnknown
        }
    }
}

pub type AwsCloudWatchLogsResultService<T> = AwsCloudWatchLogsService<T>;
pub type AwsCloudWatchLogsServiceDefinition = AwsCloudWatchLogsCapabilities;
pub type AwsCloudWatchLogsRegistrationReceipt = AwsCloudWatchLogsRegistration;
pub type AwsCloudWatchLogsRecord = AwsCloudWatchLogsRecordReceipt;
pub type AwsCloudWatchLogsVerified = AwsCloudWatchLogsVerifiedRecord;
