use std::{collections::BTreeMap, fmt};

use chrono::{DateTime, Utc};
use serde::Serialize;
use thiserror::Error;

use crate::consumer::MissionAwsSsmAutomationConsumer;
use crate::error::AwsSsmAutomationError;
use crate::model::{
    AutomationEvidenceState, AutomationExecutionMetadata, AutomationExecutionStatus,
    AutomationStepMetadata, AwsSsmAutomationReadRequest, AwsSsmAutomationScope, Digest,
    PermissionAction, PermissionSnapshot, ProviderErrorEvidence, SecretReference,
    TransportProvenance,
};
use crate::provider::{
    AwsSsmAutomationProvider, AwsSsmAutomationProviderDefinition, AwsSsmAutomationProviderError,
    AwsSsmAutomationTransport,
};
use crate::{CONTRACT_VERSION, MAX_IDENTIFIER_BYTES, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID};

type Result<T, E = AwsSsmAutomationServiceError> = std::result::Result<T, E>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Reversed,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransition {
    pub from: RegistrationStatus,
    pub to: RegistrationStatus,
    pub registration_revision: crate::model::Revision,
    pub transition_digest: Digest,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegistrationError {
    #[error("AWS SSM Automation registration is already revoked")]
    AlreadyRevoked,
    #[error("AWS SSM Automation registration is already reversed")]
    AlreadyReversed,
    #[error("AWS SSM Automation registration is not reversed")]
    NotReversed,
    #[error("AWS SSM Automation registration revision overflowed")]
    RevisionOverflow,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsSsmAutomationServiceError {
    #[error("AWS SSM Automation model error: {0}")]
    Model(#[from] AwsSsmAutomationError),
    #[error("AWS SSM Automation provider error: {0}")]
    Provider(#[from] AwsSsmAutomationProviderError),
    #[error("AWS SSM Automation registration is revoked")]
    RegistrationRevoked,
    #[error("AWS SSM Automation registration is reversed")]
    RegistrationReversed,
    #[error("AWS SSM Automation registration is not active")]
    RegistrationInactive,
    #[error("AWS SSM Automation registration has drifted")]
    RegistrationDrift,
    #[error("AWS SSM Automation execution was replaced")]
    ExecutionReplaced,
    #[error("AWS SSM Automation status regressed")]
    StatusRegression,
    #[error("AWS SSM Automation evidence was partial")]
    PartialEvidence,
    #[error("AWS SSM Automation evidence was truncated")]
    TruncatedEvidence,
    #[error("AWS SSM Automation proposal or evidence was tampered")]
    TamperedEvidence,
    #[error("AWS SSM Automation response was invalid")]
    InvalidResponse,
    #[error("AWS SSM Automation record conflicts with an existing idempotency key")]
    RecordingConflict,
    #[error("AWS SSM Automation registration lifecycle error: {0}")]
    Registration(#[from] RegistrationError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSsmAutomationCapabilities {
    pub service_id: &'static str,
    pub provider_id: &'static str,
    pub operations: [&'static str; 9],
    pub allowlisted_api_operations: [&'static str; 3],
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub connected: bool,
    pub native: bool,
    pub external_writes: bool,
    pub raw_output_retained: bool,
    pub raw_logs_retained: bool,
    pub outcome_authority: bool,
}

impl AwsSsmAutomationCapabilities {
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
                "read",
                "propose",
                "record",
                "verify",
            ],
            allowlisted_api_operations: [
                "DescribeAutomationExecutions",
                "GetAutomationExecution",
                "DescribeAutomationStepExecutions",
            ],
            read_only: true,
            proposal_only: true,
            recording_only: true,
            connected: false,
            native: false,
            external_writes: false,
            raw_output_retained: false,
            raw_logs_retained: false,
            outcome_authority: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSsmAutomationRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub evidence_policy_digest: Digest,
    pub registration_revision: crate::model::Revision,
    pub status: RegistrationStatus,
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
    provider_revision: &'a str,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    secret_reference_digest: &'a Digest,
    evidence_policy_digest: &'a Digest,
    registration_revision: crate::model::Revision,
    status: RegistrationStatus,
}

impl AwsSsmAutomationRegistration {
    fn new(
        scope: &AwsSsmAutomationScope,
        secret_reference: &SecretReference,
        permission: &PermissionSnapshot,
        provider: &AwsSsmAutomationProviderDefinition,
    ) -> Self {
        let evidence_policy_digest = Digest::from_parts(
            "hartevo-aws-ssm-automation-evidence-policy/v1",
            &[
                ("contract", CONTRACT_VERSION.to_owned()),
                ("maxPages", crate::MAX_PAGES.to_string()),
                ("maxPageSize", crate::MAX_PAGE_SIZE.to_string()),
                ("maxResponseBytes", crate::MAX_RESPONSE_BYTES.to_string()),
                ("rawOutput", "false".to_owned()),
                ("rawLogs", "false".to_owned()),
                ("rawErrors", "false".to_owned()),
            ],
        );
        let mut registration = Self {
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.version.clone(),
            provider_revision: provider.api_revision.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            permission_digest: permission.digest(),
            scope_digest: scope.digest(),
            secret_reference_digest: secret_reference.digest().clone(),
            evidence_policy_digest,
            registration_revision: crate::model::Revision::new(1).expect("revision one"),
            status: RegistrationStatus::Active,
            registration_digest: Digest::zero(),
        };
        registration.registration_digest = registration.recomputed_digest();
        registration
    }

    pub fn is_active(&self) -> bool {
        self.status == RegistrationStatus::Active
    }

    pub fn is_revoked(&self) -> bool {
        self.status == RegistrationStatus::Revoked
    }

    pub fn is_reversed(&self) -> bool {
        self.status == RegistrationStatus::Reversed
    }

    pub fn recomputed_digest(&self) -> Digest {
        crate::model::digest_serialized(&RegistrationBody {
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
            secret_reference_digest: &self.secret_reference_digest,
            evidence_policy_digest: &self.evidence_policy_digest,
            registration_revision: self.registration_revision,
            status: self.status,
        })
    }

    pub fn validate(
        &self,
        scope: &AwsSsmAutomationScope,
        secret_reference: &SecretReference,
        permission: &PermissionSnapshot,
        provider: &AwsSsmAutomationProviderDefinition,
    ) -> Result<(), AwsSsmAutomationServiceError> {
        if self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_id != provider.provider_id
            || self.provider_version != provider.version
            || self.provider_revision != provider.api_revision
            || self.provider_digest != provider.provider_digest
            || self.api_digest != provider.api_digest
            || self.permission_digest != permission.digest()
            || self.scope_digest != scope.digest()
            || self.secret_reference_digest != *secret_reference.digest()
            || self.registration_digest != self.recomputed_digest()
        {
            return Err(AwsSsmAutomationServiceError::RegistrationDrift);
        }
        Ok(())
    }

    fn transition(
        &mut self,
        to: RegistrationStatus,
    ) -> Result<RegistrationTransition, RegistrationError> {
        let from = self.status;
        match (from, to) {
            (RegistrationStatus::Revoked, _) => return Err(RegistrationError::AlreadyRevoked),
            (RegistrationStatus::Reversed, RegistrationStatus::Reversed) => {
                return Err(RegistrationError::AlreadyReversed);
            }
            (RegistrationStatus::Active, RegistrationStatus::Active) => {
                return Err(RegistrationError::NotReversed);
            }
            (
                RegistrationStatus::Active,
                RegistrationStatus::Revoked | RegistrationStatus::Reversed,
            )
            | (RegistrationStatus::Reversed, RegistrationStatus::Active) => {}
            (RegistrationStatus::Reversed, RegistrationStatus::Revoked) => {}
        }
        self.registration_revision = self
            .registration_revision
            .next()
            .map_err(|_| RegistrationError::RevisionOverflow)?;
        self.status = to;
        self.registration_digest = self.recomputed_digest();
        Ok(RegistrationTransition {
            from,
            to,
            registration_revision: self.registration_revision,
            transition_digest: Digest::from_parts(
                "hartevo-aws-ssm-automation-registration-transition/v1",
                &[
                    ("from", format!("{from:?}")),
                    ("to", format!("{to:?}")),
                    ("revision", self.registration_revision.get().to_string()),
                    ("registration", self.registration_digest.to_string()),
                ],
            ),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSsmAutomationReadResult {
    pub execution: AutomationExecutionMetadata,
    pub steps: Vec<AutomationStepMetadata>,
    pub state: AutomationEvidenceState,
    pub list_pages: u16,
    pub step_pages: u16,
    pub complete: bool,
    pub provenance: TransportProvenance,
    pub filter_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub execution_digest: Digest,
    pub step_digest: Digest,
    pub output_digest: Option<Digest>,
    pub error_digest: Option<Digest>,
    pub request_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSsmAutomationEvidence {
    pub state: AutomationEvidenceState,
    pub execution: Option<AutomationExecutionMetadata>,
    pub steps: Vec<AutomationStepMetadata>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub filter_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub execution_digest: Option<Digest>,
    pub step_digest: Digest,
    pub output_digest: Option<Digest>,
    pub error_digest: Option<Digest>,
    pub provider_error: Option<ProviderErrorEvidence>,
    pub list_pages: u16,
    pub step_pages: u16,
    pub complete: bool,
    pub provenance: TransportProvenance,
    pub observed_at: DateTime<Utc>,
    pub evidence_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceBody<'a> {
    state: AutomationEvidenceState,
    execution: &'a Option<AutomationExecutionMetadata>,
    steps: &'a [AutomationStepMetadata],
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
    filter_digest: &'a Digest,
    cursor_digest: &'a Option<Digest>,
    execution_digest: &'a Option<Digest>,
    step_digest: &'a Digest,
    output_digest: &'a Option<Digest>,
    error_digest: &'a Option<Digest>,
    provider_error: &'a Option<ProviderErrorEvidence>,
    list_pages: u16,
    step_pages: u16,
    complete: bool,
    provenance: TransportProvenance,
    observed_at: &'a DateTime<Utc>,
}

impl AwsSsmAutomationEvidence {
    fn from_read(
        read: &AwsSsmAutomationReadResult,
        scope: &AwsSsmAutomationScope,
        permission: &PermissionSnapshot,
        observed_at: DateTime<Utc>,
    ) -> Self {
        let mut evidence = Self {
            state: read.state,
            execution: Some(read.execution.clone()),
            steps: read.steps.clone(),
            scope_digest: scope.digest(),
            permission_digest: permission.digest(),
            filter_digest: read.filter_digest.clone(),
            cursor_digest: read.cursor_digest.clone(),
            execution_digest: Some(read.execution_digest.clone()),
            step_digest: read.step_digest.clone(),
            output_digest: read.output_digest.clone(),
            error_digest: read.error_digest.clone(),
            provider_error: None,
            list_pages: read.list_pages,
            step_pages: read.step_pages,
            complete: read.complete,
            provenance: read.provenance,
            observed_at,
            evidence_digest: Digest::zero(),
        };
        evidence.evidence_digest = evidence.recomputed_digest();
        evidence
    }

    fn from_error(
        error_state: AutomationEvidenceState,
        provider_error: Option<ProviderErrorEvidence>,
        request: &AwsSsmAutomationReadRequest,
        scope: &AwsSsmAutomationScope,
        observed_at: DateTime<Utc>,
        provenance: TransportProvenance,
    ) -> Self {
        let mut evidence = Self {
            state: error_state,
            execution: None,
            steps: Vec::new(),
            scope_digest: scope.digest(),
            permission_digest: scope.permission_digest.clone(),
            filter_digest: request.filter.filter_digest(),
            cursor_digest: request
                .filter
                .cursor
                .as_ref()
                .map(|cursor| cursor.token_digest().clone()),
            execution_digest: None,
            step_digest: Digest::from_text("no-steps"),
            output_digest: None,
            error_digest: provider_error
                .as_ref()
                .map(|value| value.error_digest.clone()),
            provider_error,
            list_pages: 0,
            step_pages: 0,
            complete: false,
            provenance,
            observed_at,
            evidence_digest: Digest::zero(),
        };
        evidence.evidence_digest = evidence.recomputed_digest();
        evidence
    }

    pub fn recomputed_digest(&self) -> Digest {
        crate::model::digest_serialized(&EvidenceBody {
            state: self.state,
            execution: &self.execution,
            steps: &self.steps,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            filter_digest: &self.filter_digest,
            cursor_digest: &self.cursor_digest,
            execution_digest: &self.execution_digest,
            step_digest: &self.step_digest,
            output_digest: &self.output_digest,
            error_digest: &self.error_digest,
            provider_error: &self.provider_error,
            list_pages: self.list_pages,
            step_pages: self.step_pages,
            complete: self.complete,
            provenance: self.provenance,
            observed_at: &self.observed_at,
        })
    }

    pub fn validate_integrity(&self) -> Result<(), AwsSsmAutomationServiceError> {
        if self.evidence_digest != self.recomputed_digest()
            || self.scope_digest.is_zero()
            || self.permission_digest.is_zero()
        {
            return Err(AwsSsmAutomationServiceError::TamperedEvidence);
        }
        Ok(())
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn review_only(&self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSsmAutomationProposal {
    pub evidence: AwsSsmAutomationEvidence,
    pub proposed_at: DateTime<Utc>,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub read_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub adopted_outcome: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposalBody<'a> {
    evidence: &'a AwsSsmAutomationEvidence,
    proposed_at: &'a DateTime<Utc>,
    registration_digest: &'a Digest,
    read_only: bool,
    live_execution: bool,
    connected: bool,
    native: bool,
    first_party: bool,
    provider_receipt: bool,
    adopted_outcome: bool,
}

impl AwsSsmAutomationProposal {
    fn new(
        evidence: AwsSsmAutomationEvidence,
        proposed_at: DateTime<Utc>,
        registration_digest: Digest,
    ) -> Self {
        let mut proposal = Self {
            evidence,
            proposed_at,
            registration_digest,
            proposal_digest: Digest::zero(),
            read_only: true,
            live_execution: false,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            adopted_outcome: false,
        };
        proposal.proposal_digest = proposal.recomputed_digest();
        proposal
    }

    pub fn recomputed_digest(&self) -> Digest {
        crate::model::digest_serialized(&ProposalBody {
            evidence: &self.evidence,
            proposed_at: &self.proposed_at,
            registration_digest: &self.registration_digest,
            read_only: self.read_only,
            live_execution: self.live_execution,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
            provider_receipt: self.provider_receipt,
            adopted_outcome: self.adopted_outcome,
        })
    }

    pub fn validate_integrity(&self) -> Result<(), AwsSsmAutomationServiceError> {
        self.evidence.validate_integrity()?;
        if self.proposal_digest != self.recomputed_digest()
            || !self.read_only
            || self.live_execution
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.adopted_outcome
        {
            return Err(AwsSsmAutomationServiceError::TamperedEvidence);
        }
        Ok(())
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSsmAutomationRecord {
    pub recorded: bool,
    pub recorded_at: DateTime<Utc>,
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub state: AutomationEvidenceState,
    pub retained_raw_output: bool,
    pub retained_raw_logs: bool,
    pub durable_provider_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub record_digest: Digest,
    pub replayed: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordBody<'a> {
    recorded: bool,
    recorded_at: &'a DateTime<Utc>,
    idempotency_key_digest: &'a Digest,
    proposal_digest: &'a Digest,
    evidence_digest: &'a Digest,
    registration_digest: &'a Digest,
    scope_digest: &'a Digest,
    state: AutomationEvidenceState,
    retained_raw_output: bool,
    retained_raw_logs: bool,
    durable_provider_receipt: bool,
    connected: bool,
    native: bool,
}

impl AwsSsmAutomationRecord {
    fn new(
        proposal: &AwsSsmAutomationProposal,
        idempotency_key: &str,
        recorded_at: DateTime<Utc>,
        replayed: bool,
    ) -> Self {
        let mut record = Self {
            recorded: true,
            recorded_at,
            idempotency_key_digest: Digest::from_text(idempotency_key),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.evidence.scope_digest.clone(),
            state: proposal.evidence.state,
            retained_raw_output: false,
            retained_raw_logs: false,
            durable_provider_receipt: false,
            connected: false,
            native: false,
            record_digest: Digest::zero(),
            replayed,
        };
        record.record_digest = record.recomputed_digest();
        record
    }

    pub fn recomputed_digest(&self) -> Digest {
        crate::model::digest_serialized(&RecordBody {
            recorded: self.recorded,
            recorded_at: &self.recorded_at,
            idempotency_key_digest: &self.idempotency_key_digest,
            proposal_digest: &self.proposal_digest,
            evidence_digest: &self.evidence_digest,
            registration_digest: &self.registration_digest,
            scope_digest: &self.scope_digest,
            state: self.state,
            retained_raw_output: self.retained_raw_output,
            retained_raw_logs: self.retained_raw_logs,
            durable_provider_receipt: self.durable_provider_receipt,
            connected: self.connected,
            native: self.native,
        })
    }

    pub fn validate_integrity(&self) -> Result<(), AwsSsmAutomationServiceError> {
        if self.record_digest != self.recomputed_digest()
            || !self.recorded
            || self.retained_raw_output
            || self.retained_raw_logs
            || self.durable_provider_receipt
            || self.connected
            || self.native
        {
            return Err(AwsSsmAutomationServiceError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub state: AutomationEvidenceState,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub verification_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub adopted_outcome: bool,
}

pub struct AwsSsmAutomationService<T>
where
    T: AwsSsmAutomationTransport,
{
    scope: AwsSsmAutomationScope,
    permission: PermissionSnapshot,
    secret_reference: SecretReference,
    provider: AwsSsmAutomationProvider<T>,
    registration: AwsSsmAutomationRegistration,
    now: DateTime<Utc>,
    last_execution_fingerprint: Option<Digest>,
    last_status: Option<AutomationExecutionStatus>,
    records: BTreeMap<Digest, AwsSsmAutomationRecord>,
}

impl<T> fmt::Debug for AwsSsmAutomationService<T>
where
    T: AwsSsmAutomationTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsSsmAutomationService")
            .field("scope_digest", &self.scope.digest())
            .field("permission_digest", &self.permission.digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl<T> AwsSsmAutomationService<T>
where
    T: AwsSsmAutomationTransport,
{
    pub fn register(
        scope: AwsSsmAutomationScope,
        secret_reference: SecretReference,
        permission: PermissionSnapshot,
        provider: AwsSsmAutomationProvider<T>,
        now: DateTime<Utc>,
    ) -> Result<Self, AwsSsmAutomationServiceError> {
        Self::new(scope, secret_reference, permission, provider, now)
    }

    pub fn new(
        scope: AwsSsmAutomationScope,
        secret_reference: SecretReference,
        permission: PermissionSnapshot,
        provider: AwsSsmAutomationProvider<T>,
        now: DateTime<Utc>,
    ) -> Result<Self, AwsSsmAutomationServiceError> {
        scope.validate()?;
        if scope.permission_digest != permission.digest()
            || !permission.allows(PermissionAction::DescribeAutomationExecutions)
            || !permission.allows(PermissionAction::GetAutomationExecution)
            || !permission.allows(PermissionAction::DescribeAutomationStepExecutions)
            || secret_reference.signing_service() != "ssm"
            || secret_reference.signing_region() != &scope.region
        {
            return Err(AwsSsmAutomationServiceError::Model(
                AwsSsmAutomationError::InvalidPermissionFence,
            ));
        }
        provider
            .definition()
            .validate()
            .map_err(AwsSsmAutomationServiceError::Provider)?;
        let registration = AwsSsmAutomationRegistration::new(
            &scope,
            &secret_reference,
            &permission,
            provider.definition(),
        );
        Ok(Self {
            scope,
            permission,
            secret_reference,
            provider,
            registration,
            now,
            last_execution_fingerprint: None,
            last_status: None,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AwsSsmAutomationScope {
        &self.scope
    }

    pub fn permission(&self) -> &PermissionSnapshot {
        &self.permission
    }

    pub fn provider(&self) -> &AwsSsmAutomationProvider<T> {
        &self.provider
    }

    pub fn registration(&self) -> &AwsSsmAutomationRegistration {
        &self.registration
    }

    pub fn describe_capabilities(&self) -> AwsSsmAutomationCapabilities {
        AwsSsmAutomationCapabilities::layer_one()
    }

    pub fn default_request(
        &self,
    ) -> Result<AwsSsmAutomationReadRequest, AwsSsmAutomationServiceError> {
        Ok(AwsSsmAutomationReadRequest::for_scope(&self.scope)?)
    }

    pub fn read(
        &mut self,
        request: &AwsSsmAutomationReadRequest,
    ) -> Result<AwsSsmAutomationReadResult, AwsSsmAutomationServiceError> {
        self.ensure_active()?;
        self.registration.validate(
            &self.scope,
            &self.secret_reference,
            &self.permission,
            self.provider.definition(),
        )?;
        request.validate(&self.scope)?;
        if request.permission_digest != self.registration.permission_digest {
            return Err(AwsSsmAutomationServiceError::RegistrationDrift);
        }

        let mut list_request = request.describe_request();
        let mut executions = Vec::new();
        let mut list_pages = 0_u16;
        let list_complete = loop {
            if list_pages >= request.filter.max_pages {
                return Err(AwsSsmAutomationServiceError::TruncatedEvidence);
            }
            let response = self
                .provider
                .describe_automation_executions(&list_request)?;
            list_pages = list_pages.saturating_add(1);
            if response.response_bytes > request.filter.max_response_bytes {
                return Err(AwsSsmAutomationServiceError::TruncatedEvidence);
            }
            executions.extend(response.executions);
            if let Some(cursor) = response.next_cursor {
                if list_pages >= request.filter.max_pages {
                    return Err(AwsSsmAutomationServiceError::TruncatedEvidence);
                }
                list_request.filter = list_request.filter.with_cursor(Some(cursor))?;
            } else if response.complete {
                break true;
            } else {
                return Err(AwsSsmAutomationServiceError::PartialEvidence);
            }
        };

        if executions.is_empty() {
            return Err(AwsSsmAutomationServiceError::Provider(
                AwsSsmAutomationProviderError::Transport(
                    crate::error::AwsSsmAutomationTransportError::NotFound,
                ),
            ));
        }
        if executions.iter().any(|execution| {
            execution.execution_id != self.scope.execution_id
                || execution.document_name != self.scope.document_name
                || execution.document_version != self.scope.document_version
        }) {
            return Err(AwsSsmAutomationServiceError::ExecutionReplaced);
        }
        let listed = executions
            .first()
            .cloned()
            .ok_or(AwsSsmAutomationServiceError::ExecutionReplaced)?;
        if let Some(expected_status) = &request.filter.status
            && expected_status != &listed.status
        {
            return Err(AwsSsmAutomationServiceError::Model(
                AwsSsmAutomationError::FilterMismatch,
            ));
        }
        if !self.scope.target_matches(listed.target.as_ref()) {
            return Err(AwsSsmAutomationServiceError::Model(
                AwsSsmAutomationError::ScopeMismatch { field: "target" },
            ));
        }

        let get_response = self
            .provider
            .get_automation_execution(&request.get_request())?;
        if get_response.response_bytes > request.filter.max_response_bytes {
            return Err(AwsSsmAutomationServiceError::TruncatedEvidence);
        }
        let execution = get_response.execution;
        if execution.fingerprint_digest() != listed.fingerprint_digest() {
            return Err(AwsSsmAutomationServiceError::ExecutionReplaced);
        }
        if !self.scope.target_matches(execution.target.as_ref()) {
            return Err(AwsSsmAutomationServiceError::Model(
                AwsSsmAutomationError::ScopeMismatch { field: "target" },
            ));
        }

        let mut step_request = request.steps_request();
        let mut steps = Vec::new();
        let mut step_pages = 0_u16;
        let step_complete = loop {
            if step_pages >= request.filter.max_pages {
                return Err(AwsSsmAutomationServiceError::TruncatedEvidence);
            }
            let response = self
                .provider
                .describe_automation_step_executions(&step_request)?;
            step_pages = step_pages.saturating_add(1);
            if response.response_bytes > request.filter.max_response_bytes {
                return Err(AwsSsmAutomationServiceError::TruncatedEvidence);
            }
            steps.extend(response.steps);
            if steps.len() > crate::model::MAX_STEP_COUNT {
                return Err(AwsSsmAutomationServiceError::TruncatedEvidence);
            }
            if let Some(cursor) = response.next_cursor {
                if step_pages >= request.filter.max_pages {
                    return Err(AwsSsmAutomationServiceError::TruncatedEvidence);
                }
                step_request = step_request.with_cursor(Some(cursor))?;
            } else if response.complete {
                break true;
            } else {
                return Err(AwsSsmAutomationServiceError::PartialEvidence);
            }
        };
        for step in &steps {
            if !self.scope.step_matches(&step.step_name) {
                return Err(AwsSsmAutomationServiceError::Model(
                    AwsSsmAutomationError::ScopeMismatch { field: "step" },
                ));
            }
            if !self.scope.target_matches(step.target.as_ref()) {
                return Err(AwsSsmAutomationServiceError::Model(
                    AwsSsmAutomationError::ScopeMismatch { field: "target" },
                ));
            }
        }
        if let Some(expected_step) = &self.scope.step_name
            && !steps.iter().any(|step| &step.step_name == expected_step)
        {
            return Err(AwsSsmAutomationServiceError::Model(
                AwsSsmAutomationError::ScopeMismatch { field: "step" },
            ));
        }

        if let Some(previous_fingerprint) = &self.last_execution_fingerprint
            && previous_fingerprint != &execution.fingerprint_digest()
        {
            return Err(AwsSsmAutomationServiceError::ExecutionReplaced);
        }
        if let Some(previous_status) = self.last_status
            && !execution.status.permits_transition_from(previous_status)
        {
            return Err(AwsSsmAutomationServiceError::StatusRegression);
        }
        self.last_execution_fingerprint = Some(execution.fingerprint_digest());
        self.last_status = Some(execution.status);

        let step_digest = crate::model::digest_serialized(&steps);
        Ok(AwsSsmAutomationReadResult {
            state: execution.status.evidence_state(),
            filter_digest: request.filter.filter_digest(),
            cursor_digest: request
                .filter
                .cursor
                .as_ref()
                .map(|cursor| cursor.token_digest().clone()),
            execution_digest: execution.digest(),
            output_digest: execution.output_digest.clone(),
            error_digest: execution.error_digest.clone(),
            request_digest: request.request_digest(),
            execution,
            steps,
            list_pages,
            step_pages,
            complete: list_complete && step_complete,
            provenance: self.provider.provenance(),
            step_digest,
        })
    }

    pub fn propose(
        &mut self,
        request: &AwsSsmAutomationReadRequest,
    ) -> Result<AwsSsmAutomationProposal, AwsSsmAutomationServiceError> {
        self.ensure_active()?;
        let evidence = match self.read(request) {
            Ok(read) => {
                AwsSsmAutomationEvidence::from_read(&read, &self.scope, &self.permission, self.now)
            }
            Err(error) => {
                let Some(state) = Self::evidence_state_for_error(&error) else {
                    return Err(error);
                };
                let provider_error = match &error {
                    AwsSsmAutomationServiceError::Provider(provider) => Some(provider.evidence()),
                    _ => None,
                };
                AwsSsmAutomationEvidence::from_error(
                    state,
                    provider_error,
                    request,
                    &self.scope,
                    self.now,
                    self.provider.provenance(),
                )
            }
        };
        Ok(AwsSsmAutomationProposal::new(
            evidence,
            self.now,
            self.registration.registration_digest.clone(),
        ))
    }

    pub fn verify(
        &self,
        proposal: &AwsSsmAutomationProposal,
    ) -> Result<VerificationReport, AwsSsmAutomationServiceError> {
        proposal.validate_integrity()?;
        self.registration.validate(
            &self.scope,
            &self.secret_reference,
            &self.permission,
            self.provider.definition(),
        )?;
        if !self.registration.is_active() {
            return Err(AwsSsmAutomationServiceError::RegistrationInactive);
        }
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.permission_digest != self.permission.digest()
        {
            return Err(AwsSsmAutomationServiceError::RegistrationDrift);
        }
        let verification_digest = Digest::from_parts(
            "hartevo-aws-ssm-automation-verification/v1",
            &[
                ("proposal", proposal.proposal_digest.to_string()),
                ("evidence", proposal.evidence.evidence_digest.to_string()),
                (
                    "registration",
                    self.registration.registration_digest.to_string(),
                ),
                ("state", format!("{:?}", proposal.evidence.state)),
            ],
        );
        Ok(VerificationReport {
            valid: true,
            review_eligible: true,
            state: proposal.evidence.state,
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            verification_digest,
            connected: false,
            native: false,
            adopted_outcome: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &AwsSsmAutomationProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<AwsSsmAutomationRecord, AwsSsmAutomationServiceError> {
        self.ensure_active()?;
        proposal.validate_integrity()?;
        if proposal.registration_digest != self.registration.registration_digest {
            return Err(AwsSsmAutomationServiceError::RegistrationDrift);
        }
        let idempotency_key = idempotency_key.as_ref();
        if idempotency_key.is_empty()
            || idempotency_key.len() > MAX_IDENTIFIER_BYTES
            || idempotency_key.chars().any(char::is_control)
        {
            return Err(AwsSsmAutomationServiceError::Model(
                AwsSsmAutomationError::InvalidText {
                    field: "idempotency key",
                },
            ));
        }
        let key_digest = Digest::from_text(idempotency_key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsSsmAutomationServiceError::RecordingConflict);
            }
            return Ok(AwsSsmAutomationRecord::new(
                proposal,
                idempotency_key,
                self.now,
                true,
            ));
        }
        let record = AwsSsmAutomationRecord::new(proposal, idempotency_key, self.now, false);
        self.records.insert(key_digest, record.clone());
        Ok(record)
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consumer(
        &self,
    ) -> Result<MissionAwsSsmAutomationConsumer, AwsSsmAutomationServiceError> {
        self.ensure_active_ref()?;
        MissionAwsSsmAutomationConsumer::new(self.scope.clone(), self.registration.clone())
            .map_err(|_| AwsSsmAutomationServiceError::RegistrationDrift)
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationTransition, AwsSsmAutomationServiceError> {
        let transition = self.registration.transition(RegistrationStatus::Revoked)?;
        Ok(transition)
    }

    pub fn reverse_registration(
        &mut self,
    ) -> Result<RegistrationTransition, AwsSsmAutomationServiceError> {
        let transition = self.registration.transition(RegistrationStatus::Reversed)?;
        Ok(transition)
    }

    pub fn restore_registration(
        &mut self,
    ) -> Result<RegistrationTransition, AwsSsmAutomationServiceError> {
        let transition = self.registration.transition(RegistrationStatus::Active)?;
        Ok(transition)
    }

    pub fn registration_status(&self) -> RegistrationStatus {
        self.registration.status
    }

    fn ensure_active(&self) -> Result<(), AwsSsmAutomationServiceError> {
        self.ensure_active_ref()
    }

    fn ensure_active_ref(&self) -> Result<(), AwsSsmAutomationServiceError> {
        match self.registration.status {
            RegistrationStatus::Active => Ok(()),
            RegistrationStatus::Reversed => Err(AwsSsmAutomationServiceError::RegistrationReversed),
            RegistrationStatus::Revoked => Err(AwsSsmAutomationServiceError::RegistrationRevoked),
        }
    }

    fn evidence_state_for_error(
        error: &AwsSsmAutomationServiceError,
    ) -> Option<AutomationEvidenceState> {
        match error {
            AwsSsmAutomationServiceError::Provider(provider) => {
                provider.transport_error().map(|transport| match transport {
                    crate::error::AwsSsmAutomationTransportError::InvalidFilter => {
                        AutomationEvidenceState::InvalidFilter
                    }
                    crate::error::AwsSsmAutomationTransportError::InvalidNextToken => {
                        AutomationEvidenceState::InvalidNextToken
                    }
                    crate::error::AwsSsmAutomationTransportError::Throttled { .. } => {
                        AutomationEvidenceState::Throttled
                    }
                    crate::error::AwsSsmAutomationTransportError::AccessLoss
                    | crate::error::AwsSsmAutomationTransportError::Unauthorized
                    | crate::error::AwsSsmAutomationTransportError::Forbidden => {
                        AutomationEvidenceState::AccessLoss
                    }
                    crate::error::AwsSsmAutomationTransportError::Partial => {
                        AutomationEvidenceState::Partial
                    }
                    crate::error::AwsSsmAutomationTransportError::Truncated => {
                        AutomationEvidenceState::Truncated
                    }
                    crate::error::AwsSsmAutomationTransportError::Unknown
                    | crate::error::AwsSsmAutomationTransportError::InvalidResponse
                    | crate::error::AwsSsmAutomationTransportError::BlockedEnv
                    | crate::error::AwsSsmAutomationTransportError::BadRequest
                    | crate::error::AwsSsmAutomationTransportError::NotFound
                    | crate::error::AwsSsmAutomationTransportError::Conflict
                    | crate::error::AwsSsmAutomationTransportError::ServerError { .. }
                    | crate::error::AwsSsmAutomationTransportError::Timeout => {
                        AutomationEvidenceState::ProviderUnknown
                    }
                })
            }
            AwsSsmAutomationServiceError::ExecutionReplaced => {
                Some(AutomationEvidenceState::ExecutionReplaced)
            }
            AwsSsmAutomationServiceError::StatusRegression => {
                Some(AutomationEvidenceState::ProviderUnknown)
            }
            AwsSsmAutomationServiceError::PartialEvidence => Some(AutomationEvidenceState::Partial),
            AwsSsmAutomationServiceError::TruncatedEvidence => {
                Some(AutomationEvidenceState::Truncated)
            }
            AwsSsmAutomationServiceError::RegistrationRevoked
            | AwsSsmAutomationServiceError::RegistrationReversed
            | AwsSsmAutomationServiceError::RegistrationInactive => {
                Some(AutomationEvidenceState::RegistrationRevoked)
            }
            AwsSsmAutomationServiceError::Model(_)
            | AwsSsmAutomationServiceError::InvalidResponse
            | AwsSsmAutomationServiceError::RegistrationDrift
            | AwsSsmAutomationServiceError::TamperedEvidence
            | AwsSsmAutomationServiceError::RecordingConflict
            | AwsSsmAutomationServiceError::Registration(_) => None,
        }
    }
}

pub type AwsSsmAutomationServiceAlias<T> = AwsSsmAutomationService<T>;
