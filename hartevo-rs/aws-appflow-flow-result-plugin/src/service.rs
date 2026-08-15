use std::{collections::BTreeSet, fmt};

use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionAwsAppFlowConsumer;
use crate::error::{AwsAppFlowResultError, AwsAppFlowTransportError, Result};
use crate::model::{
    AppFlowOperation, AwsAppFlowScope, ConsentScope, DescribeFlowExecutionRecordsRequest,
    DescribeFlowExecutionRecordsResponse, DescribeFlowRequest, DescribeFlowResponse, Digest,
    ErrorClass, EvidenceDigests, ExecutionEvidenceState, ExecutionRecordProjection,
    FailureProjection, FlowDefinitionProjection, ListFlowsRequest, ListFlowsResponse,
    PermissionSnapshot, SecretReference, TimingProjection, TransportProvenance,
};
use crate::provider::{AwsAppFlowProvider, AwsAppFlowTransport};
use crate::{
    CONTRACT_VERSION, MAX_PAGE_SIZE, MAX_PAGES, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID,
    contract_digest,
};

fn serialized<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).expect("bounded AppFlow digest input serializes")
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Reversed,
    Revoked,
}

impl RegistrationStatus {
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationTransitionEvidence {
    pub from: RegistrationStatus,
    pub to: RegistrationStatus,
    pub registration_revision: u64,
    pub transition_digest: Digest,
    pub reversible: bool,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsAppFlowRegistration {
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    service_id: String,
    provider_id: String,
    provider_revision: String,
    provider_digest: Digest,
    permission_digest: Digest,
    consent_digest: Digest,
    scope_digest: Digest,
    secret_reference_digest: Digest,
    flow_digest: Digest,
    execution_digest: Digest,
    flow_revision: u64,
    execution_revision: u64,
    registration_revision: u64,
    status: RegistrationStatus,
    transition_digest: Digest,
}

impl AwsAppFlowRegistration {
    fn new<T: AwsAppFlowTransport>(
        scope: &AwsAppFlowScope,
        secret: &SecretReference,
        consent: &ConsentScope,
        provider: &AwsAppFlowProvider<T>,
    ) -> Result<Self> {
        scope.validate()?;
        consent.validate_at(0)?;
        if consent.digest() != scope.consent_digest() {
            return Err(AwsAppFlowResultError::ScopeMismatch);
        }
        secret.validate(scope)?;
        let permission = PermissionSnapshot::for_layer_one(1);
        permission.validate()?;
        provider.definition().validate()?;
        let mut registration = Self {
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision: provider.definition().api_revision.clone(),
            provider_digest: provider.definition().provider_digest.clone(),
            permission_digest: permission.digest,
            consent_digest: consent.digest().clone(),
            scope_digest: scope.digest(),
            secret_reference_digest: secret.reference_digest().clone(),
            flow_digest: scope.flow_digest(),
            execution_digest: scope.execution_digest(),
            flow_revision: scope.flow_revision(),
            execution_revision: scope.execution_revision(),
            registration_revision: 1,
            status: RegistrationStatus::Active,
            transition_digest: Digest::from_text("uninitialized-registration-transition"),
        };
        registration.transition_digest = registration.compute_transition_digest();
        registration.validate_against(scope, secret, consent, provider)?;
        Ok(registration)
    }

    pub fn status(&self) -> RegistrationStatus {
        self.status
    }

    pub fn is_active(&self) -> bool {
        self.status.is_active()
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn provider_revision(&self) -> &str {
        &self.provider_revision
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        &self.secret_reference_digest
    }

    pub fn flow_digest(&self) -> &Digest {
        &self.flow_digest
    }

    pub fn execution_digest(&self) -> &Digest {
        &self.execution_digest
    }

    pub fn flow_revision(&self) -> u64 {
        self.flow_revision
    }

    pub fn execution_revision(&self) -> u64 {
        self.execution_revision
    }

    pub fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    pub fn registration_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    pub fn validate<T: AwsAppFlowTransport>(
        &self,
        scope: &AwsAppFlowScope,
        secret: &SecretReference,
        consent: &ConsentScope,
        provider: &AwsAppFlowProvider<T>,
    ) -> Result<()> {
        self.validate_against(scope, secret, consent, provider)
    }

    fn validate_against<T: AwsAppFlowTransport>(
        &self,
        scope: &AwsAppFlowScope,
        secret: &SecretReference,
        consent: &ConsentScope,
        provider: &AwsAppFlowProvider<T>,
    ) -> Result<()> {
        scope.validate()?;
        secret.validate(scope)?;
        provider.definition().validate()?;
        let permission = PermissionSnapshot::for_layer_one(1);
        permission.validate()?;
        if consent.digest() != scope.consent_digest()
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.provider_revision != provider.definition().api_revision
            || self.provider_digest != provider.definition().provider_digest
            || self.permission_digest != permission.digest
            || self.consent_digest != *consent.digest()
            || self.scope_digest != scope.digest()
            || self.secret_reference_digest != *secret.reference_digest()
            || self.flow_digest != scope.flow_digest()
            || self.execution_digest != scope.execution_digest()
            || self.flow_revision != scope.flow_revision()
            || self.execution_revision != scope.execution_revision()
            || self.registration_revision == 0
            || self.transition_digest != self.compute_transition_digest()
        {
            return Err(AwsAppFlowResultError::RegistrationInactive);
        }
        Ok(())
    }

    fn compute_transition_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-appflow-registration-transition/v1",
            &[
                ("plugin", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("service", self.service_id.clone()),
                ("provider", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.clone()),
                ("provider_digest", self.provider_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("consent", self.consent_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("secret", self.secret_reference_digest.as_str().to_owned()),
                ("flow", self.flow_digest.as_str().to_owned()),
                ("execution", self.execution_digest.as_str().to_owned()),
                ("flow_revision", self.flow_revision.to_string()),
                ("execution_revision", self.execution_revision.to_string()),
                (
                    "registration_revision",
                    self.registration_revision.to_string(),
                ),
                ("status", serialized(&self.status)),
            ],
        )
    }

    fn transition(&mut self, next: RegistrationStatus) -> Result<RegistrationTransitionEvidence> {
        let from = self.status;
        let valid = matches!(
            (from, next),
            (
                RegistrationStatus::Active,
                RegistrationStatus::Reversed | RegistrationStatus::Revoked
            ) | (
                RegistrationStatus::Reversed,
                RegistrationStatus::Active | RegistrationStatus::Revoked
            )
        );
        if !valid {
            return Err(AwsAppFlowResultError::InvalidRegistrationTransition);
        }
        self.registration_revision = self
            .registration_revision
            .checked_add(1)
            .ok_or(AwsAppFlowResultError::InvalidRegistrationTransition)?;
        self.status = next;
        self.transition_digest = self.compute_transition_digest();
        Ok(RegistrationTransitionEvidence {
            from,
            to: next,
            registration_revision: self.registration_revision,
            transition_digest: self.transition_digest.clone(),
            reversible: matches!(next, RegistrationStatus::Reversed),
        })
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.transition(RegistrationStatus::Reversed)
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.transition(RegistrationStatus::Active)
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.transition(RegistrationStatus::Revoked)
    }
}

impl Serialize for AwsAppFlowRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AwsAppFlowRegistration", 18)?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("serviceId", &self.service_id)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest)?;
        state.serialize_field("consentDigest", &self.consent_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest)?;
        state.serialize_field("flowDigest", &self.flow_digest)?;
        state.serialize_field("executionDigest", &self.execution_digest)?;
        state.serialize_field("flowRevision", &self.flow_revision)?;
        state.serialize_field("executionRevision", &self.execution_revision)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("transitionDigest", &self.transition_digest)?;
        state.end()
    }
}

impl fmt::Debug for AwsAppFlowRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsAppFlowRegistration")
            .field("registration_digest", &self.registration_digest())
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference_digest", &self.secret_reference_digest)
            .field("status", &self.status)
            .field("registration_revision", &self.registration_revision)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadLimits {
    pub max_pages: u16,
    pub max_page_size: u16,
    pub max_response_bytes: u64,
}

impl Default for ReadLimits {
    fn default() -> Self {
        Self {
            max_pages: MAX_PAGES,
            max_page_size: MAX_PAGE_SIZE,
            max_response_bytes: crate::MAX_RESPONSE_BYTES,
        }
    }
}

impl ReadLimits {
    pub fn new(max_pages: u16, max_page_size: u16, max_response_bytes: u64) -> Result<Self> {
        if max_pages == 0
            || max_pages > MAX_PAGES
            || max_page_size == 0
            || max_page_size > MAX_PAGE_SIZE
            || max_response_bytes == 0
            || max_response_bytes > crate::MAX_RESPONSE_BYTES
        {
            return Err(AwsAppFlowResultError::PaginationLimit);
        }
        Ok(Self {
            max_pages,
            max_page_size,
            max_response_bytes,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FlowEvidenceRequest {
    pub limits: ReadLimits,
    pub observed_at_ms: u64,
}

impl FlowEvidenceRequest {
    pub fn new(limits: ReadLimits, observed_at_ms: u64) -> Result<Self> {
        ReadLimits::new(
            limits.max_pages,
            limits.max_page_size,
            limits.max_response_bytes,
        )?;
        Ok(Self {
            limits,
            observed_at_ms,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionProposal {
    ReviewOnly,
    PartialReview,
    RequiresLayer2,
    BlockedEnvironment,
    NotReviewable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetryEvidence {
    pub attempts: u16,
    pub replayed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsAppFlowResultProposal {
    pub state: ExecutionEvidenceState,
    pub decision: DecisionProposal,
    pub flow: Option<FlowDefinitionProjection>,
    pub execution: Option<ExecutionRecordProjection>,
    pub execution_records: Vec<ExecutionRecordProjection>,
    pub list_pages: u16,
    pub record_pages: u16,
    pub list_complete: bool,
    pub records_complete: bool,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub source_digest: Digest,
    pub target_digest: Digest,
    pub timing: Option<TimingProjection>,
    pub failure: Option<FailureProjection>,
    pub retry: RetryEvidence,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence: EvidenceDigests,
    pub adoptable: bool,
    pub kernel_authority: bool,
    pub work_product_adoption: bool,
    pub proposal_digest: Digest,
}

impl AwsAppFlowResultProposal {
    pub fn is_review_only(&self) -> bool {
        matches!(self.decision, DecisionProposal::ReviewOnly)
    }

    pub fn can_be_adopted(&self) -> bool {
        self.adoptable
    }

    pub fn validate(&self, scope: &AwsAppFlowScope) -> Result<()> {
        scope.validate()?;
        if self.scope_digest != scope.digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.adoptable
            || self.kernel_authority
            || self.work_product_adoption
            || self.source_digest != *scope.source_digest()
            || self.target_digest != *scope.target_digest()
            || self.execution_records.iter().any(|record| {
                record.execution_digest != scope.execution_digest()
                    || record.flow_digest != scope.flow_digest()
            })
        {
            return Err(AwsAppFlowResultError::ProposalTampered);
        }
        if let Some(flow) = &self.flow {
            if flow.flow_digest != scope.flow_digest()
                || flow.flow_revision != scope.flow_revision()
            {
                return Err(AwsAppFlowResultError::ProposalTampered);
            }
        }
        if let Some(execution) = &self.execution {
            if execution.execution_digest != scope.execution_digest()
                || execution.execution_revision != scope.execution_revision()
            {
                return Err(AwsAppFlowResultError::ProposalTampered);
            }
            execution.records_processed.validate()?;
            execution.bytes_processed.validate()?;
            execution.bytes_written.validate()?;
            execution.put_failures.validate()?;
        }
        self.evidence.validate()?;
        if self.evidence.scope_digest != self.scope_digest
            || self.evidence.flow_digest != scope.flow_digest()
            || self.evidence.execution_digest != scope.execution_digest()
        {
            return Err(AwsAppFlowResultError::ProposalTampered);
        }
        if self.proposal_digest != self.compute_digest() {
            return Err(AwsAppFlowResultError::ProposalTampered);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-appflow-result-proposal/v1",
            &[
                ("state", serialized(&self.state)),
                ("decision", serialized(&self.decision)),
                ("flow", serialized(&self.flow)),
                ("execution", serialized(&self.execution)),
                ("execution_records", serialized(&self.execution_records)),
                ("list_pages", self.list_pages.to_string()),
                ("record_pages", self.record_pages.to_string()),
                ("list_complete", self.list_complete.to_string()),
                ("records_complete", self.records_complete.to_string()),
                ("provenance", serialized(&self.provenance)),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("first_party", self.first_party.to_string()),
                ("provider_receipt", self.provider_receipt.to_string()),
                ("source", self.source_digest.as_str().to_owned()),
                ("target", self.target_digest.as_str().to_owned()),
                ("timing", serialized(&self.timing)),
                ("failure", serialized(&self.failure)),
                ("retry", serialized(&self.retry)),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("evidence", serialized(&self.evidence)),
                ("adoptable", self.adoptable.to_string()),
                ("kernel_authority", self.kernel_authority.to_string()),
                (
                    "work_product_adoption",
                    self.work_product_adoption.to_string(),
                ),
            ],
        )
    }

    fn finalize(mut self) -> Self {
        self.proposal_digest = self.compute_digest();
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub deterministic: bool,
    pub state: ExecutionEvidenceState,
    pub reason: Option<String>,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub operations: Vec<AppFlowOperation>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub external_writes: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_authority: bool,
    pub forbidden_operations: Vec<String>,
}

pub struct AwsAppFlowResultService<T: AwsAppFlowTransport> {
    scope: AwsAppFlowScope,
    consent: ConsentScope,
    secret: SecretReference,
    provider: AwsAppFlowProvider<T>,
    registration: AwsAppFlowRegistration,
    clock_ms: u64,
}

impl<T: AwsAppFlowTransport> fmt::Debug for AwsAppFlowResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsAppFlowResultService")
            .field("scope", &self.scope)
            .field("registration", &self.registration)
            .field("provider", &self.provider.definition())
            .field("provenance", &self.provider.provenance())
            .finish()
    }
}

impl<T: AwsAppFlowTransport> AwsAppFlowResultService<T> {
    pub fn new(
        scope: AwsAppFlowScope,
        secret: SecretReference,
        consent: ConsentScope,
        provider: AwsAppFlowProvider<T>,
        now_ms: u64,
    ) -> Result<Self> {
        crate::validate_contract()?;
        consent.validate_at(now_ms)?;
        if consent.digest() != scope.consent_digest() {
            return Err(AwsAppFlowResultError::ScopeMismatch);
        }
        let registration = AwsAppFlowRegistration::new(&scope, &secret, &consent, &provider)?;
        Ok(Self {
            scope,
            consent,
            secret,
            provider,
            registration,
            clock_ms: now_ms,
        })
    }

    pub fn scope(&self) -> &AwsAppFlowScope {
        &self.scope
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret
    }

    pub fn registration(&self) -> &AwsAppFlowRegistration {
        &self.registration
    }

    pub fn provider(&self) -> &AwsAppFlowProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsAppFlowProvider<T> {
        &mut self.provider
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            operations: vec![
                AppFlowOperation::ListFlows,
                AppFlowOperation::DescribeFlow,
                AppFlowOperation::DescribeFlowExecutionRecords,
            ],
            read_only: true,
            proposal_only: true,
            recording_only: true,
            external_writes: false,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_authority: false,
            forbidden_operations: vec![
                "StartFlow".to_owned(),
                "StopFlow".to_owned(),
                "DeleteFlow".to_owned(),
                "UpdateFlow".to_owned(),
                "CreateFlow".to_owned(),
                "source.record.read".to_owned(),
                "target.record.read".to_owned(),
            ],
        }
    }

    pub fn default_request(&self, now_ms: u64) -> Result<FlowEvidenceRequest> {
        FlowEvidenceRequest::new(ReadLimits::default(), now_ms)
    }

    pub fn request(
        &self,
        max_pages: u16,
        max_page_size: u16,
        now_ms: u64,
    ) -> Result<FlowEvidenceRequest> {
        FlowEvidenceRequest::new(
            ReadLimits::new(max_pages, max_page_size, crate::MAX_RESPONSE_BYTES)?,
            now_ms,
        )
    }

    /// Read one bounded ListFlows projection and verify its response digest.
    pub fn list_flows(&mut self, request: ListFlowsRequest) -> Result<ListFlowsResponse> {
        self.validate_read_access()?;
        let response = self
            .provider
            .list_flows(&request)
            .map_err(map_transport_error)?;
        if response.provenance != self.provider.provenance() {
            return Err(AwsAppFlowResultError::ResponseTampered);
        }
        response.validate_integrity(&request)?;
        Ok(response)
    }

    /// Read one bounded DescribeFlow projection and verify its response digest.
    pub fn describe_flow(&mut self, request: DescribeFlowRequest) -> Result<DescribeFlowResponse> {
        self.validate_read_access()?;
        let response = self
            .provider
            .describe_flow(&request)
            .map_err(map_transport_error)?;
        if response.provenance != self.provider.provenance() {
            return Err(AwsAppFlowResultError::ResponseTampered);
        }
        response.validate_integrity(&request)?;
        Ok(response)
    }

    /// Read one bounded DescribeFlowExecutionRecords projection and verify its
    /// response digest.
    pub fn describe_flow_execution_records(
        &mut self,
        request: DescribeFlowExecutionRecordsRequest,
    ) -> Result<DescribeFlowExecutionRecordsResponse> {
        self.validate_read_access()?;
        let response = self
            .provider
            .describe_flow_execution_records(&request)
            .map_err(map_transport_error)?;
        if response.provenance != self.provider.provenance() {
            return Err(AwsAppFlowResultError::ResponseTampered);
        }
        response.validate_integrity(&request)?;
        Ok(response)
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn revoke_secret(&mut self) -> Result<()> {
        self.secret.revoke()
    }

    fn validate_ready(&self, request: &FlowEvidenceRequest) -> Result<()> {
        self.validate_read_access_at(request.observed_at_ms)?;
        ReadLimits::new(
            request.limits.max_pages,
            request.limits.max_page_size,
            request.limits.max_response_bytes,
        )?;
        Ok(())
    }

    fn validate_read_access(&self) -> Result<()> {
        self.validate_read_access_at(self.clock_ms)
    }

    fn validate_read_access_at(&self, now_ms: u64) -> Result<()> {
        if !self.registration.is_active() {
            return match self.registration.status() {
                RegistrationStatus::Reversed => Err(AwsAppFlowResultError::RegistrationReversed),
                RegistrationStatus::Revoked => Err(AwsAppFlowResultError::RegistrationRevoked),
                RegistrationStatus::Active => Err(AwsAppFlowResultError::RegistrationInactive),
            };
        }
        if self.secret.is_revoked() {
            return Err(AwsAppFlowResultError::SecretRevoked);
        }
        self.scope.validate()?;
        ReadLimits::new(MAX_PAGES, MAX_PAGE_SIZE, crate::MAX_RESPONSE_BYTES)?;
        self.consent.validate_at(now_ms)?;
        self.registration
            .validate(&self.scope, &self.secret, &self.consent, &self.provider)?;
        Ok(())
    }

    pub fn propose(&mut self, request: FlowEvidenceRequest) -> Result<AwsAppFlowResultProposal> {
        self.validate_ready(&request)?;
        self.clock_ms = request.observed_at_ms;

        let mut list_request =
            ListFlowsRequest::new(&self.scope, request.limits.max_page_size, None)?;
        let mut list_pages: u16 = 0;
        let mut list_complete = false;
        let mut list_items = Vec::new();
        let mut list_digest = Digest::from_text("appflow-list-not-observed");
        let mut list_cursor_digest = None;
        let mut seen_list_cursors = BTreeSet::new();

        loop {
            list_pages = list_pages.saturating_add(1);
            let response = match self.provider.list_flows(&list_request) {
                Ok(response) => response,
                Err(error) => {
                    return Ok(self.failure_proposal(
                        map_transport_failure(error),
                        list_pages,
                        0,
                        list_complete,
                        false,
                        None,
                        None,
                        list_digest,
                        Digest::from_text("appflow-describe-not-observed"),
                        Digest::from_text("appflow-records-not-observed"),
                        list_cursor_digest,
                    ));
                }
            };
            if response.provenance != self.provider.provenance()
                || response.response_bytes > request.limits.max_response_bytes
            {
                return Ok(self.failure_proposal(
                    (
                        ExecutionEvidenceState::Tamper,
                        FailureProjection {
                            class: ErrorClass::Tamper,
                            status_code: None,
                            retry_after_seconds: None,
                        },
                    ),
                    list_pages,
                    0,
                    false,
                    false,
                    None,
                    None,
                    list_digest,
                    Digest::from_text("appflow-describe-not-observed"),
                    Digest::from_text("appflow-records-not-observed"),
                    list_cursor_digest,
                ));
            }
            if response.validate_integrity(&list_request).is_err() {
                return Ok(self.failure_proposal(
                    (
                        ExecutionEvidenceState::Tamper,
                        FailureProjection {
                            class: ErrorClass::Tamper,
                            status_code: None,
                            retry_after_seconds: None,
                        },
                    ),
                    list_pages,
                    0,
                    false,
                    false,
                    None,
                    None,
                    list_digest,
                    Digest::from_text("appflow-describe-not-observed"),
                    Digest::from_text("appflow-records-not-observed"),
                    list_cursor_digest,
                ));
            }
            list_digest =
                Digest::from_serializable(&(&list_digest, &response.declared_digest, list_pages));
            list_items.extend(response.items);
            if let Some(cursor) = response.next_cursor {
                list_cursor_digest = Some(cursor.binding_digest().clone());
                if !seen_list_cursors.insert(cursor.binding_digest().clone()) {
                    return Ok(self.failure_proposal(
                        (
                            ExecutionEvidenceState::Replay,
                            FailureProjection {
                                class: ErrorClass::Replay,
                                status_code: None,
                                retry_after_seconds: None,
                            },
                        ),
                        list_pages,
                        0,
                        false,
                        false,
                        None,
                        None,
                        list_digest,
                        Digest::from_text("appflow-describe-not-observed"),
                        Digest::from_text("appflow-records-not-observed"),
                        list_cursor_digest,
                    ));
                }
                if list_pages >= request.limits.max_pages {
                    break;
                }
                list_request =
                    ListFlowsRequest::new(&self.scope, request.limits.max_page_size, Some(cursor))?;
            } else {
                list_complete = true;
                break;
            }
        }

        let flow_item = list_items
            .into_iter()
            .find(|item| item.flow_digest == self.scope.flow_digest());
        if flow_item.is_none() {
            return Ok(self.failure_proposal(
                (
                    ExecutionEvidenceState::NotFound,
                    FailureProjection {
                        class: ErrorClass::NotFound,
                        status_code: Some(404),
                        retry_after_seconds: None,
                    },
                ),
                list_pages,
                0,
                list_complete,
                false,
                None,
                None,
                list_digest,
                Digest::from_text("appflow-describe-not-observed"),
                Digest::from_text("appflow-records-not-observed"),
                list_cursor_digest,
            ));
        }

        let describe_request = DescribeFlowRequest::new(&self.scope)?;
        let describe_response = match self.provider.describe_flow(&describe_request) {
            Ok(response) => response,
            Err(error) => {
                return Ok(self.failure_proposal(
                    map_transport_failure(error),
                    list_pages,
                    0,
                    list_complete,
                    false,
                    None,
                    None,
                    list_digest,
                    Digest::from_text("appflow-describe-not-observed"),
                    Digest::from_text("appflow-records-not-observed"),
                    list_cursor_digest,
                ));
            }
        };
        if describe_response.provenance != self.provider.provenance()
            || describe_response
                .validate_integrity(&describe_request)
                .is_err()
        {
            return Ok(self.failure_proposal(
                (
                    ExecutionEvidenceState::Tamper,
                    FailureProjection {
                        class: ErrorClass::Tamper,
                        status_code: None,
                        retry_after_seconds: None,
                    },
                ),
                list_pages,
                0,
                list_complete,
                false,
                None,
                None,
                list_digest,
                Digest::from_text("appflow-describe-tampered"),
                Digest::from_text("appflow-records-not-observed"),
                list_cursor_digest,
            ));
        }
        let flow = describe_response.flow.clone();
        let describe_digest = describe_response.declared_digest.clone();

        let mut records_request = DescribeFlowExecutionRecordsRequest::new(
            &self.scope,
            request.limits.max_page_size,
            None,
        )?;
        let mut record_pages: u16 = 0;
        let mut records_complete = false;
        let mut execution_records = Vec::new();
        let mut records_digest = Digest::from_text("appflow-records-not-observed");
        let mut records_cursor_digest = None;
        let mut seen_record_cursors = BTreeSet::new();
        loop {
            record_pages = record_pages.saturating_add(1);
            let response = match self
                .provider
                .describe_flow_execution_records(&records_request)
            {
                Ok(response) => response,
                Err(error) => {
                    return Ok(self.failure_proposal(
                        map_transport_failure(error),
                        list_pages,
                        record_pages,
                        list_complete,
                        records_complete,
                        Some(flow),
                        None,
                        list_digest,
                        describe_digest,
                        records_digest,
                        records_cursor_digest,
                    ));
                }
            };
            if response.provenance != self.provider.provenance()
                || response.response_bytes > request.limits.max_response_bytes
                || response.validate_integrity(&records_request).is_err()
            {
                return Ok(self.failure_proposal(
                    (
                        ExecutionEvidenceState::Tamper,
                        FailureProjection {
                            class: ErrorClass::Tamper,
                            status_code: None,
                            retry_after_seconds: None,
                        },
                    ),
                    list_pages,
                    record_pages,
                    list_complete,
                    false,
                    Some(flow),
                    None,
                    list_digest,
                    describe_digest,
                    records_digest,
                    records_cursor_digest,
                ));
            }
            records_digest = Digest::from_serializable(&(
                &records_digest,
                &response.declared_digest,
                record_pages,
            ));
            execution_records.extend(response.records);
            if let Some(cursor) = response.next_cursor {
                records_cursor_digest = Some(cursor.binding_digest().clone());
                if !seen_record_cursors.insert(cursor.binding_digest().clone()) {
                    return Ok(self.failure_proposal(
                        (
                            ExecutionEvidenceState::Replay,
                            FailureProjection {
                                class: ErrorClass::Replay,
                                status_code: None,
                                retry_after_seconds: None,
                            },
                        ),
                        list_pages,
                        record_pages,
                        list_complete,
                        false,
                        Some(flow),
                        None,
                        list_digest,
                        describe_digest,
                        records_digest,
                        records_cursor_digest,
                    ));
                }
                if record_pages >= request.limits.max_pages {
                    break;
                }
                records_request = DescribeFlowExecutionRecordsRequest::new(
                    &self.scope,
                    request.limits.max_page_size,
                    Some(cursor),
                )?;
            } else {
                records_complete = true;
                break;
            }
        }

        let execution = execution_records
            .iter()
            .find(|record| record.execution_digest == self.scope.execution_digest())
            .cloned();
        if execution.is_none() {
            return Ok(self.failure_proposal(
                (
                    ExecutionEvidenceState::NotFound,
                    FailureProjection {
                        class: ErrorClass::NotFound,
                        status_code: Some(404),
                        retry_after_seconds: None,
                    },
                ),
                list_pages,
                record_pages,
                list_complete,
                records_complete,
                Some(flow),
                None,
                list_digest,
                describe_digest,
                records_digest,
                records_cursor_digest.or(list_cursor_digest),
            ));
        }
        let execution = execution.expect("checked above");
        let counters_truncated = execution.counters_truncated();
        let mut state = execution.status.evidence_state();
        if !list_complete || !records_complete || counters_truncated {
            state = ExecutionEvidenceState::Partial;
        }
        let decision = match state {
            ExecutionEvidenceState::Completed => DecisionProposal::ReviewOnly,
            ExecutionEvidenceState::Partial => DecisionProposal::PartialReview,
            ExecutionEvidenceState::InProgress | ExecutionEvidenceState::Failed => {
                DecisionProposal::RequiresLayer2
            }
            _ => DecisionProposal::NotReviewable,
        };
        let evidence = self.evidence_digests(
            list_digest,
            describe_digest,
            records_digest,
            records_cursor_digest.or(list_cursor_digest),
        );
        Ok(AwsAppFlowResultProposal {
            state,
            decision,
            flow: Some(flow),
            execution: Some(execution.clone()),
            execution_records,
            list_pages,
            record_pages,
            list_complete,
            records_complete,
            provenance: self.provider.provenance(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            source_digest: self.scope.source_digest().clone(),
            target_digest: self.scope.target_digest().clone(),
            timing: Some(execution.timing.clone()),
            failure: None,
            retry: RetryEvidence {
                attempts: 1,
                replayed: false,
            },
            scope_digest: self.scope.digest(),
            registration_digest: self.registration.registration_digest(),
            evidence,
            adoptable: false,
            kernel_authority: false,
            work_product_adoption: false,
            proposal_digest: Digest::from_text("uninitialized-proposal"),
        }
        .finalize())
    }

    pub fn verify(&self, proposal: &AwsAppFlowResultProposal) -> VerificationReport {
        let valid = proposal.validate(&self.scope).is_ok()
            && self.registration.is_active()
            && !self.secret.is_revoked()
            && self
                .registration
                .validate(&self.scope, &self.secret, &self.consent, &self.provider)
                .is_ok();
        VerificationReport {
            valid,
            review_eligible: valid && proposal.state.is_review_eligible(),
            deterministic: valid && proposal.retry.attempts == 1 && !proposal.retry.replayed,
            state: proposal.state,
            reason: if valid {
                None
            } else {
                Some("proposal or registration is invalid".to_owned())
            },
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        }
    }

    pub fn verify_proposal(
        &self,
        proposal: &AwsAppFlowResultProposal,
    ) -> Result<VerificationReport> {
        let report = self.verify(proposal);
        if report.valid {
            Ok(report)
        } else {
            Err(AwsAppFlowResultError::ProposalTampered)
        }
    }

    pub fn consumer(&self) -> Result<MissionAwsAppFlowConsumer> {
        MissionAwsAppFlowConsumer::new(self.scope.clone(), self.registration.registration_digest())
    }

    fn evidence_digests(
        &self,
        list_digest: Digest,
        describe_digest: Digest,
        records_digest: Digest,
        cursor_digest: Option<Digest>,
    ) -> EvidenceDigests {
        let mut evidence = EvidenceDigests {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: contract_digest(),
            provider_digest: self.provider.definition().provider_digest.clone(),
            permission_digest: self.provider.definition().permission_digest.clone(),
            consent_digest: self.consent.digest().clone(),
            scope_digest: self.scope.digest(),
            flow_digest: self.scope.flow_digest(),
            execution_digest: self.scope.execution_digest(),
            list_digest,
            describe_digest,
            records_digest,
            cursor_digest,
            evidence_digest: Digest::from_text("uninitialized-evidence"),
        };
        evidence.evidence_digest = evidence.compute_evidence_digest();
        evidence
    }

    fn failure_proposal(
        &self,
        failure: (ExecutionEvidenceState, FailureProjection),
        list_pages: u16,
        record_pages: u16,
        list_complete: bool,
        records_complete: bool,
        flow: Option<FlowDefinitionProjection>,
        execution: Option<ExecutionRecordProjection>,
        list_digest: Digest,
        describe_digest: Digest,
        records_digest: Digest,
        cursor_digest: Option<Digest>,
    ) -> AwsAppFlowResultProposal {
        let (state, failure_projection) = failure;
        let decision = match state {
            ExecutionEvidenceState::Partial => DecisionProposal::PartialReview,
            ExecutionEvidenceState::ProviderUnknown
            | ExecutionEvidenceState::AccessLoss
            | ExecutionEvidenceState::Throttled
            | ExecutionEvidenceState::Replay
            | ExecutionEvidenceState::Tamper
            | ExecutionEvidenceState::NotFound => DecisionProposal::NotReviewable,
            _ => DecisionProposal::RequiresLayer2,
        };
        let evidence =
            self.evidence_digests(list_digest, describe_digest, records_digest, cursor_digest);
        AwsAppFlowResultProposal {
            state,
            decision,
            timing: execution.as_ref().map(|value| value.timing.clone()),
            execution_records: execution.iter().cloned().collect(),
            flow,
            execution,
            list_pages,
            record_pages,
            list_complete,
            records_complete,
            provenance: self.provider.provenance(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            source_digest: self.scope.source_digest().clone(),
            target_digest: self.scope.target_digest().clone(),
            failure: Some(failure_projection),
            retry: RetryEvidence {
                attempts: 1,
                replayed: matches!(state, ExecutionEvidenceState::Replay),
            },
            scope_digest: self.scope.digest(),
            registration_digest: self.registration.registration_digest(),
            evidence,
            adoptable: false,
            kernel_authority: false,
            work_product_adoption: false,
            proposal_digest: Digest::from_text("uninitialized-proposal"),
        }
        .finalize()
    }
}

fn map_transport_failure(
    error: AwsAppFlowTransportError,
) -> (ExecutionEvidenceState, FailureProjection) {
    let status_code = error.status_code();
    match error {
        AwsAppFlowTransportError::Unauthorized
        | AwsAppFlowTransportError::Forbidden
        | AwsAppFlowTransportError::AccessLost => (
            ExecutionEvidenceState::AccessLoss,
            FailureProjection {
                class: ErrorClass::AccessLoss,
                status_code,
                retry_after_seconds: None,
            },
        ),
        AwsAppFlowTransportError::NotFound => (
            ExecutionEvidenceState::NotFound,
            FailureProjection {
                class: ErrorClass::NotFound,
                status_code,
                retry_after_seconds: None,
            },
        ),
        AwsAppFlowTransportError::RateLimited {
            retry_after_seconds,
        } => (
            ExecutionEvidenceState::Throttled,
            FailureProjection {
                class: ErrorClass::RateLimited,
                status_code,
                retry_after_seconds,
            },
        ),
        AwsAppFlowTransportError::ReplayMismatch | AwsAppFlowTransportError::RecordingExhausted => {
            (
                ExecutionEvidenceState::Replay,
                FailureProjection {
                    class: ErrorClass::Replay,
                    status_code: None,
                    retry_after_seconds: None,
                },
            )
        }
        AwsAppFlowTransportError::BlockedEnv => (
            ExecutionEvidenceState::ProviderUnknown,
            FailureProjection {
                class: ErrorClass::BlockedEnv,
                status_code: None,
                retry_after_seconds: None,
            },
        ),
        AwsAppFlowTransportError::BadRequest => (
            ExecutionEvidenceState::ProviderUnknown,
            FailureProjection {
                class: ErrorClass::Validation,
                status_code,
                retry_after_seconds: None,
            },
        ),
        AwsAppFlowTransportError::Conflict => (
            ExecutionEvidenceState::ProviderUnknown,
            FailureProjection {
                class: ErrorClass::Conflict,
                status_code,
                retry_after_seconds: None,
            },
        ),
        AwsAppFlowTransportError::ServerError { .. } => (
            ExecutionEvidenceState::ProviderUnknown,
            FailureProjection {
                class: ErrorClass::Server,
                status_code,
                retry_after_seconds: None,
            },
        ),
        AwsAppFlowTransportError::Timeout => (
            ExecutionEvidenceState::ProviderUnknown,
            FailureProjection {
                class: ErrorClass::Timeout,
                status_code: None,
                retry_after_seconds: None,
            },
        ),
        AwsAppFlowTransportError::MalformedResponse => (
            ExecutionEvidenceState::ProviderUnknown,
            FailureProjection {
                class: ErrorClass::Malformed,
                status_code: None,
                retry_after_seconds: None,
            },
        ),
    }
}

fn map_transport_error(error: AwsAppFlowTransportError) -> AwsAppFlowResultError {
    match error {
        AwsAppFlowTransportError::Unauthorized
        | AwsAppFlowTransportError::Forbidden
        | AwsAppFlowTransportError::AccessLost => AwsAppFlowResultError::AccessLoss,
        AwsAppFlowTransportError::NotFound => AwsAppFlowResultError::NotFound,
        AwsAppFlowTransportError::RateLimited { .. } => AwsAppFlowResultError::Throttled,
        AwsAppFlowTransportError::ReplayMismatch | AwsAppFlowTransportError::RecordingExhausted => {
            AwsAppFlowResultError::ReplayMismatch
        }
        AwsAppFlowTransportError::BlockedEnv => AwsAppFlowResultError::BlockedEnv,
        AwsAppFlowTransportError::BadRequest
        | AwsAppFlowTransportError::Conflict
        | AwsAppFlowTransportError::ServerError { .. }
        | AwsAppFlowTransportError::Timeout => AwsAppFlowResultError::ProviderUnknown,
        AwsAppFlowTransportError::MalformedResponse => AwsAppFlowResultError::MalformedResponse,
    }
}

#[allow(dead_code)]
fn _all_layer_one_permissions() -> [AppFlowOperation; 3] {
    [
        AppFlowOperation::ListFlows,
        AppFlowOperation::DescribeFlow,
        AppFlowOperation::DescribeFlowExecutionRecords,
    ]
}
