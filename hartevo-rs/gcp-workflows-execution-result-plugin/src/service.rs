//! Service, registration, and proposal/record/verify seams.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    ConsentScope, Digest, EvidenceDigests, EvidenceState, ExecutionSelector,
    GcpWorkflowsExecutionEvidence, GcpWorkflowsScope, MAX_EXECUTIONS, MAX_PAGE_SIZE, MAX_PAGES,
    ModelError, Revision, SecretReference,
};
use crate::provider::{
    ExecutionGetResponse, ExecutionOperation, ExecutionPage, ExecutionReadProposal,
    ExecutionReadRecord, ExecutionReadRequest, ExecutionTransportResponse,
    GCP_WORKFLOWS_EXECUTION_API_VERSION, GCP_WORKFLOWS_EXECUTION_PROVIDER_REVISION,
    GcpWorkflowsProvider, GcpWorkflowsProviderDefinition, GcpWorkflowsProviderError,
    GcpWorkflowsTransport, OpaquePageToken, ProviderProvenance, ResponseStatus,
};
use crate::{
    GCP_WORKFLOWS_EXECUTION_CONTRACT_VERSION, GCP_WORKFLOWS_EXECUTION_PLUGIN_VERSION_TEXT,
    GCP_WORKFLOWS_EXECUTION_PROVIDER_ID, GCP_WORKFLOWS_EXECUTION_PROVIDER_VERSION_TEXT,
    GCP_WORKFLOWS_EXECUTION_SCHEMA_VERSION, GCP_WORKFLOWS_EXECUTION_SERVICE_ID,
};

pub const GCP_WORKFLOWS_EXECUTION_SERVICE_VERSION: &str = "1.0.0";
pub const GCP_WORKFLOWS_EXECUTION_SERVICE_SCHEMA: &str =
    "hartevo.gcp-workflows-execution-result-service/v1";
pub const GCP_WORKFLOWS_EXECUTION_EVIDENCE_POLICY: &str =
    "execution-id-revision-state-timing-step-digests-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcpWorkflowsExecutionOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    ProposeListExecutions,
    ReadListExecutions,
    ProposeGetExecution,
    ReadGetExecution,
    RecordObservation,
    VerifyProposal,
    ConsumeObservation,
}

impl GcpWorkflowsExecutionOperation {
    pub const fn is_read_only(self) -> bool {
        !matches!(self, Self::Register | Self::RevokeRegistration)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpWorkflowsExecutionCapability {
    pub operation: GcpWorkflowsExecutionOperation,
    pub read_only: bool,
    pub native: bool,
    pub connected: bool,
    pub external_write: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpWorkflowsExecutionServiceDefinition {
    pub service_id: String,
    pub service_name: String,
    pub service_version: String,
    pub schema_version: String,
    pub contract_version: String,
    pub read_only: bool,
    pub live_execution: bool,
    pub native: bool,
    pub connected: bool,
    pub external_writes: bool,
    pub capabilities: Vec<GcpWorkflowsExecutionCapability>,
}

impl Default for GcpWorkflowsExecutionServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}

impl GcpWorkflowsExecutionServiceDefinition {
    pub fn new() -> Self {
        let operations = [
            GcpWorkflowsExecutionOperation::DescribeCapabilities,
            GcpWorkflowsExecutionOperation::Register,
            GcpWorkflowsExecutionOperation::RevokeRegistration,
            GcpWorkflowsExecutionOperation::ProposeListExecutions,
            GcpWorkflowsExecutionOperation::ReadListExecutions,
            GcpWorkflowsExecutionOperation::ProposeGetExecution,
            GcpWorkflowsExecutionOperation::ReadGetExecution,
            GcpWorkflowsExecutionOperation::RecordObservation,
            GcpWorkflowsExecutionOperation::VerifyProposal,
            GcpWorkflowsExecutionOperation::ConsumeObservation,
        ];
        Self {
            service_id: GCP_WORKFLOWS_EXECUTION_SERVICE_ID.to_owned(),
            service_name: crate::GCP_WORKFLOWS_EXECUTION_SERVICE_NAME.to_owned(),
            service_version: GCP_WORKFLOWS_EXECUTION_SERVICE_VERSION.to_owned(),
            schema_version: GCP_WORKFLOWS_EXECUTION_SERVICE_SCHEMA.to_owned(),
            contract_version: GCP_WORKFLOWS_EXECUTION_CONTRACT_VERSION.to_owned(),
            read_only: true,
            live_execution: false,
            native: false,
            connected: false,
            external_writes: false,
            capabilities: operations
                .into_iter()
                .map(|operation| GcpWorkflowsExecutionCapability {
                    read_only: operation.is_read_only(),
                    operation,
                    native: false,
                    connected: false,
                    external_write: false,
                })
                .collect(),
        }
    }

    pub fn describe_capabilities(&self) -> Vec<GcpWorkflowsExecutionCapability> {
        self.capabilities.clone()
    }

    pub fn validate(&self) -> Result<(), GcpWorkflowsExecutionServiceError> {
        if self.service_id != GCP_WORKFLOWS_EXECUTION_SERVICE_ID
            || self.service_name != crate::GCP_WORKFLOWS_EXECUTION_SERVICE_NAME
            || self.service_version != GCP_WORKFLOWS_EXECUTION_SERVICE_VERSION
            || self.schema_version != GCP_WORKFLOWS_EXECUTION_SERVICE_SCHEMA
            || self.contract_version != GCP_WORKFLOWS_EXECUTION_CONTRACT_VERSION
            || !self.read_only
            || self.live_execution
            || self.native
            || self.connected
            || self.external_writes
            || self.capabilities.iter().any(|capability| {
                capability.native || capability.connected || capability.external_write
            })
        {
            return Err(GcpWorkflowsExecutionServiceError::ContractDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RegistrationError {
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is not revoked")]
    NotRevoked,
    #[error("registration revision overflowed")]
    RevisionOverflow,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpWorkflowsRegistration {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub execution_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl GcpWorkflowsRegistration {
    pub fn new(
        scope: &GcpWorkflowsScope,
        secret_reference: &SecretReference,
        provider_definition: &GcpWorkflowsProviderDefinition,
    ) -> Result<Self, GcpWorkflowsExecutionServiceError> {
        if secret_reference.is_revoked()
            || secret_reference
                .scope_digest()
                .is_some_and(|digest| digest != &scope.scope_digest())
        {
            return Err(GcpWorkflowsExecutionServiceError::ScopeMismatch);
        }
        let mut registration = Self {
            schema_version: GCP_WORKFLOWS_EXECUTION_SCHEMA_VERSION.to_owned(),
            contract_version: GCP_WORKFLOWS_EXECUTION_CONTRACT_VERSION.to_owned(),
            plugin_version: GCP_WORKFLOWS_EXECUTION_PLUGIN_VERSION_TEXT.to_owned(),
            version_digest: crate::plugin_version_digest(),
            contract_digest: crate::contract_digest(),
            provider_id: provider_definition.provider_id.clone(),
            provider_version: provider_definition.provider_version.clone(),
            provider_revision: provider_definition.provider_revision.clone(),
            provider_digest: provider_definition.provider_digest(),
            permission_digest: scope.permission_digest(),
            scope_digest: scope.scope_digest(),
            execution_digest: scope.execution_digest(),
            evidence_digest: Digest::from_text(GCP_WORKFLOWS_EXECUTION_EVIDENCE_POLICY),
            secret_reference_digest: secret_reference.reference_digest().clone(),
            credential_revision: secret_reference.revision(),
            registration_revision: Revision::new(1)?,
            state: RegistrationState::Active,
            registration_digest: Digest::from_text("placeholder"),
        };
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    fn compute_digest(&self) -> Digest {
        #[derive(Serialize)]
        struct RegistrationDigestInput<'a> {
            schema_version: &'a str,
            contract_version: &'a str,
            plugin_version: &'a str,
            version_digest: &'a Digest,
            contract_digest: &'a Digest,
            provider_id: &'a str,
            provider_version: &'a str,
            provider_revision: &'a str,
            provider_digest: &'a Digest,
            permission_digest: &'a Digest,
            scope_digest: &'a Digest,
            execution_digest: &'a Digest,
            evidence_digest: &'a Digest,
            secret_reference_digest: &'a Digest,
            credential_revision: Revision,
            registration_revision: Revision,
            state: RegistrationState,
        }
        Digest::from_serializable(&RegistrationDigestInput {
            schema_version: &self.schema_version,
            contract_version: &self.contract_version,
            plugin_version: &self.plugin_version,
            version_digest: &self.version_digest,
            contract_digest: &self.contract_digest,
            provider_id: &self.provider_id,
            provider_version: &self.provider_version,
            provider_revision: &self.provider_revision,
            provider_digest: &self.provider_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            execution_digest: &self.execution_digest,
            evidence_digest: &self.evidence_digest,
            secret_reference_digest: &self.secret_reference_digest,
            credential_revision: self.credential_revision,
            registration_revision: self.registration_revision,
            state: self.state,
        })
    }

    pub fn verify_digest(&self) -> bool {
        self.schema_version == GCP_WORKFLOWS_EXECUTION_SCHEMA_VERSION
            && self.contract_version == GCP_WORKFLOWS_EXECUTION_CONTRACT_VERSION
            && self.plugin_version == GCP_WORKFLOWS_EXECUTION_PLUGIN_VERSION_TEXT
            && self.version_digest == crate::plugin_version_digest()
            && self.contract_digest == crate::contract_digest()
            && self.provider_id == GCP_WORKFLOWS_EXECUTION_PROVIDER_ID
            && self.provider_version == GCP_WORKFLOWS_EXECUTION_PROVIDER_VERSION_TEXT
            && self.provider_revision == GCP_WORKFLOWS_EXECUTION_PROVIDER_REVISION
            && self.evidence_digest == evidence_policy_digest()
            && self.registration_digest == self.compute_digest()
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn revoke(&mut self) -> Result<(), RegistrationError> {
        if !self.is_active() {
            return Err(RegistrationError::AlreadyRevoked);
        }
        self.state = RegistrationState::Revoked;
        self.registration_revision = self
            .registration_revision
            .next()
            .map_err(|_| RegistrationError::RevisionOverflow)?;
        self.registration_digest = self.compute_digest();
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), RegistrationError> {
        if self.is_active() {
            return Err(RegistrationError::NotRevoked);
        }
        self.state = RegistrationState::Active;
        self.registration_revision = self
            .registration_revision
            .next()
            .map_err(|_| RegistrationError::RevisionOverflow)?;
        self.registration_digest = self.compute_digest();
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadBounds {
    pub max_pages: u16,
    pub page_size: u16,
    pub max_executions: u16,
}

impl ReadBounds {
    pub fn new(max_pages: u16, page_size: u16, max_executions: u16) -> Result<Self, ModelError> {
        if !(1..=MAX_PAGES).contains(&max_pages)
            || !(1..=MAX_PAGE_SIZE).contains(&page_size)
            || !(1..=u16::try_from(MAX_EXECUTIONS).expect("execution bound fits u16"))
                .contains(&max_executions)
        {
            return Err(ModelError::InvalidIdentifier {
                field: "execution read bounds",
            });
        }
        Ok(Self {
            max_pages,
            page_size,
            max_executions,
        })
    }
}

impl Default for ReadBounds {
    fn default() -> Self {
        Self {
            max_pages: MAX_PAGES,
            page_size: MAX_PAGE_SIZE,
            max_executions: u16::try_from(MAX_EXECUTIONS).expect("execution bound fits u16"),
        }
    }
}

pub type GcpWorkflowsExecutionBounds = ReadBounds;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GcpWorkflowsExecutionServiceError {
    #[error("GCP Workflows registration is revoked")]
    RegistrationRevoked,
    #[error("GCP OAuth or service-account SecretReference is revoked")]
    SecretRevoked,
    #[error("GCP Workflows scope or SecretReference binding does not match")]
    ScopeMismatch,
    #[error("GCP Workflows contract or provider definition drifted")]
    ContractDrift,
    #[error("GCP Workflows registration is stale or tampered")]
    RegistrationTampered,
    #[error("GCP Workflows proposal is stale or tampered")]
    ProposalTampered,
    #[error("GCP Workflows record is stale or tampered")]
    RecordTampered,
    #[error("GCP Workflows execution is outside the exact registered scope")]
    ExecutionScopeMismatch,
    #[error("GCP Workflows cursor binding changed")]
    CursorMismatch,
    #[error("GCP Workflows response is partial or truncated")]
    PartialResponse,
    #[error("GCP Workflows provider error: {0}")]
    Provider(#[from] GcpWorkflowsProviderError),
    #[error("GCP Workflows model error: {0}")]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionRead {
    pub record: ExecutionReadRecord,
    pub next_page_token: Option<OpaquePageToken>,
}

pub type GcpWorkflowsExecutionRead = ExecutionRead;

pub struct GcpWorkflowsExecutionService<T>
where
    T: GcpWorkflowsTransport,
{
    scope: GcpWorkflowsScope,
    secret_reference: SecretReference,
    provider: GcpWorkflowsProvider<T>,
    definition: GcpWorkflowsExecutionServiceDefinition,
    registration: GcpWorkflowsRegistration,
    bounds: ReadBounds,
}

impl<T> fmt::Debug for GcpWorkflowsExecutionService<T>
where
    T: GcpWorkflowsTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpWorkflowsExecutionService")
            .field("scope_digest", &self.scope.scope_digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("bounds", &self.bounds)
            .finish_non_exhaustive()
    }
}

impl<T> GcpWorkflowsExecutionService<T>
where
    T: GcpWorkflowsTransport,
{
    pub fn new(
        scope: GcpWorkflowsScope,
        secret_reference: SecretReference,
        provider: GcpWorkflowsProvider<T>,
    ) -> Result<Self, GcpWorkflowsExecutionServiceError> {
        Self::with_bounds(scope, secret_reference, provider, ReadBounds::default())
    }

    pub fn with_bounds(
        scope: GcpWorkflowsScope,
        secret_reference: SecretReference,
        provider: GcpWorkflowsProvider<T>,
        bounds: ReadBounds,
    ) -> Result<Self, GcpWorkflowsExecutionServiceError> {
        scope.validate()?;
        if secret_reference.is_revoked() {
            return Err(GcpWorkflowsExecutionServiceError::SecretRevoked);
        }
        if secret_reference
            .scope_digest()
            .is_some_and(|digest| digest != &scope.scope_digest())
        {
            return Err(GcpWorkflowsExecutionServiceError::ScopeMismatch);
        }
        let definition = GcpWorkflowsExecutionServiceDefinition::new();
        definition.validate()?;
        let provider_definition = provider.definition();
        if provider_definition.validate().is_err()
            || !provider_definition.is_layer1()
            || provider.provenance() != provider_definition.provenance
            || provider_definition.provider_id != GCP_WORKFLOWS_EXECUTION_PROVIDER_ID
            || provider_definition.api_version != GCP_WORKFLOWS_EXECUTION_API_VERSION
            || provider_definition.provider_revision != GCP_WORKFLOWS_EXECUTION_PROVIDER_REVISION
            || !provider_definition.read_only
            || provider_definition.live_execution
            || provider_definition.native
            || provider_definition.connected
            || provider_definition.first_party
            || provider.is_native()
            || provider.is_connected()
        {
            return Err(GcpWorkflowsExecutionServiceError::ContractDrift);
        }
        let registration =
            GcpWorkflowsRegistration::new(&scope, &secret_reference, provider_definition)?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            definition,
            registration,
            bounds,
        })
    }

    pub fn definition(&self) -> &GcpWorkflowsExecutionServiceDefinition {
        &self.definition
    }

    pub fn scope(&self) -> &GcpWorkflowsScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &GcpWorkflowsProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut GcpWorkflowsProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &GcpWorkflowsRegistration {
        &self.registration
    }

    pub const fn bounds(&self) -> ReadBounds {
        self.bounds
    }

    pub const fn is_registered(&self) -> bool {
        self.registration.is_active()
    }

    pub fn provider_provenance(&self) -> ProviderProvenance {
        self.provider.provenance()
    }

    pub fn register(&mut self) -> Result<(), GcpWorkflowsExecutionServiceError> {
        if self.secret_reference.is_revoked() {
            return Err(GcpWorkflowsExecutionServiceError::SecretRevoked);
        }
        if !self.registration.is_active() {
            self.registration
                .restore()
                .map_err(|_| GcpWorkflowsExecutionServiceError::RegistrationRevoked)?;
        }
        Ok(())
    }

    pub fn revoke_registration(&mut self) -> Result<(), GcpWorkflowsExecutionServiceError> {
        self.registration
            .revoke()
            .map_err(|_| GcpWorkflowsExecutionServiceError::RegistrationRevoked)
    }

    pub fn revoke_secret_reference(&mut self) -> Result<(), GcpWorkflowsExecutionServiceError> {
        self.secret_reference.revoke()?;
        if self.registration.is_active() {
            self.registration
                .revoke()
                .map_err(|_| GcpWorkflowsExecutionServiceError::RegistrationRevoked)?;
        }
        Ok(())
    }

    fn validate_active(&self) -> Result<(), GcpWorkflowsExecutionServiceError> {
        if !self.registration.is_active() {
            return Err(GcpWorkflowsExecutionServiceError::RegistrationRevoked);
        }
        if self.secret_reference.is_revoked() {
            return Err(GcpWorkflowsExecutionServiceError::SecretRevoked);
        }
        if !self.registration.verify_digest()
            || self.registration.scope_digest != self.scope.scope_digest()
            || self.registration.permission_digest != self.scope.permission_digest()
            || self.registration.execution_digest != self.scope.execution_digest()
            || self.registration.secret_reference_digest
                != *self.secret_reference.reference_digest()
        {
            return Err(GcpWorkflowsExecutionServiceError::RegistrationTampered);
        }
        Ok(())
    }

    pub fn propose_list_executions(
        &self,
        page_number: u16,
        page_token: Option<OpaquePageToken>,
    ) -> Result<ExecutionReadProposal, GcpWorkflowsExecutionServiceError> {
        self.validate_active()?;
        let request = ExecutionReadRequest::list(
            &self.scope,
            self.provider.provider_digest(),
            page_number,
            self.bounds.page_size,
            page_token,
        )?;
        Ok(ExecutionReadProposal::new(
            self.registration.registration_digest.clone(),
            self.registration.registration_revision,
            self.provider.provider_digest(),
            self.provider.definition().provider_revision.clone(),
            request,
        ))
    }

    pub fn propose_get_execution(
        &self,
    ) -> Result<ExecutionReadProposal, GcpWorkflowsExecutionServiceError> {
        self.validate_active()?;
        let request = ExecutionReadRequest::get(&self.scope, self.provider.provider_digest())?;
        Ok(ExecutionReadProposal::new(
            self.registration.registration_digest.clone(),
            self.registration.registration_revision,
            self.provider.provider_digest(),
            self.provider.definition().provider_revision.clone(),
            request,
        ))
    }

    pub fn compile_proposal(
        &self,
    ) -> Result<ExecutionReadProposal, GcpWorkflowsExecutionServiceError> {
        match self.scope.execution {
            ExecutionSelector::Any => self.propose_list_executions(1, None),
            ExecutionSelector::Exact { .. } => self.propose_get_execution(),
        }
    }

    pub fn read_list_executions(
        &mut self,
        proposal: &ExecutionReadProposal,
    ) -> Result<ExecutionRead, GcpWorkflowsExecutionServiceError> {
        self.validate_proposal(proposal, ExecutionOperation::ListExecutions)?;
        let page = self.provider.list(proposal.request())?;
        let next_page_token = page.next_page_token().cloned();
        let record = self.record_list_executions(proposal, &page)?;
        self.verify_proposal(proposal, &record)?;
        Ok(ExecutionRead {
            record,
            next_page_token,
        })
    }

    pub fn read_get_execution(
        &mut self,
        proposal: &ExecutionReadProposal,
    ) -> Result<ExecutionRead, GcpWorkflowsExecutionServiceError> {
        self.validate_proposal(proposal, ExecutionOperation::GetExecution)?;
        let response = self.provider.get(proposal.request())?;
        let record = self.record_get_execution(proposal, &response)?;
        self.verify_proposal(proposal, &record)?;
        Ok(ExecutionRead {
            record,
            next_page_token: None,
        })
    }

    pub fn read(
        &mut self,
        proposal: &ExecutionReadProposal,
    ) -> Result<ExecutionRead, GcpWorkflowsExecutionServiceError> {
        match proposal.operation {
            ExecutionOperation::ListExecutions => self.read_list_executions(proposal),
            ExecutionOperation::GetExecution => self.read_get_execution(proposal),
        }
    }

    pub fn record_list_executions(
        &self,
        proposal: &ExecutionReadProposal,
        page: &ExecutionPage,
    ) -> Result<ExecutionReadRecord, GcpWorkflowsExecutionServiceError> {
        self.validate_proposal(proposal, ExecutionOperation::ListExecutions)?;
        if !page.verify_digest(proposal.request()) {
            return Err(GcpWorkflowsExecutionServiceError::RecordTampered);
        }
        Ok(self
            .provider
            .record_list(proposal, page, &self.scope, &self.secret_reference)?)
    }

    pub fn record_get_execution(
        &self,
        proposal: &ExecutionReadProposal,
        response: &ExecutionGetResponse,
    ) -> Result<ExecutionReadRecord, GcpWorkflowsExecutionServiceError> {
        self.validate_proposal(proposal, ExecutionOperation::GetExecution)?;
        if !response.verify_digest(proposal.request()) {
            return Err(GcpWorkflowsExecutionServiceError::RecordTampered);
        }
        Ok(self
            .provider
            .record_get(proposal, response, &self.scope, &self.secret_reference)?)
    }

    pub fn record_observation(
        &self,
        proposal: &ExecutionReadProposal,
        response: &ExecutionTransportResponse,
    ) -> Result<ExecutionReadRecord, GcpWorkflowsExecutionServiceError> {
        match response {
            ExecutionTransportResponse::List(page) => self.record_list_executions(proposal, page),
            ExecutionTransportResponse::Get(response) => {
                self.record_get_execution(proposal, response)
            }
        }
    }

    pub fn verify_proposal(
        &self,
        proposal: &ExecutionReadProposal,
        record: &ExecutionReadRecord,
    ) -> Result<(), GcpWorkflowsExecutionServiceError> {
        self.validate_proposal(proposal, proposal.operation)?;
        self.provider.verify(proposal, record)?;
        if record.scope_digest != self.scope.scope_digest()
            || record.permission_digest != self.scope.permission_digest()
            || record.secret_reference_digest != *self.secret_reference.reference_digest()
            || record
                .executions
                .iter()
                .any(|execution| !execution.matches_scope(&self.scope))
            || record
                .execution
                .as_ref()
                .is_some_and(|execution| !execution.matches_scope(&self.scope))
        {
            return Err(GcpWorkflowsExecutionServiceError::RecordTampered);
        }
        Ok(())
    }

    pub fn verify(
        &self,
        proposal: &ExecutionReadProposal,
        record: &ExecutionReadRecord,
    ) -> Result<(), GcpWorkflowsExecutionServiceError> {
        self.verify_proposal(proposal, record)
    }

    fn validate_proposal(
        &self,
        proposal: &ExecutionReadProposal,
        expected_operation: ExecutionOperation,
    ) -> Result<(), GcpWorkflowsExecutionServiceError> {
        self.validate_active()?;
        if !proposal.verify_digest()
            || proposal.operation != expected_operation
            || proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.registration_revision
            || proposal.provider_digest != self.registration.provider_digest
            || proposal.provider_revision != self.registration.provider_revision
            || proposal.request().scope_digest != self.scope.scope_digest()
            || proposal.request().permission_digest != self.scope.permission_digest()
            || !proposal
                .request()
                .verify_digest(&self.registration.provider_digest)
        {
            return Err(GcpWorkflowsExecutionServiceError::ProposalTampered);
        }
        if expected_operation.is_get() != proposal.request().execution_id.is_some()
            || expected_operation.is_list() != proposal.request().execution_id.is_none()
        {
            return Err(GcpWorkflowsExecutionServiceError::ExecutionScopeMismatch);
        }
        Ok(())
    }

    pub fn read_list_bounded(
        &mut self,
    ) -> Result<GcpWorkflowsExecutionEvidence, GcpWorkflowsExecutionServiceError> {
        self.validate_active()?;
        let mut page_number = 1_u16;
        let mut page_token = None;
        let mut records = Vec::new();
        let mut state = EvidenceState::Complete;
        let mut failure_digest = None;
        loop {
            if page_number > self.bounds.max_pages {
                state = EvidenceState::Partial;
                break;
            }
            let proposal = self.propose_list_executions(page_number, page_token.clone())?;
            match self.read_list_executions(&proposal) {
                Ok(read) => {
                    if read.record.response_status != ResponseStatus::Complete {
                        state = EvidenceState::Partial;
                    }
                    page_token = read.next_page_token;
                    records.push(read.record);
                    if page_token.is_none() {
                        break;
                    }
                    page_number = page_number.saturating_add(1);
                }
                Err(GcpWorkflowsExecutionServiceError::Provider(error)) => {
                    state = error.evidence_state();
                    failure_digest = Some(error.diagnostic_digest());
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        self.build_evidence(&records, state, failure_digest)
    }

    pub fn read_get_bounded(
        &mut self,
    ) -> Result<GcpWorkflowsExecutionEvidence, GcpWorkflowsExecutionServiceError> {
        let proposal = self.propose_get_execution()?;
        match self.read_get_execution(&proposal) {
            Ok(read) => self.build_evidence(&[read.record], EvidenceState::Complete, None),
            Err(GcpWorkflowsExecutionServiceError::Provider(error)) => {
                self.build_evidence(&[], error.evidence_state(), Some(error.diagnostic_digest()))
            }
            Err(error) => Err(error),
        }
    }

    pub fn read_bounded(
        &mut self,
    ) -> Result<GcpWorkflowsExecutionEvidence, GcpWorkflowsExecutionServiceError> {
        match self.scope.execution {
            ExecutionSelector::Any => self.read_list_bounded(),
            ExecutionSelector::Exact { .. } => self.read_get_bounded(),
        }
    }

    pub fn evidence_from_record(
        &self,
        record: &ExecutionReadRecord,
    ) -> Result<GcpWorkflowsExecutionEvidence, GcpWorkflowsExecutionServiceError> {
        self.validate_active()?;
        self.verify_record_scope(record)?;
        self.build_evidence(std::slice::from_ref(record), EvidenceState::Complete, None)
    }

    fn build_evidence(
        &self,
        records: &[ExecutionReadRecord],
        mut state: EvidenceState,
        failure_digest: Option<Digest>,
    ) -> Result<GcpWorkflowsExecutionEvidence, GcpWorkflowsExecutionServiceError> {
        let mut executions: BTreeMap<crate::ExecutionId, crate::ExecutionSummary> = BTreeMap::new();
        let mut duplicate_execution_count = 0_u16;
        let mut record_digests = Vec::new();
        let mut cursor_chain = Vec::new();
        for record in records {
            if !record.verify_integrity() {
                return Err(GcpWorkflowsExecutionServiceError::RecordTampered);
            }
            self.verify_record_scope(record)?;
            record_digests.push(record.record_digest.clone());
            cursor_chain.push(record.next_page_token_digest.clone());
            let observed = record.executions.iter().chain(record.execution.iter());
            for execution in observed {
                if let Some(previous) = executions.get(&execution.id) {
                    if previous.execution_digest != execution.execution_digest {
                        return Err(GcpWorkflowsExecutionServiceError::RecordTampered);
                    }
                    duplicate_execution_count = duplicate_execution_count.saturating_add(1);
                } else {
                    executions.insert(execution.id.clone(), execution.clone());
                }
            }
            if record.response_status != ResponseStatus::Complete {
                state = EvidenceState::Partial;
            }
        }
        let mut executions: Vec<_> = executions.into_values().collect();
        executions.sort_by(|left, right| {
            right
                .timing
                .start_time
                .cmp(&left.timing.start_time)
                .then_with(|| left.id.cmp(&right.id))
        });
        let max_executions = usize::from(self.bounds.max_executions);
        if executions.len() > max_executions {
            executions.truncate(max_executions);
            state = EvidenceState::Partial;
        }
        let mut digests = EvidenceDigests::new(
            self.registration.provider_digest.clone(),
            self.scope.permission_digest(),
            self.scope.scope_digest(),
        );
        let mut evidence = GcpWorkflowsExecutionEvidence {
            schema_version: GCP_WORKFLOWS_EXECUTION_SCHEMA_VERSION.to_owned(),
            contract_version: GCP_WORKFLOWS_EXECUTION_CONTRACT_VERSION.to_owned(),
            plugin_version: GCP_WORKFLOWS_EXECUTION_PLUGIN_VERSION_TEXT.to_owned(),
            state,
            scope_digest: self.scope.scope_digest(),
            permission_digest: self.scope.permission_digest(),
            registration_digest: self.registration.registration_digest.clone(),
            provider_digest: self.registration.provider_digest.clone(),
            provider_revision: self.registration.provider_revision.clone(),
            page_count: u16::try_from(records.len()).unwrap_or(u16::MAX),
            execution_count: u16::try_from(executions.len()).unwrap_or(u16::MAX),
            duplicate_execution_count,
            executions,
            record_digests,
            cursor_chain_digest: Digest::from_serializable(&cursor_chain),
            failure_digest,
            native: false,
            connected: false,
            outcome_authority: false,
            work_product_adoption: false,
            digests: digests.clone(),
        };
        digests.evidence_digest = evidence.compute_evidence_digest();
        evidence.digests = digests;
        Ok(evidence)
    }

    fn verify_record_scope(
        &self,
        record: &ExecutionReadRecord,
    ) -> Result<(), GcpWorkflowsExecutionServiceError> {
        if record.registration_digest != self.registration.registration_digest
            || record.registration_revision != self.registration.registration_revision
            || record.provider_digest != self.registration.provider_digest
            || record.provider_revision != self.registration.provider_revision
            || record.scope_digest != self.scope.scope_digest()
            || record.permission_digest != self.scope.permission_digest()
            || record.secret_reference_digest != *self.secret_reference.reference_digest()
        {
            return Err(GcpWorkflowsExecutionServiceError::RecordTampered);
        }
        Ok(())
    }
}

pub type GcpWorkflowsService<T> = GcpWorkflowsExecutionService<T>;
pub type GcpWorkflowsExecutionRegistration = GcpWorkflowsRegistration;
pub type GcpWorkflowsServiceDefinition = GcpWorkflowsExecutionServiceDefinition;

pub fn contract_json_is_embedded() -> bool {
    !crate::GCP_WORKFLOWS_EXECUTION_CONTRACT_JSON
        .trim()
        .is_empty()
        && crate::contract_digest().len() == 64
}

pub fn provider_revision() -> &'static str {
    GCP_WORKFLOWS_EXECUTION_PROVIDER_REVISION
}

pub fn consumer_id() -> &'static str {
    crate::MISSION_GCP_WORKFLOW_CONSUMER_ID
}

pub fn service_id() -> &'static str {
    GCP_WORKFLOWS_EXECUTION_SERVICE_ID
}

pub fn provider_id() -> &'static str {
    GCP_WORKFLOWS_EXECUTION_PROVIDER_ID
}

pub fn consent_digest(consent: &ConsentScope) -> Digest {
    consent.digest()
}

pub fn evidence_policy_digest() -> Digest {
    Digest::from_text(GCP_WORKFLOWS_EXECUTION_EVIDENCE_POLICY)
}

pub fn provider_version_digest() -> Digest {
    Digest::from_text(GCP_WORKFLOWS_EXECUTION_PROVIDER_VERSION_TEXT)
}

pub fn api_version_digest() -> Digest {
    Digest::from_text(GCP_WORKFLOWS_EXECUTION_API_VERSION)
}

pub fn revision_digest(revision: &str) -> Digest {
    Digest::from_text(revision)
}
