//! Typed proposal/record/verify service for Application Signals evidence.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AWS_APPLICATION_SIGNALS_API_VERSION, AWS_APPLICATION_SIGNALS_PLUGIN_VERSION_TEXT,
    AWS_APPLICATION_SIGNALS_SERVICE_ID, contract_digest,
    model::{
        AwsApplicationSignalsScope, Digest, EvidenceDigests, EvidenceStatus, MissionBinding,
        PluginVersion, ReadOperation, RedactionSummary, Registration, RegistrationState,
        SecretReference, ServiceDetail, ServiceName, ServiceSummary, SloDetail, SloId, SloSummary,
        TimeWindow, digest_serializable,
    },
    provider::{
        AwsApplicationSignalsProvider, AwsApplicationSignalsProviderDefinition,
        AwsApplicationSignalsReadRecord, AwsApplicationSignalsReadRequest,
        AwsApplicationSignalsRecordPage, BlockedEnvAwsApplicationSignalsTransport, ProviderError,
        ProviderProvenance,
    },
    validate_contract_document,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ContractDocumentError {
    #[error("contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("contract is invalid: {0}")]
    Invalid(String),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceDefinition {
    pub id: String,
    pub version: String,
    pub api_version: String,
    pub operation: String,
    pub read_only: bool,
    pub native: bool,
    pub connected: bool,
    pub contract_digest: Digest,
    pub version_digest: Digest,
    pub api_digest: Digest,
}

impl ServiceDefinition {
    #[must_use]
    pub fn new() -> Self {
        Self {
            id: AWS_APPLICATION_SIGNALS_SERVICE_ID.to_owned(),
            version: AWS_APPLICATION_SIGNALS_PLUGIN_VERSION_TEXT.to_owned(),
            api_version: AWS_APPLICATION_SIGNALS_API_VERSION.to_owned(),
            operation: "bounded_service_and_slo_list_get_evidence".to_owned(),
            read_only: true,
            native: false,
            connected: false,
            contract_digest: contract_digest(),
            version_digest: Digest::from_text(AWS_APPLICATION_SIGNALS_PLUGIN_VERSION_TEXT),
            api_digest: Digest::from_text(AWS_APPLICATION_SIGNALS_API_VERSION),
        }
    }

    pub fn validate(&self) -> Result<(), ContractDocumentError> {
        validate_contract_document()?;
        if self != &Self::new() {
            return Err(ContractDocumentError::Invalid(
                "service definition drifted".to_owned(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub const fn read_only(&self) -> bool {
        self.read_only
    }

    #[must_use]
    pub const fn native_connected(&self) -> bool {
        self.native || self.connected
    }
}

impl Default for ServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ServiceError {
    #[error(transparent)]
    Model(#[from] crate::model::ModelError),
    #[error(transparent)]
    Provider(ProviderError),
    #[error(transparent)]
    Contract(#[from] ContractDocumentError),
    #[error("the Application Signals registration is missing")]
    RegistrationMissing,
    #[error("the Application Signals registration has been revoked")]
    RegistrationRevoked,
    #[error("the Application Signals SigV4 SecretReference has been revoked")]
    SecretRevoked,
    #[error("the Application Signals scope does not match the request")]
    ScopeMismatch,
    #[error("the Application Signals permission fence does not permit this operation")]
    PermissionMismatch,
    #[error("the proposal digest or fence was tampered")]
    ProposalTampered,
    #[error("the provider record or response digest was tampered")]
    RecordTampered,
    #[error("the normalized Application Signals evidence was tampered")]
    EvidenceTampered,
    #[error("the redacted receipt was tampered")]
    ReceiptTampered,
    #[error("Layer-1 cannot claim native or connected evidence")]
    NativeClaim,
}

impl From<ProviderError> for ServiceError {
    fn from(value: ProviderError) -> Self {
        Self::Provider(value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityBoundary {
    pub read_only: bool,
    pub connected: bool,
    pub native_provider: bool,
    pub live_credential_resolution: bool,
    pub durable_request_receipt: bool,
    pub durable_cost_receipt: bool,
    pub independent_closed_window_readback: bool,
    pub telemetry_export: bool,
    pub slo_writes: bool,
    pub metric_writes: bool,
    pub alert_paging: bool,
    pub causal_claim: bool,
    pub outcome_authority: bool,
    pub work_product_adoption: bool,
}

impl AuthorityBoundary {
    #[must_use]
    pub const fn layer1() -> Self {
        Self {
            read_only: true,
            connected: false,
            native_provider: false,
            live_credential_resolution: false,
            durable_request_receipt: false,
            durable_cost_receipt: false,
            independent_closed_window_readback: false,
            telemetry_export: false,
            slo_writes: false,
            metric_writes: false,
            alert_paging: false,
            causal_claim: false,
            outcome_authority: false,
            work_product_adoption: false,
        }
    }

    pub fn validate(&self) -> Result<(), ServiceError> {
        if !self.read_only
            || self.connected
            || self.native_provider
            || self.live_credential_resolution
            || self.durable_request_receipt
            || self.durable_cost_receipt
            || self.independent_closed_window_readback
            || self.telemetry_export
            || self.slo_writes
            || self.metric_writes
            || self.alert_paging
            || self.causal_claim
            || self.outcome_authority
            || self.work_product_adoption
        {
            return Err(ServiceError::NativeClaim);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaginationEvidence {
    pub pages_observed: usize,
    pub items_observed: usize,
    pub complete: bool,
    pub cursor_digests: Vec<Digest>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsApplicationSignalsProposal {
    pub operation: ReadOperation,
    pub request: AwsApplicationSignalsReadRequest,
    pub request_digest: Digest,
    pub version_digest: Digest,
    pub api_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub window_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: u64,
    pub read_only: bool,
    pub native: bool,
    pub connected: bool,
    pub proposal_digest: Digest,
}

impl AwsApplicationSignalsProposal {
    fn compute_digest(&self) -> Result<Digest, ServiceError> {
        Ok(digest_serializable(&(
            self.operation,
            &self.request,
            &self.request_digest,
            &self.version_digest,
            &self.api_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.window_digest,
            &self.registration_digest,
            self.registration_revision,
            self.read_only,
            self.native,
            self.connected,
        ))?)
    }

    pub fn verify(&self) -> Result<(), ServiceError> {
        if self.proposal_digest != self.compute_digest()?
            || !self.read_only
            || self.native
            || self.connected
            || self.operation != self.request.operation()
            || self.request_digest != self.request.request_digest()?
        {
            return Err(ServiceError::ProposalTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsApplicationSignalsEvidence {
    pub operation: ReadOperation,
    pub mission: MissionBinding,
    pub account_id: crate::AccountId,
    pub region: crate::Region,
    pub service_name: Option<ServiceName>,
    pub slo_id: Option<SloId>,
    pub operation_name: Option<crate::OperationName>,
    pub time_window: TimeWindow,
    pub status: EvidenceStatus,
    pub services: Vec<ServiceSummary>,
    pub service: Option<ServiceDetail>,
    pub slos: Vec<SloSummary>,
    pub slo: Option<SloDetail>,
    pub pagination: PaginationEvidence,
    pub record_digest: Digest,
    pub registration_digest: Digest,
    pub redactions: RedactionSummary,
    pub authority: AuthorityBoundary,
    pub digests: EvidenceDigests,
}

#[derive(Serialize)]
struct EvidenceDigestMaterial<'a> {
    operation: ReadOperation,
    mission: &'a MissionBinding,
    account_id: &'a crate::AccountId,
    region: &'a crate::Region,
    service_name: &'a Option<ServiceName>,
    slo_id: &'a Option<SloId>,
    operation_name: &'a Option<crate::OperationName>,
    time_window: &'a TimeWindow,
    status: EvidenceStatus,
    services: &'a [ServiceSummary],
    service: &'a Option<ServiceDetail>,
    slos: &'a [SloSummary],
    slo: &'a Option<SloDetail>,
    pagination: &'a PaginationEvidence,
    record_digest: &'a Digest,
    registration_digest: &'a Digest,
    redactions: &'a RedactionSummary,
    authority: &'a AuthorityBoundary,
    version_digest: &'a Digest,
    api_digest: &'a Digest,
    contract_digest: &'a Digest,
    provider_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    window_digest: &'a Digest,
}

impl AwsApplicationSignalsEvidence {
    fn compute_digest(&self) -> Result<Digest, ServiceError> {
        Ok(digest_serializable(&EvidenceDigestMaterial {
            operation: self.operation,
            mission: &self.mission,
            account_id: &self.account_id,
            region: &self.region,
            service_name: &self.service_name,
            slo_id: &self.slo_id,
            operation_name: &self.operation_name,
            time_window: &self.time_window,
            status: self.status,
            services: &self.services,
            service: &self.service,
            slos: &self.slos,
            slo: &self.slo,
            pagination: &self.pagination,
            record_digest: &self.record_digest,
            registration_digest: &self.registration_digest,
            redactions: &self.redactions,
            authority: &self.authority,
            version_digest: &self.digests.version_digest,
            api_digest: &self.digests.api_digest,
            contract_digest: &self.digests.contract_digest,
            provider_digest: &self.digests.provider_digest,
            permission_digest: &self.digests.permission_digest,
            scope_digest: &self.digests.scope_digest,
            window_digest: &self.digests.window_digest,
        })?)
    }

    pub fn verify(&self) -> Result<(), ServiceError> {
        self.mission.validate()?;
        self.time_window.validate()?;
        self.redactions.validate()?;
        self.authority.validate()?;
        if self.digests.evidence_digest != self.compute_digest()? {
            return Err(ServiceError::EvidenceTampered);
        }
        Ok(())
    }

    #[must_use]
    pub const fn is_connected(&self) -> bool {
        self.authority.connected
    }

    #[must_use]
    pub const fn native_provider(&self) -> bool {
        self.authority.native_provider
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsApplicationSignalsReceipt {
    pub receipt_digest: Digest,
    pub operation: ReadOperation,
    pub status: EvidenceStatus,
    pub proposal_digest: Digest,
    pub record_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub provenance: ProviderProvenance,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub durable_request_receipt: bool,
    pub durable_cost_receipt: bool,
    pub independent_closed_window_readback: bool,
    pub adopted_outcome: bool,
    pub truth_authority: bool,
    pub redactions: RedactionSummary,
}

impl AwsApplicationSignalsReceipt {
    fn new(
        proposal: &AwsApplicationSignalsProposal,
        record: &AwsApplicationSignalsReadRecord,
        evidence: &AwsApplicationSignalsEvidence,
    ) -> Result<Self, ServiceError> {
        let mut receipt = Self {
            receipt_digest: Digest::from_text("pending-receipt-digest"),
            operation: proposal.operation,
            status: evidence.status,
            proposal_digest: proposal.proposal_digest.clone(),
            record_digest: record.record_digest.clone(),
            evidence_digest: evidence.digests.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            provenance: record.provenance,
            read_only: true,
            connected: false,
            native: false,
            durable_request_receipt: false,
            durable_cost_receipt: false,
            independent_closed_window_readback: false,
            adopted_outcome: false,
            truth_authority: false,
            redactions: RedactionSummary::layer1(),
        };
        receipt.receipt_digest = receipt.compute_digest()?;
        Ok(receipt)
    }

    fn compute_digest(&self) -> Result<Digest, ServiceError> {
        Ok(digest_serializable(&(
            self.operation,
            self.status,
            &self.proposal_digest,
            &self.record_digest,
            &self.evidence_digest,
            &self.registration_digest,
            self.provenance,
            self.read_only,
            self.connected,
            self.native,
            self.durable_request_receipt,
            self.durable_cost_receipt,
            self.independent_closed_window_readback,
            self.adopted_outcome,
            self.truth_authority,
            &self.redactions,
        ))?)
    }

    pub fn verify(&self) -> Result<(), ServiceError> {
        self.redactions.validate()?;
        if self.receipt_digest != self.compute_digest()?
            || !self.read_only
            || self.connected
            || self.native
            || self.durable_request_receipt
            || self.durable_cost_receipt
            || self.independent_closed_window_readback
            || self.adopted_outcome
            || self.truth_authority
        {
            return Err(ServiceError::ReceiptTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsApplicationSignalsReadResult {
    pub proposal: AwsApplicationSignalsProposal,
    pub record: AwsApplicationSignalsReadRecord,
    pub evidence: AwsApplicationSignalsEvidence,
    pub receipt: AwsApplicationSignalsReceipt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceVerification {
    pub verified: bool,
    pub status: EvidenceStatus,
    pub evidence_digest: Digest,
    pub native: bool,
    pub connected: bool,
    pub independent_closed_window_readback: bool,
}

pub struct AwsApplicationSignalsService<T = BlockedEnvAwsApplicationSignalsTransport>
where
    T: crate::AwsApplicationSignalsTransport,
{
    definition: ServiceDefinition,
    provider: AwsApplicationSignalsProvider<T>,
    scope: AwsApplicationSignalsScope,
    secret_reference: SecretReference,
    registration: Registration,
}

impl<T> fmt::Debug for AwsApplicationSignalsService<T>
where
    T: crate::AwsApplicationSignalsTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsApplicationSignalsService")
            .field("definition", &self.definition)
            .field("provider", &self.provider)
            .field("scope_digest", &self.scope.scope_digest)
            .field("window_digest", &self.scope.window_digest)
            .field("secret_reference", &"<opaque>")
            .field("registration", &self.registration)
            .finish()
    }
}

impl<T> AwsApplicationSignalsService<T>
where
    T: crate::AwsApplicationSignalsTransport,
{
    pub fn new(
        scope: AwsApplicationSignalsScope,
        secret_reference: SecretReference,
        provider: AwsApplicationSignalsProvider<T>,
    ) -> Result<Self, ServiceError> {
        scope.validate()?;
        if secret_reference.is_revoked() {
            return Err(ServiceError::SecretRevoked);
        }
        if secret_reference.scope_digest() != scope.digest()
            || secret_reference.account_id() != &scope.account_id
            || secret_reference.region() != &scope.region
        {
            return Err(ServiceError::ScopeMismatch);
        }
        let definition = ServiceDefinition::new();
        definition.validate()?;
        provider.definition().validate()?;
        let registration = Registration::new(
            secret_reference.credential_revision(),
            definition.version_digest.clone(),
            definition.api_digest.clone(),
            definition.contract_digest.clone(),
            provider.provider_digest(),
            scope.permissions.permission_digest.clone(),
            scope.scope_digest.clone(),
            scope.window_digest.clone(),
        )?;
        Ok(Self {
            definition,
            provider,
            scope,
            secret_reference,
            registration,
        })
    }

    #[must_use]
    pub fn service_definition(&self) -> &ServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider(&self) -> &AwsApplicationSignalsProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut AwsApplicationSignalsProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn scope(&self) -> &AwsApplicationSignalsScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn registration(&self) -> &Registration {
        &self.registration
    }

    pub fn revoke_registration(&mut self) -> Result<Digest, ServiceError> {
        self.registration.revoke().map_err(ServiceError::from)
    }

    pub fn revoke_secret_reference(&mut self) -> Result<(), ServiceError> {
        self.secret_reference.revoke().map_err(ServiceError::from)
    }

    pub fn propose(
        &self,
        request: AwsApplicationSignalsReadRequest,
    ) -> Result<AwsApplicationSignalsProposal, ServiceError> {
        self.ensure_active()?;
        self.ensure_request_scope(&request)?;
        let request_digest = request.request_digest()?;
        let mut proposal = AwsApplicationSignalsProposal {
            operation: request.operation(),
            request,
            request_digest,
            version_digest: self.definition.version_digest.clone(),
            api_digest: self.definition.api_digest.clone(),
            contract_digest: self.definition.contract_digest.clone(),
            provider_digest: self.provider.provider_digest(),
            permission_digest: self.scope.permissions.permission_digest.clone(),
            scope_digest: self.scope.scope_digest.clone(),
            window_digest: self.scope.window_digest.clone(),
            registration_digest: self.registration.registration_digest.clone(),
            registration_revision: self.registration.registration_revision,
            read_only: true,
            native: false,
            connected: false,
            proposal_digest: Digest::from_text("pending-proposal-digest"),
        };
        proposal.proposal_digest = proposal.compute_digest()?;
        Ok(proposal)
    }

    pub fn record(
        &mut self,
        proposal: &AwsApplicationSignalsProposal,
    ) -> Result<AwsApplicationSignalsReadRecord, ServiceError> {
        self.ensure_active()?;
        self.ensure_proposal_fences(proposal)?;
        self.provider
            .read(proposal.request.clone())
            .map_err(ServiceError::from)
    }

    pub fn verify(
        &self,
        proposal: &AwsApplicationSignalsProposal,
        record: &AwsApplicationSignalsReadRecord,
    ) -> Result<AwsApplicationSignalsEvidence, ServiceError> {
        self.ensure_active()?;
        self.ensure_proposal_fences(proposal)?;
        record.verify().map_err(|_| ServiceError::RecordTampered)?;
        if record.operation != proposal.operation
            || record.request_digest != proposal.request_digest
            || record.provenance.native()
            || record.provenance.connected()
        {
            return Err(ServiceError::RecordTampered);
        }
        let mut evidence = AwsApplicationSignalsEvidence {
            operation: proposal.operation,
            mission: self.scope.mission.clone(),
            account_id: self.scope.account_id.clone(),
            region: self.scope.region.clone(),
            service_name: self.scope.service_name.clone(),
            slo_id: self.scope.slo_id.clone(),
            operation_name: self.scope.operation_name.clone(),
            time_window: self.scope.time_window.clone(),
            status: record.status,
            services: Vec::new(),
            service: None,
            slos: Vec::new(),
            slo: None,
            pagination: PaginationEvidence {
                pages_observed: record.page_count,
                items_observed: record.item_count,
                complete: record.complete,
                cursor_digests: record.cursor_digests(),
            },
            record_digest: record.record_digest.clone(),
            registration_digest: self.registration.registration_digest.clone(),
            redactions: record.redactions.clone(),
            authority: AuthorityBoundary::layer1(),
            digests: EvidenceDigests {
                version_digest: self.definition.version_digest.clone(),
                api_digest: self.definition.api_digest.clone(),
                contract_digest: self.definition.contract_digest.clone(),
                provider_digest: self.provider.provider_digest(),
                permission_digest: self.scope.permissions.permission_digest.clone(),
                scope_digest: self.scope.scope_digest.clone(),
                window_digest: self.scope.window_digest.clone(),
                evidence_digest: Digest::from_text("pending-evidence-digest"),
            },
        };
        self.populate_evidence(&mut evidence, record)?;
        evidence.digests.evidence_digest = evidence.compute_digest()?;
        evidence.verify()?;
        Ok(evidence)
    }

    pub fn verify_receipt(
        &self,
        receipt: &AwsApplicationSignalsReceipt,
    ) -> Result<EvidenceVerification, ServiceError> {
        receipt.verify()?;
        Ok(EvidenceVerification {
            verified: true,
            status: receipt.status,
            evidence_digest: receipt.evidence_digest.clone(),
            native: receipt.native,
            connected: receipt.connected,
            independent_closed_window_readback: receipt.independent_closed_window_readback,
        })
    }

    pub fn read(
        &mut self,
        request: AwsApplicationSignalsReadRequest,
    ) -> Result<AwsApplicationSignalsReadResult, ServiceError> {
        let proposal = self.propose(request)?;
        let record = self.record(&proposal)?;
        let evidence = self.verify(&proposal, &record)?;
        let receipt = AwsApplicationSignalsReceipt::new(&proposal, &record, &evidence)?;
        receipt.verify()?;
        Ok(AwsApplicationSignalsReadResult {
            proposal,
            record,
            evidence,
            receipt,
        })
    }

    pub fn propose_list_services(
        &self,
        bounds: crate::ReadBounds,
    ) -> Result<AwsApplicationSignalsProposal, ServiceError> {
        let request = crate::ListServicesRequest::new(&self.scope, bounds)?;
        self.propose(AwsApplicationSignalsReadRequest::ListServices(request))
    }

    pub fn propose_get_service(&self) -> Result<AwsApplicationSignalsProposal, ServiceError> {
        let request = crate::GetServiceRequest::new(&self.scope)?;
        self.propose(AwsApplicationSignalsReadRequest::GetService(request))
    }

    pub fn propose_list_service_level_objectives(
        &self,
        bounds: crate::ReadBounds,
    ) -> Result<AwsApplicationSignalsProposal, ServiceError> {
        let request = crate::ListServiceLevelObjectivesRequest::new(&self.scope, bounds)?;
        self.propose(AwsApplicationSignalsReadRequest::ListServiceLevelObjectives(request))
    }

    pub fn propose_get_service_level_objective(
        &self,
    ) -> Result<AwsApplicationSignalsProposal, ServiceError> {
        let request = crate::GetServiceLevelObjectiveRequest::new(&self.scope)?;
        self.propose(AwsApplicationSignalsReadRequest::GetServiceLevelObjective(
            request,
        ))
    }

    fn ensure_active(&self) -> Result<(), ServiceError> {
        self.scope.validate()?;
        self.registration.verify()?;
        if self.registration.state != RegistrationState::Active {
            return Err(ServiceError::RegistrationRevoked);
        }
        if self.secret_reference.is_revoked() {
            return Err(ServiceError::SecretRevoked);
        }
        if self.secret_reference.scope_digest() != self.scope.digest()
            || self.secret_reference.account_id() != &self.scope.account_id
            || self.secret_reference.region() != &self.scope.region
        {
            return Err(ServiceError::ScopeMismatch);
        }
        Ok(())
    }

    fn ensure_request_scope(
        &self,
        request: &AwsApplicationSignalsReadRequest,
    ) -> Result<(), ServiceError> {
        if !self.scope.permissions.permits(request.operation()) {
            return Err(ServiceError::PermissionMismatch);
        }
        if request.scope_digest() != self.scope.digest()
            || request.permission_digest() != &self.scope.permissions.permission_digest
            || request.time_window() != &self.scope.time_window
        {
            return Err(ServiceError::ScopeMismatch);
        }
        match request {
            AwsApplicationSignalsReadRequest::ListServices(request) => {
                if request.account_id != self.scope.account_id
                    || request.region != self.scope.region
                    || request.service_name != self.scope.service_name
                {
                    return Err(ServiceError::ScopeMismatch);
                }
            }
            AwsApplicationSignalsReadRequest::GetService(request) => {
                if request.account_id != self.scope.account_id
                    || request.region != self.scope.region
                    || self.scope.service_name.as_ref() != Some(&request.service_name)
                {
                    return Err(ServiceError::ScopeMismatch);
                }
            }
            AwsApplicationSignalsReadRequest::ListServiceLevelObjectives(request) => {
                if request.account_id != self.scope.account_id
                    || request.region != self.scope.region
                    || self.scope.service_name.as_ref() != Some(&request.service_name)
                {
                    return Err(ServiceError::ScopeMismatch);
                }
            }
            AwsApplicationSignalsReadRequest::GetServiceLevelObjective(request) => {
                if request.account_id != self.scope.account_id
                    || request.region != self.scope.region
                    || self.scope.service_name.as_ref() != Some(&request.service_name)
                    || self.scope.slo_id.as_ref() != Some(&request.slo_id)
                    || self.scope.operation_name.as_ref() != Some(&request.operation_name)
                {
                    return Err(ServiceError::ScopeMismatch);
                }
            }
        }
        Ok(())
    }

    fn ensure_proposal_fences(
        &self,
        proposal: &AwsApplicationSignalsProposal,
    ) -> Result<(), ServiceError> {
        proposal.verify()?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.registration_revision
            || proposal.version_digest != self.definition.version_digest
            || proposal.api_digest != self.definition.api_digest
            || proposal.contract_digest != self.definition.contract_digest
            || proposal.provider_digest != self.provider.provider_digest()
            || proposal.permission_digest != self.scope.permissions.permission_digest
            || proposal.scope_digest != self.scope.scope_digest
            || proposal.window_digest != self.scope.window_digest
        {
            return Err(ServiceError::ProposalTampered);
        }
        self.ensure_request_scope(&proposal.request)
    }

    fn populate_evidence(
        &self,
        evidence: &mut AwsApplicationSignalsEvidence,
        record: &AwsApplicationSignalsReadRecord,
    ) -> Result<(), ServiceError> {
        match evidence.operation {
            ReadOperation::ListServices => {
                for page in &record.pages {
                    let AwsApplicationSignalsRecordPage::Services { services, .. } = page else {
                        return Err(ServiceError::RecordTampered);
                    };
                    for service in services {
                        service.validate()?;
                        if service.account_id != self.scope.account_id
                            || service.region != self.scope.region
                            || !self.scope.contains_service(&service.service_name)
                        {
                            return Err(ServiceError::ScopeMismatch);
                        }
                        evidence.services.push(service.clone());
                    }
                }
            }
            ReadOperation::GetService => {
                if record.pages.len() != 1 {
                    return Err(ServiceError::RecordTampered);
                }
                let AwsApplicationSignalsRecordPage::Service { service, .. } = &record.pages[0]
                else {
                    return Err(ServiceError::RecordTampered);
                };
                if service.summary.account_id != self.scope.account_id
                    || service.summary.region != self.scope.region
                    || !self.scope.contains_service(&service.summary.service_name)
                {
                    return Err(ServiceError::ScopeMismatch);
                }
                evidence.service = Some(service.clone());
            }
            ReadOperation::ListServiceLevelObjectives => {
                for page in &record.pages {
                    let AwsApplicationSignalsRecordPage::ServiceLevelObjectives { slos, .. } = page
                    else {
                        return Err(ServiceError::RecordTampered);
                    };
                    for slo in slos {
                        slo.validate()?;
                        if slo.account_id != self.scope.account_id
                            || slo.region != self.scope.region
                            || !self.scope.contains_slo(&slo.service_name, &slo.slo_id)
                            || !self.scope.contains_operation(&slo.operation_name)
                        {
                            return Err(ServiceError::ScopeMismatch);
                        }
                        evidence.slos.push(slo.clone());
                    }
                }
            }
            ReadOperation::GetServiceLevelObjective => {
                if record.pages.len() != 1 {
                    return Err(ServiceError::RecordTampered);
                }
                let AwsApplicationSignalsRecordPage::ServiceLevelObjective { slo, .. } =
                    &record.pages[0]
                else {
                    return Err(ServiceError::RecordTampered);
                };
                if slo.summary.account_id != self.scope.account_id
                    || slo.summary.region != self.scope.region
                    || !self
                        .scope
                        .contains_slo(&slo.summary.service_name, &slo.summary.slo_id)
                    || !self.scope.contains_operation(&slo.summary.operation_name)
                    || slo.window != self.scope.time_window
                {
                    return Err(ServiceError::ScopeMismatch);
                }
                evidence.slo = Some(slo.clone());
            }
        }
        Ok(())
    }
}

impl Default for AwsApplicationSignalsService<BlockedEnvAwsApplicationSignalsTransport> {
    fn default() -> Self {
        let account = crate::AccountId::new("000000000000").expect("static account");
        let region = crate::Region::new("us-east-1").expect("static region");
        let permissions = crate::PermissionScope::all(
            account.clone(),
            region.clone(),
            crate::RevisionId::new("blocked-permission-1").expect("static revision"),
        )
        .expect("static permissions");
        let mission = MissionBinding::new(
            crate::MissionId::new("blocked-mission").expect("static mission"),
            crate::ProjectId::new("blocked-project").expect("static project"),
            crate::RevisionId::new("blocked-mission-1").expect("static revision"),
            Digest::from_text("blocked-consent"),
        );
        let deployment =
            crate::DeploymentBinding::new("blocked-deployment", 1).expect("static deployment");
        let release = crate::ReleaseBinding::new("blocked-release", 1).expect("static release");
        let window = TimeWindow::closed_seconds(1, 61).expect("static window");
        let scope = AwsApplicationSignalsScope::new(
            account,
            region,
            Some(crate::ServiceName::new("blocked-service").expect("static service")),
            Some(crate::SloId::new("blocked-slo").expect("static SLO")),
            Some(crate::OperationName::new("blocked-operation").expect("static operation")),
            window,
            deployment,
            release,
            mission,
            permissions,
        )
        .expect("static scope");
        let secret = SecretReference::new("blocked-secret", &scope, 1).expect("static secret");
        Self::new(scope, secret, AwsApplicationSignalsProvider::default())
            .expect("static blocked service")
    }
}

#[allow(dead_code)]
fn _provider_definition_is_typed(
    definition: &AwsApplicationSignalsProviderDefinition,
) -> &AwsApplicationSignalsProviderDefinition {
    definition
}

#[allow(dead_code)]
fn _version_is_typed(version: PluginVersion) -> PluginVersion {
    version
}
