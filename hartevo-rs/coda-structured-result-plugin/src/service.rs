use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::{CodaProviderError, CodaStructuredResultError};
use crate::model::{
    CodaColumnId, CodaDocId, CodaPageId, CodaPageToken, CodaReadOperation, CodaReadRequest,
    CodaRecordingReceipt, CodaRegistration, CodaRegistrationRevocation, CodaRowId,
    CodaStructuredResultEvidence, CodaStructuredResultProposal, CodaStructuredResultScope,
    CodaTableId, CodaViewId, Digest,
};
use crate::provider::{CodaProvider, CodaProviderDefinition};
use crate::transport::CodaTransport;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodaServiceOperation {
    ReadDocMetadata,
    ReadPageMetadata,
    ReadTableMetadata,
    ReadViewMetadata,
    ReadColumnMetadata,
    ReadRowMetadata,
    CompileProposal,
    RecordProposal,
    VerifyProposal,
    RevokeRegistration,
    RestoreRegistration,
}

impl CodaServiceOperation {
    pub const ALL: [Self; 11] = [
        Self::ReadDocMetadata,
        Self::ReadPageMetadata,
        Self::ReadTableMetadata,
        Self::ReadViewMetadata,
        Self::ReadColumnMetadata,
        Self::ReadRowMetadata,
        Self::CompileProposal,
        Self::RecordProposal,
        Self::VerifyProposal,
        Self::RevokeRegistration,
        Self::RestoreRegistration,
    ];

    #[must_use]
    pub const fn read_only(self) -> bool {
        true
    }

    #[must_use]
    pub const fn external_write(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodaServiceCapability {
    pub operation: CodaServiceOperation,
    pub read_only: bool,
    pub bounded: bool,
    pub external_write: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodaStructuredResultServiceDefinition {
    pub id: String,
    pub version: String,
    pub operations: Vec<CodaServiceOperation>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub external_writes: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub durable_provider_receipts: bool,
    pub kernel_authority: bool,
    pub generic_knowledge_registry: bool,
}

impl CodaStructuredResultServiceDefinition {
    #[must_use]
    pub fn layer1() -> Self {
        Self {
            id: crate::CODA_SERVICE_ID.to_owned(),
            version: crate::CODA_STRUCTURED_RESULT_PLUGIN_VERSION.to_owned(),
            operations: CodaServiceOperation::ALL.to_vec(),
            read_only: true,
            proposal_only: true,
            external_writes: false,
            native: false,
            connected: false,
            first_party: false,
            durable_provider_receipts: false,
            kernel_authority: false,
            generic_knowledge_registry: false,
        }
    }

    pub fn validate(&self) -> Result<(), CodaStructuredResultError> {
        if self != &Self::layer1() {
            return Err(CodaStructuredResultError::Contract(
                "Coda service definition drifted".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Typed Layer-1 service over a CodaProvider. Host mounting and native
/// provider composition remain outside this crate.
pub struct CodaStructuredResultService<T>
where
    T: CodaTransport,
{
    provider: CodaProvider<T>,
    bound_registration_digest: Digest,
    recorded_proposals: BTreeSet<Digest>,
}

impl<T> std::fmt::Debug for CodaStructuredResultService<T>
where
    T: CodaTransport,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CodaStructuredResultService")
            .field("scope_digest", &self.provider.scope().digest())
            .field("registration_digest", &self.bound_registration_digest)
            .field("recorded_proposals", &self.recorded_proposals.len())
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T> CodaStructuredResultService<T>
where
    T: CodaTransport,
{
    pub fn new(provider: CodaProvider<T>) -> Result<Self, CodaStructuredResultError> {
        CodaStructuredResultServiceDefinition::layer1().validate()?;
        provider
            .definition()
            .validate()
            .map_err(CodaStructuredResultError::from)?;
        provider
            .registration()
            .validate()
            .map_err(|_| CodaStructuredResultError::RegistrationDrift)?;
        Ok(Self {
            bound_registration_digest: provider.registration().registration_digest.clone(),
            provider,
            recorded_proposals: BTreeSet::new(),
        })
    }

    #[must_use]
    pub fn service_definition() -> CodaStructuredResultServiceDefinition {
        CodaStructuredResultServiceDefinition::layer1()
    }

    #[must_use]
    pub fn provider(&self) -> &CodaProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut CodaProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn scope(&self) -> &CodaStructuredResultScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn registration(&self) -> &CodaRegistration {
        self.provider.registration()
    }

    #[must_use]
    pub fn provider_definition(&self) -> &CodaProviderDefinition {
        self.provider.definition()
    }

    #[must_use]
    pub fn registration_digest(&self) -> &Digest {
        &self.bound_registration_digest
    }

    #[must_use]
    pub const fn native_connected(&self) -> bool {
        false
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> Vec<CodaServiceCapability> {
        CodaServiceOperation::ALL
            .into_iter()
            .map(|operation| CodaServiceCapability {
                operation,
                read_only: operation.read_only(),
                bounded: true,
                external_write: operation.external_write(),
            })
            .collect()
    }

    pub fn read(
        &mut self,
        request: &CodaReadRequest,
    ) -> Result<CodaStructuredResultEvidence, CodaStructuredResultError> {
        self.ensure_binding()?;
        Ok(self.provider.read(request)?)
    }

    pub fn read_doc_metadata(
        &mut self,
        page_size: u32,
    ) -> Result<CodaStructuredResultEvidence, CodaStructuredResultError> {
        let request = CodaReadRequest::doc(self.scope(), page_size)?;
        self.read(&request)
    }

    pub fn read_page_metadata(
        &mut self,
        page: &CodaPageId,
        page_size: u32,
        page_token: Option<CodaPageToken>,
    ) -> Result<CodaStructuredResultEvidence, CodaStructuredResultError> {
        let request = CodaReadRequest::page(self.scope(), page, page_size, page_token)?;
        self.read(&request)
    }

    pub fn read_table_metadata(
        &mut self,
        table: &CodaTableId,
        page_size: u32,
        page_token: Option<CodaPageToken>,
    ) -> Result<CodaStructuredResultEvidence, CodaStructuredResultError> {
        let request = CodaReadRequest::table(self.scope(), table, page_size, page_token)?;
        self.read(&request)
    }

    pub fn read_view_metadata(
        &mut self,
        view: &CodaViewId,
        page_size: u32,
        page_token: Option<CodaPageToken>,
    ) -> Result<CodaStructuredResultEvidence, CodaStructuredResultError> {
        let request = CodaReadRequest::view(self.scope(), view, page_size, page_token)?;
        self.read(&request)
    }

    pub fn read_column_metadata(
        &mut self,
        column: &CodaColumnId,
        page_size: u32,
        page_token: Option<CodaPageToken>,
    ) -> Result<CodaStructuredResultEvidence, CodaStructuredResultError> {
        let request = CodaReadRequest::column(self.scope(), column, page_size, page_token)?;
        self.read(&request)
    }

    pub fn read_row_metadata(
        &mut self,
        row: &CodaRowId,
        page_size: u32,
        page_token: Option<CodaPageToken>,
    ) -> Result<CodaStructuredResultEvidence, CodaStructuredResultError> {
        let request = CodaReadRequest::row(self.scope(), row, page_size, page_token)?;
        self.read(&request)
    }

    pub fn read_operation(
        &mut self,
        operation: CodaReadOperation,
        resource_id: impl Into<String>,
        page_size: u32,
        page_token: Option<CodaPageToken>,
    ) -> Result<CodaStructuredResultEvidence, CodaStructuredResultError> {
        let request =
            CodaReadRequest::new(self.scope(), operation, resource_id, page_size, page_token)?;
        self.read(&request)
    }

    pub fn compile_proposal(
        &self,
        evidence: &CodaStructuredResultEvidence,
    ) -> Result<CodaStructuredResultProposal, CodaStructuredResultError> {
        self.ensure_binding_ref()?;
        evidence
            .validate()
            .map_err(|_| CodaStructuredResultError::Tampered)?;
        if evidence.scope_digest != self.scope().digest()
            || evidence.provider_digest != self.provider().provider_digest()
            || evidence.registration_digest != self.registration().registration_digest
            || evidence.revision_digest != self.scope().revision().digest()
        {
            return Err(CodaStructuredResultError::ScopeMismatch);
        }
        Ok(CodaStructuredResultProposal::build(
            evidence,
            self.scope(),
            self.provider().provider_digest(),
            self.registration().registration_digest.clone(),
        )?)
    }

    pub fn propose(
        &self,
        evidence: &CodaStructuredResultEvidence,
    ) -> Result<CodaStructuredResultProposal, CodaStructuredResultError> {
        self.compile_proposal(evidence)
    }

    pub fn compile_proposal_from_read(
        &mut self,
        request: &CodaReadRequest,
    ) -> Result<CodaStructuredResultProposal, CodaStructuredResultError> {
        let evidence = self.read(request)?;
        self.compile_proposal(&evidence)
    }

    pub fn record_proposal(
        &mut self,
        proposal: &CodaStructuredResultProposal,
    ) -> Result<CodaRecordingReceipt, CodaStructuredResultError> {
        self.ensure_binding()?;
        self.verify_proposal(proposal)?;
        if self.recorded_proposals.contains(&proposal.proposal_digest) {
            return Ok(self.provider.record_proposal(proposal)?);
        }
        let receipt = self.provider.record_proposal(proposal)?;
        self.recorded_proposals
            .insert(proposal.proposal_digest.clone());
        Ok(receipt)
    }

    pub fn record(
        &mut self,
        proposal: &CodaStructuredResultProposal,
    ) -> Result<CodaRecordingReceipt, CodaStructuredResultError> {
        self.record_proposal(proposal)
    }

    pub fn verify_proposal(
        &self,
        proposal: &CodaStructuredResultProposal,
    ) -> Result<(), CodaStructuredResultError> {
        self.ensure_binding_ref()?;
        proposal
            .validate()
            .map_err(|_| CodaStructuredResultError::Tampered)?;
        if proposal.scope_digest != self.scope().digest()
            || proposal.provider_digest != self.provider().provider_digest()
            || proposal.registration_digest != self.registration().registration_digest
            || proposal.project_digest != self.scope().project().digest()
            || proposal.mission_digest != self.scope().mission().digest()
            || proposal.work_product_digest != self.scope().work_product().digest()
        {
            return Err(CodaStructuredResultError::ScopeMismatch);
        }
        Ok(())
    }

    pub fn verify(
        &self,
        proposal: &CodaStructuredResultProposal,
    ) -> Result<(), CodaStructuredResultError> {
        self.verify_proposal(proposal)
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<CodaRegistrationRevocation, CodaStructuredResultError> {
        let revocation = self.provider.revoke()?;
        self.bound_registration_digest = self.provider.registration().registration_digest.clone();
        Ok(revocation)
    }

    pub fn restore_registration(
        &mut self,
    ) -> Result<CodaRegistrationRevocation, CodaStructuredResultError> {
        let restoration = self.provider.restore()?;
        self.bound_registration_digest = self.provider.registration().registration_digest.clone();
        Ok(restoration)
    }

    fn ensure_binding(&self) -> Result<(), CodaStructuredResultError> {
        self.ensure_binding_ref()
    }

    fn ensure_binding_ref(&self) -> Result<(), CodaStructuredResultError> {
        if self.provider.registration().registration_digest != self.bound_registration_digest {
            return Err(CodaStructuredResultError::RegistrationDrift);
        }
        if !self.provider.registration().is_active() {
            return Err(CodaStructuredResultError::RegistrationRevoked);
        }
        self.provider
            .registration()
            .validate()
            .map_err(|_| CodaStructuredResultError::RegistrationDrift)?;
        Ok(())
    }
}

pub type CodaStructuredResultServiceError = CodaStructuredResultError;

// Keep the imported provider error in the public module's generated docs and
// make the conversion target explicit for rustdoc users.
#[allow(dead_code)]
fn _provider_error_marker(error: CodaProviderError) -> CodaStructuredResultError {
    error.into()
}

// These imports are deliberately kept in the service module's typed API.
#[allow(dead_code)]
fn _id_marker(_doc: Option<CodaDocId>) {}
