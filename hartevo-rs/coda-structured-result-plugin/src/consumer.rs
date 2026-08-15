use std::collections::BTreeSet;

use thiserror::Error;

use crate::error::CodaStructuredResultError;
use crate::model::{
    CodaColumnId, CodaEvidenceState, CodaPageId, CodaPageToken, CodaRecordingReceipt,
    CodaRegistrationRevocation, CodaRowId, CodaStructuredResultEvidence,
    CodaStructuredResultProposal, CodaStructuredResultScope, CodaTableId, CodaViewId, Digest,
    Mission, Project, WorkProduct,
};
use crate::service::CodaStructuredResultService;
use crate::transport::CodaTransport;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionCodaStructuredConsumerError {
    #[error("Mission Coda structured-result consumer is revoked")]
    Revoked,
    #[error("Mission Coda structured-result proposal replay was rejected")]
    ReplayDetected,
    #[error("Mission Coda structured-result proposal is outside the Mission scope")]
    ScopeMismatch,
    #[error("Mission Coda structured-result proposal is tampered")]
    Tampered,
    #[error(transparent)]
    Service(#[from] CodaStructuredResultError),
}

#[derive(Clone, Debug, PartialEq)]
pub struct MissionCodaStructuredResult {
    pub project: Project,
    pub mission: Mission,
    pub work_product: WorkProduct,
    pub evidence: CodaStructuredResultEvidence,
    pub proposal_digest: Digest,
    pub idempotency_key: Digest,
    pub state: CodaEvidenceState,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub adopts_outcome: bool,
    pub adopts_work_product: bool,
    pub external_write_performed: bool,
    pub formula_executed: bool,
}

/// Mission-facing consumer for one exact Coda structured-result registration.
/// It consumes proposals below the kernel and maintains an in-memory replay
/// fence; it never adopts an Outcome or Work Product.
pub struct MissionCodaStructuredConsumer<T>
where
    T: CodaTransport,
{
    service: CodaStructuredResultService<T>,
    active: bool,
    consumed_proposals: BTreeSet<Digest>,
}

impl<T> std::fmt::Debug for MissionCodaStructuredConsumer<T>
where
    T: CodaTransport,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionCodaStructuredConsumer")
            .field("scope_digest", &self.service.scope().digest())
            .field("active", &self.active)
            .field("consumed_proposals", &self.consumed_proposals.len())
            .finish()
    }
}

impl<T> MissionCodaStructuredConsumer<T>
where
    T: CodaTransport,
{
    #[must_use]
    pub fn new(service: CodaStructuredResultService<T>) -> Self {
        Self {
            service,
            active: true,
            consumed_proposals: BTreeSet::new(),
        }
    }

    pub fn from_provider(
        provider: crate::provider::CodaProvider<T>,
    ) -> Result<Self, MissionCodaStructuredConsumerError> {
        Ok(Self::new(CodaStructuredResultService::new(provider)?))
    }

    #[must_use]
    pub fn service(&self) -> &CodaStructuredResultService<T> {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut CodaStructuredResultService<T> {
        &mut self.service
    }

    #[must_use]
    pub fn scope(&self) -> &CodaStructuredResultScope {
        self.service.scope()
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn read(
        &mut self,
        request: &crate::model::CodaReadRequest,
    ) -> Result<CodaStructuredResultEvidence, MissionCodaStructuredConsumerError> {
        self.ensure_active()?;
        Ok(self.service.read(request)?)
    }

    pub fn read_page_metadata(
        &mut self,
        page: &CodaPageId,
        page_size: u32,
        page_token: Option<CodaPageToken>,
    ) -> Result<CodaStructuredResultEvidence, MissionCodaStructuredConsumerError> {
        self.ensure_active()?;
        Ok(self
            .service
            .read_page_metadata(page, page_size, page_token)?)
    }

    pub fn read_table_metadata(
        &mut self,
        table: &CodaTableId,
        page_size: u32,
        page_token: Option<CodaPageToken>,
    ) -> Result<CodaStructuredResultEvidence, MissionCodaStructuredConsumerError> {
        self.ensure_active()?;
        Ok(self
            .service
            .read_table_metadata(table, page_size, page_token)?)
    }

    pub fn read_view_metadata(
        &mut self,
        view: &CodaViewId,
        page_size: u32,
        page_token: Option<CodaPageToken>,
    ) -> Result<CodaStructuredResultEvidence, MissionCodaStructuredConsumerError> {
        self.ensure_active()?;
        Ok(self
            .service
            .read_view_metadata(view, page_size, page_token)?)
    }

    pub fn read_column_metadata(
        &mut self,
        column: &CodaColumnId,
        page_size: u32,
        page_token: Option<CodaPageToken>,
    ) -> Result<CodaStructuredResultEvidence, MissionCodaStructuredConsumerError> {
        self.ensure_active()?;
        Ok(self
            .service
            .read_column_metadata(column, page_size, page_token)?)
    }

    pub fn read_row_metadata(
        &mut self,
        row: &CodaRowId,
        page_size: u32,
        page_token: Option<CodaPageToken>,
    ) -> Result<CodaStructuredResultEvidence, MissionCodaStructuredConsumerError> {
        self.ensure_active()?;
        Ok(self.service.read_row_metadata(row, page_size, page_token)?)
    }

    pub fn compile_proposal(
        &self,
        evidence: &CodaStructuredResultEvidence,
    ) -> Result<CodaStructuredResultProposal, MissionCodaStructuredConsumerError> {
        self.ensure_active_ref()?;
        Ok(self.service.compile_proposal(evidence)?)
    }

    pub fn record_proposal(
        &mut self,
        proposal: &CodaStructuredResultProposal,
    ) -> Result<CodaRecordingReceipt, MissionCodaStructuredConsumerError> {
        self.ensure_active()?;
        Ok(self.service.record_proposal(proposal)?)
    }

    pub fn consume(
        &mut self,
        proposal: &CodaStructuredResultProposal,
    ) -> Result<MissionCodaStructuredResult, MissionCodaStructuredConsumerError> {
        self.ensure_active()?;
        self.service
            .verify_proposal(proposal)
            .map_err(|error| match error {
                CodaStructuredResultError::Tampered => MissionCodaStructuredConsumerError::Tampered,
                CodaStructuredResultError::ScopeMismatch
                | CodaStructuredResultError::WorkProductMismatch => {
                    MissionCodaStructuredConsumerError::ScopeMismatch
                }
                other => MissionCodaStructuredConsumerError::Service(other),
            })?;
        if !self
            .consumed_proposals
            .insert(proposal.proposal_digest.clone())
        {
            return Err(MissionCodaStructuredConsumerError::ReplayDetected);
        }
        let evidence = proposal.evidence.clone();
        Ok(MissionCodaStructuredResult {
            project: self.scope().project().clone(),
            mission: self.scope().mission().clone(),
            work_product: self.scope().work_product().clone(),
            evidence,
            proposal_digest: proposal.proposal_digest.clone(),
            idempotency_key: proposal.idempotency_key.clone(),
            state: proposal.state,
            proposal_only: true,
            native: false,
            connected: false,
            first_party: false,
            adopts_outcome: false,
            adopts_work_product: false,
            external_write_performed: false,
            formula_executed: false,
        })
    }

    pub fn consume_proposal(
        &mut self,
        proposal: &CodaStructuredResultProposal,
    ) -> Result<MissionCodaStructuredResult, MissionCodaStructuredConsumerError> {
        self.consume(proposal)
    }

    pub fn revoke(
        &mut self,
    ) -> Result<CodaRegistrationRevocation, MissionCodaStructuredConsumerError> {
        self.ensure_active()?;
        let revocation = self.service.revoke_registration()?;
        self.active = false;
        Ok(revocation)
    }

    pub fn restore(
        &mut self,
    ) -> Result<CodaRegistrationRevocation, MissionCodaStructuredConsumerError> {
        if self.active {
            return Err(MissionCodaStructuredConsumerError::ScopeMismatch);
        }
        let restoration = self.service.restore_registration()?;
        self.active = true;
        Ok(restoration)
    }

    fn ensure_active(&self) -> Result<(), MissionCodaStructuredConsumerError> {
        self.ensure_active_ref()
    }

    fn ensure_active_ref(&self) -> Result<(), MissionCodaStructuredConsumerError> {
        if self.active {
            Ok(())
        } else {
            Err(MissionCodaStructuredConsumerError::Revoked)
        }
    }
}

pub type MissionCodaStructuredResultConsumer<T> = MissionCodaStructuredConsumer<T>;
