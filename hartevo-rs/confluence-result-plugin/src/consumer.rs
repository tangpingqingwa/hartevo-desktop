use crate::error::ConfluenceKnowledgeResultError;
use crate::model::{
    ConfluencePageReadRequest, ConfluenceScopeDescription, ConfluenceSearchRequest,
    KnowledgeEvidence, KnowledgeResultProposal, KnowledgeResultReceipt, KnowledgeSearchEvidence,
    MissionWorkProduct, PageEvidence, VerifiedKnowledgeResult,
};
use crate::provider::ConfluenceCredentialResolver;
use crate::service::ConfluenceKnowledgeResultService;
use crate::transport::ConfluenceTransport;

/// Mission-facing consumer. It composes bounded external evidence into a
/// redacted proposal and recording proof; it does not adopt a kernel Outcome.
pub struct MissionConfluenceKnowledgeConsumer<T, R>
where
    T: ConfluenceTransport,
    R: ConfluenceCredentialResolver,
{
    service: ConfluenceKnowledgeResultService<T, R>,
}

impl<T, R> std::fmt::Debug for MissionConfluenceKnowledgeConsumer<T, R>
where
    T: ConfluenceTransport,
    R: ConfluenceCredentialResolver,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionConfluenceKnowledgeConsumer")
            .field("service", &self.service)
            .finish()
    }
}

impl<T, R> MissionConfluenceKnowledgeConsumer<T, R>
where
    T: ConfluenceTransport,
    R: ConfluenceCredentialResolver,
{
    pub fn new(service: ConfluenceKnowledgeResultService<T, R>) -> Self {
        Self { service }
    }

    pub fn service(&self) -> &ConfluenceKnowledgeResultService<T, R> {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut ConfluenceKnowledgeResultService<T, R> {
        &mut self.service
    }

    pub fn describe_content_scope(
        &mut self,
    ) -> Result<ConfluenceScopeDescription, ConfluenceKnowledgeResultError> {
        self.service.describe_content_scope()
    }

    pub fn read_page_evidence(
        &mut self,
        request: &ConfluencePageReadRequest,
    ) -> Result<PageEvidence, ConfluenceKnowledgeResultError> {
        self.service.read_page_evidence(request)
    }

    pub fn search_knowledge(
        &mut self,
        request: &ConfluenceSearchRequest,
    ) -> Result<KnowledgeSearchEvidence, ConfluenceKnowledgeResultError> {
        self.service.search_knowledge(request)
    }

    pub fn compose_knowledge_result(
        &self,
        work_product: MissionWorkProduct,
        evidence: KnowledgeEvidence,
    ) -> Result<KnowledgeResultProposal, ConfluenceKnowledgeResultError> {
        self.service
            .compile_knowledge_proposal(work_product, evidence)
    }

    pub fn record_knowledge_receipt(
        &mut self,
        proposal: &KnowledgeResultProposal,
    ) -> Result<KnowledgeResultReceipt, ConfluenceKnowledgeResultError> {
        self.service.record_knowledge_receipt(proposal)
    }

    pub fn verify_knowledge_result(
        &mut self,
        proposal: &KnowledgeResultProposal,
        receipt: &KnowledgeResultReceipt,
    ) -> Result<VerifiedKnowledgeResult, ConfluenceKnowledgeResultError> {
        self.service.verify_knowledge_result(proposal, receipt)
    }
}
