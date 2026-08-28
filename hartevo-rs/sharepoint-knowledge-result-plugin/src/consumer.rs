use crate::{
    error::SharePointKnowledgeResultError,
    model::{
        DriveItemChildrenEvidence, DriveItemDeltaEvidence, DriveItemMetadataEvidence,
        DriveItemReadRequest, DriveItemSearchEvidence, DriveItemVersionsEvidence,
        MissionWorkProduct, SharePointKnowledgeEvidence, SharePointKnowledgeReadRequest,
        SharePointKnowledgeResultProposal, SharePointScopeDescription, SharePointSearchRequest,
    },
    provider::{EntraCredentialResolver, MicrosoftGraphSharePointProvider},
    service::SharePointKnowledgeResultService,
    transport::MicrosoftGraphSharePointTransport,
};

/// Mission-facing Layer 1 consumer. It can assemble redacted evidence into a
/// non-mutating proposal, but cannot adopt a Work Product or emit a receipt.
pub struct MissionSharePointKnowledgeConsumer<T, R>
where
    T: MicrosoftGraphSharePointTransport,
    R: EntraCredentialResolver,
{
    service: SharePointKnowledgeResultService<T, R>,
}

impl<T, R> std::fmt::Debug for MissionSharePointKnowledgeConsumer<T, R>
where
    T: MicrosoftGraphSharePointTransport,
    R: EntraCredentialResolver,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionSharePointKnowledgeConsumer")
            .field("service", &self.service)
            .finish()
    }
}

impl<T, R> MissionSharePointKnowledgeConsumer<T, R>
where
    T: MicrosoftGraphSharePointTransport,
    R: EntraCredentialResolver,
{
    pub fn new(service: SharePointKnowledgeResultService<T, R>) -> Self {
        Self { service }
    }

    pub fn from_provider(
        provider: MicrosoftGraphSharePointProvider<T, R>,
    ) -> Result<Self, SharePointKnowledgeResultError> {
        Ok(Self::new(SharePointKnowledgeResultService::new(provider)?))
    }

    pub fn service(&self) -> &SharePointKnowledgeResultService<T, R> {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut SharePointKnowledgeResultService<T, R> {
        &mut self.service
    }

    pub fn describe_scope(
        &mut self,
    ) -> Result<SharePointScopeDescription, SharePointKnowledgeResultError> {
        self.service.describe_scope()
    }

    pub fn read_drive_item_metadata(
        &mut self,
        request: &DriveItemReadRequest,
    ) -> Result<DriveItemMetadataEvidence, SharePointKnowledgeResultError> {
        self.service.read_drive_item_metadata(request)
    }

    pub fn read_drive_item_children(
        &mut self,
        request: &DriveItemReadRequest,
    ) -> Result<DriveItemChildrenEvidence, SharePointKnowledgeResultError> {
        self.service.read_drive_item_children(request)
    }

    pub fn search_drive_items(
        &mut self,
        request: &SharePointSearchRequest,
    ) -> Result<DriveItemSearchEvidence, SharePointKnowledgeResultError> {
        self.service.search_drive_items(request)
    }

    pub fn read_drive_item_versions(
        &mut self,
        request: &DriveItemReadRequest,
    ) -> Result<DriveItemVersionsEvidence, SharePointKnowledgeResultError> {
        self.service.read_drive_item_versions(request)
    }

    pub fn read_drive_item_delta(
        &mut self,
        request: &DriveItemReadRequest,
    ) -> Result<DriveItemDeltaEvidence, SharePointKnowledgeResultError> {
        self.service.read_drive_item_delta(request)
    }

    pub fn read_knowledge_evidence(
        &mut self,
        request: &SharePointKnowledgeReadRequest,
    ) -> Result<SharePointKnowledgeEvidence, SharePointKnowledgeResultError> {
        self.service.read_knowledge_evidence(request)
    }

    pub fn compose_knowledge_result(
        &mut self,
        evidence: &SharePointKnowledgeEvidence,
        work_product: MissionWorkProduct,
    ) -> Result<SharePointKnowledgeResultProposal, SharePointKnowledgeResultError> {
        self.service
            .compile_knowledge_result(evidence, work_product)
    }
}
