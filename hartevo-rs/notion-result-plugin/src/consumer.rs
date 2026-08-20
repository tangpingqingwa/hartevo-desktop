use crate::error::NotionResultError;
use crate::model::{
    MissionWorkProduct, NotionDescribeRequest, NotionPageReceipt, NotionPublishDestination,
    NotionPublishProposal, NotionReadRequest, NotionReadback, NotionScopeDescription,
    NotionVerifiedReadback,
};
use crate::provider::NotionResultProvider;
use crate::service::NotionResultService;

/// Mission-facing consumer seam.  It accepts a typed WorkProduct projection
/// and returns a proposal/receipt/read-back proof without acquiring domain,
/// Store, keyring, Browser Profile, or Effect authority.
#[derive(Debug)]
pub struct MissionNotionResultConsumer<P> {
    service: NotionResultService<P>,
}

impl<P> MissionNotionResultConsumer<P>
where
    P: NotionResultProvider,
{
    pub fn new(service: NotionResultService<P>) -> Self {
        Self { service }
    }

    pub fn service(&self) -> &NotionResultService<P> {
        &self.service
    }

    pub fn describe(
        &self,
        request: &NotionDescribeRequest,
    ) -> Result<NotionScopeDescription, NotionResultError> {
        self.service.describe(request)
    }

    pub fn compile_publish_proposal(
        &self,
        work_product: MissionWorkProduct,
        destination: NotionPublishDestination,
    ) -> Result<NotionPublishProposal, NotionResultError> {
        self.service
            .compile_publish_proposal(work_product, destination)
    }

    pub fn record_publish_proposal(
        &self,
        proposal: &NotionPublishProposal,
    ) -> Result<NotionPageReceipt, NotionResultError> {
        self.service.record_proposal(proposal)
    }

    pub fn read(&self, request: &NotionReadRequest) -> Result<NotionReadback, NotionResultError> {
        self.service.read(request)
    }

    pub fn consume_readback(
        &self,
        proposal: &NotionPublishProposal,
        receipt: &NotionPageReceipt,
        readback: &NotionReadback,
    ) -> Result<NotionVerifiedReadback, NotionResultError> {
        self.service.verify_readback(proposal, receipt, readback)
    }
}
