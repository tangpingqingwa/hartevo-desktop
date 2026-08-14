use crate::error::FirecrawlResearchEvidenceError;
use crate::model::{
    FirecrawlJobDescription, FirecrawlJobRequest, FirecrawlResearchEvidence,
    FirecrawlResearchProposal, FirecrawlResearchReceipt, FirecrawlScope, FirecrawlUrl,
    FirecrawlUrlDescription, MissionFirecrawlResearchRequest, MissionWorkProduct,
    VerifiedFirecrawlResearchResult,
};
use crate::provider::{FirecrawlCredentialResolver, FirecrawlProvider};
use crate::service::FirecrawlResearchEvidenceService;
use crate::transport::FirecrawlTransport;

pub struct MissionFirecrawlResearchConsumer<
    T: FirecrawlTransport = crate::FixtureFirecrawlTransport,
    R: FirecrawlCredentialResolver = crate::BlockedEnvCredentialResolver,
> {
    service: FirecrawlResearchEvidenceService<T, R>,
}

impl<T, R> std::fmt::Debug for MissionFirecrawlResearchConsumer<T, R>
where
    T: FirecrawlTransport,
    R: FirecrawlCredentialResolver,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionFirecrawlResearchConsumer")
            .field("service", &self.service)
            .finish()
    }
}

impl<T, R> MissionFirecrawlResearchConsumer<T, R>
where
    T: FirecrawlTransport,
    R: FirecrawlCredentialResolver,
{
    pub fn new(service: FirecrawlResearchEvidenceService<T, R>) -> Self {
        Self { service }
    }

    pub fn service(&self) -> &FirecrawlResearchEvidenceService<T, R> {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut FirecrawlResearchEvidenceService<T, R> {
        &mut self.service
    }

    pub fn describe_url(
        &self,
        url: FirecrawlUrl,
        scope: &FirecrawlScope,
    ) -> Result<FirecrawlUrlDescription, FirecrawlResearchEvidenceError> {
        self.service.describe_url(url, scope)
    }

    pub fn describe_job(
        &self,
        request: &FirecrawlJobRequest,
    ) -> Result<FirecrawlJobDescription, FirecrawlResearchEvidenceError> {
        self.service.describe_job(request)
    }

    pub fn collect(
        &mut self,
        request: &MissionFirecrawlResearchRequest,
    ) -> Result<FirecrawlResearchEvidence, FirecrawlResearchEvidenceError> {
        self.validate_mission_request(request)?;
        self.service.read(&request.job)
    }

    pub fn read_evidence(
        &mut self,
        request: &MissionFirecrawlResearchRequest,
    ) -> Result<FirecrawlResearchEvidence, FirecrawlResearchEvidenceError> {
        self.collect(request)
    }

    pub fn poll_evidence(
        &mut self,
        request: &MissionFirecrawlResearchRequest,
    ) -> Result<FirecrawlResearchEvidence, FirecrawlResearchEvidenceError> {
        self.validate_mission_request(request)?;
        self.service.poll(&request.job)
    }

    pub fn propose(
        &mut self,
        request: &MissionFirecrawlResearchRequest,
        work_product: MissionWorkProduct,
    ) -> Result<FirecrawlResearchProposal, FirecrawlResearchEvidenceError> {
        let evidence = self.collect(request)?;
        self.service
            .compile_research_proposal(work_product, evidence)
    }

    pub fn propose_research_evidence(
        &mut self,
        request: &MissionFirecrawlResearchRequest,
        work_product: MissionWorkProduct,
    ) -> Result<FirecrawlResearchProposal, FirecrawlResearchEvidenceError> {
        self.propose(request, work_product)
    }

    pub fn record(
        &self,
        proposal: &FirecrawlResearchProposal,
    ) -> Result<FirecrawlResearchReceipt, FirecrawlResearchEvidenceError> {
        self.service.record_research_receipt(proposal)
    }

    pub fn record_research_receipt(
        &self,
        proposal: &FirecrawlResearchProposal,
    ) -> Result<FirecrawlResearchReceipt, FirecrawlResearchEvidenceError> {
        self.record(proposal)
    }

    pub fn verify(
        &self,
        proposal: &FirecrawlResearchProposal,
        receipt: &FirecrawlResearchReceipt,
    ) -> Result<VerifiedFirecrawlResearchResult, FirecrawlResearchEvidenceError> {
        self.service.verify_research_evidence(proposal, receipt)
    }

    pub fn verify_research_evidence(
        &self,
        proposal: &FirecrawlResearchProposal,
        receipt: &FirecrawlResearchReceipt,
    ) -> Result<VerifiedFirecrawlResearchResult, FirecrawlResearchEvidenceError> {
        self.verify(proposal, receipt)
    }

    pub fn consume(
        &mut self,
        request: &MissionFirecrawlResearchRequest,
        work_product: MissionWorkProduct,
    ) -> Result<FirecrawlMissionEvidenceResult, FirecrawlResearchEvidenceError> {
        let evidence = self.collect(request)?;
        let proposal = self
            .service
            .compile_research_proposal(work_product, evidence.clone())?;
        let receipt = self.service.record_research_receipt(&proposal)?;
        let verification = self.service.verify_research_evidence(&proposal, &receipt)?;
        Ok(FirecrawlMissionEvidenceResult {
            evidence,
            proposal,
            receipt,
            verification,
        })
    }

    fn validate_mission_request(
        &self,
        request: &MissionFirecrawlResearchRequest,
    ) -> Result<(), FirecrawlResearchEvidenceError> {
        request.validate()?;
        if request.expected_registration_digest != self.service.current_registration_digest() {
            return Err(FirecrawlResearchEvidenceError::RegistrationDigestMismatch);
        }
        if request.expected_permission_digest != self.service.current_permission_digest() {
            return Err(FirecrawlResearchEvidenceError::PermissionDigestMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct FirecrawlMissionEvidenceResult {
    pub evidence: FirecrawlResearchEvidence,
    pub proposal: FirecrawlResearchProposal,
    pub receipt: FirecrawlResearchReceipt,
    pub verification: VerifiedFirecrawlResearchResult,
}

#[allow(dead_code)]
fn _provider_type_is_public<T, R>(_provider: &FirecrawlProvider<T, R>)
where
    T: FirecrawlTransport,
    R: FirecrawlCredentialResolver,
{
}
