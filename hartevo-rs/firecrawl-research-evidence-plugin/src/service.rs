use serde::{Deserialize, Serialize};

use crate::error::FirecrawlResearchEvidenceError;
use crate::model::{
    Digest, FirecrawlJobDescription, FirecrawlJobKind, FirecrawlJobRequest,
    FirecrawlPluginRegistration, FirecrawlProviderManifest, FirecrawlResearchEvidence,
    FirecrawlResearchProposal, FirecrawlResearchReceipt, FirecrawlScope, FirecrawlUrl,
    FirecrawlUrlDescription, MissionWorkProduct, VerifiedFirecrawlResearchResult,
};
use crate::provider::FirecrawlCredentialResolver;
use crate::provider::{FirecrawlProvider, FirecrawlProviderState};
use crate::transport::FirecrawlTransport;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirecrawlResearchEvidenceOperation {
    DescribeUrl,
    DescribeJob,
    ReadScrapeEvidence,
    ReadCrawlEvidence,
    CompileResearchProposal,
    RecordResearchReceipt,
    VerifyResearchEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FirecrawlResearchEvidenceServiceDefinition {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_version: String,
    pub operations: Vec<FirecrawlResearchEvidenceOperation>,
    pub read_only: bool,
    pub external_writes: bool,
    pub durable_native_receipts: bool,
    pub independent_readback: bool,
    pub adoption: bool,
    pub connected_authority: bool,
}

impl FirecrawlResearchEvidenceServiceDefinition {
    pub fn layer1() -> Self {
        Self {
            service_id: String::from("FirecrawlResearchEvidenceService"),
            provider_id: String::from("FirecrawlProvider"),
            consumer_id: String::from("MissionFirecrawlResearchConsumer"),
            contract_version: String::from("EXT-FIRECRAWL-01-L1/v1"),
            operations: vec![
                FirecrawlResearchEvidenceOperation::DescribeUrl,
                FirecrawlResearchEvidenceOperation::DescribeJob,
                FirecrawlResearchEvidenceOperation::ReadScrapeEvidence,
                FirecrawlResearchEvidenceOperation::ReadCrawlEvidence,
                FirecrawlResearchEvidenceOperation::CompileResearchProposal,
                FirecrawlResearchEvidenceOperation::RecordResearchReceipt,
                FirecrawlResearchEvidenceOperation::VerifyResearchEvidence,
            ],
            read_only: true,
            external_writes: false,
            durable_native_receipts: false,
            independent_readback: false,
            adoption: false,
            connected_authority: false,
        }
    }

    pub fn validate(&self) -> Result<(), FirecrawlResearchEvidenceError> {
        if self.service_id != "FirecrawlResearchEvidenceService"
            || self.provider_id != "FirecrawlProvider"
            || self.consumer_id != "MissionFirecrawlResearchConsumer"
            || self.contract_version != "EXT-FIRECRAWL-01-L1/v1"
            || self.operations.len() != 7
            || !self.read_only
            || self.external_writes
            || self.durable_native_receipts
            || self.independent_readback
            || self.adoption
            || self.connected_authority
        {
            return Err(FirecrawlResearchEvidenceError::InvalidContract {
                reason: "service definition exceeds Layer 1 authority",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        crate::canonical_digest(self)
    }
}

pub struct FirecrawlResearchEvidenceService<
    T: FirecrawlTransport = crate::FixtureFirecrawlTransport,
    R: FirecrawlCredentialResolver = crate::BlockedEnvCredentialResolver,
> {
    provider: FirecrawlProvider<T, R>,
    definition: FirecrawlResearchEvidenceServiceDefinition,
}

impl<T, R> std::fmt::Debug for FirecrawlResearchEvidenceService<T, R>
where
    T: FirecrawlTransport,
    R: FirecrawlCredentialResolver,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FirecrawlResearchEvidenceService")
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .finish()
    }
}

impl<T, R> FirecrawlResearchEvidenceService<T, R>
where
    T: FirecrawlTransport,
    R: FirecrawlCredentialResolver,
{
    pub fn new(provider: FirecrawlProvider<T, R>) -> Result<Self, FirecrawlResearchEvidenceError> {
        let definition = FirecrawlResearchEvidenceServiceDefinition::layer1();
        definition.validate()?;
        Ok(Self {
            provider,
            definition,
        })
    }

    pub fn definition(&self) -> &FirecrawlResearchEvidenceServiceDefinition {
        &self.definition
    }

    pub fn provider(&self) -> &FirecrawlProvider<T, R> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut FirecrawlProvider<T, R> {
        &mut self.provider
    }

    pub fn provider_manifest(&self) -> &FirecrawlProviderManifest {
        self.provider.provider_manifest()
    }

    pub fn registration(&self) -> &FirecrawlPluginRegistration {
        self.provider.registration()
    }

    pub fn describe_url(
        &self,
        url: FirecrawlUrl,
        scope: &FirecrawlScope,
    ) -> Result<FirecrawlUrlDescription, FirecrawlResearchEvidenceError> {
        self.provider.describe_url(url, scope)
    }

    pub fn describe_job(
        &self,
        request: &FirecrawlJobRequest,
    ) -> Result<FirecrawlJobDescription, FirecrawlResearchEvidenceError> {
        self.provider.describe_job(request)
    }

    pub fn read(
        &mut self,
        request: &FirecrawlJobRequest,
    ) -> Result<FirecrawlResearchEvidence, FirecrawlResearchEvidenceError> {
        self.provider.read(request)
    }

    pub fn scrape(
        &mut self,
        request: &FirecrawlJobRequest,
    ) -> Result<FirecrawlResearchEvidence, FirecrawlResearchEvidenceError> {
        self.provider.scrape(request)
    }

    pub fn crawl(
        &mut self,
        request: &FirecrawlJobRequest,
    ) -> Result<FirecrawlResearchEvidence, FirecrawlResearchEvidenceError> {
        self.provider.crawl(request)
    }

    pub fn poll(
        &mut self,
        request: &FirecrawlJobRequest,
    ) -> Result<FirecrawlResearchEvidence, FirecrawlResearchEvidenceError> {
        self.provider.poll(request)
    }

    pub fn compile_research_proposal(
        &self,
        work_product: MissionWorkProduct,
        evidence: FirecrawlResearchEvidence,
    ) -> Result<FirecrawlResearchProposal, FirecrawlResearchEvidenceError> {
        work_product.validate()?;
        evidence.validate()?;
        if evidence.registration_digest != self.provider.registration().registration_digest {
            return Err(FirecrawlResearchEvidenceError::RegistrationDigestMismatch);
        }
        if evidence.permission_digest != self.provider.registration().permission_digest {
            return Err(FirecrawlResearchEvidenceError::PermissionDigestMismatch);
        }
        if !self.provider.registration().enabled {
            return Err(FirecrawlResearchEvidenceError::RegistrationRevoked);
        }
        FirecrawlResearchProposal::from_evidence(&work_product, &evidence)
    }

    pub fn compile_proposal(
        &self,
        work_product: MissionWorkProduct,
        evidence: FirecrawlResearchEvidence,
    ) -> Result<FirecrawlResearchProposal, FirecrawlResearchEvidenceError> {
        self.compile_research_proposal(work_product, evidence)
    }

    pub fn record_research_receipt(
        &self,
        proposal: &FirecrawlResearchProposal,
    ) -> Result<FirecrawlResearchReceipt, FirecrawlResearchEvidenceError> {
        proposal.validate()?;
        if proposal.registration_digest != self.provider.registration().registration_digest {
            return Err(FirecrawlResearchEvidenceError::RegistrationDigestMismatch);
        }
        if !self.provider.registration().enabled {
            return Err(FirecrawlResearchEvidenceError::RegistrationRevoked);
        }
        Ok(FirecrawlResearchReceipt::from_proposal(proposal))
    }

    pub fn record_receipt(
        &self,
        proposal: &FirecrawlResearchProposal,
    ) -> Result<FirecrawlResearchReceipt, FirecrawlResearchEvidenceError> {
        self.record_research_receipt(proposal)
    }

    pub fn verify_research_evidence(
        &self,
        proposal: &FirecrawlResearchProposal,
        receipt: &FirecrawlResearchReceipt,
    ) -> Result<VerifiedFirecrawlResearchResult, FirecrawlResearchEvidenceError> {
        proposal.validate()?;
        receipt.validate()?;
        if proposal.registration_digest != self.provider.registration().registration_digest
            || receipt.registration_digest != proposal.registration_digest
        {
            return Err(FirecrawlResearchEvidenceError::RegistrationDigestMismatch);
        }
        if receipt.proposal_digest != proposal.proposal_digest
            || receipt.evidence_digest != proposal.evidence_digest
            || receipt.request_digest != proposal.request_digest
            || receipt.job_digest != proposal.job_digest
            || receipt.page_digest != proposal.page_digest
            || receipt.citation_digest != proposal.citation_digest
            || receipt.content_digest != proposal.content_digest
            || receipt.extraction_schema_digest != proposal.extraction_schema_digest
            || receipt.permission_digest != proposal.permission_digest
        {
            return Err(FirecrawlResearchEvidenceError::CitationMismatch);
        }
        let result = VerifiedFirecrawlResearchResult::verified_from(proposal, receipt);
        result.validate()?;
        Ok(result)
    }

    pub fn verify(
        &self,
        proposal: &FirecrawlResearchProposal,
        receipt: &FirecrawlResearchReceipt,
    ) -> Result<VerifiedFirecrawlResearchResult, FirecrawlResearchEvidenceError> {
        self.verify_research_evidence(proposal, receipt)
    }

    pub fn current_status(&self) -> FirecrawlProviderState {
        self.provider.state().clone()
    }

    pub fn current_registration_digest(&self) -> Digest {
        self.provider.registration().registration_digest.clone()
    }

    pub fn current_permission_digest(&self) -> Digest {
        self.provider.registration().permission_digest.clone()
    }

    pub fn is_kind(&self, request: &FirecrawlJobRequest, kind: FirecrawlJobKind) -> bool {
        request.kind() == kind
    }
}
