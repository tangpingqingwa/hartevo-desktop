use crate::error::ZoteroEvidenceError;
use crate::model::{
    MissionResearchEvidenceRequest, ZoteroCapabilityProbeRequest, ZoteroCapabilityProbeResponse,
    ZoteroCitationRequest, ZoteroCitationResponse, ZoteroEvidenceProposal, ZoteroReadRequest,
    ZoteroReadResponse,
};
use crate::provider::ZoteroEvidenceProvider;
use crate::service::ZoteroEvidenceService;

/// Mission-facing consumer. It binds the exact Mission/claim/result revision
/// to a bounded Zotero observation and formatted citation digest without
/// acquiring Domain, Store, Effect, keyring, or native authority.
#[derive(Debug)]
pub struct MissionResearchEvidenceConsumer<P> {
    service: ZoteroEvidenceService<P>,
}

impl<P> MissionResearchEvidenceConsumer<P>
where
    P: ZoteroEvidenceProvider,
{
    pub fn new(service: ZoteroEvidenceService<P>) -> Self {
        Self { service }
    }

    pub fn service(&self) -> &ZoteroEvidenceService<P> {
        &self.service
    }

    pub fn probe(
        &self,
        request: &ZoteroCapabilityProbeRequest,
    ) -> Result<ZoteroCapabilityProbeResponse, ZoteroEvidenceError> {
        self.service.probe(request)
    }

    pub fn read(
        &self,
        request: &ZoteroReadRequest,
    ) -> Result<ZoteroReadResponse, ZoteroEvidenceError> {
        self.service.read(request)
    }

    pub fn citation(
        &self,
        request: &ZoteroCitationRequest,
    ) -> Result<ZoteroCitationResponse, ZoteroEvidenceError> {
        self.service.citation(request)
    }

    pub fn propose_research_evidence(
        &self,
        request: &MissionResearchEvidenceRequest,
        read: &ZoteroReadResponse,
        citation: &ZoteroCitationResponse,
    ) -> Result<ZoteroEvidenceProposal, ZoteroEvidenceError> {
        self.service
            .propose_research_evidence(request, read, citation)
    }

    /// Alias for integration code that calls the Mission-facing operation
    /// `consume_evidence_proposal`.
    pub fn consume_evidence_proposal(
        &self,
        request: &MissionResearchEvidenceRequest,
        read: &ZoteroReadResponse,
        citation: &ZoteroCitationResponse,
    ) -> Result<ZoteroEvidenceProposal, ZoteroEvidenceError> {
        self.propose_research_evidence(request, read, citation)
    }
}
