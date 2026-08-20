use crate::{
    error::NeonBranchResultError,
    model::{
        AdoptionProposalReceipt, BranchProposalReceipt, BranchProposalRequest,
        CapabilityProbeReceipt, CapabilityProbeRequest, DatabaseResultAdoptionProposal,
        DatabaseResultAdoptionRequest, QueryProposal, QueryProposalRequest, QueryReceipt,
        RegistrationReceipt,
    },
    provider::NeonBranchResultProvider,
    service::NeonBranchResultService,
};

/// Mission-facing consumer seam. It binds a source result revision to an
/// exact child branch, point-in-time, query, schema, row-set, provider version,
/// and registration digest. It has no persistence or Work Product authority.
#[derive(Debug)]
pub struct MissionDatabaseResultConsumer<P> {
    service: NeonBranchResultService<P>,
    registration: Option<RegistrationReceipt>,
}

impl<P> MissionDatabaseResultConsumer<P>
where
    P: NeonBranchResultProvider,
{
    /// Construct a consumer bound to the service's manifest-only registration
    /// digest. An explicit registry receipt can be attached before adoption.
    pub fn new(service: NeonBranchResultService<P>) -> Self {
        Self {
            service,
            registration: None,
        }
    }

    /// Construct a consumer with an explicit active registration receipt.
    pub fn with_registration(
        service: NeonBranchResultService<P>,
        registration: RegistrationReceipt,
    ) -> Result<Self, NeonBranchResultError> {
        registration.validate()?;
        if !registration.active {
            return Err(NeonBranchResultError::RegistrationRevoked);
        }
        Ok(Self {
            service,
            registration: Some(registration),
        })
    }

    /// Attach or replace an explicit active registration receipt.
    pub fn bind_registration(
        &mut self,
        registration: RegistrationReceipt,
    ) -> Result<(), NeonBranchResultError> {
        registration.validate()?;
        if !registration.active {
            return Err(NeonBranchResultError::RegistrationRevoked);
        }
        self.registration = Some(registration);
        Ok(())
    }

    /// Borrow the typed service.
    pub fn service(&self) -> &NeonBranchResultService<P> {
        &self.service
    }

    /// Return an attached explicit registration, if one exists.
    pub fn registration(&self) -> Option<&RegistrationReceipt> {
        self.registration.as_ref()
    }

    /// Forward an exact capability probe.
    pub fn capability_probe(
        &self,
        request: &CapabilityProbeRequest,
    ) -> Result<CapabilityProbeReceipt, NeonBranchResultError> {
        self.service.capability_probe(request)
    }

    /// Forward a branch proposal/recording request.
    pub fn propose_branch(
        &self,
        request: BranchProposalRequest,
    ) -> Result<BranchProposalReceipt, NeonBranchResultError> {
        self.service.propose_branch(request)
    }

    /// Compile a bounded parameterized read proposal.
    pub fn propose_query(
        &self,
        request: QueryProposalRequest,
    ) -> Result<QueryProposal, NeonBranchResultError> {
        self.service.propose_query(request)
    }

    /// Record an independent query receipt through the provider seam.
    pub fn record_query_receipt(
        &self,
        proposal: &QueryProposal,
    ) -> Result<QueryReceipt, NeonBranchResultError> {
        self.service.record_query_receipt(proposal)
    }

    /// Compile a verified, non-durable Mission database-result adoption
    /// proposal. If an explicit registration is attached, it is fenced too.
    pub fn propose_database_result_adoption(
        &self,
        request: DatabaseResultAdoptionRequest,
    ) -> Result<DatabaseResultAdoptionProposal, NeonBranchResultError> {
        match &self.registration {
            Some(registration) => self
                .service
                .propose_database_result_adoption_with_registration(request, registration),
            None => self.service.propose_database_result_adoption(request),
        }
    }

    /// Alias for callers that use the shorter Mission-facing verb.
    pub fn propose_adoption(
        &self,
        request: DatabaseResultAdoptionRequest,
    ) -> Result<DatabaseResultAdoptionProposal, NeonBranchResultError> {
        self.propose_database_result_adoption(request)
    }

    /// Record an adoption proposal without durable adoption.
    pub fn record_adoption_proposal(
        &self,
        proposal: &DatabaseResultAdoptionProposal,
    ) -> Result<AdoptionProposalReceipt, NeonBranchResultError> {
        self.service.record_adoption_proposal(proposal)
    }
}
