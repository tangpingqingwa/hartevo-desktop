use crate::{
    error::NeonBranchResultError,
    model::{
        AdoptionProposalReceipt, BranchProposal, BranchProposalReceipt, BranchProposalRequest,
        CapabilityProbeReceipt, CapabilityProbeRequest, DatabaseResultAdoptionProposal,
        DatabaseResultAdoptionRequest, Digest, NativeStatus, NeonProviderManifest, NeonScope,
        QueryProposal, QueryProposalRequest, QueryReceipt, QueryReceiptKind,
        QueryResultObservation, RegistrationReceipt, TransportMode,
        registration_digest_for_manifest,
    },
    provider::NeonBranchResultProvider,
};

/// Typed Layer 1 service over a replaceable Neon provider. Construction binds
/// provider version, manifest digest, scope, and a manifest-only registration
/// digest; every later operation revalidates them.
#[derive(Debug)]
pub struct NeonBranchResultService<P> {
    provider: P,
    bound_manifest_digest: Digest,
    bound_scope: NeonScope,
    bound_registration_digest: Digest,
}

impl<P> NeonBranchResultService<P>
where
    P: NeonBranchResultProvider,
{
    /// Construct a service after validating the standalone Layer 1 manifest
    /// and both explicit transport seams.
    pub fn new(provider: P) -> Result<Self, NeonBranchResultError> {
        let manifest = provider.manifest();
        manifest.validate()?;
        if provider.native_status().is_native()
            || provider.native_status().is_connected()
            || provider.control_plane_mode().is_native()
            || provider.query_transport_mode().is_native()
            || provider.control_plane_mode() != manifest.control_plane_mode
            || provider.query_transport_mode() != manifest.query_transport_mode
        {
            return Err(NeonBranchResultError::NativeAuthority);
        }
        Ok(Self {
            bound_manifest_digest: manifest.digest(),
            bound_scope: manifest.scope.clone(),
            bound_registration_digest: registration_digest_for_manifest(&manifest),
            provider,
        })
    }

    /// Borrow the provider seam for deterministic fixture inspection.
    pub fn provider(&self) -> &P {
        &self.provider
    }

    /// Return the service's immutable manifest-only registration binding.
    pub fn registration_digest(&self) -> &Digest {
        &self.bound_registration_digest
    }

    /// Return the exact scope bound at construction.
    pub fn scope(&self) -> &NeonScope {
        &self.bound_scope
    }

    /// Return the current provider manifest after drift validation.
    pub fn provider_manifest(&self) -> Result<NeonProviderManifest, NeonBranchResultError> {
        self.ensure_provider()
    }

    /// Probe branch and endpoint capability through the control-plane seam.
    pub fn capability_probe(
        &self,
        request: &CapabilityProbeRequest,
    ) -> Result<CapabilityProbeReceipt, NeonBranchResultError> {
        let manifest = self.ensure_provider()?;
        request.scope.validate()?;
        request.point_in_time.validate()?;
        self.ensure_scope(&request.scope, "capability_probe.scope")?;
        let observation = self.provider.capability_probe(request)?;
        let receipt = CapabilityProbeReceipt::from_observation(request, &observation, &manifest)?;
        receipt.validate()?;
        Ok(receipt)
    }

    /// Convenience probe at branch head.
    pub fn probe(&self, scope: NeonScope) -> Result<CapabilityProbeReceipt, NeonBranchResultError> {
        self.capability_probe(&CapabilityProbeRequest::new(
            scope,
            crate::BranchPoint::head(),
        )?)
    }

    /// Compile and record a branch proposal. No live branch create/delete is
    /// possible through this method.
    pub fn propose_branch(
        &self,
        request: BranchProposalRequest,
    ) -> Result<BranchProposalReceipt, NeonBranchResultError> {
        let manifest = self.ensure_provider()?;
        request.validate()?;
        self.ensure_scope(&request.scope, "branch_proposal.scope")?;
        let proposal = BranchProposal::new(request, &manifest)?;
        let receipt = self.provider.record_branch_proposal(&proposal)?;
        receipt.validate()?;
        if receipt.proposal_digest != proposal.proposal_digest
            || receipt.branch_fence != proposal.branch_fence
        {
            return Err(NeonBranchResultError::ReceiptMismatch {
                field: "branch_proposal.receipt",
            });
        }
        Ok(receipt)
    }

    /// Compile a bounded parameterized SELECT/EXPLAIN proposal.
    pub fn propose_query(
        &self,
        request: QueryProposalRequest,
    ) -> Result<QueryProposal, NeonBranchResultError> {
        let manifest = self.ensure_provider()?;
        request.validate()?;
        self.ensure_scope(&request.scope, "query_proposal.scope")?;
        QueryProposal::new(request, &manifest)
    }

    /// Execute only through a fixture/loopback query seam and record an
    /// independent digest-only receipt.
    pub fn record_query_receipt(
        &self,
        proposal: &QueryProposal,
    ) -> Result<QueryReceipt, NeonBranchResultError> {
        let manifest = self.ensure_provider()?;
        proposal.validate()?;
        self.ensure_scope(&proposal.scope, "query_proposal.scope")?;
        if proposal.provider_manifest_digest != manifest.digest() {
            return Err(NeonBranchResultError::ProviderManifestMismatch {
                field: "query_proposal.provider_manifest_digest",
            });
        }
        let observation: QueryResultObservation = self.provider.execute_query(proposal)?;
        observation.validate()?;
        if observation.scope != proposal.scope || observation.branch_fence != proposal.branch_fence
        {
            return Err(NeonBranchResultError::ReceiptMismatch {
                field: "query_result.branch_fence",
            });
        }
        let receipt = QueryReceipt::from_observation(proposal, &observation, &manifest)?;
        let recorded = self.provider.record_query_receipt(proposal, &receipt)?;
        recorded.validate()?;
        self.verify_query_receipt(proposal, &recorded)?;
        Ok(recorded)
    }

    /// Alias emphasizing the Layer 1 recording seam.
    pub fn record_query(
        &self,
        proposal: &QueryProposal,
    ) -> Result<QueryReceipt, NeonBranchResultError> {
        self.record_query_receipt(proposal)
    }

    /// Verify a receipt against the exact proposal and independent provider
    /// recording. A successful transport response alone is insufficient.
    pub fn verify_query_receipt(
        &self,
        proposal: &QueryProposal,
        receipt: &QueryReceipt,
    ) -> Result<(), NeonBranchResultError> {
        let manifest = self.ensure_provider()?;
        proposal.validate()?;
        receipt.validate()?;
        receipt.matches_proposal(proposal)?;
        if receipt.receipt_kind != QueryReceiptKind::IndependentQueryReceipt || !receipt.independent
        {
            return Err(NeonBranchResultError::MissingIndependentReceipt);
        }
        if receipt.provider_manifest_digest != manifest.digest()
            || receipt.provider_version != manifest.version
        {
            return Err(NeonBranchResultError::ProviderManifestMismatch {
                field: "query_receipt.provider",
            });
        }
        self.provider.verify_query_receipt(proposal, receipt)?;
        Ok(())
    }

    /// Compile a Mission database-result adoption proposal using the service's
    /// manifest-only registration binding.
    pub fn propose_database_result_adoption(
        &self,
        request: DatabaseResultAdoptionRequest,
    ) -> Result<DatabaseResultAdoptionProposal, NeonBranchResultError> {
        self.propose_database_result_adoption_with_registration_digest(
            request,
            self.bound_registration_digest.clone(),
        )
    }

    /// Compile an adoption proposal using an explicit active registry receipt.
    pub fn propose_database_result_adoption_with_registration(
        &self,
        request: DatabaseResultAdoptionRequest,
        registration: &RegistrationReceipt,
    ) -> Result<DatabaseResultAdoptionProposal, NeonBranchResultError> {
        registration.validate()?;
        if !registration.active
            || registration.manifest_digest != self.bound_manifest_digest
            || registration.scope_digest != self.bound_scope.digest()
            || registration.version != self.ensure_provider()?.version
        {
            return Err(NeonBranchResultError::RegistrationMismatch);
        }
        self.propose_database_result_adoption_with_registration_digest(
            request,
            registration.registration_digest.clone(),
        )
    }

    fn propose_database_result_adoption_with_registration_digest(
        &self,
        request: DatabaseResultAdoptionRequest,
        registration_digest: Digest,
    ) -> Result<DatabaseResultAdoptionProposal, NeonBranchResultError> {
        let manifest = self.ensure_provider()?;
        request.source.validate()?;
        self.ensure_scope(&request.query_proposal.scope, "adoption.query.scope")?;
        self.verify_query_receipt(&request.query_proposal, &request.query_receipt)?;
        let proposal =
            DatabaseResultAdoptionProposal::new(request, &manifest, registration_digest)?;
        proposal.validate()?;
        Ok(proposal)
    }

    /// Record the adoption proposal without durable Work Product adoption.
    pub fn record_adoption_proposal(
        &self,
        proposal: &DatabaseResultAdoptionProposal,
    ) -> Result<AdoptionProposalReceipt, NeonBranchResultError> {
        let manifest = self.ensure_provider()?;
        proposal.validate()?;
        if proposal.provider_manifest_digest != manifest.digest()
            || proposal.scope != self.bound_scope
        {
            return Err(NeonBranchResultError::ProviderManifestMismatch {
                field: "adoption.provider_manifest_digest",
            });
        }
        let receipt = self.provider.record_adoption_proposal(proposal)?;
        receipt.validate()?;
        Ok(receipt)
    }

    /// Return the explicit native gap represented by every Layer 1 result.
    pub const fn native_status(&self) -> NativeStatus {
        NativeStatus::BlockedEnv
    }

    /// Return the control-plane seam mode after manifest validation.
    pub fn control_plane_mode(&self) -> Result<TransportMode, NeonBranchResultError> {
        self.ensure_provider()?;
        Ok(self.provider.control_plane_mode())
    }

    /// Return the query seam mode after manifest validation.
    pub fn query_transport_mode(&self) -> Result<TransportMode, NeonBranchResultError> {
        self.ensure_provider()?;
        Ok(self.provider.query_transport_mode())
    }

    fn ensure_provider(&self) -> Result<NeonProviderManifest, NeonBranchResultError> {
        let manifest = self.provider.manifest();
        manifest.validate()?;
        if manifest.digest() != self.bound_manifest_digest {
            return Err(NeonBranchResultError::ProviderManifestMismatch {
                field: "manifest_digest",
            });
        }
        if manifest.scope != self.bound_scope {
            return Err(NeonBranchResultError::ScopeMismatch {
                field: "manifest.scope",
            });
        }
        if self.provider.native_status().is_native()
            || self.provider.native_status().is_connected()
            || self.provider.control_plane_mode() != manifest.control_plane_mode
            || self.provider.query_transport_mode() != manifest.query_transport_mode
        {
            return Err(NeonBranchResultError::NativeAuthority);
        }
        Ok(manifest)
    }

    fn ensure_scope(
        &self,
        scope: &NeonScope,
        field: &'static str,
    ) -> Result<(), NeonBranchResultError> {
        scope.validate()?;
        if scope != &self.bound_scope {
            return Err(NeonBranchResultError::ScopeMismatch { field });
        }
        Ok(())
    }
}
