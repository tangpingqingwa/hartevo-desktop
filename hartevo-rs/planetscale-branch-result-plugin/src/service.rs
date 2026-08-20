use std::fmt;

use crate::provider::PlanetScaleTransport;
use crate::{
    BranchResultEvidence, BranchResultProposal, BranchResultReceipt, Digest, EvidenceState,
    FailureKind, IdempotencyKey, MISSION_PLANETSCALE_BRANCH_RESULT_CONSUMER_ID, NativeStatus,
    PLANETSCALE_BRANCH_RESULT_CONTRACT_VERSION, PLANETSCALE_BRANCH_RESULT_SCHEMA_VERSION,
    PLANETSCALE_PROVIDER_ID, PLANETSCALE_SERVICE_ID, PageCursor, PlanetScaleProvider,
    PlanetScaleRegistration, PlanetScaleScope, PostureRead, RegistrationReceipt, TransportMode,
    VerificationResult, contract_digest,
    error::{PlanetScaleBranchResultError, PlanetScaleProviderError},
};

/// Static service metadata. It describes a read-only, proposal-and-recording
/// seam and carries no host or kernel authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanetScaleServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_digest: Digest,
    pub read_only: bool,
    pub live_transport: bool,
    pub external_writes: bool,
    pub query_execution: bool,
    pub work_product_adoption: bool,
}

impl Default for PlanetScaleServiceDefinition {
    fn default() -> Self {
        Self {
            schema_version: PLANETSCALE_BRANCH_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: PLANETSCALE_BRANCH_RESULT_CONTRACT_VERSION.to_owned(),
            service_id: PLANETSCALE_SERVICE_ID.to_owned(),
            provider_id: PLANETSCALE_PROVIDER_ID.to_owned(),
            consumer_id: MISSION_PLANETSCALE_BRANCH_RESULT_CONSUMER_ID.to_owned(),
            contract_digest: contract_digest(),
            read_only: true,
            live_transport: false,
            external_writes: false,
            query_execution: false,
            work_product_adoption: false,
        }
    }
}

/// Service failures are the shared typed model errors. Provider status errors
/// can also be represented as safe `BranchResultEvidence` by `read`.
pub type PlanetScaleServiceError = PlanetScaleBranchResultError;

/// Typed Layer 1 service over a replaceable PlanetScale provider.
pub struct PlanetScaleBranchResultService<T: PlanetScaleTransport> {
    provider: PlanetScaleProvider<T>,
    definition: PlanetScaleServiceDefinition,
}

impl<T: PlanetScaleTransport> fmt::Debug for PlanetScaleBranchResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlanetScaleBranchResultService")
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .finish()
    }
}

impl<T: PlanetScaleTransport> PlanetScaleBranchResultService<T> {
    pub fn new(provider: PlanetScaleProvider<T>) -> Result<Self, PlanetScaleServiceError> {
        provider.manifest().validate()?;
        provider.registration().validate()?;
        if provider.native_status().is_native() || provider.transport_mode().is_native() {
            return Err(PlanetScaleBranchResultError::NativeAuthority);
        }
        Ok(Self {
            provider,
            definition: PlanetScaleServiceDefinition::default(),
        })
    }

    #[must_use]
    pub fn from_provider(provider: PlanetScaleProvider<T>) -> Self {
        Self {
            provider,
            definition: PlanetScaleServiceDefinition::default(),
        }
    }

    #[must_use]
    pub fn provider(&self) -> &PlanetScaleProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut PlanetScaleProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn definition(&self) -> &PlanetScaleServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn scope(&self) -> &PlanetScaleScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn registration(&self) -> &PlanetScaleRegistration {
        self.provider.registration()
    }

    pub fn registration_receipt(&self) -> Result<RegistrationReceipt, PlanetScaleServiceError> {
        self.provider.registration_receipt()
    }

    /// Compile a bounded read/proposal request. The idempotency key and cursor
    /// are represented only by digests in the serializable proposal.
    pub fn compile_proposal(
        &self,
        read: PostureRead,
        page_size: u16,
        cursor: Option<&PageCursor>,
        idempotency_key: &IdempotencyKey,
        intent: crate::ProposalIntent,
    ) -> Result<BranchResultProposal, PlanetScaleServiceError> {
        self.ensure_provider()?;
        let request = self
            .provider
            .build_request(read, page_size, cursor, idempotency_key)?;
        BranchResultProposal::new(
            request,
            intent,
            self.provider.manifest(),
            self.provider.registration(),
        )
    }

    /// Convenience branch/deploy/schema inspection proposal.
    pub fn propose_posture(
        &self,
        read: PostureRead,
        page_size: u16,
        idempotency_key: &IdempotencyKey,
    ) -> Result<BranchResultProposal, PlanetScaleServiceError> {
        self.compile_proposal(
            read,
            page_size,
            None,
            idempotency_key,
            crate::ProposalIntent::InspectBranchDeployPosture,
        )
    }

    /// Read only through the supplied non-native transport and normalize every
    /// bounded failure into typed, digest-fenced evidence.
    pub fn read(
        &mut self,
        proposal: &BranchResultProposal,
    ) -> Result<BranchResultEvidence, PlanetScaleServiceError> {
        proposal.validate()?;
        self.ensure_proposal_binding(proposal)?;
        if self.provider.registration().revoked {
            return BranchResultEvidence::failure(
                proposal,
                EvidenceState::Revoked,
                FailureKind::RegistrationRevoked,
                self.provider.transport_mode().evidence_source(),
            );
        }
        match self.provider.read_posture(&proposal.request) {
            Ok(observation) => BranchResultEvidence::from_observation(proposal, &observation),
            Err(error) => self.failure_evidence(proposal, error),
        }
    }

    /// Alias making the bounded control-plane boundary explicit at call sites.
    pub fn read_posture(
        &mut self,
        proposal: &BranchResultProposal,
    ) -> Result<BranchResultEvidence, PlanetScaleServiceError> {
        self.read(proposal)
    }

    /// Record an exact proposal/evidence pair through the provider's in-memory
    /// idempotent receipt seam.
    pub fn record(
        &mut self,
        proposal: &BranchResultProposal,
        evidence: &BranchResultEvidence,
    ) -> Result<BranchResultReceipt, PlanetScaleServiceError> {
        proposal.validate()?;
        evidence.validate_against(proposal)?;
        self.ensure_proposal_binding(proposal)?;
        self.provider.record(proposal, evidence)
    }

    /// Alias for the redacted record seam.
    pub fn record_result(
        &mut self,
        proposal: &BranchResultProposal,
        evidence: &BranchResultEvidence,
    ) -> Result<BranchResultReceipt, PlanetScaleServiceError> {
        self.record(proposal, evidence)
    }

    /// Verify both the receipt digest and the provider's independent in-memory
    /// record. A transport response alone is never sufficient.
    pub fn verify(
        &self,
        proposal: &BranchResultProposal,
        evidence: &BranchResultEvidence,
        receipt: &BranchResultReceipt,
    ) -> Result<VerificationResult, PlanetScaleServiceError> {
        proposal.validate()?;
        evidence.validate_against(proposal)?;
        self.ensure_proposal_binding(proposal)?;
        self.provider.verify(proposal, evidence, receipt)
    }

    /// Alias emphasizing that the record is independently provider-verified.
    pub fn verify_record(
        &self,
        proposal: &BranchResultProposal,
        evidence: &BranchResultEvidence,
        receipt: &BranchResultReceipt,
    ) -> Result<VerificationResult, PlanetScaleServiceError> {
        self.verify(proposal, evidence, receipt)
    }

    pub fn revoke(&mut self) -> Result<(), PlanetScaleServiceError> {
        self.provider.registration_mut().revoke()
    }

    pub fn restore(&mut self) -> Result<(), PlanetScaleServiceError> {
        self.provider.registration_mut().restore()
    }

    #[must_use]
    pub const fn native_status(&self) -> NativeStatus {
        NativeStatus::BlockedEnv
    }

    #[must_use]
    pub fn transport_mode(&self) -> TransportMode {
        self.provider.transport_mode()
    }

    fn ensure_provider(&self) -> Result<(), PlanetScaleServiceError> {
        let manifest = self.provider.manifest();
        manifest.validate()?;
        self.provider.registration().validate()?;
        if manifest.scope != *self.provider.scope()
            || manifest.transport_mode != self.provider.transport_mode()
            || manifest.native_status.is_native()
        {
            return Err(PlanetScaleBranchResultError::ProviderManifestMismatch {
                field: "service.provider_binding",
            });
        }
        Ok(())
    }

    fn ensure_proposal_binding(
        &self,
        proposal: &BranchResultProposal,
    ) -> Result<(), PlanetScaleServiceError> {
        if proposal.scope != *self.provider.scope() {
            return Err(PlanetScaleBranchResultError::ScopeMismatch {
                field: "proposal.scope",
            });
        }
        if proposal.provider_manifest_digest != self.provider.manifest().digest() {
            return Err(PlanetScaleBranchResultError::ProviderManifestMismatch {
                field: "proposal.provider_manifest_digest",
            });
        }
        if proposal.registration_digest != self.provider.registration().registration_digest {
            return Err(PlanetScaleBranchResultError::RegistrationMismatch);
        }
        Ok(())
    }

    fn failure_evidence(
        &self,
        proposal: &BranchResultProposal,
        error: PlanetScaleProviderError,
    ) -> Result<BranchResultEvidence, PlanetScaleServiceError> {
        let (state, failure) = match error {
            PlanetScaleProviderError::PermissionDenied => {
                (EvidenceState::Denied, FailureKind::PermissionDenied)
            }
            PlanetScaleProviderError::NotFound => {
                (EvidenceState::AccessLost, FailureKind::NotFound)
            }
            PlanetScaleProviderError::Conflict => (EvidenceState::Stale, FailureKind::Conflict),
            PlanetScaleProviderError::RateLimited { .. } => {
                (EvidenceState::RateLimited, FailureKind::RateLimited)
            }
            PlanetScaleProviderError::TimedOut => (EvidenceState::Partial, FailureKind::TimedOut),
            PlanetScaleProviderError::BlockedEnv => {
                (EvidenceState::AccessLost, FailureKind::BlockedEnv)
            }
            PlanetScaleProviderError::RegistrationRevoked => {
                (EvidenceState::Revoked, FailureKind::RegistrationRevoked)
            }
            PlanetScaleProviderError::InvalidResponse { .. }
            | PlanetScaleProviderError::ResponseTooLarge => {
                (EvidenceState::Tampered, FailureKind::MalformedResponse)
            }
            PlanetScaleProviderError::ProviderUnknown
            | PlanetScaleProviderError::ManifestMismatch
            | PlanetScaleProviderError::ScopeMismatch
            | PlanetScaleProviderError::ConsentMismatch
            | PlanetScaleProviderError::InvalidRequest
            | PlanetScaleProviderError::DuplicateIdempotency
            | PlanetScaleProviderError::LayerTwoOnly => {
                (EvidenceState::ProviderUnknown, FailureKind::ProviderUnknown)
            }
        };
        BranchResultEvidence::failure(
            proposal,
            state,
            failure,
            self.provider.transport_mode().evidence_source(),
        )
    }
}
