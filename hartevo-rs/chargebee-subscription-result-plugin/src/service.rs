//! Mission-scoped Chargebee subscription result service.
//!
//! Provider calls are bounded GET reads. Proposal, record, and verify are
//! local typed seams; none creates a billing effect or grants kernel authority.

use std::{collections::BTreeMap, fmt};

use crate::{
    CONTRACT_VERSION, ChargebeeEvidence, ChargebeeObservationState, ChargebeeOperationStatus,
    ChargebeeProvider, ChargebeeProviderError, ChargebeeReadBackVerification,
    ChargebeeReadEvidence, ChargebeeReadOperation, ChargebeeReadRequest, ChargebeeRecordingReceipt,
    ChargebeeRegistration, ChargebeeSubscriptionResultContract, ChargebeeSubscriptionResultError,
    ChargebeeSubscriptionResultProposal, ChargebeeSubscriptionScope, ChargebeeTransport,
    ChargebeeVerification, Digest, EVIDENCE_SCHEMA, PLUGIN_VERSION_TEXT, PROVIDER_ID,
    PROVIDER_IMPLEMENTATION, SecretReference, contract_digest,
};

/// Service operations exposed by the Layer-1 root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChargebeeServiceOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    ReadSubscription,
    ReadEntitlements,
    ReadInvoices,
    ReadUsage,
    CompileProposal,
    RecordProposal,
    VerifyProposal,
    VerifyReadBack,
}

impl ChargebeeServiceOperation {
    pub const ALL: [Self; 11] = [
        Self::DescribeCapabilities,
        Self::Register,
        Self::RevokeRegistration,
        Self::ReadSubscription,
        Self::ReadEntitlements,
        Self::ReadInvoices,
        Self::ReadUsage,
        Self::CompileProposal,
        Self::RecordProposal,
        Self::VerifyProposal,
        Self::VerifyReadBack,
    ];

    pub const fn is_provider_write(self) -> bool {
        false
    }

    pub const fn is_read_only(self) -> bool {
        true
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::DescribeCapabilities => "describe_capabilities",
            Self::Register => "register",
            Self::RevokeRegistration => "revoke_registration",
            Self::ReadSubscription => "read_subscription",
            Self::ReadEntitlements => "read_entitlements",
            Self::ReadInvoices => "read_invoices",
            Self::ReadUsage => "read_usage",
            Self::CompileProposal => "compile_proposal",
            Self::RecordProposal => "record_proposal",
            Self::VerifyProposal => "verify_proposal",
            Self::VerifyReadBack => "verify_read_back",
        }
    }

    pub const fn read_operation(self) -> Option<ChargebeeReadOperation> {
        match self {
            Self::ReadSubscription => Some(ChargebeeReadOperation::Subscription),
            Self::ReadEntitlements => Some(ChargebeeReadOperation::Entitlements),
            Self::ReadInvoices => Some(ChargebeeReadOperation::Invoices),
            Self::ReadUsage => Some(ChargebeeReadOperation::Usage),
            _ => None,
        }
    }
}

/// Capability descriptor for UI/host inspection. It is descriptive only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChargebeeCapability {
    pub operation: ChargebeeServiceOperation,
    pub read_only: bool,
    pub bounded: bool,
    pub arbitrary_query: bool,
    pub provider_write: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
}

/// Request for one aggregate proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChargebeeEvidenceProposalRequest {
    pub observed_at_ms: u64,
    pub limit: u16,
    pub entitlements_cursor: Option<crate::ChargebeeCursor>,
    pub invoices_cursor: Option<crate::ChargebeeCursor>,
}

impl ChargebeeEvidenceProposalRequest {
    pub fn new(observed_at_ms: u64) -> Self {
        Self {
            observed_at_ms,
            limit: crate::MAX_PAGE_SIZE,
            entitlements_cursor: None,
            invoices_cursor: None,
        }
    }

    #[must_use]
    pub fn with_limit(mut self, limit: u16) -> Self {
        self.limit = limit;
        self
    }

    #[must_use]
    pub fn with_entitlements_cursor(mut self, cursor: crate::ChargebeeCursor) -> Self {
        self.entitlements_cursor = Some(cursor);
        self
    }

    #[must_use]
    pub fn with_invoices_cursor(mut self, cursor: crate::ChargebeeCursor) -> Self {
        self.invoices_cursor = Some(cursor);
        self
    }
}

/// The typed Chargebee subscription result service.
pub struct ChargebeeSubscriptionResultService<T> {
    scope: ChargebeeSubscriptionScope,
    secret: SecretReference,
    provider: ChargebeeProvider<T>,
    registration: ChargebeeRegistration,
    recorded: BTreeMap<String, ChargebeeRecordingReceipt>,
}

impl<T: ChargebeeTransport> fmt::Debug for ChargebeeSubscriptionResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChargebeeSubscriptionResultService")
            .field("scope", &self.scope)
            .field("secret", &self.secret)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("recorded", &self.recorded.len())
            .finish()
    }
}

impl<T: ChargebeeTransport> ChargebeeSubscriptionResultService<T> {
    pub fn new(
        scope: ChargebeeSubscriptionScope,
        secret: SecretReference,
        provider: ChargebeeProvider<T>,
    ) -> Result<Self, ChargebeeSubscriptionResultError> {
        scope.validate()?;
        ChargebeeSubscriptionResultContract::baseline()?;
        provider
            .definition()
            .validate()
            .map_err(|error| ChargebeeSubscriptionResultError::Provider(error.to_string()))?;
        if provider.permission_digest() != scope.permission_digest()
            || secret.scope_digest() != scope.scope_digest()
        {
            return Err(ChargebeeSubscriptionResultError::ProviderMismatch);
        }
        let registration = ChargebeeRegistration::new(
            &scope,
            contract_digest(),
            provider.provider_digest(),
            provider.permission_digest().clone(),
            Digest::from_text(EVIDENCE_SCHEMA),
        );
        Ok(Self {
            scope,
            secret,
            provider,
            registration,
            recorded: BTreeMap::new(),
        })
    }

    pub fn register(&mut self) -> Result<&ChargebeeRegistration, ChargebeeSubscriptionResultError> {
        self.ensure_registration()?;
        Ok(&self.registration)
    }

    pub fn scope(&self) -> &ChargebeeSubscriptionScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret
    }

    pub fn registration(&self) -> &ChargebeeRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut ChargebeeRegistration {
        &mut self.registration
    }

    pub fn provider(&self) -> &ChargebeeProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut ChargebeeProvider<T> {
        &mut self.provider
    }

    pub const fn is_active(&self) -> bool {
        self.registration.is_active() && !self.secret.is_revoked()
    }

    pub fn revoke_registration(&mut self) -> Result<(), ChargebeeSubscriptionResultError> {
        self.registration
            .revoke()
            .map_err(ChargebeeSubscriptionResultError::from)
    }

    pub fn revoke_secret(&mut self) -> Result<(), ChargebeeSubscriptionResultError> {
        self.secret
            .revoke()
            .map_err(ChargebeeSubscriptionResultError::from)
    }

    pub const fn native_connected(&self) -> bool {
        false
    }

    pub const fn service_id(&self) -> &'static str {
        crate::SERVICE_ID
    }

    pub const fn service_implementation(&self) -> &'static str {
        crate::SERVICE_ID
    }

    pub const fn version(&self) -> hartevo_plugin_runtime::PluginVersion {
        crate::plugin_version()
    }

    pub fn describe_capabilities(&self) -> Vec<ChargebeeCapability> {
        ChargebeeServiceOperation::ALL
            .into_iter()
            .map(|operation| ChargebeeCapability {
                operation,
                read_only: operation.is_read_only(),
                bounded: true,
                arbitrary_query: false,
                provider_write: operation.is_provider_write(),
                native: false,
                connected: false,
                first_party: false,
            })
            .collect()
    }

    /// Read one bounded page using the exact scope and registration.
    pub fn read(
        &mut self,
        operation: ChargebeeReadOperation,
        limit: u16,
        cursor: Option<crate::ChargebeeCursor>,
        observed_at_ms: u64,
    ) -> Result<ChargebeeReadEvidence, ChargebeeSubscriptionResultError> {
        self.ensure_registration()?;
        let request = ChargebeeReadRequest::new(
            &self.scope,
            &self.registration.registration_digest,
            operation,
            limit,
            cursor,
            observed_at_ms,
        )?;
        self.provider
            .read_with_secret(&request, &self.secret)
            .map_err(Self::map_provider_error)
    }

    pub fn read_subscription(
        &mut self,
        observed_at_ms: u64,
    ) -> Result<ChargebeeReadEvidence, ChargebeeSubscriptionResultError> {
        self.read(
            ChargebeeReadOperation::Subscription,
            1,
            None,
            observed_at_ms,
        )
    }

    pub fn read_entitlements(
        &mut self,
        limit: u16,
        cursor: Option<crate::ChargebeeCursor>,
        observed_at_ms: u64,
    ) -> Result<ChargebeeReadEvidence, ChargebeeSubscriptionResultError> {
        self.read(
            ChargebeeReadOperation::Entitlements,
            limit,
            cursor,
            observed_at_ms,
        )
    }

    pub fn read_invoices(
        &mut self,
        limit: u16,
        cursor: Option<crate::ChargebeeCursor>,
        observed_at_ms: u64,
    ) -> Result<ChargebeeReadEvidence, ChargebeeSubscriptionResultError> {
        self.read(
            ChargebeeReadOperation::Invoices,
            limit,
            cursor,
            observed_at_ms,
        )
    }

    pub fn read_usage(
        &mut self,
        observed_at_ms: u64,
    ) -> Result<ChargebeeReadEvidence, ChargebeeSubscriptionResultError> {
        self.read(ChargebeeReadOperation::Usage, 1, None, observed_at_ms)
    }

    /// Compile a bounded redacted proposal from subscription, entitlement,
    /// invoice, and usage reads. Typed provider availability states are
    /// projected into the proposal; tamper, stale-revision, cursor, and
    /// registration failures remain hard errors.
    pub fn propose(
        &mut self,
        request: ChargebeeEvidenceProposalRequest,
    ) -> Result<ChargebeeSubscriptionResultProposal, ChargebeeSubscriptionResultError> {
        self.ensure_registration()?;
        if request.limit == 0 || request.limit > crate::MAX_PAGE_SIZE {
            return Err(ChargebeeSubscriptionResultError::InvalidInput(
                "proposal page size is outside the contract bound".to_owned(),
            ));
        }
        let mut reads = Vec::new();
        let mut statuses = Vec::new();
        let mut idempotency_keys = Vec::new();
        self.collect_operation(
            ChargebeeReadOperation::Subscription,
            1,
            None,
            request.observed_at_ms,
            &mut reads,
            &mut statuses,
            &mut idempotency_keys,
        )?;
        self.collect_operation(
            ChargebeeReadOperation::Entitlements,
            request.limit,
            request.entitlements_cursor,
            request.observed_at_ms,
            &mut reads,
            &mut statuses,
            &mut idempotency_keys,
        )?;
        self.collect_operation(
            ChargebeeReadOperation::Invoices,
            request.limit,
            request.invoices_cursor,
            request.observed_at_ms,
            &mut reads,
            &mut statuses,
            &mut idempotency_keys,
        )?;
        self.collect_operation(
            ChargebeeReadOperation::Usage,
            1,
            None,
            request.observed_at_ms,
            &mut reads,
            &mut statuses,
            &mut idempotency_keys,
        )?;
        let evidence = ChargebeeEvidence::from_reads(
            self.scope.clone(),
            self.registration.registration_digest.clone(),
            reads,
            statuses,
        )?;
        let proposal = ChargebeeSubscriptionResultProposal::new(evidence, idempotency_keys)?;
        proposal
            .validate()
            .map_err(|_error| ChargebeeSubscriptionResultError::ProposalTampered)
            .map(|()| proposal)
    }

    pub fn compile_proposal(
        &mut self,
        request: ChargebeeEvidenceProposalRequest,
    ) -> Result<ChargebeeSubscriptionResultProposal, ChargebeeSubscriptionResultError> {
        self.propose(request)
    }

    pub fn compile_evidence_proposal(
        &mut self,
        request: ChargebeeEvidenceProposalRequest,
    ) -> Result<ChargebeeSubscriptionResultProposal, ChargebeeSubscriptionResultError> {
        self.propose(request)
    }

    /// Record a proposal locally. Repeating the exact idempotency key returns
    /// the original receipt; a conflicting digest fails closed.
    pub fn record(
        &mut self,
        proposal: &ChargebeeSubscriptionResultProposal,
    ) -> Result<ChargebeeRecordingReceipt, ChargebeeSubscriptionResultError> {
        self.verify(proposal)?;
        if proposal.idempotency_keys.is_empty() {
            return Err(ChargebeeSubscriptionResultError::IdempotencyConflict);
        }
        let record_key =
            Digest::from_fields(proposal.idempotency_keys.iter().map(String::as_str)).to_string();
        if let Some(existing) = self.recorded.get(&record_key) {
            if existing.proposal_digest == proposal.proposal_digest {
                return Ok(existing.clone());
            }
            return Err(ChargebeeSubscriptionResultError::IdempotencyConflict);
        }
        let receipt = ChargebeeRecordingReceipt::new(proposal)?;
        self.recorded.insert(record_key, receipt.clone());
        Ok(receipt)
    }

    /// Verify proposal integrity and all Layer-1 authority fences.
    pub fn verify(
        &self,
        proposal: &ChargebeeSubscriptionResultProposal,
    ) -> Result<ChargebeeVerification, ChargebeeSubscriptionResultError> {
        self.ensure_registration()?;
        if proposal.scope_digest != *self.scope.scope_digest()
            || proposal.registration_digest != self.registration.registration_digest
        {
            return Err(ChargebeeSubscriptionResultError::ScopeMismatch);
        }
        proposal
            .validate()
            .map_err(|_| ChargebeeSubscriptionResultError::ProposalTampered)?;
        ChargebeeVerification::new(proposal).map_err(ChargebeeSubscriptionResultError::from)
    }

    /// Verify a later typed read-back against the original aggregate evidence.
    pub fn verify_read_back(
        &self,
        first: &ChargebeeEvidence,
        read_back: &ChargebeeEvidence,
    ) -> Result<ChargebeeReadBackVerification, ChargebeeSubscriptionResultError> {
        self.ensure_registration()?;
        if first.scope.scope_digest != *self.scope.scope_digest()
            || read_back.scope.scope_digest != *self.scope.scope_digest()
            || first.registration_digest != self.registration.registration_digest
            || read_back.registration_digest != self.registration.registration_digest
        {
            return Err(ChargebeeSubscriptionResultError::ScopeMismatch);
        }
        let verification = ChargebeeReadBackVerification::new(first, read_back)
            .map_err(ChargebeeSubscriptionResultError::from)?;
        if !verification.matched {
            return Err(ChargebeeSubscriptionResultError::ReadBackMismatch);
        }
        Ok(verification)
    }

    pub fn verify_readback(
        &self,
        first: &ChargebeeEvidence,
        read_back: &ChargebeeEvidence,
    ) -> Result<ChargebeeReadBackVerification, ChargebeeSubscriptionResultError> {
        self.verify_read_back(first, read_back)
    }

    fn collect_operation(
        &mut self,
        operation: ChargebeeReadOperation,
        limit: u16,
        cursor: Option<crate::ChargebeeCursor>,
        observed_at_ms: u64,
        reads: &mut Vec<ChargebeeReadEvidence>,
        statuses: &mut Vec<ChargebeeOperationStatus>,
        idempotency_keys: &mut Vec<String>,
    ) -> Result<(), ChargebeeSubscriptionResultError> {
        let request = ChargebeeReadRequest::new(
            &self.scope,
            &self.registration.registration_digest,
            operation,
            limit,
            cursor,
            observed_at_ms,
        )?;
        idempotency_keys.push(request.idempotency_key.clone());
        match self.provider.read_with_secret(&request, &self.secret) {
            Ok(read) => {
                statuses.push(ChargebeeOperationStatus {
                    operation,
                    state: read.state,
                    retry_after_seconds: read.response_receipt.retry_after_seconds,
                });
                reads.push(read);
                Ok(())
            }
            Err(error) if error.is_projection_state() => {
                statuses.push(ChargebeeOperationStatus {
                    operation,
                    state: observation_state_for_error(&error),
                    retry_after_seconds: self.provider.retry_after_seconds(&error),
                });
                Ok(())
            }
            Err(error) => Err(Self::map_provider_error(error)),
        }
    }

    fn ensure_registration(&self) -> Result<(), ChargebeeSubscriptionResultError> {
        if !self.registration.is_active() {
            return Err(ChargebeeSubscriptionResultError::RegistrationRevoked);
        }
        if self.secret.is_revoked() {
            return Err(ChargebeeSubscriptionResultError::SecretRevoked);
        }
        if self.secret.scope_digest() != self.scope.scope_digest() {
            return Err(ChargebeeSubscriptionResultError::RegistrationDrift(
                "secret scope digest drifted".to_owned(),
            ));
        }
        self.registration.validate(&self.scope).map_err(|error| {
            ChargebeeSubscriptionResultError::RegistrationDrift(error.to_string())
        })?;
        self.provider
            .definition()
            .validate()
            .map_err(|error| ChargebeeSubscriptionResultError::Provider(error.to_string()))?;
        if self.registration.provider_digest != self.provider.provider_digest()
            || self.registration.permission_digest != *self.provider.permission_digest()
            || self.registration.provider_revision != *self.provider.provider_revision()
            || self.registration.provider_id != PROVIDER_ID
            || self.registration.provider_implementation != PROVIDER_IMPLEMENTATION
            || self.registration.provider_version != PLUGIN_VERSION_TEXT
            || self.registration.contract_version != CONTRACT_VERSION
            || self.registration.contract_digest != contract_digest()
            || self.registration.evidence_digest != Digest::from_text(EVIDENCE_SCHEMA)
        {
            return Err(ChargebeeSubscriptionResultError::RegistrationDrift(
                "provider, contract, or evidence digest fence failed".to_owned(),
            ));
        }
        Ok(())
    }

    fn map_provider_error(error: ChargebeeProviderError) -> ChargebeeSubscriptionResultError {
        match error {
            ChargebeeProviderError::Model(error) => error.into(),
            ChargebeeProviderError::Transport(error) => {
                ChargebeeSubscriptionResultError::Transport(error.to_string())
            }
            ChargebeeProviderError::Incompatible | ChargebeeProviderError::PermissionMismatch => {
                ChargebeeSubscriptionResultError::ProviderMismatch
            }
            ChargebeeProviderError::ProviderRevisionMismatch => {
                ChargebeeSubscriptionResultError::ProviderRevisionMismatch
            }
            ChargebeeProviderError::ResponseTampered => {
                ChargebeeSubscriptionResultError::ResponseTampered
            }
            ChargebeeProviderError::ScopeMismatch => {
                ChargebeeSubscriptionResultError::ScopeMismatch
            }
            ChargebeeProviderError::DuplicateIdentifier => {
                ChargebeeSubscriptionResultError::DuplicateIdentifier
            }
            ChargebeeProviderError::PaginationDrift => {
                ChargebeeSubscriptionResultError::PaginationDrift
            }
            ChargebeeProviderError::StaleRevision => {
                ChargebeeSubscriptionResultError::StaleRevision
            }
            ChargebeeProviderError::CursorMismatch => {
                ChargebeeSubscriptionResultError::CursorMismatch
            }
            ChargebeeProviderError::RateLimited {
                retry_after_seconds,
            } => ChargebeeSubscriptionResultError::RateLimited {
                retry_after_seconds,
            },
            ChargebeeProviderError::AccessLost => ChargebeeSubscriptionResultError::AccessLost,
            ChargebeeProviderError::Denied => ChargebeeSubscriptionResultError::Denied,
            ChargebeeProviderError::Absent => ChargebeeSubscriptionResultError::Absent,
            ChargebeeProviderError::Expired => ChargebeeSubscriptionResultError::Expired,
            ChargebeeProviderError::ProviderUnknown | ChargebeeProviderError::BlockedEnv => {
                ChargebeeSubscriptionResultError::ProviderUnknown
            }
            ChargebeeProviderError::SecretRevoked => {
                ChargebeeSubscriptionResultError::SecretRevoked
            }
        }
    }
}

fn observation_state_for_error(error: &ChargebeeProviderError) -> ChargebeeObservationState {
    match error {
        ChargebeeProviderError::AccessLost => ChargebeeObservationState::AccessLost,
        ChargebeeProviderError::Denied => ChargebeeObservationState::Denied,
        ChargebeeProviderError::Absent => ChargebeeObservationState::Absent,
        ChargebeeProviderError::Expired => ChargebeeObservationState::Expired,
        ChargebeeProviderError::RateLimited { .. } => ChargebeeObservationState::RateLimited,
        ChargebeeProviderError::BlockedEnv | ChargebeeProviderError::ProviderUnknown => {
            ChargebeeObservationState::ProviderUnknown
        }
        _ => ChargebeeObservationState::Tampered,
    }
}
