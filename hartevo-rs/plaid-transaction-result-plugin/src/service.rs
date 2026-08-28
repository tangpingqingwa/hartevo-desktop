//! Typed service lifecycle and local digest/replay authority.

use std::{collections::BTreeSet, fmt};

use serde::Serialize;

use crate::{
    PLAID_TRANSACTION_RESULT_CONSUMER_ID, PLAID_TRANSACTION_RESULT_CONTRACT_VERSION,
    PLAID_TRANSACTION_RESULT_PLUGIN_VERSION, PLAID_TRANSACTION_RESULT_PROVIDER_ID,
    PLAID_TRANSACTION_RESULT_SCHEMA_VERSION, PLAID_TRANSACTION_RESULT_SERVICE_ID,
    digest_serializable,
    model::{
        Digest, EvidenceAuthority, EvidenceDisposition, EvidenceProvenance, EvidenceStatus,
        PlaidTransactionResultError, PlaidTransactionResultEvidence,
        PlaidTransactionResultProposal, PlaidTransactionResultRecord, PlaidTransactionsScope,
        PluginRegistration, RedactionMetadata, Revocation, RevocationReason, SecretReference,
        TransactionState, TransactionSyncRequest,
    },
    provider::{
        PlaidProviderDescription, PlaidTransactionsProvider, ProviderSyncRead, TransportMode,
    },
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct PlaidTransactionResultServiceDefinition {
    pub service_id: String,
    pub implementation: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub schema_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub endpoint: String,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub external_writes: bool,
    pub financial_advice: bool,
    pub kernel_authority: bool,
    pub consumer_id: String,
}

impl PlaidTransactionResultServiceDefinition {
    fn new(provider: &PlaidProviderDescription, contract_digest: Digest) -> Self {
        Self {
            service_id: PLAID_TRANSACTION_RESULT_SERVICE_ID.to_owned(),
            implementation: "PlaidTransactionResultService".to_owned(),
            plugin_version: PLAID_TRANSACTION_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: PLAID_TRANSACTION_RESULT_CONTRACT_VERSION.to_owned(),
            schema_version: PLAID_TRANSACTION_RESULT_SCHEMA_VERSION.to_owned(),
            contract_digest,
            provider_id: provider.provider_id.clone(),
            endpoint: provider.endpoint.clone(),
            read_only: true,
            connected: false,
            native: false,
            external_writes: false,
            financial_advice: false,
            kernel_authority: false,
            consumer_id: PLAID_TRANSACTION_RESULT_CONSUMER_ID.to_owned(),
        }
    }
}

/// Layer-1 Plaid Transactions service. It creates bounded redacted evidence
/// and non-mutating proposals; it never creates kernel Truth, Consent, Effect,
/// Receipt, Verification, Outcome, payment, refresh, or account authority.
pub struct PlaidTransactionResultService {
    scope: PlaidTransactionsScope,
    secret_reference: SecretReference,
    provider: PlaidTransactionsProvider,
    registration: PluginRegistration,
    definition: PlaidTransactionResultServiceDefinition,
    recorded_evidence: BTreeSet<Digest>,
}

impl PlaidTransactionResultService {
    pub fn new(
        scope: PlaidTransactionsScope,
        secret_reference: SecretReference,
        provider: PlaidTransactionsProvider,
    ) -> Result<Self, PlaidTransactionResultError> {
        if &secret_reference != scope.secret_reference() {
            return Err(PlaidTransactionResultError::ScopeMismatch(
                "secret reference is not bound to the registered Products permission",
            ));
        }
        let registration = PluginRegistration::new(&scope)?;
        let definition = PlaidTransactionResultServiceDefinition::new(
            &provider.description(),
            scope.contract_digest(),
        );
        Ok(Self {
            scope,
            secret_reference,
            provider,
            registration,
            definition,
            recorded_evidence: BTreeSet::new(),
        })
    }

    pub fn scope(&self) -> &PlaidTransactionsScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &PlaidTransactionsProvider {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut PlaidTransactionsProvider {
        &mut self.provider
    }

    pub fn registration(&self) -> &PluginRegistration {
        &self.registration
    }

    pub fn definition(&self) -> &PlaidTransactionResultServiceDefinition {
        &self.definition
    }

    pub fn describe(
        &self,
    ) -> Result<PlaidTransactionResultServiceDefinition, PlaidTransactionResultError> {
        self.ensure_active()?;
        Ok(self.definition.clone())
    }

    pub fn provider_description(
        &self,
    ) -> Result<PlaidProviderDescription, PlaidTransactionResultError> {
        self.ensure_active()?;
        Ok(self.provider.description())
    }

    pub fn evidence_mode(&self) -> TransportMode {
        self.provider.mode()
    }

    /// Compile a bounded, non-mutating `/transactions/sync` proposal.
    pub fn compile_result_proposal(
        &self,
        request: &TransactionSyncRequest,
    ) -> Result<PlaidTransactionResultProposal, PlaidTransactionResultError> {
        self.ensure_active()?;
        request.validate_against(&self.scope)?;
        let proposal =
            PlaidTransactionResultProposal::new(&self.scope, &self.registration, request);
        proposal.verify_integrity()?;
        Ok(proposal)
    }

    pub fn compile_sync_proposal(
        &self,
        request: &TransactionSyncRequest,
    ) -> Result<PlaidTransactionResultProposal, PlaidTransactionResultError> {
        self.compile_result_proposal(request)
    }

    /// Read the provider and return redacted evidence. Non-ready provider
    /// states remain explicit in the returned evidence; callers that require
    /// an all-ready result can use [`Self::read_strict`].
    pub fn read(
        &mut self,
        request: &TransactionSyncRequest,
    ) -> Result<PlaidTransactionResultEvidence, PlaidTransactionResultError> {
        let proposal = self.compile_result_proposal(request)?;
        self.read_for_proposal(&proposal, request)
    }

    /// Strict read helper that fails closed for non-ready, partial, empty,
    /// stale, access-loss, provider-unknown, and blocked states.
    pub fn read_strict(
        &mut self,
        request: &TransactionSyncRequest,
    ) -> Result<PlaidTransactionResultEvidence, PlaidTransactionResultError> {
        let evidence = self.read(request)?;
        if evidence.status != EvidenceStatus::Ready {
            return Err(PlaidTransactionResultError::NonAdoptableState {
                status: evidence.status,
            });
        }
        Ok(evidence)
    }

    pub fn read_for_proposal(
        &mut self,
        proposal: &PlaidTransactionResultProposal,
        request: &TransactionSyncRequest,
    ) -> Result<PlaidTransactionResultEvidence, PlaidTransactionResultError> {
        self.ensure_active()?;
        self.validate_proposal_binding(proposal)?;
        request.validate_against(&self.scope)?;
        if proposal.request_digest != request.digest() {
            return Err(PlaidTransactionResultError::ScopeMismatch(
                "proposal is bound to a different sync request",
            ));
        }
        let provider_read = self
            .provider
            .sync(&self.scope, &self.secret_reference, request)?;
        Ok(build_evidence(
            &self.scope,
            &self.registration,
            proposal,
            &provider_read,
        ))
    }

    /// Record a local evidence digest. This is not a provider receipt and does
    /// not imply durable storage, independent read-back, or kernel authority.
    pub fn record(
        &mut self,
        proposal: &PlaidTransactionResultProposal,
        evidence: &PlaidTransactionResultEvidence,
    ) -> Result<PlaidTransactionResultRecord, PlaidTransactionResultError> {
        self.ensure_active()?;
        self.verify(proposal, evidence)?;
        if !self
            .recorded_evidence
            .insert(evidence.evidence_digest.clone())
        {
            return Err(PlaidTransactionResultError::ReplayDetected);
        }
        let record_digest = digest_serializable(&(
            &evidence.evidence_digest,
            &self.registration.registration_digest(),
            evidence.provenance,
            "local-record/v1",
        ));
        Ok(PlaidTransactionResultRecord {
            evidence_digest: evidence.evidence_digest.clone(),
            registration_digest: self.registration.registration_digest().clone(),
            record_digest,
            provenance: evidence.provenance,
            local_only: true,
            kernel_receipt: false,
            kernel_verification: false,
            kernel_outcome_adoption: false,
        })
    }

    pub fn record_result(
        &mut self,
        proposal: &PlaidTransactionResultProposal,
        evidence: &PlaidTransactionResultEvidence,
    ) -> Result<PlaidTransactionResultRecord, PlaidTransactionResultError> {
        self.record(proposal, evidence)
    }

    /// Verify local proposal/evidence bindings only.
    pub fn verify(
        &self,
        proposal: &PlaidTransactionResultProposal,
        evidence: &PlaidTransactionResultEvidence,
    ) -> Result<(), PlaidTransactionResultError> {
        self.ensure_active()?;
        self.validate_proposal_binding(proposal)?;
        evidence.verify_integrity()?;
        if evidence.registration_digest != *self.registration.registration_digest()
            || evidence.contract_digest != self.scope.contract_digest()
            || evidence.provider_digest != self.scope.provider_digest()
            || evidence.permission_digest != self.scope.permission_digest()
            || evidence.scope_digest != self.scope.digest()
            || evidence.proposal_digest != proposal.proposal_digest
            || evidence.request_digest != proposal.request_digest
            || evidence.authority.connected
            || evidence.authority.native
            || evidence.authority.external_writes
            || evidence.authority.durable_provider_receipt
            || evidence.authority.independent_read_back
            || evidence.authority.financial_advice
            || evidence.authority.kernel_authority
            || evidence.redaction.raw_payload_retained
            || evidence.redaction.raw_secret_retained
            || evidence.redaction.raw_cursor_retained
            || evidence.redaction.raw_account_data_retained
            || evidence.redaction.raw_merchant_data_retained
            || evidence.redaction.raw_geolocation_retained
        {
            return Err(PlaidTransactionResultError::ScopeMismatch(
                "evidence is not bound to the active non-native registration",
            ));
        }
        Ok(())
    }

    pub fn revoke_registration(
        &mut self,
        revision: u64,
        reason: RevocationReason,
    ) -> Result<Revocation, PlaidTransactionResultError> {
        self.registration.revoke(revision, reason)
    }

    pub fn revoke_secret(
        &mut self,
        revision: u64,
        reason: RevocationReason,
    ) -> Result<Revocation, PlaidTransactionResultError> {
        self.registration.revoke_secret(revision, reason)
    }

    pub fn restore(&mut self) -> Result<(), PlaidTransactionResultError> {
        self.registration.restore()
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    fn ensure_active(&self) -> Result<(), PlaidTransactionResultError> {
        self.registration.validate_against(&self.scope)
    }

    fn validate_proposal_binding(
        &self,
        proposal: &PlaidTransactionResultProposal,
    ) -> Result<(), PlaidTransactionResultError> {
        proposal.verify_integrity()?;
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.permission_digest != self.scope.permission_digest()
            || proposal.provider_id != PLAID_TRANSACTION_RESULT_PROVIDER_ID
            || proposal.api_version != self.scope.api_version()
            || !proposal.non_mutating
        {
            return Err(PlaidTransactionResultError::ScopeMismatch(
                "proposal is not bound to the active non-mutating registration",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for PlaidTransactionResultService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlaidTransactionResultService")
            .field("scope_digest", &self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("definition", &self.definition)
            .field("recorded_evidence_count", &self.recorded_evidence.len())
            .finish()
    }
}

fn build_evidence(
    scope: &PlaidTransactionsScope,
    registration: &PluginRegistration,
    proposal: &PlaidTransactionResultProposal,
    read: &ProviderSyncRead,
) -> PlaidTransactionResultEvidence {
    let added_count = read
        .transactions
        .iter()
        .filter(|transaction| {
            transaction.state == TransactionState::Pending
                || transaction.state == TransactionState::Posted
        })
        .count();
    let modified_count = read
        .transactions
        .iter()
        .filter(|transaction| transaction.state == TransactionState::Modified)
        .count();
    let removed_count = read
        .transactions
        .iter()
        .filter(|transaction| transaction.state == TransactionState::Removed)
        .count();
    let disposition = match read.status {
        EvidenceStatus::Ready => EvidenceDisposition::Proposal,
        EvidenceStatus::NotReady => EvidenceDisposition::NotReady,
        EvidenceStatus::Partial => EvidenceDisposition::Partial,
        EvidenceStatus::Stale => EvidenceDisposition::Stale,
        EvidenceStatus::AccessLost => EvidenceDisposition::AccessLost,
        EvidenceStatus::Empty => EvidenceDisposition::Empty,
        EvidenceStatus::BlockedEnv => EvidenceDisposition::BlockedEnv,
        EvidenceStatus::ProviderUnknown => EvidenceDisposition::ProviderUnknown,
    };
    let provenance = match read.mode {
        TransportMode::Fixture => EvidenceProvenance::Fixture,
        TransportMode::Recording => EvidenceProvenance::Recording,
        TransportMode::Loopback => EvidenceProvenance::Loopback,
        TransportMode::BlockedEnv => EvidenceProvenance::BlockedEnv,
    };
    let high_water_digest = digest_serializable(&(&read.cursor_after_digest, &read.transactions));
    let mut evidence = PlaidTransactionResultEvidence {
        schema_version: PLAID_TRANSACTION_RESULT_SCHEMA_VERSION.to_owned(),
        contract_version: PLAID_TRANSACTION_RESULT_CONTRACT_VERSION.to_owned(),
        plugin_version: PLAID_TRANSACTION_RESULT_PLUGIN_VERSION.to_owned(),
        service_id: PLAID_TRANSACTION_RESULT_SERVICE_ID.to_owned(),
        provider_id: PLAID_TRANSACTION_RESULT_PROVIDER_ID.to_owned(),
        api_version: scope.api_version().to_owned(),
        registration_digest: registration.registration_digest().clone(),
        contract_digest: scope.contract_digest(),
        provider_digest: scope.provider_digest(),
        permission_digest: scope.permission_digest(),
        scope_digest: scope.digest(),
        proposal_digest: proposal.proposal_digest.clone(),
        request_digest: read.request_digest.clone(),
        response_digest: read.response_digest.clone(),
        failure_digest: read.failure_digest.clone(),
        cursor_before_digest: read.cursor_before_digest.clone(),
        cursor_after_digest: read.cursor_after_digest.clone(),
        high_water_digest,
        transaction_revision: scope.transaction_revision().clone(),
        update_window: scope.update_window().clone(),
        status: read.status,
        update_status: read.update_status,
        provenance,
        disposition,
        page_count: read.page_count,
        restart_count: read.restart_count,
        transaction_count: read.transactions.len(),
        added_count,
        modified_count,
        removed_count,
        has_more: read.has_more,
        request_id_digests: read.request_id_digests.clone(),
        transactions: read.transactions.clone(),
        authority: EvidenceAuthority::non_native(),
        redaction: RedactionMetadata::default(),
        evidence_digest: Digest::sha256(b"uninitialized-plaid-evidence"),
    };
    evidence.evidence_digest = evidence.calculate_digest();
    evidence
}
