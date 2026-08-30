//! Controlled Shopify Effect Broker adapter.
//!
//! The adapter is intentionally a small composition layer.  A caller supplies
//! one already validated [`ShopifyApprovedDraftFulfillment`] and one typed
//! [`ShopifyTypedEffectBoundary`]; this module exposes independent Broker
//! handles over the same in-memory boundary state.  It does not create an
//! approval, reconstruct a provider payload, or register a production
//! provider.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};

use chrono::Utc;
use hartevo_commerce_connector::shopify::SHOPIFY_PROVIDER_ID;
use hartevo_commerce_connector::shopify_effect::{
    SHOPIFY_FULFILLMENT_CAPABILITY, ShopifyProviderReceipt, shopify_fulfillment_provider_digest,
};
use hartevo_commerce_connector::shopify_effect_reconcile::{
    ShopifyApprovedDraftFulfillment, ShopifyEffectBoundaryReadback, ShopifyEffectBoundaryReceipt,
    ShopifyExactFulfillmentReadback, ShopifyTypedEffectBoundary,
};
use hartevo_connector_sdk::{
    ConnectorError, ProviderProvenanceClass, ReceiptCandidate, ReceiptCandidateStatus,
    ReconciliationStatus as ConnectorReconciliationStatus,
    VerificationObservation as ConnectorVerificationObservation,
    VerificationStatus as ConnectorVerificationStatus,
};
use hartevo_domain_kernel::{
    AccountId, ApprovalDecision, Effect, EffectId, EffectStatus, Receipt, ReceiptId, Verification,
    VerificationId, VerificationStatus,
};
use hartevo_effect_broker::{
    EffectExecutor, EffectReconciler, EffectVerifier, ProviderFailure, ReconciliationObservation,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Stable metadata for the Application-side composition. This is not a live
/// provider registration and carries no network or credential authority.
pub const SHOPIFY_APPLICATION_ADAPTER_ID: &str = "application.shopify.fulfillment.effect";

/// Errors deliberately contain no provider payload, draft, token, or raw
/// boundary error text. Callers can use the variants as redacted failure
/// classes while diagnostics remain metadata-only.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShopifyAdapterError {
    #[error("Shopify Application adapter accepts only controlled or fixture provenance")]
    UnsupportedProvenance,
    #[error("Shopify ProductionProvider is blocked in N12A")]
    ProductionProviderBlocked,
    #[error("Shopify Application adapter binding does not match the live Effect")]
    BindingMismatch,
    #[error("Shopify approved Effect or provider evidence is expired")]
    Expired,
    #[error("Shopify provider evidence is malformed or mismatched")]
    InvalidProviderEvidence,
    #[error("Shopify Application adapter state is poisoned")]
    StatePoisoned,
    #[error("Shopify Application adapter is busy or re-entered")]
    BusyOrReentrant,
    #[error("Shopify provider boundary failed closed")]
    BoundaryFailed,
    #[error("Shopify provider readback is unavailable")]
    ReadbackUnavailable,
}

struct ShopifyAdapterState<B> {
    boundary: B,
    approved: ShopifyApprovedDraftFulfillment,
    domain_binding: ShopifyDomainEffectBinding,
    provenance: ProviderProvenanceClass,
    execute_called: bool,
    last_provider_receipt: Option<ShopifyProviderReceipt>,
    last_readback: Option<ShopifyEffectBoundaryReadback>,
}

/// Exact Domain authority captured when the controlled adapter is composed.
///
/// This value is deliberately private and non-serializable. It binds one
/// in-memory provider capsule to one durable Domain Effect and its exact
/// approval/Broker authorization digests; it is not a replacement for the
/// encrypted private capsule required by N12B.
struct ShopifyDomainEffectBinding {
    effect_id: EffectId,
    approval_scope_digest: String,
    broker_authorization_digest: String,
}

impl ShopifyDomainEffectBinding {
    fn capture(effect: &Effect) -> Result<Self, ShopifyAdapterError> {
        let approval = effect
            .approval
            .as_ref()
            .ok_or(ShopifyAdapterError::BindingMismatch)?;
        if approval.decision != ApprovalDecision::Approved
            || approval.scope_digest != effect.approval_digest()
            || !is_sha256(&approval.scope_digest)
            || !is_sha256(&approval.permission_digest)
        {
            return Err(ShopifyAdapterError::BindingMismatch);
        }
        Ok(Self {
            effect_id: effect.id.clone(),
            approval_scope_digest: approval.scope_digest.clone(),
            broker_authorization_digest: approval.permission_digest.clone(),
        })
    }
}

/// A controlled Shopify provider composition. Clone the individual handles
/// with [`Self::handles`]; the handles remain independent Broker ports while
/// sharing only this private in-memory boundary state.
pub struct ShopifyEffectAdapter<B> {
    shared: Arc<Mutex<ShopifyAdapterState<B>>>,
}

impl<B> fmt::Debug for ShopifyEffectAdapter<B> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("ShopifyEffectAdapter");
        match self.shared.try_lock() {
            Ok(state) => debug
                .field("provenance", &state.provenance)
                .field("effect_id", &state.domain_binding.effect_id)
                .field("execute_called", &state.execute_called)
                .finish(),
            Err(TryLockError::Poisoned(_)) => debug.field("state", &"poisoned").finish(),
            Err(TryLockError::WouldBlock) => debug.field("state", &"busy").finish(),
        }
    }
}

/// The three independent handles consumed by the Effect Broker.
#[derive(Clone)]
pub struct ShopifyEffectAdapterHandles<B> {
    shared: Arc<Mutex<ShopifyAdapterState<B>>>,
}

impl<B> fmt::Debug for ShopifyEffectAdapterHandles<B> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("ShopifyEffectAdapterHandles");
        match self.shared.try_lock() {
            Ok(state) => debug
                .field("provenance", &state.provenance)
                .field("effect_id", &state.domain_binding.effect_id)
                .finish(),
            Err(TryLockError::Poisoned(_)) => debug.field("state", &"poisoned").finish(),
            Err(TryLockError::WouldBlock) => debug.field("state", &"busy").finish(),
        }
    }
}

/// Separate executor handle for one approved Shopify Effect.
#[derive(Clone)]
pub struct ShopifyEffectExecutor<B> {
    shared: Arc<Mutex<ShopifyAdapterState<B>>>,
}

/// Separate read-only reconciliation handle for one approved Shopify Effect.
#[derive(Clone)]
pub struct ShopifyEffectReconciler<B> {
    shared: Arc<Mutex<ShopifyAdapterState<B>>>,
}

/// Separate independent verification handle for one approved Shopify Effect.
#[derive(Clone)]
pub struct ShopifyEffectVerifier<B> {
    shared: Arc<Mutex<ShopifyAdapterState<B>>>,
}

impl<B> fmt::Debug for ShopifyEffectExecutor<B> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug_handle(formatter, "ShopifyEffectExecutor", &self.shared)
    }
}

impl<B> fmt::Debug for ShopifyEffectReconciler<B> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug_handle(formatter, "ShopifyEffectReconciler", &self.shared)
    }
}

impl<B> fmt::Debug for ShopifyEffectVerifier<B> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug_handle(formatter, "ShopifyEffectVerifier", &self.shared)
    }
}

impl<B> ShopifyEffectAdapter<B>
where
    B: ShopifyTypedEffectBoundary,
{
    /// Constructs a controlled or fixture-only composition. Production and
    /// component-harness provenance are intentionally rejected before the
    /// boundary can be called.
    pub fn new(
        boundary: B,
        approved: ShopifyApprovedDraftFulfillment,
        provenance: ProviderProvenanceClass,
        effect: &Effect,
    ) -> Result<Self, ShopifyAdapterError> {
        ensure_supported_provenance(provenance)?;
        let domain_binding = ShopifyDomainEffectBinding::capture(effect)?;
        validate_bound_effect(effect, &approved, &domain_binding, provenance)?;
        Ok(Self {
            shared: Arc::new(Mutex::new(ShopifyAdapterState {
                boundary,
                approved,
                domain_binding,
                provenance,
                execute_called: false,
                last_provider_receipt: None,
                last_readback: None,
            })),
        })
    }

    /// Convenience constructor for the only provider class used by the
    /// controlled N12A fixture.
    pub fn controlled(
        boundary: B,
        approved: ShopifyApprovedDraftFulfillment,
        effect: &Effect,
    ) -> Result<Self, ShopifyAdapterError> {
        Self::new(
            boundary,
            approved,
            ProviderProvenanceClass::ControlledProvider,
            effect,
        )
    }

    /// Convenience constructor for deterministic offline fixtures.
    pub fn fixture(
        boundary: B,
        approved: ShopifyApprovedDraftFulfillment,
        effect: &Effect,
    ) -> Result<Self, ShopifyAdapterError> {
        Self::new(boundary, approved, ProviderProvenanceClass::Fixture, effect)
    }

    /// Returns independent handles that share only the typed boundary state.
    pub fn handles(&self) -> ShopifyEffectAdapterHandles<B> {
        ShopifyEffectAdapterHandles {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Alias emphasizing the Effect Broker split.
    pub fn broker_handles(&self) -> ShopifyEffectAdapterHandles<B> {
        self.handles()
    }

    /// Returns an executor handle.
    pub fn executor(&self) -> ShopifyEffectExecutor<B> {
        ShopifyEffectExecutor {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Returns a read-only reconciliation handle.
    pub fn reconciler(&self) -> ShopifyEffectReconciler<B> {
        ShopifyEffectReconciler {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Returns an independent verification handle.
    pub fn verifier(&self) -> ShopifyEffectVerifier<B> {
        ShopifyEffectVerifier {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Checks the live Domain Effect without calling the provider boundary.
    pub fn validate_effect(&self, effect: &Effect) -> Result<(), ShopifyAdapterError> {
        let state = lock_state(&self.shared)?;
        validate_bound_effect(
            effect,
            &state.approved,
            &state.domain_binding,
            state.provenance,
        )
    }
}

impl<B> ShopifyEffectAdapterHandles<B>
where
    B: ShopifyTypedEffectBoundary,
{
    /// Splits the composition into independent mutable Broker ports.
    pub fn into_parts(
        self,
    ) -> (
        ShopifyEffectExecutor<B>,
        ShopifyEffectReconciler<B>,
        ShopifyEffectVerifier<B>,
    ) {
        (
            ShopifyEffectExecutor {
                shared: Arc::clone(&self.shared),
            },
            ShopifyEffectReconciler {
                shared: Arc::clone(&self.shared),
            },
            ShopifyEffectVerifier {
                shared: self.shared,
            },
        )
    }
}

/// Alias retained for callers that refer to the composition as a provider
/// adapter rather than an Effect adapter.
pub type ShopifyProviderAdapter<B> = ShopifyEffectAdapter<B>;

/// Constructs a controlled/fixture Shopify Application adapter.
pub fn compose_shopify_effect_adapter<B>(
    boundary: B,
    approved: ShopifyApprovedDraftFulfillment,
    provenance: ProviderProvenanceClass,
    effect: &Effect,
) -> Result<ShopifyEffectAdapter<B>, ShopifyAdapterError>
where
    B: ShopifyTypedEffectBoundary,
{
    ShopifyEffectAdapter::new(boundary, approved, provenance, effect)
}

/// Constructs the controlled-provider variant without exposing a production
/// provenance choice to a fixture caller.
pub fn compose_controlled_shopify_effect_adapter<B>(
    boundary: B,
    approved: ShopifyApprovedDraftFulfillment,
    effect: &Effect,
) -> Result<ShopifyEffectAdapter<B>, ShopifyAdapterError>
where
    B: ShopifyTypedEffectBoundary,
{
    ShopifyEffectAdapter::controlled(boundary, approved, effect)
}

impl<B> EffectExecutor for ShopifyEffectExecutor<B>
where
    B: ShopifyTypedEffectBoundary,
{
    fn execute(&mut self, effect: &Effect) -> Result<Receipt, ProviderFailure> {
        let now = Utc::now();
        let Ok(mut state) = lock_state(&self.shared) else {
            return Err(rejected_failure());
        };
        if validate_execution_effect(
            effect,
            &state.approved,
            &state.domain_binding,
            state.provenance,
            now,
        )
        .is_err()
        {
            return Err(rejected_failure());
        }
        if state.execute_called {
            return Err(uncertain_failure());
        }
        // Set the one-shot fence before entering the typed boundary. A timeout
        // or malformed response therefore cannot make this Effect executable
        // a second time through another cloned handle.
        state.execute_called = true;
        let boundary_result = {
            let approved = state.approved.clone();
            state.boundary.execute(&approved)
        };
        match boundary_result {
            Ok(boundary_receipt) => {
                // Provider evidence is created by the boundary call, so its
                // upper time bound must be sampled after that call returns.
                let observed_now = Utc::now();
                if validate_boundary_receipt(
                    effect,
                    &state.approved,
                    &boundary_receipt,
                    state.provenance,
                    observed_now,
                )
                .is_err()
                {
                    return Err(uncertain_failure());
                }
                state.last_provider_receipt = Some(boundary_receipt.provider_receipt.clone());
                map_domain_receipt(effect, &boundary_receipt).map_err(|_| uncertain_failure())
            }
            Err(ConnectorError::ProviderRejected) => Err(rejected_failure()),
            Err(_) => Err(uncertain_failure()),
        }
    }
}

impl<B> EffectReconciler for ShopifyEffectReconciler<B>
where
    B: ShopifyTypedEffectBoundary,
{
    fn reconcile(&mut self, effect: &Effect) -> ReconciliationObservation {
        let Ok(mut state) = lock_state(&self.shared) else {
            return fallback_reconciliation("state-lock");
        };
        if validate_reconciliation_effect(
            effect,
            &state.approved,
            &state.domain_binding,
            state.provenance,
        )
        .is_err()
        {
            return fallback_reconciliation("effect-binding");
        }
        let Ok(readback) = fetch_readback(&mut state) else {
            return fallback_reconciliation("provider-readback");
        };
        map_reconciliation(effect, &state.approved, &readback)
            .unwrap_or_else(|_| fallback_reconciliation("readback-evidence"))
    }
}

impl<B> EffectVerifier for ShopifyEffectVerifier<B>
where
    B: ShopifyTypedEffectBoundary,
{
    fn verify(&mut self, effect: &Effect, receipt: &Receipt) -> Verification {
        let Ok(mut state) = lock_state(&self.shared) else {
            return inconclusive_verification(receipt, Utc::now());
        };
        if validate_verification_effect(
            effect,
            receipt,
            &state.approved,
            &state.domain_binding,
            state.provenance,
        )
        .is_err()
        {
            return rejected_verification(receipt, false, receipt.accepted_at);
        }
        let readback = match fetch_readback_for_verification(&mut state) {
            Ok(readback) => readback,
            Err(
                ShopifyAdapterError::InvalidProviderEvidence | ShopifyAdapterError::BindingMismatch,
            ) => return rejected_verification(receipt, false, receipt.accepted_at),
            Err(_) => return inconclusive_verification(receipt, Utc::now()),
        };
        let Some(candidate) = readback.receipt.as_ref() else {
            return inconclusive_verification(receipt, readback.reconciliation.observed_at());
        };
        let Some(exact_readback) = readback.exact_readback.as_ref() else {
            return inconclusive_verification(receipt, readback.reconciliation.observed_at());
        };
        let mapped_receipt =
            map_domain_receipt_from_parts(effect, candidate, &exact_readback.provider_receipt);
        if readback.reconciliation.status() != ConnectorReconciliationStatus::ReceiptFound
            || !mapped_receipt
                .as_ref()
                .is_ok_and(|mapped| mapped == receipt)
        {
            return rejected_verification(receipt, false, readback.reconciliation.observed_at());
        }
        let provider_result = {
            let approved = state.approved.clone();
            state.boundary.verify(&approved, &readback)
        };
        let Ok(provider_verification) = provider_result else {
            return inconclusive_verification(receipt, Utc::now());
        };
        map_domain_verification(
            effect,
            receipt,
            candidate,
            &provider_verification,
            Utc::now(),
        )
    }
}

fn ensure_supported_provenance(
    provenance: ProviderProvenanceClass,
) -> Result<(), ShopifyAdapterError> {
    match provenance {
        ProviderProvenanceClass::ControlledProvider | ProviderProvenanceClass::Fixture => Ok(()),
        ProviderProvenanceClass::ProductionProvider => {
            Err(ShopifyAdapterError::ProductionProviderBlocked)
        }
        ProviderProvenanceClass::ComponentHarness => {
            Err(ShopifyAdapterError::UnsupportedProvenance)
        }
    }
}

fn lock_state<B>(
    shared: &Arc<Mutex<ShopifyAdapterState<B>>>,
) -> Result<MutexGuard<'_, ShopifyAdapterState<B>>, ShopifyAdapterError> {
    match shared.try_lock() {
        Ok(state) => Ok(state),
        Err(TryLockError::Poisoned(_)) => Err(ShopifyAdapterError::StatePoisoned),
        Err(TryLockError::WouldBlock) => Err(ShopifyAdapterError::BusyOrReentrant),
    }
}

fn debug_handle<B>(
    formatter: &mut fmt::Formatter<'_>,
    name: &str,
    shared: &Arc<Mutex<ShopifyAdapterState<B>>>,
) -> fmt::Result {
    let mut debug = formatter.debug_struct(name);
    match shared.try_lock() {
        Ok(state) => debug
            .field("provenance", &state.provenance)
            .field("effect_id", &state.domain_binding.effect_id)
            .finish(),
        Err(TryLockError::Poisoned(_)) => debug.field("state", &"poisoned").finish(),
        Err(TryLockError::WouldBlock) => debug.field("state", &"busy").finish(),
    }
}

fn validate_bound_effect(
    effect: &Effect,
    approved: &ShopifyApprovedDraftFulfillment,
    binding: &ShopifyDomainEffectBinding,
    provenance: ProviderProvenanceClass,
) -> Result<(), ShopifyAdapterError> {
    ensure_supported_provenance(provenance)?;
    let draft = approved.draft();
    let scope = draft.tenant_scope().connector_scope();
    let approval = effect
        .approval
        .as_ref()
        .ok_or(ShopifyAdapterError::BindingMismatch)?;
    approved
        .validate_at(approval.decided_at)
        .map_err(|_| ShopifyAdapterError::BindingMismatch)?;
    if approval.decision != ApprovalDecision::Approved
        || approval.scope_digest != effect.approval_digest()
        || effect.id != binding.effect_id
        || approval.scope_digest != binding.approval_scope_digest
        || approval.permission_digest != binding.broker_authorization_digest
        || approval.permission_digest != approved.execution_context().authorization_digest()
        || approval.valid_until > effect.expires_at
        || approval.decided_at >= approval.valid_until
        || effect.tenant_id.as_str() != scope.tenant_id()
        || effect.project_id.as_str() != scope.project_id()
        || effect.mission_id.as_str() != draft.mission_id()
        || effect.provider != SHOPIFY_PROVIDER_ID
        || effect.provider != scope.provider_id()
        || effect.capability != SHOPIFY_FULFILLMENT_CAPABILITY
        || effect.account_id.as_ref().map(AccountId::as_str) != Some(scope.account_id())
        || effect.required_scopes != *scope.scopes()
        || effect.payload_digest != draft.request_digest()
        || effect.idempotency_key != draft.idempotency_key().as_str()
        || effect.expires_at != draft.expires_at()
        || effect.expires_at != approved.prepared_effect().expires_at()
    {
        return Err(ShopifyAdapterError::BindingMismatch);
    }
    Ok(())
}

fn validate_execution_effect(
    effect: &Effect,
    approved: &ShopifyApprovedDraftFulfillment,
    binding: &ShopifyDomainEffectBinding,
    provenance: ProviderProvenanceClass,
    now: chrono::DateTime<Utc>,
) -> Result<(), ShopifyAdapterError> {
    validate_bound_effect(effect, approved, binding, provenance)?;
    let approval = effect
        .approval
        .as_ref()
        .ok_or(ShopifyAdapterError::BindingMismatch)?;
    if effect.status != EffectStatus::Approved
        || approval.valid_until <= now
        || effect.expires_at <= now
    {
        return Err(ShopifyAdapterError::Expired);
    }
    approved
        .validate_at(now)
        .map_err(|_| ShopifyAdapterError::Expired)
}

fn validate_reconciliation_effect(
    effect: &Effect,
    approved: &ShopifyApprovedDraftFulfillment,
    binding: &ShopifyDomainEffectBinding,
    provenance: ProviderProvenanceClass,
) -> Result<(), ShopifyAdapterError> {
    validate_bound_effect(effect, approved, binding, provenance)?;
    if effect.status != EffectStatus::VerificationRequired || effect.receipt.is_some() {
        return Err(ShopifyAdapterError::BindingMismatch);
    }
    Ok(())
}

fn validate_verification_effect(
    effect: &Effect,
    receipt: &Receipt,
    approved: &ShopifyApprovedDraftFulfillment,
    binding: &ShopifyDomainEffectBinding,
    provenance: ProviderProvenanceClass,
) -> Result<(), ShopifyAdapterError> {
    validate_bound_effect(effect, approved, binding, provenance)?;
    if effect.status != EffectStatus::ReceiptRecorded
        || effect.receipt.as_ref() != Some(receipt)
        || !domain_receipt_matches_effect(effect, receipt)
    {
        return Err(ShopifyAdapterError::BindingMismatch);
    }
    Ok(())
}

fn validate_boundary_receipt(
    effect: &Effect,
    approved: &ShopifyApprovedDraftFulfillment,
    boundary_receipt: &ShopifyEffectBoundaryReceipt,
    provenance: ProviderProvenanceClass,
    now: chrono::DateTime<Utc>,
) -> Result<(), ShopifyAdapterError> {
    validate_receipt_candidate(approved, &boundary_receipt.receipt, now)?;
    validate_provider_receipt(
        approved,
        &boundary_receipt.provider_receipt,
        provenance,
        now,
    )?;
    if effect.provider != SHOPIFY_PROVIDER_ID {
        return Err(ShopifyAdapterError::BindingMismatch);
    }
    Ok(())
}

fn validate_receipt_candidate(
    approved: &ShopifyApprovedDraftFulfillment,
    receipt: &ReceiptCandidate,
    now: chrono::DateTime<Utc>,
) -> Result<(), ShopifyAdapterError> {
    if receipt.effect_digest() != approved.prepared_effect().effect_digest()
        || receipt.scope() != approved.prepared_effect().scope()
        || receipt.idempotency_key() != approved.sdk_idempotency_key()
        || receipt.status() == ReceiptCandidateStatus::Rejected
        || receipt.observed_at() > now
        || !is_sha256(receipt.receipt_digest())
        || !is_sha256(receipt.provider_request_id_digest())
        || !is_sha256(receipt.response_digest())
    {
        return Err(ShopifyAdapterError::InvalidProviderEvidence);
    }
    Ok(())
}

fn validate_provider_receipt(
    approved: &ShopifyApprovedDraftFulfillment,
    receipt: &ShopifyProviderReceipt,
    provenance: ProviderProvenanceClass,
    now: chrono::DateTime<Utc>,
) -> Result<(), ShopifyAdapterError> {
    let draft = approved.draft();
    if !receipt.receipt_id.starts_with("shopify-provider-receipt-")
        || !receipt
            .provider_operation_id
            .starts_with("shopify-provider-op-")
        || receipt.request_digest != draft.request_digest()
        || receipt.idempotency_key != *draft.idempotency_key()
        || receipt.scope_digest != draft.tenant_scope().digest()
        || receipt.shop != *draft.tenant_scope().shop()
        || receipt.order_gid != *draft.order_gid()
        || receipt.fulfillment_order_gid != *draft.fulfillment_order_gid()
        || receipt.line_items != draft.line_items()
        || receipt.provider_generation != draft.provider_generation()
        || receipt.approval_revision != draft.approval_revision()
        || receipt.provider_digest != shopify_fulfillment_provider_digest(draft.api_version())
        || receipt.observed_at > now
        || !is_sha256(&receipt.evidence_digest)
        || receipt.provenance_class != provenance
    {
        return Err(ShopifyAdapterError::InvalidProviderEvidence);
    }
    Ok(())
}

fn validate_boundary_readback(
    approved: &ShopifyApprovedDraftFulfillment,
    readback: &ShopifyEffectBoundaryReadback,
    provenance: ProviderProvenanceClass,
    now: chrono::DateTime<Utc>,
) -> Result<(), ShopifyAdapterError> {
    let reconciliation = &readback.reconciliation;
    if reconciliation.effect_digest() != approved.prepared_effect().effect_digest()
        || reconciliation.scope() != approved.prepared_effect().scope()
        || reconciliation.observed_at() > now
        || !is_sha256(reconciliation.provider_state_digest())
        || reconciliation.freshness().validate_at(now).is_err()
    {
        return Err(ShopifyAdapterError::InvalidProviderEvidence);
    }
    if reconciliation.status() == ConnectorReconciliationStatus::ReceiptFound {
        let receipt = readback
            .receipt
            .as_ref()
            .ok_or(ShopifyAdapterError::ReadbackUnavailable)?;
        let exact = readback
            .exact_readback
            .as_ref()
            .ok_or(ShopifyAdapterError::ReadbackUnavailable)?;
        validate_receipt_candidate(approved, receipt, now)?;
        validate_exact_readback(approved, exact, provenance, now)?;
    } else if readback.receipt.is_some() || readback.exact_readback.is_some() {
        return Err(ShopifyAdapterError::InvalidProviderEvidence);
    }
    Ok(())
}

fn validate_exact_readback(
    approved: &ShopifyApprovedDraftFulfillment,
    readback: &ShopifyExactFulfillmentReadback,
    provenance: ProviderProvenanceClass,
    now: chrono::DateTime<Utc>,
) -> Result<(), ShopifyAdapterError> {
    let draft = approved.draft();
    validate_provider_receipt(approved, &readback.provider_receipt, provenance, now)?;
    if readback.scope_digest != draft.tenant_scope().digest()
        || readback.account_id != draft.tenant_scope().connector_scope().account_id()
        || readback.shop != *draft.tenant_scope().shop()
        || readback.order_gid != *draft.order_gid()
        || readback.fulfillment_order_gid != *draft.fulfillment_order_gid()
        || readback.line_items != draft.line_items()
        || readback.observed_at < readback.provider_receipt.observed_at
        || readback.observed_at > now
        || readback.provenance_class != provenance
        || !is_sha256(&readback.state_digest)
    {
        return Err(ShopifyAdapterError::InvalidProviderEvidence);
    }
    Ok(())
}

fn fetch_readback<B>(
    state: &mut ShopifyAdapterState<B>,
) -> Result<ShopifyEffectBoundaryReadback, ShopifyAdapterError>
where
    B: ShopifyTypedEffectBoundary,
{
    let readback = {
        let approved = &state.approved;
        let prior = state.last_provider_receipt.as_ref();
        state
            .boundary
            .reconcile(approved, prior)
            .map_err(|_| ShopifyAdapterError::BoundaryFailed)?
    };
    // Readback evidence is produced by the external boundary call. Sampling
    // afterwards accepts evidence created during the call without accepting a
    // future-dated observation.
    let now = Utc::now();
    validate_boundary_readback(&state.approved, &readback, state.provenance, now)?;
    if let Some(exact) = &readback.exact_readback {
        state.last_provider_receipt = Some(exact.provider_receipt.clone());
    }
    state.last_readback = Some(readback.clone());
    Ok(readback)
}

fn fetch_readback_for_verification<B>(
    state: &mut ShopifyAdapterState<B>,
) -> Result<ShopifyEffectBoundaryReadback, ShopifyAdapterError>
where
    B: ShopifyTypedEffectBoundary,
{
    if let Some(readback) = state.last_readback.clone() {
        let now = Utc::now();
        validate_boundary_readback(&state.approved, &readback, state.provenance, now)?;
        return Ok(readback);
    }
    fetch_readback(state)
}

fn map_domain_receipt(
    effect: &Effect,
    boundary_receipt: &ShopifyEffectBoundaryReceipt,
) -> Result<Receipt, ShopifyAdapterError> {
    map_domain_receipt_from_parts(
        effect,
        &boundary_receipt.receipt,
        &boundary_receipt.provider_receipt,
    )
}

fn map_domain_receipt_from_parts(
    effect: &Effect,
    candidate: &ReceiptCandidate,
    provider_receipt: &ShopifyProviderReceipt,
) -> Result<Receipt, ShopifyAdapterError> {
    if candidate.response_digest().is_empty()
        || provider_receipt.receipt_id.trim().is_empty()
        || provider_receipt.provider_operation_id.trim().is_empty()
    {
        return Err(ShopifyAdapterError::InvalidProviderEvidence);
    }
    let receipt = Receipt {
        id: ReceiptId::from_stable(provider_receipt.receipt_id.clone()),
        provider: effect.provider.clone(),
        external_id: provider_receipt.provider_operation_id.clone(),
        accepted_at: candidate.observed_at(),
        request_digest: effect.approval_digest(),
        response_digest: candidate.response_digest().to_owned(),
    };
    if !domain_receipt_matches_effect(effect, &receipt) {
        return Err(ShopifyAdapterError::InvalidProviderEvidence);
    }
    Ok(receipt)
}

fn domain_receipt_matches_effect(effect: &Effect, receipt: &Receipt) -> bool {
    receipt.provider == effect.provider
        && !receipt.external_id.trim().is_empty()
        && receipt.request_digest == effect.approval_digest()
        && is_sha256(&receipt.response_digest)
        && receipt.accepted_at < effect.expires_at
        && effect
            .approval
            .as_ref()
            .is_some_and(|approval| receipt.accepted_at >= approval.decided_at)
}

fn map_reconciliation(
    effect: &Effect,
    approved: &ShopifyApprovedDraftFulfillment,
    readback: &ShopifyEffectBoundaryReadback,
) -> Result<ReconciliationObservation, ShopifyAdapterError> {
    let observation = &readback.reconciliation;
    let evidence_digest = observation.provider_state_digest().to_owned();
    let observed_at = observation.observed_at();
    match observation.status() {
        ConnectorReconciliationStatus::ReceiptFound => {
            let candidate = readback
                .receipt
                .as_ref()
                .ok_or(ShopifyAdapterError::ReadbackUnavailable)?;
            let exact = readback
                .exact_readback
                .as_ref()
                .ok_or(ShopifyAdapterError::ReadbackUnavailable)?;
            let receipt =
                map_domain_receipt_from_parts(effect, candidate, &exact.provider_receipt)?;
            Ok(ReconciliationObservation::ReceiptFound {
                receipt,
                evidence_digest,
                observed_at,
            })
        }
        ConnectorReconciliationStatus::NotExecuted => Ok(ReconciliationObservation::NotExecuted {
            evidence_digest,
            observed_at,
        }),
        ConnectorReconciliationStatus::StillUncertain => {
            let _ = approved;
            Ok(ReconciliationObservation::StillUncertain {
                reason: "Shopify readback remains uncertain".to_owned(),
                evidence_digest,
                observed_at,
            })
        }
        ConnectorReconciliationStatus::ProviderRejected => {
            let _ = approved;
            Ok(ReconciliationObservation::ProviderRejected {
                reason: "Shopify provider rejected the operation".to_owned(),
                evidence_digest,
                observed_at,
            })
        }
    }
}

fn map_domain_verification(
    _effect: &Effect,
    receipt: &Receipt,
    candidate: &ReceiptCandidate,
    verification: &ConnectorVerificationObservation,
    observed_now: chrono::DateTime<Utc>,
) -> Verification {
    let evidence_valid = verification.subject_digest() == candidate.receipt_digest()
        && verification.scope() == candidate.scope()
        && verification.independent()
        && verification.observed_at() >= receipt.accepted_at
        && verification.observed_at() <= observed_now
        && is_sha256(verification.evidence_digest());
    let status = if evidence_valid {
        match verification.status() {
            ConnectorVerificationStatus::Confirmed => VerificationStatus::Confirmed,
            ConnectorVerificationStatus::Rejected => VerificationStatus::Rejected,
            ConnectorVerificationStatus::Inconclusive => VerificationStatus::Inconclusive,
        }
    } else {
        VerificationStatus::Rejected
    };
    let evidence_digest = if is_sha256(verification.evidence_digest()) {
        verification.evidence_digest().to_owned()
    } else {
        digest("shopify-invalid-verification")
    };
    Verification {
        id: verification_id(receipt, &evidence_digest),
        status,
        verifier: "shopify-controlled-independent-readback".to_owned(),
        independent: verification.independent() && evidence_valid,
        observed_at: verification.observed_at(),
        evidence_digest,
        receipt_id: receipt.id.clone(),
    }
}

fn rejected_verification(
    receipt: &Receipt,
    independent: bool,
    observed_at: chrono::DateTime<Utc>,
) -> Verification {
    let evidence_digest = digest("shopify-application-verification-rejected");
    Verification {
        id: verification_id(receipt, &evidence_digest),
        status: VerificationStatus::Rejected,
        verifier: "shopify-controlled-independent-readback".to_owned(),
        independent,
        observed_at: observed_at.max(receipt.accepted_at),
        evidence_digest,
        receipt_id: receipt.id.clone(),
    }
}

fn inconclusive_verification(
    receipt: &Receipt,
    observed_at: chrono::DateTime<Utc>,
) -> Verification {
    let evidence_digest = digest("shopify-application-verification-inconclusive");
    Verification {
        id: verification_id(receipt, &evidence_digest),
        status: VerificationStatus::Inconclusive,
        verifier: "shopify-controlled-independent-readback".to_owned(),
        independent: true,
        observed_at: observed_at.max(receipt.accepted_at),
        evidence_digest,
        receipt_id: receipt.id.clone(),
    }
}

fn verification_id(receipt: &Receipt, evidence_digest: &str) -> VerificationId {
    VerificationId::from_stable(format!(
        "shopify-application-verification-{}",
        digest(&format!("{}:{evidence_digest}", receipt.id.as_str()))
    ))
}

fn fallback_reconciliation(reason: &str) -> ReconciliationObservation {
    ReconciliationObservation::StillUncertain {
        reason: "Shopify Application adapter failed closed".to_owned(),
        evidence_digest: digest(reason),
        observed_at: Utc::now(),
    }
}

fn rejected_failure() -> ProviderFailure {
    ProviderFailure::Rejected("Shopify Application adapter rejected the Effect".to_owned())
}

fn uncertain_failure() -> ProviderFailure {
    ProviderFailure::Uncertain("Shopify provider state remains uncertain".to_owned())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn digest(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    use chrono::Duration;
    use hartevo_commerce_connector::shopify::{ShopDomain, ShopifyApiVersion};
    use hartevo_commerce_connector::shopify_effect::{
        DraftFulfillmentRequest, ShopifyApprovalRevision, ShopifyEffectIdempotencyKey,
        ShopifyFulfillmentLineItem, ShopifyFulfillmentOrderGid, ShopifyFulfillmentOrderLineItemGid,
        ShopifyFulfillmentScope, ShopifyOrderGid,
    };
    use hartevo_commerce_connector::shopify_effect_reconcile::{
        ShopifyEffectBoundaryReadback, ShopifyEffectBoundaryReceipt,
        ShopifyExactFulfillmentReadback, ShopifyFulfillmentGid, ShopifyPluginRevision,
        ShopifyTypedEffectBoundary,
    };
    use hartevo_connector_sdk::{
        ConnectorScope, EffectExecutionContext, FreshnessWindow, PreparedEffect,
        ReconciliationStatus as ConnectorReconciliationStatus,
        VerificationStatus as ConnectorVerificationStatus,
    };
    use hartevo_domain_kernel::{
        AccountId, ActorId, Approval, ApprovalDecision, ConnectionId, ConsentState, CurrencyCode,
        EffectClass, EffectId, EffectRisk, EffectStatus, MissionId, Money, ProjectId, TenantId,
    };
    use hartevo_effect_broker::{
        EffectExecutor as _, EffectReconciler as _, EffectVerifier as _, ProviderFailure,
        ReconciliationObservation as DomainReconciliationObservation,
    };

    use super::*;

    const READ_SCOPE: &str = "read_merchant_managed_fulfillment_orders";
    const WRITE_SCOPE: &str = "write_merchant_managed_fulfillment_orders";

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ReconcileMode {
        ReceiptFound,
        NotExecuted,
        StillUncertain,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ProviderTimeMode {
        DraftCreated,
        DuringCall,
    }

    #[derive(Clone, Debug)]
    struct BoundaryStats {
        execute: Arc<AtomicU32>,
        reconcile: Arc<AtomicU32>,
        verify: Arc<AtomicU32>,
    }

    impl BoundaryStats {
        fn new() -> Self {
            Self {
                execute: Arc::new(AtomicU32::new(0)),
                reconcile: Arc::new(AtomicU32::new(0)),
                verify: Arc::new(AtomicU32::new(0)),
            }
        }

        fn execute_calls(&self) -> u32 {
            self.execute.load(Ordering::SeqCst)
        }

        fn reconcile_calls(&self) -> u32 {
            self.reconcile.load(Ordering::SeqCst)
        }

        fn verify_calls(&self) -> u32 {
            self.verify.load(Ordering::SeqCst)
        }
    }

    type EffectMutation = Box<dyn Fn(&mut Effect)>;

    #[derive(Clone, Debug)]
    struct FakeBoundary {
        approved: ShopifyApprovedDraftFulfillment,
        stats: BoundaryStats,
        mode: ReconcileMode,
        uncertain_after_commit: bool,
        independent: bool,
        verification_status: ConnectorVerificationStatus,
        readback_mismatch: bool,
        provider_time: ProviderTimeMode,
        committed: Arc<Mutex<bool>>,
    }

    impl FakeBoundary {
        fn new(approved: ShopifyApprovedDraftFulfillment, mode: ReconcileMode) -> Self {
            Self {
                approved,
                stats: BoundaryStats::new(),
                mode,
                uncertain_after_commit: false,
                independent: true,
                verification_status: ConnectorVerificationStatus::Confirmed,
                readback_mismatch: false,
                provider_time: ProviderTimeMode::DraftCreated,
                committed: Arc::new(Mutex::new(false)),
            }
        }

        fn receipt(&self) -> ShopifyProviderReceipt {
            let draft = self.approved.draft();
            ShopifyProviderReceipt {
                receipt_id: "shopify-provider-receipt-application-test".to_owned(),
                provider_operation_id: "shopify-provider-op-application-test".to_owned(),
                request_digest: draft.request_digest().to_owned(),
                idempotency_key: draft.idempotency_key().clone(),
                scope_digest: draft.tenant_scope().digest(),
                shop: draft.tenant_scope().shop().clone(),
                order_gid: draft.order_gid().clone(),
                fulfillment_order_gid: draft.fulfillment_order_gid().clone(),
                line_items: draft.line_items().to_owned(),
                provider_generation: draft.provider_generation(),
                approval_revision: draft.approval_revision(),
                provider_digest: shopify_fulfillment_provider_digest(draft.api_version()),
                observed_at: match self.provider_time {
                    ProviderTimeMode::DraftCreated => draft.created_at(),
                    ProviderTimeMode::DuringCall => Utc::now(),
                },
                evidence_digest: digest("application-shopify-provider-receipt"),
                provenance_class: ProviderProvenanceClass::ControlledProvider,
            }
        }

        fn candidate(&self, receipt: &ShopifyProviderReceipt) -> ReceiptCandidate {
            ReceiptCandidate::new(
                self.approved.prepared_effect(),
                digest("application-shopify-provider-request"),
                ReceiptCandidateStatus::Uncertain,
                digest("application-shopify-provider-response"),
                receipt.observed_at,
            )
            .expect("receipt candidate")
        }

        fn readback(&self) -> ShopifyEffectBoundaryReadback {
            let receipt = self.receipt();
            let candidate = self.candidate(&receipt);
            let draft = self.approved.draft();
            let (status, provider_state_digest) = match self.mode {
                ReconcileMode::ReceiptFound => (
                    ConnectorReconciliationStatus::ReceiptFound,
                    digest("application-shopify-provider-state"),
                ),
                ReconcileMode::NotExecuted => (
                    ConnectorReconciliationStatus::NotExecuted,
                    digest("application-shopify-not-executed"),
                ),
                ReconcileMode::StillUncertain => (
                    ConnectorReconciliationStatus::StillUncertain,
                    digest("application-shopify-still-uncertain"),
                ),
            };
            let reconciliation = hartevo_connector_sdk::ReconciliationObservation::new(
                self.approved.prepared_effect().effect_digest().to_owned(),
                self.approved.prepared_effect().scope().clone(),
                status,
                provider_state_digest,
                receipt.observed_at,
                FreshnessWindow::new(
                    receipt.observed_at,
                    receipt.observed_at + Duration::seconds(600),
                    1,
                )
                .expect("freshness"),
            )
            .expect("reconciliation observation");
            if status != ConnectorReconciliationStatus::ReceiptFound {
                return ShopifyEffectBoundaryReadback {
                    receipt: None,
                    reconciliation,
                    exact_readback: None,
                };
            }
            let mut exact = ShopifyExactFulfillmentReadback::new(
                ShopifyFulfillmentGid::parse("gid://shopify/Fulfillment/3001")
                    .expect("fulfillment gid"),
                receipt,
                draft.tenant_scope().digest(),
                draft.tenant_scope().connector_scope().account_id(),
                draft.tenant_scope().shop().clone(),
                draft.order_gid().clone(),
                draft.fulfillment_order_gid().clone(),
                draft.line_items().to_owned(),
                hartevo_commerce_connector::shopify_effect::ShopifyReadbackStatus::Fulfilled,
                draft.created_at(),
                digest("application-shopify-exact-state"),
                ProviderProvenanceClass::ControlledProvider,
            )
            .expect("exact readback");
            if self.readback_mismatch {
                exact.account_id = "swapped-account".to_owned();
            }
            ShopifyEffectBoundaryReadback {
                receipt: Some(candidate),
                reconciliation,
                exact_readback: Some(exact),
            }
        }
    }

    impl ShopifyTypedEffectBoundary for FakeBoundary {
        fn execute(
            &mut self,
            _approved: &ShopifyApprovedDraftFulfillment,
        ) -> Result<ShopifyEffectBoundaryReceipt, ConnectorError> {
            self.stats.execute.fetch_add(1, Ordering::SeqCst);
            *self.committed.lock().expect("commit state") = true;
            if self.provider_time == ProviderTimeMode::DuringCall {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            let receipt = self.receipt();
            if self.uncertain_after_commit {
                return Err(ConnectorError::ProviderUncertain);
            }
            Ok(ShopifyEffectBoundaryReceipt {
                receipt: self.candidate(&receipt),
                provider_receipt: receipt,
            })
        }

        fn reconcile(
            &mut self,
            _approved: &ShopifyApprovedDraftFulfillment,
            _prior_provider_receipt: Option<&ShopifyProviderReceipt>,
        ) -> Result<ShopifyEffectBoundaryReadback, ConnectorError> {
            self.stats.reconcile.fetch_add(1, Ordering::SeqCst);
            if self.mode == ReconcileMode::ReceiptFound
                && !*self.committed.lock().expect("commit state")
            {
                return Ok(ShopifyEffectBoundaryReadback {
                    receipt: None,
                    reconciliation: self.readback().reconciliation,
                    exact_readback: None,
                });
            }
            Ok(self.readback())
        }

        fn verify(
            &mut self,
            _approved: &ShopifyApprovedDraftFulfillment,
            readback: &ShopifyEffectBoundaryReadback,
        ) -> Result<ConnectorVerificationObservation, ConnectorError> {
            self.stats.verify.fetch_add(1, Ordering::SeqCst);
            let receipt = readback.receipt.as_ref().expect("receipt");
            ConnectorVerificationObservation::new(
                receipt.receipt_digest().to_owned(),
                self.approved.prepared_effect().scope().clone(),
                self.verification_status,
                digest("application-shopify-verification"),
                receipt.observed_at(),
                self.independent,
            )
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_lines)]
    fn approved_and_effect(
        suffix: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> (ShopifyApprovedDraftFulfillment, Effect) {
        let scope = ShopifyFulfillmentScope::new(
            ConnectorScope::new(
                "tenant-application",
                "project-application",
                "shopify",
                "account-application",
                [READ_SCOPE.to_owned(), WRITE_SCOPE.to_owned()],
            )
            .expect("connector scope"),
            ShopDomain::parse("application.myshopify.com").expect("shop"),
        )
        .expect("Shopify scope");
        let draft = DraftFulfillmentRequest::new(
            format!("shopify-draft-fulfillment-application-{suffix}"),
            "mission-application",
            scope.clone(),
            ShopifyApiVersion::latest(),
            ShopifyOrderGid::parse("gid://shopify/Order/1001").expect("order"),
            ShopifyFulfillmentOrderGid::parse("gid://shopify/FulfillmentOrder/2001")
                .expect("fulfillment order"),
            vec![
                ShopifyFulfillmentLineItem::new(
                    ShopifyFulfillmentOrderLineItemGid::parse(
                        "gid://shopify/FulfillmentOrderLineItem/5001",
                    )
                    .expect("line item"),
                    1,
                )
                .expect("line item quantity"),
            ],
            1,
            ShopifyApprovalRevision::new(1).expect("approval revision"),
            ShopifyEffectIdempotencyKey::parse(format!("shopify-effect-idem-application-{suffix}"))
                .expect("idempotency"),
            now - Duration::seconds(1),
            now + Duration::seconds(300),
        )
        .expect("draft");
        let capability = hartevo_connector_sdk::ProviderCapabilityKey::new(
            SHOPIFY_PROVIDER_ID,
            SHOPIFY_FULFILLMENT_CAPABILITY,
        )
        .expect("capability");
        let adapter =
            hartevo_commerce_connector::shopify_effect::shopify_fulfillment_adapter_identity()
                .expect("adapter identity");
        let prepared = PreparedEffect::new(
            scope.connector_scope().clone(),
            capability,
            adapter,
            draft.request_digest().to_owned(),
            hartevo_commerce_connector::shopify_effect_reconcile::shopify_sdk_effect_idempotency_key(
                &draft,
            ),
            draft.created_at(),
            draft.expires_at(),
            0,
        )
        .expect("prepared effect");
        let authorization_digest = digest("application-shopify-authorization");
        let execution_context = EffectExecutionContext::from_broker(
            prepared.scope().clone(),
            prepared.effect_digest(),
            authorization_digest.clone(),
            draft.expires_at() + Duration::seconds(30),
        )
        .expect("execution context");
        let approved = ShopifyApprovedDraftFulfillment::new(
            draft.clone(),
            prepared,
            execution_context,
            ShopifyPluginRevision::new(1).expect("plugin revision"),
        )
        .expect("approved Shopify draft");
        let mut effect = Effect {
            id: EffectId::from_stable(format!("effect-application-{suffix}")),
            tenant_id: TenantId::from_stable("tenant-application"),
            project_id: ProjectId::from_stable("project-application"),
            mission_id: MissionId::from_stable("mission-application"),
            actor_id: ActorId::from_stable("actor-application"),
            capability: SHOPIFY_FULFILLMENT_CAPABILITY.to_owned(),
            provider: SHOPIFY_PROVIDER_ID.to_owned(),
            connection_id: Some(ConnectionId::from_stable("connection-application")),
            account_id: Some(AccountId::from_stable("account-application")),
            required_scopes: BTreeSet::from([READ_SCOPE.to_owned(), WRITE_SCOPE.to_owned()]),
            effect_class: EffectClass::ExternalWrite,
            description: "Create the approved Shopify fulfillment".to_owned(),
            target_resource: "shopify://application/fulfillment".to_owned(),
            audience_digest: None,
            payload_digest: draft.request_digest().to_owned(),
            asset_digests: BTreeSet::new(),
            scheduled_for: None,
            timezone: "UTC".to_owned(),
            consent: ConsentState::NotRequired,
            consent_record_id: None,
            consent_requirement: None,
            conversation_guard: None,
            creator_contact_guard: None,
            policy_version: "policy-application-shopify".to_owned(),
            risk: EffectRisk::High,
            idempotency_key: draft.idempotency_key().as_str().to_owned(),
            amount: Money::zero(CurrencyCode::parse("USD").expect("USD")),
            expires_at: draft.expires_at(),
            status: EffectStatus::Approved,
            approval: None,
            receipt: None,
            verification: None,
        };
        effect.approval = Some(Approval {
            id: hartevo_domain_kernel::ApprovalId::from_stable(format!(
                "approval-application-{suffix}"
            )),
            decision: ApprovalDecision::Approved,
            decided_by: ActorId::from_stable("approver-application"),
            decided_at: now - Duration::seconds(1),
            valid_until: now + Duration::seconds(200),
            scope_digest: effect.approval_digest(),
            permission_digest: authorization_digest,
        });
        (approved, effect)
    }

    fn uncertain_effect(effect: &Effect) -> Effect {
        let mut uncertain = effect.clone();
        uncertain.status = EffectStatus::VerificationRequired;
        uncertain.receipt = None;
        uncertain.verification = None;
        uncertain
    }

    fn effect_with_receipt(effect: &Effect, receipt: &Receipt) -> Effect {
        let mut with_receipt = effect.clone();
        with_receipt.status = EffectStatus::ReceiptRecorded;
        with_receipt.receipt = Some(receipt.clone());
        with_receipt.verification = None;
        with_receipt
    }

    #[test]
    fn controlled_adapter_maps_success_once_with_independent_handles() {
        let now = Utc::now();
        let (approved, effect) = approved_and_effect("success", now);
        let boundary = FakeBoundary::new(approved.clone(), ReconcileMode::ReceiptFound);
        let stats = boundary.stats.clone();
        let adapter =
            ShopifyEffectAdapter::controlled(boundary, approved.clone(), &effect).expect("adapter");
        let (mut executor, mut reconciler, mut verifier) = adapter.handles().into_parts();

        let receipt = executor.execute(&effect).expect("one controlled execution");
        let effect_with_receipt = effect_with_receipt(&effect, &receipt);
        let verification = verifier.verify(&effect_with_receipt, &receipt);
        assert_eq!(
            verification.status,
            hartevo_domain_kernel::VerificationStatus::Confirmed
        );
        assert!(verification.independent);
        assert_ne!(receipt.id.as_str(), verification.id.as_str());
        assert_eq!(stats.execute_calls(), 1);
        assert_eq!(stats.reconcile_calls(), 1);
        assert_eq!(stats.verify_calls(), 1);

        let observation = reconciler.reconcile(&uncertain_effect(&effect));
        assert!(matches!(
            observation,
            DomainReconciliationObservation::ReceiptFound { .. }
        ));
        // Reconciliation is read-only and does not reopen the one-shot execute
        // fence; this second call is rejected without another boundary write.
        assert!(matches!(
            executor.execute(&effect),
            Err(ProviderFailure::Uncertain(_))
        ));
        assert_eq!(stats.execute_calls(), 1);
    }

    #[test]
    fn timeout_after_commit_reconciles_and_verifies_without_execute_replay() {
        let now = Utc::now();
        let (approved, effect) = approved_and_effect("timeout", now);
        let mut boundary = FakeBoundary::new(approved.clone(), ReconcileMode::ReceiptFound);
        boundary.uncertain_after_commit = true;
        let stats = boundary.stats.clone();
        let adapter =
            ShopifyEffectAdapter::controlled(boundary, approved, &effect).expect("adapter");
        let (mut executor, mut reconciler, mut verifier) = adapter.handles().into_parts();

        assert!(matches!(
            executor.execute(&effect),
            Err(ProviderFailure::Uncertain(_))
        ));
        let observation = reconciler.reconcile(&uncertain_effect(&effect));
        let receipt = match observation {
            DomainReconciliationObservation::ReceiptFound { receipt, .. } => receipt,
            other => panic!("expected readback receipt, got {other:?}"),
        };
        let verification = verifier.verify(&effect_with_receipt(&effect, &receipt), &receipt);
        assert_eq!(
            verification.status,
            hartevo_domain_kernel::VerificationStatus::Confirmed
        );
        assert!(verification.independent);
        assert_eq!(stats.execute_calls(), 1);
        assert_eq!(stats.reconcile_calls(), 1);
        assert_eq!(stats.verify_calls(), 1);
    }

    #[test]
    fn provider_evidence_created_during_boundary_call_is_not_future_dated() {
        let now = Utc::now();
        let (approved, effect) = approved_and_effect("provider-time", now);
        let mut boundary = FakeBoundary::new(approved.clone(), ReconcileMode::StillUncertain);
        boundary.provider_time = ProviderTimeMode::DuringCall;
        let stats = boundary.stats.clone();
        let adapter =
            ShopifyEffectAdapter::controlled(boundary, approved, &effect).expect("adapter");
        let mut executor = adapter.executor();

        let receipt = executor
            .execute(&effect)
            .expect("evidence produced during the call");
        assert!(receipt.accepted_at >= now);
        assert_eq!(stats.execute_calls(), 1);
    }

    #[test]
    fn not_executed_is_read_only_and_verifier_is_not_called() {
        let now = Utc::now();
        let (approved, effect) = approved_and_effect("not-executed", now);
        let mut boundary = FakeBoundary::new(approved.clone(), ReconcileMode::NotExecuted);
        boundary.uncertain_after_commit = true;
        let stats = boundary.stats.clone();
        let adapter =
            ShopifyEffectAdapter::controlled(boundary, approved, &effect).expect("adapter");
        let (mut executor, mut reconciler, mut verifier) = adapter.handles().into_parts();

        assert!(matches!(
            executor.execute(&effect),
            Err(ProviderFailure::Uncertain(_))
        ));
        let observation = reconciler.reconcile(&uncertain_effect(&effect));
        assert!(matches!(
            observation,
            DomainReconciliationObservation::NotExecuted { .. }
        ));
        let fake_receipt = Receipt {
            id: ReceiptId::from_stable("unused-receipt"),
            provider: SHOPIFY_PROVIDER_ID.to_owned(),
            external_id: "unused-operation".to_owned(),
            accepted_at: now,
            request_digest: effect.approval_digest(),
            response_digest: digest("unused-response"),
        };
        let _ = verifier.verify(&effect, &fake_receipt);
        assert_eq!(stats.execute_calls(), 1);
        assert_eq!(stats.reconcile_calls(), 1);
        assert_eq!(stats.verify_calls(), 0);
    }

    #[test]
    fn mismatched_effects_and_production_provenance_never_call_boundary() {
        let now = Utc::now();
        let (approved, effect) = approved_and_effect("binding", now);
        let boundary = FakeBoundary::new(approved.clone(), ReconcileMode::ReceiptFound);
        let stats = boundary.stats.clone();
        let adapter =
            ShopifyEffectAdapter::controlled(boundary, approved, &effect).expect("adapter");
        let (mut executor, mut reconciler, mut verifier) = adapter.handles().into_parts();

        let mutations: Vec<EffectMutation> = vec![
            Box::new(|effect| effect.id = EffectId::from_stable("swapped-effect")),
            Box::new(|effect| effect.tenant_id = TenantId::from_stable("swapped-tenant")),
            Box::new(|effect| effect.project_id = ProjectId::from_stable("swapped-project")),
            Box::new(|effect| effect.mission_id = MissionId::from_stable("swapped-mission")),
            Box::new(|effect| effect.provider = "other-provider".to_owned()),
            Box::new(|effect| effect.capability = "other.capability".to_owned()),
            Box::new(|effect| effect.account_id = Some(AccountId::from_stable("swapped-account"))),
            Box::new(|effect| effect.required_scopes = BTreeSet::from([READ_SCOPE.to_owned()])),
            Box::new(|effect| effect.payload_digest = digest("swapped-payload")),
            Box::new(|effect| effect.idempotency_key = "shopify-effect-idem-swapped".to_owned()),
            Box::new(|effect| {
                effect.approval.as_mut().expect("approval").scope_digest =
                    digest("swapped-approval-scope");
            }),
            Box::new(|effect| {
                effect
                    .approval
                    .as_mut()
                    .expect("approval")
                    .permission_digest = digest("swapped-broker-authorization");
            }),
            Box::new(move |effect| effect.expires_at = now + Duration::seconds(301)),
        ];
        for mutate in mutations {
            let mut mismatched = effect.clone();
            mutate(&mut mismatched);
            assert!(executor.execute(&mismatched).is_err());
            assert!(matches!(
                reconciler.reconcile(&mismatched),
                DomainReconciliationObservation::StillUncertain { .. }
            ));
            let receipt = Receipt {
                id: ReceiptId::from_stable("mismatched-receipt"),
                provider: SHOPIFY_PROVIDER_ID.to_owned(),
                external_id: "mismatched-operation".to_owned(),
                accepted_at: now,
                request_digest: mismatched.approval_digest(),
                response_digest: digest("mismatched-response"),
            };
            let _ = verifier.verify(&mismatched, &receipt);
        }
        assert_eq!(stats.execute_calls(), 0);
        assert_eq!(stats.reconcile_calls(), 0);
        assert_eq!(stats.verify_calls(), 0);

        let (production_approved, _) = approved_and_effect("production", now);
        let production_boundary =
            FakeBoundary::new(production_approved.clone(), ReconcileMode::ReceiptFound);
        let production_stats = production_boundary.stats.clone();
        let result = ShopifyEffectAdapter::new(
            production_boundary,
            production_approved,
            ProviderProvenanceClass::ProductionProvider,
            &effect,
        );
        assert!(matches!(
            result,
            Err(ShopifyAdapterError::ProductionProviderBlocked)
        ));
        assert_eq!(production_stats.execute_calls(), 0);
    }

    #[test]
    fn expired_approval_still_allows_read_only_reconciliation_but_not_execution() {
        let approval_time = Utc::now() - Duration::seconds(250);
        let (approved, effect) = approved_and_effect("expired-approval", approval_time);
        let boundary = FakeBoundary::new(approved.clone(), ReconcileMode::NotExecuted);
        let stats = boundary.stats.clone();
        let adapter =
            ShopifyEffectAdapter::controlled(boundary, approved, &effect).expect("adapter");
        let (mut executor, mut reconciler, _verifier) = adapter.handles().into_parts();

        assert!(executor.execute(&effect).is_err());
        assert!(matches!(
            reconciler.reconcile(&uncertain_effect(&effect)),
            DomainReconciliationObservation::NotExecuted { .. }
        ));
        assert_eq!(stats.execute_calls(), 0);
        assert_eq!(stats.reconcile_calls(), 1);
        assert_eq!(stats.verify_calls(), 0);
    }

    #[test]
    fn verification_independence_and_redaction_fail_closed() {
        let now = Utc::now();
        let (approved, effect) = approved_and_effect("redaction", now);
        let mut boundary = FakeBoundary::new(approved.clone(), ReconcileMode::ReceiptFound);
        boundary.independent = false;
        let stats = boundary.stats.clone();
        let adapter =
            ShopifyEffectAdapter::controlled(boundary, approved.clone(), &effect).expect("adapter");
        let (mut executor, _reconciler, mut verifier) = adapter.handles().into_parts();
        let receipt = executor.execute(&effect).expect("receipt");
        let verification = verifier.verify(&effect_with_receipt(&effect, &receipt), &receipt);
        assert_eq!(
            verification.status,
            hartevo_domain_kernel::VerificationStatus::Rejected
        );
        assert!(!verification.independent);
        assert_eq!(stats.verify_calls(), 1);

        let debug = format!("{adapter:?}");
        let error = serde_json::to_string(&ShopifyAdapterError::BindingMismatch)
            .expect("redacted adapter error JSON");
        for text in [&debug, &error] {
            assert!(!text.contains("private-payload"));
            assert!(!text.contains("access-token"));
            assert!(!text.contains("authorization"));
            assert!(!text.contains("shopify-provider-receipt-application-test"));
            assert!(!text.contains(approved.draft().request_digest()));
            assert!(!text.contains(approved.execution_context().authorization_digest()));
        }
    }

    #[test]
    fn independent_inconclusive_verification_remains_recoverable() {
        let now = Utc::now();
        let (approved, effect) = approved_and_effect("inconclusive", now);
        let mut boundary = FakeBoundary::new(approved.clone(), ReconcileMode::ReceiptFound);
        boundary.verification_status = ConnectorVerificationStatus::Inconclusive;
        let stats = boundary.stats.clone();
        let adapter =
            ShopifyEffectAdapter::controlled(boundary, approved, &effect).expect("adapter");
        let (mut executor, _reconciler, mut verifier) = adapter.handles().into_parts();
        let receipt = executor.execute(&effect).expect("receipt");

        let verification = verifier.verify(&effect_with_receipt(&effect, &receipt), &receipt);
        assert_eq!(verification.status, VerificationStatus::Inconclusive);
        assert!(verification.independent);
        assert_ne!(verification.id.as_str(), receipt.id.as_str());
        assert_eq!(stats.execute_calls(), 1);
        assert_eq!(stats.reconcile_calls(), 1);
        assert_eq!(stats.verify_calls(), 1);
    }

    #[test]
    fn readback_mismatch_fails_closed_before_independent_verifier() {
        let now = Utc::now();
        let (approved, effect) = approved_and_effect("readback-mismatch", now);
        let mut boundary = FakeBoundary::new(approved.clone(), ReconcileMode::ReceiptFound);
        boundary.readback_mismatch = true;
        let stats = boundary.stats.clone();
        let adapter =
            ShopifyEffectAdapter::controlled(boundary, approved, &effect).expect("adapter");
        let (mut executor, _reconciler, mut verifier) = adapter.handles().into_parts();
        let receipt = executor.execute(&effect).expect("receipt");
        let verification = verifier.verify(&effect_with_receipt(&effect, &receipt), &receipt);
        assert_eq!(verification.status, VerificationStatus::Rejected);
        assert!(!verification.independent);
        assert_eq!(stats.execute_calls(), 1);
        assert_eq!(stats.reconcile_calls(), 1);
        assert_eq!(stats.verify_calls(), 0);
    }

    #[test]
    fn production_constructor_rejects_component_harness_too() {
        let now = Utc::now();
        let (approved, effect) = approved_and_effect("component-harness", now);
        let boundary = FakeBoundary::new(approved.clone(), ReconcileMode::StillUncertain);
        assert!(matches!(
            ShopifyEffectAdapter::new(
                boundary,
                approved,
                ProviderProvenanceClass::ComponentHarness,
                &effect,
            ),
            Err(ShopifyAdapterError::UnsupportedProvenance)
        ));
    }
}
