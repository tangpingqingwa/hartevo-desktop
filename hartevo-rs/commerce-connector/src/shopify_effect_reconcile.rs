//! Shopify fulfillment receipt/readback reconciliation layer.
//!
//! This is the second layer on top of [`crate::shopify_effect`].  It consumes
//! a Mission-approved draft together with the existing Connector SDK typed
//! Effect capsule and evidence types.  The host supplies the
//! [`ShopifyTypedEffectBoundary`] bridge; a production bridge is expected to
//! delegate to the already-authorized Connector Worker/Effect Broker.  This
//! module never creates an authority, a dispatch fence, a live probe fence,
//! or an execution context.
//!
//! Durable state contains only provider identities, request/response digests,
//! typed evidence snapshots, and the exact Shopify fulfillment state.  Secret
//! material and the opaque SDK execution context are never checkpointed.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use hartevo_connector_sdk::{
    ConnectorError, EffectExecutionContext, FreshnessWindow, PreparedEffect,
    ProviderProvenanceClass, ReceiptCandidate, ReceiptCandidateStatus, ReconciliationObservation,
    ReconciliationStatus, VerificationObservation, VerificationStatus,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::shopify::{ShopDomain, ShopifyApiVersion};
use crate::shopify_effect::{
    DraftFulfillmentRequest, SHOPIFY_FULFILLMENT_CAPABILITY,
    SHOPIFY_FULFILLMENT_LIVE_VALIDATION_STATUS, ShopifyApprovalRevision,
    ShopifyEffectIdempotencyKey, ShopifyEffectLifecycle, ShopifyFulfillmentEffectError,
    ShopifyFulfillmentLineItem, ShopifyFulfillmentOrderGid, ShopifyFulfillmentScope,
    ShopifyOrderGid, ShopifyProviderReceipt, ShopifyReadbackStatus,
    shopify_fulfillment_adapter_identity, shopify_fulfillment_provider_digest,
};

pub const SHOPIFY_FULFILLMENT_EFFECT_OPERATION: &str = "fulfillmentCreate";
/// The approved Effect owns exactly one Provider execution permit. A
/// reconciliation observation can never create another permit, including when
/// Shopify proves that the original call was not executed.
pub const SHOPIFY_FULFILLMENT_RECONCILIATION_MAX_EXECUTE_ATTEMPTS: u32 = 1;

/// A plugin revision is separate from the SDK credential and worker
/// generations.  It binds the provider implementation that interpreted the
/// approved draft to every durable evidence record.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ShopifyPluginRevision(u64);

impl ShopifyPluginRevision {
    pub fn new(value: u64) -> Result<Self, ShopifyReceiptReadbackError> {
        if value == 0 {
            return Err(ShopifyReceiptReadbackError::InvalidPluginRevision);
        }
        Ok(Self(value))
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

/// A strict Shopify Fulfillment GID from the exact readback state.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ShopifyFulfillmentGid(String);

impl ShopifyFulfillmentGid {
    pub fn parse(value: impl Into<String>) -> Result<Self, ShopifyReceiptReadbackError> {
        let value = value.into();
        let prefix = "gid://shopify/Fulfillment/";
        let suffix = value.strip_prefix(prefix).unwrap_or_default();
        if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ShopifyReceiptReadbackError::InvalidFulfillmentGid(value));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The exact provider state returned by the Shopify readback query.  This is
/// intentionally richer than a generic reconciliation status: order,
/// fulfillment order, line items, shop, account, and provider receipt all
/// have to match the approved draft before Verification can be emitted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyExactFulfillmentReadback {
    pub fulfillment_gid: ShopifyFulfillmentGid,
    pub provider_receipt: ShopifyProviderReceipt,
    pub scope_digest: String,
    pub account_id: String,
    pub shop: ShopDomain,
    pub order_gid: ShopifyOrderGid,
    pub fulfillment_order_gid: ShopifyFulfillmentOrderGid,
    pub line_items: Vec<ShopifyFulfillmentLineItem>,
    pub status: ShopifyReadbackStatus,
    pub observed_at: DateTime<Utc>,
    pub state_digest: String,
    pub provenance_class: ProviderProvenanceClass,
}

impl ShopifyExactFulfillmentReadback {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fulfillment_gid: ShopifyFulfillmentGid,
        provider_receipt: ShopifyProviderReceipt,
        scope_digest: impl Into<String>,
        account_id: impl Into<String>,
        shop: ShopDomain,
        order_gid: ShopifyOrderGid,
        fulfillment_order_gid: ShopifyFulfillmentOrderGid,
        line_items: Vec<ShopifyFulfillmentLineItem>,
        status: ShopifyReadbackStatus,
        observed_at: DateTime<Utc>,
        state_digest: impl Into<String>,
        provenance_class: ProviderProvenanceClass,
    ) -> Result<Self, ShopifyReceiptReadbackError> {
        let readback = Self {
            fulfillment_gid,
            provider_receipt,
            scope_digest: scope_digest.into(),
            account_id: account_id.into(),
            shop,
            order_gid,
            fulfillment_order_gid,
            line_items,
            status,
            observed_at,
            state_digest: state_digest.into(),
            provenance_class,
        };
        if readback.account_id.is_empty()
            || !is_sha256(&readback.scope_digest)
            || !is_sha256(&readback.state_digest)
            || readback.line_items.is_empty()
        {
            return Err(ShopifyReceiptReadbackError::InvalidReadbackShape);
        }
        Ok(readback)
    }
}

/// Provider request identity persisted before dispatch.  The SDK idempotency
/// key and the Shopify-facing key are both retained so a recovery can prove
/// that it is the same effect, not a new fulfillment request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyProviderRequestIdentity {
    pub operation: String,
    pub scope_digest: String,
    pub account_id: String,
    pub shop: ShopDomain,
    pub api_version: ShopifyApiVersion,
    pub order_gid: ShopifyOrderGid,
    pub fulfillment_order_gid: ShopifyFulfillmentOrderGid,
    pub line_items: Vec<ShopifyFulfillmentLineItem>,
    pub request_digest: String,
    pub idempotency_key: ShopifyEffectIdempotencyKey,
    pub sdk_idempotency_key: String,
    pub effect_digest: String,
    pub provider_generation: u64,
    pub approval_revision: ShopifyApprovalRevision,
    pub plugin_revision: ShopifyPluginRevision,
    pub provider_digest: String,
}

impl ShopifyProviderRequestIdentity {
    fn from_approved(approved: &ShopifyApprovedDraftFulfillment) -> Self {
        let draft = approved.draft();
        Self {
            operation: SHOPIFY_FULFILLMENT_EFFECT_OPERATION.to_owned(),
            scope_digest: draft.tenant_scope().digest(),
            account_id: draft
                .tenant_scope()
                .connector_scope()
                .account_id()
                .to_owned(),
            shop: draft.tenant_scope().shop().clone(),
            api_version: draft.api_version().clone(),
            order_gid: draft.order_gid().clone(),
            fulfillment_order_gid: draft.fulfillment_order_gid().clone(),
            line_items: draft.line_items().to_owned(),
            request_digest: draft.request_digest().to_owned(),
            idempotency_key: draft.idempotency_key().clone(),
            sdk_idempotency_key: approved.prepared_effect().idempotency_key().to_owned(),
            effect_digest: approved.prepared_effect().effect_digest().to_owned(),
            provider_generation: draft.provider_generation(),
            approval_revision: draft.approval_revision(),
            plugin_revision: approved.plugin_revision(),
            provider_digest: shopify_fulfillment_provider_digest(draft.api_version()),
        }
    }
}

/// Provider response identity persisted after execute or recovered from exact
/// readback.  It contains no response payload, only stable identities and
/// digests suitable for a durable Receipt/evidence record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyProviderResponseIdentity {
    pub receipt_id: String,
    pub provider_operation_id: String,
    pub provider_request_id_digest: String,
    pub receipt_digest: String,
    pub response_digest: String,
    pub provider_response_digest: String,
    pub provider_generation: u64,
    pub approval_revision: ShopifyApprovalRevision,
    pub observed_at: DateTime<Utc>,
    pub provenance_class: ProviderProvenanceClass,
}

impl ShopifyProviderResponseIdentity {
    fn from_evidence(
        receipt: &ReceiptCandidate,
        provider_receipt: &ShopifyProviderReceipt,
    ) -> Self {
        Self {
            receipt_id: provider_receipt.receipt_id.clone(),
            provider_operation_id: provider_receipt.provider_operation_id.clone(),
            provider_request_id_digest: receipt.provider_request_id_digest().to_owned(),
            receipt_digest: receipt.receipt_digest().to_owned(),
            response_digest: receipt.response_digest().to_owned(),
            provider_response_digest: provider_receipt.evidence_digest.clone(),
            provider_generation: provider_receipt.provider_generation,
            approval_revision: provider_receipt.approval_revision,
            observed_at: provider_receipt.observed_at,
            provenance_class: provider_receipt.provenance_class,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyReceiptEvidenceSnapshot {
    pub receipt_digest: String,
    pub effect_digest: String,
    pub provider_request_id_digest: String,
    pub idempotency_key: String,
    pub status: ReceiptCandidateStatus,
    pub response_digest: String,
    pub observed_at: DateTime<Utc>,
}

impl ShopifyReceiptEvidenceSnapshot {
    fn from_receipt(receipt: &ReceiptCandidate) -> Self {
        Self {
            receipt_digest: receipt.receipt_digest().to_owned(),
            effect_digest: receipt.effect_digest().to_owned(),
            provider_request_id_digest: receipt.provider_request_id_digest().to_owned(),
            idempotency_key: receipt.idempotency_key().to_owned(),
            status: receipt.status(),
            response_digest: receipt.response_digest().to_owned(),
            observed_at: receipt.observed_at(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyReconciliationEvidenceSnapshot {
    pub effect_digest: String,
    pub scope_digest: String,
    pub status: ReconciliationStatus,
    pub provider_state_digest: String,
    pub observed_at: DateTime<Utc>,
    pub freshness_observed_at: DateTime<Utc>,
    pub freshness_valid_until: DateTime<Utc>,
    pub freshness_source_revision: u64,
}

impl ShopifyReconciliationEvidenceSnapshot {
    fn from_observation(observation: &ReconciliationObservation) -> Self {
        Self {
            effect_digest: observation.effect_digest().to_owned(),
            scope_digest: observation.scope().digest(),
            status: observation.status(),
            provider_state_digest: observation.provider_state_digest().to_owned(),
            observed_at: observation.observed_at(),
            freshness_observed_at: observation.freshness().observed_at(),
            freshness_valid_until: observation.freshness().valid_until(),
            freshness_source_revision: observation.freshness().source_revision(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyVerificationEvidenceSnapshot {
    pub subject_digest: String,
    pub scope_digest: String,
    pub status: VerificationStatus,
    pub evidence_digest: String,
    pub observed_at: DateTime<Utc>,
    pub independent: bool,
}

impl ShopifyVerificationEvidenceSnapshot {
    fn from_observation(observation: &VerificationObservation) -> Self {
        Self {
            subject_digest: observation.subject_digest().to_owned(),
            scope_digest: observation.scope().digest(),
            status: observation.status(),
            evidence_digest: observation.evidence_digest().to_owned(),
            observed_at: observation.observed_at(),
            independent: observation.independent(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShopifyFulfillmentOutcomeStatus {
    Confirmed,
    Rejected,
    Inconclusive,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyFulfillmentOutcomeEvidence {
    pub status: ShopifyFulfillmentOutcomeStatus,
    pub operation: String,
    pub effect_digest: String,
    pub request_digest: String,
    pub readback_state_digest: String,
    pub evidence_digest: String,
    pub observed_at: DateTime<Utc>,
    pub provenance_class: ProviderProvenanceClass,
    pub live_validation_status: String,
}

impl ShopifyFulfillmentOutcomeEvidence {
    pub fn is_first_party(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShopifyFulfillmentReconciliationState {
    Prepared,
    InFlight,
    Uncertain,
    NotExecuted,
    ReceiptObserved,
    Reconciled,
    Verified,
    Rejected,
    FailedClosed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyFulfillmentReconciliationRecord {
    pub request: DraftFulfillmentRequest,
    pub state: ShopifyFulfillmentReconciliationState,
    pub execute_attempts: u32,
    pub approval_binding_digest: String,
    pub provider_request: ShopifyProviderRequestIdentity,
    pub provider_receipt: Option<ShopifyProviderReceipt>,
    pub provider_response: Option<ShopifyProviderResponseIdentity>,
    pub receipt: Option<ShopifyReceiptEvidenceSnapshot>,
    pub reconciliation: Option<ShopifyReconciliationEvidenceSnapshot>,
    pub exact_readback: Option<ShopifyExactFulfillmentReadback>,
    pub verification: Option<ShopifyVerificationEvidenceSnapshot>,
    pub outcome: Option<ShopifyFulfillmentOutcomeEvidence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyFulfillmentReconciliationStore {
    lifecycle: ShopifyEffectLifecycle,
    scope_digest: String,
    provider_generation: u64,
    plugin_revision: ShopifyPluginRevision,
    records: BTreeMap<String, ShopifyFulfillmentReconciliationRecord>,
}

impl ShopifyFulfillmentReconciliationStore {
    pub fn new(
        scope: &ShopifyFulfillmentScope,
        provider_generation: u64,
        plugin_revision: ShopifyPluginRevision,
    ) -> Result<Self, ShopifyReceiptReadbackError> {
        if provider_generation == 0 {
            return Err(ShopifyReceiptReadbackError::InvalidProviderGeneration);
        }
        Ok(Self {
            lifecycle: ShopifyEffectLifecycle::Mounted,
            scope_digest: scope.digest(),
            provider_generation,
            plugin_revision,
            records: BTreeMap::new(),
        })
    }

    pub const fn lifecycle(&self) -> ShopifyEffectLifecycle {
        self.lifecycle
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub const fn provider_generation(&self) -> u64 {
        self.provider_generation
    }

    pub const fn plugin_revision(&self) -> ShopifyPluginRevision {
        self.plugin_revision
    }

    pub fn records(&self) -> &BTreeMap<String, ShopifyFulfillmentReconciliationRecord> {
        &self.records
    }

    fn record(&self, key: &str) -> Option<&ShopifyFulfillmentReconciliationRecord> {
        self.records.get(key)
    }

    fn record_mut(&mut self, key: &str) -> Option<&mut ShopifyFulfillmentReconciliationRecord> {
        self.records.get_mut(key)
    }

    fn insert_prepared(&mut self, approved: &ShopifyApprovedDraftFulfillment) {
        let request = approved.draft().clone();
        let key = request.idempotency_key().as_str().to_owned();
        self.records.insert(
            key,
            ShopifyFulfillmentReconciliationRecord {
                request,
                state: ShopifyFulfillmentReconciliationState::Prepared,
                execute_attempts: 0,
                approval_binding_digest: approved.approval_binding_digest().to_owned(),
                provider_request: ShopifyProviderRequestIdentity::from_approved(approved),
                provider_receipt: None,
                provider_response: None,
                receipt: None,
                reconciliation: None,
                exact_readback: None,
                verification: None,
                outcome: None,
            },
        );
    }

    fn rotate_generation(
        &mut self,
        scope: &ShopifyFulfillmentScope,
        provider_generation: u64,
    ) -> Result<(), ShopifyReceiptReadbackError> {
        if provider_generation <= self.provider_generation {
            return Err(ShopifyReceiptReadbackError::GenerationMustIncrease);
        }
        self.provider_generation = provider_generation;
        self.scope_digest = scope.digest();
        self.records.clear();
        self.lifecycle = ShopifyEffectLifecycle::Mounted;
        Ok(())
    }

    fn revoke(&mut self) {
        self.records.clear();
        self.lifecycle = ShopifyEffectLifecycle::Revoked;
    }

    fn unmount(&mut self) {
        self.records.clear();
        self.lifecycle = ShopifyEffectLifecycle::Unmounted;
    }
}

/// The host-facing typed bridge.  Its implementation is expected to wrap the
/// existing Connector Worker/Effect Broker boundary.  This crate only passes
/// typed SDK inputs/outputs and never obtains the authority itself.
pub trait ShopifyTypedEffectBoundary {
    fn execute(
        &mut self,
        approved: &ShopifyApprovedDraftFulfillment,
    ) -> Result<ShopifyEffectBoundaryReceipt, ConnectorError>;

    fn reconcile(
        &mut self,
        approved: &ShopifyApprovedDraftFulfillment,
        prior_provider_receipt: Option<&ShopifyProviderReceipt>,
    ) -> Result<ShopifyEffectBoundaryReadback, ConnectorError>;

    fn verify(
        &mut self,
        approved: &ShopifyApprovedDraftFulfillment,
        readback: &ShopifyEffectBoundaryReadback,
    ) -> Result<VerificationObservation, ConnectorError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShopifyEffectBoundaryReceipt {
    pub receipt: ReceiptCandidate,
    pub provider_receipt: ShopifyProviderReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShopifyEffectBoundaryReadback {
    pub receipt: Option<ReceiptCandidate>,
    pub reconciliation: ReconciliationObservation,
    pub exact_readback: Option<ShopifyExactFulfillmentReadback>,
}

/// An approved draft plus the opaque, already-created SDK Effect capsule.
/// Construction validates the binding but is not itself an approval action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShopifyApprovedDraftFulfillment {
    draft: DraftFulfillmentRequest,
    prepared_effect: PreparedEffect,
    execution_context: EffectExecutionContext,
    plugin_revision: ShopifyPluginRevision,
    approval_binding_digest: String,
}

impl ShopifyApprovedDraftFulfillment {
    pub fn new(
        draft: DraftFulfillmentRequest,
        prepared_effect: PreparedEffect,
        execution_context: EffectExecutionContext,
        plugin_revision: ShopifyPluginRevision,
    ) -> Result<Self, ShopifyReceiptReadbackError> {
        let approved = Self {
            draft,
            prepared_effect,
            execution_context,
            plugin_revision,
            approval_binding_digest: String::new(),
        };
        approved.validate_core_shape()?;
        let approval_binding_digest = approved.calculate_binding_digest();
        Ok(Self {
            approval_binding_digest,
            ..approved
        })
    }

    pub fn draft(&self) -> &DraftFulfillmentRequest {
        &self.draft
    }

    pub fn prepared_effect(&self) -> &PreparedEffect {
        &self.prepared_effect
    }

    pub fn execution_context(&self) -> &EffectExecutionContext {
        &self.execution_context
    }

    pub const fn plugin_revision(&self) -> ShopifyPluginRevision {
        self.plugin_revision
    }

    pub fn approval_binding_digest(&self) -> &str {
        &self.approval_binding_digest
    }

    pub fn sdk_idempotency_key(&self) -> &str {
        self.prepared_effect.idempotency_key()
    }

    pub fn provider_request_identity(&self) -> ShopifyProviderRequestIdentity {
        ShopifyProviderRequestIdentity::from_approved(self)
    }

    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<(), ShopifyReceiptReadbackError> {
        self.validate_shape()?;
        if now < self.draft.created_at()
            || now >= self.draft.expires_at()
            || now < self.prepared_effect.prepared_at()
            || now >= self.prepared_effect.expires_at()
            || now >= self.execution_context.expires_at()
        {
            return Err(ShopifyReceiptReadbackError::ApprovedEffectExpired);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), ShopifyReceiptReadbackError> {
        self.validate_core_shape()?;
        if self.approval_binding_digest.is_empty()
            || self.approval_binding_digest != self.calculate_binding_digest()
        {
            return Err(ShopifyReceiptReadbackError::ApprovedEffectBindingMismatch);
        }
        Ok(())
    }

    fn validate_core_shape(&self) -> Result<(), ShopifyReceiptReadbackError> {
        self.draft.validate()?;
        if self.plugin_revision.value() == 0 {
            return Err(ShopifyReceiptReadbackError::InvalidPluginRevision);
        }
        let adapter = shopify_fulfillment_adapter_identity()
            .map_err(ShopifyReceiptReadbackError::Connector)?;
        if self.prepared_effect.scope() != self.draft.tenant_scope().connector_scope()
            || self.prepared_effect.adapter() != &adapter
            || self.prepared_effect.capability().provider_id()
                != crate::shopify::SHOPIFY_PROVIDER_ID
            || self.prepared_effect.capability().capability_id() != SHOPIFY_FULFILLMENT_CAPABILITY
            || self.prepared_effect.payload_digest() != self.draft.request_digest()
            || self.prepared_effect.idempotency_key()
                != shopify_sdk_effect_idempotency_key(&self.draft)
            || self.execution_context.scope() != self.prepared_effect.scope()
            || self.execution_context.effect_digest() != self.prepared_effect.effect_digest()
            || self.execution_context.expires_at() < self.prepared_effect.expires_at()
        {
            return Err(ShopifyReceiptReadbackError::ApprovedEffectBindingMismatch);
        }
        Ok(())
    }

    fn calculate_binding_digest(&self) -> String {
        sha256_digest([
            self.draft.request_digest().to_owned(),
            self.draft.tenant_scope().digest(),
            self.prepared_effect.effect_digest().to_owned(),
            self.execution_context.authorization_digest().to_owned(),
            self.plugin_revision.value().to_string(),
            self.draft.provider_generation().to_string(),
            self.draft.approval_revision().value().to_string(),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyFulfillmentReceiptReadbackOutcome {
    pub operation: String,
    pub request_digest: String,
    pub effect_digest: String,
    pub approval_binding_digest: String,
    pub scope_digest: String,
    pub account_id: String,
    pub shop: ShopDomain,
    pub order_gid: ShopifyOrderGid,
    pub fulfillment_order_gid: ShopifyFulfillmentOrderGid,
    pub provider_generation: u64,
    pub approval_revision: ShopifyApprovalRevision,
    pub plugin_revision: ShopifyPluginRevision,
    pub provider_request: ShopifyProviderRequestIdentity,
    pub provider_response: ShopifyProviderResponseIdentity,
    pub provider_receipt: ShopifyProviderReceipt,
    pub exact_readback: ShopifyExactFulfillmentReadback,
    pub receipt: ReceiptCandidate,
    pub reconciliation: ReconciliationObservation,
    pub verification: VerificationObservation,
    pub outcome: ShopifyFulfillmentOutcomeEvidence,
    pub replayed: bool,
    pub provenance_class: ProviderProvenanceClass,
    pub live_validation_status: String,
}

impl ShopifyFulfillmentReceiptReadbackOutcome {
    pub fn is_first_party(&self) -> bool {
        false
    }

    pub fn is_catalog_only(&self) -> bool {
        false
    }
}

#[derive(Debug)]
pub struct ShopifyFulfillmentReceiptReadbackService<B>
where
    B: ShopifyTypedEffectBoundary,
{
    boundary: B,
    tenant_scope: ShopifyFulfillmentScope,
    api_version: ShopifyApiVersion,
    plugin_revision: ShopifyPluginRevision,
    provenance_class: ProviderProvenanceClass,
    store: ShopifyFulfillmentReconciliationStore,
}

impl<B> ShopifyFulfillmentReceiptReadbackService<B>
where
    B: ShopifyTypedEffectBoundary,
{
    pub fn new(
        boundary: B,
        tenant_scope: ShopifyFulfillmentScope,
        api_version: ShopifyApiVersion,
        plugin_revision: ShopifyPluginRevision,
        provenance_class: ProviderProvenanceClass,
        store: ShopifyFulfillmentReconciliationStore,
    ) -> Result<Self, ShopifyReceiptReadbackError> {
        if store.scope_digest() != tenant_scope.digest()
            || store.provider_generation() == 0
            || store.plugin_revision() != plugin_revision
        {
            return Err(ShopifyReceiptReadbackError::StoreBindingMismatch);
        }
        Ok(Self {
            boundary,
            tenant_scope,
            api_version,
            plugin_revision,
            provenance_class,
            store,
        })
    }

    pub fn boundary(&self) -> &B {
        &self.boundary
    }

    pub fn boundary_mut(&mut self) -> &mut B {
        &mut self.boundary
    }

    pub fn store(&self) -> &ShopifyFulfillmentReconciliationStore {
        &self.store
    }

    pub const fn lifecycle(&self) -> ShopifyEffectLifecycle {
        self.store.lifecycle()
    }

    pub const fn live_validation_status(&self) -> &'static str {
        SHOPIFY_FULFILLMENT_LIVE_VALIDATION_STATUS
    }

    pub const fn is_first_party(&self) -> bool {
        false
    }

    pub fn submit_approved(
        &mut self,
        approved: &ShopifyApprovedDraftFulfillment,
        now: DateTime<Utc>,
    ) -> Result<ShopifyFulfillmentReceiptReadbackOutcome, ShopifyReceiptReadbackError> {
        self.ensure_operable(approved, now)?;
        let key = approved.draft().idempotency_key().as_str().to_owned();
        if let Some(record) = self.store.record(&key).cloned() {
            Self::validate_record_binding(&record, approved)?;
            match record.state {
                ShopifyFulfillmentReconciliationState::Verified => {
                    return self.output_from_record(&record, approved, true, now);
                }
                ShopifyFulfillmentReconciliationState::Rejected => {
                    return Err(ShopifyReceiptReadbackError::PreviouslyRejected);
                }
                ShopifyFulfillmentReconciliationState::FailedClosed => {
                    return Err(ShopifyReceiptReadbackError::PreviouslyFailedClosed);
                }
                ShopifyFulfillmentReconciliationState::NotExecuted => {
                    let evidence_digest = record
                        .reconciliation
                        .as_ref()
                        .map(|reconciliation| reconciliation.provider_state_digest.clone())
                        .ok_or(ShopifyReceiptReadbackError::MissingReconciliationEvidence)?;
                    return Err(ShopifyReceiptReadbackError::NotExecutedTerminal {
                        evidence_digest,
                    });
                }
                ShopifyFulfillmentReconciliationState::Prepared => {
                    return self.execute_once(approved, now);
                }
                ShopifyFulfillmentReconciliationState::InFlight
                | ShopifyFulfillmentReconciliationState::Uncertain
                | ShopifyFulfillmentReconciliationState::ReceiptObserved
                | ShopifyFulfillmentReconciliationState::Reconciled => {
                    return self.reconcile_existing(approved, now, true);
                }
            }
        }
        self.store.insert_prepared(approved);
        self.execute_once(approved, now)
    }

    pub fn rotate_generation(
        &mut self,
        scope: &ShopifyFulfillmentScope,
        provider_generation: u64,
    ) -> Result<(), ShopifyReceiptReadbackError> {
        if scope.connector_scope().provider_id() != crate::shopify::SHOPIFY_PROVIDER_ID {
            return Err(ShopifyReceiptReadbackError::ScopeDrift);
        }
        self.store.rotate_generation(scope, provider_generation)?;
        self.tenant_scope = scope.clone();
        Ok(())
    }

    pub fn revoke(&mut self, _at: DateTime<Utc>) {
        self.store.revoke();
    }

    pub fn unmount(&mut self, _at: DateTime<Utc>) {
        self.store.unmount();
    }

    fn ensure_operable(
        &self,
        approved: &ShopifyApprovedDraftFulfillment,
        now: DateTime<Utc>,
    ) -> Result<(), ShopifyReceiptReadbackError> {
        if self.lifecycle() != ShopifyEffectLifecycle::Mounted {
            return Err(ShopifyReceiptReadbackError::ConsumerNotMounted);
        }
        if self.provenance_class == ProviderProvenanceClass::ProductionProvider {
            return Err(ShopifyReceiptReadbackError::BlockedEnv);
        }
        approved.validate_at(now)?;
        if approved.draft().tenant_scope() != &self.tenant_scope
            || approved.draft().api_version() != &self.api_version
            || approved.draft().provider_generation() != self.store.provider_generation()
            || approved.plugin_revision() != self.plugin_revision
        {
            return Err(ShopifyReceiptReadbackError::ScopeDrift);
        }
        Ok(())
    }

    fn execute_once(
        &mut self,
        approved: &ShopifyApprovedDraftFulfillment,
        now: DateTime<Utc>,
    ) -> Result<ShopifyFulfillmentReceiptReadbackOutcome, ShopifyReceiptReadbackError> {
        let key = approved.draft().idempotency_key().as_str().to_owned();
        let attempts = self
            .store
            .record(&key)
            .map_or(0, |record| record.execute_attempts);
        if attempts >= SHOPIFY_FULFILLMENT_RECONCILIATION_MAX_EXECUTE_ATTEMPTS {
            return Err(ShopifyReceiptReadbackError::ExecutionUncertain);
        }
        if let Some(record) = self.store.record_mut(&key) {
            record.state = ShopifyFulfillmentReconciliationState::InFlight;
            record.execute_attempts = record.execute_attempts.saturating_add(1);
        }
        match self.boundary.execute(approved) {
            Ok(boundary_receipt) => {
                if let Err(error) = self.validate_boundary_receipt(approved, &boundary_receipt, now)
                {
                    return self.fail_closed(&key, error);
                }
                if let Some(record) = self.store.record_mut(&key) {
                    record.provider_receipt = Some(boundary_receipt.provider_receipt.clone());
                    record.provider_response =
                        Some(ShopifyProviderResponseIdentity::from_evidence(
                            &boundary_receipt.receipt,
                            &boundary_receipt.provider_receipt,
                        ));
                    record.receipt = Some(ShopifyReceiptEvidenceSnapshot::from_receipt(
                        &boundary_receipt.receipt,
                    ));
                    record.state = ShopifyFulfillmentReconciliationState::ReceiptObserved;
                }
                self.reconcile_existing(approved, now, false)
            }
            Err(ConnectorError::ProviderRejected) => {
                if let Some(record) = self.store.record_mut(&key) {
                    record.state = ShopifyFulfillmentReconciliationState::Rejected;
                }
                Err(ShopifyReceiptReadbackError::ProviderRejected)
            }
            Err(_) => {
                if let Some(record) = self.store.record_mut(&key) {
                    record.state = ShopifyFulfillmentReconciliationState::Uncertain;
                }
                Err(ShopifyReceiptReadbackError::ExecutionUncertain)
            }
        }
    }

    fn reconcile_existing(
        &mut self,
        approved: &ShopifyApprovedDraftFulfillment,
        now: DateTime<Utc>,
        replayed: bool,
    ) -> Result<ShopifyFulfillmentReceiptReadbackOutcome, ShopifyReceiptReadbackError> {
        let key = approved.draft().idempotency_key().as_str().to_owned();
        let prior_provider_receipt = self
            .store
            .record(&key)
            .and_then(|record| record.provider_receipt.as_ref())
            .cloned();
        let boundary_readback = match self
            .boundary
            .reconcile(approved, prior_provider_receipt.as_ref())
        {
            Ok(readback) => readback,
            Err(ConnectorError::ProviderUncertain) => {
                return Err(ShopifyReceiptReadbackError::ReadbackPending);
            }
            Err(error) => return Err(ShopifyReceiptReadbackError::Boundary(error)),
        };
        if let Err(error) = self.validate_boundary_readback(approved, &boundary_readback, now) {
            return self.fail_closed(&key, error);
        }
        match boundary_readback.reconciliation.status() {
            ReconciliationStatus::StillUncertain => {
                if let Some(record) = self.store.record_mut(&key) {
                    record.state = ShopifyFulfillmentReconciliationState::Uncertain;
                }
                Err(ShopifyReceiptReadbackError::ReadbackPending)
            }
            ReconciliationStatus::ProviderRejected => {
                if let Some(record) = self.store.record_mut(&key) {
                    record.state = ShopifyFulfillmentReconciliationState::Rejected;
                }
                Err(ShopifyReceiptReadbackError::ProviderRejected)
            }
            ReconciliationStatus::NotExecuted => {
                if prior_provider_receipt.is_some() {
                    return self.fail_closed(&key, ShopifyReceiptReadbackError::ReadbackMismatch);
                }
                let evidence_digest = boundary_readback
                    .reconciliation
                    .provider_state_digest()
                    .to_owned();
                if let Some(record) = self.store.record_mut(&key) {
                    record.reconciliation =
                        Some(ShopifyReconciliationEvidenceSnapshot::from_observation(
                            &boundary_readback.reconciliation,
                        ));
                    record.state = ShopifyFulfillmentReconciliationState::NotExecuted;
                }
                Err(ShopifyReceiptReadbackError::NotExecutedTerminal { evidence_digest })
            }
            ReconciliationStatus::ReceiptFound => {
                self.finish_reconciliation(approved, &boundary_readback, now, replayed)
            }
        }
    }

    fn finish_reconciliation(
        &mut self,
        approved: &ShopifyApprovedDraftFulfillment,
        boundary_readback: &ShopifyEffectBoundaryReadback,
        now: DateTime<Utc>,
        replayed: bool,
    ) -> Result<ShopifyFulfillmentReceiptReadbackOutcome, ShopifyReceiptReadbackError> {
        let key = approved.draft().idempotency_key().as_str().to_owned();
        let exact_readback = boundary_readback
            .exact_readback
            .as_ref()
            .ok_or(ShopifyReceiptReadbackError::MissingReadbackEvidence)?;
        let receipt = boundary_readback
            .receipt
            .as_ref()
            .ok_or(ShopifyReceiptReadbackError::MissingReceiptEvidence)?;
        let receipt_snapshot = ShopifyReceiptEvidenceSnapshot::from_receipt(receipt);
        if let Some(record) = self.store.record(&key)
            && (record
                .receipt
                .as_ref()
                .is_some_and(|snapshot| snapshot != &receipt_snapshot)
                || record
                    .provider_receipt
                    .as_ref()
                    .is_some_and(|prior| prior != &exact_readback.provider_receipt))
        {
            return self.fail_closed(&key, ShopifyReceiptReadbackError::ReadbackMismatch);
        }
        if let Err(error) = Self::validate_receipt_candidate(approved, receipt, now) {
            return self.fail_closed(&key, error);
        }
        let provider_response = ShopifyProviderResponseIdentity::from_evidence(
            receipt,
            &exact_readback.provider_receipt,
        );
        if let Some(record) = self.store.record(&key)
            && record
                .provider_response
                .as_ref()
                .is_some_and(|prior| prior != &provider_response)
        {
            return self.fail_closed(&key, ShopifyReceiptReadbackError::ReadbackMismatch);
        }
        let reconciliation = ShopifyReconciliationEvidenceSnapshot::from_observation(
            &boundary_readback.reconciliation,
        );
        if let Some(record) = self.store.record_mut(&key) {
            record.provider_receipt = Some(exact_readback.provider_receipt.clone());
            record.provider_response = Some(provider_response);
            record.receipt = Some(receipt_snapshot);
            record.reconciliation = Some(reconciliation);
            record.exact_readback = Some(exact_readback.clone());
            record.state = ShopifyFulfillmentReconciliationState::Reconciled;
        }
        let verification = match self.boundary.verify(approved, boundary_readback) {
            Ok(verification) => verification,
            Err(ConnectorError::ProviderUncertain) => {
                return Err(ShopifyReceiptReadbackError::VerificationPending);
            }
            Err(error) => return Err(ShopifyReceiptReadbackError::Boundary(error)),
        };
        if let Err(error) = Self::validate_verification(approved, receipt, &verification, now) {
            return self.fail_closed(&key, error);
        }
        let outcome = self.build_outcome(approved, exact_readback, &verification);
        if let Some(record) = self.store.record_mut(&key) {
            record.verification = Some(ShopifyVerificationEvidenceSnapshot::from_observation(
                &verification,
            ));
            record.outcome = Some(outcome);
            record.state = ShopifyFulfillmentReconciliationState::Verified;
        }
        let record = self
            .store
            .record(&key)
            .ok_or(ShopifyReceiptReadbackError::DurableRecordMissing)?
            .clone();
        self.output_from_record(&record, approved, replayed, now)
    }

    fn validate_boundary_receipt(
        &self,
        approved: &ShopifyApprovedDraftFulfillment,
        boundary_receipt: &ShopifyEffectBoundaryReceipt,
        now: DateTime<Utc>,
    ) -> Result<(), ShopifyReceiptReadbackError> {
        Self::validate_receipt_candidate(approved, &boundary_receipt.receipt, now)?;
        self.validate_provider_receipt(approved, &boundary_receipt.provider_receipt, now)
    }

    fn validate_receipt_candidate(
        approved: &ShopifyApprovedDraftFulfillment,
        receipt: &ReceiptCandidate,
        now: DateTime<Utc>,
    ) -> Result<(), ShopifyReceiptReadbackError> {
        if receipt.effect_digest() != approved.prepared_effect().effect_digest()
            || receipt.scope() != approved.prepared_effect().scope()
            || receipt.idempotency_key() != approved.sdk_idempotency_key()
            || receipt.status() == ReceiptCandidateStatus::Rejected
            || receipt.observed_at() > now
            || !is_sha256(receipt.receipt_digest())
            || !is_sha256(receipt.provider_request_id_digest())
            || !is_sha256(receipt.response_digest())
        {
            return Err(ShopifyReceiptReadbackError::ReceiptBindingMismatch);
        }
        Ok(())
    }

    fn validate_provider_receipt(
        &self,
        approved: &ShopifyApprovedDraftFulfillment,
        receipt: &ShopifyProviderReceipt,
        now: DateTime<Utc>,
    ) -> Result<(), ShopifyReceiptReadbackError> {
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
            || receipt.provenance_class != self.provenance_class
        {
            return Err(ShopifyReceiptReadbackError::ProviderResponseMismatch);
        }
        Ok(())
    }

    fn validate_boundary_readback(
        &self,
        approved: &ShopifyApprovedDraftFulfillment,
        readback: &ShopifyEffectBoundaryReadback,
        now: DateTime<Utc>,
    ) -> Result<(), ShopifyReceiptReadbackError> {
        let reconciliation = &readback.reconciliation;
        if reconciliation.effect_digest() != approved.prepared_effect().effect_digest()
            || reconciliation.scope() != approved.prepared_effect().scope()
            || reconciliation.observed_at() > now
            || !is_sha256(reconciliation.provider_state_digest())
        {
            return Err(ShopifyReceiptReadbackError::ReconciliationBindingMismatch);
        }
        reconciliation
            .freshness()
            .validate_at(now)
            .map_err(|_| ShopifyReceiptReadbackError::ReadbackFreshnessExpired)?;
        if reconciliation.status() == ReconciliationStatus::ReceiptFound {
            let exact_readback = readback
                .exact_readback
                .as_ref()
                .ok_or(ShopifyReceiptReadbackError::MissingReadbackEvidence)?;
            self.validate_exact_readback(approved, exact_readback, now)?;
        } else if readback.exact_readback.is_some() || readback.receipt.is_some() {
            return Err(ShopifyReceiptReadbackError::ReadbackMismatch);
        }
        Ok(())
    }

    fn validate_exact_readback(
        &self,
        approved: &ShopifyApprovedDraftFulfillment,
        readback: &ShopifyExactFulfillmentReadback,
        now: DateTime<Utc>,
    ) -> Result<(), ShopifyReceiptReadbackError> {
        let draft = approved.draft();
        self.validate_provider_receipt(approved, &readback.provider_receipt, now)?;
        if readback.scope_digest != draft.tenant_scope().digest()
            || readback.account_id != draft.tenant_scope().connector_scope().account_id()
            || readback.shop != *draft.tenant_scope().shop()
            || readback.order_gid != *draft.order_gid()
            || readback.fulfillment_order_gid != *draft.fulfillment_order_gid()
            || readback.line_items != draft.line_items()
            || readback.observed_at < readback.provider_receipt.observed_at
            || readback.observed_at > now
            || readback.provenance_class != self.provenance_class
            || !is_sha256(&readback.state_digest)
        {
            return Err(ShopifyReceiptReadbackError::ReadbackMismatch);
        }
        Ok(())
    }

    fn validate_verification(
        approved: &ShopifyApprovedDraftFulfillment,
        receipt: &ReceiptCandidate,
        verification: &VerificationObservation,
        now: DateTime<Utc>,
    ) -> Result<(), ShopifyReceiptReadbackError> {
        if verification.subject_digest() != receipt.receipt_digest()
            || verification.scope() != approved.prepared_effect().scope()
            || verification.status() != VerificationStatus::Confirmed
            || !verification.independent()
            || verification.observed_at() > now
            || !is_sha256(verification.evidence_digest())
        {
            return Err(ShopifyReceiptReadbackError::VerificationMismatch);
        }
        Ok(())
    }

    fn build_outcome(
        &self,
        approved: &ShopifyApprovedDraftFulfillment,
        readback: &ShopifyExactFulfillmentReadback,
        verification: &VerificationObservation,
    ) -> ShopifyFulfillmentOutcomeEvidence {
        let evidence_digest = sha256_digest([
            approved.prepared_effect().effect_digest().to_owned(),
            approved.draft().request_digest().to_owned(),
            readback.state_digest.clone(),
            verification.evidence_digest().to_owned(),
            readback.fulfillment_gid.as_str().to_owned(),
        ]);
        ShopifyFulfillmentOutcomeEvidence {
            status: ShopifyFulfillmentOutcomeStatus::Confirmed,
            operation: SHOPIFY_FULFILLMENT_EFFECT_OPERATION.to_owned(),
            effect_digest: approved.prepared_effect().effect_digest().to_owned(),
            request_digest: approved.draft().request_digest().to_owned(),
            readback_state_digest: readback.state_digest.clone(),
            evidence_digest,
            observed_at: verification.observed_at(),
            provenance_class: self.provenance_class,
            live_validation_status: SHOPIFY_FULFILLMENT_LIVE_VALIDATION_STATUS.to_owned(),
        }
    }

    fn validate_record_binding(
        record: &ShopifyFulfillmentReconciliationRecord,
        approved: &ShopifyApprovedDraftFulfillment,
    ) -> Result<(), ShopifyReceiptReadbackError> {
        if record.request.request_digest() != approved.draft().request_digest()
            || record.request.idempotency_key() != approved.draft().idempotency_key()
            || record.provider_request.effect_digest != approved.prepared_effect().effect_digest()
            || record.provider_request.scope_digest != approved.draft().tenant_scope().digest()
            || record.provider_request.account_id
                != approved
                    .draft()
                    .tenant_scope()
                    .connector_scope()
                    .account_id()
            || record.provider_request.provider_generation != approved.draft().provider_generation()
            || record.provider_request.approval_revision != approved.draft().approval_revision()
            || record.provider_request.plugin_revision != approved.plugin_revision()
            || record.approval_binding_digest != approved.approval_binding_digest()
        {
            return Err(ShopifyReceiptReadbackError::DurableRecordBindingMismatch);
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn output_from_record(
        &self,
        record: &ShopifyFulfillmentReconciliationRecord,
        approved: &ShopifyApprovedDraftFulfillment,
        replayed: bool,
        now: DateTime<Utc>,
    ) -> Result<ShopifyFulfillmentReceiptReadbackOutcome, ShopifyReceiptReadbackError> {
        Self::validate_record_binding(record, approved)?;
        let receipt_snapshot = record
            .receipt
            .as_ref()
            .ok_or(ShopifyReceiptReadbackError::MissingReceiptEvidence)?;
        let receipt = ReceiptCandidate::new(
            approved.prepared_effect(),
            receipt_snapshot.provider_request_id_digest.clone(),
            receipt_snapshot.status,
            receipt_snapshot.response_digest.clone(),
            receipt_snapshot.observed_at,
        )
        .map_err(ShopifyReceiptReadbackError::Connector)?;
        if receipt.receipt_digest() != receipt_snapshot.receipt_digest {
            return Err(ShopifyReceiptReadbackError::ReceiptBindingMismatch);
        }
        let reconciliation_snapshot = record
            .reconciliation
            .as_ref()
            .ok_or(ShopifyReceiptReadbackError::MissingReconciliationEvidence)?;
        let freshness = FreshnessWindow::new(
            reconciliation_snapshot.freshness_observed_at,
            reconciliation_snapshot.freshness_valid_until,
            reconciliation_snapshot.freshness_source_revision,
        )
        .map_err(ShopifyReceiptReadbackError::Connector)?;
        freshness
            .validate_at(now)
            .map_err(|_| ShopifyReceiptReadbackError::ReadbackFreshnessExpired)?;
        let reconciliation = ReconciliationObservation::new(
            reconciliation_snapshot.effect_digest.clone(),
            approved.prepared_effect().scope().clone(),
            reconciliation_snapshot.status,
            reconciliation_snapshot.provider_state_digest.clone(),
            reconciliation_snapshot.observed_at,
            freshness,
        )
        .map_err(ShopifyReceiptReadbackError::Connector)?;
        let verification_snapshot = record
            .verification
            .as_ref()
            .ok_or(ShopifyReceiptReadbackError::MissingVerificationEvidence)?;
        let verification = VerificationObservation::new(
            verification_snapshot.subject_digest.clone(),
            approved.prepared_effect().scope().clone(),
            verification_snapshot.status,
            verification_snapshot.evidence_digest.clone(),
            verification_snapshot.observed_at,
            verification_snapshot.independent,
        )
        .map_err(ShopifyReceiptReadbackError::Connector)?;
        Self::validate_receipt_candidate(approved, &receipt, now)?;
        Self::validate_verification(approved, &receipt, &verification, now)?;
        let exact_readback = record
            .exact_readback
            .clone()
            .ok_or(ShopifyReceiptReadbackError::MissingReadbackEvidence)?;
        self.validate_exact_readback(approved, &exact_readback, now)?;
        let provider_receipt = record
            .provider_receipt
            .clone()
            .ok_or(ShopifyReceiptReadbackError::MissingProviderResponse)?;
        let provider_response = record
            .provider_response
            .clone()
            .ok_or(ShopifyReceiptReadbackError::MissingProviderResponse)?;
        let outcome = record
            .outcome
            .clone()
            .ok_or(ShopifyReceiptReadbackError::MissingOutcomeEvidence)?;
        if outcome.status != ShopifyFulfillmentOutcomeStatus::Confirmed
            || !outcome.is_first_party()
                && self.provenance_class == ProviderProvenanceClass::ProductionProvider
        {
            return Err(ShopifyReceiptReadbackError::VerificationMismatch);
        }
        Ok(ShopifyFulfillmentReceiptReadbackOutcome {
            operation: SHOPIFY_FULFILLMENT_EFFECT_OPERATION.to_owned(),
            request_digest: approved.draft().request_digest().to_owned(),
            effect_digest: approved.prepared_effect().effect_digest().to_owned(),
            approval_binding_digest: approved.approval_binding_digest().to_owned(),
            scope_digest: approved.draft().tenant_scope().digest(),
            account_id: approved
                .draft()
                .tenant_scope()
                .connector_scope()
                .account_id()
                .to_owned(),
            shop: approved.draft().tenant_scope().shop().clone(),
            order_gid: approved.draft().order_gid().clone(),
            fulfillment_order_gid: approved.draft().fulfillment_order_gid().clone(),
            provider_generation: approved.draft().provider_generation(),
            approval_revision: approved.draft().approval_revision(),
            plugin_revision: approved.plugin_revision(),
            provider_request: record.provider_request.clone(),
            provider_response,
            provider_receipt,
            exact_readback,
            receipt,
            reconciliation,
            verification,
            outcome,
            replayed,
            provenance_class: self.provenance_class,
            live_validation_status: SHOPIFY_FULFILLMENT_LIVE_VALIDATION_STATUS.to_owned(),
        })
    }

    fn fail_closed<T>(
        &mut self,
        key: &str,
        error: ShopifyReceiptReadbackError,
    ) -> Result<T, ShopifyReceiptReadbackError> {
        if let Some(record) = self.store.record_mut(key) {
            record.state = ShopifyFulfillmentReconciliationState::FailedClosed;
        }
        Err(error)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ShopifyReceiptReadbackError {
    #[error("Shopify plugin revision is invalid")]
    InvalidPluginRevision,
    #[error("Shopify provider generation is invalid")]
    InvalidProviderGeneration,
    #[error("invalid Shopify Fulfillment GID {0}")]
    InvalidFulfillmentGid(String),
    #[error("invalid Shopify readback shape")]
    InvalidReadbackShape,
    #[error("approved Shopify Effect is expired")]
    ApprovedEffectExpired,
    #[error("approved Shopify Effect does not match the typed draft")]
    ApprovedEffectBindingMismatch,
    #[error("Shopify reconciliation store does not match its mounted scope/revision")]
    StoreBindingMismatch,
    #[error("Shopify reconciliation consumer is not mounted")]
    ConsumerNotMounted,
    #[error("live Shopify credentials/effect authority are unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("Shopify scope, account, generation, API version, or plugin revision drifted")]
    ScopeDrift,
    #[error("Shopify idempotency key conflicts with a durable receipt record")]
    IdempotencyConflict,
    #[error("Shopify durable record binding does not match the approved Effect")]
    DurableRecordBindingMismatch,
    #[error("Shopify provider request/response identity does not match the approved Effect")]
    ProviderResponseMismatch,
    #[error("Shopify provider receipt candidate does not match the approved Effect")]
    ReceiptBindingMismatch,
    #[error("Shopify reconciliation observation does not match the approved Effect")]
    ReconciliationBindingMismatch,
    #[error("Shopify readback freshness has expired")]
    ReadbackFreshnessExpired,
    #[error("exact Shopify fulfillment/order readback does not match the draft")]
    ReadbackMismatch,
    #[error("Shopify Verification evidence does not match the Receipt")]
    VerificationMismatch,
    #[error("Shopify provider operation was rejected")]
    ProviderRejected,
    #[error("Shopify provider operation remains uncertain; retry only by exact readback")]
    ExecutionUncertain,
    #[error(
        "Shopify reconciliation proved this approved Effect was not executed ({evidence_digest}); a new approval is required"
    )]
    NotExecutedTerminal { evidence_digest: String },
    #[error("Shopify provider readback is pending")]
    ReadbackPending,
    #[error("Shopify Verification evidence is pending")]
    VerificationPending,
    #[error("Shopify Receipt evidence is missing")]
    MissingReceiptEvidence,
    #[error("Shopify reconciliation evidence is missing")]
    MissingReconciliationEvidence,
    #[error("Shopify Verification evidence is missing")]
    MissingVerificationEvidence,
    #[error("Shopify exact readback evidence is missing")]
    MissingReadbackEvidence,
    #[error("Shopify provider response evidence is missing")]
    MissingProviderResponse,
    #[error("Shopify Outcome evidence is missing")]
    MissingOutcomeEvidence,
    #[error("Shopify durable record is missing")]
    DurableRecordMissing,
    #[error("Shopify operation was previously rejected")]
    PreviouslyRejected,
    #[error("Shopify operation previously failed closed")]
    PreviouslyFailedClosed,
    #[error("Shopify generation must increase on rotation")]
    GenerationMustIncrease,
    #[error("Shopify provider execute/reconcile/verify boundary failed: {0}")]
    Boundary(ConnectorError),
    #[error("Connector SDK rejected the typed evidence: {0}")]
    Connector(ConnectorError),
    #[error("Shopify adapter identity rejected: {0}")]
    ShopifyEffect(ShopifyFulfillmentEffectError),
}

impl From<ShopifyFulfillmentEffectError> for ShopifyReceiptReadbackError {
    fn from(error: ShopifyFulfillmentEffectError) -> Self {
        Self::ShopifyEffect(error)
    }
}

pub fn shopify_sdk_effect_idempotency_key(draft: &DraftFulfillmentRequest) -> String {
    format!(
        "effect-idem-{}",
        sha256_digest([draft.idempotency_key().as_str().to_owned()])
    )
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256_digest<I>(parts: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part.len().to_string().as_bytes());
        digest.update(b":");
        digest.update(part.as_bytes());
        digest.update(b"|");
    }
    hex_encode(&digest.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
