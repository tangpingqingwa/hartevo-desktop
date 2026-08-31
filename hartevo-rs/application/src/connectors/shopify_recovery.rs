//! Restart-safe, controlled Shopify payload recovery.
//!
//! The private approved draft is stored only through encrypted project
//! Context-Material CAS. SQLCipher stores a content-free exact binding and a
//! monotonic recovery state. Capsule reopening and all pre-claim
//! authentication remain provider-free; the N16 source obtains a fresh
//! Secret/transport only after its dedicated Broker claim.

use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_commerce_connector::shopify::SHOPIFY_PROVIDER_ID;
pub use hartevo_commerce_connector::shopify_effect::{
    DraftFulfillmentRequest, ShopifyApprovalRevision, ShopifyEffectIdempotencyKey,
    ShopifyFulfillmentLineItem, ShopifyFulfillmentOrderLineItemGid, ShopifyFulfillmentScope,
};
use hartevo_commerce_connector::shopify_effect::{
    SHOPIFY_FULFILLMENT_CAPABILITY, shopify_fulfillment_adapter_identity,
};
use hartevo_commerce_connector::shopify_effect_reconcile::{
    ShopifyApprovedDraftFulfillment, ShopifyPluginRevision, ShopifyTypedEffectBoundary,
    shopify_sdk_effect_idempotency_key,
};
use hartevo_commerce_connector::shopify_transport::{
    ShopifyExpectedFulfillmentIdentity, ShopifyFulfillmentReadbackRequest,
    ShopifyNativeReadbackError, ShopifyReadbackCancellation,
};
pub use hartevo_connector_sdk::ConnectorScope;
use hartevo_connector_sdk::{
    EffectExecutionContext, PreparedEffect, ProviderCapabilityKey, ProviderProvenanceClass,
};
use hartevo_domain_kernel::{
    ApprovalDecision, Connection, ConnectionSnapshot, Effect, EffectStatus, Verification,
    VerificationStatus,
};
use hartevo_effect_broker::{
    DurableReceiptReconciliation, EffectPermissionResolver, EffectPolicy,
    IndependentVerificationObservation, PermissionEvidence, ReceiptRecoveryFence,
    ReceiptVerificationClaimBinding, ReceiptVerificationSource, SecretBrokerConsumer,
    SecretBrokerError, SecretBrokerService, SecretBrokerServiceDefinition, SecretScope,
    StagedReceiptFound, VerificationSourceError, receipt_binding_digest,
};
use hartevo_storage::{
    ContextMaterialStoreError, ProjectStore, ProviderRecoveryBinding, ProviderRecoveryCapsule,
    ProviderRecoveryHead, ProviderRecoveryState, SecretStore, SecretStoreError, StorageError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::shopify::{
    SHOPIFY_APPLICATION_ADAPTER_ID, ShopifyAdapterError, ShopifyEffectAdapter,
    validate_controlled_recovery_effect,
};
use super::shopify_readback::{
    SHOPIFY_INDEPENDENT_VERIFICATION_REGISTRY_VERSION, ShopifyBrokeredReadback,
    ShopifyReadbackBridgeError, ShopifyReadbackCredentialBinding, ShopifySecretReadbackProvider,
    UreqShopifyAdminReadbackTransport, approved_line_item_binding_digest,
    dispatch_shopify_readback_with_registry, shopify_independent_verification_adapter_identity,
    shopify_readback_registry_for,
};
use crate::{ApplicationService, ProjectContextMaterialSession};

const SHOPIFY_RECOVERY_CAPSULE_SCHEMA: &str = "hartevo-shopify-recovery-capsule/v1";
const SHOPIFY_RECEIPT_FOUND_EVIDENCE_SCHEMA: &str = "hartevo-shopify-receipt-found-evidence/v1";
const SHOPIFY_RECOVERY_CAPSULE_REVISION: u64 = 1;
const SHOPIFY_APPLICATION_ADAPTER_VERSION: u64 = 1;
const SHOPIFY_INDEPENDENT_VERIFICATION_EVIDENCE_SCHEMA: &str =
    "hartevo-shopify-independent-verification-evidence/v1";

/// Content-free handle safe for ordinary durable projections and UI status.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyRecoveryCapsuleRef {
    pub project_id: hartevo_domain_kernel::ProjectId,
    pub effect_id: hartevo_domain_kernel::EffectId,
    pub binding_digest: String,
    pub storage_ref: String,
    pub content_digest: String,
    pub key_version: u64,
    pub object_revision: u64,
    pub head_revision: u64,
    pub state: ProviderRecoveryState,
}

impl fmt::Debug for ShopifyRecoveryCapsuleRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShopifyRecoveryCapsuleRef")
            .field("project_id", &"[REDACTED]")
            .field("effect_id", &"[REDACTED]")
            .field("binding_digest", &"[DIGEST]")
            .field("storage_ref", &"[REDACTED]")
            .field("content_digest", &"[DIGEST]")
            .field("key_version", &self.key_version)
            .field("object_revision", &self.object_revision)
            .field("head_revision", &self.head_revision)
            .field("state", &self.state)
            .finish()
    }
}

impl ShopifyRecoveryCapsuleRef {
    /// Produces the current content-free handle after a durable recovery-state
    /// transition. The encrypted capsule and provider payload remain sealed.
    pub fn from_head(head: &ProviderRecoveryHead) -> Self {
        Self {
            project_id: head.binding.project_id.clone(),
            effect_id: head.binding.effect_id.clone(),
            binding_digest: head.binding.binding_digest.clone(),
            storage_ref: head.capsule.storage_ref.clone(),
            content_digest: head.capsule.content_digest.clone(),
            key_version: head.capsule.key_version,
            object_revision: head.capsule.object_revision,
            head_revision: head.revision,
            state: head.state,
        }
    }

    fn matches_head(&self, head: &ProviderRecoveryHead) -> bool {
        self.project_id == head.binding.project_id
            && self.effect_id == head.binding.effect_id
            && self.binding_digest == head.binding.binding_digest
            && self.storage_ref == head.capsule.storage_ref
            && self.content_digest == head.capsule.content_digest
            && self.key_version == head.capsule.key_version
            && self.object_revision == head.capsule.object_revision
            && self.head_revision == head.revision
            && self.state == head.state
    }

    /// Content-free immutable link between this exact recovery head and one
    /// known-GID readback selector. Desktop binds this digest into the Cordis
    /// reconciliation permit; Application recomputes it after reopening the
    /// authenticated capsule.
    pub fn readback_authority_digest(
        &self,
        request: &ShopifyFulfillmentReadbackRequest,
    ) -> Result<String, ShopifyNativeReadbackError> {
        if request.expected_identity().is_some()
            || self.head_revision == 0
            || self.key_version == 0
            || self.object_revision != SHOPIFY_RECOVERY_CAPSULE_REVISION
            || !is_sha256(&self.binding_digest)
            || !is_sha256(&self.content_digest)
            || !matches!(
                self.state,
                ProviderRecoveryState::InFlight | ProviderRecoveryState::Uncertain
            )
        {
            return Err(ShopifyNativeReadbackError::InvalidRequest);
        }
        Ok(canonical_digest(&[
            "hartevo-shopify-recovery-readback-authority/v1".to_owned(),
            self.project_id.to_string(),
            self.effect_id.to_string(),
            self.binding_digest.clone(),
            self.content_digest.clone(),
            self.key_version.to_string(),
            self.object_revision.to_string(),
            self.head_revision.to_string(),
            match self.state {
                ProviderRecoveryState::Prepared => "prepared",
                ProviderRecoveryState::InFlight => "in_flight",
                ProviderRecoveryState::Uncertain => "uncertain",
                ProviderRecoveryState::NotExecuted => "not_executed",
                ProviderRecoveryState::ReceiptObserved => "receipt_observed",
                ProviderRecoveryState::Verified => "verified",
                ProviderRecoveryState::FailedClosed => "failed_closed",
            }
            .to_owned(),
            request.selector_digest(),
        ]))
    }
}

/// Result of a claim-before-return recovery. The contained adapter is still
/// controlled-provider-only; obtaining it means the durable head is already
/// `InFlight`, so a crash cannot recover another execution permit.
pub struct ClaimedShopifyRecovery<B> {
    adapter: ShopifyEffectAdapter<B>,
    head: ProviderRecoveryHead,
}

impl<B> fmt::Debug for ClaimedShopifyRecovery<B> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaimedShopifyRecovery")
            .field("effect_id", &self.head.binding.effect_id)
            .field("state", &self.head.state)
            .field("revision", &self.head.revision)
            .finish_non_exhaustive()
    }
}

impl<B> ClaimedShopifyRecovery<B> {
    pub fn adapter(&self) -> &ShopifyEffectAdapter<B> {
        &self.adapter
    }

    pub fn head(&self) -> &ProviderRecoveryHead {
        &self.head
    }

    pub fn into_adapter(self) -> ShopifyEffectAdapter<B> {
        self.adapter
    }
}

/// Read-only reopening of the approved private capsule for an already
/// uncertain Effect. It carries no adapter, execution handle, or provider.
pub struct ReopenedShopifyReconciliation {
    approved: ShopifyApprovedDraftFulfillment,
    effect: Effect,
    head: ProviderRecoveryHead,
    current_mission_revision: u64,
}

impl fmt::Debug for ReopenedShopifyReconciliation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReopenedShopifyReconciliation")
            .field("effect_id", &self.effect.id)
            .field("current_mission_revision", &self.current_mission_revision)
            .field("recovery_state", &self.head.state)
            .field("recovery_revision", &self.head.revision)
            .finish_non_exhaustive()
    }
}

impl ReopenedShopifyReconciliation {
    /// Confirms that Desktop's already-loaded Cordis fence still names this
    /// exact reopened Effect and credential generation without exposing the
    /// decrypted approved draft or recovery head.
    pub fn matches_current_fence(
        &self,
        effect: &Effect,
        expected_mission_revision: u64,
        credential_revision: u64,
    ) -> bool {
        self.current_mission_revision == expected_mission_revision
            && &self.effect == effect
            && self.head.binding.credential_revision == credential_revision
    }

    /// Replaces a minimal known-GID request with one bound to the exact
    /// approved private draft. No draft field crosses into Desktop.
    pub fn bind_exact_readback(
        &self,
        request: &ShopifyFulfillmentReadbackRequest,
        authority_digest: &str,
    ) -> Result<ShopifyFulfillmentReadbackRequest, ShopifyNativeReadbackError> {
        let draft = self.approved.draft();
        let current_reference = ShopifyRecoveryCapsuleRef::from_head(&self.head);
        if current_reference
            .readback_authority_digest(request)?
            .as_str()
            != authority_digest
            || request.expected_identity().is_some()
            || draft.api_version() != request.api_version()
            || draft.tenant_scope().shop() != request.shop()
        {
            return Err(ShopifyNativeReadbackError::InvalidRequest);
        }
        let expected = ShopifyExpectedFulfillmentIdentity::new(
            draft.order_gid().clone(),
            draft.fulfillment_order_gid().clone(),
            draft.line_items().to_vec(),
            self.effect
                .approval
                .as_ref()
                .map(|approval| approval.decided_at.max(self.head.prepared_at))
                .ok_or(ShopifyNativeReadbackError::InvalidRequest)?,
        )?;
        ShopifyFulfillmentReadbackRequest::new_exact(
            request.shop().clone(),
            request.api_version().clone(),
            request.fulfillment_id().clone(),
            expected,
        )
    }

    /// Seals one production readback as a receipt-only Broker observation.
    /// The full identity stays in encrypted project material; the returned
    /// value contains only the Domain Receipt and exact durable fences needed
    /// for the SQLCipher atomic commit.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_lines)]
    pub fn seal_receipt_found(
        &self,
        brokered: &ShopifyBrokeredReadback,
        selector: &ShopifyFulfillmentReadbackRequest,
        exact_request: &ShopifyFulfillmentReadbackRequest,
        connection_snapshot: ConnectionSnapshot,
        material: &ProjectContextMaterialSession,
        observation_authority_digest: &str,
        execution_started_at: DateTime<Utc>,
        observed_at: DateTime<Utc>,
    ) -> Result<StagedReceiptFound, ShopifyRecoveryError> {
        if !is_sha256(observation_authority_digest)
            || material.project_id() != &self.effect.project_id
            || material.keyring_revision() != self.head.binding.keyring_revision
            || selector.expected_identity().is_some()
            || self
                .bind_exact_readback(selector, observation_authority_digest)
                .map_err(|_| ShopifyRecoveryError::BindingMismatch)?
                != *exact_request
        {
            return Err(ShopifyRecoveryError::BindingMismatch);
        }
        let metadata = brokered
            .identity_metadata(observed_at)
            .map_err(|_| ShopifyRecoveryError::InvalidReceiptEvidence)?;
        let draft = self.approved.draft();
        let approval = self
            .effect
            .approval
            .as_ref()
            .ok_or(ShopifyRecoveryError::BindingMismatch)?;
        let connection = Connection::restore(connection_snapshot.clone())
            .map_err(|_| ShopifyRecoveryError::BindingMismatch)?;
        let expected_line_items = approved_line_item_binding_digest(draft.line_items());
        if metadata.provenance_class != ProviderProvenanceClass::ProductionProvider
            || metadata.fulfillment_id != *exact_request.fulfillment_id()
            || metadata.api_version != *draft.api_version()
            || metadata.order_id != *draft.order_gid()
            || metadata.fulfillment_order_id != *draft.fulfillment_order_gid()
            || metadata.line_item_binding_digest != expected_line_items
            || !metadata.lease_reclaimed
            || brokered.credential_use().credential_revision()
                != self.head.binding.credential_revision
            || brokered.credential_use().used_at() < execution_started_at
            || brokered.credential_use().used_at() > observed_at
            || metadata.provider_created_at < execution_started_at
            || metadata.provider_updated_at < metadata.provider_created_at
            || metadata.provider_updated_at > observed_at
            || metadata.provider_created_at >= self.effect.expires_at
            || connection_snapshot.tenant_id != self.effect.tenant_id
            || connection_snapshot.project_id != self.effect.project_id
            || connection_snapshot.provider != SHOPIFY_PROVIDER_ID
            || self.effect.connection_id.as_ref() != Some(&connection_snapshot.id)
            || self.effect.account_id.as_ref() != Some(&connection_snapshot.account_id)
            || connection_snapshot.revision != self.head.binding.credential_revision
            || connection_snapshot.expected_external_account_id
                != draft.tenant_scope().shop().as_str()
            || connection_snapshot.last_probe.as_ref().is_none_or(|probe| {
                probe.observed_external_account_id != draft.tenant_scope().shop().as_str()
            })
            || !connection.permits_scopes(&self.effect.required_scopes, observed_at)
            || approval.scope_digest != self.effect.approval_digest()
            || approval.permission_digest != self.head.binding.broker_authorization_digest
            || self.current_mission_revision == 0
            || !matches!(
                self.head.state,
                ProviderRecoveryState::InFlight | ProviderRecoveryState::Uncertain
            )
        {
            return Err(ShopifyRecoveryError::BindingMismatch);
        }

        let evidence = StoredShopifyReceiptFoundEvidence {
            schema: SHOPIFY_RECEIPT_FOUND_EVIDENCE_SCHEMA.to_owned(),
            effect_id: self.effect.id.as_str().to_owned(),
            effect_approval_digest: approval.scope_digest.clone(),
            broker_authorization_digest: approval.permission_digest.clone(),
            original_execution_started_at: execution_started_at,
            recovery_binding_digest: self.head.binding.binding_digest.clone(),
            recovery_capsule_content_digest: self.head.capsule.content_digest.clone(),
            recovery_capsule_key_version: self.head.capsule.key_version,
            recovery_capsule_object_revision: self.head.capsule.object_revision,
            recovery_head_revision: self.head.revision,
            recovery_head_state: self.head.state,
            credential_revision: self.head.binding.credential_revision,
            secret_broker_use_digest: brokered.credential_use().use_digest().to_owned(),
            selector_digest: selector.selector_digest(),
            observation_authority_digest: observation_authority_digest.to_owned(),
            shop: draft.tenant_scope().shop().as_str().to_owned(),
            api_version: draft.api_version().as_str().to_owned(),
            fulfillment_id: metadata.fulfillment_id.as_str().to_owned(),
            fulfillment_status: metadata.status.as_str().to_owned(),
            order_id: metadata.order_id.as_str().to_owned(),
            fulfillment_order_id: metadata.fulfillment_order_id.as_str().to_owned(),
            line_item_binding_digest: metadata.line_item_binding_digest,
            native_response_digest: metadata.response_digest,
            native_evidence_digest: metadata.evidence_digest,
            native_request_id_digest: metadata.request_id_digest,
            provider_created_at: metadata.provider_created_at,
            provider_updated_at: metadata.provider_updated_at,
            observed_at,
            provenance_class: metadata.provenance_class,
        };
        let encoded = serde_json::to_string(&evidence)
            .map_err(|_| ShopifyRecoveryError::InvalidReceiptEvidence)?;
        let descriptor = material.put_text(&encoded)?;
        if descriptor.content_digest != sha256(encoded.as_bytes())
            || descriptor.storage_ref != format!("cas://{}", descriptor.content_digest)
        {
            return Err(ShopifyRecoveryError::InvalidReceiptEvidence);
        }
        let recovery = ReceiptRecoveryFence::new(
            self.current_mission_revision,
            connection_snapshot,
            self.head.revision,
            self.head.binding.binding_digest.clone(),
            self.head.capsule.content_digest.clone(),
            self.head.capsule.key_version,
            self.head.capsule.object_revision,
            descriptor.storage_ref,
            descriptor.content_digest.clone(),
        )
        .map_err(|_| ShopifyRecoveryError::InvalidReceiptEvidence)?;
        StagedReceiptFound::new(
            &self.effect,
            recovered_shopify_external_id(metadata.fulfillment_id.as_str()),
            metadata.provider_created_at,
            descriptor.content_digest,
            observed_at,
            recovery,
        )
        .map_err(|_| ShopifyRecoveryError::InvalidReceiptEvidence)
    }
}

/// Read-only reopening for the N16 independent verification route. The
/// original InFlight/Uncertain reference remains immutable; `head` is the
/// current ReceiptObserved/terminal recovery head. No execution adapter is
/// carried by this value.
pub struct ReopenedShopifyVerification {
    approved: ShopifyApprovedDraftFulfillment,
    effect: Effect,
    head: ProviderRecoveryHead,
    original_reference: ShopifyRecoveryCapsuleRef,
    current_mission_revision: u64,
    connection: Option<ConnectionSnapshot>,
}

impl fmt::Debug for ReopenedShopifyVerification {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReopenedShopifyVerification")
            .field("effect_id", &self.effect.id)
            .field("current_mission_revision", &self.current_mission_revision)
            .field("recovery_state", &self.head.state)
            .field("recovery_revision", &self.head.revision)
            .field("has_live_connection", &self.connection.is_some())
            .finish_non_exhaustive()
    }
}

impl ReopenedShopifyVerification {
    fn bind_exact_readback(
        &self,
        request: &ShopifyFulfillmentReadbackRequest,
        authority_digest: &str,
    ) -> Result<ShopifyFulfillmentReadbackRequest, ShopifyNativeReadbackError> {
        let draft = self.approved.draft();
        if self
            .original_reference
            .readback_authority_digest(request)?
            .as_str()
            != authority_digest
            || request.expected_identity().is_some()
            || draft.api_version() != request.api_version()
            || draft.tenant_scope().shop() != request.shop()
        {
            return Err(ShopifyNativeReadbackError::InvalidRequest);
        }
        let expected = ShopifyExpectedFulfillmentIdentity::new(
            draft.order_gid().clone(),
            draft.fulfillment_order_gid().clone(),
            draft.line_items().to_vec(),
            self.effect
                .approval
                .as_ref()
                .map(|approval| approval.decided_at.max(self.head.prepared_at))
                .ok_or(ShopifyNativeReadbackError::InvalidRequest)?,
        )?;
        ShopifyFulfillmentReadbackRequest::new_exact(
            request.shop().clone(),
            request.api_version().clone(),
            request.fulfillment_id().clone(),
            expected,
        )
    }

    pub fn effect(&self) -> &Effect {
        &self.effect
    }

    pub fn head(&self) -> &ProviderRecoveryHead {
        &self.head
    }

    pub const fn current_mission_revision(&self) -> u64 {
        self.current_mission_revision
    }

    pub fn original_reference(&self) -> &ShopifyRecoveryCapsuleRef {
        &self.original_reference
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredShopifyReceiptFoundEvidence {
    schema: String,
    effect_id: String,
    effect_approval_digest: String,
    broker_authorization_digest: String,
    original_execution_started_at: DateTime<Utc>,
    recovery_binding_digest: String,
    recovery_capsule_content_digest: String,
    recovery_capsule_key_version: u64,
    recovery_capsule_object_revision: u64,
    recovery_head_revision: u64,
    recovery_head_state: ProviderRecoveryState,
    credential_revision: u64,
    secret_broker_use_digest: String,
    selector_digest: String,
    observation_authority_digest: String,
    shop: String,
    api_version: String,
    fulfillment_id: String,
    fulfillment_status: String,
    order_id: String,
    fulfillment_order_id: String,
    line_item_binding_digest: String,
    native_response_digest: String,
    native_evidence_digest: String,
    native_request_id_digest: Option<String>,
    provider_created_at: DateTime<Utc>,
    provider_updated_at: DateTime<Utc>,
    observed_at: DateTime<Utc>,
    provenance_class: ProviderProvenanceClass,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredShopifyVerificationEvidence {
    schema: String,
    effect_id: String,
    receipt_id: String,
    receipt_response_digest: String,
    receipt_binding_digest: String,
    n15_evidence_digest: String,
    recovery_binding_digest: String,
    recovery_capsule_content_digest: String,
    recovery_capsule_key_version: u64,
    recovery_capsule_object_revision: u64,
    recovery_head_revision: u64,
    recovery_head_state: ProviderRecoveryState,
    credential_revision: u64,
    selector_digest: String,
    observation_authority_digest: String,
    source_binding_digest: String,
    adapter_id: String,
    adapter_version: u32,
    registry_version: String,
    shop: String,
    api_version: String,
    fulfillment_id: String,
    fulfillment_status: String,
    order_id: String,
    fulfillment_order_id: String,
    line_item_binding_digest: String,
    native_response_digest: String,
    native_evidence_digest: String,
    native_request_id_digest: Option<String>,
    secret_broker_use_digest: String,
    provider_created_at: DateTime<Utc>,
    provider_updated_at: DateTime<Utc>,
    observed_at: DateTime<Utc>,
    provenance_class: ProviderProvenanceClass,
}

/// Fresh, production-shaped Shopify source for the N16 route. The source is
/// deliberately lazy: construction binds only content-free selector and
/// recovery metadata. Secret Broker/provider objects are created inside
/// `observe` after local N15 evidence and cancellation fences pass.
pub struct ShopifyIndependentVerificationSource<'a, S, T> {
    secret_store: &'a S,
    material: &'a ProjectContextMaterialSession,
    approved: ShopifyApprovedDraftFulfillment,
    effect: Effect,
    head: ProviderRecoveryHead,
    original_reference: ShopifyRecoveryCapsuleRef,
    connection: Option<ConnectionSnapshot>,
    selector: ShopifyFulfillmentReadbackRequest,
    exact_request: ShopifyFulfillmentReadbackRequest,
    binding: ShopifyReadbackCredentialBinding,
    observation_authority_digest: String,
    source_binding_digest: String,
    verifier_id: String,
    cancellation: ShopifyReadbackCancellation,
    transport: Option<T>,
    expected_provenance: ProviderProvenanceClass,
}

impl<S, T> fmt::Debug for ShopifyIndependentVerificationSource<'_, S, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShopifyIndependentVerificationSource")
            .field("effect_id", &self.effect.id)
            .field("selector_digest", &self.selector.selector_digest())
            .field("source_binding_digest", &"[DIGEST]")
            .field("verifier_id", &self.verifier_id)
            .field("has_transport", &self.transport.is_some())
            .field("has_live_connection", &self.connection.is_some())
            .finish_non_exhaustive()
    }
}

impl<'a, S, T> ShopifyIndependentVerificationSource<'a, S, T>
where
    S: SecretStore,
    T: hartevo_commerce_connector::shopify_transport::ShopifyAdminReadbackTransport,
{
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn new_with_provenance(
        secret_store: &'a S,
        material: &'a ProjectContextMaterialSession,
        reopened: ReopenedShopifyVerification,
        selector: ShopifyFulfillmentReadbackRequest,
        observation_authority_digest: impl Into<String>,
        cancellation: ShopifyReadbackCancellation,
        transport: T,
        expected_provenance: ProviderProvenanceClass,
    ) -> Result<Self, ShopifyRecoveryError> {
        let observation_authority_digest = observation_authority_digest.into();
        let exact_request = reopened
            .bind_exact_readback(&selector, &observation_authority_digest)
            .map_err(|_| ShopifyRecoveryError::BindingMismatch)?;
        let receipt = reopened
            .effect
            .receipt
            .as_ref()
            .ok_or(ShopifyRecoveryError::BindingMismatch)?;
        if material.project_id() != &reopened.effect.project_id
            || material.keyring_revision() != reopened.head.binding.keyring_revision
            || !material
                .readable_key_versions()
                .contains(&reopened.head.capsule.key_version)
            || !is_sha256(&observation_authority_digest)
            || !matches!(
                reopened.head.state,
                ProviderRecoveryState::ReceiptObserved
                    | ProviderRecoveryState::Verified
                    | ProviderRecoveryState::FailedClosed
            )
            || reopened.head.readback_content_digest.as_deref()
                != Some(receipt.response_digest.as_str())
            || reopened.head.receipt_evidence_digest.as_deref()
                != Some(receipt.response_digest.as_str())
        {
            return Err(ShopifyRecoveryError::BindingMismatch);
        }
        let adapter = shopify_independent_verification_adapter_identity()
            .map_err(|_| ShopifyRecoveryError::BindingMismatch)?;
        let binding = ShopifyReadbackCredentialBinding::new_with_adapter(
            SecretScope::new(
                reopened.effect.tenant_id.clone(),
                reopened.effect.project_id.clone(),
                reopened.effect.mission_id.clone(),
                SHOPIFY_PROVIDER_ID,
                reopened
                    .effect
                    .account_id
                    .clone()
                    .ok_or(ShopifyRecoveryError::BindingMismatch)?,
                SHOPIFY_FULFILLMENT_CAPABILITY,
            )
            .map_err(|_| ShopifyRecoveryError::BindingMismatch)?,
            selector.shop().clone(),
            reopened.head.binding.credential_revision,
            adapter.clone(),
        )
        .map_err(|_| ShopifyRecoveryError::BindingMismatch)?;
        let verifier_id = "shopify.independent-verification".to_owned();
        let source_binding_digest = canonical_digest(&[
            "hartevo-shopify-independent-verification-source/v1".to_owned(),
            reopened.effect.id.to_string(),
            reopened.effect.provider.clone(),
            reopened.effect.capability.clone(),
            receipt_binding_digest(receipt),
            reopened.head.binding.binding_digest.clone(),
            reopened.head.capsule.content_digest.clone(),
            reopened.head.capsule.key_version.to_string(),
            reopened.head.capsule.object_revision.to_string(),
            reopened.original_reference.head_revision.to_string(),
            recovery_state_name(reopened.original_reference.state).to_owned(),
            reopened
                .original_reference
                .head_revision
                .checked_add(1)
                .ok_or(ShopifyRecoveryError::BindingMismatch)?
                .to_string(),
            selector.selector_digest(),
            exact_request.selector_digest(),
            observation_authority_digest.clone(),
            adapter.adapter_id().to_owned(),
            adapter.adapter_version().to_string(),
            SHOPIFY_INDEPENDENT_VERIFICATION_REGISTRY_VERSION.to_owned(),
            reopened.head.binding.plugin_revision.to_string(),
            reopened.head.binding.provider_generation.to_string(),
            reopened.head.binding.credential_revision.to_string(),
        ]);
        let source = Self {
            secret_store,
            material,
            approved: reopened.approved,
            effect: reopened.effect,
            head: reopened.head,
            original_reference: reopened.original_reference,
            connection: reopened.connection,
            selector,
            exact_request,
            binding,
            observation_authority_digest,
            source_binding_digest,
            verifier_id,
            cancellation,
            transport: Some(transport),
            expected_provenance,
        };
        // Authenticate the immutable N15 receipt/evidence capsule before the
        // Broker can insert a verification claim. The source repeats this
        // check in `observe` and `validate_recovered`; this first check closes
        // the pre-claim missing/corrupt/swapped-evidence window without any
        // Secret Broker or provider access.
        let receipt = source
            .effect
            .receipt
            .as_ref()
            .ok_or(ShopifyRecoveryError::BindingMismatch)?;
        source
            .validate_n15_receipt_material_inner(receipt, None)
            .map_err(|_| ShopifyRecoveryError::InvalidReceiptEvidence)?;
        Ok(source)
    }

    pub fn binding(&self) -> &ShopifyReadbackCredentialBinding {
        &self.binding
    }

    pub fn selector(&self) -> &ShopifyFulfillmentReadbackRequest {
        &self.selector
    }

    pub fn observation_authority_digest(&self) -> &str {
        &self.observation_authority_digest
    }

    pub fn source_binding_digest(&self) -> &str {
        &self.source_binding_digest
    }

    pub fn verifier_id(&self) -> &str {
        &self.verifier_id
    }

    /// Whether this source was reopened against a live Connection for an
    /// initial provider read. Terminal replay deliberately has no live
    /// Connection requirement so credential rotation cannot block local
    /// durable recovery.
    #[must_use]
    pub const fn requires_live_connection(&self) -> bool {
        self.connection.is_some()
    }

    #[must_use]
    pub const fn credential_revision(&self) -> u64 {
        self.head.binding.credential_revision
    }

    pub fn claim_binding(&self) -> Result<ReceiptVerificationClaimBinding, ShopifyRecoveryError> {
        let receipt = self
            .effect
            .receipt
            .as_ref()
            .ok_or(ShopifyRecoveryError::BindingMismatch)?;
        ReceiptVerificationClaimBinding::new(
            self.effect.approval_digest(),
            self.effect
                .approval
                .as_ref()
                .ok_or(ShopifyRecoveryError::BindingMismatch)?
                .permission_digest
                .clone(),
            receipt_binding_digest(receipt),
            self.observation_authority_digest.clone(),
            self.source_binding_digest.clone(),
        )
        .map_err(|_| ShopifyRecoveryError::BindingMismatch)
    }

    fn load_material(&self, storage_ref: &str) -> Result<String, VerificationSourceError> {
        match self.material.load_text(storage_ref) {
            Ok(Some(value)) => Ok(value.as_str().to_owned()),
            Ok(None) => Err(VerificationSourceError::Rejected),
            Err(_) => Err(VerificationSourceError::Unavailable),
        }
    }

    fn validate_n15_receipt_material(
        &self,
        subject: &hartevo_effect_broker::ReceiptVerificationSubject,
    ) -> Result<DateTime<Utc>, VerificationSourceError> {
        let approval = self
            .effect
            .approval
            .as_ref()
            .ok_or(VerificationSourceError::Rejected)?;
        if subject.effect_id() != &self.effect.id
            || subject.provider() != self.effect.provider
            || subject.capability() != self.effect.capability
            || subject.approval_scope_digest() != self.effect.approval_digest()
            || subject.broker_authorization_digest() != approval.permission_digest
        {
            return Err(VerificationSourceError::Rejected);
        }
        self.validate_n15_receipt_material_inner(
            subject.receipt(),
            Some(subject.execution_started_at()),
        )
    }

    fn validate_n15_receipt_material_inner(
        &self,
        receipt: &hartevo_domain_kernel::Receipt,
        execution_started_at: Option<DateTime<Utc>>,
    ) -> Result<DateTime<Utc>, VerificationSourceError> {
        let approval = self
            .effect
            .approval
            .as_ref()
            .ok_or(VerificationSourceError::Rejected)?;
        if receipt.provider != self.effect.provider
            || receipt.request_digest != self.effect.approval_digest()
            || !is_sha256(&receipt.response_digest)
            || execution_started_at.is_some_and(|started_at| receipt.accepted_at < started_at)
            || self.head.readback_storage_ref.as_deref()
                != Some(format!("cas://{}", receipt.response_digest).as_str())
            || self.head.readback_content_digest.as_deref()
                != Some(receipt.response_digest.as_str())
            || self.head.receipt_evidence_digest.as_deref()
                != Some(receipt.response_digest.as_str())
            || !matches!(
                self.head.state,
                ProviderRecoveryState::ReceiptObserved
                    | ProviderRecoveryState::Verified
                    | ProviderRecoveryState::FailedClosed
            )
        {
            return Err(VerificationSourceError::Rejected);
        }
        let storage_ref = self
            .head
            .readback_storage_ref
            .as_deref()
            .ok_or(VerificationSourceError::Rejected)?;
        let resolved = self.load_material(storage_ref)?;
        if sha256(resolved.as_bytes()) != receipt.response_digest {
            return Err(VerificationSourceError::Rejected);
        }
        let evidence: StoredShopifyReceiptFoundEvidence =
            serde_json::from_str(&resolved).map_err(|_| VerificationSourceError::Rejected)?;
        let draft = self.approved.draft();
        let expected_receipt_head_revision = self
            .original_reference
            .head_revision
            .checked_add(1)
            .ok_or(VerificationSourceError::Rejected)?;
        let expected_current_head_revision = match self.head.state {
            ProviderRecoveryState::ReceiptObserved => expected_receipt_head_revision,
            ProviderRecoveryState::Verified | ProviderRecoveryState::FailedClosed => {
                expected_receipt_head_revision
                    .checked_add(1)
                    .ok_or(VerificationSourceError::Rejected)?
            }
            _ => return Err(VerificationSourceError::Rejected),
        };
        if evidence.schema != SHOPIFY_RECEIPT_FOUND_EVIDENCE_SCHEMA
            || evidence.effect_id != self.effect.id.as_str()
            || evidence.effect_approval_digest != approval.scope_digest
            || evidence.broker_authorization_digest != approval.permission_digest
            || execution_started_at
                .is_some_and(|started_at| evidence.original_execution_started_at != started_at)
            || evidence.recovery_binding_digest != self.head.binding.binding_digest
            || evidence.recovery_capsule_content_digest != self.head.capsule.content_digest
            || evidence.recovery_capsule_key_version != self.head.capsule.key_version
            || evidence.recovery_capsule_object_revision != self.head.capsule.object_revision
            || evidence.recovery_head_revision != self.original_reference.head_revision
            || evidence.recovery_head_state != self.original_reference.state
            || self.head.revision != expected_current_head_revision
            || evidence.credential_revision != self.head.binding.credential_revision
            || evidence.selector_digest != self.selector.selector_digest()
            || evidence.observation_authority_digest != self.observation_authority_digest
            || evidence.shop != self.selector.shop().as_str()
            || evidence.shop != draft.tenant_scope().shop().as_str()
            || evidence.api_version != self.selector.api_version().as_str()
            || evidence.api_version != draft.api_version().as_str()
            || evidence.fulfillment_id != self.selector.fulfillment_id().as_str()
            || evidence.order_id != draft.order_gid().as_str()
            || evidence.fulfillment_order_id != draft.fulfillment_order_gid().as_str()
            || evidence.line_item_binding_digest
                != approved_line_item_binding_digest(draft.line_items())
            || evidence.fulfillment_status.trim().is_empty()
            || evidence.original_execution_started_at > receipt.accepted_at
            || evidence.provider_created_at != receipt.accepted_at
            || evidence.provider_created_at < evidence.original_execution_started_at
            || execution_started_at
                .is_some_and(|started_at| evidence.provider_created_at < started_at)
            || evidence.provider_updated_at < evidence.provider_created_at
            || evidence.observed_at < evidence.provider_updated_at
            || evidence.observed_at > self.head.updated_at
            || evidence.provenance_class != ProviderProvenanceClass::ProductionProvider
            || receipt.external_id != recovered_shopify_external_id(&evidence.fulfillment_id)
            || !is_sha256(&evidence.secret_broker_use_digest)
            || !is_sha256(&evidence.line_item_binding_digest)
            || !is_sha256(&evidence.native_response_digest)
            || !is_sha256(&evidence.native_evidence_digest)
            || evidence
                .native_request_id_digest
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
        {
            return Err(VerificationSourceError::Rejected);
        }
        Ok(evidence.provider_updated_at)
    }

    fn validate_connection(&self, at: DateTime<Utc>) -> Result<(), VerificationSourceError> {
        let connection = self
            .connection
            .as_ref()
            .ok_or(VerificationSourceError::Rejected)
            .and_then(|snapshot| {
                Connection::restore(snapshot.clone()).map_err(|_| VerificationSourceError::Rejected)
            })?;
        if connection.tenant_id() != &self.effect.tenant_id
            || connection.project_id() != &self.effect.project_id
            || connection.provider() != self.effect.provider
            || self.effect.connection_id.as_ref() != Some(connection.id())
            || self.effect.account_id.as_ref() != Some(connection.account_id())
            || connection.last_probe().is_none_or(|probe| {
                probe.observed_external_account_id
                    != self.approved.draft().tenant_scope().shop().as_str()
            })
            || connection.snapshot().expected_external_account_id
                != self.approved.draft().tenant_scope().shop().as_str()
            || connection.revision() != self.head.binding.credential_revision
            || !connection.permits_scopes(&self.effect.required_scopes, at)
        {
            return Err(VerificationSourceError::Rejected);
        }
        Ok(())
    }

    fn map_bridge_error(error: &ShopifyReadbackBridgeError) -> VerificationSourceError {
        match error {
            ShopifyReadbackBridgeError::Transport(
                ShopifyNativeReadbackError::CancelledBeforeDispatch
                | ShopifyNativeReadbackError::CancelledAfterDispatch,
            ) => VerificationSourceError::Cancelled,
            ShopifyReadbackBridgeError::SecretStore(SecretStoreError::BackendUnavailable)
            | ShopifyReadbackBridgeError::SecretBroker(SecretBrokerError::Crashed)
            | ShopifyReadbackBridgeError::Transport(
                ShopifyNativeReadbackError::TimedOut
                | ShopifyNativeReadbackError::RateLimited
                | ShopifyNativeReadbackError::TransportUnavailable,
            ) => VerificationSourceError::Unavailable,
            ShopifyReadbackBridgeError::BindingMismatch
            | ShopifyReadbackBridgeError::MissingProviderOutcome
            | ShopifyReadbackBridgeError::MissingReceiptIdentity
            | ShopifyReadbackBridgeError::InvalidReceiptIdentity
            | ShopifyReadbackBridgeError::ProviderContract(_)
            | ShopifyReadbackBridgeError::SecretBroker(_)
            | ShopifyReadbackBridgeError::SecretStore(_)
            | ShopifyReadbackBridgeError::Transport(_) => VerificationSourceError::Rejected,
        }
    }

    fn verification_status(status: &str) -> VerificationStatus {
        match status {
            "SUCCESS" => VerificationStatus::Confirmed,
            "CANCELLED" | "FAILED" | "FAILURE" | "REJECTED" | "ERROR" => {
                VerificationStatus::Rejected
            }
            _ => VerificationStatus::Inconclusive,
        }
    }

    fn validate_verification_material(
        &self,
        subject: &hartevo_effect_broker::ReceiptVerificationSubject,
        verification: &Verification,
    ) -> Result<(), VerificationSourceError> {
        let n15_provider_updated_at = self.validate_n15_receipt_material(subject)?;
        if verification.receipt_id != subject.receipt().id
            || !verification.independent
            || verification.verifier != self.verifier_id
            || verification.observed_at < subject.receipt().accepted_at
            || verification.observed_at > Utc::now()
            || !is_sha256(&verification.evidence_digest)
        {
            return Err(VerificationSourceError::Rejected);
        }
        let storage_ref = format!("cas://{}", verification.evidence_digest);
        let resolved = self.load_material(&storage_ref)?;
        let evidence: StoredShopifyVerificationEvidence =
            serde_json::from_str(&resolved).map_err(|_| VerificationSourceError::Rejected)?;
        let receipt = subject.receipt();
        let expected_receipt_head_revision = self
            .original_reference
            .head_revision
            .checked_add(1)
            .ok_or(VerificationSourceError::Rejected)?;
        if sha256(resolved.as_bytes()) != verification.evidence_digest
            || evidence.schema != SHOPIFY_INDEPENDENT_VERIFICATION_EVIDENCE_SCHEMA
            || evidence.effect_id != self.effect.id.as_str()
            || evidence.receipt_id != receipt.id.as_str()
            || evidence.receipt_response_digest != receipt.response_digest
            || evidence.receipt_binding_digest != receipt_binding_digest(receipt)
            || evidence.n15_evidence_digest != receipt.response_digest
            || evidence.recovery_binding_digest != self.head.binding.binding_digest
            || evidence.recovery_capsule_content_digest != self.head.capsule.content_digest
            || evidence.recovery_capsule_key_version != self.head.capsule.key_version
            || evidence.recovery_capsule_object_revision != self.head.capsule.object_revision
            || evidence.recovery_head_revision != expected_receipt_head_revision
            || evidence.recovery_head_state != ProviderRecoveryState::ReceiptObserved
            || evidence.credential_revision != self.head.binding.credential_revision
            || evidence.selector_digest != self.selector.selector_digest()
            || evidence.observation_authority_digest != self.observation_authority_digest
            || evidence.source_binding_digest != self.source_binding_digest
            || evidence.adapter_id != self.binding.adapter().adapter_id()
            || evidence.adapter_version != self.binding.adapter().adapter_version()
            || evidence.registry_version != SHOPIFY_INDEPENDENT_VERIFICATION_REGISTRY_VERSION
            || evidence.shop != self.selector.shop().as_str()
            || evidence.api_version != self.selector.api_version().as_str()
            || evidence.fulfillment_id != self.selector.fulfillment_id().as_str()
            || evidence.order_id != self.approved.draft().order_gid().as_str()
            || evidence.fulfillment_order_id
                != self.approved.draft().fulfillment_order_gid().as_str()
            || evidence.line_item_binding_digest
                != approved_line_item_binding_digest(self.approved.draft().line_items())
            || evidence.fulfillment_status.trim().is_empty()
            || Self::verification_status(&evidence.fulfillment_status) != verification.status
            || evidence.provider_created_at != receipt.accepted_at
            || evidence.provider_created_at < subject.execution_started_at()
            || evidence.provider_created_at > evidence.provider_updated_at
            || evidence.provider_updated_at < n15_provider_updated_at
            || evidence.provider_updated_at > evidence.observed_at
            || evidence.observed_at != verification.observed_at
            || evidence.observed_at > Utc::now()
            || evidence.provenance_class != ProviderProvenanceClass::ProductionProvider
            || !is_sha256(&evidence.n15_evidence_digest)
            || !is_sha256(&evidence.native_response_digest)
            || !is_sha256(&evidence.native_evidence_digest)
            || !is_sha256(&evidence.secret_broker_use_digest)
            || !is_sha256(&evidence.line_item_binding_digest)
            || evidence
                .native_request_id_digest
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
        {
            return Err(VerificationSourceError::Rejected);
        }
        Ok(())
    }
}

impl<'a, S> ShopifyIndependentVerificationSource<'a, S, UreqShopifyAdminReadbackTransport>
where
    S: SecretStore,
{
    pub fn new_native(
        secret_store: &'a S,
        material: &'a ProjectContextMaterialSession,
        reopened: ReopenedShopifyVerification,
        selector: ShopifyFulfillmentReadbackRequest,
        observation_authority_digest: impl Into<String>,
        cancellation: ShopifyReadbackCancellation,
        transport: UreqShopifyAdminReadbackTransport,
    ) -> Result<Self, ShopifyRecoveryError> {
        Self::new_with_provenance(
            secret_store,
            material,
            reopened,
            selector,
            observation_authority_digest,
            cancellation,
            transport,
            ProviderProvenanceClass::ProductionProvider,
        )
    }
}

impl<S, T> ReceiptVerificationSource for ShopifyIndependentVerificationSource<'_, S, T>
where
    S: SecretStore,
    T: hartevo_commerce_connector::shopify_transport::ShopifyAdminReadbackTransport,
{
    fn verifier_id(&self) -> &str {
        &self.verifier_id
    }

    fn source_binding_digest(&self) -> String {
        self.source_binding_digest.clone()
    }

    // The fresh read, post-read fences, evidence sealing, and classification
    // intentionally remain adjacent so their security order is auditable.
    #[allow(clippy::too_many_lines)]
    fn observe(
        &mut self,
        subject: &hartevo_effect_broker::ReceiptVerificationSubject,
    ) -> Result<IndependentVerificationObservation, VerificationSourceError> {
        let n15_provider_updated_at = self.validate_n15_receipt_material(subject)?;
        if self.cancellation.is_cancelled() {
            return Err(VerificationSourceError::Cancelled);
        }
        let now = Utc::now();
        self.validate_connection(now)?;
        let transport = self
            .transport
            .take()
            .ok_or(VerificationSourceError::Unavailable)?;
        let definition = SecretBrokerServiceDefinition::production()
            .map_err(|_| VerificationSourceError::Unavailable)?;
        let reference = self
            .binding
            .broker_reference(&definition)
            .map_err(|_| VerificationSourceError::Rejected)?;
        let mut service = SecretBrokerService::new(definition, reference)
            .map_err(|_| VerificationSourceError::Unavailable)?;
        service
            .mount(now)
            .map_err(|_| VerificationSourceError::Unavailable)?;
        let consumer_id = format!(
            "secret-consumer-shopify-independent-{}",
            &self.source_binding_digest[..16]
        );
        let consumer = SecretBrokerConsumer::new(
            consumer_id,
            self.effect.tenant_id.clone(),
            self.effect.project_id.clone(),
            self.effect.mission_id.clone(),
        )
        .map_err(|_| VerificationSourceError::Rejected)?;
        let identity = self.binding.adapter().clone();
        let registry = shopify_readback_registry_for(
            identity.clone(),
            SHOPIFY_INDEPENDENT_VERIFICATION_REGISTRY_VERSION,
        )
        .map_err(|_| VerificationSourceError::Unavailable)?;
        let mut provider = ShopifySecretReadbackProvider::new_with_identity(
            self.secret_store,
            self.binding.clone(),
            self.exact_request.clone(),
            self.cancellation.clone(),
            transport,
            self.expected_provenance,
            identity,
        )
        .map_err(|_| VerificationSourceError::Rejected)?;
        let brokered = dispatch_shopify_readback_with_registry(
            &consumer,
            &mut service,
            &mut provider,
            &registry,
            now,
        )
        .map_err(|error| Self::map_bridge_error(&error))?;
        if self.cancellation.is_cancelled() {
            return Err(VerificationSourceError::Cancelled);
        }
        self.validate_connection(Utc::now())?;
        let observed_at = Utc::now();
        let metadata = brokered
            .identity_metadata(observed_at)
            .map_err(|error| Self::map_bridge_error(&error))?;
        let receipt = subject.receipt();
        let draft = self.approved.draft();
        let identity = metadata.fulfillment_id.clone();
        if metadata.provenance_class != self.expected_provenance
            || metadata.fulfillment_id != *self.exact_request.fulfillment_id()
            || metadata.api_version != *draft.api_version()
            || metadata.order_id != *draft.order_gid()
            || metadata.fulfillment_order_id != *draft.fulfillment_order_gid()
            || metadata.line_item_binding_digest
                != approved_line_item_binding_digest(draft.line_items())
            || !metadata.lease_reclaimed
            || brokered.credential_use().credential_revision()
                != self.head.binding.credential_revision
            || brokered.credential_use().used_at() < subject.execution_started_at()
            || brokered.credential_use().used_at() > observed_at
            || metadata.provider_created_at < subject.execution_started_at()
            || metadata.provider_created_at != receipt.accepted_at
            || metadata.provider_updated_at < metadata.provider_created_at
            || metadata.provider_updated_at < n15_provider_updated_at
            || metadata.provider_updated_at > observed_at
            || metadata.provider_created_at >= self.effect.expires_at
        {
            return Err(VerificationSourceError::Rejected);
        }
        let evidence = StoredShopifyVerificationEvidence {
            schema: SHOPIFY_INDEPENDENT_VERIFICATION_EVIDENCE_SCHEMA.to_owned(),
            effect_id: self.effect.id.as_str().to_owned(),
            receipt_id: receipt.id.as_str().to_owned(),
            receipt_response_digest: receipt.response_digest.clone(),
            receipt_binding_digest: receipt_binding_digest(receipt),
            n15_evidence_digest: receipt.response_digest.clone(),
            recovery_binding_digest: self.head.binding.binding_digest.clone(),
            recovery_capsule_content_digest: self.head.capsule.content_digest.clone(),
            recovery_capsule_key_version: self.head.capsule.key_version,
            recovery_capsule_object_revision: self.head.capsule.object_revision,
            recovery_head_revision: self
                .original_reference
                .head_revision
                .checked_add(1)
                .ok_or(VerificationSourceError::Rejected)?,
            recovery_head_state: ProviderRecoveryState::ReceiptObserved,
            credential_revision: self.head.binding.credential_revision,
            selector_digest: self.selector.selector_digest(),
            observation_authority_digest: self.observation_authority_digest.clone(),
            source_binding_digest: self.source_binding_digest.clone(),
            adapter_id: self.binding.adapter().adapter_id().to_owned(),
            adapter_version: self.binding.adapter().adapter_version(),
            registry_version: SHOPIFY_INDEPENDENT_VERIFICATION_REGISTRY_VERSION.to_owned(),
            shop: draft.tenant_scope().shop().as_str().to_owned(),
            api_version: draft.api_version().as_str().to_owned(),
            fulfillment_id: identity.as_str().to_owned(),
            fulfillment_status: metadata.status.as_str().to_owned(),
            order_id: metadata.order_id.as_str().to_owned(),
            fulfillment_order_id: metadata.fulfillment_order_id.as_str().to_owned(),
            line_item_binding_digest: metadata.line_item_binding_digest,
            native_response_digest: metadata.response_digest,
            native_evidence_digest: metadata.evidence_digest,
            native_request_id_digest: metadata.request_id_digest,
            secret_broker_use_digest: metadata.credential_use_digest,
            provider_created_at: metadata.provider_created_at,
            provider_updated_at: metadata.provider_updated_at,
            observed_at,
            provenance_class: metadata.provenance_class,
        };
        let encoded =
            serde_json::to_string(&evidence).map_err(|_| VerificationSourceError::Rejected)?;
        let descriptor = self
            .material
            .put_text(&encoded)
            .map_err(|_| VerificationSourceError::Unavailable)?;
        if descriptor.content_digest != sha256(encoded.as_bytes())
            || descriptor.storage_ref != format!("cas://{}", descriptor.content_digest)
            || descriptor.content_digest == receipt.response_digest
        {
            return Err(VerificationSourceError::Rejected);
        }
        let status = Self::verification_status(metadata.status.as_str());
        Ok(match status {
            VerificationStatus::Confirmed => IndependentVerificationObservation::Confirmed {
                evidence_digest: descriptor.content_digest,
                observed_at,
            },
            VerificationStatus::Rejected => IndependentVerificationObservation::Rejected {
                evidence_digest: descriptor.content_digest,
                observed_at,
            },
            VerificationStatus::Inconclusive => IndependentVerificationObservation::Inconclusive {
                evidence_digest: descriptor.content_digest,
                observed_at,
            },
        })
    }

    fn validate_recovered(
        &self,
        subject: &hartevo_effect_broker::ReceiptVerificationSubject,
        verification: &Verification,
    ) -> Result<(), VerificationSourceError> {
        self.validate_verification_material(subject, verification)
    }
}

#[derive(Debug, Error)]
pub enum ShopifyRecoveryError {
    #[error("Shopify recovery binding does not match current durable authority")]
    BindingMismatch,
    #[error("Shopify recovery capsule is missing, malformed, or unauthenticated")]
    InvalidCapsule,
    #[error("Shopify recovery is reconciliation-only and cannot issue execution")]
    ReconciliationOnly,
    #[error("Shopify recovery authorization or payload has expired")]
    Expired,
    #[error("Shopify receipt-found evidence is malformed or could not be sealed")]
    InvalidReceiptEvidence,
    #[error(transparent)]
    Adapter(#[from] ShopifyAdapterError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    ContextMaterial(#[from] ContextMaterialStoreError),
    #[error(transparent)]
    Readback(#[from] ShopifyReadbackBridgeError),
}

/// Application-owned composition over one SQLCipher project store and one
/// project Context-Material key session.
pub struct ShopifySecureRecovery<'a> {
    store: &'a mut ProjectStore,
    material: &'a ProjectContextMaterialSession,
}

impl fmt::Debug for ShopifySecureRecovery<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShopifySecureRecovery")
            .field("project_id", self.material.project_id())
            .field("keyring_revision", &self.material.keyring_revision())
            .field("active_key_version", &self.material.active_key_version())
            .finish_non_exhaustive()
    }
}

impl<'a> ShopifySecureRecovery<'a> {
    pub fn new(store: &'a mut ProjectStore, material: &'a ProjectContextMaterialSession) -> Self {
        Self { store, material }
    }

    /// Writes the authenticated encrypted capsule first and publishes its
    /// content-free SQLCipher head only after the CAS write has completed.
    pub fn prepare_controlled(
        &mut self,
        effect: &Effect,
        approved: &ShopifyApprovedDraftFulfillment,
        policy: &EffectPolicy,
        now: DateTime<Utc>,
    ) -> Result<ShopifyRecoveryCapsuleRef, ShopifyRecoveryError> {
        let authority = self.load_current_authority(
            &effect.project_id,
            &effect.mission_id,
            &effect.id,
            policy,
            now,
        )?;
        if authority.effect != *effect {
            return Err(ShopifyRecoveryError::BindingMismatch);
        }
        ensure_live_shape(
            &authority.effect,
            authority.mission_revision,
            authority.credential_revision,
            approved,
            self.material,
            now,
            true,
        )?;
        let reproducible = rebuild_approved(
            approved.draft().clone(),
            approved.plugin_revision(),
            &authority.authorization_digest,
            authority.effect.expires_at,
        )?;
        if reproducible.prepared_effect() != approved.prepared_effect()
            || reproducible.approval_binding_digest() != approved.approval_binding_digest()
        {
            return Err(ShopifyRecoveryError::BindingMismatch);
        }
        let binding = recovery_binding(
            &authority.effect,
            authority.mission_revision,
            authority.credential_revision,
            approved,
            self.material.keyring_revision(),
            self.material.active_key_version(),
        )?;
        let private = StoredShopifyRecoveryCapsule {
            schema: SHOPIFY_RECOVERY_CAPSULE_SCHEMA.to_owned(),
            binding_digest: binding.binding_digest.clone(),
            draft: approved.draft().clone(),
        };
        let encoded =
            serde_json::to_string(&private).map_err(|_| ShopifyRecoveryError::InvalidCapsule)?;
        let descriptor = self.material.put_text(&encoded)?;
        if descriptor.key_version != self.material.active_key_version() {
            return Err(ShopifyRecoveryError::BindingMismatch);
        }
        let head = ProviderRecoveryHead::prepared(
            binding,
            ProviderRecoveryCapsule {
                storage_ref: descriptor.storage_ref,
                content_digest: descriptor.content_digest,
                byte_len: descriptor.byte_len,
                key_version: descriptor.key_version,
                object_revision: SHOPIFY_RECOVERY_CAPSULE_REVISION,
            },
            approved.prepared_effect().prepared_at(),
            effect.expires_at,
        )?;
        let outcome = self.store.prepare_provider_recovery(&head)?;
        Ok(ShopifyRecoveryCapsuleRef::from_head(&outcome.head))
    }

    /// Reopens an exact `Prepared` capsule, validates current authority, then
    /// commits `InFlight` before returning an executor-capable adapter.
    #[allow(clippy::too_many_arguments)]
    pub fn claim_controlled_adapter<B>(
        &mut self,
        reference: &ShopifyRecoveryCapsuleRef,
        policy: &EffectPolicy,
        boundary: B,
        now: DateTime<Utc>,
    ) -> Result<ClaimedShopifyRecovery<B>, ShopifyRecoveryError>
    where
        B: ShopifyTypedEffectBoundary,
    {
        let head = self
            .store
            .load_provider_recovery(&reference.project_id, &reference.effect_id)?;
        if !reference.matches_head(&head)
            || head.state != ProviderRecoveryState::Prepared
            || !head.execution_claimable()
            || head.capsule.object_revision != SHOPIFY_RECOVERY_CAPSULE_REVISION
        {
            return Err(ShopifyRecoveryError::ReconciliationOnly);
        }
        if now < head.prepared_at || now >= head.expires_at {
            return Err(ShopifyRecoveryError::Expired);
        }
        if self.material.project_id() != &head.binding.project_id
            || self.material.keyring_revision() != head.binding.keyring_revision
            || !self
                .material
                .readable_key_versions()
                .contains(&head.capsule.key_version)
        {
            return Err(ShopifyRecoveryError::BindingMismatch);
        }
        let resolved = self
            .material
            .load_text(&head.capsule.storage_ref)?
            .ok_or(ShopifyRecoveryError::InvalidCapsule)?;
        if sha256(resolved.as_str().as_bytes()) != head.capsule.content_digest
            || u64::try_from(resolved.as_str().len()).ok() != Some(head.capsule.byte_len)
        {
            return Err(ShopifyRecoveryError::InvalidCapsule);
        }
        let private: StoredShopifyRecoveryCapsule = serde_json::from_str(resolved.as_str())
            .map_err(|_| ShopifyRecoveryError::InvalidCapsule)?;
        if private.schema != SHOPIFY_RECOVERY_CAPSULE_SCHEMA
            || private.binding_digest != head.binding.binding_digest
        {
            return Err(ShopifyRecoveryError::InvalidCapsule);
        }
        let authority = self.load_current_authority(
            &head.binding.project_id,
            &head.binding.mission_id,
            &head.binding.effect_id,
            policy,
            now,
        )?;
        let approved = rebuild_approved(
            private.draft,
            ShopifyPluginRevision::new(head.binding.plugin_revision)
                .map_err(|_| ShopifyRecoveryError::BindingMismatch)?,
            &authority.authorization_digest,
            authority.effect.expires_at,
        )?;
        ensure_live_shape(
            &authority.effect,
            authority.mission_revision,
            authority.credential_revision,
            &approved,
            self.material,
            now,
            true,
        )?;
        let live_binding = recovery_binding(
            &authority.effect,
            authority.mission_revision,
            authority.credential_revision,
            &approved,
            self.material.keyring_revision(),
            head.capsule.key_version,
        )?;
        if live_binding != head.binding {
            return Err(ShopifyRecoveryError::BindingMismatch);
        }

        // Construct first but do not expose or call the adapter. The durable
        // CAS claim is committed before the value can leave this method.
        let adapter = ShopifyEffectAdapter::controlled(boundary, approved, &authority.effect)?;
        let claimed = self.store.claim_provider_recovery_execution_authorized(
            &head.binding.project_id,
            &head.binding.effect_id,
            head.revision,
            &head.binding.binding_digest,
            &authority.effect,
            &authority.permission_evidence,
            now,
        )?;
        Ok(ClaimedShopifyRecovery {
            adapter,
            head: claimed,
        })
    }

    pub fn load_head(
        &self,
        reference: &ShopifyRecoveryCapsuleRef,
    ) -> Result<ProviderRecoveryHead, ShopifyRecoveryError> {
        let head = self
            .store
            .load_provider_recovery(&reference.project_id, &reference.effect_id)?;
        if reference.project_id != head.binding.project_id
            || reference.effect_id != head.binding.effect_id
            || reference.binding_digest != head.binding.binding_digest
            || reference.storage_ref != head.capsule.storage_ref
            || reference.content_digest != head.capsule.content_digest
            || reference.key_version != head.capsule.key_version
            || reference.object_revision != head.capsule.object_revision
            || head.capsule.object_revision != SHOPIFY_RECOVERY_CAPSULE_REVISION
        {
            return Err(ShopifyRecoveryError::BindingMismatch);
        }
        Ok(head)
    }

    /// Reopens an exact reconciliation-only capsule without changing its
    /// durable head or issuing an execution-capable adapter.
    pub fn reopen_reconciliation(
        &mut self,
        reference: &ShopifyRecoveryCapsuleRef,
    ) -> Result<ReopenedShopifyReconciliation, ShopifyRecoveryError> {
        let head = self
            .store
            .load_provider_recovery(&reference.project_id, &reference.effect_id)?;
        if !reference.matches_head(&head)
            || !matches!(
                head.state,
                ProviderRecoveryState::InFlight | ProviderRecoveryState::Uncertain
            )
            || head.capsule.object_revision != SHOPIFY_RECOVERY_CAPSULE_REVISION
            || head.readback_storage_ref.is_some()
            || head.receipt_evidence_digest.is_some()
            || head.verification_evidence_digest.is_some()
        {
            return Err(ShopifyRecoveryError::ReconciliationOnly);
        }
        if self.material.project_id() != &head.binding.project_id
            || self.material.keyring_revision() != head.binding.keyring_revision
            || !self
                .material
                .readable_key_versions()
                .contains(&head.capsule.key_version)
        {
            return Err(ShopifyRecoveryError::BindingMismatch);
        }
        let resolved = self
            .material
            .load_text(&head.capsule.storage_ref)?
            .ok_or(ShopifyRecoveryError::InvalidCapsule)?;
        if sha256(resolved.as_str().as_bytes()) != head.capsule.content_digest
            || u64::try_from(resolved.as_str().len()).ok() != Some(head.capsule.byte_len)
        {
            return Err(ShopifyRecoveryError::InvalidCapsule);
        }
        let private: StoredShopifyRecoveryCapsule = serde_json::from_str(resolved.as_str())
            .map_err(|_| ShopifyRecoveryError::InvalidCapsule)?;
        if private.schema != SHOPIFY_RECOVERY_CAPSULE_SCHEMA
            || private.binding_digest != head.binding.binding_digest
        {
            return Err(ShopifyRecoveryError::InvalidCapsule);
        }

        let project = self.store.load_project(&head.binding.project_id)?;
        let mission = self
            .store
            .load_mission(&head.binding.project_id, &head.binding.mission_id)?;
        let effect = mission
            .effect(&head.binding.effect_id)
            .map_err(|_| ShopifyRecoveryError::BindingMismatch)?
            .clone();
        let approval = effect
            .approval
            .as_ref()
            .ok_or(ShopifyRecoveryError::BindingMismatch)?;
        let connection_id = effect
            .connection_id
            .as_ref()
            .ok_or(ShopifyRecoveryError::BindingMismatch)?;
        let connection = self
            .store
            .load_connection(&head.binding.project_id, connection_id)?;
        if project.tenant_id != mission.tenant_id
            || mission.project_id != project.id
            || mission.revision < head.binding.mission_revision
            || self.material.tenant_id != mission.tenant_id
            || effect.status != EffectStatus::VerificationRequired
            || effect.receipt.is_some()
            || effect.verification.is_some()
            || approval.decision != ApprovalDecision::Approved
            || approval.scope_digest != effect.approval_digest()
            || connection.tenant_id() != &effect.tenant_id
            || connection.project_id() != &effect.project_id
            || connection.provider() != SHOPIFY_PROVIDER_ID
            || connection.revision() != head.binding.credential_revision
        {
            return Err(ShopifyRecoveryError::BindingMismatch);
        }
        let approved = rebuild_approved(
            private.draft,
            ShopifyPluginRevision::new(head.binding.plugin_revision)
                .map_err(|_| ShopifyRecoveryError::BindingMismatch)?,
            &approval.permission_digest,
            effect.expires_at,
        )?;
        validate_controlled_recovery_effect(&effect, &approved)?;
        let live_binding = recovery_binding(
            &effect,
            head.binding.mission_revision,
            head.binding.credential_revision,
            &approved,
            self.material.keyring_revision(),
            head.capsule.key_version,
        )?;
        if live_binding != head.binding {
            return Err(ShopifyRecoveryError::BindingMismatch);
        }
        Ok(ReopenedShopifyReconciliation {
            approved,
            effect,
            head,
            current_mission_revision: mission.revision,
        })
    }

    /// Reopens the exact N15 recovery capsule for independent verification.
    /// The input reference must name the immutable InFlight/Uncertain head;
    /// the current head must already carry the authenticated ReceiptObserved
    /// readback (or one of the N16 terminal states). This method performs no
    /// Secret Broker or provider work and does not require a live credential
    /// for terminal replay.
    // Reopening authenticates every immutable N15/N16 binding before any
    // caller can construct a provider-backed source; keep that proof local.
    #[allow(clippy::too_many_lines)]
    pub fn reopen_verification(
        &mut self,
        reference: &ShopifyRecoveryCapsuleRef,
    ) -> Result<ReopenedShopifyVerification, ShopifyRecoveryError> {
        if !matches!(
            reference.state,
            ProviderRecoveryState::InFlight | ProviderRecoveryState::Uncertain
        ) || reference.head_revision == 0
        {
            return Err(ShopifyRecoveryError::BindingMismatch);
        }
        let head = self.load_head(reference)?;
        if head.revision <= reference.head_revision
            || head.binding.project_id != reference.project_id
            || head.binding.effect_id != reference.effect_id
            || head.binding.binding_digest != reference.binding_digest
            || head.capsule.storage_ref != reference.storage_ref
            || head.capsule.content_digest != reference.content_digest
            || head.capsule.key_version != reference.key_version
            || head.capsule.object_revision != reference.object_revision
            || !matches!(
                head.state,
                ProviderRecoveryState::ReceiptObserved
                    | ProviderRecoveryState::Verified
                    | ProviderRecoveryState::FailedClosed
            )
        {
            return Err(ShopifyRecoveryError::BindingMismatch);
        }
        let expected_head_revision = reference
            .head_revision
            .checked_add(1)
            .ok_or(ShopifyRecoveryError::BindingMismatch)?;
        let expected_revision = match head.state {
            ProviderRecoveryState::ReceiptObserved => expected_head_revision,
            ProviderRecoveryState::FailedClosed | ProviderRecoveryState::Verified => {
                expected_head_revision
                    .checked_add(1)
                    .ok_or(ShopifyRecoveryError::BindingMismatch)?
            }
            _ => return Err(ShopifyRecoveryError::BindingMismatch),
        };
        if head.revision != expected_revision
            || head.readback_storage_ref.is_none()
            || head.readback_content_digest.is_none()
            || head.receipt_evidence_digest.is_none()
        {
            return Err(ShopifyRecoveryError::BindingMismatch);
        }
        if self.material.project_id() != &head.binding.project_id
            || self.material.keyring_revision() != head.binding.keyring_revision
            || !self
                .material
                .readable_key_versions()
                .contains(&head.capsule.key_version)
        {
            return Err(ShopifyRecoveryError::BindingMismatch);
        }
        let resolved = self
            .material
            .load_text(&head.capsule.storage_ref)?
            .ok_or(ShopifyRecoveryError::InvalidCapsule)?;
        if sha256(resolved.as_str().as_bytes()) != head.capsule.content_digest
            || u64::try_from(resolved.as_str().len()).ok() != Some(head.capsule.byte_len)
        {
            return Err(ShopifyRecoveryError::InvalidCapsule);
        }
        let private: StoredShopifyRecoveryCapsule = serde_json::from_str(resolved.as_str())
            .map_err(|_| ShopifyRecoveryError::InvalidCapsule)?;
        if private.schema != SHOPIFY_RECOVERY_CAPSULE_SCHEMA
            || private.binding_digest != head.binding.binding_digest
        {
            return Err(ShopifyRecoveryError::InvalidCapsule);
        }
        let project = self.store.load_project(&head.binding.project_id)?;
        let mission = self
            .store
            .load_mission(&head.binding.project_id, &head.binding.mission_id)?;
        let effect = mission
            .effect(&head.binding.effect_id)
            .map_err(|_| ShopifyRecoveryError::BindingMismatch)?
            .clone();
        let approval = effect
            .approval
            .as_ref()
            .ok_or(ShopifyRecoveryError::BindingMismatch)?;
        let receipt = effect
            .receipt
            .as_ref()
            .ok_or(ShopifyRecoveryError::BindingMismatch)?;
        let projection_shape_is_valid = match (&effect.status, &effect.verification, head.state) {
            (
                EffectStatus::ReceiptRecorded,
                None,
                ProviderRecoveryState::ReceiptObserved
                | ProviderRecoveryState::Verified
                | ProviderRecoveryState::FailedClosed,
            ) => true,
            (
                EffectStatus::VerificationRequired,
                Some(verification),
                ProviderRecoveryState::ReceiptObserved,
            ) => verification.status == VerificationStatus::Inconclusive,
            (EffectStatus::Verified, Some(verification), ProviderRecoveryState::Verified) => {
                verification.status == VerificationStatus::Confirmed
            }
            (EffectStatus::Failed, Some(verification), ProviderRecoveryState::FailedClosed) => {
                verification.status == VerificationStatus::Rejected
            }
            _ => false,
        };
        if project.tenant_id != mission.tenant_id
            || mission.project_id != project.id
            || mission.revision < head.binding.mission_revision
            || self.material.tenant_id != mission.tenant_id
            || effect.tenant_id != head.binding.tenant_id
            || effect.project_id != head.binding.project_id
            || effect.mission_id != head.binding.mission_id
            || effect.id != head.binding.effect_id
            || effect.provider != SHOPIFY_PROVIDER_ID
            || effect.capability != SHOPIFY_FULFILLMENT_CAPABILITY
            || effect.effect_class != hartevo_domain_kernel::EffectClass::ExternalWrite
            || !projection_shape_is_valid
            || approval.decision != ApprovalDecision::Approved
            || approval.scope_digest != effect.approval_digest()
            || approval.permission_digest != head.binding.broker_authorization_digest
            || receipt.provider != effect.provider
            || receipt.response_digest != head.readback_content_digest.clone().unwrap_or_default()
        {
            return Err(ShopifyRecoveryError::BindingMismatch);
        }
        let approved = rebuild_approved(
            private.draft,
            ShopifyPluginRevision::new(head.binding.plugin_revision)
                .map_err(|_| ShopifyRecoveryError::BindingMismatch)?,
            &approval.permission_digest,
            effect.expires_at,
        )?;
        validate_controlled_recovery_effect(&effect, &approved)?;
        let live_binding = recovery_binding(
            &effect,
            head.binding.mission_revision,
            head.binding.credential_revision,
            &approved,
            self.material.keyring_revision(),
            head.capsule.key_version,
        )?;
        if live_binding != head.binding {
            return Err(ShopifyRecoveryError::BindingMismatch);
        }
        let connection = if head.state == ProviderRecoveryState::ReceiptObserved
            && effect.status == EffectStatus::ReceiptRecorded
        {
            let connection_id = effect
                .connection_id
                .as_ref()
                .ok_or(ShopifyRecoveryError::BindingMismatch)?;
            self.store
                .load_connection(&head.binding.project_id, connection_id)
                .ok()
                .filter(|connection| {
                    connection.tenant_id() == &effect.tenant_id
                        && connection.project_id() == &effect.project_id
                        && connection.provider() == SHOPIFY_PROVIDER_ID
                        && effect.account_id.as_ref() == Some(connection.account_id())
                        && connection.revision() == head.binding.credential_revision
                })
                .map(|connection| connection.snapshot())
        } else {
            // A committed N16 result is durable truth. Replay must remain
            // provider/Secret-free even if a credential was later rotated or
            // revoked, so no live Connection is required here.
            None
        };
        Ok(ReopenedShopifyVerification {
            approved,
            effect,
            head,
            original_reference: reference.clone(),
            current_mission_revision: mission.revision,
            connection,
        })
    }

    /// Authenticates the exact encrypted evidence behind a receipt already
    /// committed by Phase A. This is a local restart check only: it obtains no
    /// credential and performs no provider readback.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_lines)]
    pub fn authenticate_receipt_found(
        &mut self,
        reference: &ShopifyRecoveryCapsuleRef,
        selector: &ShopifyFulfillmentReadbackRequest,
        observation_authority_digest: &str,
        effect: &Effect,
        durable: &DurableReceiptReconciliation,
    ) -> Result<(), ShopifyRecoveryError> {
        if selector.expected_identity().is_some()
            || self.material.project_id() != &effect.project_id
            || reference.project_id != effect.project_id
            || reference.effect_id != effect.id
            || reference
                .readback_authority_digest(selector)
                .map_err(|_| ShopifyRecoveryError::BindingMismatch)?
                != observation_authority_digest
        {
            return Err(ShopifyRecoveryError::BindingMismatch);
        }
        let approval = effect
            .approval
            .as_ref()
            .ok_or(ShopifyRecoveryError::BindingMismatch)?;
        let effect_shape_is_valid = match effect.status {
            EffectStatus::VerificationRequired => {
                effect.receipt.is_none() && effect.verification.is_none()
            }
            EffectStatus::ReceiptRecorded => {
                effect.receipt.as_ref() == Some(&durable.receipt) && effect.verification.is_none()
            }
            _ => false,
        };
        if !effect_shape_is_valid
            || approval.decision != ApprovalDecision::Approved
            || approval.scope_digest != effect.approval_digest()
            || durable.receipt.provider != effect.provider
            || durable.receipt.request_digest != approval.scope_digest
            || durable.receipt.accepted_at < durable.execution_started_at
        {
            return Err(ShopifyRecoveryError::BindingMismatch);
        }

        let head = self
            .store
            .load_provider_recovery(&reference.project_id, &reference.effect_id)?;
        let expected_committed_revision = reference
            .head_revision
            .checked_add(1)
            .ok_or(ShopifyRecoveryError::BindingMismatch)?;
        let readback_storage_ref = head
            .readback_storage_ref
            .as_deref()
            .ok_or(ShopifyRecoveryError::InvalidReceiptEvidence)?;
        let readback_content_digest = head
            .readback_content_digest
            .as_deref()
            .ok_or(ShopifyRecoveryError::InvalidReceiptEvidence)?;
        if head.state != ProviderRecoveryState::ReceiptObserved
            || head.revision != expected_committed_revision
            || head.binding.project_id != reference.project_id
            || head.binding.effect_id != reference.effect_id
            || head.binding.binding_digest != reference.binding_digest
            || head.capsule.storage_ref != reference.storage_ref
            || head.capsule.content_digest != reference.content_digest
            || head.capsule.key_version != reference.key_version
            || head.capsule.object_revision != reference.object_revision
            || !matches!(
                reference.state,
                ProviderRecoveryState::InFlight | ProviderRecoveryState::Uncertain
            )
            || readback_storage_ref != format!("cas://{readback_content_digest}")
            || head.receipt_evidence_digest.as_deref() != Some(readback_content_digest)
            || head.verification_evidence_digest.is_some()
            || durable.receipt.response_digest != readback_content_digest
            || durable.completion.operation_at() != head.updated_at
        {
            return Err(ShopifyRecoveryError::BindingMismatch);
        }

        if !self
            .material
            .readable_key_versions()
            .contains(&head.capsule.key_version)
        {
            return Err(ShopifyRecoveryError::InvalidCapsule);
        }
        let capsule = self
            .material
            .load_text(&head.capsule.storage_ref)?
            .ok_or(ShopifyRecoveryError::InvalidCapsule)?;
        if sha256(capsule.as_str().as_bytes()) != head.capsule.content_digest
            || u64::try_from(capsule.as_str().len()).ok() != Some(head.capsule.byte_len)
        {
            return Err(ShopifyRecoveryError::InvalidCapsule);
        }
        let private: StoredShopifyRecoveryCapsule = serde_json::from_str(capsule.as_str())
            .map_err(|_| ShopifyRecoveryError::InvalidCapsule)?;
        if private.schema != SHOPIFY_RECOVERY_CAPSULE_SCHEMA
            || private.binding_digest != head.binding.binding_digest
        {
            return Err(ShopifyRecoveryError::InvalidCapsule);
        }
        let approved = rebuild_approved(
            private.draft,
            ShopifyPluginRevision::new(head.binding.plugin_revision)
                .map_err(|_| ShopifyRecoveryError::BindingMismatch)?,
            &approval.permission_digest,
            effect.expires_at,
        )?;
        validate_controlled_recovery_effect(effect, &approved)?;
        let expected_binding = recovery_binding(
            effect,
            head.binding.mission_revision,
            head.binding.credential_revision,
            &approved,
            head.binding.keyring_revision,
            head.capsule.key_version,
        )?;
        if expected_binding != head.binding {
            return Err(ShopifyRecoveryError::BindingMismatch);
        }

        let resolved = self
            .material
            .load_text(readback_storage_ref)?
            .ok_or(ShopifyRecoveryError::InvalidReceiptEvidence)?;
        if sha256(resolved.as_str().as_bytes()) != readback_content_digest {
            return Err(ShopifyRecoveryError::InvalidReceiptEvidence);
        }
        let evidence: StoredShopifyReceiptFoundEvidence =
            serde_json::from_str(resolved.as_str())
                .map_err(|_| ShopifyRecoveryError::InvalidReceiptEvidence)?;
        let draft = approved.draft();
        let optional_digests_are_valid = evidence
            .native_request_id_digest
            .as_deref()
            .is_none_or(is_sha256);
        if evidence.schema != SHOPIFY_RECEIPT_FOUND_EVIDENCE_SCHEMA
            || evidence.effect_id != effect.id.as_str()
            || evidence.effect_approval_digest != approval.scope_digest
            || evidence.broker_authorization_digest != approval.permission_digest
            || evidence.original_execution_started_at != durable.execution_started_at
            || evidence.recovery_binding_digest != head.binding.binding_digest
            || evidence.recovery_capsule_content_digest != head.capsule.content_digest
            || evidence.recovery_capsule_key_version != head.capsule.key_version
            || evidence.recovery_capsule_object_revision != head.capsule.object_revision
            || evidence.recovery_head_revision != reference.head_revision
            || evidence.recovery_head_state != reference.state
            || evidence.credential_revision != head.binding.credential_revision
            || evidence.selector_digest != selector.selector_digest()
            || evidence.observation_authority_digest != observation_authority_digest
            || evidence.shop != selector.shop().as_str()
            || evidence.shop != draft.tenant_scope().shop().as_str()
            || evidence.api_version != selector.api_version().as_str()
            || evidence.api_version != draft.api_version().as_str()
            || evidence.fulfillment_id != selector.fulfillment_id().as_str()
            || evidence.order_id != draft.order_gid().as_str()
            || evidence.fulfillment_order_id != draft.fulfillment_order_gid().as_str()
            || evidence.line_item_binding_digest
                != approved_line_item_binding_digest(draft.line_items())
            || evidence.fulfillment_status.trim().is_empty()
            || evidence.provider_created_at != durable.receipt.accepted_at
            || evidence.provider_created_at < durable.execution_started_at
            || evidence.provider_updated_at < evidence.provider_created_at
            || evidence.observed_at < evidence.provider_updated_at
            || durable.completion.operation_at() < evidence.observed_at
            || evidence.provenance_class != ProviderProvenanceClass::ProductionProvider
            || durable.receipt.external_id
                != recovered_shopify_external_id(&evidence.fulfillment_id)
            || !is_sha256(&evidence.secret_broker_use_digest)
            || !is_sha256(&evidence.line_item_binding_digest)
            || !is_sha256(&evidence.native_response_digest)
            || !is_sha256(&evidence.native_evidence_digest)
            || !optional_digests_are_valid
        {
            return Err(ShopifyRecoveryError::InvalidReceiptEvidence);
        }
        Ok(())
    }

    fn load_current_authority(
        &self,
        project_id: &hartevo_domain_kernel::ProjectId,
        mission_id: &hartevo_domain_kernel::MissionId,
        effect_id: &hartevo_domain_kernel::EffectId,
        policy: &EffectPolicy,
        now: DateTime<Utc>,
    ) -> Result<CurrentShopifyAuthority, ShopifyRecoveryError> {
        let project = self.store.load_project(project_id)?;
        let mission = self.store.load_mission(project_id, mission_id)?;
        let effect = mission
            .effects
            .iter()
            .find(|candidate| &candidate.id == effect_id)
            .cloned()
            .ok_or(ShopifyRecoveryError::BindingMismatch)?;
        if project.tenant_id != mission.tenant_id
            || mission.project_id != project.id
            || self.material.tenant_id != mission.tenant_id
            || self.material.project_id() != &mission.project_id
        {
            return Err(ShopifyRecoveryError::BindingMismatch);
        }
        let permission_evidence = self
            .store
            .authorize(&effect, now)
            .map_err(|_| ShopifyRecoveryError::BindingMismatch)?;
        let claim_context = policy
            .execution_claim_context(&effect, permission_evidence.clone())
            .map_err(|_| ShopifyRecoveryError::BindingMismatch)?;
        claim_context
            .validate_dispatch_at(&effect, now)
            .map_err(|_| ShopifyRecoveryError::BindingMismatch)?;
        let connection_id = effect
            .connection_id
            .as_ref()
            .ok_or(ShopifyRecoveryError::BindingMismatch)?;
        let connection = self.store.load_connection(project_id, connection_id)?;
        Ok(CurrentShopifyAuthority {
            effect,
            mission_revision: mission.revision,
            credential_revision: connection.revision(),
            authorization_digest: claim_context.authorization_digest,
            permission_evidence,
        })
    }
}

impl ApplicationService {
    /// Application-owned preparation seam for Desktop: reconstructs the
    /// approved typed payload only from the current durable Effect approval,
    /// then publishes the encrypted N12B capsule. No provider is obtained.
    pub fn prepare_shopify_controlled_recovery_draft(
        &mut self,
        material: &ProjectContextMaterialSession,
        effect: &Effect,
        draft: DraftFulfillmentRequest,
        plugin_revision: u64,
        policy: &EffectPolicy,
        now: DateTime<Utc>,
    ) -> Result<ShopifyRecoveryCapsuleRef, ShopifyRecoveryError> {
        let approval = effect
            .approval
            .as_ref()
            .ok_or(ShopifyRecoveryError::BindingMismatch)?;
        let approved = rebuild_approved(
            draft,
            ShopifyPluginRevision::new(plugin_revision)
                .map_err(|_| ShopifyRecoveryError::BindingMismatch)?,
            &approval.permission_digest,
            effect.expires_at,
        )?;
        ShopifySecureRecovery::new(&mut self.store, material)
            .prepare_controlled(effect, &approved, policy, now)
    }

    /// Application-owned wrapper so Desktop never obtains the ProjectStore or
    /// decrypted capsule bytes.
    pub fn reopen_shopify_reconciliation(
        &mut self,
        material: &ProjectContextMaterialSession,
        reference: &ShopifyRecoveryCapsuleRef,
    ) -> Result<ReopenedShopifyReconciliation, ShopifyRecoveryError> {
        ShopifySecureRecovery::new(&mut self.store, material).reopen_reconciliation(reference)
    }

    /// Re-authenticates one committed Phase-A receipt against the exact
    /// selector/recovery authority before restart projection. No provider or
    /// credential path is reachable from this method.
    pub fn authenticate_shopify_receipt_found(
        &mut self,
        material: &ProjectContextMaterialSession,
        reference: &ShopifyRecoveryCapsuleRef,
        selector: &ShopifyFulfillmentReadbackRequest,
        observation_authority_digest: &str,
        effect: &Effect,
        durable: &DurableReceiptReconciliation,
    ) -> Result<(), ShopifyRecoveryError> {
        ShopifySecureRecovery::new(&mut self.store, material).authenticate_receipt_found(
            reference,
            selector,
            observation_authority_digest,
            effect,
            durable,
        )
    }

    /// Reopens the exact N16 source material without constructing a provider.
    pub fn reopen_shopify_verification(
        &mut self,
        material: &ProjectContextMaterialSession,
        reference: &ShopifyRecoveryCapsuleRef,
    ) -> Result<ReopenedShopifyVerification, ShopifyRecoveryError> {
        ShopifySecureRecovery::new(&mut self.store, material).reopen_verification(reference)
    }

    /// Constructs a fresh production-shaped independent source. The source
    /// keeps Secret Broker/provider construction lazy until `observe`.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_shopify_independent_verification_source<'a, S>(
        &mut self,
        secret_store: &'a S,
        material: &'a ProjectContextMaterialSession,
        reference: &ShopifyRecoveryCapsuleRef,
        selector: ShopifyFulfillmentReadbackRequest,
        observation_authority_digest: impl Into<String>,
        cancellation: ShopifyReadbackCancellation,
        transport: UreqShopifyAdminReadbackTransport,
    ) -> Result<
        ShopifyIndependentVerificationSource<'a, S, UreqShopifyAdminReadbackTransport>,
        ShopifyRecoveryError,
    >
    where
        S: SecretStore,
    {
        // The returned source borrows only the caller-owned SecretStore and
        // Context-Material session; no borrow of Application's ProjectStore
        // escapes this preparation call.
        let reopened =
            ShopifySecureRecovery::new(&mut self.store, material).reopen_verification(reference)?;
        ShopifyIndependentVerificationSource::new_native(
            secret_store,
            material,
            reopened,
            selector,
            observation_authority_digest,
            cancellation,
            transport,
        )
    }
}

struct CurrentShopifyAuthority {
    effect: Effect,
    mission_revision: u64,
    credential_revision: u64,
    authorization_digest: String,
    permission_evidence: PermissionEvidence,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredShopifyRecoveryCapsule {
    schema: String,
    binding_digest: String,
    draft: DraftFulfillmentRequest,
}

fn rebuild_approved(
    draft: DraftFulfillmentRequest,
    plugin_revision: ShopifyPluginRevision,
    authorization_digest: &str,
    execution_expires_at: DateTime<Utc>,
) -> Result<ShopifyApprovedDraftFulfillment, ShopifyRecoveryError> {
    let prepared = PreparedEffect::new(
        draft.tenant_scope().connector_scope().clone(),
        ProviderCapabilityKey::new(SHOPIFY_PROVIDER_ID, SHOPIFY_FULFILLMENT_CAPABILITY)
            .map_err(|_| ShopifyRecoveryError::BindingMismatch)?,
        shopify_fulfillment_adapter_identity()
            .map_err(|_| ShopifyRecoveryError::BindingMismatch)?,
        draft.request_digest().to_owned(),
        shopify_sdk_effect_idempotency_key(&draft),
        draft.created_at(),
        draft.expires_at(),
        0,
    )
    .map_err(|_| ShopifyRecoveryError::BindingMismatch)?;
    let execution_context = EffectExecutionContext::from_broker(
        prepared.scope().clone(),
        prepared.effect_digest(),
        authorization_digest,
        execution_expires_at,
    )
    .map_err(|_| ShopifyRecoveryError::BindingMismatch)?;
    ShopifyApprovedDraftFulfillment::new(draft, prepared, execution_context, plugin_revision)
        .map_err(|_| ShopifyRecoveryError::BindingMismatch)
}

fn ensure_live_shape(
    effect: &Effect,
    mission_revision: u64,
    credential_revision: u64,
    approved: &ShopifyApprovedDraftFulfillment,
    material: &ProjectContextMaterialSession,
    now: DateTime<Utc>,
    require_live_execution: bool,
) -> Result<(), ShopifyRecoveryError> {
    if mission_revision == 0
        || credential_revision == 0
        || material.project_id() != &effect.project_id
        || material.keyring_revision() == 0
        || material.active_key_version() == 0
    {
        return Err(ShopifyRecoveryError::BindingMismatch);
    }
    validate_controlled_recovery_effect(effect, approved)?;
    let approval = effect
        .approval
        .as_ref()
        .ok_or(ShopifyRecoveryError::BindingMismatch)?;
    if approval.decision != ApprovalDecision::Approved
        || effect.status != EffectStatus::Approved
        || effect.provider != SHOPIFY_PROVIDER_ID
        || effect.capability != SHOPIFY_FULFILLMENT_CAPABILITY
    {
        return Err(ShopifyRecoveryError::BindingMismatch);
    }
    if require_live_execution
        && (approval.valid_until <= now
            || effect.expires_at <= now
            || approved.validate_at(now).is_err())
    {
        return Err(ShopifyRecoveryError::Expired);
    }
    Ok(())
}

fn recovery_binding(
    effect: &Effect,
    mission_revision: u64,
    credential_revision: u64,
    approved: &ShopifyApprovedDraftFulfillment,
    keyring_revision: u64,
    capsule_key_version: u64,
) -> Result<ProviderRecoveryBinding, ShopifyRecoveryError> {
    let approval = effect
        .approval
        .as_ref()
        .ok_or(ShopifyRecoveryError::BindingMismatch)?;
    let draft = approved.draft();
    let prepared = approved.prepared_effect();
    let scope = draft.tenant_scope();
    let fields = vec![
        SHOPIFY_RECOVERY_CAPSULE_SCHEMA.to_owned(),
        SHOPIFY_RECOVERY_CAPSULE_REVISION.to_string(),
        effect.tenant_id.to_string(),
        effect.project_id.to_string(),
        effect.mission_id.to_string(),
        mission_revision.to_string(),
        effect.id.to_string(),
        effect.approval_digest(),
        approval.id.to_string(),
        "approved".to_owned(),
        approval.decided_at.to_rfc3339(),
        approval.valid_until.to_rfc3339(),
        approval.scope_digest.clone(),
        approval.permission_digest.clone(),
        effect.provider.clone(),
        effect.capability.clone(),
        scope.digest(),
        scope.shop().as_str().to_owned(),
        SHOPIFY_APPLICATION_ADAPTER_ID.to_owned(),
        SHOPIFY_APPLICATION_ADAPTER_VERSION.to_string(),
        prepared.adapter().adapter_id().to_owned(),
        prepared.adapter().adapter_version().to_string(),
        prepared.effect_digest().to_owned(),
        approved.plugin_revision().value().to_string(),
        draft.provider_generation().to_string(),
        draft.request_digest().to_owned(),
        sha256(draft.idempotency_key().as_str().as_bytes()),
        sha256(approved.sdk_idempotency_key().as_bytes()),
        prepared.prepared_at().to_rfc3339(),
        prepared.expires_at().to_rfc3339(),
        credential_revision.to_string(),
        keyring_revision.to_string(),
        capsule_key_version.to_string(),
        approved.approval_binding_digest().to_owned(),
    ];
    let binding_digest = canonical_digest(&fields);
    let binding = ProviderRecoveryBinding {
        tenant_id: effect.tenant_id.clone(),
        project_id: effect.project_id.clone(),
        mission_id: effect.mission_id.clone(),
        mission_revision,
        effect_id: effect.id.clone(),
        effect_digest: prepared.effect_digest().to_owned(),
        approval_scope_digest: approval.scope_digest.clone(),
        broker_authorization_digest: approval.permission_digest.clone(),
        provider_id: effect.provider.clone(),
        capability_id: effect.capability.clone(),
        account_scope_digest: scope.digest(),
        adapter_id: SHOPIFY_APPLICATION_ADAPTER_ID.to_owned(),
        adapter_version: SHOPIFY_APPLICATION_ADAPTER_VERSION,
        plugin_revision: approved.plugin_revision().value(),
        provider_generation: draft.provider_generation(),
        payload_digest: draft.request_digest().to_owned(),
        provider_idempotency_key_digest: sha256(draft.idempotency_key().as_str().as_bytes()),
        sdk_idempotency_key_digest: sha256(approved.sdk_idempotency_key().as_bytes()),
        credential_revision,
        keyring_revision,
        binding_digest,
    };
    binding.validate()?;
    Ok(binding)
}

fn canonical_digest(fields: &[String]) -> String {
    let mut digest = Sha256::new();
    for field in fields {
        digest.update(field.len().to_be_bytes());
        digest.update(field.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

fn sha256(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn recovered_shopify_external_id(fulfillment_id: &str) -> String {
    format!("shopify-fulfillment:{}", sha256(fulfillment_id.as_bytes()))
}

fn recovery_state_name(state: ProviderRecoveryState) -> &'static str {
    match state {
        ProviderRecoveryState::Prepared => "prepared",
        ProviderRecoveryState::InFlight => "in_flight",
        ProviderRecoveryState::Uncertain => "uncertain",
        ProviderRecoveryState::NotExecuted => "not_executed",
        ProviderRecoveryState::ReceiptObserved => "receipt_observed",
        ProviderRecoveryState::Verified => "verified",
        ProviderRecoveryState::FailedClosed => "failed_closed",
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;

    use chrono::Duration;
    use hartevo_commerce_connector::shopify::{ShopDomain, ShopifyApiVersion};
    use hartevo_commerce_connector::shopify_effect::{
        ShopifyApprovalRevision, ShopifyEffectIdempotencyKey, ShopifyFulfillmentLineItem,
        ShopifyFulfillmentOrderGid, ShopifyFulfillmentOrderLineItemGid, ShopifyFulfillmentScope,
        ShopifyOrderGid, shopify_fulfillment_adapter_identity,
    };
    use hartevo_commerce_connector::shopify_effect_reconcile::{
        ShopifyEffectBoundaryReadback, ShopifyEffectBoundaryReceipt,
    };
    use hartevo_commerce_connector::shopify_transport::ShopifyFulfillmentGid;
    use hartevo_connector_sdk::{ConnectorError, ConnectorScope, ProviderCapabilityKey};
    use hartevo_domain_kernel::{
        AccountId, ActorId, Approval, ApprovalId, Connection, ConnectionId, ConnectionProbe,
        ConsentState, CurrencyCode, DeviceId, EffectClass, EffectId, EffectRisk, Mission,
        MissionContract, MissionId, Money, ProbeOutcome, Project, ProjectId, StorageMode, TenantId,
    };
    use hartevo_effect_broker::{EffectRateLimit, SecretScope};
    use hartevo_storage::{DatabaseKey, KeyMaterial, LocalEncryptedContextMaterialStore};
    use tempfile::TempDir;

    use super::*;
    use crate::connectors::shopify_readback::{
        ShopifyReadbackCredentialBinding, fixture_brokered_exact_readback,
    };

    const READ_SCOPE: &str = "read_merchant_managed_fulfillment_orders";
    const WRITE_SCOPE: &str = "write_merchant_managed_fulfillment_orders";
    const PRIVATE_LINE_ITEM_MARKER: &str = "FulfillmentOrderLineItem/987654321";

    struct NeverCalledBoundary;

    impl ShopifyTypedEffectBoundary for NeverCalledBoundary {
        fn execute(
            &mut self,
            _approved: &ShopifyApprovedDraftFulfillment,
        ) -> Result<ShopifyEffectBoundaryReceipt, ConnectorError> {
            panic!("recovery construction must not execute a provider")
        }

        fn reconcile(
            &mut self,
            _approved: &ShopifyApprovedDraftFulfillment,
            _prior_provider_receipt: Option<
                &hartevo_commerce_connector::shopify_effect::ShopifyProviderReceipt,
            >,
        ) -> Result<ShopifyEffectBoundaryReadback, ConnectorError> {
            panic!("recovery construction must not reconcile a provider")
        }

        fn verify(
            &mut self,
            _approved: &ShopifyApprovedDraftFulfillment,
            _readback: &ShopifyEffectBoundaryReadback,
        ) -> Result<hartevo_connector_sdk::VerificationObservation, ConnectorError> {
            panic!("recovery construction must not verify a provider")
        }
    }

    fn material_session(
        root: &std::path::Path,
        tenant_id: &TenantId,
        project_id: &ProjectId,
    ) -> ProjectContextMaterialSession {
        ProjectContextMaterialSession {
            store: LocalEncryptedContextMaterialStore::new(
                root,
                tenant_id.clone(),
                project_id.clone(),
                1,
                KeyMaterial::from_bytes([7_u8; 32]).unwrap(),
            )
            .unwrap(),
            tenant_id: tenant_id.clone(),
            project_id: project_id.clone(),
            device_id: DeviceId::from_stable("device-shopify-recovery"),
            keyring_revision: 3,
            active_key_version: 1,
            readable_key_versions: BTreeSet::from([1]),
            unavailable_historical_key_versions: BTreeSet::new(),
        }
    }

    fn assert_n14_exact_readback_binding(
        reopened: &ReopenedShopifyReconciliation,
        reference: &ShopifyRecoveryCapsuleRef,
        approved: &ShopifyApprovedDraftFulfillment,
        effect: &Effect,
        head_before: &ProviderRecoveryHead,
    ) {
        let reference_debug = format!("{reference:?}");
        for private in [
            reference.project_id.to_string(),
            reference.effect_id.to_string(),
            reference.binding_digest.clone(),
            reference.storage_ref.clone(),
            reference.content_digest.clone(),
        ] {
            assert!(
                !reference_debug.contains(&private),
                "recovery Debug leaked private identity or locator"
            );
        }
        let selector = ShopifyFulfillmentReadbackRequest::new(
            approved.draft().tenant_scope().shop().clone(),
            approved.draft().api_version().clone(),
            ShopifyFulfillmentGid::parse("gid://shopify/Fulfillment/3001").unwrap(),
        )
        .unwrap();
        let authority_digest = reference.readback_authority_digest(&selector).unwrap();
        let other_selector = ShopifyFulfillmentReadbackRequest::new(
            approved.draft().tenant_scope().shop().clone(),
            approved.draft().api_version().clone(),
            ShopifyFulfillmentGid::parse("gid://shopify/Fulfillment/3002").unwrap(),
        )
        .unwrap();
        assert_ne!(
            authority_digest,
            reference
                .readback_authority_digest(&other_selector)
                .unwrap()
        );
        let exact_readback = reopened
            .bind_exact_readback(&selector, &authority_digest)
            .unwrap();
        let expected_identity = exact_readback
            .expected_identity()
            .expect("approved capsule binds exact identity");
        assert_eq!(effect.target_resource, "shopify://recovery/fulfillment");
        assert_eq!(expected_identity.order_id(), approved.draft().order_gid());
        assert_eq!(
            expected_identity.fulfillment_order_id(),
            approved.draft().fulfillment_order_gid()
        );
        assert_eq!(
            expected_identity.line_items(),
            approved.draft().line_items()
        );
        assert_eq!(
            expected_identity.provider_created_at_not_before(),
            head_before.prepared_at
        );
        let observed = hartevo_commerce_connector::shopify_transport::ShopifyFulfillmentReadback::fixture_exact(
            &exact_readback,
            "SUCCESS",
            head_before.prepared_at + Duration::seconds(1),
            head_before.prepared_at + Duration::seconds(2),
        )
        .unwrap();
        assert!(observed.receipt_identity().is_some());
        let wrong_shop = ShopifyFulfillmentReadbackRequest::new(
            ShopDomain::parse("other.myshopify.com").unwrap(),
            approved.draft().api_version().clone(),
            ShopifyFulfillmentGid::parse("gid://shopify/Fulfillment/3001").unwrap(),
        )
        .unwrap();
        assert_eq!(
            reopened.bind_exact_readback(&wrong_shop, &authority_digest),
            Err(ShopifyNativeReadbackError::InvalidRequest)
        );
    }

    #[allow(clippy::too_many_lines)]
    fn approved_and_effect(
        now: DateTime<Utc>,
        authorization_digest: String,
    ) -> (ShopifyApprovedDraftFulfillment, Effect) {
        let scope = ShopifyFulfillmentScope::new(
            ConnectorScope::new(
                "tenant-shopify-recovery",
                "project-shopify-recovery",
                SHOPIFY_PROVIDER_ID,
                "account-shopify-recovery",
                [READ_SCOPE.to_owned(), WRITE_SCOPE.to_owned()],
            )
            .unwrap(),
            ShopDomain::parse("recovery.myshopify.com").unwrap(),
        )
        .unwrap();
        let draft = DraftFulfillmentRequest::new(
            "shopify-draft-fulfillment-recovery",
            "mission-shopify-recovery",
            scope.clone(),
            ShopifyApiVersion::latest(),
            ShopifyOrderGid::parse("gid://shopify/Order/1001").unwrap(),
            ShopifyFulfillmentOrderGid::parse("gid://shopify/FulfillmentOrder/2001").unwrap(),
            vec![
                ShopifyFulfillmentLineItem::new(
                    ShopifyFulfillmentOrderLineItemGid::parse(format!(
                        "gid://shopify/{PRIVATE_LINE_ITEM_MARKER}"
                    ))
                    .unwrap(),
                    1,
                )
                .unwrap(),
            ],
            5,
            ShopifyApprovalRevision::new(2).unwrap(),
            ShopifyEffectIdempotencyKey::parse("shopify-effect-idem-recovery").unwrap(),
            now - Duration::seconds(1),
            now + Duration::minutes(5),
        )
        .unwrap();
        let prepared = PreparedEffect::new(
            scope.connector_scope().clone(),
            ProviderCapabilityKey::new(SHOPIFY_PROVIDER_ID, SHOPIFY_FULFILLMENT_CAPABILITY)
                .unwrap(),
            shopify_fulfillment_adapter_identity().unwrap(),
            draft.request_digest().to_owned(),
            hartevo_commerce_connector::shopify_effect_reconcile::shopify_sdk_effect_idempotency_key(
                &draft,
            ),
            draft.created_at(),
            draft.expires_at(),
            0,
        )
        .unwrap();
        let execution_context = EffectExecutionContext::from_broker(
            prepared.scope().clone(),
            prepared.effect_digest(),
            authorization_digest.clone(),
            draft.expires_at() + Duration::seconds(30),
        )
        .unwrap();
        let approved = ShopifyApprovedDraftFulfillment::new(
            draft.clone(),
            prepared,
            execution_context,
            ShopifyPluginRevision::new(4).unwrap(),
        )
        .unwrap();
        let mut effect = Effect {
            id: EffectId::from_stable("effect-shopify-recovery"),
            tenant_id: TenantId::from_stable("tenant-shopify-recovery"),
            project_id: ProjectId::from_stable("project-shopify-recovery"),
            mission_id: MissionId::from_stable("mission-shopify-recovery"),
            actor_id: ActorId::from_stable("actor-shopify-recovery"),
            capability: SHOPIFY_FULFILLMENT_CAPABILITY.to_owned(),
            provider: SHOPIFY_PROVIDER_ID.to_owned(),
            connection_id: Some(ConnectionId::from_stable("connection-shopify-recovery")),
            account_id: Some(AccountId::from_stable("account-shopify-recovery")),
            required_scopes: BTreeSet::from([READ_SCOPE.to_owned(), WRITE_SCOPE.to_owned()]),
            effect_class: EffectClass::ExternalWrite,
            description: "Create one controlled Shopify fulfillment".into(),
            target_resource: "shopify://recovery/fulfillment".into(),
            audience_digest: None,
            payload_digest: draft.request_digest().to_owned(),
            asset_digests: BTreeSet::new(),
            scheduled_for: None,
            timezone: "UTC".into(),
            consent: ConsentState::NotRequired,
            consent_record_id: None,
            consent_requirement: None,
            conversation_guard: None,
            creator_contact_guard: None,
            policy_version: "policy-shopify-recovery".into(),
            risk: EffectRisk::High,
            idempotency_key: draft.idempotency_key().as_str().to_owned(),
            amount: Money::zero(CurrencyCode::parse("USD").unwrap()),
            expires_at: draft.expires_at(),
            status: EffectStatus::Approved,
            approval: None,
            receipt: None,
            verification: None,
        };
        effect.approval = Some(Approval {
            id: ApprovalId::from_stable("approval-shopify-recovery"),
            decision: ApprovalDecision::Approved,
            decided_by: ActorId::from_stable("approver-shopify-recovery"),
            decided_at: now - Duration::seconds(1),
            valid_until: now + Duration::minutes(4),
            scope_digest: effect.approval_digest(),
            permission_digest: authorization_digest,
        });
        (approved, effect)
    }

    fn effect_policy() -> EffectPolicy {
        EffectPolicy {
            version: "policy-shopify-recovery".into(),
            allowed_capabilities: BTreeSet::from([SHOPIFY_FULFILLMENT_CAPABILITY.into()]),
            allowed_classes: BTreeSet::from([EffectClass::ExternalWrite]),
            max_amounts_minor: BTreeMap::from([(CurrencyCode::parse("USD").unwrap(), 0)]),
            rate_limits: vec![EffectRateLimit {
                rule_id: "shopify-recovery-write".into(),
                provider: SHOPIFY_PROVIDER_ID.into(),
                capability: SHOPIFY_FULFILLMENT_CAPABILITY.into(),
                max_executions: 1,
                window_seconds: 60,
            }],
        }
    }

    fn persist_live_authority(
        store: &mut ProjectStore,
        workspace_root: &std::path::Path,
        now: DateTime<Utc>,
    ) -> (ShopifyApprovedDraftFulfillment, Effect, EffectPolicy) {
        let (_, unsigned_effect) = approved_and_effect(now, sha256(b"unsigned-placeholder"));
        let project = Project::create_local(
            unsigned_effect.tenant_id.clone(),
            unsigned_effect.project_id.clone(),
            "Shopify recovery",
            "",
            workspace_root,
            StorageMode::LocalExisting,
        )
        .unwrap();
        store.save_project(&project).unwrap();

        let connection_id = unsigned_effect.connection_id.clone().unwrap();
        let account_id = unsigned_effect.account_id.clone().unwrap();
        let mut connection = Connection::register(
            connection_id,
            unsigned_effect.tenant_id.clone(),
            unsigned_effect.project_id.clone(),
            SHOPIFY_PROVIDER_ID,
            account_id.clone(),
            account_id.to_string(),
            unsigned_effect.required_scopes.clone(),
            now - Duration::minutes(1),
        )
        .unwrap();
        store
            .create_connection(
                &connection,
                "connection.registered",
                &serde_json::json!({}),
                now - Duration::minutes(1),
            )
            .unwrap();
        connection.begin_probe(now - Duration::seconds(30)).unwrap();
        store
            .update_connection(
                &connection,
                1,
                "connection.probe_started",
                &serde_json::json!({}),
                now - Duration::seconds(30),
            )
            .unwrap();
        connection
            .apply_probe(
                ConnectionProbe {
                    outcome: ProbeOutcome::Successful,
                    observed_external_account_id: account_id.to_string(),
                    granted_scopes: unsigned_effect.required_scopes.clone(),
                    probed_at: now - Duration::seconds(20),
                    valid_until: now + Duration::minutes(5),
                    credential_expires_at: now + Duration::minutes(5),
                    evidence_digest: sha256(b"shopify-recovery-probe"),
                },
                now - Duration::seconds(20),
            )
            .unwrap();
        store
            .update_connection(
                &connection,
                2,
                "connection.probed",
                &serde_json::json!({}),
                now - Duration::seconds(20),
            )
            .unwrap();

        let policy = effect_policy();
        let permission_evidence = store.authorize(&unsigned_effect, now).unwrap();
        let claim_context = policy
            .execution_claim_context(&unsigned_effect, permission_evidence)
            .unwrap();
        let (approved, effect) =
            approved_and_effect(now, claim_context.authorization_digest.clone());
        let mut mission = Mission::compile(
            effect.tenant_id.clone(),
            effect.mission_id.clone(),
            effect.project_id.clone(),
            "Shopify recovery mission",
            MissionContract::bootstrap(
                "Create one controlled Shopify fulfillment",
                [SHOPIFY_FULFILLMENT_CAPABILITY.to_owned()],
                now - Duration::minutes(1),
            ),
            now - Duration::minutes(1),
        )
        .unwrap();
        mission.effects.push(effect.clone());
        mission.revision = 9;
        store.save_mission(&mission).unwrap();
        (approved, effect, policy)
    }

    fn database_key() -> DatabaseKey {
        DatabaseKey::new([8_u8; 32]).unwrap()
    }

    #[test]
    fn encrypted_prepared_capsule_reopens_and_claims_exactly_once() {
        let temporary = TempDir::new().unwrap();
        let database_path = temporary.path().join("shopify-recovery.sqlite3");
        let now = Utc::now();

        let mut store = ProjectStore::open(&database_path, &database_key()).unwrap();
        let (approved, effect, policy) = persist_live_authority(&mut store, temporary.path(), now);
        let material = material_session(temporary.path(), &effect.tenant_id, &effect.project_id);
        let reference = ShopifySecureRecovery::new(&mut store, &material)
            .prepare_controlled(&effect, &approved, &policy, now)
            .unwrap();
        let digest = reference.content_digest.clone();
        let raw_path = temporary
            .path()
            .join(".hartevo/context-material")
            .join(&digest[..2])
            .join(format!("{digest}.hctx"));
        let raw = fs::read(raw_path).unwrap();
        assert!(
            !raw.windows(PRIVATE_LINE_ITEM_MARKER.len())
                .any(|window| window == PRIVATE_LINE_ITEM_MARKER.as_bytes())
        );
        let serialized_head = serde_json::to_string(
            &store
                .load_provider_recovery(&effect.project_id, &effect.id)
                .unwrap(),
        )
        .unwrap();
        assert!(!serialized_head.contains(PRIVATE_LINE_ITEM_MARKER));
        drop(store);
        drop(material);

        let material = material_session(temporary.path(), &effect.tenant_id, &effect.project_id);
        let mut store = ProjectStore::open(&database_path, &database_key()).unwrap();
        let current_ref = {
            let mut recovery = ShopifySecureRecovery::new(&mut store, &material);
            let mut stale_policy = policy.clone();
            stale_policy.version = "policy-shopify-recovery-stale".into();
            assert!(matches!(
                recovery.claim_controlled_adapter(
                    &reference,
                    &stale_policy,
                    NeverCalledBoundary,
                    now,
                ),
                Err(ShopifyRecoveryError::BindingMismatch)
            ));
            assert_eq!(recovery.load_head(&reference).unwrap().revision, 1);
            let claimed = recovery
                .claim_controlled_adapter(&reference, &policy, NeverCalledBoundary, now)
                .unwrap();
            assert_eq!(claimed.head().state, ProviderRecoveryState::InFlight);
            assert_eq!(claimed.head().revision, 2);
            ShopifyRecoveryCapsuleRef::from_head(claimed.head())
        };
        drop(store);
        drop(material);

        let material = material_session(temporary.path(), &effect.tenant_id, &effect.project_id);
        let mut store = ProjectStore::open(&database_path, &database_key()).unwrap();
        let mut recovery = ShopifySecureRecovery::new(&mut store, &material);
        assert!(matches!(
            recovery.claim_controlled_adapter(&current_ref, &policy, NeverCalledBoundary, now,),
            Err(ShopifyRecoveryError::ReconciliationOnly)
        ));
        let head = recovery.load_head(&current_ref).unwrap();
        assert_eq!(head.state, ProviderRecoveryState::InFlight);
        assert_eq!(head.revision, 2);
    }

    #[test]
    fn n12b_uncertain_capsule_binds_n14_known_gid_without_rewriting_effect_or_head() {
        let temporary = TempDir::new().unwrap();
        let database_path = temporary.path().join("shopify-reconciliation.sqlite3");
        let now = Utc::now();
        let mut store = ProjectStore::open(&database_path, &database_key()).unwrap();
        let (approved, effect, policy) = persist_live_authority(&mut store, temporary.path(), now);
        let material = material_session(temporary.path(), &effect.tenant_id, &effect.project_id);
        let prepared = ShopifySecureRecovery::new(&mut store, &material)
            .prepare_controlled(&effect, &approved, &policy, now)
            .unwrap();
        assert!(matches!(
            ShopifySecureRecovery::new(&mut store, &material).reopen_reconciliation(&prepared),
            Err(ShopifyRecoveryError::ReconciliationOnly)
        ));

        let claimed = ShopifySecureRecovery::new(&mut store, &material)
            .claim_controlled_adapter(&prepared, &policy, NeverCalledBoundary, now)
            .unwrap();
        let reference = ShopifyRecoveryCapsuleRef::from_head(claimed.head());
        drop(claimed);

        let mut mission = store
            .load_mission(&effect.project_id, &effect.mission_id)
            .unwrap();
        let current_effect = mission
            .effects
            .iter_mut()
            .find(|candidate| candidate.id == effect.id)
            .unwrap();
        current_effect.status = EffectStatus::VerificationRequired;
        mission.revision += 1;
        let current_revision = mission.revision;
        store.save_mission(&mission).unwrap();
        let head_before = store
            .load_provider_recovery(&effect.project_id, &effect.id)
            .unwrap();

        let reopened = ShopifySecureRecovery::new(&mut store, &material)
            .reopen_reconciliation(&reference)
            .unwrap();
        assert_eq!(reopened.approved.draft(), approved.draft());
        assert_eq!(
            reopened.approved.prepared_effect(),
            approved.prepared_effect()
        );
        assert_eq!(
            reopened.approved.approval_binding_digest(),
            approved.approval_binding_digest()
        );
        assert_eq!(reopened.effect.status, EffectStatus::VerificationRequired);
        assert_eq!(reopened.current_mission_revision, current_revision);
        assert_eq!(reopened.head, head_before);
        assert_n14_exact_readback_binding(&reopened, &reference, &approved, &effect, &head_before);
        assert_eq!(
            store
                .load_provider_recovery(&effect.project_id, &effect.id)
                .unwrap(),
            head_before
        );
    }

    #[test]
    fn fixture_readback_cannot_be_sealed_as_a_recovered_receipt() {
        let temporary = TempDir::new().unwrap();
        let database_path = temporary
            .path()
            .join("shopify-fixture-receipt-rejection.sqlite3");
        let now = Utc::now();
        let mut store = ProjectStore::open(&database_path, &database_key()).unwrap();
        let (approved, effect, policy) = persist_live_authority(&mut store, temporary.path(), now);
        let material = material_session(temporary.path(), &effect.tenant_id, &effect.project_id);
        let prepared = ShopifySecureRecovery::new(&mut store, &material)
            .prepare_controlled(&effect, &approved, &policy, now)
            .unwrap();
        let claimed = ShopifySecureRecovery::new(&mut store, &material)
            .claim_controlled_adapter(&prepared, &policy, NeverCalledBoundary, now)
            .unwrap();
        let reference = ShopifyRecoveryCapsuleRef::from_head(claimed.head());
        drop(claimed);

        let mut mission = store
            .load_mission(&effect.project_id, &effect.mission_id)
            .unwrap();
        mission
            .effects
            .iter_mut()
            .find(|candidate| candidate.id == effect.id)
            .unwrap()
            .status = EffectStatus::VerificationRequired;
        mission.revision += 1;
        store.save_mission(&mission).unwrap();
        let mission_before = mission.clone();
        let head_before = store
            .load_provider_recovery(&effect.project_id, &effect.id)
            .unwrap();
        let reopened = ShopifySecureRecovery::new(&mut store, &material)
            .reopen_reconciliation(&reference)
            .unwrap();
        let selector = ShopifyFulfillmentReadbackRequest::new(
            approved.draft().tenant_scope().shop().clone(),
            approved.draft().api_version().clone(),
            ShopifyFulfillmentGid::parse("gid://shopify/Fulfillment/3001").unwrap(),
        )
        .unwrap();
        let authority_digest = reference.readback_authority_digest(&selector).unwrap();
        let exact_request = reopened
            .bind_exact_readback(&selector, &authority_digest)
            .unwrap();
        let scope = SecretScope::new(
            effect.tenant_id.clone(),
            effect.project_id.clone(),
            effect.mission_id.clone(),
            SHOPIFY_PROVIDER_ID,
            effect.account_id.clone().unwrap(),
            SHOPIFY_FULFILLMENT_CAPABILITY,
        )
        .unwrap();
        let binding = ShopifyReadbackCredentialBinding::new(
            scope,
            approved.draft().tenant_scope().shop().clone(),
            head_before.binding.credential_revision,
        )
        .unwrap();
        let observed_at = now + Duration::seconds(2);
        let brokered = fixture_brokered_exact_readback(
            binding,
            exact_request.clone(),
            now + Duration::seconds(1),
            observed_at,
            observed_at,
        )
        .unwrap();
        assert_eq!(
            brokered.readback().provenance_class(),
            ProviderProvenanceClass::Fixture
        );
        let connection = store
            .load_connection(&effect.project_id, effect.connection_id.as_ref().unwrap())
            .unwrap();
        assert!(matches!(
            reopened.seal_receipt_found(
                &brokered,
                &selector,
                &exact_request,
                connection.snapshot(),
                &material,
                &authority_digest,
                now,
                observed_at,
            ),
            Err(ShopifyRecoveryError::BindingMismatch)
        ));
        assert_eq!(
            store
                .load_provider_recovery(&effect.project_id, &effect.id)
                .unwrap(),
            head_before
        );
        assert_eq!(
            store
                .load_mission(&effect.project_id, &effect.mission_id)
                .unwrap(),
            mission_before
        );
    }

    #[test]
    fn reconciliation_reopen_rejects_connection_rotation_without_mutating_head() {
        let temporary = TempDir::new().unwrap();
        let database_path = temporary
            .path()
            .join("shopify-reconciliation-rotation.sqlite3");
        let now = Utc::now();
        let mut store = ProjectStore::open(&database_path, &database_key()).unwrap();
        let (approved, effect, policy) = persist_live_authority(&mut store, temporary.path(), now);
        let material = material_session(temporary.path(), &effect.tenant_id, &effect.project_id);
        let prepared = ShopifySecureRecovery::new(&mut store, &material)
            .prepare_controlled(&effect, &approved, &policy, now)
            .unwrap();
        let claimed = ShopifySecureRecovery::new(&mut store, &material)
            .claim_controlled_adapter(&prepared, &policy, NeverCalledBoundary, now)
            .unwrap();
        let reference = ShopifyRecoveryCapsuleRef::from_head(claimed.head());
        drop(claimed);
        let mut mission = store
            .load_mission(&effect.project_id, &effect.mission_id)
            .unwrap();
        mission
            .effects
            .iter_mut()
            .find(|candidate| candidate.id == effect.id)
            .unwrap()
            .status = EffectStatus::VerificationRequired;
        mission.revision += 1;
        store.save_mission(&mission).unwrap();

        let connection_id = effect.connection_id.as_ref().unwrap();
        let mut connection = store
            .load_connection(&effect.project_id, connection_id)
            .unwrap();
        let expected_revision = connection.revision();
        connection.begin_probe(now).unwrap();
        store
            .update_connection(
                &connection,
                expected_revision,
                "connection.probe_started",
                &serde_json::json!({}),
                now,
            )
            .unwrap();
        let head_before = store
            .load_provider_recovery(&effect.project_id, &effect.id)
            .unwrap();
        assert!(matches!(
            ShopifySecureRecovery::new(&mut store, &material).reopen_reconciliation(&reference),
            Err(ShopifyRecoveryError::BindingMismatch)
        ));
        assert_eq!(
            store
                .load_provider_recovery(&effect.project_id, &effect.id)
                .unwrap(),
            head_before
        );
    }

    #[test]
    fn missing_or_changed_durable_authority_cannot_claim() {
        let temporary = TempDir::new().unwrap();
        let database_path = temporary.path().join("shopify-recovery-authority.sqlite3");
        let now = Utc::now();
        let mut store = ProjectStore::open(&database_path, &database_key()).unwrap();
        let (approved, effect, policy) = persist_live_authority(&mut store, temporary.path(), now);
        let material = material_session(temporary.path(), &effect.tenant_id, &effect.project_id);
        let reference = ShopifySecureRecovery::new(&mut store, &material)
            .prepare_controlled(&effect, &approved, &policy, now)
            .unwrap();

        let mut mission = store
            .load_mission(&effect.project_id, &effect.mission_id)
            .unwrap();
        mission.revision += 1;
        store.save_mission(&mission).unwrap();
        let mut recovery = ShopifySecureRecovery::new(&mut store, &material);
        assert!(matches!(
            recovery.claim_controlled_adapter(&reference, &policy, NeverCalledBoundary, now,),
            Err(ShopifyRecoveryError::BindingMismatch)
        ));
        assert_eq!(recovery.load_head(&reference).unwrap().revision, 1);

        let revoked = TempDir::new().unwrap();
        let revoked_database = revoked.path().join("shopify-recovery-revoked.sqlite3");
        let mut revoked_store = ProjectStore::open(&revoked_database, &database_key()).unwrap();
        let (approved, effect, policy) =
            persist_live_authority(&mut revoked_store, revoked.path(), now);
        let revoked_material =
            material_session(revoked.path(), &effect.tenant_id, &effect.project_id);
        let reference = ShopifySecureRecovery::new(&mut revoked_store, &revoked_material)
            .prepare_controlled(&effect, &approved, &policy, now)
            .unwrap();
        let connection_id = effect.connection_id.as_ref().unwrap();
        let mut connection = revoked_store
            .load_connection(&effect.project_id, connection_id)
            .unwrap();
        let expected_revision = connection.revision();
        connection.revoke(now).unwrap();
        revoked_store
            .update_connection(
                &connection,
                expected_revision,
                "connection.revoked",
                &serde_json::json!({}),
                now,
            )
            .unwrap();
        let mut recovery = ShopifySecureRecovery::new(&mut revoked_store, &revoked_material);
        assert!(matches!(
            recovery.claim_controlled_adapter(&reference, &policy, NeverCalledBoundary, now,),
            Err(ShopifyRecoveryError::BindingMismatch)
        ));
        assert_eq!(recovery.load_head(&reference).unwrap().revision, 1);
    }

    #[test]
    fn empty_store_and_unknown_capsule_revision_fail_closed() {
        let temporary = TempDir::new().unwrap();
        let database_path = temporary.path().join("shopify-recovery-empty.sqlite3");
        let now = Utc::now();
        let (approved, effect) =
            approved_and_effect(now, sha256(b"shopify-recovery-authorization"));
        let policy = effect_policy();
        let material = material_session(temporary.path(), &effect.tenant_id, &effect.project_id);
        let mut store = ProjectStore::open(&database_path, &database_key()).unwrap();
        assert!(matches!(
            ShopifySecureRecovery::new(&mut store, &material)
                .prepare_controlled(&effect, &approved, &policy, now),
            Err(ShopifyRecoveryError::Storage(
                StorageError::ProjectNotFound(_)
            ))
        ));

        let (approved, effect, policy) = persist_live_authority(&mut store, temporary.path(), now);
        let reference = ShopifySecureRecovery::new(&mut store, &material)
            .prepare_controlled(&effect, &approved, &policy, now)
            .unwrap();
        let mut unknown = reference.clone();
        unknown.object_revision = SHOPIFY_RECOVERY_CAPSULE_REVISION + 1;
        assert!(matches!(
            ShopifySecureRecovery::new(&mut store, &material).claim_controlled_adapter(
                &unknown,
                &policy,
                NeverCalledBoundary,
                now,
            ),
            Err(ShopifyRecoveryError::ReconciliationOnly)
        ));
        assert_eq!(
            store
                .load_provider_recovery(&effect.project_id, &effect.id)
                .unwrap()
                .revision,
            1
        );
    }
}
