//! Restart-safe, controlled Shopify payload recovery.
//!
//! The private approved draft is stored only through encrypted project
//! Context-Material CAS. SQLCipher stores a content-free exact binding and a
//! monotonic recovery state. This module never obtains a production provider,
//! credential, network transport, or Effect authority.

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
    ShopifyNativeReadbackError,
};
pub use hartevo_connector_sdk::ConnectorScope;
use hartevo_connector_sdk::{EffectExecutionContext, PreparedEffect, ProviderCapabilityKey};
use hartevo_domain_kernel::{ApprovalDecision, Effect, EffectStatus};
use hartevo_effect_broker::{EffectPermissionResolver, EffectPolicy, PermissionEvidence};
use hartevo_storage::{
    ContextMaterialStoreError, ProjectStore, ProviderRecoveryBinding, ProviderRecoveryCapsule,
    ProviderRecoveryHead, ProviderRecoveryState, StorageError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::shopify::{
    SHOPIFY_APPLICATION_ADAPTER_ID, ShopifyAdapterError, ShopifyEffectAdapter,
    validate_controlled_recovery_effect,
};
use crate::{ApplicationService, ProjectContextMaterialSession};

const SHOPIFY_RECOVERY_CAPSULE_SCHEMA: &str = "hartevo-shopify-recovery-capsule/v1";
const SHOPIFY_RECOVERY_CAPSULE_REVISION: u64 = 1;
const SHOPIFY_APPLICATION_ADAPTER_VERSION: u64 = 1;

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
            .field("project_id", &self.project_id)
            .field("effect_id", &self.effect_id)
            .field("binding_digest", &self.binding_digest)
            .field("storage_ref", &self.storage_ref)
            .field("content_digest", &self.content_digest)
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
    #[error(transparent)]
    Adapter(#[from] ShopifyAdapterError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    ContextMaterial(#[from] ContextMaterialStoreError),
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
    use hartevo_effect_broker::EffectRateLimit;
    use hartevo_storage::{DatabaseKey, KeyMaterial, LocalEncryptedContextMaterialStore};
    use tempfile::TempDir;

    use super::*;

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
