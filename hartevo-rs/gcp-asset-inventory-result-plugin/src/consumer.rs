//! Mission-bound Cloud Asset Inventory evidence consumer.

use std::fmt;

use thiserror::Error;

use crate::model::{
    AssetInventoryEvidence, AssetInventoryScope, AssetProjection, Digest, EffectObservation,
    RedactedAsset,
};
use crate::service::{GcpAssetInventoryRegistration, RegistrationState};
use crate::{GCP_ASSET_INVENTORY_PROVIDER_ID, MISSION_GCP_ASSET_INVENTORY_CONSUMER_ID};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error("Mission GCP Asset Inventory consumer is revoked")]
    Revoked,
    #[error("Mission GCP Asset Inventory registration is stale, revoked, or tampered")]
    RegistrationMismatch,
    #[error("Mission GCP Asset Inventory evidence is tampered or internally inconsistent")]
    EvidenceTampered,
    #[error("Mission GCP Asset Inventory evidence does not match the exact scope")]
    ScopeMismatch,
    #[error("Mission GCP Asset Inventory evidence provider, scope, or contract binding drifted")]
    BindingDrift,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionGcpAssetInventoryState {
    EvidenceAvailable,
    PartialEvidence,
    AccessLost,
    ProviderUnknown,
}

impl MissionGcpAssetInventoryState {
    pub const fn from_projection(projection: AssetProjection) -> Self {
        match projection {
            AssetProjection::Complete => Self::EvidenceAvailable,
            AssetProjection::Partial(_) => Self::PartialEvidence,
            AssetProjection::AccessLost => Self::AccessLost,
            AssetProjection::ProviderUnknown => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionGcpAssetInventoryResult {
    pub consumer_id: &'static str,
    pub scope: AssetInventoryScope,
    pub project_id: String,
    pub project_revision: u64,
    pub mission_id: String,
    pub mission_revision: u64,
    pub work_product_id: String,
    pub work_product_revision: u64,
    pub projection: AssetProjection,
    pub state: MissionGcpAssetInventoryState,
    pub assets: Vec<RedactedAsset>,
    pub evidence: AssetInventoryEvidence,
    pub evidence_digest: Digest,
    pub effect_observation: EffectObservation,
    pub external_effect_succeeded: bool,
    pub adopts_outcome: bool,
    pub truth_authority: bool,
}

pub struct MissionGcpAssetConsumer {
    scope: AssetInventoryScope,
    registration: GcpAssetInventoryRegistration,
    active: bool,
}

impl fmt::Debug for MissionGcpAssetConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionGcpAssetConsumer")
            .field("scope_digest", &self.scope.scope_digest())
            .field("registration", &self.registration)
            .field("active", &self.active)
            .finish()
    }
}

impl MissionGcpAssetConsumer {
    pub fn new(
        scope: AssetInventoryScope,
        registration: &GcpAssetInventoryRegistration,
    ) -> Result<Self, ConsumerError> {
        if registration.state != RegistrationState::Active
            || !registration.verify_digest()
            || registration.scope_digest != scope.scope_digest()
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration: registration.clone(),
            active: true,
        })
    }

    pub const fn consumer_id(&self) -> &'static str {
        MISSION_GCP_ASSET_INVENTORY_CONSUMER_ID
    }

    pub fn registration(&self) -> &GcpAssetInventoryRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &AssetInventoryScope {
        &self.scope
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Revoked);
        }
        self.active = false;
        Ok(())
    }

    pub fn consume(
        &self,
        evidence: AssetInventoryEvidence,
    ) -> Result<MissionGcpAssetInventoryResult, ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Revoked);
        }
        if self.registration.state != RegistrationState::Active
            || !self.registration.verify_digest()
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        if !evidence.verify_integrity() {
            return Err(ConsumerError::EvidenceTampered);
        }
        if evidence.scope_digest != self.registration.scope_digest
            || evidence.registration_digest != self.registration.registration_digest
            || evidence.registration_revision != self.registration.revision
            || evidence.provider_id != GCP_ASSET_INVENTORY_PROVIDER_ID
            || evidence.digests.provider_digest != self.registration.provider_digest
            || evidence.digests.version_digest != self.registration.version_digest
            || evidence.digests.contract_digest != self.registration.contract_digest
            || evidence.digests.permission_digest != self.registration.permission_digest
            || evidence.digests.scope_digest != self.registration.scope_digest
            || evidence.digests.query_digest != self.registration.query_digest
        {
            return Err(ConsumerError::BindingDrift);
        }
        if evidence
            .assets
            .iter()
            .any(|asset| !asset.matches_scope(&self.scope))
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        let state = MissionGcpAssetInventoryState::from_projection(evidence.projection);
        Ok(MissionGcpAssetInventoryResult {
            consumer_id: MISSION_GCP_ASSET_INVENTORY_CONSUMER_ID,
            scope: self.scope.clone(),
            project_id: self.scope.project.id.clone(),
            project_revision: self.scope.project.revision.get(),
            mission_id: self.scope.mission.id.clone(),
            mission_revision: self.scope.mission.revision.get(),
            work_product_id: self.scope.work_product.id.clone(),
            work_product_revision: self.scope.work_product.revision.get(),
            projection: evidence.projection,
            state,
            assets: evidence.assets.clone(),
            evidence_digest: evidence.digests.evidence_digest.clone(),
            effect_observation: evidence.effect_observation,
            external_effect_succeeded: false,
            adopts_outcome: false,
            truth_authority: false,
            evidence,
        })
    }

    pub fn consume_observation(
        &self,
        evidence: AssetInventoryEvidence,
    ) -> Result<MissionGcpAssetInventoryResult, ConsumerError> {
        self.consume(evidence)
    }
}

pub type MissionGcpAssetInventoryConsumer = MissionGcpAssetConsumer;
pub type MissionGcpAssetResult = MissionGcpAssetInventoryResult;
