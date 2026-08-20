use std::collections::{BTreeSet, HashSet};
use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    BrowserControlLeaseId, BrowserProfileId, BrowserSnapshotId, BrowserTabId, BrowserWorkspaceId,
    Mission, MissionId, ProjectId, TenantId,
};
use serde::{Deserialize, Serialize};

use crate::workspace::{digest, digest_json, is_bounded_identifier, is_sha256};
use crate::{
    BrowserControlState, BrowserError, BrowserLeaseProof, BrowserProfile, BrowserProfileSource,
    BrowserProfileStatus, BrowserWorkspace,
};

const HANDOFF_SCHEMA_VERSION: u32 = 1;
const HANDOFF_SERVICE_ID: &str = "hartevo.browser-workspace.handoff";
const HANDOFF_SERVICE_VERSION: u32 = 1;
const MAX_HANDOFF_EVENTS: usize = 4_096;

/// The handoff plugin exposes only the user-control boundary and durable,
/// redacted lifecycle records. Browser actions and navigation remain outside
/// this contract.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserHandoffCapability {
    HumanTakeover,
    AgentResume,
    DurableLog,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserHandoffServiceDefinition {
    pub schema_version: u32,
    pub service_id: String,
    pub version: u32,
    pub provider_id: String,
    pub capabilities: BTreeSet<BrowserHandoffCapability>,
    pub service_digest: String,
}

impl BrowserHandoffServiceDefinition {
    pub fn authenticated(provider_id: impl Into<String>) -> Result<Self, BrowserError> {
        let definition = Self {
            schema_version: HANDOFF_SCHEMA_VERSION,
            service_id: HANDOFF_SERVICE_ID.to_owned(),
            version: HANDOFF_SERVICE_VERSION,
            provider_id: provider_id.into(),
            capabilities: BTreeSet::from([
                BrowserHandoffCapability::HumanTakeover,
                BrowserHandoffCapability::AgentResume,
                BrowserHandoffCapability::DurableLog,
            ]),
            service_digest: String::new(),
        };
        let service_digest = definition.unsigned_digest()?;
        let definition = Self {
            service_digest,
            ..definition
        };
        definition.validate()?;
        Ok(definition)
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != HANDOFF_SCHEMA_VERSION
            || self.service_id != HANDOFF_SERVICE_ID
            || self.version != HANDOFF_SERVICE_VERSION
            || !is_bounded_identifier(&self.provider_id)
            || self.capabilities
                != BTreeSet::from([
                    BrowserHandoffCapability::HumanTakeover,
                    BrowserHandoffCapability::AgentResume,
                    BrowserHandoffCapability::DurableLog,
                ])
            || !is_sha256(&self.service_digest)
            || self.service_digest != self.unsigned_digest()?
        {
            return Err(BrowserError::InvalidHandoffOffer);
        }
        Ok(())
    }

    pub fn supports(&self, capability: BrowserHandoffCapability) -> bool {
        self.capabilities.contains(&capability)
    }

    fn unsigned_digest(&self) -> Result<String, BrowserError> {
        digest_json(&(
            self.schema_version,
            &self.service_id,
            self.version,
            &self.provider_id,
            &self.capabilities,
        ))
    }
}

impl fmt::Debug for BrowserHandoffServiceDefinition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserHandoffServiceDefinition")
            .field("schema_version", &self.schema_version)
            .field("service_id", &self.service_id)
            .field("version", &self.version)
            .field("provider_id", &self.provider_id)
            .field("capabilities", &self.capabilities)
            .field("service_digest", &self.service_digest)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserHandoffScope {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub profile_id: BrowserProfileId,
    pub workspace_id: BrowserWorkspaceId,
    pub identity_digest: String,
}

impl BrowserHandoffScope {
    pub(crate) fn bind(
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
    ) -> Result<Self, BrowserError> {
        profile.validate()?;
        workspace.validate()?;
        if profile.source != BrowserProfileSource::Managed
            || profile.status != BrowserProfileStatus::Active
            || profile.tenant_id != workspace.tenant_id
            || profile.project_id != workspace.project_id
            || profile.id != workspace.profile_id
            || profile.identity.identity_digest != workspace.expected_identity_digest
        {
            return Err(BrowserError::ScopeMismatch);
        }
        let scope = Self {
            tenant_id: workspace.tenant_id.clone(),
            project_id: workspace.project_id.clone(),
            mission_id: workspace.mission_id.clone(),
            profile_id: profile.id.clone(),
            workspace_id: workspace.id.clone(),
            identity_digest: profile.identity.identity_digest.clone(),
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        if !is_bounded_identifier(self.tenant_id.as_str())
            || !is_bounded_identifier(self.project_id.as_str())
            || !is_bounded_identifier(self.mission_id.as_str())
            || !is_bounded_identifier(self.profile_id.as_str())
            || !is_bounded_identifier(self.workspace_id.as_str())
            || !is_sha256(&self.identity_digest)
        {
            return Err(BrowserError::InvalidHandoffOffer);
        }
        Ok(())
    }
}

impl fmt::Debug for BrowserHandoffScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserHandoffScope")
            .field("tenant_id", &self.tenant_id)
            .field("project_id", &self.project_id)
            .field("mission_id", &self.mission_id)
            .field("profile_id", &self.profile_id)
            .field("workspace_id", &self.workspace_id)
            .field("identity_digest", &self.identity_digest)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserHandoffFrameBinding {
    pub tab_id: BrowserTabId,
    pub frame_id_digest: String,
    pub loader_id_digest: String,
    pub url_digest: String,
    pub navigation_revision: u64,
}

impl BrowserHandoffFrameBinding {
    pub(crate) fn from_verified(
        tab_id: BrowserTabId,
        frame_id: &str,
        loader_id: &str,
        url: &str,
        navigation_revision: u64,
    ) -> Result<Self, BrowserError> {
        let binding = Self {
            tab_id,
            frame_id_digest: digest(frame_id.as_bytes()),
            loader_id_digest: digest(loader_id.as_bytes()),
            url_digest: digest(url.as_bytes()),
            navigation_revision,
        };
        binding.validate()?;
        Ok(binding)
    }

    #[cfg(test)]
    fn from_test_values(
        tab_id: BrowserTabId,
        frame_id: &str,
        loader_id: &str,
        url: &str,
        navigation_revision: u64,
    ) -> Result<Self, BrowserError> {
        Self::from_verified(tab_id, frame_id, loader_id, url, navigation_revision)
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        if !is_bounded_identifier(self.tab_id.as_str())
            || !is_sha256(&self.frame_id_digest)
            || !is_sha256(&self.loader_id_digest)
            || !is_sha256(&self.url_digest)
            || self.navigation_revision == 0
        {
            return Err(BrowserError::InvalidHandoffOffer);
        }
        Ok(())
    }
}

impl fmt::Debug for BrowserHandoffFrameBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserHandoffFrameBinding")
            .field("tab_id", &self.tab_id)
            .field("frame_id_digest", &self.frame_id_digest)
            .field("loader_id_digest", &self.loader_id_digest)
            .field("url_digest", &self.url_digest)
            .field("navigation_revision", &self.navigation_revision)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserHandoffSnapshot {
    pub schema_version: u32,
    pub snapshot_id: BrowserSnapshotId,
    pub scope: BrowserHandoffScope,
    pub frame: BrowserHandoffFrameBinding,
    pub profile_revision: u64,
    pub workspace_revision: u64,
    pub lease_generation: u64,
    pub control_state: BrowserControlState,
    pub observed_at: DateTime<Utc>,
    pub snapshot_digest: String,
}

pub(crate) struct BrowserHandoffSnapshotInput {
    pub snapshot_id: BrowserSnapshotId,
    pub scope: BrowserHandoffScope,
    pub frame: BrowserHandoffFrameBinding,
    pub profile_revision: u64,
    pub workspace_revision: u64,
    pub lease_generation: u64,
    pub control_state: BrowserControlState,
    pub observed_at: DateTime<Utc>,
}

impl BrowserHandoffSnapshot {
    pub(crate) fn from_verified(input: BrowserHandoffSnapshotInput) -> Result<Self, BrowserError> {
        let snapshot = Self {
            schema_version: HANDOFF_SCHEMA_VERSION,
            snapshot_id: input.snapshot_id,
            scope: input.scope,
            frame: input.frame,
            profile_revision: input.profile_revision,
            workspace_revision: input.workspace_revision,
            lease_generation: input.lease_generation,
            control_state: input.control_state,
            observed_at: input.observed_at,
            snapshot_digest: String::new(),
        };
        let snapshot_digest = snapshot.unsigned_digest()?;
        let snapshot = Self {
            snapshot_digest,
            ..snapshot
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        self.scope.validate()?;
        self.frame.validate()?;
        if self.schema_version != HANDOFF_SCHEMA_VERSION
            || self.snapshot_id.as_str().trim().is_empty()
            || self.profile_revision == 0
            || self.workspace_revision == 0
            || self.lease_generation == 0
            || !is_sha256(&self.snapshot_digest)
            || self.snapshot_digest != self.unsigned_digest()?
        {
            return Err(BrowserError::InvalidHandoffOffer);
        }
        Ok(())
    }

    fn unsigned_digest(&self) -> Result<String, BrowserError> {
        digest_json(&serde_json::json!({
            "schemaVersion": self.schema_version,
            "snapshotId": self.snapshot_id,
            "scope": self.scope,
            "frame": self.frame,
            "profileRevision": self.profile_revision,
            "workspaceRevision": self.workspace_revision,
            "leaseGeneration": self.lease_generation,
            "controlState": self.control_state,
            "observedAt": self.observed_at,
        }))
    }
}

impl fmt::Debug for BrowserHandoffSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserHandoffSnapshot")
            .field("schema_version", &self.schema_version)
            .field("snapshot_id", &self.snapshot_id)
            .field("scope", &self.scope)
            .field("frame", &self.frame)
            .field("profile_revision", &self.profile_revision)
            .field("workspace_revision", &self.workspace_revision)
            .field("lease_generation", &self.lease_generation)
            .field("control_state", &self.control_state)
            .field("observed_at", &self.observed_at)
            .field("snapshot_digest", &self.snapshot_digest)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserTakeoverOffer {
    pub schema_version: u32,
    pub offer_id: BrowserSnapshotId,
    pub provider_instance_id: String,
    pub scope: BrowserHandoffScope,
    pub snapshot_id: BrowserSnapshotId,
    pub snapshot_digest: String,
    pub frame: BrowserHandoffFrameBinding,
    pub profile_revision: u64,
    pub workspace_revision: u64,
    pub lease_generation: u64,
    pub lease: BrowserLeaseProof,
    pub issued_at: DateTime<Utc>,
    pub offer_digest: String,
}

impl BrowserTakeoverOffer {
    fn issue(
        provider_instance_id: String,
        scope: BrowserHandoffScope,
        snapshot: &BrowserHandoffSnapshot,
        lease: BrowserLeaseProof,
        issued_at: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        if snapshot.control_state != BrowserControlState::AgentControlled {
            return Err(BrowserError::ControlLeaseLost);
        }
        let offer = Self {
            schema_version: HANDOFF_SCHEMA_VERSION,
            offer_id: BrowserSnapshotId::new(),
            provider_instance_id,
            scope,
            snapshot_id: snapshot.snapshot_id.clone(),
            snapshot_digest: snapshot.snapshot_digest.clone(),
            frame: snapshot.frame.clone(),
            profile_revision: snapshot.profile_revision,
            workspace_revision: snapshot.workspace_revision,
            lease_generation: snapshot.lease_generation,
            lease,
            issued_at,
            offer_digest: String::new(),
        };
        let offer_digest = offer.unsigned_digest()?;
        let offer = Self {
            offer_digest,
            ..offer
        };
        offer.validate_shape()?;
        Ok(offer)
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        self.validate_shape()
    }

    fn validate_shape(&self) -> Result<(), BrowserError> {
        self.scope.validate()?;
        self.frame.validate()?;
        if self.schema_version != HANDOFF_SCHEMA_VERSION
            || self.offer_id.as_str().trim().is_empty()
            || !is_bounded_identifier(&self.provider_instance_id)
            || !is_sha256(&self.snapshot_digest)
            || self.lease.workspace_id != self.scope.workspace_id
            || self.lease.generation != self.lease_generation
            || self.profile_revision == 0
            || self.workspace_revision == 0
            || self.lease_generation == 0
            || !is_sha256(&self.offer_digest)
            || self.offer_digest != self.unsigned_digest()?
        {
            return Err(BrowserError::InvalidHandoffOffer);
        }
        Ok(())
    }

    fn validate_for(
        &self,
        provider_instance_id: &str,
        scope: &BrowserHandoffScope,
        workspace: &BrowserWorkspace,
        profile: &BrowserProfile,
        snapshot: &BrowserHandoffSnapshot,
        active_offer: Option<&BrowserTakeoverOffer>,
    ) -> Result<(), BrowserError> {
        self.validate_shape()?;
        let expected_scope = BrowserHandoffScope::bind(profile, workspace)?;
        if provider_instance_id != self.provider_instance_id
            || scope != &expected_scope
            || self.scope != expected_scope
            || workspace.control_state != BrowserControlState::AgentControlled
            || self.frame != snapshot.frame
            || self.profile_revision != profile.revision
            || self.workspace_revision != workspace.revision
            || self.lease_generation != workspace.lease_generation
            || self.lease != workspace.agent_lease_proof(snapshot.observed_at)?
            || snapshot.control_state != BrowserControlState::AgentControlled
            || snapshot.observed_at < self.issued_at
            || active_offer != Some(self)
        {
            return Err(BrowserError::StaleSnapshot);
        }
        Ok(())
    }

    fn unsigned_digest(&self) -> Result<String, BrowserError> {
        digest_json(&serde_json::json!({
            "schemaVersion": self.schema_version,
            "offerId": self.offer_id,
            "providerInstanceId": self.provider_instance_id,
            "scope": self.scope,
            "snapshotId": self.snapshot_id,
            "snapshotDigest": self.snapshot_digest,
            "frame": self.frame,
            "profileRevision": self.profile_revision,
            "workspaceRevision": self.workspace_revision,
            "leaseGeneration": self.lease_generation,
            "lease": self.lease,
            "issuedAt": self.issued_at,
        }))
    }
}

impl fmt::Debug for BrowserTakeoverOffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserTakeoverOffer")
            .field("schema_version", &self.schema_version)
            .field("offer_id", &self.offer_id)
            .field("provider_instance_id", &self.provider_instance_id)
            .field("scope", &self.scope)
            .field("snapshot_id", &self.snapshot_id)
            .field("snapshot_digest", &self.snapshot_digest)
            .field("frame", &self.frame)
            .field("profile_revision", &self.profile_revision)
            .field("workspace_revision", &self.workspace_revision)
            .field("lease_generation", &self.lease_generation)
            .field("issued_at", &self.issued_at)
            .field("offer_digest", &self.offer_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserTakeoverReceipt {
    pub schema_version: u32,
    pub receipt_id: BrowserSnapshotId,
    pub offer_id: BrowserSnapshotId,
    pub provider_instance_id: String,
    pub scope: BrowserHandoffScope,
    pub pre_snapshot_digest: String,
    pub frame: BrowserHandoffFrameBinding,
    pub profile_revision: u64,
    pub workspace_revision: u64,
    pub from_generation: u64,
    pub to_generation: u64,
    pub evidence_digest: String,
    pub issued_at: DateTime<Utc>,
    pub receipt_digest: String,
}

impl BrowserTakeoverReceipt {
    fn issue(
        offer: &BrowserTakeoverOffer,
        next_workspace: &BrowserWorkspace,
        evidence_digest: String,
        issued_at: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        let receipt = Self {
            schema_version: HANDOFF_SCHEMA_VERSION,
            receipt_id: BrowserSnapshotId::new(),
            offer_id: offer.offer_id.clone(),
            provider_instance_id: offer.provider_instance_id.clone(),
            scope: offer.scope.clone(),
            pre_snapshot_digest: offer.snapshot_digest.clone(),
            frame: offer.frame.clone(),
            profile_revision: offer.profile_revision,
            workspace_revision: offer.workspace_revision,
            from_generation: offer.lease_generation,
            to_generation: next_workspace.lease_generation,
            evidence_digest,
            issued_at,
            receipt_digest: String::new(),
        };
        let receipt_digest = receipt.unsigned_digest()?;
        let receipt = Self {
            receipt_digest,
            ..receipt
        };
        receipt.validate_shape()?;
        Ok(receipt)
    }

    fn validate_shape(&self) -> Result<(), BrowserError> {
        self.scope.validate()?;
        self.frame.validate()?;
        if self.schema_version != HANDOFF_SCHEMA_VERSION
            || self.receipt_id.as_str().trim().is_empty()
            || self.offer_id.as_str().trim().is_empty()
            || !is_bounded_identifier(&self.provider_instance_id)
            || !is_sha256(&self.pre_snapshot_digest)
            || self.profile_revision == 0
            || self.workspace_revision == 0
            || self.from_generation == 0
            || self.to_generation != self.from_generation.saturating_add(1)
            || !is_sha256(&self.evidence_digest)
            || !is_sha256(&self.receipt_digest)
            || self.receipt_digest != self.unsigned_digest()?
        {
            return Err(BrowserError::InvalidHandoffReceipt);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        self.validate_shape()
    }

    fn unsigned_digest(&self) -> Result<String, BrowserError> {
        digest_json(&serde_json::json!({
            "schemaVersion": self.schema_version,
            "receiptId": self.receipt_id,
            "offerId": self.offer_id,
            "providerInstanceId": self.provider_instance_id,
            "scope": self.scope,
            "preSnapshotDigest": self.pre_snapshot_digest,
            "frame": self.frame,
            "profileRevision": self.profile_revision,
            "workspaceRevision": self.workspace_revision,
            "fromGeneration": self.from_generation,
            "toGeneration": self.to_generation,
            "evidenceDigest": self.evidence_digest,
            "issuedAt": self.issued_at,
        }))
    }
}

impl fmt::Debug for BrowserTakeoverReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserTakeoverReceipt")
            .field("schema_version", &self.schema_version)
            .field("receipt_id", &self.receipt_id)
            .field("offer_id", &self.offer_id)
            .field("provider_instance_id", &self.provider_instance_id)
            .field("scope", &self.scope)
            .field("pre_snapshot_digest", &self.pre_snapshot_digest)
            .field("frame", &self.frame)
            .field("profile_revision", &self.profile_revision)
            .field("workspace_revision", &self.workspace_revision)
            .field("from_generation", &self.from_generation)
            .field("to_generation", &self.to_generation)
            .field("evidence_digest", &self.evidence_digest)
            .field("issued_at", &self.issued_at)
            .field("receipt_digest", &self.receipt_digest)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserResumeReceipt {
    pub schema_version: u32,
    pub receipt_id: BrowserSnapshotId,
    pub takeover_receipt_id: BrowserSnapshotId,
    pub offer_id: BrowserSnapshotId,
    pub provider_instance_id: String,
    pub scope: BrowserHandoffScope,
    pub snapshot_id: BrowserSnapshotId,
    pub snapshot_digest: String,
    pub frame: BrowserHandoffFrameBinding,
    pub profile_revision: u64,
    pub workspace_revision: u64,
    pub lease_generation: u64,
    pub evidence_digest: String,
    pub issued_at: DateTime<Utc>,
    pub receipt_digest: String,
}

impl BrowserResumeReceipt {
    fn issue(
        takeover: &BrowserTakeoverReceipt,
        snapshot: &BrowserHandoffSnapshot,
        evidence_digest: String,
        issued_at: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        if snapshot.control_state != BrowserControlState::UserControlled
            || snapshot.frame != takeover.frame
            || snapshot.scope != takeover.scope
        {
            return Err(BrowserError::StaleSnapshot);
        }
        let receipt = Self {
            schema_version: HANDOFF_SCHEMA_VERSION,
            receipt_id: BrowserSnapshotId::new(),
            takeover_receipt_id: takeover.receipt_id.clone(),
            offer_id: takeover.offer_id.clone(),
            provider_instance_id: takeover.provider_instance_id.clone(),
            scope: takeover.scope.clone(),
            snapshot_id: snapshot.snapshot_id.clone(),
            snapshot_digest: snapshot.snapshot_digest.clone(),
            frame: snapshot.frame.clone(),
            profile_revision: snapshot.profile_revision,
            workspace_revision: snapshot.workspace_revision,
            lease_generation: snapshot.lease_generation,
            evidence_digest,
            issued_at,
            receipt_digest: String::new(),
        };
        let receipt_digest = receipt.unsigned_digest()?;
        let receipt = Self {
            receipt_digest,
            ..receipt
        };
        receipt.validate_shape()?;
        Ok(receipt)
    }

    fn validate_shape(&self) -> Result<(), BrowserError> {
        self.scope.validate()?;
        self.frame.validate()?;
        if self.schema_version != HANDOFF_SCHEMA_VERSION
            || self.receipt_id.as_str().trim().is_empty()
            || self.takeover_receipt_id.as_str().trim().is_empty()
            || self.offer_id.as_str().trim().is_empty()
            || !is_bounded_identifier(&self.provider_instance_id)
            || self.snapshot_id.as_str().trim().is_empty()
            || !is_sha256(&self.snapshot_digest)
            || self.profile_revision == 0
            || self.workspace_revision == 0
            || self.lease_generation == 0
            || !is_sha256(&self.evidence_digest)
            || !is_sha256(&self.receipt_digest)
            || self.receipt_digest != self.unsigned_digest()?
        {
            return Err(BrowserError::InvalidHandoffReceipt);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        self.validate_shape()
    }

    fn unsigned_digest(&self) -> Result<String, BrowserError> {
        digest_json(&serde_json::json!({
            "schemaVersion": self.schema_version,
            "receiptId": self.receipt_id,
            "takeoverReceiptId": self.takeover_receipt_id,
            "offerId": self.offer_id,
            "providerInstanceId": self.provider_instance_id,
            "scope": self.scope,
            "snapshotId": self.snapshot_id,
            "snapshotDigest": self.snapshot_digest,
            "frame": self.frame,
            "profileRevision": self.profile_revision,
            "workspaceRevision": self.workspace_revision,
            "leaseGeneration": self.lease_generation,
            "evidenceDigest": self.evidence_digest,
            "issuedAt": self.issued_at,
        }))
    }
}

impl fmt::Debug for BrowserResumeReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserResumeReceipt")
            .field("schema_version", &self.schema_version)
            .field("receipt_id", &self.receipt_id)
            .field("takeover_receipt_id", &self.takeover_receipt_id)
            .field("offer_id", &self.offer_id)
            .field("provider_instance_id", &self.provider_instance_id)
            .field("scope", &self.scope)
            .field("snapshot_id", &self.snapshot_id)
            .field("snapshot_digest", &self.snapshot_digest)
            .field("frame", &self.frame)
            .field("profile_revision", &self.profile_revision)
            .field("workspace_revision", &self.workspace_revision)
            .field("lease_generation", &self.lease_generation)
            .field("evidence_digest", &self.evidence_digest)
            .field("issued_at", &self.issued_at)
            .field("receipt_digest", &self.receipt_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "receipt")]
pub enum BrowserHandoffEvent {
    Takeover(BrowserTakeoverReceipt),
    Resume(BrowserResumeReceipt),
}

impl BrowserHandoffEvent {
    fn validate_for(
        &self,
        scope: &BrowserHandoffScope,
        provider_instance_id: &str,
    ) -> Result<&BrowserSnapshotId, BrowserError> {
        match self {
            Self::Takeover(receipt) => {
                receipt.validate_shape()?;
                if &receipt.scope != scope || receipt.provider_instance_id != provider_instance_id {
                    return Err(BrowserError::InvalidHandoffReceipt);
                }
                Ok(&receipt.receipt_id)
            }
            Self::Resume(receipt) => {
                receipt.validate_shape()?;
                if &receipt.scope != scope || receipt.provider_instance_id != provider_instance_id {
                    return Err(BrowserError::InvalidHandoffReceipt);
                }
                Ok(&receipt.receipt_id)
            }
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserHandoffLog {
    pub schema_version: u32,
    pub scope: BrowserHandoffScope,
    pub provider_instance_id: String,
    pub events: Vec<BrowserHandoffEvent>,
    pub log_digest: String,
}

impl BrowserHandoffLog {
    fn new(scope: BrowserHandoffScope, provider_instance_id: String) -> Result<Self, BrowserError> {
        scope.validate()?;
        if !is_bounded_identifier(&provider_instance_id) {
            return Err(BrowserError::InvalidHandoffOffer);
        }
        let log = Self {
            schema_version: HANDOFF_SCHEMA_VERSION,
            scope,
            provider_instance_id,
            events: Vec::new(),
            log_digest: String::new(),
        };
        let log_digest = log.unsigned_digest()?;
        Ok(Self { log_digest, ..log })
    }

    fn append(&mut self, event: BrowserHandoffEvent) -> Result<(), BrowserError> {
        if self.events.len() >= MAX_HANDOFF_EVENTS {
            return Err(BrowserError::CounterOverflow);
        }
        let event_id = event.validate_for(&self.scope, &self.provider_instance_id)?;
        if self
            .events
            .iter()
            .map(|existing| match existing {
                BrowserHandoffEvent::Takeover(receipt) => &receipt.receipt_id,
                BrowserHandoffEvent::Resume(receipt) => &receipt.receipt_id,
            })
            .any(|existing| existing == event_id)
        {
            return Err(BrowserError::InvalidHandoffReceipt);
        }
        let mut events = self.events.clone();
        events.push(event.clone());
        validate_event_sequence(&events)?;
        self.events.push(event);
        self.log_digest = self.unsigned_digest()?;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        self.scope.validate()?;
        if self.schema_version != HANDOFF_SCHEMA_VERSION
            || !is_bounded_identifier(&self.provider_instance_id)
            || self.events.len() > MAX_HANDOFF_EVENTS
            || self.log_digest != self.unsigned_digest()?
        {
            return Err(BrowserError::InvalidHandoffReceipt);
        }
        let mut ids = HashSet::new();
        for event in &self.events {
            let id = event.validate_for(&self.scope, &self.provider_instance_id)?;
            if !ids.insert(id.clone()) {
                return Err(BrowserError::InvalidHandoffReceipt);
            }
        }
        validate_event_sequence(&self.events)?;
        Ok(())
    }

    pub fn digest(&self) -> Result<String, BrowserError> {
        self.validate()?;
        Ok(self.log_digest.clone())
    }

    fn unsigned_digest(&self) -> Result<String, BrowserError> {
        digest_json(&(
            &self.schema_version,
            &self.scope,
            &self.provider_instance_id,
            &self.events,
        ))
    }
}

fn validate_event_sequence(events: &[BrowserHandoffEvent]) -> Result<(), BrowserError> {
    let mut awaiting_resume = false;
    let mut last_takeover_id = None;
    for event in events {
        match event {
            BrowserHandoffEvent::Takeover(receipt) => {
                if awaiting_resume {
                    return Err(BrowserError::InvalidHandoffReceipt);
                }
                awaiting_resume = true;
                last_takeover_id = Some(&receipt.receipt_id);
            }
            BrowserHandoffEvent::Resume(receipt) => {
                if !awaiting_resume || last_takeover_id != Some(&receipt.takeover_receipt_id) {
                    return Err(BrowserError::InvalidHandoffReceipt);
                }
                awaiting_resume = false;
            }
        }
    }
    Ok(())
}

impl fmt::Debug for BrowserHandoffLog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserHandoffLog")
            .field("schema_version", &self.schema_version)
            .field("scope", &self.scope)
            .field("provider_instance_id", &self.provider_instance_id)
            .field("event_count", &self.events.len())
            .field("log_digest", &self.log_digest)
            .finish()
    }
}

/// The only host authority consumed by the handoff provider: read a redacted
/// exact binding and sync the already-validated workspace control state.
pub trait BrowserHandoffHost {
    fn observe_handoff_snapshot(
        &mut self,
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        now: DateTime<Utc>,
    ) -> Result<BrowserHandoffSnapshot, BrowserError>;

    fn sync_workspace(&mut self, workspace: &BrowserWorkspace) -> Result<(), BrowserError>;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserHandoffProviderState {
    AgentMounted,
    UserTakenOver,
    AgentResumed,
    Crashed,
    Closed,
}

pub struct BrowserWorkspaceHandoffProvider {
    definition: BrowserHandoffServiceDefinition,
    profile: BrowserProfile,
    workspace: BrowserWorkspace,
    scope: BrowserHandoffScope,
    provider_instance_id: String,
    state: BrowserHandoffProviderState,
    host: Option<Box<dyn BrowserHandoffHost>>,
    active_offer: Option<BrowserTakeoverOffer>,
    takeover_receipt: Option<BrowserTakeoverReceipt>,
    pending_resume_receipt: Option<BrowserResumeReceipt>,
    last_snapshot: Option<BrowserHandoffSnapshot>,
}

impl fmt::Debug for BrowserWorkspaceHandoffProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserWorkspaceHandoffProvider")
            .field("definition", &self.definition)
            .field("profile", &self.profile)
            .field("workspace", &self.workspace)
            .field("scope", &self.scope)
            .field("provider_instance_id", &self.provider_instance_id)
            .field("state", &self.state)
            .field("active_offer", &self.active_offer)
            .field("takeover_receipt", &self.takeover_receipt)
            .field("pending_resume_receipt", &self.pending_resume_receipt)
            .field("last_snapshot", &self.last_snapshot)
            .finish_non_exhaustive()
    }
}

impl BrowserWorkspaceHandoffProvider {
    pub fn mount(
        definition: BrowserHandoffServiceDefinition,
        profile: BrowserProfile,
        workspace: BrowserWorkspace,
        mut host: Box<dyn BrowserHandoffHost>,
        now: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        definition.validate()?;
        let scope = BrowserHandoffScope::bind(&profile, &workspace)?;
        workspace.agent_lease_proof(now)?;
        let snapshot = host.observe_handoff_snapshot(&profile, &workspace, now)?;
        validate_agent_snapshot(&scope, &profile, &workspace, &snapshot)?;
        let provider_instance_id = BrowserSnapshotId::new().to_string();
        Ok(Self {
            definition,
            profile,
            workspace,
            scope,
            provider_instance_id,
            state: BrowserHandoffProviderState::AgentMounted,
            host: Some(host),
            active_offer: None,
            takeover_receipt: None,
            pending_resume_receipt: None,
            last_snapshot: Some(snapshot),
        })
    }

    pub fn state(&self) -> BrowserHandoffProviderState {
        self.state
    }

    pub fn scope(&self) -> &BrowserHandoffScope {
        &self.scope
    }

    pub fn workspace(&self) -> &BrowserWorkspace {
        &self.workspace
    }

    pub fn profile(&self) -> &BrowserProfile {
        &self.profile
    }

    pub fn provider_instance_id(&self) -> &str {
        &self.provider_instance_id
    }

    pub fn agent_lease_proof(&self, now: DateTime<Utc>) -> Result<BrowserLeaseProof, BrowserError> {
        self.require_agent(now)?;
        self.workspace.agent_lease_proof(now)
    }

    pub fn request_takeover_offer(
        &mut self,
        now: DateTime<Utc>,
    ) -> Result<BrowserTakeoverOffer, BrowserError> {
        self.require_agent(now)?;
        let snapshot = self.observe_current_snapshot(now)?;
        validate_agent_snapshot(&self.scope, &self.profile, &self.workspace, &snapshot)?;
        let lease = self.workspace.agent_lease_proof(now)?;
        let offer = BrowserTakeoverOffer::issue(
            self.provider_instance_id.clone(),
            self.scope.clone(),
            &snapshot,
            lease,
            now,
        )?;
        self.active_offer = Some(offer.clone());
        Ok(offer)
    }

    /// The dispatch boundary is intentionally tiny. A proof issued before
    /// takeover becomes unusable as soon as the workspace leaves
    /// `AgentControlled`.
    pub fn authorize_agent_dispatch(
        &self,
        proof: &BrowserLeaseProof,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.require_agent(now)?;
        self.workspace.validate_agent_lease(proof, now)
    }

    pub fn takeover(
        &mut self,
        offer: &BrowserTakeoverOffer,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<BrowserTakeoverReceipt, BrowserError> {
        self.require_agent(now)?;
        let snapshot = self.observe_current_snapshot(now)?;
        offer.validate_for(
            &self.provider_instance_id,
            &self.scope,
            &self.workspace,
            &self.profile,
            &snapshot,
            self.active_offer.as_ref(),
        )?;
        let mut next = self.workspace.clone();
        next.user_takeover(
            self.workspace.revision,
            self.workspace.lease_generation,
            BrowserControlLeaseId::new(),
            evidence_digest.clone(),
            now,
        )?;
        let sync_result = self
            .host
            .as_mut()
            .ok_or(BrowserError::HandoffHostUnavailable)?
            .sync_workspace(&next);
        self.workspace = next;
        self.active_offer = None;
        self.pending_resume_receipt = None;
        self.last_snapshot = Some(snapshot);
        self.invalidate_host_if_failed(sync_result, now)?;
        self.state = BrowserHandoffProviderState::UserTakenOver;
        let receipt = BrowserTakeoverReceipt::issue(offer, &self.workspace, evidence_digest, now)?;
        self.takeover_receipt = Some(receipt.clone());
        Ok(receipt)
    }

    pub fn prepare_resume_receipt(
        &mut self,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<BrowserResumeReceipt, BrowserError> {
        if self.state != BrowserHandoffProviderState::UserTakenOver {
            return Err(BrowserError::InvalidHandoffReceipt);
        }
        let takeover = self
            .takeover_receipt
            .as_ref()
            .ok_or(BrowserError::InvalidHandoffReceipt)?
            .clone();
        let snapshot = self.observe_current_snapshot(now)?;
        validate_user_snapshot(&self.scope, &self.profile, &self.workspace, &snapshot)?;
        if snapshot.frame != takeover.frame
            || snapshot.observed_at < takeover.issued_at
            || snapshot.snapshot_digest == takeover.pre_snapshot_digest
        {
            return Err(BrowserError::StaleSnapshot);
        }
        let receipt = BrowserResumeReceipt::issue(&takeover, &snapshot, evidence_digest, now)?;
        self.pending_resume_receipt = Some(receipt.clone());
        Ok(receipt)
    }

    pub fn resume_agent(
        &mut self,
        receipt: &BrowserResumeReceipt,
        lease_expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        if self.state != BrowserHandoffProviderState::UserTakenOver {
            return Err(BrowserError::InvalidHandoffReceipt);
        }
        receipt.validate_shape()?;
        let takeover = self
            .takeover_receipt
            .as_ref()
            .ok_or(BrowserError::InvalidHandoffReceipt)?;
        if receipt.takeover_receipt_id != takeover.receipt_id
            || receipt.offer_id != takeover.offer_id
            || receipt.provider_instance_id != self.provider_instance_id
            || receipt.scope != self.scope
            || receipt.frame != takeover.frame
            || receipt.profile_revision != self.profile.revision
            || receipt.workspace_revision != self.workspace.revision
            || receipt.lease_generation != self.workspace.lease_generation
            || self.pending_resume_receipt.as_ref() != Some(receipt)
        {
            return Err(BrowserError::InvalidHandoffReceipt);
        }
        let snapshot = self.observe_current_snapshot(now)?;
        validate_user_snapshot(&self.scope, &self.profile, &self.workspace, &snapshot)?;
        if snapshot.frame != receipt.frame
            || snapshot.profile_revision != receipt.profile_revision
            || snapshot.workspace_revision != receipt.workspace_revision
            || snapshot.lease_generation != receipt.lease_generation
            || snapshot.observed_at < receipt.issued_at
        {
            return Err(BrowserError::StaleSnapshot);
        }
        let mut next = self.workspace.clone();
        next.continue_agent(
            self.workspace.revision,
            self.workspace.lease_generation,
            BrowserControlLeaseId::new(),
            lease_expires_at,
            receipt.evidence_digest.clone(),
            now,
        )?;
        let sync_result = self
            .host
            .as_mut()
            .ok_or(BrowserError::HandoffHostUnavailable)?
            .sync_workspace(&next);
        self.workspace = next;
        self.pending_resume_receipt = None;
        self.last_snapshot = Some(snapshot);
        self.invalidate_host_if_failed(sync_result, now)?;
        self.state = BrowserHandoffProviderState::AgentResumed;
        Ok(())
    }

    pub fn mark_host_crashed(
        &mut self,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        if matches!(
            self.state,
            BrowserHandoffProviderState::Crashed | BrowserHandoffProviderState::Closed
        ) {
            return Err(BrowserError::InvalidControlTransition);
        }
        if matches!(
            self.workspace.control_state,
            BrowserControlState::AgentControlled | BrowserControlState::UserControlled
        ) {
            self.workspace.pause(
                self.workspace.revision,
                self.workspace.lease_generation,
                BrowserControlLeaseId::new(),
                evidence_digest,
                now,
            )?;
        }
        self.host = None;
        self.active_offer = None;
        self.pending_resume_receipt = None;
        self.state = BrowserHandoffProviderState::Crashed;
        Ok(())
    }

    pub fn close(
        &mut self,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        if matches!(
            self.state,
            BrowserHandoffProviderState::Crashed | BrowserHandoffProviderState::Closed
        ) {
            return Err(BrowserError::InvalidControlTransition);
        }
        if matches!(
            self.workspace.control_state,
            BrowserControlState::AgentControlled | BrowserControlState::UserControlled
        ) {
            let mut next = self.workspace.clone();
            next.pause(
                self.workspace.revision,
                self.workspace.lease_generation,
                BrowserControlLeaseId::new(),
                evidence_digest,
                now,
            )?;
            let sync_result = self
                .host
                .as_mut()
                .ok_or(BrowserError::HandoffHostUnavailable)?
                .sync_workspace(&next);
            self.workspace = next;
            self.invalidate_host_if_failed(sync_result, now)?;
        }
        self.host = None;
        self.active_offer = None;
        self.pending_resume_receipt = None;
        self.state = BrowserHandoffProviderState::Closed;
        Ok(())
    }

    fn require_agent(&self, now: DateTime<Utc>) -> Result<(), BrowserError> {
        if !matches!(
            self.state,
            BrowserHandoffProviderState::AgentMounted | BrowserHandoffProviderState::AgentResumed
        ) {
            return Err(BrowserError::ControlLeaseLost);
        }
        self.workspace.validate_agent_lease(
            &BrowserLeaseProof {
                workspace_id: self.workspace.id.clone(),
                lease_id: self.workspace.lease_id.clone(),
                generation: self.workspace.lease_generation,
            },
            now,
        )
    }

    fn observe_current_snapshot(
        &mut self,
        now: DateTime<Utc>,
    ) -> Result<BrowserHandoffSnapshot, BrowserError> {
        let snapshot = self
            .host
            .as_mut()
            .ok_or(BrowserError::HandoffHostUnavailable)?
            .observe_handoff_snapshot(&self.profile, &self.workspace, now)
            .map_err(|error| self.fail_closed_host(error, now))?;
        snapshot.validate()?;
        self.last_snapshot = Some(snapshot.clone());
        Ok(snapshot)
    }

    fn invalidate_host_if_failed(
        &mut self,
        result: Result<(), BrowserError>,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        if let Err(error) = result {
            return Err(self.fail_closed_host(error, now));
        }
        Ok(())
    }

    fn fail_closed_host(&mut self, error: BrowserError, now: DateTime<Utc>) -> BrowserError {
        let evidence_digest = digest(error.code().as_bytes());
        if matches!(
            self.workspace.control_state,
            BrowserControlState::AgentControlled | BrowserControlState::UserControlled
        ) {
            let _ = self.workspace.pause(
                self.workspace.revision,
                self.workspace.lease_generation,
                BrowserControlLeaseId::new(),
                evidence_digest,
                now,
            );
        }
        self.host = None;
        self.active_offer = None;
        self.pending_resume_receipt = None;
        self.state = BrowserHandoffProviderState::Crashed;
        error
    }
}

fn validate_agent_snapshot(
    scope: &BrowserHandoffScope,
    profile: &BrowserProfile,
    workspace: &BrowserWorkspace,
    snapshot: &BrowserHandoffSnapshot,
) -> Result<(), BrowserError> {
    snapshot.validate()?;
    if snapshot.scope != *scope
        || snapshot.scope != BrowserHandoffScope::bind(profile, workspace)?
        || snapshot.profile_revision != profile.revision
        || snapshot.workspace_revision != workspace.revision
        || snapshot.lease_generation != workspace.lease_generation
        || snapshot.control_state != BrowserControlState::AgentControlled
    {
        return Err(BrowserError::StaleSnapshot);
    }
    Ok(())
}

fn validate_user_snapshot(
    scope: &BrowserHandoffScope,
    profile: &BrowserProfile,
    workspace: &BrowserWorkspace,
    snapshot: &BrowserHandoffSnapshot,
) -> Result<(), BrowserError> {
    snapshot.validate()?;
    if snapshot.scope != *scope
        || snapshot.scope != BrowserHandoffScope::bind(profile, workspace)?
        || snapshot.profile_revision != profile.revision
        || snapshot.workspace_revision != workspace.revision
        || snapshot.lease_generation != workspace.lease_generation
        || snapshot.control_state != BrowserControlState::UserControlled
    {
        return Err(BrowserError::StaleSnapshot);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserHandoffConsumerState {
    Unselected,
    Selected,
    AgentMounted,
    UserTakenOver,
    AgentResumed,
    Crashed,
    Closed,
}

pub struct MissionBrowserHandoffConsumer {
    tenant_id: TenantId,
    project_id: ProjectId,
    mission_id: MissionId,
    selected_profile: Option<BrowserProfile>,
    selected_workspace: Option<BrowserWorkspace>,
    provider: Option<BrowserWorkspaceHandoffProvider>,
    log: Option<BrowserHandoffLog>,
    state: BrowserHandoffConsumerState,
}

impl fmt::Debug for MissionBrowserHandoffConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionBrowserHandoffConsumer")
            .field("tenant_id", &self.tenant_id)
            .field("project_id", &self.project_id)
            .field("mission_id", &self.mission_id)
            .field("selected_profile", &self.selected_profile)
            .field("selected_workspace", &self.selected_workspace)
            .field("provider", &self.provider)
            .field("log", &self.log)
            .field("state", &self.state)
            .finish()
    }
}

impl MissionBrowserHandoffConsumer {
    pub fn new(mission: &Mission) -> Result<Self, BrowserError> {
        if !is_bounded_identifier(mission.tenant_id.as_str())
            || !is_bounded_identifier(mission.project_id.as_str())
            || !is_bounded_identifier(mission.id.as_str())
        {
            return Err(BrowserError::ScopeMismatch);
        }
        Ok(Self {
            tenant_id: mission.tenant_id.clone(),
            project_id: mission.project_id.clone(),
            mission_id: mission.id.clone(),
            selected_profile: None,
            selected_workspace: None,
            provider: None,
            log: None,
            state: BrowserHandoffConsumerState::Unselected,
        })
    }

    pub fn state(&self) -> BrowserHandoffConsumerState {
        self.state
    }

    pub fn selected_workspace(&self) -> Option<&BrowserWorkspace> {
        self.selected_workspace.as_ref()
    }

    pub fn provider(&self) -> Option<&BrowserWorkspaceHandoffProvider> {
        self.provider.as_ref()
    }

    pub fn log(&self) -> Option<&BrowserHandoffLog> {
        self.log.as_ref()
    }

    pub fn select_profile(
        &mut self,
        profile: BrowserProfile,
        workspace: BrowserWorkspace,
    ) -> Result<(), BrowserError> {
        if self.provider.is_some() {
            return Err(BrowserError::InvalidControlTransition);
        }
        if profile.tenant_id != self.tenant_id
            || profile.project_id != self.project_id
            || workspace.mission_id != self.mission_id
            || profile.id != workspace.profile_id
            || profile.tenant_id != workspace.tenant_id
            || profile.project_id != workspace.project_id
        {
            return Err(BrowserError::ScopeMismatch);
        }
        BrowserHandoffScope::bind(&profile, &workspace)?;
        self.selected_profile = Some(profile);
        self.selected_workspace = Some(workspace);
        self.log = None;
        self.state = BrowserHandoffConsumerState::Selected;
        Ok(())
    }

    pub fn mount(
        &mut self,
        definition: BrowserHandoffServiceDefinition,
        host: Box<dyn BrowserHandoffHost>,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        if self.provider.is_some()
            || !matches!(
                self.state,
                BrowserHandoffConsumerState::Selected | BrowserHandoffConsumerState::Closed
            )
        {
            return Err(BrowserError::InvalidControlTransition);
        }
        let profile = self
            .selected_profile
            .clone()
            .ok_or(BrowserError::ScopeMismatch)?;
        let workspace = self
            .selected_workspace
            .clone()
            .ok_or(BrowserError::ScopeMismatch)?;
        let provider =
            BrowserWorkspaceHandoffProvider::mount(definition, profile, workspace, host, now)?;
        self.log = Some(BrowserHandoffLog::new(
            provider.scope().clone(),
            provider.provider_instance_id().to_owned(),
        )?);
        self.provider = Some(provider);
        self.state = BrowserHandoffConsumerState::AgentMounted;
        Ok(())
    }

    pub fn request_takeover_offer(
        &mut self,
        now: DateTime<Utc>,
    ) -> Result<BrowserTakeoverOffer, BrowserError> {
        let result = self
            .provider
            .as_mut()
            .ok_or(BrowserError::ControlLeaseLost)
            .and_then(|provider| provider.request_takeover_offer(now));
        self.propagate_provider_crash();
        result
    }

    pub fn authorize_agent_dispatch(
        &self,
        proof: &BrowserLeaseProof,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.provider
            .as_ref()
            .ok_or(BrowserError::ControlLeaseLost)?
            .authorize_agent_dispatch(proof, now)
    }

    pub fn takeover(
        &mut self,
        offer: &BrowserTakeoverOffer,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<BrowserTakeoverReceipt, BrowserError> {
        let result = self
            .provider
            .as_mut()
            .ok_or(BrowserError::ControlLeaseLost)
            .and_then(|provider| provider.takeover(offer, evidence_digest, now));
        let receipt = match result {
            Ok(receipt) => receipt,
            Err(error) => {
                self.propagate_provider_crash();
                return Err(error);
            }
        };
        self.log
            .as_mut()
            .ok_or(BrowserError::InvalidHandoffReceipt)?
            .append(BrowserHandoffEvent::Takeover(receipt.clone()))?;
        self.sync_workspace_from_provider()?;
        self.state = BrowserHandoffConsumerState::UserTakenOver;
        Ok(receipt)
    }

    pub fn prepare_resume_receipt(
        &mut self,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<BrowserResumeReceipt, BrowserError> {
        let result = self
            .provider
            .as_mut()
            .ok_or(BrowserError::ControlLeaseLost)
            .and_then(|provider| provider.prepare_resume_receipt(evidence_digest, now));
        self.propagate_provider_crash();
        result
    }

    pub fn resume_agent(
        &mut self,
        receipt: &BrowserResumeReceipt,
        lease_expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        let result = self
            .provider
            .as_mut()
            .ok_or(BrowserError::ControlLeaseLost)
            .and_then(|provider| provider.resume_agent(receipt, lease_expires_at, now));
        if let Err(error) = result {
            self.propagate_provider_crash();
            return Err(error);
        }
        self.log
            .as_mut()
            .ok_or(BrowserError::InvalidHandoffReceipt)?
            .append(BrowserHandoffEvent::Resume(receipt.clone()))?;
        self.sync_workspace_from_provider()?;
        self.state = BrowserHandoffConsumerState::AgentResumed;
        Ok(())
    }

    pub fn mark_host_crashed(
        &mut self,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        let result = self
            .provider
            .as_mut()
            .ok_or(BrowserError::ControlLeaseLost)
            .and_then(|provider| provider.mark_host_crashed(evidence_digest, now));
        if let Err(error) = result {
            self.propagate_provider_crash();
            return Err(error);
        }
        self.sync_workspace_from_provider()?;
        self.provider = None;
        self.state = BrowserHandoffConsumerState::Crashed;
        Ok(())
    }

    pub fn close(
        &mut self,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        let result = self
            .provider
            .as_mut()
            .ok_or(BrowserError::ControlLeaseLost)
            .and_then(|provider| provider.close(evidence_digest, now));
        if let Err(error) = result {
            self.propagate_provider_crash();
            return Err(error);
        }
        self.sync_workspace_from_provider()?;
        self.provider = None;
        self.state = BrowserHandoffConsumerState::Closed;
        Ok(())
    }

    fn sync_workspace_from_provider(&mut self) -> Result<(), BrowserError> {
        self.selected_workspace = Some(
            self.provider
                .as_ref()
                .ok_or(BrowserError::ControlLeaseLost)?
                .workspace()
                .clone(),
        );
        Ok(())
    }

    fn propagate_provider_crash(&mut self) {
        if self
            .provider
            .as_ref()
            .is_some_and(|provider| provider.state() == BrowserHandoffProviderState::Crashed)
        {
            if let Some(provider) = self.provider.as_ref() {
                self.selected_workspace = Some(provider.workspace().clone());
            }
            self.provider = None;
            self.state = BrowserHandoffConsumerState::Crashed;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        AccountId, BrowserWorkspaceId, MissionContract, Project, StorageMode,
    };
    use std::cell::RefCell;
    use std::rc::Rc;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 9, 0, 0)
            .single()
            .expect("fixture time")
    }

    fn sha(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn fixture() -> (
        Mission,
        BrowserProfile,
        BrowserWorkspace,
        BrowserHandoffServiceDefinition,
    ) {
        let current = now();
        let project = Project::create_local(
            TenantId::from("tenant-handoff"),
            ProjectId::from("project-handoff"),
            "Handoff",
            "",
            "/workspace/handoff",
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mission = Mission::compile(
            project.tenant_id.clone(),
            MissionId::from("mission-handoff"),
            project.id.clone(),
            "Handoff mission",
            MissionContract::bootstrap("handoff", ["browser.read".into()], current),
            current,
        )
        .expect("mission");
        let profile = BrowserProfile::create_managed(
            BrowserProfileId::from("profile-handoff"),
            &project,
            "credential-manager://handoff-profile",
            crate::BrowserIdentity::new(
                "provider-handoff",
                AccountId::from("account-handoff"),
                sha('1'),
                sha('2'),
                current,
            )
            .expect("identity"),
            current,
        )
        .expect("profile");
        let workspace = BrowserWorkspace::create(
            BrowserWorkspaceId::from("workspace-handoff"),
            &project,
            &mission,
            &profile,
            BrowserTabId::from("tab-handoff"),
            BrowserControlLeaseId::from("lease-handoff-1"),
            current + Duration::hours(1),
            sha('3'),
            current,
        )
        .expect("workspace");
        let definition =
            BrowserHandoffServiceDefinition::authenticated("handoff-provider").expect("definition");
        (mission, profile, workspace, definition)
    }

    #[derive(Clone)]
    struct FakeBrowserHandoffHost {
        profile: BrowserProfile,
        workspace: BrowserWorkspace,
        frame_id: String,
        loader_id: String,
        url: String,
        snapshot_counter: u64,
        detached: bool,
        crashed: bool,
    }

    impl FakeBrowserHandoffHost {
        fn new(profile: BrowserProfile, workspace: BrowserWorkspace) -> Self {
            Self {
                profile,
                workspace,
                frame_id: "root-frame-1".into(),
                loader_id: "loader-1".into(),
                url: "https://example.test/germany".into(),
                snapshot_counter: 0,
                detached: false,
                crashed: false,
            }
        }

        fn drift_frame(&mut self) {
            self.frame_id = "root-frame-drift".into();
        }

        fn drift_loader(&mut self) {
            self.loader_id = "loader-drift".into();
        }

        fn detach(&mut self) {
            self.detached = true;
        }
    }

    impl BrowserHandoffHost for FakeBrowserHandoffHost {
        fn observe_handoff_snapshot(
            &mut self,
            profile: &BrowserProfile,
            workspace: &BrowserWorkspace,
            observed_at: DateTime<Utc>,
        ) -> Result<BrowserHandoffSnapshot, BrowserError> {
            if self.detached {
                return Err(BrowserError::TabNotFound);
            }
            if self.crashed {
                return Err(BrowserError::HostExited);
            }
            if profile.id != self.profile.id
                || profile.revision != self.profile.revision
                || workspace.id != self.workspace.id
                || workspace.revision != self.workspace.revision
                || workspace.lease_generation != self.workspace.lease_generation
            {
                return Err(BrowserError::ScopeMismatch);
            }
            self.snapshot_counter = self.snapshot_counter.saturating_add(1);
            let scope = BrowserHandoffScope::bind(profile, workspace)?;
            let frame = BrowserHandoffFrameBinding::from_test_values(
                workspace.active_tab_id.clone(),
                &self.frame_id,
                &self.loader_id,
                &self.url,
                1,
            )?;
            BrowserHandoffSnapshot::from_verified(BrowserHandoffSnapshotInput {
                snapshot_id: BrowserSnapshotId::from_stable(format!(
                    "handoff-snapshot-{}",
                    self.snapshot_counter
                )),
                scope,
                frame,
                profile_revision: profile.revision,
                workspace_revision: workspace.revision,
                lease_generation: workspace.lease_generation,
                control_state: workspace.control_state,
                observed_at,
            })
        }

        fn sync_workspace(&mut self, workspace: &BrowserWorkspace) -> Result<(), BrowserError> {
            if self.detached || self.crashed {
                return Err(BrowserError::HostExited);
            }
            if !workspace.is_valid_successor_of(&self.workspace)?
                || workspace.profile_id != self.profile.id
            {
                return Err(BrowserError::ScopeMismatch);
            }
            self.workspace = workspace.clone();
            Ok(())
        }
    }

    #[derive(Clone)]
    struct SharedFakeBrowserHandoffHost(Rc<RefCell<FakeBrowserHandoffHost>>);

    impl BrowserHandoffHost for SharedFakeBrowserHandoffHost {
        fn observe_handoff_snapshot(
            &mut self,
            profile: &BrowserProfile,
            workspace: &BrowserWorkspace,
            observed_at: DateTime<Utc>,
        ) -> Result<BrowserHandoffSnapshot, BrowserError> {
            self.0
                .borrow_mut()
                .observe_handoff_snapshot(profile, workspace, observed_at)
        }

        fn sync_workspace(&mut self, workspace: &BrowserWorkspace) -> Result<(), BrowserError> {
            self.0.borrow_mut().sync_workspace(workspace)
        }
    }

    fn mount_fixture() -> (
        MissionBrowserHandoffConsumer,
        BrowserWorkspace,
        DateTime<Utc>,
    ) {
        let (mission, profile, workspace, definition) = fixture();
        let mut consumer = MissionBrowserHandoffConsumer::new(&mission).expect("consumer");
        consumer
            .select_profile(profile.clone(), workspace.clone())
            .expect("select");
        consumer
            .mount(
                definition,
                Box::new(FakeBrowserHandoffHost::new(profile, workspace.clone())),
                now() + Duration::seconds(1),
            )
            .expect("mount");
        (consumer, workspace, now() + Duration::seconds(1))
    }

    #[test]
    fn takeover_pauses_old_dispatch_and_logs_redacted_receipt() {
        let (mut consumer, workspace, at) = mount_fixture();
        let old_proof = workspace.agent_lease_proof(at).expect("old proof");
        let offer = consumer
            .request_takeover_offer(at + Duration::seconds(1))
            .expect("offer");
        let serialized = serde_json::to_string(&offer).expect("offer json");
        assert!(!serialized.contains("credential"));
        assert!(!serialized.contains("cookie"));
        let receipt = consumer
            .takeover(&offer, sha('4'), at + Duration::seconds(2))
            .expect("takeover");
        assert_eq!(consumer.state(), BrowserHandoffConsumerState::UserTakenOver);
        assert_eq!(receipt.from_generation + 1, receipt.to_generation);
        assert!(matches!(
            consumer
                .authorize_agent_dispatch(&old_proof, at + Duration::seconds(3))
                .expect_err("old agent proof must be cancelled"),
            BrowserError::ControlLeaseLost
        ));
        let log = consumer.log().expect("durable log");
        assert_eq!(log.events.len(), 1);
        log.validate().expect("valid log");
        consumer
            .close(sha('8'), at + Duration::seconds(4))
            .expect("close");
        assert_eq!(consumer.state(), BrowserHandoffConsumerState::Closed);
        assert_eq!(
            consumer
                .selected_workspace()
                .expect("closed workspace")
                .control_state,
            BrowserControlState::PausedUser
        );
    }

    #[test]
    fn resume_requires_fresh_snapshot_and_explicit_receipt() {
        let (mut consumer, _, at) = mount_fixture();
        let offer = consumer
            .request_takeover_offer(at + Duration::seconds(1))
            .expect("offer");
        consumer
            .takeover(&offer, sha('4'), at + Duration::seconds(2))
            .expect("takeover");
        let receipt = consumer
            .prepare_resume_receipt(sha('5'), at + Duration::seconds(3))
            .expect("fresh resume receipt");
        let mut tampered = receipt.clone();
        tampered.frame.loader_id_digest = sha('9');
        assert!(matches!(
            consumer
                .resume_agent(
                    &tampered,
                    at + Duration::hours(1),
                    at + Duration::seconds(4)
                )
                .expect_err("tampered explicit receipt"),
            BrowserError::InvalidHandoffReceipt
        ));
        consumer
            .resume_agent(&receipt, at + Duration::hours(1), at + Duration::seconds(5))
            .expect("resume");
        assert_eq!(consumer.state(), BrowserHandoffConsumerState::AgentResumed);
        assert_eq!(consumer.log().expect("log").events.len(), 2);
        assert!(
            consumer
                .provider()
                .expect("provider")
                .agent_lease_proof(at + Duration::seconds(6))
                .is_ok()
        );
    }

    #[test]
    fn frame_loader_and_scope_drift_fail_closed_without_wrong_handoff() {
        let (mission, profile, workspace, definition) = fixture();
        let shared = Rc::new(RefCell::new(FakeBrowserHandoffHost::new(
            profile.clone(),
            workspace.clone(),
        )));
        let mut frame_consumer = MissionBrowserHandoffConsumer::new(&mission).expect("consumer");
        frame_consumer
            .select_profile(profile.clone(), workspace.clone())
            .expect("select");
        frame_consumer
            .mount(
                definition.clone(),
                Box::new(SharedFakeBrowserHandoffHost(shared.clone())),
                now() + Duration::seconds(1),
            )
            .expect("mount");
        let frame_offer = frame_consumer
            .request_takeover_offer(now() + Duration::seconds(2))
            .expect("offer");
        shared.borrow_mut().drift_frame();
        assert!(matches!(
            frame_consumer
                .takeover(&frame_offer, sha('4'), now() + Duration::seconds(3))
                .expect_err("frame drift"),
            BrowserError::StaleSnapshot
        ));
        assert_eq!(
            frame_consumer.state(),
            BrowserHandoffConsumerState::AgentMounted
        );

        let shared = Rc::new(RefCell::new(FakeBrowserHandoffHost::new(
            profile.clone(),
            workspace.clone(),
        )));
        let mut loader_consumer = MissionBrowserHandoffConsumer::new(&mission).expect("consumer");
        loader_consumer
            .select_profile(profile.clone(), workspace.clone())
            .expect("select loader");
        loader_consumer
            .mount(
                definition.clone(),
                Box::new(SharedFakeBrowserHandoffHost(shared.clone())),
                now() + Duration::seconds(1),
            )
            .expect("mount loader");
        let loader_offer = loader_consumer
            .request_takeover_offer(now() + Duration::seconds(2))
            .expect("loader offer");
        loader_consumer
            .takeover(&loader_offer, sha('5'), now() + Duration::seconds(3))
            .expect("loader takeover");
        shared.borrow_mut().drift_loader();
        assert!(matches!(
            loader_consumer
                .prepare_resume_receipt(sha('6'), now() + Duration::seconds(4))
                .expect_err("loader drift"),
            BrowserError::StaleSnapshot
        ));
        assert_eq!(
            loader_consumer.state(),
            BrowserHandoffConsumerState::UserTakenOver
        );

        let mut scope_consumer = MissionBrowserHandoffConsumer::new(&mission).expect("consumer");
        scope_consumer
            .select_profile(profile.clone(), workspace.clone())
            .expect("select scope");
        scope_consumer
            .mount(
                definition,
                Box::new(FakeBrowserHandoffHost::new(profile, workspace)),
                now() + Duration::seconds(1),
            )
            .expect("mount scope");
        let scope_offer = scope_consumer
            .request_takeover_offer(now() + Duration::seconds(2))
            .expect("scope offer");
        let mut wrong_scope = scope_offer.clone();
        wrong_scope.scope.mission_id = MissionId::from("mission-other");
        assert!(matches!(
            scope_consumer
                .takeover(&wrong_scope, sha('7'), now() + Duration::seconds(3))
                .expect_err("mission drift"),
            BrowserError::InvalidHandoffOffer | BrowserError::StaleSnapshot
        ));
    }

    #[test]
    fn profile_drift_crashes_provider_before_handoff() {
        let (mission, profile, workspace, definition) = fixture();
        let shared = Rc::new(RefCell::new(FakeBrowserHandoffHost::new(
            profile.clone(),
            workspace.clone(),
        )));
        let mut consumer = MissionBrowserHandoffConsumer::new(&mission).expect("consumer");
        consumer
            .select_profile(profile.clone(), workspace.clone())
            .expect("select profile");
        consumer
            .mount(
                definition,
                Box::new(SharedFakeBrowserHandoffHost(shared.clone())),
                now() + Duration::seconds(1),
            )
            .expect("mount profile");
        let offer = consumer
            .request_takeover_offer(now() + Duration::seconds(2))
            .expect("profile offer");
        shared.borrow_mut().profile.revision = 2;
        assert!(matches!(
            consumer
                .takeover(&offer, sha('8'), now() + Duration::seconds(3))
                .expect_err("profile drift"),
            BrowserError::ScopeMismatch
        ));
        assert_eq!(consumer.state(), BrowserHandoffConsumerState::Crashed);
    }

    #[test]
    fn host_detach_crash_and_reopen_fail_closed() {
        let (mission, profile, workspace, definition) = fixture();
        let mut host = FakeBrowserHandoffHost::new(profile.clone(), workspace.clone());
        host.detach();
        let mut consumer = MissionBrowserHandoffConsumer::new(&mission).expect("consumer");
        consumer
            .select_profile(profile.clone(), workspace.clone())
            .expect("select");
        assert!(matches!(
            consumer
                .mount(
                    definition.clone(),
                    Box::new(host),
                    now() + Duration::seconds(1)
                )
                .expect_err("detached host must not mount"),
            BrowserError::TabNotFound
        ));

        let (mut consumer, _workspace, at) = mount_fixture();
        let offer = consumer
            .request_takeover_offer(at + Duration::seconds(1))
            .expect("offer");
        consumer
            .mark_host_crashed(sha('6'), at + Duration::seconds(2))
            .expect("crash cancellation");
        assert_eq!(consumer.state(), BrowserHandoffConsumerState::Crashed);
        assert_eq!(
            consumer
                .selected_workspace()
                .expect("workspace")
                .control_state,
            BrowserControlState::PausedAgent
        );
        assert!(matches!(
            consumer
                .takeover(&offer, sha('7'), at + Duration::seconds(3))
                .expect_err("old offer after crash"),
            BrowserError::ControlLeaseLost
        ));
        let (mission, reopened_profile, _, definition) = fixture();
        let paused_workspace = consumer
            .selected_workspace()
            .expect("paused workspace")
            .clone();
        let mut reopened = MissionBrowserHandoffConsumer::new(&mission).expect("reopened");
        reopened
            .select_profile(reopened_profile.clone(), paused_workspace.clone())
            .expect("reselect is only scope validation");
        assert!(matches!(
            reopened
                .mount(
                    definition,
                    Box::new(FakeBrowserHandoffHost::new(
                        reopened_profile,
                        paused_workspace,
                    )),
                    at + Duration::seconds(4),
                )
                .expect_err("paused workspace cannot reopen agent authority"),
            BrowserError::ControlLeaseLost | BrowserError::ScopeMismatch
        ));
    }
}
