//! Plugin-first attribution outcome service contracts.
//!
//! This module is deliberately narrower than the generic plugin runtime: it
//! describes the service/provider/consumer binding for one attribution result
//! packet. Provider registry validation remains at the storage boundary, while
//! this module owns the immutable Project/Mission/source-evidence fences.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    AttributionLedger, MissionId, ObservationOrigin, OutcomeCandidateId, OutcomeKind, ProjectId,
    ProviderEventIdentity, SourceEventId, TenantId, VerifiedOutcome,
};

pub const ATTRIBUTION_OUTCOME_PLUGIN_SCHEMA_VERSION: &str = "hartevo-attribution-outcome-plugin/v1";
pub const ATTRIBUTION_OUTCOME_PLUGIN_CONTRACT_VERSION: &str = "attribution-outcome-plugin/v1";
pub const ATTRIBUTION_OUTCOME_SERVICE_ID: &str = "attribution.outcome.result";
pub const ATTRIBUTION_OUTCOME_SERVICE_VERSION: u32 = 1;
pub const ATTRIBUTION_OUTCOME_PLUGIN_MOUNT_EVENT_TYPE: &str =
    "attribution-outcome-plugin.mounted/v1";
pub const ATTRIBUTION_OUTCOME_PLUGIN_UNMOUNT_EVENT_TYPE: &str =
    "attribution-outcome-plugin.unmounted/v1";
pub const ATTRIBUTION_OUTCOME_PLUGIN_REVOKE_EVENT_TYPE: &str =
    "attribution-outcome-plugin.revoked/v1";
pub const ATTRIBUTION_OUTCOME_RESULT_PACKET_EVENT_TYPE: &str =
    "attribution-outcome-plugin.result-packet/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomePluginIdentity {
    pub plugin_id: String,
    pub version: u32,
    pub manifest_digest: String,
}

impl OutcomePluginIdentity {
    pub fn new(
        plugin_id: impl Into<String>,
        version: u32,
        manifest_digest: impl Into<String>,
    ) -> Result<Self, AttributionOutcomePluginError> {
        let identity = Self {
            plugin_id: plugin_id.into(),
            version,
            manifest_digest: manifest_digest.into(),
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<(), AttributionOutcomePluginError> {
        if !valid_identifier(&self.plugin_id)
            || self.version == 0
            || !is_sha256(&self.manifest_digest)
        {
            return Err(AttributionOutcomePluginError::InvalidPluginIdentity);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomePluginScope {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub mission_revision: u64,
}

impl OutcomePluginScope {
    pub fn validate(&self) -> Result<(), AttributionOutcomePluginError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.mission_revision == 0
        {
            return Err(AttributionOutcomePluginError::InvalidPluginScope);
        }
        Ok(())
    }
}

/// The service definition is content-addressed independently of any provider
/// registration. The registry binding is supplied by storage when a provider
/// is mounted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeServiceDefinition {
    pub service_id: String,
    pub contract_version: String,
    pub service_version: u32,
    pub definition_digest: String,
}

impl OutcomeServiceDefinition {
    pub fn attribution_result() -> Self {
        let mut service = Self {
            service_id: ATTRIBUTION_OUTCOME_SERVICE_ID.into(),
            contract_version: ATTRIBUTION_OUTCOME_PLUGIN_CONTRACT_VERSION.into(),
            service_version: ATTRIBUTION_OUTCOME_SERVICE_VERSION,
            definition_digest: String::new(),
        };
        service.definition_digest = service
            .content_digest()
            .expect("static attribution outcome service definition");
        service
    }

    pub fn validate(&self) -> Result<(), AttributionOutcomePluginError> {
        if !valid_identifier(&self.service_id)
            || self.contract_version != ATTRIBUTION_OUTCOME_PLUGIN_CONTRACT_VERSION
            || self.service_version == 0
            || self.definition_digest != self.content_digest()?
        {
            return Err(AttributionOutcomePluginError::InvalidServiceDefinition);
        }
        Ok(())
    }

    fn content_digest(&self) -> Result<String, AttributionOutcomePluginError> {
        canonical_digest(&(
            &self.service_id,
            &self.contract_version,
            self.service_version,
        ))
    }
}

/// Provider metadata is deliberately registry-shaped, but not a second
/// provider registry. Storage matches these fields against the existing
/// `ProviderAdapterRegistry` before persisting a mount.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeServiceProvider {
    pub provider_id: String,
    pub capability_id: String,
    pub adapter_id: String,
    pub adapter_version: u32,
    pub registry_version: String,
    pub registry_digest: String,
}

impl OutcomeServiceProvider {
    pub fn validate(&self) -> Result<(), AttributionOutcomePluginError> {
        if !valid_identifier(&self.provider_id)
            || !valid_identifier(&self.capability_id)
            || !valid_identifier(&self.adapter_id)
            || self.adapter_version == 0
            || !valid_registry_version(&self.registry_version)
            || !is_sha256(&self.registry_digest)
        {
            return Err(AttributionOutcomePluginError::InvalidServiceProvider);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeMissionConsumer {
    pub consumer_id: String,
    pub service_id: String,
    pub provider_id: String,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub mission_revision: u64,
}

impl OutcomeMissionConsumer {
    pub fn validate(
        &self,
        scope: &OutcomePluginScope,
        service: &OutcomeServiceDefinition,
        provider: &OutcomeServiceProvider,
    ) -> Result<(), AttributionOutcomePluginError> {
        if !valid_identifier(&self.consumer_id)
            || self.service_id != service.service_id
            || self.provider_id != provider.provider_id
            || self.project_id != scope.project_id
            || self.mission_id != scope.mission_id
            || self.mission_revision != scope.mission_revision
        {
            return Err(AttributionOutcomePluginError::InvalidMissionConsumer);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomePluginMount {
    pub mount_id: String,
    pub identity: OutcomePluginIdentity,
    pub scope: OutcomePluginScope,
    pub service: OutcomeServiceDefinition,
    pub provider: OutcomeServiceProvider,
    pub consumer: OutcomeMissionConsumer,
    pub generation: u64,
    pub mounted_at: DateTime<Utc>,
    pub mount_digest: String,
}

impl OutcomePluginMount {
    pub fn new(
        identity: OutcomePluginIdentity,
        scope: OutcomePluginScope,
        service: OutcomeServiceDefinition,
        provider: OutcomeServiceProvider,
        consumer: OutcomeMissionConsumer,
        generation: u64,
        mounted_at: DateTime<Utc>,
    ) -> Result<Self, AttributionOutcomePluginError> {
        let mut mount = Self {
            mount_id: String::new(),
            identity,
            scope,
            service,
            provider,
            consumer,
            generation,
            mounted_at,
            mount_digest: String::new(),
        };
        mount.mount_digest = mount.content_digest()?;
        mount.mount_id = format!("mount:{}", mount.mount_digest);
        mount.validate()?;
        Ok(mount)
    }

    pub fn validate(&self) -> Result<(), AttributionOutcomePluginError> {
        if self.mount_id != format!("mount:{}", self.mount_digest)
            || self.generation == 0
            || self.mount_digest != self.content_digest()?
        {
            return Err(AttributionOutcomePluginError::InvalidMount);
        }
        self.identity.validate()?;
        self.scope.validate()?;
        self.service.validate()?;
        self.provider.validate()?;
        self.consumer
            .validate(&self.scope, &self.service, &self.provider)?;
        Ok(())
    }

    fn content_digest(&self) -> Result<String, AttributionOutcomePluginError> {
        canonical_digest(&(
            ATTRIBUTION_OUTCOME_PLUGIN_SCHEMA_VERSION,
            &self.identity,
            &self.scope,
            &self.service,
            &self.provider,
            &self.consumer,
            self.generation,
            self.mounted_at,
        ))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomePluginMountState {
    Active,
    Unmounted,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomePluginMountReceipt {
    pub mount_id: String,
    pub plugin_id: String,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub mission_revision: u64,
    pub generation: u64,
    pub mount_digest: String,
    pub service_id: String,
    pub provider_id: String,
    pub registry_version: String,
    pub registry_digest: String,
    pub receipt_digest: String,
}

impl OutcomePluginMountReceipt {
    pub fn from_mount(mount: &OutcomePluginMount) -> Result<Self, AttributionOutcomePluginError> {
        mount.validate()?;
        let mut receipt = Self {
            mount_id: mount.mount_id.clone(),
            plugin_id: mount.identity.plugin_id.clone(),
            project_id: mount.scope.project_id.clone(),
            mission_id: mount.scope.mission_id.clone(),
            mission_revision: mount.scope.mission_revision,
            generation: mount.generation,
            mount_digest: mount.mount_digest.clone(),
            service_id: mount.service.service_id.clone(),
            provider_id: mount.provider.provider_id.clone(),
            registry_version: mount.provider.registry_version.clone(),
            registry_digest: mount.provider.registry_digest.clone(),
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.content_digest()?;
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), AttributionOutcomePluginError> {
        if !self.mount_id.starts_with("mount:")
            || !valid_identifier(&self.plugin_id)
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.mission_revision == 0
            || self.generation == 0
            || !is_sha256(&self.mount_digest)
            || !valid_identifier(&self.service_id)
            || !valid_identifier(&self.provider_id)
            || !valid_registry_version(&self.registry_version)
            || !is_sha256(&self.registry_digest)
            || self.receipt_digest != self.content_digest()?
        {
            return Err(AttributionOutcomePluginError::InvalidMountReceipt);
        }
        Ok(())
    }

    fn content_digest(&self) -> Result<String, AttributionOutcomePluginError> {
        canonical_digest(&(
            ATTRIBUTION_OUTCOME_PLUGIN_SCHEMA_VERSION,
            &self.mount_id,
            &self.plugin_id,
            &self.project_id,
            &self.mission_id,
            self.mission_revision,
            self.generation,
            &self.mount_digest,
            &self.service_id,
            &self.provider_id,
            &self.registry_version,
            &self.registry_digest,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomePluginMountRecord {
    pub mount: OutcomePluginMount,
    pub receipt: OutcomePluginMountReceipt,
    pub state: OutcomePluginMountState,
    pub changed_at: DateTime<Utc>,
    pub reason_digest: Option<String>,
}

impl OutcomePluginMountRecord {
    pub fn active(
        mount: OutcomePluginMount,
        receipt: OutcomePluginMountReceipt,
    ) -> Result<Self, AttributionOutcomePluginError> {
        let record = Self {
            changed_at: mount.mounted_at,
            mount,
            receipt,
            state: OutcomePluginMountState::Active,
            reason_digest: None,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn transition(
        &self,
        state: OutcomePluginMountState,
        changed_at: DateTime<Utc>,
        reason_digest: Option<String>,
    ) -> Result<Self, AttributionOutcomePluginError> {
        if changed_at < self.changed_at {
            return Err(AttributionOutcomePluginError::InvalidMountRecord);
        }
        let record = Self {
            mount: self.mount.clone(),
            receipt: self.receipt.clone(),
            state,
            changed_at,
            reason_digest,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), AttributionOutcomePluginError> {
        self.mount.validate()?;
        self.receipt.validate()?;
        if self.receipt.mount_id != self.mount.mount_id
            || self.receipt.mount_digest != self.mount.mount_digest
            || self.receipt.plugin_id != self.mount.identity.plugin_id
            || self.receipt.project_id != self.mount.scope.project_id
            || self.receipt.mission_id != self.mount.scope.mission_id
            || self.receipt.mission_revision != self.mount.scope.mission_revision
            || self.receipt.generation != self.mount.generation
            || self.changed_at < self.mount.mounted_at
            || (self.state == OutcomePluginMountState::Active && self.reason_digest.is_some())
            || (self.state != OutcomePluginMountState::Active && self.reason_digest.is_none())
            || self
                .reason_digest
                .as_ref()
                .is_some_and(|digest| !is_sha256(digest))
        {
            return Err(AttributionOutcomePluginError::InvalidMountRecord);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeResultStatus {
    Candidate,
    Verified,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeResultReadiness {
    RequiresIndependentVerification,
    AdoptableVerified,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeResultPacket {
    pub packet_id: String,
    pub plugin_id: String,
    pub plugin_version: u32,
    pub plugin_manifest_digest: String,
    pub mount_id: String,
    pub service_id: String,
    pub provider_id: String,
    pub provider_registry_version: String,
    pub provider_registry_digest: String,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub mission_revision: u64,
    pub source_ledger_revision: u64,
    pub source_event_id: SourceEventId,
    pub candidate_id: OutcomeCandidateId,
    pub provider_event_identity: ProviderEventIdentity,
    pub outcome_kind: OutcomeKind,
    pub amount: crate::Money,
    pub source_event_digest: String,
    pub source_request_digest: String,
    pub source_origin: ObservationOrigin,
    pub status: OutcomeResultStatus,
    pub readiness: OutcomeResultReadiness,
    pub verified_outcome: Option<VerifiedOutcome>,
    pub packet_digest: String,
}

impl OutcomeResultPacket {
    pub fn from_ledger(
        ledger: &AttributionLedger,
        mount: &OutcomePluginMount,
        candidate_id: &OutcomeCandidateId,
    ) -> Result<Self, AttributionOutcomePluginError> {
        mount.validate()?;
        ledger
            .validate()
            .map_err(|error| AttributionOutcomePluginError::Ledger(error.to_string()))?;
        let candidate = ledger
            .candidates
            .iter()
            .find(|candidate| candidate.id == *candidate_id)
            .ok_or(AttributionOutcomePluginError::CandidateNotFound)?;
        let source = ledger
            .events
            .iter()
            .find(|event| event.id == candidate.source_event_id)
            .ok_or(AttributionOutcomePluginError::SourceEventNotFound)?;
        if source.tenant_id != mount.scope.tenant_id
            || source.project_id != mount.scope.project_id
            || source.mission_id.as_ref() != Some(&mount.scope.mission_id)
            || source.identity.provider != mount.provider.provider_id
            || candidate.provider != mount.provider.provider_id
        {
            return Err(AttributionOutcomePluginError::SourceScopeMismatch);
        }
        let verified_outcome = ledger
            .verified_outcomes
            .iter()
            .find(|outcome| outcome.candidate_id == *candidate_id)
            .cloned();
        let (status, readiness) = match verified_outcome.as_ref() {
            Some(_) => {
                if source.provenance.origin == ObservationOrigin::Estimate {
                    return Err(AttributionOutcomePluginError::EstimateCannotBeVerified);
                }
                (
                    OutcomeResultStatus::Verified,
                    OutcomeResultReadiness::AdoptableVerified,
                )
            }
            None => (
                OutcomeResultStatus::Candidate,
                OutcomeResultReadiness::RequiresIndependentVerification,
            ),
        };
        let packet_id = format!(
            "outcome-result:{}:{}:{}",
            mount.mount_id, candidate.id, ledger.revision
        );
        let mut packet = Self {
            packet_id,
            plugin_id: mount.identity.plugin_id.clone(),
            plugin_version: mount.identity.version,
            plugin_manifest_digest: mount.identity.manifest_digest.clone(),
            mount_id: mount.mount_id.clone(),
            service_id: mount.service.service_id.clone(),
            provider_id: mount.provider.provider_id.clone(),
            provider_registry_version: mount.provider.registry_version.clone(),
            provider_registry_digest: mount.provider.registry_digest.clone(),
            tenant_id: mount.scope.tenant_id.clone(),
            project_id: mount.scope.project_id.clone(),
            mission_id: mount.scope.mission_id.clone(),
            mission_revision: mount.scope.mission_revision,
            source_ledger_revision: ledger.revision,
            source_event_id: source.id.clone(),
            candidate_id: candidate.id.clone(),
            provider_event_identity: source.identity.clone(),
            outcome_kind: candidate.kind,
            amount: candidate.amount.clone(),
            source_event_digest: candidate.source_event_digest.clone(),
            source_request_digest: source.provenance.request_digest.clone(),
            source_origin: source.provenance.origin,
            status,
            readiness,
            verified_outcome,
            packet_digest: String::new(),
        };
        packet.packet_digest = packet.content_digest()?;
        packet.validate_against(ledger, mount)?;
        Ok(packet)
    }

    pub fn validate(&self) -> Result<(), AttributionOutcomePluginError> {
        if self.packet_id.trim().is_empty()
            || !valid_identifier(&self.plugin_id)
            || self.plugin_version == 0
            || !is_sha256(&self.plugin_manifest_digest)
            || !self.mount_id.starts_with("mount:")
            || !valid_identifier(&self.service_id)
            || !valid_identifier(&self.provider_id)
            || !valid_registry_version(&self.provider_registry_version)
            || !is_sha256(&self.provider_registry_digest)
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.mission_revision == 0
            || self.source_ledger_revision == 0
            || self.source_event_id.as_str().trim().is_empty()
            || self.candidate_id.as_str().trim().is_empty()
            || self.provider_event_identity.provider != self.provider_id
            || self.outcome_kind == OutcomeKind::Conversion && !self.amount.is_positive()
            || !is_sha256(&self.source_event_digest)
            || !is_sha256(&self.source_request_digest)
            || self.verified_outcome.is_some() != (self.status == OutcomeResultStatus::Verified)
            || (self.status == OutcomeResultStatus::Verified
                && self.readiness != OutcomeResultReadiness::AdoptableVerified)
            || (self.status == OutcomeResultStatus::Candidate
                && self.readiness != OutcomeResultReadiness::RequiresIndependentVerification)
            || self.packet_digest != self.content_digest()?
        {
            return Err(AttributionOutcomePluginError::InvalidResultPacket);
        }
        if let Some(verified) = &self.verified_outcome
            && (verified.candidate_id != self.candidate_id
                || verified.source_event_id != self.source_event_id
                || verified.candidate_digest != self.source_event_digest)
        {
            return Err(AttributionOutcomePluginError::InvalidResultPacket);
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        ledger: &AttributionLedger,
        mount: &OutcomePluginMount,
    ) -> Result<(), AttributionOutcomePluginError> {
        self.validate_against_revision(ledger, mount, true)
    }

    /// Validates a packet while replaying a later ledger revision. The packet
    /// keeps its own exact source revision; replay only requires that revision
    /// to be no newer than the durable ledger and preserves historical
    /// candidate packets after a later independent verification.
    pub fn validate_for_replay(
        &self,
        ledger: &AttributionLedger,
        mount: &OutcomePluginMount,
    ) -> Result<(), AttributionOutcomePluginError> {
        self.validate_against_revision(ledger, mount, false)
    }

    fn validate_against_revision(
        &self,
        ledger: &AttributionLedger,
        mount: &OutcomePluginMount,
        exact_revision: bool,
    ) -> Result<(), AttributionOutcomePluginError> {
        self.validate()?;
        mount.validate()?;
        if self.plugin_id != mount.identity.plugin_id
            || self.plugin_version != mount.identity.version
            || self.plugin_manifest_digest != mount.identity.manifest_digest
            || self.mount_id != mount.mount_id
            || self.service_id != mount.service.service_id
            || self.provider_id != mount.provider.provider_id
            || self.provider_registry_version != mount.provider.registry_version
            || self.provider_registry_digest != mount.provider.registry_digest
            || self.tenant_id != mount.scope.tenant_id
            || self.project_id != mount.scope.project_id
            || self.mission_id != mount.scope.mission_id
            || self.mission_revision != mount.scope.mission_revision
            || (exact_revision && self.source_ledger_revision != ledger.revision)
            || (!exact_revision && self.source_ledger_revision > ledger.revision)
        {
            return Err(AttributionOutcomePluginError::BindingMismatch);
        }
        let candidate = ledger
            .candidates
            .iter()
            .find(|candidate| candidate.id == self.candidate_id)
            .ok_or(AttributionOutcomePluginError::CandidateNotFound)?;
        let source = ledger
            .events
            .iter()
            .find(|event| event.id == self.source_event_id)
            .ok_or(AttributionOutcomePluginError::SourceEventNotFound)?;
        if candidate.source_event_id != source.id
            || candidate.kind != self.outcome_kind
            || candidate.amount != self.amount
            || candidate.provider != self.provider_id
            || source.identity != self.provider_event_identity
            || source
                .canonical_digest()
                .map_err(|error| AttributionOutcomePluginError::Ledger(error.to_string()))?
                != self.source_event_digest
            || source.provenance.request_digest != self.source_request_digest
            || source.provenance.origin != self.source_origin
            || source.mission_id.as_ref() != Some(&self.mission_id)
        {
            return Err(AttributionOutcomePluginError::SourceScopeMismatch);
        }
        let current_verified = ledger
            .verified_outcomes
            .iter()
            .find(|outcome| outcome.candidate_id == self.candidate_id);
        match (
            self.status,
            current_verified,
            self.verified_outcome.as_ref(),
        ) {
            (OutcomeResultStatus::Candidate, _, None) => {}
            (OutcomeResultStatus::Verified, Some(current), Some(packet)) if current == packet => {
                if self.source_origin == ObservationOrigin::Estimate {
                    return Err(AttributionOutcomePluginError::EstimateCannotBeVerified);
                }
            }
            _ => return Err(AttributionOutcomePluginError::VerificationMismatch),
        }
        Ok(())
    }

    fn content_digest(&self) -> Result<String, AttributionOutcomePluginError> {
        canonical_digest(&serde_json::json!({
            "schemaVersion": ATTRIBUTION_OUTCOME_PLUGIN_SCHEMA_VERSION,
            "packetId": self.packet_id,
            "pluginId": self.plugin_id,
            "pluginVersion": self.plugin_version,
            "pluginManifestDigest": self.plugin_manifest_digest,
            "mountId": self.mount_id,
            "serviceId": self.service_id,
            "providerId": self.provider_id,
            "providerRegistryVersion": self.provider_registry_version,
            "providerRegistryDigest": self.provider_registry_digest,
            "tenantId": self.tenant_id,
            "projectId": self.project_id,
            "missionId": self.mission_id,
            "missionRevision": self.mission_revision,
            "sourceLedgerRevision": self.source_ledger_revision,
            "sourceEventId": self.source_event_id,
            "candidateId": self.candidate_id,
            "providerEventIdentity": self.provider_event_identity,
            "outcomeKind": self.outcome_kind,
            "amount": self.amount,
            "sourceEventDigest": self.source_event_digest,
            "sourceRequestDigest": self.source_request_digest,
            "sourceOrigin": self.source_origin,
            "status": self.status,
            "readiness": self.readiness,
            "verifiedOutcome": self.verified_outcome,
        }))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionOutcomePluginSnapshot {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mounts: Vec<OutcomePluginMountRecord>,
    pub packets: Vec<OutcomeResultPacket>,
    pub replay_digest: String,
}

impl AttributionOutcomePluginSnapshot {
    pub fn new(
        tenant_id: TenantId,
        project_id: ProjectId,
        mounts: Vec<OutcomePluginMountRecord>,
        packets: Vec<OutcomeResultPacket>,
    ) -> Result<Self, AttributionOutcomePluginError> {
        let mut snapshot = Self {
            schema_version: ATTRIBUTION_OUTCOME_PLUGIN_SCHEMA_VERSION.into(),
            tenant_id,
            project_id,
            mounts,
            packets,
            replay_digest: String::new(),
        };
        snapshot.replay_digest = snapshot.content_digest()?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn validate(&self) -> Result<(), AttributionOutcomePluginError> {
        if self.schema_version != ATTRIBUTION_OUTCOME_PLUGIN_SCHEMA_VERSION
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.replay_digest != self.content_digest()?
        {
            return Err(AttributionOutcomePluginError::InvalidPluginSnapshot);
        }
        let mut mount_ids = BTreeSet::new();
        for record in &self.mounts {
            record.validate()?;
            if record.mount.scope.tenant_id != self.tenant_id
                || record.mount.scope.project_id != self.project_id
                || !mount_ids.insert(record.mount.mount_id.clone())
            {
                return Err(AttributionOutcomePluginError::InvalidPluginSnapshot);
            }
        }
        let mut packet_ids = BTreeSet::new();
        for packet in &self.packets {
            packet.validate()?;
            if packet.tenant_id != self.tenant_id
                || packet.project_id != self.project_id
                || !packet_ids.insert(packet.packet_id.clone())
            {
                return Err(AttributionOutcomePluginError::InvalidPluginSnapshot);
            }
        }
        Ok(())
    }

    fn content_digest(&self) -> Result<String, AttributionOutcomePluginError> {
        canonical_digest(&(
            &self.schema_version,
            &self.tenant_id,
            &self.project_id,
            &self.mounts,
            &self.packets,
        ))
    }
}

#[derive(Debug, Error)]
pub enum AttributionOutcomePluginError {
    #[error("plugin identity is invalid")]
    InvalidPluginIdentity,
    #[error("plugin Project/Mission scope is invalid")]
    InvalidPluginScope,
    #[error("outcome service definition is invalid")]
    InvalidServiceDefinition,
    #[error("outcome service provider metadata is invalid")]
    InvalidServiceProvider,
    #[error("outcome Mission consumer binding is invalid")]
    InvalidMissionConsumer,
    #[error("outcome plugin mount is invalid")]
    InvalidMount,
    #[error("outcome plugin mount receipt is invalid")]
    InvalidMountReceipt,
    #[error("outcome plugin mount record is invalid")]
    InvalidMountRecord,
    #[error("outcome result packet is invalid")]
    InvalidResultPacket,
    #[error("outcome result packet binding differs from its mount or ledger")]
    BindingMismatch,
    #[error("outcome candidate is missing")]
    CandidateNotFound,
    #[error("outcome source event is missing")]
    SourceEventNotFound,
    #[error("outcome source event is outside the exact Project/Mission/provider scope")]
    SourceScopeMismatch,
    #[error("an estimate-origin source cannot be promoted to a verified result")]
    EstimateCannotBeVerified,
    #[error("outcome result verification differs from the durable ledger")]
    VerificationMismatch,
    #[error("attribution ledger is invalid: {0}")]
    Ledger(String),
    #[error("plugin contract serialization failed: {0}")]
    Serialization(String),
    #[error("plugin snapshot is invalid")]
    InvalidPluginSnapshot,
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, AttributionOutcomePluginError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| AttributionOutcomePluginError::Serialization(error.to_string()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn valid_identifier(value: &str) -> bool {
    if value.is_empty() || value.len() > 96 {
        return false;
    }
    value.split('.').all(|segment| {
        !segment.is_empty()
            && segment.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
            })
            && !matches!(segment.as_bytes().first(), Some(b'-' | b'_'))
            && !matches!(segment.as_bytes().last(), Some(b'-' | b'_'))
    })
}

fn valid_registry_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use proptest::prelude::*;

    use super::*;
    use crate::{
        CorrectionLineage, CurrencyCode, Money, ObservationProvenance, ProviderEntityRef,
        SourceEntityKind, SourceEvent, SourceEventKind, SourceEventLinks, VerificationMethod,
    };

    fn at(minute: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 8, 0, 0)
            .single()
            .expect("time")
            + chrono::Duration::minutes(minute)
    }

    fn mount() -> OutcomePluginMount {
        let identity = OutcomePluginIdentity::new("attribution.outcome.plugin", 1, "a".repeat(64))
            .expect("plugin");
        let scope = OutcomePluginScope {
            tenant_id: TenantId::from("tenant-1"),
            project_id: ProjectId::from("project-1"),
            mission_id: MissionId::from("mission-1"),
            mission_revision: 7,
        };
        let service = OutcomeServiceDefinition::attribution_result();
        let provider = OutcomeServiceProvider {
            provider_id: "meta".into(),
            capability_id: "marketplace.read".into(),
            adapter_id: "meta.readback".into(),
            adapter_version: 1,
            registry_version: "fixture-registry.v1".into(),
            registry_digest: "b".repeat(64),
        };
        let consumer = OutcomeMissionConsumer {
            consumer_id: "mission.outcome.consumer".into(),
            service_id: service.service_id.clone(),
            provider_id: provider.provider_id.clone(),
            project_id: scope.project_id.clone(),
            mission_id: scope.mission_id.clone(),
            mission_revision: scope.mission_revision,
        };
        OutcomePluginMount::new(identity, scope, service, provider, consumer, 1, at(1))
            .expect("mount")
    }

    fn ledger(estimate: bool, verified: bool) -> AttributionLedger {
        let tenant_id = TenantId::from("tenant-1");
        let project_id = ProjectId::from("project-1");
        let provider = "meta";
        let identity = ProviderEventIdentity::new(provider, "acct-1", "order-1").expect("identity");
        let account =
            ProviderEntityRef::new(SourceEntityKind::Account, provider, "acct-1", "acct-1")
                .expect("account");
        let mut links = SourceEventLinks::new(account).expect("links");
        links.order = Some(
            ProviderEntityRef::new(SourceEntityKind::Order, provider, "acct-1", "order-1")
                .expect("order"),
        );
        let event = SourceEvent {
            id: SourceEventId::from_stable("order-1"),
            tenant_id: tenant_id.clone(),
            project_id: project_id.clone(),
            mission_id: Some(MissionId::from("mission-1")),
            identity,
            kind: SourceEventKind::Order,
            links,
            provider_occurred_at: at(1),
            observed_at: at(2),
            ingested_at: at(3),
            amount: Some(Money::new(100, CurrencyCode::parse("USD").expect("USD"))),
            fx_quote: None,
            provenance: ObservationProvenance::new(
                if estimate {
                    ObservationOrigin::Estimate
                } else {
                    ObservationOrigin::FirstParty
                },
                "c".repeat(64),
                at(2),
            )
            .expect("provenance"),
            lineage: CorrectionLineage::original(SourceEventId::from_stable("order-1")),
            payload_digest: "d".repeat(64),
        };
        let candidate = event.outcome_candidate().expect("candidate");
        let candidate_id = candidate.id.clone();
        let mut ledger = AttributionLedger::new(
            tenant_id,
            project_id,
            CurrencyCode::parse("USD").expect("USD"),
        )
        .expect("ledger");
        ledger.ingest_event(event).expect("event");
        ledger.register_candidate(candidate).expect("candidate");
        if verified {
            let result = ledger.verify_candidate(
                &candidate_id,
                crate::OutcomeVerification {
                    method: VerificationMethod::IndependentReadback,
                    verifier: "meta-readback".into(),
                    independent: true,
                    verified_at: at(4),
                    evidence_digest: "e".repeat(64),
                },
            );
            if estimate {
                assert!(result.is_err());
            } else {
                result.expect("verification");
            }
        }
        ledger
    }

    #[test]
    fn candidate_packet_never_claims_verification_and_verified_packet_is_adoptable() {
        let mount = mount();
        let candidate_ledger = ledger(false, false);
        let candidate = candidate_ledger.candidates[0].id.clone();
        let packet = OutcomeResultPacket::from_ledger(&candidate_ledger, &mount, &candidate)
            .expect("candidate packet");
        assert_eq!(packet.status, OutcomeResultStatus::Candidate);
        assert_eq!(
            packet.readiness,
            OutcomeResultReadiness::RequiresIndependentVerification
        );
        assert!(packet.verified_outcome.is_none());

        let verified_ledger = ledger(false, true);
        let packet = OutcomeResultPacket::from_ledger(&verified_ledger, &mount, &candidate)
            .expect("verified packet");
        assert_eq!(packet.status, OutcomeResultStatus::Verified);
        assert_eq!(packet.readiness, OutcomeResultReadiness::AdoptableVerified);
        packet
            .validate_against(&verified_ledger, &mount)
            .expect("valid");
    }

    #[test]
    fn estimate_origin_cannot_be_promoted_to_verified_result() {
        let mount = mount();
        let estimated = ledger(true, false);
        let candidate = estimated.candidates[0].id.clone();
        let packet = OutcomeResultPacket::from_ledger(&estimated, &mount, &candidate)
            .expect("estimate remains a candidate");
        assert_eq!(packet.status, OutcomeResultStatus::Candidate);
        assert!(packet.verified_outcome.is_none());
    }

    proptest! {
        #[test]
        fn mount_and_receipt_digests_are_stable_for_generation(generation in 1_u64..1000) {
            let mut value = mount();
            value.generation = generation;
            value.mount_digest = value.content_digest().expect("mount digest");
            value.mount_id = format!("mount:{}", value.mount_digest);
            let receipt = OutcomePluginMountReceipt::from_mount(&value).expect("receipt");
            prop_assert_eq!(OutcomePluginMountReceipt::from_mount(&value).expect("receipt"), receipt);
            prop_assert!(value.validate().is_ok());
        }
    }

    #[test]
    fn packet_digest_tamper_and_scope_swap_fail_closed() {
        let mount = mount();
        let state = ledger(false, true);
        let candidate = state.candidates[0].id.clone();
        let mut packet =
            OutcomeResultPacket::from_ledger(&state, &mount, &candidate).expect("packet");
        packet.provider_id = "other".into();
        assert!(packet.validate().is_err());
    }
}
