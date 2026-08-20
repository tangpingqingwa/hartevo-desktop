use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::service::FigmaExportReceipt;
use crate::types::{
    FigmaDesignRegistration, FigmaEvidenceClass, FigmaFileMetadata, FigmaNodeMetadata, FigmaScope,
    FigmaTimestamp, FigmaTypeError, MissionDesignSource, NodeId, ProposalId, ProviderVersion,
    RegistrationStatus, ResultId, Sha256Digest,
};

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum MissionDesignResultError {
    #[error("Mission source does not match the bound Figma scope")]
    SourceMissionMismatch,
    #[error("Figma file metadata does not match the exact file/version scope")]
    FileScopeMismatch,
    #[error("Figma node metadata is incomplete, duplicated, or out of scope")]
    NodeScopeMismatch,
    #[error("Figma export receipts are missing, duplicated, or out of scope")]
    AmbiguousExports,
    #[error("Figma export receipt failed integrity validation")]
    ExportIntegrity,
    #[error("Figma result provider binding does not match the registration")]
    ProviderBindingMismatch,
    #[error("Figma result digest does not match its exact typed material")]
    ResultDigestMismatch,
    #[error("Figma result cannot claim native or Connected evidence")]
    NativeEvidence,
    #[error("Figma type boundary failed: {0}")]
    Type(#[from] FigmaTypeError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionDesignResult {
    result_id: ResultId,
    scope: FigmaScope,
    source: MissionDesignSource,
    file: FigmaFileMetadata,
    node_ids: BTreeSet<NodeId>,
    nodes: Vec<FigmaNodeMetadata>,
    exports: Vec<FigmaExportReceipt>,
    export_digests: BTreeSet<Sha256Digest>,
    provider_version: ProviderVersion,
    registration_digest: Sha256Digest,
    evidence_class: FigmaEvidenceClass,
    connected: bool,
    native: bool,
    result_digest: Sha256Digest,
}

impl<'de> Deserialize<'de> for MissionDesignResult {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct WireResult {
            result_id: ResultId,
            scope: FigmaScope,
            source: MissionDesignSource,
            file: FigmaFileMetadata,
            node_ids: BTreeSet<NodeId>,
            nodes: Vec<FigmaNodeMetadata>,
            exports: Vec<FigmaExportReceipt>,
            export_digests: BTreeSet<Sha256Digest>,
            provider_version: ProviderVersion,
            registration_digest: Sha256Digest,
            evidence_class: FigmaEvidenceClass,
            connected: bool,
            native: bool,
            result_digest: Sha256Digest,
        }
        let wire = WireResult::deserialize(deserializer)?;
        let result = Self {
            result_id: wire.result_id,
            scope: wire.scope,
            source: wire.source,
            file: wire.file,
            node_ids: wire.node_ids,
            nodes: wire.nodes,
            exports: wire.exports,
            export_digests: wire.export_digests,
            provider_version: wire.provider_version,
            registration_digest: wire.registration_digest,
            evidence_class: wire.evidence_class,
            connected: wire.connected,
            native: wire.native,
            result_digest: wire.result_digest,
        };
        result
            .validate_integrity()
            .map_err(serde::de::Error::custom)?;
        Ok(result)
    }
}

#[derive(Serialize)]
struct ResultDigestMaterial<'a> {
    result_id: &'a ResultId,
    scope: &'a FigmaScope,
    source: &'a MissionDesignSource,
    file: &'a FigmaFileMetadata,
    node_ids: &'a BTreeSet<NodeId>,
    nodes: &'a [FigmaNodeMetadata],
    exports: &'a [FigmaExportReceipt],
    export_digests: &'a BTreeSet<Sha256Digest>,
    provider_version: &'a ProviderVersion,
    registration_digest: &'a Sha256Digest,
    evidence_class: FigmaEvidenceClass,
    connected: bool,
    native: bool,
}

impl MissionDesignResult {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        result_id: ResultId,
        scope: FigmaScope,
        source: MissionDesignSource,
        file: FigmaFileMetadata,
        nodes: Vec<FigmaNodeMetadata>,
        exports: Vec<FigmaExportReceipt>,
        provider_version: ProviderVersion,
        registration_digest: Sha256Digest,
        evidence_class: FigmaEvidenceClass,
    ) -> Result<Self, MissionDesignResultError> {
        let node_ids = nodes
            .iter()
            .map(|node| node.node_id().clone())
            .collect::<BTreeSet<_>>();
        let export_digests = exports
            .iter()
            .map(|export| export.metadata().content_digest().clone())
            .collect::<BTreeSet<_>>();
        let result = Self {
            result_id,
            scope,
            source,
            file,
            node_ids,
            nodes,
            exports,
            export_digests,
            provider_version,
            registration_digest,
            evidence_class,
            connected: false,
            native: false,
            result_digest: Sha256Digest::from_text("uninitialized-design-result"),
        };
        result.validate_shape()?;
        let mut result = result;
        result.result_digest = result.compute_digest();
        Ok(result)
    }

    fn validate_shape(&self) -> Result<(), MissionDesignResultError> {
        if self.connected || self.native || self.source.mission_id() != self.scope.mission_id() {
            return Err(MissionDesignResultError::NativeEvidence);
        }
        self.file
            .validate_for_scope(&self.scope)
            .map_err(|_| MissionDesignResultError::FileScopeMismatch)?;
        if self.nodes.len() != self.scope.node_ids().len()
            || self.node_ids != *self.scope.node_ids()
            || self
                .nodes
                .iter()
                .any(|node| node.validate_for_scope(&self.scope).is_err())
        {
            return Err(MissionDesignResultError::NodeScopeMismatch);
        }
        if self.exports.is_empty() || self.exports.len() > self.scope.node_ids().len() {
            return Err(MissionDesignResultError::AmbiguousExports);
        }
        let mut export_keys = BTreeSet::new();
        let mut export_digests = BTreeSet::new();
        if self.exports.iter().any(|export| {
            export.validate_integrity().is_err()
                || export.metadata().file_key() != self.scope.file_key()
                || export.metadata().version_id() != self.scope.version_id()
                || !self.scope.node_ids().contains(export.metadata().node_id())
                || !export_keys.insert((
                    export.metadata().node_id().clone(),
                    export.metadata().format().clone(),
                    export.metadata().scale(),
                ))
                || !export_digests.insert(export.metadata().content_digest().clone())
                || export.evidence_class() != self.evidence_class
                || export.connected()
                || export.native()
        }) {
            return Err(MissionDesignResultError::AmbiguousExports);
        }
        if export_digests != self.export_digests {
            return Err(MissionDesignResultError::ExportIntegrity);
        }
        if self.evidence_class.is_connected() || self.evidence_class.is_native() {
            return Err(MissionDesignResultError::NativeEvidence);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Sha256Digest {
        Sha256Digest::from_serializable(&ResultDigestMaterial {
            result_id: &self.result_id,
            scope: &self.scope,
            source: &self.source,
            file: &self.file,
            node_ids: &self.node_ids,
            nodes: &self.nodes,
            exports: &self.exports,
            export_digests: &self.export_digests,
            provider_version: &self.provider_version,
            registration_digest: &self.registration_digest,
            evidence_class: self.evidence_class,
            connected: self.connected,
            native: self.native,
        })
        .expect("design result material is serializable")
    }

    pub fn validate_integrity(&self) -> Result<(), MissionDesignResultError> {
        self.validate_shape()?;
        if self.compute_digest() != self.result_digest {
            return Err(MissionDesignResultError::ResultDigestMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn result_id(&self) -> &ResultId {
        &self.result_id
    }

    #[must_use]
    pub fn scope(&self) -> &FigmaScope {
        &self.scope
    }

    #[must_use]
    pub fn source(&self) -> &MissionDesignSource {
        &self.source
    }

    #[must_use]
    pub fn file(&self) -> &FigmaFileMetadata {
        &self.file
    }

    #[must_use]
    pub fn node_ids(&self) -> &BTreeSet<NodeId> {
        &self.node_ids
    }

    #[must_use]
    pub fn nodes(&self) -> &[FigmaNodeMetadata] {
        &self.nodes
    }

    #[must_use]
    pub fn exports(&self) -> &[FigmaExportReceipt] {
        &self.exports
    }

    #[must_use]
    pub fn export_digests(&self) -> &BTreeSet<Sha256Digest> {
        &self.export_digests
    }

    #[must_use]
    pub fn provider_version(&self) -> &ProviderVersion {
        &self.provider_version
    }

    #[must_use]
    pub fn registration_digest(&self) -> &Sha256Digest {
        &self.registration_digest
    }

    #[must_use]
    pub const fn evidence_class(&self) -> FigmaEvidenceClass {
        self.evidence_class
    }

    #[must_use]
    pub const fn connected(&self) -> bool {
        self.connected
    }

    #[must_use]
    pub const fn native(&self) -> bool {
        self.native
    }

    #[must_use]
    pub fn result_digest(&self) -> &Sha256Digest {
        &self.result_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionReason {
    DesignBrief,
    UiChange,
    VisualExperiment,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdoptionRequest {
    proposal_id: ProposalId,
    result: MissionDesignResult,
    revision_fence: MissionDesignSource,
    requested_node_ids: BTreeSet<NodeId>,
    requested_export_digests: BTreeSet<Sha256Digest>,
    requested_at: FigmaTimestamp,
    reason: AdoptionReason,
}

impl<'de> Deserialize<'de> for AdoptionRequest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct WireRequest {
            proposal_id: ProposalId,
            result: MissionDesignResult,
            revision_fence: MissionDesignSource,
            requested_node_ids: BTreeSet<NodeId>,
            requested_export_digests: BTreeSet<Sha256Digest>,
            requested_at: FigmaTimestamp,
            reason: AdoptionReason,
        }
        let wire = WireRequest::deserialize(deserializer)?;
        Self::new(
            wire.proposal_id,
            wire.result,
            wire.revision_fence,
            wire.requested_node_ids,
            wire.requested_export_digests,
            wire.requested_at,
            wire.reason,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl AdoptionRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proposal_id: ProposalId,
        result: MissionDesignResult,
        revision_fence: MissionDesignSource,
        requested_node_ids: BTreeSet<NodeId>,
        requested_export_digests: BTreeSet<Sha256Digest>,
        requested_at: FigmaTimestamp,
        reason: AdoptionReason,
    ) -> Result<Self, AdoptionError> {
        if requested_node_ids.is_empty() || requested_export_digests.is_empty() {
            return Err(AdoptionError::AmbiguousSelection);
        }
        Ok(Self {
            proposal_id,
            result,
            revision_fence,
            requested_node_ids,
            requested_export_digests,
            requested_at,
            reason,
        })
    }

    pub fn for_result(
        proposal_id: ProposalId,
        result: MissionDesignResult,
        requested_at: FigmaTimestamp,
        reason: AdoptionReason,
    ) -> Result<Self, AdoptionError> {
        let revision_fence = result.source().clone();
        let requested_node_ids = result.node_ids().clone();
        let requested_export_digests = result.export_digests().clone();
        Self::new(
            proposal_id,
            result,
            revision_fence,
            requested_node_ids,
            requested_export_digests,
            requested_at,
            reason,
        )
    }

    #[must_use]
    pub fn proposal_id(&self) -> &ProposalId {
        &self.proposal_id
    }

    #[must_use]
    pub fn result(&self) -> &MissionDesignResult {
        &self.result
    }

    #[must_use]
    pub fn revision_fence(&self) -> &MissionDesignSource {
        &self.revision_fence
    }

    #[must_use]
    pub fn requested_node_ids(&self) -> &BTreeSet<NodeId> {
        &self.requested_node_ids
    }

    #[must_use]
    pub fn requested_export_digests(&self) -> &BTreeSet<Sha256Digest> {
        &self.requested_export_digests
    }

    #[must_use]
    pub fn requested_at(&self) -> &FigmaTimestamp {
        &self.requested_at
    }

    #[must_use]
    pub const fn reason(&self) -> &AdoptionReason {
        &self.reason
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    Proposed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DesignAdoptionProposal {
    proposal_id: ProposalId,
    result_id: ResultId,
    mission_id: crate::types::MissionId,
    project_id: crate::types::ProjectId,
    file_key: crate::types::FileKey,
    version_id: crate::types::VersionId,
    node_ids: BTreeSet<NodeId>,
    export_digests: BTreeSet<Sha256Digest>,
    source_result_revision: u64,
    source_result_revision_digest: Sha256Digest,
    result_digest: Sha256Digest,
    provider_version: ProviderVersion,
    registration_digest: Sha256Digest,
    scope_digest: Sha256Digest,
    evidence_class: FigmaEvidenceClass,
    status: ProposalStatus,
    requested_at: FigmaTimestamp,
    reason: AdoptionReason,
    connected: bool,
    native: bool,
    proposal_digest: Sha256Digest,
}

impl<'de> Deserialize<'de> for DesignAdoptionProposal {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct WireProposal {
            proposal_id: ProposalId,
            result_id: ResultId,
            mission_id: crate::types::MissionId,
            project_id: crate::types::ProjectId,
            file_key: crate::types::FileKey,
            version_id: crate::types::VersionId,
            node_ids: BTreeSet<NodeId>,
            export_digests: BTreeSet<Sha256Digest>,
            source_result_revision: u64,
            source_result_revision_digest: Sha256Digest,
            result_digest: Sha256Digest,
            provider_version: ProviderVersion,
            registration_digest: Sha256Digest,
            scope_digest: Sha256Digest,
            evidence_class: FigmaEvidenceClass,
            status: ProposalStatus,
            requested_at: FigmaTimestamp,
            reason: AdoptionReason,
            connected: bool,
            native: bool,
            proposal_digest: Sha256Digest,
        }
        let wire = WireProposal::deserialize(deserializer)?;
        let proposal = Self {
            proposal_id: wire.proposal_id,
            result_id: wire.result_id,
            mission_id: wire.mission_id,
            project_id: wire.project_id,
            file_key: wire.file_key,
            version_id: wire.version_id,
            node_ids: wire.node_ids,
            export_digests: wire.export_digests,
            source_result_revision: wire.source_result_revision,
            source_result_revision_digest: wire.source_result_revision_digest,
            result_digest: wire.result_digest,
            provider_version: wire.provider_version,
            registration_digest: wire.registration_digest,
            scope_digest: wire.scope_digest,
            evidence_class: wire.evidence_class,
            status: wire.status,
            requested_at: wire.requested_at,
            reason: wire.reason,
            connected: wire.connected,
            native: wire.native,
            proposal_digest: wire.proposal_digest,
        };
        proposal
            .validate_integrity()
            .map_err(serde::de::Error::custom)?;
        Ok(proposal)
    }
}

#[derive(Serialize)]
struct ProposalDigestMaterial<'a> {
    proposal_id: &'a ProposalId,
    result_id: &'a ResultId,
    mission_id: &'a crate::types::MissionId,
    project_id: &'a crate::types::ProjectId,
    file_key: &'a crate::types::FileKey,
    version_id: &'a crate::types::VersionId,
    node_ids: &'a BTreeSet<NodeId>,
    export_digests: &'a BTreeSet<Sha256Digest>,
    source_result_revision: u64,
    source_result_revision_digest: &'a Sha256Digest,
    result_digest: &'a Sha256Digest,
    provider_version: &'a ProviderVersion,
    registration_digest: &'a Sha256Digest,
    scope_digest: &'a Sha256Digest,
    evidence_class: FigmaEvidenceClass,
    status: ProposalStatus,
    requested_at: &'a FigmaTimestamp,
    reason: &'a AdoptionReason,
    connected: bool,
    native: bool,
}

impl DesignAdoptionProposal {
    fn compute_digest(&self) -> Sha256Digest {
        Sha256Digest::from_serializable(&ProposalDigestMaterial {
            proposal_id: &self.proposal_id,
            result_id: &self.result_id,
            mission_id: &self.mission_id,
            project_id: &self.project_id,
            file_key: &self.file_key,
            version_id: &self.version_id,
            node_ids: &self.node_ids,
            export_digests: &self.export_digests,
            source_result_revision: self.source_result_revision,
            source_result_revision_digest: &self.source_result_revision_digest,
            result_digest: &self.result_digest,
            provider_version: &self.provider_version,
            registration_digest: &self.registration_digest,
            scope_digest: &self.scope_digest,
            evidence_class: self.evidence_class,
            status: self.status,
            requested_at: &self.requested_at,
            reason: &self.reason,
            connected: self.connected,
            native: self.native,
        })
        .expect("proposal material is serializable")
    }

    pub fn validate_integrity(&self) -> Result<(), AdoptionError> {
        if self.connected
            || self.native
            || self.node_ids.is_empty()
            || self.export_digests.is_empty()
            || self.status != ProposalStatus::Proposed
            || self.compute_digest() != self.proposal_digest
        {
            return Err(AdoptionError::ProposalIntegrity);
        }
        Ok(())
    }

    #[must_use]
    pub fn proposal_id(&self) -> &ProposalId {
        &self.proposal_id
    }

    #[must_use]
    pub fn result_id(&self) -> &ResultId {
        &self.result_id
    }

    #[must_use]
    pub fn mission_id(&self) -> &crate::types::MissionId {
        &self.mission_id
    }

    #[must_use]
    pub fn project_id(&self) -> &crate::types::ProjectId {
        &self.project_id
    }

    #[must_use]
    pub fn file_key(&self) -> &crate::types::FileKey {
        &self.file_key
    }

    #[must_use]
    pub fn version_id(&self) -> &crate::types::VersionId {
        &self.version_id
    }

    #[must_use]
    pub fn node_ids(&self) -> &BTreeSet<NodeId> {
        &self.node_ids
    }

    #[must_use]
    pub fn export_digests(&self) -> &BTreeSet<Sha256Digest> {
        &self.export_digests
    }

    #[must_use]
    pub const fn source_result_revision(&self) -> u64 {
        self.source_result_revision
    }

    #[must_use]
    pub fn source_result_revision_digest(&self) -> &Sha256Digest {
        &self.source_result_revision_digest
    }

    #[must_use]
    pub fn result_digest(&self) -> &Sha256Digest {
        &self.result_digest
    }

    #[must_use]
    pub fn provider_version(&self) -> &ProviderVersion {
        &self.provider_version
    }

    #[must_use]
    pub fn registration_digest(&self) -> &Sha256Digest {
        &self.registration_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Sha256Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn evidence_class(&self) -> FigmaEvidenceClass {
        self.evidence_class
    }

    #[must_use]
    pub const fn status(&self) -> ProposalStatus {
        self.status
    }

    #[must_use]
    pub const fn connected(&self) -> bool {
        self.connected
    }

    #[must_use]
    pub const fn native(&self) -> bool {
        self.native
    }

    #[must_use]
    pub const fn is_adopted(&self) -> bool {
        false
    }

    #[must_use]
    pub fn proposal_digest(&self) -> &Sha256Digest {
        &self.proposal_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum AdoptionError {
    #[error("Figma registration is not active")]
    RegistrationInactive,
    #[error("Figma registration digest does not match the result")]
    RegistrationMismatch,
    #[error("Figma result scope does not match the registered scope")]
    ScopeMismatch,
    #[error("Figma result revision fence is stale or mismatched")]
    StaleRevision,
    #[error("Figma result selection is ambiguous")]
    AmbiguousSelection,
    #[error("Figma result integrity validation failed")]
    ResultIntegrity,
    #[error("Figma result evidence is BLOCKED_ENV and cannot become a proposal")]
    BlockedEnvironment,
    #[error("Figma adoption proposal integrity validation failed")]
    ProposalIntegrity,
    #[error("Figma type boundary failed: {0}")]
    Type(#[from] FigmaTypeError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionDesignResultConsumer {
    registration: FigmaDesignRegistration,
}

impl MissionDesignResultConsumer {
    pub fn new(registration: FigmaDesignRegistration) -> Result<Self, AdoptionError> {
        registration
            .validate()
            .map_err(|_| AdoptionError::RegistrationMismatch)?;
        Ok(Self { registration })
    }

    pub fn propose(
        &self,
        request: &AdoptionRequest,
    ) -> Result<DesignAdoptionProposal, AdoptionError> {
        if !self.registration.is_active() {
            return Err(AdoptionError::RegistrationInactive);
        }
        if request.result.registration_digest() != self.registration.record_digest()
            || request.result.provider_version() != self.registration.binding().provider_version()
        {
            return Err(AdoptionError::RegistrationMismatch);
        }
        if request.result.scope() != self.registration.scope() {
            return Err(AdoptionError::ScopeMismatch);
        }
        request
            .result
            .validate_integrity()
            .map_err(|_| AdoptionError::ResultIntegrity)?;
        if request.result.evidence_class() == FigmaEvidenceClass::BlockedEnv {
            return Err(AdoptionError::BlockedEnvironment);
        }
        let source = request.result.source();
        if request.revision_fence.mission_id() != source.mission_id()
            || request.revision_fence.result_revision() != source.result_revision()
            || request.revision_fence.result_revision_digest() != source.result_revision_digest()
        {
            return Err(AdoptionError::StaleRevision);
        }
        if request.requested_node_ids != *request.result.node_ids()
            || request.requested_export_digests != *request.result.export_digests()
        {
            return Err(AdoptionError::AmbiguousSelection);
        }
        let mut proposal = DesignAdoptionProposal {
            proposal_id: request.proposal_id.clone(),
            result_id: request.result.result_id().clone(),
            mission_id: request.result.scope().mission_id().clone(),
            project_id: request.result.scope().project_id().clone(),
            file_key: request.result.scope().file_key().clone(),
            version_id: request.result.scope().version_id().clone(),
            node_ids: request.result.node_ids().clone(),
            export_digests: request.result.export_digests().clone(),
            source_result_revision: source.result_revision(),
            source_result_revision_digest: source.result_revision_digest().clone(),
            result_digest: request.result.result_digest().clone(),
            provider_version: request.result.provider_version().clone(),
            registration_digest: request.result.registration_digest().clone(),
            scope_digest: request.result.scope().digest(),
            evidence_class: request.result.evidence_class(),
            status: ProposalStatus::Proposed,
            requested_at: request.requested_at.clone(),
            reason: request.reason.clone(),
            connected: false,
            native: false,
            proposal_digest: Sha256Digest::from_text("uninitialized-proposal"),
        };
        proposal.proposal_digest = proposal.compute_digest();
        Ok(proposal)
    }

    #[must_use]
    pub fn registration(&self) -> &FigmaDesignRegistration {
        &self.registration
    }

    #[must_use]
    pub const fn registration_status(&self) -> &RegistrationStatus {
        self.registration.status()
    }
}
