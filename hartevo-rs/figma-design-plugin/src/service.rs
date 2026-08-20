use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::consumer::{
    AdoptionError, AdoptionRequest, DesignAdoptionProposal, MissionDesignResult,
    MissionDesignResultConsumer, MissionDesignResultError,
};
use crate::provider::{
    FigmaDesignProvider, FigmaProviderError, FigmaProviderEvidence, FigmaTransport, PageCursor,
};
use crate::types::{
    ExportRequest, FigmaDesignRegistration, FigmaEvidenceClass, FigmaExportMetadata,
    FigmaExportPayload, FigmaFileMetadata, FigmaNodeMetadata, FigmaProviderMode, FigmaScope,
    FigmaTypeError, FigmaVersion, MAX_EXPORT_BYTES, MAX_VERSION_PAGE_SIZE, MAX_VERSION_PAGES,
    MissionDesignSource, ProviderVersion, ReceiptId, RegistrationId, Sha256Digest,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FigmaReadOperation {
    FileMetadata,
    VersionHistory,
    NodeMetadata,
    BoundedExportMetadata,
    DesignResultRecord,
    AdoptionProposal,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FigmaReceiptStatus {
    Recorded,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FigmaReadReceipt {
    receipt_id: ReceiptId,
    operation: FigmaReadOperation,
    status: FigmaReceiptStatus,
    scope_digest: Sha256Digest,
    registration_digest: Sha256Digest,
    provider_version: ProviderVersion,
    file_key: crate::types::FileKey,
    version_id: crate::types::VersionId,
    node_ids: BTreeSet<crate::types::NodeId>,
    observed_digest: Sha256Digest,
    evidence_class: FigmaEvidenceClass,
    connected: bool,
    native: bool,
    receipt_digest: Sha256Digest,
}

impl<'de> Deserialize<'de> for FigmaReadReceipt {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct WireReceipt {
            receipt_id: ReceiptId,
            operation: FigmaReadOperation,
            status: FigmaReceiptStatus,
            scope_digest: Sha256Digest,
            registration_digest: Sha256Digest,
            provider_version: ProviderVersion,
            file_key: crate::types::FileKey,
            version_id: crate::types::VersionId,
            node_ids: BTreeSet<crate::types::NodeId>,
            observed_digest: Sha256Digest,
            evidence_class: FigmaEvidenceClass,
            connected: bool,
            native: bool,
            receipt_digest: Sha256Digest,
        }
        let wire = WireReceipt::deserialize(deserializer)?;
        let receipt = Self {
            receipt_id: wire.receipt_id,
            operation: wire.operation,
            status: wire.status,
            scope_digest: wire.scope_digest,
            registration_digest: wire.registration_digest,
            provider_version: wire.provider_version,
            file_key: wire.file_key,
            version_id: wire.version_id,
            node_ids: wire.node_ids,
            observed_digest: wire.observed_digest,
            evidence_class: wire.evidence_class,
            connected: wire.connected,
            native: wire.native,
            receipt_digest: wire.receipt_digest,
        };
        receipt.validate().map_err(serde::de::Error::custom)?;
        Ok(receipt)
    }
}

#[derive(Serialize)]
struct ReadReceiptDigestMaterial<'a> {
    receipt_id: &'a ReceiptId,
    operation: FigmaReadOperation,
    status: FigmaReceiptStatus,
    scope_digest: &'a Sha256Digest,
    registration_digest: &'a Sha256Digest,
    provider_version: &'a ProviderVersion,
    file_key: &'a crate::types::FileKey,
    version_id: &'a crate::types::VersionId,
    node_ids: &'a BTreeSet<crate::types::NodeId>,
    observed_digest: &'a Sha256Digest,
    evidence_class: FigmaEvidenceClass,
    connected: bool,
    native: bool,
}

impl FigmaReadReceipt {
    fn new_success(
        operation: FigmaReadOperation,
        scope: &FigmaScope,
        evidence: &FigmaProviderEvidence,
        observed_digest: Sha256Digest,
    ) -> Self {
        let receipt_seed = Sha256Digest::from_text(&format!(
            "figma-receipt|{operation:?}|{}|{}",
            scope.digest().as_str(),
            observed_digest.as_str()
        ));
        let receipt_id = ReceiptId::new(format!("receipt-{}", &receipt_seed.as_str()[..24]))
            .expect("receipt id is bounded");
        let mut receipt = Self {
            receipt_id,
            operation,
            status: FigmaReceiptStatus::Recorded,
            scope_digest: scope.digest(),
            registration_digest: evidence.registration_digest().clone(),
            provider_version: evidence.provider_version().clone(),
            file_key: scope.file_key().clone(),
            version_id: scope.version_id().clone(),
            node_ids: scope.node_ids().clone(),
            observed_digest,
            evidence_class: evidence.evidence_class(),
            connected: false,
            native: false,
            receipt_digest: Sha256Digest::from_text("uninitialized-receipt"),
        };
        receipt.receipt_digest = receipt.compute_digest();
        receipt
    }

    fn compute_digest(&self) -> Sha256Digest {
        Sha256Digest::from_serializable(&ReadReceiptDigestMaterial {
            receipt_id: &self.receipt_id,
            operation: self.operation,
            status: self.status,
            scope_digest: &self.scope_digest,
            registration_digest: &self.registration_digest,
            provider_version: &self.provider_version,
            file_key: &self.file_key,
            version_id: &self.version_id,
            node_ids: &self.node_ids,
            observed_digest: &self.observed_digest,
            evidence_class: self.evidence_class,
            connected: self.connected,
            native: self.native,
        })
        .expect("read receipt material is serializable")
    }

    fn validate(&self) -> Result<(), FigmaServiceError> {
        if self.connected
            || self.native
            || self.node_ids.is_empty()
            || self.compute_digest() != self.receipt_digest
        {
            return Err(FigmaServiceError::ReceiptIntegrity);
        }
        Ok(())
    }

    #[must_use]
    pub fn receipt_id(&self) -> &ReceiptId {
        &self.receipt_id
    }

    #[must_use]
    pub const fn operation(&self) -> FigmaReadOperation {
        self.operation
    }

    #[must_use]
    pub const fn status(&self) -> FigmaReceiptStatus {
        self.status
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Sha256Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn registration_digest(&self) -> &Sha256Digest {
        &self.registration_digest
    }

    #[must_use]
    pub fn provider_version(&self) -> &ProviderVersion {
        &self.provider_version
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
    pub fn node_ids(&self) -> &BTreeSet<crate::types::NodeId> {
        &self.node_ids
    }

    #[must_use]
    pub fn observed_digest(&self) -> &Sha256Digest {
        &self.observed_digest
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
    pub fn receipt_digest(&self) -> &Sha256Digest {
        &self.receipt_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FigmaExportReceipt {
    metadata: FigmaExportMetadata,
    request_digest: Sha256Digest,
    response_digest: Sha256Digest,
    evidence_class: FigmaEvidenceClass,
    connected: bool,
    native: bool,
    receipt_digest: Sha256Digest,
}

impl<'de> Deserialize<'de> for FigmaExportReceipt {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct WireReceipt {
            metadata: FigmaExportMetadata,
            request_digest: Sha256Digest,
            response_digest: Sha256Digest,
            evidence_class: FigmaEvidenceClass,
            connected: bool,
            native: bool,
            receipt_digest: Sha256Digest,
        }
        let wire = WireReceipt::deserialize(deserializer)?;
        let receipt = Self {
            metadata: wire.metadata,
            request_digest: wire.request_digest,
            response_digest: wire.response_digest,
            evidence_class: wire.evidence_class,
            connected: wire.connected,
            native: wire.native,
            receipt_digest: wire.receipt_digest,
        };
        receipt
            .validate_integrity()
            .map_err(serde::de::Error::custom)?;
        Ok(receipt)
    }
}

#[derive(Serialize)]
struct ExportReceiptDigestMaterial<'a> {
    metadata: &'a FigmaExportMetadata,
    request_digest: &'a Sha256Digest,
    response_digest: &'a Sha256Digest,
    evidence_class: FigmaEvidenceClass,
    connected: bool,
    native: bool,
}

impl FigmaExportReceipt {
    fn from_verified_payload(
        request: &ExportRequest,
        payload: &FigmaExportPayload,
        response_digest: Sha256Digest,
        evidence_class: FigmaEvidenceClass,
    ) -> Result<Self, FigmaServiceError> {
        payload
            .verify_exact(request)
            .map_err(|_| FigmaServiceError::ExportFence)?;
        let mut receipt = Self {
            metadata: payload.metadata().clone(),
            request_digest: request.digest(),
            response_digest,
            evidence_class,
            connected: false,
            native: false,
            receipt_digest: Sha256Digest::from_text("uninitialized-export-receipt"),
        };
        receipt.receipt_digest = receipt.compute_digest();
        Ok(receipt)
    }

    fn compute_digest(&self) -> Sha256Digest {
        Sha256Digest::from_serializable(&ExportReceiptDigestMaterial {
            metadata: &self.metadata,
            request_digest: &self.request_digest,
            response_digest: &self.response_digest,
            evidence_class: self.evidence_class,
            connected: self.connected,
            native: self.native,
        })
        .expect("export receipt material is serializable")
    }

    pub fn validate_integrity(&self) -> Result<(), FigmaServiceError> {
        if self.connected
            || self.native
            || self.metadata.max_bytes() > MAX_EXPORT_BYTES
            || self.metadata.byte_length() > self.metadata.max_bytes()
            || self.metadata.truncated()
            || !self.metadata.complete()
            || self.compute_digest() != self.receipt_digest
        {
            return Err(FigmaServiceError::ReceiptIntegrity);
        }
        Ok(())
    }

    #[must_use]
    pub fn metadata(&self) -> &FigmaExportMetadata {
        &self.metadata
    }

    #[must_use]
    pub fn request_digest(&self) -> &Sha256Digest {
        &self.request_digest
    }

    #[must_use]
    pub fn response_digest(&self) -> &Sha256Digest {
        &self.response_digest
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
    pub fn receipt_digest(&self) -> &Sha256Digest {
        &self.receipt_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FigmaReadResult<T> {
    pub value: T,
    pub receipt: FigmaReadReceipt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionListPlan {
    page_size: usize,
    max_pages: usize,
}

impl VersionListPlan {
    pub fn new(page_size: usize, max_pages: usize) -> Result<Self, FigmaServiceError> {
        if page_size == 0
            || page_size > MAX_VERSION_PAGE_SIZE
            || max_pages == 0
            || max_pages > MAX_VERSION_PAGES
        {
            return Err(FigmaServiceError::PaginationBound);
        }
        Ok(Self {
            page_size,
            max_pages,
        })
    }

    #[must_use]
    pub const fn default_layer1() -> Self {
        Self {
            page_size: 25,
            max_pages: MAX_VERSION_PAGES,
        }
    }

    #[must_use]
    pub const fn page_size(&self) -> usize {
        self.page_size
    }

    #[must_use]
    pub const fn max_pages(&self) -> usize {
        self.max_pages
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum FigmaServiceError {
    #[error("Figma provider call failed: {0}")]
    Provider(#[from] FigmaProviderError),
    #[error("Figma service pagination bound is invalid or exhausted")]
    PaginationBound,
    #[error("Figma version cursor did not advance")]
    CursorDidNotAdvance,
    #[error("Figma version history contains an ambiguous duplicate")]
    DuplicateVersion,
    #[error("Figma source Mission does not match the Figma scope")]
    SourceMissionMismatch,
    #[error("Figma result or receipt integrity check failed")]
    ReceiptIntegrity,
    #[error("Figma export failed its exact-byte fence")]
    ExportFence,
    #[error("Figma typed boundary failed: {0}")]
    Type(#[from] FigmaTypeError),
    #[error("Figma design result failed validation: {0}")]
    Result(#[from] MissionDesignResultError),
    #[error("Figma adoption proposal failed validation: {0}")]
    Adoption(#[from] AdoptionError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FigmaDesignService<T> {
    provider: FigmaDesignProvider<T>,
}

impl<T: FigmaTransport> FigmaDesignService<T> {
    #[must_use]
    pub fn new(provider: FigmaDesignProvider<T>) -> Self {
        Self { provider }
    }

    pub fn inspect_file(
        &mut self,
    ) -> Result<FigmaReadResult<FigmaFileMetadata>, FigmaServiceError> {
        let observation = self.provider.read_file_metadata()?;
        let receipt = FigmaReadReceipt::new_success(
            FigmaReadOperation::FileMetadata,
            self.provider.scope(),
            &observation.evidence,
            observation.value.metadata_digest().clone(),
        );
        Ok(FigmaReadResult {
            value: observation.value,
            receipt,
        })
    }

    pub fn list_versions(
        &mut self,
        plan: VersionListPlan,
    ) -> Result<FigmaReadResult<Vec<FigmaVersion>>, FigmaServiceError> {
        let mut cursor: Option<PageCursor> = None;
        let mut versions = Vec::new();
        let mut version_ids = BTreeSet::new();
        let mut response_digests = Vec::new();
        for page_index in 0..plan.max_pages {
            let observation = self
                .provider
                .list_versions(plan.page_size, cursor.as_ref())?;
            response_digests.push(observation.response_digest);
            let response = observation.value;
            if response
                .versions
                .iter()
                .any(|version| !version_ids.insert(version.version_id().clone()))
            {
                return Err(FigmaServiceError::DuplicateVersion);
            }
            versions.extend(response.versions);
            match response.next_cursor {
                None => break,
                Some(next_cursor)
                    if cursor
                        .as_ref()
                        .is_some_and(|old| old.is_same_as(&next_cursor)) =>
                {
                    return Err(FigmaServiceError::CursorDidNotAdvance);
                }
                Some(_next_cursor) if page_index + 1 == plan.max_pages => {
                    return Err(FigmaServiceError::PaginationBound);
                }
                Some(next_cursor) => cursor = Some(next_cursor),
            }
        }
        let observed_digest = Sha256Digest::from_serializable(&(&versions, &response_digests))?;
        let evidence = self.provider.evidence();
        let receipt = FigmaReadReceipt::new_success(
            FigmaReadOperation::VersionHistory,
            self.provider.scope(),
            &evidence,
            observed_digest,
        );
        Ok(FigmaReadResult {
            value: versions,
            receipt,
        })
    }

    pub fn inspect_nodes(
        &mut self,
    ) -> Result<FigmaReadResult<Vec<FigmaNodeMetadata>>, FigmaServiceError> {
        let observation = self.provider.read_node_metadata()?;
        let observed_digest =
            Sha256Digest::from_serializable(&(&observation.value, &observation.response_digest))?;
        let receipt = FigmaReadReceipt::new_success(
            FigmaReadOperation::NodeMetadata,
            self.provider.scope(),
            &observation.evidence,
            observed_digest,
        );
        Ok(FigmaReadResult {
            value: observation.value,
            receipt,
        })
    }

    pub fn record_bounded_export(
        &mut self,
        request: &ExportRequest,
    ) -> Result<FigmaReadResult<FigmaExportReceipt>, FigmaServiceError> {
        let observation = self.provider.export(request)?;
        let export_receipt = FigmaExportReceipt::from_verified_payload(
            request,
            &observation.value,
            observation.response_digest.clone(),
            observation.evidence.evidence_class(),
        )?;
        let observed_digest = export_receipt.receipt_digest().clone();
        let receipt = FigmaReadReceipt::new_success(
            FigmaReadOperation::BoundedExportMetadata,
            self.provider.scope(),
            &observation.evidence,
            observed_digest,
        );
        Ok(FigmaReadResult {
            value: export_receipt,
            receipt,
        })
    }

    pub fn collect_design_result(
        &mut self,
        source: MissionDesignSource,
        export_requests: &[ExportRequest],
    ) -> Result<FigmaReadResult<MissionDesignResult>, FigmaServiceError> {
        if source.mission_id() != self.provider.scope().mission_id() {
            return Err(FigmaServiceError::SourceMissionMismatch);
        }
        if export_requests.is_empty()
            || export_requests.len() > self.provider.scope().node_ids().len()
        {
            return Err(FigmaServiceError::Result(
                MissionDesignResultError::AmbiguousExports,
            ));
        }
        let file = self.inspect_file()?.value;
        let nodes = self.inspect_nodes()?.value;
        let mut exports = Vec::with_capacity(export_requests.len());
        for request in export_requests {
            exports.push(self.record_bounded_export(request)?.value);
        }
        let evidence = self.provider.evidence();
        let result = MissionDesignResult::new(
            crate::types::ResultId::new(format!(
                "design-result-{}",
                &source.result_revision_digest().as_str()[..24]
            ))?,
            self.provider.scope().clone(),
            source,
            file,
            nodes,
            exports,
            self.provider.provider_version().clone(),
            self.provider.registration().record_digest().clone(),
            evidence.evidence_class(),
        )?;
        let observed_digest = result.result_digest().clone();
        let receipt = FigmaReadReceipt::new_success(
            FigmaReadOperation::DesignResultRecord,
            self.provider.scope(),
            &evidence,
            observed_digest,
        );
        Ok(FigmaReadResult {
            value: result,
            receipt,
        })
    }

    pub fn propose_adoption(
        &self,
        consumer: &MissionDesignResultConsumer,
        request: &AdoptionRequest,
    ) -> Result<FigmaReadResult<DesignAdoptionProposal>, FigmaServiceError> {
        if consumer.registration().record_digest() != self.provider.registration().record_digest() {
            return Err(FigmaServiceError::Adoption(
                AdoptionError::RegistrationMismatch,
            ));
        }
        let proposal = consumer.propose(request)?;
        let evidence = self.provider.evidence();
        let receipt = FigmaReadReceipt::new_success(
            FigmaReadOperation::AdoptionProposal,
            self.provider.scope(),
            &evidence,
            proposal.proposal_digest().clone(),
        );
        Ok(FigmaReadResult {
            value: proposal,
            receipt,
        })
    }

    #[must_use]
    pub fn provider(&self) -> &FigmaDesignProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn registration(&self) -> &FigmaDesignRegistration {
        self.provider.registration()
    }

    #[must_use]
    pub fn scope(&self) -> &FigmaScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn mode(&self) -> FigmaProviderMode {
        self.provider.mode()
    }

    #[must_use]
    pub fn provider_version(&self) -> &ProviderVersion {
        self.provider.provider_version()
    }

    #[must_use]
    pub fn registration_id(&self) -> &RegistrationId {
        self.provider.registration().registration_id()
    }
}
