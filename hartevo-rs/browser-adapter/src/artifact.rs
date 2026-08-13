//! Mission-scoped, read-only browser download quarantine.
//!
//! This module deliberately stops at a typed quarantine receipt.  It never
//! opens, executes, publishes, or treats a browser filename or native path as
//! authority.  A native host must implement [`BrowserArtifactHost`] and prove
//! the same frame revision before and after the download bytes are read.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    BrowserProfileId, BrowserTabId, BrowserWorkspaceId, MissionId, ProjectId, TenantId,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::workspace::{digest, digest_json, is_bounded_identifier, is_sha256};
use crate::{
    BrowserError, BrowserLeaseProof, BrowserProfile, BrowserProfileStatus, BrowserWorkspace,
};

const ARTIFACT_SCHEMA_VERSION: u32 = 1;
const MAX_ARTIFACT_BYTES: usize = 64 * 1_024 * 1_024;
const MAX_ARTIFACT_FILENAME_BYTES: usize = 512;
const MAX_ARTIFACT_MEDIA_TYPE_BYTES: usize = 256;

/// Exact project/Mission/profile/workspace scope for an artifact provider.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserArtifactScope {
    pub schema_version: u32,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub profile_id: BrowserProfileId,
    pub profile_revision: u64,
    pub workspace_id: BrowserWorkspaceId,
    pub workspace_revision: u64,
    pub tab_id: BrowserTabId,
    pub identity_digest: String,
}

impl BrowserArtifactScope {
    /// Builds a scope from one already validated active profile and workspace.
    pub fn from_workspace(
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        tab_id: BrowserTabId,
    ) -> Result<Self, BrowserError> {
        profile.validate()?;
        workspace.validate()?;
        if profile.status != BrowserProfileStatus::Active
            || profile.tenant_id != workspace.tenant_id
            || profile.project_id != workspace.project_id
            || profile.id != workspace.profile_id
            || profile.identity.identity_digest != workspace.expected_identity_digest
            || !workspace.tabs.contains(&tab_id)
        {
            return Err(BrowserError::ArtifactScopeMismatch);
        }
        let scope = Self {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            tenant_id: workspace.tenant_id.clone(),
            project_id: workspace.project_id.clone(),
            mission_id: workspace.mission_id.clone(),
            profile_id: profile.id.clone(),
            profile_revision: profile.revision,
            workspace_id: workspace.id.clone(),
            workspace_revision: workspace.revision,
            tab_id,
            identity_digest: profile.identity.identity_digest.clone(),
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != ARTIFACT_SCHEMA_VERSION
            || !is_bounded_identifier(self.tenant_id.as_str())
            || !is_bounded_identifier(self.project_id.as_str())
            || !is_bounded_identifier(self.mission_id.as_str())
            || !is_bounded_identifier(self.profile_id.as_str())
            || self.profile_revision == 0
            || !is_bounded_identifier(self.workspace_id.as_str())
            || self.workspace_revision == 0
            || !is_bounded_identifier(self.tab_id.as_str())
            || !is_sha256(&self.identity_digest)
        {
            return Err(BrowserError::InvalidArtifact);
        }
        Ok(())
    }

    fn validate_against(
        &self,
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
    ) -> Result<(), BrowserError> {
        self.validate()?;
        profile.validate()?;
        workspace.validate()?;
        if self.tenant_id != workspace.tenant_id
            || self.project_id != workspace.project_id
            || self.mission_id != workspace.mission_id
            || self.profile_id != profile.id
            || self.profile_revision != profile.revision
            || self.workspace_id != workspace.id
            || self.workspace_revision != workspace.revision
            || self.identity_digest != profile.identity.identity_digest
            || workspace.profile_id != profile.id
            || workspace.expected_identity_digest != profile.identity.identity_digest
            || !workspace.tabs.contains(&self.tab_id)
        {
            return Err(BrowserError::ArtifactScopeMismatch);
        }
        Ok(())
    }

    fn evidence_digest(&self) -> Result<String, BrowserError> {
        digest_json(self)
    }
}

/// A digest-only frame/session/navigation revision used to fence a download.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserArtifactFrameRevision {
    pub schema_version: u32,
    pub scope_digest: String,
    pub tab_id: BrowserTabId,
    pub lease_generation: u64,
    pub document_generation: u64,
    pub navigation_revision: u64,
    pub session_id_digest: String,
    pub frame_id_digest: String,
    pub loader_id_digest: String,
    pub url_digest: String,
    pub origin_digest: String,
}

/// Raw frame observation supplied by a native host before its identifiers are
/// reduced to digests.
#[derive(Clone, Eq, PartialEq)]
pub struct BrowserArtifactFrameObservation {
    pub session_id: String,
    pub frame_id: String,
    pub loader_id: String,
    pub navigation_revision: u64,
    pub document_generation: u64,
    pub url: String,
}

impl fmt::Debug for BrowserArtifactFrameObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserArtifactFrameObservation")
            .field("session_id_digest", &digest(self.session_id.as_bytes()))
            .field("frame_id_digest", &digest(self.frame_id.as_bytes()))
            .field("loader_id_digest", &digest(self.loader_id.as_bytes()))
            .field("navigation_revision", &self.navigation_revision)
            .field("document_generation", &self.document_generation)
            .field("url_digest", &digest(self.url.as_bytes()))
            .finish()
    }
}

impl BrowserArtifactFrameRevision {
    /// Creates a revision from the native host's opaque IDs and current URL.
    pub fn observed(
        scope: &BrowserArtifactScope,
        observation: &BrowserArtifactFrameObservation,
    ) -> Result<Self, BrowserError> {
        if !is_bounded_identifier(&observation.session_id)
            || !is_bounded_identifier(&observation.frame_id)
            || !is_bounded_identifier(&observation.loader_id)
        {
            return Err(BrowserError::InvalidArtifact);
        }
        let (_, origin) = canonical_source_identity(&observation.url)?;
        let frame = Self {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            scope_digest: scope.evidence_digest()?,
            tab_id: scope.tab_id.clone(),
            lease_generation: 0,
            document_generation: observation.document_generation,
            navigation_revision: observation.navigation_revision,
            session_id_digest: digest(observation.session_id.as_bytes()),
            frame_id_digest: digest(observation.frame_id.as_bytes()),
            loader_id_digest: digest(observation.loader_id.as_bytes()),
            url_digest: digest(observation.url.as_bytes()),
            origin_digest: digest(origin.as_bytes()),
        };
        frame.with_lease_generation(1)
    }

    /// Sets the exact agent lease generation observed for this frame.
    pub fn with_lease_generation(mut self, lease_generation: u64) -> Result<Self, BrowserError> {
        self.lease_generation = lease_generation;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != ARTIFACT_SCHEMA_VERSION
            || !is_sha256(&self.scope_digest)
            || !is_bounded_identifier(self.tab_id.as_str())
            || self.lease_generation == 0
            || self.document_generation == 0
            || self.navigation_revision == 0
            || !is_sha256(&self.session_id_digest)
            || !is_sha256(&self.frame_id_digest)
            || !is_sha256(&self.loader_id_digest)
            || !is_sha256(&self.url_digest)
            || !is_sha256(&self.origin_digest)
        {
            return Err(BrowserError::InvalidArtifact);
        }
        Ok(())
    }

    fn validate_for(
        &self,
        scope: &BrowserArtifactScope,
        proof: &BrowserLeaseProof,
    ) -> Result<(), BrowserError> {
        self.validate()?;
        if self.scope_digest != scope.evidence_digest()?
            || self.tab_id != scope.tab_id
            || self.lease_generation != proof.generation
            || proof.workspace_id != scope.workspace_id
        {
            return Err(BrowserError::ArtifactFrameStale);
        }
        Ok(())
    }
}

/// Bytes and metadata returned by a native browser host before quarantine.
///
/// The bytes are intentionally private to the provider boundary in spirit;
/// callers receive only the digest and count in the resulting receipt.
#[derive(Clone)]
pub struct BrowserArtifactCapture {
    pub artifact_id: String,
    pub frame: BrowserArtifactFrameRevision,
    pub filename: String,
    pub media_type: String,
    pub source_url: String,
    pub source_origin: String,
    pub bytes: Vec<u8>,
    pub observed_at: DateTime<Utc>,
}

/// Input object for constructing a host capture without a path authority.
#[derive(Clone)]
pub struct BrowserArtifactCaptureInput {
    pub artifact_id: String,
    pub frame: BrowserArtifactFrameRevision,
    pub filename: String,
    pub media_type: String,
    pub source_url: String,
    pub source_origin: String,
    pub bytes: Vec<u8>,
    pub observed_at: DateTime<Utc>,
}

impl fmt::Debug for BrowserArtifactCaptureInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserArtifactCaptureInput")
            .field("artifact_id", &self.artifact_id)
            .field("frame", &self.frame)
            .field("filename", &self.filename)
            .field("media_type", &self.media_type)
            .field("source_url_digest", &digest(self.source_url.as_bytes()))
            .field(
                "source_origin_digest",
                &digest(self.source_origin.as_bytes()),
            )
            .field("byte_count", &self.bytes.len())
            .field("bytes_digest", &digest(&self.bytes))
            .field("observed_at", &self.observed_at)
            .finish()
    }
}

impl BrowserArtifactCapture {
    pub fn new(input: BrowserArtifactCaptureInput) -> Result<Self, BrowserError> {
        let capture = Self {
            artifact_id: input.artifact_id,
            frame: input.frame,
            filename: input.filename,
            media_type: input.media_type,
            source_url: input.source_url,
            source_origin: input.source_origin,
            bytes: input.bytes,
            observed_at: input.observed_at,
        };
        capture.validate()?;
        Ok(capture)
    }

    fn validate(&self) -> Result<(), BrowserError> {
        if !is_bounded_identifier(&self.artifact_id)
            || !valid_display_filename(&self.filename)
            || !valid_media_type(&self.media_type)
            || self.bytes.len() > MAX_ARTIFACT_BYTES
        {
            return Err(BrowserError::InvalidArtifact);
        }
        self.frame.validate()?;
        let (canonical_url, canonical_origin) = canonical_source_identity(&self.source_url)?;
        if canonical_url != self.source_url || canonical_origin != self.source_origin {
            return Err(BrowserError::InvalidArtifact);
        }
        Ok(())
    }

    fn bytes_digest(&self) -> String {
        digest(&self.bytes)
    }
}

impl fmt::Debug for BrowserArtifactCapture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserArtifactCapture")
            .field("artifact_id", &self.artifact_id)
            .field("frame", &self.frame)
            .field("filename", &self.filename)
            .field("media_type", &self.media_type)
            .field("source_url_digest", &digest(self.source_url.as_bytes()))
            .field(
                "source_origin_digest",
                &digest(self.source_origin.as_bytes()),
            )
            .field("byte_count", &self.bytes.len())
            .field("bytes_digest", &self.bytes_digest())
            .field("observed_at", &self.observed_at)
            .finish()
    }
}

/// Typed receipt handed to File/Result consumers after quarantine.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserArtifactQuarantineReceipt {
    pub schema_version: u32,
    pub provider_generation: u64,
    pub sequence: u64,
    pub artifact_id: String,
    pub scope: BrowserArtifactScope,
    pub frame: BrowserArtifactFrameRevision,
    pub filename: String,
    pub media_type: String,
    pub byte_count: u64,
    pub bytes_digest: String,
    pub source_url: String,
    pub source_origin: String,
    pub quarantine_ref: String,
    pub observed_at: DateTime<Utc>,
    pub opened: bool,
    pub execution_permitted: bool,
}

impl BrowserArtifactQuarantineReceipt {
    fn from_capture(
        provider_generation: u64,
        sequence: u64,
        scope: BrowserArtifactScope,
        capture: &BrowserArtifactCapture,
    ) -> Result<Self, BrowserError> {
        let quarantine_ref = digest_json(&(
            provider_generation,
            sequence,
            &capture.artifact_id,
            &scope,
            &capture.frame,
            capture.bytes_digest(),
            &capture.source_url,
            capture.observed_at,
        ))?;
        let byte_count =
            u64::try_from(capture.bytes.len()).map_err(|_| BrowserError::CounterOverflow)?;
        let receipt = Self {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            provider_generation,
            sequence,
            artifact_id: capture.artifact_id.clone(),
            scope,
            frame: capture.frame.clone(),
            filename: capture.filename.clone(),
            media_type: capture.media_type.clone(),
            byte_count,
            bytes_digest: capture.bytes_digest(),
            source_url: capture.source_url.clone(),
            source_origin: capture.source_origin.clone(),
            quarantine_ref,
            observed_at: capture.observed_at,
            opened: false,
            execution_permitted: false,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != ARTIFACT_SCHEMA_VERSION
            || self.provider_generation == 0
            || self.sequence == 0
            || !is_bounded_identifier(&self.artifact_id)
            || self.byte_count > MAX_ARTIFACT_BYTES as u64
            || !is_sha256(&self.bytes_digest)
            || !is_sha256(&self.quarantine_ref)
            || self.opened
            || self.execution_permitted
            || !valid_display_filename(&self.filename)
            || !valid_media_type(&self.media_type)
        {
            return Err(BrowserError::InvalidArtifact);
        }
        self.scope.validate()?;
        self.frame
            .validate_for(
                &self.scope,
                &BrowserLeaseProof {
                    workspace_id: self.scope.workspace_id.clone(),
                    lease_id: hartevo_domain_kernel::BrowserControlLeaseId::from(
                        "receipt-validation",
                    ),
                    generation: self.frame.lease_generation,
                },
            )
            .map_err(|_| BrowserError::InvalidArtifact)?;
        let (canonical_url, canonical_origin) = canonical_source_identity(&self.source_url)?;
        if canonical_url != self.source_url
            || canonical_origin != self.source_origin
            || digest(self.source_url.as_bytes()) != self.frame.url_digest
            || digest(self.source_origin.as_bytes()) != self.frame.origin_digest
        {
            return Err(BrowserError::InvalidArtifact);
        }
        Ok(())
    }

    pub fn evidence_digest(&self) -> Result<String, BrowserError> {
        self.validate()?;
        digest_json(self)
    }
}

/// Durable, append-only model-visible result projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserArtifactResultLog {
    pub schema_version: u32,
    pub scope: BrowserArtifactScope,
    pub provider_generation: u64,
    pub entries: Vec<BrowserArtifactQuarantineReceipt>,
}

impl BrowserArtifactResultLog {
    fn empty(scope: BrowserArtifactScope, provider_generation: u64) -> Result<Self, BrowserError> {
        let log = Self {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            scope,
            provider_generation,
            entries: Vec::new(),
        };
        log.validate()?;
        Ok(log)
    }

    pub fn restore(
        scope: BrowserArtifactScope,
        provider_generation: u64,
        entries: Vec<BrowserArtifactQuarantineReceipt>,
    ) -> Result<Self, BrowserError> {
        let log = Self {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            scope,
            provider_generation,
            entries,
        };
        log.validate()?;
        Ok(log)
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != ARTIFACT_SCHEMA_VERSION || self.provider_generation == 0 {
            return Err(BrowserError::InvalidArtifact);
        }
        self.scope.validate()?;
        let mut ids = BTreeSet::new();
        for (index, entry) in self.entries.iter().enumerate() {
            entry.validate()?;
            if entry.sequence
                != u64::try_from(index + 1).map_err(|_| BrowserError::CounterOverflow)?
                || entry.scope != self.scope
                || !ids.insert(entry.artifact_id.clone())
            {
                return Err(BrowserError::InvalidArtifact);
            }
        }
        Ok(())
    }

    pub fn evidence_digest(&self) -> Result<String, BrowserError> {
        self.validate()?;
        digest_json(self)
    }
}

/// Typed request from the quarantine provider to a File Inspection consumer.
///
/// It carries no native path or executable authority.  Every source and byte
/// fact is copied from the immutable [`BrowserArtifactQuarantineReceipt`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserArtifactFileInspectionRequest {
    pub schema_version: u32,
    pub request_id: String,
    pub provider_generation: u64,
    pub sequence: u64,
    pub receipt_digest: String,
    pub artifact_id: String,
    pub scope: BrowserArtifactScope,
    pub frame: BrowserArtifactFrameRevision,
    pub quarantine_ref: String,
    pub bytes_digest: String,
    pub media_type: String,
    pub byte_count: u64,
    pub source_url: String,
    pub source_origin: String,
    pub requested_at: DateTime<Utc>,
}

impl BrowserArtifactFileInspectionRequest {
    fn from_receipt(
        request_id: String,
        receipt: &BrowserArtifactQuarantineReceipt,
        requested_at: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        let request = Self {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            request_id,
            provider_generation: receipt.provider_generation,
            sequence: receipt.sequence,
            receipt_digest: receipt.evidence_digest()?,
            artifact_id: receipt.artifact_id.clone(),
            scope: receipt.scope.clone(),
            frame: receipt.frame.clone(),
            quarantine_ref: receipt.quarantine_ref.clone(),
            bytes_digest: receipt.bytes_digest.clone(),
            media_type: receipt.media_type.clone(),
            byte_count: receipt.byte_count,
            source_url: receipt.source_url.clone(),
            source_origin: receipt.source_origin.clone(),
            requested_at,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != ARTIFACT_SCHEMA_VERSION
            || !is_sha256(&self.request_id)
            || self.provider_generation == 0
            || self.sequence == 0
            || !is_sha256(&self.receipt_digest)
            || !is_bounded_identifier(&self.artifact_id)
            || !is_sha256(&self.quarantine_ref)
            || !is_sha256(&self.bytes_digest)
            || self.byte_count > MAX_ARTIFACT_BYTES as u64
            || !valid_media_type(&self.media_type)
        {
            return Err(BrowserError::ArtifactInspectionInvalid);
        }
        self.scope.validate()?;
        self.frame
            .validate_for(
                &self.scope,
                &BrowserLeaseProof {
                    workspace_id: self.scope.workspace_id.clone(),
                    lease_id: hartevo_domain_kernel::BrowserControlLeaseId::from(
                        "inspection-request-validation",
                    ),
                    generation: self.frame.lease_generation,
                },
            )
            .map_err(|_| BrowserError::ArtifactInspectionInvalid)?;
        let (canonical_url, canonical_origin) = canonical_source_identity(&self.source_url)
            .map_err(|_| BrowserError::ArtifactInspectionInvalid)?;
        if canonical_url != self.source_url
            || canonical_origin != self.source_origin
            || digest(self.source_url.as_bytes()) != self.frame.url_digest
            || digest(self.source_origin.as_bytes()) != self.frame.origin_digest
        {
            return Err(BrowserError::ArtifactInspectionInvalid);
        }
        Ok(())
    }

    fn matches_receipt(&self, receipt: &BrowserArtifactQuarantineReceipt) -> bool {
        self.provider_generation == receipt.provider_generation
            && self.sequence == receipt.sequence
            && self.receipt_digest
                == receipt
                    .evidence_digest()
                    .ok()
                    .as_deref()
                    .unwrap_or_default()
            && self.artifact_id == receipt.artifact_id
            && self.scope == receipt.scope
            && self.frame == receipt.frame
            && self.quarantine_ref == receipt.quarantine_ref
            && self.bytes_digest == receipt.bytes_digest
            && self.media_type == receipt.media_type
            && self.byte_count == receipt.byte_count
            && self.source_url == receipt.source_url
            && self.source_origin == receipt.source_origin
    }

    pub fn evidence_digest(&self) -> Result<String, BrowserError> {
        self.validate()?;
        digest_json(self)
    }
}

/// The only result that can transition a quarantined artifact to adoption is
/// `Clean`; every other verdict is terminally rejected by the provider.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserArtifactInspectionVerdict {
    Clean,
    Malware,
    Tampered,
    Unknown,
    ScannerUnavailable,
}

/// Scanner identity/evidence supplied with one inspection result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserArtifactInspectionEvidence {
    pub verdict: BrowserArtifactInspectionVerdict,
    pub inspector_id: String,
    pub inspector_version: String,
    pub scanner_evidence_digest: String,
    pub inspected_at: DateTime<Utc>,
}

/// Typed result returned by a File Inspection consumer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserArtifactFileInspectionResult {
    pub schema_version: u32,
    pub request_id: String,
    pub verdict: BrowserArtifactInspectionVerdict,
    pub receipt_digest: String,
    pub artifact_id: String,
    pub scope: BrowserArtifactScope,
    pub frame: BrowserArtifactFrameRevision,
    pub quarantine_ref: String,
    pub bytes_digest: String,
    pub media_type: String,
    pub byte_count: u64,
    pub source_url: String,
    pub source_origin: String,
    pub inspector_id: String,
    pub inspector_version: String,
    pub scanner_evidence_digest: String,
    pub inspected_at: DateTime<Utc>,
}

impl BrowserArtifactFileInspectionResult {
    pub fn from_request(
        request: &BrowserArtifactFileInspectionRequest,
        evidence: BrowserArtifactInspectionEvidence,
    ) -> Result<Self, BrowserError> {
        let result = Self {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            request_id: request.request_id.clone(),
            verdict: evidence.verdict,
            receipt_digest: request.receipt_digest.clone(),
            artifact_id: request.artifact_id.clone(),
            scope: request.scope.clone(),
            frame: request.frame.clone(),
            quarantine_ref: request.quarantine_ref.clone(),
            bytes_digest: request.bytes_digest.clone(),
            media_type: request.media_type.clone(),
            byte_count: request.byte_count,
            source_url: request.source_url.clone(),
            source_origin: request.source_origin.clone(),
            inspector_id: evidence.inspector_id,
            inspector_version: evidence.inspector_version,
            scanner_evidence_digest: evidence.scanner_evidence_digest,
            inspected_at: evidence.inspected_at,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != ARTIFACT_SCHEMA_VERSION
            || !is_sha256(&self.request_id)
            || !is_sha256(&self.receipt_digest)
            || !is_bounded_identifier(&self.artifact_id)
            || !is_sha256(&self.quarantine_ref)
            || !is_sha256(&self.bytes_digest)
            || self.byte_count > MAX_ARTIFACT_BYTES as u64
            || !is_bounded_identifier(&self.inspector_id)
            || !is_bounded_identifier(&self.inspector_version)
            || !is_sha256(&self.scanner_evidence_digest)
            || !valid_media_type(&self.media_type)
        {
            return Err(BrowserError::ArtifactInspectionInvalid);
        }
        self.scope.validate()?;
        self.frame
            .validate_for(
                &self.scope,
                &BrowserLeaseProof {
                    workspace_id: self.scope.workspace_id.clone(),
                    lease_id: hartevo_domain_kernel::BrowserControlLeaseId::from(
                        "inspection-result-validation",
                    ),
                    generation: self.frame.lease_generation,
                },
            )
            .map_err(|_| BrowserError::ArtifactInspectionInvalid)?;
        let (canonical_url, canonical_origin) = canonical_source_identity(&self.source_url)
            .map_err(|_| BrowserError::ArtifactInspectionInvalid)?;
        if canonical_url != self.source_url
            || canonical_origin != self.source_origin
            || digest(self.source_url.as_bytes()) != self.frame.url_digest
            || digest(self.source_origin.as_bytes()) != self.frame.origin_digest
        {
            return Err(BrowserError::ArtifactInspectionInvalid);
        }
        Ok(())
    }

    fn matches_request(&self, request: &BrowserArtifactFileInspectionRequest) -> bool {
        self.request_id == request.request_id
            && self.receipt_digest == request.receipt_digest
            && self.artifact_id == request.artifact_id
            && self.scope == request.scope
            && self.frame == request.frame
            && self.quarantine_ref == request.quarantine_ref
            && self.bytes_digest == request.bytes_digest
            && self.media_type == request.media_type
            && self.byte_count == request.byte_count
            && self.source_url == request.source_url
            && self.source_origin == request.source_origin
            && self.inspected_at >= request.requested_at
    }

    pub fn evidence_digest(&self) -> Result<String, BrowserError> {
        self.validate()?;
        digest_json(self)
    }
}

/// A scanner/inspection implementation consumes only a typed request and
/// returns a typed result.  It cannot return a path or an execution command.
pub trait BrowserArtifactInspector {
    fn inspect(
        &mut self,
        request: &BrowserArtifactFileInspectionRequest,
    ) -> Result<BrowserArtifactFileInspectionResult, BrowserError>;
}

/// Explicit NOT_EVALUATED boundary when no real scanner is available.
#[derive(Debug, Default)]
pub struct UnavailableBrowserArtifactInspector;

impl BrowserArtifactInspector for UnavailableBrowserArtifactInspector {
    fn inspect(
        &mut self,
        _request: &BrowserArtifactFileInspectionRequest,
    ) -> Result<BrowserArtifactFileInspectionResult, BrowserError> {
        Err(BrowserError::ArtifactInspectionUnavailable)
    }
}

/// Adoption authorization is a receipt only.  It never opens, executes, or
/// moves the quarantined bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserArtifactSafeForAdoption {
    pub schema_version: u32,
    pub provider_generation: u64,
    pub request_id: String,
    pub artifact_id: String,
    pub receipt_digest: String,
    pub scope: BrowserArtifactScope,
    pub frame: BrowserArtifactFrameRevision,
    pub quarantine_ref: String,
    pub bytes_digest: String,
    pub media_type: String,
    pub byte_count: u64,
    pub source_url: String,
    pub source_origin: String,
    pub inspector_id: String,
    pub inspector_version: String,
    pub scanner_evidence_digest: String,
    pub inspected_at: DateTime<Utc>,
    pub state: BrowserArtifactAdoptionState,
    pub opened: bool,
    pub execution_permitted: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserArtifactAdoptionState {
    SafeForAdoption,
}

impl BrowserArtifactSafeForAdoption {
    fn from_result(
        provider_generation: u64,
        result: &BrowserArtifactFileInspectionResult,
    ) -> Result<Self, BrowserError> {
        if result.verdict != BrowserArtifactInspectionVerdict::Clean {
            return Err(BrowserError::ArtifactInspectionRejected);
        }
        let adoption = Self {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            provider_generation,
            request_id: result.request_id.clone(),
            artifact_id: result.artifact_id.clone(),
            receipt_digest: result.receipt_digest.clone(),
            scope: result.scope.clone(),
            frame: result.frame.clone(),
            quarantine_ref: result.quarantine_ref.clone(),
            bytes_digest: result.bytes_digest.clone(),
            media_type: result.media_type.clone(),
            byte_count: result.byte_count,
            source_url: result.source_url.clone(),
            source_origin: result.source_origin.clone(),
            inspector_id: result.inspector_id.clone(),
            inspector_version: result.inspector_version.clone(),
            scanner_evidence_digest: result.scanner_evidence_digest.clone(),
            inspected_at: result.inspected_at,
            state: BrowserArtifactAdoptionState::SafeForAdoption,
            opened: false,
            execution_permitted: false,
        };
        adoption.validate()?;
        Ok(adoption)
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != ARTIFACT_SCHEMA_VERSION
            || self.provider_generation == 0
            || !is_sha256(&self.request_id)
            || !is_bounded_identifier(&self.artifact_id)
            || !is_sha256(&self.receipt_digest)
            || !is_sha256(&self.quarantine_ref)
            || !is_sha256(&self.bytes_digest)
            || self.byte_count > MAX_ARTIFACT_BYTES as u64
            || !valid_media_type(&self.media_type)
            || !is_bounded_identifier(&self.inspector_id)
            || !is_bounded_identifier(&self.inspector_version)
            || !is_sha256(&self.scanner_evidence_digest)
            || self.state != BrowserArtifactAdoptionState::SafeForAdoption
            || self.opened
            || self.execution_permitted
        {
            return Err(BrowserError::ArtifactInspectionInvalid);
        }
        self.scope.validate()?;
        self.frame
            .validate_for(
                &self.scope,
                &BrowserLeaseProof {
                    workspace_id: self.scope.workspace_id.clone(),
                    lease_id: hartevo_domain_kernel::BrowserControlLeaseId::from(
                        "adoption-validation",
                    ),
                    generation: self.frame.lease_generation,
                },
            )
            .map_err(|_| BrowserError::ArtifactInspectionInvalid)?;
        let (canonical_url, canonical_origin) = canonical_source_identity(&self.source_url)
            .map_err(|_| BrowserError::ArtifactInspectionInvalid)?;
        if canonical_url != self.source_url
            || canonical_origin != self.source_origin
            || digest(self.source_url.as_bytes()) != self.frame.url_digest
            || digest(self.source_origin.as_bytes()) != self.frame.origin_digest
        {
            return Err(BrowserError::ArtifactInspectionInvalid);
        }
        Ok(())
    }

    pub fn evidence_digest(&self) -> Result<String, BrowserError> {
        self.validate()?;
        digest_json(self)
    }
}

/// Provider lifecycle used to fail closed after restart, revoke, or a stale
/// frame observation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserArtifactProviderState {
    Mounted,
    Invalidated,
    Revoked,
    Restarted,
}

/// Native host boundary for exact, read-only download capture.
pub trait BrowserArtifactHost {
    fn observe_artifact_frame(
        &mut self,
        scope: &BrowserArtifactScope,
        now: DateTime<Utc>,
    ) -> Result<BrowserArtifactFrameRevision, BrowserError>;

    fn capture_download(
        &mut self,
        scope: &BrowserArtifactScope,
        expected_frame: &BrowserArtifactFrameRevision,
        artifact_id: &str,
        now: DateTime<Utc>,
    ) -> Result<BrowserArtifactCapture, BrowserError>;
}

/// File/Result consumer receives only a typed quarantine receipt.
pub trait BrowserArtifactResultSink {
    fn accept_quarantine_receipt(
        &mut self,
        receipt: &BrowserArtifactQuarantineReceipt,
    ) -> Result<(), BrowserError>;
}

/// Mission-scoped consumer/provider for browser downloads.
#[derive(Clone, Debug)]
pub struct BrowserArtifactPlugin {
    scope: BrowserArtifactScope,
    state: BrowserArtifactProviderState,
    provider_generation: u64,
    result_log: BrowserArtifactResultLog,
    captured: BTreeMap<String, BrowserArtifactQuarantineReceipt>,
    delivered: BTreeSet<String>,
    pending_inspections: BTreeMap<String, BrowserArtifactFileInspectionRequest>,
    completed_inspections: BTreeSet<String>,
    rejected_inspections: BTreeSet<String>,
    safe_adoptions: BTreeMap<String, BrowserArtifactSafeForAdoption>,
    next_inspection_sequence: u64,
}

impl BrowserArtifactPlugin {
    pub fn mount(
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        scope: BrowserArtifactScope,
    ) -> Result<Self, BrowserError> {
        scope.validate_against(profile, workspace)?;
        if profile.status != BrowserProfileStatus::Active {
            return Err(BrowserError::ArtifactScopeMismatch);
        }
        let result_log = BrowserArtifactResultLog::empty(scope.clone(), 1)?;
        Ok(Self {
            scope,
            state: BrowserArtifactProviderState::Mounted,
            provider_generation: 1,
            result_log,
            captured: BTreeMap::new(),
            delivered: BTreeSet::new(),
            pending_inspections: BTreeMap::new(),
            completed_inspections: BTreeSet::new(),
            rejected_inspections: BTreeSet::new(),
            safe_adoptions: BTreeMap::new(),
            next_inspection_sequence: 1,
        })
    }

    /// Remounts from a durable log with a new provider generation. Old
    /// receipts remain evidence but cannot be delivered through this cursor.
    pub fn remount(
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        scope: BrowserArtifactScope,
        log: BrowserArtifactResultLog,
    ) -> Result<Self, BrowserError> {
        scope.validate_against(profile, workspace)?;
        if profile.status != BrowserProfileStatus::Active || log.scope != scope {
            return Err(BrowserError::ArtifactScopeMismatch);
        }
        log.validate()?;
        let provider_generation = log
            .provider_generation
            .checked_add(1)
            .ok_or(BrowserError::CounterOverflow)?;
        let captured = log
            .entries
            .iter()
            .map(|entry| (entry.artifact_id.clone(), entry.clone()))
            .collect();
        let new_log = BrowserArtifactResultLog {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            scope: scope.clone(),
            provider_generation,
            entries: log.entries,
        };
        new_log.validate()?;
        Ok(Self {
            scope,
            state: BrowserArtifactProviderState::Mounted,
            provider_generation,
            result_log: new_log,
            captured,
            delivered: BTreeSet::new(),
            pending_inspections: BTreeMap::new(),
            completed_inspections: BTreeSet::new(),
            rejected_inspections: BTreeSet::new(),
            safe_adoptions: BTreeMap::new(),
            next_inspection_sequence: 1,
        })
    }

    pub fn scope(&self) -> &BrowserArtifactScope {
        &self.scope
    }

    pub fn state(&self) -> BrowserArtifactProviderState {
        self.state
    }

    pub fn result_log(&self) -> &BrowserArtifactResultLog {
        &self.result_log
    }

    pub fn restart(&mut self) -> Result<(), BrowserError> {
        match self.state {
            BrowserArtifactProviderState::Mounted | BrowserArtifactProviderState::Invalidated => {
                self.state = BrowserArtifactProviderState::Restarted;
                self.clear_inspection_state();
                Ok(())
            }
            BrowserArtifactProviderState::Revoked => Err(BrowserError::ArtifactProviderRevoked),
            BrowserArtifactProviderState::Restarted => Err(BrowserError::ArtifactProviderRestarted),
        }
    }

    pub fn revoke(
        &mut self,
        profile: &mut BrowserProfile,
        expected_revision: u64,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        if self.state == BrowserArtifactProviderState::Revoked {
            return Err(BrowserError::ArtifactProviderRevoked);
        }
        if self.state != BrowserArtifactProviderState::Mounted {
            return Err(BrowserError::ArtifactProviderUnavailable);
        }
        if profile.id != self.scope.profile_id || profile.revision != self.scope.profile_revision {
            return Err(BrowserError::ArtifactScopeMismatch);
        }
        profile.revoke(expected_revision, evidence_digest, now)?;
        self.state = BrowserArtifactProviderState::Revoked;
        self.clear_inspection_state();
        Ok(())
    }

    pub fn capture_download<H: BrowserArtifactHost>(
        &mut self,
        host: &mut H,
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        proof: &BrowserLeaseProof,
        artifact_id: &str,
        now: DateTime<Utc>,
    ) -> Result<BrowserArtifactQuarantineReceipt, BrowserError> {
        self.ensure_mounted()?;
        if self.captured.contains_key(artifact_id) {
            return Err(BrowserError::ArtifactDuplicate);
        }
        if let Err(error) = self.scope.validate_against(profile, workspace) {
            return Err(self.invalidate(error));
        }
        if profile.status != BrowserProfileStatus::Active {
            return Err(BrowserError::ArtifactProviderRevoked);
        }
        if let Err(error) = workspace.validate_agent_lease(proof, now) {
            return Err(self.invalidate(error));
        }
        if !is_bounded_identifier(artifact_id) || proof.workspace_id != workspace.id {
            return Err(BrowserError::ArtifactScopeMismatch);
        }
        let first_frame = host
            .observe_artifact_frame(&self.scope, now)
            .map_err(|error| self.host_failure(error))?;
        if let Err(error) = first_frame.validate_for(&self.scope, proof) {
            return Err(self.invalidate(error));
        }
        if first_frame.lease_generation != workspace.lease_generation {
            return Err(self.invalidate(BrowserError::ArtifactFrameStale));
        }
        let capture = host
            .capture_download(&self.scope, &first_frame, artifact_id, now)
            .map_err(|error| self.host_failure(error))?;
        if capture.artifact_id != artifact_id {
            return Err(self.invalidate(BrowserError::ArtifactScopeMismatch));
        }
        if let Err(error) = capture.validate() {
            return Err(self.invalidate(error));
        }
        if capture.frame != first_frame || capture.observed_at < now {
            return Err(self.invalidate(BrowserError::ArtifactFrameStale));
        }
        if let Err(error) = workspace.validate_agent_lease(proof, capture.observed_at) {
            return Err(self.invalidate(error));
        }
        let second_frame = host
            .observe_artifact_frame(&self.scope, capture.observed_at)
            .map_err(|error| self.host_failure(error))?;
        if let Err(error) = second_frame.validate_for(&self.scope, proof) {
            return Err(self.invalidate(error));
        }
        if second_frame != first_frame {
            return Err(self.invalidate(BrowserError::ArtifactFrameStale));
        }
        let sequence = u64::try_from(self.result_log.entries.len() + 1)
            .map_err(|_| BrowserError::CounterOverflow)?;
        let receipt = match BrowserArtifactQuarantineReceipt::from_capture(
            self.provider_generation,
            sequence,
            self.scope.clone(),
            &capture,
        ) {
            Ok(receipt) => receipt,
            Err(error) => return Err(self.invalidate(error)),
        };
        self.result_log.entries.push(receipt.clone());
        self.result_log.validate()?;
        self.captured
            .insert(receipt.artifact_id.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn deliver_receipt<S: BrowserArtifactResultSink>(
        &mut self,
        receipt: &BrowserArtifactQuarantineReceipt,
        sink: &mut S,
    ) -> Result<(), BrowserError> {
        self.ensure_mounted()?;
        receipt.validate()?;
        if receipt.provider_generation != self.provider_generation
            || receipt.scope != self.scope
            || self.captured.get(&receipt.artifact_id) != Some(receipt)
        {
            return Err(BrowserError::ArtifactProviderRestarted);
        }
        if !self.delivered.insert(receipt.artifact_id.clone()) {
            return Err(BrowserError::ArtifactDuplicate);
        }
        if let Err(error) = sink.accept_quarantine_receipt(receipt) {
            self.delivered.remove(&receipt.artifact_id);
            return Err(error);
        }
        Ok(())
    }

    /// Unmounts the provider and reclaims every pending inspection cursor.
    pub fn unmount(&mut self) -> Result<(), BrowserError> {
        self.restart()
    }

    /// Creates one typed File Inspection request from one exact quarantine
    /// receipt.  A second request for the same receipt is rejected.
    pub fn prepare_file_inspection(
        &mut self,
        receipt: &BrowserArtifactQuarantineReceipt,
        requested_at: DateTime<Utc>,
    ) -> Result<BrowserArtifactFileInspectionRequest, BrowserError> {
        self.ensure_mounted()?;
        receipt.validate()?;
        if receipt.provider_generation != self.provider_generation
            || receipt.scope != self.scope
            || self.captured.get(&receipt.artifact_id) != Some(receipt)
        {
            return Err(BrowserError::ArtifactProviderRestarted);
        }
        if requested_at < receipt.observed_at {
            return Err(BrowserError::ArtifactInspectionInvalid);
        }
        let receipt_digest = receipt.evidence_digest()?;
        if self.rejected_inspections.contains(&receipt_digest)
            || self.completed_inspections.contains(&receipt_digest)
            || self
                .pending_inspections
                .values()
                .any(|request| request.receipt_digest == receipt_digest)
            || self.safe_adoptions.contains_key(&receipt.artifact_id)
        {
            return Err(BrowserError::ArtifactInspectionDuplicate);
        }
        let sequence = self.next_inspection_sequence;
        self.next_inspection_sequence = self
            .next_inspection_sequence
            .checked_add(1)
            .ok_or(BrowserError::CounterOverflow)?;
        let request_id = digest_json(&(
            self.provider_generation,
            sequence,
            &receipt_digest,
            requested_at,
        ))?;
        let request =
            BrowserArtifactFileInspectionRequest::from_receipt(request_id, receipt, requested_at)?;
        if !request.matches_receipt(receipt) {
            return Err(BrowserError::ArtifactInspectionInvalid);
        }
        if self
            .pending_inspections
            .insert(request.request_id.clone(), request.clone())
            .is_some()
        {
            return Err(BrowserError::ArtifactInspectionDuplicate);
        }
        Ok(request)
    }

    /// Runs one typed inspector and closes the request exactly once.
    pub fn inspect_pending<I: BrowserArtifactInspector>(
        &mut self,
        inspector: &mut I,
        request_id: &str,
    ) -> Result<BrowserArtifactSafeForAdoption, BrowserError> {
        self.ensure_mounted()?;
        let request = self
            .pending_inspections
            .get(request_id)
            .cloned()
            .ok_or_else(|| self.reopened_or_invalid_request(request_id))?;
        let result = match inspector.inspect(&request) {
            Ok(result) => result,
            Err(error) => {
                self.reject_inspection(&request);
                return Err(error);
            }
        };
        self.submit_file_inspection_result(&request, &result)
    }

    /// Accepts one typed File Inspection result and marks the artifact
    /// `SafeForAdoption` only after every original receipt field matches.
    pub fn submit_file_inspection_result(
        &mut self,
        request: &BrowserArtifactFileInspectionRequest,
        result: &BrowserArtifactFileInspectionResult,
    ) -> Result<BrowserArtifactSafeForAdoption, BrowserError> {
        self.ensure_mounted()?;
        let pending = self
            .pending_inspections
            .get(&request.request_id)
            .cloned()
            .ok_or_else(|| self.reopened_or_invalid_request(&request.request_id))?;
        if pending != *request {
            self.reject_inspection(&pending);
            return Err(BrowserError::ArtifactInspectionInvalid);
        }
        if let Err(error) = request.validate() {
            self.reject_inspection(&pending);
            return Err(error);
        }
        if let Err(error) = result.validate() {
            self.reject_inspection(&pending);
            return Err(error);
        }
        if !result.matches_request(&pending) {
            self.reject_inspection(&pending);
            return Err(BrowserError::ArtifactInspectionInvalid);
        }
        if result.verdict != BrowserArtifactInspectionVerdict::Clean {
            self.reject_inspection(&pending);
            return Err(
                if result.verdict == BrowserArtifactInspectionVerdict::ScannerUnavailable {
                    BrowserError::ArtifactInspectionUnavailable
                } else {
                    BrowserError::ArtifactInspectionRejected
                },
            );
        }
        let adoption =
            match BrowserArtifactSafeForAdoption::from_result(self.provider_generation, result) {
                Ok(adoption) => adoption,
                Err(error) => {
                    self.reject_inspection(&pending);
                    return Err(error);
                }
            };
        self.pending_inspections.remove(&pending.request_id);
        self.completed_inspections
            .insert(pending.request_id.clone());
        self.completed_inspections
            .insert(pending.receipt_digest.clone());
        if self
            .safe_adoptions
            .insert(adoption.artifact_id.clone(), adoption.clone())
            .is_some()
        {
            return Err(BrowserError::ArtifactInspectionDuplicate);
        }
        Ok(adoption)
    }

    pub fn safe_for_adoption(
        &self,
        artifact_id: &str,
    ) -> Result<&BrowserArtifactSafeForAdoption, BrowserError> {
        self.ensure_mounted()?;
        self.safe_adoptions
            .get(artifact_id)
            .ok_or(BrowserError::ArtifactNotSafeForAdoption)
    }

    pub fn pending_inspection_count(&self) -> usize {
        self.pending_inspections.len()
    }

    pub fn safe_adoption_count(&self) -> usize {
        self.safe_adoptions.len()
    }

    fn ensure_mounted(&self) -> Result<(), BrowserError> {
        match self.state {
            BrowserArtifactProviderState::Mounted => Ok(()),
            BrowserArtifactProviderState::Revoked => Err(BrowserError::ArtifactProviderRevoked),
            BrowserArtifactProviderState::Restarted => Err(BrowserError::ArtifactProviderRestarted),
            BrowserArtifactProviderState::Invalidated => {
                Err(BrowserError::ArtifactProviderUnavailable)
            }
        }
    }

    fn invalidate(&mut self, error: BrowserError) -> BrowserError {
        self.state = BrowserArtifactProviderState::Invalidated;
        self.clear_inspection_state();
        error
    }

    fn host_failure(&mut self, error: BrowserError) -> BrowserError {
        if matches!(
            error,
            BrowserError::HostExited
                | BrowserError::HostRestarted
                | BrowserError::ProtocolPoisoned
                | BrowserError::ProtocolUnavailable
        ) {
            self.state = BrowserArtifactProviderState::Restarted;
            self.clear_inspection_state();
        } else if matches!(error, BrowserError::ArtifactFrameStale) {
            self.state = BrowserArtifactProviderState::Invalidated;
            self.clear_inspection_state();
        }
        error
    }

    fn reject_inspection(&mut self, request: &BrowserArtifactFileInspectionRequest) {
        self.pending_inspections.remove(&request.request_id);
        self.rejected_inspections.insert(request.request_id.clone());
        self.rejected_inspections
            .insert(request.receipt_digest.clone());
    }

    fn reopened_or_invalid_request(&self, request_id: &str) -> BrowserError {
        if self.rejected_inspections.contains(request_id)
            || self.completed_inspections.contains(request_id)
        {
            BrowserError::ArtifactInspectionReopened
        } else {
            BrowserError::ArtifactInspectionInvalid
        }
    }

    fn clear_inspection_state(&mut self) {
        self.pending_inspections.clear();
        self.safe_adoptions.clear();
    }
}

/// Explicit fail-closed native boundary used when the real Chrome download
/// transport is unavailable in the current environment.
#[derive(Debug, Default)]
pub struct UnavailableBrowserArtifactHost;

impl BrowserArtifactHost for UnavailableBrowserArtifactHost {
    fn observe_artifact_frame(
        &mut self,
        _scope: &BrowserArtifactScope,
        _now: DateTime<Utc>,
    ) -> Result<BrowserArtifactFrameRevision, BrowserError> {
        Err(BrowserError::ProtocolUnavailable)
    }

    fn capture_download(
        &mut self,
        _scope: &BrowserArtifactScope,
        _expected_frame: &BrowserArtifactFrameRevision,
        _artifact_id: &str,
        _now: DateTime<Utc>,
    ) -> Result<BrowserArtifactCapture, BrowserError> {
        Err(BrowserError::ProtocolUnavailable)
    }
}

fn canonical_source_identity(source_url: &str) -> Result<(String, String), BrowserError> {
    if source_url.is_empty()
        || source_url.len() > 32 * 1_024
        || source_url.trim() != source_url
        || source_url.chars().any(char::is_control)
    {
        return Err(BrowserError::InvalidArtifact);
    }
    let parsed = Url::parse(source_url).map_err(|_| BrowserError::InvalidArtifact)?;
    if parsed.scheme() != "https"
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(BrowserError::InvalidArtifact);
    }
    let canonical_url = parsed.to_string();
    let origin = parsed.origin();
    if !origin.is_tuple() {
        return Err(BrowserError::InvalidArtifact);
    }
    Ok((canonical_url, origin.ascii_serialization()))
}

fn valid_display_filename(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ARTIFACT_FILENAME_BYTES
        && value == value.trim()
        && !value.chars().any(char::is_control)
        && !value.contains('/')
        && !value.contains('\\')
        && value != "."
        && value != ".."
}

fn valid_media_type(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ARTIFACT_MEDIA_TYPE_BYTES
        && value == value.trim()
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        AccountId, BrowserControlLeaseId, BrowserProfileId, BrowserTabId, BrowserWorkspaceId,
        Mission, MissionContract, MissionId, Project, ProjectId, StorageMode, TenantId,
    };

    use super::*;
    use crate::{BrowserIdentity, BrowserProfile, BrowserWorkspace};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 8, 0, 0)
            .single()
            .expect("fixture time")
    }

    fn sha(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn fixture() -> (
        BrowserProfile,
        BrowserWorkspace,
        BrowserArtifactScope,
        BrowserArtifactFrameRevision,
    ) {
        let now = now();
        let project = Project::create_local(
            TenantId::from("tenant-artifact"),
            ProjectId::from("project-artifact"),
            "Artifact project",
            "",
            "/workspace/artifact",
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mission = Mission::compile(
            project.tenant_id.clone(),
            MissionId::from("mission-artifact"),
            project.id.clone(),
            "Artifact mission",
            MissionContract::bootstrap(
                "Capture one read-only artifact",
                ["browser.read".into()],
                now,
            ),
            now,
        )
        .expect("mission");
        let profile = BrowserProfile::create_managed(
            BrowserProfileId::from("profile-artifact"),
            &project,
            "keyring://artifact-profile",
            BrowserIdentity::new(
                "artifact-provider",
                AccountId::from("account-artifact"),
                sha('a'),
                sha('b'),
                now,
            )
            .expect("identity"),
            now,
        )
        .expect("profile");
        let workspace = BrowserWorkspace::create(
            BrowserWorkspaceId::from("workspace-artifact"),
            &project,
            &mission,
            &profile,
            BrowserTabId::from("tab-artifact"),
            BrowserControlLeaseId::from("lease-artifact"),
            now + Duration::hours(1),
            sha('c'),
            now,
        )
        .expect("workspace");
        let scope = BrowserArtifactScope::from_workspace(
            &profile,
            &workspace,
            BrowserTabId::from("tab-artifact"),
        )
        .expect("scope");
        let frame = BrowserArtifactFrameRevision::observed(
            &scope,
            &BrowserArtifactFrameObservation {
                session_id: "session-artifact".into(),
                frame_id: "frame-artifact".into(),
                loader_id: "loader-artifact".into(),
                navigation_revision: 1,
                document_generation: 1,
                url: "https://example.com/research/report.pdf".into(),
            },
        )
        .expect("frame")
        .with_lease_generation(workspace.lease_generation)
        .expect("lease frame");
        (profile, workspace, scope, frame)
    }

    struct FakeArtifactHost {
        frame: BrowserArtifactFrameRevision,
        capture: Option<BrowserArtifactCapture>,
        second_frame: Option<BrowserArtifactFrameRevision>,
        fail_closed: Option<BrowserError>,
    }

    impl BrowserArtifactHost for FakeArtifactHost {
        fn observe_artifact_frame(
            &mut self,
            _scope: &BrowserArtifactScope,
            _now: DateTime<Utc>,
        ) -> Result<BrowserArtifactFrameRevision, BrowserError> {
            if let Some(error) = self.fail_closed.take() {
                return Err(error);
            }
            Ok(self
                .second_frame
                .take()
                .unwrap_or_else(|| self.frame.clone()))
        }

        fn capture_download(
            &mut self,
            _scope: &BrowserArtifactScope,
            expected_frame: &BrowserArtifactFrameRevision,
            _artifact_id: &str,
            _now: DateTime<Utc>,
        ) -> Result<BrowserArtifactCapture, BrowserError> {
            if expected_frame != &self.frame {
                return Err(BrowserError::ArtifactFrameStale);
            }
            self.capture.take().ok_or(BrowserError::ProtocolUnavailable)
        }
    }

    fn capture(frame: BrowserArtifactFrameRevision, artifact_id: &str) -> BrowserArtifactCapture {
        BrowserArtifactCapture::new(BrowserArtifactCaptureInput {
            artifact_id: artifact_id.into(),
            frame,
            filename: "report.pdf".into(),
            media_type: "application/pdf".into(),
            source_url: "https://example.com/research/report.pdf".into(),
            source_origin: "https://example.com".into(),
            bytes: b"research evidence".to_vec(),
            observed_at: now(),
        })
        .expect("capture")
    }

    fn mounted_inspection_fixture(
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        scope: BrowserArtifactScope,
        frame: BrowserArtifactFrameRevision,
        artifact_id: &str,
    ) -> (
        BrowserArtifactPlugin,
        BrowserArtifactQuarantineReceipt,
        BrowserArtifactFileInspectionRequest,
    ) {
        let mut plugin = BrowserArtifactPlugin::mount(profile, workspace, scope).expect("mount");
        let mut host = FakeArtifactHost {
            frame: frame.clone(),
            capture: Some(capture(frame, artifact_id)),
            second_frame: None,
            fail_closed: None,
        };
        let proof = workspace.agent_lease_proof(now()).expect("lease");
        let receipt = plugin
            .capture_download(&mut host, profile, workspace, &proof, artifact_id, now())
            .expect("capture");
        let request = plugin
            .prepare_file_inspection(&receipt, now() + Duration::seconds(1))
            .expect("request");
        (plugin, receipt, request)
    }

    #[derive(Default)]
    struct Sink {
        receipts: Vec<BrowserArtifactQuarantineReceipt>,
    }

    impl BrowserArtifactResultSink for Sink {
        fn accept_quarantine_receipt(
            &mut self,
            receipt: &BrowserArtifactQuarantineReceipt,
        ) -> Result<(), BrowserError> {
            self.receipts.push(receipt.clone());
            Ok(())
        }
    }

    struct FakeInspector {
        verdict: BrowserArtifactInspectionVerdict,
        tamper_bytes: bool,
        tamper_frame_and_source: bool,
    }

    impl BrowserArtifactInspector for FakeInspector {
        fn inspect(
            &mut self,
            request: &BrowserArtifactFileInspectionRequest,
        ) -> Result<BrowserArtifactFileInspectionResult, BrowserError> {
            let mut result = BrowserArtifactFileInspectionResult::from_request(
                request,
                BrowserArtifactInspectionEvidence {
                    verdict: self.verdict,
                    inspector_id: "fake-inspector".into(),
                    inspector_version: "fixture-1".into(),
                    scanner_evidence_digest: sha('e'),
                    inspected_at: request.requested_at + Duration::seconds(1),
                },
            )?;
            if self.tamper_bytes {
                result.bytes_digest = sha('f');
            }
            if self.tamper_frame_and_source {
                let source_url = "https://example.com/research/other.pdf".to_owned();
                result.source_url = source_url.clone();
                result.source_origin = "https://example.com".into();
                result.frame = BrowserArtifactFrameRevision {
                    url_digest: digest(source_url.as_bytes()),
                    ..result.frame
                };
            }
            Ok(result)
        }
    }

    #[test]
    fn capture_creates_typed_receipt_with_exact_metadata_and_no_execution_authority() {
        let (profile, workspace, scope, frame) = fixture();
        let mut plugin = BrowserArtifactPlugin::mount(&profile, &workspace, scope).expect("mount");
        let mut host = FakeArtifactHost {
            frame: frame.clone(),
            capture: Some(capture(frame, "artifact-1")),
            second_frame: None,
            fail_closed: None,
        };
        let receipt = plugin
            .capture_download(
                &mut host,
                &profile,
                &workspace,
                &workspace.agent_lease_proof(now()).expect("lease"),
                "artifact-1",
                now(),
            )
            .expect("receipt");
        assert_eq!(receipt.byte_count, 17);
        assert_eq!(receipt.bytes_digest, digest(b"research evidence"));
        assert_eq!(receipt.media_type, "application/pdf");
        assert_eq!(
            receipt.source_url,
            "https://example.com/research/report.pdf"
        );
        assert_eq!(receipt.source_origin, "https://example.com");
        assert!(!receipt.opened);
        assert!(!receipt.execution_permitted);
        assert_eq!(plugin.result_log().entries.len(), 1);
        assert!(!format!("{receipt:?}").contains("research evidence"));
    }

    #[test]
    fn clean_file_inspection_exactly_matches_receipt_and_marks_safe_for_adoption() {
        let (profile, workspace, scope, frame) = fixture();
        let mut plugin = BrowserArtifactPlugin::mount(&profile, &workspace, scope).expect("mount");
        let mut host = FakeArtifactHost {
            frame: frame.clone(),
            capture: Some(capture(frame, "artifact-inspection-clean")),
            second_frame: None,
            fail_closed: None,
        };
        let proof = workspace.agent_lease_proof(now()).expect("lease");
        let receipt = plugin
            .capture_download(
                &mut host,
                &profile,
                &workspace,
                &proof,
                "artifact-inspection-clean",
                now(),
            )
            .expect("capture");
        let request = plugin
            .prepare_file_inspection(&receipt, now() + Duration::seconds(1))
            .expect("inspection request");
        assert_eq!(request.artifact_id, receipt.artifact_id);
        assert_eq!(
            request.receipt_digest,
            receipt.evidence_digest().expect("receipt digest")
        );
        assert_eq!(request.bytes_digest, receipt.bytes_digest);
        assert_eq!(request.media_type, receipt.media_type);
        assert_eq!(request.byte_count, receipt.byte_count);
        assert_eq!(request.source_url, receipt.source_url);
        assert_eq!(request.source_origin, receipt.source_origin);
        assert_eq!(request.frame, receipt.frame);
        assert_eq!(plugin.pending_inspection_count(), 1);
        assert!(matches!(
            plugin.prepare_file_inspection(&receipt, now() + Duration::seconds(2)),
            Err(BrowserError::ArtifactInspectionDuplicate)
        ));

        let mut inspector = FakeInspector {
            verdict: BrowserArtifactInspectionVerdict::Clean,
            tamper_bytes: false,
            tamper_frame_and_source: false,
        };
        let adoption = plugin
            .inspect_pending(&mut inspector, &request.request_id)
            .expect("safe adoption");
        assert_eq!(
            adoption.state,
            BrowserArtifactAdoptionState::SafeForAdoption
        );
        assert_eq!(adoption.receipt_digest, request.receipt_digest);
        assert_eq!(adoption.bytes_digest, receipt.bytes_digest);
        assert_eq!(adoption.byte_count, receipt.byte_count);
        assert_eq!(adoption.source_url, receipt.source_url);
        assert_eq!(adoption.frame, receipt.frame);
        assert!(!adoption.opened);
        assert!(!adoption.execution_permitted);
        assert_eq!(plugin.safe_adoption_count(), 1);
        assert_eq!(
            plugin
                .safe_for_adoption(&receipt.artifact_id)
                .expect("safe")
                .state,
            adoption.state
        );
        assert!(matches!(
            plugin.inspect_pending(&mut inspector, &request.request_id),
            Err(BrowserError::ArtifactInspectionReopened)
        ));
    }

    #[test]
    fn tampered_inspection_never_marks_safe_and_cannot_reopen() {
        let (profile, workspace, scope, frame) = fixture();
        let (mut plugin, _, request) = mounted_inspection_fixture(
            &profile,
            &workspace,
            scope,
            frame,
            "artifact-inspection-tamper",
        );
        let mut tampered = FakeInspector {
            verdict: BrowserArtifactInspectionVerdict::Clean,
            tamper_bytes: true,
            tamper_frame_and_source: false,
        };
        assert!(matches!(
            plugin.inspect_pending(&mut tampered, &request.request_id),
            Err(BrowserError::ArtifactInspectionInvalid)
        ));
        assert_eq!(plugin.pending_inspection_count(), 0);
        assert_eq!(plugin.safe_adoption_count(), 0);
        assert!(matches!(
            plugin.inspect_pending(&mut tampered, &request.request_id),
            Err(BrowserError::ArtifactInspectionReopened)
        ));
    }

    #[test]
    fn unknown_inspection_never_marks_safe() {
        let (profile, workspace, scope, frame) = fixture();
        let (mut plugin, _, request) = mounted_inspection_fixture(
            &profile,
            &workspace,
            scope,
            frame,
            "artifact-inspection-unknown",
        );
        let mut unknown = FakeInspector {
            verdict: BrowserArtifactInspectionVerdict::Unknown,
            tamper_bytes: false,
            tamper_frame_and_source: false,
        };
        assert!(matches!(
            plugin.inspect_pending(&mut unknown, &request.request_id),
            Err(BrowserError::ArtifactInspectionRejected)
        ));
        assert_eq!(plugin.safe_adoption_count(), 0);
    }

    #[test]
    fn malware_inspection_never_marks_safe() {
        let (profile, workspace, scope, frame) = fixture();
        let (mut plugin, _, request) = mounted_inspection_fixture(
            &profile,
            &workspace,
            scope,
            frame,
            "artifact-inspection-malware",
        );
        let mut malware = FakeInspector {
            verdict: BrowserArtifactInspectionVerdict::Malware,
            tamper_bytes: false,
            tamper_frame_and_source: false,
        };
        assert!(matches!(
            plugin.inspect_pending(&mut malware, &request.request_id),
            Err(BrowserError::ArtifactInspectionRejected)
        ));
        assert_eq!(plugin.safe_adoption_count(), 0);
    }

    #[test]
    fn unavailable_inspection_is_not_evaluated_and_cannot_reopen() {
        let (profile, workspace, scope, frame) = fixture();
        let (mut plugin, _, request) = mounted_inspection_fixture(
            &profile,
            &workspace,
            scope,
            frame,
            "artifact-inspection-unavailable",
        );
        let mut unavailable = UnavailableBrowserArtifactInspector;
        assert!(matches!(
            plugin.inspect_pending(&mut unavailable, &request.request_id),
            Err(BrowserError::ArtifactInspectionUnavailable)
        ));
        assert_eq!(plugin.pending_inspection_count(), 0);
        assert!(matches!(
            plugin.inspect_pending(&mut unavailable, &request.request_id),
            Err(BrowserError::ArtifactInspectionReopened)
        ));
    }

    #[test]
    fn scanner_unavailable_verdict_is_not_evaluated() {
        let (profile, workspace, scope, frame) = fixture();
        let (mut plugin, _, request) = mounted_inspection_fixture(
            &profile,
            &workspace,
            scope,
            frame,
            "artifact-inspection-not-evaluated",
        );
        let mut inspector = FakeInspector {
            verdict: BrowserArtifactInspectionVerdict::ScannerUnavailable,
            tamper_bytes: false,
            tamper_frame_and_source: false,
        };
        assert!(matches!(
            plugin.inspect_pending(&mut inspector, &request.request_id),
            Err(BrowserError::ArtifactInspectionUnavailable)
        ));
        assert_eq!(plugin.safe_adoption_count(), 0);
    }

    #[test]
    fn source_revision_mismatch_never_marks_safe() {
        let (profile, workspace, scope, frame) = fixture();
        let (mut plugin, _, request) = mounted_inspection_fixture(
            &profile,
            &workspace,
            scope,
            frame,
            "artifact-inspection-revision",
        );
        let mut inspector = FakeInspector {
            verdict: BrowserArtifactInspectionVerdict::Clean,
            tamper_bytes: false,
            tamper_frame_and_source: true,
        };
        assert!(matches!(
            plugin.inspect_pending(&mut inspector, &request.request_id),
            Err(BrowserError::ArtifactInspectionInvalid)
        ));
        assert_eq!(plugin.safe_adoption_count(), 0);
    }

    #[test]
    fn unmount_reclaims_pending_inspection_and_rejects_result() {
        let (profile, workspace, scope, frame) = fixture();
        let (mut plugin, _, request) = mounted_inspection_fixture(
            &profile,
            &workspace,
            scope,
            frame,
            "artifact-inspection-unmount",
        );
        assert_eq!(plugin.pending_inspection_count(), 1);
        plugin.unmount().expect("unmount");
        assert_eq!(plugin.pending_inspection_count(), 0);
        assert!(matches!(
            plugin.submit_file_inspection_result(
                &request,
                &BrowserArtifactFileInspectionResult::from_request(
                    &request,
                    BrowserArtifactInspectionEvidence {
                        verdict: BrowserArtifactInspectionVerdict::Clean,
                        inspector_id: "fake-inspector".into(),
                        inspector_version: "fixture-1".into(),
                        scanner_evidence_digest: sha('e'),
                        inspected_at: now() + Duration::seconds(2),
                    },
                )
                .expect("result"),
            ),
            Err(BrowserError::ArtifactProviderRestarted)
        ));
    }

    #[test]
    fn revoke_reclaims_pending_inspection_and_rejects_result() {
        let (mut profile, workspace, scope, frame) = fixture();
        let (mut plugin, _, request) = mounted_inspection_fixture(
            &profile,
            &workspace,
            scope,
            frame,
            "artifact-inspection-revoke",
        );
        let profile_revision = profile.revision;
        plugin
            .revoke(
                &mut profile,
                profile_revision,
                sha('d'),
                now() + Duration::seconds(1),
            )
            .expect("revoke");
        assert_eq!(plugin.pending_inspection_count(), 0);
        let mut unavailable = UnavailableBrowserArtifactInspector;
        assert!(matches!(
            plugin.inspect_pending(&mut unavailable, &request.request_id),
            Err(BrowserError::ArtifactProviderRevoked)
        ));
    }

    #[test]
    fn duplicate_capture_and_delivery_fail_closed_exactly_once() {
        let (profile, workspace, scope, frame) = fixture();
        let mut plugin = BrowserArtifactPlugin::mount(&profile, &workspace, scope).expect("mount");
        let mut host = FakeArtifactHost {
            frame: frame.clone(),
            capture: Some(capture(frame.clone(), "artifact-duplicate")),
            second_frame: None,
            fail_closed: None,
        };
        let proof = workspace.agent_lease_proof(now()).expect("lease");
        let receipt = plugin
            .capture_download(
                &mut host,
                &profile,
                &workspace,
                &proof,
                "artifact-duplicate",
                now(),
            )
            .expect("first capture");
        let mut duplicate_host = FakeArtifactHost {
            frame: frame.clone(),
            capture: Some(capture(frame, "artifact-duplicate")),
            second_frame: None,
            fail_closed: None,
        };
        assert!(matches!(
            plugin.capture_download(
                &mut duplicate_host,
                &profile,
                &workspace,
                &proof,
                "artifact-duplicate",
                now(),
            ),
            Err(BrowserError::ArtifactDuplicate)
        ));
        let mut sink = Sink::default();
        plugin
            .deliver_receipt(&receipt, &mut sink)
            .expect("delivery");
        assert!(matches!(
            plugin.deliver_receipt(&receipt, &mut sink),
            Err(BrowserError::ArtifactDuplicate)
        ));
        assert_eq!(sink.receipts.len(), 1);
    }

    #[test]
    fn redirect_or_frame_drift_invalidates_provider_before_quarantine() {
        let (profile, workspace, scope, frame) = fixture();
        let mut plugin = BrowserArtifactPlugin::mount(&profile, &workspace, scope).expect("mount");
        let mut redirected = capture(frame.clone(), "artifact-redirect");
        redirected.source_url = "https://example.net/research/report.pdf".into();
        redirected.source_origin = "https://example.net".into();
        let mut host = FakeArtifactHost {
            frame: frame.clone(),
            capture: Some(redirected),
            second_frame: None,
            fail_closed: None,
        };
        let proof = workspace.agent_lease_proof(now()).expect("lease");
        assert!(matches!(
            plugin.capture_download(
                &mut host,
                &profile,
                &workspace,
                &proof,
                "artifact-redirect",
                now()
            ),
            Err(BrowserError::InvalidArtifact)
        ));
        assert_eq!(plugin.state(), BrowserArtifactProviderState::Invalidated);

        let mut plugin = BrowserArtifactPlugin::mount(&profile, &workspace, plugin.scope().clone())
            .expect("remount for frame drift");
        let drifted = BrowserArtifactFrameRevision::observed(
            &plugin.scope().clone(),
            &BrowserArtifactFrameObservation {
                session_id: "session-artifact".into(),
                frame_id: "frame-artifact".into(),
                loader_id: "loader-drifted".into(),
                navigation_revision: 2,
                document_generation: 2,
                url: "https://example.com/research/new.pdf".into(),
            },
        )
        .expect("drifted frame")
        .with_lease_generation(workspace.lease_generation)
        .expect("drift lease");
        let mut host = FakeArtifactHost {
            frame: frame.clone(),
            capture: Some(capture(frame, "artifact-frame-drift")),
            second_frame: Some(drifted),
            fail_closed: None,
        };
        assert!(matches!(
            plugin.capture_download(
                &mut host,
                &profile,
                &workspace,
                &proof,
                "artifact-frame-drift",
                now(),
            ),
            Err(BrowserError::ArtifactFrameStale)
        ));
        assert_eq!(plugin.state(), BrowserArtifactProviderState::Invalidated);
    }

    #[test]
    fn cross_scope_and_filename_path_authority_are_rejected() {
        let (profile, workspace, scope, frame) = fixture();
        let mut plugin =
            BrowserArtifactPlugin::mount(&profile, &workspace, scope.clone()).expect("mount");
        let wrong_frame = BrowserArtifactFrameRevision {
            scope_digest: digest(b"other-mission"),
            ..frame.clone()
        };
        let mut host = FakeArtifactHost {
            frame: wrong_frame,
            capture: Some(capture(frame, "artifact-cross-scope")),
            second_frame: None,
            fail_closed: None,
        };
        let proof = workspace.agent_lease_proof(now()).expect("lease");
        assert!(matches!(
            plugin.capture_download(
                &mut host,
                &profile,
                &workspace,
                &proof,
                "artifact-cross-scope",
                now()
            ),
            Err(BrowserError::ArtifactFrameStale)
        ));
        assert!(
            BrowserArtifactCapture::new(BrowserArtifactCaptureInput {
                artifact_id: "artifact-path".into(),
                frame: BrowserArtifactFrameRevision::observed(
                    &scope,
                    &BrowserArtifactFrameObservation {
                        session_id: "session-artifact".into(),
                        frame_id: "frame-artifact".into(),
                        loader_id: "loader-artifact".into(),
                        navigation_revision: 1,
                        document_generation: 1,
                        url: "https://example.com/research/report.pdf".into(),
                    },
                )
                .expect("frame")
                .with_lease_generation(workspace.lease_generation)
                .expect("lease"),
                filename: "../report.pdf".into(),
                media_type: "application/pdf".into(),
                source_url: "https://example.com/research/report.pdf".into(),
                source_origin: "https://example.com".into(),
                bytes: b"bytes".to_vec(),
                observed_at: now(),
            })
            .is_err()
        );
    }

    #[test]
    fn restart_revoke_restore_and_unavailable_native_host_fail_closed() {
        let (profile, workspace, scope, frame) = fixture();
        let mut plugin =
            BrowserArtifactPlugin::mount(&profile, &workspace, scope.clone()).expect("mount");
        let mut host = FakeArtifactHost {
            frame: frame.clone(),
            capture: Some(capture(frame, "artifact-restart")),
            second_frame: None,
            fail_closed: None,
        };
        let proof = workspace.agent_lease_proof(now()).expect("lease");
        let receipt = plugin
            .capture_download(
                &mut host,
                &profile,
                &workspace,
                &proof,
                "artifact-restart",
                now(),
            )
            .expect("capture");
        let log = plugin.result_log().clone();
        plugin.restart().expect("restart");
        let mut sink = Sink::default();
        assert!(matches!(
            plugin.deliver_receipt(&receipt, &mut sink),
            Err(BrowserError::ArtifactProviderRestarted)
        ));
        let remounted = BrowserArtifactPlugin::remount(&profile, &workspace, scope.clone(), log)
            .expect("remount");
        assert_eq!(remounted.state(), BrowserArtifactProviderState::Mounted);
        let mut unavailable = UnavailableBrowserArtifactHost;
        let mut remounted = remounted;
        assert!(matches!(
            remounted.capture_download(
                &mut unavailable,
                &profile,
                &workspace,
                &proof,
                "artifact-new",
                now(),
            ),
            Err(BrowserError::ProtocolUnavailable)
        ));
        assert_eq!(remounted.state(), BrowserArtifactProviderState::Restarted);

        let mut profile = profile;
        let mut plugin = BrowserArtifactPlugin::mount(&profile, &workspace, scope).expect("mount");
        let profile_revision = profile.revision;
        plugin
            .revoke(
                &mut profile,
                profile_revision,
                sha('d'),
                now() + Duration::seconds(1),
            )
            .expect("revoke");
        assert!(matches!(
            plugin.restart(),
            Err(BrowserError::ArtifactProviderRevoked)
        ));
        assert!(matches!(
            plugin.capture_download(
                &mut unavailable,
                &profile,
                &workspace,
                &proof,
                "artifact-revoked",
                now() + Duration::seconds(1),
            ),
            Err(BrowserError::ArtifactProviderRevoked)
        ));
    }
}
