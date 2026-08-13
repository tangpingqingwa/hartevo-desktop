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
        } else if matches!(error, BrowserError::ArtifactFrameStale) {
            self.state = BrowserArtifactProviderState::Invalidated;
        }
        error
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
