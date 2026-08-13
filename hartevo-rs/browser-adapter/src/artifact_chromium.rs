//! Chromium-backed download transport for the Mission artifact quarantine.
//!
//! The service in this module is deliberately narrower than a browser file
//! API.  A caller supplies one immutable download identity and the provider
//! must prove that the CDP download, tab/frame lifecycle, profile, workspace,
//! and provider generation all match before bytes are read.  Native paths are
//! private implementation details and are removed before the operation
//! returns; no File Broker authority is created here.

use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{BrowserProfileId, BrowserWorkspaceId};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::artifact::{
    BrowserArtifactCapture, BrowserArtifactFrameRevision, BrowserArtifactHost,
    BrowserArtifactPlugin, BrowserArtifactProviderState, BrowserArtifactQuarantineReceipt,
    BrowserArtifactResultLog, BrowserArtifactResultSink, BrowserArtifactScope,
};
use crate::workspace::{digest, digest_json, is_bounded_identifier, is_sha256};
use crate::{
    BrowserError, BrowserLeaseProof, BrowserProfile, BrowserProfileStatus, BrowserWorkspace,
};

const DOWNLOAD_SCHEMA_VERSION: u32 = 1;
const MAX_DOWNLOAD_GUID_BYTES: usize = 4_096;
const MAX_BROWSER_CONTEXT_ID_BYTES: usize = 4_096;
const MAX_TARGET_ID_BYTES: usize = 4_096;
const MAX_SOURCE_URL_BYTES: usize = 32 * 1_024;

/// Immutable identity supplied by the Mission consumer for one expected CDP
/// download.  Raw GUID/context/target identifiers are accepted only by the
/// constructor and retained as digests, so they cannot become model-visible
/// authority or durable credentials.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserArtifactDownloadRequest {
    pub schema_version: u32,
    pub artifact_id: String,
    pub download_guid_digest: String,
    pub browser_context_digest: String,
    pub target_id_digest: String,
    pub profile_id: BrowserProfileId,
    pub profile_revision: u64,
    pub workspace_id: BrowserWorkspaceId,
    pub workspace_revision: u64,
    pub provider_generation: u64,
    pub frame: BrowserArtifactFrameRevision,
    pub expected_url: String,
    pub expected_origin: String,
}

/// Raw identity bundle used only while constructing a request through the
/// native provider. Raw GUID material is crate-visible only and is redacted
/// from Debug output.
pub struct BrowserArtifactDownloadDescriptor {
    pub(crate) artifact_id: String,
    pub(crate) download_guid: String,
    pub(crate) expected_url: String,
    pub(crate) expected_origin: String,
    pub(crate) provider_generation: u64,
}

impl BrowserArtifactDownloadDescriptor {
    pub fn new(
        artifact_id: impl Into<String>,
        download_guid: impl Into<String>,
        expected_url: impl Into<String>,
        expected_origin: impl Into<String>,
        provider_generation: u64,
    ) -> Self {
        Self {
            artifact_id: artifact_id.into(),
            download_guid: download_guid.into(),
            expected_url: expected_url.into(),
            expected_origin: expected_origin.into(),
            provider_generation,
        }
    }
}

impl fmt::Debug for BrowserArtifactDownloadDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserArtifactDownloadDescriptor")
            .field("artifact_id", &self.artifact_id)
            .field(
                "download_guid_digest",
                &digest(self.download_guid.as_bytes()),
            )
            .field("expected_url_digest", &digest(self.expected_url.as_bytes()))
            .field(
                "expected_origin_digest",
                &digest(self.expected_origin.as_bytes()),
            )
            .field("provider_generation", &self.provider_generation)
            .finish()
    }
}

impl BrowserArtifactDownloadRequest {
    /// Creates a request from the exact raw identity observed by the native
    /// transport. The raw download GUID and CDP identifiers are never kept in
    /// the request or its Debug/Serialize projection.
    pub fn new(
        scope: &BrowserArtifactScope,
        frame: BrowserArtifactFrameRevision,
        descriptor: &BrowserArtifactDownloadDescriptor,
        browser_context_id: &str,
        target_id: &str,
    ) -> Result<Self, BrowserError> {
        if descriptor.download_guid.is_empty()
            || descriptor.download_guid.len() > MAX_DOWNLOAD_GUID_BYTES
            || browser_context_id.is_empty()
            || browser_context_id.len() > MAX_BROWSER_CONTEXT_ID_BYTES
            || target_id.is_empty()
            || target_id.len() > MAX_TARGET_ID_BYTES
        {
            return Err(BrowserError::InvalidArtifact);
        }
        let request = Self {
            schema_version: DOWNLOAD_SCHEMA_VERSION,
            artifact_id: descriptor.artifact_id.clone(),
            download_guid_digest: digest(descriptor.download_guid.as_bytes()),
            browser_context_digest: digest(browser_context_id.as_bytes()),
            target_id_digest: digest(target_id.as_bytes()),
            profile_id: scope.profile_id.clone(),
            profile_revision: scope.profile_revision,
            workspace_id: scope.workspace_id.clone(),
            workspace_revision: scope.workspace_revision,
            provider_generation: descriptor.provider_generation,
            frame,
            expected_url: descriptor.expected_url.clone(),
            expected_origin: descriptor.expected_origin.clone(),
        };
        request.validate_for(scope, None, None, None)
    }

    /// Validates the immutable request against the mounted Mission scope.
    /// Optional profile/workspace/proof arguments let the service perform the
    /// stronger lease and lifecycle check without exposing raw identifiers.
    pub fn validate_for(
        &self,
        scope: &BrowserArtifactScope,
        profile: Option<&BrowserProfile>,
        workspace: Option<&BrowserWorkspace>,
        proof: Option<&BrowserLeaseProof>,
    ) -> Result<Self, BrowserError> {
        scope.validate()?;
        if self.schema_version != DOWNLOAD_SCHEMA_VERSION
            || !is_bounded_identifier(&self.artifact_id)
            || !is_sha256(&self.download_guid_digest)
            || !is_sha256(&self.browser_context_digest)
            || !is_sha256(&self.target_id_digest)
            || self.profile_id != scope.profile_id
            || self.profile_revision != scope.profile_revision
            || self.workspace_id != scope.workspace_id
            || self.workspace_revision != scope.workspace_revision
            || self.provider_generation == 0
            || self.frame.tab_id != scope.tab_id
            || self.frame.scope_digest != digest_json(scope)?
        {
            return Err(BrowserError::ArtifactScopeMismatch);
        }
        self.frame.validate()?;
        let (canonical_url, canonical_origin) = canonical_source_identity(&self.expected_url)?;
        if canonical_url != self.expected_url
            || canonical_origin != self.expected_origin
            || digest(self.expected_origin.as_bytes()) != self.frame.origin_digest
        {
            return Err(BrowserError::ArtifactFrameStale);
        }
        if let (Some(profile), Some(workspace), Some(proof)) = (profile, workspace, proof) {
            profile.validate()?;
            workspace.validate()?;
            if profile.status != BrowserProfileStatus::Active
                || profile.id != self.profile_id
                || profile.revision != self.profile_revision
                || workspace.id != self.workspace_id
                || workspace.revision != self.workspace_revision
                || workspace.profile_id != profile.id
                || workspace.expected_identity_digest != profile.identity.identity_digest
                || proof.workspace_id != workspace.id
                || proof.generation != workspace.lease_generation
            {
                return Err(BrowserError::ArtifactScopeMismatch);
            }
        } else if profile.is_some() || workspace.is_some() || proof.is_some() {
            return Err(BrowserError::ArtifactScopeMismatch);
        }
        Ok(self.clone())
    }
}

/// Provider contract used by [`BrowserArtifactCaptureService`].  `arm` must
/// configure a private quarantine destination and bind the exact request;
/// `cleanup` must remove every pending file/handler and is called on both
/// success and failure.
pub trait BrowserArtifactDownloadProvider: BrowserArtifactHost {
    fn arm_download(
        &mut self,
        scope: &BrowserArtifactScope,
        request: &BrowserArtifactDownloadRequest,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError>;

    fn cleanup_download(&mut self) -> Result<(), BrowserError>;
}

/// Mission-scoped consumer that projects a completed browser download into
/// the existing #194 quarantine receipt and durable result log.
#[derive(Clone, Debug)]
pub struct BrowserArtifactCaptureService {
    plugin: BrowserArtifactPlugin,
    pending_artifact_id: Option<String>,
}

impl BrowserArtifactCaptureService {
    pub fn mount(
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        scope: BrowserArtifactScope,
    ) -> Result<Self, BrowserError> {
        Ok(Self {
            plugin: BrowserArtifactPlugin::mount(profile, workspace, scope)?,
            pending_artifact_id: None,
        })
    }

    pub fn remount(
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        scope: BrowserArtifactScope,
        log: BrowserArtifactResultLog,
    ) -> Result<Self, BrowserError> {
        Ok(Self {
            plugin: BrowserArtifactPlugin::remount(profile, workspace, scope, log)?,
            pending_artifact_id: None,
        })
    }

    pub fn scope(&self) -> &BrowserArtifactScope {
        self.plugin.scope()
    }

    pub fn state(&self) -> BrowserArtifactProviderState {
        self.plugin.state()
    }

    pub fn provider_generation(&self) -> u64 {
        self.plugin.result_log().provider_generation
    }

    pub fn result_log(&self) -> &BrowserArtifactResultLog {
        self.plugin.result_log()
    }

    /// Arms one provider request, captures it through the existing exact
    /// frame fence, and always asks the provider to remove its temporary
    /// state before returning.
    pub fn capture_download<P: BrowserArtifactDownloadProvider>(
        &mut self,
        provider: &mut P,
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        proof: &BrowserLeaseProof,
        request: &BrowserArtifactDownloadRequest,
        now: DateTime<Utc>,
    ) -> Result<BrowserArtifactQuarantineReceipt, BrowserError> {
        if self.pending_artifact_id.is_some() {
            return Err(BrowserError::ArtifactDuplicate);
        }
        if request.provider_generation != self.provider_generation() {
            return Err(BrowserError::ArtifactProviderRestarted);
        }
        request.validate_for(self.scope(), Some(profile), Some(workspace), Some(proof))?;
        workspace.validate_agent_lease(proof, now)?;
        self.pending_artifact_id = Some(request.artifact_id.clone());
        let armed = provider.arm_download(self.scope(), request, now);
        let result = match armed {
            Ok(()) => self.plugin.capture_download(
                provider,
                profile,
                workspace,
                proof,
                &request.artifact_id,
                now,
            ),
            Err(error) => Err(error),
        };
        let cleanup = provider.cleanup_download();
        self.pending_artifact_id = None;
        match (result, cleanup) {
            (Ok(receipt), Ok(())) => Ok(receipt),
            (Err(error), Ok(())) | (_, Err(error)) => Err(error),
        }
    }

    /// Cancels an in-flight provider and fences the service cursor.  A late
    /// completion cannot be associated with a future generation.
    pub fn restart<P: BrowserArtifactDownloadProvider>(
        &mut self,
        provider: &mut P,
    ) -> Result<(), BrowserError> {
        provider.cleanup_download()?;
        self.pending_artifact_id = None;
        self.plugin.restart()
    }

    pub fn revoke<P: BrowserArtifactDownloadProvider>(
        &mut self,
        provider: &mut P,
        profile: &mut BrowserProfile,
        expected_revision: u64,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        provider.cleanup_download()?;
        self.pending_artifact_id = None;
        self.plugin
            .revoke(profile, expected_revision, evidence_digest, now)
    }

    pub fn deliver_receipt<S: BrowserArtifactResultSink>(
        &mut self,
        receipt: &BrowserArtifactQuarantineReceipt,
        sink: &mut S,
    ) -> Result<(), BrowserError> {
        self.plugin.deliver_receipt(receipt, sink)
    }
}

#[cfg(unix)]
pub use chromium_transport::ChromiumArtifactDownloadTransport;

#[cfg(unix)]
mod chromium_transport {
    use std::fmt;

    use super::{
        BrowserArtifactCapture, BrowserArtifactDownloadDescriptor, BrowserArtifactDownloadProvider,
        BrowserArtifactDownloadRequest, BrowserArtifactFrameRevision, BrowserArtifactHost,
        BrowserArtifactScope,
    };
    use crate::BrowserError;
    use crate::chromium_host::ManagedChromiumHost;
    use chrono::{DateTime, Utc};

    /// Real Chromium CDP provider.  It deliberately exposes only the typed
    /// provider trait; the host's temporary path and raw CDP identifiers stay
    /// inside the native transport.
    pub struct ChromiumArtifactDownloadTransport<'a> {
        host: &'a mut ManagedChromiumHost,
    }

    impl<'a> ChromiumArtifactDownloadTransport<'a> {
        pub fn new(host: &'a mut ManagedChromiumHost) -> Self {
            Self { host }
        }

        pub fn request_for_download(
            &mut self,
            scope: &BrowserArtifactScope,
            frame: &BrowserArtifactFrameRevision,
            descriptor: &BrowserArtifactDownloadDescriptor,
            now: DateTime<Utc>,
        ) -> Result<BrowserArtifactDownloadRequest, BrowserError> {
            self.host
                .browser_artifact_build_request(scope, frame, descriptor, now)
        }
    }

    impl fmt::Debug for ChromiumArtifactDownloadTransport<'_> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("ChromiumArtifactDownloadTransport")
                .finish_non_exhaustive()
        }
    }

    impl BrowserArtifactHost for ChromiumArtifactDownloadTransport<'_> {
        fn observe_artifact_frame(
            &mut self,
            scope: &BrowserArtifactScope,
            now: DateTime<Utc>,
        ) -> Result<BrowserArtifactFrameRevision, BrowserError> {
            self.host.browser_artifact_observe_frame(scope, now)
        }

        fn capture_download(
            &mut self,
            scope: &BrowserArtifactScope,
            expected_frame: &BrowserArtifactFrameRevision,
            artifact_id: &str,
            now: DateTime<Utc>,
        ) -> Result<BrowserArtifactCapture, BrowserError> {
            self.host
                .browser_artifact_capture_download(scope, expected_frame, artifact_id, now)
        }
    }

    impl BrowserArtifactDownloadProvider for ChromiumArtifactDownloadTransport<'_> {
        fn arm_download(
            &mut self,
            scope: &BrowserArtifactScope,
            request: &BrowserArtifactDownloadRequest,
            now: DateTime<Utc>,
        ) -> Result<(), BrowserError> {
            self.host.browser_artifact_arm_download(scope, request, now)
        }

        fn cleanup_download(&mut self) -> Result<(), BrowserError> {
            self.host.browser_artifact_cleanup_download()
        }
    }
}

fn canonical_source_identity(source_url: &str) -> Result<(String, String), BrowserError> {
    if source_url.is_empty()
        || source_url.len() > MAX_SOURCE_URL_BYTES
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        AccountId, BrowserControlLeaseId, BrowserProfileId, BrowserTabId, BrowserWorkspaceId,
        Mission, MissionContract, MissionId, Project, ProjectId, StorageMode, TenantId,
    };

    use super::*;
    use crate::{BrowserArtifactCaptureInput, BrowserIdentity};

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
        BrowserLeaseProof,
    ) {
        let at = now();
        let project = Project::create_local(
            TenantId::from("tenant-download"),
            ProjectId::from("project-download"),
            "Download project",
            "",
            "/workspace/download",
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mission = Mission::compile(
            project.tenant_id.clone(),
            MissionId::from("mission-download"),
            project.id.clone(),
            "Download mission",
            MissionContract::bootstrap("Capture one artifact", BTreeSet::new(), at),
            at,
        )
        .expect("mission");
        let profile = BrowserProfile::create_managed(
            BrowserProfileId::from("profile-download"),
            &project,
            "keyring://download-profile",
            BrowserIdentity::new(
                "chromium",
                AccountId::from("account-download"),
                sha('a'),
                sha('b'),
                at,
            )
            .expect("identity"),
            at,
        )
        .expect("profile");
        let workspace = BrowserWorkspace::create(
            BrowserWorkspaceId::from("workspace-download"),
            &project,
            &mission,
            &profile,
            BrowserTabId::from("tab-download"),
            BrowserControlLeaseId::from("lease-download"),
            at + Duration::hours(1),
            sha('c'),
            at,
        )
        .expect("workspace");
        let scope = BrowserArtifactScope::from_workspace(
            &profile,
            &workspace,
            BrowserTabId::from("tab-download"),
        )
        .expect("scope");
        let frame = BrowserArtifactFrameRevision::observed(
            &scope,
            &crate::BrowserArtifactFrameObservation {
                session_id: "session-download".into(),
                frame_id: "frame-download".into(),
                loader_id: "loader-download".into(),
                navigation_revision: 1,
                document_generation: 1,
                url: "https://example.com/download/report.pdf".into(),
            },
        )
        .expect("frame")
        .with_lease_generation(workspace.lease_generation)
        .expect("lease frame");
        let proof = workspace.agent_lease_proof(at).expect("proof");
        (profile, workspace, scope, frame, proof)
    }

    struct FakeDownloadProvider {
        frame: BrowserArtifactFrameRevision,
        request: Option<BrowserArtifactDownloadRequest>,
        expected_guid_digest: String,
        drift: bool,
        cleanup_count: u32,
    }

    impl BrowserArtifactHost for FakeDownloadProvider {
        fn observe_artifact_frame(
            &mut self,
            _scope: &BrowserArtifactScope,
            _now: DateTime<Utc>,
        ) -> Result<BrowserArtifactFrameRevision, BrowserError> {
            Ok(self.frame.clone())
        }

        fn capture_download(
            &mut self,
            _scope: &BrowserArtifactScope,
            expected_frame: &BrowserArtifactFrameRevision,
            artifact_id: &str,
            at: DateTime<Utc>,
        ) -> Result<BrowserArtifactCapture, BrowserError> {
            let request = self
                .request
                .take()
                .ok_or(BrowserError::ProtocolUnavailable)?;
            if request.artifact_id != artifact_id || request.frame != *expected_frame {
                return Err(BrowserError::ArtifactFrameStale);
            }
            let frame = if self.drift {
                let mut changed = self.frame.clone();
                changed.navigation_revision += 1;
                changed
            } else {
                self.frame.clone()
            };
            BrowserArtifactCapture::new(BrowserArtifactCaptureInput {
                artifact_id: artifact_id.into(),
                frame,
                filename: "report.pdf".into(),
                media_type: "application/pdf".into(),
                source_url: request.expected_url,
                source_origin: request.expected_origin,
                bytes: b"deterministic evidence".to_vec(),
                observed_at: at,
            })
        }
    }

    impl BrowserArtifactDownloadProvider for FakeDownloadProvider {
        fn arm_download(
            &mut self,
            _scope: &BrowserArtifactScope,
            request: &BrowserArtifactDownloadRequest,
            _now: DateTime<Utc>,
        ) -> Result<(), BrowserError> {
            if request.download_guid_digest != self.expected_guid_digest {
                return Err(BrowserError::ArtifactScopeMismatch);
            }
            if self.request.is_some() {
                return Err(BrowserError::ArtifactDuplicate);
            }
            self.request = Some(request.clone());
            Ok(())
        }

        fn cleanup_download(&mut self) -> Result<(), BrowserError> {
            self.request = None;
            self.cleanup_count += 1;
            Ok(())
        }
    }

    #[test]
    fn service_projects_exact_download_into_quarantine_without_authority() {
        let (profile, workspace, scope, frame, proof) = fixture();
        let mut service = BrowserArtifactCaptureService::mount(&profile, &workspace, scope.clone())
            .expect("mount");
        let mut provider = FakeDownloadProvider {
            frame: frame.clone(),
            request: None,
            expected_guid_digest: digest(b"guid-1"),
            drift: false,
            cleanup_count: 0,
        };
        let descriptor = BrowserArtifactDownloadDescriptor::new(
            "artifact-download-1",
            "guid-1",
            "https://example.com/download/report.pdf",
            "https://example.com",
            service.provider_generation(),
        );
        let request = BrowserArtifactDownloadRequest::new(
            &scope,
            frame,
            &descriptor,
            "context-1",
            "target-1",
        )
        .expect("request");
        let receipt = service
            .capture_download(&mut provider, &profile, &workspace, &proof, &request, now())
            .expect("capture");
        assert!(!receipt.opened);
        assert!(!receipt.execution_permitted);
        assert_eq!(receipt.byte_count, b"deterministic evidence".len() as u64);
        assert_eq!(service.result_log().entries.len(), 1);
        assert_eq!(provider.cleanup_count, 1);
        assert!(provider.request.is_none());
    }

    #[test]
    fn download_url_is_exact_without_requiring_page_url_equality() {
        let (profile, workspace, scope, original_frame, proof) = fixture();
        let page_frame = BrowserArtifactFrameRevision::observed(
            &scope,
            &crate::BrowserArtifactFrameObservation {
                session_id: "session-download".into(),
                frame_id: "frame-download".into(),
                loader_id: "loader-download".into(),
                navigation_revision: 2,
                document_generation: 2,
                url: "https://example.com/research/index.html".into(),
            },
        )
        .expect("page frame")
        .with_lease_generation(workspace.lease_generation)
        .expect("lease frame");
        let mut service = BrowserArtifactCaptureService::mount(&profile, &workspace, scope.clone())
            .expect("mount");
        let mut provider = FakeDownloadProvider {
            frame: page_frame.clone(),
            request: None,
            expected_guid_digest: digest(b"guid-page-link"),
            drift: false,
            cleanup_count: 0,
        };
        let descriptor = BrowserArtifactDownloadDescriptor::new(
            "artifact-page-link",
            "guid-page-link",
            "https://example.com/download/report.pdf",
            "https://example.com",
            service.provider_generation(),
        );
        let request = BrowserArtifactDownloadRequest::new(
            &scope,
            page_frame,
            &descriptor,
            "context-1",
            "target-1",
        )
        .expect("request");
        let receipt = service
            .capture_download(&mut provider, &profile, &workspace, &proof, &request, now())
            .expect("capture");
        assert_eq!(
            receipt.source_url,
            "https://example.com/download/report.pdf"
        );
        assert_ne!(
            receipt.frame.url_digest,
            digest(receipt.source_url.as_bytes())
        );
        assert_ne!(receipt.frame.url_digest, original_frame.url_digest);
    }

    #[test]
    fn guid_mismatch_and_frame_drift_fail_closed_and_cleanup() {
        let (profile, workspace, scope, frame, proof) = fixture();
        let mut service = BrowserArtifactCaptureService::mount(&profile, &workspace, scope.clone())
            .expect("mount");
        let mut provider = FakeDownloadProvider {
            frame: frame.clone(),
            request: None,
            expected_guid_digest: digest(b"different-guid"),
            drift: false,
            cleanup_count: 0,
        };
        let descriptor = BrowserArtifactDownloadDescriptor::new(
            "artifact-download-2",
            "guid-2",
            "https://example.com/download/report.pdf",
            "https://example.com",
            service.provider_generation(),
        );
        let request = BrowserArtifactDownloadRequest::new(
            &scope,
            frame.clone(),
            &descriptor,
            "context-1",
            "target-1",
        )
        .expect("request");
        assert!(matches!(
            service
                .capture_download(&mut provider, &profile, &workspace, &proof, &request, now(),)
                .expect_err("GUID mismatch"),
            BrowserError::ArtifactScopeMismatch
        ));
        assert_eq!(provider.cleanup_count, 1);

        provider.expected_guid_digest = digest(b"guid-3");
        provider.drift = true;
        let descriptor = BrowserArtifactDownloadDescriptor::new(
            "artifact-download-3",
            "guid-3",
            "https://example.com/download/report.pdf",
            "https://example.com",
            service.provider_generation(),
        );
        let request = BrowserArtifactDownloadRequest::new(
            &scope,
            frame,
            &descriptor,
            "context-1",
            "target-1",
        )
        .expect("request");
        assert!(matches!(
            service
                .capture_download(&mut provider, &profile, &workspace, &proof, &request, now(),)
                .expect_err("frame drift"),
            BrowserError::ArtifactFrameStale
        ));
        assert_eq!(provider.cleanup_count, 2);
        assert_eq!(service.state(), BrowserArtifactProviderState::Invalidated);
    }

    #[test]
    fn restart_and_revoke_cancel_pending_cursor_before_late_completion() {
        let (mut profile, workspace, scope, frame, proof) = fixture();
        let mut service = BrowserArtifactCaptureService::mount(&profile, &workspace, scope.clone())
            .expect("mount");
        let mut provider = FakeDownloadProvider {
            frame: frame.clone(),
            request: None,
            expected_guid_digest: digest(b"guid-4"),
            drift: false,
            cleanup_count: 0,
        };
        let descriptor = BrowserArtifactDownloadDescriptor::new(
            "artifact-download-4",
            "guid-4",
            "https://example.com/download/report.pdf",
            "https://example.com",
            service.provider_generation(),
        );
        let request = BrowserArtifactDownloadRequest::new(
            &scope,
            frame,
            &descriptor,
            "context-1",
            "target-1",
        )
        .expect("request");
        provider
            .arm_download(&scope, &request, now())
            .expect("arm pending");
        service.restart(&mut provider).expect("restart");
        assert_eq!(service.state(), BrowserArtifactProviderState::Restarted);
        assert!(provider.request.is_none());
        assert!(matches!(
            service
                .capture_download(&mut provider, &profile, &workspace, &proof, &request, now(),)
                .expect_err("old cursor"),
            BrowserError::ArtifactProviderRestarted
        ));
        // The profile revision mismatch is checked before any provider arm.
        let evidence = digest(b"revoke");
        let revision = profile.revision;
        assert!(
            service
                .revoke(&mut provider, &mut profile, revision, evidence, now())
                .is_err()
        );
    }
}
