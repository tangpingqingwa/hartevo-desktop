use std::fmt;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    BrowserProfileId, BrowserTabId, BrowserWorkspaceId, MissionId, ProjectId,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::read_observation::BrowserReadObservationMedia;
use crate::workspace::{digest, digest_json, is_bounded_identifier, is_sha256};
use crate::{BrowserError, BrowserWorkspace};

const VISUAL_OBSERVATION_SCHEMA_VERSION: u32 = 1;
const PROTOCOL_OBSERVATION_SCHEMA_VERSION: u32 = 1;
const MAX_VISUAL_BYTES: usize = 8 * 1_024 * 1_024;
const MAX_VIEWPORT_DIMENSION: u32 = 100_000;
const VISUAL_RETENTION_POLICY: &str = "hartevo-browser-visual-transient-png-v1";

/// The only protocol fallback currently exposed by the adapter. Callers get
/// typed layout metadata, never an arbitrary CDP method or raw response.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserProtocolProbeKind {
    LayoutMetrics,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BrowserLayoutMetrics {
    pub visual_width: u32,
    pub visual_height: u32,
    pub content_width: u32,
    pub content_height: u32,
}

/// A content-free, scope-bound result of the allowlisted layout protocol
/// probe. It exists to explain a fallback decision, not to authorize input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserProtocolObservation {
    pub schema_version: u32,
    pub workspace_id: BrowserWorkspaceId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub profile_id: BrowserProfileId,
    pub identity_digest: String,
    pub tab_id: BrowserTabId,
    pub lease_generation: u64,
    pub document_generation: u64,
    pub url_digest: String,
    pub origin_digest: String,
    pub frame_id_digest: String,
    pub loader_id_digest: String,
    pub execution_context_id_digest: String,
    pub execution_context_generation: u64,
    pub observed_at: DateTime<Utc>,
    pub probe: BrowserProtocolProbeKind,
    pub viewport_width: u32,
    pub viewport_height: u32,
    pub content_width: u32,
    pub content_height: u32,
    pub observation_digest: String,
}

impl BrowserProtocolObservation {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_layout_metrics(
        workspace: &BrowserWorkspace,
        tab_id: BrowserTabId,
        document_generation: u64,
        url_digest: String,
        origin_digest: String,
        frame_id: &str,
        loader_id: &str,
        execution_context_id: &str,
        execution_context_generation: u64,
        metrics: BrowserLayoutMetrics,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        workspace.validate()?;
        if !workspace.tabs.contains(&tab_id) {
            return Err(BrowserError::ScopeMismatch);
        }
        let mut observation = Self {
            schema_version: PROTOCOL_OBSERVATION_SCHEMA_VERSION,
            workspace_id: workspace.id.clone(),
            project_id: workspace.project_id.clone(),
            mission_id: workspace.mission_id.clone(),
            profile_id: workspace.profile_id.clone(),
            identity_digest: workspace.expected_identity_digest.clone(),
            tab_id,
            lease_generation: workspace.lease_generation,
            document_generation,
            url_digest,
            origin_digest,
            frame_id_digest: digest(frame_id.as_bytes()),
            loader_id_digest: digest(loader_id.as_bytes()),
            execution_context_id_digest: digest(execution_context_id.as_bytes()),
            execution_context_generation,
            observed_at,
            probe: BrowserProtocolProbeKind::LayoutMetrics,
            viewport_width: metrics.visual_width,
            viewport_height: metrics.visual_height,
            content_width: metrics.content_width,
            content_height: metrics.content_height,
            observation_digest: String::new(),
        };
        observation.observation_digest = observation.compute_observation_digest()?;
        observation.validate_for(workspace)?;
        Ok(observation)
    }

    pub fn validate_for(&self, workspace: &BrowserWorkspace) -> Result<(), BrowserError> {
        workspace.validate()?;
        if self.schema_version != PROTOCOL_OBSERVATION_SCHEMA_VERSION
            || self.workspace_id != workspace.id
            || self.project_id != workspace.project_id
            || self.mission_id != workspace.mission_id
            || self.profile_id != workspace.profile_id
            || self.identity_digest != workspace.expected_identity_digest
            || !workspace.tabs.contains(&self.tab_id)
            || self.lease_generation != workspace.lease_generation
            || self.document_generation == 0
            || !is_bounded_identifier(self.tab_id.as_str())
            || !is_sha256(&self.identity_digest)
            || !is_sha256(&self.url_digest)
            || !is_sha256(&self.origin_digest)
            || !is_sha256(&self.frame_id_digest)
            || !is_sha256(&self.loader_id_digest)
            || !is_sha256(&self.execution_context_id_digest)
            || self.execution_context_generation == 0
            || !valid_dimension(self.viewport_width)
            || !valid_dimension(self.viewport_height)
            || !valid_dimension(self.content_width)
            || !valid_dimension(self.content_height)
            || self.content_width < self.viewport_width
            || self.content_height < self.viewport_height
            || self.probe != BrowserProtocolProbeKind::LayoutMetrics
            || !is_sha256(&self.observation_digest)
            || self.observation_digest != self.compute_observation_digest()?
        {
            return Err(BrowserError::InvalidProtocolObservation);
        }
        Ok(())
    }

    pub fn evidence_digest(&self) -> Result<String, BrowserError> {
        self.validate_for_scope()?;
        Ok(self.observation_digest.clone())
    }

    fn validate_for_scope(&self) -> Result<(), BrowserError> {
        if self.schema_version != PROTOCOL_OBSERVATION_SCHEMA_VERSION
            || !is_sha256(&self.observation_digest)
            || self.observation_digest != self.compute_observation_digest()?
        {
            return Err(BrowserError::InvalidProtocolObservation);
        }
        Ok(())
    }

    fn compute_observation_digest(&self) -> Result<String, BrowserError> {
        digest_json(&json!({
            "schemaVersion": self.schema_version,
            "workspaceId": self.workspace_id,
            "projectId": self.project_id,
            "missionId": self.mission_id,
            "profileId": self.profile_id,
            "identityDigest": self.identity_digest,
            "tabId": self.tab_id,
            "leaseGeneration": self.lease_generation,
            "documentGeneration": self.document_generation,
            "urlDigest": self.url_digest,
            "originDigest": self.origin_digest,
            "frameIdDigest": self.frame_id_digest,
            "loaderIdDigest": self.loader_id_digest,
            "executionContextIdDigest": self.execution_context_id_digest,
            "executionContextGeneration": self.execution_context_generation,
            "observedAt": self.observed_at,
            "probe": self.probe,
            "viewportWidth": self.viewport_width,
            "viewportHeight": self.viewport_height,
            "contentWidth": self.content_width,
            "contentHeight": self.content_height,
        }))
    }
}

/// Durable metadata for a screenshot whose pixels are held only in a
/// zeroizing transient buffer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserVisualObservationMetadata {
    pub schema_version: u32,
    pub workspace_id: BrowserWorkspaceId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub profile_id: BrowserProfileId,
    pub identity_digest: String,
    pub tab_id: BrowserTabId,
    pub lease_generation: u64,
    pub document_generation: u64,
    pub url_digest: String,
    pub origin_digest: String,
    pub frame_id_digest: String,
    pub loader_id_digest: String,
    pub execution_context_id_digest: String,
    pub execution_context_generation: u64,
    pub viewport_width: u32,
    pub viewport_height: u32,
    pub observed_at: DateTime<Utc>,
    pub media_type: BrowserReadObservationMedia,
    pub byte_count: u64,
    pub canonical_content_digest: String,
    pub retention_policy_digest: String,
    pub observation_digest: String,
}

impl BrowserVisualObservationMetadata {
    #[allow(clippy::too_many_arguments)]
    fn from_captured(
        workspace: &BrowserWorkspace,
        tab_id: BrowserTabId,
        document_generation: u64,
        url_digest: String,
        origin_digest: String,
        frame_id: &str,
        loader_id: &str,
        execution_context_id: &str,
        execution_context_generation: u64,
        metrics: BrowserLayoutMetrics,
        image: &[u8],
        observed_at: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        let byte_count =
            u64::try_from(image.len()).map_err(|_| BrowserError::VisualObservationImageInvalid)?;
        if image.is_empty() || image.len() > MAX_VISUAL_BYTES {
            return Err(BrowserError::VisualObservationImageInvalid);
        }
        let mut metadata = Self {
            schema_version: VISUAL_OBSERVATION_SCHEMA_VERSION,
            workspace_id: workspace.id.clone(),
            project_id: workspace.project_id.clone(),
            mission_id: workspace.mission_id.clone(),
            profile_id: workspace.profile_id.clone(),
            identity_digest: workspace.expected_identity_digest.clone(),
            tab_id,
            lease_generation: workspace.lease_generation,
            document_generation,
            url_digest,
            origin_digest,
            frame_id_digest: digest(frame_id.as_bytes()),
            loader_id_digest: digest(loader_id.as_bytes()),
            execution_context_id_digest: digest(execution_context_id.as_bytes()),
            execution_context_generation,
            viewport_width: metrics.visual_width,
            viewport_height: metrics.visual_height,
            observed_at,
            media_type: BrowserReadObservationMedia::new("image/png")?,
            byte_count,
            canonical_content_digest: digest(image),
            retention_policy_digest: digest(VISUAL_RETENTION_POLICY.as_bytes()),
            observation_digest: String::new(),
        };
        metadata.observation_digest = metadata.compute_observation_digest()?;
        metadata.validate_for(workspace, image)?;
        Ok(metadata)
    }

    pub fn validate_for(
        &self,
        workspace: &BrowserWorkspace,
        image: &[u8],
    ) -> Result<(), BrowserError> {
        workspace.validate()?;
        if self.schema_version != VISUAL_OBSERVATION_SCHEMA_VERSION
            || self.workspace_id != workspace.id
            || self.project_id != workspace.project_id
            || self.mission_id != workspace.mission_id
            || self.profile_id != workspace.profile_id
            || self.identity_digest != workspace.expected_identity_digest
            || !workspace.tabs.contains(&self.tab_id)
            || self.lease_generation != workspace.lease_generation
            || self.document_generation == 0
            || !is_bounded_identifier(self.tab_id.as_str())
            || !is_sha256(&self.identity_digest)
            || !is_sha256(&self.url_digest)
            || !is_sha256(&self.origin_digest)
            || !is_sha256(&self.frame_id_digest)
            || !is_sha256(&self.loader_id_digest)
            || !is_sha256(&self.execution_context_id_digest)
            || self.execution_context_generation == 0
            || !valid_dimension(self.viewport_width)
            || !valid_dimension(self.viewport_height)
            || self.media_type.as_str() != "image/png"
            || self.byte_count == 0
            || self.byte_count > MAX_VISUAL_BYTES as u64
            || u64::try_from(image.len()).ok() != Some(self.byte_count)
            || self.canonical_content_digest != digest(image)
            || self.retention_policy_digest != digest(VISUAL_RETENTION_POLICY.as_bytes())
            || !is_sha256(&self.observation_digest)
            || self.observation_digest != self.compute_observation_digest()?
        {
            return Err(BrowserError::InvalidVisualObservation);
        }
        Ok(())
    }

    pub fn evidence_digest(&self) -> Result<String, BrowserError> {
        if self.schema_version != VISUAL_OBSERVATION_SCHEMA_VERSION
            || !is_sha256(&self.observation_digest)
            || self.observation_digest != self.compute_observation_digest()?
        {
            return Err(BrowserError::InvalidVisualObservation);
        }
        Ok(self.observation_digest.clone())
    }

    fn compute_observation_digest(&self) -> Result<String, BrowserError> {
        digest_json(&json!({
            "schemaVersion": self.schema_version,
            "workspaceId": self.workspace_id,
            "projectId": self.project_id,
            "missionId": self.mission_id,
            "profileId": self.profile_id,
            "identityDigest": self.identity_digest,
            "tabId": self.tab_id,
            "leaseGeneration": self.lease_generation,
            "documentGeneration": self.document_generation,
            "urlDigest": self.url_digest,
            "originDigest": self.origin_digest,
            "frameIdDigest": self.frame_id_digest,
            "loaderIdDigest": self.loader_id_digest,
            "executionContextIdDigest": self.execution_context_id_digest,
            "executionContextGeneration": self.execution_context_generation,
            "viewportWidth": self.viewport_width,
            "viewportHeight": self.viewport_height,
            "observedAt": self.observed_at,
            "mediaType": self.media_type,
            "byteCount": self.byte_count,
            "canonicalContentDigest": self.canonical_content_digest,
            "retentionPolicyDigest": self.retention_policy_digest,
        }))
    }
}

/// A visual observation keeps pixels transiently available to a caller that
/// explicitly needs the visual fallback. No serde implementation includes the
/// image, and dropping or consuming the value zeroizes the pixel buffer.
pub struct BrowserVisualObservation {
    metadata: BrowserVisualObservationMetadata,
    image: Zeroizing<Vec<u8>>,
}

impl BrowserVisualObservation {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_captured(
        workspace: &BrowserWorkspace,
        tab_id: BrowserTabId,
        document_generation: u64,
        url_digest: String,
        origin_digest: String,
        frame_id: &str,
        loader_id: &str,
        execution_context_id: &str,
        execution_context_generation: u64,
        metrics: BrowserLayoutMetrics,
        image: Zeroizing<Vec<u8>>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        let metadata = BrowserVisualObservationMetadata::from_captured(
            workspace,
            tab_id,
            document_generation,
            url_digest,
            origin_digest,
            frame_id,
            loader_id,
            execution_context_id,
            execution_context_generation,
            metrics,
            &image,
            observed_at,
        )?;
        Ok(Self { metadata, image })
    }

    pub fn metadata(&self) -> &BrowserVisualObservationMetadata {
        &self.metadata
    }

    pub fn image_bytes(&self) -> &[u8] {
        &self.image
    }

    pub fn into_image(self) -> Zeroizing<Vec<u8>> {
        self.image
    }

    pub fn validate_for(&self, workspace: &BrowserWorkspace) -> Result<(), BrowserError> {
        self.metadata.validate_for(workspace, &self.image)
    }

    pub fn evidence_digest(&self) -> Result<String, BrowserError> {
        self.metadata.validate_for_scope()?;
        Ok(self.metadata.observation_digest.clone())
    }
}

impl fmt::Debug for BrowserVisualObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserVisualObservation")
            .field("metadata", &self.metadata)
            .field("image_redacted", &true)
            .field("image_byte_count", &self.image.len())
            .finish_non_exhaustive()
    }
}

impl BrowserVisualObservationMetadata {
    fn validate_for_scope(&self) -> Result<(), BrowserError> {
        if self.schema_version != VISUAL_OBSERVATION_SCHEMA_VERSION
            || !is_sha256(&self.observation_digest)
            || self.observation_digest != self.compute_observation_digest()?
        {
            return Err(BrowserError::InvalidVisualObservation);
        }
        Ok(())
    }
}

pub(crate) fn decode_screenshot(response: &Value) -> Result<Zeroizing<Vec<u8>>, BrowserError> {
    let encoded = response
        .get("data")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= MAX_VISUAL_BYTES * 2)
        .ok_or(BrowserError::VisualObservationResponseInvalid)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| BrowserError::VisualObservationImageInvalid)?;
    if bytes.is_empty()
        || bytes.len() > MAX_VISUAL_BYTES
        || bytes.get(..8) != Some(b"\x89PNG\r\n\x1a\n")
    {
        return Err(BrowserError::VisualObservationImageInvalid);
    }
    Ok(Zeroizing::new(bytes))
}

pub(crate) fn parse_layout_metrics(response: &Value) -> Result<BrowserLayoutMetrics, BrowserError> {
    let object = response
        .as_object()
        .ok_or(BrowserError::ProtocolProbeResponseInvalid)?;
    let visual = object
        .get("visualViewport")
        .or_else(|| object.get("layoutViewport"))
        .and_then(Value::as_object)
        .ok_or(BrowserError::ProtocolProbeResponseInvalid)?;
    let content = object
        .get("contentSize")
        .or_else(|| object.get("layoutViewport"))
        .and_then(Value::as_object)
        .ok_or(BrowserError::ProtocolProbeResponseInvalid)?;
    Ok(BrowserLayoutMetrics {
        visual_width: parse_dimension(visual.get("clientWidth"), "visual.clientWidth")?,
        visual_height: parse_dimension(visual.get("clientHeight"), "visual.clientHeight")?,
        content_width: parse_dimension(content.get("width"), "content.width")?,
        content_height: parse_dimension(content.get("height"), "content.height")?,
    })
}

fn parse_dimension(value: Option<&Value>, _field: &str) -> Result<u32, BrowserError> {
    let value = value
        .and_then(Value::as_f64)
        .filter(|value| {
            value.is_finite() && *value > 0.0 && *value <= f64::from(MAX_VIEWPORT_DIMENSION)
        })
        .ok_or(BrowserError::ProtocolProbeResponseInvalid)?;
    let rounded = value.round();
    format!("{rounded:.0}")
        .parse::<u32>()
        .map_err(|_| BrowserError::ProtocolProbeResponseInvalid)
}

fn valid_dimension(value: u32) -> bool {
    value > 0 && value <= MAX_VIEWPORT_DIMENSION
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use hartevo_domain_kernel::{
        AccountId, BrowserControlLeaseId, BrowserProfileId, Mission, MissionContract, Project,
        ProjectId, StorageMode, TenantId,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::BrowserIdentity;

    fn sha(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn workspace() -> (TempDir, BrowserWorkspace) {
        let temp = TempDir::new().expect("temp");
        let now = Utc
            .with_ymd_and_hms(2026, 8, 13, 0, 0, 0)
            .single()
            .expect("time");
        let project = Project::create_local(
            TenantId::from("tenant-visual"),
            ProjectId::from("project-visual"),
            "Visual",
            "",
            temp.path().to_str().expect("root"),
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mission = Mission::compile(
            project.tenant_id.clone(),
            "mission-visual".into(),
            project.id.clone(),
            "Visual fallback",
            MissionContract::bootstrap("Visual fallback", ["browser.read".into()], now),
            now,
        )
        .expect("mission");
        let identity = BrowserIdentity::new(
            "visual-provider",
            AccountId::from("visual-account"),
            sha('a'),
            sha('b'),
            now,
        )
        .expect("identity");
        let profile = crate::BrowserProfile::create_managed(
            BrowserProfileId::from("profile-visual"),
            &project,
            "keyring://visual",
            identity,
            now,
        )
        .expect("profile");
        let workspace = BrowserWorkspace::create(
            "workspace-visual".into(),
            &project,
            &mission,
            &profile,
            "tab-visual".into(),
            BrowserControlLeaseId::from("lease-visual-1"),
            now + chrono::Duration::hours(1),
            sha('c'),
            now,
        )
        .expect("workspace");
        (temp, workspace)
    }

    #[test]
    fn screenshot_decode_is_png_bounded_and_content_free() {
        let png = b"\x89PNG\r\n\x1a\nvisual-pixel-secret";
        let encoded = base64::engine::general_purpose::STANDARD.encode(png);
        let bytes = decode_screenshot(&json!({"data": encoded})).expect("png");
        assert_eq!(bytes.as_slice(), png);
        assert!(decode_screenshot(&json!({"data": "bm90LXBuZw=="})).is_err());
    }

    #[test]
    fn layout_probe_rejects_ambiguous_or_unbounded_metrics() {
        let response = json!({
            "visualViewport": {"clientWidth": 1280, "clientHeight": 720},
            "contentSize": {"width": 1280, "height": 1440}
        });
        let metrics = parse_layout_metrics(&response).expect("layout metrics");
        assert_eq!(metrics.visual_width, 1280);
        assert_eq!(metrics.content_height, 1440);
        assert!(
            parse_layout_metrics(&json!({
                "visualViewport": {"clientWidth": 0, "clientHeight": 720},
                "contentSize": {"width": 1280, "height": 1440}
            }))
            .is_err()
        );
    }

    #[test]
    fn visual_observation_zeroizes_pixels_and_tamper_fails() {
        let (_temp, workspace) = workspace();
        let image = Zeroizing::new(b"\x89PNG\r\n\x1a\nvisual-pixel-secret".to_vec());
        let observation = BrowserVisualObservation::from_captured(
            &workspace,
            "tab-visual".into(),
            2,
            sha('d'),
            sha('e'),
            "frame-visual",
            "loader-visual",
            "context-visual",
            3,
            BrowserLayoutMetrics {
                visual_width: 1280,
                visual_height: 720,
                content_width: 1280,
                content_height: 1440,
            },
            image,
            workspace.created_at,
        )
        .expect("visual observation");
        observation.validate_for(&workspace).expect("valid visual");
        let debug = format!("{observation:?}");
        assert!(!debug.contains("visual-pixel-secret"));
        assert!(debug.contains("image_redacted"));
        let mut tampered = observation.metadata.clone();
        tampered.viewport_width = 1;
        assert!(matches!(
            tampered.validate_for(&workspace, observation.image_bytes()),
            Err(BrowserError::InvalidVisualObservation)
        ));
    }

    #[test]
    fn protocol_observation_binds_all_workspace_scope() {
        let (_temp, workspace) = workspace();
        let observation = BrowserProtocolObservation::from_layout_metrics(
            &workspace,
            "tab-visual".into(),
            2,
            sha('d'),
            sha('e'),
            "frame-visual",
            "loader-visual",
            "context-visual",
            3,
            BrowserLayoutMetrics {
                visual_width: 1280,
                visual_height: 720,
                content_width: 1280,
                content_height: 1440,
            },
            workspace.created_at,
        )
        .expect("protocol observation");
        observation
            .validate_for(&workspace)
            .expect("valid protocol");
        let mut tampered = observation.clone();
        tampered.project_id = ProjectId::from("other-project");
        assert!(matches!(
            tampered.validate_for(&workspace),
            Err(BrowserError::InvalidProtocolObservation)
        ));
    }
}
