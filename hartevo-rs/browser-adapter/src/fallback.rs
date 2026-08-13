use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    BrowserProfileId, BrowserTabId, BrowserWorkspaceId, MissionId, ProjectId,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::workspace::{digest_json, is_bounded_identifier, is_sha256};
use crate::{BrowserError, BrowserWorkspace};

const FALLBACK_TRACE_SCHEMA_VERSION: u32 = 1;
const MAX_FALLBACK_STEPS: usize = 3;

/// The bounded observation paths an agent may use for one page state.
/// Semantic is always attempted first; visual and protocol are diagnostics,
/// never arbitrary interaction surfaces.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserFallbackPath {
    Semantic,
    Visual,
    Protocol,
}

/// A machine-readable explanation for why the next observation path was
/// selected. The values intentionally describe generic page-state problems,
/// not a provider or market-specific workflow.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserFallbackReason {
    InitialSemantic,
    SemanticUnavailable,
    SemanticAmbiguous,
    CanvasOrVirtualized,
    VisualVerificationFailed,
    ProtocolDiagnosticRequired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFallbackStep {
    pub path: BrowserFallbackPath,
    pub reason: BrowserFallbackReason,
    pub probe_digest: String,
    pub verification_digest: String,
}

/// An immutable, scope-bound record of one semantic → visual → protocol
/// decision. It contains digests and reasons only; observations themselves
/// remain owned by their typed, short-lived adapters.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFallbackTrace {
    pub schema_version: u32,
    pub workspace_id: BrowserWorkspaceId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub profile_id: BrowserProfileId,
    pub identity_digest: String,
    pub tab_id: BrowserTabId,
    pub lease_generation: u64,
    pub document_generation: u64,
    pub started_at: DateTime<Utc>,
    pub steps: Vec<BrowserFallbackStep>,
    pub selected_path: BrowserFallbackPath,
    pub trace_digest: String,
}

/// Builder that enforces fallback order before a trace can be emitted.
#[derive(Clone, Debug)]
pub struct BrowserFallbackTraceBuilder {
    workspace_id: BrowserWorkspaceId,
    project_id: ProjectId,
    mission_id: MissionId,
    profile_id: BrowserProfileId,
    identity_digest: String,
    tab_id: BrowserTabId,
    lease_generation: u64,
    document_generation: u64,
    started_at: DateTime<Utc>,
    steps: Vec<BrowserFallbackStep>,
}

impl BrowserFallbackTrace {
    pub fn begin(
        workspace: &BrowserWorkspace,
        tab_id: BrowserTabId,
        document_generation: u64,
        semantic_probe_digest: impl Into<String>,
        semantic_verification_digest: impl Into<String>,
        started_at: DateTime<Utc>,
    ) -> Result<BrowserFallbackTraceBuilder, BrowserError> {
        workspace.validate()?;
        let semantic_probe_digest = semantic_probe_digest.into();
        let semantic_verification_digest = semantic_verification_digest.into();
        if !workspace.tabs.contains(&tab_id)
            || document_generation == 0
            || started_at < workspace.created_at
            || !is_sha256(&semantic_probe_digest)
            || !is_sha256(&semantic_verification_digest)
        {
            return Err(BrowserError::InvalidFallbackTrace);
        }
        Ok(BrowserFallbackTraceBuilder {
            workspace_id: workspace.id.clone(),
            project_id: workspace.project_id.clone(),
            mission_id: workspace.mission_id.clone(),
            profile_id: workspace.profile_id.clone(),
            identity_digest: workspace.expected_identity_digest.clone(),
            tab_id,
            lease_generation: workspace.lease_generation,
            document_generation,
            started_at,
            steps: vec![BrowserFallbackStep {
                path: BrowserFallbackPath::Semantic,
                reason: BrowserFallbackReason::InitialSemantic,
                probe_digest: semantic_probe_digest,
                verification_digest: semantic_verification_digest,
            }],
        })
    }

    pub fn validate_for(
        &self,
        workspace: &BrowserWorkspace,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        workspace.validate()?;
        if self.schema_version != FALLBACK_TRACE_SCHEMA_VERSION
            || self.workspace_id != workspace.id
            || self.project_id != workspace.project_id
            || self.mission_id != workspace.mission_id
            || self.profile_id != workspace.profile_id
            || self.identity_digest != workspace.expected_identity_digest
            || !workspace.tabs.contains(&self.tab_id)
            || self.lease_generation != workspace.lease_generation
            || self.document_generation == 0
            || self.started_at < workspace.created_at
            || self.started_at > now
            || !is_bounded_identifier(self.tab_id.as_str())
            || !is_sha256(&self.identity_digest)
            || self.steps.is_empty()
            || self.steps.len() > MAX_FALLBACK_STEPS
            || self.selected_path
                != self
                    .steps
                    .last()
                    .map_or(BrowserFallbackPath::Protocol, |step| step.path)
            || !valid_step_order(&self.steps)
            || !is_sha256(&self.trace_digest)
            || self.trace_digest != self.compute_trace_digest()?
        {
            return Err(BrowserError::InvalidFallbackTrace);
        }
        Ok(())
    }

    pub fn evidence_digest(&self) -> Result<String, BrowserError> {
        if !is_sha256(&self.trace_digest) || self.trace_digest != self.compute_trace_digest()? {
            return Err(BrowserError::InvalidFallbackTrace);
        }
        Ok(self.trace_digest.clone())
    }

    fn compute_trace_digest(&self) -> Result<String, BrowserError> {
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
            "startedAt": self.started_at,
            "steps": self.steps,
            "selectedPath": self.selected_path,
        }))
    }
}

impl BrowserFallbackTraceBuilder {
    pub fn to_visual(
        mut self,
        reason: BrowserFallbackReason,
        probe_digest: impl Into<String>,
        verification_digest: impl Into<String>,
    ) -> Result<Self, BrowserError> {
        if self.steps.len() != 1
            || self.steps[0].path != BrowserFallbackPath::Semantic
            || !matches!(
                reason,
                BrowserFallbackReason::SemanticUnavailable
                    | BrowserFallbackReason::SemanticAmbiguous
                    | BrowserFallbackReason::CanvasOrVirtualized
            )
        {
            return Err(BrowserError::FallbackOrderViolation);
        }
        self.steps.push(validated_step(
            BrowserFallbackPath::Visual,
            reason,
            probe_digest.into(),
            verification_digest.into(),
        )?);
        Ok(self)
    }

    pub fn to_protocol(
        mut self,
        reason: BrowserFallbackReason,
        probe_digest: impl Into<String>,
        verification_digest: impl Into<String>,
    ) -> Result<Self, BrowserError> {
        if self.steps.len() != 2
            || self.steps[1].path != BrowserFallbackPath::Visual
            || !matches!(
                reason,
                BrowserFallbackReason::VisualVerificationFailed
                    | BrowserFallbackReason::ProtocolDiagnosticRequired
            )
        {
            return Err(BrowserError::FallbackOrderViolation);
        }
        self.steps.push(validated_step(
            BrowserFallbackPath::Protocol,
            reason,
            probe_digest.into(),
            verification_digest.into(),
        )?);
        Ok(self)
    }

    pub fn finish(
        self,
        selected_path: BrowserFallbackPath,
    ) -> Result<BrowserFallbackTrace, BrowserError> {
        if self.steps.is_empty() || self.steps.last().map(|step| step.path) != Some(selected_path) {
            return Err(BrowserError::FallbackOrderViolation);
        }
        let mut trace = BrowserFallbackTrace {
            schema_version: FALLBACK_TRACE_SCHEMA_VERSION,
            workspace_id: self.workspace_id,
            project_id: self.project_id,
            mission_id: self.mission_id,
            profile_id: self.profile_id,
            identity_digest: self.identity_digest,
            tab_id: self.tab_id,
            lease_generation: self.lease_generation,
            document_generation: self.document_generation,
            started_at: self.started_at,
            steps: self.steps,
            selected_path,
            trace_digest: String::new(),
        };
        trace.trace_digest = trace.compute_trace_digest()?;
        Ok(trace)
    }
}

fn validated_step(
    path: BrowserFallbackPath,
    reason: BrowserFallbackReason,
    probe_digest: String,
    verification_digest: String,
) -> Result<BrowserFallbackStep, BrowserError> {
    if !is_sha256(&probe_digest) || !is_sha256(&verification_digest) {
        return Err(BrowserError::InvalidFallbackTrace);
    }
    Ok(BrowserFallbackStep {
        path,
        reason,
        probe_digest,
        verification_digest,
    })
}

fn valid_step_order(steps: &[BrowserFallbackStep]) -> bool {
    if steps.first().is_none_or(|step| {
        step.path != BrowserFallbackPath::Semantic
            || step.reason != BrowserFallbackReason::InitialSemantic
    }) {
        return false;
    }
    if steps
        .iter()
        .any(|step| !is_sha256(&step.probe_digest) || !is_sha256(&step.verification_digest))
    {
        return false;
    }
    match steps {
        [semantic] => semantic.path == BrowserFallbackPath::Semantic,
        [semantic, visual] => {
            semantic.path == BrowserFallbackPath::Semantic
                && visual.path == BrowserFallbackPath::Visual
                && matches!(
                    visual.reason,
                    BrowserFallbackReason::SemanticUnavailable
                        | BrowserFallbackReason::SemanticAmbiguous
                        | BrowserFallbackReason::CanvasOrVirtualized
                )
        }
        [semantic, visual, protocol] => {
            semantic.path == BrowserFallbackPath::Semantic
                && visual.path == BrowserFallbackPath::Visual
                && protocol.path == BrowserFallbackPath::Protocol
                && matches!(
                    visual.reason,
                    BrowserFallbackReason::SemanticUnavailable
                        | BrowserFallbackReason::SemanticAmbiguous
                        | BrowserFallbackReason::CanvasOrVirtualized
                )
                && matches!(
                    protocol.reason,
                    BrowserFallbackReason::VisualVerificationFailed
                        | BrowserFallbackReason::ProtocolDiagnosticRequired
                )
        }
        _ => false,
    }
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
            TenantId::from("tenant-fallback"),
            ProjectId::from("project-fallback"),
            "Fallback",
            "",
            temp.path().to_str().expect("root"),
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mission = Mission::compile(
            project.tenant_id.clone(),
            "mission-fallback".into(),
            project.id.clone(),
            "Fallback mission",
            MissionContract::bootstrap("Fallback", ["browser.read".into()], now),
            now,
        )
        .expect("mission");
        let identity = BrowserIdentity::new(
            "fallback-provider",
            AccountId::from("fallback-account"),
            sha('a'),
            sha('b'),
            now,
        )
        .expect("identity");
        let profile = crate::BrowserProfile::create_managed(
            BrowserProfileId::from("profile-fallback"),
            &project,
            "keyring://fallback",
            identity,
            now,
        )
        .expect("profile");
        let workspace = BrowserWorkspace::create(
            "workspace-fallback".into(),
            &project,
            &mission,
            &profile,
            "tab-fallback".into(),
            BrowserControlLeaseId::from("lease-fallback-1"),
            now + chrono::Duration::hours(1),
            sha('c'),
            now,
        )
        .expect("workspace");
        (temp, workspace)
    }

    #[test]
    fn fallback_trace_enforces_order_and_scope() {
        let (_temp, workspace) = workspace();
        let trace = BrowserFallbackTrace::begin(
            &workspace,
            "tab-fallback".into(),
            2,
            sha('d'),
            sha('e'),
            workspace.created_at,
        )
        .expect("begin")
        .to_visual(
            BrowserFallbackReason::SemanticUnavailable,
            sha('f'),
            sha('0'),
        )
        .expect("visual")
        .to_protocol(
            BrowserFallbackReason::VisualVerificationFailed,
            sha('1'),
            sha('2'),
        )
        .expect("protocol")
        .finish(BrowserFallbackPath::Protocol)
        .expect("finish");
        trace
            .validate_for(
                &workspace,
                workspace.created_at + chrono::Duration::minutes(1),
            )
            .expect("valid trace");
        assert_eq!(trace.steps.len(), 3);
        assert!(trace.evidence_digest().is_ok());
    }

    #[test]
    fn fallback_trace_rejects_skip_and_tampering() {
        let (_temp, workspace) = workspace();
        let builder = BrowserFallbackTrace::begin(
            &workspace,
            "tab-fallback".into(),
            2,
            sha('d'),
            sha('e'),
            workspace.created_at,
        )
        .expect("begin");
        assert!(matches!(
            builder.clone().to_protocol(
                BrowserFallbackReason::ProtocolDiagnosticRequired,
                sha('f'),
                sha('0'),
            ),
            Err(BrowserError::FallbackOrderViolation)
        ));
        let mut trace = builder
            .to_visual(
                BrowserFallbackReason::CanvasOrVirtualized,
                sha('f'),
                sha('0'),
            )
            .expect("visual")
            .finish(BrowserFallbackPath::Visual)
            .expect("finish");
        trace.project_id = ProjectId::from("other-project");
        assert!(matches!(
            trace.validate_for(
                &workspace,
                workspace.created_at + chrono::Duration::minutes(1)
            ),
            Err(BrowserError::InvalidFallbackTrace)
        ));
    }
}
