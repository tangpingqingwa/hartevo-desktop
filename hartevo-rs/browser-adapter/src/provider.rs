use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{BrowserSnapshotId, BrowserTabId};
use serde::{Deserialize, Serialize};

use crate::action::SemanticSnapshot;
use crate::service::{
    BrowserFrameScope, BrowserObservationCursor, BrowserObservationObjectiveRequest,
    BrowserWorkspaceMountRequest, BrowserWorkspaceServiceDefinition, canonical_source_uri,
};
use crate::workspace::{digest, digest_json, is_sha256};
use crate::{
    BrowserError, BrowserLeaseProof, BrowserProfile, BrowserProfileStatus, BrowserWorkspace,
};

#[cfg(unix)]
use crate::{ChromiumLaunchConfig, ManagedChromiumHost};

const OBSERVATION_SCHEMA_VERSION: u32 = 1;

/// Narrow host contract consumed by the mounted observation provider. A host
/// must return an exact root-frame binding for every read; it cannot grant
/// browser authority or silently widen the workspace scope.
pub trait BrowserObservationHost {
    fn sync_workspace(&mut self, workspace: &BrowserWorkspace) -> Result<(), BrowserError>;

    fn observe_root_frame_scope(
        &mut self,
        tab_id: &BrowserTabId,
        proof: &BrowserLeaseProof,
        now: DateTime<Utc>,
    ) -> Result<BrowserFrameScope, BrowserError>;

    fn observe_ax(
        &mut self,
        tab_id: &BrowserTabId,
        proof: &BrowserLeaseProof,
        snapshot_id: BrowserSnapshotId,
        now: DateTime<Utc>,
    ) -> Result<SemanticSnapshot, BrowserError>;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserProviderLifecycle {
    MountedAgent,
    TakenOverByUser,
    Unmounted,
    Revoked,
    Crashed,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DurableBrowserObservation {
    pub schema_version: u32,
    pub objective_id: BrowserSnapshotId,
    pub cursor_id: String,
    pub observation_id: BrowserSnapshotId,
    pub service_id: String,
    pub service_digest: String,
    pub provider_id: String,
    pub tenant_id: hartevo_domain_kernel::TenantId,
    pub project_id: hartevo_domain_kernel::ProjectId,
    pub mission_id: hartevo_domain_kernel::MissionId,
    pub profile_id: hartevo_domain_kernel::BrowserProfileId,
    pub workspace_id: hartevo_domain_kernel::BrowserWorkspaceId,
    pub tab_id: BrowserTabId,
    pub frame_scope: BrowserFrameScope,
    pub profile_revision: u64,
    pub workspace_revision: u64,
    pub lease_generation: u64,
    pub document_generation: u64,
    pub source_uri: String,
    pub source_origin_digest: String,
    pub identity_digest: String,
    pub url_digest: String,
    pub content_digest: String,
    pub redaction_digest: String,
    pub snapshot_digest: String,
    pub authenticated: bool,
    pub business_verified: bool,
    pub observed_at: DateTime<Utc>,
    pub result_digest: String,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserObservationResult {
    pub schema_version: u32,
    pub objective_id: BrowserSnapshotId,
    pub cursor_id: String,
    pub request_digest: String,
    pub observation: DurableBrowserObservation,
    pub observed_at: DateTime<Utc>,
    pub result_digest: String,
}

impl BrowserObservationResult {
    fn from_observation(
        request: &BrowserObservationObjectiveRequest,
        observation: DurableBrowserObservation,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        let result = Self {
            schema_version: OBSERVATION_SCHEMA_VERSION,
            objective_id: request.objective_id.clone(),
            cursor_id: request.cursor.cursor_id.clone(),
            request_digest: request.request_digest.clone(),
            observation,
            observed_at,
            result_digest: String::new(),
        };
        let result_digest = result.unsigned_digest()?;
        let result = Self {
            result_digest,
            ..result
        };
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != OBSERVATION_SCHEMA_VERSION
            || self.objective_id != self.observation.objective_id
            || self.cursor_id != self.observation.cursor_id
            || !is_sha256(&self.request_digest)
            || !is_sha256(&self.result_digest)
            || self.observed_at < self.observation.observed_at
            || self.result_digest != self.unsigned_digest()?
        {
            return Err(BrowserError::InvalidObservationObjective);
        }
        self.observation.digest()?;
        Ok(())
    }

    pub fn digest(&self) -> Result<String, BrowserError> {
        self.validate()?;
        Ok(self.result_digest.clone())
    }

    fn unsigned_digest(&self) -> Result<String, BrowserError> {
        digest_json(&serde_json::json!({
            "schemaVersion": self.schema_version,
            "objectiveId": self.objective_id,
            "cursorId": self.cursor_id,
            "requestDigest": self.request_digest,
            "observation": self.observation,
            "observedAt": self.observed_at,
        }))
    }
}

impl fmt::Debug for BrowserObservationResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserObservationResult")
            .field("schema_version", &self.schema_version)
            .field("objective_id", &self.objective_id)
            .field("cursor_id", &self.cursor_id)
            .field("request_digest", &self.request_digest)
            .field("observation", &self.observation)
            .field("observed_at", &self.observed_at)
            .field("result_digest", &self.result_digest)
            .finish()
    }
}

impl DurableBrowserObservation {
    fn from_snapshot(
        definition: &BrowserWorkspaceServiceDefinition,
        mount: &BrowserWorkspaceMountRequest,
        request: &BrowserObservationObjectiveRequest,
        snapshot: &SemanticSnapshot,
        source_uri: String,
        source_origin_digest: String,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        let observation = Self {
            schema_version: OBSERVATION_SCHEMA_VERSION,
            objective_id: request.objective_id.clone(),
            cursor_id: request.cursor.cursor_id.clone(),
            observation_id: snapshot.id.clone(),
            service_id: definition.service_id.clone(),
            service_digest: definition.service_digest.clone(),
            provider_id: definition.provider_id.clone(),
            tenant_id: mount.scope.tenant_id.clone(),
            project_id: mount.scope.project_id.clone(),
            mission_id: mount.scope.mission_id.clone(),
            profile_id: mount.scope.profile_id.clone(),
            workspace_id: mount.scope.workspace_id.clone(),
            tab_id: snapshot.tab_id.clone(),
            frame_scope: request.frame_scope.clone(),
            profile_revision: mount.profile_revision,
            workspace_revision: mount.workspace_revision,
            lease_generation: snapshot.lease_generation,
            document_generation: snapshot.document_generation,
            source_uri,
            source_origin_digest,
            identity_digest: snapshot.identity_digest.clone(),
            url_digest: snapshot.url_digest.clone(),
            content_digest: snapshot.content_digest.clone(),
            redaction_digest: snapshot.redaction_digest.clone(),
            snapshot_digest: snapshot.digest()?,
            authenticated: true,
            business_verified: false,
            observed_at,
            result_digest: String::new(),
        };
        let result_digest = observation.unsigned_digest()?;
        let observation = Self {
            result_digest,
            ..observation
        };
        observation.validate_for(definition, mount, request, snapshot)
    }

    pub fn validate_for(
        &self,
        definition: &BrowserWorkspaceServiceDefinition,
        mount: &BrowserWorkspaceMountRequest,
        request: &BrowserObservationObjectiveRequest,
        snapshot: &SemanticSnapshot,
    ) -> Result<Self, BrowserError> {
        definition.validate()?;
        mount.scope.validate()?;
        if self.schema_version != OBSERVATION_SCHEMA_VERSION
            || self.objective_id != request.objective_id
            || self.cursor_id != request.cursor.cursor_id
            || mount.schema_version != 1
            || mount.service_id != definition.service_id
            || mount.service_digest != definition.service_digest
            || mount.lease.workspace_id != mount.scope.workspace_id
            || mount.profile_revision == 0
            || mount.workspace_revision == 0
            || self.service_id != definition.service_id
            || self.service_digest != definition.service_digest
            || self.provider_id != definition.provider_id
            || self.tenant_id != mount.scope.tenant_id
            || self.project_id != mount.scope.project_id
            || self.mission_id != mount.scope.mission_id
            || self.profile_id != mount.scope.profile_id
            || self.workspace_id != mount.scope.workspace_id
            || self.profile_revision != mount.profile_revision
            || self.workspace_revision != mount.workspace_revision
            || self.observation_id != snapshot.id
            || self.frame_scope != request.frame_scope
            || snapshot.workspace_id != mount.scope.workspace_id
            || snapshot.identity_digest != mount.scope.identity_digest
            || snapshot.lease_generation != mount.lease.generation
            || self.tab_id != snapshot.tab_id
            || self.lease_generation != snapshot.lease_generation
            || self.document_generation != snapshot.document_generation
            || self.identity_digest != snapshot.identity_digest
            || self.url_digest != snapshot.url_digest
            || self.content_digest != snapshot.content_digest
            || self.redaction_digest != snapshot.redaction_digest
            || self.snapshot_digest != snapshot.digest()?
            || !self.authenticated
            || self.business_verified
            || self.observed_at < snapshot.created_at
            || !is_sha256(&self.service_digest)
            || !is_sha256(&self.source_origin_digest)
            || !is_sha256(&self.identity_digest)
            || !is_sha256(&self.url_digest)
            || !is_sha256(&self.content_digest)
            || !is_sha256(&self.redaction_digest)
            || !is_sha256(&self.snapshot_digest)
            || !is_sha256(&self.result_digest)
        {
            return Err(BrowserError::InvalidSnapshot);
        }
        let (canonical_uri, origin) = canonical_source_uri(&self.source_uri)?;
        if canonical_uri != self.source_uri
            || digest(canonical_uri.as_bytes()) != self.url_digest
            || digest(origin.as_bytes()) != self.source_origin_digest
            || self.result_digest != self.unsigned_digest()?
        {
            return Err(BrowserError::InvalidSnapshot);
        }
        Ok(self.clone())
    }

    pub fn digest(&self) -> Result<String, BrowserError> {
        if !is_sha256(&self.result_digest) {
            return Err(BrowserError::InvalidSnapshot);
        }
        Ok(self.result_digest.clone())
    }

    fn unsigned_digest(&self) -> Result<String, BrowserError> {
        digest_json(&serde_json::json!({
            "schemaVersion": self.schema_version,
            "objectiveId": self.objective_id,
            "cursorId": self.cursor_id,
            "observationId": self.observation_id,
            "serviceId": self.service_id,
            "serviceDigest": self.service_digest,
            "providerId": self.provider_id,
            "tenantId": self.tenant_id,
            "projectId": self.project_id,
            "missionId": self.mission_id,
            "profileId": self.profile_id,
            "workspaceId": self.workspace_id,
            "tabId": self.tab_id,
            "frameScope": self.frame_scope,
            "profileRevision": self.profile_revision,
            "workspaceRevision": self.workspace_revision,
            "leaseGeneration": self.lease_generation,
            "documentGeneration": self.document_generation,
            "sourceUri": self.source_uri,
            "sourceOriginDigest": self.source_origin_digest,
            "identityDigest": self.identity_digest,
            "urlDigest": self.url_digest,
            "contentDigest": self.content_digest,
            "redactionDigest": self.redaction_digest,
            "snapshotDigest": self.snapshot_digest,
            "authenticated": self.authenticated,
            "businessVerified": self.business_verified,
            "observedAt": self.observed_at,
        }))
    }
}

impl fmt::Debug for DurableBrowserObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableBrowserObservation")
            .field("schema_version", &self.schema_version)
            .field("objective_id", &self.objective_id)
            .field("cursor_id", &self.cursor_id)
            .field("observation_id", &self.observation_id)
            .field("service_id", &self.service_id)
            .field("service_digest", &self.service_digest)
            .field("provider_id", &self.provider_id)
            .field("tenant_id", &self.tenant_id)
            .field("project_id", &self.project_id)
            .field("mission_id", &self.mission_id)
            .field("profile_id", &self.profile_id)
            .field("workspace_id", &self.workspace_id)
            .field("tab_id", &self.tab_id)
            .field("frame_scope", &self.frame_scope)
            .field("profile_revision", &self.profile_revision)
            .field("workspace_revision", &self.workspace_revision)
            .field("lease_generation", &self.lease_generation)
            .field("document_generation", &self.document_generation)
            .field("source_uri", &self.source_uri)
            .field("source_origin_digest", &self.source_origin_digest)
            .field("identity_digest", &self.identity_digest)
            .field("url_digest", &self.url_digest)
            .field("content_digest", &self.content_digest)
            .field("redaction_digest", &self.redaction_digest)
            .field("snapshot_digest", &self.snapshot_digest)
            .field("authenticated", &self.authenticated)
            .field("business_verified", &self.business_verified)
            .field("observed_at", &self.observed_at)
            .field("result_digest", &self.result_digest)
            .finish()
    }
}

pub struct AuthenticatedChromiumProvider {
    definition: BrowserWorkspaceServiceDefinition,
    profile: BrowserProfile,
    workspace: BrowserWorkspace,
    mount: BrowserWorkspaceMountRequest,
    lifecycle: BrowserProviderLifecycle,
    cursor_epoch: u64,
    last_observation: Option<DurableBrowserObservation>,
    host: Option<Box<dyn BrowserObservationHost>>,
}

impl fmt::Debug for AuthenticatedChromiumProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedChromiumProvider")
            .field("definition", &self.definition)
            .field("profile", &self.profile)
            .field("workspace", &self.workspace)
            .field("mount", &self.mount)
            .field("lifecycle", &self.lifecycle)
            .field("cursor_epoch", &self.cursor_epoch)
            .field("last_observation", &self.last_observation)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedChromiumProvider {
    #[cfg(unix)]
    pub fn mount(
        definition: BrowserWorkspaceServiceDefinition,
        request: BrowserWorkspaceMountRequest,
        profile: BrowserProfile,
        workspace: BrowserWorkspace,
        config: &ChromiumLaunchConfig,
        now: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        Self::mount_chromium(definition, request, profile, workspace, config, now)
    }

    #[cfg(unix)]
    pub fn mount_chromium(
        definition: BrowserWorkspaceServiceDefinition,
        request: BrowserWorkspaceMountRequest,
        profile: BrowserProfile,
        workspace: BrowserWorkspace,
        config: &ChromiumLaunchConfig,
        now: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        request.validate_for(&definition, &profile, &workspace, now)?;
        let mut host = ManagedChromiumHost::spawn(profile.clone(), workspace.clone(), config)?;
        if let Err(error) =
            host.attach_about_blank_tab(&workspace.active_tab_id, &request.lease, now)
        {
            let _ = host.shutdown();
            return Err(error);
        }
        Ok(Self {
            definition,
            profile,
            workspace,
            mount: request,
            lifecycle: BrowserProviderLifecycle::MountedAgent,
            cursor_epoch: 1,
            last_observation: None,
            host: Some(Box::new(host)),
        })
    }

    #[cfg(test)]
    pub(crate) fn mount_contract_for_test(
        definition: BrowserWorkspaceServiceDefinition,
        request: BrowserWorkspaceMountRequest,
        profile: BrowserProfile,
        workspace: BrowserWorkspace,
        frame_scope: BrowserFrameScope,
        snapshot: SemanticSnapshot,
        now: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        request.validate_for(&definition, &profile, &workspace, now)?;
        frame_scope.validate()?;
        if frame_scope.tab_id != snapshot.tab_id || frame_scope.url_digest != snapshot.url_digest {
            return Err(BrowserError::ScopeMismatch);
        }
        let host_workspace = workspace.clone();
        Ok(Self {
            definition,
            profile,
            workspace,
            mount: request,
            lifecycle: BrowserProviderLifecycle::MountedAgent,
            cursor_epoch: 1,
            last_observation: None,
            host: Some(Box::new(ContractObservationHost {
                workspace: host_workspace,
                frame_scope,
                snapshot,
            })),
        })
    }

    pub fn lifecycle(&self) -> BrowserProviderLifecycle {
        self.lifecycle
    }

    pub fn definition(&self) -> &BrowserWorkspaceServiceDefinition {
        &self.definition
    }

    pub fn profile(&self) -> &BrowserProfile {
        &self.profile
    }

    pub fn workspace(&self) -> &BrowserWorkspace {
        &self.workspace
    }

    pub fn mount_request(&self) -> &BrowserWorkspaceMountRequest {
        &self.mount
    }

    pub fn last_observation(&self) -> Option<&DurableBrowserObservation> {
        self.last_observation.as_ref()
    }

    pub fn request_observation(
        &mut self,
        objective_id: BrowserSnapshotId,
        observation_id: BrowserSnapshotId,
        source_uri: impl AsRef<str>,
        now: DateTime<Utc>,
    ) -> Result<BrowserObservationObjectiveRequest, BrowserError> {
        self.require_agent(now)?;
        let tab_id = self.workspace.active_tab_id.clone();
        let frame_scope = match self
            .host
            .as_mut()
            .ok_or(BrowserError::ProtocolUnavailable)?
            .observe_root_frame_scope(&tab_id, &self.mount.lease, now)
        {
            Ok(frame_scope) => frame_scope,
            Err(error) => return Err(self.invalidate_after_host_failure(error, now)),
        };
        frame_scope.validate()?;
        let (canonical_uri, _) = canonical_source_uri(source_uri.as_ref())?;
        if digest(canonical_uri.as_bytes()) != frame_scope.url_digest {
            return Err(BrowserError::ScopeMismatch);
        }
        let cursor = BrowserObservationCursor::issue(
            objective_id.clone(),
            self.mount.scope.clone(),
            frame_scope.clone(),
            self.mount.lease.clone(),
            self.cursor_epoch,
            now,
        )?;
        BrowserObservationObjectiveRequest::issue(
            objective_id,
            observation_id,
            canonical_uri,
            self.mount.scope.clone(),
            frame_scope,
            cursor,
            now,
        )
    }

    pub(crate) fn validate_observation_request(
        &self,
        request: &BrowserObservationObjectiveRequest,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.require_agent(now)?;
        request.validate_for(
            &self.mount.scope,
            &request.frame_scope,
            &self.mount.lease,
            self.cursor_epoch,
            now,
        )
    }

    pub fn observe_objective(
        &mut self,
        request: &BrowserObservationObjectiveRequest,
        now: DateTime<Utc>,
    ) -> Result<BrowserObservationResult, BrowserError> {
        self.require_agent(now)?;
        request.validate_for(
            &self.mount.scope,
            &request.frame_scope,
            &self.mount.lease,
            self.cursor_epoch,
            now,
        )?;
        let tab_id = self.workspace.active_tab_id.clone();
        let before = match self
            .host
            .as_mut()
            .ok_or(BrowserError::ProtocolUnavailable)?
            .observe_root_frame_scope(&tab_id, &self.mount.lease, now)
        {
            Ok(scope) => scope,
            Err(error) => return Err(self.invalidate_after_host_failure(error, now)),
        };
        if before != request.frame_scope {
            self.invalidate_cursor();
            return Err(BrowserError::StaleSnapshot);
        }
        let snapshot = match self
            .host
            .as_mut()
            .ok_or(BrowserError::ProtocolUnavailable)?
            .observe_ax(
                &tab_id,
                &self.mount.lease,
                request.observation_id.clone(),
                now,
            ) {
            Ok(snapshot) => snapshot,
            Err(error) => return Err(self.invalidate_after_host_failure(error, now)),
        };
        let after = match self
            .host
            .as_mut()
            .ok_or(BrowserError::ProtocolUnavailable)?
            .observe_root_frame_scope(&tab_id, &self.mount.lease, now)
        {
            Ok(scope) => scope,
            Err(error) => return Err(self.invalidate_after_host_failure(error, now)),
        };
        if after != request.frame_scope {
            self.invalidate_cursor();
            return Err(BrowserError::StaleSnapshot);
        }
        let observation = self.record_snapshot_for_request(&snapshot, request, now)?;
        BrowserObservationResult::from_observation(request, observation, now)
    }

    #[cfg(unix)]
    pub fn observe_public_source(
        &mut self,
        tab_id: &BrowserTabId,
        snapshot_id: BrowserSnapshotId,
        source_uri: impl AsRef<str>,
        now: DateTime<Utc>,
    ) -> Result<DurableBrowserObservation, BrowserError> {
        if &self.workspace.active_tab_id != tab_id {
            return Err(BrowserError::ScopeMismatch);
        }
        let request =
            self.request_observation(snapshot_id.clone(), snapshot_id, source_uri, now)?;
        Ok(self.observe_objective(&request, now)?.observation)
    }

    fn record_snapshot_for_request(
        &mut self,
        snapshot: &SemanticSnapshot,
        request: &BrowserObservationObjectiveRequest,
        observed_at: DateTime<Utc>,
    ) -> Result<DurableBrowserObservation, BrowserError> {
        request.validate_for(
            &self.mount.scope,
            &request.frame_scope,
            &self.mount.lease,
            self.cursor_epoch,
            observed_at,
        )?;
        snapshot.validate_for(&self.workspace)?;
        if snapshot.tab_id != request.frame_scope.tab_id
            || snapshot.lease_generation != self.mount.lease.generation
            || snapshot.identity_digest != self.profile.identity.identity_digest
            || snapshot.url_digest != request.frame_scope.url_digest
        {
            return Err(BrowserError::StaleSnapshot);
        }
        let (canonical_uri, origin) = canonical_source_uri(&request.source_uri)?;
        if canonical_uri != request.source_uri
            || digest(canonical_uri.as_bytes()) != snapshot.url_digest
        {
            return Err(BrowserError::ScopeMismatch);
        }
        let observation = DurableBrowserObservation::from_snapshot(
            &self.definition,
            &self.mount,
            request,
            snapshot,
            canonical_uri,
            digest(origin.as_bytes()),
            observed_at,
        )?;
        self.last_observation = Some(observation.clone());
        Ok(observation)
    }

    pub fn takeover_user(
        &mut self,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.require_agent(now)?;
        let mut next = self.workspace.clone();
        next.user_takeover(
            self.workspace.revision,
            self.workspace.lease_generation,
            hartevo_domain_kernel::BrowserControlLeaseId::new(),
            evidence_digest,
            now,
        )?;
        self.sync_host(&next)?;
        self.workspace = next;
        self.mount.lease = BrowserLeaseProof {
            workspace_id: self.workspace.id.clone(),
            lease_id: self.workspace.lease_id.clone(),
            generation: self.workspace.lease_generation,
        };
        self.mount.workspace_revision = self.workspace.revision;
        self.invalidate_cursor();
        self.lifecycle = BrowserProviderLifecycle::TakenOverByUser;
        self.last_observation = None;
        Ok(())
    }

    pub fn return_to_agent(
        &mut self,
        lease_expires_at: DateTime<Utc>,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        if self.lifecycle != BrowserProviderLifecycle::TakenOverByUser {
            return Err(BrowserError::InvalidControlTransition);
        }
        let mut next = self.workspace.clone();
        next.continue_agent(
            self.workspace.revision,
            self.workspace.lease_generation,
            hartevo_domain_kernel::BrowserControlLeaseId::new(),
            lease_expires_at,
            evidence_digest,
            now,
        )?;
        self.sync_host(&next)?;
        self.workspace = next;
        self.mount.lease = self.workspace.agent_lease_proof(now)?;
        self.mount.workspace_revision = self.workspace.revision;
        self.invalidate_cursor();
        self.lifecycle = BrowserProviderLifecycle::MountedAgent;
        self.last_observation = None;
        Ok(())
    }

    pub fn unmount(
        &mut self,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        if matches!(
            self.lifecycle,
            BrowserProviderLifecycle::Revoked | BrowserProviderLifecycle::Unmounted
        ) {
            return Err(BrowserError::InvalidControlTransition);
        }
        let sync_result = self.cancel_control_lease(evidence_digest, now, true);
        self.host.take();
        if let Err(error) = sync_result {
            self.lifecycle = BrowserProviderLifecycle::Crashed;
            self.invalidate_cursor();
            self.last_observation = None;
            return Err(error);
        }
        self.invalidate_cursor();
        self.lifecycle = BrowserProviderLifecycle::Unmounted;
        self.last_observation = None;
        Ok(())
    }

    pub fn revoke(
        &mut self,
        expected_revision: u64,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<BrowserProfile, BrowserError> {
        if self.lifecycle == BrowserProviderLifecycle::Revoked
            || self.profile.revision != expected_revision
            || self.profile.status != BrowserProfileStatus::Active
        {
            return Err(BrowserError::InvalidProfileTransition);
        }
        self.unmount(evidence_digest.clone(), now)?;
        self.profile
            .revoke(expected_revision, evidence_digest, now)?;
        self.lifecycle = BrowserProviderLifecycle::Revoked;
        self.last_observation = None;
        Ok(self.profile.clone())
    }

    fn require_agent(&self, now: DateTime<Utc>) -> Result<(), BrowserError> {
        if self.lifecycle != BrowserProviderLifecycle::MountedAgent {
            return Err(BrowserError::ControlLeaseLost);
        }
        self.mount
            .validate_for(&self.definition, &self.profile, &self.workspace, now)
    }

    pub fn mark_host_crashed(
        &mut self,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        if matches!(
            self.lifecycle,
            BrowserProviderLifecycle::Revoked | BrowserProviderLifecycle::Unmounted
        ) {
            return Err(BrowserError::InvalidControlTransition);
        }
        let cancellation = self.cancel_control_lease(evidence_digest, now, false);
        self.host.take();
        self.invalidate_cursor();
        self.lifecycle = BrowserProviderLifecycle::Crashed;
        self.last_observation = None;
        cancellation
    }

    fn invalidate_after_host_failure(
        &mut self,
        error: BrowserError,
        now: DateTime<Utc>,
    ) -> BrowserError {
        let evidence_digest = digest(error.code().as_bytes());
        let _ = self.cancel_control_lease(evidence_digest, now, false);
        self.host.take();
        self.invalidate_cursor();
        self.lifecycle = BrowserProviderLifecycle::Crashed;
        self.last_observation = None;
        error
    }

    fn invalidate_cursor(&mut self) {
        self.cursor_epoch = self.cursor_epoch.saturating_add(1).max(1);
    }

    fn cancel_control_lease(
        &mut self,
        evidence_digest: String,
        now: DateTime<Utc>,
        sync_host: bool,
    ) -> Result<(), BrowserError> {
        if !matches!(
            self.workspace.control_state,
            crate::BrowserControlState::AgentControlled
                | crate::BrowserControlState::UserControlled
        ) {
            return Ok(());
        }
        let mut next = self.workspace.clone();
        next.pause(
            self.workspace.revision,
            self.workspace.lease_generation,
            hartevo_domain_kernel::BrowserControlLeaseId::new(),
            evidence_digest,
            now,
        )?;
        let sync_result = if sync_host {
            self.host.as_mut().map(|host| host.sync_workspace(&next))
        } else {
            None
        };
        self.workspace = next;
        self.mount.workspace_revision = self.workspace.revision;
        match sync_result {
            Some(Ok(())) | None => Ok(()),
            Some(Err(error)) => Err(error),
        }
    }

    fn sync_host(&mut self, workspace: &BrowserWorkspace) -> Result<(), BrowserError> {
        if let Some(host) = self.host.as_mut() {
            host.sync_workspace(workspace)?;
        }
        Ok(())
    }
}

#[cfg(test)]
struct ContractObservationHost {
    workspace: BrowserWorkspace,
    frame_scope: BrowserFrameScope,
    snapshot: SemanticSnapshot,
}

#[cfg(test)]
impl BrowserObservationHost for ContractObservationHost {
    fn sync_workspace(&mut self, workspace: &BrowserWorkspace) -> Result<(), BrowserError> {
        if *workspace == self.workspace {
            return Ok(());
        }
        if !workspace.is_valid_successor_of(&self.workspace)? {
            return Err(BrowserError::ScopeMismatch);
        }
        self.workspace = workspace.clone();
        Ok(())
    }

    fn observe_root_frame_scope(
        &mut self,
        tab_id: &BrowserTabId,
        proof: &BrowserLeaseProof,
        now: DateTime<Utc>,
    ) -> Result<BrowserFrameScope, BrowserError> {
        self.workspace.validate_agent_lease(proof, now)?;
        if &self.frame_scope.tab_id != tab_id {
            return Err(BrowserError::ScopeMismatch);
        }
        Ok(self.frame_scope.clone())
    }

    fn observe_ax(
        &mut self,
        tab_id: &BrowserTabId,
        proof: &BrowserLeaseProof,
        snapshot_id: BrowserSnapshotId,
        now: DateTime<Utc>,
    ) -> Result<SemanticSnapshot, BrowserError> {
        self.workspace.validate_agent_lease(proof, now)?;
        if &self.snapshot.tab_id != tab_id || self.snapshot.id != snapshot_id {
            return Err(BrowserError::StaleSnapshot);
        }
        self.snapshot.validate_for(&self.workspace)?;
        Ok(self.snapshot.clone())
    }
}
