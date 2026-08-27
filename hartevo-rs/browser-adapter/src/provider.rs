use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{BrowserSnapshotId, BrowserTabId};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::action::SemanticSnapshot;
use crate::navigation::{
    BrowserNavigationPolicy, BrowserNavigationReceipt, BrowserNavigationTarget,
};
use crate::service::{BrowserWorkspaceMountRequest, BrowserWorkspaceServiceDefinition};
use crate::workspace::{digest, digest_json, is_bounded_identifier, is_sha256};
use crate::{
    BrowserError, BrowserLeaseProof, BrowserProfile, BrowserProfileStatus, BrowserWorkspace,
};

#[cfg(unix)]
use crate::{BrowserControlHost, ChromiumLaunchConfig, ManagedChromiumHost};

const OBSERVATION_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserProviderLifecycle {
    MountedAgent,
    TakenOverByUser,
    Unmounted,
    Revoked,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DurableBrowserObservation {
    pub schema_version: u32,
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

impl DurableBrowserObservation {
    fn from_snapshot(
        definition: &BrowserWorkspaceServiceDefinition,
        request: &BrowserWorkspaceMountRequest,
        snapshot: &SemanticSnapshot,
        source_uri: String,
        source_origin_digest: String,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        let observation = Self {
            schema_version: OBSERVATION_SCHEMA_VERSION,
            observation_id: snapshot.id.clone(),
            service_id: definition.service_id.clone(),
            service_digest: definition.service_digest.clone(),
            provider_id: definition.provider_id.clone(),
            tenant_id: request.scope.tenant_id.clone(),
            project_id: request.scope.project_id.clone(),
            mission_id: request.scope.mission_id.clone(),
            profile_id: request.scope.profile_id.clone(),
            workspace_id: request.scope.workspace_id.clone(),
            tab_id: snapshot.tab_id.clone(),
            profile_revision: request.profile_revision,
            workspace_revision: request.workspace_revision,
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
        observation.validate_for(definition, request, snapshot)
    }

    pub fn validate_for(
        &self,
        definition: &BrowserWorkspaceServiceDefinition,
        request: &BrowserWorkspaceMountRequest,
        snapshot: &SemanticSnapshot,
    ) -> Result<Self, BrowserError> {
        definition.validate()?;
        request.scope.validate()?;
        if self.schema_version != OBSERVATION_SCHEMA_VERSION
            || request.schema_version != 1
            || request.service_id != definition.service_id
            || request.service_digest != definition.service_digest
            || request.lease.workspace_id != request.scope.workspace_id
            || request.profile_revision == 0
            || request.workspace_revision == 0
            || self.service_id != definition.service_id
            || self.service_digest != definition.service_digest
            || self.provider_id != definition.provider_id
            || self.tenant_id != request.scope.tenant_id
            || self.project_id != request.scope.project_id
            || self.mission_id != request.scope.mission_id
            || self.profile_id != request.scope.profile_id
            || self.workspace_id != request.scope.workspace_id
            || self.profile_revision != request.profile_revision
            || self.workspace_revision != request.workspace_revision
            || self.observation_id != snapshot.id
            || snapshot.workspace_id != request.scope.workspace_id
            || snapshot.identity_digest != request.scope.identity_digest
            || snapshot.lease_generation != request.lease.generation
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

fn canonical_source_uri(raw_uri: &str) -> Result<(String, String), BrowserError> {
    if !is_bounded_identifier(raw_uri) {
        return Err(BrowserError::NavigationTargetRejected);
    }
    let parsed = Url::parse(raw_uri).map_err(|_| BrowserError::NavigationTargetRejected)?;
    if parsed.scheme() != "https"
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.host().is_none()
        || parsed.fragment().is_some()
    {
        return Err(BrowserError::NavigationTargetRejected);
    }
    let origin = parsed.origin();
    if !origin.is_tuple() {
        return Err(BrowserError::NavigationTargetRejected);
    }
    Ok((parsed.to_string(), origin.ascii_serialization()))
}

pub struct AuthenticatedChromiumProvider {
    definition: BrowserWorkspaceServiceDefinition,
    profile: BrowserProfile,
    workspace: BrowserWorkspace,
    mount: BrowserWorkspaceMountRequest,
    lifecycle: BrowserProviderLifecycle,
    last_observation: Option<DurableBrowserObservation>,
    #[cfg(unix)]
    host: Option<ManagedChromiumHost>,
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
            last_observation: None,
            host: Some(host),
        })
    }

    #[cfg(test)]
    pub(crate) fn mount_contract_for_test(
        definition: BrowserWorkspaceServiceDefinition,
        request: BrowserWorkspaceMountRequest,
        profile: BrowserProfile,
        workspace: BrowserWorkspace,
        now: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        request.validate_for(&definition, &profile, &workspace, now)?;
        Ok(Self {
            definition,
            profile,
            workspace,
            mount: request,
            lifecycle: BrowserProviderLifecycle::MountedAgent,
            last_observation: None,
            #[cfg(unix)]
            host: None,
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

    #[cfg(unix)]
    pub fn navigate_allowlisted(
        &mut self,
        tab_id: &BrowserTabId,
        policy: &BrowserNavigationPolicy,
        target: &BrowserNavigationTarget,
        now: DateTime<Utc>,
    ) -> Result<BrowserNavigationReceipt, BrowserError> {
        self.require_agent(now)?;
        self.host
            .as_mut()
            .ok_or(BrowserError::ProtocolUnavailable)?
            .navigate_allowlisted(tab_id, &self.mount.lease, policy, target, now)
    }

    #[cfg(unix)]
    pub fn observe_public_source(
        &mut self,
        tab_id: &BrowserTabId,
        snapshot_id: BrowserSnapshotId,
        source_uri: impl AsRef<str>,
        now: DateTime<Utc>,
    ) -> Result<DurableBrowserObservation, BrowserError> {
        self.require_agent(now)?;
        let snapshot = self
            .host
            .as_mut()
            .ok_or(BrowserError::ProtocolUnavailable)?
            .observe_ax(tab_id, &self.mount.lease, snapshot_id, now)?;
        self.record_snapshot(&snapshot, source_uri.as_ref(), now)
    }

    #[cfg(test)]
    pub(crate) fn record_snapshot_for_test(
        &mut self,
        snapshot: &SemanticSnapshot,
        source_uri: impl AsRef<str>,
        now: DateTime<Utc>,
    ) -> Result<DurableBrowserObservation, BrowserError> {
        self.require_agent(now)?;
        self.record_snapshot(snapshot, source_uri.as_ref(), now)
    }

    fn record_snapshot(
        &mut self,
        snapshot: &SemanticSnapshot,
        source_uri: &str,
        observed_at: DateTime<Utc>,
    ) -> Result<DurableBrowserObservation, BrowserError> {
        snapshot.validate_for(&self.workspace)?;
        if snapshot.lease_generation != self.mount.lease.generation
            || snapshot.identity_digest != self.profile.identity.identity_digest
            || observed_at < snapshot.created_at
        {
            return Err(BrowserError::StaleSnapshot);
        }
        let (canonical_uri, origin) = canonical_source_uri(source_uri)?;
        if digest(canonical_uri.as_bytes()) != snapshot.url_digest {
            return Err(BrowserError::ScopeMismatch);
        }
        let observation = DurableBrowserObservation::from_snapshot(
            &self.definition,
            &self.mount,
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
        self.lifecycle = BrowserProviderLifecycle::MountedAgent;
        self.last_observation = None;
        Ok(())
    }

    pub fn unmount(&mut self) -> Result<(), BrowserError> {
        if self.lifecycle == BrowserProviderLifecycle::Revoked {
            return Err(BrowserError::InvalidControlTransition);
        }
        #[cfg(unix)]
        let _ = self.host.take();
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
        self.unmount()?;
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

    fn sync_host(&mut self, workspace: &BrowserWorkspace) -> Result<(), BrowserError> {
        #[cfg(unix)]
        if let Some(host) = self.host.as_mut() {
            host.sync_workspace(workspace)?;
        }
        Ok(())
    }
}
