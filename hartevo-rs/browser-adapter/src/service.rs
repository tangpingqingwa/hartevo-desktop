use std::collections::BTreeSet;
use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    BrowserProfileId, BrowserSnapshotId, BrowserTabId, BrowserWorkspaceId, MissionId, ProjectId,
    TenantId,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::workspace::{digest, digest_json, is_bounded_identifier, is_sha256};
use crate::{
    BrowserError, BrowserLeaseProof, BrowserProfile, BrowserProfileSource, BrowserProfileStatus,
    BrowserWorkspace,
};

const SERVICE_SCHEMA_VERSION: u32 = 1;
const SERVICE_ID: &str = "hartevo.browser-workspace";
const SERVICE_VERSION: u32 = 1;

/// Capabilities exposed by the authenticated Browser Workspace service.
///
/// The set is deliberately small: the provider is a read-only observation
/// surface and the user-control boundary. Effectful browser actions remain
/// behind the existing Effect Broker/action contracts.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserWorkspaceCapability {
    AuthenticatedRead,
    DurableObservation,
    HumanTakeover,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserWorkspaceScope {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub profile_id: BrowserProfileId,
    pub workspace_id: BrowserWorkspaceId,
    pub identity_digest: String,
}

impl BrowserWorkspaceScope {
    pub fn bind(
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
    ) -> Result<Self, BrowserError> {
        profile.validate()?;
        workspace.validate()?;
        if profile.source != BrowserProfileSource::Managed
            || profile.status != BrowserProfileStatus::Active
            || profile.tenant_id != workspace.tenant_id
            || profile.project_id != workspace.project_id
            || profile.id != workspace.profile_id
            || profile.identity.identity_digest != workspace.expected_identity_digest
        {
            return Err(BrowserError::ScopeMismatch);
        }
        let scope = Self {
            tenant_id: workspace.tenant_id.clone(),
            project_id: workspace.project_id.clone(),
            mission_id: workspace.mission_id.clone(),
            profile_id: profile.id.clone(),
            workspace_id: workspace.id.clone(),
            identity_digest: profile.identity.identity_digest.clone(),
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        if !is_bounded_identifier(self.tenant_id.as_str())
            || !is_bounded_identifier(self.project_id.as_str())
            || !is_bounded_identifier(self.mission_id.as_str())
            || !is_bounded_identifier(self.profile_id.as_str())
            || !is_bounded_identifier(self.workspace_id.as_str())
            || !is_sha256(&self.identity_digest)
        {
            return Err(BrowserError::ScopeMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for BrowserWorkspaceScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserWorkspaceScope")
            .field("tenant_id", &self.tenant_id)
            .field("project_id", &self.project_id)
            .field("mission_id", &self.mission_id)
            .field("profile_id", &self.profile_id)
            .field("workspace_id", &self.workspace_id)
            .field("identity_digest", &self.identity_digest)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserWorkspaceServiceDefinition {
    pub schema_version: u32,
    pub service_id: String,
    pub version: u32,
    pub provider_id: String,
    pub capabilities: BTreeSet<BrowserWorkspaceCapability>,
    pub service_digest: String,
}

impl BrowserWorkspaceServiceDefinition {
    pub fn authenticated_chromium(provider_id: impl Into<String>) -> Result<Self, BrowserError> {
        let definition = Self {
            schema_version: SERVICE_SCHEMA_VERSION,
            service_id: SERVICE_ID.to_owned(),
            version: SERVICE_VERSION,
            provider_id: provider_id.into(),
            capabilities: BTreeSet::from([
                BrowserWorkspaceCapability::AuthenticatedRead,
                BrowserWorkspaceCapability::DurableObservation,
                BrowserWorkspaceCapability::HumanTakeover,
            ]),
            service_digest: String::new(),
        };
        let service_digest = definition.unsigned_digest()?;
        let definition = Self {
            service_digest,
            ..definition
        };
        definition.validate()?;
        Ok(definition)
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != SERVICE_SCHEMA_VERSION
            || self.service_id != SERVICE_ID
            || self.version != SERVICE_VERSION
            || !is_bounded_identifier(&self.provider_id)
            || self.capabilities
                != BTreeSet::from([
                    BrowserWorkspaceCapability::AuthenticatedRead,
                    BrowserWorkspaceCapability::DurableObservation,
                    BrowserWorkspaceCapability::HumanTakeover,
                ])
            || !is_sha256(&self.service_digest)
            || self.service_digest != self.unsigned_digest()?
        {
            return Err(BrowserError::ScopeMismatch);
        }
        Ok(())
    }

    pub fn supports(&self, capability: BrowserWorkspaceCapability) -> bool {
        self.capabilities.contains(&capability)
    }

    fn unsigned_digest(&self) -> Result<String, BrowserError> {
        digest_json(&(
            self.schema_version,
            &self.service_id,
            self.version,
            &self.provider_id,
            &self.capabilities,
        ))
    }

    pub fn mount_request(
        &self,
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        requested_at: DateTime<Utc>,
    ) -> Result<BrowserWorkspaceMountRequest, BrowserError> {
        self.validate()?;
        let scope = BrowserWorkspaceScope::bind(profile, workspace)?;
        let lease = workspace.agent_lease_proof(requested_at)?;
        let request = BrowserWorkspaceMountRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            service_id: self.service_id.clone(),
            service_digest: self.service_digest.clone(),
            scope,
            lease,
            profile_revision: profile.revision,
            workspace_revision: workspace.revision,
            requested_at,
        };
        request.validate_for(self, profile, workspace, requested_at)?;
        Ok(request)
    }
}

impl fmt::Debug for BrowserWorkspaceServiceDefinition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserWorkspaceServiceDefinition")
            .field("schema_version", &self.schema_version)
            .field("service_id", &self.service_id)
            .field("version", &self.version)
            .field("provider_id", &self.provider_id)
            .field("capabilities", &self.capabilities)
            .field("service_digest", &self.service_digest)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserWorkspaceMountRequest {
    pub schema_version: u32,
    pub service_id: String,
    pub service_digest: String,
    pub scope: BrowserWorkspaceScope,
    pub lease: BrowserLeaseProof,
    pub profile_revision: u64,
    pub workspace_revision: u64,
    pub requested_at: DateTime<Utc>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFrameScope {
    pub schema_version: u32,
    pub tab_id: BrowserTabId,
    pub frame_id_digest: String,
    pub loader_id_digest: String,
    pub url_digest: String,
    pub origin_digest: String,
    pub document_generation: u64,
}

impl BrowserFrameScope {
    pub(crate) fn from_verified(
        tab_id: BrowserTabId,
        frame_id: &str,
        loader_id: &str,
        url: &str,
        document_generation: u64,
    ) -> Result<Self, BrowserError> {
        let parsed = Url::parse(url).map_err(|_| BrowserError::StaleSnapshot)?;
        let origin = parsed.origin();
        if !origin.is_tuple() {
            return Err(BrowserError::StaleSnapshot);
        }
        let scope = Self {
            schema_version: SERVICE_SCHEMA_VERSION,
            tab_id,
            frame_id_digest: digest(frame_id.as_bytes()),
            loader_id_digest: digest(loader_id.as_bytes()),
            url_digest: digest(url.as_bytes()),
            origin_digest: digest(origin.ascii_serialization().as_bytes()),
            document_generation,
        };
        scope.validate()?;
        Ok(scope)
    }

    #[cfg(test)]
    pub(crate) fn from_test_values(
        tab_id: BrowserTabId,
        frame_id: &str,
        loader_id: &str,
        url: &str,
        document_generation: u64,
    ) -> Result<Self, BrowserError> {
        Self::from_verified(tab_id, frame_id, loader_id, url, document_generation)
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != SERVICE_SCHEMA_VERSION
            || !is_bounded_identifier(self.tab_id.as_str())
            || !is_sha256(&self.frame_id_digest)
            || !is_sha256(&self.loader_id_digest)
            || !is_sha256(&self.url_digest)
            || !is_sha256(&self.origin_digest)
            || self.document_generation == 0
        {
            return Err(BrowserError::StaleSnapshot);
        }
        Ok(())
    }
}

impl fmt::Debug for BrowserFrameScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserFrameScope")
            .field("schema_version", &self.schema_version)
            .field("tab_id", &self.tab_id)
            .field("frame_id_digest", &self.frame_id_digest)
            .field("loader_id_digest", &self.loader_id_digest)
            .field("url_digest", &self.url_digest)
            .field("origin_digest", &self.origin_digest)
            .field("document_generation", &self.document_generation)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserObservationCursor {
    pub schema_version: u32,
    pub cursor_id: String,
    pub objective_id: BrowserSnapshotId,
    pub scope: BrowserWorkspaceScope,
    pub frame_scope: BrowserFrameScope,
    pub lease: BrowserLeaseProof,
    pub provider_epoch: u64,
    pub issued_at: DateTime<Utc>,
    pub cursor_digest: String,
}

impl BrowserObservationCursor {
    pub(crate) fn issue(
        objective_id: BrowserSnapshotId,
        scope: BrowserWorkspaceScope,
        frame_scope: BrowserFrameScope,
        lease: BrowserLeaseProof,
        provider_epoch: u64,
        issued_at: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        let cursor = Self {
            schema_version: SERVICE_SCHEMA_VERSION,
            cursor_id: BrowserSnapshotId::new().to_string(),
            objective_id,
            scope,
            frame_scope,
            lease,
            provider_epoch,
            issued_at,
            cursor_digest: String::new(),
        };
        let cursor_digest = cursor.unsigned_digest()?;
        let cursor = Self {
            cursor_digest,
            ..cursor
        };
        cursor.validate_shape()?;
        Ok(cursor)
    }

    pub(crate) fn validate_for(
        &self,
        objective_id: &BrowserSnapshotId,
        scope: &BrowserWorkspaceScope,
        frame_scope: &BrowserFrameScope,
        lease: &BrowserLeaseProof,
        provider_epoch: u64,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.validate_shape()?;
        if &self.objective_id != objective_id
            || &self.scope != scope
            || &self.frame_scope != frame_scope
            || &self.lease != lease
            || self.provider_epoch != provider_epoch
            || self.issued_at > now
        {
            return Err(BrowserError::ObservationCursorInvalid);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), BrowserError> {
        self.scope.validate()?;
        self.frame_scope.validate()?;
        if self.schema_version != SERVICE_SCHEMA_VERSION
            || !is_bounded_identifier(&self.cursor_id)
            || self.objective_id.as_str().trim().is_empty()
            || self.lease.workspace_id != self.scope.workspace_id
            || self.lease.generation == 0
            || self.provider_epoch == 0
            || !is_sha256(&self.cursor_digest)
            || self.cursor_digest != self.unsigned_digest()?
        {
            return Err(BrowserError::ObservationCursorInvalid);
        }
        Ok(())
    }

    fn unsigned_digest(&self) -> Result<String, BrowserError> {
        digest_json(&serde_json::json!({
            "schemaVersion": self.schema_version,
            "cursorId": self.cursor_id,
            "objectiveId": self.objective_id,
            "scope": self.scope,
            "frameScope": self.frame_scope,
            "lease": self.lease,
            "providerEpoch": self.provider_epoch,
            "issuedAt": self.issued_at,
        }))
    }
}

impl fmt::Debug for BrowserObservationCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserObservationCursor")
            .field("schema_version", &self.schema_version)
            .field("cursor_id", &self.cursor_id)
            .field("objective_id", &self.objective_id)
            .field("scope", &self.scope)
            .field("frame_scope", &self.frame_scope)
            .field("lease_generation", &self.lease.generation)
            .field("provider_epoch", &self.provider_epoch)
            .field("issued_at", &self.issued_at)
            .field("cursor_digest", &self.cursor_digest)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserObservationObjectiveRequest {
    pub schema_version: u32,
    pub objective_id: BrowserSnapshotId,
    pub observation_id: BrowserSnapshotId,
    pub source_uri: String,
    pub scope: BrowserWorkspaceScope,
    pub frame_scope: BrowserFrameScope,
    pub cursor: BrowserObservationCursor,
    pub requested_at: DateTime<Utc>,
    pub request_digest: String,
}

impl BrowserObservationObjectiveRequest {
    pub(crate) fn issue(
        objective_id: BrowserSnapshotId,
        observation_id: BrowserSnapshotId,
        source_uri: String,
        scope: BrowserWorkspaceScope,
        frame_scope: BrowserFrameScope,
        cursor: BrowserObservationCursor,
        requested_at: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        let request = Self {
            schema_version: SERVICE_SCHEMA_VERSION,
            objective_id,
            observation_id,
            source_uri,
            scope,
            frame_scope,
            cursor,
            requested_at,
            request_digest: String::new(),
        };
        let request_digest = request.unsigned_digest()?;
        let request = Self {
            request_digest,
            ..request
        };
        request.validate_shape()?;
        Ok(request)
    }

    pub(crate) fn validate_for(
        &self,
        scope: &BrowserWorkspaceScope,
        frame_scope: &BrowserFrameScope,
        lease: &BrowserLeaseProof,
        provider_epoch: u64,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.validate_shape()?;
        if &self.scope != scope || &self.frame_scope != frame_scope {
            return Err(BrowserError::ScopeMismatch);
        }
        self.cursor.validate_for(
            &self.objective_id,
            scope,
            frame_scope,
            lease,
            provider_epoch,
            now,
        )?;
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), BrowserError> {
        self.scope.validate()?;
        self.frame_scope.validate()?;
        if self.schema_version != SERVICE_SCHEMA_VERSION
            || self.objective_id.as_str().trim().is_empty()
            || self.observation_id.as_str().trim().is_empty()
            || !is_https_source_uri(&self.source_uri)
            || digest(self.source_uri.as_bytes()) != self.frame_scope.url_digest
            || self.request_digest != self.unsigned_digest()?
        {
            return Err(BrowserError::InvalidObservationObjective);
        }
        Ok(())
    }

    fn unsigned_digest(&self) -> Result<String, BrowserError> {
        digest_json(&serde_json::json!({
            "schemaVersion": self.schema_version,
            "objectiveId": self.objective_id,
            "observationId": self.observation_id,
            "sourceUri": self.source_uri,
            "scope": self.scope,
            "frameScope": self.frame_scope,
            "cursor": self.cursor,
            "requestedAt": self.requested_at,
        }))
    }
}

impl fmt::Debug for BrowserObservationObjectiveRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserObservationObjectiveRequest")
            .field("schema_version", &self.schema_version)
            .field("objective_id", &self.objective_id)
            .field("observation_id", &self.observation_id)
            .field("source_uri", &self.source_uri)
            .field("scope", &self.scope)
            .field("frame_scope", &self.frame_scope)
            .field("cursor", &self.cursor)
            .field("requested_at", &self.requested_at)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

pub(crate) fn canonical_source_uri(raw_uri: &str) -> Result<(String, String), BrowserError> {
    if !is_bounded_identifier(raw_uri) {
        return Err(BrowserError::NavigationTargetRejected);
    }
    let parsed = Url::parse(raw_uri).map_err(|_| BrowserError::NavigationTargetRejected)?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
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

fn is_https_source_uri(raw_uri: &str) -> bool {
    canonical_source_uri(raw_uri).is_ok_and(|(canonical, _)| canonical == raw_uri)
}

impl BrowserWorkspaceMountRequest {
    pub fn validate_for(
        &self,
        definition: &BrowserWorkspaceServiceDefinition,
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        definition.validate()?;
        profile.validate()?;
        workspace.validate()?;
        let expected_scope = BrowserWorkspaceScope::bind(profile, workspace)?;
        if self.schema_version != SERVICE_SCHEMA_VERSION
            || self.service_id != definition.service_id
            || self.service_digest != definition.service_digest
            || self.scope != expected_scope
            || self.lease.workspace_id != workspace.id
            || self.profile_revision != profile.revision
            || self.workspace_revision != workspace.revision
            || self.requested_at > now
        {
            return Err(BrowserError::ScopeMismatch);
        }
        workspace.validate_agent_lease(&self.lease, now)
    }
}

impl fmt::Debug for BrowserWorkspaceMountRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserWorkspaceMountRequest")
            .field("schema_version", &self.schema_version)
            .field("service_id", &self.service_id)
            .field("service_digest", &self.service_digest)
            .field("scope", &self.scope)
            .field("lease_generation", &self.lease.generation)
            .field("profile_revision", &self.profile_revision)
            .field("workspace_revision", &self.workspace_revision)
            .field("requested_at", &self.requested_at)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_digest_binds_provider_and_capabilities() {
        let definition =
            BrowserWorkspaceServiceDefinition::authenticated_chromium("provider-service-test")
                .expect("definition");
        definition.validate().expect("valid definition");

        let mut provider_tampered = definition.clone();
        provider_tampered.provider_id = "provider-other".to_owned();
        assert!(provider_tampered.validate().is_err());

        let mut capability_tampered = definition.clone();
        capability_tampered
            .capabilities
            .remove(&BrowserWorkspaceCapability::HumanTakeover);
        assert!(capability_tampered.validate().is_err());
    }
}
