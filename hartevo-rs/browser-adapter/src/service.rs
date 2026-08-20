use std::collections::BTreeSet;
use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{BrowserProfileId, BrowserWorkspaceId, MissionId, ProjectId, TenantId};
use serde::{Deserialize, Serialize};

use crate::workspace::{digest_json, is_bounded_identifier, is_sha256};
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
