use serde::{Deserialize, Serialize};

use crate::error::GoogleWorkspaceError;
use crate::model::{PluginScope, sha256_hex};

/// A version/digest/scope-bound local registration.  It contains no token,
/// Store, keyring, Browser Profile, or Effect handle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoogleWorkspacePluginRegistration {
    pub plugin_id: String,
    pub plugin_version: u64,
    pub provider_digest: String,
    pub scope: PluginScope,
    pub registration_revision: u64,
    pub active: bool,
}

impl GoogleWorkspacePluginRegistration {
    pub fn new(scope: PluginScope) -> Self {
        Self {
            plugin_id: String::from(crate::GOOGLE_WORKSPACE_PLUGIN_ID),
            plugin_version: crate::GOOGLE_WORKSPACE_PLUGIN_VERSION,
            provider_digest: sha256_hex(crate::GOOGLE_WORKSPACE_CONTRACT_JSON.as_bytes()),
            scope,
            registration_revision: 1,
            active: true,
        }
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn scope_digest(&self) -> String {
        self.scope.digest()
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, GoogleWorkspaceError> {
        if !self.active {
            return Err(GoogleWorkspaceError::PluginRevoked);
        }
        self.registration_revision = self
            .registration_revision
            .checked_add(1)
            .ok_or(GoogleWorkspaceError::RegistrationRevisionOverflow)?;
        self.active = false;
        Ok(RegistrationRevocation {
            plugin_id: self.plugin_id.clone(),
            provider_digest: self.provider_digest.clone(),
            scope_digest: self.scope_digest(),
            revocation_revision: self.registration_revision,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    pub plugin_id: String,
    pub provider_digest: String,
    pub scope_digest: String,
    pub revocation_revision: u64,
}
