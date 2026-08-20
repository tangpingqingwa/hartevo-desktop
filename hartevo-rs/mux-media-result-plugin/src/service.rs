//! Typed service definition and reversible registration lifecycle.

use serde::Serialize;

use crate::{
    MISSION_MUX_MEDIA_RESULT_CONSUMER_ID, MUX_API_ORIGIN, MUX_MEDIA_RESULT_PLUGIN_ID,
    MUX_MEDIA_RESULT_PLUGIN_VERSION, MUX_MEDIA_RESULT_PROVIDER_ID,
    MUX_MEDIA_RESULT_PROVIDER_REVISION, MUX_MEDIA_RESULT_SERVICE_ID,
    MUX_MEDIA_RESULT_SERVICE_SCHEMA, contract_digest,
    model::{
        Digest, MuxError, MuxMediaResultProposal, MuxMediaResultRequest, MuxRegistration, MuxScope,
        RegistrationState,
    },
    plugin_definition, plugin_version_digest, provider_digest,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MuxServiceDefinition {
    pub id: String,
    pub version: String,
    pub schema: String,
    pub service_digest: Digest,
    pub read_only: bool,
    pub live_execution: bool,
    pub external_writes: bool,
    pub connected: bool,
    pub outcome_authority: bool,
}

impl Default for MuxServiceDefinition {
    fn default() -> Self {
        Self {
            id: MUX_MEDIA_RESULT_SERVICE_ID.to_owned(),
            version: MUX_MEDIA_RESULT_PLUGIN_VERSION.to_owned(),
            schema: MUX_MEDIA_RESULT_SERVICE_SCHEMA.to_owned(),
            service_digest: crate::domain_digest(
                "hartevo:mux-media-result:service:v1",
                &(
                    MUX_MEDIA_RESULT_SERVICE_ID,
                    MUX_MEDIA_RESULT_PLUGIN_VERSION,
                    MUX_MEDIA_RESULT_SERVICE_SCHEMA,
                    "read_only_metadata_proposal",
                ),
            ),
            read_only: true,
            live_execution: false,
            external_writes: false,
            connected: false,
            outcome_authority: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MuxProviderDefinition {
    pub id: String,
    pub version: String,
    pub provider_revision: String,
    pub schema: String,
    pub provider_digest: Digest,
    pub allowlisted_operations: Vec<String>,
    pub read_only: bool,
    pub native: bool,
    pub connected: bool,
}

impl Default for MuxProviderDefinition {
    fn default() -> Self {
        Self {
            id: MUX_MEDIA_RESULT_PROVIDER_ID.to_owned(),
            version: MUX_MEDIA_RESULT_PLUGIN_VERSION.to_owned(),
            provider_revision: MUX_MEDIA_RESULT_PROVIDER_REVISION.to_owned(),
            schema: crate::MUX_MEDIA_RESULT_PROVIDER_SCHEMA.to_owned(),
            provider_digest: provider_digest(),
            allowlisted_operations: vec![
                "GET /video/v1/assets?limit<=25&page<=4&cursor<=256".to_owned(),
                "GET /video/v1/assets/{ASSET_ID}".to_owned(),
                "GET /video/v1/playback-ids/{PLAYBACK_ID}".to_owned(),
                "project_track_metadata_from_asset_GET".to_owned(),
                "project_delivery_readiness_from_asset_GET".to_owned(),
            ],
            read_only: true,
            native: false,
            connected: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MuxMediaResultCapabilities {
    pub service_id: String,
    pub provider_id: String,
    pub provider_revision: String,
    pub api_origin: String,
    pub allowlisted_get_seams: Vec<String>,
    pub transport_modes: Vec<String>,
    pub read_only: bool,
    pub asset_mutation: bool,
    pub playback_mutation: bool,
    pub static_rendition_generation: bool,
    pub signed_token_generation: bool,
    pub media_download: bool,
    pub viewer_analytics: bool,
    pub connected: bool,
    pub native: bool,
    pub kernel_outcome_authority: bool,
}

impl Default for MuxMediaResultCapabilities {
    fn default() -> Self {
        Self {
            service_id: MUX_MEDIA_RESULT_SERVICE_ID.to_owned(),
            provider_id: MUX_MEDIA_RESULT_PROVIDER_ID.to_owned(),
            provider_revision: MUX_MEDIA_RESULT_PROVIDER_REVISION.to_owned(),
            api_origin: MUX_API_ORIGIN.to_owned(),
            allowlisted_get_seams: vec![
                "GET /video/v1/assets?limit<=25&page<=4&cursor<=256".to_owned(),
                "GET /video/v1/assets/{ASSET_ID}".to_owned(),
                "GET /video/v1/playback-ids/{PLAYBACK_ID}".to_owned(),
                "track_metadata_projection_from_asset_metadata".to_owned(),
                "delivery_readiness_projection_from_asset_metadata".to_owned(),
            ],
            transport_modes: vec![
                "recording".to_owned(),
                "fixture".to_owned(),
                "loopback".to_owned(),
                "BLOCKED_ENV".to_owned(),
            ],
            read_only: true,
            asset_mutation: false,
            playback_mutation: false,
            static_rendition_generation: false,
            signed_token_generation: false,
            media_download: false,
            viewer_analytics: false,
            connected: false,
            native: false,
            kernel_outcome_authority: false,
        }
    }
}

/// The typed Layer-1 service.  Registration is local and reversible; it does
/// not mount a provider in a host runtime or establish native authority.
#[derive(Clone, Debug)]
pub struct MuxMediaResultService {
    scope: MuxScope,
    registration: MuxRegistration,
    capabilities: MuxMediaResultCapabilities,
}

impl MuxMediaResultService {
    pub fn new(scope: MuxScope) -> Result<Self, MuxError> {
        validate_service_contract()?;
        let registration = MuxRegistration::new(&scope);
        registration.validate_against(&scope)?;
        Ok(Self {
            scope,
            registration,
            capabilities: MuxMediaResultCapabilities::default(),
        })
    }

    pub fn scope(&self) -> &MuxScope {
        &self.scope
    }

    pub fn registration(&self) -> &MuxRegistration {
        &self.registration
    }

    pub fn capabilities(&self) -> &MuxMediaResultCapabilities {
        &self.capabilities
    }

    pub fn describe_capabilities(&self) -> MuxMediaResultCapabilities {
        self.capabilities.clone()
    }

    pub fn service_definition(&self) -> MuxServiceDefinition {
        MuxServiceDefinition::default()
    }

    pub fn provider_definition(&self) -> MuxProviderDefinition {
        MuxProviderDefinition::default()
    }

    pub fn plugin_definition(&self) -> Result<crate::MuxMediaResultPluginDefinition, MuxError> {
        plugin_definition(&self.scope)
    }

    pub fn compile_media_result_proposal(
        &self,
        request: &MuxMediaResultRequest,
    ) -> Result<MuxMediaResultProposal, MuxError> {
        self.ensure_active()?;
        MuxMediaResultProposal::compile(&self.scope, &self.registration, request)
    }

    pub fn revoke_registration(&mut self) -> Result<(), MuxError> {
        self.registration
            .revoke(crate::model::RevocationReason::HostRequested)
    }

    pub fn is_registered(&self) -> bool {
        self.registration.state == RegistrationState::Active
    }

    fn ensure_active(&self) -> Result<(), MuxError> {
        if !self.registration.is_active() {
            return Err(MuxError::RegistrationRevoked);
        }
        self.registration.validate_against(&self.scope)
    }
}

pub(crate) fn validate_service_contract() -> Result<(), MuxError> {
    let contract = crate::MuxMediaResultContract::baseline()?;
    if contract.digest() != contract_digest()
        || plugin_version_digest() != crate::plugin_version_digest()
        || provider_digest() != crate::provider_digest()
        || MUX_MEDIA_RESULT_PLUGIN_ID.is_empty()
        || MISSION_MUX_MEDIA_RESULT_CONSUMER_ID.is_empty()
    {
        return Err(MuxError::ContractInvalid(
            "service contract digests do not close",
        ));
    }
    Ok(())
}
