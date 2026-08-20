//! Layer-1 governed Mux media-delivery result plugin.
//!
//! The crate is intentionally a standalone nested workspace.  It exposes a
//! typed, read/proposal/recording-only seam for bounded Mux Video metadata.
//! It does not resolve native credentials, make live HTTPS calls, download
//! media, mint playback tokens, mutate Mux resources, retain viewer data, or
//! become Hartevo Effect, Receipt, Verification, or Outcome authority.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

mod consumer;
mod model;
mod provider;
mod service;
mod transport;

pub use consumer::{MissionMuxMediaConsumer, MissionMuxMediaObservation, MissionMuxMediaResult};
pub use model::{
    AssetMetadataProjection, AssetScope, ConsentOperation, ConsentScope,
    DeliveryReadinessProjection, Digest, DimensionProjection, EncodingProjection, EncodingScope,
    MissionScope, MuxApiHost, MuxAssetId, MuxAssetPayload, MuxAssetRevision, MuxAssetState,
    MuxCursor, MuxEncodingRevision, MuxEnvironment, MuxEnvironmentScope, MuxError,
    MuxMediaResultEvidence, MuxMediaResultProposal, MuxMediaResultRequest,
    MuxPlaybackAssociationPayload, MuxPlaybackId, MuxPlaybackPayload, MuxPlaybackPolicy,
    MuxPlaybackProjection, MuxPlaybackRevision, MuxPlaybackScope, MuxProgressPayload,
    MuxProjectScope, MuxReadReceipt, MuxRegistration, MuxScope, MuxScopeInput, MuxSecretKind,
    MuxTrackId, MuxTrackKind, MuxTrackPayload, MuxTrackProjection, MuxTrackRevision, MuxTrackScope,
    MuxTrackStatus, MuxTransportMode, PlaybackPolicyRevision, ProjectScope, RegistrationState,
    RevocationReason, SecretReference, StaticRenditionScope, WorkProductScope,
};
pub use provider::{
    MuxProvider, MuxProviderResponse, MuxReadBounds, MuxReadRequest, MuxRetryPolicy,
    ProviderFailureClass, ProviderProvenance, classify_status,
};
pub use service::{
    MuxMediaResultCapabilities, MuxMediaResultService, MuxProviderDefinition, MuxServiceDefinition,
};
pub use transport::{
    BlockedEnvMuxTransport, FixtureMuxTransport, LoopbackMuxTransport, MuxEndpoint,
    MuxEndpointKind, MuxHttpRequest, MuxHttpResponse, MuxJsonResponse, MuxResponseBody,
    MuxTransport, MuxTransportError, NativeMuxHttpsTransport, RecordingMuxTransport,
};

pub const MUX_MEDIA_RESULT_SCHEMA_VERSION: &str = "hartevo.mux-media-result.contract/v1";
pub const MUX_MEDIA_RESULT_CONTRACT_VERSION: &str = "mux-media-result/v1";
pub const MUX_MEDIA_RESULT_PLUGIN_ID: &str = "mux-media-result";
pub const MUX_MEDIA_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const MUX_MEDIA_RESULT_SERVICE_ID: &str = "mux.media.result";
pub const MUX_MEDIA_RESULT_SERVICE_NAME: &str = "MuxMediaResultService";
pub const MUX_MEDIA_RESULT_PROVIDER_ID: &str = "mux.video.metadata";
pub const MUX_MEDIA_RESULT_PROVIDER_NAME: &str = "MuxProvider";
pub const MISSION_MUX_MEDIA_RESULT_CONSUMER_ID: &str = "mission.mux-media.result";
pub const MISSION_MUX_MEDIA_RESULT_CONSUMER_NAME: &str = "MissionMuxMediaConsumer";
pub const MUX_MEDIA_RESULT_PROVIDER_REVISION: &str = "mux-video-api-v1-read-r1";
pub const MUX_MEDIA_RESULT_SERVICE_SCHEMA: &str = "hartevo.mux-media-result-service/v1";
pub const MUX_MEDIA_RESULT_PROVIDER_SCHEMA: &str = "hartevo.mux-provider/v1";
pub const MISSION_MUX_MEDIA_RESULT_CONSUMER_SCHEMA: &str =
    "hartevo.mission-mux-media-result-consumer/v1";
pub const MUX_MEDIA_RESULT_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/mux-media-result/mux-media-result.v1.json");
pub const MUX_API_ORIGIN: &str = "https://api.mux.com";
pub const MUX_MEDIA_RESULT_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const MUX_MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MUX_MAX_TRACKS: usize = 64;
pub const MUX_MAX_PLAYBACK_IDS: usize = 32;
pub const MUX_MAX_PAGES: u16 = 4;
pub const MUX_MAX_CURSOR_BYTES: usize = 256;
pub const MUX_MAX_RETRY_ATTEMPTS: u8 = 3;
pub const MUX_MAX_BACKOFF_SECONDS: u32 = 30;

/// SHA-256 of the exact version text used by this crate.
pub fn plugin_version_digest() -> Digest {
    model::domain_digest(
        "hartevo:mux-media-result:plugin-version:v1",
        MUX_MEDIA_RESULT_PLUGIN_VERSION,
    )
}

/// SHA-256 of the exact checked-in contract bytes.
pub fn contract_digest() -> Digest {
    Digest::sha256(MUX_MEDIA_RESULT_CONTRACT_JSON.as_bytes())
}

/// SHA-256 binding the provider identity, revision, schema, and GET allowlist.
pub fn provider_digest() -> Digest {
    model::domain_digest(
        "hartevo:mux-media-result:provider:v1",
        &(
            MUX_MEDIA_RESULT_PROVIDER_ID,
            MUX_MEDIA_RESULT_PROVIDER_REVISION,
            MUX_MEDIA_RESULT_PROVIDER_SCHEMA,
            [
                "GET /video/v1/assets/{ASSET_ID}",
                "GET /video/v1/assets?limit=25&page<=4&cursor<=256",
                "GET /video/v1/playback-ids/{PLAYBACK_ID}",
                "asset_track_metadata_projection",
                "asset_delivery_readiness_projection",
            ],
        ),
    )
}

/// The fixed authority boundary of this Layer-1 plugin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
        false
    }

    pub const fn external_writes() -> bool {
        false
    }

    pub const fn signed_token_generation() -> bool {
        false
    }

    pub const fn media_download() -> bool {
        false
    }

    pub const fn viewer_analytics() -> bool {
        false
    }

    pub const fn adopted_outcome() -> bool {
        false
    }
}

/// A typed validation view of the checked-in JSON contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MuxMediaResultContract {
    #[serde(rename = "$schema")]
    pub schema_url: String,
    #[serde(rename = "$id")]
    pub contract_id: String,
    pub title: String,
    pub description: String,
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub layer: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub provider_revision: String,
    pub operations: Vec<String>,
    pub scope: Vec<String>,
    pub digests: Vec<String>,
    pub allowlisted_get_seams: Vec<MuxGetSeamContract>,
    pub bounds: MuxBoundsContract,
    pub redaction: MuxRedactionContract,
    pub registration: MuxRegistrationContract,
    pub authority: MuxAuthorityContract,
    pub evidence_modes: Vec<String>,
    pub forbidden: Vec<String>,
    pub native_gap: MuxNativeGapContract,
    pub honest_native_gap: String,
    pub primary_api_basis: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MuxGetSeamContract {
    pub name: String,
    pub method: String,
    pub path: String,
    pub projection: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MuxBoundsContract {
    pub max_response_bytes: usize,
    pub max_tracks: usize,
    pub max_playback_ids: usize,
    pub max_pages: u16,
    pub max_cursor_bytes: usize,
    pub max_retry_attempts: u8,
    pub max_backoff_seconds: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MuxRedactionContract {
    pub request_receipts: String,
    pub result_receipts: String,
    pub removed: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MuxRegistrationContract {
    pub bound_fields: Vec<String>,
    pub version_and_scope_bound: bool,
    pub contract_bound: bool,
    pub provider_bound: bool,
    pub reversible: bool,
    pub revocable: bool,
    pub fail_closed_on: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct MuxAuthorityContract {
    pub connected: bool,
    pub native: bool,
    pub external_writes: bool,
    pub asset_mutation: bool,
    pub playback_mutation: bool,
    pub static_rendition_generation: bool,
    pub signed_token_generation: bool,
    pub media_download: bool,
    pub webhooks: bool,
    pub viewer_analytics: bool,
    pub durable_native_receipt: bool,
    pub independent_read_back: bool,
    pub kernel_outcome_adoption: bool,
    pub publication_authority: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MuxNativeGapContract {
    pub status: String,
    pub connected: bool,
    pub deferred_to: String,
    pub fail_closed_cases: Vec<String>,
}

impl MuxMediaResultContract {
    pub fn baseline() -> Result<Self, MuxError> {
        let contract =
            serde_json::from_str::<Self>(MUX_MEDIA_RESULT_CONTRACT_JSON).map_err(|_| {
                MuxError::ContractInvalid("contract JSON does not match its typed schema")
            })?;
        contract.validate()?;
        Ok(contract)
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    pub fn validate(&self) -> Result<(), MuxError> {
        if self.schema_version != MUX_MEDIA_RESULT_SCHEMA_VERSION
            || self.contract_version != MUX_MEDIA_RESULT_CONTRACT_VERSION
            || self.plugin_version != MUX_MEDIA_RESULT_PLUGIN_VERSION
            || self.layer != "Layer-1"
            || self.service_id != MUX_MEDIA_RESULT_SERVICE_ID
            || self.provider_id != MUX_MEDIA_RESULT_PROVIDER_ID
            || self.consumer_id != MISSION_MUX_MEDIA_RESULT_CONSUMER_ID
            || self.provider_revision != MUX_MEDIA_RESULT_PROVIDER_REVISION
        {
            return Err(MuxError::ContractInvalid("contract identity drifted"));
        }

        let required_operations = [
            "describe_capabilities",
            "register",
            "revoke_registration",
            "compile_media_result_proposal",
            "read_asset_metadata",
            "read_playback_association",
            "project_track_metadata",
            "project_delivery_readiness",
            "record_redacted_receipt",
            "consume_media_result",
        ];
        if self.operations != required_operations {
            return Err(MuxError::ContractInvalid("operation allowlist drifted"));
        }

        let required_scope = [
            "mux_environment_and_revision",
            "mux_api_host",
            "opaque_secret_reference_and_revision",
            "asset_id_and_revision",
            "playback_id_and_revision",
            "playback_policy_and_revision",
            "track_id_and_revision",
            "static_rendition_scope_and_revision",
            "encoding_scope_and_revision",
            "project_id_and_revision",
            "mission_id_and_revision",
            "work_product_id_and_revision",
            "consent_id_and_revision",
        ];
        if self.scope != required_scope {
            return Err(MuxError::ContractInvalid("scope allowlist drifted"));
        }

        let required_digests = [
            "plugin_version_digest",
            "contract_digest",
            "provider_digest",
            "scope_digest",
            "registration_digest",
            "asset_digest",
            "playback_digest",
            "track_digest",
            "encoding_digest",
            "proposal_digest",
            "request_digest",
            "response_digest",
            "receipt_digest",
            "evidence_digest",
            "observation_digest",
        ];
        if self.digests != required_digests {
            return Err(MuxError::ContractInvalid("digest allowlist drifted"));
        }

        let required_seams = [
            ("asset_list_metadata", "GET", "/video/v1/assets"),
            ("asset_metadata", "GET", "/video/v1/assets/{ASSET_ID}"),
            (
                "playback_association",
                "GET",
                "/video/v1/playback-ids/{PLAYBACK_ID}",
            ),
            (
                "track_metadata_projection",
                "GET",
                "/video/v1/assets/{ASSET_ID}",
            ),
            (
                "delivery_readiness_projection",
                "GET",
                "/video/v1/assets/{ASSET_ID}",
            ),
        ];
        if self.allowlisted_get_seams.len() != required_seams.len()
            || self
                .allowlisted_get_seams
                .iter()
                .zip(required_seams)
                .any(|(actual, expected)| {
                    actual.name != expected.0
                        || actual.method != expected.1
                        || actual.path != expected.2
                })
        {
            return Err(MuxError::ContractInvalid("GET seam allowlist drifted"));
        }

        if self.bounds.max_response_bytes != MUX_MAX_RESPONSE_BYTES
            || self.bounds.max_tracks != MUX_MAX_TRACKS
            || self.bounds.max_playback_ids != MUX_MAX_PLAYBACK_IDS
            || self.bounds.max_pages != MUX_MAX_PAGES
            || self.bounds.max_cursor_bytes != MUX_MAX_CURSOR_BYTES
            || self.bounds.max_retry_attempts != MUX_MAX_RETRY_ATTEMPTS
            || self.bounds.max_backoff_seconds != MUX_MAX_BACKOFF_SECONDS
        {
            return Err(MuxError::ContractInvalid("contract bounds drifted"));
        }

        let authority = &self.authority;
        if authority.connected
            || authority.native
            || authority.external_writes
            || authority.asset_mutation
            || authority.playback_mutation
            || authority.static_rendition_generation
            || authority.signed_token_generation
            || authority.media_download
            || authority.webhooks
            || authority.viewer_analytics
            || authority.durable_native_receipt
            || authority.independent_read_back
            || authority.kernel_outcome_adoption
            || authority.publication_authority
            || self.native_gap.status != MUX_MEDIA_RESULT_BLOCKED_ENV
            || self.native_gap.connected
        {
            return Err(MuxError::ContractInvalid(
                "Layer-1 authority boundary is not closed",
            ));
        }

        if self.evidence_modes
            != [
                "recording",
                "fixture",
                "loopback",
                MUX_MEDIA_RESULT_BLOCKED_ENV,
            ]
            || self.redaction.removed.is_empty()
            || !self.registration.version_and_scope_bound
            || !self.registration.contract_bound
            || !self.registration.provider_bound
            || !self.registration.reversible
            || !self.registration.revocable
        {
            return Err(MuxError::ContractInvalid(
                "redaction, modes, or registration drifted",
            ));
        }
        Ok(())
    }
}

/// The local contribution metadata.  It is descriptive only; mounting it in
/// a host runtime is deliberately outside this Layer-1 root.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MuxMediaResultPluginDefinition {
    pub plugin_id: String,
    pub plugin_version: String,
    pub plugin_version_digest: Digest,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_digest: Digest,
    pub service_id: String,
    pub consumer_id: String,
    pub scope_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub external_writes: bool,
    pub outcome_authority: bool,
}

impl MuxMediaResultPluginDefinition {
    pub fn validate(&self) -> Result<(), MuxError> {
        if self.plugin_id != MUX_MEDIA_RESULT_PLUGIN_ID
            || self.plugin_version != MUX_MEDIA_RESULT_PLUGIN_VERSION
            || self.plugin_version_digest != plugin_version_digest()
            || self.contract_version != MUX_MEDIA_RESULT_CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != MUX_MEDIA_RESULT_PROVIDER_ID
            || self.provider_digest != provider_digest()
            || self.service_id != MUX_MEDIA_RESULT_SERVICE_ID
            || self.consumer_id != MISSION_MUX_MEDIA_RESULT_CONSUMER_ID
            || self.connected
            || self.native
            || self.external_writes
            || self.outcome_authority
        {
            return Err(MuxError::RegistrationTampered);
        }
        if !self.scope_digest.is_sha256() {
            return Err(MuxError::InvalidDigest("plugin definition scope digest"));
        }
        Ok(())
    }
}

pub fn plugin_definition(scope: &MuxScope) -> Result<MuxMediaResultPluginDefinition, MuxError> {
    let definition = MuxMediaResultPluginDefinition {
        plugin_id: MUX_MEDIA_RESULT_PLUGIN_ID.to_owned(),
        plugin_version: MUX_MEDIA_RESULT_PLUGIN_VERSION.to_owned(),
        plugin_version_digest: plugin_version_digest(),
        contract_version: MUX_MEDIA_RESULT_CONTRACT_VERSION.to_owned(),
        contract_digest: contract_digest(),
        provider_id: MUX_MEDIA_RESULT_PROVIDER_ID.to_owned(),
        provider_digest: provider_digest(),
        service_id: MUX_MEDIA_RESULT_SERVICE_ID.to_owned(),
        consumer_id: MISSION_MUX_MEDIA_RESULT_CONSUMER_ID.to_owned(),
        scope_digest: scope.digest(),
        connected: false,
        native: false,
        external_writes: false,
        outcome_authority: false,
    };
    definition.validate()?;
    Ok(definition)
}

pub(crate) use model::domain_digest;

use serde::{Deserialize, Serialize};
