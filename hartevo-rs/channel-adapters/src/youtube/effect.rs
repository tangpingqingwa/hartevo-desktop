//! Typed ingress for an already-authorized YouTube publish Effect.
//!
//! This module records the authority decision that was made elsewhere. It has
//! no approval, execution, or credential-issuance method; the verification
//! service can only consume the exact boundary and perform provider readback.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{
    DraftVideoPublishRequest, YouTubeError, YouTubePublishBinding, is_sha256, sha256_json, valid_id,
};

pub const YOUTUBE_PUBLISH_PLUGIN_ID: &str = "youtube.publish";
pub const YOUTUBE_PUBLISH_PLUGIN_REVISION: u64 = 1;
const YOUTUBE_PUBLISH_PLUGIN_CONTRACT: &str = "youtube-controlled-publish-receipt-readback/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YouTubePluginIdentity {
    plugin_id: String,
    plugin_revision: u64,
    contract_digest: String,
}

impl YouTubePluginIdentity {
    pub fn new(
        plugin_id: impl Into<String>,
        plugin_revision: u64,
        contract_digest: impl Into<String>,
    ) -> Result<Self, YouTubeError> {
        let identity = Self {
            plugin_id: valid_id(plugin_id.into(), "YouTube plugin ID", 128)?,
            plugin_revision,
            contract_digest: contract_digest.into(),
        };
        if identity.plugin_revision == 0 || !is_sha256(&identity.contract_digest) {
            return Err(YouTubeError::InvalidRequest(
                "YouTube plugin identity must have a positive revision and SHA-256 contract digest",
            ));
        }
        Ok(identity)
    }

    pub fn youtube_publish_v1() -> Self {
        let contract_digest = sha256_json(&serde_json::json!({
            "plugin_id": YOUTUBE_PUBLISH_PLUGIN_ID,
            "plugin_revision": YOUTUBE_PUBLISH_PLUGIN_REVISION,
            "contract": YOUTUBE_PUBLISH_PLUGIN_CONTRACT,
        }));
        Self {
            plugin_id: YOUTUBE_PUBLISH_PLUGIN_ID.to_owned(),
            plugin_revision: YOUTUBE_PUBLISH_PLUGIN_REVISION,
            contract_digest,
        }
    }

    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    pub const fn plugin_revision(&self) -> u64 {
        self.plugin_revision
    }

    pub fn contract_digest(&self) -> &str {
        &self.contract_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct YouTubeEffectId(String);

impl YouTubeEffectId {
    pub fn new(value: impl Into<String>) -> Result<Self, YouTubeError> {
        Ok(Self(valid_id(value.into(), "YouTube effect ID", 256)?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YouTubeAuthorizedPublishEffect {
    plugin: YouTubePluginIdentity,
    effect_id: YouTubeEffectId,
    effect_revision: u64,
    binding: YouTubePublishBinding,
    request: DraftVideoPublishRequest,
    effect_digest: String,
    authorization_digest: String,
    scope_digest: String,
    authorized_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
}

impl YouTubeAuthorizedPublishEffect {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plugin: YouTubePluginIdentity,
        effect_id: YouTubeEffectId,
        effect_revision: u64,
        binding: YouTubePublishBinding,
        request: DraftVideoPublishRequest,
        authorization_digest: impl Into<String>,
        scope_digest: impl Into<String>,
        authorized_at: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Result<Self, YouTubeError> {
        let mut effect = Self {
            plugin,
            effect_id,
            effect_revision,
            binding,
            request,
            effect_digest: String::new(),
            authorization_digest: authorization_digest.into(),
            scope_digest: scope_digest.into(),
            authorized_at,
            valid_until,
        };
        effect.effect_digest = effect.canonical_digest();
        effect.validate_at(authorized_at)?;
        Ok(effect)
    }

    pub const fn plugin(&self) -> &YouTubePluginIdentity {
        &self.plugin
    }

    pub const fn effect_id(&self) -> &YouTubeEffectId {
        &self.effect_id
    }

    pub const fn effect_revision(&self) -> u64 {
        self.effect_revision
    }

    pub const fn binding(&self) -> &YouTubePublishBinding {
        &self.binding
    }

    pub const fn request(&self) -> &DraftVideoPublishRequest {
        &self.request
    }

    pub fn effect_digest(&self) -> &str {
        &self.effect_digest
    }

    pub fn authorization_digest(&self) -> &str {
        &self.authorization_digest
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub const fn authorized_at(&self) -> DateTime<Utc> {
        self.authorized_at
    }

    pub const fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }

    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<(), YouTubeError> {
        if self.effect_revision == 0
            || self.binding != *self.request.binding()
            || self.valid_until <= self.authorized_at
            || !is_sha256(&self.authorization_digest)
            || !is_sha256(&self.scope_digest)
            || !is_sha256(&self.effect_digest)
            || self.effect_digest != self.canonical_digest()
        {
            return Err(YouTubeError::EffectBoundaryMismatch);
        }
        self.request.validate_at(self.request.created_at())?;
        if now < self.authorized_at || now >= self.valid_until {
            return Err(YouTubeError::EffectExpired);
        }
        Ok(())
    }

    fn canonical_digest(&self) -> String {
        sha256_json(&serde_json::json!({
            "schema": "hartevo-youtube-authorized-publish-effect/v1",
            "plugin": self.plugin,
            "effect_id": self.effect_id,
            "effect_revision": self.effect_revision,
            "binding": self.binding,
            "request_digest": self.request.request_digest(),
            "idempotency_key": self.request.idempotency_key(),
            "authorization_digest": self.authorization_digest,
            "scope_digest": self.scope_digest,
            "authorized_at": self.authorized_at,
            "valid_until": self.valid_until,
        }))
    }
}
