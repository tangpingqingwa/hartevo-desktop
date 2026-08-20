use std::collections::BTreeSet;
use std::env;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::digest_hex;
use crate::graphql::LinearRateLimitReceipt;
use crate::ids::{
    LinearAppId, LinearIdError, LinearOrganizationId, LinearScopeSet, LinearTeamId, LinearUserId,
};
use crate::provider::LinearProviderProvenance;

pub const LINEAR_OAUTH_AUTHORIZE_ENDPOINT: &str = "https://linear.app/oauth/authorize";
pub const LINEAR_OAUTH_TOKEN_ENDPOINT: &str = "https://api.linear.app/oauth/token";

#[derive(Clone, Eq, PartialEq)]
pub struct LinearAccessToken(String);

impl fmt::Debug for LinearAccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LinearAccessToken([REDACTED])")
    }
}

impl LinearAccessToken {
    pub fn new(value: impl Into<String>) -> Result<Self, LinearOAuthError> {
        let value = value.into();
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(LinearOAuthError::InvalidAccessToken);
        }
        Ok(Self(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "id")]
pub enum LinearActorIdentity {
    User(LinearUserId),
    App(LinearAppId),
}

impl LinearActorIdentity {
    pub fn id(&self) -> &str {
        match self {
            Self::User(id) => id.as_str(),
            Self::App(id) => id.as_str(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinearAppIdentity {
    pub client_id: String,
    #[serde(default)]
    pub application_id: Option<LinearAppId>,
}

impl LinearAppIdentity {
    pub fn new(
        client_id: impl Into<String>,
        application_id: Option<LinearAppId>,
    ) -> Result<Self, LinearOAuthError> {
        let client_id = client_id.into();
        if client_id.trim().is_empty()
            || client_id.len() > 256
            || client_id.chars().any(char::is_control)
        {
            return Err(LinearOAuthError::InvalidAppIdentity);
        }
        Ok(Self {
            client_id,
            application_id,
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct LinearOAuthInstallation {
    organization_id: LinearOrganizationId,
    team_ids: BTreeSet<LinearTeamId>,
    actor: LinearActorIdentity,
    app_identity: LinearAppIdentity,
    scopes: LinearScopeSet,
    token_expires_at_ms: u64,
    access_token: LinearAccessToken,
}

impl fmt::Debug for LinearOAuthInstallation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinearOAuthInstallation")
            .field("organization_id", &self.organization_id)
            .field("team_ids", &self.team_ids)
            .field("actor", &self.actor)
            .field("app_identity", &self.app_identity)
            .field("scopes", &self.scopes)
            .field("token_expires_at_ms", &self.token_expires_at_ms)
            .field("access_token", &"[REDACTED]")
            .finish()
    }
}

impl LinearOAuthInstallation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization_id: LinearOrganizationId,
        team_ids: impl IntoIterator<Item = LinearTeamId>,
        actor: LinearActorIdentity,
        app_identity: LinearAppIdentity,
        scopes: LinearScopeSet,
        token_expires_at_ms: u64,
        access_token: LinearAccessToken,
    ) -> Result<Self, LinearOAuthError> {
        let team_ids = team_ids.into_iter().collect::<BTreeSet<_>>();
        if team_ids.is_empty() {
            return Err(LinearOAuthError::EmptyTeamScope);
        }
        if !scopes.contains("read") {
            return Err(LinearOAuthError::MissingReadScope);
        }
        if token_expires_at_ms == 0 {
            return Err(LinearOAuthError::InvalidTokenExpiry);
        }
        if access_token.is_empty() {
            return Err(LinearOAuthError::InvalidAccessToken);
        }
        Ok(Self {
            organization_id,
            team_ids,
            actor,
            app_identity,
            scopes,
            token_expires_at_ms,
            access_token,
        })
    }

    pub fn organization_id(&self) -> &LinearOrganizationId {
        &self.organization_id
    }

    pub fn team_ids(&self) -> &BTreeSet<LinearTeamId> {
        &self.team_ids
    }

    pub fn actor(&self) -> &LinearActorIdentity {
        &self.actor
    }

    pub fn app_identity(&self) -> &LinearAppIdentity {
        &self.app_identity
    }

    pub fn scopes(&self) -> &LinearScopeSet {
        &self.scopes
    }

    pub const fn token_expires_at_ms(&self) -> u64 {
        self.token_expires_at_ms
    }

    pub fn token_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.token_expires_at_ms
    }

    pub(crate) fn access_token(&self) -> LinearAccessToken {
        self.access_token.clone()
    }

    pub fn scope_digest(&self) -> String {
        digest_hex(self.scopes.to_string().as_bytes())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinearOAuthApp {
    pub client_id: String,
    pub redirect_uri: Url,
    pub scopes: LinearScopeSet,
    pub state: String,
}

impl LinearOAuthApp {
    pub fn new(
        client_id: impl Into<String>,
        redirect_uri: Url,
        scopes: LinearScopeSet,
        state: impl Into<String>,
    ) -> Result<Self, LinearOAuthError> {
        let client_id = client_id.into();
        let state = state.into();
        if client_id.trim().is_empty() || state.trim().is_empty() {
            return Err(LinearOAuthError::InvalidOAuthRequest);
        }
        if redirect_uri.scheme() != "https" {
            return Err(LinearOAuthError::InvalidRedirectUri);
        }
        if scopes.is_empty() {
            return Err(LinearOAuthError::InvalidOAuthRequest);
        }
        Ok(Self {
            client_id,
            redirect_uri,
            scopes,
            state,
        })
    }

    pub fn authorization_url(&self) -> Result<Url, LinearOAuthError> {
        let mut url = Url::parse(LINEAR_OAUTH_AUTHORIZE_ENDPOINT)
            .map_err(|_| LinearOAuthError::InvalidOAuthRequest)?;
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("client_id", &self.client_id)
                .append_pair("redirect_uri", self.redirect_uri.as_str())
                .append_pair("response_type", "code")
                .append_pair("scope", &self.scopes.to_string())
                .append_pair("state", &self.state);
        }
        Ok(url)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinearOAuthProbeReceipt {
    pub organization_id: LinearOrganizationId,
    pub team_ids: BTreeSet<LinearTeamId>,
    pub actor: LinearActorIdentity,
    pub app_identity: LinearAppIdentity,
    pub scopes: LinearScopeSet,
    pub token_expires_at_ms: u64,
    pub observed_viewer_id: String,
    pub observed_organization_id: String,
    pub observed_team_ids: BTreeSet<LinearTeamId>,
    pub rate_limit: LinearRateLimitReceipt,
    pub provider_provenance: LinearProviderProvenance,
    pub observed_at_ms: u64,
    pub evidence_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinearEnvProbe {
    Ready(LinearOAuthInstallation),
    BlockedEnv { missing: Vec<String> },
}

impl LinearEnvProbe {
    pub fn from_process_env() -> Result<Self, LinearOAuthError> {
        let required = [
            "HARTEVO_LINEAR_ACCESS_TOKEN",
            "HARTEVO_LINEAR_ORGANIZATION_ID",
            "HARTEVO_LINEAR_TEAM_IDS",
            "HARTEVO_LINEAR_ACTOR_ID",
            "HARTEVO_LINEAR_ACTOR_KIND",
            "HARTEVO_LINEAR_APP_CLIENT_ID",
            "HARTEVO_LINEAR_SCOPES",
            "HARTEVO_LINEAR_TOKEN_EXPIRES_AT_MS",
        ];
        let missing = required
            .iter()
            .filter(|name| {
                env::var(name)
                    .ok()
                    .is_none_or(|value| value.trim().is_empty())
            })
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Ok(Self::BlockedEnv { missing });
        }

        let token = LinearAccessToken::new(
            env::var("HARTEVO_LINEAR_ACCESS_TOKEN")
                .map_err(|error| LinearOAuthError::Environment(error.to_string()))?,
        )?;
        let organization_id =
            LinearOrganizationId::new(env_value("HARTEVO_LINEAR_ORGANIZATION_ID")?)?;
        let team_ids = env_value("HARTEVO_LINEAR_TEAM_IDS")?
            .split(',')
            .map(|value| LinearTeamId::new(value.trim()))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let actor_id = env_value("HARTEVO_LINEAR_ACTOR_ID")?;
        let actor = match env_value("HARTEVO_LINEAR_ACTOR_KIND")?
            .to_ascii_lowercase()
            .as_str()
        {
            "user" => LinearActorIdentity::User(LinearUserId::new(actor_id)?),
            "app" => LinearActorIdentity::App(LinearAppId::new(actor_id)?),
            _ => return Err(LinearOAuthError::InvalidActorKind),
        };
        let application_id = env::var("HARTEVO_LINEAR_APP_ID")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(LinearAppId::new)
            .transpose()?;
        let app_identity =
            LinearAppIdentity::new(env_value("HARTEVO_LINEAR_APP_CLIENT_ID")?, application_id)?;
        let scopes = LinearScopeSet::new(
            env_value("HARTEVO_LINEAR_SCOPES")?
                .split(',')
                .map(|value| value.trim().to_owned()),
        )?;
        let token_expires_at_ms = env_value("HARTEVO_LINEAR_TOKEN_EXPIRES_AT_MS")?
            .parse()
            .map_err(|_| LinearOAuthError::InvalidTokenExpiry)?;
        Ok(Self::Ready(LinearOAuthInstallation::new(
            organization_id,
            team_ids,
            actor,
            app_identity,
            scopes,
            token_expires_at_ms,
            token,
        )?))
    }
}

fn env_value(name: &str) -> Result<String, LinearOAuthError> {
    env::var(name).map_err(|error| LinearOAuthError::Environment(error.to_string()))
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LinearOAuthError {
    #[error("invalid Linear access token")]
    InvalidAccessToken,
    #[error("Linear installation must bind at least one team")]
    EmptyTeamScope,
    #[error("Linear installation must request the read scope")]
    MissingReadScope,
    #[error("Linear token expiry is invalid")]
    InvalidTokenExpiry,
    #[error("Linear app identity is invalid")]
    InvalidAppIdentity,
    #[error("Linear OAuth request is invalid")]
    InvalidOAuthRequest,
    #[error("Linear OAuth redirect URI must use HTTPS")]
    InvalidRedirectUri,
    #[error("Linear OAuth actor kind must be user or app")]
    InvalidActorKind,
    #[error("Linear OAuth environment could not be read: {0}")]
    Environment(String),
    #[error("Linear identifier is invalid: {0}")]
    InvalidIdentifier(#[from] LinearIdError),
}
