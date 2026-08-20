use std::{collections::BTreeMap, env, fmt};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::transport::VercelTransportError;
use crate::{
    DeploymentEnvironment, DeploymentState, PLUGIN_ID, PreviewDeploymentProposal,
    PreviewDeploymentProposalInput, ProviderProvenance, SERVICE_ID, TargetProjection,
    VERCEL_TOKEN_ENVIRONMENT_VARIABLE, VercelDeliveryError, VercelPluginRegistration, digest_parts,
};

/// Minimal authenticated team payload projected from the official API.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamApi {
    pub id: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub name: String,
}

/// Minimal authenticated project payload projected from the official API.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectApi {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub team_id: Option<String>,
    #[serde(default)]
    pub framework: Option<String>,
}

/// Provider deployment source metadata. Unknown provider fields are retained
/// only as a bounded, non-secret metadata map.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VercelDeploymentSourceApi {
    #[serde(rename = "type", default)]
    pub source_type: Option<String>,
    #[serde(default)]
    pub sha: Option<String>,
    #[serde(rename = "ref", default)]
    pub ref_name: Option<String>,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default)]
    pub repo: Option<String>,
}

/// Minimal deployment payload. The official API has evolved fields over time,
/// so optional fields are ignored when absent while scope fields are checked
/// whenever Vercel returns them.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VercelDeploymentApi {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub uid: Option<String>,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub ready_state: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub team_id: Option<String>,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub created_at: Option<u64>,
    #[serde(default)]
    pub ready_at: Option<u64>,
    #[serde(default)]
    pub meta: BTreeMap<String, String>,
    #[serde(default)]
    pub git_source: Option<VercelDeploymentSourceApi>,
}

impl VercelDeploymentApi {
    fn effective_id(&self) -> Option<&str> {
        (!self.id.trim().is_empty())
            .then_some(self.id.as_str())
            .or_else(|| self.uid.as_deref().filter(|value| !value.trim().is_empty()))
    }

    fn effective_state(&self) -> Option<&str> {
        self.ready_state.as_deref().or(self.state.as_deref())
    }
}

/// Deployment list response from GET /v6/deployments.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentListApi {
    #[serde(default)]
    pub deployments: Vec<VercelDeploymentApi>,
    #[serde(default)]
    pub pagination: Option<DeploymentPaginationApi>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentPaginationApi {
    #[serde(default)]
    pub count: u64,
    #[serde(default)]
    pub next: Option<u64>,
    #[serde(default)]
    pub prev: Option<u64>,
}

/// A single build/log event from GET /v3/deployments/{idOrUrl}/events.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentEventApi {
    #[serde(rename = "type", default)]
    pub event_type: String,
    #[serde(default)]
    pub created: u64,
    #[serde(default)]
    pub payload: Value,
}

/// Normalized source projection exposed to Missions and audit consumers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentSourceProjection {
    pub provider_type: Option<String>,
    pub repository: Option<String>,
    pub reference: Option<String>,
    pub commit_sha: Option<String>,
    pub repo_id: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

/// Normalized deployment identity, target, state, and source projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentProjection {
    pub id: String,
    pub url: String,
    pub name: String,
    pub team_id: String,
    pub project_id: String,
    pub environment: DeploymentEnvironment,
    pub state: DeploymentState,
    pub raw_state: String,
    pub source: Option<DeploymentSourceProjection>,
    pub created_at_ms: Option<u64>,
    pub ready_at_ms: Option<u64>,
    pub scope_digest: String,
    pub provenance: ProviderProvenance,
    pub native: bool,
}

/// Normalized event projection. The raw event payload is represented only by
/// a digest so provider payloads cannot become an accidental secret store.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentEventProjection {
    pub event_type: String,
    pub created_at_ms: u64,
    pub state: DeploymentState,
    pub message: Option<String>,
    pub payload_digest: String,
}

/// Read result for a deployment list.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentListProjection {
    pub deployments: Vec<DeploymentProjection>,
    pub next_cursor: Option<u64>,
    pub scope_digest: String,
    pub provenance: ProviderProvenance,
    pub native: bool,
    pub read_digest: String,
}

/// Read result for deployment events.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentEventsProjection {
    pub deployment_id: String,
    pub events: Vec<DeploymentEventProjection>,
    pub scope_digest: String,
    pub provenance: ProviderProvenance,
    pub native: bool,
    pub read_digest: String,
}

/// Authenticated read-only API boundary. There is intentionally no create,
/// upload, cancel, delete, domain, or environment-variable operation here.
pub trait VercelApiTransport: fmt::Debug + Send + Sync {
    fn provenance(&self) -> ProviderProvenance;

    fn get_team(&self, bearer_token: &str, team_id: &str) -> Result<TeamApi, VercelTransportError>;

    fn get_project(
        &self,
        bearer_token: &str,
        team_id: &str,
        project_id: &str,
    ) -> Result<ProjectApi, VercelTransportError>;

    fn list_deployments(
        &self,
        bearer_token: &str,
        team_id: &str,
        project_id: &str,
    ) -> Result<DeploymentListApi, VercelTransportError>;

    fn get_deployment(
        &self,
        bearer_token: &str,
        team_id: &str,
        deployment_id_or_url: &str,
    ) -> Result<VercelDeploymentApi, VercelTransportError>;

    fn get_deployment_events(
        &self,
        bearer_token: &str,
        team_id: &str,
        deployment_id_or_url: &str,
    ) -> Result<Vec<DeploymentEventApi>, VercelTransportError>;
}

/// The credential resolver receives an opaque reference and returns a
/// zeroizing token for one call. It has no Store, keyring, or browser access.
pub trait VercelCredentialResolver: fmt::Debug + Send + Sync {
    fn resolve(
        &self,
        reference: &crate::VercelSecretReference,
    ) -> Result<Zeroizing<String>, VercelProviderError>;
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvCredentialResolver;

impl VercelCredentialResolver for BlockedEnvCredentialResolver {
    fn resolve(
        &self,
        _reference: &crate::VercelSecretReference,
    ) -> Result<Zeroizing<String>, VercelProviderError> {
        Err(VercelProviderError::BlockedEnv)
    }
}

/// Native credentials are opt-in through one documented environment boundary.
/// A missing or malformed value remains BLOCKED_ENV and cannot create a
/// Connected/native state.
#[derive(Clone, Debug, Default)]
pub struct EnvironmentVercelCredentialResolver;

impl VercelCredentialResolver for EnvironmentVercelCredentialResolver {
    fn resolve(
        &self,
        _reference: &crate::VercelSecretReference,
    ) -> Result<Zeroizing<String>, VercelProviderError> {
        let token = env::var(VERCEL_TOKEN_ENVIRONMENT_VARIABLE)
            .map_err(|_| VercelProviderError::BlockedEnv)?;
        if token.trim().is_empty() || token.chars().any(char::is_control) {
            return Err(VercelProviderError::BlockedEnv);
        }
        Ok(Zeroizing::new(token))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VercelProviderState {
    Disconnected,
    Connected,
    ReachableNonNative,
    BlockedEnv,
    Revoked,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum VercelProviderError {
    #[error("BLOCKED_ENV: Vercel credential is unavailable")]
    BlockedEnv,
    #[error("provider registration is revoked")]
    Revoked,
    #[error("provider is disconnected")]
    Disconnected,
    #[error("invalid provider input: {detail}")]
    InvalidInput { detail: String },
    #[error("provider scope mismatch: {detail}")]
    ScopeMismatch { detail: String },
    #[error("provider digest mismatch: {field}")]
    DigestMismatch { field: String },
    #[error("provider request was rejected: {detail}")]
    Rejected { detail: String },
    #[error("provider response is uncertain: {detail}")]
    Uncertain { detail: String },
    #[error("provider response could not be decoded: {detail}")]
    Decode { detail: String },
    #[error("provider transport failed: {detail}")]
    Transport { detail: String },
    #[error("provider is rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("provider retry budget exhausted: {detail}")]
    RetryExhausted { detail: String },
}

impl From<VercelDeliveryError> for VercelProviderError {
    fn from(error: VercelDeliveryError) -> Self {
        match error {
            VercelDeliveryError::BlockedEnv => Self::BlockedEnv,
            VercelDeliveryError::Revoked => Self::Revoked,
            VercelDeliveryError::ScopeMismatch { detail } => Self::ScopeMismatch { detail },
            VercelDeliveryError::DigestMismatch { field } => Self::DigestMismatch { field },
            VercelDeliveryError::InvalidInput { detail, .. } => Self::InvalidInput { detail },
            other => Self::InvalidInput {
                detail: other.to_string(),
            },
        }
    }
}

impl From<VercelTransportError> for VercelProviderError {
    fn from(error: VercelTransportError) -> Self {
        match error {
            VercelTransportError::Unauthorized { status }
            | VercelTransportError::Rejected { status } => Self::Rejected {
                detail: format!("HTTP {status}"),
            },
            VercelTransportError::RateLimited {
                status: _,
                retry_after_seconds,
            } => Self::RateLimited {
                retry_after_seconds,
            },
            VercelTransportError::Uncertain { status } => Self::Uncertain {
                detail: format!("HTTP {status}"),
            },
            VercelTransportError::Transport { detail } => Self::Transport { detail },
            VercelTransportError::Decode { detail } => Self::Decode { detail },
            VercelTransportError::InvalidConfiguration { detail } => Self::InvalidInput { detail },
            VercelTransportError::RetryExhausted { detail } => Self::RetryExhausted { detail },
        }
    }
}

/// Provider-owned Layer 1 implementation. It can probe and read only.
#[derive(Debug)]
pub struct VercelDeploymentProvider<T, R> {
    registration: VercelPluginRegistration,
    transport: T,
    credentials: R,
    state: VercelProviderState,
    last_target: Option<TargetProjection>,
}

impl<T, R> VercelDeploymentProvider<T, R>
where
    T: VercelApiTransport,
    R: VercelCredentialResolver,
{
    pub fn new(
        registration: VercelPluginRegistration,
        transport: T,
        credentials: R,
    ) -> Result<Self, VercelProviderError> {
        registration.validate().map_err(VercelProviderError::from)?;
        Ok(Self {
            registration,
            transport,
            credentials,
            state: VercelProviderState::Disconnected,
            last_target: None,
        })
    }

    pub fn registration(&self) -> &VercelPluginRegistration {
        &self.registration
    }

    pub fn state(&self) -> VercelProviderState {
        self.state
    }

    pub fn provenance(&self) -> ProviderProvenance {
        match self.state {
            VercelProviderState::BlockedEnv | VercelProviderState::Revoked => {
                ProviderProvenance::BlockedEnv
            }
            VercelProviderState::Disconnected
            | VercelProviderState::Connected
            | VercelProviderState::ReachableNonNative => self.transport.provenance(),
        }
    }

    pub fn is_native(&self) -> bool {
        self.state == VercelProviderState::Connected && self.transport.provenance().is_native()
    }

    pub fn last_target_projection(&self) -> Option<&TargetProjection> {
        self.last_target.as_ref()
    }

    pub fn revoke(&mut self, revoked_at_ms: u64) -> Result<(), VercelProviderError> {
        self.registration
            .revoke(revoked_at_ms)
            .map_err(VercelProviderError::from)?;
        self.state = VercelProviderState::Revoked;
        self.last_target = None;
        Ok(())
    }

    pub fn probe_team_project(&mut self) -> Result<TargetProjection, VercelProviderError> {
        let token = self.authenticated_token()?;
        let target = &self.registration.target;
        let team = self
            .transport
            .get_team(token.as_str(), &target.team_id)
            .map_err(VercelProviderError::from)?;
        if team.id != target.team_id {
            return Err(VercelProviderError::ScopeMismatch {
                detail: "team response id differs from registered team".to_owned(),
            });
        }
        let project = self
            .transport
            .get_project(token.as_str(), &target.team_id, &target.project_id)
            .map_err(VercelProviderError::from)?;
        if project.id != target.project_id {
            return Err(VercelProviderError::ScopeMismatch {
                detail: "project response id differs from registered project".to_owned(),
            });
        }
        if project
            .team_id
            .as_deref()
            .or(project.account_id.as_deref())
            .is_some_and(|value| value != target.team_id)
        {
            return Err(VercelProviderError::ScopeMismatch {
                detail: "project response is not owned by the registered team".to_owned(),
            });
        }

        let provenance = self.provenance();
        let projection = TargetProjection {
            team_id: team.id,
            team_slug: team.slug,
            team_name: team.name,
            project_id: project.id,
            project_name: project.name,
            account_id: project.account_id,
            framework: project.framework,
            environment: DeploymentEnvironment::Preview,
            scope_digest: crate::registration_scope_digest(&self.registration.scope, target),
            provenance,
            native: provenance.is_native(),
        };
        self.state = if provenance.is_native() {
            VercelProviderState::Connected
        } else {
            VercelProviderState::ReachableNonNative
        };
        self.last_target = Some(projection.clone());
        Ok(projection)
    }

    pub fn read_deployments(&mut self) -> Result<DeploymentListProjection, VercelProviderError> {
        let token = self.authenticated_token()?;
        let target = &self.registration.target;
        let response = self
            .transport
            .list_deployments(token.as_str(), &target.team_id, &target.project_id)
            .map_err(VercelProviderError::from)?;
        let provenance = self.provenance();
        let deployments = response
            .deployments
            .iter()
            .map(|deployment| self.project_deployment(deployment))
            .collect::<Result<Vec<_>, _>>()?;
        let read_digest = digest_parts([
            target.team_id.as_str(),
            target.project_id.as_str(),
            &serde_json::to_string(&deployments).map_err(|error| VercelProviderError::Decode {
                detail: error.to_string(),
            })?,
        ]);
        Ok(DeploymentListProjection {
            deployments,
            next_cursor: response.pagination.and_then(|page| page.next),
            scope_digest: crate::registration_scope_digest(&self.registration.scope, target),
            provenance,
            native: provenance.is_native(),
            read_digest,
        })
    }

    pub fn read_deployment(
        &mut self,
        deployment_id_or_url: &str,
    ) -> Result<DeploymentProjection, VercelProviderError> {
        if deployment_id_or_url.trim().is_empty() {
            return Err(VercelProviderError::InvalidInput {
                detail: "deployment id or URL is empty".to_owned(),
            });
        }
        let token = self.authenticated_token()?;
        let target = &self.registration.target;
        let deployment = self
            .transport
            .get_deployment(token.as_str(), &target.team_id, deployment_id_or_url)
            .map_err(VercelProviderError::from)?;
        self.project_deployment(&deployment)
    }

    pub fn read_deployment_events(
        &mut self,
        deployment_id_or_url: &str,
    ) -> Result<DeploymentEventsProjection, VercelProviderError> {
        if deployment_id_or_url.trim().is_empty() {
            return Err(VercelProviderError::InvalidInput {
                detail: "deployment id or URL is empty".to_owned(),
            });
        }
        let token = self.authenticated_token()?;
        let target = &self.registration.target;
        let events = self
            .transport
            .get_deployment_events(token.as_str(), &target.team_id, deployment_id_or_url)
            .map_err(VercelProviderError::from)?;
        let projected = events
            .iter()
            .map(project_event)
            .collect::<Result<Vec<_>, _>>()?;
        let read_digest = digest_parts([
            deployment_id_or_url,
            &serde_json::to_string(&projected).map_err(|error| VercelProviderError::Decode {
                detail: error.to_string(),
            })?,
        ]);
        Ok(DeploymentEventsProjection {
            deployment_id: deployment_id_or_url.to_owned(),
            events: projected,
            scope_digest: crate::registration_scope_digest(&self.registration.scope, target),
            provenance: self.provenance(),
            native: self.provenance().is_native(),
            read_digest,
        })
    }

    /// Probe the exact target and construct a canonical non-mutating Preview
    /// proposal. No transport method available to this provider can create a
    /// deployment.
    pub fn propose_preview(
        &mut self,
        input: PreviewDeploymentProposalInput,
    ) -> Result<PreviewDeploymentProposal, VercelProviderError> {
        input.validate().map_err(VercelProviderError::from)?;
        if input.scope != self.registration.scope {
            return Err(VercelProviderError::ScopeMismatch {
                detail: "proposal Mission scope differs from registration".to_owned(),
            });
        }
        let target_projection = self.probe_team_project()?;
        let target = self.registration.target.clone();
        let mut proposal = PreviewDeploymentProposal {
            proposal_id: String::new(),
            proposal_digest: String::new(),
            scope: input.scope,
            target,
            target_projection,
            source_commit: input.source_commit,
            artifact_digest: input.artifact.artifact_digest,
            file_digests: input.artifact.files,
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: self.registration.plugin_version.clone(),
            service_id: SERVICE_ID.to_owned(),
            registration_digest: self.registration.registration_digest.clone(),
            operation: "preview_proposal".to_owned(),
            requested_at_ms: input.requested_at_ms,
            non_mutating: true,
            external_effect_created: false,
        };
        proposal.proposal_digest = proposal.compute_digest();
        proposal.proposal_id = format!("preview-proposal-{}", &proposal.proposal_digest[..24]);
        proposal.validate().map_err(VercelProviderError::from)?;
        Ok(proposal)
    }

    fn authenticated_token(&mut self) -> Result<Zeroizing<String>, VercelProviderError> {
        if self.registration.is_revoked() {
            self.state = VercelProviderState::Revoked;
            return Err(VercelProviderError::Revoked);
        }
        let token = match self
            .credentials
            .resolve(&self.registration.secret_reference)
        {
            Ok(token) => token,
            Err(error @ VercelProviderError::BlockedEnv) => {
                self.state = VercelProviderState::BlockedEnv;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        if token.trim().is_empty() {
            self.state = VercelProviderState::BlockedEnv;
            return Err(VercelProviderError::BlockedEnv);
        }
        if self.state == VercelProviderState::BlockedEnv {
            self.state = VercelProviderState::Disconnected;
        }
        Ok(token)
    }

    fn project_deployment(
        &self,
        deployment: &VercelDeploymentApi,
    ) -> Result<DeploymentProjection, VercelProviderError> {
        let target = &self.registration.target;
        let id = deployment
            .effective_id()
            .ok_or_else(|| VercelProviderError::Decode {
                detail: "deployment response has no id or uid".to_owned(),
            })?;
        if deployment
            .project_id
            .as_deref()
            .is_some_and(|project_id| project_id != target.project_id)
        {
            return Err(VercelProviderError::ScopeMismatch {
                detail: format!("deployment {id} is outside the registered project"),
            });
        }
        if deployment
            .team_id
            .as_deref()
            .or(deployment.account_id.as_deref())
            .is_some_and(|team_id| team_id != target.team_id)
        {
            return Err(VercelProviderError::ScopeMismatch {
                detail: format!("deployment {id} is outside the registered team"),
            });
        }
        let raw_state = deployment.effective_state().unwrap_or("UNKNOWN").to_owned();
        let provenance = self.provenance();
        Ok(DeploymentProjection {
            id: id.to_owned(),
            url: deployment.url.clone(),
            name: deployment.name.clone(),
            team_id: target.team_id.clone(),
            project_id: target.project_id.clone(),
            environment: DeploymentEnvironment::from_api(deployment.target.as_deref()),
            state: DeploymentState::from_api(Some(raw_state.as_str())),
            raw_state,
            source: deployment_source(deployment),
            created_at_ms: deployment.created_at,
            ready_at_ms: deployment.ready_at,
            scope_digest: crate::registration_scope_digest(&self.registration.scope, target),
            provenance,
            native: provenance.is_native(),
        })
    }
}

fn deployment_source(deployment: &VercelDeploymentApi) -> Option<DeploymentSourceProjection> {
    let source = deployment.git_source.as_ref();
    let metadata = deployment
        .meta
        .iter()
        .filter(|(key, _)| {
            key.starts_with("github")
                || key.starts_with("gitlab")
                || key.starts_with("bitbucket")
                || *key == "commitSha"
                || *key == "branch"
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    if source.is_none() && metadata.is_empty() {
        return None;
    }
    Some(DeploymentSourceProjection {
        provider_type: source.and_then(|item| item.source_type.clone()),
        repository: source
            .and_then(|item| item.repo.clone())
            .or_else(|| metadata.get("githubRepo").cloned()),
        reference: source
            .and_then(|item| item.ref_name.clone())
            .or_else(|| metadata.get("githubCommitRef").cloned())
            .or_else(|| metadata.get("branch").cloned()),
        commit_sha: source
            .and_then(|item| item.sha.clone())
            .or_else(|| metadata.get("githubCommitSha").cloned())
            .or_else(|| metadata.get("commitSha").cloned()),
        repo_id: source
            .and_then(|item| item.repo_id.clone())
            .or_else(|| metadata.get("githubRepoId").cloned()),
        metadata,
    })
}

fn project_event(
    event: &DeploymentEventApi,
) -> Result<DeploymentEventProjection, VercelProviderError> {
    let payload_json =
        serde_json::to_string(&event.payload).map_err(|error| VercelProviderError::Decode {
            detail: error.to_string(),
        })?;
    let ready_state = event
        .payload
        .get("info")
        .and_then(|value| value.get("readyState"))
        .and_then(Value::as_str)
        .or_else(|| event.payload.get("readyState").and_then(Value::as_str));
    let message = event
        .payload
        .get("text")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let raw_state = ready_state
        .or_else(|| (!event.event_type.trim().is_empty()).then_some(event.event_type.as_str()));
    Ok(DeploymentEventProjection {
        event_type: event.event_type.clone(),
        created_at_ms: event.created,
        state: DeploymentState::from_api(raw_state),
        message,
        payload_digest: digest_parts([payload_json.as_str()]),
    })
}
