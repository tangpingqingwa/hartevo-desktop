use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::digest_hex;
use crate::graphql::{
    LINEAR_CYCLES_QUERY, LINEAR_ISSUES_QUERY, LINEAR_OAUTH_PROBE_QUERY, LINEAR_PROJECTS_QUERY,
    LinearCycle, LinearGraphQlDecodeError, LinearGraphQlRequest, LinearGraphQlRequestError,
    LinearGraphQlTransport, LinearHttpsGraphQlTransport, LinearIssue, LinearPageRequest,
    LinearProject, LinearRateLimitReceipt, LinearReadPage, LinearReadReceipt, LinearResourceKind,
    LinearTeamPageData, decode_graphql, request_variables,
};
use crate::ids::{
    LinearCursor, LinearIdError, LinearIssueId, LinearOrganizationId, LinearProjectId, LinearTeamId,
};
use crate::oauth::{
    LinearActorIdentity, LinearOAuthError, LinearOAuthInstallation, LinearOAuthProbeReceipt,
};
use crate::webhook::{
    LinearReplayFence, LinearWebhookError, LinearWebhookEvent, LinearWebhookEventKind,
    LinearWebhookHeaders, LinearWebhookOutcome, verify_and_fence_linear_webhook,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const LINEAR_PROVIDER_ID: &str = "linear.oauth.work";
pub const LINEAR_PROVIDER_VERSION: u16 = 1;
pub const LINEAR_DEFAULT_REPLAY_FENCE_CAPACITY: usize = 1_024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinearProviderProvenance {
    NativeHttps,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl LinearProviderProvenance {
    pub const fn is_native(self) -> bool {
        matches!(self, Self::NativeHttps)
    }

    pub const fn is_connected_eligible(self) -> bool {
        self.is_native()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum LinearCapabilityState {
    Mounted {
        provenance: LinearProviderProvenance,
    },
    Connected {
        provenance: LinearProviderProvenance,
        observed_at_ms: u64,
    },
    Revoked {
        provenance: LinearProviderProvenance,
        reason: LinearRevocationReason,
        revoked_at_ms: u64,
    },
    Unmounted,
}

impl LinearCapabilityState {
    pub const fn is_native_connected(&self) -> bool {
        matches!(
            self,
            Self::Connected {
                provenance: LinearProviderProvenance::NativeHttps,
                ..
            }
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinearRevocationReason {
    OAuthRevoked,
    PermissionChange,
    TokenExpired,
    Unauthorized,
    Manual,
    Unmounted,
}

pub struct LinearOAuthWorkProvider<T> {
    transport: T,
    installation: LinearOAuthInstallation,
    provenance: LinearProviderProvenance,
    state: LinearCapabilityState,
    replay_fence: LinearReplayFence,
}

impl<T: fmt::Debug> fmt::Debug for LinearOAuthWorkProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinearOAuthWorkProvider")
            .field("transport", &self.transport)
            .field("installation", &self.installation)
            .field("provenance", &self.provenance)
            .field("state", &self.state)
            .field("replay_fence", &self.replay_fence)
            .finish()
    }
}

impl<T> LinearOAuthWorkProvider<T> {
    pub fn new(transport: T, installation: LinearOAuthInstallation) -> Self {
        Self::with_provenance(transport, installation, LinearProviderProvenance::Fixture)
    }

    pub fn new_loopback(transport: T, installation: LinearOAuthInstallation) -> Self {
        Self::with_provenance(transport, installation, LinearProviderProvenance::Loopback)
    }

    pub fn new_blocked_env(transport: T, installation: LinearOAuthInstallation) -> Self {
        Self::with_provenance(
            transport,
            installation,
            LinearProviderProvenance::BlockedEnv,
        )
    }

    fn with_provenance(
        transport: T,
        installation: LinearOAuthInstallation,
        provenance: LinearProviderProvenance,
    ) -> Self {
        Self {
            transport,
            installation,
            provenance,
            state: LinearCapabilityState::Mounted { provenance },
            replay_fence: LinearReplayFence::new(LINEAR_DEFAULT_REPLAY_FENCE_CAPACITY)
                .expect("positive default replay fence capacity"),
        }
    }

    pub fn installation(&self) -> &LinearOAuthInstallation {
        &self.installation
    }

    pub const fn provider_id() -> &'static str {
        LINEAR_PROVIDER_ID
    }

    pub const fn provider_version() -> u16 {
        LINEAR_PROVIDER_VERSION
    }

    pub const fn provenance(&self) -> LinearProviderProvenance {
        self.provenance
    }

    pub const fn state(&self) -> &LinearCapabilityState {
        &self.state
    }

    pub const fn is_native(&self) -> bool {
        self.provenance.is_native()
    }

    pub fn is_connected(&self) -> bool {
        self.state.is_native_connected()
    }

    pub fn replay_fence(&self) -> &LinearReplayFence {
        &self.replay_fence
    }

    pub fn revoke(&mut self, reason: LinearRevocationReason, now_ms: u64) {
        self.state = LinearCapabilityState::Revoked {
            provenance: self.provenance,
            reason,
            revoked_at_ms: now_ms,
        };
    }

    pub fn unmount(&mut self, now_ms: u64) {
        self.revoke(LinearRevocationReason::Unmounted, now_ms);
        self.state = LinearCapabilityState::Unmounted;
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

impl LinearOAuthWorkProvider<LinearHttpsGraphQlTransport> {
    pub fn new_https(
        installation: LinearOAuthInstallation,
    ) -> LinearOAuthWorkProvider<LinearHttpsGraphQlTransport> {
        LinearOAuthWorkProvider::with_provenance(
            LinearHttpsGraphQlTransport::default(),
            installation,
            LinearProviderProvenance::NativeHttps,
        )
    }
}

impl<T: LinearGraphQlTransport> LinearOAuthWorkProvider<T> {
    pub fn probe(&mut self) -> Result<LinearOAuthProbeReceipt, LinearProviderError> {
        self.probe_at(current_time_ms())
    }

    pub fn probe_at(
        &mut self,
        now_ms: u64,
    ) -> Result<LinearOAuthProbeReceipt, LinearProviderError> {
        self.ensure_mountable()?;
        if self.installation.token_expired(now_ms) {
            self.revoke(LinearRevocationReason::TokenExpired, now_ms);
            return Err(LinearProviderError::TokenExpired);
        }
        let request = LinearGraphQlRequest::new(
            "LinearOAuthProbe",
            LINEAR_OAUTH_PROBE_QUERY,
            serde_json::json!({
                "teamIds": self
                    .installation
                    .team_ids()
                    .iter()
                    .map(LinearTeamId::as_str)
                    .collect::<Vec<_>>(),
            }),
            self.installation.access_token(),
        )?;
        let response = self.execute(&request)?;
        let decoded = match decode_graphql::<crate::graphql::LinearOAuthProbeData>(&response) {
            Ok(decoded) => decoded,
            Err(error) => return Err(self.handle_graphql_error(&error, now_ms)),
        };
        let organization_id = LinearOrganizationId::new(decoded.data.organization.id.clone())?;
        if organization_id != *self.installation.organization_id() {
            self.revoke(LinearRevocationReason::PermissionChange, now_ms);
            return Err(LinearProviderError::OrganizationMismatch {
                expected: self.installation.organization_id().to_string(),
                observed: organization_id.to_string(),
            });
        }
        let actor_mismatch = match self.installation.actor() {
            LinearActorIdentity::User(expected) if expected.as_str() != decoded.data.viewer.id => {
                Some((expected.to_string(), decoded.data.viewer.id.clone()))
            }
            _ => None,
        };
        if let Some((expected, observed)) = actor_mismatch {
            self.revoke(LinearRevocationReason::PermissionChange, now_ms);
            return Err(LinearProviderError::ActorMismatch { expected, observed });
        }
        let observed_team_ids = decoded
            .data
            .teams
            .nodes
            .iter()
            .map(|team| team.id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        let missing_team_ids = self
            .installation
            .team_ids()
            .difference(&observed_team_ids)
            .cloned()
            .collect::<Vec<_>>();
        if !missing_team_ids.is_empty() {
            self.revoke(LinearRevocationReason::PermissionChange, now_ms);
            return Err(LinearProviderError::MissingTeamScope(missing_team_ids));
        }
        self.state = LinearCapabilityState::Connected {
            provenance: self.provenance,
            observed_at_ms: now_ms,
        };
        let mut receipt = LinearOAuthProbeReceipt {
            organization_id: self.installation.organization_id().clone(),
            team_ids: self.installation.team_ids().clone(),
            actor: self.installation.actor().clone(),
            app_identity: self.installation.app_identity().clone(),
            scopes: self.installation.scopes().clone(),
            token_expires_at_ms: self.installation.token_expires_at_ms(),
            observed_viewer_id: decoded.data.viewer.id,
            observed_organization_id: decoded.data.organization.id,
            observed_team_ids,
            rate_limit: decoded.rate_limit,
            provider_provenance: self.provenance,
            observed_at_ms: now_ms,
            evidence_digest: String::new(),
        };
        receipt.evidence_digest = digest_hex(
            &serde_json::to_vec(&receipt_without_digest(&receipt))
                .map_err(|error| LinearProviderError::Serialization(error.to_string()))?,
        );
        Ok(receipt)
    }

    pub fn read_issues(
        &mut self,
        team_id: LinearTeamId,
        page: &LinearPageRequest,
    ) -> Result<LinearReadPage<LinearIssue>, LinearProviderError> {
        self.read_issues_at(team_id, page, current_time_ms())
    }

    pub fn read_issues_at(
        &mut self,
        team_id: LinearTeamId,
        page: &LinearPageRequest,
        now_ms: u64,
    ) -> Result<LinearReadPage<LinearIssue>, LinearProviderError> {
        self.read_team_page(
            team_id,
            page,
            now_ms,
            LinearResourceKind::Issues,
            LINEAR_ISSUES_QUERY,
            |team| team.issues,
        )
    }

    pub fn read_projects(
        &mut self,
        team_id: LinearTeamId,
        page: &LinearPageRequest,
    ) -> Result<LinearReadPage<LinearProject>, LinearProviderError> {
        self.read_projects_at(team_id, page, current_time_ms())
    }

    pub fn read_projects_at(
        &mut self,
        team_id: LinearTeamId,
        page: &LinearPageRequest,
        now_ms: u64,
    ) -> Result<LinearReadPage<LinearProject>, LinearProviderError> {
        self.read_team_page(
            team_id,
            page,
            now_ms,
            LinearResourceKind::Projects,
            LINEAR_PROJECTS_QUERY,
            |team| team.projects,
        )
    }

    pub fn read_cycles(
        &mut self,
        team_id: LinearTeamId,
        page: &LinearPageRequest,
    ) -> Result<LinearReadPage<LinearCycle>, LinearProviderError> {
        self.read_cycles_at(team_id, page, current_time_ms())
    }

    pub fn read_cycles_at(
        &mut self,
        team_id: LinearTeamId,
        page: &LinearPageRequest,
        now_ms: u64,
    ) -> Result<LinearReadPage<LinearCycle>, LinearProviderError> {
        self.read_team_page(
            team_id,
            page,
            now_ms,
            LinearResourceKind::Cycles,
            LINEAR_CYCLES_QUERY,
            |team| team.cycles,
        )
    }

    fn read_team_page<N, F>(
        &mut self,
        team_id: LinearTeamId,
        page: &LinearPageRequest,
        now_ms: u64,
        resource: LinearResourceKind,
        query: &'static str,
        select: F,
    ) -> Result<LinearReadPage<N>, LinearProviderError>
    where
        N: for<'de> serde::Deserialize<'de> + fmt::Debug,
        F: FnOnce(
            crate::graphql::LinearTeamResource<N>,
        ) -> Option<crate::graphql::LinearResourcePage<N>>,
    {
        self.ensure_ready(now_ms)?;
        if !self.installation.team_ids().contains(&team_id) {
            return Err(LinearProviderError::TeamOutOfScope(team_id.to_string()));
        }
        let requested_after = page.after.clone();
        let request = LinearGraphQlRequest::new(
            match resource {
                LinearResourceKind::Issues => "LinearIssuesPage",
                LinearResourceKind::Projects => "LinearProjectsPage",
                LinearResourceKind::Cycles => "LinearCyclesPage",
            },
            query,
            request_variables(&team_id, page),
            self.installation.access_token(),
        )?;
        let response = self.execute(&request)?;
        let decoded = match decode_graphql::<LinearTeamPageData<N>>(&response) {
            Ok(decoded) => decoded,
            Err(error) => return Err(self.handle_graphql_error(&error, now_ms)),
        };
        let team = decoded
            .data
            .team
            .ok_or(LinearProviderError::TeamNotFound(team_id.to_string()))?;
        if team.id != team_id {
            return Err(LinearProviderError::TeamIdentityMismatch {
                expected: team_id.to_string(),
                observed: team.id.to_string(),
            });
        }
        let page_data = select(team).ok_or(LinearProviderError::ResourceUnavailable(resource))?;
        page_data.page_info.validate()?;
        if requested_after
            .as_ref()
            .zip(page_data.page_info.end_cursor.as_ref())
            .is_some_and(|(requested, returned)| requested == returned)
        {
            return Err(LinearProviderError::RepeatedCursor(
                requested_after.expect("cursor exists in repeated-cursor branch"),
            ));
        }
        let read = LinearReadReceipt {
            resource,
            team_id,
            requested_first: page.first,
            requested_after,
            returned_count: page_data.nodes.len(),
            page_info: page_data.page_info,
            rate_limit: decoded.rate_limit,
            provider_provenance: self.provenance,
            observed_at_ms: now_ms,
            query_digest: digest_hex(query.as_bytes()),
        };
        Ok(LinearReadPage::new(page_data.nodes, read))
    }

    pub fn receive_webhook(
        &mut self,
        raw_body: &[u8],
        headers: LinearWebhookHeaders,
        signing_secret: &[u8],
        now_ms: u64,
    ) -> Result<LinearWebhookOutcome, LinearProviderError> {
        let outcome = verify_and_fence_linear_webhook(
            raw_body,
            headers,
            signing_secret,
            &mut self.replay_fence,
            now_ms,
        )?;
        let outcome = match outcome {
            LinearWebhookOutcome::Accepted(delivery) => {
                if delivery.event.is_revocation() && self.webhook_matches(&delivery.event) {
                    let reason = match delivery.event.kind {
                        LinearWebhookEventKind::OAuthRevoked
                        | LinearWebhookEventKind::OAuthAuthorization => {
                            LinearRevocationReason::OAuthRevoked
                        }
                        LinearWebhookEventKind::PermissionChange => {
                            LinearRevocationReason::PermissionChange
                        }
                        _ => LinearRevocationReason::PermissionChange,
                    };
                    self.revoke(reason, now_ms);
                } else if !self.webhook_matches(&delivery.event) {
                    return Ok(LinearWebhookOutcome::Ignored(delivery));
                }
                LinearWebhookOutcome::Accepted(delivery)
            }
            other => other,
        };
        Ok(outcome)
    }

    fn webhook_matches(&self, event: &LinearWebhookEvent) -> bool {
        if event.organization_id.as_ref() != Some(self.installation.organization_id()) {
            return false;
        }
        if let Some(app_id) = event.oauth_client_id.as_ref() {
            let app_identity = self.installation.app_identity();
            let application_matches = app_identity
                .application_id
                .as_ref()
                .is_some_and(|expected| expected == app_id);
            if !application_matches && app_identity.client_id != app_id.as_str() {
                return false;
            }
        }
        event
            .team_id
            .as_ref()
            .is_none_or(|team_id| self.installation.team_ids().contains(team_id))
    }

    fn execute(
        &mut self,
        request: &LinearGraphQlRequest,
    ) -> Result<crate::graphql::LinearGraphQlResponse, LinearProviderError> {
        self.transport
            .execute(request)
            .map_err(LinearProviderError::Transport)
    }

    fn ensure_mountable(&self) -> Result<(), LinearProviderError> {
        match &self.state {
            LinearCapabilityState::Mounted { .. } | LinearCapabilityState::Connected { .. } => {
                Ok(())
            }
            LinearCapabilityState::Revoked { reason, .. } => {
                Err(LinearProviderError::Revoked(*reason))
            }
            LinearCapabilityState::Unmounted => Err(LinearProviderError::Unmounted),
        }
    }

    fn ensure_ready(&mut self, now_ms: u64) -> Result<(), LinearProviderError> {
        self.ensure_mountable()?;
        if !matches!(self.state, LinearCapabilityState::Connected { .. }) {
            return Err(LinearProviderError::NotProbed);
        }
        if self.installation.token_expired(now_ms) {
            self.revoke(LinearRevocationReason::TokenExpired, now_ms);
            return Err(LinearProviderError::TokenExpired);
        }
        Ok(())
    }

    fn handle_graphql_error(
        &mut self,
        error: &LinearGraphQlDecodeError,
        now_ms: u64,
    ) -> LinearProviderError {
        if error.is_auth_failure() {
            self.revoke(LinearRevocationReason::Unauthorized, now_ms);
            return LinearProviderError::Unauthorized;
        }
        if error.is_rate_limited() {
            return LinearProviderError::RateLimited {
                rate_limit: Box::new(error.rate_limit().cloned().unwrap_or_default()),
                message: error.to_string(),
            };
        }
        LinearProviderError::GraphQl(error.to_string())
    }
}

fn receipt_without_digest(receipt: &LinearOAuthProbeReceipt) -> serde_json::Value {
    serde_json::json!({
        "organizationId": receipt.organization_id,
        "teamIds": receipt.team_ids,
        "actor": receipt.actor,
        "appIdentity": receipt.app_identity,
        "scopes": receipt.scopes,
        "tokenExpiresAtMs": receipt.token_expires_at_ms,
        "observedViewerId": receipt.observed_viewer_id,
        "observedOrganizationId": receipt.observed_organization_id,
        "observedTeamIds": receipt.observed_team_ids,
        "rateLimit": receipt.rate_limit,
        "providerProvenance": receipt.provider_provenance,
        "observedAtMs": receipt.observed_at_ms,
    })
}

fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LinearProviderError {
    #[error("Linear OAuth error: {0}")]
    OAuth(#[from] LinearOAuthError),
    #[error("Linear GraphQL request error: {0}")]
    Request(#[from] LinearGraphQlRequestError),
    #[error("Linear GraphQL transport error: {0}")]
    Transport(#[from] crate::graphql::LinearTransportError),
    #[error("Linear GraphQL failed: {0}")]
    GraphQl(String),
    #[error("Linear GraphQL request was rate limited: {message}")]
    RateLimited {
        rate_limit: Box<LinearRateLimitReceipt>,
        message: String,
    },
    #[error("Linear OAuth capability was revoked: {0:?}")]
    Revoked(LinearRevocationReason),
    #[error("Linear OAuth request was unauthorized")]
    Unauthorized,
    #[error("Linear OAuth capability is unmounted")]
    Unmounted,
    #[error("Linear OAuth capability has not completed its probe")]
    NotProbed,
    #[error("Linear OAuth token is expired")]
    TokenExpired,
    #[error("Linear organization mismatch: expected {expected}, observed {observed}")]
    OrganizationMismatch { expected: String, observed: String },
    #[error("Linear actor mismatch: expected {expected}, observed {observed}")]
    ActorMismatch { expected: String, observed: String },
    #[error("Linear installation lost team scope: {0:?}")]
    MissingTeamScope(Vec<LinearTeamId>),
    #[error("Linear team {0} is outside the mounted scope")]
    TeamOutOfScope(String),
    #[error("Linear team {0} was not returned by the provider")]
    TeamNotFound(String),
    #[error("Linear team identity mismatch: expected {expected}, observed {observed}")]
    TeamIdentityMismatch { expected: String, observed: String },
    #[error("Linear resource page is unavailable: {0:?}")]
    ResourceUnavailable(LinearResourceKind),
    #[error("Linear pagination returned its input cursor again: {0}")]
    RepeatedCursor(LinearCursor),
    #[error("Linear pagination metadata is invalid: {0}")]
    InvalidPagination(String),
    #[error("Linear webhook error: {0}")]
    Webhook(#[from] LinearWebhookError),
    #[error("Linear response serialization failed: {0}")]
    Serialization(String),
    #[error("Linear identifier is invalid: {0}")]
    InvalidIdentifier(#[from] LinearIdError),
    #[error("Linear issue {0} is outside the mounted team scope")]
    IssueOutOfScope(LinearIssueId),
    #[error("Linear project {0} is outside the mounted team scope")]
    ProjectOutOfScope(LinearProjectId),
}
