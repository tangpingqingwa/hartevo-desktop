use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{RenderDeploymentError, RenderTransportError, Result};
use crate::model::{
    BackoffReceipt, Digest, Identifier, MAX_DEPLOYS_PER_PAGE, ProviderProvenance, RenderDeployId,
    RenderDeployStatus, RenderDeploymentScope, RenderEnvironmentId, RenderHealthProjection,
    RenderHealthState, RenderRegion, RenderServiceId, RenderServiceStatus, RenderWorkspaceId,
    Revision, SecretReference,
};
use crate::transport::{RenderRequest, RenderResponse, RenderTransport, RetryPolicy};
use crate::{
    CONTRACT_VERSION, PROVIDER_ID, PROVIDER_VERSION, RENDER_API_BASE_URL,
    RENDER_PROVIDER_API_REVISION,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenderProviderDefinition {
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub base_url: String,
    pub provider_digest: Digest,
    pub read_only: bool,
    pub recording_only: bool,
    pub external_writes: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl Default for RenderProviderDefinition {
    fn default() -> Self {
        let provider_digest = Digest::from_parts(
            "render-provider-definition/v1",
            &[
                ("provider", PROVIDER_ID.to_owned()),
                ("version", PROVIDER_VERSION.to_owned()),
                ("api", RENDER_PROVIDER_API_REVISION.to_owned()),
                ("base_url", RENDER_API_BASE_URL.to_owned()),
                ("contract", CONTRACT_VERSION.to_owned()),
            ],
        );
        Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: PROVIDER_VERSION.to_owned(),
            api_revision: RENDER_PROVIDER_API_REVISION.to_owned(),
            base_url: RENDER_API_BASE_URL.to_owned(),
            provider_digest,
            read_only: true,
            recording_only: true,
            external_writes: false,
            connected: false,
            native: false,
            first_party: false,
        }
    }
}

/// Wire fixture used by deterministic transports. It intentionally models
/// only bounded metadata; arbitrary Render payloads, logs, secrets, and env
/// values are not accepted into the typed projection.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderHealthFixture {
    #[serde(default = "default_health_status")]
    pub status: String,
    #[serde(default)]
    pub check_count: u32,
    #[serde(default)]
    pub passing_count: u32,
    #[serde(default)]
    pub last_checked_at: Option<u64>,
    #[serde(default)]
    pub detail: Option<String>,
}

impl Default for RenderHealthFixture {
    fn default() -> Self {
        Self {
            status: default_health_status(),
            check_count: 1,
            passing_count: 1,
            last_checked_at: Some(1),
            detail: None,
        }
    }
}

fn default_health_status() -> String {
    "unknown".to_owned()
}

impl RenderHealthFixture {
    #[must_use]
    pub fn healthy() -> Self {
        Self {
            status: "healthy".to_owned(),
            check_count: 1,
            passing_count: 1,
            last_checked_at: Some(1),
            detail: None,
        }
    }

    #[must_use]
    pub fn degraded() -> Self {
        Self {
            status: "degraded".to_owned(),
            check_count: 2,
            passing_count: 1,
            last_checked_at: Some(1),
            detail: Some("bounded degraded health metadata".to_owned()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderServiceFixture {
    pub service_id: String,
    #[serde(default)]
    pub service_uid: String,
    #[serde(default)]
    pub workspace_id: String,
    pub environment_id: String,
    #[serde(default = "default_region")]
    pub region: String,
    #[serde(default = "default_service_status")]
    pub status: String,
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub latest_deploy_id: Option<String>,
    #[serde(default)]
    pub health_check_path: Option<String>,
    #[serde(default)]
    pub health: RenderHealthFixture,
}

fn default_region() -> String {
    "unknown".to_owned()
}

fn default_service_status() -> String {
    "unknown".to_owned()
}

impl RenderServiceFixture {
    #[must_use]
    pub fn ready(scope: &RenderDeploymentScope) -> Self {
        Self {
            service_id: scope.service_id().as_str().to_owned(),
            service_uid: "render-service-uid-1".to_owned(),
            workspace_id: scope.workspace_id().as_str().to_owned(),
            environment_id: scope.environment_id().as_str().to_owned(),
            region: scope.region().as_str().to_owned(),
            status: "available".to_owned(),
            revision: 1,
            latest_deploy_id: Some(scope.deploy_id().as_str().to_owned()),
            health_check_path: Some("/health".to_owned()),
            health: RenderHealthFixture::healthy(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderDeployFixture {
    pub deploy_id: String,
    pub service_id: String,
    pub environment_id: String,
    pub commit: String,
    #[serde(default = "default_deploy_status")]
    pub status: String,
    #[serde(default)]
    pub created_at: Option<u64>,
    #[serde(default)]
    pub finished_at: Option<u64>,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub health: RenderHealthFixture,
}

fn default_deploy_status() -> String {
    "unknown".to_owned()
}

impl RenderDeployFixture {
    #[must_use]
    pub fn live(scope: &RenderDeploymentScope) -> Self {
        Self {
            deploy_id: scope.deploy_id().as_str().to_owned(),
            service_id: scope.service_id().as_str().to_owned(),
            environment_id: scope.environment_id().as_str().to_owned(),
            commit: scope.commit_digest().as_str().to_owned(),
            status: "live".to_owned(),
            created_at: Some(1),
            finished_at: Some(2),
            image: Some("sha256:render-image".to_owned()),
            source: Some("render-source".to_owned()),
            health: RenderHealthFixture::healthy(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderDeployPageFixture {
    pub service_id: String,
    pub environment_id: String,
    #[serde(default)]
    pub deploys: Vec<RenderDeployFixture>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderHealthSnapshot {
    pub(crate) state: RenderHealthState,
    pub(crate) check_count: u32,
    pub(crate) passing_count: u32,
    pub(crate) last_checked_at: Option<u64>,
    pub(crate) detail_digest: Digest,
}

impl RenderHealthSnapshot {
    #[must_use]
    pub const fn state(&self) -> RenderHealthState {
        self.state
    }

    #[must_use]
    pub const fn check_count(&self) -> u32 {
        self.check_count
    }

    #[must_use]
    pub const fn passing_count(&self) -> u32 {
        self.passing_count
    }

    #[must_use]
    pub const fn last_checked_at(&self) -> Option<u64> {
        self.last_checked_at
    }

    pub(crate) fn projection(&self) -> Result<RenderHealthProjection> {
        RenderHealthProjection::new(
            self.state,
            self.check_count,
            self.passing_count,
            self.last_checked_at,
            self.detail_digest.clone(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderServiceSnapshot {
    pub(crate) service_id: RenderServiceId,
    pub(crate) service_uid_digest: Digest,
    pub(crate) workspace_id: RenderWorkspaceId,
    pub(crate) environment_id: RenderEnvironmentId,
    pub(crate) region: RenderRegion,
    pub(crate) status: RenderServiceStatus,
    pub(crate) health: RenderHealthSnapshot,
    pub(crate) latest_deploy_id: Option<RenderDeployId>,
    pub(crate) health_check_path_digest: Option<Digest>,
    pub(crate) revision: Revision,
}

impl RenderServiceSnapshot {
    #[must_use]
    pub fn service_id(&self) -> &RenderServiceId {
        &self.service_id
    }

    #[must_use]
    pub const fn status(&self) -> RenderServiceStatus {
        self.status
    }

    #[must_use]
    pub fn health(&self) -> &RenderHealthSnapshot {
        &self.health
    }

    #[must_use]
    pub fn service_uid_digest(&self) -> &Digest {
        &self.service_uid_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderDeploySnapshot {
    pub(crate) deploy_id: RenderDeployId,
    pub(crate) service_id: RenderServiceId,
    pub(crate) environment_id: RenderEnvironmentId,
    pub(crate) commit_digest: Digest,
    pub(crate) status: RenderDeployStatus,
    pub(crate) created_at: Option<u64>,
    pub(crate) finished_at: Option<u64>,
    pub(crate) image_digest: Option<Digest>,
    pub(crate) source_digest: Option<Digest>,
    pub(crate) health: RenderHealthSnapshot,
}

impl RenderDeploySnapshot {
    #[must_use]
    pub fn deploy_id(&self) -> &RenderDeployId {
        &self.deploy_id
    }

    #[must_use]
    pub fn commit_digest(&self) -> &Digest {
        &self.commit_digest
    }

    #[must_use]
    pub const fn status(&self) -> RenderDeployStatus {
        self.status
    }

    #[must_use]
    pub fn health(&self) -> &RenderHealthSnapshot {
        &self.health
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderDeployPage {
    pub(crate) service_id: RenderServiceId,
    pub(crate) environment_id: RenderEnvironmentId,
    pub(crate) deploys: Vec<RenderDeploySnapshot>,
    pub(crate) next_cursor: Option<String>,
    pub(crate) page_digest: Digest,
    pub(crate) cursor_digest: Option<Digest>,
}

impl RenderDeployPage {
    #[must_use]
    pub fn deploys(&self) -> &[RenderDeploySnapshot] {
        &self.deploys
    }

    #[must_use]
    pub fn next_cursor_digest(&self) -> Option<Digest> {
        self.next_cursor.as_ref().map(|value| {
            Digest::from_parts("render-pagination-cursor/v1", &[("token", value.clone())])
        })
    }

    #[must_use]
    pub fn page_digest(&self) -> &Digest {
        &self.page_digest
    }

    #[must_use]
    pub fn cursor_digest(&self) -> Option<&Digest> {
        self.cursor_digest.as_ref()
    }
}

/// Standalone Render provider. It receives only a deterministic transport;
/// there is no native credential resolver or live client in this crate.
pub struct RenderProvider<T: RenderTransport> {
    scope: RenderDeploymentScope,
    secret_reference: SecretReference,
    transport: T,
    definition: RenderProviderDefinition,
    retry_policy: RetryPolicy,
    last_backoff: Option<BackoffReceipt>,
}

impl<T: RenderTransport> fmt::Debug for RenderProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderProvider")
            .field("scope_digest", &self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .field("transport", &self.transport)
            .field("definition", &self.definition)
            .field("retry_policy", &self.retry_policy)
            .field("last_backoff", &self.last_backoff)
            .finish()
    }
}

impl<T: RenderTransport> RenderProvider<T> {
    pub fn new(
        transport: T,
        scope: RenderDeploymentScope,
        secret_reference: SecretReference,
    ) -> Result<Self> {
        secret_reference.validate(&scope)?;
        Ok(Self {
            scope,
            secret_reference,
            transport,
            definition: RenderProviderDefinition::default(),
            retry_policy: RetryPolicy::default(),
            last_backoff: None,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &RenderDeploymentScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn definition(&self) -> &RenderProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> &Digest {
        &self.definition.provider_digest
    }

    #[must_use]
    pub fn provenance(&self) -> ProviderProvenance {
        self.transport.provenance()
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn set_retry_policy(&mut self, retry_policy: RetryPolicy) -> Result<()> {
        if retry_policy.max_attempts == 0
            || retry_policy.max_attempts > crate::model::MAX_RETRY_ATTEMPTS
        {
            return Err(RenderDeploymentError::InvalidRequest);
        }
        self.retry_policy = retry_policy;
        Ok(())
    }

    #[must_use]
    pub fn take_backoff(&mut self) -> Option<BackoffReceipt> {
        self.last_backoff.take()
    }

    pub fn read_service(&mut self) -> Result<RenderServiceSnapshot> {
        let request = RenderRequest::get_service(&self.scope)?;
        let response = self.execute_request(&request)?;
        let fixture: RenderServiceFixture = parse_json(&response)?;
        snapshot_service(fixture, &self.scope)
    }

    pub fn list_deploys(&mut self, cursor: Option<(&str, u16)>) -> Result<RenderDeployPage> {
        let request = RenderRequest::list_deploys(&self.scope, cursor)?;
        let response = self.execute_request(&request)?;
        let fixture: RenderDeployPageFixture = parse_json(&response)?;
        if fixture.deploys.len() > MAX_DEPLOYS_PER_PAGE {
            return Err(RenderDeploymentError::InvalidResponse);
        }
        let service_id = Identifier::new(fixture.service_id)?;
        let environment_id = Identifier::new(fixture.environment_id)?;
        if service_id != *self.scope.service_id() || environment_id != *self.scope.environment_id()
        {
            return Err(RenderDeploymentError::ScopeMismatch);
        }
        let mut deploys = Vec::with_capacity(fixture.deploys.len());
        for deploy in fixture.deploys {
            deploys.push(snapshot_deploy(deploy, &self.scope)?);
        }
        let next_cursor = fixture.next_cursor.filter(|value| !value.is_empty());
        if next_cursor
            .as_ref()
            .is_some_and(|value| value.len() > crate::model::MAX_CURSOR_BYTES)
        {
            return Err(RenderDeploymentError::InvalidResponse);
        }
        let cursor_digest = cursor.map(|(value, _)| {
            Digest::from_parts(
                "render-pagination-cursor/v1",
                &[("token", value.to_owned())],
            )
        });
        Ok(RenderDeployPage {
            service_id,
            environment_id,
            deploys,
            next_cursor,
            page_digest: response.response_digest(),
            cursor_digest,
        })
    }

    pub fn read_deploy(&mut self) -> Result<RenderDeploySnapshot> {
        let request = RenderRequest::get_deploy(&self.scope)?;
        let response = self.execute_request(&request)?;
        let fixture: RenderDeployFixture = parse_json(&response)?;
        let snapshot = snapshot_deploy(fixture, &self.scope)?;
        if snapshot.deploy_id != *self.scope.deploy_id() {
            return Err(RenderDeploymentError::ScopeMismatch);
        }
        Ok(snapshot)
    }

    pub fn reject_write(&self, operation: &'static str) -> Result<()> {
        Err(RenderDeploymentError::MutationForbidden { operation })
    }

    fn execute_request(&mut self, request: &RenderRequest) -> Result<RenderResponse> {
        if !request.is_allowlisted() {
            return Err(RenderDeploymentError::InvalidRequest);
        }
        self.last_backoff = None;
        let mut attempt = 1;
        loop {
            let response = match self.transport.execute(request) {
                Ok(response) => response,
                Err(RenderTransportError::RateLimited {
                    retry_after_seconds,
                }) if attempt < self.retry_policy.max_attempts => {
                    self.last_backoff = Some(BackoffReceipt::new(
                        attempt + 1,
                        retry_after_seconds
                            .unwrap_or_else(|| self.retry_policy.backoff_seconds(attempt)),
                    ));
                    attempt += 1;
                    continue;
                }
                Err(error) => return Err(RenderDeploymentError::Transport(error)),
            };
            if response.status() == 429 && attempt < self.retry_policy.max_attempts {
                self.last_backoff = Some(BackoffReceipt::new(
                    attempt + 1,
                    self.retry_policy.backoff_seconds(attempt),
                ));
                attempt += 1;
                continue;
            }
            response.validate_size_and_digest()?;
            if response.status() != 200 {
                return Err(RenderDeploymentError::Transport(status_error(
                    response.status(),
                )));
            }
            return Ok(response);
        }
    }
}

fn parse_json<T: for<'de> Deserialize<'de>>(response: &RenderResponse) -> Result<T> {
    serde_json::from_slice(response.body()).map_err(|_| RenderDeploymentError::InvalidResponse)
}

fn status_error(status: u16) -> RenderTransportError {
    match status {
        401 | 403 => RenderTransportError::AccessLost,
        404 => RenderTransportError::NotFound,
        409 => RenderTransportError::Conflict,
        429 => RenderTransportError::RateLimited {
            retry_after_seconds: None,
        },
        408 => RenderTransportError::Timeout,
        status if (500..=599).contains(&status) => RenderTransportError::ProviderUnknown,
        _ => RenderTransportError::ProviderUnknown,
    }
}

fn snapshot_service(
    fixture: RenderServiceFixture,
    scope: &RenderDeploymentScope,
) -> Result<RenderServiceSnapshot> {
    let service_id = Identifier::new(fixture.service_id)?;
    let workspace_id = Identifier::new(if fixture.workspace_id.is_empty() {
        scope.workspace_id().as_str().to_owned()
    } else {
        fixture.workspace_id
    })?;
    let environment_id = Identifier::new(fixture.environment_id)?;
    let region = Identifier::new(fixture.region)?;
    if service_id != *scope.service_id()
        || workspace_id != *scope.workspace_id()
        || environment_id != *scope.environment_id()
        || region != *scope.region()
    {
        return Err(RenderDeploymentError::ScopeMismatch);
    }
    let service_uid = if fixture.service_uid.is_empty() {
        service_id.as_str().to_owned()
    } else {
        fixture.service_uid
    };
    let revision = Revision::new(fixture.revision.max(1))?;
    let health = snapshot_health(fixture.health)?;
    Ok(RenderServiceSnapshot {
        service_id,
        service_uid_digest: Digest::from_text(service_uid),
        workspace_id,
        environment_id,
        region,
        status: RenderServiceStatus::from_wire(&fixture.status),
        health,
        latest_deploy_id: fixture.latest_deploy_id.map(Identifier::new).transpose()?,
        health_check_path_digest: fixture.health_check_path.map(Digest::from_text),
        revision,
    })
}

fn snapshot_deploy(
    fixture: RenderDeployFixture,
    scope: &RenderDeploymentScope,
) -> Result<RenderDeploySnapshot> {
    let deploy_id = Identifier::new(fixture.deploy_id)?;
    let service_id = Identifier::new(fixture.service_id)?;
    let environment_id = Identifier::new(fixture.environment_id)?;
    if service_id != *scope.service_id() || environment_id != *scope.environment_id() {
        return Err(RenderDeploymentError::ScopeMismatch);
    }
    if fixture.commit.is_empty() {
        return Err(RenderDeploymentError::InvalidResponse);
    }
    Ok(RenderDeploySnapshot {
        deploy_id,
        service_id,
        environment_id,
        commit_digest: parse_or_digest(fixture.commit),
        status: RenderDeployStatus::from_wire(&fixture.status),
        created_at: fixture.created_at,
        finished_at: fixture.finished_at,
        image_digest: fixture.image.map(parse_or_digest),
        source_digest: fixture.source.map(parse_or_digest),
        health: snapshot_health(fixture.health)?,
    })
}

fn snapshot_health(fixture: RenderHealthFixture) -> Result<RenderHealthSnapshot> {
    if fixture.check_count > crate::model::MAX_HEALTH_CHECKS
        || fixture.passing_count > fixture.check_count
    {
        return Err(RenderDeploymentError::InvalidResponse);
    }
    Ok(RenderHealthSnapshot {
        state: RenderHealthState::from_wire(&fixture.status),
        check_count: fixture.check_count,
        passing_count: fixture.passing_count,
        last_checked_at: fixture.last_checked_at,
        detail_digest: Digest::from_text(fixture.detail.unwrap_or_default()),
    })
}

fn parse_or_digest(value: String) -> Digest {
    Digest::parse(value.clone()).unwrap_or_else(|_| Digest::from_text(value))
}

impl RenderServiceSnapshot {
    pub(crate) fn to_projection(&self) -> Result<crate::model::RenderServiceProjection> {
        let health = self.health.projection()?;
        let service_digest = Digest::from_parts(
            "render-service-projection/v1",
            &[
                ("service", self.service_id.digest().as_str().to_owned()),
                ("uid", self.service_uid_digest.as_str().to_owned()),
                ("workspace", self.workspace_id.digest().as_str().to_owned()),
                (
                    "environment",
                    self.environment_id.digest().as_str().to_owned(),
                ),
                ("region", self.region.digest().as_str().to_owned()),
                ("status", format!("{:?}", self.status)),
                ("health", health.health_digest.as_str().to_owned()),
                (
                    "latest_deploy",
                    self.latest_deploy_id
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                (
                    "health_check_path",
                    self.health_check_path_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("revision", self.revision.get().to_string()),
            ],
        );
        Ok(crate::model::RenderServiceProjection {
            service_id_digest: self.service_id.digest(),
            service_uid_digest: self.service_uid_digest.clone(),
            workspace_id_digest: self.workspace_id.digest(),
            environment_id_digest: self.environment_id.digest(),
            region_digest: self.region.digest(),
            status: self.status,
            health,
            latest_deploy_id_digest: self.latest_deploy_id.as_ref().map(Identifier::digest),
            health_check_path_digest: self.health_check_path_digest.clone(),
            observed_revision: self.revision,
            service_digest,
        })
    }
}

impl RenderDeploySnapshot {
    pub(crate) fn to_projection(&self) -> Result<crate::model::RenderDeployProjection> {
        let health = self.health.projection()?;
        let deploy_digest = Digest::from_parts(
            "render-deploy-projection/v1",
            &[
                ("deploy", self.deploy_id.digest().as_str().to_owned()),
                ("service", self.service_id.digest().as_str().to_owned()),
                (
                    "environment",
                    self.environment_id.digest().as_str().to_owned(),
                ),
                ("commit", self.commit_digest.as_str().to_owned()),
                ("status", format!("{:?}", self.status)),
                (
                    "created_at",
                    self.created_at
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "finished_at",
                    self.finished_at
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "image",
                    self.image_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "source",
                    self.source_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("health", health.health_digest.as_str().to_owned()),
            ],
        );
        Ok(crate::model::RenderDeployProjection {
            deploy_id_digest: self.deploy_id.digest(),
            service_id_digest: self.service_id.digest(),
            environment_id_digest: self.environment_id.digest(),
            commit_digest: self.commit_digest.clone(),
            status: self.status,
            created_at: self.created_at,
            finished_at: self.finished_at,
            image_digest: self.image_digest.clone(),
            source_digest: self.source_digest.clone(),
            health,
            deploy_digest,
        })
    }
}

impl RenderProviderDefinition {
    #[must_use]
    pub fn is_layer_one_honest(&self) -> bool {
        self.read_only
            && self.recording_only
            && !self.external_writes
            && !self.connected
            && !self.native
            && !self.first_party
    }
}
