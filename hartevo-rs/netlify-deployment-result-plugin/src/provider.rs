use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};

use crate::error::{NetlifyDeploymentError, NetlifyTransportError, Result};
use crate::model::{
    Digest, FileManifestMetadata, MAX_DEPLOYS_PER_PAGE, MAX_LINK_HEADER_BYTES, MAX_RESPONSE_BYTES,
    NetlifyDeployId, NetlifyDeploymentMetadata, NetlifyDeploymentScope, NetlifySiteId,
    OpaqueCursor, SecretReference, TransportProvenance,
};
use crate::{NETLIFY_PROVIDER_API_REVISION, PROVIDER_ID, PROVIDER_VERSION};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetlifyOperation {
    ListSiteDeploys,
    GetDeploy,
}

impl NetlifyOperation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListSiteDeploys => "list_site_deploys",
            Self::GetDeploy => "get_deploy",
        }
    }
}

/// A request contains only exact scope and digest fields. It never carries a
/// bearer token or the opaque cursor itself.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetlifyRequest {
    pub operation: NetlifyOperation,
    pub method: &'static str,
    pub host: &'static str,
    pub path: String,
    pub site_id: NetlifySiteId,
    pub deploy_id: Option<NetlifyDeployId>,
    pub cursor_digest: Option<Digest>,
    pub poll_attempt: u8,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub request_digest: Digest,
}

impl NetlifyRequest {
    fn list(
        scope: &NetlifyDeploymentScope,
        secret: &SecretReference,
        cursor: Option<&OpaqueCursor>,
        poll_attempt: u8,
    ) -> Self {
        let cursor_digest = cursor.map(|cursor| cursor.digest().clone());
        let path = format!("/api/v1/sites/{}/deploys", scope.site_id().as_str());
        let request_digest = Digest::from_parts(
            "netlify-request/v1",
            &[
                (
                    "operation",
                    NetlifyOperation::ListSiteDeploys.as_str().to_owned(),
                ),
                ("method", "GET".to_owned()),
                ("host", "https://api.netlify.com".to_owned()),
                ("path", path.clone()),
                ("site", scope.site_id().digest().as_str().to_owned()),
                (
                    "cursor",
                    cursor_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("attempt", poll_attempt.to_string()),
                ("scope", scope.digest().as_str().to_owned()),
                ("secret", secret.reference_digest().as_str().to_owned()),
            ],
        );
        Self {
            operation: NetlifyOperation::ListSiteDeploys,
            method: "GET",
            host: "https://api.netlify.com",
            path,
            site_id: scope.site_id().clone(),
            deploy_id: None,
            cursor_digest,
            poll_attempt,
            scope_digest: scope.digest(),
            secret_reference_digest: secret.reference_digest().clone(),
            request_digest,
        }
    }

    fn get_deploy(
        scope: &NetlifyDeploymentScope,
        secret: &SecretReference,
        poll_attempt: u8,
    ) -> Self {
        let path = format!("/api/v1/deploys/{}", scope.deploy_id().as_str());
        let request_digest = Digest::from_parts(
            "netlify-request/v1",
            &[
                ("operation", NetlifyOperation::GetDeploy.as_str().to_owned()),
                ("method", "GET".to_owned()),
                ("host", "https://api.netlify.com".to_owned()),
                ("path", path.clone()),
                ("site", scope.site_id().digest().as_str().to_owned()),
                ("deploy", scope.deploy_id().digest().as_str().to_owned()),
                ("attempt", poll_attempt.to_string()),
                ("scope", scope.digest().as_str().to_owned()),
                ("secret", secret.reference_digest().as_str().to_owned()),
            ],
        );
        Self {
            operation: NetlifyOperation::GetDeploy,
            method: "GET",
            host: "https://api.netlify.com",
            path,
            site_id: scope.site_id().clone(),
            deploy_id: Some(scope.deploy_id().clone()),
            cursor_digest: None,
            poll_attempt,
            scope_digest: scope.digest(),
            secret_reference_digest: secret.reference_digest().clone(),
            request_digest,
        }
    }

    #[must_use]
    pub fn is_allowlisted(&self) -> bool {
        self.method == "GET"
            && self.host == "https://api.netlify.com"
            && ((self.operation == NetlifyOperation::ListSiteDeploys
                && self.deploy_id.is_none()
                && self.path == format!("/api/v1/sites/{}/deploys", self.site_id.as_str()))
                || (self.operation == NetlifyOperation::GetDeploy
                    && self.deploy_id.as_ref().is_some_and(|deploy_id| {
                        self.path == format!("/api/v1/deploys/{}", deploy_id.as_str())
                    })))
    }
}

/// The raw response body and Link header are kept private to the parser. The
/// public type exposes only bounded byte/digest metadata for test assertions.
#[derive(Clone, Eq, PartialEq)]
pub struct NetlifyResponse {
    status: u16,
    body: Vec<u8>,
    link_header: Option<String>,
    response_digest: Digest,
    declared_response_digest: Digest,
}

impl fmt::Debug for NetlifyResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetlifyResponse")
            .field("status", &self.status)
            .field("response_bytes", &self.body.len())
            .field("response_digest", &self.response_digest)
            .field("declared_response_digest", &self.declared_response_digest)
            .field(
                "link_header_digest",
                &self.link_header.as_ref().map(Digest::from_text),
            )
            .finish()
    }
}

impl NetlifyResponse {
    #[must_use]
    pub fn new(status: u16, body: Vec<u8>, link_header: Option<String>) -> Self {
        let response_digest = Digest::from_bytes(&body);
        Self {
            status,
            body,
            link_header,
            declared_response_digest: response_digest.clone(),
            response_digest,
        }
    }

    pub fn json<T: Serialize>(status: u16, value: &T, link_header: Option<String>) -> Result<Self> {
        let body =
            serde_json::to_vec(value).map_err(|_| NetlifyDeploymentError::InvalidResponse)?;
        Ok(Self::new(status, body, link_header))
    }

    #[must_use]
    pub fn with_declared_response_digest(mut self, digest: Digest) -> Self {
        self.declared_response_digest = digest;
        self
    }

    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    #[must_use]
    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    #[must_use]
    pub fn declared_response_digest(&self) -> &Digest {
        &self.declared_response_digest
    }

    #[must_use]
    pub const fn response_bytes(&self) -> usize {
        self.body.len()
    }
}

pub trait NetlifyTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn execute(
        &mut self,
        request: &NetlifyRequest,
    ) -> std::result::Result<NetlifyResponse, NetlifyTransportError>;
}

#[derive(Clone, Debug)]
pub struct NetlifyProviderDefinition {
    pub provider_id: String,
    pub provider_revision: u64,
    pub release: String,
    pub api_revision: String,
    pub provider_digest: Digest,
}

impl NetlifyProviderDefinition {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let release = release.into();
        if provider_revision == 0 || release.is_empty() {
            return Err(NetlifyDeploymentError::InvalidRevision { field: "provider" });
        }
        let definition = Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            release: release.clone(),
            api_revision: NETLIFY_PROVIDER_API_REVISION.to_owned(),
            provider_digest: Digest::from_parts(
                "netlify-provider-definition/v1",
                &[
                    ("id", PROVIDER_ID.to_owned()),
                    ("revision", provider_revision.to_string()),
                    ("release", release.clone()),
                    ("api", NETLIFY_PROVIDER_API_REVISION.to_owned()),
                ],
            ),
        };
        Ok(definition)
    }

    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.release.is_empty()
            || self.api_revision != NETLIFY_PROVIDER_API_REVISION
        {
            return Err(NetlifyDeploymentError::InvalidRegistration);
        }
        Digest::parse(self.provider_digest.as_str().to_owned()).map(|_| ())
    }
}

impl Default for NetlifyProviderDefinition {
    fn default() -> Self {
        Self::new(1, PROVIDER_VERSION).expect("static Netlify provider definition is valid")
    }
}

pub struct NetlifyProvider<T: NetlifyTransport> {
    transport: T,
    scope: NetlifyDeploymentScope,
    secret_reference: SecretReference,
    definition: NetlifyProviderDefinition,
}

impl<T: NetlifyTransport> fmt::Debug for NetlifyProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetlifyProvider")
            .field("transport", &self.transport)
            .field("scope_digest", &self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .field("definition", &self.definition)
            .finish()
    }
}

impl<T: NetlifyTransport> NetlifyProvider<T> {
    pub fn new(
        transport: T,
        scope: NetlifyDeploymentScope,
        secret_reference: SecretReference,
    ) -> Result<Self> {
        Self::with_definition(
            transport,
            scope,
            secret_reference,
            NetlifyProviderDefinition::default(),
        )
    }

    pub fn with_definition(
        transport: T,
        scope: NetlifyDeploymentScope,
        secret_reference: SecretReference,
        definition: NetlifyProviderDefinition,
    ) -> Result<Self> {
        scope.validate()?;
        secret_reference.validate(&scope)?;
        definition.validate()?;
        Ok(Self {
            transport,
            scope,
            secret_reference,
            definition,
        })
    }

    #[must_use]
    pub fn definition(&self) -> &NetlifyProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn scope(&self) -> &NetlifyDeploymentScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn provenance(&self) -> TransportProvenance {
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

    pub fn list_site_deploys(
        &mut self,
        cursor: Option<&OpaqueCursor>,
        poll_attempt: u8,
    ) -> Result<NetlifyDeployPage> {
        self.ensure_usable()?;
        let request =
            NetlifyRequest::list(&self.scope, &self.secret_reference, cursor, poll_attempt);
        if !request.is_allowlisted() {
            return Err(NetlifyDeploymentError::InvalidRequest);
        }
        let response = self
            .transport
            .execute(&request)
            .map_err(NetlifyDeploymentError::Transport)?;
        let response = Self::validate_response(response)?;
        if response.status != 200 {
            return Err(status_error(response.status));
        }
        let wire: WireDeployPage = serde_json::from_slice(&response.body)
            .map_err(|_| NetlifyDeploymentError::InvalidResponse)?;
        if wire.deploys.len() > MAX_DEPLOYS_PER_PAGE {
            return Err(NetlifyDeploymentError::InvalidResponse);
        }
        if wire.site_id != self.scope.site_id().as_str() {
            return Err(NetlifyDeploymentError::ScopeMismatch);
        }
        let mut deploys = Vec::with_capacity(wire.deploys.len());
        for deploy in wire.deploys {
            let metadata = metadata_from_wire(deploy)?;
            if self.scope.site_is_allowed(self.scope.site_id())
                && metadata.site_id_digest != self.scope.site_id().digest()
            {
                return Err(NetlifyDeploymentError::ScopeMismatch);
            }
            deploys.push(metadata);
        }
        let link =
            NetlifyLinkHeader::from_header(response.link_header.as_deref(), self.scope.site_id())?;
        Ok(NetlifyDeployPage {
            site_id_digest: self.scope.site_id().digest(),
            deploys,
            next_cursor: link.next_cursor,
            response_digest: response.response_digest,
            link_header_digest: link.header_digest,
        })
    }

    pub fn get_deploy(&mut self, poll_attempt: u8) -> Result<NetlifyDeploymentMetadata> {
        self.ensure_usable()?;
        let request = NetlifyRequest::get_deploy(&self.scope, &self.secret_reference, poll_attempt);
        if !request.is_allowlisted() {
            return Err(NetlifyDeploymentError::InvalidRequest);
        }
        let response = self
            .transport
            .execute(&request)
            .map_err(NetlifyDeploymentError::Transport)?;
        let response = Self::validate_response(response)?;
        if response.status != 200 {
            return Err(status_error(response.status));
        }
        let wire: WireDeploy = serde_json::from_slice(&response.body)
            .map_err(|_| NetlifyDeploymentError::InvalidResponse)?;
        let metadata = metadata_from_wire(wire)?;
        if metadata.site_id_digest != self.scope.site_id().digest()
            || metadata.deploy_id_digest != self.scope.deploy_id().digest()
        {
            return Err(NetlifyDeploymentError::ScopeMismatch);
        }
        Ok(metadata)
    }

    fn ensure_usable(&self) -> Result<()> {
        self.scope.validate()?;
        if self.secret_reference.is_revoked() {
            Err(NetlifyDeploymentError::SecretRevoked)
        } else {
            self.secret_reference.validate(&self.scope)
        }
    }

    fn validate_response(response: NetlifyResponse) -> Result<NetlifyResponse> {
        if response.response_bytes() > MAX_RESPONSE_BYTES
            || response.response_digest != response.declared_response_digest
        {
            return Err(NetlifyDeploymentError::TamperedEvidence);
        }
        Ok(response)
    }
}

fn status_error(status: u16) -> NetlifyDeploymentError {
    NetlifyDeploymentError::Transport(match status {
        401 => NetlifyTransportError::Unauthorized,
        403 => NetlifyTransportError::Forbidden,
        404 => NetlifyTransportError::NotFound,
        409 => NetlifyTransportError::Conflict,
        429 => NetlifyTransportError::RateLimited {
            retry_after_seconds: None,
        },
        status if (500..=599).contains(&status) => NetlifyTransportError::ServerError(status),
        _ => NetlifyTransportError::ProviderUnknown,
    })
}

fn metadata_from_wire(wire: WireDeploy) -> Result<NetlifyDeploymentMetadata> {
    let file_manifest = FileManifestMetadata::new(
        wire.file_count,
        wire.file_bytes,
        wire.file_manifest_digest,
        wire.file_manifest_truncated,
    )?;
    NetlifyDeploymentMetadata::from_wire(
        &wire.site_id,
        &wire.id,
        &wire.state,
        &wire.branch,
        &wire.commit_ref,
        &wire.context,
        wire.deploy_url.as_deref(),
        file_manifest,
        wire.expires_at,
    )
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct WireDeployPage {
    site_id: String,
    deploys: Vec<WireDeploy>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct WireDeploy {
    id: String,
    site_id: String,
    state: String,
    branch: String,
    commit_ref: String,
    context: String,
    deploy_url: Option<String>,
    file_count: u64,
    file_bytes: u64,
    file_manifest_digest: String,
    file_manifest_truncated: bool,
    expires_at: Option<u64>,
}

/// Safe fixture input mirroring only the bounded fields the parser is allowed
/// to project. It has no file map, source bundle, environment, log, or secret.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct NetlifyDeployFixture {
    pub id: String,
    pub site_id: String,
    pub state: String,
    pub branch: String,
    pub commit_ref: String,
    pub context: String,
    pub deploy_url: Option<String>,
    pub file_count: u64,
    pub file_bytes: u64,
    pub file_manifest_digest: String,
    pub file_manifest_truncated: bool,
    pub expires_at: Option<u64>,
}

impl NetlifyDeployFixture {
    #[must_use]
    pub fn ready(
        site_id: impl Into<String>,
        id: impl Into<String>,
        branch: impl Into<String>,
        commit_ref: impl Into<String>,
        context: impl Into<String>,
        manifest_digest: &Digest,
    ) -> Self {
        Self {
            id: id.into(),
            site_id: site_id.into(),
            state: "ready".to_owned(),
            branch: branch.into(),
            commit_ref: commit_ref.into(),
            context: context.into(),
            deploy_url: Some("https://example.netlify.app".to_owned()),
            file_count: 3,
            file_bytes: 4_096,
            file_manifest_digest: manifest_digest.as_str().to_owned(),
            file_manifest_truncated: false,
            expires_at: None,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct NetlifyDeployPageFixture {
    pub site_id: String,
    pub deploys: Vec<NetlifyDeployFixture>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetlifyDeployPage {
    pub site_id_digest: Digest,
    pub deploys: Vec<NetlifyDeploymentMetadata>,
    pub next_cursor: Option<OpaqueCursorView>,
    pub response_digest: Digest,
    pub link_header_digest: Option<Digest>,
}

impl NetlifyDeployPage {
    #[must_use]
    pub fn next_cursor(&self) -> Option<OpaqueCursor> {
        self.next_cursor.as_ref().map(OpaqueCursorView::to_cursor)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct OpaqueCursorView(Digest);

impl OpaqueCursorView {
    fn new(cursor: &OpaqueCursor) -> Self {
        Self(cursor.digest().clone())
    }

    fn to_cursor(&self) -> OpaqueCursor {
        OpaqueCursor::from_digest(self.0.clone())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetlifyLinkHeader {
    pub next_cursor: Option<OpaqueCursorView>,
    pub header_digest: Option<Digest>,
}

impl NetlifyLinkHeader {
    fn from_header(header: Option<&str>, site_id: &NetlifySiteId) -> Result<Self> {
        let Some(header) = header else {
            return Ok(Self {
                next_cursor: None,
                header_digest: None,
            });
        };
        if header.is_empty() || header.len() > MAX_LINK_HEADER_BYTES {
            return Err(NetlifyDeploymentError::InvalidResponse);
        }
        let mut next_cursor = None;
        for link in header.split(',') {
            if !link.contains("rel=\"next\"") && !link.contains("rel=next") {
                continue;
            }
            if next_cursor.is_some() {
                return Err(NetlifyDeploymentError::InvalidResponse);
            }
            let start = link
                .find('<')
                .ok_or(NetlifyDeploymentError::InvalidResponse)?;
            let end = link[start + 1..]
                .find('>')
                .map(|offset| start + 1 + offset)
                .ok_or(NetlifyDeploymentError::InvalidResponse)?;
            let url = &link[start + 1..end];
            let expected_path = format!(
                "https://api.netlify.com/api/v1/sites/{}/deploys?",
                site_id.as_str()
            );
            if !url.starts_with(&expected_path) {
                return Err(NetlifyDeploymentError::ScopeMismatch);
            }
            let token = url
                .split_once("cursor=")
                .map(|(_, value)| value.split('&').next().unwrap_or(value))
                .filter(|value| !value.is_empty())
                .ok_or(NetlifyDeploymentError::InvalidResponse)?;
            next_cursor = Some(OpaqueCursorView::new(&OpaqueCursor::from_token(token)?));
        }
        Ok(Self {
            next_cursor,
            header_digest: Some(Digest::from_text(header)),
        })
    }
}

pub struct RecordingTransport {
    responses: VecDeque<NetlifyResponse>,
    requests: Vec<NetlifyRequest>,
}

impl fmt::Debug for RecordingTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordingTransport")
            .field("queued_responses", &self.responses.len())
            .field("request_count", &self.requests.len())
            .finish()
    }
}

impl RecordingTransport {
    #[must_use]
    pub fn new<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = NetlifyResponse>,
    {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn from_response(response: NetlifyResponse) -> Self {
        Self::new([response])
    }

    pub fn push_response(&mut self, response: NetlifyResponse) {
        self.responses.push_back(response);
    }

    #[must_use]
    pub fn requests(&self) -> &[NetlifyRequest] {
        &self.requests
    }
}

impl NetlifyTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn execute(
        &mut self,
        request: &NetlifyRequest,
    ) -> std::result::Result<NetlifyResponse, NetlifyTransportError> {
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .ok_or(NetlifyTransportError::Timeout)
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    response: NetlifyResponse,
}

impl FixtureTransport {
    #[must_use]
    pub fn new(response: NetlifyResponse) -> Self {
        Self { response }
    }
}

impl NetlifyTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn execute(
        &mut self,
        _request: &NetlifyRequest,
    ) -> std::result::Result<NetlifyResponse, NetlifyTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    response: NetlifyResponse,
    requests: Vec<NetlifyRequest>,
}

impl LoopbackTransport {
    #[must_use]
    pub fn new(response: NetlifyResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[NetlifyRequest] {
        &self.requests
    }
}

impl NetlifyTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn execute(
        &mut self,
        request: &NetlifyRequest,
    ) -> std::result::Result<NetlifyResponse, NetlifyTransportError> {
        self.requests.push(request.clone());
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl NetlifyTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &NetlifyRequest,
    ) -> std::result::Result<NetlifyResponse, NetlifyTransportError> {
        Err(NetlifyTransportError::BlockedEnv)
    }
}
