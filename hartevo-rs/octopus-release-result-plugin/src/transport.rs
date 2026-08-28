//! Allowlisted GET transport seams and redacted response receipts.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    ChannelPayload, DeploymentPayload, DeploymentProcessPayload, DeploymentProcessTemplatePayload,
    EnvironmentPayload, ProjectPayload, ReleasePayload, SpacePayload, TaskPayload, TenantPayload,
};
use crate::{
    Digest, MAX_RECEIPTS, MAX_RESPONSE_BYTES, OctopusReleaseResultError, digest_serialized,
    validate_identifier, validate_text,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }

    pub const fn is_blocked(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum OctopusHttpMethod {
    Get,
}

impl OctopusHttpMethod {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
        }
    }
}

/// The only provider resource paths that a Layer-1 Octopus transport may
/// represent. No POST/PUT/PATCH/DELETE endpoint exists in this enum.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum OctopusEndpoint {
    Spaces {
        server: String,
    },
    Projects {
        server: String,
        space_id: String,
    },
    Channels {
        server: String,
        space_id: String,
        project_id: String,
    },
    Environments {
        server: String,
        space_id: String,
    },
    Tenants {
        server: String,
        space_id: String,
    },
    Release {
        server: String,
        space_id: String,
        release_id: String,
    },
    DeploymentProcess {
        server: String,
        space_id: String,
        deployment_process_id: String,
    },
    DeploymentProcessTemplate {
        server: String,
        space_id: String,
        deployment_process_id: String,
        channel_id: String,
    },
    Deployment {
        server: String,
        space_id: String,
        deployment_id: String,
    },
    Task {
        server: String,
        task_id: String,
    },
}

impl OctopusEndpoint {
    pub fn path_and_query(&self) -> Result<String, OctopusTransportError> {
        let (server, path) = match self {
            Self::Spaces { server } => (server, "/api/spaces".to_owned()),
            Self::Projects { server, space_id } => {
                (server, format!("/api/{}/projects", segment(space_id)?))
            }
            Self::Channels {
                server,
                space_id,
                project_id,
            } => (
                server,
                format!(
                    "/api/{}/projects/{}/channels",
                    segment(space_id)?,
                    segment(project_id)?
                ),
            ),
            Self::Environments { server, space_id } => {
                (server, format!("/api/{}/environments", segment(space_id)?))
            }
            Self::Tenants { server, space_id } => {
                (server, format!("/api/{}/tenants", segment(space_id)?))
            }
            Self::Release {
                server,
                space_id,
                release_id,
            } => (
                server,
                format!(
                    "/api/{}/releases/{}",
                    segment(space_id)?,
                    segment(release_id)?
                ),
            ),
            Self::DeploymentProcess {
                server,
                space_id,
                deployment_process_id,
            } => (
                server,
                format!(
                    "/api/{}/deploymentprocesses/{}",
                    segment(space_id)?,
                    segment(deployment_process_id)?
                ),
            ),
            Self::DeploymentProcessTemplate {
                server,
                space_id,
                deployment_process_id,
                channel_id,
            } => (
                server,
                format!(
                    "/api/{}/deploymentprocesses/{}/template?channel={}",
                    segment(space_id)?,
                    segment(deployment_process_id)?,
                    segment(channel_id)?
                ),
            ),
            Self::Deployment {
                server,
                space_id,
                deployment_id,
            } => (
                server,
                format!(
                    "/api/{}/deployments/{}",
                    segment(space_id)?,
                    segment(deployment_id)?
                ),
            ),
            Self::Task { server, task_id } => (server, format!("/api/tasks/{}", segment(task_id)?)),
        };
        validate_server(server)?;
        Ok(format!("{server}{path}"))
    }

    pub fn operation_name(&self) -> &'static str {
        match self {
            Self::Spaces { .. } => "read_spaces",
            Self::Projects { .. } => "read_projects",
            Self::Channels { .. } => "read_channels",
            Self::Environments { .. } => "read_environments",
            Self::Tenants { .. } => "read_tenants",
            Self::Release { .. } => "read_releases",
            Self::DeploymentProcess { .. } | Self::DeploymentProcessTemplate { .. } => {
                "read_deployment_process_metadata"
            }
            Self::Deployment { .. } => "read_deployment_state",
            Self::Task { .. } => "read_task_state",
        }
    }
}

fn validate_server(server: &str) -> Result<(), OctopusTransportError> {
    validate_text(server, "server origin", 256, false)
        .map_err(|_| OctopusTransportError::InvalidEndpoint)?;
    let Some(host) = server.strip_prefix("https://") else {
        return Err(OctopusTransportError::InvalidEndpoint);
    };
    if host.is_empty() || host.contains('/') || host.contains('?') || host.contains('#') {
        return Err(OctopusTransportError::InvalidEndpoint);
    }
    Ok(())
}

fn segment(value: &str) -> Result<String, OctopusTransportError> {
    validate_identifier(value, "Octopus endpoint identifier")
        .map_err(|_| OctopusTransportError::InvalidEndpoint)?;
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut encoded, "%{byte:02X}").expect("writing to String cannot fail");
        }
    }
    Ok(encoded)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OctopusHttpRequest {
    pub method: OctopusHttpMethod,
    pub endpoint: OctopusEndpoint,
    pub max_response_bytes: usize,
    pub request_digest: Digest,
}

impl OctopusHttpRequest {
    pub fn new(
        endpoint: OctopusEndpoint,
        max_response_bytes: usize,
    ) -> Result<Self, OctopusTransportError> {
        if max_response_bytes == 0 || max_response_bytes > MAX_RESPONSE_BYTES {
            return Err(OctopusTransportError::ResponseTooLarge);
        }
        let path = endpoint.path_and_query()?;
        let request_digest = Digest::from_text(&format!("GET\0{path}"))
            .map_err(|_| OctopusTransportError::InvalidEndpoint)?;
        Ok(Self {
            method: OctopusHttpMethod::Get,
            endpoint,
            max_response_bytes,
            request_digest,
        })
    }

    pub fn path_and_query(&self) -> Result<String, OctopusTransportError> {
        self.endpoint.path_and_query()
    }
}

/// Only redacted response metadata is retained in a receipt. The typed body
/// exists only at the ephemeral transport/provider seam and is never copied
/// into a receipt or recording log.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OctopusReceipt {
    pub method: String,
    pub request_path_and_query: String,
    pub request_digest: Digest,
    pub status: u16,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub provenance: TransportProvenance,
    pub raw_provider_payload: bool,
    pub credential_material: bool,
    pub provider_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub redaction_digest: Digest,
}

impl OctopusReceipt {
    fn new(
        request: &OctopusHttpRequest,
        status: u16,
        response_bytes: usize,
        response_digest: Digest,
        provenance: TransportProvenance,
    ) -> Result<Self, OctopusTransportError> {
        let path = request.path_and_query()?;
        let redaction_digest = Digest::from_parts(
            "octopus-release-result/receipt-redaction/v1",
            [
                ("path".to_owned(), path.clone()),
                ("status".to_owned(), status.to_string()),
                ("response".to_owned(), response_digest.as_str().to_owned()),
                ("provenance".to_owned(), provenance.as_str().to_owned()),
            ],
        );
        Ok(Self {
            method: request.method.as_str().to_owned(),
            request_path_and_query: path,
            request_digest: request.request_digest.clone(),
            status,
            response_bytes,
            response_digest,
            provenance,
            raw_provider_payload: false,
            credential_material: false,
            provider_receipt: false,
            connected: false,
            native: false,
            redaction_digest,
        })
    }

    pub fn validate(&self) -> Result<(), OctopusReleaseResultError> {
        self.request_digest.validate()?;
        self.response_digest.validate()?;
        self.redaction_digest.validate()?;
        if self.method != "GET"
            || self.raw_provider_payload
            || self.credential_material
            || self.provider_receipt
            || self.connected
            || self.native
            || self.response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(OctopusReleaseResultError::RedactionViolation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum OctopusResponseBody {
    Spaces(Vec<SpacePayload>),
    Projects(Vec<ProjectPayload>),
    Channels(Vec<ChannelPayload>),
    Environments(Vec<EnvironmentPayload>),
    Tenants(Vec<TenantPayload>),
    Release(ReleasePayload),
    DeploymentProcess(DeploymentProcessPayload),
    DeploymentProcessTemplate(DeploymentProcessTemplatePayload),
    Deployment(DeploymentPayload),
    Task(TaskPayload),
}

impl OctopusResponseBody {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Spaces(_) => "spaces",
            Self::Projects(_) => "projects",
            Self::Channels(_) => "channels",
            Self::Environments(_) => "environments",
            Self::Tenants(_) => "tenants",
            Self::Release(_) => "release",
            Self::DeploymentProcess(_) => "deployment_process",
            Self::DeploymentProcessTemplate(_) => "deployment_process_template",
            Self::Deployment(_) => "deployment",
            Self::Task(_) => "task",
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::parse(digest_serialized(self)).expect("response body digest is valid")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OctopusHttpResponse {
    pub status: u16,
    pub body: Option<OctopusResponseBody>,
    pub receipt: OctopusReceipt,
}

impl OctopusHttpResponse {
    pub fn from_body(
        request: &OctopusHttpRequest,
        body: OctopusResponseBody,
        provenance: TransportProvenance,
    ) -> Result<Self, OctopusTransportError> {
        let response_bytes = serde_json::to_vec(&body)
            .map_err(|_| OctopusTransportError::MalformedResponse)?
            .len();
        if response_bytes > request.max_response_bytes {
            return Err(OctopusTransportError::ResponseTooLarge);
        }
        let response_digest = body.digest();
        Ok(Self {
            status: 200,
            body: Some(body),
            receipt: OctopusReceipt::new(
                request,
                200,
                response_bytes,
                response_digest,
                provenance,
            )?,
        })
    }

    fn status(
        request: &OctopusHttpRequest,
        status: u16,
        provenance: TransportProvenance,
    ) -> Result<Self, OctopusTransportError> {
        let response_digest = Digest::from_text(&format!("octopus-http-status:{status}"))
            .map_err(|_| OctopusTransportError::MalformedResponse)?;
        Ok(Self {
            status,
            body: None,
            receipt: OctopusReceipt::new(request, status, 0, response_digest, provenance)?,
        })
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum OctopusTransportError {
    #[error("invalid allowlisted endpoint")]
    InvalidEndpoint,
    #[error("fixture has no response for the allowlisted endpoint")]
    FixtureMissing,
    #[error("fixture response is malformed")]
    MalformedResponse,
    #[error("response exceeded the Layer-1 byte bound")]
    ResponseTooLarge,
    #[error("BLOCKED_ENV")]
    BlockedEnv,
    #[error("transport timeout")]
    Timeout,
    #[error("transport access lost")]
    AccessLost,
    #[error("transport returned server status {status}")]
    ServerStatus { status: u16 },
}

pub trait OctopusTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn get(
        &mut self,
        request: &OctopusHttpRequest,
    ) -> Result<OctopusHttpResponse, OctopusTransportError>;
}

#[derive(Clone, Debug)]
struct FixtureReply {
    status: u16,
    body: Option<OctopusResponseBody>,
}

#[derive(Clone, Debug)]
pub struct FixtureOctopusTransport {
    replies: BTreeMap<String, FixtureReply>,
}

impl FixtureOctopusTransport {
    pub fn new(
        entries: Vec<(OctopusEndpoint, OctopusResponseBody)>,
    ) -> Result<Self, OctopusTransportError> {
        let mut transport = Self {
            replies: BTreeMap::new(),
        };
        for (endpoint, body) in entries {
            transport.insert(endpoint, body)?;
        }
        Ok(transport)
    }

    pub fn empty() -> Self {
        Self {
            replies: BTreeMap::new(),
        }
    }

    pub fn insert(
        &mut self,
        endpoint: OctopusEndpoint,
        body: OctopusResponseBody,
    ) -> Result<(), OctopusTransportError> {
        let path = endpoint.path_and_query()?;
        self.replies.insert(
            path,
            FixtureReply {
                status: 200,
                body: Some(body),
            },
        );
        Ok(())
    }

    pub fn insert_status(
        &mut self,
        endpoint: OctopusEndpoint,
        status: u16,
    ) -> Result<(), OctopusTransportError> {
        let path = endpoint.path_and_query()?;
        self.replies
            .insert(path, FixtureReply { status, body: None });
        Ok(())
    }

    fn response(
        &self,
        request: &OctopusHttpRequest,
        provenance: TransportProvenance,
    ) -> Result<OctopusHttpResponse, OctopusTransportError> {
        let path = request.path_and_query()?;
        let Some(reply) = self.replies.get(&path) else {
            return Err(OctopusTransportError::FixtureMissing);
        };
        if reply.status == 200 {
            let Some(body) = reply.body.clone() else {
                return Err(OctopusTransportError::MalformedResponse);
            };
            OctopusHttpResponse::from_body(request, body, provenance)
        } else {
            OctopusHttpResponse::status(request, reply.status, provenance)
        }
    }
}

impl OctopusTransport for FixtureOctopusTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn get(
        &mut self,
        request: &OctopusHttpRequest,
    ) -> Result<OctopusHttpResponse, OctopusTransportError> {
        self.response(request, self.provenance())
    }
}

#[derive(Clone, Debug)]
pub struct RecordingOctopusTransport {
    fixture: FixtureOctopusTransport,
    requests: Vec<OctopusHttpRequest>,
}

impl RecordingOctopusTransport {
    pub fn new(
        entries: Vec<(OctopusEndpoint, OctopusResponseBody)>,
    ) -> Result<Self, OctopusTransportError> {
        Ok(Self {
            fixture: FixtureOctopusTransport::new(entries)?,
            requests: Vec::new(),
        })
    }

    pub fn with_fixture(fixture: FixtureOctopusTransport) -> Self {
        Self {
            fixture,
            requests: Vec::new(),
        }
    }

    pub fn requests(&self) -> &[OctopusHttpRequest] {
        &self.requests
    }

    pub fn insert_status(
        &mut self,
        endpoint: OctopusEndpoint,
        status: u16,
    ) -> Result<(), OctopusTransportError> {
        self.fixture.insert_status(endpoint, status)
    }
}

impl OctopusTransport for RecordingOctopusTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn get(
        &mut self,
        request: &OctopusHttpRequest,
    ) -> Result<OctopusHttpResponse, OctopusTransportError> {
        self.requests.push(request.clone());
        self.fixture.response(request, self.provenance())
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackOctopusTransport {
    fixture: FixtureOctopusTransport,
    requests: Vec<OctopusHttpRequest>,
}

impl LoopbackOctopusTransport {
    pub fn new(
        entries: Vec<(OctopusEndpoint, OctopusResponseBody)>,
    ) -> Result<Self, OctopusTransportError> {
        Ok(Self {
            fixture: FixtureOctopusTransport::new(entries)?,
            requests: Vec::new(),
        })
    }

    pub fn requests(&self) -> &[OctopusHttpRequest] {
        &self.requests
    }
}

impl OctopusTransport for LoopbackOctopusTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn get(
        &mut self,
        request: &OctopusHttpRequest,
    ) -> Result<OctopusHttpResponse, OctopusTransportError> {
        self.requests.push(request.clone());
        self.fixture.response(request, self.provenance())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvOctopusTransport;

impl OctopusTransport for BlockedEnvOctopusTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn get(
        &mut self,
        _request: &OctopusHttpRequest,
    ) -> Result<OctopusHttpResponse, OctopusTransportError> {
        Err(OctopusTransportError::BlockedEnv)
    }
}

pub type FakeOctopusTransport = FixtureOctopusTransport;

#[allow(dead_code)]
const _: () = {
    assert!(MAX_RECEIPTS >= 10);
};
