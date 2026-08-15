use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    error::FastlyServiceResultError,
    model::{
        Digest, FastlyDomainProjection, FastlyServiceResultScope, MAX_RESPONSE_BYTES, PAGE_SIZE,
    },
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FastlyHttpMethod {
    Get,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum FastlyEndpoint {
    Service {
        account_digest: Digest,
        service_digest: Digest,
    },
    Version {
        service_digest: Digest,
        version_digest: Digest,
    },
    Environment {
        service_digest: Digest,
        version_digest: Digest,
        environment_digest: Digest,
    },
    Domain {
        service_digest: Digest,
        version_digest: Digest,
        domain_digest: Digest,
    },
    Validation {
        service_digest: Digest,
        version_digest: Digest,
    },
}

impl FastlyEndpoint {
    #[must_use]
    pub fn path_template(&self) -> &'static str {
        match self {
            Self::Service { .. } => "/service/{service}",
            Self::Version { .. } => "/service/{service}/version/{version}",
            Self::Environment { .. } => {
                "/service/{service}/version/{version}/environment/{environment}"
            }
            Self::Domain { .. } => "/service/{service}/version/{version}/domain/{domain}",
            Self::Validation { .. } => "/service/{service}/version/{version}/validation",
        }
    }

    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Service { .. } => "service",
            Self::Version { .. } => "version",
            Self::Environment { .. } => "environment",
            Self::Domain { .. } => "domain",
            Self::Validation { .. } => "validation",
        }
    }

    #[must_use]
    pub fn is_allowlisted(&self) -> bool {
        true
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        let encoded = serde_json::to_vec(self).unwrap_or_default();
        Digest::from_parts(
            "fastly-endpoint/v1",
            &[
                ("name", self.name().to_owned()),
                ("endpoint", crate::model::sha256_hex(&encoded)),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FastlyRequest {
    pub method: FastlyHttpMethod,
    pub endpoint: FastlyEndpoint,
    pub scope_digest: Digest,
    pub page: u16,
    pub per_page: u16,
}

impl FastlyRequest {
    #[must_use]
    pub fn new(endpoint: FastlyEndpoint, page: u16) -> Self {
        Self {
            method: FastlyHttpMethod::Get,
            endpoint,
            scope_digest: Digest::pending(),
            page: page.max(1),
            per_page: PAGE_SIZE,
        }
    }

    #[must_use]
    pub fn is_get(&self) -> bool {
        matches!(self.method, FastlyHttpMethod::Get)
    }

    #[must_use]
    pub fn is_allowlisted(&self) -> bool {
        self.is_get() && self.endpoint.is_allowlisted() && self.page > 0 && self.per_page > 0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        let encoded = serde_json::to_vec(self).unwrap_or_default();
        Digest::from_parts(
            "fastly-request/v1",
            &[
                ("request", crate::model::sha256_hex(&encoded)),
                ("path", self.endpoint.path_template().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FastlyServicePayload {
    pub scope_digest: Digest,
    pub account_digest: Digest,
    pub service_digest: Digest,
    pub metadata_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FastlyVersionPayload {
    pub scope_digest: Digest,
    pub version_digest: Digest,
    pub config_digest: Digest,
    pub state: crate::model::FastlyVersionState,
    pub active: bool,
    pub staging: bool,
    pub testing: bool,
    pub metadata_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FastlyEnvironmentPayload {
    pub scope_digest: Digest,
    pub environment_digest: Digest,
    pub version_digest: Digest,
    pub state: crate::model::FastlyEnvironmentState,
    pub active: bool,
    pub staging: bool,
    pub testing: bool,
    pub metadata_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FastlyDomainPagePayload {
    pub scope_digest: Digest,
    pub page: u16,
    pub total_pages: u16,
    pub entries: Vec<FastlyDomainProjection>,
    pub partial: bool,
    pub page_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FastlyValidationPayload {
    pub scope_digest: Digest,
    pub validation_digest: Digest,
    pub config_digest: Digest,
    pub state: crate::model::FastlyValidationState,
    pub error_count: u16,
    pub warning_count: u16,
    pub metadata_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "payload")]
pub enum FastlyResponseBody {
    Service(FastlyServicePayload),
    Version(FastlyVersionPayload),
    Environment(FastlyEnvironmentPayload),
    Domain(FastlyDomainPagePayload),
    Validation(FastlyValidationPayload),
}

impl FastlyResponseBody {
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Service(_) => "service",
            Self::Version(_) => "version",
            Self::Environment(_) => "environment",
            Self::Domain(_) => "domain",
            Self::Validation(_) => "validation",
        }
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        match self {
            Self::Service(payload) => &payload.scope_digest,
            Self::Version(payload) => &payload.scope_digest,
            Self::Environment(payload) => &payload.scope_digest,
            Self::Domain(payload) => &payload.scope_digest,
            Self::Validation(payload) => &payload.scope_digest,
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        let encoded = serde_json::to_vec(self).unwrap_or_default();
        Digest::from_parts(
            "fastly-response-body/v1",
            &[
                ("kind", self.kind().to_owned()),
                ("body", crate::model::sha256_hex(&encoded)),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FastlyResponse {
    pub status: u16,
    pub body: Option<FastlyResponseBody>,
    pub response_bytes: usize,
    pub declared_digest: Option<Digest>,
}

impl FastlyResponse {
    pub fn from_body(status: u16, body: FastlyResponseBody) -> Result<Self, FastlyTransportError> {
        let response_bytes = serde_json::to_vec(&body)
            .map_err(|_| FastlyTransportError::UnexpectedBody)?
            .len();
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(FastlyTransportError::ResponseTooLarge);
        }
        Ok(Self {
            status,
            body: Some(body),
            response_bytes,
            declared_digest: None,
        })
    }

    #[must_use]
    pub fn empty(status: u16) -> Self {
        Self {
            status,
            body: None,
            response_bytes: 0,
            declared_digest: None,
        }
    }

    #[must_use]
    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.declared_digest = Some(digest);
        self
    }

    pub fn validate_for(&self, request: &FastlyRequest) -> Result<(), FastlyTransportError> {
        if self.response_bytes > MAX_RESPONSE_BYTES {
            return Err(FastlyTransportError::ResponseTooLarge);
        }
        if let Some(body) = &self.body {
            if body.kind() != request.endpoint.name()
                || body.scope_digest() != &request.scope_digest
            {
                return Err(FastlyTransportError::UnexpectedBody);
            }
            if self
                .declared_digest
                .as_ref()
                .is_some_and(|declared| declared != &body.digest())
            {
                return Err(FastlyTransportError::Tampered);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    #[must_use]
    pub const fn connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn first_party(self) -> bool {
        false
    }

    #[must_use]
    pub const fn provider_receipt(self) -> bool {
        false
    }
}

impl fmt::Display for TransportProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Fake => "fake",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FastlyTransportError {
    RateLimited { retry_after_seconds: Option<u32> },
    AccessLoss,
    ProviderUnknown,
    Timeout,
    ServerError { status: u16 },
    NotFound,
    ResponseTooLarge,
    UnexpectedBody,
    Tampered,
    BlockedEnv,
}

pub trait FastlyTransport: fmt::Debug {
    fn execute(
        &mut self,
        request: &FastlyRequest,
    ) -> std::result::Result<FastlyResponse, FastlyTransportError>;

    fn provenance(&self) -> TransportProvenance;

    fn requests(&self) -> &[FastlyRequest] {
        &[]
    }
}

#[derive(Clone, Debug)]
struct ScriptedTransport {
    provenance: TransportProvenance,
    queue: VecDeque<std::result::Result<FastlyResponse, FastlyTransportError>>,
    requests: Vec<FastlyRequest>,
}

impl ScriptedTransport {
    fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            queue: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    fn from_responses(provenance: TransportProvenance, responses: Vec<FastlyResponse>) -> Self {
        Self {
            provenance,
            queue: responses.into_iter().map(Ok).collect(),
            requests: Vec::new(),
        }
    }

    fn push_response(&mut self, response: FastlyResponse) {
        self.queue.push_back(Ok(response));
    }

    fn push_error(&mut self, error: FastlyTransportError) {
        self.queue.push_back(Err(error));
    }

    fn requests(&self) -> &[FastlyRequest] {
        &self.requests
    }
}

macro_rules! scripted_transport {
    ($name:ident, $provenance:expr) => {
        #[derive(Clone, Debug)]
        pub struct $name {
            inner: ScriptedTransport,
        }

        impl Default for $name {
            fn default() -> Self {
                Self {
                    inner: ScriptedTransport::new($provenance),
                }
            }
        }

        impl $name {
            #[must_use]
            pub fn from_responses(responses: Vec<FastlyResponse>) -> Self {
                Self {
                    inner: ScriptedTransport::from_responses($provenance, responses),
                }
            }

            pub fn push_response(&mut self, response: FastlyResponse) {
                self.inner.push_response(response);
            }

            pub fn push_error(&mut self, error: FastlyTransportError) {
                self.inner.push_error(error);
            }

            #[must_use]
            pub fn requests(&self) -> &[FastlyRequest] {
                self.inner.requests()
            }
        }

        impl FastlyTransport for $name {
            fn execute(
                &mut self,
                request: &FastlyRequest,
            ) -> std::result::Result<FastlyResponse, FastlyTransportError> {
                self.inner.requests.push(request.clone());
                if !request.is_allowlisted() {
                    return Err(FastlyTransportError::UnexpectedBody);
                }
                self.inner
                    .queue
                    .pop_front()
                    .unwrap_or(Err(FastlyTransportError::ProviderUnknown))
            }

            fn provenance(&self) -> TransportProvenance {
                self.inner.provenance
            }

            fn requests(&self) -> &[FastlyRequest] {
                self.inner.requests()
            }
        }
    };
}

scripted_transport!(RecordingTransport, TransportProvenance::Recording);
scripted_transport!(FakeTransport, TransportProvenance::Fake);
scripted_transport!(LoopbackTransport, TransportProvenance::Loopback);

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl FastlyTransport for BlockedEnvTransport {
    fn execute(
        &mut self,
        request: &FastlyRequest,
    ) -> std::result::Result<FastlyResponse, FastlyTransportError> {
        let _ = request;
        Err(FastlyTransportError::BlockedEnv)
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }
}

pub type RecordingFastlyTransport = RecordingTransport;
pub type FakeFastlyTransport = FakeTransport;
pub type LoopbackFastlyTransport = LoopbackTransport;
pub type BlockedEnvFastlyTransport = BlockedEnvTransport;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FastlyFixtureSet {
    pub service: FastlyServicePayload,
    pub version: FastlyVersionPayload,
    pub environment: FastlyEnvironmentPayload,
    pub domain_pages: Vec<FastlyDomainPagePayload>,
    pub validation: FastlyValidationPayload,
}

impl FastlyFixtureSet {
    #[must_use]
    pub fn for_scope(scope: &FastlyServiceResultScope) -> Self {
        let scope_digest = scope.digest();
        let account_digest = scope.account().digest();
        let service_digest = scope.service().digest();
        let version_digest = scope.version().digest();
        let environment_digest = scope.environment().digest();
        let domain_digest = scope.domain().digest();
        let config_digest = Digest::from_parts(
            "fastly-config-metadata/v1",
            &[
                ("service", service_digest.to_string()),
                ("version", version_digest.to_string()),
                ("environment", environment_digest.to_string()),
            ],
        );
        let metadata_digest = Digest::from_parts(
            "fastly-service-metadata/v1",
            &[
                ("account", account_digest.to_string()),
                ("service", service_digest.to_string()),
            ],
        );
        let version_metadata_digest = Digest::from_parts(
            "fastly-version-metadata/v1",
            &[
                ("version", version_digest.to_string()),
                ("config", config_digest.to_string()),
            ],
        );
        let environment_metadata_digest = Digest::from_parts(
            "fastly-environment-metadata/v1",
            &[
                ("environment", environment_digest.to_string()),
                ("version", version_digest.to_string()),
            ],
        );
        let domain_metadata_digest = Digest::from_parts(
            "fastly-domain-metadata/v1",
            &[
                ("domain", domain_digest.to_string()),
                ("version", version_digest.to_string()),
            ],
        );
        let validation_digest = Digest::from_parts(
            "fastly-validation/v1",
            &[
                ("scope", scope_digest.to_string()),
                ("config", config_digest.to_string()),
                ("status", "passed".to_owned()),
            ],
        );
        let page_digest = Digest::from_parts(
            "fastly-domain-page/v1",
            &[
                ("scope", scope_digest.to_string()),
                ("page", "1".to_owned()),
                ("domain", domain_digest.to_string()),
            ],
        );
        Self {
            service: FastlyServicePayload {
                scope_digest: scope_digest.clone(),
                account_digest,
                service_digest: service_digest.clone(),
                metadata_digest,
            },
            version: FastlyVersionPayload {
                scope_digest: scope_digest.clone(),
                version_digest: version_digest.clone(),
                config_digest: config_digest.clone(),
                state: crate::model::FastlyVersionState::Active,
                active: true,
                staging: false,
                testing: false,
                metadata_digest: version_metadata_digest,
            },
            environment: FastlyEnvironmentPayload {
                scope_digest: scope_digest.clone(),
                environment_digest,
                version_digest: version_digest.clone(),
                state: crate::model::FastlyEnvironmentState::Staging,
                active: false,
                staging: true,
                testing: false,
                metadata_digest: environment_metadata_digest,
            },
            domain_pages: vec![FastlyDomainPagePayload {
                scope_digest: scope_digest.clone(),
                page: 1,
                total_pages: 1,
                entries: vec![FastlyDomainProjection {
                    domain_digest,
                    version_digest,
                    state: crate::model::FastlyDomainState::Present,
                    tls: crate::model::FastlyTlsState::Enabled,
                    metadata_digest: domain_metadata_digest,
                }],
                partial: false,
                page_digest,
            }],
            validation: FastlyValidationPayload {
                scope_digest,
                validation_digest,
                config_digest,
                state: crate::model::FastlyValidationState::Passed,
                error_count: 0,
                warning_count: 0,
                metadata_digest: Digest::from_text("fastly-validation-metadata:passed"),
            },
        }
    }

    #[must_use]
    pub fn responses(&self) -> Vec<FastlyResponse> {
        let mut responses = Vec::with_capacity(4 + self.domain_pages.len());
        responses.push(
            FastlyResponse::from_body(200, FastlyResponseBody::Service(self.service.clone()))
                .expect("fixture service response"),
        );
        responses.push(
            FastlyResponse::from_body(200, FastlyResponseBody::Version(self.version.clone()))
                .expect("fixture version response"),
        );
        responses.push(
            FastlyResponse::from_body(
                200,
                FastlyResponseBody::Environment(self.environment.clone()),
            )
            .expect("fixture environment response"),
        );
        responses.extend(self.domain_pages.iter().cloned().map(|page| {
            FastlyResponse::from_body(200, FastlyResponseBody::Domain(page))
                .expect("fixture domain response")
        }));
        responses.push(
            FastlyResponse::from_body(200, FastlyResponseBody::Validation(self.validation.clone()))
                .expect("fixture validation response"),
        );
        responses
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    inner: ScriptedTransport,
    fixture: FastlyFixtureSet,
}

impl FixtureTransport {
    #[must_use]
    pub fn for_scope(scope: &FastlyServiceResultScope) -> Self {
        let fixture = FastlyFixtureSet::for_scope(scope);
        Self {
            inner: ScriptedTransport::from_responses(
                TransportProvenance::Fixture,
                fixture.responses(),
            ),
            fixture,
        }
    }

    #[must_use]
    pub fn from_fixture(fixture: FastlyFixtureSet) -> Self {
        Self {
            inner: ScriptedTransport::from_responses(
                TransportProvenance::Fixture,
                fixture.responses(),
            ),
            fixture,
        }
    }

    #[must_use]
    pub fn fixture(&self) -> &FastlyFixtureSet {
        &self.fixture
    }

    #[must_use]
    pub fn requests(&self) -> &[FastlyRequest] {
        self.inner.requests()
    }
}

impl FastlyTransport for FixtureTransport {
    fn execute(
        &mut self,
        request: &FastlyRequest,
    ) -> std::result::Result<FastlyResponse, FastlyTransportError> {
        self.inner.requests.push(request.clone());
        self.inner
            .queue
            .pop_front()
            .unwrap_or(Err(FastlyTransportError::ProviderUnknown))
    }

    fn provenance(&self) -> TransportProvenance {
        self.inner.provenance
    }

    fn requests(&self) -> &[FastlyRequest] {
        self.inner.requests()
    }
}

pub type FastlyFixtureTransport = FixtureTransport;

impl From<FastlyServiceResultError> for FastlyTransportError {
    fn from(value: FastlyServiceResultError) -> Self {
        match value {
            FastlyServiceResultError::ResponseTooLarge => Self::ResponseTooLarge,
            FastlyServiceResultError::Tampered => Self::Tampered,
            _ => Self::UnexpectedBody,
        }
    }
}

impl FastlyTransportError {
    #[must_use]
    pub const fn status(&self) -> Option<u16> {
        match self {
            Self::ServerError { status } => Some(*status),
            Self::AccessLoss => Some(403),
            Self::NotFound => Some(404),
            Self::RateLimited { .. } => Some(429),
            _ => None,
        }
    }
}

pub type FastlyResponseError = FastlyTransportError;
