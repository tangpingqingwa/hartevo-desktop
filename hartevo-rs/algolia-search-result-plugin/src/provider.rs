use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AlgoliaAnalyticsAcl, AlgoliaAnalyticsPayload, AlgoliaApplicationId, AlgoliaHttpMethod,
    AlgoliaIndexName, AlgoliaRateLimitReceipt, AlgoliaRegistration, AlgoliaSearchQualityAggregate,
    AlgoliaSearchQualityMetric, AlgoliaSearchQualityScope, Digest, MAX_REQUESTS_PER_MINUTE,
    MAX_RESPONSE_BYTES, ModelError, RegistrationState, SecretReference, TransportProvenance,
};

/// A safe request representation for the four allowlisted Analytics API GET
/// seams. It contains no API key, query term, user token, IP-derived value,
/// object ID, or event payload. Tags are represented by digests only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AlgoliaAnalyticsRequest {
    pub method: AlgoliaHttpMethod,
    pub host: String,
    pub path: String,
    pub application_id: AlgoliaApplicationId,
    pub index_name: AlgoliaIndexName,
    pub start_date: String,
    pub end_date: String,
    pub metric: AlgoliaSearchQualityMetric,
    pub tag_digests: Vec<Digest>,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub request_digest: Digest,
}

impl AlgoliaAnalyticsRequest {
    #[must_use]
    pub fn digest(&self) -> Digest {
        crate::canonical_digest(&(
            self.method,
            &self.host,
            &self.path,
            &self.application_id,
            &self.index_name,
            &self.start_date,
            &self.end_date,
            self.metric,
            &self.tag_digests,
            &self.scope_digest,
            &self.consent_digest,
            &self.secret_reference_digest,
        ))
    }

    #[must_use]
    pub fn is_allowlisted(&self) -> bool {
        self.method == AlgoliaHttpMethod::Get
            && self.host.starts_with("https://analytics.")
            && matches!(
                self.path.as_str(),
                "/2/searches/count"
                    | "/2/searches/noResultRate"
                    | "/2/clicks/clickThroughRate"
                    | "/2/conversions/conversionRate"
            )
            && self.tag_digests.iter().all(|digest| digest.len() == 64)
    }
}

/// A fixture response intentionally keeps its raw JSON body private to the
/// provider parser. Evidence and receipts expose only an SHA-256 response
/// digest and bounded aggregate fields.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AlgoliaAnalyticsResponse {
    pub status: u16,
    #[serde(skip)]
    body: Vec<u8>,
    pub rate_limit: AlgoliaRateLimitReceipt,
}

impl fmt::Debug for AlgoliaAnalyticsResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AlgoliaAnalyticsResponse")
            .field("status", &self.status)
            .field("body_digest", &crate::sha256_digest(&self.body))
            .field("body_bytes", &self.body.len())
            .field("rate_limit", &self.rate_limit)
            .finish()
    }
}

impl AlgoliaAnalyticsResponse {
    /// Build a deterministic fixture response from a serializable aggregate
    /// payload. The body is not exposed by this type.
    #[must_use]
    pub fn json<T: Serialize>(status: u16, value: &T) -> Self {
        Self::json_with_rate_limit(status, value, AlgoliaRateLimitReceipt::default())
    }

    /// Build a fixture response with a bounded rate-limit receipt.
    #[must_use]
    pub fn json_with_rate_limit<T: Serialize>(
        status: u16,
        value: &T,
        rate_limit: AlgoliaRateLimitReceipt,
    ) -> Self {
        let body = serde_json::to_vec(value).expect("Algolia fixture payload serializes");
        Self {
            status,
            body,
            rate_limit,
        }
    }

    /// Build a fixture response for malformed-response and response-size
    /// adversarial tests. The bytes never leave the provider parser.
    #[must_use]
    pub fn new(status: u16, body: Vec<u8>, rate_limit: AlgoliaRateLimitReceipt) -> Self {
        Self {
            status,
            body,
            rate_limit,
        }
    }

    #[must_use]
    pub fn response_digest(&self) -> Digest {
        crate::sha256_digest(&self.body)
    }

    #[must_use]
    pub const fn response_bytes(&self) -> usize {
        self.body.len()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AlgoliaTransportError {
    #[error("Algolia native transport is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("Algolia transport timed out")]
    Timeout,
    #[error("Algolia transport failed without a native response")]
    ProviderUnknown,
}

/// Layer-1 transport seam. Implementations may replay bounded fixture data,
/// but this crate never supplies an implementation that resolves credentials
/// or opens native HTTPS.
pub trait AlgoliaAnalyticsTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn execute(
        &mut self,
        request: &AlgoliaAnalyticsRequest,
    ) -> Result<AlgoliaAnalyticsResponse, AlgoliaTransportError>;
}

#[derive(Clone, Debug)]
pub struct FixtureAlgoliaAnalyticsTransport {
    response: AlgoliaAnalyticsResponse,
}

impl FixtureAlgoliaAnalyticsTransport {
    #[must_use]
    pub fn new(response: AlgoliaAnalyticsResponse) -> Self {
        Self { response }
    }
}

impl AlgoliaAnalyticsTransport for FixtureAlgoliaAnalyticsTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn execute(
        &mut self,
        _request: &AlgoliaAnalyticsRequest,
    ) -> Result<AlgoliaAnalyticsResponse, AlgoliaTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct RecordingAlgoliaAnalyticsTransport {
    response: AlgoliaAnalyticsResponse,
    requests: Vec<AlgoliaAnalyticsRequest>,
}

impl RecordingAlgoliaAnalyticsTransport {
    #[must_use]
    pub fn new(response: AlgoliaAnalyticsResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[AlgoliaAnalyticsRequest] {
        &self.requests
    }
}

impl AlgoliaAnalyticsTransport for RecordingAlgoliaAnalyticsTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn execute(
        &mut self,
        request: &AlgoliaAnalyticsRequest,
    ) -> Result<AlgoliaAnalyticsResponse, AlgoliaTransportError> {
        self.requests.push(request.clone());
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackAlgoliaAnalyticsTransport {
    response: AlgoliaAnalyticsResponse,
    requests: Vec<AlgoliaAnalyticsRequest>,
}

impl LoopbackAlgoliaAnalyticsTransport {
    #[must_use]
    pub fn new(response: AlgoliaAnalyticsResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[AlgoliaAnalyticsRequest] {
        &self.requests
    }
}

impl AlgoliaAnalyticsTransport for LoopbackAlgoliaAnalyticsTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn execute(
        &mut self,
        request: &AlgoliaAnalyticsRequest,
    ) -> Result<AlgoliaAnalyticsResponse, AlgoliaTransportError> {
        self.requests.push(request.clone());
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvAlgoliaAnalyticsTransport;

impl AlgoliaAnalyticsTransport for BlockedEnvAlgoliaAnalyticsTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &AlgoliaAnalyticsRequest,
    ) -> Result<AlgoliaAnalyticsResponse, AlgoliaTransportError> {
        Err(AlgoliaTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AlgoliaProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub capability_digest: Digest,
    pub acl_digest: Digest,
    pub provenance: TransportProvenance,
    pub max_requests_per_minute: u16,
    pub max_response_bytes: usize,
    pub read_only: bool,
    pub live_execution: bool,
    pub native: bool,
    pub connected: bool,
}

impl AlgoliaProviderDefinition {
    #[must_use]
    pub fn layer1(provenance: TransportProvenance, acl: &AlgoliaAnalyticsAcl) -> Self {
        let capability_digest = crate::canonical_digest(&(
            crate::ALGOLIA_SEARCH_RESULT_SCHEMA_VERSION,
            crate::ALGOLIA_ANALYTICS_PROVIDER_ID,
            crate::ALGOLIA_ANALYTICS_API_REVISION,
            "aggregate_get_only",
            "/2/searches/count",
            "/2/searches/noResultRate",
            "/2/clicks/clickThroughRate",
            "/2/conversions/conversionRate",
        ));
        Self {
            schema_version: crate::ALGOLIA_SEARCH_RESULT_SCHEMA_VERSION.to_owned(),
            provider_id: crate::ALGOLIA_ANALYTICS_PROVIDER_ID.to_owned(),
            provider_version: crate::ALGOLIA_ANALYTICS_PROVIDER_VERSION.to_owned(),
            api_revision: crate::ALGOLIA_ANALYTICS_API_REVISION.to_owned(),
            capability_digest,
            acl_digest: acl.digest(),
            provenance,
            max_requests_per_minute: MAX_REQUESTS_PER_MINUTE,
            max_response_bytes: MAX_RESPONSE_BYTES,
            read_only: true,
            live_execution: false,
            native: false,
            connected: false,
        }
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        crate::canonical_digest(self)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AlgoliaProviderError {
    #[error("Algolia registration is revoked or drifted")]
    RegistrationRevoked,
    #[error("Algolia SecretReference is revoked")]
    SecretRevoked,
    #[error("Algolia Analytics ACL is missing")]
    MissingAnalyticsAcl,
    #[error("Algolia region or scope is invalid")]
    ScopeMismatch,
    #[error("Algolia request rate bound was exhausted")]
    RateLimited {
        request: AlgoliaAnalyticsRequest,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: AlgoliaRateLimitReceipt,
    },
    #[error("Algolia response status is {status_code}")]
    HttpStatus {
        request: AlgoliaAnalyticsRequest,
        status_code: u16,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: AlgoliaRateLimitReceipt,
    },
    #[error("Algolia response exceeded the Layer-1 response bound")]
    ResponseTooLarge {
        request: AlgoliaAnalyticsRequest,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: AlgoliaRateLimitReceipt,
    },
    #[error("Algolia Analytics response was malformed or outside aggregate bounds")]
    MalformedResponse {
        request: AlgoliaAnalyticsRequest,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: AlgoliaRateLimitReceipt,
    },
    #[error("Algolia rate-limit receipt is invalid")]
    InvalidRateLimitReceipt { request: AlgoliaAnalyticsRequest },
    #[error("Algolia transport failed")]
    Transport {
        request: AlgoliaAnalyticsRequest,
        error: AlgoliaTransportError,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: AlgoliaRateLimitReceipt,
    },
    #[error(transparent)]
    Model(#[from] ModelError),
}

impl AlgoliaProviderError {
    #[must_use]
    pub fn request(&self) -> Option<&AlgoliaAnalyticsRequest> {
        match self {
            Self::RegistrationRevoked
            | Self::SecretRevoked
            | Self::MissingAnalyticsAcl
            | Self::ScopeMismatch
            | Self::Model(_) => None,
            Self::RateLimited { request, .. }
            | Self::HttpStatus { request, .. }
            | Self::ResponseTooLarge { request, .. }
            | Self::MalformedResponse { request, .. }
            | Self::InvalidRateLimitReceipt { request }
            | Self::Transport { request, .. } => Some(request),
        }
    }

    #[must_use]
    pub fn metadata(&self) -> Option<(Digest, usize, AlgoliaRateLimitReceipt, Option<u16>)> {
        match self {
            Self::RateLimited {
                response_digest,
                response_bytes,
                rate_limit,
                ..
            } => Some((
                response_digest.clone(),
                *response_bytes,
                rate_limit.clone(),
                Some(429),
            )),
            Self::HttpStatus {
                status_code,
                response_digest,
                response_bytes,
                rate_limit,
                ..
            } => Some((
                response_digest.clone(),
                *response_bytes,
                rate_limit.clone(),
                Some(*status_code),
            )),
            Self::ResponseTooLarge {
                response_digest,
                response_bytes,
                rate_limit,
                ..
            }
            | Self::MalformedResponse {
                response_digest,
                response_bytes,
                rate_limit,
                ..
            } => Some((
                response_digest.clone(),
                *response_bytes,
                rate_limit.clone(),
                None,
            )),
            Self::Transport {
                response_digest,
                response_bytes,
                rate_limit,
                ..
            } => Some((
                response_digest.clone(),
                *response_bytes,
                rate_limit.clone(),
                None,
            )),
            Self::InvalidRateLimitReceipt { .. }
            | Self::RegistrationRevoked
            | Self::SecretRevoked
            | Self::MissingAnalyticsAcl
            | Self::ScopeMismatch
            | Self::Model(_) => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AlgoliaProviderRead {
    pub request: AlgoliaAnalyticsRequest,
    pub aggregate: AlgoliaSearchQualityAggregate,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub rate_limit: AlgoliaRateLimitReceipt,
    pub provenance: TransportProvenance,
}

/// Typed provider boundary for bounded Algolia Analytics aggregate reads.
#[derive(Clone)]
pub struct AlgoliaAnalyticsProvider<T: AlgoliaAnalyticsTransport> {
    scope: AlgoliaSearchQualityScope,
    secret_reference: SecretReference,
    transport: T,
    definition: AlgoliaProviderDefinition,
    registration: AlgoliaRegistration,
    requests_issued: u16,
}

impl<T: AlgoliaAnalyticsTransport> fmt::Debug for AlgoliaAnalyticsProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AlgoliaAnalyticsProvider")
            .field("scope_digest", &self.scope.scope_digest())
            .field("secret_reference", &self.secret_reference)
            .field("transport_provenance", &self.definition.provenance)
            .field("definition", &self.definition)
            .field("registration", &self.registration)
            .field("requests_issued", &self.requests_issued)
            .finish_non_exhaustive()
    }
}

impl<T: AlgoliaAnalyticsTransport> AlgoliaAnalyticsProvider<T> {
    pub fn new(
        scope: AlgoliaSearchQualityScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, AlgoliaProviderError> {
        scope.validate()?;
        if secret_reference.is_revoked() {
            return Err(AlgoliaProviderError::SecretRevoked);
        }
        if !scope
            .acl()
            .has(crate::AlgoliaAnalyticsPermission::Analytics)
        {
            return Err(AlgoliaProviderError::MissingAnalyticsAcl);
        }
        let definition = AlgoliaProviderDefinition::layer1(transport.provenance(), scope.acl());
        let registration =
            AlgoliaRegistration::bind(&scope, &secret_reference, definition.provider_digest());
        Ok(Self {
            scope,
            secret_reference,
            transport,
            definition,
            registration,
            requests_issued: 0,
        })
    }

    pub fn with_registration(
        scope: AlgoliaSearchQualityScope,
        secret_reference: SecretReference,
        transport: T,
        registration: AlgoliaRegistration,
    ) -> Result<Self, AlgoliaProviderError> {
        scope.validate()?;
        let definition = AlgoliaProviderDefinition::layer1(transport.provenance(), scope.acl());
        registration
            .validate(&scope, &secret_reference, &definition.provider_digest())
            .map_err(|_| AlgoliaProviderError::ScopeMismatch)?;
        Ok(Self {
            scope,
            secret_reference,
            transport,
            definition,
            registration,
            requests_issued: 0,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &AlgoliaSearchQualityScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn definition(&self) -> &AlgoliaProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest()
    }

    #[must_use]
    pub fn registration(&self) -> &AlgoliaRegistration {
        &self.registration
    }

    #[must_use]
    pub fn transport_provenance(&self) -> TransportProvenance {
        self.definition.provenance
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read(&mut self) -> Result<AlgoliaProviderRead, AlgoliaProviderError> {
        self.read_metric(self.scope.metric())
    }

    pub fn read_aggregate(&mut self) -> Result<AlgoliaProviderRead, AlgoliaProviderError> {
        self.read()
    }

    pub fn read_metric(
        &mut self,
        metric: AlgoliaSearchQualityMetric,
    ) -> Result<AlgoliaProviderRead, AlgoliaProviderError> {
        self.ensure_ready()?;
        if metric != self.scope.metric() {
            return Err(AlgoliaProviderError::ScopeMismatch);
        }
        let request = self.build_request(metric);
        if !request.is_allowlisted() || request.host != self.scope.region().host() {
            return Err(AlgoliaProviderError::ScopeMismatch);
        }
        if self.requests_issued >= self.definition.max_requests_per_minute {
            return Err(AlgoliaProviderError::RateLimited {
                request,
                response_digest: crate::sha256_digest(b"algolia-request-rate-budget"),
                response_bytes: 0,
                rate_limit: AlgoliaRateLimitReceipt::new(
                    self.definition.max_requests_per_minute,
                    Some(0),
                    Some(60),
                    true,
                )
                .expect("bounded request rate receipt"),
            });
        }
        self.requests_issued = self.requests_issued.saturating_add(1);
        let provenance = self.definition.provenance;
        let response = match self.transport.execute(&request) {
            Ok(response) => response,
            Err(error) => {
                return Err(AlgoliaProviderError::Transport {
                    request,
                    error,
                    response_digest: crate::sha256_digest(b"algolia-transport-no-response"),
                    response_bytes: 0,
                    rate_limit: AlgoliaRateLimitReceipt::default(),
                });
            }
        };
        if response.rate_limit.limit_per_minute == 0
            || response.rate_limit.limit_per_minute > MAX_REQUESTS_PER_MINUTE
            || response
                .rate_limit
                .remaining
                .is_some_and(|remaining| remaining > response.rate_limit.limit_per_minute)
            || response
                .rate_limit
                .retry_after_seconds
                .is_some_and(|retry| retry > crate::MAX_RETRY_AFTER_SECONDS)
        {
            return Err(AlgoliaProviderError::InvalidRateLimitReceipt { request });
        }
        let response_digest = response.response_digest();
        let response_bytes = response.response_bytes();
        let rate_limit = response.rate_limit.clone();
        if !(200..=299).contains(&response.status) {
            return Err(AlgoliaProviderError::HttpStatus {
                request,
                status_code: response.status,
                response_digest,
                response_bytes,
                rate_limit,
            });
        }
        if response_bytes > self.definition.max_response_bytes {
            return Err(AlgoliaProviderError::ResponseTooLarge {
                request,
                response_digest,
                response_bytes,
                rate_limit,
            });
        }
        let payload = match serde_json::from_slice::<AlgoliaAnalyticsPayload>(&response.body) {
            Ok(payload) => payload,
            Err(_) => {
                return Err(AlgoliaProviderError::MalformedResponse {
                    request,
                    response_digest,
                    response_bytes,
                    rate_limit,
                });
            }
        };
        let aggregate = match payload.normalize(metric, self.scope.analytics_window()) {
            Ok(aggregate) => aggregate,
            Err(_) => {
                return Err(AlgoliaProviderError::MalformedResponse {
                    request,
                    response_digest,
                    response_bytes,
                    rate_limit,
                });
            }
        };
        // Do not bind proposal identity to provider JSON key/array ordering.
        // The raw body remains private and is never exposed; this digest is
        // over the normalized, sorted aggregate and bounded receipt metadata.
        let normalized_response_digest = crate::canonical_digest(&(
            "algolia-normalized-response/v1",
            metric,
            &aggregate,
            &rate_limit,
        ));
        let normalized_response_bytes = serde_json::to_vec(&aggregate)
            .expect("normalized Algolia aggregate serializes")
            .len();
        Ok(AlgoliaProviderRead {
            request,
            aggregate,
            response_digest: normalized_response_digest,
            response_bytes: normalized_response_bytes,
            rate_limit,
            provenance,
        })
    }

    pub fn revoke(&mut self) -> Result<crate::RegistrationRevocationReceipt, AlgoliaProviderError> {
        self.registration
            .revoke()
            .map_err(AlgoliaProviderError::Model)
    }

    pub fn restore(&mut self) -> Result<(), AlgoliaProviderError> {
        self.registration
            .restore()
            .map_err(AlgoliaProviderError::Model)
    }

    pub fn revoke_secret(&mut self) -> Result<(), AlgoliaProviderError> {
        self.secret_reference
            .revoke()
            .map_err(AlgoliaProviderError::Model)
    }

    fn ensure_ready(&self) -> Result<(), AlgoliaProviderError> {
        if self.registration.state != RegistrationState::Active {
            return Err(AlgoliaProviderError::RegistrationRevoked);
        }
        if self.secret_reference.is_revoked() {
            return Err(AlgoliaProviderError::SecretRevoked);
        }
        if !self
            .scope
            .acl()
            .has(crate::AlgoliaAnalyticsPermission::Analytics)
        {
            return Err(AlgoliaProviderError::MissingAnalyticsAcl);
        }
        self.registration
            .validate(&self.scope, &self.secret_reference, &self.provider_digest())
            .map_err(|_| AlgoliaProviderError::RegistrationRevoked)
    }

    fn build_request(&self, metric: AlgoliaSearchQualityMetric) -> AlgoliaAnalyticsRequest {
        let mut request = AlgoliaAnalyticsRequest {
            method: AlgoliaHttpMethod::Get,
            host: self.scope.region().host().to_owned(),
            path: metric.endpoint().to_owned(),
            application_id: self.scope.application_id().clone(),
            index_name: self.scope.index_name().clone(),
            start_date: self.scope.analytics_window().start_date().to_owned(),
            end_date: self.scope.analytics_window().end_date().to_owned(),
            metric,
            tag_digests: self
                .scope
                .tags()
                .iter()
                .map(|tag| tag.digest().clone())
                .collect(),
            scope_digest: self.scope.digest(),
            consent_digest: self.scope.consent_digest().clone(),
            secret_reference_digest: self.secret_reference.digest(),
            request_digest: String::new(),
        };
        request.request_digest = request.digest();
        request
    }
}

// Keep the public name discoverable for callers that used the provider
// provenance name from an earlier Layer-1 connector.
pub type AlgoliaSearchQualityProvider<T> = AlgoliaAnalyticsProvider<T>;
