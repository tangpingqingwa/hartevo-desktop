//! GET-only Android Publisher transport seams and redacted receipts.
//!
//! The only official endpoint represented here is the Android Publisher
//! track-release list.  There is no edit, upload, mutation, or raw-payload
//! transport method.  Official response bytes are parsed and dropped before
//! the provider receives the typed allowlist projection.

use std::{collections::BTreeMap, fmt, time::Duration as StdDuration};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use url::Url;

use crate::model::{
    AccessTokenLease, Digest, GooglePlayReleasePayload, GooglePlayTrackPayload, PackageName,
    ReleaseId, ReleaseLifecycleState, TrackName,
};
use crate::{
    GOOGLE_PLAY_API_ORIGIN, MAX_RELEASES, MAX_RESPONSE_BYTES, MAX_VERSION_CODES_PER_RELEASE,
    digest_serialized_with_domain, validate_identifier, validate_text,
};

type TransportResult<T> = std::result::Result<T, GooglePlayTransportError>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    OfficialHttpsRead,
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OfficialHttpsRead => "official_https_read",
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }

    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum GooglePlayHttpMethod {
    Get,
}

impl GooglePlayHttpMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
        }
    }
}

/// The sole allowlisted Android Publisher resource path in Layer 1.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum GooglePlayEndpoint {
    TrackReleases {
        package_name: PackageName,
        track: TrackName,
    },
}

impl GooglePlayEndpoint {
    pub fn path_and_query(&self) -> TransportResult<String> {
        let mut url = Url::parse(GOOGLE_PLAY_API_ORIGIN)
            .map_err(|error| GooglePlayTransportError::InvalidEndpoint(error.to_string()))?;
        match self {
            Self::TrackReleases {
                package_name,
                track,
            } => {
                let mut segments = url.path_segments_mut().map_err(|()| {
                    GooglePlayTransportError::InvalidEndpoint(
                        "Android Publisher origin cannot accept path segments".to_owned(),
                    )
                })?;
                segments
                    .push("androidpublisher")
                    .push("v3")
                    .push("applications")
                    .push(package_name.as_str())
                    .push("tracks")
                    .push(track.as_str())
                    .push("releases");
            }
        }
        Ok(url.to_string())
    }

    pub const fn operation_name(&self) -> &'static str {
        match self {
            Self::TrackReleases { .. } => "read_track_release_summaries",
        }
    }

    pub fn package_and_track(&self) -> (&PackageName, &TrackName) {
        match self {
            Self::TrackReleases {
                package_name,
                track,
            } => (package_name, track),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GooglePlayHttpRequest {
    pub method: GooglePlayHttpMethod,
    pub endpoint: GooglePlayEndpoint,
    pub max_response_bytes: usize,
    pub observed_at_epoch_seconds: u64,
    pub request_digest: Digest,
}

impl GooglePlayHttpRequest {
    pub fn new(
        endpoint: GooglePlayEndpoint,
        max_response_bytes: usize,
        observed_at_epoch_seconds: u64,
    ) -> TransportResult<Self> {
        if max_response_bytes == 0 || max_response_bytes > MAX_RESPONSE_BYTES {
            return Err(GooglePlayTransportError::InvalidRequest(
                "response bound is outside the Layer-1 maximum".to_owned(),
            ));
        }
        let path = endpoint.path_and_query()?;
        let request_digest = digest_serialized_with_domain(
            "googleplay-release-result/request/v1",
            &(GooglePlayHttpMethod::Get, &path, max_response_bytes),
        );
        Ok(Self {
            method: GooglePlayHttpMethod::Get,
            endpoint,
            max_response_bytes,
            observed_at_epoch_seconds,
            request_digest,
        })
    }

    pub fn path_and_query(&self) -> TransportResult<String> {
        self.endpoint.path_and_query()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GooglePlayResponseReceipt {
    pub method: String,
    pub request_path_and_query: String,
    pub request_digest: Digest,
    pub status: u16,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub provider_revision: String,
    pub provenance: TransportProvenance,
    pub raw_provider_payload: bool,
    pub credential_material: bool,
    pub provider_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub redaction_digest: Digest,
}

impl GooglePlayResponseReceipt {
    fn new(
        request: &GooglePlayHttpRequest,
        status: u16,
        response_bytes: usize,
        response_digest: Digest,
        provenance: TransportProvenance,
    ) -> TransportResult<Self> {
        if response_bytes > request.max_response_bytes {
            return Err(GooglePlayTransportError::ResponseTooLarge);
        }
        let path = request.path_and_query()?;
        let redaction_digest = digest_serialized_with_domain(
            "googleplay-release-result/receipt-redaction/v1",
            &(
                path.clone(),
                status,
                response_bytes,
                &response_digest,
                provenance,
            ),
        );
        Ok(Self {
            method: GooglePlayHttpMethod::Get.as_str().to_owned(),
            request_path_and_query: path,
            request_digest: request.request_digest.clone(),
            status,
            response_bytes,
            response_digest,
            provider_revision: crate::PROVIDER_REVISION.to_owned(),
            provenance,
            raw_provider_payload: false,
            credential_material: false,
            provider_receipt: false,
            connected: false,
            native: false,
            redaction_digest,
        })
    }

    pub fn validate(&self) -> crate::Result<()> {
        if self.method != "GET"
            || self.provider_revision != crate::PROVIDER_REVISION
            || self.raw_provider_payload
            || self.credential_material
            || self.provider_receipt
            || self.connected
            || self.native
            || self.response_bytes > MAX_RESPONSE_BYTES
            || !self.request_digest.is_sha256()
            || !self.response_digest.is_sha256()
            || !self.redaction_digest.is_sha256()
        {
            return Err(crate::GooglePlayReleaseResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum GooglePlayResponseBody {
    TrackReleases(GooglePlayTrackPayload),
}

impl GooglePlayResponseBody {
    pub fn digest(&self) -> Digest {
        digest_serialized_with_domain("googleplay-release-result/response-body/v1", self)
    }

    pub const fn kind(&self) -> &'static str {
        match self {
            Self::TrackReleases(_) => "track_releases",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GooglePlayHttpResponse {
    status: u16,
    body: Option<GooglePlayResponseBody>,
    receipt: GooglePlayResponseReceipt,
}

impl GooglePlayHttpResponse {
    pub fn from_body(
        request: &GooglePlayHttpRequest,
        body: GooglePlayResponseBody,
        provenance: TransportProvenance,
    ) -> TransportResult<Self> {
        let bytes = serde_json::to_vec(&body)
            .map_err(|error| GooglePlayTransportError::MalformedResponse(error.to_string()))?;
        if bytes.len() > request.max_response_bytes {
            return Err(GooglePlayTransportError::ResponseTooLarge);
        }
        let receipt =
            GooglePlayResponseReceipt::new(request, 200, bytes.len(), body.digest(), provenance)?;
        Ok(Self {
            status: 200,
            body: Some(body),
            receipt,
        })
    }

    pub fn from_json(
        request: &GooglePlayHttpRequest,
        status: u16,
        body: &str,
        provenance: TransportProvenance,
    ) -> TransportResult<Self> {
        if body.len() > request.max_response_bytes {
            return Err(GooglePlayTransportError::ResponseTooLarge);
        }
        let value = serde_json::from_str::<Value>(body)
            .map_err(|error| GooglePlayTransportError::MalformedResponse(error.to_string()))?;
        let normalized = decode_track_payload(request, &value)?;
        let response_body = GooglePlayResponseBody::TrackReleases(normalized);
        let receipt = GooglePlayResponseReceipt::new(
            request,
            status,
            body.len(),
            Digest::from_text(body),
            provenance,
        )?;
        Ok(Self {
            status,
            body: Some(response_body),
            receipt,
        })
    }

    fn status(
        request: &GooglePlayHttpRequest,
        status: u16,
        provenance: TransportProvenance,
    ) -> TransportResult<Self> {
        let receipt = GooglePlayResponseReceipt::new(
            request,
            status,
            0,
            Digest::from_text(&format!("googleplay-http-status:{status}")),
            provenance,
        )?;
        Ok(Self {
            status,
            body: None,
            receipt,
        })
    }

    pub const fn status_code(&self) -> u16 {
        self.status
    }

    pub fn body(&self) -> Option<&GooglePlayResponseBody> {
        self.body.as_ref()
    }

    pub fn receipt(&self) -> &GooglePlayResponseReceipt {
        &self.receipt
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GooglePlayTransportError {
    #[error("invalid allowlisted endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("invalid GET request: {0}")]
    InvalidRequest(String),
    #[error("fixture has no response for the allowlisted endpoint")]
    FixtureMissing,
    #[error("fixture response is malformed: {0}")]
    MalformedResponse(String),
    #[error("response exceeded the Layer-1 byte bound")]
    ResponseTooLarge,
    #[error("credential is unavailable for the official HTTPS read")]
    CredentialUnavailable,
    #[error("BLOCKED_ENV")]
    BlockedEnv,
    #[error("transport timeout")]
    Timeout,
    #[error("transport failed: {0}")]
    Transport(String),
}

pub trait GooglePlayTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn get(
        &mut self,
        request: &GooglePlayHttpRequest,
        token: Option<&AccessTokenLease>,
    ) -> std::result::Result<GooglePlayHttpResponse, GooglePlayTransportError>;
}

#[derive(Clone, Debug)]
struct FixtureReply {
    status: Option<u16>,
    body: Option<GooglePlayResponseBody>,
    error: Option<GooglePlayTransportError>,
}

#[derive(Clone, Debug, Default)]
pub struct FixtureGooglePlayTransport {
    replies: BTreeMap<String, FixtureReply>,
}

impl FixtureGooglePlayTransport {
    pub fn new(
        entries: impl IntoIterator<Item = (GooglePlayEndpoint, GooglePlayResponseBody)>,
    ) -> TransportResult<Self> {
        let mut fixture = Self::default();
        for (endpoint, body) in entries {
            fixture.insert(endpoint, body)?;
        }
        Ok(fixture)
    }

    pub fn empty() -> Self {
        Self::default()
    }

    pub fn insert(
        &mut self,
        endpoint: GooglePlayEndpoint,
        body: GooglePlayResponseBody,
    ) -> TransportResult<()> {
        let path = endpoint.path_and_query()?;
        self.replies.insert(
            path,
            FixtureReply {
                status: Some(200),
                body: Some(body),
                error: None,
            },
        );
        Ok(())
    }

    pub fn insert_status(
        &mut self,
        endpoint: GooglePlayEndpoint,
        status: u16,
    ) -> TransportResult<()> {
        let path = endpoint.path_and_query()?;
        self.replies.insert(
            path,
            FixtureReply {
                status: Some(status),
                body: None,
                error: None,
            },
        );
        Ok(())
    }

    pub fn insert_timeout(&mut self, endpoint: GooglePlayEndpoint) -> TransportResult<()> {
        let path = endpoint.path_and_query()?;
        self.replies.insert(
            path,
            FixtureReply {
                status: None,
                body: None,
                error: Some(GooglePlayTransportError::Timeout),
            },
        );
        Ok(())
    }

    fn response(
        &self,
        request: &GooglePlayHttpRequest,
        provenance: TransportProvenance,
    ) -> TransportResult<GooglePlayHttpResponse> {
        let path = request.path_and_query()?;
        let reply = self
            .replies
            .get(&path)
            .ok_or(GooglePlayTransportError::FixtureMissing)?;
        if let Some(error) = &reply.error {
            return Err(error.clone());
        }
        if let Some(status) = reply.status
            && status != 200
        {
            return GooglePlayHttpResponse::status(request, status, provenance);
        }
        let body = reply.body.clone().ok_or_else(|| {
            GooglePlayTransportError::MalformedResponse("missing body".to_owned())
        })?;
        GooglePlayHttpResponse::from_body(request, body, provenance)
    }
}

impl GooglePlayTransport for FixtureGooglePlayTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn get(
        &mut self,
        request: &GooglePlayHttpRequest,
        _token: Option<&AccessTokenLease>,
    ) -> std::result::Result<GooglePlayHttpResponse, GooglePlayTransportError> {
        self.response(request, self.provenance())
    }
}

#[derive(Clone, Debug)]
pub struct RecordingGooglePlayTransport {
    fixture: FixtureGooglePlayTransport,
    requests: Vec<GooglePlayHttpRequest>,
}

impl RecordingGooglePlayTransport {
    pub fn new(
        entries: impl IntoIterator<Item = (GooglePlayEndpoint, GooglePlayResponseBody)>,
    ) -> TransportResult<Self> {
        Ok(Self {
            fixture: FixtureGooglePlayTransport::new(entries)?,
            requests: Vec::new(),
        })
    }

    pub fn with_fixture(fixture: FixtureGooglePlayTransport) -> Self {
        Self {
            fixture,
            requests: Vec::new(),
        }
    }

    pub fn requests(&self) -> &[GooglePlayHttpRequest] {
        &self.requests
    }

    pub fn insert_status(
        &mut self,
        endpoint: GooglePlayEndpoint,
        status: u16,
    ) -> TransportResult<()> {
        self.fixture.insert_status(endpoint, status)
    }
}

impl GooglePlayTransport for RecordingGooglePlayTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn get(
        &mut self,
        request: &GooglePlayHttpRequest,
        _token: Option<&AccessTokenLease>,
    ) -> std::result::Result<GooglePlayHttpResponse, GooglePlayTransportError> {
        self.requests.push(request.clone());
        self.fixture.response(request, self.provenance())
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackGooglePlayTransport {
    fixture: FixtureGooglePlayTransport,
    requests: Vec<GooglePlayHttpRequest>,
}

impl LoopbackGooglePlayTransport {
    pub fn new(
        entries: impl IntoIterator<Item = (GooglePlayEndpoint, GooglePlayResponseBody)>,
    ) -> TransportResult<Self> {
        Ok(Self {
            fixture: FixtureGooglePlayTransport::new(entries)?,
            requests: Vec::new(),
        })
    }

    pub fn requests(&self) -> &[GooglePlayHttpRequest] {
        &self.requests
    }
}

impl GooglePlayTransport for LoopbackGooglePlayTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn get(
        &mut self,
        request: &GooglePlayHttpRequest,
        _token: Option<&AccessTokenLease>,
    ) -> std::result::Result<GooglePlayHttpResponse, GooglePlayTransportError> {
        self.requests.push(request.clone());
        self.fixture.response(request, self.provenance())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvGooglePlayTransport;

impl GooglePlayTransport for BlockedEnvGooglePlayTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn get(
        &mut self,
        _request: &GooglePlayHttpRequest,
        _token: Option<&AccessTokenLease>,
    ) -> std::result::Result<GooglePlayHttpResponse, GooglePlayTransportError> {
        Err(GooglePlayTransportError::BlockedEnv)
    }
}

pub type FakeGooglePlayTransport = FixtureGooglePlayTransport;

/// Official Android Publisher HTTPS read transport.  It is intentionally
/// inert until a host supplies a short-lived token lease; the crate itself
/// does not resolve native service-account or OAuth material.
pub struct UreqGooglePlayTransport {
    origin: String,
    agent: ureq::Agent,
}

impl fmt::Debug for UreqGooglePlayTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UreqGooglePlayTransport")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl UreqGooglePlayTransport {
    pub fn new(origin: impl Into<String>) -> TransportResult<Self> {
        let origin = origin.into().trim_end_matches('/').to_owned();
        let parsed = Url::parse(&origin)
            .map_err(|error| GooglePlayTransportError::InvalidEndpoint(error.to_string()))?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || (parsed.path() != "" && parsed.path() != "/")
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(GooglePlayTransportError::InvalidEndpoint(
                "Android Publisher origin must be HTTPS without credentials, path, or query"
                    .to_owned(),
            ));
        }
        let agent = ureq::Agent::config_builder()
            .user_agent("hartevo-googleplay-release-result/1")
            .timeout_global(Some(StdDuration::from_secs(30)))
            .build()
            .into();
        Ok(Self { origin, agent })
    }

    pub fn android_publisher() -> TransportResult<Self> {
        Self::new(GOOGLE_PLAY_API_ORIGIN)
    }

    fn endpoint_url(&self, endpoint: &GooglePlayEndpoint) -> TransportResult<String> {
        let relative = Url::parse(&endpoint.path_and_query()?)
            .map_err(|error| GooglePlayTransportError::InvalidEndpoint(error.to_string()))?;
        let mut url = Url::parse(&self.origin)
            .map_err(|error| GooglePlayTransportError::InvalidEndpoint(error.to_string()))?;
        url.set_path(relative.path());
        url.set_query(relative.query());
        Ok(url.to_string())
    }
}

impl GooglePlayTransport for UreqGooglePlayTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::OfficialHttpsRead
    }

    fn get(
        &mut self,
        request: &GooglePlayHttpRequest,
        token: Option<&AccessTokenLease>,
    ) -> std::result::Result<GooglePlayHttpResponse, GooglePlayTransportError> {
        let token = token.ok_or(GooglePlayTransportError::CredentialUnavailable)?;
        token
            .validate_at(request.observed_at_epoch_seconds)
            .map_err(|_| GooglePlayTransportError::CredentialUnavailable)?;
        let url = self.endpoint_url(&request.endpoint)?;
        let response = self
            .agent
            .get(&url)
            .header("Authorization", format!("Bearer {}", token.as_str()))
            .header("Accept", "application/json")
            .call();
        let mut response = match response {
            Ok(response) => response,
            Err(ureq::Error::StatusCode(status)) => {
                return GooglePlayHttpResponse::status(request, status, self.provenance());
            }
            Err(error) => return Err(classify_ureq_error(error)),
        };
        let status = response.status().as_u16();
        let response_limit = u64::try_from(request.max_response_bytes)
            .map_err(|error| GooglePlayTransportError::Transport(error.to_string()))?
            .saturating_add(1);
        let body = response
            .body_mut()
            .with_config()
            .limit(response_limit)
            .read_to_string()
            .map_err(classify_ureq_error)?;
        if body.len() > request.max_response_bytes {
            return Err(GooglePlayTransportError::ResponseTooLarge);
        }
        GooglePlayHttpResponse::from_json(request, status, &body, self.provenance())
    }
}

fn classify_ureq_error(error: ureq::Error) -> GooglePlayTransportError {
    let message = error.to_string();
    if message.to_ascii_lowercase().contains("timeout")
        || message.to_ascii_lowercase().contains("timed out")
    {
        GooglePlayTransportError::Timeout
    } else {
        GooglePlayTransportError::Transport(message)
    }
}

fn decode_track_payload(
    request: &GooglePlayHttpRequest,
    value: &Value,
) -> TransportResult<GooglePlayTrackPayload> {
    let (request_package, request_track) = request.endpoint.package_and_track();
    let package_name = value
        .get("packageName")
        .and_then(Value::as_str)
        .map(PackageName::parse)
        .transpose()
        .map_err(|error| GooglePlayTransportError::MalformedResponse(error.to_string()))?;
    let track = value
        .get("track")
        .and_then(Value::as_str)
        .map(TrackName::parse)
        .transpose()
        .map_err(|error| GooglePlayTransportError::MalformedResponse(error.to_string()))?
        .unwrap_or_else(|| request_track.clone());
    let releases = value
        .get("releases")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            GooglePlayTransportError::MalformedResponse("releases is not an array".to_owned())
        })?;
    if releases.len() > MAX_RELEASES {
        return Err(GooglePlayTransportError::ResponseTooLarge);
    }
    let mut normalized = Vec::with_capacity(releases.len());
    for release in releases {
        normalized.push(decode_release_payload(release)?);
    }
    let payload = GooglePlayTrackPayload {
        package_name,
        track,
        releases: normalized,
        partial: value
            .get("partial")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    };
    if payload
        .package_name
        .as_ref()
        .is_some_and(|package| package != request_package)
        || payload.track != *request_track
    {
        return Err(GooglePlayTransportError::MalformedResponse(
            "response package or track is outside the request scope".to_owned(),
        ));
    }
    Ok(payload)
}

fn decode_release_payload(value: &Value) -> TransportResult<GooglePlayReleasePayload> {
    let release_id = value
        .get("name")
        .or_else(|| value.get("releaseName"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            GooglePlayTransportError::MalformedResponse("release name is missing".to_owned())
        })
        .and_then(|name| {
            ReleaseId::parse(name)
                .map_err(|error| GooglePlayTransportError::MalformedResponse(error.to_string()))
        })?;
    let lifecycle_state = value
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            GooglePlayTransportError::MalformedResponse("release status is missing".to_owned())
        })
        .and_then(|status| {
            ReleaseLifecycleState::parse(status)
                .map_err(|error| GooglePlayTransportError::MalformedResponse(error.to_string()))
        })?;
    let version_codes = value
        .get("versionCodes")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            GooglePlayTransportError::MalformedResponse("versionCodes is not an array".to_owned())
        })?
        .iter()
        .map(parse_version_code)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if version_codes.is_empty()
        || version_codes.len() > MAX_VERSION_CODES_PER_RELEASE
        || version_codes.contains(&0)
    {
        return Err(GooglePlayTransportError::MalformedResponse(
            "versionCodes is outside the Layer-1 bound".to_owned(),
        ));
    }
    let user_fraction_millionths = value
        .get("userFraction")
        .and_then(Value::as_f64)
        .map(|fraction| {
            if !fraction.is_finite() || !(0.0..=1.0).contains(&fraction) || fraction == 0.0 {
                return Err(GooglePlayTransportError::MalformedResponse(
                    "userFraction is invalid".to_owned(),
                ));
            }
            let millionths = (fraction * 1_000_000.0).round() as u32;
            if millionths == 0 || millionths > 1_000_000 {
                Err(GooglePlayTransportError::MalformedResponse(
                    "userFraction is outside the Layer-1 bound".to_owned(),
                ))
            } else {
                Ok(millionths)
            }
        })
        .transpose()?;
    let country_targeting_digest = value
        .get("countryTargeting")
        .map(|targeting| {
            serde_json::to_string(targeting)
                .map(|serialized| Digest::from_text(&serialized))
                .map_err(|error| GooglePlayTransportError::MalformedResponse(error.to_string()))
        })
        .transpose()?;
    let mut artifact_digests = BTreeMap::new();
    if let Some(object) = value.get("artifactDigests").and_then(Value::as_object) {
        for (version_code, digest) in object {
            let version_code = version_code.parse::<u64>().map_err(|_| {
                GooglePlayTransportError::MalformedResponse(
                    "artifact digest version code is invalid".to_owned(),
                )
            })?;
            let digest = digest.as_str().ok_or_else(|| {
                GooglePlayTransportError::MalformedResponse(
                    "artifact digest is not a string".to_owned(),
                )
            })?;
            let digest = Digest::parse(digest)
                .map_err(|error| GooglePlayTransportError::MalformedResponse(error.to_string()))?;
            artifact_digests.insert(version_code, digest);
        }
    }
    Ok(GooglePlayReleasePayload {
        release_name: value
            .get("releaseName")
            .and_then(Value::as_str)
            .map(str::to_owned),
        release_id,
        lifecycle_state,
        version_codes,
        user_fraction_millionths,
        country_targeting_digest,
        artifact_digests,
        halted: value
            .get("halted")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

fn parse_version_code(value: &Value) -> std::result::Result<u64, GooglePlayTransportError> {
    if let Some(number) = value.as_u64() {
        return Ok(number);
    }
    value
        .as_str()
        .ok_or_else(|| {
            GooglePlayTransportError::MalformedResponse("version code is not numeric".to_owned())
        })?
        .parse::<u64>()
        .map_err(|_| {
            GooglePlayTransportError::MalformedResponse("version code is invalid".to_owned())
        })
}

#[allow(dead_code)]
fn _endpoint_validation_helpers(value: &str) -> crate::Result<()> {
    validate_text(value, "endpoint", MAX_RESPONSE_BYTES, true)?;
    validate_identifier(value, "endpoint")
}
