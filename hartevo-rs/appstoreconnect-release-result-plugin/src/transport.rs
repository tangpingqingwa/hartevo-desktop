//! GET-only App Store Connect resource/relationship transport seams.
//!
//! The fixture, recording, loopback, and blocked-environment transports are
//! intentionally the only implementations in this root.  A receipt carries
//! status/size/digests and redacted ES256 metadata, never a JWT, private key,
//! raw response, or provider-native receipt.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{AppStoreConnectResponseBody, Digest, PageToken, SecretReference};
use crate::{
    AppStoreConnectReleaseResultError, MAX_IDENTIFIER_BYTES, MAX_RECEIPTS, MAX_RESPONSE_BYTES,
    Result, digest_serialized, validate_identifier, validate_text,
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AppStoreConnectHttpMethod {
    Get,
}

impl AppStoreConnectHttpMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
        }
    }
}

/// Only documented App Store Connect REST GET paths are representable here.
/// There is no POST/PATCH/PUT/DELETE endpoint variant.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", tag = "endpoint", content = "value")]
pub enum AppStoreConnectEndpoint {
    Apps {
        origin: String,
        bundle_id: String,
    },
    App {
        origin: String,
        app_id: String,
    },
    PreReleaseVersions {
        origin: String,
        app_id: String,
    },
    PreReleaseVersion {
        origin: String,
        pre_release_version_id: String,
    },
    PreReleaseVersionBuilds {
        origin: String,
        pre_release_version_id: String,
    },
    Build {
        origin: String,
        build_id: String,
    },
    BuildPreReleaseVersion {
        origin: String,
        build_id: String,
    },
    BuildAppStoreVersion {
        origin: String,
        build_id: String,
    },
    AppStoreVersions {
        origin: String,
        app_id: String,
    },
    AppStoreVersion {
        origin: String,
        app_store_version_id: String,
    },
    AppStoreVersionBuild {
        origin: String,
        app_store_version_id: String,
    },
    AppStoreVersionBuildRelationship {
        origin: String,
        app_store_version_id: String,
    },
    BetaGroups {
        origin: String,
        app_id: String,
    },
    BetaGroup {
        origin: String,
        beta_group_id: String,
    },
    BetaGroupBuilds {
        origin: String,
        beta_group_id: String,
    },
    BuildBetaAppReviewSubmission {
        origin: String,
        build_id: String,
    },
    BetaAppReviewSubmission {
        origin: String,
        beta_app_review_submission_id: String,
    },
    ReviewSubmissions {
        origin: String,
        app_id: String,
    },
    ReviewSubmission {
        origin: String,
        review_submission_id: String,
    },
    AppStoreVersionSubmission {
        origin: String,
        app_store_version_id: String,
    },
}

impl AppStoreConnectEndpoint {
    pub fn path_and_query(&self) -> std::result::Result<String, AppStoreConnectTransportError> {
        let (origin, path) = match self {
            Self::Apps { origin, bundle_id } => (
                origin,
                format!("/v1/apps?filter[bundleId]={}", segment(bundle_id)?),
            ),
            Self::App { origin, app_id } => (origin, format!("/v1/apps/{}", segment(app_id)?)),
            Self::PreReleaseVersions { origin, app_id } => (
                origin,
                format!("/v1/apps/{}/preReleaseVersions", segment(app_id)?),
            ),
            Self::PreReleaseVersion {
                origin,
                pre_release_version_id,
            } => (
                origin,
                format!(
                    "/v1/preReleaseVersions/{}",
                    segment(pre_release_version_id)?
                ),
            ),
            Self::PreReleaseVersionBuilds {
                origin,
                pre_release_version_id,
            } => (
                origin,
                format!(
                    "/v1/preReleaseVersions/{}/builds",
                    segment(pre_release_version_id)?
                ),
            ),
            Self::Build { origin, build_id } => {
                (origin, format!("/v1/builds/{}", segment(build_id)?))
            }
            Self::BuildPreReleaseVersion { origin, build_id } => (
                origin,
                format!("/v1/builds/{}/preReleaseVersion", segment(build_id)?),
            ),
            Self::BuildAppStoreVersion { origin, build_id } => (
                origin,
                format!("/v1/builds/{}/appStoreVersion", segment(build_id)?),
            ),
            Self::AppStoreVersions { origin, app_id } => (
                origin,
                format!("/v1/apps/{}/appStoreVersions", segment(app_id)?),
            ),
            Self::AppStoreVersion {
                origin,
                app_store_version_id,
            } => (
                origin,
                format!("/v1/appStoreVersions/{}", segment(app_store_version_id)?),
            ),
            Self::AppStoreVersionBuild {
                origin,
                app_store_version_id,
            } => (
                origin,
                format!(
                    "/v1/appStoreVersions/{}/build",
                    segment(app_store_version_id)?
                ),
            ),
            Self::AppStoreVersionBuildRelationship {
                origin,
                app_store_version_id,
            } => (
                origin,
                format!(
                    "/v1/appStoreVersions/{}/relationships/build",
                    segment(app_store_version_id)?
                ),
            ),
            Self::BetaGroups { origin, app_id } => {
                (origin, format!("/v1/apps/{}/betaGroups", segment(app_id)?))
            }
            Self::BetaGroup {
                origin,
                beta_group_id,
            } => (
                origin,
                format!("/v1/betaGroups/{}", segment(beta_group_id)?),
            ),
            Self::BetaGroupBuilds {
                origin,
                beta_group_id,
            } => (
                origin,
                format!("/v1/betaGroups/{}/builds", segment(beta_group_id)?),
            ),
            Self::BuildBetaAppReviewSubmission { origin, build_id } => (
                origin,
                format!("/v1/builds/{}/betaAppReviewSubmission", segment(build_id)?),
            ),
            Self::BetaAppReviewSubmission {
                origin,
                beta_app_review_submission_id,
            } => (
                origin,
                format!(
                    "/v1/betaAppReviewSubmissions/{}",
                    segment(beta_app_review_submission_id)?
                ),
            ),
            Self::ReviewSubmissions { origin, app_id } => (
                origin,
                format!("/v1/apps/{}/reviewSubmissions", segment(app_id)?),
            ),
            Self::ReviewSubmission {
                origin,
                review_submission_id,
            } => (
                origin,
                format!("/v1/reviewSubmissions/{}", segment(review_submission_id)?),
            ),
            Self::AppStoreVersionSubmission {
                origin,
                app_store_version_id,
            } => (
                origin,
                format!(
                    "/v1/appStoreVersions/{}/appStoreVersionSubmission",
                    segment(app_store_version_id)?
                ),
            ),
        };
        validate_origin(origin)?;
        Ok(format!("{}{path}", origin.trim_end_matches('/')))
    }

    pub const fn operation_name(&self) -> &'static str {
        match self {
            Self::Apps { .. } | Self::App { .. } => "read_app",
            Self::PreReleaseVersions { .. } | Self::PreReleaseVersion { .. } => {
                "read_pre_release_version"
            }
            Self::Build { .. }
            | Self::BuildPreReleaseVersion { .. }
            | Self::PreReleaseVersionBuilds { .. } => "read_build_processing",
            Self::BuildAppStoreVersion { .. }
            | Self::AppStoreVersions { .. }
            | Self::AppStoreVersion { .. }
            | Self::AppStoreVersionBuild { .. }
            | Self::AppStoreVersionBuildRelationship { .. } => "read_app_store_version",
            Self::BetaGroups { .. } | Self::BetaGroup { .. } | Self::BetaGroupBuilds { .. } => {
                "read_beta_group"
            }
            Self::BuildBetaAppReviewSubmission { .. } | Self::BetaAppReviewSubmission { .. } => {
                "read_beta_review"
            }
            Self::ReviewSubmissions { .. }
            | Self::ReviewSubmission { .. }
            | Self::AppStoreVersionSubmission { .. } => "read_review_submission",
        }
    }
}

fn validate_origin(origin: &str) -> std::result::Result<(), AppStoreConnectTransportError> {
    validate_text(origin, "App Store Connect API origin", 256, false)
        .map_err(|_| AppStoreConnectTransportError::InvalidEndpoint)?;
    let Some(host) = origin.strip_prefix("https://") else {
        return Err(AppStoreConnectTransportError::InvalidEndpoint);
    };
    if host.is_empty() || host.contains('/') || host.contains('?') || host.contains('#') {
        return Err(AppStoreConnectTransportError::InvalidEndpoint);
    }
    Ok(())
}

fn segment(value: &str) -> std::result::Result<String, AppStoreConnectTransportError> {
    validate_identifier(value, "App Store Connect endpoint identifier")
        .map_err(|_| AppStoreConnectTransportError::InvalidEndpoint)?;
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum JwtAlgorithm {
    Es256,
}

impl JwtAlgorithm {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
        }
    }
}

/// Redacted JWT metadata.  It contains only digests and fixed false flags;
/// no constructor retains the supplied token or private-key bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JwtRedaction {
    pub algorithm: JwtAlgorithm,
    pub key_id_digest: Digest,
    pub issuer_id_digest: Digest,
    pub jwt_digest: Digest,
    pub private_key_digest: Digest,
    pub raw_jwt: bool,
    pub private_key_material: bool,
}

impl JwtRedaction {
    pub fn from_es256(team_key_id: &str, issuer_id: &str, jwt: &str) -> Result<Self> {
        Self::from_es256_material(team_key_id, issuer_id, jwt, b"redacted-private-key")
    }

    pub fn from_es256_material(
        team_key_id: &str,
        issuer_id: &str,
        jwt: &str,
        private_key_material: &[u8],
    ) -> Result<Self> {
        validate_identifier(team_key_id, "Apple team key ID")?;
        validate_identifier(issuer_id, "Apple issuer ID")?;
        validate_text(jwt, "JWT", MAX_IDENTIFIER_BYTES, false)?;
        if private_key_material.is_empty() {
            return Err(AppStoreConnectReleaseResultError::InvalidSecretReference);
        }
        Ok(Self {
            algorithm: JwtAlgorithm::Es256,
            key_id_digest: Digest::from_bytes(team_key_id.as_bytes())?,
            issuer_id_digest: Digest::from_bytes(issuer_id.as_bytes())?,
            jwt_digest: Digest::from_bytes(jwt.as_bytes())?,
            private_key_digest: Digest::from_bytes(private_key_material)?,
            raw_jwt: false,
            private_key_material: false,
        })
    }

    pub fn for_secret_reference(reference: &SecretReference) -> Self {
        let marker = Digest::from_text("unresolved-layer1-jwt").expect("digest");
        Self {
            algorithm: JwtAlgorithm::Es256,
            key_id_digest: reference.reference_digest.clone(),
            issuer_id_digest: reference.reference_digest.clone(),
            jwt_digest: marker.clone(),
            private_key_digest: reference.reference_digest.clone(),
            raw_jwt: false,
            private_key_material: false,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.algorithm != JwtAlgorithm::Es256 || self.raw_jwt || self.private_key_material {
            return Err(AppStoreConnectReleaseResultError::RedactionViolation);
        }
        self.key_id_digest.validate()?;
        self.issuer_id_digest.validate()?;
        self.jwt_digest.validate()?;
        self.private_key_digest.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppStoreConnectHttpRequest {
    pub method: AppStoreConnectHttpMethod,
    pub endpoint: AppStoreConnectEndpoint,
    pub page_index: usize,
    pub page_token: Option<PageToken>,
    pub max_response_bytes: usize,
    pub authorization: JwtRedaction,
    pub request_digest: Digest,
}

impl AppStoreConnectHttpRequest {
    pub fn new(
        endpoint: AppStoreConnectEndpoint,
        max_response_bytes: usize,
        authorization: JwtRedaction,
    ) -> std::result::Result<Self, AppStoreConnectTransportError> {
        if max_response_bytes == 0 || max_response_bytes > MAX_RESPONSE_BYTES {
            return Err(AppStoreConnectTransportError::ResponseTooLarge);
        }
        authorization
            .validate()
            .map_err(|_| AppStoreConnectTransportError::InvalidAuthorization)?;
        let path = endpoint.path_and_query()?;
        let request_digest = Digest::from_parts(
            "appstoreconnect-release-result/request/v1",
            [
                ("method".to_owned(), "GET".to_owned()),
                ("path".to_owned(), path),
                ("page".to_owned(), "0".to_owned()),
                (
                    "authorization".to_owned(),
                    digest_serialized(&authorization),
                ),
            ],
        );
        Ok(Self {
            method: AppStoreConnectHttpMethod::Get,
            endpoint,
            page_index: 0,
            page_token: None,
            max_response_bytes,
            authorization,
            request_digest,
        })
    }

    pub fn with_page(
        mut self,
        page_index: usize,
        page_token: Option<PageToken>,
    ) -> std::result::Result<Self, AppStoreConnectTransportError> {
        if page_index == 0 || page_index > crate::MAX_PAGES {
            return Err(AppStoreConnectTransportError::PaginationLimit);
        }
        let path = self.endpoint.path_and_query()?;
        self.page_index = page_index;
        self.page_token = page_token;
        self.request_digest = Digest::from_parts(
            "appstoreconnect-release-result/request/v1",
            [
                ("method".to_owned(), "GET".to_owned()),
                ("path".to_owned(), path),
                ("page".to_owned(), page_index.to_string()),
                (
                    "page_token".to_owned(),
                    self.page_token
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().to_string()),
                ),
                (
                    "authorization".to_owned(),
                    digest_serialized(&self.authorization),
                ),
            ],
        );
        Ok(self)
    }

    pub fn path_and_query(&self) -> std::result::Result<String, AppStoreConnectTransportError> {
        self.endpoint.path_and_query()
    }
}

/// Redacted provider response receipt.  Raw App Store Connect JSON is never a
/// field here, and credential material is represented only by false flags.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppStoreConnectReceipt {
    pub method: String,
    pub request_path_and_query: String,
    pub request_digest: Digest,
    pub status: u16,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub provenance: TransportProvenance,
    pub authorization: JwtRedaction,
    pub raw_provider_payload: bool,
    pub credential_material: bool,
    pub provider_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub redaction_digest: Digest,
}

impl AppStoreConnectReceipt {
    fn new(
        request: &AppStoreConnectHttpRequest,
        status: u16,
        response_bytes: usize,
        response_digest: Digest,
        provenance: TransportProvenance,
    ) -> std::result::Result<Self, AppStoreConnectTransportError> {
        let path = request.path_and_query()?;
        let redaction_digest = Digest::from_parts(
            "appstoreconnect-release-result/receipt-redaction/v1",
            [
                ("path".to_owned(), path.clone()),
                ("status".to_owned(), status.to_string()),
                ("response".to_owned(), response_digest.as_str().to_owned()),
                ("provenance".to_owned(), provenance.as_str().to_owned()),
                (
                    "authorization".to_owned(),
                    digest_serialized(&request.authorization),
                ),
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
            authorization: request.authorization.clone(),
            raw_provider_payload: false,
            credential_material: false,
            provider_receipt: false,
            connected: false,
            native: false,
            redaction_digest,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.request_digest.validate()?;
        self.response_digest.validate()?;
        self.authorization.validate()?;
        self.redaction_digest.validate()?;
        if self.method != "GET"
            || self.raw_provider_payload
            || self.credential_material
            || self.provider_receipt
            || self.connected
            || self.native
            || self.response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(AppStoreConnectReleaseResultError::RedactionViolation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AppStoreConnectHttpResponse {
    pub status: u16,
    pub body: Option<AppStoreConnectResponseBody>,
    pub receipt: AppStoreConnectReceipt,
}

impl AppStoreConnectHttpResponse {
    pub fn from_body(
        request: &AppStoreConnectHttpRequest,
        body: AppStoreConnectResponseBody,
        provenance: TransportProvenance,
    ) -> std::result::Result<Self, AppStoreConnectTransportError> {
        let response_bytes = serde_json::to_vec(&body)
            .map_err(|_| AppStoreConnectTransportError::MalformedResponse)?
            .len();
        if response_bytes > request.max_response_bytes {
            return Err(AppStoreConnectTransportError::ResponseTooLarge);
        }
        let response_digest = body.digest();
        Ok(Self {
            status: 200,
            body: Some(body),
            receipt: AppStoreConnectReceipt::new(
                request,
                200,
                response_bytes,
                response_digest,
                provenance,
            )?,
        })
    }

    fn status(
        request: &AppStoreConnectHttpRequest,
        status: u16,
        provenance: TransportProvenance,
    ) -> std::result::Result<Self, AppStoreConnectTransportError> {
        let response_digest = Digest::from_text(&format!("appstoreconnect-http-status:{status}"))
            .map_err(|_| AppStoreConnectTransportError::MalformedResponse)?;
        Ok(Self {
            status,
            body: None,
            receipt: AppStoreConnectReceipt::new(request, status, 0, response_digest, provenance)?,
        })
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AppStoreConnectTransportError {
    #[error("invalid allowlisted endpoint")]
    InvalidEndpoint,
    #[error("fixture has no response for the allowlisted endpoint")]
    FixtureMissing,
    #[error("fixture response is malformed")]
    MalformedResponse,
    #[error("response exceeded the Layer-1 byte bound")]
    ResponseTooLarge,
    #[error("pagination exceeded the Layer-1 bound")]
    PaginationLimit,
    #[error("invalid redacted authorization metadata")]
    InvalidAuthorization,
    #[error("BLOCKED_ENV")]
    BlockedEnv,
    #[error("transport timeout")]
    Timeout,
    #[error("transport access lost")]
    AccessLost,
    #[error("transport returned server status {status}")]
    ServerStatus { status: u16 },
}

pub trait AppStoreConnectTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn get(
        &mut self,
        request: &AppStoreConnectHttpRequest,
    ) -> std::result::Result<AppStoreConnectHttpResponse, AppStoreConnectTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum FixtureReply {
    Body(AppStoreConnectResponseBody),
    Status(u16),
    Error(AppStoreConnectTransportError),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FixtureKey {
    endpoint: AppStoreConnectEndpoint,
    page_index: usize,
    page_token: Option<PageToken>,
}

#[derive(Clone, Debug)]
pub struct FixtureAppStoreConnectTransport {
    replies: BTreeMap<FixtureKey, FixtureReply>,
}

impl FixtureAppStoreConnectTransport {
    pub fn new(
        entries: Vec<(AppStoreConnectEndpoint, AppStoreConnectResponseBody)>,
    ) -> std::result::Result<Self, AppStoreConnectTransportError> {
        let mut transport = Self::empty();
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
        endpoint: AppStoreConnectEndpoint,
        body: AppStoreConnectResponseBody,
    ) -> std::result::Result<(), AppStoreConnectTransportError> {
        self.insert_page(endpoint, 0, None, body)
    }

    pub fn insert_page(
        &mut self,
        endpoint: AppStoreConnectEndpoint,
        page_index: usize,
        page_token: Option<PageToken>,
        body: AppStoreConnectResponseBody,
    ) -> std::result::Result<(), AppStoreConnectTransportError> {
        if page_index >= crate::MAX_PAGES {
            return Err(AppStoreConnectTransportError::PaginationLimit);
        }
        endpoint
            .path_and_query()
            .map_err(|_| AppStoreConnectTransportError::InvalidEndpoint)?;
        self.replies.insert(
            FixtureKey {
                endpoint,
                page_index,
                page_token,
            },
            FixtureReply::Body(body),
        );
        Ok(())
    }

    pub fn insert_status(
        &mut self,
        endpoint: AppStoreConnectEndpoint,
        status: u16,
    ) -> std::result::Result<(), AppStoreConnectTransportError> {
        self.insert_status_page(endpoint, 0, None, status)
    }

    pub fn insert_status_page(
        &mut self,
        endpoint: AppStoreConnectEndpoint,
        page_index: usize,
        page_token: Option<PageToken>,
        status: u16,
    ) -> std::result::Result<(), AppStoreConnectTransportError> {
        endpoint
            .path_and_query()
            .map_err(|_| AppStoreConnectTransportError::InvalidEndpoint)?;
        self.replies.insert(
            FixtureKey {
                endpoint,
                page_index,
                page_token,
            },
            FixtureReply::Status(status),
        );
        Ok(())
    }

    pub fn insert_error(
        &mut self,
        endpoint: AppStoreConnectEndpoint,
        error: AppStoreConnectTransportError,
    ) -> std::result::Result<(), AppStoreConnectTransportError> {
        endpoint
            .path_and_query()
            .map_err(|_| AppStoreConnectTransportError::InvalidEndpoint)?;
        self.replies.insert(
            FixtureKey {
                endpoint,
                page_index: 0,
                page_token: None,
            },
            FixtureReply::Error(error),
        );
        Ok(())
    }

    fn response(
        &self,
        request: &AppStoreConnectHttpRequest,
        provenance: TransportProvenance,
    ) -> std::result::Result<AppStoreConnectHttpResponse, AppStoreConnectTransportError> {
        let key = FixtureKey {
            endpoint: request.endpoint.clone(),
            page_index: request.page_index,
            page_token: request.page_token.clone(),
        };
        let Some(reply) = self.replies.get(&key) else {
            return Err(AppStoreConnectTransportError::FixtureMissing);
        };
        match reply {
            FixtureReply::Body(body) => {
                AppStoreConnectHttpResponse::from_body(request, body.clone(), provenance)
            }
            FixtureReply::Status(status) => {
                AppStoreConnectHttpResponse::status(request, *status, provenance)
            }
            FixtureReply::Error(error) => Err(error.clone()),
        }
    }
}

impl AppStoreConnectTransport for FixtureAppStoreConnectTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn get(
        &mut self,
        request: &AppStoreConnectHttpRequest,
    ) -> std::result::Result<AppStoreConnectHttpResponse, AppStoreConnectTransportError> {
        self.response(request, self.provenance())
    }
}

#[derive(Clone, Debug)]
pub struct RecordingAppStoreConnectTransport {
    fixture: FixtureAppStoreConnectTransport,
    requests: Vec<AppStoreConnectHttpRequest>,
}

impl RecordingAppStoreConnectTransport {
    pub fn new(
        entries: Vec<(AppStoreConnectEndpoint, AppStoreConnectResponseBody)>,
    ) -> std::result::Result<Self, AppStoreConnectTransportError> {
        Ok(Self {
            fixture: FixtureAppStoreConnectTransport::new(entries)?,
            requests: Vec::new(),
        })
    }

    pub fn with_fixture(fixture: FixtureAppStoreConnectTransport) -> Self {
        Self {
            fixture,
            requests: Vec::new(),
        }
    }

    pub fn requests(&self) -> &[AppStoreConnectHttpRequest] {
        &self.requests
    }

    pub fn insert(
        &mut self,
        endpoint: AppStoreConnectEndpoint,
        body: AppStoreConnectResponseBody,
    ) -> std::result::Result<(), AppStoreConnectTransportError> {
        self.fixture.insert(endpoint, body)
    }

    pub fn insert_status(
        &mut self,
        endpoint: AppStoreConnectEndpoint,
        status: u16,
    ) -> std::result::Result<(), AppStoreConnectTransportError> {
        self.fixture.insert_status(endpoint, status)
    }

    pub fn insert_error(
        &mut self,
        endpoint: AppStoreConnectEndpoint,
        error: AppStoreConnectTransportError,
    ) -> std::result::Result<(), AppStoreConnectTransportError> {
        self.fixture.insert_error(endpoint, error)
    }
}

impl AppStoreConnectTransport for RecordingAppStoreConnectTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn get(
        &mut self,
        request: &AppStoreConnectHttpRequest,
    ) -> std::result::Result<AppStoreConnectHttpResponse, AppStoreConnectTransportError> {
        self.requests.push(request.clone());
        self.fixture.response(request, self.provenance())
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackAppStoreConnectTransport {
    fixture: FixtureAppStoreConnectTransport,
    requests: Vec<AppStoreConnectHttpRequest>,
}

impl LoopbackAppStoreConnectTransport {
    pub fn new(
        entries: Vec<(AppStoreConnectEndpoint, AppStoreConnectResponseBody)>,
    ) -> std::result::Result<Self, AppStoreConnectTransportError> {
        Ok(Self {
            fixture: FixtureAppStoreConnectTransport::new(entries)?,
            requests: Vec::new(),
        })
    }

    pub fn with_fixture(fixture: FixtureAppStoreConnectTransport) -> Self {
        Self {
            fixture,
            requests: Vec::new(),
        }
    }

    pub fn requests(&self) -> &[AppStoreConnectHttpRequest] {
        &self.requests
    }
}

impl AppStoreConnectTransport for LoopbackAppStoreConnectTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn get(
        &mut self,
        request: &AppStoreConnectHttpRequest,
    ) -> std::result::Result<AppStoreConnectHttpResponse, AppStoreConnectTransportError> {
        self.requests.push(request.clone());
        self.fixture.response(request, self.provenance())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvAppStoreConnectTransport;

impl AppStoreConnectTransport for BlockedEnvAppStoreConnectTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn get(
        &mut self,
        _request: &AppStoreConnectHttpRequest,
    ) -> std::result::Result<AppStoreConnectHttpResponse, AppStoreConnectTransportError> {
        Err(AppStoreConnectTransportError::BlockedEnv)
    }
}

pub type FakeAppStoreConnectTransport = FixtureAppStoreConnectTransport;

const _: () = {
    assert!(MAX_RECEIPTS >= 16);
};
