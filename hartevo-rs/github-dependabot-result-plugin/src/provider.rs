//! Read-only GitHub Dependabot provider seam.
//!
//! The provider accepts only typed bounded requests and returns typed pages.
//! It has no live HTTP implementation in Layer 1. Fixture, recording,
//! loopback, and BLOCKED_ENV transports make provenance explicit and all
//! report `connected == false`, `native == false`, and `first_party == false`.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};
use serde_json::Value;
use thiserror::Error;

use crate::{
    GITHUB_DEPENDABOT_API_REVISION, GITHUB_DEPENDABOT_PROVIDER_ID,
    model::{
        AdvisoryIdentifier, AlertNumber, AlertState, CommitSha, DependabotAlert, Digest,
        GithubDependabotReadPage, GithubDependabotReadRequest, ModelError, OpaqueCursor,
        PackageEcosystem, ProviderId, ProviderRevision, Severity, TransportError,
        TransportProvenance,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("GitHub Dependabot provider model error: {0}")]
    Model(#[from] ModelError),
    #[error("GitHub Dependabot provider version is empty")]
    EmptyVersion,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubDependabotProviderDefinition {
    pub id: &'static str,
    pub implementation: &'static str,
    pub version: &'static str,
    pub api_revision: &'static str,
    pub operations: [&'static str; 2],
    pub methods: [&'static str; 1],
    pub read_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub etag_304: bool,
}

impl GithubDependabotProviderDefinition {
    pub const fn layer_one() -> Self {
        Self {
            id: GITHUB_DEPENDABOT_PROVIDER_ID,
            implementation: "GithubDependabotProvider",
            version: "1.0.0",
            api_revision: GITHUB_DEPENDABOT_API_REVISION,
            operations: [
                "GET /repos/{owner}/{repo}/dependabot/alerts",
                "GET /repos/{owner}/{repo}/dependabot/alerts/{alert_number}",
            ],
            methods: ["GET"],
            read_only: true,
            native: false,
            connected: false,
            first_party: false,
            external_writes: false,
            etag_304: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubDependabotProviderIdentity {
    pub provider_id: ProviderId,
    pub version: String,
    pub api_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub provenance: TransportProvenance,
}

impl GithubDependabotProviderIdentity {
    pub fn new(
        version: impl Into<String>,
        api_revision: ProviderRevision,
        provenance: TransportProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let version = version.into();
        if version.is_empty() {
            return Err(ProviderDefinitionError::EmptyVersion);
        }
        let provider_id = ProviderId::new(GITHUB_DEPENDABOT_PROVIDER_ID)?;
        let provider_digest = Digest::from_parts(
            "hartevo-github-dependabot-provider/v1",
            &[
                provider_id.as_str().to_owned(),
                version.clone(),
                api_revision.as_str().to_owned(),
                format!("{provenance:?}"),
            ],
        );
        let api_digest = Digest::from_parts(
            "hartevo-github-dependabot-api/v1",
            &[
                GITHUB_DEPENDABOT_API_REVISION.to_owned(),
                "GET:list-alerts".to_owned(),
                "GET:get-alert".to_owned(),
                "etag:304".to_owned(),
            ],
        );
        Ok(Self {
            provider_id,
            version,
            api_revision,
            provider_digest,
            api_digest,
            provenance,
        })
    }
}

pub trait GithubDependabotTransport: Send + fmt::Debug {
    fn read(
        &mut self,
        request: &GithubDependabotReadRequest,
    ) -> Result<GithubDependabotReadPage, TransportError>;
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GithubDependabotProviderError {
    #[error("GitHub Dependabot provider transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("GitHub Dependabot provider model error: {0}")]
    Model(#[from] ModelError),
    #[error("GitHub Dependabot page binding is invalid")]
    PageBinding,
    #[error("GitHub Dependabot response is malformed")]
    MalformedResponse,
}

#[derive(Clone)]
pub struct GithubDependabotProvider<T>
where
    T: GithubDependabotTransport,
{
    transport: T,
    identity: GithubDependabotProviderIdentity,
}

impl<T> fmt::Debug for GithubDependabotProvider<T>
where
    T: GithubDependabotTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubDependabotProvider")
            .field("identity", &self.identity)
            .field("transport", &self.transport)
            .finish()
    }
}

impl<T> GithubDependabotProvider<T>
where
    T: GithubDependabotTransport,
{
    pub fn new(
        transport: T,
        version: impl Into<String>,
        provenance: TransportProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        Self::new_with_revision(
            transport,
            version,
            ProviderRevision::new(GITHUB_DEPENDABOT_API_REVISION)?,
            provenance,
        )
    }

    pub fn new_with_revision(
        transport: T,
        version: impl Into<String>,
        api_revision: ProviderRevision,
        provenance: TransportProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        Ok(Self {
            transport,
            identity: GithubDependabotProviderIdentity::new(version, api_revision, provenance)?,
        })
    }

    pub fn identity(&self) -> &GithubDependabotProviderIdentity {
        &self.identity
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read(
        &mut self,
        request: &GithubDependabotReadRequest,
    ) -> Result<GithubDependabotReadPage, GithubDependabotProviderError> {
        let page = self.transport.read(request)?;
        page.validate_for(request).map_err(|error| match error {
            ModelError::ScopeMismatch { .. } => GithubDependabotProviderError::PageBinding,
            _ => GithubDependabotProviderError::MalformedResponse,
        })?;
        Ok(page)
    }

    /// Parse the bounded fields of a recorded GitHub response. The raw body
    /// is never returned or stored; descriptions, names, paths, links, and
    /// unknown fields are discarded after digesting only the permitted values.
    pub fn parse_json_page(
        request: &GithubDependabotReadRequest,
        page_number: u16,
        response_bytes: usize,
        body: &[u8],
        provider_revision: ProviderRevision,
    ) -> Result<GithubDependabotReadPage, GithubDependabotProviderError> {
        Self::parse_json_page_with_headers(
            request,
            page_number,
            response_bytes,
            body,
            None,
            None,
            provider_revision,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn parse_json_page_with_headers(
        request: &GithubDependabotReadRequest,
        page_number: u16,
        response_bytes: usize,
        body: &[u8],
        next_cursor: Option<OpaqueCursor>,
        etag: Option<&str>,
        provider_revision: ProviderRevision,
    ) -> Result<GithubDependabotReadPage, GithubDependabotProviderError> {
        if response_bytes == 0 || response_bytes > request.max_response_bytes {
            return Err(GithubDependabotProviderError::MalformedResponse);
        }
        let value = serde_json::from_slice::<Value>(body)
            .map_err(|_| GithubDependabotProviderError::MalformedResponse)?;
        let alerts_value = value
            .as_array()
            .or_else(|| value.get("alerts").and_then(Value::as_array))
            .ok_or(GithubDependabotProviderError::MalformedResponse)?;
        if alerts_value.len() > crate::model::MAX_ALERTS_PER_PAGE {
            return Err(GithubDependabotProviderError::MalformedResponse);
        }
        let mut alerts = Vec::with_capacity(alerts_value.len());
        for alert in alerts_value {
            alerts.push(parse_alert(alert)?);
        }
        let etag_digest = etag.map(|value| {
            Digest::from_parts("hartevo-github-dependabot-etag/v1", &[value.to_owned()])
        });
        GithubDependabotReadPage::new_with_headers(
            request,
            page_number,
            alerts,
            next_cursor,
            response_bytes,
            provider_revision,
            etag_digest,
            false,
        )
        .map_err(Into::into)
    }

    pub fn parse_not_modified_page(
        request: &GithubDependabotReadRequest,
        page_number: u16,
        etag: Option<&str>,
        provider_revision: ProviderRevision,
    ) -> Result<GithubDependabotReadPage, GithubDependabotProviderError> {
        let etag_digest = etag.map(|value| {
            Digest::from_parts("hartevo-github-dependabot-etag/v1", &[value.to_owned()])
        });
        GithubDependabotReadPage::not_modified(request, page_number, etag_digest, provider_revision)
            .map_err(Into::into)
    }
}

fn parse_alert(value: &Value) -> Result<DependabotAlert, GithubDependabotProviderError> {
    let number = AlertNumber::new(required_u64(value, "number")?)?;
    let alert_revision = crate::model::Revision::new(
        optional_u64(value, "alert_revision")
            .or_else(|| optional_u64(value, "revision"))
            .unwrap_or(1),
    )?;
    let state = AlertState::parse_api(required_string(value, "state")?)?;
    let dependency = value
        .get("dependency")
        .ok_or(GithubDependabotProviderError::MalformedResponse)?;
    let package = dependency
        .get("package")
        .ok_or(GithubDependabotProviderError::MalformedResponse)?;
    let package_ecosystem = PackageEcosystem::parse_api(required_string(package, "ecosystem")?)?;
    let package_name = required_string(package, "name")?;
    let manifest = dependency
        .get("manifest")
        .ok_or(GithubDependabotProviderError::MalformedResponse)?;
    let manifest_path = required_string(manifest, "path")?;
    let advisory = value.get("security_advisory");
    let severity = advisory
        .and_then(|item| item.get("severity"))
        .and_then(Value::as_str)
        .or_else(|| value.get("severity").and_then(Value::as_str))
        .map(Severity::parse_api)
        .transpose()?
        .ok_or(GithubDependabotProviderError::MalformedResponse)?;
    let mut identifiers = Vec::new();
    if let Some(identifier) = advisory
        .and_then(|item| item.get("ghsa_id"))
        .and_then(Value::as_str)
    {
        identifiers.push(AdvisoryIdentifier::new(identifier)?);
    }
    if let Some(identifier) = advisory
        .and_then(|item| item.get("cve_id"))
        .and_then(Value::as_str)
    {
        identifiers.push(AdvisoryIdentifier::new(identifier)?);
    }
    let updated_at = parse_timestamp(value, "updated_at")?;
    let first_detected_at = parse_timestamp_optional(value, "created_at")?.unwrap_or(updated_at);
    let cvss_score = advisory
        .and_then(|item| item.get("cvss"))
        .and_then(|item| item.get("score"))
        .and_then(score_basis_points);
    let epss_score = advisory
        .and_then(|item| item.get("epss"))
        .and_then(|item| item.get("percentage"))
        .and_then(epss_basis_points);
    DependabotAlert::new(
        number,
        alert_revision,
        state,
        package_ecosystem,
        package_name,
        manifest_path,
        identifiers,
        severity,
        cvss_score,
        epss_score,
        first_detected_at,
        updated_at,
    )
    .map_err(Into::into)
}

fn required_string<'a>(
    value: &'a Value,
    field: &'static str,
) -> Result<&'a str, GithubDependabotProviderError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(GithubDependabotProviderError::MalformedResponse)
}

fn required_u64(value: &Value, field: &'static str) -> Result<u64, GithubDependabotProviderError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(GithubDependabotProviderError::MalformedResponse)
}

fn optional_u64(value: &Value, field: &'static str) -> Option<u64> {
    value.get(field).and_then(Value::as_u64)
}

fn parse_timestamp(
    value: &Value,
    field: &'static str,
) -> Result<DateTime<Utc>, GithubDependabotProviderError> {
    let raw = required_string(value, field)?;
    DateTime::parse_from_rfc3339(raw)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| GithubDependabotProviderError::MalformedResponse)
}

fn parse_timestamp_optional(
    value: &Value,
    field: &'static str,
) -> Result<Option<DateTime<Utc>>, GithubDependabotProviderError> {
    let Some(raw) = value.get(field).and_then(Value::as_str) else {
        return Ok(None);
    };
    DateTime::parse_from_rfc3339(raw)
        .map(|timestamp| Some(timestamp.with_timezone(&Utc)))
        .map_err(|_| GithubDependabotProviderError::MalformedResponse)
}

fn score_basis_points(value: &Value) -> Option<u16> {
    let score = value
        .as_f64()
        .or_else(|| value.as_str().and_then(|value| value.parse::<f64>().ok()))?;
    if !(0.0..=10.0).contains(&score) {
        return None;
    }
    Some((score * 100.0).round() as u16)
}

fn epss_basis_points(value: &Value) -> Option<u16> {
    let score = value
        .as_f64()
        .or_else(|| value.as_str().and_then(|value| value.parse::<f64>().ok()))?;
    let score = if score <= 1.0 { score * 100.0 } else { score };
    if !(0.0..=100.0).contains(&score) {
        return None;
    }
    Some((score * 100.0).round() as u16)
}

#[derive(Clone, Debug, Default)]
pub struct RecordingGithubDependabotTransport {
    responses: VecDeque<Result<GithubDependabotReadPage, TransportError>>,
    requests: Vec<GithubDependabotReadRequest>,
}

impl RecordingGithubDependabotTransport {
    pub fn new(
        responses: impl IntoIterator<Item = Result<GithubDependabotReadPage, TransportError>>,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        }
    }

    pub fn push_response(&mut self, response: Result<GithubDependabotReadPage, TransportError>) {
        self.responses.push_back(response);
    }

    pub fn push_page_response(
        &mut self,
        response: Result<GithubDependabotReadPage, TransportError>,
    ) {
        self.push_response(response);
    }

    pub fn requests(&self) -> &[GithubDependabotReadRequest] {
        &self.requests
    }
}

impl GithubDependabotTransport for RecordingGithubDependabotTransport {
    fn read(
        &mut self,
        request: &GithubDependabotReadRequest,
    ) -> Result<GithubDependabotReadPage, TransportError> {
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .unwrap_or(Err(TransportError::Unknown))
    }
}

#[derive(Clone, Debug, Default)]
pub struct FixtureGithubDependabotTransport {
    responses: VecDeque<Result<GithubDependabotReadPage, TransportError>>,
    requests: Vec<GithubDependabotReadRequest>,
}

impl FixtureGithubDependabotTransport {
    pub fn from_pages(
        pages: impl IntoIterator<Item = Result<GithubDependabotReadPage, TransportError>>,
    ) -> Self {
        Self {
            responses: pages.into_iter().collect(),
            requests: Vec::new(),
        }
    }

    pub fn push_response(&mut self, response: Result<GithubDependabotReadPage, TransportError>) {
        self.responses.push_back(response);
    }

    pub fn requests(&self) -> &[GithubDependabotReadRequest] {
        &self.requests
    }
}

impl GithubDependabotTransport for FixtureGithubDependabotTransport {
    fn read(
        &mut self,
        request: &GithubDependabotReadRequest,
    ) -> Result<GithubDependabotReadPage, TransportError> {
        self.requests.push(request.clone());
        self.responses.pop_front().unwrap_or_else(|| {
            GithubDependabotReadPage::new(
                request,
                1,
                Vec::new(),
                None,
                1,
                ProviderRevision::new(GITHUB_DEPENDABOT_API_REVISION)
                    .map_err(|_| TransportError::MalformedResponse)?,
            )
            .map_err(|_| TransportError::MalformedResponse)
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct LoopbackGithubDependabotTransport {
    alerts: Vec<DependabotAlert>,
}

impl LoopbackGithubDependabotTransport {
    pub fn with_alerts(alerts: impl IntoIterator<Item = DependabotAlert>) -> Self {
        Self {
            alerts: alerts.into_iter().collect(),
        }
    }
}

impl GithubDependabotTransport for LoopbackGithubDependabotTransport {
    fn read(
        &mut self,
        request: &GithubDependabotReadRequest,
    ) -> Result<GithubDependabotReadPage, TransportError> {
        let alerts = self
            .alerts
            .iter()
            .filter(|alert| {
                request
                    .alert_number
                    .is_none_or(|number| alert.alert_number == number)
            })
            .filter(|alert| alert.matches_filter(&request.filter))
            .cloned()
            .collect::<Vec<_>>();
        GithubDependabotReadPage::new(
            request,
            1,
            alerts,
            None,
            1,
            ProviderRevision::new(GITHUB_DEPENDABOT_API_REVISION)
                .map_err(|_| TransportError::MalformedResponse)?,
        )
        .map_err(|_| TransportError::MalformedResponse)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvGithubDependabotTransport;

impl GithubDependabotTransport for BlockedEnvGithubDependabotTransport {
    fn read(
        &mut self,
        _request: &GithubDependabotReadRequest,
    ) -> Result<GithubDependabotReadPage, TransportError> {
        Err(TransportError::BlockedEnvironment)
    }
}

pub type FakeGithubDependabotTransport = FixtureGithubDependabotTransport;
pub type BlockedEnvTransport = BlockedEnvGithubDependabotTransport;
pub type ProviderProvenance = TransportProvenance;

pub fn is_access_loss(error: &TransportError) -> bool {
    matches!(
        error,
        TransportError::Unauthorized | TransportError::Forbidden | TransportError::NotFound
    )
}

#[allow(dead_code)]
fn _keep_commit_scope_type_visible(_: &CommitSha) {}
