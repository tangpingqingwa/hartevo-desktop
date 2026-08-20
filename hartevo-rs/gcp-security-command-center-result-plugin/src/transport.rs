//! Non-native transport seams for Security Command Center.
//!
//! There is deliberately no live HTTPS transport in this Layer-1 crate. The
//! recording and loopback implementations exercise the same bounded request
//! and response shapes that a later host-owned transport may implement.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};
use serde::Serialize;
use thiserror::Error;
use url::Url;

use crate::{
    Digest, FindingFilter, FindingRecord, FindingsGroupRequest, FindingsListRequest, GroupBy,
    GroupFindingBucket, ModelError, OpaquePageToken, ProviderRevision, TransportProvenance,
    digest_serializable,
};

pub const SECURITY_CENTER_API_ORIGIN: &str = "https://securitycenter.googleapis.com";
pub const SECURITY_CENTER_API_VERSION: &str = "v1";

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TransportError {
    #[error("BLOCKED_ENV: host-owned Google credential and HTTPS authority are unavailable")]
    BlockedEnv,
    #[error("Security Command Center returned HTTP 401")]
    Unauthorized,
    #[error("Security Command Center returned HTTP 403")]
    Forbidden,
    #[error("Security Command Center returned HTTP 404")]
    NotFound,
    #[error("Security Command Center returned HTTP 429")]
    RateLimited,
    #[error("Security Command Center request timed out")]
    Timeout,
    #[error("Security Command Center returned a server error")]
    Server,
    #[error("the fixture or loopback transport has no response")]
    NoFixtureResponse,
    #[error("the normalized response exceeded the transport bound")]
    ResponseTooLarge,
    #[error("the normalized response failed its tamper check")]
    ResponseTampered,
    #[error("findings.group is not available from this transport")]
    GroupUnsupported,
    #[error("the transport returned an invalid response")]
    InvalidResponse,
}

impl TransportError {
    pub const fn is_access_loss(&self) -> bool {
        matches!(self, Self::Unauthorized | Self::Forbidden | Self::NotFound)
    }

    pub const fn is_blocked_env(&self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecurityCenterEndpoint {
    FindingsList { parent_path: String },
    FindingsGroup { parent_path: String },
}

impl SecurityCenterEndpoint {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::FindingsList { .. } => "findings.list",
            Self::FindingsGroup { .. } => "findings.group",
        }
    }

    pub const fn method(&self) -> &'static str {
        match self {
            Self::FindingsList { .. } => "GET",
            Self::FindingsGroup { .. } => "POST",
        }
    }

    fn parent_path(&self) -> &str {
        match self {
            Self::FindingsList { parent_path } | Self::FindingsGroup { parent_path } => parent_path,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityCenterHttpRequest {
    endpoint: SecurityCenterEndpoint,
    filter: FindingFilter,
    group_by: Option<GroupBy>,
    page_number: u16,
    page_size: u32,
    page_token: Option<OpaquePageToken>,
    api_version: String,
    requested_at: DateTime<Utc>,
    max_response_bytes: usize,
    request_digest: Digest,
}

impl SecurityCenterHttpRequest {
    pub fn for_findings_list(
        request: &FindingsListRequest,
        requested_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        Self::new(
            SecurityCenterEndpoint::FindingsList {
                parent_path: request
                    .target()
                    .parent_path(request.location(), request.source_id()),
            },
            request.filter().clone(),
            None,
            request,
            requested_at,
        )
    }

    pub fn for_findings_group(
        request: &FindingsGroupRequest,
        requested_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        Self::new(
            SecurityCenterEndpoint::FindingsGroup {
                parent_path: request
                    .target()
                    .parent_path(request.location(), request.source_id()),
            },
            request.filter().clone(),
            Some(request.group_by()),
            request,
            requested_at,
        )
    }

    fn new<R>(
        endpoint: SecurityCenterEndpoint,
        filter: FindingFilter,
        group_by: Option<GroupBy>,
        request: &R,
        requested_at: DateTime<Utc>,
    ) -> Result<Self, ModelError>
    where
        R: RequestBinding,
    {
        filter.validate()?;
        request.page().validate()?;
        request.bounds().validate()?;
        Ok(Self {
            endpoint,
            filter,
            group_by,
            page_number: request.page().page_number(),
            page_size: request.page().page_size(),
            page_token: request.page().page_token().cloned(),
            api_version: SECURITY_CENTER_API_VERSION.to_owned(),
            requested_at,
            max_response_bytes: request.bounds().max_response_bytes,
            request_digest: request.request_digest().clone(),
        })
    }

    pub const fn endpoint(&self) -> &SecurityCenterEndpoint {
        &self.endpoint
    }

    pub const fn operation(&self) -> &'static str {
        self.endpoint.operation()
    }

    pub const fn method(&self) -> &'static str {
        self.endpoint.method()
    }

    pub fn filter(&self) -> &FindingFilter {
        &self.filter
    }

    pub const fn group_by(&self) -> Option<GroupBy> {
        self.group_by
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub const fn page_size(&self) -> u32 {
        self.page_size
    }

    pub fn page_token(&self) -> Option<&OpaquePageToken> {
        self.page_token.as_ref()
    }

    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    pub const fn requested_at(&self) -> DateTime<Utc> {
        self.requested_at
    }

    pub const fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> Result<String, TransportError> {
        self.path_and_query_with_page_token(self.page_token.as_ref().map(OpaquePageToken::as_str))
    }

    pub fn redacted_path_and_query(&self) -> Result<String, TransportError> {
        let token = self
            .page_token
            .as_ref()
            .map(|page_token| format!("digest:{}", page_token.digest()));
        self.path_and_query_with_page_token(token.as_deref())
    }

    fn path_and_query_with_page_token(
        &self,
        page_token: Option<&str>,
    ) -> Result<String, TransportError> {
        let mut url =
            Url::parse(SECURITY_CENTER_API_ORIGIN).map_err(|_| TransportError::InvalidResponse)?;
        let endpoint = match &self.endpoint {
            SecurityCenterEndpoint::FindingsList { .. } => "findings",
            SecurityCenterEndpoint::FindingsGroup { .. } => "findings:group",
        };
        url.set_path(&format!(
            "/{}/{}/{}",
            SECURITY_CENTER_API_VERSION,
            self.endpoint.parent_path(),
            endpoint
        ));
        {
            let mut query = url.query_pairs_mut();
            let filter = self.filter.to_api_filter();
            if !filter.is_empty() {
                query.append_pair("filter", &filter);
            }
            query
                .append_pair("pageSize", &self.page_size.to_string())
                .append_pair("pageNumber", &self.page_number.to_string())
                .append_pair("api-version", &self.api_version);
            if let Some(page_token) = page_token {
                query.append_pair("pageToken", page_token);
            }
            if let Some(group_by) = self.group_by {
                query.append_pair("groupBy", group_by.as_str());
            }
        }
        Ok(url.to_string())
    }

    fn recorded(&self) -> Result<RecordedSecurityCenterRequest, TransportError> {
        let redacted_path_and_query = self.redacted_path_and_query()?;
        Ok(RecordedSecurityCenterRequest {
            operation: self.operation().to_owned(),
            method: self.method().to_owned(),
            api_version: self.api_version.clone(),
            redacted_path_and_query: redacted_path_and_query.clone(),
            path_digest: Digest::from_text(redacted_path_and_query),
            request_digest: self.request_digest.clone(),
            filter_digest: self.filter.digest(),
            page_digest: digest_serializable(&(
                self.page_number,
                self.page_size,
                self.page_token.as_ref().map(OpaquePageToken::digest),
            )),
        })
    }
}

trait RequestBinding {
    fn page(&self) -> &crate::PageBinding;
    fn bounds(&self) -> crate::RequestBounds;
    fn request_digest(&self) -> &Digest;
}

impl RequestBinding for FindingsListRequest {
    fn page(&self) -> &crate::PageBinding {
        self.page()
    }

    fn bounds(&self) -> crate::RequestBounds {
        self.bounds()
    }

    fn request_digest(&self) -> &Digest {
        self.request_digest()
    }
}

impl RequestBinding for FindingsGroupRequest {
    fn page(&self) -> &crate::PageBinding {
        self.page()
    }

    fn bounds(&self) -> crate::RequestBounds {
        self.bounds()
    }

    fn request_digest(&self) -> &Digest {
        self.request_digest()
    }
}

impl GroupBy {
    fn as_str(self) -> &'static str {
        match self {
            Self::Category => "category",
            Self::Resource => "resource",
            Self::State => "state",
            Self::Severity => "severity",
            Self::Source => "source",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindingsListResponse {
    pub findings: Vec<FindingRecord>,
    pub partial: bool,
    pub warning_count: u32,
    pub provider_revision: ProviderRevision,
    next_page_token: Option<OpaquePageToken>,
    pub response_digest: Digest,
}

impl FindingsListResponse {
    pub fn new(
        findings: Vec<FindingRecord>,
        next_page_token: Option<OpaquePageToken>,
        partial: bool,
        warning_count: u32,
        provider_revision: ProviderRevision,
    ) -> Result<Self, ModelError> {
        for finding in &findings {
            finding.validate()?;
        }
        let response_digest = digest_serializable(&ListResponseDigestView {
            findings: &findings,
            next_page_token_digest: next_page_token.as_ref().map(OpaquePageToken::digest),
            partial,
            warning_count,
            provider_revision: &provider_revision,
        });
        Ok(Self {
            findings,
            partial,
            warning_count,
            provider_revision,
            next_page_token,
            response_digest,
        })
    }

    pub fn next_page_token(&self) -> Option<&OpaquePageToken> {
        self.next_page_token.as_ref()
    }

    pub fn validate(&self) -> Result<(), TransportError> {
        for finding in &self.findings {
            finding
                .validate()
                .map_err(|_| TransportError::ResponseTampered)?;
        }
        let expected = digest_serializable(&ListResponseDigestView {
            findings: &self.findings,
            next_page_token_digest: self.next_page_token.as_ref().map(OpaquePageToken::digest),
            partial: self.partial,
            warning_count: self.warning_count,
            provider_revision: &self.provider_revision,
        });
        if self.response_digest != expected {
            return Err(TransportError::ResponseTampered);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct ListResponseDigestView<'a> {
    findings: &'a [FindingRecord],
    next_page_token_digest: Option<Digest>,
    partial: bool,
    warning_count: u32,
    provider_revision: &'a ProviderRevision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindingsGroupResponse {
    pub groups: Vec<GroupFindingBucket>,
    pub partial: bool,
    pub warning_count: u32,
    pub provider_revision: ProviderRevision,
    next_page_token: Option<OpaquePageToken>,
    pub response_digest: Digest,
}

impl FindingsGroupResponse {
    pub fn new(
        groups: Vec<GroupFindingBucket>,
        next_page_token: Option<OpaquePageToken>,
        partial: bool,
        warning_count: u32,
        provider_revision: ProviderRevision,
    ) -> Result<Self, ModelError> {
        for group in &groups {
            group.validate()?;
        }
        let response_digest = digest_serializable(&GroupResponseDigestView {
            groups: &groups,
            next_page_token_digest: next_page_token.as_ref().map(OpaquePageToken::digest),
            partial,
            warning_count,
            provider_revision: &provider_revision,
        });
        Ok(Self {
            groups,
            partial,
            warning_count,
            provider_revision,
            next_page_token,
            response_digest,
        })
    }

    pub fn next_page_token(&self) -> Option<&OpaquePageToken> {
        self.next_page_token.as_ref()
    }

    pub fn validate(&self) -> Result<(), TransportError> {
        for group in &self.groups {
            group
                .validate()
                .map_err(|_| TransportError::ResponseTampered)?;
        }
        let expected = digest_serializable(&GroupResponseDigestView {
            groups: &self.groups,
            next_page_token_digest: self.next_page_token.as_ref().map(OpaquePageToken::digest),
            partial: self.partial,
            warning_count: self.warning_count,
            provider_revision: &self.provider_revision,
        });
        if self.response_digest != expected {
            return Err(TransportError::ResponseTampered);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct GroupResponseDigestView<'a> {
    groups: &'a [GroupFindingBucket],
    next_page_token_digest: Option<Digest>,
    partial: bool,
    warning_count: u32,
    provider_revision: &'a ProviderRevision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedSecurityCenterRequest {
    pub operation: String,
    pub method: String,
    pub api_version: String,
    pub redacted_path_and_query: String,
    pub path_digest: Digest,
    pub request_digest: Digest,
    pub filter_digest: Digest,
    pub page_digest: Digest,
}

pub trait GcpSecurityCenterTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn list_findings(
        &mut self,
        request: &SecurityCenterHttpRequest,
    ) -> Result<FindingsListResponse, TransportError>;

    fn group_findings(
        &mut self,
        request: &SecurityCenterHttpRequest,
    ) -> Result<FindingsGroupResponse, TransportError>;
}

#[derive(Clone, Debug)]
pub struct RecordingGcpSecurityCenterTransport {
    provenance: TransportProvenance,
    requests: Vec<RecordedSecurityCenterRequest>,
    list_responses: VecDeque<Result<FindingsListResponse, TransportError>>,
    group_responses: VecDeque<Result<FindingsGroupResponse, TransportError>>,
}

impl Default for RecordingGcpSecurityCenterTransport {
    fn default() -> Self {
        Self::new(TransportProvenance::Recording)
    }
}

impl RecordingGcpSecurityCenterTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            requests: Vec::new(),
            list_responses: VecDeque::new(),
            group_responses: VecDeque::new(),
        }
    }

    pub fn fixture(
        responses: impl IntoIterator<Item = Result<FindingsListResponse, TransportError>>,
    ) -> Self {
        let mut transport = Self::new(TransportProvenance::Fixture);
        transport.list_responses.extend(responses);
        transport
    }

    pub fn loopback(
        responses: impl IntoIterator<Item = Result<FindingsListResponse, TransportError>>,
    ) -> Self {
        let mut transport = Self::new(TransportProvenance::Loopback);
        transport.list_responses.extend(responses);
        transport
    }

    pub fn push_list_response(&mut self, response: Result<FindingsListResponse, TransportError>) {
        self.list_responses.push_back(response);
    }

    pub fn push_group_response(&mut self, response: Result<FindingsGroupResponse, TransportError>) {
        self.group_responses.push_back(response);
    }

    pub fn requests(&self) -> &[RecordedSecurityCenterRequest] {
        &self.requests
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn record_request(
        &mut self,
        request: &SecurityCenterHttpRequest,
    ) -> Result<(), TransportError> {
        self.requests.push(request.recorded()?);
        Ok(())
    }
}

impl GcpSecurityCenterTransport for RecordingGcpSecurityCenterTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn list_findings(
        &mut self,
        request: &SecurityCenterHttpRequest,
    ) -> Result<FindingsListResponse, TransportError> {
        self.record_request(request)?;
        self.list_responses
            .pop_front()
            .unwrap_or(Err(TransportError::NoFixtureResponse))
    }

    fn group_findings(
        &mut self,
        request: &SecurityCenterHttpRequest,
    ) -> Result<FindingsGroupResponse, TransportError> {
        self.record_request(request)?;
        self.group_responses
            .pop_front()
            .unwrap_or(Err(TransportError::GroupUnsupported))
    }
}

pub type FakeGcpSecurityCenterTransport = RecordingGcpSecurityCenterTransport;
pub type FixtureGcpSecurityCenterTransport = RecordingGcpSecurityCenterTransport;
pub type LoopbackGcpSecurityCenterTransport = RecordingGcpSecurityCenterTransport;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvGcpSecurityCenterTransport;

impl GcpSecurityCenterTransport for BlockedEnvGcpSecurityCenterTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn list_findings(
        &mut self,
        _request: &SecurityCenterHttpRequest,
    ) -> Result<FindingsListResponse, TransportError> {
        Err(TransportError::BlockedEnv)
    }

    fn group_findings(
        &mut self,
        _request: &SecurityCenterHttpRequest,
    ) -> Result<FindingsGroupResponse, TransportError> {
        Err(TransportError::BlockedEnv)
    }
}

pub type BlockedEnvTransport = BlockedEnvGcpSecurityCenterTransport;
