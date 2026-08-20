//! Provider and transport seams for bounded Amazon Detective reads.
//!
//! No implementation in this module resolves credentials or performs native
//! SigV4/HTTPS. Transports are fixtures/recordings/loopbacks or an explicit
//! `BLOCKED_ENV` fence, and all four provenance classes report false for
//! connected, native, and first-party authority.

use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AWS_DETECTIVE_API_VERSION, AWS_DETECTIVE_BLOCKED_ENV, AWS_DETECTIVE_CONTRACT_VERSION,
    AWS_DETECTIVE_PROVIDER_ID, AWS_DETECTIVE_PROVIDER_REVISION, AWS_DETECTIVE_PROVIDER_VERSION,
    DetectiveOperation, Digest, GetInvestigationRequest, ListIndicatorsRequest,
    ListInvestigationsRequest, ListMembersRequest, ModelError, OpaqueCursor, ProviderRevision,
    digest_serializable,
};

/// The origin of a Layer-1 response. None of these origins is native or
/// connected evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }

    pub const fn is_blocked(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    InvalidRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    RateLimited,
    ServerFailure,
    Timeout,
    BlockedEnvironment,
    MalformedResponse,
    Unknown,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TransportError {
    #[error("Amazon Detective provider returned HTTP 400")]
    InvalidRequest,
    #[error("Amazon Detective provider returned HTTP 401")]
    Unauthorized,
    #[error("Amazon Detective provider returned HTTP 403")]
    Forbidden,
    #[error("Amazon Detective resource was not found (HTTP 404)")]
    NotFound,
    #[error("Amazon Detective provider rate limited the request (HTTP 429)")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Amazon Detective provider returned a server failure")]
    ServerFailure { status_code: Option<u16> },
    #[error("Amazon Detective provider timed out")]
    Timeout,
    #[error("Amazon Detective native transport is unavailable in BLOCKED_ENV")]
    BlockedEnvironment,
    #[error("Amazon Detective provider response was malformed")]
    MalformedResponse,
    #[error("Amazon Detective provider returned an unknown error")]
    Unknown,
}

impl TransportError {
    pub const fn kind(&self) -> ProviderErrorKind {
        match self {
            Self::InvalidRequest => ProviderErrorKind::InvalidRequest,
            Self::Unauthorized => ProviderErrorKind::Unauthorized,
            Self::Forbidden => ProviderErrorKind::Forbidden,
            Self::NotFound => ProviderErrorKind::NotFound,
            Self::RateLimited { .. } => ProviderErrorKind::RateLimited,
            Self::ServerFailure { .. } => ProviderErrorKind::ServerFailure,
            Self::Timeout => ProviderErrorKind::Timeout,
            Self::BlockedEnvironment => ProviderErrorKind::BlockedEnvironment,
            Self::MalformedResponse => ProviderErrorKind::MalformedResponse,
            Self::Unknown => ProviderErrorKind::Unknown,
        }
    }

    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::InvalidRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::RateLimited { .. } => Some(429),
            Self::ServerFailure { status_code } => *status_code,
            Self::Timeout | Self::BlockedEnvironment | Self::MalformedResponse | Self::Unknown => {
                None
            }
        }
    }

    pub const fn retry_after_seconds(&self) -> Option<u64> {
        match self {
            Self::RateLimited {
                retry_after_seconds,
            } => *retry_after_seconds,
            _ => None,
        }
    }

    pub const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. } | Self::ServerFailure { .. } | Self::Timeout
        )
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProviderError {
    #[error("Amazon Detective provider definition is invalid")]
    InvalidDefinition,
    #[error("Amazon Detective provider request is invalid: {0}")]
    InvalidRequest(String),
    #[error("Amazon Detective provider operation is not allowlisted")]
    OperationNotAllowlisted,
    #[error("Amazon Detective provider returned a page for the wrong operation")]
    PageOperationMismatch,
    #[error("Amazon Detective provider page is malformed")]
    MalformedPage,
    #[error("Amazon Detective provider page exceeded the response bound")]
    ResponseTooLarge,
    #[error("Amazon Detective provider returned a transport error: {0}")]
    Transport(TransportError),
    #[error("Amazon Detective provider model error: {0}")]
    Model(#[from] ModelError),
}

impl From<TransportError> for ProviderError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderErrorEvidence {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u64>,
}

impl ProviderError {
    pub fn evidence(&self) -> Option<ProviderErrorEvidence> {
        match self {
            Self::Transport(error) => Some(ProviderErrorEvidence {
                kind: error.kind(),
                status_code: error.status_code(),
                retry_after_seconds: error.retry_after_seconds(),
            }),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InvestigationPage {
    pub page_number: u16,
    pub items: Vec<crate::InvestigationProjection>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: usize,
    pub provider_revision: ProviderRevision,
}

impl InvestigationPage {
    pub fn new(
        page_number: u16,
        items: Vec<crate::InvestigationProjection>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
    ) -> Result<Self, ModelError> {
        let page = Self {
            page_number,
            items,
            next_cursor,
            response_bytes,
            provider_revision: ProviderRevision::new(AWS_DETECTIVE_PROVIDER_REVISION)?,
        };
        page.validate_shape()?;
        Ok(page)
    }

    pub fn validate_shape(&self) -> Result<(), ModelError> {
        if self.page_number == 0 || self.items.len() > usize::from(crate::MAX_PAGE_SIZE) {
            return Err(ModelError::Invalid {
                field: "investigation page",
            });
        }
        if self.response_bytes == 0 || self.response_bytes > crate::MAX_RESPONSE_BYTES {
            return Err(ModelError::Invalid {
                field: "investigation response size",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(&(
            self.page_number,
            &self.items,
            self.next_cursor.as_ref().map(OpaqueCursor::token_digest),
            self.response_bytes,
            &self.provider_revision,
        ))
        .unwrap_or_else(|_| Digest::zero())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetInvestigationResponse {
    pub item: Option<crate::InvestigationProjection>,
    pub response_bytes: usize,
    pub provider_revision: ProviderRevision,
}

impl GetInvestigationResponse {
    pub fn new(
        item: Option<crate::InvestigationProjection>,
        response_bytes: usize,
    ) -> Result<Self, ModelError> {
        let response = Self {
            item,
            response_bytes,
            provider_revision: ProviderRevision::new(AWS_DETECTIVE_PROVIDER_REVISION)?,
        };
        response.validate_shape()?;
        Ok(response)
    }

    pub fn validate_shape(&self) -> Result<(), ModelError> {
        if self.response_bytes == 0 || self.response_bytes > crate::MAX_RESPONSE_BYTES {
            return Err(ModelError::Invalid {
                field: "investigation response size",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(&(&self.item, self.response_bytes, &self.provider_revision))
            .unwrap_or_else(|_| Digest::zero())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IndicatorPage {
    pub page_number: u16,
    pub items: Vec<crate::IndicatorProjection>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: usize,
    pub provider_revision: ProviderRevision,
}

impl IndicatorPage {
    pub fn new(
        page_number: u16,
        items: Vec<crate::IndicatorProjection>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
    ) -> Result<Self, ModelError> {
        let page = Self {
            page_number,
            items,
            next_cursor,
            response_bytes,
            provider_revision: ProviderRevision::new(AWS_DETECTIVE_PROVIDER_REVISION)?,
        };
        page.validate_shape()?;
        Ok(page)
    }

    pub fn validate_shape(&self) -> Result<(), ModelError> {
        if self.page_number == 0 || self.items.len() > usize::from(crate::MAX_PAGE_SIZE) {
            return Err(ModelError::Invalid {
                field: "indicator page",
            });
        }
        if self.response_bytes == 0 || self.response_bytes > crate::MAX_RESPONSE_BYTES {
            return Err(ModelError::Invalid {
                field: "indicator response size",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(&(
            self.page_number,
            &self.items,
            self.next_cursor.as_ref().map(OpaqueCursor::token_digest),
            self.response_bytes,
            &self.provider_revision,
        ))
        .unwrap_or_else(|_| Digest::zero())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemberPage {
    pub page_number: u16,
    pub items: Vec<crate::MemberProjection>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: usize,
    pub provider_revision: ProviderRevision,
}

impl MemberPage {
    pub fn new(
        page_number: u16,
        items: Vec<crate::MemberProjection>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
    ) -> Result<Self, ModelError> {
        let page = Self {
            page_number,
            items,
            next_cursor,
            response_bytes,
            provider_revision: ProviderRevision::new(AWS_DETECTIVE_PROVIDER_REVISION)?,
        };
        page.validate_shape()?;
        Ok(page)
    }

    pub fn validate_shape(&self) -> Result<(), ModelError> {
        if self.page_number == 0 || self.items.len() > usize::from(crate::MAX_PAGE_SIZE) {
            return Err(ModelError::Invalid {
                field: "member page",
            });
        }
        if self.response_bytes == 0 || self.response_bytes > crate::MAX_RESPONSE_BYTES {
            return Err(ModelError::Invalid {
                field: "member response size",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(&(
            self.page_number,
            &self.items,
            self.next_cursor.as_ref().map(OpaqueCursor::token_digest),
            self.response_bytes,
            &self.provider_revision,
        ))
        .unwrap_or_else(|_| Digest::zero())
    }
}

impl From<InvestigationPage> for AwsDetectiveResponse {
    fn from(value: InvestigationPage) -> Self {
        Self::Investigations(value)
    }
}

impl From<GetInvestigationResponse> for AwsDetectiveResponse {
    fn from(value: GetInvestigationResponse) -> Self {
        Self::Investigation(value)
    }
}

impl From<IndicatorPage> for AwsDetectiveResponse {
    fn from(value: IndicatorPage) -> Self {
        Self::Indicators(value)
    }
}

impl From<MemberPage> for AwsDetectiveResponse {
    fn from(value: MemberPage) -> Self {
        Self::Members(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum AwsDetectiveResponse {
    Investigations(InvestigationPage),
    Investigation(GetInvestigationResponse),
    Indicators(IndicatorPage),
    Members(MemberPage),
}

pub type DetectiveResponse = AwsDetectiveResponse;

/// Transport inputs are already redacted request types; a transport cannot
/// receive a raw entity, graph edge, indicator text, or provider token.
pub trait AwsDetectiveTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;

    fn list_investigations(
        &mut self,
        request: &ListInvestigationsRequest,
    ) -> Result<InvestigationPage, TransportError>;

    fn get_investigation(
        &mut self,
        request: &GetInvestigationRequest,
    ) -> Result<GetInvestigationResponse, TransportError>;

    fn list_indicators(
        &mut self,
        request: &ListIndicatorsRequest,
    ) -> Result<IndicatorPage, TransportError>;

    fn list_members(&mut self, request: &ListMembersRequest) -> Result<MemberPage, TransportError>;
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsDetectiveTransport for BlockedEnvTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn list_investigations(
        &mut self,
        _request: &ListInvestigationsRequest,
    ) -> Result<InvestigationPage, TransportError> {
        Err(TransportError::BlockedEnvironment)
    }

    fn get_investigation(
        &mut self,
        _request: &GetInvestigationRequest,
    ) -> Result<GetInvestigationResponse, TransportError> {
        Err(TransportError::BlockedEnvironment)
    }

    fn list_indicators(
        &mut self,
        _request: &ListIndicatorsRequest,
    ) -> Result<IndicatorPage, TransportError> {
        Err(TransportError::BlockedEnvironment)
    }

    fn list_members(
        &mut self,
        _request: &ListMembersRequest,
    ) -> Result<MemberPage, TransportError> {
        Err(TransportError::BlockedEnvironment)
    }
}

#[derive(Clone, Debug)]
struct MemoryTransport {
    responses: VecDeque<Result<AwsDetectiveResponse, TransportError>>,
    calls: Vec<TransportCall>,
    provenance: ProviderProvenance,
}

impl MemoryTransport {
    fn new(provenance: ProviderProvenance) -> Self {
        Self {
            responses: VecDeque::new(),
            calls: Vec::new(),
            provenance,
        }
    }

    fn push_response<R>(&mut self, response: Result<R, TransportError>)
    where
        R: Into<AwsDetectiveResponse>,
    {
        self.responses
            .push_back(response.map(Into::<AwsDetectiveResponse>::into));
    }

    fn pop_response(
        &mut self,
        operation: DetectiveOperation,
        request_digest: Digest,
        cursor_digest: Option<Digest>,
    ) -> Result<AwsDetectiveResponse, TransportError> {
        self.calls.push(TransportCall {
            operation,
            request_digest,
            cursor_digest,
            provenance: self.provenance,
            connected: false,
            native: false,
            first_party: false,
        });
        self.responses
            .pop_front()
            .unwrap_or(Err(TransportError::Unknown))
    }

    fn calls(&self) -> &[TransportCall] {
        &self.calls
    }

    fn clear_calls(&mut self) {
        self.calls.clear();
    }
}

macro_rules! memory_transport {
    ($name:ident, $provenance:expr) => {
        #[derive(Clone, Debug)]
        pub struct $name {
            inner: MemoryTransport,
        }

        impl Default for $name {
            fn default() -> Self {
                Self {
                    inner: MemoryTransport::new($provenance),
                }
            }
        }

        impl $name {
            pub fn push_response<R>(&mut self, response: Result<R, TransportError>)
            where
                R: Into<AwsDetectiveResponse>,
            {
                self.inner.push_response(response);
            }

            pub fn push_investigations(
                &mut self,
                response: Result<InvestigationPage, TransportError>,
            ) {
                self.push_response(response);
            }

            pub fn push_get_investigation(
                &mut self,
                response: Result<GetInvestigationResponse, TransportError>,
            ) {
                self.push_response(response);
            }

            pub fn push_indicators(&mut self, response: Result<IndicatorPage, TransportError>) {
                self.push_response(response);
            }

            pub fn push_members(&mut self, response: Result<MemberPage, TransportError>) {
                self.push_response(response);
            }

            pub fn calls(&self) -> &[TransportCall] {
                self.inner.calls()
            }

            pub fn clear_calls(&mut self) {
                self.inner.clear_calls();
            }

            pub fn provenance(&self) -> ProviderProvenance {
                $provenance
            }
        }

        impl AwsDetectiveTransport for $name {
            fn provenance(&self) -> ProviderProvenance {
                $provenance
            }

            fn list_investigations(
                &mut self,
                request: &ListInvestigationsRequest,
            ) -> Result<InvestigationPage, TransportError> {
                match self.inner.pop_response(
                    DetectiveOperation::ListInvestigations,
                    request.request_digest(),
                    request
                        .cursor
                        .as_ref()
                        .map(|cursor| cursor.token_digest().clone()),
                )? {
                    AwsDetectiveResponse::Investigations(page) => Ok(page),
                    _ => Err(TransportError::MalformedResponse),
                }
            }

            fn get_investigation(
                &mut self,
                request: &GetInvestigationRequest,
            ) -> Result<GetInvestigationResponse, TransportError> {
                match self.inner.pop_response(
                    DetectiveOperation::GetInvestigation,
                    request.request_digest(),
                    None,
                )? {
                    AwsDetectiveResponse::Investigation(response) => Ok(response),
                    _ => Err(TransportError::MalformedResponse),
                }
            }

            fn list_indicators(
                &mut self,
                request: &ListIndicatorsRequest,
            ) -> Result<IndicatorPage, TransportError> {
                match self.inner.pop_response(
                    DetectiveOperation::ListIndicators,
                    request.request_digest(),
                    request
                        .cursor
                        .as_ref()
                        .map(|cursor| cursor.token_digest().clone()),
                )? {
                    AwsDetectiveResponse::Indicators(page) => Ok(page),
                    _ => Err(TransportError::MalformedResponse),
                }
            }

            fn list_members(
                &mut self,
                request: &ListMembersRequest,
            ) -> Result<MemberPage, TransportError> {
                match self.inner.pop_response(
                    DetectiveOperation::ListMembers,
                    request.request_digest(),
                    request
                        .cursor
                        .as_ref()
                        .map(|cursor| cursor.token_digest().clone()),
                )? {
                    AwsDetectiveResponse::Members(page) => Ok(page),
                    _ => Err(TransportError::MalformedResponse),
                }
            }
        }
    };
}

memory_transport!(
    RecordingAwsDetectiveTransport,
    ProviderProvenance::Recording
);
memory_transport!(FixtureAwsDetectiveTransport, ProviderProvenance::Fixture);
memory_transport!(LoopbackAwsDetectiveTransport, ProviderProvenance::Loopback);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransportCall {
    pub operation: DetectiveOperation,
    pub request_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub provenance: ProviderProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsDetectiveProviderDefinition {
    pub provider_id: String,
    pub api_version: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub contract_version: String,
    pub read_only: bool,
    pub native: bool,
    pub first_party: bool,
    pub connected: bool,
    pub external_writes: bool,
    pub allowed_operations: Vec<DetectiveOperation>,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub version_digest: Digest,
    pub provenance: ProviderProvenance,
}

impl Default for AwsDetectiveProviderDefinition {
    fn default() -> Self {
        Self::new(ProviderProvenance::BlockedEnv)
    }
}

impl AwsDetectiveProviderDefinition {
    pub fn new(provenance: ProviderProvenance) -> Self {
        let provider_id = AWS_DETECTIVE_PROVIDER_ID.to_owned();
        let api_version = AWS_DETECTIVE_API_VERSION.to_owned();
        let provider_version = AWS_DETECTIVE_PROVIDER_VERSION.to_owned();
        let provider_revision = AWS_DETECTIVE_PROVIDER_REVISION.to_owned();
        let contract_version = AWS_DETECTIVE_CONTRACT_VERSION.to_owned();
        let allowed_operations = DetectiveOperation::ALL.to_vec();
        let api_digest = Digest::from_text(&api_version);
        let version_digest = Digest::from_parts(
            "hartevo-aws-detective-provider-version/v1",
            &[
                provider_version.clone(),
                provider_revision.clone(),
                api_version.clone(),
                contract_version.clone(),
            ],
        );
        let provider_digest = digest_serializable(&(
            &provider_id,
            &api_version,
            &provider_version,
            &provider_revision,
            &contract_version,
            &allowed_operations,
            true,
            false,
            false,
            false,
            provenance,
        ))
        .unwrap_or_else(|_| Digest::zero());
        Self {
            provider_id,
            api_version,
            provider_version,
            provider_revision,
            contract_version,
            read_only: true,
            native: false,
            first_party: false,
            connected: false,
            external_writes: false,
            allowed_operations,
            provider_digest,
            api_digest,
            version_digest,
            provenance,
        }
    }

    pub fn validate(&self) -> Result<(), ProviderError> {
        let expected = Self::new(self.provenance);
        if self != &expected
            || self.native
            || self.first_party
            || self.connected
            || self.external_writes
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
        {
            return Err(ProviderError::InvalidDefinition);
        }
        Ok(())
    }
}

pub struct AwsDetectiveProvider<T = BlockedEnvTransport> {
    transport: T,
    definition: AwsDetectiveProviderDefinition,
}

impl<T: AwsDetectiveTransport> fmt::Debug for AwsDetectiveProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsDetectiveProvider")
            .field("definition", &self.definition)
            .field("provenance", &self.provenance())
            .finish_non_exhaustive()
    }
}

impl Default for AwsDetectiveProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("static BLOCKED_ENV provider definition")
    }
}

impl<T: AwsDetectiveTransport> AwsDetectiveProvider<T> {
    pub fn new(transport: T) -> Result<Self, ProviderError> {
        let definition = AwsDetectiveProviderDefinition::new(transport.provenance());
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn from_transport(transport: T) -> Self {
        Self::new(transport).expect("static Layer-1 provider definition")
    }

    pub fn definition(&self) -> &AwsDetectiveProviderDefinition {
        &self.definition
    }

    pub fn identity(&self) -> &AwsDetectiveProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.transport.provenance()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn validate(&self) -> Result<(), ProviderError> {
        self.definition.validate()
    }

    pub fn list_investigations(
        &mut self,
        request: &ListInvestigationsRequest,
    ) -> Result<InvestigationPage, ProviderError> {
        self.validate_request(
            DetectiveOperation::ListInvestigations,
            request.bounds.page_size,
        )?;
        let page = self.transport.list_investigations(request)?;
        page.validate_shape()?;
        self.validate_page_revision(&page.provider_revision)?;
        Ok(page)
    }

    pub fn get_investigation(
        &mut self,
        request: &GetInvestigationRequest,
    ) -> Result<GetInvestigationResponse, ProviderError> {
        let response = self.transport.get_investigation(request)?;
        response.validate_shape()?;
        self.validate_page_revision(&response.provider_revision)?;
        Ok(response)
    }

    pub fn list_indicators(
        &mut self,
        request: &ListIndicatorsRequest,
    ) -> Result<IndicatorPage, ProviderError> {
        self.validate_request(DetectiveOperation::ListIndicators, request.bounds.page_size)?;
        let page = self.transport.list_indicators(request)?;
        page.validate_shape()?;
        self.validate_page_revision(&page.provider_revision)?;
        Ok(page)
    }

    pub fn list_members(
        &mut self,
        request: &ListMembersRequest,
    ) -> Result<MemberPage, ProviderError> {
        self.validate_request(DetectiveOperation::ListMembers, request.bounds.page_size)?;
        let page = self.transport.list_members(request)?;
        page.validate_shape()?;
        self.validate_page_revision(&page.provider_revision)?;
        Ok(page)
    }

    fn validate_request(
        &self,
        operation: DetectiveOperation,
        page_size: u16,
    ) -> Result<(), ProviderError> {
        if !self.definition.allowed_operations.contains(&operation) {
            return Err(ProviderError::OperationNotAllowlisted);
        }
        if page_size == 0 || page_size > crate::MAX_PAGE_SIZE {
            return Err(ProviderError::InvalidRequest("page size".to_owned()));
        }
        Ok(())
    }

    fn validate_page_revision(&self, revision: &ProviderRevision) -> Result<(), ProviderError> {
        if revision.as_str() != self.definition.provider_revision {
            return Err(ProviderError::MalformedPage);
        }
        Ok(())
    }
}

impl<T> AwsDetectiveProvider<T> {
    pub const fn blocked_environment_status() -> &'static str {
        AWS_DETECTIVE_BLOCKED_ENV
    }
}

pub type RecordingTransport = RecordingAwsDetectiveTransport;
pub type FixtureTransport = FixtureAwsDetectiveTransport;
pub type LoopbackTransport = LoopbackAwsDetectiveTransport;
pub type BlockedEnvAwsDetectiveTransport = BlockedEnvTransport;
