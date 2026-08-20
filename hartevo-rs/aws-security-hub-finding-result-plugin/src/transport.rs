//! Non-native transport seams for the Layer-1 Security Hub provider.
//!
//! Every transport accepts normalized requests and returns normalized pages.
//! None accepts a secret, resolves credentials, or exposes raw provider JSON.

use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    AccessLossKind, GetFindingsApi, GetFindingsPage, GetFindingsRequest, ProviderProvenance,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AwsSecurityHubTransportError {
    #[error("BLOCKED_ENV: native Security Hub transport is unavailable")]
    BlockedEnv,
    #[error("Security Hub access was denied")]
    AccessDenied,
    #[error("the host did not provide a credential lease")]
    CredentialUnavailable,
    #[error("Security Hub provider is unavailable")]
    ProviderUnavailable,
    #[error("Security Hub request was throttled")]
    Throttled,
    #[error("invalid normalized transport request: {0}")]
    InvalidRequest(String),
    #[error("recording transport response queue is exhausted")]
    QueueExhausted,
}

impl AwsSecurityHubTransportError {
    pub const fn access_loss_kind(&self) -> Option<AccessLossKind> {
        match self {
            Self::BlockedEnv => Some(AccessLossKind::BlockedEnv),
            Self::AccessDenied => Some(AccessLossKind::AccessDenied),
            Self::CredentialUnavailable => Some(AccessLossKind::CredentialUnavailable),
            Self::ProviderUnavailable | Self::Throttled => {
                Some(AccessLossKind::ProviderUnavailable)
            }
            Self::InvalidRequest(_) | Self::QueueExhausted => None,
        }
    }

    pub fn provider_code(&self) -> &'static str {
        match self {
            Self::BlockedEnv => "BLOCKED_ENV",
            Self::AccessDenied => "ACCESS_DENIED",
            Self::CredentialUnavailable => "CREDENTIAL_UNAVAILABLE",
            Self::ProviderUnavailable => "PROVIDER_UNAVAILABLE",
            Self::Throttled => "THROTTLED",
            Self::InvalidRequest(_) => "INVALID_REQUEST",
            Self::QueueExhausted => "QUEUE_EXHAUSTED",
        }
    }
}

/// A redacted request trace suitable for deterministic recording assertions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedAwsSecurityHubRequest {
    pub api: GetFindingsApi,
    pub scope_digest: crate::model::Digest,
    pub filter_digest: crate::model::Digest,
    pub page_number: u16,
    pub page_size: u16,
    pub page_token_digest: Option<crate::model::Digest>,
    pub request_digest: crate::model::Digest,
}

impl From<&GetFindingsRequest> for RecordedAwsSecurityHubRequest {
    fn from(request: &GetFindingsRequest) -> Self {
        let binding = request.binding();
        Self {
            api: binding.api,
            scope_digest: binding.scope_digest,
            filter_digest: binding.filter_digest,
            page_number: binding.page_number,
            page_size: binding.page_size,
            page_token_digest: binding.page_token_digest,
            request_digest: binding.request_digest,
        }
    }
}

pub trait AwsSecurityHubTransport: fmt::Debug {
    fn get_findings(
        &mut self,
        request: &GetFindingsRequest,
    ) -> Result<GetFindingsPage, AwsSecurityHubTransportError>;

    fn get_findings_v2(
        &mut self,
        request: &GetFindingsRequest,
    ) -> Result<GetFindingsPage, AwsSecurityHubTransportError>;

    fn provenance(&self) -> ProviderProvenance;

    fn is_native(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug)]
pub struct RecordingAwsSecurityHubTransport {
    responses: VecDeque<Result<GetFindingsPage, AwsSecurityHubTransportError>>,
    requests: Vec<RecordedAwsSecurityHubRequest>,
    provenance: ProviderProvenance,
}

impl Default for RecordingAwsSecurityHubTransport {
    fn default() -> Self {
        Self::new(std::iter::empty())
    }
}

impl RecordingAwsSecurityHubTransport {
    pub fn new(
        responses: impl IntoIterator<Item = Result<GetFindingsPage, AwsSecurityHubTransportError>>,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: ProviderProvenance::Recording,
        }
    }

    pub fn fixture(
        responses: impl IntoIterator<Item = Result<GetFindingsPage, AwsSecurityHubTransportError>>,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: ProviderProvenance::Fixture,
        }
    }

    pub fn loopback(
        responses: impl IntoIterator<Item = Result<GetFindingsPage, AwsSecurityHubTransportError>>,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: ProviderProvenance::Loopback,
        }
    }

    #[must_use]
    pub fn with_provenance(mut self, provenance: ProviderProvenance) -> Self {
        self.provenance = provenance;
        self
    }

    pub fn push_response(
        &mut self,
        response: Result<GetFindingsPage, AwsSecurityHubTransportError>,
    ) {
        self.responses.push_back(response);
    }

    pub fn requests(&self) -> &[RecordedAwsSecurityHubRequest] {
        &self.requests
    }

    pub fn call_count(&self) -> usize {
        self.requests.len()
    }

    pub fn remaining_responses(&self) -> usize {
        self.responses.len()
    }

    fn execute(
        &mut self,
        request: &GetFindingsRequest,
        expected_api: GetFindingsApi,
    ) -> Result<GetFindingsPage, AwsSecurityHubTransportError> {
        if request.api() != expected_api {
            return Err(AwsSecurityHubTransportError::InvalidRequest(
                "transport operation and request API differ".to_owned(),
            ));
        }
        self.requests.push(request.into());
        self.responses
            .pop_front()
            .ok_or(AwsSecurityHubTransportError::QueueExhausted)?
    }
}

impl AwsSecurityHubTransport for RecordingAwsSecurityHubTransport {
    fn get_findings(
        &mut self,
        request: &GetFindingsRequest,
    ) -> Result<GetFindingsPage, AwsSecurityHubTransportError> {
        self.execute(request, GetFindingsApi::GetFindings)
    }

    fn get_findings_v2(
        &mut self,
        request: &GetFindingsRequest,
    ) -> Result<GetFindingsPage, AwsSecurityHubTransportError> {
        self.execute(request, GetFindingsApi::GetFindingsV2)
    }

    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }
}

pub type FakeAwsSecurityHubTransport = RecordingAwsSecurityHubTransport;
pub type FixtureAwsSecurityHubTransport = RecordingAwsSecurityHubTransport;
pub type RecordingTransport = RecordingAwsSecurityHubTransport;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvAwsSecurityHubTransport;

pub type BlockedEnvTransport = BlockedEnvAwsSecurityHubTransport;

impl AwsSecurityHubTransport for BlockedEnvAwsSecurityHubTransport {
    fn get_findings(
        &mut self,
        _request: &GetFindingsRequest,
    ) -> Result<GetFindingsPage, AwsSecurityHubTransportError> {
        Err(AwsSecurityHubTransportError::BlockedEnv)
    }

    fn get_findings_v2(
        &mut self,
        _request: &GetFindingsRequest,
    ) -> Result<GetFindingsPage, AwsSecurityHubTransportError> {
        Err(AwsSecurityHubTransportError::BlockedEnv)
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }
}

/// Deterministic loopback evidence. It proves only that the normalized seam
/// can be exercised; an empty result is not a native provider assertion.
#[derive(Clone, Copy, Debug, Default)]
pub struct LoopbackAwsSecurityHubTransport;

pub type LoopbackTransport = LoopbackAwsSecurityHubTransport;

impl LoopbackAwsSecurityHubTransport {
    fn empty_page(
        request: &GetFindingsRequest,
    ) -> Result<GetFindingsPage, AwsSecurityHubTransportError> {
        GetFindingsPage::new(request, Vec::new(), None, false, "loopback-securityhub-r1")
            .map_err(|error| AwsSecurityHubTransportError::InvalidRequest(error.to_string()))
    }
}

impl AwsSecurityHubTransport for LoopbackAwsSecurityHubTransport {
    fn get_findings(
        &mut self,
        request: &GetFindingsRequest,
    ) -> Result<GetFindingsPage, AwsSecurityHubTransportError> {
        if request.api() != GetFindingsApi::GetFindings {
            return Err(AwsSecurityHubTransportError::InvalidRequest(
                "loopback GetFindings request used the wrong API".to_owned(),
            ));
        }
        Self::empty_page(request)
    }

    fn get_findings_v2(
        &mut self,
        request: &GetFindingsRequest,
    ) -> Result<GetFindingsPage, AwsSecurityHubTransportError> {
        if request.api() != GetFindingsApi::GetFindingsV2 {
            return Err(AwsSecurityHubTransportError::InvalidRequest(
                "loopback GetFindingsV2 request used the wrong API".to_owned(),
            ));
        }
        Self::empty_page(request)
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Loopback
    }
}
