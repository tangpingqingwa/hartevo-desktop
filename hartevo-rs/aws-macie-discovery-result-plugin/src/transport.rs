//! Non-native Macie transport seams for Layer 1.
//!
//! Transports operate only on normalized requests and pages. They accept no
//! secret, resolve no credential, and expose no raw provider JSON.

use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    AccessLossKind, GetFindingsPage, GetFindingsRequest, ListFindingsPage, ListFindingsRequest,
    MacieApiOperation, ProviderProvenance,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MacieTransportError {
    #[error("BLOCKED_ENV: native Macie transport is unavailable")]
    BlockedEnv,
    #[error("Macie access was denied")]
    AccessDenied,
    #[error("the host did not provide a credential lease")]
    CredentialUnavailable,
    #[error("Macie provider is unavailable")]
    ProviderUnavailable,
    #[error("Macie request was throttled")]
    Throttled,
    #[error("Macie returned an unknown provider response")]
    ProviderUnknown,
    #[error("invalid normalized Macie transport request: {0}")]
    InvalidRequest(String),
    #[error("recording transport response queue is exhausted")]
    QueueExhausted,
}

impl MacieTransportError {
    pub const fn access_loss_kind(&self) -> Option<AccessLossKind> {
        match self {
            Self::BlockedEnv => Some(AccessLossKind::BlockedEnv),
            Self::AccessDenied => Some(AccessLossKind::AccessDenied),
            Self::CredentialUnavailable => Some(AccessLossKind::CredentialUnavailable),
            Self::ProviderUnavailable => Some(AccessLossKind::ProviderUnavailable),
            Self::Throttled => Some(AccessLossKind::Throttled),
            Self::ProviderUnknown | Self::InvalidRequest(_) | Self::QueueExhausted => None,
        }
    }

    pub const fn provider_code(&self) -> &'static str {
        match self {
            Self::BlockedEnv => "BLOCKED_ENV",
            Self::AccessDenied => "ACCESS_DENIED",
            Self::CredentialUnavailable => "CREDENTIAL_UNAVAILABLE",
            Self::ProviderUnavailable => "PROVIDER_UNAVAILABLE",
            Self::Throttled => "THROTTLED",
            Self::ProviderUnknown => "PROVIDER_UNKNOWN",
            Self::InvalidRequest(_) => "INVALID_REQUEST",
            Self::QueueExhausted => "QUEUE_EXHAUSTED",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedMacieRequest {
    pub operation: MacieApiOperation,
    pub scope_digest: crate::model::Digest,
    pub filter_digest: crate::model::Digest,
    pub page_number: u16,
    pub page_size: u16,
    pub page_token_digest: Option<crate::model::Digest>,
    pub finding_allowlist_digest: Option<crate::model::Digest>,
    pub finding_count: usize,
    pub request_digest: crate::model::Digest,
}

impl From<&ListFindingsRequest> for RecordedMacieRequest {
    fn from(request: &ListFindingsRequest) -> Self {
        let binding = request.binding();
        Self {
            operation: binding.operation,
            scope_digest: binding.scope_digest,
            filter_digest: binding.filter_digest,
            page_number: binding.page_number,
            page_size: binding.page_size,
            page_token_digest: binding.page_token_digest,
            finding_allowlist_digest: None,
            finding_count: 0,
            request_digest: binding.request_digest,
        }
    }
}

impl From<&GetFindingsRequest> for RecordedMacieRequest {
    fn from(request: &GetFindingsRequest) -> Self {
        let binding = request.binding();
        Self {
            operation: binding.operation,
            scope_digest: binding.scope_digest,
            filter_digest: binding.filter_digest,
            page_number: binding.page_number,
            page_size: binding.page_size,
            page_token_digest: None,
            finding_allowlist_digest: binding.finding_allowlist_digest,
            finding_count: request.finding_ids().len(),
            request_digest: binding.request_digest,
        }
    }
}

pub trait MacieTransport: fmt::Debug {
    fn list_findings(
        &mut self,
        request: &ListFindingsRequest,
    ) -> Result<ListFindingsPage, MacieTransportError>;

    fn get_findings(
        &mut self,
        request: &GetFindingsRequest,
    ) -> Result<GetFindingsPage, MacieTransportError>;

    fn provenance(&self) -> ProviderProvenance;

    fn is_native(&self) -> bool {
        false
    }

    fn is_connected(&self) -> bool {
        false
    }

    fn is_first_party(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug)]
pub struct RecordingMacieTransport {
    list_responses: VecDeque<Result<ListFindingsPage, MacieTransportError>>,
    get_responses: VecDeque<Result<GetFindingsPage, MacieTransportError>>,
    requests: Vec<RecordedMacieRequest>,
    provenance: ProviderProvenance,
}

impl Default for RecordingMacieTransport {
    fn default() -> Self {
        Self::new(std::iter::empty(), std::iter::empty())
    }
}

impl RecordingMacieTransport {
    pub fn new(
        list_responses: impl IntoIterator<Item = Result<ListFindingsPage, MacieTransportError>>,
        get_responses: impl IntoIterator<Item = Result<GetFindingsPage, MacieTransportError>>,
    ) -> Self {
        Self {
            list_responses: list_responses.into_iter().collect(),
            get_responses: get_responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: ProviderProvenance::Recording,
        }
    }

    pub fn fixture(
        list_responses: impl IntoIterator<Item = Result<ListFindingsPage, MacieTransportError>>,
        get_responses: impl IntoIterator<Item = Result<GetFindingsPage, MacieTransportError>>,
    ) -> Self {
        Self {
            list_responses: list_responses.into_iter().collect(),
            get_responses: get_responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: ProviderProvenance::Fixture,
        }
    }

    pub fn loopback(
        list_responses: impl IntoIterator<Item = Result<ListFindingsPage, MacieTransportError>>,
        get_responses: impl IntoIterator<Item = Result<GetFindingsPage, MacieTransportError>>,
    ) -> Self {
        Self {
            list_responses: list_responses.into_iter().collect(),
            get_responses: get_responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: ProviderProvenance::Loopback,
        }
    }

    #[must_use]
    pub fn with_provenance(mut self, provenance: ProviderProvenance) -> Self {
        self.provenance = provenance;
        self
    }

    pub fn push_list_response(&mut self, response: Result<ListFindingsPage, MacieTransportError>) {
        self.list_responses.push_back(response);
    }

    pub fn push_get_response(&mut self, response: Result<GetFindingsPage, MacieTransportError>) {
        self.get_responses.push_back(response);
    }

    pub fn requests(&self) -> &[RecordedMacieRequest] {
        &self.requests
    }

    pub fn call_count(&self) -> usize {
        self.requests.len()
    }

    pub fn remaining_list_responses(&self) -> usize {
        self.list_responses.len()
    }

    pub fn remaining_get_responses(&self) -> usize {
        self.get_responses.len()
    }

    fn execute_list(
        &mut self,
        request: &ListFindingsRequest,
    ) -> Result<ListFindingsPage, MacieTransportError> {
        self.requests.push(request.into());
        self.list_responses
            .pop_front()
            .ok_or(MacieTransportError::QueueExhausted)?
    }

    fn execute_get(
        &mut self,
        request: &GetFindingsRequest,
    ) -> Result<GetFindingsPage, MacieTransportError> {
        self.requests.push(request.into());
        self.get_responses
            .pop_front()
            .ok_or(MacieTransportError::QueueExhausted)?
    }
}

impl MacieTransport for RecordingMacieTransport {
    fn list_findings(
        &mut self,
        request: &ListFindingsRequest,
    ) -> Result<ListFindingsPage, MacieTransportError> {
        self.execute_list(request)
    }

    fn get_findings(
        &mut self,
        request: &GetFindingsRequest,
    ) -> Result<GetFindingsPage, MacieTransportError> {
        self.execute_get(request)
    }

    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }
}

pub type FakeMacieTransport = RecordingMacieTransport;
pub type FixtureMacieTransport = RecordingMacieTransport;
pub type RecordingTransport = RecordingMacieTransport;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvMacieTransport;

pub type BlockedEnvTransport = BlockedEnvMacieTransport;

impl MacieTransport for BlockedEnvMacieTransport {
    fn list_findings(
        &mut self,
        _request: &ListFindingsRequest,
    ) -> Result<ListFindingsPage, MacieTransportError> {
        Err(MacieTransportError::BlockedEnv)
    }

    fn get_findings(
        &mut self,
        _request: &GetFindingsRequest,
    ) -> Result<GetFindingsPage, MacieTransportError> {
        Err(MacieTransportError::BlockedEnv)
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }
}

/// Deterministic empty loopback evidence. It proves only that the normalized
/// request/response seam can be exercised.
#[derive(Clone, Copy, Debug, Default)]
pub struct LoopbackMacieTransport;

pub type LoopbackTransport = LoopbackMacieTransport;

impl MacieTransport for LoopbackMacieTransport {
    fn list_findings(
        &mut self,
        request: &ListFindingsRequest,
    ) -> Result<ListFindingsPage, MacieTransportError> {
        ListFindingsPage::new(
            request,
            crate::model::FindingIdAllowlist::empty(),
            None,
            false,
            crate::AWS_MACIE_PROVIDER_REVISION,
        )
        .map_err(|error| MacieTransportError::InvalidRequest(error.to_string()))
    }

    fn get_findings(
        &mut self,
        request: &GetFindingsRequest,
    ) -> Result<GetFindingsPage, MacieTransportError> {
        GetFindingsPage::new(
            request,
            Vec::new(),
            false,
            crate::AWS_MACIE_PROVIDER_REVISION,
        )
        .map_err(|error| MacieTransportError::InvalidRequest(error.to_string()))
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Loopback
    }
}
