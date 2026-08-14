//! Deterministic Layer-1 transport seams.
//!
//! There is deliberately no native HTTP client in this root.  The transport
//! request contains only fixed endpoint identities and digests; it has no
//! authentication header, token, lease id, or raw request body.

use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::VAULT_GOVERNANCE_RESULT_PROVIDER_REVISION;
use crate::model::{
    CapabilityClass, Digest, PolicyClass, ProviderProvenance, VaultCapabilityMetadata,
    VaultHealthMetadata, VaultLeaseMetadata, VaultOperation, VaultResponsePayload, VaultScope,
    VaultTokenSelfMetadata, digest_serializable, mount_digest, response_digest,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum VaultTransportError {
    #[error("BLOCKED_ENV: native Vault authentication and HTTPS authority are unavailable")]
    BlockedEnv,
    #[error("Vault transport timed out")]
    Timeout,
    #[error("Vault provider is unknown to the Layer-1 adapter")]
    ProviderUnknown,
    #[error("Vault request is invalid")]
    InvalidRequest,
    #[error("Vault response could not be decoded")]
    Decode,
    #[error("Vault transport failed")]
    Transport,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultEndpoint {
    SysHealth,
    AuthTokenLookupSelf,
    SysCapabilitiesSelf { path_digests: Vec<Digest> },
    SysLeasesLookup { lease_digest: Digest },
}

impl VaultEndpoint {
    pub const fn operation(&self) -> VaultOperation {
        match self {
            Self::SysHealth => VaultOperation::SysHealth,
            Self::AuthTokenLookupSelf => VaultOperation::AuthTokenLookupSelf,
            Self::SysCapabilitiesSelf { .. } => VaultOperation::SysCapabilitiesSelfAllowlisted,
            Self::SysLeasesLookup { .. } => VaultOperation::SysLeasesLookupMetadata,
        }
    }

    pub const fn api_path(&self) -> &'static str {
        match self {
            Self::SysHealth => "/v1/sys/health",
            Self::AuthTokenLookupSelf => "/v1/auth/token/lookup-self",
            Self::SysCapabilitiesSelf { .. } => "/v1/sys/capabilities-self",
            Self::SysLeasesLookup { .. } => "/v1/sys/leases/lookup",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultRequest {
    endpoint: VaultEndpoint,
    namespace_digest: Digest,
    mount_digest: Digest,
    scope_digest: Digest,
    request_digest: Digest,
}

impl VaultRequest {
    pub(crate) fn new(scope: &VaultScope, endpoint: VaultEndpoint) -> Self {
        let request_digest = digest_serializable(&(
            &endpoint,
            scope.namespace().as_str(),
            mount_digest(scope.mount()),
            scope.scope_digest(),
        ));
        Self {
            endpoint,
            namespace_digest: Digest::from_text(scope.namespace().as_str()),
            mount_digest: mount_digest(scope.mount()),
            scope_digest: scope.scope_digest(),
            request_digest,
        }
    }

    pub fn endpoint(&self) -> &VaultEndpoint {
        &self.endpoint
    }

    pub fn operation(&self) -> VaultOperation {
        self.endpoint.operation()
    }

    pub fn api_path(&self) -> &'static str {
        self.endpoint.api_path()
    }

    pub fn namespace_digest(&self) -> &Digest {
        &self.namespace_digest
    }

    pub fn mount_digest(&self) -> &Digest {
        &self.mount_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultHttpResponse {
    operation: VaultOperation,
    request_digest: Digest,
    status: u16,
    response_size: usize,
    provider_revision: String,
    payload: VaultResponsePayload,
    response_digest: Digest,
}

impl VaultHttpResponse {
    pub fn new(
        operation: VaultOperation,
        status: u16,
        response_size: usize,
        provider_revision: impl Into<String>,
        payload: VaultResponsePayload,
    ) -> Result<Self, VaultTransportError> {
        let provider_revision = provider_revision.into();
        if provider_revision.is_empty() {
            return Err(VaultTransportError::InvalidRequest);
        }
        let response_digest = response_digest(operation, status, &payload);
        Ok(Self {
            operation,
            request_digest: Digest::zero(),
            status,
            response_size,
            provider_revision,
            payload,
            response_digest,
        })
    }

    pub fn for_request(
        request: &VaultRequest,
        status: u16,
        response_size: usize,
        provider_revision: impl Into<String>,
        payload: VaultResponsePayload,
    ) -> Result<Self, VaultTransportError> {
        let mut response = Self::new(
            request.operation(),
            status,
            response_size,
            provider_revision,
            payload,
        )?;
        response.request_digest = request.request_digest().clone();
        Ok(response)
    }

    #[must_use]
    pub fn bound_to(mut self, request_digest: Digest) -> Self {
        self.request_digest = request_digest;
        self
    }

    pub fn operation(&self) -> VaultOperation {
        self.operation
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub const fn status(&self) -> u16 {
        self.status
    }

    pub const fn response_size(&self) -> usize {
        self.response_size
    }

    pub fn provider_revision(&self) -> &str {
        &self.provider_revision
    }

    pub fn payload(&self) -> &VaultResponsePayload {
        &self.payload
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }
}

/// A Layer-1 provider can only use one of these deterministic seams.  A host
/// may supply a future native adapter behind a later layer without changing
/// this contract or making BLOCKED_ENV look connected.
pub trait VaultTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;

    fn execute(&mut self, request: &VaultRequest)
    -> Result<VaultHttpResponse, VaultTransportError>;
}

fn deterministic_fixture_response(
    request: &VaultRequest,
) -> Result<VaultHttpResponse, VaultTransportError> {
    let payload = match request.endpoint() {
        VaultEndpoint::SysHealth => VaultResponsePayload::Health(VaultHealthMetadata::default()),
        VaultEndpoint::AuthTokenLookupSelf => VaultResponsePayload::TokenSelf(
            VaultTokenSelfMetadata::new(
                Digest::from_text("fixture-token"),
                Digest::from_text("fixture-accessor"),
                Some(Digest::from_text("fixture-entity")),
                3_600,
                true,
                vec![PolicyClass::Default, PolicyClass::ReadOnly],
            )
            .map_err(|_error| VaultTransportError::Decode)?,
        ),
        VaultEndpoint::SysCapabilitiesSelf { path_digests } => {
            let entries = path_digests
                .iter()
                .cloned()
                .map(|path_digest| {
                    VaultCapabilityMetadata::new(
                        path_digest,
                        vec![CapabilityClass::Read, CapabilityClass::List],
                    )
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_error| VaultTransportError::Decode)?;
            VaultResponsePayload::CapabilitiesSelf(entries)
        }
        VaultEndpoint::SysLeasesLookup { lease_digest } => {
            VaultResponsePayload::LeaseLookup(VaultLeaseMetadata::new(
                lease_digest.clone(),
                request.mount_digest().clone(),
                Digest::from_text("fixture-lease-path"),
                1_800,
                true,
            ))
        }
    };
    VaultHttpResponse::for_request(
        request,
        200,
        512,
        VAULT_GOVERNANCE_RESULT_PROVIDER_REVISION,
        payload,
    )
}

#[derive(Clone, Debug, Default)]
pub struct FixtureVaultTransport {
    scripted: VecDeque<Result<VaultHttpResponse, VaultTransportError>>,
    requests: Vec<VaultRequest>,
}

impl FixtureVaultTransport {
    pub fn push_response(&mut self, response: VaultHttpResponse) {
        self.scripted.push_back(Ok(response));
    }

    pub fn push_error(&mut self, error: VaultTransportError) {
        self.scripted.push_back(Err(error));
    }

    pub fn requests(&self) -> &[VaultRequest] {
        &self.requests
    }
}

impl VaultTransport for FixtureVaultTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fixture
    }

    fn execute(
        &mut self,
        request: &VaultRequest,
    ) -> Result<VaultHttpResponse, VaultTransportError> {
        self.requests.push(request.clone());
        match self.scripted.pop_front() {
            Some(response) => response,
            None => deterministic_fixture_response(request),
        }
    }
}

/// Backwards-compatible name for deterministic fixture tests.
pub type FakeVaultTransport = FixtureVaultTransport;

#[derive(Clone, Debug, Default)]
pub struct RecordingVaultTransport {
    scripted: VecDeque<Result<VaultHttpResponse, VaultTransportError>>,
    requests: Vec<VaultRequest>,
}

impl RecordingVaultTransport {
    pub fn push_response(&mut self, response: VaultHttpResponse) {
        self.scripted.push_back(Ok(response));
    }

    pub fn push_error(&mut self, error: VaultTransportError) {
        self.scripted.push_back(Err(error));
    }

    pub fn requests(&self) -> &[VaultRequest] {
        &self.requests
    }
}

impl VaultTransport for RecordingVaultTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Recording
    }

    fn execute(
        &mut self,
        request: &VaultRequest,
    ) -> Result<VaultHttpResponse, VaultTransportError> {
        self.requests.push(request.clone());
        match self.scripted.pop_front() {
            Some(response) => response,
            None => deterministic_fixture_response(request),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct LoopbackVaultTransport {
    scripted: VecDeque<Result<VaultHttpResponse, VaultTransportError>>,
    requests: Vec<VaultRequest>,
}

impl LoopbackVaultTransport {
    pub fn push_response(&mut self, response: VaultHttpResponse) {
        self.scripted.push_back(Ok(response));
    }

    pub fn push_error(&mut self, error: VaultTransportError) {
        self.scripted.push_back(Err(error));
    }

    pub fn requests(&self) -> &[VaultRequest] {
        &self.requests
    }
}

impl VaultTransport for LoopbackVaultTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Loopback
    }

    fn execute(
        &mut self,
        request: &VaultRequest,
    ) -> Result<VaultHttpResponse, VaultTransportError> {
        self.requests.push(request.clone());
        match self.scripted.pop_front() {
            Some(response) => response,
            None => deterministic_fixture_response(request),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvVaultTransport;

impl VaultTransport for BlockedEnvVaultTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &VaultRequest,
    ) -> Result<VaultHttpResponse, VaultTransportError> {
        Err(VaultTransportError::BlockedEnv)
    }
}

pub type BlockedEnvTransport = BlockedEnvVaultTransport;
