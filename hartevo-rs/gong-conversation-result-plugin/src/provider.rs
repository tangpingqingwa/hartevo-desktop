//! Gong public-API read provider and non-native transport seams.

use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    Digest, GONG_CONVERSATION_RESULT_PROVIDER_ID, GONG_CONVERSATION_RESULT_SCHEMA_VERSION,
    GONG_CONVERSATION_RESULT_SERVICE_ID, GONG_DAILY_REQUEST_LIMIT, GONG_MAX_PAGES,
    GONG_MAX_RESPONSE_BYTES, GONG_PAGE_SIZE, GONG_PROVIDER_REVISION, GONG_REQUESTS_PER_SECOND,
    GongReadRequest, GongReadResponse, PluginVersion, canonical_digest,
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
    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GongTransportError {
    #[error("BLOCKED_ENV: native Gong credential authority is unavailable")]
    BlockedEnv,
    #[error("Gong access was denied")]
    Unauthorized,
    #[error("Gong scope is forbidden")]
    Forbidden,
    #[error("Gong call or analysis is not retained")]
    RetentionGap,
    #[error("Gong resource was not found")]
    NotFound,
    #[error("Gong API rate limit exceeded; retry after {retry_after_seconds} seconds")]
    RateLimited { retry_after_seconds: u32 },
    #[error("Gong API daily request limit exceeded")]
    DailyLimit,
    #[error("Gong provider timed out")]
    Timeout,
    #[error("Gong provider returned a server failure")]
    ServerFailure { status: u16 },
    #[error("Gong provider returned an invalid normalized response")]
    InvalidResponse,
    #[error("Gong request was tampered with")]
    RequestTampered,
    #[error("Gong response duplicated an earlier request")]
    DuplicateRequest,
    #[error("Gong provider response exceeded the bounded response size")]
    ResponseTooLarge,
    #[error("Gong mutation is outside the Layer-1 provider allowlist")]
    MutationForbidden,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GongProviderError {
    #[error(transparent)]
    Transport(#[from] GongTransportError),
    #[error(transparent)]
    Model(#[from] crate::ModelError),
    #[error("Gong provider definition is invalid")]
    InvalidDefinition,
    #[error("Gong provider capability digest does not match the request")]
    CapabilityDrift,
    #[error("Gong request exceeded the Layer-1 per-second or daily budget")]
    BudgetExceeded,
    #[error("Gong request was duplicated")]
    DuplicateRequest,
    #[error("Gong response binding or digest is invalid")]
    InvalidResponseBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GongProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub service_id: String,
    pub version: PluginVersion,
    pub provider_version: String,
    pub implementation: String,
    pub capability_digest: Digest,
    pub provenance: TransportProvenance,
    pub allowlisted_operations: Vec<String>,
    pub read_only: bool,
    pub reversible: bool,
    pub revocable: bool,
    pub native: bool,
    pub connected: bool,
}

impl GongProviderDefinition {
    pub fn layer1(provenance: TransportProvenance) -> Result<Self, GongProviderError> {
        let mut definition = Self {
            schema_version: GONG_CONVERSATION_RESULT_SCHEMA_VERSION.to_owned(),
            provider_id: GONG_CONVERSATION_RESULT_PROVIDER_ID.to_owned(),
            service_id: GONG_CONVERSATION_RESULT_SERVICE_ID.to_owned(),
            version: PluginVersion::V1,
            provider_version: GONG_PROVIDER_REVISION.to_owned(),
            implementation: "GongProvider".to_owned(),
            capability_digest: Digest::parse(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )?,
            provenance,
            allowlisted_operations: allowlisted_operations(),
            read_only: true,
            reversible: true,
            revocable: true,
            native: false,
            connected: false,
        };
        definition.capability_digest = canonical_digest(&GongProviderCapabilityFingerprint {
            schema_version: &definition.schema_version,
            provider_id: &definition.provider_id,
            service_id: &definition.service_id,
            version: definition.version,
            provider_version: &definition.provider_version,
            implementation: &definition.implementation,
            provenance: definition.provenance,
            allowlisted_operations: &definition.allowlisted_operations,
            read_only: definition.read_only,
            native: definition.native,
            connected: definition.connected,
        });
        definition.validate()?;
        Ok(definition)
    }

    pub fn validate(&self) -> Result<(), GongProviderError> {
        if self.schema_version != GONG_CONVERSATION_RESULT_SCHEMA_VERSION
            || self.provider_id != GONG_CONVERSATION_RESULT_PROVIDER_ID
            || self.service_id != GONG_CONVERSATION_RESULT_SERVICE_ID
            || self.version != PluginVersion::V1
            || self.provider_version != GONG_PROVIDER_REVISION
            || self.implementation != "GongProvider"
            || self.allowlisted_operations != allowlisted_operations()
            || !self.read_only
            || !self.reversible
            || !self.revocable
            || self.native
            || self.connected
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.capability_digest != self.computed_capability_digest()
        {
            return Err(GongProviderError::InvalidDefinition);
        }
        Ok(())
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        canonical_digest(self)
    }

    fn computed_capability_digest(&self) -> Digest {
        canonical_digest(&GongProviderCapabilityFingerprint {
            schema_version: &self.schema_version,
            provider_id: &self.provider_id,
            service_id: &self.service_id,
            version: self.version,
            provider_version: &self.provider_version,
            implementation: &self.implementation,
            provenance: self.provenance,
            allowlisted_operations: &self.allowlisted_operations,
            read_only: self.read_only,
            native: self.native,
            connected: self.connected,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GongProviderCapabilityFingerprint<'a> {
    schema_version: &'a str,
    provider_id: &'a str,
    service_id: &'a str,
    version: PluginVersion,
    provider_version: &'a str,
    implementation: &'a str,
    provenance: TransportProvenance,
    allowlisted_operations: &'a [String],
    read_only: bool,
    native: bool,
    connected: bool,
}

fn allowlisted_operations() -> Vec<String> {
    [
        "call_metadata",
        "interaction_metrics",
        "topics_trackers",
        "action_item_counts",
        "scorecard_status",
        "external_crm_context_identifiers",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

#[derive(Clone, Debug, Default)]
struct RequestBudget {
    second: Option<u64>,
    second_count: u8,
    day: Option<u64>,
    day_count: u32,
}

impl RequestBudget {
    fn admit(&mut self, epoch_seconds: u64) -> Result<(), GongProviderError> {
        let day = epoch_seconds / 86_400;
        if self.day != Some(day) {
            self.day = Some(day);
            self.day_count = 0;
        }
        if self.day_count >= GONG_DAILY_REQUEST_LIMIT {
            return Err(GongProviderError::BudgetExceeded);
        }
        if self.second != Some(epoch_seconds) {
            self.second = Some(epoch_seconds);
            self.second_count = 0;
        }
        if self.second_count >= GONG_REQUESTS_PER_SECOND {
            return Err(GongProviderError::BudgetExceeded);
        }
        self.second_count = self.second_count.saturating_add(1);
        self.day_count = self.day_count.saturating_add(1);
        Ok(())
    }
}

pub trait GongTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn read(&mut self, request: &GongReadRequest) -> Result<GongReadResponse, GongTransportError>;
}

#[derive(Debug)]
pub struct GongProvider<T = BlockedEnvTransport>
where
    T: GongTransport,
{
    transport: T,
    definition: GongProviderDefinition,
    budget: RequestBudget,
    seen_request_digests: BTreeSet<Digest>,
}

impl<T> GongProvider<T>
where
    T: GongTransport,
{
    pub fn new(transport: T) -> Result<Self, GongProviderError> {
        let definition = GongProviderDefinition::layer1(transport.provenance())?;
        Ok(Self {
            transport,
            definition,
            budget: RequestBudget::default(),
            seen_request_digests: BTreeSet::new(),
        })
    }

    pub fn with_definition(
        transport: T,
        definition: GongProviderDefinition,
    ) -> Result<Self, GongProviderError> {
        definition.validate()?;
        if definition.provenance != transport.provenance() {
            return Err(GongProviderError::InvalidDefinition);
        }
        Ok(Self {
            transport,
            definition,
            budget: RequestBudget::default(),
            seen_request_digests: BTreeSet::new(),
        })
    }

    #[must_use]
    pub fn definition(&self) -> &GongProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provenance(&self) -> TransportProvenance {
        self.definition.provenance
    }

    #[must_use]
    pub const fn is_native(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_connected(&self) -> bool {
        false
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    #[must_use]
    pub fn requests_seen(&self) -> usize {
        self.seen_request_digests.len()
    }

    pub fn read(
        &mut self,
        request: &GongReadRequest,
    ) -> Result<GongReadResponse, GongProviderError> {
        self.definition.validate()?;
        validate_request_shape(request)?;
        if request.provider_capability_digest != self.definition.capability_digest {
            return Err(GongProviderError::CapabilityDrift);
        }
        if !self
            .seen_request_digests
            .insert(request.request_digest.clone())
        {
            return Err(GongProviderError::DuplicateRequest);
        }
        self.budget.admit(request.requested_at_epoch_seconds)?;
        let response = self.transport.read(request)?;
        if response
            .validate_request_binding(request, GONG_PROVIDER_REVISION)
            .is_err()
        {
            return Err(GongProviderError::InvalidResponseBinding);
        }
        Ok(response)
    }
}

fn validate_request_shape(request: &GongReadRequest) -> Result<(), GongProviderError> {
    if request.page == 0
        || request.page > GONG_MAX_PAGES
        || request.page_size != GONG_PAGE_SIZE
        || request.max_response_bytes == 0
        || request.max_response_bytes > GONG_MAX_RESPONSE_BYTES
        || request.request_digest != request.integrity_digest()
        || request.operation.as_str().is_empty()
        || request.endpoint_path().is_empty()
    {
        return Err(GongProviderError::Transport(
            GongTransportError::RequestTampered,
        ));
    }
    if let Some(window) = &request.date_window {
        window.validate()?;
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct RecordingGongTransport {
    provenance: TransportProvenance,
    responses: VecDeque<Result<GongReadResponse, GongTransportError>>,
    requests: Vec<GongReadRequest>,
}

impl RecordingGongTransport {
    pub fn new(
        provenance: TransportProvenance,
        responses: impl IntoIterator<Item = Result<GongReadResponse, GongTransportError>>,
    ) -> Self {
        Self {
            provenance,
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        }
    }

    pub fn fixture(
        responses: impl IntoIterator<Item = Result<GongReadResponse, GongTransportError>>,
    ) -> Self {
        Self::new(TransportProvenance::Fixture, responses)
    }

    pub fn recording(
        responses: impl IntoIterator<Item = Result<GongReadResponse, GongTransportError>>,
    ) -> Self {
        Self::new(TransportProvenance::Recording, responses)
    }

    #[must_use]
    pub fn requests(&self) -> &[GongReadRequest] {
        &self.requests
    }
}

impl GongTransport for RecordingGongTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn read(&mut self, request: &GongReadRequest) -> Result<GongReadResponse, GongTransportError> {
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .unwrap_or(Err(GongTransportError::InvalidResponse))
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackGongTransport {
    inner: RecordingGongTransport,
}

impl LoopbackGongTransport {
    pub fn new(
        responses: impl IntoIterator<Item = Result<GongReadResponse, GongTransportError>>,
    ) -> Self {
        Self {
            inner: RecordingGongTransport::new(TransportProvenance::Loopback, responses),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[GongReadRequest] {
        self.inner.requests()
    }
}

impl GongTransport for LoopbackGongTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn read(&mut self, request: &GongReadRequest) -> Result<GongReadResponse, GongTransportError> {
        self.inner.read(request)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl GongTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read(&mut self, _request: &GongReadRequest) -> Result<GongReadResponse, GongTransportError> {
        Err(GongTransportError::BlockedEnv)
    }
}

pub type FakeGongTransport = RecordingGongTransport;
