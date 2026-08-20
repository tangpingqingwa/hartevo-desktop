use std::{collections::VecDeque, fmt};

use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::error::{RedisCloudDatabaseResultError, RedisCloudTransportError, Result};
use crate::model::{
    CostReceipt, Digest, OpaquePageToken, PageInfo, ProviderProvenance, RedisCloudDatabasePosture,
    RedisCloudDatabaseScope, RedisCloudResponsePayload, RedisCloudSubscriptionPosture,
    RequestReceipt,
};
use crate::{
    API_REVISION, MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES, PROVIDER_ID,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum RedisCloudOperation {
    GetAccount,
    GetSubscription,
    GetDatabase,
}

impl RedisCloudOperation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetAccount => "GetAccount",
            Self::GetSubscription => "GetSubscription",
            Self::GetDatabase => "GetDatabase",
        }
    }
    #[must_use]
    pub const fn path_template(self) -> &'static str {
        match self {
            Self::GetAccount => "GET /account",
            Self::GetSubscription => "GET /subscriptions/{subscriptionId}",
            Self::GetDatabase => "GET /subscriptions/{subscriptionId}/databases/{databaseId}",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisCloudReadRequest {
    pub operation: RedisCloudOperation,
    pub scope_digest: Digest,
    pub page_size: u16,
    pub page_number: u16,
    pub cursor: Option<OpaquePageToken>,
    pub request_digest: Digest,
    pub path_digest: Digest,
}

impl RedisCloudReadRequest {
    pub fn new(
        scope: &RedisCloudDatabaseScope,
        operation: RedisCloudOperation,
        page_size: u16,
        cursor: Option<OpaquePageToken>,
    ) -> Result<Self> {
        scope.validate()?;
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(RedisCloudDatabaseResultError::PaginationRejected);
        }
        let page_number = cursor.as_ref().map_or(1, |value| value.page_number);
        if page_number == 0 || page_number > MAX_PAGES {
            return Err(RedisCloudDatabaseResultError::PaginationRejected);
        }
        if let Some(cursor) = cursor.as_ref() {
            cursor.validate(scope, operation.as_str())?;
        }
        let scope_digest = scope.digest();
        let path_digest = Digest::from_parts(
            "redis-cloud-request-path/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                ("template", operation.path_template().to_owned()),
            ],
        );
        let request_digest = Digest::from_parts(
            "redis-cloud-read-request/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                ("scope", scope_digest.as_str().to_owned()),
                ("page_size", page_size.to_string()),
                ("page_number", page_number.to_string()),
                (
                    "cursor",
                    cursor
                        .as_ref()
                        .map_or_else(String::new, |value| value.token_digest.as_str().to_owned()),
                ),
                ("path", path_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            operation,
            scope_digest,
            page_size,
            page_number,
            cursor,
            request_digest,
            path_digest,
        })
    }

    pub fn first(scope: &RedisCloudDatabaseScope, operation: RedisCloudOperation) -> Result<Self> {
        Self::new(scope, operation, 1, None)
    }
    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }
    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
    #[must_use]
    pub fn path_digest(&self) -> &Digest {
        &self.path_digest
    }
    #[must_use]
    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn recorded_request(&self) -> Result<RequestReceipt> {
        RequestReceipt::new(
            self.operation.as_str(),
            self.request_digest.clone(),
            self.path_digest.clone(),
            self.scope_digest.clone(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisCloudResponse {
    pub operation: RedisCloudOperation,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub payload: RedisCloudResponsePayload,
    pub response_bytes: u64,
    pub response_digest: Digest,
    pub page: PageInfo,
    pub provenance: ProviderProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub request_receipt: RequestReceipt,
    pub cost_receipt: CostReceipt,
}

impl RedisCloudResponse {
    pub fn new(
        request: &RedisCloudReadRequest,
        payload: RedisCloudResponsePayload,
        response_bytes: u64,
        response_digest: Digest,
        provenance: ProviderProvenance,
    ) -> Result<Self> {
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(RedisCloudDatabaseResultError::TruncatedEvidence);
        }
        response_digest.validate()?;
        let response = Self {
            operation: request.operation,
            scope_digest: request.scope_digest.clone(),
            request_digest: request.request_digest.clone(),
            payload,
            response_bytes,
            response_digest,
            page: PageInfo::first(request.page_size)?,
            provenance,
            evidence_digest: Digest::from_text("unsealed-redis-cloud-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            request_receipt: request.recorded_request()?,
            cost_receipt: CostReceipt::new(request.operation.as_str(), response_bytes)?,
        };
        let mut response = response;
        response.evidence_digest = response.calculate_evidence_digest();
        Ok(response)
    }

    pub fn from_raw_response(
        request: &RedisCloudReadRequest,
        payload: RedisCloudResponsePayload,
        raw_response: impl AsRef<[u8]>,
        provenance: ProviderProvenance,
    ) -> Result<Self> {
        let raw = raw_response.as_ref();
        if raw.len() > MAX_RESPONSE_BYTES as usize {
            return Err(RedisCloudDatabaseResultError::TruncatedEvidence);
        }
        Self::new(
            request,
            payload,
            raw.len() as u64,
            Digest::from_bytes(raw),
            provenance,
        )
    }

    pub fn account(
        request: &RedisCloudReadRequest,
        scope: &RedisCloudDatabaseScope,
        raw_response: impl AsRef<[u8]>,
        provenance: ProviderProvenance,
    ) -> Result<Self> {
        Self::from_raw_response(
            request,
            RedisCloudResponsePayload::Account {
                account_digest: scope.account().digest(),
            },
            raw_response,
            provenance,
        )
    }
    pub fn subscription(
        request: &RedisCloudReadRequest,
        posture: RedisCloudSubscriptionPosture,
        raw_response: impl AsRef<[u8]>,
        provenance: ProviderProvenance,
    ) -> Result<Self> {
        Self::from_raw_response(
            request,
            RedisCloudResponsePayload::Subscription(posture),
            raw_response,
            provenance,
        )
    }
    pub fn database(
        request: &RedisCloudReadRequest,
        posture: RedisCloudDatabasePosture,
        raw_response: impl AsRef<[u8]>,
        provenance: ProviderProvenance,
    ) -> Result<Self> {
        Self::from_raw_response(
            request,
            RedisCloudResponsePayload::Database(posture),
            raw_response,
            provenance,
        )
    }

    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }
    pub fn with_next_cursor(mut self, cursor: OpaquePageToken) -> Self {
        self.page.next_cursor = Some(cursor);
        self.evidence_digest = self.calculate_evidence_digest();
        self
    }
    pub fn with_truncated(mut self, truncated: bool) -> Self {
        self.page.truncated = truncated;
        self.evidence_digest = self.calculate_evidence_digest();
        self
    }

    pub(crate) fn validate_integrity(
        &self,
        request: &RedisCloudReadRequest,
        scope: &RedisCloudDatabaseScope,
    ) -> Result<()> {
        if self.operation != request.operation
            || self.scope_digest != request.scope_digest
            || self.request_digest != request.request_digest
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.provenance.is_first_party()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.response_digest.validate().is_err()
            || self.evidence_digest != self.calculate_evidence_digest()
        {
            return Err(RedisCloudDatabaseResultError::TamperedEvidence);
        }
        match (request.operation, &self.payload) {
            (RedisCloudOperation::GetAccount, RedisCloudResponsePayload::Account { .. })
            | (RedisCloudOperation::GetSubscription, RedisCloudResponsePayload::Subscription(_))
            | (RedisCloudOperation::GetDatabase, RedisCloudResponsePayload::Database(_)) => {}
            _ => return Err(RedisCloudDatabaseResultError::TamperedEvidence),
        }
        if self.page.page_number != request.page_number {
            return Err(RedisCloudDatabaseResultError::PaginationRejected);
        }
        self.page.validate(scope, request.operation.as_str())?;
        self.payload.validate_against(scope)?;
        self.request_receipt.validate(scope)?;
        if self.request_receipt.operation != request.operation.as_str()
            || self.request_receipt.request_digest != request.request_digest
            || self.request_receipt.path_digest != request.path_digest
        {
            return Err(RedisCloudDatabaseResultError::TamperedEvidence);
        }
        self.cost_receipt.validate()?;
        if self.cost_receipt.operation != request.operation.as_str()
            || self.cost_receipt.response_bytes != self.response_bytes
        {
            return Err(RedisCloudDatabaseResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_evidence_digest(&self) -> Digest {
        Digest::from_parts(
            "redis-cloud-response-evidence/v1",
            &[
                ("operation", self.operation.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("payload", format!("{:?}", self.payload)),
                ("response", self.response_digest.as_str().to_owned()),
                ("bytes", self.response_bytes.to_string()),
                ("page", format!("{:?}", self.page)),
                ("provenance", self.provenance.as_str().to_owned()),
                (
                    "request_receipt",
                    self.request_receipt.request_digest.as_str().to_owned(),
                ),
                (
                    "cost_receipt",
                    self.cost_receipt.cost_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedisCloudProviderDefinition {
    provider_id: String,
    provider_revision: u64,
    release: String,
    provider_digest: Digest,
    api_digest: Digest,
    provenance: ProviderProvenance,
}

impl RedisCloudProviderDefinition {
    pub fn new(
        provider_revision: u64,
        release: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self> {
        let release = release.into();
        if provider_revision == 0 || release.is_empty() || release.len() > MAX_IDENTIFIER_BYTES {
            return Err(RedisCloudDatabaseResultError::ProviderDrift);
        }
        let definition = Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            release,
            provider_digest: Digest::from_text("unsealed-redis-cloud-provider"),
            api_digest: Digest::from_text(API_REVISION),
            provenance,
        };
        let mut definition = definition;
        definition.provider_digest = definition.calculate_provider_digest();
        definition.validate()?;
        Ok(definition)
    }

    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }
    #[must_use]
    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }
    #[must_use]
    pub fn release(&self) -> &str {
        &self.release
    }
    #[must_use]
    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }
    #[must_use]
    pub fn api_digest(&self) -> &Digest {
        &self.api_digest
    }
    #[must_use]
    pub const fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    fn calculate_provider_digest(&self) -> Digest {
        Digest::from_parts(
            "redis-cloud-provider-definition/v1",
            &[
                ("id", self.provider_id.clone()),
                ("revision", self.provider_revision.to_string()),
                ("release", self.release.clone()),
                ("api", API_REVISION.to_owned()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.release.is_empty()
            || self.release.len() > MAX_IDENTIFIER_BYTES
            || self.api_digest != Digest::from_text(API_REVISION)
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.provenance.is_first_party()
            || self.provider_digest != self.calculate_provider_digest()
        {
            return Err(RedisCloudDatabaseResultError::ProviderDrift);
        }
        self.provider_digest.validate()
    }
}

impl Serialize for RedisCloudProviderDefinition {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("RedisCloudProviderDefinition", 7)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("release", &self.release)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("apiRevision", &API_REVISION)?;
        state.serialize_field("provenance", &self.provenance)?;
        state.end()
    }
}

pub trait RedisCloudTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;
    fn execute(
        &mut self,
        request: &RedisCloudReadRequest,
    ) -> std::result::Result<RedisCloudResponse, RedisCloudTransportError>;
}

pub struct RedisCloudProvider<T> {
    transport: T,
    definition: RedisCloudProviderDefinition,
}

impl<T: RedisCloudTransport> fmt::Debug for RedisCloudProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisCloudProvider")
            .field("definition", &self.definition)
            .field("transport_provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: RedisCloudTransport> RedisCloudProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_identity(transport, 1, "layer1-recording")
    }

    pub fn with_identity(
        transport: T,
        provider_revision: u64,
        release: impl Into<String>,
    ) -> Result<Self> {
        let definition =
            RedisCloudProviderDefinition::new(provider_revision, release, transport.provenance())?;
        Ok(Self {
            transport,
            definition,
        })
    }
    #[must_use]
    pub fn definition(&self) -> &RedisCloudProviderDefinition {
        &self.definition
    }
    #[must_use]
    pub const fn provenance(&self) -> ProviderProvenance {
        self.definition.provenance()
    }

    pub fn execute(
        &mut self,
        request: &RedisCloudReadRequest,
        scope: &RedisCloudDatabaseScope,
    ) -> std::result::Result<RedisCloudResponse, RedisCloudTransportError> {
        let response = self.transport.execute(request)?;
        match response.validate_integrity(request, scope) {
            Ok(()) => {}
            Err(RedisCloudDatabaseResultError::TamperedEvidence) => {
                return Err(RedisCloudTransportError::Tampered {
                    operation: request.operation.as_str().to_owned(),
                    response_digest: response.response_digest.clone(),
                });
            }
            Err(
                RedisCloudDatabaseResultError::PaginationRejected
                | RedisCloudDatabaseResultError::CursorMismatch,
            ) => {
                return Err(RedisCloudTransportError::Pagination {
                    operation: request.operation.as_str().to_owned(),
                    response_digest: response.response_digest.clone(),
                });
            }
            Err(RedisCloudDatabaseResultError::TruncatedEvidence) => {
                return Err(RedisCloudTransportError::Truncated {
                    operation: request.operation.as_str().to_owned(),
                    response_digest: response.response_digest.clone(),
                });
            }
            Err(RedisCloudDatabaseResultError::StaleState) => {
                return Err(RedisCloudTransportError::ScopeDrift {
                    operation: request.operation.as_str().to_owned(),
                });
            }
            Err(RedisCloudDatabaseResultError::ScopeDrift) => {
                return Err(RedisCloudTransportError::ScopeDrift {
                    operation: request.operation.as_str().to_owned(),
                });
            }
            Err(_) => {
                return Err(RedisCloudTransportError::InvalidResponse {
                    operation: request.operation.as_str().to_owned(),
                    response_digest: response.response_digest.clone(),
                });
            }
        }
        if response.provenance != self.provenance()
            || response.connected
            || response.native
            || response.first_party
            || response.provider_receipt
            || response.provenance.is_native()
            || response.provenance.is_connected()
            || response.provenance.is_first_party()
        {
            return Err(RedisCloudTransportError::InvalidResponse {
                operation: request.operation.as_str().to_owned(),
                response_digest: response.response_digest.clone(),
            });
        }
        if response.page.next_cursor.is_some() {
            return Err(RedisCloudTransportError::Pagination {
                operation: request.operation.as_str().to_owned(),
                response_digest: response.response_digest.clone(),
            });
        }
        if response.page.truncated {
            return Err(RedisCloudTransportError::Truncated {
                operation: request.operation.as_str().to_owned(),
                response_digest: response.response_digest.clone(),
            });
        }
        Ok(response)
    }

    pub fn get_account(
        &mut self,
        request: &RedisCloudReadRequest,
        scope: &RedisCloudDatabaseScope,
    ) -> std::result::Result<RedisCloudResponse, RedisCloudTransportError> {
        self.execute(request, scope)
    }
    pub fn get_subscription(
        &mut self,
        request: &RedisCloudReadRequest,
        scope: &RedisCloudDatabaseScope,
    ) -> std::result::Result<RedisCloudResponse, RedisCloudTransportError> {
        self.execute(request, scope)
    }
    pub fn get_database(
        &mut self,
        request: &RedisCloudReadRequest,
        scope: &RedisCloudDatabaseScope,
    ) -> std::result::Result<RedisCloudResponse, RedisCloudTransportError> {
        self.execute(request, scope)
    }
    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl Default for RedisCloudProvider<BlockedEnvRedisCloudTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvRedisCloudTransport).expect("blocked Redis Cloud provider definition")
    }
}

fn queued_response(
    responses: &mut VecDeque<std::result::Result<RedisCloudResponse, RedisCloudTransportError>>,
    request: &RedisCloudReadRequest,
) -> std::result::Result<RedisCloudResponse, RedisCloudTransportError> {
    responses.pop_front().unwrap_or_else(|| {
        Err(RedisCloudTransportError::ProviderUnknown {
            operation: request.operation.as_str().to_owned(),
            response_digest: Digest::from_text("missing-redis-cloud-fixture-response"),
        })
    })
}

macro_rules! queued_transport {
    ($name:ident, $provenance:expr) => {
        #[derive(Debug, Default)]
        pub struct $name {
            responses: VecDeque<std::result::Result<RedisCloudResponse, RedisCloudTransportError>>,
        }

        impl $name {
            pub fn new(
                response: std::result::Result<RedisCloudResponse, RedisCloudTransportError>,
            ) -> Self {
                let mut transport = Self::default();
                transport.responses.push_back(response);
                transport
            }
            pub fn from_responses<I>(responses: I) -> Self
            where
                I: IntoIterator<
                    Item = std::result::Result<RedisCloudResponse, RedisCloudTransportError>,
                >,
            {
                Self {
                    responses: responses.into_iter().collect(),
                }
            }
            pub fn push_response(
                &mut self,
                response: std::result::Result<RedisCloudResponse, RedisCloudTransportError>,
            ) {
                self.responses.push_back(response);
            }
        }

        impl RedisCloudTransport for $name {
            fn provenance(&self) -> ProviderProvenance {
                $provenance
            }
            fn execute(
                &mut self,
                request: &RedisCloudReadRequest,
            ) -> std::result::Result<RedisCloudResponse, RedisCloudTransportError> {
                queued_response(&mut self.responses, request)
            }
        }
    };
}

queued_transport!(RecordingRedisCloudTransport, ProviderProvenance::Recording);
queued_transport!(FixtureRedisCloudTransport, ProviderProvenance::Fixture);
queued_transport!(FakeRedisCloudTransport, ProviderProvenance::Fake);
queued_transport!(LoopbackRedisCloudTransport, ProviderProvenance::Loopback);

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvRedisCloudTransport;

impl RedisCloudTransport for BlockedEnvRedisCloudTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }
    fn execute(
        &mut self,
        _request: &RedisCloudReadRequest,
    ) -> std::result::Result<RedisCloudResponse, RedisCloudTransportError> {
        Err(RedisCloudTransportError::BlockedEnv)
    }
}

pub type RecordingTransport = RecordingRedisCloudTransport;
pub type FixtureTransport = FixtureRedisCloudTransport;
pub type FakeTransport = FakeRedisCloudTransport;
pub type LoopbackTransport = LoopbackRedisCloudTransport;
pub type BlockedEnvTransport = BlockedEnvRedisCloudTransport;
