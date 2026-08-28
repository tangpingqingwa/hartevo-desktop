use std::{collections::BTreeMap, fmt, sync::Arc};

use serde::Deserialize;

use crate::{
    PROVIDER_ID, PROVIDER_VERSION,
    error::{OpenAiBatchProviderError, OpenAiBatchResultError, Result},
    model::{
        BatchCursor, BatchGetRequest, BatchListRequest, BatchMetadata, BatchMetadataDigest,
        BatchRequestCounts, BatchStatus, BatchTimestamps, CompletionWindow, Digest, Endpoint,
        FileId, FileReference, FileRole, ModelId, NativeStatus, OpenAiBatchScope,
        ProviderProvenance, Revision,
    },
    transport::{
        BlockedEnvOpenAiBatchTransport, GetRequest, OpenAiBatchHttpResponse, OpenAiBatchTransport,
        OpenAiBatchTransportError,
    },
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProviderDefinitionIdentity {
    id: String,
    version: String,
    operations: Vec<String>,
    native_status: NativeStatus,
    connected: bool,
    native: bool,
    external_writes: bool,
}

/// Provider metadata is a contract identity, not a model registry entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenAiBatchProviderDefinition {
    id: String,
    version: String,
    operations: Vec<String>,
    native_status: NativeStatus,
    connected: bool,
    native: bool,
    external_writes: bool,
    digest: Digest,
}

impl OpenAiBatchProviderDefinition {
    #[must_use]
    pub fn layer1() -> Self {
        let identity = ProviderDefinitionIdentity {
            id: String::from(PROVIDER_ID),
            version: String::from(PROVIDER_VERSION),
            operations: vec![
                String::from("GET /v1/batches"),
                String::from("GET /v1/batches/{batch_id}"),
            ],
            native_status: NativeStatus::BlockedEnv,
            connected: false,
            native: false,
            external_writes: false,
        };
        Self {
            id: identity.id.clone(),
            version: identity.version.clone(),
            operations: identity.operations.clone(),
            native_status: identity.native_status,
            connected: identity.connected,
            native: identity.native,
            external_writes: identity.external_writes,
            digest: Digest::from_serializable(&identity),
        }
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    #[must_use]
    pub fn operations(&self) -> &[String] {
        &self.operations
    }

    #[must_use]
    pub const fn native_status(&self) -> NativeStatus {
        self.native_status
    }

    #[must_use]
    pub const fn connected(&self) -> bool {
        self.connected
    }

    #[must_use]
    pub const fn native(&self) -> bool {
        self.native
    }

    #[must_use]
    pub const fn external_writes(&self) -> bool {
        self.external_writes
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::layer1();
        if self == &expected {
            Ok(())
        } else {
            Err(OpenAiBatchResultError::ProviderDrift)
        }
    }
}

/// A successful list read after raw JSON has been reduced to bounded metadata.
#[derive(Clone, Debug)]
pub struct BatchListResponse {
    pub batches: Vec<BatchMetadata>,
    pub next_cursor: Option<BatchCursor>,
    pub has_more: bool,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub observed_at: u64,
    pub snapshot_revision: Revision,
}

/// A successful single-batch read after raw JSON has been reduced to bounded
/// metadata.
#[derive(Clone, Debug)]
pub struct BatchGetResponse {
    pub batch: BatchMetadata,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub observed_at: u64,
    pub snapshot_revision: Revision,
}

/// Typed OpenAI Batch provider.  It owns only a host transport seam and the
/// fixed provider manifest; it does not resolve or store API-key bytes.
#[derive(Clone)]
pub struct OpenAiBatchProvider {
    definition: OpenAiBatchProviderDefinition,
    transport: Arc<dyn OpenAiBatchTransport>,
    provenance: ProviderProvenance,
}

impl fmt::Debug for OpenAiBatchProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAiBatchProvider")
            .field("definition", &self.definition)
            .field("provenance", &self.provenance)
            .field("transport", &self.transport)
            .finish()
    }
}

impl OpenAiBatchProvider {
    pub fn new<T>(transport: T, provenance: ProviderProvenance) -> Result<Self>
    where
        T: OpenAiBatchTransport + 'static,
    {
        Self::with_transport(Arc::new(transport), provenance)
    }

    pub fn with_transport(
        transport: Arc<dyn OpenAiBatchTransport>,
        provenance: ProviderProvenance,
    ) -> Result<Self> {
        let definition = OpenAiBatchProviderDefinition::layer1();
        definition.validate()?;
        Ok(Self {
            definition,
            transport,
            provenance,
        })
    }

    pub fn recording<T>(transport: T) -> Result<Self>
    where
        T: OpenAiBatchTransport + 'static,
    {
        Self::new(transport, ProviderProvenance::Recording)
    }

    pub fn fixture<T>(transport: T) -> Result<Self>
    where
        T: OpenAiBatchTransport + 'static,
    {
        Self::new(transport, ProviderProvenance::Fixture)
    }

    pub fn loopback<T>(transport: T) -> Result<Self>
    where
        T: OpenAiBatchTransport + 'static,
    {
        Self::new(transport, ProviderProvenance::Loopback)
    }

    pub fn blocked_env() -> Result<Self> {
        Self::new(
            BlockedEnvOpenAiBatchTransport,
            ProviderProvenance::BlockedEnv,
        )
    }

    /// Build a deterministic fixture provider whose response is shaped like
    /// the official Batch object.  The fixture is still non-native evidence.
    pub fn fixture_for_scope(scope: &OpenAiBatchScope) -> Result<Self> {
        let transport = crate::RecordingOpenAiBatchTransport::new();
        transport.push_response(
            OpenAiBatchHttpResponse::new(200, fixture_batch_json(scope)?)
                .with_observed_at(1_700_000_100)
                .with_snapshot_revision(scope.identity().scope_revision),
        );
        Self::fixture(transport)
    }

    #[must_use]
    pub fn definition(&self) -> &OpenAiBatchProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        self.definition.digest().clone()
    }

    #[must_use]
    pub const fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    #[must_use]
    pub const fn native_status(&self) -> NativeStatus {
        NativeStatus::BlockedEnv
    }

    #[must_use]
    pub const fn connected(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn native(&self) -> bool {
        false
    }

    pub fn list_batches(
        &self,
        scope: &OpenAiBatchScope,
        request: &BatchListRequest,
    ) -> Result<BatchListResponse> {
        scope.validate()?;
        if let Some(cursor) = &request.cursor
            && cursor.scope_digest() != &scope.scope_digest()
        {
            return Err(OpenAiBatchResultError::CursorMismatch);
        }
        let http_request = GetRequest::list(request.limit, request.cursor.as_ref())?;
        let response = self.send_get(&http_request, scope)?;
        let response_bytes = response.body().len();
        let response_digest = Digest::from_bytes(response.body());
        let response = Self::ensure_success(response, response_digest.clone())?;
        let raw: RawBatchList = serde_json::from_slice(response.body()).map_err(|_| {
            OpenAiBatchResultError::Provider(OpenAiBatchProviderError::MalformedResponse(
                "batch list JSON",
            ))
        })?;
        if raw.object != "list" {
            return Err(OpenAiBatchResultError::Provider(
                OpenAiBatchProviderError::MalformedResponse("batch list object"),
            ));
        }
        if raw.data.len() > crate::MAX_BATCHES_PER_PAGE {
            return Err(OpenAiBatchResultError::InvalidResponse(
                "batch list exceeds the page item bound",
            ));
        }
        let mut batches = Vec::with_capacity(raw.data.len());
        for raw_batch in raw.data {
            batches.push(project_raw_batch(raw_batch, scope)?);
        }
        let next_cursor = if raw.has_more {
            let last_id = raw.last_id.ok_or(OpenAiBatchResultError::Provider(
                OpenAiBatchProviderError::PartialResponse,
            ))?;
            Some(BatchCursor::new(
                last_id,
                scope.scope_digest(),
                response_digest.clone(),
            )?)
        } else {
            None
        };
        Ok(BatchListResponse {
            batches,
            next_cursor,
            has_more: raw.has_more,
            response_bytes,
            response_digest,
            observed_at: response.observed_at(),
            snapshot_revision: response.snapshot_revision(),
        })
    }

    pub fn get_batch(
        &self,
        scope: &OpenAiBatchScope,
        request: &BatchGetRequest,
    ) -> Result<BatchGetResponse> {
        scope.validate()?;
        if let Some(expected) = &scope.identity().batch_id
            && expected != &request.batch_id
        {
            return Err(OpenAiBatchResultError::BatchMismatch);
        }
        let http_request = GetRequest::batch(request.batch_id.clone())?;
        let response = self.send_get(&http_request, scope)?;
        let response_bytes = response.body().len();
        let response_digest = Digest::from_bytes(response.body());
        let response = Self::ensure_success(response, response_digest.clone())?;
        let raw: RawBatch = serde_json::from_slice(response.body()).map_err(|_| {
            OpenAiBatchResultError::Provider(OpenAiBatchProviderError::MalformedResponse(
                "batch JSON",
            ))
        })?;
        if raw.object != "batch" {
            return Err(OpenAiBatchResultError::Provider(
                OpenAiBatchProviderError::MalformedResponse("batch object"),
            ));
        }
        let batch = project_raw_batch(raw, scope)?;
        if batch.batch_id != request.batch_id {
            return Err(OpenAiBatchResultError::Provider(
                OpenAiBatchProviderError::ResponseTampered,
            ));
        }
        Ok(BatchGetResponse {
            batch,
            response_bytes,
            response_digest,
            observed_at: response.observed_at(),
            snapshot_revision: response.snapshot_revision(),
        })
    }

    fn send_get(
        &self,
        request: &GetRequest,
        scope: &OpenAiBatchScope,
    ) -> Result<OpenAiBatchHttpResponse> {
        let allowed_path =
            request.path() == "/v1/batches" || request.path().starts_with("/v1/batches/");
        if request.method() != crate::transport::HttpMethod::Get || !allowed_path {
            return Err(OpenAiBatchResultError::MutationForbidden(
                "non-GET or non-Batch request",
            ));
        }
        self.transport
            .get(request, scope.secret_reference())
            .map_err(map_transport_error)
    }

    fn ensure_success(
        response: OpenAiBatchHttpResponse,
        _response_digest: Digest,
    ) -> Result<OpenAiBatchHttpResponse> {
        if response.body().len() > crate::MAX_RESPONSE_BYTES {
            return Err(OpenAiBatchResultError::ResponseTooLarge {
                actual: response.body().len(),
                maximum: crate::MAX_RESPONSE_BYTES,
            });
        }
        match response.status() {
            200 => Ok(response),
            401 => Err(OpenAiBatchResultError::Provider(
                OpenAiBatchProviderError::Unauthorized,
            )),
            403 => Err(OpenAiBatchResultError::Provider(
                OpenAiBatchProviderError::Forbidden,
            )),
            404 => Err(OpenAiBatchResultError::Provider(
                OpenAiBatchProviderError::NotFound,
            )),
            409 => Err(OpenAiBatchResultError::Provider(
                OpenAiBatchProviderError::Conflict,
            )),
            429 => Err(OpenAiBatchResultError::Provider(
                OpenAiBatchProviderError::RateLimited {
                    retry_after_seconds: None,
                },
            )),
            408 | 504 => Err(OpenAiBatchResultError::Provider(
                OpenAiBatchProviderError::Timeout,
            )),
            500..=599 => Err(OpenAiBatchResultError::Provider(
                OpenAiBatchProviderError::ServerError {
                    status: response.status(),
                },
            )),
            status => Err(OpenAiBatchResultError::UnsupportedStatus(status)),
        }
    }
}

fn map_transport_error(error: OpenAiBatchTransportError) -> OpenAiBatchResultError {
    OpenAiBatchResultError::Provider(match error {
        OpenAiBatchTransportError::BlockedEnv => OpenAiBatchProviderError::BlockedEnv,
        OpenAiBatchTransportError::Timeout => OpenAiBatchProviderError::Timeout,
        OpenAiBatchTransportError::TransportUnavailable => {
            OpenAiBatchProviderError::TransportUnavailable
        }
        OpenAiBatchTransportError::AccessLoss => OpenAiBatchProviderError::AccessLoss,
        OpenAiBatchTransportError::Unauthorized => OpenAiBatchProviderError::Unauthorized,
        OpenAiBatchTransportError::Forbidden => OpenAiBatchProviderError::Forbidden,
    })
}

#[derive(Debug, Deserialize)]
struct RawBatchList {
    object: String,
    data: Vec<RawBatch>,
    has_more: bool,
    last_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawBatch {
    object: String,
    id: String,
    completion_window: String,
    created_at: u64,
    endpoint: String,
    input_file_id: String,
    status: String,
    cancelled_at: Option<u64>,
    cancelling_at: Option<u64>,
    completed_at: Option<u64>,
    error_file_id: Option<String>,
    errors: Option<RawErrors>,
    expired_at: Option<u64>,
    expires_at: Option<u64>,
    failed_at: Option<u64>,
    finalizing_at: Option<u64>,
    in_progress_at: Option<u64>,
    metadata: Option<BTreeMap<String, String>>,
    model: Option<String>,
    output_file_id: Option<String>,
    request_counts: Option<RawRequestCounts>,
}

#[derive(Debug, Deserialize, serde::Serialize)]
struct RawErrors {
    data: Option<Vec<RawBatchError>>,
}

#[derive(Debug, Deserialize, serde::Serialize)]
struct RawBatchError {
    code: Option<String>,
    line: Option<u64>,
    message: Option<String>,
    param: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawRequestCounts {
    total: u64,
    completed: u64,
    failed: u64,
}

fn project_raw_batch(raw: RawBatch, scope: &OpenAiBatchScope) -> Result<BatchMetadata> {
    let batch_id = crate::BatchId::new(raw.id)?;
    let endpoint = Endpoint::new(raw.endpoint)?;
    let input_file_id = FileId::new(raw.input_file_id)?;
    let output_file = raw
        .output_file_id
        .map(|id| FileId::new(id).map(|id| FileReference::new(id, FileRole::Output)))
        .transpose()?;
    let error_file = raw
        .error_file_id
        .map(|id| FileId::new(id).map(|id| FileReference::new(id, FileRole::Error)))
        .transpose()?;
    let model = raw.model.map(ModelId::new).transpose()?;
    let errors_digest = raw.errors.as_ref().map(Digest::from_serializable);
    let error_count = raw
        .errors
        .as_ref()
        .and_then(|errors| errors.data.as_ref())
        .map_or(0, |errors| u32::try_from(errors.len()).unwrap_or(u32::MAX));
    let metadata = BatchMetadataDigest::from_map(raw.metadata.as_ref())?;
    let request_counts = raw.request_counts.ok_or(OpenAiBatchResultError::Provider(
        OpenAiBatchProviderError::MalformedResponse("request_counts"),
    ))?;
    let batch = BatchMetadata::new(
        scope.identity().organization_id.clone(),
        scope.identity().project_id.clone(),
        batch_id,
        endpoint,
        FileReference::new(input_file_id, FileRole::Input),
        output_file,
        error_file,
        model,
        BatchStatus::parse(&raw.status)?,
        CompletionWindow::new(raw.completion_window)?,
        raw.created_at,
        BatchTimestamps {
            in_progress_at: raw.in_progress_at,
            finalizing_at: raw.finalizing_at,
            completed_at: raw.completed_at,
            failed_at: raw.failed_at,
            expired_at: raw.expired_at,
            cancelling_at: raw.cancelling_at,
            cancelled_at: raw.cancelled_at,
        },
        BatchRequestCounts::new(
            request_counts.total,
            request_counts.completed,
            request_counts.failed,
        )?,
        crate::BatchExpiry {
            expires_at: raw.expires_at,
            expired_at: raw.expired_at,
        },
        metadata,
        errors_digest,
        error_count,
    )?;
    batch.validate_for_scope(scope)?;
    Ok(batch)
}

fn fixture_batch_json(scope: &OpenAiBatchScope) -> Result<Vec<u8>> {
    let batch_id = scope
        .identity()
        .batch_id
        .clone()
        .unwrap_or(crate::BatchId::new("batch-fixture")?);
    let endpoint = scope
        .identity()
        .endpoint
        .clone()
        .unwrap_or(crate::Endpoint::new("/v1/responses")?);
    let input_file_id = scope
        .identity()
        .input_file_id
        .clone()
        .unwrap_or(crate::FileId::new("file-input-fixture")?);
    let value = serde_json::json!({
        "id": batch_id.as_str(),
        "object": "batch",
        "endpoint": endpoint.as_str(),
        "input_file_id": input_file_id.as_str(),
        "completion_window": "24h",
        "status": "completed",
        "output_file_id": "file-output-fixture",
        "error_file_id": "file-error-fixture",
        "created_at": 1_700_000_000_u64,
        "completed_at": 1_700_000_100_u64,
        "expires_at": 1_700_086_400_u64,
        "request_counts": {"total": 10_u64, "completed": 9_u64, "failed": 1_u64},
        "model": scope
            .identity()
            .model
            .model_id
            .as_ref()
            .map(ModelId::as_str),
        "metadata": {"source": "fixture"}
    });
    serde_json::to_vec(&value).map_err(|_| OpenAiBatchResultError::InvalidResponse("fixture JSON"))
}
