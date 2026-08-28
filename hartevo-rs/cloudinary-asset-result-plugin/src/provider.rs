use std::{collections::VecDeque, fmt};

use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::error::{CloudinaryAssetResultError, CloudinaryTransportError, Result};
use crate::model::{
    AssetProjection, CloudinaryOperation, CloudinaryScope, CostReceipt, DeliveryMetadataPayload,
    DeliveryProjection, Digest, RequestReceipt, ResourceMetadataPayload,
    TransformationMetadataPayload, TransformationProjection, TransportProvenance,
    UsageMetadataPayload, UsageProjection,
};
use crate::{
    API_REVISION, CONTRACT_VERSION, MAX_BACKOFF_SECONDS, MAX_COLLECTION_ITEMS,
    MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES, MAX_RETRY_ATTEMPTS,
    PROVIDER_ID,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CloudinaryRetryPolicy {
    pub max_attempts: u8,
    pub max_backoff_seconds: u64,
}

impl Default for CloudinaryRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: MAX_RETRY_ATTEMPTS,
            max_backoff_seconds: MAX_BACKOFF_SECONDS,
        }
    }
}

impl CloudinaryRetryPolicy {
    pub fn new(max_attempts: u8, max_backoff_seconds: u64) -> Result<Self> {
        if max_attempts == 0
            || max_attempts > MAX_RETRY_ATTEMPTS
            || max_backoff_seconds > MAX_BACKOFF_SECONDS
        {
            return Err(CloudinaryAssetResultError::InvalidRequest);
        }
        Ok(Self {
            max_attempts,
            max_backoff_seconds,
        })
    }

    pub fn backoff_seconds(self, attempt: u8, retry_after_seconds: Option<u64>) -> u64 {
        let requested = retry_after_seconds.unwrap_or(1);
        let exponent = attempt.saturating_sub(1).min(5);
        let exponential = 1_u64 << u32::from(exponent);
        requested.max(exponential).min(self.max_backoff_seconds)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudinaryReadRequest {
    pub scope_digest: Digest,
    pub cloud_digest: Digest,
    pub folder_digest: Digest,
    pub asset_digest: Digest,
    pub public_id_digest: Digest,
    pub version_digest: Digest,
    pub transformation_digest: Digest,
    pub delivery_digest: Digest,
    pub page_size: u16,
    pub max_pages: u16,
    pub max_response_bytes: u64,
    pub retry_policy: CloudinaryRetryPolicy,
    pub expected_provider_digest: Digest,
    pub expected_registration_digest: Digest,
    pub request_digest: Digest,
}

pub type CloudinaryAssetResultRequest = CloudinaryReadRequest;

impl CloudinaryReadRequest {
    pub fn new(
        scope: &CloudinaryScope,
        page_size: u16,
        max_pages: u16,
        max_response_bytes: u64,
        retry_policy: CloudinaryRetryPolicy,
        expected_provider_digest: Digest,
        expected_registration_digest: Digest,
    ) -> Result<Self> {
        scope.validate()?;
        if page_size == 0
            || page_size > MAX_PAGE_SIZE
            || max_pages == 0
            || max_pages > MAX_PAGES
            || max_response_bytes == 0
            || max_response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(CloudinaryAssetResultError::InvalidRequest);
        }
        expected_provider_digest.validate()?;
        expected_registration_digest.validate()?;
        let mut request = Self {
            scope_digest: scope.digest(),
            cloud_digest: scope.cloud_digest(),
            folder_digest: scope.folder_digest(),
            asset_digest: scope.asset_digest(),
            public_id_digest: scope.public_id_digest(),
            version_digest: scope.version_digest(),
            transformation_digest: scope.transformation_digest(),
            delivery_digest: scope.delivery_digest(),
            page_size,
            max_pages,
            max_response_bytes,
            retry_policy,
            expected_provider_digest,
            expected_registration_digest,
            request_digest: Digest::from_text("unsealed-cloudinary-request"),
        };
        request.request_digest = request.digest_without_self();
        Ok(request)
    }

    pub fn first(
        scope: &CloudinaryScope,
        expected_provider_digest: Digest,
        expected_registration_digest: Digest,
    ) -> Result<Self> {
        Self::new(
            scope,
            MAX_PAGE_SIZE,
            MAX_PAGES,
            MAX_RESPONSE_BYTES,
            CloudinaryRetryPolicy::default(),
            expected_provider_digest,
            expected_registration_digest,
        )
    }

    pub fn digest(&self) -> Digest {
        self.digest_without_self()
    }

    pub fn path_digest(&self, operation: CloudinaryOperation) -> Digest {
        Digest::from_parts(
            "cloudinary-redacted-path/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                ("cloud", self.cloud_digest.as_str().to_owned()),
                ("folder", self.folder_digest.as_str().to_owned()),
                ("asset", self.asset_digest.as_str().to_owned()),
                ("page_size", self.page_size.to_string()),
                ("max_pages", self.max_pages.to_string()),
            ],
        )
    }

    pub fn recorded_request(&self, operation: CloudinaryOperation) -> RecordedRequest {
        RecordedRequest {
            operation,
            scope_digest: self.scope_digest.clone(),
            cloud_digest: self.cloud_digest.clone(),
            folder_digest: self.folder_digest.clone(),
            asset_digest: self.asset_digest.clone(),
            public_id_digest: self.public_id_digest.clone(),
            version_digest: self.version_digest.clone(),
            transformation_digest: self.transformation_digest.clone(),
            delivery_digest: self.delivery_digest.clone(),
            request_digest: self.request_digest.clone(),
            path_digest: self.path_digest(operation),
            redacted: true,
        }
    }

    fn digest_without_self(&self) -> Digest {
        Digest::from_parts(
            "cloudinary-read-request/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("cloud", self.cloud_digest.as_str().to_owned()),
                ("folder", self.folder_digest.as_str().to_owned()),
                ("asset", self.asset_digest.as_str().to_owned()),
                ("public_id", self.public_id_digest.as_str().to_owned()),
                ("version", self.version_digest.as_str().to_owned()),
                (
                    "transformation",
                    self.transformation_digest.as_str().to_owned(),
                ),
                ("delivery", self.delivery_digest.as_str().to_owned()),
                ("page_size", self.page_size.to_string()),
                ("max_pages", self.max_pages.to_string()),
                ("max_response_bytes", self.max_response_bytes.to_string()),
                ("max_attempts", self.retry_policy.max_attempts.to_string()),
                (
                    "max_backoff_seconds",
                    self.retry_policy.max_backoff_seconds.to_string(),
                ),
                (
                    "provider",
                    self.expected_provider_digest.as_str().to_owned(),
                ),
                (
                    "registration",
                    self.expected_registration_digest.as_str().to_owned(),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self, scope: &CloudinaryScope) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.cloud_digest != scope.cloud_digest()
            || self.folder_digest != scope.folder_digest()
            || self.asset_digest != scope.asset_digest()
            || self.public_id_digest != scope.public_id_digest()
            || self.version_digest != scope.version_digest()
            || self.transformation_digest != scope.transformation_digest()
            || self.delivery_digest != scope.delivery_digest()
            || self.request_digest != self.digest()
        {
            return Err(CloudinaryAssetResultError::ScopeMismatch);
        }
        if self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(CloudinaryAssetResultError::InvalidRequest);
        }
        self.expected_provider_digest.validate()?;
        self.expected_registration_digest.validate()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: CloudinaryOperation,
    pub scope_digest: Digest,
    pub cloud_digest: Digest,
    pub folder_digest: Digest,
    pub asset_digest: Digest,
    pub public_id_digest: Digest,
    pub version_digest: Digest,
    pub transformation_digest: Digest,
    pub delivery_digest: Digest,
    pub request_digest: Digest,
    pub path_digest: Digest,
    pub redacted: bool,
}

impl RecordedRequest {
    pub fn receipt(&self, attempts: u8) -> RequestReceipt {
        RequestReceipt::new(
            self.operation,
            self.request_digest.clone(),
            self.path_digest.clone(),
            self.scope_digest.clone(),
            attempts,
        )
    }

    fn validate(&self) -> Result<()> {
        if !self.redacted {
            return Err(CloudinaryAssetResultError::TamperedEvidence);
        }
        for digest in [
            &self.scope_digest,
            &self.cloud_digest,
            &self.folder_digest,
            &self.asset_digest,
            &self.public_id_digest,
            &self.version_digest,
            &self.transformation_digest,
            &self.delivery_digest,
            &self.request_digest,
            &self.path_digest,
        ] {
            digest.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudinaryProviderResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub resource: Option<ResourceMetadataPayload>,
    pub usage: Option<UsageMetadataPayload>,
    pub transformation: Option<TransformationMetadataPayload>,
    pub delivery: Option<DeliveryMetadataPayload>,
    pub response_bytes: u64,
    pub attempts: u8,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub request_receipt: RequestReceipt,
    pub cost_receipt: CostReceipt,
}

pub type CloudinaryProviderResult = CloudinaryProviderResponse;

type CloudinaryProjections = (
    Option<AssetProjection>,
    Option<UsageProjection>,
    Option<TransformationProjection>,
    Option<DeliveryProjection>,
);

impl CloudinaryProviderResponse {
    pub fn new(
        request: &CloudinaryReadRequest,
        resource: Option<ResourceMetadataPayload>,
        usage: Option<UsageMetadataPayload>,
        transformation: Option<TransformationMetadataPayload>,
        delivery: Option<DeliveryMetadataPayload>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        request.validate_scope_only()?;
        if response_bytes > request.max_response_bytes || response_bytes > MAX_RESPONSE_BYTES {
            return Err(CloudinaryAssetResultError::PartialEvidence);
        }
        let recorded_request = request.recorded_request(CloudinaryOperation::ResourceMetadata);
        recorded_request.validate()?;
        let request_receipt = recorded_request.receipt(1);
        let cost_receipt = CostReceipt::new(CloudinaryOperation::ResourceMetadata, response_bytes)?;
        let mut response = Self {
            scope_digest: request.scope_digest.clone(),
            request_digest: request.request_digest.clone(),
            resource,
            usage,
            transformation,
            delivery,
            response_bytes,
            attempts: 1,
            provenance,
            response_digest: Digest::from_text("unsealed-cloudinary-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            request_receipt,
            cost_receipt,
        };
        response.response_digest = response.calculate_digest(request);
        Ok(response)
    }

    pub fn with_declared_digest(mut self, response_digest: Digest) -> Self {
        self.response_digest = response_digest;
        self
    }

    pub fn with_attempts(mut self, attempts: u8, request: &CloudinaryReadRequest) -> Self {
        self.attempts = attempts;
        let recorded_request = request.recorded_request(CloudinaryOperation::ResourceMetadata);
        self.request_receipt = recorded_request.receipt(attempts);
        self.response_digest = self.calculate_digest(request);
        self
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub(crate) fn validate_integrity(&self, request: &CloudinaryReadRequest) -> Result<()> {
        request.validate_scope_only()?;
        if self.scope_digest != request.scope_digest
            || self.request_digest != request.request_digest
            || self.response_bytes > request.max_response_bytes
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.attempts == 0
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.provenance.is_first_party()
            || self.response_digest != self.calculate_digest(request)
        {
            return Err(CloudinaryAssetResultError::TamperedEvidence);
        }
        self.request_receipt.validate_integrity()?;
        self.cost_receipt.validate_integrity()?;
        let expected_request_receipt = request
            .recorded_request(CloudinaryOperation::ResourceMetadata)
            .receipt(self.attempts);
        let expected_cost_receipt =
            CostReceipt::new(CloudinaryOperation::ResourceMetadata, self.response_bytes)?;
        if self.request_receipt != expected_request_receipt
            || self.cost_receipt != expected_cost_receipt
        {
            return Err(CloudinaryAssetResultError::TamperedEvidence);
        }
        if let Some(resource) = &self.resource {
            resource.validate()?;
        }
        if let Some(usage) = &self.usage {
            usage.validate()?;
        }
        if let Some(transformation) = &self.transformation {
            transformation.validate()?;
        }
        if let Some(delivery) = &self.delivery {
            delivery.validate()?;
        }
        Ok(())
    }

    pub(crate) fn projections(&self, scope: &CloudinaryScope) -> Result<CloudinaryProjections> {
        Ok((
            self.resource
                .as_ref()
                .map(|value| value.project(scope))
                .transpose()?,
            self.usage
                .as_ref()
                .map(|value| value.project(scope))
                .transpose()?,
            self.transformation
                .as_ref()
                .map(|value| value.project(scope))
                .transpose()?,
            self.delivery
                .as_ref()
                .map(|value| value.project(scope))
                .transpose()?,
        ))
    }

    fn calculate_digest(&self, request: &CloudinaryReadRequest) -> Digest {
        Digest::from_parts(
            "cloudinary-provider-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                (
                    "resource",
                    self.resource
                        .as_ref()
                        .map_or_else(String::new, resource_payload_digest),
                ),
                (
                    "usage",
                    self.usage
                        .as_ref()
                        .map_or_else(String::new, usage_payload_digest),
                ),
                (
                    "transformation",
                    self.transformation
                        .as_ref()
                        .map_or_else(String::new, transformation_payload_digest),
                ),
                (
                    "delivery",
                    self.delivery
                        .as_ref()
                        .map_or_else(String::new, delivery_payload_digest),
                ),
                ("response_bytes", self.response_bytes.to_string()),
                ("attempts", self.attempts.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
                (
                    "request_receipt",
                    self.request_receipt.receipt_digest.as_str().to_owned(),
                ),
                (
                    "cost_receipt",
                    self.cost_receipt.receipt_digest.as_str().to_owned(),
                ),
                ("request_limit", request.max_response_bytes.to_string()),
            ],
        )
    }
}

fn resource_payload_digest(payload: &ResourceMetadataPayload) -> String {
    Digest::from_parts(
        "cloudinary-resource-payload/v1",
        &[
            ("asset", payload.asset_id.clone()),
            ("public_id", payload.public_id.clone()),
            ("folder", payload.folder.clone()),
            ("version", payload.version.clone()),
            ("resource_type", payload.resource_type.as_str().to_owned()),
            ("status", payload.status.clone()),
            ("bytes", payload.bytes.to_string()),
            (
                "width",
                payload
                    .width
                    .map_or_else(String::new, |value| value.to_string()),
            ),
            (
                "height",
                payload
                    .height
                    .map_or_else(String::new, |value| value.to_string()),
            ),
            ("format", payload.format.clone()),
            ("derived", payload.derived_count.to_string()),
            ("metadata", payload.metadata_count.to_string()),
        ],
    )
    .as_str()
    .to_owned()
}

fn usage_payload_digest(payload: &UsageMetadataPayload) -> String {
    Digest::from_parts(
        "cloudinary-usage-payload/v1",
        &[
            ("storage", payload.storage_bytes.to_string()),
            ("bandwidth", payload.bandwidth_bytes.to_string()),
            ("requests", payload.request_count.to_string()),
            ("transformations", payload.transformation_count.to_string()),
        ],
    )
    .as_str()
    .to_owned()
}

fn transformation_payload_digest(payload: &TransformationMetadataPayload) -> String {
    Digest::from_parts(
        "cloudinary-transformation-payload/v1",
        &[
            ("transformation", payload.transformation.clone()),
            ("components", payload.component_count.to_string()),
            ("version", payload.version.clone()),
        ],
    )
    .as_str()
    .to_owned()
}

fn delivery_payload_digest(payload: &DeliveryMetadataPayload) -> String {
    Digest::from_parts(
        "cloudinary-delivery-payload/v1",
        &[
            ("delivery_type", format!("{:?}", payload.delivery_type)),
            ("resource_type", payload.resource_type.as_str().to_owned()),
            ("format", payload.format.clone()),
            ("version", payload.version.clone()),
            ("reference", payload.reference_digest().as_str().to_owned()),
        ],
    )
    .as_str()
    .to_owned()
}

#[derive(Clone, Debug)]
pub struct CloudinaryProviderDefinition {
    pub provider_id: String,
    pub provider_revision: u64,
    pub api_revision: String,
    pub contract_version: String,
    pub release: String,
    pub capability_digest: Digest,
    pub provider_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl CloudinaryProviderDefinition {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let release = release.into();
        if provider_revision == 0 || !valid_release(&release) {
            return Err(CloudinaryAssetResultError::ProviderDrift);
        }
        let capability_digest = Digest::from_parts(
            "cloudinary-provider-capabilities/v1",
            &crate::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| ("permission", (*permission).to_owned()))
                .collect::<Vec<_>>(),
        );
        let provider_digest = Digest::from_parts(
            "cloudinary-provider/v1",
            &[
                ("provider_id", PROVIDER_ID.to_owned()),
                ("provider_revision", provider_revision.to_string()),
                ("api_revision", API_REVISION.to_owned()),
                ("contract_version", CONTRACT_VERSION.to_owned()),
                ("release", release.clone()),
                ("capability", capability_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            api_revision: API_REVISION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            release,
            capability_digest,
            provider_digest,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.api_revision != API_REVISION
            || self.contract_version != CONTRACT_VERSION
            || !valid_release(&self.release)
            || self.connected
            || self.native
            || self.first_party
            || self.provider_digest
                != Self::new(self.provider_revision, self.release.clone())?.provider_digest
        {
            return Err(CloudinaryAssetResultError::ProviderDrift);
        }
        Ok(())
    }
}

impl Serialize for CloudinaryProviderDefinition {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("CloudinaryProviderDefinition", 10)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("apiRevision", &self.api_revision)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("release", &self.release)?;
        state.serialize_field("capabilityDigest", &self.capability_digest)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("connected", &self.connected)?;
        state.serialize_field("native", &self.native)?;
        state.serialize_field("firstParty", &self.first_party)?;
        state.end()
    }
}

fn valid_release(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub trait CloudinaryTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn read(
        &mut self,
        request: &CloudinaryReadRequest,
    ) -> std::result::Result<CloudinaryProviderResponse, CloudinaryTransportError>;
}

pub struct CloudinaryProvider<T> {
    transport: T,
    definition: CloudinaryProviderDefinition,
    retry_policy: CloudinaryRetryPolicy,
}

impl<T: CloudinaryTransport> fmt::Debug for CloudinaryProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudinaryProvider")
            .field("definition", &self.definition)
            .field("transport_provenance", &self.transport.provenance())
            .field("retry_policy", &self.retry_policy)
            .finish()
    }
}

impl<T: CloudinaryTransport> CloudinaryProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_options(
            transport,
            1,
            "layer1-recording",
            CloudinaryRetryPolicy::default(),
        )
    }

    pub fn with_identity(
        transport: T,
        provider_revision: u64,
        release: impl Into<String>,
    ) -> Result<Self> {
        Self::with_options(
            transport,
            provider_revision,
            release,
            CloudinaryRetryPolicy::default(),
        )
    }

    pub fn with_options(
        transport: T,
        provider_revision: u64,
        release: impl Into<String>,
        retry_policy: CloudinaryRetryPolicy,
    ) -> Result<Self> {
        let definition = CloudinaryProviderDefinition::new(provider_revision, release)?;
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
            retry_policy,
        })
    }

    pub fn definition(&self) -> &CloudinaryProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn retry_policy(&self) -> CloudinaryRetryPolicy {
        self.retry_policy
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read(
        &mut self,
        request: &CloudinaryReadRequest,
    ) -> std::result::Result<CloudinaryProviderResponse, CloudinaryTransportError> {
        self.read_detailed(request).map_err(|failure| failure.error)
    }

    pub fn read_resource_metadata(
        &mut self,
        request: &CloudinaryReadRequest,
    ) -> std::result::Result<CloudinaryProviderResponse, CloudinaryTransportError> {
        self.read(request)
    }

    pub fn read_usage_metadata(
        &mut self,
        request: &CloudinaryReadRequest,
    ) -> std::result::Result<CloudinaryProviderResponse, CloudinaryTransportError> {
        self.read(request)
    }

    pub fn read_transformation_metadata(
        &mut self,
        request: &CloudinaryReadRequest,
    ) -> std::result::Result<CloudinaryProviderResponse, CloudinaryTransportError> {
        self.read(request)
    }

    pub fn read_delivery_metadata(
        &mut self,
        request: &CloudinaryReadRequest,
    ) -> std::result::Result<CloudinaryProviderResponse, CloudinaryTransportError> {
        self.read(request)
    }

    pub fn read_detailed(
        &mut self,
        request: &CloudinaryReadRequest,
    ) -> std::result::Result<CloudinaryProviderResponse, CloudinaryProviderFailure> {
        if request.validate_scope_only().is_err() {
            return Err(CloudinaryProviderFailure {
                error: CloudinaryTransportError::InvalidResponse,
                attempts: 0,
                backoff_seconds: 0,
            });
        }
        let retry_policy = CloudinaryRetryPolicy {
            max_attempts: self
                .retry_policy
                .max_attempts
                .min(request.retry_policy.max_attempts),
            max_backoff_seconds: self
                .retry_policy
                .max_backoff_seconds
                .min(request.retry_policy.max_backoff_seconds),
        };
        let mut attempts = 0_u8;
        let mut backoff_seconds = 0_u64;
        while attempts < retry_policy.max_attempts {
            attempts = attempts.saturating_add(1);
            match self.transport.read(request) {
                Ok(response) => {
                    let response = response.with_attempts(attempts, request);
                    if let Err(error) = self.validate_response(&response, request) {
                        return Err(CloudinaryProviderFailure {
                            error,
                            attempts,
                            backoff_seconds,
                        });
                    }
                    return Ok(response);
                }
                Err(CloudinaryTransportError::RateLimited {
                    retry_after_seconds,
                }) if attempts < retry_policy.max_attempts => {
                    backoff_seconds = retry_policy.backoff_seconds(attempts, retry_after_seconds);
                }
                Err(error) => {
                    return Err(CloudinaryProviderFailure {
                        error,
                        attempts,
                        backoff_seconds,
                    });
                }
            }
        }
        Err(CloudinaryProviderFailure {
            error: CloudinaryTransportError::BackoffExhausted,
            attempts,
            backoff_seconds,
        })
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    fn validate_response(
        &self,
        response: &CloudinaryProviderResponse,
        request: &CloudinaryReadRequest,
    ) -> std::result::Result<(), CloudinaryTransportError> {
        response
            .validate_integrity(request)
            .map_err(|error| match error {
                CloudinaryAssetResultError::PartialEvidence => CloudinaryTransportError::Partial,
                CloudinaryAssetResultError::TamperedEvidence => CloudinaryTransportError::Tampered,
                CloudinaryAssetResultError::InvalidEvidence
                | CloudinaryAssetResultError::RevisionDrift
                | CloudinaryAssetResultError::ScopeMismatch => {
                    CloudinaryTransportError::InvalidResponse
                }
                _ => CloudinaryTransportError::InvalidResponse,
            })?;
        if response.provenance != self.provenance()
            || response.connected
            || response.native
            || response.first_party
            || response.provider_receipt
        {
            return Err(CloudinaryTransportError::InvalidResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudinaryProviderFailure {
    pub error: CloudinaryTransportError,
    pub attempts: u8,
    pub backoff_seconds: u64,
}

impl Default for CloudinaryProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked Cloudinary provider definition")
    }
}

impl<T: CloudinaryTransport> CloudinaryProvider<T> {
    pub fn from_registration(
        registration: &crate::service::CloudinaryAssetResultRegistration,
        transport: T,
    ) -> Result<Self> {
        let provider = Self::with_identity(
            transport,
            registration.provider_revision(),
            registration.provider_release().to_owned(),
        )?;
        if provider.definition.provider_digest != *registration.provider_digest() {
            return Err(CloudinaryAssetResultError::ProviderDrift);
        }
        Ok(provider)
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    responses: VecDeque<std::result::Result<CloudinaryProviderResponse, CloudinaryTransportError>>,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_response(
        &mut self,
        response: std::result::Result<CloudinaryProviderResponse, CloudinaryTransportError>,
    ) {
        self.responses.push_back(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }
}

impl Default for RecordingTransport {
    fn default() -> Self {
        Self::new(TransportProvenance::Recording)
    }
}

impl CloudinaryTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn read(
        &mut self,
        request: &CloudinaryReadRequest,
    ) -> std::result::Result<CloudinaryProviderResponse, CloudinaryTransportError> {
        self.requests
            .push(request.recorded_request(CloudinaryOperation::ResourceMetadata));
        self.responses
            .pop_front()
            .unwrap_or(Err(CloudinaryTransportError::InvalidResponse))
    }
}

pub type FakeTransport = RecordingTransport;
pub type FakeCloudinaryTransport = RecordingTransport;

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope: CloudinaryScope,
}

impl FixtureTransport {
    pub fn for_scope(scope: &CloudinaryScope) -> Self {
        Self {
            scope: scope.clone(),
        }
    }

    fn response(
        &self,
        request: &CloudinaryReadRequest,
        provenance: TransportProvenance,
    ) -> std::result::Result<CloudinaryProviderResponse, CloudinaryTransportError> {
        CloudinaryProviderResponse::new(
            request,
            Some(ResourceMetadataPayload::fixture(&self.scope)),
            Some(UsageMetadataPayload::fixture()),
            Some(TransformationMetadataPayload::fixture(&self.scope)),
            Some(
                DeliveryMetadataPayload::fixture(&self.scope)
                    .map_err(|_| CloudinaryTransportError::InvalidResponse)?,
            ),
            2_048,
            provenance,
        )
        .map_err(|_| CloudinaryTransportError::InvalidResponse)
    }
}

impl CloudinaryTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn read(
        &mut self,
        request: &CloudinaryReadRequest,
    ) -> std::result::Result<CloudinaryProviderResponse, CloudinaryTransportError> {
        self.response(request, TransportProvenance::Fixture)
    }
}

pub type FixtureCloudinaryTransport = FixtureTransport;

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    inner: FixtureTransport,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &CloudinaryScope) -> Self {
        Self {
            inner: FixtureTransport::for_scope(scope),
        }
    }
}

impl CloudinaryTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn read(
        &mut self,
        request: &CloudinaryReadRequest,
    ) -> std::result::Result<CloudinaryProviderResponse, CloudinaryTransportError> {
        self.inner.response(request, TransportProvenance::Loopback)
    }
}

pub type LoopbackCloudinaryTransport = LoopbackTransport;

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl CloudinaryTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read(
        &mut self,
        _request: &CloudinaryReadRequest,
    ) -> std::result::Result<CloudinaryProviderResponse, CloudinaryTransportError> {
        Err(CloudinaryTransportError::BlockedEnv)
    }
}

pub type BlockedEnvCloudinaryTransport = BlockedEnvTransport;

impl CloudinaryReadRequest {
    fn validate_scope_only(&self) -> Result<()> {
        if self.scope_digest.as_str().is_empty()
            || self.cloud_digest.as_str().is_empty()
            || self.folder_digest.as_str().is_empty()
            || self.asset_digest.as_str().is_empty()
            || self.public_id_digest.as_str().is_empty()
            || self.version_digest.as_str().is_empty()
            || self.transformation_digest.as_str().is_empty()
            || self.delivery_digest.as_str().is_empty()
            || self.request_digest != self.digest()
        {
            return Err(CloudinaryAssetResultError::InvalidRequest);
        }
        Ok(())
    }
}

#[allow(dead_code)]
fn _bounded_collection(value: usize) -> Result<()> {
    if value > MAX_COLLECTION_ITEMS {
        Err(CloudinaryAssetResultError::PartialEvidence)
    } else {
        Ok(())
    }
}
