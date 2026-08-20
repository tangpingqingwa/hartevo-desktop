//! Bounded, non-native AWS Kinesis provider seams.
//!
//! There is intentionally no AWS SDK, SigV4 signer, credential resolver, HTTP
//! client, record reader, or mutation API in this Layer-1 crate.

use std::{collections::VecDeque, fmt, fmt::Write as _};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::error::{AwsKinesisStreamResultError, AwsKinesisTransportError, Result};
use crate::model::{
    AwsKinesisStreamScope, ConsumerMetadataInput, ConsumerProjection, Cursor, Digest, ShardFilter,
    ShardLineageProjection, ShardMetadataInput, StreamSummary, StreamSummaryInput,
    TransportProvenance, validate_response_bytes,
};
use crate::service::AwsKinesisStreamResultRegistration;
use crate::{CONTRACT_VERSION, LAYER1_PERMISSIONS, PROVIDER_API_REVISION, PROVIDER_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AwsKinesisOperation {
    DescribeStreamSummary,
    ListShards,
    DescribeStreamConsumer,
}

impl AwsKinesisOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DescribeStreamSummary => "DescribeStreamSummary",
            Self::ListShards => "ListShards",
            Self::DescribeStreamConsumer => "DescribeStreamConsumer",
        }
    }
}

pub trait AwsKinesisTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn describe_stream_summary(
        &mut self,
        request: &DescribeStreamSummaryRequest,
    ) -> std::result::Result<DescribeStreamSummaryResponse, AwsKinesisTransportError>;

    fn list_shards(
        &mut self,
        request: &ListShardsRequest,
    ) -> std::result::Result<ListShardsResponse, AwsKinesisTransportError>;

    fn describe_stream_consumer(
        &mut self,
        request: &DescribeStreamConsumerRequest,
    ) -> std::result::Result<DescribeStreamConsumerResponse, AwsKinesisTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsKinesisOperation,
    pub scope_digest: Digest,
    pub filter_digest: Option<Digest>,
    pub consumer_digest: Option<Digest>,
    pub cursor_digest: Option<Digest>,
    pub request_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct DescribeStreamSummaryRequest {
    scope: AwsKinesisStreamScope,
    request_digest: Digest,
}

impl DescribeStreamSummaryRequest {
    pub fn for_scope(scope: &AwsKinesisStreamScope) -> Result<Self> {
        scope.validate()?;
        let request_digest = Digest::from_parts(
            "aws-kinesis-describe-stream-summary-request/v1",
            &[("scope", scope.digest().as_str().to_owned())],
        );
        Ok(Self {
            scope: scope.clone(),
            request_digest,
        })
    }

    pub fn scope(&self) -> &AwsKinesisStreamScope {
        &self.scope
    }
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn redacted_request(&self) -> String {
        format!(
            "X-Amz-Target=Kinesis_20131202.DescribeStreamSummary&streamArnDigest={}",
            self.scope.stream().arn().digest().as_str()
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsKinesisOperation::DescribeStreamSummary,
            scope_digest: self.scope.digest(),
            filter_digest: None,
            consumer_digest: None,
            cursor_digest: None,
            request_digest: self.request_digest.clone(),
        }
    }
}

impl fmt::Debug for DescribeStreamSummaryRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DescribeStreamSummaryRequest")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListShardsRequest {
    scope: AwsKinesisStreamScope,
    filter: ShardFilter,
    cursor: Option<Cursor>,
    max_results: u16,
    request_digest: Digest,
}

impl ListShardsRequest {
    pub fn new(
        scope: &AwsKinesisStreamScope,
        filter: ShardFilter,
        cursor: Option<Cursor>,
        max_results: u16,
    ) -> Result<Self> {
        Self::new_at(scope, filter, cursor, max_results, Utc::now())
    }

    pub fn new_at(
        scope: &AwsKinesisStreamScope,
        filter: ShardFilter,
        cursor: Option<Cursor>,
        max_results: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        scope.validate()?;
        filter.validate()?;
        if max_results == 0 || max_results > crate::MAX_PAGE_SIZE {
            return Err(AwsKinesisStreamResultError::InvalidRequest);
        }
        if let Some(cursor) = &cursor {
            cursor.validate_against(scope, &filter, observed_at)?;
        }
        let request_digest = Digest::from_parts(
            "aws-kinesis-list-shards-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("filter", filter.digest().as_str().to_owned()),
                (
                    "cursor",
                    cursor.as_ref().map_or_else(String::new, |value| {
                        value.token_digest().as_str().to_owned()
                    }),
                ),
                (
                    "page",
                    cursor
                        .as_ref()
                        .map_or_else(|| "1".to_owned(), |value| value.page_number().to_string()),
                ),
                ("max_results", max_results.to_string()),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            filter,
            cursor,
            max_results,
            request_digest,
        })
    }

    pub fn scope(&self) -> &AwsKinesisStreamScope {
        &self.scope
    }
    pub fn filter(&self) -> &ShardFilter {
        &self.filter
    }
    pub fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }
    pub const fn max_results(&self) -> u16 {
        self.max_results
    }
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
    pub fn page_number(&self) -> u16 {
        self.cursor.as_ref().map_or(1, Cursor::page_number)
    }

    pub fn redacted_request(&self) -> String {
        let mut query = format!(
            "X-Amz-Target=Kinesis_20131202.ListShards&streamArnDigest={}&maxResults={}",
            self.scope.stream().arn().digest().as_str(),
            self.max_results
        );
        let _ = write!(
            query,
            "&filterDigest={}&nextTokenDigest={}",
            self.filter.digest().as_str(),
            self.cursor
                .as_ref()
                .map_or("", |cursor| cursor.token_digest().as_str())
        );
        query
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsKinesisOperation::ListShards,
            scope_digest: self.scope.digest(),
            filter_digest: Some(self.filter.digest()),
            consumer_digest: None,
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|value| value.token_digest().clone()),
            request_digest: self.request_digest.clone(),
        }
    }
}

impl fmt::Debug for ListShardsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListShardsRequest")
            .field("scope_digest", &self.scope.digest())
            .field("filter_digest", &self.filter.digest())
            .field("cursor", &self.cursor)
            .field("max_results", &self.max_results)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DescribeStreamConsumerRequest {
    scope: AwsKinesisStreamScope,
    request_digest: Digest,
}

impl DescribeStreamConsumerRequest {
    pub fn for_scope(scope: &AwsKinesisStreamScope) -> Result<Self> {
        scope.validate()?;
        let consumer = scope
            .consumer()
            .ok_or(AwsKinesisStreamResultError::ConsumerDrift)?;
        let request_digest = Digest::from_parts(
            "aws-kinesis-describe-stream-consumer-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("consumer", consumer.digest().as_str().to_owned()),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            request_digest,
        })
    }

    pub fn scope(&self) -> &AwsKinesisStreamScope {
        &self.scope
    }
    pub fn consumer(&self) -> Option<&crate::model::ConsumerIdentity> {
        self.scope.consumer()
    }
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn redacted_request(&self) -> String {
        format!(
            "X-Amz-Target=Kinesis_20131202.DescribeStreamConsumer&consumerDigest={}",
            self.scope
                .consumer()
                .map_or_else(String::new, |consumer| consumer
                    .digest()
                    .as_str()
                    .to_owned(),)
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsKinesisOperation::DescribeStreamConsumer,
            scope_digest: self.scope.digest(),
            filter_digest: None,
            consumer_digest: self
                .scope
                .consumer()
                .map(crate::model::ConsumerIdentity::digest),
            cursor_digest: None,
            request_digest: self.request_digest.clone(),
        }
    }
}

impl fmt::Debug for DescribeStreamConsumerRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DescribeStreamConsumerRequest")
            .field("scope_digest", &self.scope.digest())
            .field(
                "consumer_digest",
                &self
                    .scope
                    .consumer()
                    .map(crate::model::ConsumerIdentity::digest),
            )
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeStreamSummaryResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub summary: StreamSummary,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl DescribeStreamSummaryResponse {
    pub fn new(
        request: &DescribeStreamSummaryRequest,
        summary: StreamSummary,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        summary.validate_against(request.scope())?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            summary,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-kinesis-summary-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn validate_integrity(&self, request: &DescribeStreamSummaryRequest) -> Result<()> {
        validate_response_bytes(self.response_bytes)?;
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsKinesisStreamResultError::TamperedEvidence);
        }
        self.summary.validate_against(request.scope())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-kinesis-describe-stream-summary-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("summary", self.summary.digest().as_str().to_owned()),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListShardsResponse {
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub shards: Vec<ShardLineageProjection>,
    pub next_cursor: Option<Cursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl ListShardsResponse {
    pub fn new(
        request: &ListShardsRequest,
        shards: Vec<ShardMetadataInput>,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if shards.len() > request.max_results() as usize || shards.len() > crate::MAX_SHARDS {
            return Err(AwsKinesisStreamResultError::PartialEvidence);
        }
        let shards = shards
            .into_iter()
            .map(ShardLineageProjection::from_input)
            .collect::<Result<Vec<_>>>()?;
        if let Some(cursor) = &next_cursor {
            if cursor.scope_digest() != &request.scope().digest()
                || cursor.filter_digest() != &request.filter().digest()
                || cursor.page_number() != request.page_number().saturating_add(1)
            {
                return Err(AwsKinesisStreamResultError::CursorMismatch);
            }
        }
        let mut response = Self {
            scope_digest: request.scope().digest(),
            filter_digest: request.filter().digest(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            shards,
            next_cursor,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-kinesis-shards-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }

    pub fn validate_integrity(&self, request: &ListShardsRequest) -> Result<()> {
        validate_response_bytes(self.response_bytes)?;
        if self.scope_digest != request.scope().digest()
            || self.filter_digest != request.filter().digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.shards.len() > request.max_results() as usize
            || self.shards.len() > crate::MAX_SHARDS
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsKinesisStreamResultError::TamperedEvidence);
        }
        for shard in &self.shards {
            shard.validate()?;
        }
        if let Some(cursor) = &self.next_cursor {
            if cursor.scope_digest() != &request.scope().digest()
                || cursor.filter_digest() != &request.filter().digest()
                || cursor.page_number() != request.page_number().saturating_add(1)
            {
                return Err(AwsKinesisStreamResultError::CursorMismatch);
            }
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-kinesis-list-shards-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("filter", self.filter_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                (
                    "shards",
                    self.shards
                        .iter()
                        .map(|value| value.lineage_digest.as_str())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "cursor",
                    self.next_cursor.as_ref().map_or_else(String::new, |value| {
                        value.token_digest().as_str().to_owned()
                    }),
                ),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeStreamConsumerResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub metadata: ConsumerProjection,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl DescribeStreamConsumerResponse {
    pub fn new(
        request: &DescribeStreamConsumerRequest,
        input: ConsumerMetadataInput,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        let metadata = ConsumerProjection::new(request.scope(), input)?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            metadata,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-kinesis-consumer-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn validate_integrity(&self, request: &DescribeStreamConsumerRequest) -> Result<()> {
        validate_response_bytes(self.response_bytes)?;
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsKinesisStreamResultError::TamperedEvidence);
        }
        self.metadata.validate_against(request.scope())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-kinesis-describe-stream-consumer-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                (
                    "metadata",
                    self.metadata.metadata_digest.as_str().to_owned(),
                ),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug)]
pub struct AwsKinesisProviderDefinition {
    pub provider_id: String,
    pub provider_revision: u64,
    pub api_revision: String,
    pub contract_version: String,
    pub release: String,
    pub capability_digest: Digest,
    pub api_digest: Digest,
    pub provider_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl AwsKinesisProviderDefinition {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let release = release.into();
        if provider_revision == 0 {
            return Err(AwsKinesisStreamResultError::ProviderDrift);
        }
        if release.is_empty() || release.len() > 128 {
            return Err(AwsKinesisStreamResultError::ProviderDrift);
        }
        let capability_digest = Digest::from_parts(
            "aws-kinesis-provider-capabilities/v1",
            &LAYER1_PERMISSIONS
                .iter()
                .map(|permission| ("permission", (*permission).to_owned()))
                .collect::<Vec<_>>(),
        );
        let api_digest = Digest::from_text(PROVIDER_API_REVISION);
        let provider_digest = Digest::from_parts(
            "aws-kinesis-provider/v1",
            &[
                ("provider_id", PROVIDER_ID.to_owned()),
                ("provider_revision", provider_revision.to_string()),
                ("api_revision", PROVIDER_API_REVISION.to_owned()),
                ("api_digest", api_digest.as_str().to_owned()),
                ("contract_version", CONTRACT_VERSION.to_owned()),
                ("release", release.clone()),
                ("capability", capability_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            api_revision: PROVIDER_API_REVISION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            release,
            capability_digest,
            api_digest,
            provider_digest,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::new(self.provider_revision, self.release.clone())?;
        if self.provider_id != expected.provider_id
            || self.api_revision != expected.api_revision
            || self.contract_version != expected.contract_version
            || self.capability_digest != expected.capability_digest
            || self.api_digest != expected.api_digest
            || self.provider_digest != expected.provider_digest
            || self.connected
            || self.native
            || self.first_party
        {
            Err(AwsKinesisStreamResultError::ProviderDrift)
        } else {
            Ok(())
        }
    }
}

impl Serialize for AwsKinesisProviderDefinition {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsKinesisProviderDefinition", 12)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("apiRevision", &self.api_revision)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
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

pub struct AwsKinesisProvider<T> {
    transport: T,
    definition: AwsKinesisProviderDefinition,
}

impl<T: AwsKinesisTransport> fmt::Debug for AwsKinesisProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsKinesisProvider")
            .field("definition", &self.definition)
            .field("transport_provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: AwsKinesisTransport> AwsKinesisProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_identity(transport, 1, "layer1-recording")
    }

    pub fn with_identity(
        transport: T,
        provider_revision: u64,
        release: impl Into<String>,
    ) -> Result<Self> {
        let definition = AwsKinesisProviderDefinition::new(provider_revision, release)?;
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsKinesisProviderDefinition {
        &self.definition
    }
    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn describe_stream_summary(
        &mut self,
        request: &DescribeStreamSummaryRequest,
    ) -> std::result::Result<DescribeStreamSummaryResponse, AwsKinesisTransportError> {
        let response = self.transport.describe_stream_summary(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsKinesisTransportError::InvalidResponse)?;
        self.validate_provenance(response.provenance)?;
        Ok(response)
    }

    pub fn list_shards(
        &mut self,
        request: &ListShardsRequest,
    ) -> std::result::Result<ListShardsResponse, AwsKinesisTransportError> {
        let response = self.transport.list_shards(request)?;
        response
            .validate_integrity(request)
            .map_err(|error| match error {
                AwsKinesisStreamResultError::CursorExpired => {
                    AwsKinesisTransportError::TokenExpired
                }
                _ => AwsKinesisTransportError::InvalidResponse,
            })?;
        self.validate_provenance(response.provenance)?;
        Ok(response)
    }

    pub fn describe_stream_consumer(
        &mut self,
        request: &DescribeStreamConsumerRequest,
    ) -> std::result::Result<DescribeStreamConsumerResponse, AwsKinesisTransportError> {
        let response = self.transport.describe_stream_consumer(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsKinesisTransportError::InvalidResponse)?;
        self.validate_provenance(response.provenance)?;
        Ok(response)
    }

    fn validate_provenance(
        &self,
        provenance: TransportProvenance,
    ) -> std::result::Result<(), AwsKinesisTransportError> {
        if provenance != self.provenance()
            || provenance.is_native()
            || provenance.claims_connected()
            || provenance.claims_first_party()
        {
            Err(AwsKinesisTransportError::InvalidResponse)
        } else {
            Ok(())
        }
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl Default for AwsKinesisProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked Kinesis provider")
    }
}

impl<T: AwsKinesisTransport> AwsKinesisProvider<T> {
    pub fn from_registration(
        registration: &AwsKinesisStreamResultRegistration,
        transport: T,
    ) -> Result<Self> {
        let provider = Self::with_identity(
            transport,
            registration.provider_revision(),
            registration.provider_release().to_owned(),
        )?;
        if provider.definition.provider_digest != *registration.provider_digest() {
            return Err(AwsKinesisStreamResultError::ProviderDrift);
        }
        Ok(provider)
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    summary_responses:
        VecDeque<std::result::Result<DescribeStreamSummaryResponse, AwsKinesisTransportError>>,
    shard_responses: VecDeque<std::result::Result<ListShardsResponse, AwsKinesisTransportError>>,
    consumer_responses:
        VecDeque<std::result::Result<DescribeStreamConsumerResponse, AwsKinesisTransportError>>,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            summary_responses: VecDeque::new(),
            shard_responses: VecDeque::new(),
            consumer_responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_summary_response(
        &mut self,
        response: std::result::Result<DescribeStreamSummaryResponse, AwsKinesisTransportError>,
    ) {
        self.summary_responses.push_back(response);
    }

    pub fn push_shard_response(
        &mut self,
        response: std::result::Result<ListShardsResponse, AwsKinesisTransportError>,
    ) {
        self.shard_responses.push_back(response);
    }

    pub fn push_consumer_response(
        &mut self,
        response: std::result::Result<DescribeStreamConsumerResponse, AwsKinesisTransportError>,
    ) {
        self.consumer_responses.push_back(response);
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

impl AwsKinesisTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn describe_stream_summary(
        &mut self,
        request: &DescribeStreamSummaryRequest,
    ) -> std::result::Result<DescribeStreamSummaryResponse, AwsKinesisTransportError> {
        self.requests.push(request.recorded_request());
        self.summary_responses
            .pop_front()
            .unwrap_or(Err(AwsKinesisTransportError::InvalidResponse))
    }

    fn list_shards(
        &mut self,
        request: &ListShardsRequest,
    ) -> std::result::Result<ListShardsResponse, AwsKinesisTransportError> {
        self.requests.push(request.recorded_request());
        self.shard_responses
            .pop_front()
            .unwrap_or(Err(AwsKinesisTransportError::InvalidResponse))
    }

    fn describe_stream_consumer(
        &mut self,
        request: &DescribeStreamConsumerRequest,
    ) -> std::result::Result<DescribeStreamConsumerResponse, AwsKinesisTransportError> {
        self.requests.push(request.recorded_request());
        self.consumer_responses
            .pop_front()
            .unwrap_or(Err(AwsKinesisTransportError::InvalidResponse))
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope: AwsKinesisStreamScope,
    observed_at: DateTime<Utc>,
}

impl FixtureTransport {
    pub fn for_scope(scope: &AwsKinesisStreamScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
        }
    }

    fn summary(&self) -> Result<StreamSummary> {
        StreamSummary::new(
            &self.scope,
            StreamSummaryInput {
                status: crate::model::StreamStatus::Active,
                mode: crate::model::StreamMode::Provisioned,
                retention_period_hours: 24,
                open_shard_count: 2,
                creation_timestamp_epoch_seconds: self.scope.stream_version().value(),
                monitoring_metrics: vec!["IncomingBytes".to_owned(), "OutgoingBytes".to_owned()],
                encryption_type: crate::model::EncryptionType::Kms,
                encryption_key_id: Some(
                    "arn:aws:kms:us-east-1:123456789012:key/fixture-kinesis-key".to_owned(),
                ),
                max_record_size_kib: Some(1_024),
            },
        )
    }

    fn shards() -> Vec<ShardMetadataInput> {
        vec![
            ShardMetadataInput::new("shardId-000000000001", None::<String>, None::<String>),
            ShardMetadataInput::new(
                "shardId-000000000002",
                Some("shardId-000000000001"),
                None::<String>,
            ),
        ]
    }

    fn consumer(&self) -> Option<ConsumerMetadataInput> {
        self.scope.consumer().map(|_| ConsumerMetadataInput {
            status: crate::model::ConsumerStatus::Active,
            creation_timestamp_epoch_seconds: self.observed_at.timestamp().saturating_sub(60),
        })
    }
}

impl AwsKinesisTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn describe_stream_summary(
        &mut self,
        request: &DescribeStreamSummaryRequest,
    ) -> std::result::Result<DescribeStreamSummaryResponse, AwsKinesisTransportError> {
        DescribeStreamSummaryResponse::new(
            request,
            self.summary()
                .map_err(|_| AwsKinesisTransportError::InvalidResponse)?,
            768,
            TransportProvenance::Fixture,
        )
        .map_err(|_| AwsKinesisTransportError::InvalidResponse)
    }

    fn list_shards(
        &mut self,
        request: &ListShardsRequest,
    ) -> std::result::Result<ListShardsResponse, AwsKinesisTransportError> {
        ListShardsResponse::new(
            request,
            Self::shards(),
            None,
            1_024,
            TransportProvenance::Fixture,
        )
        .map_err(|_| AwsKinesisTransportError::InvalidResponse)
    }

    fn describe_stream_consumer(
        &mut self,
        request: &DescribeStreamConsumerRequest,
    ) -> std::result::Result<DescribeStreamConsumerResponse, AwsKinesisTransportError> {
        let input = self
            .consumer()
            .ok_or(AwsKinesisTransportError::InvalidResponse)?;
        DescribeStreamConsumerResponse::new(request, input, 512, TransportProvenance::Fixture)
            .map_err(|_| AwsKinesisTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    inner: FixtureTransport,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &AwsKinesisStreamScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            inner: FixtureTransport::for_scope(scope, observed_at),
        }
    }
}

impl AwsKinesisTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn describe_stream_summary(
        &mut self,
        request: &DescribeStreamSummaryRequest,
    ) -> std::result::Result<DescribeStreamSummaryResponse, AwsKinesisTransportError> {
        DescribeStreamSummaryResponse::new(
            request,
            self.inner
                .summary()
                .map_err(|_| AwsKinesisTransportError::InvalidResponse)?,
            768,
            TransportProvenance::Loopback,
        )
        .map_err(|_| AwsKinesisTransportError::InvalidResponse)
    }

    fn list_shards(
        &mut self,
        request: &ListShardsRequest,
    ) -> std::result::Result<ListShardsResponse, AwsKinesisTransportError> {
        ListShardsResponse::new(
            request,
            FixtureTransport::shards(),
            None,
            1_024,
            TransportProvenance::Loopback,
        )
        .map_err(|_| AwsKinesisTransportError::InvalidResponse)
    }

    fn describe_stream_consumer(
        &mut self,
        request: &DescribeStreamConsumerRequest,
    ) -> std::result::Result<DescribeStreamConsumerResponse, AwsKinesisTransportError> {
        let input = self
            .inner
            .consumer()
            .ok_or(AwsKinesisTransportError::InvalidResponse)?;
        DescribeStreamConsumerResponse::new(request, input, 512, TransportProvenance::Loopback)
            .map_err(|_| AwsKinesisTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsKinesisTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn describe_stream_summary(
        &mut self,
        _request: &DescribeStreamSummaryRequest,
    ) -> std::result::Result<DescribeStreamSummaryResponse, AwsKinesisTransportError> {
        Err(AwsKinesisTransportError::BlockedEnv)
    }

    fn list_shards(
        &mut self,
        _request: &ListShardsRequest,
    ) -> std::result::Result<ListShardsResponse, AwsKinesisTransportError> {
        Err(AwsKinesisTransportError::BlockedEnv)
    }

    fn describe_stream_consumer(
        &mut self,
        _request: &DescribeStreamConsumerRequest,
    ) -> std::result::Result<DescribeStreamConsumerResponse, AwsKinesisTransportError> {
        Err(AwsKinesisTransportError::BlockedEnv)
    }
}
