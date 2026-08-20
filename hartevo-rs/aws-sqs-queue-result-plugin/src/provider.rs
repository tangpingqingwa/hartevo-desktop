//! Read-only AWS SQS provider seams.
//!
//! There is intentionally no AWS SDK, SigV4 signer, credential resolver, HTTP
//! client, message type, or queue-mutation method in this Layer-1 provider.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use thiserror::Error;

use crate::error::{AwsSqsQueueError, AwsSqsQueueTransportError, Result};
use crate::model::{
    AwsSqsQueueScope, Cursor, DeadLetterSourceProjection, Digest, QueueAttributesInput,
    QueueAttributesProjection, QueueIdentity, QueueListFilter, QueueSummary, QueueUrl,
    TransportProvenance,
};
use crate::{
    CONTRACT_VERSION, LAYER1_PERMISSIONS, MAX_DEAD_LETTER_SOURCES, MAX_PAGES, MAX_RESPONSE_BYTES,
    PROVIDER_API_REVISION, PROVIDER_ID,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsSqsProviderError {
    #[error("AWS SQS provider model error: {0}")]
    Model(#[from] AwsSqsQueueError),
    #[error("AWS SQS provider transport error: {0}")]
    Transport(#[from] AwsSqsQueueTransportError),
    #[error("AWS SQS provider page binding or digest is invalid")]
    PageBinding,
    #[error("AWS SQS provider revision is incompatible")]
    ProviderRevision,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum AwsSqsOperation {
    #[serde(rename = "ListQueues")]
    ListQueues,
    #[serde(rename = "GetQueueUrl")]
    GetQueueUrl,
    #[serde(rename = "GetQueueAttributes")]
    GetQueueAttributes,
    #[serde(rename = "ListDeadLetterSourceQueues")]
    ListDeadLetterSourceQueues,
}

impl AwsSqsOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListQueues => "ListQueues",
            Self::GetQueueUrl => "GetQueueUrl",
            Self::GetQueueAttributes => "GetQueueAttributes",
            Self::ListDeadLetterSourceQueues => "ListDeadLetterSourceQueues",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsSqsOperation,
    pub scope_digest: Digest,
    pub queue_digest: Digest,
    pub dead_letter_queue_digest: Option<Digest>,
    pub filter_digest: Option<Digest>,
    pub cursor_digest: Option<Digest>,
    pub request_digest: Digest,
    pub path_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListQueuesRequest {
    scope: AwsSqsQueueScope,
    filter: QueueListFilter,
    page_number: u16,
    cursor: Option<Cursor>,
    request_digest: Digest,
}

impl ListQueuesRequest {
    pub fn new(
        scope: &AwsSqsQueueScope,
        filter: QueueListFilter,
        page_number: u16,
        cursor: Option<Cursor>,
    ) -> Result<Self> {
        if page_number == 0 || page_number > MAX_PAGES {
            return Err(AwsSqsQueueError::InvalidRequest);
        }
        filter.validate_against(scope)?;
        if let Some(cursor) = &cursor {
            cursor.validate_against(scope, &filter)?;
            if cursor.page_number() != page_number {
                return Err(AwsSqsQueueError::CursorMismatch);
            }
        }
        let request_digest = Digest::from_parts(
            "aws-sqs-list-queues-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("filter", filter.digest().as_str().to_owned()),
                ("page", page_number.to_string()),
                (
                    "cursor",
                    cursor
                        .as_ref()
                        .map_or_else(String::new, |value| value.token_digest().to_string()),
                ),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            filter,
            page_number,
            cursor,
            request_digest,
        })
    }

    pub fn scope(&self) -> &AwsSqsQueueScope {
        &self.scope
    }

    pub fn filter(&self) -> &QueueListFilter {
        &self.filter
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        let prefix_digest = self
            .filter
            .queue_name_prefix()
            .map_or_else(String::new, |value| Digest::from_text(value).to_string());
        format!(
            "Action=ListQueues&QueueNamePrefixDigest={prefix_digest}&MaxResults={}&Page={}&NextTokenDigest={}",
            self.filter.max_results(),
            self.page_number,
            self.cursor
                .as_ref()
                .map_or_else(String::new, |value| value.token_digest().to_string())
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsSqsOperation::ListQueues,
            scope_digest: self.scope.digest(),
            queue_digest: self.scope.queue_digest(),
            dead_letter_queue_digest: self.scope.dead_letter_relationship_digest(),
            filter_digest: Some(self.filter.digest()),
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|value| value.token_digest().clone()),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for ListQueuesRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListQueuesRequest")
            .field("scope_digest", &self.scope.digest())
            .field("filter", &self.filter)
            .field("page_number", &self.page_number)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl Serialize for ListQueuesRequest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ListQueuesRequest", 6)?;
        state.serialize_field("scopeDigest", &self.scope.digest())?;
        state.serialize_field("filterDigest", &self.filter.digest())?;
        state.serialize_field("pageNumber", &self.page_number)?;
        state.serialize_field("cursor", &self.cursor)?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.serialize_field("pathDigest", &Digest::from_text(self.path_and_query()))?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetQueueUrlRequest {
    scope: AwsSqsQueueScope,
    queue: QueueIdentity,
    request_digest: Digest,
}

impl GetQueueUrlRequest {
    pub fn for_scope(scope: &AwsSqsQueueScope) -> Result<Self> {
        Self::for_queue(scope, scope.queue())
    }

    pub fn for_queue(scope: &AwsSqsQueueScope, queue: &QueueIdentity) -> Result<Self> {
        queue.validate_for(scope.account(), scope.region())?;
        Ok(Self {
            scope: scope.clone(),
            queue: queue.clone(),
            request_digest: Digest::from_parts(
                "aws-sqs-get-queue-url-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("queue", queue.digest().as_str().to_owned()),
                    ("account", scope.account().digest().as_str().to_owned()),
                ],
            ),
        })
    }

    pub fn scope(&self) -> &AwsSqsQueueScope {
        &self.scope
    }

    pub fn queue(&self) -> &QueueIdentity {
        &self.queue
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "Action=GetQueueUrl&QueueNameDigest={}&QueueOwnerAWSAccountIdDigest={}",
            self.queue.name().digest(),
            self.scope.account().digest()
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsSqsOperation::GetQueueUrl,
            scope_digest: self.scope.digest(),
            queue_digest: self.queue.digest(),
            dead_letter_queue_digest: self.scope.dead_letter_relationship_digest(),
            filter_digest: None,
            cursor_digest: None,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for GetQueueUrlRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetQueueUrlRequest")
            .field("scope_digest", &self.scope.digest())
            .field("queue_digest", &self.queue.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl Serialize for GetQueueUrlRequest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("GetQueueUrlRequest", 4)?;
        state.serialize_field("scopeDigest", &self.scope.digest())?;
        state.serialize_field("queueDigest", &self.queue.digest())?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.serialize_field("pathDigest", &Digest::from_text(self.path_and_query()))?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetQueueAttributesRequest {
    scope: AwsSqsQueueScope,
    queue_url: QueueUrl,
    request_digest: Digest,
}

impl GetQueueAttributesRequest {
    pub fn for_scope(scope: &AwsSqsQueueScope) -> Result<Self> {
        let queue_url = scope
            .queue()
            .url()
            .cloned()
            .ok_or(AwsSqsQueueError::InvalidRequest)?;
        Self::new(scope, queue_url)
    }

    pub fn new(scope: &AwsSqsQueueScope, queue_url: QueueUrl) -> Result<Self> {
        if queue_url.account_id()? != *scope.account()
            || queue_url.region()? != *scope.region()
            || queue_url.queue_name()? != *scope.queue().name()
        {
            return Err(AwsSqsQueueError::QueueReplaced);
        }
        if let Some(expected) = scope.queue().url()
            && expected != &queue_url
        {
            return Err(AwsSqsQueueError::QueueReplaced);
        }
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "aws-sqs-get-queue-attributes-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("queue", scope.queue_digest().as_str().to_owned()),
                    ("queue_url", queue_url.digest().as_str().to_owned()),
                    (
                        "attribute_names",
                        "posture_and_approximate_counts_only".to_owned(),
                    ),
                ],
            ),
            queue_url,
        })
    }

    pub fn scope(&self) -> &AwsSqsQueueScope {
        &self.scope
    }

    pub fn queue_url(&self) -> &QueueUrl {
        &self.queue_url
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "Action=GetQueueAttributes&QueueUrlDigest={}&AttributeNamesDigest={}",
            self.queue_url.digest(),
            Digest::from_text("posture_and_approximate_counts_only")
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsSqsOperation::GetQueueAttributes,
            scope_digest: self.scope.digest(),
            queue_digest: self.scope.queue_digest(),
            dead_letter_queue_digest: self.scope.dead_letter_relationship_digest(),
            filter_digest: None,
            cursor_digest: None,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for GetQueueAttributesRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetQueueAttributesRequest")
            .field("scope_digest", &self.scope.digest())
            .field("queue_url_digest", &self.queue_url.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl Serialize for GetQueueAttributesRequest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("GetQueueAttributesRequest", 4)?;
        state.serialize_field("scopeDigest", &self.scope.digest())?;
        state.serialize_field("queueUrlDigest", &self.queue_url.digest())?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.serialize_field("pathDigest", &Digest::from_text(self.path_and_query()))?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListDeadLetterSourceQueuesRequest {
    scope: AwsSqsQueueScope,
    dead_letter_queue_url: QueueUrl,
    request_digest: Digest,
}

impl ListDeadLetterSourceQueuesRequest {
    pub fn for_scope(scope: &AwsSqsQueueScope) -> Result<Self> {
        let dead_letter_queue = scope
            .dead_letter_queue()
            .ok_or(AwsSqsQueueError::InvalidRequest)?;
        let queue_url = dead_letter_queue
            .url()
            .cloned()
            .ok_or(AwsSqsQueueError::InvalidRequest)?;
        Self::new(scope, queue_url)
    }

    pub fn new(scope: &AwsSqsQueueScope, dead_letter_queue_url: QueueUrl) -> Result<Self> {
        let expected = scope
            .dead_letter_queue()
            .ok_or(AwsSqsQueueError::InvalidRequest)?;
        if dead_letter_queue_url.account_id()? != *scope.account()
            || dead_letter_queue_url.region()? != *scope.region()
            || dead_letter_queue_url.queue_name()? != *expected.name()
            || expected
                .url()
                .is_some_and(|value| value != &dead_letter_queue_url)
        {
            return Err(AwsSqsQueueError::QueueReplaced);
        }
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "aws-sqs-list-dead-letter-source-queues-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("dead_letter_queue", expected.digest().as_str().to_owned()),
                    (
                        "queue_url",
                        dead_letter_queue_url.digest().as_str().to_owned(),
                    ),
                ],
            ),
            dead_letter_queue_url,
        })
    }

    pub fn scope(&self) -> &AwsSqsQueueScope {
        &self.scope
    }

    pub fn dead_letter_queue_url(&self) -> &QueueUrl {
        &self.dead_letter_queue_url
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "Action=ListDeadLetterSourceQueues&QueueUrlDigest={}",
            self.dead_letter_queue_url.digest()
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsSqsOperation::ListDeadLetterSourceQueues,
            scope_digest: self.scope.digest(),
            queue_digest: self.scope.queue_digest(),
            dead_letter_queue_digest: self.scope.dead_letter_relationship_digest(),
            filter_digest: None,
            cursor_digest: None,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for ListDeadLetterSourceQueuesRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListDeadLetterSourceQueuesRequest")
            .field("scope_digest", &self.scope.digest())
            .field(
                "dead_letter_queue_url_digest",
                &self.dead_letter_queue_url.digest(),
            )
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl Serialize for ListDeadLetterSourceQueuesRequest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ListDeadLetterSourceQueuesRequest", 4)?;
        state.serialize_field("scopeDigest", &self.scope.digest())?;
        state.serialize_field(
            "deadLetterQueueUrlDigest",
            &self.dead_letter_queue_url.digest(),
        )?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.serialize_field("pathDigest", &Digest::from_text(self.path_and_query()))?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListQueuesResponse {
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub queues: Vec<QueueSummary>,
    pub next_cursor: Option<Cursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl ListQueuesResponse {
    pub fn new(
        request: &ListQueuesRequest,
        queues: Vec<QueueSummary>,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if queues.len() > request.filter.max_results() as usize {
            return Err(AwsSqsQueueError::PartialEvidence);
        }
        if let Some(cursor) = &next_cursor {
            cursor.validate_against(request.scope(), request.filter())?;
            if cursor.page_number() != request.page_number().saturating_add(1) {
                return Err(AwsSqsQueueError::CursorMismatch);
            }
        }
        let mut result = Self {
            scope_digest: request.scope().digest(),
            filter_digest: request.filter().digest(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            queues,
            next_cursor,
            response_bytes,
            provenance,
            evidence_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        result.evidence_digest = result.calculate_digest();
        Ok(result)
    }

    pub fn from_queue_urls(
        request: &ListQueuesRequest,
        queue_urls: Vec<QueueUrl>,
        next_token: Option<String>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        let next_cursor = next_token
            .map(|token| {
                Cursor::new(
                    token,
                    request.scope(),
                    request.filter(),
                    request.page_number().saturating_add(1),
                )
            })
            .transpose()?;
        let queues = queue_urls
            .into_iter()
            .map(QueueSummary::new)
            .collect::<Result<Vec<_>>>()?;
        Self::new(request, queues, next_cursor, response_bytes, provenance)
    }

    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }

    pub fn digest(&self) -> Digest {
        self.evidence_digest.clone()
    }

    pub fn validate_integrity(&self, request: &ListQueuesRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.filter_digest != request.filter().digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.queues.len() > request.filter.max_results() as usize
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsSqsQueueError::TamperedEvidence);
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate_against(request.scope(), request.filter())?;
            if cursor.page_number() != request.page_number().saturating_add(1) {
                return Err(AwsSqsQueueError::CursorMismatch);
            }
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-sqs-list-queues-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("filter", self.filter_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                (
                    "queues",
                    self.queues
                        .iter()
                        .map(|queue| {
                            format!("{}:{}", queue.queue_name_digest, queue.queue_url_digest)
                        })
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "cursor",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| cursor.token_digest().to_string()),
                ),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetQueueUrlResponse {
    pub scope_digest: Digest,
    pub queue_digest: Digest,
    pub queue_url: QueueUrl,
    pub queue_name_digest: Digest,
    pub request_digest: Digest,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl GetQueueUrlResponse {
    pub fn new(
        request: &GetQueueUrlRequest,
        queue_url: QueueUrl,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if queue_url.queue_name()? != *request.queue().name()
            || queue_url.account_id()? != *request.scope().account()
            || queue_url.region()? != *request.scope().region()
        {
            return Err(AwsSqsQueueError::QueueReplaced);
        }
        let mut result = Self {
            scope_digest: request.scope().digest(),
            queue_digest: request.queue().digest(),
            queue_name_digest: queue_url.queue_name()?.digest(),
            queue_url,
            request_digest: request.request_digest().clone(),
            response_bytes,
            provenance,
            evidence_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        result.evidence_digest = result.calculate_digest();
        Ok(result)
    }

    pub fn digest(&self) -> Digest {
        self.evidence_digest.clone()
    }

    pub fn validate_integrity(&self, request: &GetQueueUrlRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.queue_digest != request.queue().digest()
            || self.queue_name_digest != request.queue().name().digest()
            || self.request_digest != *request.request_digest()
            || self.queue_url.queue_name()? != *request.queue().name()
            || self.queue_url.account_id()? != *request.scope().account()
            || self.queue_url.region()? != *request.scope().region()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsSqsQueueError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-sqs-get-queue-url-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("queue", self.queue_digest.as_str().to_owned()),
                ("url", self.queue_url.digest().as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetQueueAttributesResponse {
    pub scope_digest: Digest,
    pub queue_digest: Digest,
    pub attributes: QueueAttributesProjection,
    pub request_digest: Digest,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl GetQueueAttributesResponse {
    pub fn new(
        request: &GetQueueAttributesRequest,
        attributes: QueueAttributesInput,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        attributes.validate()?;
        let attributes = attributes.project();
        if attributes.identity().name() != request.scope().queue().name()
            || attributes.identity().url() != Some(request.queue_url())
            || !attributes
                .identity()
                .matches_expected(request.scope().queue())
        {
            return Err(AwsSqsQueueError::QueueReplaced);
        }
        let mut result = Self {
            scope_digest: request.scope().digest(),
            queue_digest: request.scope().queue_digest(),
            attributes,
            request_digest: request.request_digest().clone(),
            response_bytes,
            provenance,
            evidence_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        result.evidence_digest = result.calculate_digest();
        Ok(result)
    }

    pub fn digest(&self) -> Digest {
        self.evidence_digest.clone()
    }

    pub fn validate_integrity(&self, request: &GetQueueAttributesRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.queue_digest != request.scope().queue_digest()
            || self.request_digest != *request.request_digest()
            || !self.attributes.matches_scope(request.scope())
            || self.attributes.identity().url() != Some(request.queue_url())
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || !self.attributes.counts.eventually_consistent
            || self.attributes.counts.delivery_proof
            || self.attributes.counts.approximate_number_of_messages > crate::MAX_APPROXIMATE_COUNT
            || self
                .attributes
                .counts
                .approximate_number_of_messages_not_visible
                > crate::MAX_APPROXIMATE_COUNT
            || self
                .attributes
                .counts
                .approximate_number_of_messages_delayed
                > crate::MAX_APPROXIMATE_COUNT
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsSqsQueueError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-sqs-get-queue-attributes-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("queue", self.queue_digest.as_str().to_owned()),
                ("attributes", self.attributes.digest().as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListDeadLetterSourceQueuesResponse {
    pub scope_digest: Digest,
    pub dead_letter_queue_digest: Digest,
    pub source_queues: Vec<DeadLetterSourceProjection>,
    pub request_digest: Digest,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl ListDeadLetterSourceQueuesResponse {
    pub fn new(
        request: &ListDeadLetterSourceQueuesRequest,
        source_queues: Vec<QueueIdentity>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if source_queues.len() > MAX_DEAD_LETTER_SOURCES {
            return Err(AwsSqsQueueError::PartialEvidence);
        }
        for source_queue in &source_queues {
            source_queue.validate_for(request.scope().account(), request.scope().region())?;
        }
        let source_queues = source_queues
            .iter()
            .map(DeadLetterSourceProjection::new)
            .collect::<Vec<_>>();
        let mut result = Self {
            scope_digest: request.scope().digest(),
            dead_letter_queue_digest: request
                .scope()
                .dead_letter_relationship_digest()
                .ok_or(AwsSqsQueueError::InvalidRequest)?,
            source_queues,
            request_digest: request.request_digest().clone(),
            response_bytes,
            provenance,
            evidence_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        result.evidence_digest = result.calculate_digest();
        Ok(result)
    }

    pub fn digest(&self) -> Digest {
        self.evidence_digest.clone()
    }

    pub fn validate_integrity(&self, request: &ListDeadLetterSourceQueuesRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.dead_letter_queue_digest
                != request
                    .scope()
                    .dead_letter_relationship_digest()
                    .ok_or(AwsSqsQueueError::ScopeMismatch)?
            || self.request_digest != *request.request_digest()
            || self.source_queues.len() > MAX_DEAD_LETTER_SOURCES
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsSqsQueueError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-sqs-list-dead-letter-source-queues-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "dead_letter_queue",
                    self.dead_letter_queue_digest.as_str().to_owned(),
                ),
                (
                    "sources",
                    self.source_queues
                        .iter()
                        .map(|source| source.queue_digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("request", self.request_digest.as_str().to_owned()),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsSqsProviderDefinition {
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

impl AwsSqsProviderDefinition {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let release = release.into();
        if provider_revision == 0
            || release.is_empty()
            || release.len() > crate::MAX_IDENTIFIER_BYTES
            || release.chars().any(char::is_control)
        {
            return Err(AwsSqsQueueError::ProviderDrift);
        }
        let capability_digest = Digest::from_parts(
            "aws-sqs-provider-capabilities/v1",
            &LAYER1_PERMISSIONS
                .iter()
                .map(|permission| ("permission", (*permission).to_owned()))
                .chain(
                    [
                        AwsSqsOperation::ListQueues,
                        AwsSqsOperation::GetQueueUrl,
                        AwsSqsOperation::GetQueueAttributes,
                        AwsSqsOperation::ListDeadLetterSourceQueues,
                    ]
                    .into_iter()
                    .map(|operation| ("operation", operation.as_str().to_owned())),
                )
                .collect::<Vec<_>>(),
        );
        let provider_digest = Digest::from_parts(
            "aws-sqs-provider/v1",
            &[
                ("provider_id", PROVIDER_ID.to_owned()),
                ("provider_revision", provider_revision.to_string()),
                ("api_revision", PROVIDER_API_REVISION.to_owned()),
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
            provider_digest,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn api_digest(&self) -> &Digest {
        &self.capability_digest
    }

    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.api_revision != PROVIDER_API_REVISION
            || self.contract_version != CONTRACT_VERSION
            || self.release.is_empty()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_digest
                != Self::new(self.provider_revision, self.release.clone())?.provider_digest
        {
            Err(AwsSqsQueueError::ProviderDrift)
        } else {
            Ok(())
        }
    }
}

impl Serialize for AwsSqsProviderDefinition {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AwsSqsProviderDefinition", 10)?;
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

/// Typed provider exposing exactly the four Layer-1 SQS read operations.
pub struct AwsSqsProvider<T> {
    transport: T,
    definition: AwsSqsProviderDefinition,
}

impl<T: AwsSqsTransport> fmt::Debug for AwsSqsProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsSqsProvider")
            .field("definition", &self.definition)
            .field("transport_provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: AwsSqsTransport> AwsSqsProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_identity(transport, 1, "layer1-recording")
    }

    pub fn with_identity(
        transport: T,
        provider_revision: u64,
        release: impl Into<String>,
    ) -> Result<Self> {
        let definition = AwsSqsProviderDefinition::new(provider_revision, release)?;
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsSqsProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn list_queues(
        &mut self,
        request: &ListQueuesRequest,
    ) -> std::result::Result<ListQueuesResponse, AwsSqsQueueTransportError> {
        let response = self.transport.list_queues(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsSqsQueueTransportError::InvalidResponse)?;
        self.ensure_provenance(response.provenance)?;
        Ok(response)
    }

    pub fn get_queue_url(
        &mut self,
        request: &GetQueueUrlRequest,
    ) -> std::result::Result<GetQueueUrlResponse, AwsSqsQueueTransportError> {
        let response = self.transport.get_queue_url(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsSqsQueueTransportError::InvalidResponse)?;
        self.ensure_provenance(response.provenance)?;
        Ok(response)
    }

    pub fn get_queue_attributes(
        &mut self,
        request: &GetQueueAttributesRequest,
    ) -> std::result::Result<GetQueueAttributesResponse, AwsSqsQueueTransportError> {
        let response = self.transport.get_queue_attributes(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsSqsQueueTransportError::InvalidResponse)?;
        self.ensure_provenance(response.provenance)?;
        Ok(response)
    }

    pub fn list_dead_letter_source_queues(
        &mut self,
        request: &ListDeadLetterSourceQueuesRequest,
    ) -> std::result::Result<ListDeadLetterSourceQueuesResponse, AwsSqsQueueTransportError> {
        let response = self.transport.list_dead_letter_source_queues(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsSqsQueueTransportError::InvalidResponse)?;
        self.ensure_provenance(response.provenance)?;
        Ok(response)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    fn ensure_provenance(
        &self,
        response_provenance: TransportProvenance,
    ) -> std::result::Result<(), AwsSqsQueueTransportError> {
        if response_provenance != self.provenance()
            || response_provenance.is_native()
            || response_provenance.is_connected()
        {
            Err(AwsSqsQueueTransportError::InvalidResponse)
        } else {
            Ok(())
        }
    }
}

impl Default for AwsSqsProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked AWS SQS provider definition")
    }
}

/// The only transport trait exposed by Layer 1.
pub trait AwsSqsTransport: Send + fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn list_queues(
        &mut self,
        request: &ListQueuesRequest,
    ) -> std::result::Result<ListQueuesResponse, AwsSqsQueueTransportError>;

    fn get_queue_url(
        &mut self,
        request: &GetQueueUrlRequest,
    ) -> std::result::Result<GetQueueUrlResponse, AwsSqsQueueTransportError>;

    fn get_queue_attributes(
        &mut self,
        request: &GetQueueAttributesRequest,
    ) -> std::result::Result<GetQueueAttributesResponse, AwsSqsQueueTransportError>;

    fn list_dead_letter_source_queues(
        &mut self,
        request: &ListDeadLetterSourceQueuesRequest,
    ) -> std::result::Result<ListDeadLetterSourceQueuesResponse, AwsSqsQueueTransportError>;
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    list_queues_responses:
        VecDeque<std::result::Result<ListQueuesResponse, AwsSqsQueueTransportError>>,
    get_queue_url_responses:
        VecDeque<std::result::Result<GetQueueUrlResponse, AwsSqsQueueTransportError>>,
    get_queue_attributes_responses:
        VecDeque<std::result::Result<GetQueueAttributesResponse, AwsSqsQueueTransportError>>,
    list_dead_letter_source_queues_responses: VecDeque<
        std::result::Result<ListDeadLetterSourceQueuesResponse, AwsSqsQueueTransportError>,
    >,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            list_queues_responses: VecDeque::new(),
            get_queue_url_responses: VecDeque::new(),
            get_queue_attributes_responses: VecDeque::new(),
            list_dead_letter_source_queues_responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_list_queues_response(
        &mut self,
        response: std::result::Result<ListQueuesResponse, AwsSqsQueueTransportError>,
    ) {
        self.list_queues_responses.push_back(response);
    }

    pub fn push_get_queue_url_response(
        &mut self,
        response: std::result::Result<GetQueueUrlResponse, AwsSqsQueueTransportError>,
    ) {
        self.get_queue_url_responses.push_back(response);
    }

    pub fn push_get_queue_attributes_response(
        &mut self,
        response: std::result::Result<GetQueueAttributesResponse, AwsSqsQueueTransportError>,
    ) {
        self.get_queue_attributes_responses.push_back(response);
    }

    pub fn push_list_dead_letter_source_queues_response(
        &mut self,
        response: std::result::Result<
            ListDeadLetterSourceQueuesResponse,
            AwsSqsQueueTransportError,
        >,
    ) {
        self.list_dead_letter_source_queues_responses
            .push_back(response);
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

impl AwsSqsTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn list_queues(
        &mut self,
        request: &ListQueuesRequest,
    ) -> std::result::Result<ListQueuesResponse, AwsSqsQueueTransportError> {
        self.requests.push(request.recorded_request());
        self.list_queues_responses
            .pop_front()
            .unwrap_or(Err(AwsSqsQueueTransportError::InvalidResponse))
    }

    fn get_queue_url(
        &mut self,
        request: &GetQueueUrlRequest,
    ) -> std::result::Result<GetQueueUrlResponse, AwsSqsQueueTransportError> {
        self.requests.push(request.recorded_request());
        self.get_queue_url_responses
            .pop_front()
            .unwrap_or(Err(AwsSqsQueueTransportError::InvalidResponse))
    }

    fn get_queue_attributes(
        &mut self,
        request: &GetQueueAttributesRequest,
    ) -> std::result::Result<GetQueueAttributesResponse, AwsSqsQueueTransportError> {
        self.requests.push(request.recorded_request());
        self.get_queue_attributes_responses
            .pop_front()
            .unwrap_or(Err(AwsSqsQueueTransportError::InvalidResponse))
    }

    fn list_dead_letter_source_queues(
        &mut self,
        request: &ListDeadLetterSourceQueuesRequest,
    ) -> std::result::Result<ListDeadLetterSourceQueuesResponse, AwsSqsQueueTransportError> {
        self.requests.push(request.recorded_request());
        self.list_dead_letter_source_queues_responses
            .pop_front()
            .unwrap_or(Err(AwsSqsQueueTransportError::InvalidResponse))
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope: AwsSqsQueueScope,
    observed_at: DateTime<Utc>,
}

impl FixtureTransport {
    pub fn for_scope(scope: &AwsSqsQueueScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
        }
    }

    fn list_response(
        &self,
        request: &ListQueuesRequest,
        provenance: TransportProvenance,
    ) -> std::result::Result<ListQueuesResponse, AwsSqsQueueTransportError> {
        let url = self
            .scope
            .queue()
            .url()
            .cloned()
            .ok_or(AwsSqsQueueTransportError::InvalidResponse)?;
        ListQueuesResponse::new(
            request,
            vec![QueueSummary::new(url).map_err(|_| AwsSqsQueueTransportError::InvalidResponse)?],
            None,
            512,
            provenance,
        )
        .map_err(|_| AwsSqsQueueTransportError::InvalidResponse)
    }

    fn url_response(
        request: &GetQueueUrlRequest,
        queue: &QueueIdentity,
        provenance: TransportProvenance,
    ) -> std::result::Result<GetQueueUrlResponse, AwsSqsQueueTransportError> {
        let url = queue
            .url()
            .cloned()
            .ok_or(AwsSqsQueueTransportError::InvalidResponse)?;
        GetQueueUrlResponse::new(request, url, 512, provenance)
            .map_err(|_| AwsSqsQueueTransportError::InvalidResponse)
    }

    fn attributes(
        &self,
        request: &GetQueueAttributesRequest,
        provenance: TransportProvenance,
    ) -> std::result::Result<GetQueueAttributesResponse, AwsSqsQueueTransportError> {
        let created_at = self.observed_at - Duration::hours(1);
        let counts = crate::model::ApproximateQueueCounts::new(0, 0, 0, self.observed_at)
            .map_err(|_| AwsSqsQueueTransportError::InvalidResponse)?;
        let mut input = QueueAttributesInput::new(
            self.scope.queue().clone(),
            if self.scope.queue().name().is_fifo() {
                crate::model::QueueKind::Fifo
            } else {
                crate::model::QueueKind::Standard
            },
            counts,
            created_at,
            self.observed_at,
        )
        .map_err(|_| AwsSqsQueueTransportError::InvalidResponse)?
        .with_encryption(crate::model::EncryptionPosture::SqsManaged);
        if let Some(dlq) = self.scope.dead_letter_queue()
            && let Some(arn) = dlq.arn().cloned()
        {
            let redrive = crate::model::RedrivePolicyInput::new(arn, 5)
                .map_err(|_| AwsSqsQueueTransportError::InvalidResponse)?;
            input = input.with_redrive(redrive);
        }
        GetQueueAttributesResponse::new(request, input, 512, provenance)
            .map_err(|_| AwsSqsQueueTransportError::InvalidResponse)
    }

    fn dlq_response(
        &self,
        request: &ListDeadLetterSourceQueuesRequest,
        provenance: TransportProvenance,
    ) -> std::result::Result<ListDeadLetterSourceQueuesResponse, AwsSqsQueueTransportError> {
        ListDeadLetterSourceQueuesResponse::new(
            request,
            vec![self.scope.queue().clone()],
            512,
            provenance,
        )
        .map_err(|_| AwsSqsQueueTransportError::InvalidResponse)
    }
}

impl AwsSqsTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn list_queues(
        &mut self,
        request: &ListQueuesRequest,
    ) -> std::result::Result<ListQueuesResponse, AwsSqsQueueTransportError> {
        self.list_response(request, TransportProvenance::Fixture)
    }

    fn get_queue_url(
        &mut self,
        request: &GetQueueUrlRequest,
    ) -> std::result::Result<GetQueueUrlResponse, AwsSqsQueueTransportError> {
        let queue = if request.queue().name() == self.scope.queue().name() {
            self.scope.queue()
        } else if self
            .scope
            .dead_letter_queue()
            .is_some_and(|value| value.name() == request.queue().name())
        {
            self.scope.dead_letter_queue().expect("checked DLQ")
        } else {
            return Err(AwsSqsQueueTransportError::NotFound);
        };
        Self::url_response(request, queue, TransportProvenance::Fixture)
    }

    fn get_queue_attributes(
        &mut self,
        request: &GetQueueAttributesRequest,
    ) -> std::result::Result<GetQueueAttributesResponse, AwsSqsQueueTransportError> {
        self.attributes(request, TransportProvenance::Fixture)
    }

    fn list_dead_letter_source_queues(
        &mut self,
        request: &ListDeadLetterSourceQueuesRequest,
    ) -> std::result::Result<ListDeadLetterSourceQueuesResponse, AwsSqsQueueTransportError> {
        self.dlq_response(request, TransportProvenance::Fixture)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    inner: FixtureTransport,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &AwsSqsQueueScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            inner: FixtureTransport::for_scope(scope, observed_at),
        }
    }
}

impl AwsSqsTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn list_queues(
        &mut self,
        request: &ListQueuesRequest,
    ) -> std::result::Result<ListQueuesResponse, AwsSqsQueueTransportError> {
        self.inner
            .list_response(request, TransportProvenance::Loopback)
    }

    fn get_queue_url(
        &mut self,
        request: &GetQueueUrlRequest,
    ) -> std::result::Result<GetQueueUrlResponse, AwsSqsQueueTransportError> {
        let queue = if request.queue().name() == self.inner.scope.queue().name() {
            self.inner.scope.queue()
        } else if self
            .inner
            .scope
            .dead_letter_queue()
            .is_some_and(|value| value.name() == request.queue().name())
        {
            self.inner.scope.dead_letter_queue().expect("checked DLQ")
        } else {
            return Err(AwsSqsQueueTransportError::NotFound);
        };
        FixtureTransport::url_response(request, queue, TransportProvenance::Loopback)
    }

    fn get_queue_attributes(
        &mut self,
        request: &GetQueueAttributesRequest,
    ) -> std::result::Result<GetQueueAttributesResponse, AwsSqsQueueTransportError> {
        self.inner
            .attributes(request, TransportProvenance::Loopback)
    }

    fn list_dead_letter_source_queues(
        &mut self,
        request: &ListDeadLetterSourceQueuesRequest,
    ) -> std::result::Result<ListDeadLetterSourceQueuesResponse, AwsSqsQueueTransportError> {
        self.inner
            .dlq_response(request, TransportProvenance::Loopback)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsSqsTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn list_queues(
        &mut self,
        _request: &ListQueuesRequest,
    ) -> std::result::Result<ListQueuesResponse, AwsSqsQueueTransportError> {
        Err(AwsSqsQueueTransportError::BlockedEnv)
    }

    fn get_queue_url(
        &mut self,
        _request: &GetQueueUrlRequest,
    ) -> std::result::Result<GetQueueUrlResponse, AwsSqsQueueTransportError> {
        Err(AwsSqsQueueTransportError::BlockedEnv)
    }

    fn get_queue_attributes(
        &mut self,
        _request: &GetQueueAttributesRequest,
    ) -> std::result::Result<GetQueueAttributesResponse, AwsSqsQueueTransportError> {
        Err(AwsSqsQueueTransportError::BlockedEnv)
    }

    fn list_dead_letter_source_queues(
        &mut self,
        _request: &ListDeadLetterSourceQueuesRequest,
    ) -> std::result::Result<ListDeadLetterSourceQueuesResponse, AwsSqsQueueTransportError> {
        Err(AwsSqsQueueTransportError::BlockedEnv)
    }
}

fn validate_response_bytes(response_bytes: u64) -> Result<()> {
    if response_bytes == 0 || response_bytes > MAX_RESPONSE_BYTES {
        Err(AwsSqsQueueError::PartialEvidence)
    } else {
        Ok(())
    }
}

pub type FixtureAwsSqsTransport = FixtureTransport;
pub type LoopbackAwsSqsTransport = LoopbackTransport;
