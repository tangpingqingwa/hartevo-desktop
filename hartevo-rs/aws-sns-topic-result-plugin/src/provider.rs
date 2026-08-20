//! Metadata-only AWS SNS provider seams.
//!
//! The provider exposes only the four allowlisted SNS read operations. A
//! transport receives typed, digest-bound requests and returns typed,
//! already-redacted responses. There is deliberately no AWS SDK, signer,
//! credential resolver, HTTP client, message path, endpoint address, or
//! mutation operation in this Layer-1 crate.

use std::{collections::VecDeque, fmt};

use serde::{Serialize, Serializer, ser::SerializeStruct};
use zeroize::Zeroize;

use crate::error::{AwsSnsTopicError, AwsSnsTransportError, Result};
use crate::model::{
    AwsSnsTopicScope, Digest, SubscriptionIdentity, SubscriptionPosture, TopicIdentity,
    TopicPosture, TransportProvenance,
};
use crate::service::AwsSnsTopicRegistration;
use crate::{
    CONTRACT_VERSION, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES, PROVIDER_API_REVISION,
    PROVIDER_ID,
};

pub const LIST_TOPICS_OPERATION_PATH: &str = "/topics";
pub const GET_TOPIC_ATTRIBUTES_OPERATION_PATH: &str = "/topics/{topicDigest}/attributes";
pub const LIST_SUBSCRIPTIONS_BY_TOPIC_OPERATION_PATH: &str = "/topics/{topicDigest}/subscriptions";
pub const GET_SUBSCRIPTION_ATTRIBUTES_OPERATION_PATH: &str =
    "/subscriptions/{subscriptionDigest}/attributes";
const MAX_CURSOR_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum AwsSnsOperation {
    ListTopics,
    GetTopicAttributes,
    ListSubscriptionsByTopic,
    GetSubscriptionAttributes,
}

impl AwsSnsOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListTopics => "ListTopics",
            Self::GetTopicAttributes => "GetTopicAttributes",
            Self::ListSubscriptionsByTopic => "ListSubscriptionsByTopic",
            Self::GetSubscriptionAttributes => "GetSubscriptionAttributes",
        }
    }
}

/// The only provider transport trait exposed by Layer 1.
pub trait AwsSnsTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn list_topics(
        &mut self,
        request: &ListTopicsRequest,
    ) -> std::result::Result<ListTopicsResponse, AwsSnsTransportError>;

    fn get_topic_attributes(
        &mut self,
        request: &GetTopicAttributesRequest,
    ) -> std::result::Result<GetTopicAttributesResponse, AwsSnsTransportError>;

    fn list_subscriptions_by_topic(
        &mut self,
        request: &ListSubscriptionsByTopicRequest,
    ) -> std::result::Result<ListSubscriptionsByTopicResponse, AwsSnsTransportError>;

    fn get_subscription_attributes(
        &mut self,
        request: &GetSubscriptionAttributesRequest,
    ) -> std::result::Result<GetSubscriptionAttributesResponse, AwsSnsTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSnsProviderDefinition {
    pub id: String,
    pub contract_version: String,
    pub api_revision: String,
    pub operations: Vec<AwsSnsOperation>,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl AwsSnsProviderDefinition {
    pub fn for_transport(provenance: TransportProvenance) -> Result<Self> {
        let definition = Self {
            id: PROVIDER_ID.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            api_revision: PROVIDER_API_REVISION.to_owned(),
            operations: vec![
                AwsSnsOperation::ListTopics,
                AwsSnsOperation::GetTopicAttributes,
                AwsSnsOperation::ListSubscriptionsByTopic,
                AwsSnsOperation::GetSubscriptionAttributes,
            ],
            provenance,
            connected: false,
            native: false,
            first_party: false,
        };
        definition.validate()?;
        Ok(definition)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-sns-provider-definition/v1",
            &[
                ("id", self.id.clone()),
                ("contract", self.contract_version.clone()),
                ("api", self.api_revision.clone()),
                (
                    "operations",
                    self.operations
                        .iter()
                        .map(|operation| operation.as_str())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("first_party", self.first_party.to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.id != PROVIDER_ID
            || self.contract_version != CONTRACT_VERSION
            || self.api_revision != PROVIDER_API_REVISION
            || self.operations
                != vec![
                    AwsSnsOperation::ListTopics,
                    AwsSnsOperation::GetTopicAttributes,
                    AwsSnsOperation::ListSubscriptionsByTopic,
                    AwsSnsOperation::GetSubscriptionAttributes,
                ]
            || self.connected
            || self.native
            || self.first_party
            || self.provenance.is_native()
        {
            Err(AwsSnsTopicError::ProviderDrift)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
pub struct AwsSnsProvider<T: AwsSnsTransport> {
    transport: T,
    definition: AwsSnsProviderDefinition,
}

impl<T: AwsSnsTransport> AwsSnsProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        let definition = AwsSnsProviderDefinition::for_transport(transport.provenance())?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn definition(&self) -> &AwsSnsProviderDefinition {
        &self.definition
    }

    pub fn provider_digest(&self) -> Digest {
        self.definition.digest()
    }

    pub fn provider_binding_digest(&self) -> Digest {
        AwsSnsTopicRegistration::provider_binding_digest(
            &self.definition,
            &self.definition.digest(),
        )
    }

    pub fn list_topics(
        &mut self,
        request: &ListTopicsRequest,
    ) -> std::result::Result<ListTopicsResponse, AwsSnsTransportError> {
        self.transport.list_topics(request)
    }

    pub fn get_topic_attributes(
        &mut self,
        request: &GetTopicAttributesRequest,
    ) -> std::result::Result<GetTopicAttributesResponse, AwsSnsTransportError> {
        self.transport.get_topic_attributes(request)
    }

    pub fn list_subscriptions_by_topic(
        &mut self,
        request: &ListSubscriptionsByTopicRequest,
    ) -> std::result::Result<ListSubscriptionsByTopicResponse, AwsSnsTransportError> {
        self.transport.list_subscriptions_by_topic(request)
    }

    pub fn get_subscription_attributes(
        &mut self,
        request: &GetSubscriptionAttributesRequest,
    ) -> std::result::Result<GetSubscriptionAttributesResponse, AwsSnsTransportError> {
        self.transport.get_subscription_attributes(request)
    }
}

impl Default for AwsSnsProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked AWS SNS provider definition")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueCursor {
    token_digest: Digest,
    binding_digest: Digest,
    page_number: u16,
}

impl OpaqueCursor {
    pub fn new(raw_token: impl Into<String>) -> Result<Self> {
        let mut raw_token = raw_token.into();
        if raw_token.is_empty() || raw_token.len() > MAX_CURSOR_BYTES {
            raw_token.zeroize();
            return Err(AwsSnsTopicError::InvalidRequest);
        }
        let token_digest = Digest::from_parts(
            "aws-sns-provider-cursor/v1",
            &[("token", raw_token.clone())],
        );
        raw_token.zeroize();
        Ok(Self {
            token_digest,
            binding_digest: Digest::zero(),
            page_number: 1,
        })
    }

    pub fn for_next_page(
        raw_token: impl Into<String>,
        operation: AwsSnsOperation,
        scope_digest: &Digest,
        page_number: u16,
    ) -> Result<Self> {
        if !(2..=MAX_PAGES).contains(&page_number) {
            return Err(AwsSnsTopicError::InvalidRequest);
        }
        let mut cursor = Self::new(raw_token)?;
        cursor.binding_digest = Digest::from_parts(
            "aws-sns-cursor-binding/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                ("scope", scope_digest.as_str().to_owned()),
                ("page", page_number.to_string()),
            ],
        );
        cursor.page_number = page_number;
        Ok(cursor)
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    fn validate_for(
        &self,
        operation: AwsSnsOperation,
        scope_digest: &Digest,
        page_number: u16,
    ) -> Result<()> {
        self.token_digest.validate()?;
        if self.binding_digest == Digest::zero() {
            return Ok(());
        }
        let expected = Digest::from_parts(
            "aws-sns-cursor-binding/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                ("scope", scope_digest.as_str().to_owned()),
                ("page", page_number.to_string()),
            ],
        );
        if self.binding_digest == expected {
            Ok(())
        } else {
            Err(AwsSnsTopicError::ScopeMismatch)
        }
    }
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

impl Serialize for OpaqueCursor {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("OpaqueCursor", 3)?;
        state.serialize_field("tokenDigest", &self.token_digest)?;
        state.serialize_field("bindingDigest", &self.binding_digest)?;
        state.serialize_field("pageNumber", &self.page_number)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsSnsOperation,
    pub scope_digest: Digest,
    pub topic_digest: Option<Digest>,
    pub subscription_digest: Option<Digest>,
    pub cursor_digest: Option<Digest>,
    pub request_digest: Digest,
    pub path_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListTopicsRequest {
    scope: AwsSnsTopicScope,
    max_results: u16,
    cursor: Option<OpaqueCursor>,
    request_digest: Digest,
}

impl ListTopicsRequest {
    pub fn new(
        scope: &AwsSnsTopicScope,
        max_results: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self> {
        scope.validate()?;
        validate_page_size(max_results)?;
        let page_number = cursor.as_ref().map_or(1, OpaqueCursor::page_number);
        if page_number > MAX_PAGES {
            return Err(AwsSnsTopicError::InvalidRequest);
        }
        if let Some(cursor) = &cursor {
            cursor.validate_for(AwsSnsOperation::ListTopics, &scope.digest(), page_number)?;
        }
        let request_digest = request_digest(
            AwsSnsOperation::ListTopics,
            scope,
            None,
            None,
            max_results,
            cursor.as_ref(),
        );
        Ok(Self {
            scope: scope.clone(),
            max_results,
            cursor,
            request_digest,
        })
    }

    pub fn scope(&self) -> &AwsSnsTopicScope {
        &self.scope
    }

    pub const fn max_results(&self) -> u16 {
        self.max_results
    }

    pub fn cursor(&self) -> Option<&OpaqueCursor> {
        self.cursor.as_ref()
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn page_number(&self) -> u16 {
        self.cursor.as_ref().map_or(1, OpaqueCursor::page_number)
    }

    pub fn path_and_query(&self) -> String {
        let cursor = self.cursor.as_ref().map_or_else(String::new, |value| {
            value.token_digest().as_str().to_owned()
        });
        format!(
            "{LIST_TOPICS_OPERATION_PATH}?maxResults={}&nextTokenDigest={cursor}",
            self.max_results
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsSnsOperation::ListTopics,
            scope_digest: self.scope.digest(),
            topic_digest: None,
            subscription_digest: None,
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.token_digest().clone()),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for ListTopicsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListTopicsRequest")
            .field("scope_digest", &self.scope.digest())
            .field("max_results", &self.max_results)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetTopicAttributesRequest {
    scope: AwsSnsTopicScope,
    request_digest: Digest,
}

impl GetTopicAttributesRequest {
    pub fn new(scope: &AwsSnsTopicScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: request_digest(
                AwsSnsOperation::GetTopicAttributes,
                scope,
                Some(scope.topic()),
                None,
                0,
                None,
            ),
        })
    }

    pub fn scope(&self) -> &AwsSnsTopicScope {
        &self.scope
    }

    pub fn topic(&self) -> &TopicIdentity {
        self.scope.topic()
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/topics/{}/attributes",
            self.scope.topic().digest().as_str()
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsSnsOperation::GetTopicAttributes,
            scope_digest: self.scope.digest(),
            topic_digest: Some(self.scope.topic().digest()),
            subscription_digest: None,
            cursor_digest: None,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for GetTopicAttributesRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetTopicAttributesRequest")
            .field("scope_digest", &self.scope.digest())
            .field("topic_digest", &self.scope.topic().digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListSubscriptionsByTopicRequest {
    scope: AwsSnsTopicScope,
    max_results: u16,
    cursor: Option<OpaqueCursor>,
    request_digest: Digest,
}

impl ListSubscriptionsByTopicRequest {
    pub fn new(
        scope: &AwsSnsTopicScope,
        max_results: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self> {
        scope.validate()?;
        validate_page_size(max_results)?;
        let page_number = cursor.as_ref().map_or(1, OpaqueCursor::page_number);
        if page_number > MAX_PAGES {
            return Err(AwsSnsTopicError::InvalidRequest);
        }
        if let Some(cursor) = &cursor {
            cursor.validate_for(
                AwsSnsOperation::ListSubscriptionsByTopic,
                &scope.digest(),
                page_number,
            )?;
        }
        let request_digest = request_digest(
            AwsSnsOperation::ListSubscriptionsByTopic,
            scope,
            Some(scope.topic()),
            None,
            max_results,
            cursor.as_ref(),
        );
        Ok(Self {
            scope: scope.clone(),
            max_results,
            cursor,
            request_digest,
        })
    }

    pub fn scope(&self) -> &AwsSnsTopicScope {
        &self.scope
    }

    pub fn topic(&self) -> &TopicIdentity {
        self.scope.topic()
    }

    pub const fn max_results(&self) -> u16 {
        self.max_results
    }

    pub fn cursor(&self) -> Option<&OpaqueCursor> {
        self.cursor.as_ref()
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn page_number(&self) -> u16 {
        self.cursor.as_ref().map_or(1, OpaqueCursor::page_number)
    }

    pub fn path_and_query(&self) -> String {
        let cursor = self.cursor.as_ref().map_or_else(String::new, |value| {
            value.token_digest().as_str().to_owned()
        });
        format!(
            "/topics/{}/subscriptions?maxResults={}&nextTokenDigest={cursor}",
            self.scope.topic().digest().as_str(),
            self.max_results,
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsSnsOperation::ListSubscriptionsByTopic,
            scope_digest: self.scope.digest(),
            topic_digest: Some(self.scope.topic().digest()),
            subscription_digest: None,
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.token_digest().clone()),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for ListSubscriptionsByTopicRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListSubscriptionsByTopicRequest")
            .field("scope_digest", &self.scope.digest())
            .field("topic_digest", &self.scope.topic().digest())
            .field("max_results", &self.max_results)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetSubscriptionAttributesRequest {
    scope: AwsSnsTopicScope,
    subscription: SubscriptionIdentity,
    request_digest: Digest,
}

impl GetSubscriptionAttributesRequest {
    pub fn new(scope: &AwsSnsTopicScope, subscription: &SubscriptionIdentity) -> Result<Self> {
        scope.validate()?;
        if !scope.is_subscription_allowlisted(subscription) {
            return Err(AwsSnsTopicError::SubscriptionAllowlistViolation);
        }
        Ok(Self {
            scope: scope.clone(),
            subscription: subscription.clone(),
            request_digest: request_digest(
                AwsSnsOperation::GetSubscriptionAttributes,
                scope,
                Some(scope.topic()),
                Some(subscription),
                0,
                None,
            ),
        })
    }

    pub fn scope(&self) -> &AwsSnsTopicScope {
        &self.scope
    }

    pub fn topic(&self) -> &TopicIdentity {
        self.scope.topic()
    }

    pub fn subscription(&self) -> &SubscriptionIdentity {
        &self.subscription
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/subscriptions/{}/attributes",
            self.subscription.digest().as_str()
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsSnsOperation::GetSubscriptionAttributes,
            scope_digest: self.scope.digest(),
            topic_digest: Some(self.scope.topic().digest()),
            subscription_digest: Some(self.subscription.digest()),
            cursor_digest: None,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for GetSubscriptionAttributesRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetSubscriptionAttributesRequest")
            .field("scope_digest", &self.scope.digest())
            .field("topic_digest", &self.scope.topic().digest())
            .field("subscription_digest", &self.subscription.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TopicRecord {
    pub topic_digest: Digest,
    pub posture: TopicPosture,
}

impl TopicRecord {
    pub fn new(topic: &TopicIdentity, posture: TopicPosture) -> Self {
        Self {
            topic_digest: topic.digest(),
            posture,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-sns-topic-record/v1",
            &[
                ("topic", self.topic_digest.as_str().to_owned()),
                ("posture", self.posture.digest().as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionRecord {
    pub subscription_digest: Digest,
    pub posture: SubscriptionPosture,
}

impl SubscriptionRecord {
    pub fn new(subscription: &SubscriptionIdentity, posture: SubscriptionPosture) -> Result<Self> {
        if posture.subscription_digest != subscription.digest() {
            return Err(AwsSnsTopicError::SubscriptionReplaced);
        }
        Ok(Self {
            subscription_digest: subscription.digest(),
            posture,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-sns-subscription-record/v1",
            &[
                ("subscription", self.subscription_digest.as_str().to_owned()),
                ("posture", self.posture.digest().as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListTopicsResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub topics: Vec<TopicRecord>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl ListTopicsResponse {
    pub fn new(
        request: &ListTopicsRequest,
        topics: Vec<TopicRecord>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response(response_bytes, topics.len(), request.max_results())?;
        validate_next_cursor(
            request.scope(),
            AwsSnsOperation::ListTopics,
            request.page_number(),
            next_cursor.as_ref(),
        )?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            topics,
            next_cursor,
            response_bytes,
            provenance,
            evidence_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn validate_integrity(&self, request: &ListTopicsRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.topics.len() > request.max_results() as usize
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsSnsTopicError::TamperedEvidence);
        }
        validate_next_cursor(
            request.scope(),
            AwsSnsOperation::ListTopics,
            request.page_number(),
            self.next_cursor.as_ref(),
        )
    }

    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-sns-list-topics-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                (
                    "topics",
                    self.topics
                        .iter()
                        .map(TopicRecord::digest)
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "cursor",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| {
                            cursor.token_digest().as_str().to_owned()
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
pub struct GetTopicAttributesResponse {
    pub scope_digest: Digest,
    pub topic_digest: Digest,
    pub request_digest: Digest,
    pub posture: TopicPosture,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl GetTopicAttributesResponse {
    pub fn new(
        request: &GetTopicAttributesRequest,
        topic: &TopicIdentity,
        posture: TopicPosture,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response(response_bytes, 1, 1)?;
        if !request.scope().is_topic_allowlisted(topic) {
            return Err(AwsSnsTopicError::TopicReplaced);
        }
        let mut response = Self {
            scope_digest: request.scope().digest(),
            topic_digest: topic.digest(),
            request_digest: request.request_digest().clone(),
            posture,
            response_bytes,
            provenance,
            evidence_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn validate_integrity(&self, request: &GetTopicAttributesRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.topic_digest != request.topic().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsSnsTopicError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-sns-get-topic-attributes-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("topic", self.topic_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("posture", self.posture.digest().as_str().to_owned()),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListSubscriptionsByTopicResponse {
    pub scope_digest: Digest,
    pub topic_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub subscriptions: Vec<SubscriptionRecord>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl ListSubscriptionsByTopicResponse {
    pub fn new(
        request: &ListSubscriptionsByTopicRequest,
        subscriptions: Vec<SubscriptionRecord>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response(response_bytes, subscriptions.len(), request.max_results())?;
        validate_next_cursor(
            request.scope(),
            AwsSnsOperation::ListSubscriptionsByTopic,
            request.page_number(),
            next_cursor.as_ref(),
        )?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            topic_digest: request.topic().digest(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            subscriptions,
            next_cursor,
            response_bytes,
            provenance,
            evidence_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn validate_integrity(&self, request: &ListSubscriptionsByTopicRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.topic_digest != request.topic().digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.subscriptions.len() > request.max_results() as usize
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsSnsTopicError::TamperedEvidence);
        }
        validate_next_cursor(
            request.scope(),
            AwsSnsOperation::ListSubscriptionsByTopic,
            request.page_number(),
            self.next_cursor.as_ref(),
        )
    }

    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-sns-list-subscriptions-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("topic", self.topic_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                (
                    "subscriptions",
                    self.subscriptions
                        .iter()
                        .map(SubscriptionRecord::digest)
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "cursor",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| {
                            cursor.token_digest().as_str().to_owned()
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
pub struct GetSubscriptionAttributesResponse {
    pub scope_digest: Digest,
    pub topic_digest: Digest,
    pub subscription_digest: Digest,
    pub request_digest: Digest,
    pub posture: SubscriptionPosture,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl GetSubscriptionAttributesResponse {
    pub fn new(
        request: &GetSubscriptionAttributesRequest,
        subscription: &SubscriptionIdentity,
        posture: SubscriptionPosture,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response(response_bytes, 1, 1)?;
        if !request.scope().is_subscription_allowlisted(subscription) {
            return Err(AwsSnsTopicError::SubscriptionReplaced);
        }
        if posture.subscription_digest != subscription.digest() {
            return Err(AwsSnsTopicError::SubscriptionReplaced);
        }
        let mut response = Self {
            scope_digest: request.scope().digest(),
            topic_digest: request.topic().digest(),
            subscription_digest: subscription.digest(),
            request_digest: request.request_digest().clone(),
            posture,
            response_bytes,
            provenance,
            evidence_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn validate_integrity(&self, request: &GetSubscriptionAttributesRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.topic_digest != request.topic().digest()
            || self.subscription_digest != request.subscription().digest()
            || self.request_digest != *request.request_digest()
            || self.posture.subscription_digest != self.subscription_digest
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsSnsTopicError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-sns-get-subscription-attributes-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("topic", self.topic_digest.as_str().to_owned()),
                ("subscription", self.subscription_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("posture", self.posture.digest().as_str().to_owned()),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

fn request_digest(
    operation: AwsSnsOperation,
    scope: &AwsSnsTopicScope,
    topic: Option<&TopicIdentity>,
    subscription: Option<&SubscriptionIdentity>,
    max_results: u16,
    cursor: Option<&OpaqueCursor>,
) -> Digest {
    Digest::from_parts(
        "aws-sns-request/v1",
        &[
            ("operation", operation.as_str().to_owned()),
            ("scope", scope.digest().as_str().to_owned()),
            (
                "topic",
                topic.map_or_else(String::new, |value| value.digest().as_str().to_owned()),
            ),
            (
                "subscription",
                subscription.map_or_else(String::new, |value| value.digest().as_str().to_owned()),
            ),
            ("max_results", max_results.to_string()),
            (
                "cursor",
                cursor.map_or_else(String::new, |value| {
                    value.token_digest().as_str().to_owned()
                }),
            ),
        ],
    )
}

fn validate_page_size(max_results: u16) -> Result<()> {
    if (1..=MAX_PAGE_SIZE).contains(&max_results) {
        Ok(())
    } else {
        Err(AwsSnsTopicError::InvalidRequest)
    }
}

fn validate_response(response_bytes: u64, item_count: usize, max_results: u16) -> Result<()> {
    if response_bytes > MAX_RESPONSE_BYTES || item_count > max_results as usize {
        Err(AwsSnsTopicError::PartialEvidence)
    } else {
        Ok(())
    }
}

fn validate_next_cursor(
    scope: &AwsSnsTopicScope,
    operation: AwsSnsOperation,
    page_number: u16,
    cursor: Option<&OpaqueCursor>,
) -> Result<()> {
    if let Some(cursor) = cursor {
        if page_number >= MAX_PAGES {
            return Err(AwsSnsTopicError::PartialEvidence);
        }
        cursor.validate_for(operation, &scope.digest(), page_number.saturating_add(1))?;
    }
    Ok(())
}

#[derive(Clone, Debug, Default)]
pub struct RecordingTransport {
    list_topics: VecDeque<std::result::Result<ListTopicsResponse, AwsSnsTransportError>>,
    get_topic_attributes:
        VecDeque<std::result::Result<GetTopicAttributesResponse, AwsSnsTransportError>>,
    list_subscriptions:
        VecDeque<std::result::Result<ListSubscriptionsByTopicResponse, AwsSnsTransportError>>,
    get_subscription_attributes:
        VecDeque<std::result::Result<GetSubscriptionAttributesResponse, AwsSnsTransportError>>,
}

impl RecordingTransport {
    pub fn push_list_topics(
        &mut self,
        response: std::result::Result<ListTopicsResponse, AwsSnsTransportError>,
    ) {
        self.list_topics.push_back(response);
    }

    pub fn push_list_topics_response(
        &mut self,
        response: std::result::Result<ListTopicsResponse, AwsSnsTransportError>,
    ) {
        self.push_list_topics(response);
    }

    pub fn push_get_topic_attributes(
        &mut self,
        response: std::result::Result<GetTopicAttributesResponse, AwsSnsTransportError>,
    ) {
        self.get_topic_attributes.push_back(response);
    }

    pub fn push_get_topic_attributes_response(
        &mut self,
        response: std::result::Result<GetTopicAttributesResponse, AwsSnsTransportError>,
    ) {
        self.push_get_topic_attributes(response);
    }

    pub fn push_list_subscriptions(
        &mut self,
        response: std::result::Result<ListSubscriptionsByTopicResponse, AwsSnsTransportError>,
    ) {
        self.list_subscriptions.push_back(response);
    }

    pub fn push_list_subscriptions_by_topic(
        &mut self,
        response: std::result::Result<ListSubscriptionsByTopicResponse, AwsSnsTransportError>,
    ) {
        self.push_list_subscriptions(response);
    }

    pub fn push_get_subscription_attributes(
        &mut self,
        response: std::result::Result<GetSubscriptionAttributesResponse, AwsSnsTransportError>,
    ) {
        self.get_subscription_attributes.push_back(response);
    }

    pub fn push_get_subscription_attributes_response(
        &mut self,
        response: std::result::Result<GetSubscriptionAttributesResponse, AwsSnsTransportError>,
    ) {
        self.push_get_subscription_attributes(response);
    }
}

impl AwsSnsTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn list_topics(
        &mut self,
        _request: &ListTopicsRequest,
    ) -> std::result::Result<ListTopicsResponse, AwsSnsTransportError> {
        self.list_topics
            .pop_front()
            .unwrap_or(Err(AwsSnsTransportError::BlockedEnv))
    }

    fn get_topic_attributes(
        &mut self,
        _request: &GetTopicAttributesRequest,
    ) -> std::result::Result<GetTopicAttributesResponse, AwsSnsTransportError> {
        self.get_topic_attributes
            .pop_front()
            .unwrap_or(Err(AwsSnsTransportError::BlockedEnv))
    }

    fn list_subscriptions_by_topic(
        &mut self,
        _request: &ListSubscriptionsByTopicRequest,
    ) -> std::result::Result<ListSubscriptionsByTopicResponse, AwsSnsTransportError> {
        self.list_subscriptions
            .pop_front()
            .unwrap_or(Err(AwsSnsTransportError::BlockedEnv))
    }

    fn get_subscription_attributes(
        &mut self,
        _request: &GetSubscriptionAttributesRequest,
    ) -> std::result::Result<GetSubscriptionAttributesResponse, AwsSnsTransportError> {
        self.get_subscription_attributes
            .pop_front()
            .unwrap_or(Err(AwsSnsTransportError::BlockedEnv))
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsSnsTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn list_topics(
        &mut self,
        _request: &ListTopicsRequest,
    ) -> std::result::Result<ListTopicsResponse, AwsSnsTransportError> {
        Err(AwsSnsTransportError::BlockedEnv)
    }

    fn get_topic_attributes(
        &mut self,
        _request: &GetTopicAttributesRequest,
    ) -> std::result::Result<GetTopicAttributesResponse, AwsSnsTransportError> {
        Err(AwsSnsTransportError::BlockedEnv)
    }

    fn list_subscriptions_by_topic(
        &mut self,
        _request: &ListSubscriptionsByTopicRequest,
    ) -> std::result::Result<ListSubscriptionsByTopicResponse, AwsSnsTransportError> {
        Err(AwsSnsTransportError::BlockedEnv)
    }

    fn get_subscription_attributes(
        &mut self,
        _request: &GetSubscriptionAttributesRequest,
    ) -> std::result::Result<GetSubscriptionAttributesResponse, AwsSnsTransportError> {
        Err(AwsSnsTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Default)]
pub struct FixtureTransport {
    scope: Option<AwsSnsTopicScope>,
}

impl FixtureTransport {
    pub fn for_scope(scope: impl Into<AwsSnsTopicScope>) -> Result<Self> {
        let scope = scope.into();
        scope.validate()?;
        Ok(Self { scope: Some(scope) })
    }
}

#[derive(Clone, Debug, Default)]
pub struct LoopbackTransport {
    scope: Option<AwsSnsTopicScope>,
}

impl LoopbackTransport {
    pub fn for_scope(scope: impl Into<AwsSnsTopicScope>) -> Result<Self> {
        let scope = scope.into();
        scope.validate()?;
        Ok(Self { scope: Some(scope) })
    }
}

macro_rules! impl_synthetic_transport {
    ($transport:ident, $provenance:expr) => {
        impl AwsSnsTransport for $transport {
            fn provenance(&self) -> TransportProvenance {
                $provenance
            }

            fn list_topics(
                &mut self,
                request: &ListTopicsRequest,
            ) -> std::result::Result<ListTopicsResponse, AwsSnsTransportError> {
                let scope = self
                    .scope
                    .as_ref()
                    .ok_or(AwsSnsTransportError::BlockedEnv)?;
                let record = TopicRecord::new(scope.topic(), TopicPosture::fixture());
                ListTopicsResponse::new(request, vec![record], None, 256, $provenance)
                    .map_err(|_| AwsSnsTransportError::InvalidResponse)
            }

            fn get_topic_attributes(
                &mut self,
                request: &GetTopicAttributesRequest,
            ) -> std::result::Result<GetTopicAttributesResponse, AwsSnsTransportError> {
                let scope = self
                    .scope
                    .as_ref()
                    .ok_or(AwsSnsTransportError::BlockedEnv)?;
                GetTopicAttributesResponse::new(
                    request,
                    scope.topic(),
                    TopicPosture::fixture(),
                    256,
                    $provenance,
                )
                .map_err(|_| AwsSnsTransportError::InvalidResponse)
            }

            fn list_subscriptions_by_topic(
                &mut self,
                request: &ListSubscriptionsByTopicRequest,
            ) -> std::result::Result<ListSubscriptionsByTopicResponse, AwsSnsTransportError> {
                let scope = self
                    .scope
                    .as_ref()
                    .ok_or(AwsSnsTransportError::BlockedEnv)?;
                let page_number = request.page_number();
                let page_size = usize::from(request.max_results());
                let start = usize::from(page_number.saturating_sub(1)) * page_size;
                let end = start
                    .saturating_add(page_size)
                    .min(scope.subscriptions().len());
                let subscriptions = scope
                    .subscriptions()
                    .get(start..end)
                    .unwrap_or_default()
                    .iter()
                    .map(|subscription| {
                        SubscriptionRecord::new(
                            subscription,
                            SubscriptionPosture::fixture(subscription),
                        )
                    })
                    .collect::<Result<Vec<_>>>()
                    .map_err(|_| AwsSnsTransportError::InvalidResponse)?;
                let next_cursor = if end < scope.subscriptions().len() {
                    Some(
                        OpaqueCursor::for_next_page(
                            format!("synthetic-page-{}", page_number.saturating_add(1)),
                            AwsSnsOperation::ListSubscriptionsByTopic,
                            &scope.digest(),
                            page_number.saturating_add(1),
                        )
                        .map_err(|_| AwsSnsTransportError::InvalidResponse)?,
                    )
                } else {
                    None
                };
                ListSubscriptionsByTopicResponse::new(
                    request,
                    subscriptions,
                    next_cursor,
                    512,
                    $provenance,
                )
                .map_err(|_| AwsSnsTransportError::InvalidResponse)
            }

            fn get_subscription_attributes(
                &mut self,
                request: &GetSubscriptionAttributesRequest,
            ) -> std::result::Result<GetSubscriptionAttributesResponse, AwsSnsTransportError> {
                let scope = self
                    .scope
                    .as_ref()
                    .ok_or(AwsSnsTransportError::BlockedEnv)?;
                GetSubscriptionAttributesResponse::new(
                    request,
                    request.subscription(),
                    SubscriptionPosture::fixture(request.subscription()),
                    256,
                    $provenance,
                )
                .map_err(|_| {
                    let _ = scope;
                    AwsSnsTransportError::InvalidResponse
                })
            }
        }
    };
}

impl_synthetic_transport!(FixtureTransport, TransportProvenance::Fixture);
impl_synthetic_transport!(LoopbackTransport, TransportProvenance::Loopback);
