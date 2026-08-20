use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    GCP_PUBSUB_SUBSCRIPTION_RESULT_PROVIDER_ID, GCP_PUBSUB_SUBSCRIPTION_RESULT_SCHEMA_VERSION,
    model::{
        Digest, GcpPubsubSubscriptionScope, ModelError, OpaquePageToken, PermissionFence,
        ProviderErrorKind, Revision, SecretReference, SubscriptionConfiguration,
        TopicConfiguration,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider version is empty")]
    EmptyVersion,
    #[error("Layer 1 accepts only fixture, recording, loopback, or BLOCKED_ENV provenance")]
    NativeProviderForbidden,
    #[error("transport provenance does not match the provider definition")]
    ProvenanceMismatch,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpPubsubProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_version: String,
    pub capability_digest: Digest,
    pub provider_digest: Digest,
    pub provenance: ProviderProvenance,
    pub get_topic: bool,
    pub get_subscription: bool,
    pub list_subscriptions: bool,
    pub live_execution: bool,
    pub native: bool,
    pub first_party: bool,
}

impl GcpPubsubProviderDefinition {
    pub fn new(
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_version = provider_version.into();
        if provider_version.is_empty() {
            return Err(ProviderDefinitionError::EmptyVersion);
        }
        if provenance.native() || provenance.connected() || provenance.first_party() {
            return Err(ProviderDefinitionError::NativeProviderForbidden);
        }
        let capability_digest = Digest::from_fields(
            "gcp-pubsub-provider-capability/v1",
            &[
                GCP_PUBSUB_SUBSCRIPTION_RESULT_SCHEMA_VERSION.to_owned(),
                GCP_PUBSUB_SUBSCRIPTION_RESULT_PROVIDER_ID.to_owned(),
                provider_version.clone(),
                format!("{provenance:?}"),
                "GET /v1/{topic}".to_owned(),
                "GET /v1/{subscription}".to_owned(),
                "GET /v1/{project}/subscriptions".to_owned(),
                "live_execution=false".to_owned(),
                "native=false".to_owned(),
                "first_party=false".to_owned(),
            ],
        );
        let provider_digest = Digest::from_fields(
            "gcp-pubsub-provider-definition/v1",
            &[
                GCP_PUBSUB_SUBSCRIPTION_RESULT_SCHEMA_VERSION.to_owned(),
                GCP_PUBSUB_SUBSCRIPTION_RESULT_PROVIDER_ID.to_owned(),
                provider_version.clone(),
                capability_digest.as_str().to_owned(),
                format!("{provenance:?}"),
            ],
        );
        Ok(Self {
            schema_version: GCP_PUBSUB_SUBSCRIPTION_RESULT_SCHEMA_VERSION.to_owned(),
            provider_id: GCP_PUBSUB_SUBSCRIPTION_RESULT_PROVIDER_ID.to_owned(),
            provider_version,
            capability_digest,
            provider_digest,
            provenance,
            get_topic: true,
            get_subscription: true,
            list_subscriptions: true,
            live_execution: false,
            native: false,
            first_party: false,
        })
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("GCP Pub/Sub provider transport returned {kind:?}")]
pub struct TransportError {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub blocked_env: bool,
    diagnostic_digest: Digest,
}

impl TransportError {
    pub fn new(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        diagnostic: impl AsRef<[u8]>,
    ) -> Self {
        let retryable = matches!(
            kind,
            ProviderErrorKind::RateLimited
                | ProviderErrorKind::ServerFailure
                | ProviderErrorKind::Timeout
        );
        Self {
            kind,
            status_code,
            retryable,
            blocked_env: kind == ProviderErrorKind::BlockedEnv,
            diagnostic_digest: Digest::from_text(diagnostic),
        }
    }

    pub fn bad_request() -> Self {
        Self::new(ProviderErrorKind::BadRequest, Some(400), "bad-request")
    }

    pub fn unauthenticated() -> Self {
        Self::new(
            ProviderErrorKind::Unauthenticated,
            Some(401),
            "unauthenticated",
        )
    }

    pub fn permission_denied() -> Self {
        Self::new(
            ProviderErrorKind::PermissionDenied,
            Some(403),
            "permission-denied",
        )
    }

    pub fn not_found() -> Self {
        Self::new(ProviderErrorKind::NotFound, Some(404), "not-found")
    }

    pub fn rate_limited() -> Self {
        Self::new(ProviderErrorKind::RateLimited, Some(429), "rate-limited")
    }

    pub fn server_failure() -> Self {
        Self::new(
            ProviderErrorKind::ServerFailure,
            Some(500),
            "server-failure",
        )
    }

    pub fn timeout() -> Self {
        Self::new(ProviderErrorKind::Timeout, None, "timeout")
    }

    pub fn malformed_response() -> Self {
        Self::new(
            ProviderErrorKind::MalformedResponse,
            None,
            "malformed-response",
        )
    }

    pub fn blocked_env() -> Self {
        Self::new(ProviderErrorKind::BlockedEnv, None, "BLOCKED_ENV")
    }

    pub fn unknown() -> Self {
        Self::new(ProviderErrorKind::Unknown, None, "unknown")
    }

    pub fn diagnostic_digest(&self) -> &Digest {
        &self.diagnostic_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderOperation {
    GetTopic,
    GetSubscription,
    ListSubscriptions,
}

impl ProviderOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetTopic => "get_topic",
            Self::GetSubscription => "get_subscription",
            Self::ListSubscriptions => "list_subscriptions",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: ProviderOperation,
    pub scope_digest: Digest,
    pub resource_digest: Digest,
    pub page_token_digest: Option<Digest>,
    pub request_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTopicRequest {
    pub scope_digest: Digest,
    pub project_digest: Digest,
    pub topic_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub work_product_revision: Revision,
    pub credential_revision: Revision,
    pub secret_reference_digest: Digest,
    pub request_digest: Digest,
}

impl GetTopicRequest {
    pub fn new(
        scope: &GcpPubsubSubscriptionScope,
        secret: &SecretReference,
    ) -> Result<Self, ModelError> {
        if secret.scope_digest() != &scope.scope_digest() || secret.is_revoked() {
            return Err(ModelError::InvalidScope);
        }
        let request_digest = Digest::from_fields(
            "gcp-pubsub-get-topic-request/v1",
            &[
                scope.scope_digest().as_str().to_owned(),
                scope.topic().digest().as_str().to_owned(),
                scope.permission_digest().as_str().to_owned(),
                scope.consent_digest().as_str().to_owned(),
                secret.reference_digest().as_str().to_owned(),
                secret.credential_revision().get().to_string(),
            ],
        );
        Ok(Self {
            scope_digest: scope.scope_digest(),
            project_digest: scope.project().digest(),
            topic_digest: scope.topic().digest(),
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            work_product_revision: scope.work_product_revision(),
            credential_revision: secret.credential_revision(),
            secret_reference_digest: secret.reference_digest().clone(),
            request_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetSubscriptionRequest {
    pub scope_digest: Digest,
    pub project_digest: Digest,
    pub subscription_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub work_product_revision: Revision,
    pub credential_revision: Revision,
    pub secret_reference_digest: Digest,
    pub request_digest: Digest,
}

impl GetSubscriptionRequest {
    pub fn new(
        scope: &GcpPubsubSubscriptionScope,
        secret: &SecretReference,
    ) -> Result<Self, ModelError> {
        if secret.scope_digest() != &scope.scope_digest() || secret.is_revoked() {
            return Err(ModelError::InvalidScope);
        }
        let request_digest = Digest::from_fields(
            "gcp-pubsub-get-subscription-request/v1",
            &[
                scope.scope_digest().as_str().to_owned(),
                scope.subscription().digest().as_str().to_owned(),
                scope.permission_digest().as_str().to_owned(),
                scope.consent_digest().as_str().to_owned(),
                secret.reference_digest().as_str().to_owned(),
                secret.credential_revision().get().to_string(),
            ],
        );
        Ok(Self {
            scope_digest: scope.scope_digest(),
            project_digest: scope.project().digest(),
            subscription_digest: scope.subscription().digest(),
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            work_product_revision: scope.work_product_revision(),
            credential_revision: secret.credential_revision(),
            secret_reference_digest: secret.reference_digest().clone(),
            request_digest,
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListSubscriptionsRequest {
    pub scope_digest: Digest,
    pub project_digest: Digest,
    pub page_size: u32,
    pub page_token: Option<OpaquePageToken>,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub work_product_revision: Revision,
    pub credential_revision: Revision,
    pub secret_reference_digest: Digest,
    list_digest: Digest,
    request_digest: Digest,
}

impl ListSubscriptionsRequest {
    pub fn new(
        scope: &GcpPubsubSubscriptionScope,
        secret: &SecretReference,
        page_size: u32,
        page_token: Option<OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        if secret.scope_digest() != &scope.scope_digest() || secret.is_revoked() {
            return Err(ModelError::InvalidScope);
        }
        if page_size == 0 || page_size > crate::model::MAX_PAGE_SIZE {
            return Err(ModelError::InvalidPageToken);
        }
        let list_digest = Digest::from_fields(
            "gcp-pubsub-list-subscriptions/v1",
            &[
                scope.scope_digest().as_str().to_owned(),
                scope.project().digest().as_str().to_owned(),
                page_size.to_string(),
            ],
        );
        if let Some(token) = &page_token {
            token.validate_binding(&scope.scope_digest(), &list_digest)?;
        }
        let request_digest = Digest::from_fields(
            "gcp-pubsub-list-subscriptions-request/v1",
            &[
                list_digest.as_str().to_owned(),
                page_token
                    .as_ref()
                    .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                secret.reference_digest().as_str().to_owned(),
                secret.credential_revision().get().to_string(),
            ],
        );
        Ok(Self {
            scope_digest: scope.scope_digest(),
            project_digest: scope.project().digest(),
            page_size,
            page_token,
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            work_product_revision: scope.work_product_revision(),
            credential_revision: secret.credential_revision(),
            secret_reference_digest: secret.reference_digest().clone(),
            list_digest,
            request_digest,
        })
    }

    pub fn list_digest(&self) -> &Digest {
        &self.list_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn page_number(&self) -> u8 {
        self.page_token
            .as_ref()
            .map_or(1, OpaquePageToken::page_number)
    }

    pub fn page_token_digest(&self) -> Option<Digest> {
        self.page_token.as_ref().map(OpaquePageToken::digest)
    }
}

impl fmt::Debug for ListSubscriptionsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListSubscriptionsRequest")
            .field("scope_digest", &self.scope_digest)
            .field("project_digest", &self.project_digest)
            .field("page_size", &self.page_size)
            .field("page_token_digest", &self.page_token_digest())
            .field("list_digest", &self.list_digest)
            .field("request_digest", &self.request_digest)
            .field("credential_revision", &self.credential_revision)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopicConfigurationResponse {
    pub configuration: TopicConfiguration,
    pub observed_fence: PermissionFence,
    pub observed_credential_revision: Revision,
    response_digest: Digest,
}

impl TopicConfigurationResponse {
    pub fn new(
        configuration: TopicConfiguration,
        observed_fence: PermissionFence,
        observed_credential_revision: Revision,
    ) -> Self {
        let response_digest = Digest::from_fields(
            "gcp-pubsub-topic-response/v1",
            &[
                configuration.configuration_digest().as_str().to_owned(),
                observed_fence.scope_digest.as_str().to_owned(),
                observed_fence.permission_digest.as_str().to_owned(),
                observed_fence.consent_digest.as_str().to_owned(),
                observed_fence.work_product_revision.get().to_string(),
                observed_credential_revision.get().to_string(),
            ],
        );
        Self {
            configuration,
            observed_fence,
            observed_credential_revision,
            response_digest,
        }
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        self.configuration.validate_digest()?;
        let expected = Self::new(
            self.configuration.clone(),
            self.observed_fence.clone(),
            self.observed_credential_revision,
        )
        .response_digest;
        if expected == self.response_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionConfigurationResponse {
    pub configuration: SubscriptionConfiguration,
    pub observed_fence: PermissionFence,
    pub observed_credential_revision: Revision,
    response_digest: Digest,
}

impl SubscriptionConfigurationResponse {
    pub fn new(
        configuration: SubscriptionConfiguration,
        observed_fence: PermissionFence,
        observed_credential_revision: Revision,
    ) -> Self {
        let response_digest = Digest::from_fields(
            "gcp-pubsub-subscription-response/v1",
            &[
                configuration.configuration_digest().as_str().to_owned(),
                observed_fence.scope_digest.as_str().to_owned(),
                observed_fence.permission_digest.as_str().to_owned(),
                observed_fence.consent_digest.as_str().to_owned(),
                observed_fence.work_product_revision.get().to_string(),
                observed_credential_revision.get().to_string(),
            ],
        );
        Self {
            configuration,
            observed_fence,
            observed_credential_revision,
            response_digest,
        }
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        self.configuration.validate_digest()?;
        let expected = Self::new(
            self.configuration.clone(),
            self.observed_fence.clone(),
            self.observed_credential_revision,
        )
        .response_digest;
        if expected == self.response_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListSubscriptionsResponse {
    pub subscription_projections: Vec<crate::model::ResourceProjection>,
    pub next_page_token: Option<OpaquePageToken>,
    pub page_number: u8,
    pub observed_fence: PermissionFence,
    pub observed_credential_revision: Revision,
    response_digest: Digest,
}

impl ListSubscriptionsResponse {
    pub fn new(
        subscription_resources: impl IntoIterator<Item = crate::model::SubscriptionResource>,
        next_page_token: Option<OpaquePageToken>,
        page_number: u8,
        observed_fence: PermissionFence,
        observed_credential_revision: Revision,
        list_digest: &Digest,
    ) -> Result<Self, ModelError> {
        if let Some(token) = &next_page_token {
            token.validate_binding(&observed_fence.scope_digest, list_digest)?;
        }
        let subscription_projections = subscription_resources
            .into_iter()
            .map(|resource| resource.projection())
            .collect::<Vec<_>>();
        let response_digest = Self::compute_digest(
            &subscription_projections,
            next_page_token.as_ref(),
            page_number,
            &observed_fence,
            observed_credential_revision,
            list_digest,
        );
        Ok(Self {
            subscription_projections,
            next_page_token,
            page_number: page_number.max(1),
            observed_fence,
            observed_credential_revision,
            response_digest,
        })
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub fn validate_digest(&self, list_digest: &Digest) -> Result<(), ModelError> {
        if let Some(token) = &self.next_page_token {
            token.validate_binding(&self.observed_fence.scope_digest, list_digest)?;
        }
        let expected = Self::compute_digest(
            &self.subscription_projections,
            self.next_page_token.as_ref(),
            self.page_number,
            &self.observed_fence,
            self.observed_credential_revision,
            list_digest,
        );
        if expected == self.response_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    fn compute_digest(
        subscriptions: &[crate::model::ResourceProjection],
        next_page_token: Option<&OpaquePageToken>,
        page_number: u8,
        fence: &PermissionFence,
        credential_revision: Revision,
        list_digest: &Digest,
    ) -> Digest {
        let subscription_digests = subscriptions
            .iter()
            .map(|value| value.digest.as_str())
            .collect::<Vec<_>>()
            .join(",");
        Digest::from_fields(
            "gcp-pubsub-list-subscriptions-response/v1",
            &[
                subscription_digests,
                next_page_token
                    .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                page_number.to_string(),
                fence.scope_digest.as_str().to_owned(),
                fence.permission_digest.as_str().to_owned(),
                fence.consent_digest.as_str().to_owned(),
                fence.work_product_revision.get().to_string(),
                credential_revision.get().to_string(),
                list_digest.as_str().to_owned(),
            ],
        )
    }
}

pub trait GcpPubsubTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;

    fn get_topic(
        &mut self,
        request: &GetTopicRequest,
    ) -> Result<TopicConfigurationResponse, TransportError>;

    fn get_subscription(
        &mut self,
        request: &GetSubscriptionRequest,
    ) -> Result<SubscriptionConfigurationResponse, TransportError>;

    fn list_subscriptions(
        &mut self,
        request: &ListSubscriptionsRequest,
    ) -> Result<ListSubscriptionsResponse, TransportError>;
}

pub trait GcpPubsubProviderApi: fmt::Debug {
    fn definition(&self) -> &GcpPubsubProviderDefinition;

    fn provenance(&self) -> ProviderProvenance {
        self.definition().provenance
    }

    fn get_topic(
        &mut self,
        request: &GetTopicRequest,
    ) -> Result<TopicConfigurationResponse, TransportError>;

    fn get_subscription(
        &mut self,
        request: &GetSubscriptionRequest,
    ) -> Result<SubscriptionConfigurationResponse, TransportError>;

    fn list_subscriptions(
        &mut self,
        request: &ListSubscriptionsRequest,
    ) -> Result<ListSubscriptionsResponse, TransportError>;
}

#[derive(Debug)]
pub struct GcpPubsubProvider<T> {
    transport: T,
    definition: GcpPubsubProviderDefinition,
}

impl<T: GcpPubsubTransport> GcpPubsubProvider<T> {
    pub fn new(
        transport: T,
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        if transport.provenance() != provenance {
            return Err(ProviderDefinitionError::ProvenanceMismatch);
        }
        Ok(Self {
            transport,
            definition: GcpPubsubProviderDefinition::new(provider_version, provenance)?,
        })
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

impl<T: GcpPubsubTransport> GcpPubsubProviderApi for GcpPubsubProvider<T> {
    fn definition(&self) -> &GcpPubsubProviderDefinition {
        &self.definition
    }

    fn get_topic(
        &mut self,
        request: &GetTopicRequest,
    ) -> Result<TopicConfigurationResponse, TransportError> {
        self.transport.get_topic(request)
    }

    fn get_subscription(
        &mut self,
        request: &GetSubscriptionRequest,
    ) -> Result<SubscriptionConfigurationResponse, TransportError> {
        self.transport.get_subscription(request)
    }

    fn list_subscriptions(
        &mut self,
        request: &ListSubscriptionsRequest,
    ) -> Result<ListSubscriptionsResponse, TransportError> {
        self.transport.list_subscriptions(request)
    }
}

#[derive(Debug)]
pub struct RecordingGcpPubsubTransport {
    provenance: ProviderProvenance,
    topic_responses: VecDeque<Result<TopicConfigurationResponse, TransportError>>,
    subscription_responses: VecDeque<Result<SubscriptionConfigurationResponse, TransportError>>,
    list_responses: VecDeque<Result<ListSubscriptionsResponse, TransportError>>,
    requests: Vec<RecordedRequest>,
}

impl Default for RecordingGcpPubsubTransport {
    fn default() -> Self {
        Self::new(ProviderProvenance::Recording)
    }
}

impl RecordingGcpPubsubTransport {
    pub fn new(provenance: ProviderProvenance) -> Self {
        Self {
            provenance,
            topic_responses: VecDeque::new(),
            subscription_responses: VecDeque::new(),
            list_responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_topic_response(
        &mut self,
        response: Result<TopicConfigurationResponse, TransportError>,
    ) {
        self.topic_responses.push_back(response);
    }

    pub fn push_subscription_response(
        &mut self,
        response: Result<SubscriptionConfigurationResponse, TransportError>,
    ) {
        self.subscription_responses.push_back(response);
    }

    pub fn push_list_response(
        &mut self,
        response: Result<ListSubscriptionsResponse, TransportError>,
    ) {
        self.list_responses.push_back(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }

    fn record(
        &mut self,
        operation: ProviderOperation,
        scope_digest: &Digest,
        resource_digest: &Digest,
        page_token_digest: Option<Digest>,
        request_digest: &Digest,
    ) {
        self.requests.push(RecordedRequest {
            operation,
            scope_digest: scope_digest.clone(),
            resource_digest: resource_digest.clone(),
            page_token_digest,
            request_digest: request_digest.clone(),
        });
    }

    fn missing_response(operation: ProviderOperation) -> TransportError {
        TransportError::new(
            ProviderErrorKind::Unknown,
            None,
            format!("missing-recorded-{}", operation.as_str()),
        )
    }
}

impl GcpPubsubTransport for RecordingGcpPubsubTransport {
    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    fn get_topic(
        &mut self,
        request: &GetTopicRequest,
    ) -> Result<TopicConfigurationResponse, TransportError> {
        self.record(
            ProviderOperation::GetTopic,
            &request.scope_digest,
            &request.topic_digest,
            None,
            &request.request_digest,
        );
        self.topic_responses
            .pop_front()
            .unwrap_or_else(|| Err(Self::missing_response(ProviderOperation::GetTopic)))
    }

    fn get_subscription(
        &mut self,
        request: &GetSubscriptionRequest,
    ) -> Result<SubscriptionConfigurationResponse, TransportError> {
        self.record(
            ProviderOperation::GetSubscription,
            &request.scope_digest,
            &request.subscription_digest,
            None,
            &request.request_digest,
        );
        self.subscription_responses
            .pop_front()
            .unwrap_or_else(|| Err(Self::missing_response(ProviderOperation::GetSubscription)))
    }

    fn list_subscriptions(
        &mut self,
        request: &ListSubscriptionsRequest,
    ) -> Result<ListSubscriptionsResponse, TransportError> {
        self.record(
            ProviderOperation::ListSubscriptions,
            &request.scope_digest,
            &request.project_digest,
            request.page_token_digest(),
            request.request_digest(),
        );
        self.list_responses
            .pop_front()
            .unwrap_or_else(|| Err(Self::missing_response(ProviderOperation::ListSubscriptions)))
    }
}

/// The fixture transport is the same bounded queue with explicit fixture
/// provenance. It has no network capability and retains no message data.
#[derive(Debug, Default)]
pub struct FixtureGcpPubsubTransport {
    inner: RecordingGcpPubsubTransport,
}

impl FixtureGcpPubsubTransport {
    pub fn push_topic_response(
        &mut self,
        response: Result<TopicConfigurationResponse, TransportError>,
    ) {
        self.inner.push_topic_response(response);
    }

    pub fn push_subscription_response(
        &mut self,
        response: Result<SubscriptionConfigurationResponse, TransportError>,
    ) {
        self.inner.push_subscription_response(response);
    }

    pub fn push_list_response(
        &mut self,
        response: Result<ListSubscriptionsResponse, TransportError>,
    ) {
        self.inner.push_list_response(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        self.inner.requests()
    }
}

impl GcpPubsubTransport for FixtureGcpPubsubTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fixture
    }

    fn get_topic(
        &mut self,
        request: &GetTopicRequest,
    ) -> Result<TopicConfigurationResponse, TransportError> {
        self.inner.get_topic(request)
    }

    fn get_subscription(
        &mut self,
        request: &GetSubscriptionRequest,
    ) -> Result<SubscriptionConfigurationResponse, TransportError> {
        self.inner.get_subscription(request)
    }

    fn list_subscriptions(
        &mut self,
        request: &ListSubscriptionsRequest,
    ) -> Result<ListSubscriptionsResponse, TransportError> {
        self.inner.list_subscriptions(request)
    }
}

#[derive(Debug, Default)]
pub struct LoopbackTransport;

impl GcpPubsubTransport for LoopbackTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Loopback
    }

    fn get_topic(
        &mut self,
        _request: &GetTopicRequest,
    ) -> Result<TopicConfigurationResponse, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn get_subscription(
        &mut self,
        _request: &GetSubscriptionRequest,
    ) -> Result<SubscriptionConfigurationResponse, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn list_subscriptions(
        &mut self,
        _request: &ListSubscriptionsRequest,
    ) -> Result<ListSubscriptionsResponse, TransportError> {
        Err(TransportError::blocked_env())
    }
}

#[derive(Debug, Default)]
pub struct BlockedEnvTransport;

impl GcpPubsubTransport for BlockedEnvTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn get_topic(
        &mut self,
        _request: &GetTopicRequest,
    ) -> Result<TopicConfigurationResponse, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn get_subscription(
        &mut self,
        _request: &GetSubscriptionRequest,
    ) -> Result<SubscriptionConfigurationResponse, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn list_subscriptions(
        &mut self,
        _request: &ListSubscriptionsRequest,
    ) -> Result<ListSubscriptionsResponse, TransportError> {
        Err(TransportError::blocked_env())
    }
}
