use std::{collections::BTreeSet, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::{
    GCP_PUBSUB_SUBSCRIPTION_RESULT_CONSUMER_ID, GCP_PUBSUB_SUBSCRIPTION_RESULT_CONTRACT_JSON,
    GCP_PUBSUB_SUBSCRIPTION_RESULT_CONTRACT_VERSION, GCP_PUBSUB_SUBSCRIPTION_RESULT_PROVIDER_ID,
    GCP_PUBSUB_SUBSCRIPTION_RESULT_SCHEMA_VERSION, GCP_PUBSUB_SUBSCRIPTION_RESULT_SERVICE_ID,
    Layer1Authority,
    model::{
        Digest, EvidenceDigests, GcpPubsubSubscriptionScope, ModelError, PermissionFence,
        ProviderErrorEvidence, ProviderErrorKind, ProviderResourceScopeProjection, Revision,
        SecretReference, SubscriptionConfiguration, SubscriptionPosture, SubscriptionProjection,
        TopicConfiguration, TopicProjection,
    },
    provider::{
        GcpPubsubProviderApi, GcpPubsubProviderDefinition, GetSubscriptionRequest, GetTopicRequest,
        ListSubscriptionsRequest, ListSubscriptionsResponse, ProviderDefinitionError,
        ProviderOperation, ProviderProvenance, TransportError,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ServiceError {
    #[error("registration is revoked or reversed")]
    RegistrationRevoked,
    #[error("SecretReference is revoked")]
    SecretRevoked,
    #[error("service, provider, secret, or scope binding does not match")]
    ScopeMismatch,
    #[error("provider evidence was tampered with or its digest is stale")]
    TamperedEvidence,
    #[error("provider returned a repeated page token")]
    PageLoop,
    #[error("provider response shape exceeded the Layer-1 bounded projection")]
    InvalidResponseShape,
    #[error(transparent)]
    ProviderDefinition(#[from] ProviderDefinitionError),
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransition {
    pub previous_status: RegistrationStatus,
    pub new_status: RegistrationStatus,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpPubsubRegistration {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub provider_version: String,
    pub provider_definition_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub revision: Revision,
    pub status: RegistrationStatus,
}

impl GcpPubsubRegistration {
    pub fn new(
        scope: &GcpPubsubSubscriptionScope,
        provider: &GcpPubsubProviderDefinition,
    ) -> Result<Self, ServiceError> {
        if provider.provider_id != GCP_PUBSUB_SUBSCRIPTION_RESULT_PROVIDER_ID
            || provider.native
            || provider.first_party
            || provider.live_execution
        {
            return Err(ServiceError::ScopeMismatch);
        }
        let revision = Revision::new(1)?;
        let scope_digest = scope.scope_digest();
        let registration_digest = Digest::from_fields(
            "gcp-pubsub-registration/v1",
            &[
                GCP_PUBSUB_SUBSCRIPTION_RESULT_SCHEMA_VERSION.to_owned(),
                GCP_PUBSUB_SUBSCRIPTION_RESULT_CONTRACT_VERSION.to_owned(),
                GCP_PUBSUB_SUBSCRIPTION_RESULT_SERVICE_ID.to_owned(),
                provider.provider_id.clone(),
                GCP_PUBSUB_SUBSCRIPTION_RESULT_CONSUMER_ID.to_owned(),
                provider.provider_version.clone(),
                provider.provider_digest.as_str().to_owned(),
                scope_digest.as_str().to_owned(),
                revision.get().to_string(),
            ],
        );
        Ok(Self {
            schema_version: GCP_PUBSUB_SUBSCRIPTION_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: GCP_PUBSUB_SUBSCRIPTION_RESULT_CONTRACT_VERSION.to_owned(),
            service_id: GCP_PUBSUB_SUBSCRIPTION_RESULT_SERVICE_ID.to_owned(),
            provider_id: provider.provider_id.clone(),
            consumer_id: GCP_PUBSUB_SUBSCRIPTION_RESULT_CONSUMER_ID.to_owned(),
            provider_version: provider.provider_version.clone(),
            provider_definition_digest: provider.provider_digest.clone(),
            scope_digest,
            registration_digest,
            revision,
            status: RegistrationStatus::Active,
        })
    }

    pub fn ensure_active(&self) -> Result<(), ServiceError> {
        if self.status == RegistrationStatus::Active {
            Ok(())
        } else {
            Err(ServiceError::RegistrationRevoked)
        }
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransition, ServiceError> {
        self.transition(RegistrationStatus::Revoked)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransition, ServiceError> {
        if self.status != RegistrationStatus::Revoked {
            return Err(ServiceError::RegistrationRevoked);
        }
        self.transition(RegistrationStatus::Reversed)
    }

    fn transition(
        &mut self,
        new_status: RegistrationStatus,
    ) -> Result<RegistrationTransition, ServiceError> {
        if self.status != RegistrationStatus::Active && new_status == RegistrationStatus::Revoked {
            return Err(ServiceError::RegistrationRevoked);
        }
        let previous_status = self.status;
        self.status = new_status;
        let transition_digest = Digest::from_fields(
            "gcp-pubsub-registration-transition/v1",
            &[
                format!("{previous_status:?}"),
                format!("{new_status:?}"),
                self.registration_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.revision.get().to_string(),
            ],
        );
        Ok(RegistrationTransition {
            previous_status,
            new_status,
            registration_digest: self.registration_digest.clone(),
            transition_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpPubsubServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_digest: Digest,
    pub read_only: bool,
    pub live_execution: bool,
    pub delivery_completion_evidence: bool,
    pub native: bool,
    pub first_party: bool,
}

impl Default for GcpPubsubServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}

impl GcpPubsubServiceDefinition {
    pub fn new() -> Self {
        Self {
            schema_version: GCP_PUBSUB_SUBSCRIPTION_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: GCP_PUBSUB_SUBSCRIPTION_RESULT_CONTRACT_VERSION.to_owned(),
            service_id: GCP_PUBSUB_SUBSCRIPTION_RESULT_SERVICE_ID.to_owned(),
            provider_id: GCP_PUBSUB_SUBSCRIPTION_RESULT_PROVIDER_ID.to_owned(),
            consumer_id: GCP_PUBSUB_SUBSCRIPTION_RESULT_CONSUMER_ID.to_owned(),
            contract_digest: Digest::from_text(GCP_PUBSUB_SUBSCRIPTION_RESULT_CONTRACT_JSON),
            read_only: true,
            live_execution: false,
            delivery_completion_evidence: false,
            native: false,
            first_party: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InspectionRequest {
    pub max_pages: u8,
    pub page_size: u32,
}

impl InspectionRequest {
    pub fn new(max_pages: u8, page_size: u32) -> Result<Self, ModelError> {
        if max_pages == 0
            || max_pages > crate::model::MAX_PAGES
            || page_size == 0
            || page_size > crate::model::MAX_PAGE_SIZE
        {
            return Err(ModelError::InvalidPageToken);
        }
        Ok(Self {
            max_pages,
            page_size,
        })
    }
}

impl Default for InspectionRequest {
    fn default() -> Self {
        Self {
            max_pages: 4,
            page_size: 50,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpPubsubResultEvidence {
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub work_product_revision: Revision,
    pub provider_resource_scope: ProviderResourceScopeProjection,
    pub topic: Option<TopicProjection>,
    pub subscription: Option<SubscriptionProjection>,
    pub page_token_digests: Vec<Digest>,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub digests: EvidenceDigests,
    pub provenance: ProviderProvenance,
    pub authority: Layer1Authority,
    pub configuration_is_delivery_completion: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpPubsubSubscriptionResultProposal {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub posture: SubscriptionPosture,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub provider_definition_digest: Digest,
    pub evidence: GcpPubsubResultEvidence,
    pub proposal_digest: Digest,
}

impl GcpPubsubSubscriptionResultProposal {
    pub fn status(&self) -> SubscriptionPosture {
        self.posture
    }

    pub const fn is_adopted(&self) -> bool {
        false
    }

    pub const fn authority(&self) -> Layer1Authority {
        self.evidence.authority
    }
}

impl fmt::Display for GcpPubsubSubscriptionResultProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "GcpPubsubSubscriptionResultProposal({:?})",
            self.posture
        )
    }
}

pub struct GcpPubsubSubscriptionResultService<P> {
    scope: GcpPubsubSubscriptionScope,
    secret_reference: SecretReference,
    provider: P,
    registration: GcpPubsubRegistration,
}

impl<P: GcpPubsubProviderApi> fmt::Debug for GcpPubsubSubscriptionResultService<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpPubsubSubscriptionResultService")
            .field("scope_digest", &self.scope.scope_digest())
            .field("secret_reference", &self.secret_reference)
            .field("registration", &self.registration)
            .field("provider", &self.provider.definition())
            .finish()
    }
}

impl<P: GcpPubsubProviderApi> GcpPubsubSubscriptionResultService<P> {
    pub fn new(
        scope: GcpPubsubSubscriptionScope,
        secret_reference: SecretReference,
        provider: P,
    ) -> Result<Self, ServiceError> {
        if secret_reference.scope_digest() != &scope.scope_digest()
            || secret_reference.is_revoked()
            || provider.definition().provider_id != GCP_PUBSUB_SUBSCRIPTION_RESULT_PROVIDER_ID
            || provider.definition().native
            || provider.definition().first_party
            || provider.definition().live_execution
        {
            return Err(ServiceError::ScopeMismatch);
        }
        let registration = GcpPubsubRegistration::new(&scope, provider.definition())?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            registration,
        })
    }

    pub fn definition() -> GcpPubsubServiceDefinition {
        GcpPubsubServiceDefinition::new()
    }

    pub fn scope(&self) -> &GcpPubsubSubscriptionScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    pub fn registration(&self) -> &GcpPubsubRegistration {
        &self.registration
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransition, ServiceError> {
        self.registration.revoke()
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransition, ServiceError> {
        self.registration.reverse()
    }

    pub fn revoke_secret(&mut self) -> Result<(), ServiceError> {
        self.secret_reference.revoke()?;
        Ok(())
    }

    pub fn inspect(&mut self) -> Result<GcpPubsubSubscriptionResultProposal, ServiceError> {
        self.propose(InspectionRequest::default())
    }

    pub fn propose(
        &mut self,
        request: InspectionRequest,
    ) -> Result<GcpPubsubSubscriptionResultProposal, ServiceError> {
        if self.registration.status != RegistrationStatus::Active {
            return Ok(self.finish(
                SubscriptionPosture::Revoked,
                None,
                None,
                Vec::new(),
                Vec::new(),
                false,
            ));
        }
        if self.secret_reference.is_revoked() {
            return Ok(self.finish(
                SubscriptionPosture::Revoked,
                None,
                None,
                Vec::new(),
                Vec::new(),
                false,
            ));
        }

        let topic_request = GetTopicRequest::new(&self.scope, &self.secret_reference)?;
        let topic = match self.provider.get_topic(&topic_request) {
            Ok(response) => {
                if self.validate_topic_response(&response).is_err() {
                    return Ok(self.finish(
                        SubscriptionPosture::Tampered,
                        None,
                        None,
                        Vec::new(),
                        Vec::new(),
                        false,
                    ));
                }
                response.configuration
            }
            Err(error) => {
                return Ok(self.finish(
                    posture_for_transport_error(&error),
                    None,
                    None,
                    Vec::new(),
                    vec![provider_error(ProviderOperation::GetTopic, &error)],
                    false,
                ));
            }
        };

        let subscription_request =
            GetSubscriptionRequest::new(&self.scope, &self.secret_reference)?;
        let subscription = match self.provider.get_subscription(&subscription_request) {
            Ok(response) => {
                if self.validate_subscription_response(&response).is_err() {
                    return Ok(self.finish(
                        SubscriptionPosture::Tampered,
                        Some(&topic),
                        None,
                        Vec::new(),
                        Vec::new(),
                        false,
                    ));
                }
                Some(response.configuration)
            }
            Err(error) => {
                return Ok(self.finish(
                    posture_for_transport_error(&error),
                    Some(&topic),
                    None,
                    Vec::new(),
                    vec![provider_error(ProviderOperation::GetSubscription, &error)],
                    false,
                ));
            }
        };
        let Some(subscription) = subscription else {
            return Ok(self.finish(
                SubscriptionPosture::Partial,
                Some(&topic),
                None,
                Vec::new(),
                Vec::new(),
                false,
            ));
        };

        let mut page_token = None;
        let mut page_tokens = Vec::new();
        let mut seen_tokens = BTreeSet::new();
        let mut found_subscription = false;
        let mut list_complete = false;
        let mut provider_errors = Vec::new();
        for page in 1..=request.max_pages {
            let list_request = ListSubscriptionsRequest::new(
                &self.scope,
                &self.secret_reference,
                request.page_size,
                page_token.clone(),
            )?;
            let response = match self.provider.list_subscriptions(&list_request) {
                Ok(response) => response,
                Err(error) => {
                    provider_errors
                        .push(provider_error(ProviderOperation::ListSubscriptions, &error));
                    return Ok(self.finish(
                        posture_for_transport_error(&error),
                        Some(&topic),
                        Some(&subscription),
                        page_tokens,
                        provider_errors,
                        list_complete,
                    ));
                }
            };
            if response.page_number != page
                || self
                    .validate_list_response(&response, &list_request)
                    .is_err()
            {
                return Ok(self.finish(
                    SubscriptionPosture::Tampered,
                    Some(&topic),
                    Some(&subscription),
                    page_tokens,
                    provider_errors,
                    false,
                ));
            }
            found_subscription |= response
                .subscription_projections
                .iter()
                .any(|value| value.digest == self.scope.subscription().digest());
            if let Some(next) = &response.next_page_token {
                if !seen_tokens.insert(next.digest()) {
                    return Ok(self.finish(
                        SubscriptionPosture::Tampered,
                        Some(&topic),
                        Some(&subscription),
                        page_tokens,
                        provider_errors,
                        false,
                    ));
                }
                page_tokens.push(next.digest());
                page_token = Some(next.clone());
                if page == request.max_pages {
                    return Ok(self.finish(
                        SubscriptionPosture::Partial,
                        Some(&topic),
                        Some(&subscription),
                        page_tokens,
                        provider_errors,
                        false,
                    ));
                }
            } else {
                list_complete = true;
                break;
            }
        }

        if !found_subscription {
            return Ok(self.finish(
                SubscriptionPosture::Partial,
                Some(&topic),
                Some(&subscription),
                page_tokens,
                provider_errors,
                list_complete,
            ));
        }
        let posture = posture_for_configuration(&topic, &subscription, list_complete);
        Ok(self.finish(
            posture,
            Some(&topic),
            Some(&subscription),
            page_tokens,
            provider_errors,
            list_complete,
        ))
    }

    fn validate_topic_response(
        &self,
        response: &crate::provider::TopicConfigurationResponse,
    ) -> Result<(), ServiceError> {
        response.validate_digest()?;
        if response.configuration.name().digest() != self.scope.topic().digest()
            || !fence_matches(&response.observed_fence, &self.scope.fence())
            || response.observed_credential_revision != self.secret_reference.credential_revision()
        {
            return Err(ServiceError::TamperedEvidence);
        }
        let expected_schema = self
            .scope
            .schema()
            .map(crate::model::SchemaResource::digest);
        let observed_schema = response
            .configuration
            .schema()
            .map(|value| value.schema().digest());
        if expected_schema != observed_schema {
            return Err(ServiceError::TamperedEvidence);
        }
        Ok(())
    }

    fn validate_subscription_response(
        &self,
        response: &crate::provider::SubscriptionConfigurationResponse,
    ) -> Result<(), ServiceError> {
        response.validate_digest()?;
        if response.configuration.name().digest() != self.scope.subscription().digest()
            || response.configuration.topic().digest() != self.scope.topic().digest()
            || !fence_matches(&response.observed_fence, &self.scope.fence())
            || response.observed_credential_revision != self.secret_reference.credential_revision()
        {
            return Err(ServiceError::TamperedEvidence);
        }
        let expected_dead_letter = self
            .scope
            .dead_letter_topic()
            .map(crate::model::TopicResource::digest);
        let observed_dead_letter = response
            .configuration
            .dead_letter()
            .map(|value| value.topic().digest());
        if expected_dead_letter != observed_dead_letter {
            return Err(ServiceError::TamperedEvidence);
        }
        Ok(())
    }

    fn validate_list_response(
        &self,
        response: &ListSubscriptionsResponse,
        request: &ListSubscriptionsRequest,
    ) -> Result<(), ServiceError> {
        response.validate_digest(request.list_digest())?;
        if !fence_matches(&response.observed_fence, &self.scope.fence())
            || response.observed_credential_revision != self.secret_reference.credential_revision()
        {
            return Err(ServiceError::TamperedEvidence);
        }
        Ok(())
    }

    fn finish(
        &self,
        posture: SubscriptionPosture,
        topic: Option<&TopicConfiguration>,
        subscription: Option<&SubscriptionConfiguration>,
        page_token_digests: Vec<Digest>,
        provider_errors: Vec<ProviderErrorEvidence>,
        list_complete: bool,
    ) -> GcpPubsubSubscriptionResultProposal {
        let topic_projection = topic.map(TopicConfiguration::projection);
        let subscription_projection = subscription.map(SubscriptionConfiguration::projection);
        let configuration_digest = Digest::from_fields(
            "gcp-pubsub-subscription-configuration-evidence/v1",
            &[
                topic.map_or_else(String::new, |value| {
                    value.configuration_digest().as_str().to_owned()
                }),
                subscription.map_or_else(String::new, |value| {
                    value.configuration_digest().as_str().to_owned()
                }),
                self.scope.scope_digest().as_str().to_owned(),
                self.scope.permission_digest().as_str().to_owned(),
                self.scope.consent_digest().as_str().to_owned(),
                page_token_digests
                    .iter()
                    .map(Digest::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
                list_complete.to_string(),
            ],
        );
        let result_digest = Digest::from_fields(
            "gcp-pubsub-subscription-result/v1",
            &[
                format!("{posture:?}"),
                self.scope.scope_digest().as_str().to_owned(),
                configuration_digest.as_str().to_owned(),
                self.scope.permission_digest().as_str().to_owned(),
                self.registration.registration_digest.as_str().to_owned(),
                self.registration.revision.get().to_string(),
                self.provider
                    .definition()
                    .provider_digest
                    .as_str()
                    .to_owned(),
                format!("{:?}", self.provider.provenance()),
                provider_errors
                    .iter()
                    .map(|value| value.error_digest.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            ],
        );
        let evidence = GcpPubsubResultEvidence {
            scope_digest: self.scope.scope_digest(),
            permission_digest: self.scope.permission_digest().clone(),
            consent_digest: self.scope.consent_digest().clone(),
            work_product_revision: self.scope.work_product_revision(),
            provider_resource_scope: self.scope.provider_resource_projection(),
            topic: topic_projection,
            subscription: subscription_projection,
            page_token_digests,
            provider_errors,
            digests: EvidenceDigests {
                topic_digest: topic.map(|value| value.configuration_digest().clone()),
                subscription_digest: subscription.map(|value| value.configuration_digest().clone()),
                configuration_digest,
                permission_digest: self.scope.permission_digest().clone(),
                result_digest: result_digest.clone(),
            },
            provenance: self.provider.provenance(),
            authority: Layer1Authority::offline(),
            configuration_is_delivery_completion: false,
        };
        let proposal_digest = Digest::from_fields(
            "gcp-pubsub-subscription-proposal/v1",
            &[
                result_digest.as_str().to_owned(),
                self.scope.scope_digest().as_str().to_owned(),
                self.registration.registration_digest.as_str().to_owned(),
                self.registration.revision.get().to_string(),
            ],
        );
        GcpPubsubSubscriptionResultProposal {
            service_id: GCP_PUBSUB_SUBSCRIPTION_RESULT_SERVICE_ID.to_owned(),
            provider_id: GCP_PUBSUB_SUBSCRIPTION_RESULT_PROVIDER_ID.to_owned(),
            consumer_id: GCP_PUBSUB_SUBSCRIPTION_RESULT_CONSUMER_ID.to_owned(),
            posture,
            scope_digest: self.scope.scope_digest(),
            registration_digest: self.registration.registration_digest.clone(),
            registration_revision: self.registration.revision,
            provider_definition_digest: self.provider.definition().provider_digest.clone(),
            evidence,
            proposal_digest,
        }
    }
}

fn fence_matches(observed: &PermissionFence, expected: &PermissionFence) -> bool {
    observed == expected
}

fn posture_for_transport_error(error: &TransportError) -> SubscriptionPosture {
    match error.kind {
        ProviderErrorKind::Unauthenticated | ProviderErrorKind::PermissionDenied => {
            SubscriptionPosture::AccessLost
        }
        ProviderErrorKind::BadRequest
        | ProviderErrorKind::NotFound
        | ProviderErrorKind::MalformedResponse => SubscriptionPosture::Misconfigured,
        ProviderErrorKind::RateLimited
        | ProviderErrorKind::ServerFailure
        | ProviderErrorKind::Timeout
        | ProviderErrorKind::BlockedEnv
        | ProviderErrorKind::Unknown => SubscriptionPosture::ProviderUnknown,
    }
}

fn posture_for_configuration(
    topic: &TopicConfiguration,
    subscription: &SubscriptionConfiguration,
    list_complete: bool,
) -> SubscriptionPosture {
    if !list_complete {
        return SubscriptionPosture::Partial;
    }
    if subscription.detached() {
        SubscriptionPosture::Detached
    } else if subscription.expired() {
        SubscriptionPosture::Expired
    } else if subscription.state() == crate::model::SubscriptionState::ResourceError
        || topic.state() == crate::model::TopicState::Unknown
        || subscription.state() == crate::model::SubscriptionState::Unknown
    {
        SubscriptionPosture::Misconfigured
    } else if topic.state() != crate::model::TopicState::Active
        || subscription.state() != crate::model::SubscriptionState::Active
    {
        SubscriptionPosture::Partial
    } else {
        SubscriptionPosture::Active
    }
}

fn provider_error(operation: ProviderOperation, error: &TransportError) -> ProviderErrorEvidence {
    ProviderErrorEvidence {
        operation: operation.as_str().to_owned(),
        kind: error.kind,
        status_code: error.status_code,
        error_digest: error.diagnostic_digest().clone(),
    }
}
