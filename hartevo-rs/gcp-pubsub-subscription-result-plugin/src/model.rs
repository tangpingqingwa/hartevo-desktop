use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 128;
pub(crate) const MAX_RESOURCE_NAME_BYTES: usize = 512;
pub(crate) const MAX_FILTER_BYTES: usize = 4 * 1024;
pub(crate) const MAX_ENDPOINT_BYTES: usize = 2 * 1024;
pub(crate) const MAX_PAGE_TOKEN_BYTES: usize = 4 * 1024;
pub(crate) const MAX_PAGE_SIZE: u32 = 100;
pub(crate) const MAX_PAGES: u8 = 16;
pub(crate) const MAX_RETENTION_SECONDS: u64 = 31 * 24 * 60 * 60;
pub(crate) const MAX_EXPIRATION_SECONDS: u64 = 10 * 365 * 24 * 60 * 60;
pub(crate) const MIN_RETENTION_SECONDS: u64 = 10 * 60;
pub(crate) const MIN_EXPIRATION_SECONDS: u64 = 24 * 60 * 60;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("resource name is malformed or belongs to a different project")]
    InvalidResourceName,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("scope is invalid or contains a provider resource from another project")]
    InvalidScope,
    #[error("duration is outside the bounded Pub/Sub configuration range")]
    InvalidDuration,
    #[error("dead-letter delivery attempts must be between 5 and 100")]
    InvalidDeadLetterAttempts,
    #[error("retry backoff must be between 0 and 600 seconds and ordered")]
    InvalidRetryPolicy,
    #[error("push endpoint is malformed or has no bounded domain projection")]
    InvalidPushEndpoint,
    #[error("filter is empty, contains control data, or is too large")]
    InvalidFilter,
    #[error("schema settings are invalid")]
    InvalidSchema,
    #[error("opaque page token is empty or too large")]
    InvalidPageToken,
    #[error("opaque page token is not bound to this scope and list request")]
    PageTokenBindingMismatch,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration is already revoked or reversed")]
    RegistrationInactive,
    #[error("secret reference is already revoked")]
    SecretAlreadyRevoked,
    #[error("configuration digest does not match its immutable fields")]
    DigestMismatch,
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field);
        }
        Self::from_bytes(&bytes)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

fn append_field(bytes: &mut Vec<u8>, field: &str) {
    bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
    bytes.extend_from_slice(field.as_bytes());
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && !value.starts_with('.')
        && !value.ends_with('.')
}

fn valid_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

macro_rules! identifier_type {
    ($name:ident) => {
        #[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if valid_identifier(&value) {
                    Ok(Self(value))
                } else {
                    Err(ModelError::InvalidIdentifier)
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_fields(
                    concat!(stringify!($name), "/v1"),
                    std::slice::from_ref(&self.0),
                )
            }

            pub fn redacted(&self) -> String {
                format!("{}:{}", stringify!($name), &self.digest().as_str()[..16])
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.redacted())
                    .finish()
            }
        }
    };
}

identifier_type!(ProjectId);
identifier_type!(TopicId);
identifier_type!(SubscriptionId);
identifier_type!(SchemaId);
identifier_type!(MissionId);
identifier_type!(WorkProductId);
identifier_type!(ServiceId);
identifier_type!(ProviderId);
identifier_type!(ConsumerId);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GoogleAuthKind {
    OAuth,
    ServiceAccount,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::InvalidIdentifier)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Serialize for Revision {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u64(self.0)
    }
}

/// A provider resource name is kept only inside the offline provider seam.
/// Its debug output and all result projections expose a digest, never the raw
/// `projects/...` value.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct TopicResource {
    project: ProjectId,
    topic: TopicId,
    raw: String,
}

impl TopicResource {
    pub fn new(project: ProjectId, topic: TopicId) -> Self {
        let raw = format!("projects/{}/topics/{}", project.as_str(), topic.as_str());
        Self {
            project,
            topic,
            raw,
        }
    }

    pub fn from_name(name: impl Into<String>, project: &ProjectId) -> Result<Self, ModelError> {
        let name = name.into();
        let prefix = format!("projects/{}/topics/", project.as_str());
        let Some(topic) = name.strip_prefix(&prefix) else {
            return Err(ModelError::InvalidResourceName);
        };
        if name.len() > MAX_RESOURCE_NAME_BYTES || !valid_identifier(topic) {
            return Err(ModelError::InvalidResourceName);
        }
        Ok(Self::new(project.clone(), TopicId::new(topic)?))
    }

    pub fn project(&self) -> &ProjectId {
        &self.project
    }

    pub fn topic(&self) -> &TopicId {
        &self.topic
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-pubsub-topic-resource/v1",
            std::slice::from_ref(&self.raw),
        )
    }

    pub fn projection(&self) -> ResourceProjection {
        ResourceProjection::new(ResourceKind::Topic, self.digest())
    }
}

impl fmt::Debug for TopicResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TopicResource")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct SubscriptionResource {
    project: ProjectId,
    subscription: SubscriptionId,
    raw: String,
}

impl SubscriptionResource {
    pub fn new(project: ProjectId, subscription: SubscriptionId) -> Self {
        let raw = format!(
            "projects/{}/subscriptions/{}",
            project.as_str(),
            subscription.as_str()
        );
        Self {
            project,
            subscription,
            raw,
        }
    }

    pub fn from_name(name: impl Into<String>, project: &ProjectId) -> Result<Self, ModelError> {
        let name = name.into();
        let prefix = format!("projects/{}/subscriptions/", project.as_str());
        let Some(subscription) = name.strip_prefix(&prefix) else {
            return Err(ModelError::InvalidResourceName);
        };
        if name.len() > MAX_RESOURCE_NAME_BYTES || !valid_identifier(subscription) {
            return Err(ModelError::InvalidResourceName);
        }
        Ok(Self::new(
            project.clone(),
            SubscriptionId::new(subscription)?,
        ))
    }

    pub fn project(&self) -> &ProjectId {
        &self.project
    }

    pub fn subscription(&self) -> &SubscriptionId {
        &self.subscription
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-pubsub-subscription-resource/v1",
            std::slice::from_ref(&self.raw),
        )
    }

    pub fn projection(&self) -> ResourceProjection {
        ResourceProjection::new(ResourceKind::Subscription, self.digest())
    }
}

impl fmt::Debug for SubscriptionResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubscriptionResource")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct SchemaResource {
    project: ProjectId,
    schema: SchemaId,
    raw: String,
}

impl SchemaResource {
    pub fn new(project: ProjectId, schema: SchemaId) -> Self {
        let raw = format!("projects/{}/schemas/{}", project.as_str(), schema.as_str());
        Self {
            project,
            schema,
            raw,
        }
    }

    pub fn from_name(name: impl Into<String>, project: &ProjectId) -> Result<Self, ModelError> {
        let name = name.into();
        let prefix = format!("projects/{}/schemas/", project.as_str());
        let Some(schema) = name.strip_prefix(&prefix) else {
            return Err(ModelError::InvalidResourceName);
        };
        if name.len() > MAX_RESOURCE_NAME_BYTES || !valid_identifier(schema) {
            return Err(ModelError::InvalidResourceName);
        }
        Ok(Self::new(project.clone(), SchemaId::new(schema)?))
    }

    pub fn project(&self) -> &ProjectId {
        &self.project
    }

    pub fn schema(&self) -> &SchemaId {
        &self.schema
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-pubsub-schema-resource/v1",
            std::slice::from_ref(&self.raw),
        )
    }

    pub fn projection(&self) -> ResourceProjection {
        ResourceProjection::new(ResourceKind::Schema, self.digest())
    }
}

impl fmt::Debug for SchemaResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SchemaResource")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Topic,
    Subscription,
    Schema,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceProjection {
    pub kind: ResourceKind,
    pub digest: Digest,
}

impl ResourceProjection {
    fn new(kind: ResourceKind, digest: Digest) -> Self {
        Self { kind, digest }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderResourceScopeProjection {
    pub project_digest: Digest,
    pub topic: ResourceProjection,
    pub subscription: ResourceProjection,
    pub schema: Option<ResourceProjection>,
    pub dead_letter_topic: Option<ResourceProjection>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpPubsubSubscriptionScope {
    project: ProjectId,
    topic: TopicResource,
    subscription: SubscriptionResource,
    schema: Option<SchemaResource>,
    dead_letter_topic: Option<TopicResource>,
    mission: MissionId,
    work_product: WorkProductId,
    work_product_revision: Revision,
    permission_digest: Digest,
    consent_digest: Digest,
    scope_digest: Digest,
}

impl GcpPubsubSubscriptionScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project: ProjectId,
        topic: TopicResource,
        subscription: SubscriptionResource,
        schema: Option<SchemaResource>,
        dead_letter_topic: Option<TopicResource>,
        mission: MissionId,
        work_product: WorkProductId,
        work_product_revision: Revision,
        permission_digest: Digest,
        consent_digest: Digest,
    ) -> Result<Self, ModelError> {
        if topic.project() != &project
            || subscription.project() != &project
            || schema
                .as_ref()
                .is_some_and(|value| value.project() != &project)
            || dead_letter_topic
                .as_ref()
                .is_some_and(|value| value.project() != &project)
        {
            return Err(ModelError::InvalidScope);
        }
        let scope_digest = Digest::from_fields(
            "gcp-pubsub-subscription-scope/v1",
            &[
                project.digest().as_str().to_owned(),
                topic.digest().as_str().to_owned(),
                subscription.digest().as_str().to_owned(),
                schema
                    .as_ref()
                    .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                dead_letter_topic
                    .as_ref()
                    .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                mission.digest().as_str().to_owned(),
                work_product.digest().as_str().to_owned(),
                work_product_revision.get().to_string(),
                permission_digest.as_str().to_owned(),
                consent_digest.as_str().to_owned(),
            ],
        );
        Ok(Self {
            project,
            topic,
            subscription,
            schema,
            dead_letter_topic,
            mission,
            work_product,
            work_product_revision,
            permission_digest,
            consent_digest,
            scope_digest,
        })
    }

    pub fn project(&self) -> &ProjectId {
        &self.project
    }

    pub fn topic(&self) -> &TopicResource {
        &self.topic
    }

    pub fn subscription(&self) -> &SubscriptionResource {
        &self.subscription
    }

    pub fn schema(&self) -> Option<&SchemaResource> {
        self.schema.as_ref()
    }

    pub fn dead_letter_topic(&self) -> Option<&TopicResource> {
        self.dead_letter_topic.as_ref()
    }

    pub fn mission(&self) -> &MissionId {
        &self.mission
    }

    pub fn work_product(&self) -> &WorkProductId {
        &self.work_product
    }

    pub const fn work_product_revision(&self) -> Revision {
        self.work_product_revision
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub fn scope_digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    pub fn provider_resource_projection(&self) -> ProviderResourceScopeProjection {
        ProviderResourceScopeProjection {
            project_digest: self.project.digest(),
            topic: self.topic.projection(),
            subscription: self.subscription.projection(),
            schema: self.schema.as_ref().map(SchemaResource::projection),
            dead_letter_topic: self
                .dead_letter_topic
                .as_ref()
                .map(TopicResource::projection),
        }
    }

    pub(crate) fn fence(&self) -> PermissionFence {
        PermissionFence {
            scope_digest: self.scope_digest(),
            permission_digest: self.permission_digest.clone(),
            consent_digest: self.consent_digest.clone(),
            work_product_revision: self.work_product_revision,
        }
    }
}

/// An opaque keyring reference. The caller-provided reference id is hashed
/// immediately and is never retained, serialized, or printed.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    auth_kind: GoogleAuthKind,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            auth_kind: self.auth_kind,
            revoked: self.revoked,
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("auth_kind", &self.auth_kind)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.auth_kind == other.auth_kind
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &GcpPubsubSubscriptionScope,
        credential_revision: u64,
        auth_kind: GoogleAuthKind,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_identifier(&reference_id) {
            return Err(ModelError::InvalidIdentifier);
        }
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.scope_digest();
        let reference_digest = Digest::from_fields(
            "gcp-pubsub-secret-reference/v1",
            &[
                reference_id,
                scope_digest.as_str().to_owned(),
                credential_revision.get().to_string(),
                format!("{auth_kind:?}"),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
            auth_kind,
            revoked: false,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn auth_kind(&self) -> GoogleAuthKind {
        self.auth_kind
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::SecretAlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionFence {
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub work_product_revision: Revision,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FilterProjection {
    pub configured: bool,
    pub length: usize,
    pub digest: Option<Digest>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct FilterExpression {
    value: String,
    digest: Digest,
}

impl FilterExpression {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if !valid_text(&value, MAX_FILTER_BYTES) {
            return Err(ModelError::InvalidFilter);
        }
        Ok(Self {
            digest: Digest::from_fields("gcp-pubsub-filter/v1", std::slice::from_ref(&value)),
            value,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn projection(&self) -> FilterProjection {
        FilterProjection {
            configured: true,
            length: self.value.len(),
            digest: Some(self.digest.clone()),
        }
    }
}

impl fmt::Debug for FilterExpression {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FilterExpression")
            .field("length", &self.value.len())
            .field("digest", &self.digest)
            .finish()
    }
}

impl From<Option<&FilterExpression>> for FilterProjection {
    fn from(value: Option<&FilterExpression>) -> Self {
        value.map_or(
            Self {
                configured: false,
                length: 0,
                digest: None,
            },
            FilterExpression::projection,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PushWrapper {
    Pubsub,
    NoWrapper,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PushEndpointProjection {
    pub configured: bool,
    pub domain: Option<String>,
    pub endpoint_digest: Option<Digest>,
    pub oidc_service_account_digest: Option<Digest>,
    pub audience_digest: Option<Digest>,
    pub wrapper: Option<PushWrapper>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct PushConfiguration {
    endpoint: Option<String>,
    endpoint_domain: Option<String>,
    endpoint_digest: Option<Digest>,
    oidc_service_account: Option<String>,
    oidc_service_account_digest: Option<Digest>,
    audience: Option<String>,
    audience_digest: Option<Digest>,
    wrapper: PushWrapper,
}

impl PushConfiguration {
    pub fn new(
        endpoint: Option<impl Into<String>>,
        oidc_service_account: Option<impl Into<String>>,
        audience: Option<impl Into<String>>,
        wrapper: PushWrapper,
    ) -> Result<Self, ModelError> {
        let endpoint = endpoint.map(Into::into);
        let endpoint_domain = endpoint.as_deref().map(endpoint_domain).transpose()?;
        let endpoint_digest = endpoint
            .as_deref()
            .map(|value| Digest::from_fields("gcp-pubsub-push-endpoint/v1", &[value.to_owned()]));
        let oidc_service_account = oidc_service_account.map(Into::into);
        let oidc_service_account_digest = oidc_service_account.as_deref().map(|value| {
            Digest::from_fields("gcp-pubsub-oidc-service-account/v1", &[value.to_owned()])
        });
        if oidc_service_account
            .as_deref()
            .is_some_and(|value| !valid_email_like(value))
        {
            return Err(ModelError::InvalidIdentifier);
        }
        let audience = audience.map(Into::into);
        if audience
            .as_deref()
            .is_some_and(|value| !valid_text(value, MAX_IDENTIFIER_BYTES * 4))
        {
            return Err(ModelError::InvalidIdentifier);
        }
        let audience_digest = audience
            .as_deref()
            .map(|value| Digest::from_fields("gcp-pubsub-oidc-audience/v1", &[value.to_owned()]));
        Ok(Self {
            endpoint,
            endpoint_domain,
            endpoint_digest,
            oidc_service_account,
            oidc_service_account_digest,
            audience,
            audience_digest,
            wrapper,
        })
    }

    pub fn projection(&self) -> PushEndpointProjection {
        PushEndpointProjection {
            configured: self.endpoint.is_some(),
            domain: self.endpoint_domain.clone(),
            endpoint_digest: self.endpoint_digest.clone(),
            oidc_service_account_digest: self.oidc_service_account_digest.clone(),
            audience_digest: self.audience_digest.clone(),
            wrapper: self.endpoint.as_ref().map(|_| self.wrapper),
        }
    }

    pub fn configuration_digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-pubsub-push-configuration/v1",
            &[
                self.endpoint_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
                self.oidc_service_account_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
                self.audience_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
                format!("{:?}", self.wrapper),
            ],
        )
    }
}

impl fmt::Debug for PushConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PushConfiguration")
            .field("projection", &self.projection())
            .finish()
    }
}

fn valid_email_like(value: &str) -> bool {
    valid_text(value, 320)
        && value.matches('@').count() == 1
        && value.split('@').all(valid_identifier)
}

fn endpoint_domain(value: &str) -> Result<String, ModelError> {
    if !valid_text(value, MAX_ENDPOINT_BYTES) {
        return Err(ModelError::InvalidPushEndpoint);
    }
    let Some(scheme_end) = value.find("://") else {
        return Err(ModelError::InvalidPushEndpoint);
    };
    let authority = &value[scheme_end + 3..]
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return Err(ModelError::InvalidPushEndpoint);
    }
    let host = authority
        .rsplit_once(':')
        .map_or(*authority, |(host, port)| {
            if port.bytes().all(|byte| byte.is_ascii_digit()) {
                host
            } else {
                authority
            }
        });
    let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if host.is_empty()
        || host.len() > 253
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return Err(ModelError::InvalidPushEndpoint);
    }
    Ok(host)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaEncoding {
    Unspecified,
    Json,
    Binary,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaProjection {
    pub resource: ResourceProjection,
    pub encoding: SchemaEncoding,
    pub first_revision_digest: Option<Digest>,
    pub last_revision_digest: Option<Digest>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SchemaSettings {
    schema: SchemaResource,
    encoding: SchemaEncoding,
    first_revision: Option<String>,
    last_revision: Option<String>,
}

impl SchemaSettings {
    pub fn new(
        schema: SchemaResource,
        encoding: SchemaEncoding,
        first_revision: Option<impl Into<String>>,
        last_revision: Option<impl Into<String>>,
    ) -> Result<Self, ModelError> {
        let first_revision = first_revision.map(Into::into);
        let last_revision = last_revision.map(Into::into);
        if first_revision
            .as_deref()
            .is_some_and(|value| !valid_identifier(value))
            || last_revision
                .as_deref()
                .is_some_and(|value| !valid_identifier(value))
        {
            return Err(ModelError::InvalidSchema);
        }
        Ok(Self {
            schema,
            encoding,
            first_revision,
            last_revision,
        })
    }

    pub fn schema(&self) -> &SchemaResource {
        &self.schema
    }

    pub fn projection(&self) -> SchemaProjection {
        SchemaProjection {
            resource: self.schema.projection(),
            encoding: self.encoding,
            first_revision_digest: self.first_revision.as_ref().map(|value| {
                Digest::from_fields("gcp-pubsub-schema-revision/v1", std::slice::from_ref(value))
            }),
            last_revision_digest: self.last_revision.as_ref().map(|value| {
                Digest::from_fields("gcp-pubsub-schema-revision/v1", std::slice::from_ref(value))
            }),
        }
    }

    pub fn digest(&self) -> Digest {
        let projection = self.projection();
        Digest::from_fields(
            "gcp-pubsub-schema-settings/v1",
            &[
                projection.resource.digest.as_str().to_owned(),
                format!("{:?}", projection.encoding),
                projection
                    .first_revision_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
                projection
                    .last_revision_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ],
        )
    }
}

impl fmt::Debug for SchemaSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SchemaSettings")
            .field("projection", &self.projection())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TopicState {
    Active,
    StateUnspecified,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionState {
    Active,
    ResourceError,
    StateUnspecified,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TopicProjection {
    pub resource: ResourceProjection,
    pub schema: Option<SchemaProjection>,
    pub message_retention_seconds: Option<u64>,
    pub state: TopicState,
    pub configuration_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct TopicConfiguration {
    name: TopicResource,
    schema: Option<SchemaSettings>,
    message_retention_seconds: Option<u64>,
    state: TopicState,
    configuration_digest: Digest,
}

impl TopicConfiguration {
    pub fn new(
        name: TopicResource,
        schema: Option<SchemaSettings>,
        message_retention_seconds: Option<u64>,
        state: TopicState,
    ) -> Result<Self, ModelError> {
        validate_retention(message_retention_seconds)?;
        let configuration_digest =
            Self::compute_digest(&name, schema.as_ref(), message_retention_seconds, state);
        Ok(Self {
            name,
            schema,
            message_retention_seconds,
            state,
            configuration_digest,
        })
    }

    pub fn name(&self) -> &TopicResource {
        &self.name
    }

    pub fn schema(&self) -> Option<&SchemaSettings> {
        self.schema.as_ref()
    }

    pub fn state(&self) -> TopicState {
        self.state
    }

    pub fn configuration_digest(&self) -> &Digest {
        &self.configuration_digest
    }

    pub fn projection(&self) -> TopicProjection {
        TopicProjection {
            resource: self.name.projection(),
            schema: self.schema.as_ref().map(SchemaSettings::projection),
            message_retention_seconds: self.message_retention_seconds,
            state: self.state,
            configuration_digest: self.configuration_digest.clone(),
        }
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        if self.configuration_digest
            == Self::compute_digest(
                &self.name,
                self.schema.as_ref(),
                self.message_retention_seconds,
                self.state,
            )
        {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    fn compute_digest(
        name: &TopicResource,
        schema: Option<&SchemaSettings>,
        message_retention_seconds: Option<u64>,
        state: TopicState,
    ) -> Digest {
        Digest::from_fields(
            "gcp-pubsub-topic-configuration/v1",
            &[
                name.digest().as_str().to_owned(),
                schema.map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                message_retention_seconds.map_or_else(String::new, |value| value.to_string()),
                format!("{state:?}"),
            ],
        )
    }
}

impl fmt::Debug for TopicConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TopicConfiguration")
            .field("projection", &self.projection())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeadLetterProjection {
    pub topic: ResourceProjection,
    pub max_delivery_attempts: u8,
}

#[derive(Clone, Eq, PartialEq)]
pub struct DeadLetterPolicy {
    topic: TopicResource,
    max_delivery_attempts: u8,
}

impl DeadLetterPolicy {
    pub fn new(topic: TopicResource, max_delivery_attempts: u8) -> Result<Self, ModelError> {
        if !(5..=100).contains(&max_delivery_attempts) {
            return Err(ModelError::InvalidDeadLetterAttempts);
        }
        Ok(Self {
            topic,
            max_delivery_attempts,
        })
    }

    pub fn topic(&self) -> &TopicResource {
        &self.topic
    }

    pub fn projection(&self) -> DeadLetterProjection {
        DeadLetterProjection {
            topic: self.topic.projection(),
            max_delivery_attempts: self.max_delivery_attempts,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-pubsub-dead-letter-policy/v1",
            &[
                self.topic.digest().as_str().to_owned(),
                self.max_delivery_attempts.to_string(),
            ],
        )
    }
}

impl fmt::Debug for DeadLetterPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeadLetterPolicy")
            .field("projection", &self.projection())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetryPolicy {
    pub minimum_backoff_seconds: u16,
    pub maximum_backoff_seconds: u16,
}

impl RetryPolicy {
    pub fn new(
        minimum_backoff_seconds: u16,
        maximum_backoff_seconds: u16,
    ) -> Result<Self, ModelError> {
        if minimum_backoff_seconds > 600
            || maximum_backoff_seconds > 600
            || minimum_backoff_seconds > maximum_backoff_seconds
        {
            return Err(ModelError::InvalidRetryPolicy);
        }
        Ok(Self {
            minimum_backoff_seconds,
            maximum_backoff_seconds,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-pubsub-retry-policy/v1",
            &[
                self.minimum_backoff_seconds.to_string(),
                self.maximum_backoff_seconds.to_string(),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpirationPolicy {
    pub ttl_seconds: Option<u64>,
    pub expired: bool,
}

impl ExpirationPolicy {
    pub fn new(ttl_seconds: Option<u64>, expired: bool) -> Result<Self, ModelError> {
        if ttl_seconds.is_some_and(|value| {
            !(MIN_EXPIRATION_SECONDS..=MAX_EXPIRATION_SECONDS).contains(&value)
        }) {
            return Err(ModelError::InvalidDuration);
        }
        Ok(Self {
            ttl_seconds,
            expired,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-pubsub-expiration-policy/v1",
            &[
                self.ttl_seconds
                    .map_or_else(String::new, |value| value.to_string()),
                self.expired.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionProjection {
    pub resource: ResourceProjection,
    pub topic: ResourceProjection,
    pub state: SubscriptionState,
    pub detached: bool,
    pub expired: bool,
    pub ack_deadline_seconds: u16,
    pub retain_acked_messages: bool,
    pub message_retention_seconds: Option<u64>,
    pub topic_message_retention_seconds: Option<u64>,
    pub expiration: ExpirationPolicy,
    pub filter: FilterProjection,
    pub dead_letter: Option<DeadLetterProjection>,
    pub retry: Option<RetryPolicy>,
    pub push: Option<PushEndpointProjection>,
    pub enable_message_ordering: bool,
    pub enable_exactly_once_delivery: bool,
    pub configuration_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SubscriptionConfiguration {
    name: SubscriptionResource,
    topic: TopicResource,
    state: SubscriptionState,
    detached: bool,
    ack_deadline_seconds: u16,
    retain_acked_messages: bool,
    message_retention_seconds: Option<u64>,
    topic_message_retention_seconds: Option<u64>,
    expiration: ExpirationPolicy,
    filter: Option<FilterExpression>,
    dead_letter: Option<DeadLetterPolicy>,
    retry: Option<RetryPolicy>,
    push: Option<PushConfiguration>,
    enable_message_ordering: bool,
    enable_exactly_once_delivery: bool,
    configuration_digest: Digest,
}

impl SubscriptionConfiguration {
    #[allow(clippy::fn_params_excessive_bools)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: SubscriptionResource,
        topic: TopicResource,
        state: SubscriptionState,
        detached: bool,
        ack_deadline_seconds: u16,
        retain_acked_messages: bool,
        message_retention_seconds: Option<u64>,
        topic_message_retention_seconds: Option<u64>,
        expiration: ExpirationPolicy,
        filter: Option<FilterExpression>,
        dead_letter: Option<DeadLetterPolicy>,
        retry: Option<RetryPolicy>,
        push: Option<PushConfiguration>,
        enable_message_ordering: bool,
        enable_exactly_once_delivery: bool,
    ) -> Result<Self, ModelError> {
        if ack_deadline_seconds > 600 {
            return Err(ModelError::InvalidDuration);
        }
        validate_retention(message_retention_seconds)?;
        validate_retention(topic_message_retention_seconds)?;
        if dead_letter
            .as_ref()
            .is_some_and(|value| value.topic().project() != name.project())
            || topic.project() != name.project()
        {
            return Err(ModelError::InvalidScope);
        }
        let configuration_digest = Self::compute_digest(
            &name,
            &topic,
            state,
            detached,
            ack_deadline_seconds,
            retain_acked_messages,
            message_retention_seconds,
            topic_message_retention_seconds,
            expiration,
            filter.as_ref(),
            dead_letter.as_ref(),
            retry,
            push.as_ref(),
            enable_message_ordering,
            enable_exactly_once_delivery,
        );
        Ok(Self {
            name,
            topic,
            state,
            detached,
            ack_deadline_seconds,
            retain_acked_messages,
            message_retention_seconds,
            topic_message_retention_seconds,
            expiration,
            filter,
            dead_letter,
            retry,
            push,
            enable_message_ordering,
            enable_exactly_once_delivery,
            configuration_digest,
        })
    }

    pub fn name(&self) -> &SubscriptionResource {
        &self.name
    }

    pub fn topic(&self) -> &TopicResource {
        &self.topic
    }

    pub fn state(&self) -> SubscriptionState {
        self.state
    }

    pub const fn detached(&self) -> bool {
        self.detached
    }

    pub const fn expired(&self) -> bool {
        self.expiration.expired
    }

    pub fn dead_letter(&self) -> Option<&DeadLetterPolicy> {
        self.dead_letter.as_ref()
    }

    pub fn configuration_digest(&self) -> &Digest {
        &self.configuration_digest
    }

    pub fn projection(&self) -> SubscriptionProjection {
        SubscriptionProjection {
            resource: self.name.projection(),
            topic: self.topic.projection(),
            state: self.state,
            detached: self.detached,
            expired: self.expired(),
            ack_deadline_seconds: self.ack_deadline_seconds,
            retain_acked_messages: self.retain_acked_messages,
            message_retention_seconds: self.message_retention_seconds,
            topic_message_retention_seconds: self.topic_message_retention_seconds,
            expiration: self.expiration,
            filter: self.filter.as_ref().into(),
            dead_letter: self.dead_letter.as_ref().map(DeadLetterPolicy::projection),
            retry: self.retry,
            push: self.push.as_ref().map(PushConfiguration::projection),
            enable_message_ordering: self.enable_message_ordering,
            enable_exactly_once_delivery: self.enable_exactly_once_delivery,
            configuration_digest: self.configuration_digest.clone(),
        }
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        let expected = Self::compute_digest(
            &self.name,
            &self.topic,
            self.state,
            self.detached,
            self.ack_deadline_seconds,
            self.retain_acked_messages,
            self.message_retention_seconds,
            self.topic_message_retention_seconds,
            self.expiration,
            self.filter.as_ref(),
            self.dead_letter.as_ref(),
            self.retry,
            self.push.as_ref(),
            self.enable_message_ordering,
            self.enable_exactly_once_delivery,
        );
        if expected == self.configuration_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    #[allow(clippy::fn_params_excessive_bools)]
    fn compute_digest(
        name: &SubscriptionResource,
        topic: &TopicResource,
        state: SubscriptionState,
        detached: bool,
        ack_deadline_seconds: u16,
        retain_acked_messages: bool,
        message_retention_seconds: Option<u64>,
        topic_message_retention_seconds: Option<u64>,
        expiration: ExpirationPolicy,
        filter: Option<&FilterExpression>,
        dead_letter: Option<&DeadLetterPolicy>,
        retry: Option<RetryPolicy>,
        push: Option<&PushConfiguration>,
        enable_message_ordering: bool,
        enable_exactly_once_delivery: bool,
    ) -> Digest {
        Digest::from_fields(
            "gcp-pubsub-subscription-configuration/v1",
            &[
                name.digest().as_str().to_owned(),
                topic.digest().as_str().to_owned(),
                format!("{state:?}"),
                detached.to_string(),
                ack_deadline_seconds.to_string(),
                retain_acked_messages.to_string(),
                message_retention_seconds.map_or_else(String::new, |value| value.to_string()),
                topic_message_retention_seconds.map_or_else(String::new, |value| value.to_string()),
                expiration.digest().as_str().to_owned(),
                filter.map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                dead_letter.map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                retry.map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                push.map_or_else(String::new, |value| {
                    value.configuration_digest().as_str().to_owned()
                }),
                enable_message_ordering.to_string(),
                enable_exactly_once_delivery.to_string(),
            ],
        )
    }
}

impl fmt::Debug for SubscriptionConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubscriptionConfiguration")
            .field("projection", &self.projection())
            .finish()
    }
}

fn validate_retention(value: Option<u64>) -> Result<(), ModelError> {
    if value
        .is_some_and(|seconds| !(MIN_RETENTION_SECONDS..=MAX_RETENTION_SECONDS).contains(&seconds))
    {
        Err(ModelError::InvalidDuration)
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SubscriptionPosture {
    Active,
    Detached,
    Expired,
    Misconfigured,
    Partial,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub topic_digest: Option<Digest>,
    pub subscription_digest: Option<Digest>,
    pub configuration_digest: Digest,
    pub permission_digest: Digest,
    pub result_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    BadRequest,
    Unauthenticated,
    PermissionDenied,
    NotFound,
    RateLimited,
    ServerFailure,
    Timeout,
    MalformedResponse,
    BlockedEnv,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderErrorEvidence {
    pub operation: String,
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
}

/// A token can be passed through the provider seam, but only its digest and
/// binding are retained. The provider's raw pagination token is never part of
/// a request receipt or result projection.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaquePageToken {
    token_digest: Digest,
    binding_digest: Digest,
    page_number: u8,
}

impl OpaquePageToken {
    pub fn new(value: impl AsRef<[u8]>) -> Result<Self, ModelError> {
        let bytes = value.as_ref();
        if bytes.is_empty()
            || bytes.len() > MAX_PAGE_TOKEN_BYTES
            || bytes.iter().any(u8::is_ascii_whitespace)
        {
            return Err(ModelError::InvalidPageToken);
        }
        Ok(Self {
            token_digest: Digest::from_bytes(bytes),
            binding_digest: Digest::from_text("unbound-page-token"),
            page_number: 1,
        })
    }

    pub fn bound(
        value: impl AsRef<[u8]>,
        scope_digest: &Digest,
        list_digest: &Digest,
        page_number: u8,
    ) -> Result<Self, ModelError> {
        let mut token = Self::new(value)?;
        token.binding_digest = Self::compute_binding_digest(scope_digest, list_digest);
        token.page_number = page_number.max(1);
        Ok(token)
    }

    #[must_use]
    pub fn bind_to(&self, scope_digest: &Digest, list_digest: &Digest, page_number: u8) -> Self {
        Self {
            token_digest: self.token_digest.clone(),
            binding_digest: Self::compute_binding_digest(scope_digest, list_digest),
            page_number: page_number.max(1),
        }
    }

    pub fn digest(&self) -> Digest {
        self.token_digest.clone()
    }

    pub fn page_number(&self) -> u8 {
        self.page_number
    }

    pub fn validate_binding(
        &self,
        scope_digest: &Digest,
        list_digest: &Digest,
    ) -> Result<(), ModelError> {
        if self.binding_digest == Self::compute_binding_digest(scope_digest, list_digest) {
            Ok(())
        } else {
            Err(ModelError::PageTokenBindingMismatch)
        }
    }

    fn compute_binding_digest(scope_digest: &Digest, list_digest: &Digest) -> Digest {
        Digest::from_fields(
            "gcp-pubsub-page-token-binding/v1",
            &[
                scope_digest.as_str().to_owned(),
                list_digest.as_str().to_owned(),
            ],
        )
    }
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BoundedLabels {
    pub count: usize,
    pub key_digest: Option<Digest>,
}

impl BoundedLabels {
    pub fn from_map(labels: &BTreeMap<String, String>) -> Self {
        let key_digest = if labels.is_empty() {
            None
        } else {
            let keys = labels.keys().cloned().collect::<Vec<_>>().join("\u{1f}");
            Some(Digest::from_fields("gcp-pubsub-label-keys/v1", &[keys]))
        };
        Self {
            count: labels.len(),
            key_digest,
        }
    }
}
